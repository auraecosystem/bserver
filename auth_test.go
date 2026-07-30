package main

import (
	"strings"
	"testing"
	"time"
)

func TestAuthTokenRoundTrip(t *testing.T) {
	secret := []byte("test-secret-key-01234567890123456789")
	email := "crystal@stg.net"
	now := time.Unix(1_700_000_000, 0)
	tok := makeAuthToken(secret, email, now.Add(7*24*time.Hour))

	if !validAuthToken(secret, email, tok, now) {
		t.Fatal("freshly minted token should validate")
	}
}

func TestAuthTokenExpiry(t *testing.T) {
	secret := []byte("test-secret-key-01234567890123456789")
	email := "crystal@stg.net"
	issued := time.Unix(1_700_000_000, 0)
	tok := makeAuthToken(secret, email, issued.Add(time.Hour))

	if validAuthToken(secret, email, tok, issued.Add(2*time.Hour)) {
		t.Error("expired token must be rejected")
	}
	if !validAuthToken(secret, email, tok, issued.Add(30*time.Minute)) {
		t.Error("token still within lifetime should validate")
	}
}

func TestAuthTokenTampering(t *testing.T) {
	secret := []byte("test-secret-key-01234567890123456789")
	email := "crystal@stg.net"
	now := time.Unix(1_700_000_000, 0)
	tok := makeAuthToken(secret, email, now.Add(time.Hour))

	// Wrong signing key.
	if validAuthToken([]byte("different-secret-key-000000000000000"), email, tok, now) {
		t.Error("token signed with a different secret must be rejected")
	}
	// Flipped last byte of the signature.
	bad := tok[:len(tok)-1]
	if tok[len(tok)-1] == 'A' {
		bad += "B"
	} else {
		bad += "A"
	}
	if validAuthToken(secret, email, bad, now) {
		t.Error("token with a tampered signature must be rejected")
	}
	// Mismatched recipient (e.g. secret shared across vhosts).
	if validAuthToken(secret, "someone@else.net", tok, now) {
		t.Error("token whose embedded address differs from the vhost must be rejected")
	}
	// Structurally broken tokens.
	for _, junk := range []string{"", "no-dot", "a.b.c", ".", "payload."} {
		if validAuthToken(secret, email, junk, now) {
			t.Errorf("malformed token %q must be rejected", junk)
		}
	}
}

func TestSafeNext(t *testing.T) {
	cases := map[string]string{
		"/recipe?list":        "/recipe?list",
		"/":                   "/",
		"":                    "/",
		"//evil.com":          "/", // protocol-relative open redirect
		"https://evil.com":    "/", // absolute URL
		"javascript:alert(1)": "/", // scheme injection
		"/a/b/c":              "/a/b/c",
		"/\\evil.com":         "/", // browsers normalize \ to / => //evil.com
		"/\\/evil.com":        "/", // same, with an extra slash
		"/a\\b":               "/", // backslash anywhere is rejected
		"/a\r\nSet-Cookie: x": "/", // control bytes rejected
	}
	for in, want := range cases {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodeIssueAndCheck(t *testing.T) {
	email := "codetest@stg.net" // unique key so other tests don't interfere
	deleteAuthCode(email)

	code, err := issueCode(email)
	if err != nil {
		t.Fatalf("issueCode: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
	if checkCode(email, "000000") && code != "000000" {
		t.Error("a wrong code should not verify")
	}
	if !checkCode(email, code) {
		t.Error("the correct code should verify")
	}
	if checkCode(email, code) {
		t.Error("a code must be single-use (rejected after first success)")
	}
}

func TestCodeSendRateLimit(t *testing.T) {
	email := "ratetest@stg.net"
	deleteAuthCode(email)

	if _, err := issueCode(email); err != nil {
		t.Fatalf("first issue should succeed: %v", err)
	}
	// A second immediate request is throttled by the minimum-gap rule.
	if _, err := issueCode(email); err == nil {
		t.Error("a second immediate code request should be rate-limited")
	} else if !strings.Contains(err.Error(), "wait") {
		t.Errorf("unexpected rate-limit error: %v", err)
	}
}

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"crystal@stg.net": "c*****l@stg.net",
		"ab@x.com":        "a***@x.com",
		"a@x.com":         "a***@x.com",
	}
	for in, want := range cases {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
