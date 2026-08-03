package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthTokenRoundTrip(t *testing.T) {
	secret := []byte("test-secret-key-01234567890123456789")
	email := "crystal@stg.net"
	now := time.Unix(1_700_000_000, 0)
	tok := makeAuthToken(secret, email, now.Add(7*24*time.Hour))

	got, ok := parseAuthToken(secret, tok, now)
	if !ok {
		t.Fatal("freshly minted token should validate")
	}
	if got != email {
		t.Fatalf("token should carry its address: got %q, want %q", got, email)
	}
}

func TestAuthTokenExpiry(t *testing.T) {
	secret := []byte("test-secret-key-01234567890123456789")
	email := "crystal@stg.net"
	issued := time.Unix(1_700_000_000, 0)
	tok := makeAuthToken(secret, email, issued.Add(time.Hour))

	if _, ok := parseAuthToken(secret, tok, issued.Add(2*time.Hour)); ok {
		t.Error("expired token must be rejected")
	}
	if _, ok := parseAuthToken(secret, tok, issued.Add(30*time.Minute)); !ok {
		t.Error("token still within lifetime should validate")
	}
}

func TestAuthTokenTampering(t *testing.T) {
	secret := []byte("test-secret-key-01234567890123456789")
	email := "crystal@stg.net"
	now := time.Unix(1_700_000_000, 0)
	tok := makeAuthToken(secret, email, now.Add(time.Hour))

	// Wrong signing key.
	if _, ok := parseAuthToken([]byte("different-secret-key-000000000000000"), tok, now); ok {
		t.Error("token signed with a different secret must be rejected")
	}
	// Flipped last byte of the signature.
	bad := tok[:len(tok)-1]
	if tok[len(tok)-1] == 'A' {
		bad += "B"
	} else {
		bad += "A"
	}
	if _, ok := parseAuthToken(secret, bad, now); ok {
		t.Error("token with a tampered signature must be rejected")
	}
	// Structurally broken tokens.
	for _, junk := range []string{"", "no-dot", "a.b.c", ".", "payload."} {
		if _, ok := parseAuthToken(secret, junk, now); ok {
			t.Errorf("malformed token %q must be rejected", junk)
		}
	}
}

// A correctly-signed token is not by itself a session: the address it carries
// must still be approved. This is what makes a ban take effect immediately
// rather than when the cookie eventually expires, and it also stands in for the
// address check that used to live inside the token comparison — a token minted
// for another vhost's user is rejected here unless that address is approved.
func TestAuthCookieRequiresApproval(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users")
	if err := os.WriteFile(usersFile, []byte("friend@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := siteSettings{
		AuthEmail:     "crystal@stg.net",
		AuthSecret:    []byte("test-secret-key-01234567890123456789"),
		AuthUsersFile: usersFile,
	}
	expiry := time.Now().Add(time.Hour)

	req := func(email string) *http.Request {
		r := httptest.NewRequest("GET", "/recipe?list", nil)
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: makeAuthToken(s.AuthSecret, email, expiry)})
		return r
	}

	for _, email := range []string{"crystal@stg.net", "friend@example.com"} {
		got, ok := validAuthCookie(req(email), s)
		if !ok {
			t.Errorf("approved address %q should hold a session", email)
		}
		if got != email {
			t.Errorf("session identity: got %q, want %q", got, email)
		}
	}
	if _, ok := validAuthCookie(req("stranger@example.com"), s); ok {
		t.Error("address absent from the users file must not hold a session")
	}

	// Revoking on disk takes effect without a restart, even though the cookie
	// itself is still perfectly valid and unexpired.
	if err := os.WriteFile(usersFile, []byte("# friend removed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := validAuthCookie(req("friend@example.com"), s); ok {
		t.Error("a revoked address must lose its session on the very next request")
	}
	// The owner address is never revocable this way, so the site cannot be
	// locked out by an empty or broken users file.
	if _, ok := validAuthCookie(req("crystal@stg.net"), s); !ok {
		t.Error("owner address must keep access regardless of the users file")
	}
}

func TestAuthAllowedNormalizesCase(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users")
	if err := os.WriteFile(usersFile, []byte("  Friend@Example.COM  \n\n# a comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := siteSettings{AuthEmail: "Crystal@STG.net", AuthUsersFile: usersFile}

	for _, addr := range []string{"friend@example.com", "FRIEND@EXAMPLE.COM", " friend@example.com "} {
		if !authAllowed(s, addr) {
			t.Errorf("%q should match the approved address regardless of case/space", addr)
		}
	}
	if !authAllowed(s, "crystal@stg.net") {
		t.Error("owner address should match case-insensitively too")
	}
	if authAllowed(s, "") || authAllowed(s, "# a comment") {
		t.Error("blank lines and comments must not become approved addresses")
	}
}

// A missing users file must fail closed — only the owner may sign in — rather
// than being read as "no restrictions".
func TestAuthUsersFileMissingFailsClosed(t *testing.T) {
	s := siteSettings{AuthEmail: "crystal@stg.net", AuthUsersFile: "/nonexistent/nope"}
	if !authAllowed(s, "crystal@stg.net") {
		t.Error("owner must still be allowed when the users file is missing")
	}
	if authAllowed(s, "anyone@example.com") {
		t.Error("a missing users file must not admit anyone")
	}
}

// The proxied path (a web shell here) must be reachable only by the addresses
// listed for it, not by everyone who can sign in. This cannot be enforced by the
// app, so it is worth pinning down: a signed-in ordinary user gets 403, a listed
// one gets through.
func TestProxyPathUsersFile(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users")
	superFile := filepath.Join(dir, "supers")
	if err := os.WriteFile(usersFile, []byte("friend@example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(superFile, []byte("crystal@stg.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := siteSettings{
		AuthEmail:      "crystal@stg.net",
		AuthSecret:     []byte("test-secret-key-01234567890123456789"),
		AuthUsersFile:  usersFile,
		ProxyPathUsers: superFile,
	}
	// Both are legitimately signed in; only one may reach the backend.
	if !authAllowed(s, "friend@example.com") {
		t.Fatal("precondition: friend should be able to sign in at all")
	}
	if !loadAuthUsers(s.ProxyPathUsers)["crystal@stg.net"] {
		t.Error("listed address should be allowed through to the proxy")
	}
	if loadAuthUsers(s.ProxyPathUsers)["friend@example.com"] {
		t.Error("signing in must not by itself grant access to the proxied path")
	}
}

// A site that has not opted into multiple users must keep the original
// one-button login: no address field, and auth-email assumed. Sites that set
// auth-users-file get the field, because there the address is a real choice.
func TestLoginPageAsksForAddressOnlyWhenMultiUser(t *testing.T) {
	base := siteSettings{
		AuthEmail:  "owner@example.com",
		AuthSecret: []byte("test-secret-key-01234567890123456789"),
	}
	render := func(s siteSettings) string {
		w := httptest.NewRecorder()
		authLoginPage(w, httptest.NewRequest("GET", "/auth/login", nil), s, "")
		return w.Body.String()
	}

	if strings.Contains(render(base), `name="email"`) {
		t.Error("single-recipient site must not ask for an address")
	}
	multi := base
	multi.AuthUsersFile = filepath.Join(t.TempDir(), "users")
	if !strings.Contains(render(multi), `name="email"`) {
		t.Error("multi-user site must ask which address is signing in")
	}
}

func TestPlausibleEmail(t *testing.T) {
	ok := []string{"a@b.co", "crystal@stg.net", "first.last+tag@sub.example.org"}
	bad := []string{
		"", "nope", "@example.com", "user@", "user@localhost",
		"user@example.com\r\nBcc: victim@example.com", // header injection
		"user name@example.com",
		strings.Repeat("x", 250) + "@example.com", // over length
	}
	for _, a := range ok {
		if !plausibleEmail(a) {
			t.Errorf("%q should be accepted", a)
		}
	}
	for _, a := range bad {
		if plausibleEmail(a) {
			t.Errorf("%q should be rejected", a)
		}
	}
}

// The per-address limits cannot bound a site that accepts many addresses, so
// the global cap is what actually stops the endpoint relaying mail. Rotating
// addresses must hit it.
func TestIssueCodeGlobalCap(t *testing.T) {
	// The code store and the global send log are package-level, so this test
	// both starts from a clean slate and restores one — otherwise filling the
	// hourly cap here would starve every later test in the package.
	authCodesMu.Lock()
	prevCodes, prevLog := authCodes, authSendGlobalLog
	authCodes = map[string]*authCodeEntry{}
	authSendGlobalLog = nil
	authCodesMu.Unlock()
	t.Cleanup(func() {
		authCodesMu.Lock()
		authCodes, authSendGlobalLog = prevCodes, prevLog
		authCodesMu.Unlock()
	})

	sent := 0
	for i := 0; i < authSendGlobal+10; i++ {
		if _, err := issueCode(fmt.Sprintf("user%d@example.com", i)); err == nil {
			sent++
		}
	}
	if sent != authSendGlobal {
		t.Errorf("global cap: sent %d codes, want exactly %d", sent, authSendGlobal)
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
