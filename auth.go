package main

// Passwordless per-vhost authentication.
//
// When a vhost sets auth-email in its _config.yaml, the whole vhost is gated:
// the splash page and a small always-public set stay open, but every other
// path requires a valid bs_auth cookie. A visitor gets the cookie by requesting
// a one-time numeric code, which is emailed to auth-email, and entering it. The
// cookie is an HMAC-signed token carrying the recipient address and an expiry
// (default 7 days), so it can be verified statelessly on every request and
// survives server restarts (the signing secret is persisted to a file).
//
// The gate itself lives in server.go's ServeHTTP; this file provides the token
// scheme, the code store, the mailer, and the /auth/* endpoints.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	authCookieName  = "bs_auth"
	authCodeTTL     = 10 * time.Minute
	authCodeMaxTry  = 5               // wrong-code guesses before a code is burned
	authSendMinGap  = 30 * time.Second // minimum spacing between code emails
	authSendPerHour = 5                // max code emails per hour
	authDialTimeout = 20 * time.Second
	authSMTPDeadln  = 60 * time.Second // overall deadline once connected (covers greet-pause)
)

// loadOrCreateSecret returns the HMAC signing key stored at path, generating and
// persisting a fresh 32-byte key (base64url-encoded, 0600) if the file does not
// yet exist. Persisting it means issued 7-day cookies stay valid across restarts.
func loadOrCreateSecret(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		s := strings.TrimSpace(string(b))
		if len(s) < 16 {
			return nil, fmt.Errorf("secret too short (%d bytes); delete %s to regenerate", len(s), path)
		}
		return []byte(s), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return nil, err
	}
	log.Printf("auth: generated new signing secret at %s", path)
	return []byte(enc), nil
}

// --- Signed cookie token ---------------------------------------------------

// makeAuthToken builds "payload.signature", where payload is a base64url copy of
// "email|expiryUnix" and signature is its HMAC-SHA256 under secret.
func makeAuthToken(secret []byte, email string, expiry time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(email + "|" + strconv.FormatInt(expiry.Unix(), 10)))
	return payload + "." + authSign(secret, payload)
}

func authSign(secret []byte, payload string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// validAuthToken reports whether token is a well-formed, correctly-signed,
// unexpired cookie whose embedded address matches wantEmail. The signature is
// checked in constant time; only if it holds is the payload trusted.
func validAuthToken(secret []byte, wantEmail, token string, now time.Time) bool {
	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return false
	}
	payload, sig := token[:dot], token[dot+1:]
	if subtle.ConstantTimeCompare([]byte(sig), []byte(authSign(secret, payload))) != 1 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	bar := strings.LastIndexByte(string(raw), '|')
	if bar < 0 {
		return false
	}
	email, expStr := string(raw[:bar]), string(raw[bar+1:])
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || now.Unix() >= exp {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(email), []byte(wantEmail)) == 1
}

// validAuthCookie reports whether the request carries a valid bs_auth cookie.
// All cookies of that name are checked, not just the first, to tolerate a stale
// duplicate (see anyCookieMatches for the same reasoning).
func validAuthCookie(r *http.Request, s siteSettings) bool {
	now := time.Now()
	for _, c := range r.Cookies() {
		if c.Name == authCookieName && validAuthToken(s.AuthSecret, s.AuthEmail, c.Value, now) {
			return true
		}
	}
	return false
}

func setAuthCookie(w http.ResponseWriter, s siteSettings) {
	expiry := time.Now().Add(s.AuthTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    makeAuthToken(s.AuthSecret, s.AuthEmail, expiry),
		Path:     "/",
		Expires:  expiry,
		MaxAge:   int(s.AuthTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// authPublic reports whether p is reachable without authentication: the splash
// page, favicon/robots, ACME + security.txt under /.well-known, and any extra
// prefixes the vhost lists in auth-public. Note that /auth/* is handled before
// this check in the gate, so it is not listed here.
func authPublic(p string, s siteSettings) bool {
	switch p {
	case "/", "/favicon.ico", "/robots.txt", "/sitemap.xml":
		return true
	}
	if strings.HasPrefix(p, "/.well-known/") {
		return true
	}
	for _, pre := range s.AuthPublic {
		pre = "/" + strings.Trim(pre, "/")
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// safeNext sanitizes a post-login redirect target so it can only point back into
// this site — a leading single slash and no scheme/host — defeating open
// redirects like //evil.com or https://evil.com.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

// --- One-time code store ---------------------------------------------------

type authCodeEntry struct {
	hash    [32]byte
	expiry  time.Time
	tries   int
	sentLog []time.Time // send timestamps within the trailing hour, for rate limiting
}

var authCodes sync.Map // email -> *authCodeEntry (this site has one recipient, but keying by email keeps it general)

func newAuthCode() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is catastrophic; fail closed with an unusable code.
		return ""
	}
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(b[:])%1_000_000)
}

// issueCode enforces the send rate limits, mints a fresh code, stores its hash,
// and returns the plaintext to mail. The returned error is a user-facing reason
// when a send is refused (too frequent / hourly cap).
func issueCode(email string) (string, error) {
	now := time.Now()
	v, _ := authCodes.LoadOrStore(email, &authCodeEntry{})
	e := v.(*authCodeEntry)

	// Prune send log to the trailing hour, then apply the two limits.
	kept := e.sentLog[:0]
	for _, t := range e.sentLog {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	e.sentLog = kept
	if len(e.sentLog) > 0 && now.Sub(e.sentLog[len(e.sentLog)-1]) < authSendMinGap {
		return "", fmt.Errorf("please wait a moment before requesting another code")
	}
	if len(e.sentLog) >= authSendPerHour {
		return "", fmt.Errorf("too many codes requested; try again later")
	}

	code := newAuthCode()
	if code == "" {
		return "", fmt.Errorf("could not generate a code")
	}
	e.hash = sha256.Sum256([]byte(code))
	e.expiry = now.Add(authCodeTTL)
	e.tries = 0
	e.sentLog = append(e.sentLog, now)
	return code, nil
}

// checkCode verifies a submitted code, consuming it on success and burning it
// after too many wrong guesses.
func checkCode(email, code string) bool {
	v, ok := authCodes.Load(email)
	if !ok {
		return false
	}
	e := v.(*authCodeEntry)
	if time.Now().After(e.expiry) || e.tries >= authCodeMaxTry {
		authCodes.Delete(email)
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(code)))
	if subtle.ConstantTimeCompare(got[:], e.hash[:]) == 1 {
		authCodes.Delete(email) // single use
		return true
	}
	e.tries++
	return false
}

// --- Mailer ----------------------------------------------------------------

// sendLoginCode delivers the code to s.AuthEmail via direct SMTP to s.AuthSMTP.
// It dials with a timeout and sets an overall deadline so a slow/greylisting
// relay (a deliberately delayed 220 banner is common) cannot hang the sender.
// No SMTP auth or STARTTLS is attempted — this targets a trusted internal relay.
func sendLoginCode(s siteSettings) error {
	code, err := issueCode(s.AuthEmail)
	if err != nil {
		return err
	}
	host := s.AuthSMTP
	if h, _, e := net.SplitHostPort(s.AuthSMTP); e == nil {
		host = h
	}
	helo, _ := os.Hostname()
	if helo == "" {
		helo = "localhost"
	}
	// A Message-ID and Date are mandatory for RFC 5322 compliance; strict MXs
	// (e.g. Google) reject messages that omit them.
	domain := s.AuthFrom
	if at := strings.LastIndexByte(s.AuthFrom, '@'); at >= 0 {
		domain = s.AuthFrom[at+1:]
	}
	var idbuf [16]byte
	_, _ = rand.Read(idbuf[:])
	msgID := "<" + base64.RawURLEncoding.EncodeToString(idbuf[:]) + "@" + domain + ">"
	body := "From: " + s.AuthFrom + "\r\n" +
		"To: " + s.AuthEmail + "\r\n" +
		"Subject: Your login code\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: " + msgID + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Your login code is: " + code + "\r\n\r\n" +
		"It expires in 10 minutes. If you did not request it, you can ignore this email.\r\n"

	conn, err := net.DialTimeout("tcp", s.AuthSMTP, authDialTimeout)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(authSMTPDeadln))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello(helo); err != nil {
		return err
	}
	if err := c.Mail(s.AuthFrom); err != nil {
		return err
	}
	if err := c.Rcpt(s.AuthEmail); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(body)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// --- HTTP endpoints --------------------------------------------------------

// serveAuth dispatches the /auth/* endpoints. p is the cleaned request path.
func serveAuth(w http.ResponseWriter, r *http.Request, s siteSettings, p string) {
	switch p {
	case "/auth/login":
		authLoginPage(w, r, s, "")
	case "/auth/send":
		authSend(w, r, s)
	case "/auth/verify":
		authVerify(w, r, s)
	case "/auth/logout":
		clearAuthCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func authSend(w http.ResponseWriter, r *http.Request, s siteSettings) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	next := safeNext(r.FormValue("next"))
	// Mail is sent synchronously so we can surface a real failure to the user,
	// but the SMTP deadline bounds how long that can take.
	if err := sendLoginCode(s); err != nil {
		log.Printf("auth: sending login code to %s failed: %v", s.AuthEmail, err)
		authLoginPage(w, r, s, err.Error())
		return
	}
	http.Redirect(w, r, "/auth/login?sent=1&next="+urlQueryEscape(next), http.StatusSeeOther)
}

func authVerify(w http.ResponseWriter, r *http.Request, s siteSettings) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}
	next := safeNext(r.FormValue("next"))
	if checkCode(s.AuthEmail, r.FormValue("code")) {
		setAuthCookie(w, s)
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/auth/login?err=1&next="+urlQueryEscape(next), http.StatusSeeOther)
}

// authLoginPage renders the self-contained login page. errMsg, when non-empty,
// is an inline error to show (e.g. a mail failure). Query flags sent=1 / err=1
// drive the "code sent" and "incorrect code" notices.
func authLoginPage(w http.ResponseWriter, r *http.Request, s siteSettings, errMsg string) {
	next := safeNext(r.URL.Query().Get("next"))
	sent := r.URL.Query().Get("sent") == "1"
	if errMsg == "" && r.URL.Query().Get("err") == "1" {
		errMsg = "That code was incorrect or expired. Request a new one."
	}

	var notice string
	if errMsg != "" {
		notice = `<p class="msg err">` + html.EscapeString(errMsg) + `</p>`
	} else if sent {
		notice = `<p class="msg ok">A login code was sent to ` + html.EscapeString(maskEmail(s.AuthEmail)) + `. Enter it below.</p>`
	}

	nextEsc := html.EscapeString(next)
	page := `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f5f5f7;color:#1d1d1f}
@media(prefers-color-scheme:dark){body{background:#111;color:#eee}}
.card{background:#fff;max-width:22rem;width:calc(100% - 2rem);padding:2rem;border-radius:14px;
  box-shadow:0 8px 30px rgba(0,0,0,.12)}
@media(prefers-color-scheme:dark){.card{background:#1c1c1e;box-shadow:0 8px 30px rgba(0,0,0,.5)}}
h1{font-size:1.35rem;margin:0 0 .25rem}
p.sub{margin:0 0 1.25rem;color:#666}
@media(prefers-color-scheme:dark){p.sub{color:#aaa}}
form{margin:0}
button,input{font:inherit;width:100%;padding:.6rem .7rem;border-radius:9px;border:1px solid #ccc}
@media(prefers-color-scheme:dark){button,input{border-color:#444;background:#2c2c2e;color:#eee}}
button{border:0;background:#0a84ff;color:#fff;font-weight:600;cursor:pointer;margin-top:.25rem}
button:hover{background:#0060df}
.divider{display:flex;align-items:center;gap:.75rem;margin:1.25rem 0;color:#999;font-size:.85rem}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:#ddd}
@media(prefers-color-scheme:dark){.divider::before,.divider::after{background:#3a3a3c}}
label{display:block;font-size:.8rem;color:#666;margin:0 0 .3rem}
@media(prefers-color-scheme:dark){label{color:#aaa}}
.msg{padding:.6rem .7rem;border-radius:9px;margin:0 0 1rem;font-size:.9rem}
.msg.ok{background:#e7f6ec;color:#1a7f37}
.msg.err{background:#fdecea;color:#c0362c}
@media(prefers-color-scheme:dark){.msg.ok{background:#0f2e1a;color:#4ade80}.msg.err{background:#3a1513;color:#f87171}}
.home{display:block;text-align:center;margin-top:1.25rem;font-size:.85rem;color:#0a84ff;text-decoration:none}
</style></head><body>
<div class="card">
<h1>🍲 Sign in</h1>
<p class="sub">Access to the cookbook is protected. We'll email a one-time code.</p>
` + notice + `
<form method="post" action="/auth/send">
<input type="hidden" name="next" value="` + nextEsc + `">
<button type="submit">Email me a login code</button>
</form>
<div class="divider">then enter it</div>
<form method="post" action="/auth/verify">
<input type="hidden" name="next" value="` + nextEsc + `">
<label for="code">6-digit code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
  pattern="[0-9]*" maxlength="6" placeholder="123456" autofocus>
<button type="submit">Sign in</button>
</form>
<a class="home" href="/">← Back to home</a>
</div></body></html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

// maskEmail turns "crystal@stg.net" into "c****t@stg.net" for display, keeping
// the domain and the first/last local-part characters as a recognizability hint
// without printing the full address.
func maskEmail(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 {
		return addr
	}
	local, domain := addr[:at], addr[at:]
	if len(local) <= 2 {
		return string(local[0]) + "***" + domain
	}
	return string(local[0]) + strings.Repeat("*", len(local)-2) + string(local[len(local)-1]) + domain
}

// urlQueryEscape percent-escapes a value for use in a query string. Kept tiny
// and local to avoid a net/url import solely for this.
func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' || c == '_' || c == '.' || c == '~' ||
			('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
