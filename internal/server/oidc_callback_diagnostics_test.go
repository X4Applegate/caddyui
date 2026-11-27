// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #158: every way the OIDC callback can refuse a sign-in must leave a
// line in the server log saying why, and none of those lines may contain the
// token. These tests drive the real callback against a fake identity
// provider that signs genuine RS256 ID tokens, so go-oidc's verification runs
// exactly as it does in production and only the claims vary.

const (
	fakeIdPClientID    = "caddyui-test"
	fakeIdPAccessToken = "at-must-never-be-logged"
)

type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	nonce  string
	claims map[string]any // merged over the standard iss/aud/sub/exp/iat/nonce
	// rawClaims, if set, is spliced verbatim after the standard claims, for
	// payloads a map cannot express (duplicate keys in a set order).
	rawClaims string
	idToken   string // the last ID token issued
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, nonce: "nonce-" + oidcRandom()}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.srv.URL,
			"authorization_endpoint":                p.srv.URL + "/auth",
			"token_endpoint":                        p.srv.URL + "/token",
			"jwks_uri":                              p.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64(key.N.Bytes()),
			"e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		p.idToken = p.sign(t)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fakeIdPAccessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     p.idToken,
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) sign(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":   p.srv.URL,
		"aud":   fakeIdPClientID,
		"sub":   "subject-1234",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": p.nonce,
	}
	for k, v := range p.claims {
		claims[k] = v
	}
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	body := enc(claims)
	if p.rawClaims != "" {
		b, _ := json.Marshal(claims)
		b = append(append(b[:len(b)-1], ","+p.rawClaims...), '}')
		body = base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"}) + "." + body
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func oidcCallbackTestServer(t *testing.T, issuer string) *Server {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for k, v := range map[string]string{
		settingOIDCEnabled:      "1",
		settingOIDCIssuer:       issuer,
		settingOIDCClientID:     fakeIdPClientID,
		settingOIDCClientSecret: "client-secret",
		settingOIDCRedirectURL:  "https://caddyui.example.test/auth/oidc/callback",
	} {
		if err := models.SetSetting(conn, k, v); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{DB: conn}
}

// runOIDCCallback completes one callback with valid state and nonce and
// returns where it redirected and everything it logged.
func runOIDCCallback(t *testing.T, s *Server, p *fakeIdP) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	prev, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(prevFlags) })

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=auth-code&state=state-1", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: "state-1"})
	req.AddCookie(&http.Cookie{Name: oidcNonceCookie, Value: p.nonce})
	rec := httptest.NewRecorder()
	s.getOIDCCallback(rec, req)
	log.SetOutput(prev)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback: HTTP %d, want 303; log:\n%s", rec.Code, buf.String())
	}
	return rec.Header().Get("Location"), buf.String()
}

// assertNoTokenInLog fails if the ID token, any of its three JWT segments,
// or the access token appears in the log.
func assertNoTokenInLog(t *testing.T, p *fakeIdP, logged string) {
	t.Helper()
	if p.idToken == "" {
		t.Fatal("the fake provider never issued an ID token; the callback did not reach the token exchange")
	}
	if strings.Contains(logged, p.idToken) {
		t.Error("the raw ID token was written to the log")
	}
	for i, seg := range strings.Split(p.idToken, ".") {
		if len(seg) > 8 && strings.Contains(logged, seg) {
			t.Errorf("JWT segment %d of the ID token was written to the log", i)
		}
	}
	if strings.Contains(logged, fakeIdPAccessToken) {
		t.Error("the access token was written to the log")
	}
}

func TestOIDCCallbackStringEmailVerifiedIsRejectedAndDiagnosed(t *testing.T) {
	p := newFakeIdP(t)
	p.claims = map[string]any{"email": "user@example.com", "email_verified": "true", "name": "User"}
	s := oidcCallbackTestServer(t, p.srv.URL)
	if err := models.SetSetting(s.DB, settingOIDCAutoCreate, "1"); err != nil {
		t.Fatal(err)
	}

	loc, logged := runOIDCCallback(t, s, p)

	// Still strict: a string "true" is not a verified email.
	if loc != "/login?error=sso" {
		t.Errorf("redirect = %q, want /login?error=sso", loc)
	}
	if u, _ := models.GetUserByEmail(s.DB, "user@example.com"); u != nil {
		t.Error("an account was provisioned from a string-typed email_verified claim")
	}
	want := `oidc: rejecting sign-in: ID token claims could not be decoded: claim "email_verified" is a JSON string, but CaddyUI requires a JSON boolean`
	if !strings.Contains(logged, want) {
		t.Errorf("log does not name the malformed claim.\nwant substring: %s\ngot:\n%s", want, logged)
	}
	assertNoTokenInLog(t, p, logged)
}

func TestOIDCCallbackMissingEmailVerifiedIsRejectedAndDiagnosed(t *testing.T) {
	p := newFakeIdP(t)
	// What Microsoft Entra ID sends by default: an email, no email_verified.
	p.claims = map[string]any{"email": "user@example.com", "name": "User"}
	s := oidcCallbackTestServer(t, p.srv.URL)
	if _, err := models.CreateUser(s.DB, "user@example.com", "x", "User", models.RoleView); err != nil {
		t.Fatal(err)
	}

	loc, logged := runOIDCCallback(t, s, p)

	// An existing account does not exempt the identity from verification.
	if loc != "/login?error=sso_email" {
		t.Errorf("redirect = %q, want /login?error=sso_email", loc)
	}
	if !strings.Contains(logged, "the ID token has no email_verified claim") {
		t.Errorf("log does not say email_verified was absent:\n%s", logged)
	}
	assertNoTokenInLog(t, p, logged)
}

func TestOIDCCallbackFalseEmailVerifiedIsDistinguishedFromMissing(t *testing.T) {
	p := newFakeIdP(t)
	p.claims = map[string]any{"email": "user@example.com", "email_verified": false}
	s := oidcCallbackTestServer(t, p.srv.URL)

	loc, logged := runOIDCCallback(t, s, p)

	if loc != "/login?error=sso_email" {
		t.Errorf("redirect = %q, want /login?error=sso_email", loc)
	}
	if !strings.Contains(logged, "email_verified is false") || strings.Contains(logged, "no email_verified claim") {
		t.Errorf("log does not distinguish false from absent:\n%s", logged)
	}
	assertNoTokenInLog(t, p, logged)
}

func TestOIDCCallbackMissingEmailIsRejectedAndDiagnosed(t *testing.T) {
	p := newFakeIdP(t)
	p.claims = map[string]any{"email_verified": true}
	s := oidcCallbackTestServer(t, p.srv.URL)

	loc, logged := runOIDCCallback(t, s, p)

	if loc != "/login?error=sso_email" {
		t.Errorf("redirect = %q, want /login?error=sso_email", loc)
	}
	if !strings.Contains(logged, "the ID token has no email claim") {
		t.Errorf("log does not say the email claim was absent:\n%s", logged)
	}
	assertNoTokenInLog(t, p, logged)
}

// The harness itself has to be able to succeed, or every rejection above
// could be an artefact of a broken fake provider.
func TestOIDCCallbackVerifiedEmailStillSignsIn(t *testing.T) {
	p := newFakeIdP(t)
	p.claims = map[string]any{"email": "user@example.com", "email_verified": true}
	s := oidcCallbackTestServer(t, p.srv.URL)
	if _, err := models.CreateUser(s.DB, "user@example.com", "x", "User", models.RoleView); err != nil {
		t.Fatal(err)
	}

	loc, logged := runOIDCCallback(t, s, p)

	if loc != "/" {
		t.Errorf("redirect = %q, want / (signed in); log:\n%s", loc, logged)
	}
	assertNoTokenInLog(t, p, logged)
}

// Review finding on #158: the logged reason used exact-key lookups while the
// decision uses encoding/json's case-insensitive, last-key-wins matching, so a
// token could log an empty reason or claim the email was missing while
// printing it. Both tokens from that review, end to end.
func TestOIDCCallbackRejectionReasonMatchesTheDecision(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
	}{
		{"duplicate email_verified, last false", nil},
		{"upper-case EMAIL", map[string]any{"EMAIL": "a@x.test", "email_verified": false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newFakeIdP(t)
			p.claims = c.claims
			if c.claims == nil {
				// A Go map cannot hold both keys in order; splice the raw
				// JSON so "Email_Verified" really comes last.
				p.rawClaims = `"email":"a@x.test","email_verified":true,"Email_Verified":false`
			}
			s := oidcCallbackTestServer(t, p.srv.URL)

			loc, logged := runOIDCCallback(t, s, p)

			if loc != "/login?error=sso_email" {
				t.Errorf("redirect = %q, want /login?error=sso_email", loc)
			}
			if !strings.Contains(logged, `("a@x.test" verified=false): email_verified is false; every SSO sign-in`) {
				t.Errorf("logged reason does not match the decision:\n%s", logged)
			}
			if strings.Contains(logged, "no email claim") || strings.Contains(logged, "): ; ") {
				t.Errorf("logged reason contradicts the decision:\n%s", logged)
			}
			assertNoTokenInLog(t, p, logged)
		})
	}
}

// captureOIDCCallback runs the callback for an arbitrary request and returns
// the response and everything logged.
func captureOIDCCallback(t *testing.T, s *Server, req *http.Request) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	rec := httptest.NewRecorder()
	s.getOIDCCallback(rec, req)
	return rec, buf.String()
}

func TestOIDCCallbackWhenSSOIsOffLogsWhy(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn}

	rec, logged := captureOIDCCallback(t, s, httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=x&state=y", nil))

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("got %d %q, want 303 /login", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(logged, "oidc: callback received but SSO is disabled or not fully configured") {
		t.Errorf("no log line for a callback with SSO off:\n%q", logged)
	}
}

// Anyone can request the callback URL, so its error parameter is attacker
// text. A newline in it must not start a second, forged log line.
func TestOIDCCallbackProviderErrorCannotForgeLogLines(t *testing.T) {
	s := oidcCallbackTestServer(t, "https://idp.example.test")
	req := httptest.NewRequest(http.MethodGet,
		"/auth/oidc/callback?error=access_denied%0A2026/01/01%2000:00:00%20FORGED%20admin%20login%0D%0Aagain", nil)

	rec, logged := captureOIDCCallback(t, s, req)

	if rec.Header().Get("Location") != "/login?error=sso_denied" {
		t.Errorf("redirect = %q, want /login?error=sso_denied", rec.Header().Get("Location"))
	}
	if n := strings.Count(logged, "\n"); n != 1 {
		t.Errorf("one request produced %d log lines, want 1:\n%s", n, logged)
	}
	if strings.ContainsAny(strings.TrimSuffix(logged, "\n"), "\r\n") {
		t.Errorf("raw CR/LF from the query reached the log:\n%q", logged)
	}
	if !strings.Contains(logged, `oidc: provider returned error: "access_denied\n2026/01/01 00:00:00 FORGED admin login\r\nagain"`) {
		t.Errorf("error parameter not logged in escaped form:\n%s", logged)
	}
}
