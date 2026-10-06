// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Security regression tests (v2.57.1). They drive the REAL router with four
// accounts — an admin, two customer-level users (alice, bob) and a read-only
// viewer — against a fake Caddy admin API, so they exercise the actual
// middleware stacking rather than individual handlers.
//
// Each test asserts the FIXED behaviour, so it fails on the vulnerable code.

const (
	secKeyMaterial = "SEC_PRIVATE_KEY_MATERIAL"
	secDNSToken    = "SEC_CF_DNS_TOKEN"
)

type secEnv struct {
	s      *Server
	h      http.Handler
	db     *sql.DB
	ids    map[string]int64
	tokens map[string]string
	mu     sync.Mutex
	reqs   []string // "METHOD path :: body" seen by the fake Caddy admin API
}

func newSecEnv(t *testing.T) *secEnv {
	t.Helper()
	e := &secEnv{ids: map[string]int64{}, tokens: map[string]string{}}
	dbPath := filepath.Join(t.TempDir(), "caddyui.db")
	conn, err := appdb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	e.db = conn

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.reqs = append(e.reqs, r.Method+" "+r.URL.RequestURI()+" :: "+string(b))
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config"):
			fmt.Fprintf(w, `{"apps":{"tls":{"certificates":{"load_pem":[{"certificate":"CERT","key":"%s"}]},"automation":{"policies":[{"issuers":[{"module":"acme","challenges":{"dns":{"provider":{"name":"cloudflare","api_token":"%s"}}}}]}]}},"http":{"servers":{"srv0":{"routes":[]}}}}}`, secKeyMaterial, secDNSToken)
		case r.URL.Path == "/adapt":
			fmt.Fprint(w, `{"result":{"apps":{"http":{"servers":{"srv0":{"routes":[]}}}}}}`)
		default:
			fmt.Fprint(w, `{}`)
		}
	}))
	t.Cleanup(fake.Close)

	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: fake.URL, Type: models.CaddyServerTypeManaged}); err != nil {
		t.Fatal(err)
	}
	tpls, err := parseTemplates(os.DirFS("../../web/templates"))
	if err != nil {
		t.Fatal(err)
	}
	e.s = &Server{DB: conn, Caddy: caddy.New(fake.URL, "", ""), Templates: tpls, Static: os.DirFS("../../web/static"), DBPath: dbPath,
		healthFailures: map[int64]int{}, appHealth: map[int64]appHealthEntry{}, runtimeLogTimers: map[int64]*time.Timer{}}
	e.h = e.s.Routes()

	hash, _ := auth.HashPassword("password-123")
	for _, u := range []struct{ name, role string }{{"admin", models.RoleAdmin}, {"alice", models.RoleUser}, {"bob", models.RoleUser}, {"viewer", models.RoleView}} {
		id, err := models.CreateUser(conn, u.name+"@t", hash, u.name, u.role)
		if err != nil {
			t.Fatal(err)
		}
		e.ids[u.name] = id
		tok, _, err := auth.CreateSession(conn, id)
		if err != nil {
			t.Fatal(err)
		}
		e.tokens[u.name] = tok
	}
	return e
}

// do performs a request as one of the fixture accounts through the real router.
func (e *secEnv) do(t *testing.T, who, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "172.18.0.9:5555"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if tok, ok := e.tokens[who]; ok {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: tok})
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", e.s.csrfTokenFor(tok))
		}
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// bearer performs a request authenticated with an API token.
func (e *secEnv) bearer(t *testing.T, raw, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "172.18.0.9:5555"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// newToken stores an API token of the given scope owned by the admin and
// returns its raw value.
func (e *secEnv) newToken(t *testing.T, name, scope string) string {
	t.Helper()
	raw := "cadu_" + name + "_test_token"
	sum := sha256.Sum256([]byte(raw))
	if _, err := models.CreateAPIToken(e.db, e.ids["admin"], name, hex.EncodeToString(sum[:]), scope, nil); err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *secEnv) bobHost(t *testing.T) int64 {
	t.Helper()
	id, err := models.CreateProxyHost(e.db, 1, e.ids["bob"], &models.ProxyHost{
		Domains: "bob.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080, Enabled: true,
		HTTPBasicAuthUpstream: "svc:UPSTREAM_BASIC_SECRET", APIKeyValue: "BOB_API_KEY",
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// --- admin-only surfaces -------------------------------------------------

// The database, the live Caddy config and the snapshots contain every stored
// credential, certificate private keys and DNS API tokens. Only admins may reach
// them. Before v2.57.1 /backup sat in the requireWrite group (any non-viewer),
// and /caddy-config, /import and the snapshot download were open to every role.
func TestSecurityConfigAndBackupSurfacesAreAdminOnly(t *testing.T) {
	e := newSecEnv(t)
	if _, err := models.CreateSnapshot(e.db, 1, models.SnapshotSourceManual, "s", `{"k":"`+secKeyMaterial+`"}`); err != nil {
		t.Fatal(err)
	}
	routes := []struct{ method, path string }{
		{http.MethodGet, "/backup"},
		{http.MethodGet, "/caddy-config"},
		{http.MethodGet, "/import"},
		{http.MethodPost, "/import"},
		{http.MethodGet, "/snapshots"},
		{http.MethodGet, "/snapshots/1/download"},
		{http.MethodGet, "/snapshots/1/diff"},
		{http.MethodPost, "/snapshots"},
		{http.MethodPost, "/snapshots/upload"},
		{http.MethodPost, "/snapshots/auto"},
		{http.MethodPost, "/snapshots/1/restore"},
		{http.MethodPost, "/snapshots/1/delete"},
		{http.MethodGet, "/certificates/import/porkbun"},
		{http.MethodPost, "/certificates/import/porkbun"},
		{http.MethodGet, "/api/notifier-status"},
	}
	for _, rt := range routes {
		for _, who := range []string{"alice", "viewer"} {
			var form url.Values
			if rt.method == http.MethodPost {
				form = url.Values{}
			}
			rec := e.do(t, who, rt.method, rt.path, form)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s -> %d, want 403", who, rt.method, rt.path, rec.Code)
			}
			if strings.Contains(rec.Body.String(), secKeyMaterial) || strings.Contains(rec.Body.String(), secDNSToken) {
				t.Errorf("%s %s %s leaked secret material to a non-admin", who, rt.method, rt.path)
			}
		}
	}
	// The admin still gets them (not forbidden; the page itself may need Caddy).
	for _, p := range []string{"/backup", "/caddy-config", "/snapshots"} {
		if rec := e.do(t, "admin", http.MethodGet, p, nil); rec.Code == http.StatusForbidden {
			t.Errorf("admin GET %s -> 403, must still be allowed", p)
		}
	}
	// The navigation no longer advertises pages a non-admin cannot open.
	body := e.do(t, "alice", http.MethodGet, "/proxy-hosts", nil).Body.String()
	for _, link := range []string{`href="/caddy-config"`, `href="/snapshots"`, `href="/import"`} {
		if strings.Contains(body, link) {
			t.Errorf("a non-admin's navigation still links to %s", link)
		}
	}
}

// --- per-row ownership ---------------------------------------------------

// Every single-host handler checks ownership; the export, maintenance, health
// and expectation endpoints did not, so any account could read another tenant's
// upstream credentials or change their host by ID.
func TestSecuritySingleHostHandlersEnforceOwnership(t *testing.T) {
	e := newSecEnv(t)
	id := e.bobHost(t)
	base := fmt.Sprintf("/proxy-hosts/%d", id)

	for _, c := range []struct{ method, suffix string }{
		{http.MethodGet, "/export.json"},
		{http.MethodGet, "/export.caddyfile"},
		{http.MethodGet, "/health"},
		{http.MethodPost, "/maintenance"},
		{http.MethodPost, "/expectations/run"},
	} {
		for _, who := range []string{"alice", "viewer"} {
			var form url.Values
			if c.method == http.MethodPost {
				form = url.Values{}
			}
			rec := e.do(t, who, c.method, base+c.suffix, form)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s -> %d, want 403", who, c.method, base+c.suffix, rec.Code)
			}
			body := rec.Body.String()
			if strings.Contains(body, "UPSTREAM_BASIC_SECRET") || strings.Contains(body, "BOB_API_KEY") || strings.Contains(body, "bob.example.test") {
				t.Errorf("%s %s %s leaked another tenant's host data", who, c.method, base+c.suffix)
			}
		}
	}
	if ph, _ := models.GetProxyHost(e.db, id); ph.MaintenanceMode {
		t.Error("another tenant's host was put into maintenance mode")
	}

	// The owner and the admin still can.
	for _, who := range []string{"bob", "admin"} {
		if rec := e.do(t, who, http.MethodGet, base+"/export.json", nil); rec.Code != http.StatusOK {
			t.Errorf("%s export.json -> %d, want 200", who, rec.Code)
		}
	}
}

func TestSecurityCertificateInspectIsScopedToVisibleCertificates(t *testing.T) {
	e := newSecEnv(t)
	cid, err := models.CreateCertificate(e.db, 1, e.ids["bob"], &models.Certificate{
		Name: "BOB-PRIVATE-CERT", Domains: "bob-secret.example.test", Source: models.CertSourcePath,
		CertPath: "/certs/bob.crt", KeyPath: "/certs/bob.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/certificates/%d/inspect", cid)
	rec := e.do(t, "alice", http.MethodGet, path, nil)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "BOB-PRIVATE-CERT") || strings.Contains(rec.Body.String(), "/certs/bob.key") {
		t.Errorf("alice inspecting bob's certificate -> %d (leaked=%v), want 404", rec.Code, strings.Contains(rec.Body.String(), "BOB-PRIVATE-CERT"))
	}
	if rec := e.do(t, "bob", http.MethodGet, path, nil); rec.Code != http.StatusOK {
		t.Errorf("owner inspecting their own certificate -> %d, want 200", rec.Code)
	}
}

// --- REST API certificate list -------------------------------------------

// The list endpoint returned key_pem for every global (admin-owned)
// certificate to every role, including read-only tokens, while the single-row
// GET correctly refused. Secrets now follow canManageOwned in both.
func TestSecurityAPICertificateListNeverReturnsKeysTheCallerCannotManage(t *testing.T) {
	e := newSecEnv(t)
	if _, err := models.CreateCertificate(e.db, 1, 0, &models.Certificate{
		Name: "wildcard", Domains: "*.example.test", Source: models.CertSourcePEM,
		CertPEM: "CERTPEM", KeyPEM: "-----BEGIN PRIVATE KEY-----ADMIN_GLOBAL_KEY-----END PRIVATE KEY-----",
		KeyPath: "/secret/path.key",
	}); err != nil {
		t.Fatal(err)
	}
	ro := e.newToken(t, "readonly", models.TokenScopeReadOnly)

	check := func(label string, rec *httptest.ResponseRecorder, wantKey bool) {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("%s -> %d: %s", label, rec.Code, rec.Body.String())
		}
		has := strings.Contains(rec.Body.String(), "ADMIN_GLOBAL_KEY") || strings.Contains(rec.Body.String(), "/secret/path.key")
		if has != wantKey {
			t.Errorf("%s: key material present=%v, want %v", label, has, wantKey)
		}
	}
	check("admin list", e.do(t, "admin", http.MethodGet, "/api/v1/certificates", nil), true)
	check("alice list", e.do(t, "alice", http.MethodGet, "/api/v1/certificates", nil), false)
	check("viewer list", e.do(t, "viewer", http.MethodGet, "/api/v1/certificates", nil), false)
	check("read-only token list", e.bearer(t, ro, http.MethodGet, "/api/v1/certificates", nil), false)
	// The rest of the row is still listed: only the secrets are withheld.
	if body := e.do(t, "alice", http.MethodGet, "/api/v1/certificates", nil).Body.String(); !strings.Contains(body, "wildcard") {
		t.Error("the certificate itself should still be listed for a non-admin")
	}
}

// --- API token scope -----------------------------------------------------

// proxy_write was only enforced inside the requireWrite route group, so a
// leaked proxy-host CI token could mint a full-scope token, create an admin and
// change settings through routes outside that group.
func TestSecurityAPITokenScopeIsEnforcedOnEveryRoute(t *testing.T) {
	e := newSecEnv(t)
	pw := e.newToken(t, "proxywrite", models.TokenScopeProxyWrite)
	ro := e.newToken(t, "readonly", models.TokenScopeReadOnly)
	full := e.newToken(t, "full", models.TokenScopeFull)

	deny := func(label, raw, method, path string, form url.Values) {
		t.Helper()
		if rec := e.bearer(t, raw, method, path, form); rec.Code != http.StatusForbidden {
			t.Errorf("%s -> %d, want 403", label, rec.Code)
		}
	}
	deny("proxy_write token creating an API token", pw, http.MethodPost, "/api-tokens", url.Values{"name": {"x"}, "scopes": {"full"}})
	deny("proxy_write token creating a user", pw, http.MethodPost, "/users", url.Values{"email": {"evil@t"}, "name": {"evil"}, "password": {"password-xyz"}, "password_confirm": {"password-xyz"}, "role": {"admin"}})
	deny("proxy_write token changing settings", pw, http.MethodPost, "/settings", url.Values{"site_title": {"pwned"}})
	deny("proxy_write token on a non-API write path", pw, http.MethodPost, "/proxy-hosts", url.Values{})
	deny("read_only token creating an API token", ro, http.MethodPost, "/api-tokens", url.Values{"name": {"x"}})
	// Even a full-scope token cannot manage tokens: that needs a browser session.
	deny("full token creating an API token", full, http.MethodPost, "/api-tokens", url.Values{"name": {"x"}, "scopes": {"full"}})
	deny("full token revoking an API token", full, http.MethodPost, "/api-tokens/1/revoke", url.Values{})

	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM api_tokens`).Scan(&n)
	if n != 3 {
		t.Errorf("api_tokens rows = %d, want the 3 fixtures only", n)
	}
	if u, _ := models.GetUserByEmail(e.db, "evil@t"); u != nil {
		t.Error("a proxy_write token created a user")
	}

	// What the scopes are for still works.
	if rec := e.bearer(t, pw, http.MethodGet, "/api/v1/proxy-hosts", nil); rec.Code != http.StatusOK {
		t.Errorf("proxy_write token listing proxy hosts -> %d, want 200", rec.Code)
	}
	if rec := e.bearer(t, ro, http.MethodGet, "/api/v1/proxy-hosts", nil); rec.Code != http.StatusOK {
		t.Errorf("read_only token listing proxy hosts -> %d, want 200", rec.Code)
	}
}

// --- sign-in brute force --------------------------------------------------

func (e *secEnv) postForm(t *testing.T, path, remoteAddr string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// The lockout counted a column the failure row never wrote to, so
// max_login_attempts had never locked anything out.
func TestSecurityLoginLockoutActuallyLocksOut(t *testing.T) {
	e := newSecEnv(t)
	if err := models.SetSetting(e.db, settingMaxLoginAttempts, "3"); err != nil {
		t.Fatal(err)
	}
	wrong := url.Values{"email": {"admin@t"}, "password": {"wrong"}}
	locked := func(addr string) bool {
		return strings.Contains(e.postForm(t, "/login", addr, wrong).Body.String(), "Too many failed")
	}
	for i := 1; i <= 3; i++ {
		if locked("203.0.113.9:4444") {
			t.Fatalf("locked after only %d failure(s); the limit is 3", i-1)
		}
	}
	if !locked("203.0.113.9:4444") {
		t.Fatal("the 4th attempt from the same address was not locked out")
	}
	// Another address is unaffected — the lockout is per client, not global.
	if locked("203.0.113.10:4444") {
		t.Fatal("a different client address was locked out too")
	}
	// Even the right password is refused while locked out.
	good := url.Values{"email": {"admin@t"}, "password": {"password-123"}}
	if !strings.Contains(e.postForm(t, "/login", "203.0.113.9:4444", good).Body.String(), "Too many failed") {
		t.Fatal("the correct password was accepted during a lockout")
	}
}

// Wrong second-factor codes were retried without limit on one pending token,
// and a fresh password login reset nothing, so a known password bought
// unlimited guesses at a 6-digit code.
func TestSecurityTOTPGuessesAreLimited(t *testing.T) {
	e := newSecEnv(t)
	const secret = "JBSWY3DPEHPK3PXP"
	if err := models.SetUserTOTP(e.db, e.ids["admin"], secret, true); err != nil {
		t.Fatal(err)
	}
	login := func() string {
		rec := e.postForm(t, "/login", "203.0.113.50:1", url.Values{"email": {"admin@t"}, "password": {"password-123"}})
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login/totp?t=") {
			return "" // refused
		}
		return strings.TrimPrefix(rec.Header().Get("Location"), "/login/totp?t=")
	}
	guess := func(tok, code string) string {
		return e.postForm(t, "/login/totp", "203.0.113.50:1", url.Values{"token": {tok}, "code": {code}}).Body.String()
	}

	// One token allows a handful of guesses, then dies.
	tok := login()
	if tok == "" {
		t.Fatal("first-factor login should hand out a TOTP step")
	}
	for i := 1; i < maxTOTPAttemptsPerToken; i++ {
		if body := guess(tok, "000000"); !strings.Contains(body, "Invalid code") {
			t.Fatalf("guess %d: want 'Invalid code', got %q", i, excerpt(body, "code"))
		}
	}
	if body := guess(tok, "000000"); !strings.Contains(body, "Too many incorrect codes") {
		t.Fatalf("guess %d should exhaust the token, got %q", maxTOTPAttemptsPerToken, excerpt(body, "Too many"))
	}
	if body := guess(tok, "000000"); !strings.Contains(body, "Session expired") {
		t.Fatal("an exhausted token must not be usable again")
	}

	// A fresh password login does not reset the budget: after enough failures
	// the account itself is locked out of the second-factor step.
	for round := 0; round < 3 && login() != ""; round++ {
		t2 := login()
		for i := 0; t2 != "" && i < maxTOTPAttemptsPerToken; i++ {
			guess(t2, "000000")
		}
	}
	if login() != "" {
		t.Fatal("an account with many failed second-factor codes can still start a new TOTP step")
	}
}

// --- sessions after a credential change ----------------------------------

// A stolen session used to survive the password reset meant to evict it.
func TestSecurityPasswordChangeSignsOtherSessionsOut(t *testing.T) {
	e := newSecEnv(t)
	// A second device for alice.
	otherTok, _, err := auth.CreateSession(e.db, e.ids["alice"])
	if err != nil {
		t.Fatal(err)
	}
	alive := func(tok string) bool {
		u, _ := auth.UserFromSession(e.db, tok)
		return u != nil
	}
	if !alive(otherTok) || !alive(e.tokens["alice"]) {
		t.Fatal("setup: both of alice's sessions should be valid")
	}

	// Self-service change from the browser holding e.tokens["alice"].
	rec := e.do(t, "alice", http.MethodPost, "/profile", url.Values{
		"action": {"change_password"}, "current_password": {"password-123"},
		"new_password": {"brand-new-pass-1"}, "confirm_password": {"brand-new-pass-1"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("profile change_password -> %d", rec.Code)
	}
	if alive(otherTok) {
		t.Error("another device's session survived the password change")
	}
	if !alive(e.tokens["alice"]) {
		t.Error("the browser that changed the password was signed out too")
	}

	// A reset/admin-initiated change (models.UpdateUserPassword) signs out everywhere.
	h, _ := auth.HashPassword("another-pass-123")
	if err := models.UpdateUserPassword(e.db, e.ids["alice"], h); err != nil {
		t.Fatal(err)
	}
	if alive(e.tokens["alice"]) {
		t.Error("a password reset left the account's session valid")
	}
	// Other accounts are untouched.
	if !alive(e.tokens["bob"]) {
		t.Error("an unrelated account was signed out")
	}
}

// --- emailed links and first-run setup -----------------------------------

// POST /forgot-password is unauthenticated, and the emailed link used to be
// built from the request's Host header: a forged Host got a working reset token
// mailed to the victim, pointing at the attacker.
func TestSecurityEmailedLinksIgnoreTheRequestHostWhenConfigured(t *testing.T) {
	e := newSecEnv(t)
	req := func(host string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/forgot-password", nil)
		r.Host = host
		r.RemoteAddr = "203.0.113.200:1"
		return r
	}

	// Configured via the environment: the Host header is irrelevant.
	t.Setenv("CADDYUI_PUBLIC_URL", "https://caddyui.example.com/")
	if got := e.s.publicBaseURL(req("evil.attacker.test")); got != "https://caddyui.example.com" {
		t.Errorf("with CADDYUI_PUBLIC_URL set, base = %q, want https://caddyui.example.com", got)
	}

	// Not set: fall back to the configured OIDC redirect URL's origin.
	t.Setenv("CADDYUI_PUBLIC_URL", "")
	if err := models.SetSetting(e.db, settingOIDCRedirectURL, "https://sso.example.com/auth/oidc/callback"); err != nil {
		t.Fatal(err)
	}
	if got := e.s.publicBaseURL(req("evil.attacker.test")); got != "https://sso.example.com" {
		t.Errorf("with an OIDC redirect URL, base = %q, want https://sso.example.com", got)
	}

	// Nothing configured: the request is the only source (unchanged), but a
	// forwarded scheme is trusted only from a trusted proxy.
	if err := models.SetSetting(e.db, settingOIDCRedirectURL, ""); err != nil {
		t.Fatal(err)
	}
	direct := req("ui.example.com")
	direct.Header.Set("X-Forwarded-Proto", "https") // from a public peer: ignored
	if got := e.s.publicBaseURL(direct); got != "http://ui.example.com" {
		t.Errorf("untrusted X-Forwarded-Proto was honoured: %q", got)
	}
	viaProxy := req("ui.example.com")
	viaProxy.RemoteAddr = "172.18.0.9:5555" // private peer = trusted proxy
	viaProxy.Header.Set("X-Forwarded-Proto", "https")
	if got := e.s.publicBaseURL(viaProxy); got != "https://ui.example.com" {
		t.Errorf("proxied https request base = %q, want https://ui.example.com", got)
	}

	for in, want := range map[string]string{
		"https://a.example.com:8443/some/path?x=1": "https://a.example.com:8443",
		"http://a.example.com":                     "http://a.example.com",
		"ftp://a.example.com":                      "",
		"https://user:pw@a.example.com":            "",
		"//a.example.com":                          "",
		"not a url":                                "",
		"":                                         "",
	} {
		if got := cleanBaseURL(in); got != want {
			t.Errorf("cleanBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func newEmptySetupServer(t *testing.T) *Server {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newRenderingTestServer(t, conn)
}

func setupRequest(email, pw string) *http.Request {
	return postForm0("/setup", url.Values{"email": {email}, "name": {"x"}, "password": {pw}, "password_confirm": {pw}})
}

func postForm0(path string, v url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestSecuritySetupEnforcesPasswordMinimumServerSide(t *testing.T) {
	s := newEmptySetupServer(t)
	rec := httptest.NewRecorder()
	s.postSetup(rec, setupRequest("admin@example.com", "short"))
	if n, _ := models.CountUsers(s.DB); n != 0 {
		t.Fatalf("a 5-character password created %d user(s); the minimum is 8", n)
	}
	if !strings.Contains(rec.Body.String(), "at least 8 characters") {
		t.Errorf("the form should explain the minimum, got %q", excerpt(rec.Body.String(), "characters"))
	}
	rec = httptest.NewRecorder()
	s.postSetup(rec, setupRequest("admin@example.com", "long-enough-pass"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a valid setup -> %d, want 303", rec.Code)
	}
	if n, _ := models.CountUsers(s.DB); n != 1 {
		t.Fatalf("users after a valid setup = %d, want 1", n)
	}
}

// Two simultaneous first-run requests used to be able to both see zero users
// and both create an admin.
func TestSecuritySetupCreatesExactlyOneAdminUnderConcurrency(t *testing.T) {
	s := newEmptySetupServer(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.postSetup(httptest.NewRecorder(), setupRequest(fmt.Sprintf("admin%d@example.com", i), "long-enough-pass"))
		}(i)
	}
	wg.Wait()
	if n, _ := models.CountUsers(s.DB); n != 1 {
		t.Fatalf("%d concurrent setups created %d admins, want exactly 1", 12, n)
	}
}

// attachSession adds a fixture account's session cookie (and CSRF header for
// writes) to a hand-built request.
func (e *secEnv) attachSession(req *http.Request, who string) {
	req.RemoteAddr = "172.18.0.9:5555"
	tok := e.tokens[who]
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: tok})
	if req.Method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", e.s.csrfTokenFor(tok))
	}
}

// --- sync serialization ---------------------------------------------------

// syncCaddy points the shared s.Caddy at one server for its whole duration, so
// concurrent syncs of different servers crossed over: a reproduction pushed one
// server's routes (with their certificate keys and basic-auth hashes) to
// another server in most iterations.
func TestSecurityConcurrentSyncsNeverPushOneServersRoutesToAnother(t *testing.T) {
	e := newSecEnv(t)
	var mu sync.Mutex
	crossA, crossB := 0, 0
	mk := func(other string, cross *int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodGet && strings.Contains(string(b), other) {
				mu.Lock()
				*cross++
				mu.Unlock()
			}
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config") {
				fmt.Fprint(w, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
				return
			}
			fmt.Fprint(w, `{}`)
		}))
	}
	A := mk("b-only.example.test", &crossA)
	B := mk("a-only.example.test", &crossB)
	defer A.Close()
	defer B.Close()
	if _, err := e.db.Exec(`UPDATE caddy_servers SET admin_url=? WHERE id=1`, A.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateCaddyServer(e.db, &models.CaddyServer{Name: "edge", AdminURL: B.URL, Type: models.CaddyServerTypeManaged}); err != nil {
		t.Fatal(err)
	}
	for _, h := range []struct {
		server int64
		domain string
	}{{1, "a-only.example.test"}, {2, "b-only.example.test"}} {
		if _, err := models.CreateProxyHost(e.db, h.server, 0, &models.ProxyHost{Domains: h.domain, ForwardScheme: "http", ForwardHost: "10.0.0.1", ForwardPort: 80, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = e.s.syncCaddy(1, false) }()
		go func() { defer wg.Done(); _ = e.s.syncCaddy(2, false) }()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if crossA != 0 || crossB != 0 {
		t.Fatalf("cross-server config pushes: B's routes reached server A %d times, A's routes reached server B %d times (want 0/0)", crossA, crossB)
	}
}

// --- fleet copies --------------------------------------------------------

// A copy of a customer's host used to adopt ANY target row with the same
// domains, overwrite it and reset its owner: one customer could take over
// another's host on a second server just by saving a host with that domain and
// ticking "Also deploy to".
func TestSecurityFleetCopyOfATenantHostNeverAdoptsAnotherOwnersRow(t *testing.T) {
	e := newSecEnv(t)
	var adminURL string
	_ = e.db.QueryRow(`SELECT admin_url FROM caddy_servers WHERE id=1`).Scan(&adminURL)
	if _, err := models.CreateCaddyServer(e.db, &models.CaddyServer{Name: "edge", AdminURL: adminURL, Type: models.CaddyServerTypeManaged}); err != nil {
		t.Fatal(err)
	}
	victim, err := models.CreateProxyHost(e.db, 2, e.ids["bob"], &models.ProxyHost{
		Domains: "victim.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	adminHost, err := models.CreateProxyHost(e.db, 2, 0, &models.ProxyHost{
		Domains: "admin-site.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.6", ForwardPort: 9090, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	for _, domain := range []string{"victim.example.test", "admin-site.example.test"} {
		e.do(t, "alice", http.MethodPost, "/proxy-hosts", url.Values{
			"domains": {domain}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.99"},
			"forward_port": {"80"}, "enabled": {"on"}, "deploy_to": {"2"}})
	}

	check := func(id int64, wantHost string, wantOwner sql.NullInt64) {
		t.Helper()
		var fh string
		var owner sql.NullInt64
		if err := e.db.QueryRow(`SELECT forward_host, owner_id FROM proxy_hosts WHERE id=?`, id).Scan(&fh, &owner); err != nil {
			t.Fatal(err)
		}
		if fh != wantHost || owner != wantOwner {
			t.Errorf("host %d on the target is now forward_host=%q owner=%v, want %q owner=%v — another account's row was overwritten", id, fh, owner, wantHost, wantOwner)
		}
	}
	check(victim, "10.0.0.5", sql.NullInt64{Int64: e.ids["bob"], Valid: true})
	check(adminHost, "10.0.0.6", sql.NullInt64{})

	// An admin-owned source keeps today's behaviour: it adopts and updates the
	// same-domain row on the target.
	srcID, err := models.CreateProxyHost(e.db, 1, 0, &models.ProxyHost{
		Domains: "admin-site.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.77", ForwardPort: 9090, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	src, _ := models.GetProxyHost(e.db, srcID)
	e.s.crossDeployProxyHost("admin@t", 1, src, []int64{2})
	check(adminHost, "10.0.0.77", sql.NullInt64{})
}

// Certificate export writes a private key to a directory of the requester's
// choosing and source push copies a domain's key out of Caddy's storage to
// other servers; both act with CaddyUI's authority, so they are admin-only.
func TestSecurityCertificateExportAndFleetPushAreAdminOnly(t *testing.T) {
	e := newSecEnv(t)
	managed := func(extra url.Values) url.Values {
		f := url.Values{"name": {"wild"}, "domains": {"*.victim.example.test"}, "source": {"managed"},
			"dns_provider": {"cloudflare"}}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	for label, extra := range map[string]url.Values{
		"export to a directory": {"export_dir": {"/data"}, "export_cert_file": {"c.pem"}, "export_key_file": {"caddyui.db"}},
		"source push":           {"fleet_distribution_mode": {models.CertFleetDistributionSourcePush}, "deploy_to": {"2"}},
	} {
		rec := e.do(t, "alice", http.MethodPost, "/certificates", managed(extra))
		if rec.Code == http.StatusSeeOther || !strings.Contains(rec.Body.String(), "admin-only") {
			t.Errorf("alice: %s -> %d, want a refusal saying it is admin-only (got %q)", label, rec.Code, excerpt(rec.Body.String(), "admin"))
		}
	}
	if rows, _ := models.ListCertificates(e.db, 1); len(rows) != 0 {
		t.Errorf("%d certificate(s) were stored by the refused requests", len(rows))
	}
	// Copying a certificate to other servers is ignored for a non-admin.
	r := httptest.NewRequest(http.MethodPost, "/certificates", strings.NewReader(url.Values{"deploy_to": {"2"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	if got := e.s.certificateDeployTargets(r); len(got) != 0 {
		t.Errorf("a non-admin's certificate deploy targets = %v, want none", got)
	}
}

// --- hostname hijack and imports -----------------------------------------

func (e *secEnv) json(t *testing.T, who, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	e.attachSession(req, who)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// The UI refuses a domain another host or redirect already holds; the REST API
// did not. Caddy keeps the first matching route and the newest row sorts first,
// so a duplicate silently took over the existing host's traffic.
func TestSecurityRESTAPIRefusesDuplicateDomains(t *testing.T) {
	e := newSecEnv(t)
	e.bobHost(t) // bob.example.test

	dup := map[string]any{"domains": "bob.example.test", "forward_scheme": "http", "forward_host": "203.0.113.9", "forward_port": 80, "enabled": true}
	if rec := e.json(t, "alice", http.MethodPost, "/api/v1/proxy-hosts", dup); rec.Code != http.StatusConflict {
		t.Errorf("duplicate proxy host via REST -> %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if rec := e.json(t, "alice", http.MethodPost, "/api/v1/redirection-hosts", map[string]any{
		"domains": "bob.example.test", "forward_domain": "evil.example.test", "enabled": true}); rec.Code != http.StatusConflict {
		t.Errorf("duplicate redirection via REST -> %d, want 409: %s", rec.Code, rec.Body.String())
	}

	// A different domain is fine, and editing one's own host onto a taken
	// domain is refused.
	ok := map[string]any{"domains": "alice.example.test", "forward_scheme": "http", "forward_host": "203.0.113.9", "forward_port": 80, "enabled": true}
	rec := e.json(t, "alice", http.MethodPost, "/api/v1/proxy-hosts", ok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("a unique domain via REST -> %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	rec = e.json(t, "alice", http.MethodPut, fmt.Sprintf("/api/v1/proxy-hosts/%d", created.ID), map[string]any{"domains": "bob.example.test"})
	if rec.Code != http.StatusConflict {
		t.Errorf("editing onto a taken domain via REST -> %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

func multipartUpload(t *testing.T, field, content string) (*strings.Reader, string) {
	t.Helper()
	const boundary = "----secboundary"
	body := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + field + "\"; filename=\"host.json\"\r\nContent-Type: application/json\r\n\r\n" + content + "\r\n--" + boundary + "--\r\n"
	return strings.NewReader(body), "multipart/form-data; boundary=" + boundary
}

// An imported file is attacker-controlled. A DNS record ID in it made a later
// delete of the host delete THAT record at the DNS provider using the admin's
// credentials; a duplicate domain hijacked another host.
func TestSecurityProxyHostImportDropsRuntimeStateAndRefusesDuplicates(t *testing.T) {
	e := newSecEnv(t)
	e.bobHost(t)
	upload := func(who, content string) *httptest.ResponseRecorder {
		body, ct := multipartUpload(t, "config_file", content)
		req := httptest.NewRequest(http.MethodPost, "/proxy-hosts/import", body)
		req.Header.Set("Content-Type", ct)
		e.attachSession(req, who)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}

	if rec := upload("alice", `{"Domains":"bob.example.test","ForwardScheme":"http","ForwardHost":"203.0.113.9","ForwardPort":80}`); rec.Code != http.StatusConflict {
		t.Errorf("importing a host onto a taken domain -> %d, want 409: %s", rec.Code, rec.Body.String())
	}

	rec := upload("alice", `{"Domains":"imp.example.test","ForwardScheme":"http","ForwardHost":"203.0.113.9","ForwardPort":80,
		"DNSProvider":"cloudflare","DNSZoneID":"zone-of-someone-else","DNSRecordID":"record-to-delete","CFDNSRecordID":"cf-rec","CFZoneID":"cf-zone","CertificateID":777}`)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a clean import -> %d: %s", rec.Code, rec.Body.String())
	}
	var prov, zone, rec1, cf, cert, skip = "", "", "", "", int64(0), 0
	if err := e.db.QueryRow(`SELECT COALESCE(dns_provider,''), COALESCE(dns_zone_id,''), COALESCE(dns_record_id,''), COALESCE(cf_dns_record_id,''), COALESCE(certificate_id,0), COALESCE(dns_skip_record,0) FROM proxy_hosts WHERE domains='imp.example.test'`).
		Scan(&prov, &zone, &rec1, &cf, &cert, &skip); err != nil {
		t.Fatal(err)
	}
	if prov != "" || zone != "" || rec1 != "" || cf != "" || cert != 0 {
		t.Errorf("uploaded DNS/certificate state survived the import: provider=%q zone=%q record=%q cf=%q cert=%d", prov, zone, rec1, cf, cert)
	}
}

// A certificate ID arrives as a plain number; the forms only offer visible
// certificates, but nothing checked that on the server.
func TestSecurityNonAdminCannotReferenceAnotherTenantsCertificate(t *testing.T) {
	e := newSecEnv(t)
	bobCert, err := models.CreateCertificate(e.db, 1, e.ids["bob"], &models.Certificate{
		Name: "bob-private", Domains: "bob.example.test", Source: models.CertSourcePEM, CertPEM: "c", KeyPEM: "k"})
	if err != nil {
		t.Fatal(err)
	}
	globalCert, err := models.CreateCertificate(e.db, 1, 0, &models.Certificate{
		Name: "wildcard", Domains: "*.example.test", Source: models.CertSourcePEM, CertPEM: "c", KeyPEM: "k"})
	if err != nil {
		t.Fatal(err)
	}
	host := func(cert int64, domain string) url.Values {
		return url.Values{"domains": {domain}, "forward_scheme": {"http"}, "forward_host": {"10.0.0.5"}, "forward_port": {"80"},
			"enabled": {"on"}, "certificate_id": {strconv.FormatInt(cert, 10)}}
	}
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", host(bobCert, "a1.example.test")); rec.Code == http.StatusSeeOther {
		t.Error("alice bound another tenant's private certificate to her host")
	}
	// A shared (global) certificate remains selectable.
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", host(globalCert, "a2.example.test")); rec.Code != http.StatusSeeOther {
		t.Errorf("a global certificate was refused: %d %s", rec.Code, excerpt(rec.Body.String(), "not found"))
	}
}
