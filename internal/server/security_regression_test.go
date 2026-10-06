// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
