// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// TestUpstreamHostBlockedForNonAdmin covers the address classifier that backs
// the SSRF guard reported (3rd finding) in GHSA-r4wm-rgc5-q834.
func TestUpstreamHostBlockedForNonAdmin(t *testing.T) {
	cases := []struct {
		host      string
		adminHost string
		blocked   bool
	}{
		// Loopback / admin-API vectors.
		{"127.0.0.1", "", true},
		{"127.0.0.1:2019", "", true},
		{"localhost", "", true},
		{"localhost:2019", "", true},
		{"app.localhost", "", true},
		{"[::1]", "", true},
		{"::1", "", true},
		{"[::1]:2019", "", true},
		// Unspecified.
		{"0.0.0.0", "", true},
		{"[::]", "", true},
		// Link-local incl. cloud metadata.
		{"169.254.169.254", "", true},
		{"169.254.1.1:80", "", true},
		// Configured remote admin endpoint (not loopback) is blocked by host match.
		{"10.8.0.1", "10.8.0.1", true},
		// Allowed: public and private-LAN upstreams (legitimate delegated use).
		{"203.0.113.10", "", false},
		{"203.0.113.10:8080", "", false},
		{"192.168.1.50", "", false},
		{"10.0.0.5:3000", "", false},
		{"172.16.4.4", "", false},
		{"backend.invalid", "", false},  // unresolvable hostname → not blocked
		{"10.8.0.2", "10.8.0.1", false}, // different host than admin endpoint
		{"", "", false},                 // empty handled by callers
	}
	for _, c := range cases {
		if got := upstreamHostBlockedForNonAdmin(c.host, c.adminHost); got != c.blocked {
			t.Errorf("upstreamHostBlockedForNonAdmin(%q, %q) = %v, want %v", c.host, c.adminHost, got, c.blocked)
		}
	}
}

// TestValidateProxyUpstreamsForUser covers role-awareness and every upstream
// sink (primary host, extra upstreams, Host override).
func TestValidateProxyUpstreamsForUser(t *testing.T) {
	s := &Server{Caddy: caddy.New("http://127.0.0.1:2019", "", "")}
	admin := &models.User{ID: 1, IsAdmin: true, Role: models.RoleAdmin}
	user := &models.User{ID: 2, Role: models.RoleUser}

	// Admins are never restricted, even for the admin API itself.
	if msg := s.validateProxyUpstreamsForUser(admin, &models.ProxyHost{ForwardHost: "127.0.0.1", ForwardPort: 2019}); msg != "" {
		t.Fatalf("admin must be unrestricted, got: %s", msg)
	}

	blocked := []*models.ProxyHost{
		{ForwardHost: "127.0.0.1", ForwardPort: 2019},                                     // primary → admin API
		{ForwardHost: "localhost", ForwardPort: 8080},                                     // primary → loopback name
		{ForwardHost: "backend", ForwardPort: 80, ExtraUpstreams: `["127.0.0.1:2019"]`},   // extra upstream
		{ForwardHost: "backend", ForwardPort: 80, UpstreamHostOverride: "localhost:2019"}, // Host override bypass
		{ForwardHost: "169.254.169.254", ForwardPort: 80},                                 // cloud metadata
	}
	for _, p := range blocked {
		if msg := s.validateProxyUpstreamsForUser(user, p); msg == "" {
			t.Errorf("expected non-admin block for %+v, got allowed", p)
		}
	}

	allowed := []*models.ProxyHost{
		{ForwardHost: "203.0.113.10", ForwardPort: 8080}, // public
		{ForwardHost: "192.168.1.10", ForwardPort: 3000}, // private LAN still allowed
	}
	for _, p := range allowed {
		if msg := s.validateProxyUpstreamsForUser(user, p); msg != "" {
			t.Errorf("expected allow for %+v, got blocked: %s", p, msg)
		}
	}
}

// TestAPIV1ProxyHostSSRFGuard is the end-to-end handler regression: a low-priv
// user-role account must not be able to create OR update a proxy host whose
// upstream targets the Caddy admin API / internal addresses, while admins and
// legitimate public upstreams keep working.
func TestAPIV1ProxyHostSSRFGuard(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// AdminURL points at a closed port so the post-write sync fails instantly
	// and non-fatally (trySyncCaddy logs and moves on).
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New("http://127.0.0.1:1", "", "")}

	admin := &models.User{ID: 1, Email: "admin@test", IsAdmin: true, Role: models.RoleAdmin}
	user := &models.User{ID: 2, Email: "user@test", Role: models.RoleUser}

	post := func(u *models.User, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy-hosts", strings.NewReader(body))
		ctx := context.WithValue(req.Context(), auth.ContextUserKey, u)
		rec := httptest.NewRecorder()
		s.apiV1CreateProxyHost(rec, req.WithContext(ctx))
		return rec
	}
	put := func(u *models.User, id int64, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/proxy-hosts/"+strconv.FormatInt(id, 10), strings.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", strconv.FormatInt(id, 10))
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = context.WithValue(ctx, auth.ContextUserKey, u)
		rec := httptest.NewRecorder()
		s.apiV1UpdateProxyHost(rec, req.WithContext(ctx))
		return rec
	}

	// 1. user-role create targeting the Caddy admin API → 403, nothing persisted.
	rec := post(user, `{"domains":"evil.test","forward_scheme":"http","forward_host":"127.0.0.1","forward_port":2019,"enabled":true}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SSRF create: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if hosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil); len(hosts) != 0 {
		t.Fatalf("blocked host must not be persisted, found %d", len(hosts))
	}

	// 2. user-role create via extra upstream → 403.
	if rec := post(user, `{"domains":"evil2.test","forward_scheme":"http","forward_host":"backend","forward_port":80,"enabled":true,"extra_upstreams":"[\"127.0.0.1:2019\"]"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("SSRF create via extra_upstreams: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. user-role create with a legitimate public upstream → 201.
	if rec := post(user, `{"domains":"ok.test","forward_scheme":"http","forward_host":"203.0.113.10","forward_port":8080,"enabled":true}`); rec.Code != http.StatusCreated {
		t.Fatalf("legit user create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// 4. admin create targeting loopback → 201 (admins unrestricted; common
	//    single-admin "proxy to localhost app" case must keep working).
	if rec := post(admin, `{"domains":"adminlocal.test","forward_scheme":"http","forward_host":"127.0.0.1","forward_port":3000,"enabled":true}`); rec.Code != http.StatusCreated {
		t.Fatalf("admin loopback create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. user edits their legitimate host to target the admin API → 403, unchanged.
	var okID int64
	allHosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil)
	for _, h := range allHosts {
		if h.Domains == "ok.test" {
			okID = h.ID
		}
	}
	if okID == 0 {
		t.Fatal("could not find user's legit host to edit")
	}
	if rec := put(user, okID, `{"forward_host":"127.0.0.1","forward_port":2019}`); rec.Code != http.StatusForbidden {
		t.Fatalf("SSRF update: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	after, _ := models.GetProxyHost(conn, okID)
	if after == nil || after.ForwardHost != "203.0.113.10" {
		t.Fatalf("blocked update must not change upstream, got %+v", after)
	}
}
