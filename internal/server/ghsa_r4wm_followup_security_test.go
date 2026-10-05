// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// GHSA-r4wm-rgc5-q834 (3rd finding, fixed in v2.52.2) introduced
// validateProxyUpstreamsForUser so a non-admin account can't point a proxy
// host's upstream at the Caddy admin API / loopback / link-local addresses.
// Auditing GHSA-5h8j-xxm3-7ggr (the AI exec-tool bypass, fixed in v2.56.1)
// turned up four MORE proxy-host creation paths that predate that guard and
// were never updated to call it: JSON-file import, "Import from Caddy",
// paste-a-Caddyfile import, and reclassifying an existing raw route into a
// proxy host. This file covers all four, plus two related but separate
// IDOR findings (clone endpoints missing the ownership check every other
// access to the same resource enforces) found during the same audit.

func newEvilUpstreamProxyHost() *models.ProxyHost {
	return &models.ProxyHost{
		Domains:       "evil.test",
		ForwardScheme: "http",
		ForwardHost:   "127.0.0.1",
		ForwardPort:   2019,
		Enabled:       true,
	}
}

func TestImportProxyHostSSRFGuard(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New("http://127.0.0.1:1", "", "")}
	user := &models.User{ID: 1, Email: "user@test", Role: models.RoleUser}

	upload := func(ph *models.ProxyHost) *httptest.ResponseRecorder {
		body, _ := json.Marshal(ph)
		var buf strings.Builder
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("config_file", "host.json")
		_, _ = fw.Write(body)
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/proxy-hosts/import", strings.NewReader(buf.String()))
		req.Header.Set("Content-Type", mw.FormDataContentType())
		ctx := context.WithValue(req.Context(), auth.ContextUserKey, user)
		rec := httptest.NewRecorder()
		s.importProxyHost(rec, req.WithContext(ctx))
		return rec
	}

	rec := upload(newEvilUpstreamProxyHost())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("malicious upstream import: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if hosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil); len(hosts) != 0 {
		t.Fatalf("blocked upstream must not be persisted, found %d", len(hosts))
	}

	legit := &models.ProxyHost{Domains: "ok.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true}
	if rec := upload(legit); rec.Code != http.StatusSeeOther {
		t.Fatalf("legit upstream import: expected redirect, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPostImportSSRFGuard(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["evil-import.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}]}]},
			{"match":[{"host":["ok-import.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"203.0.113.10:8080"}]}]}
		]}}}}}`))
	}))
	defer admin.Close()

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: admin.URL}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New(admin.URL, "", "")}
	user := &models.User{ID: 1, Email: "user@test", Role: models.RoleUser}

	req := httptest.NewRequest(http.MethodPost, "/import", nil)
	ctx := context.WithValue(req.Context(), auth.ContextUserKey, user)
	rec := httptest.NewRecorder()
	s.postImport(rec, req.WithContext(ctx))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rec.Code, rec.Body.String())
	}

	hosts, err := models.ListProxyHosts(conn, 1, 1, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range hosts {
		got[h.Domains] = true
	}
	if got["evil-import.test"] {
		t.Fatalf("malicious upstream must not have been imported, got hosts: %#v", hosts)
	}
	if !got["ok-import.test"] {
		t.Fatalf("legit upstream should have been imported, got hosts: %#v", hosts)
	}
}

func TestPostCaddyfileImportSSRFGuard(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[
			{"match":[{"host":["evil-paste.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}]}]}
		]}}}}}}`))
	}))
	defer admin.Close()

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: admin.URL}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New(admin.URL, "", "")}
	user := &models.User{ID: 1, Email: "user@test", Role: models.RoleUser}

	form := url.Values{"caddyfile": {"evil-paste.test {\n\treverse_proxy 127.0.0.1:2019\n}\n"}}
	req := httptest.NewRequest(http.MethodPost, "/caddyfile-import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(req.Context(), auth.ContextUserKey, user)
	rec := httptest.NewRecorder()
	s.postCaddyfileImport(rec, req.WithContext(ctx))

	// The handler's own final page render isn't exercised here (this Server
	// has no template FS loaded, matching every other direct-handler test in
	// this package) — the security property under test is that nothing
	// malicious reaches the database, not the rendered summary's wording.
	_ = rec
	if hosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil); len(hosts) != 0 {
		t.Fatalf("malicious pasted upstream must not be persisted, found %d: %#v", len(hosts), hosts)
	}
}

func TestPostReclassifyRawRoutesSSRFGuard(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New("http://127.0.0.1:1", "", "")}
	user := &models.User{ID: 1, Email: "user@test", Role: models.RoleUser}

	route := `{"match":[{"host":["evil-reclassify.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}]}]}`
	rrID, err := models.CreateRawRoute(conn, 1, user.ID, &models.RawRoute{Label: "evil-reclassify.test", JSONData: route, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/raw-routes/reclassify", nil)
	ctx := context.WithValue(req.Context(), auth.ContextUserKey, user)
	rec := httptest.NewRecorder()
	s.postReclassifyRawRoutes(rec, req.WithContext(ctx))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rec.Code, rec.Body.String())
	}

	if hosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil); len(hosts) != 0 {
		t.Fatalf("malicious raw route must not have been reclassified into a proxy host, found %d", len(hosts))
	}
	if rr, err := models.GetRawRoute(conn, rrID); err != nil || rr == nil {
		t.Fatalf("raw route should still exist (kept, not converted): %v", err)
	}
}

func TestCloneProxyHostRequiresOwnership(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New("http://127.0.0.1:1", "", "")}

	owner := &models.User{ID: 1, Email: "owner@test", Role: models.RoleUser}
	other := &models.User{ID: 2, Email: "other@test", Role: models.RoleUser}
	admin := &models.User{ID: 3, Email: "admin@test", IsAdmin: true, Role: models.RoleAdmin}

	srcID, err := models.CreateProxyHost(conn, 1, owner.ID, &models.ProxyHost{Domains: "source.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 80})
	if err != nil {
		t.Fatal(err)
	}

	clone := func(u *models.User) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/proxy-hosts/"+strconv.FormatInt(srcID, 10)+"/clone", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", strconv.FormatInt(srcID, 10))
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = context.WithValue(ctx, auth.ContextUserKey, u)
		rec := httptest.NewRecorder()
		s.cloneProxyHost(rec, req.WithContext(ctx))
		return rec
	}

	if rec := clone(other); rec.Code != http.StatusForbidden {
		t.Fatalf("non-owner clone: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if hosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil); len(hosts) != 1 {
		t.Fatalf("non-owner clone must not create a copy, found %d proxy hosts", len(hosts))
	}
	if rec := clone(owner); rec.Code != http.StatusSeeOther {
		t.Fatalf("owner clone: expected redirect, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := clone(admin); rec.Code != http.StatusSeeOther {
		t.Fatalf("admin clone: expected redirect, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCloneRedirectionHostRequiresOwnership(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New("http://127.0.0.1:1", "", "")}

	owner := &models.User{ID: 1, Email: "owner@test", Role: models.RoleUser}
	other := &models.User{ID: 2, Email: "other@test", Role: models.RoleUser}

	srcID, err := models.CreateRedirectionHost(conn, 1, owner.ID, &models.RedirectionHost{Domains: "source-rd.test", ForwardDomain: "target.test", ForwardHTTPCode: 301})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/redirection-hosts/"+strconv.FormatInt(srcID, 10)+"/clone", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.FormatInt(srcID, 10))
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, auth.ContextUserKey, other)
	rec := httptest.NewRecorder()
	s.cloneRedirectionHost(rec, req.WithContext(ctx))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-owner clone: expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if hosts, _ := models.ListRedirectionHosts(conn, 1, 1, true, nil); len(hosts) != 1 {
		t.Fatalf("non-owner clone must not create a copy, found %d redirection hosts", len(hosts))
	}
}
