// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// adaptRecorder is a Caddy admin API stand-in that never runs Caddy: it
// records every Caddyfile sent to /adapt and refuses it. Tests that send
// text Caddy must never see (deeply nested blocks, file imports) use it to
// prove the text was refused before any adapt, without putting a real
// Caddy at risk.
type adaptRecorder struct {
	mu     sync.Mutex
	bodies []string
}

func (a *adaptRecorder) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.bodies...)
}

func (a *adaptRecorder) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.bodies = nil
}

// round8Marker is what the recorder answers; a response carrying it means
// the text reached the adapter.
const round8Marker = "ADAPTER-WAS-CALLED"

// newAdaptRecorderFixture is newExportFixture with an adaptRecorder as the
// server's Caddy admin API.
func newAdaptRecorderFixture(t *testing.T) (*Server, *sql.DB, int64, *adaptRecorder, *models.User, *models.User) {
	t.Helper()
	rec := &adaptRecorder{}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/adapt" {
			b, _ := io.ReadAll(r.Body)
			rec.mu.Lock()
			rec.bodies = append(rec.bodies, string(b))
			rec.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"`+round8Marker+`"}`)
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config") {
			_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
			return
		}
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(fake.Close)
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	sid, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Primary", AdminURL: fake.URL, Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	adminID, err := models.CreateUser(conn, "admin@example.test", "x", "Admin", models.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	tenantID, err := models.CreateUser(conn, "tenant@example.test", "x", "Tenant", models.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	s := newRenderingTestServer(t, conn)
	s.Caddy = caddy.New(fake.URL, "", "")
	return s, conn, sid, rec,
		&models.User{ID: adminID, Email: "admin@example.test", Role: models.RoleAdmin, IsAdmin: true},
		&models.User{ID: tenantID, Email: "tenant@example.test", Role: models.RoleUser}
}

// tenantCaddyfilePaths drives one non-admin Caddyfile text through every
// path that adapts it: the raw-route API (create and update), the raw-route
// form (create and update), the validate button, and a proxy host's
// Advanced config (form create and update, and the preview). raw is used
// where a whole Caddyfile is expected, adv where an Advanced config is. It
// returns, per path, the response status and body.
func tenantCaddyfilePaths(t *testing.T, s *Server, conn *sql.DB, sid int64, tenant *models.User, raw, adv string) map[string]*httptest.ResponseRecorder {
	t.Helper()
	out := map[string]*httptest.ResponseRecorder{}

	body, _ := json.Marshal(map[string]any{"label": "r8", "enabled": true, "caddyfile_src": raw})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.apiV1CreateRawRoute(rec, req)
	out["raw-route API create"] = rec

	rrID, err := models.CreateRawRoute(conn, sid, tenant.ID, &models.RawRoute{Label: "existing", Enabled: true,
		JSONData: `{"match":[{"host":["r8.example.test"]}],"handle":[{"handler":"static_response","body":"ok"}]}`})
	if err != nil {
		t.Fatal(err)
	}
	id := strconv.FormatInt(rrID, 10)
	req = asUser(httptest.NewRequest(http.MethodPut, "/api/v1/raw-routes/"+id, strings.NewReader(string(body))), sid, tenant, map[string]string{"id": id})
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	s.apiV1UpdateRawRoute(rec, req)
	out["raw-route API update"] = rec

	form := url.Values{"label": {"r8"}, "enabled": {"on"}, "caddyfile_src": {raw}}
	rec = httptest.NewRecorder()
	s.createRawRoute(rec, asUser(postForm(t, "/raw-routes", form), sid, tenant, nil))
	out["raw-route form create"] = rec
	rec = httptest.NewRecorder()
	s.updateRawRoute(rec, asUser(postForm(t, "/raw-routes/"+id, form), sid, tenant, map[string]string{"id": id}))
	out["raw-route form update"] = rec

	rec = httptest.NewRecorder()
	s.apiValidateRawRoute(rec, asUser(postForm(t, "/api/raw-routes/validate", url.Values{"caddyfile_src": {raw}}), sid, tenant, nil))
	out["raw-route validate"] = rec

	pform := url.Values{"domains": {"r8adv.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"},
		"forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {adv}}
	rec = httptest.NewRecorder()
	s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", pform), sid, tenant, nil))
	out["proxy host form create"] = rec

	phID, err := models.CreateProxyHost(conn, sid, tenant.ID, &models.ProxyHost{Domains: "r8adv.example.test", ForwardScheme: "http",
		ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	pid := strconv.FormatInt(phID, 10)
	rec = httptest.NewRecorder()
	s.updateProxyHost(rec, asUser(postForm(t, "/proxy-hosts/"+pid, pform), sid, tenant, map[string]string{"id": pid}))
	out["proxy host form update"] = rec

	rec = httptest.NewRecorder()
	s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", pform), sid, tenant, nil))
	out["proxy host preview"] = rec
	return out
}

// tenantPathRefused reports why one response from tenantCaddyfilePaths
// does not read as a refusal, or "".
func tenantPathRefused(path string, rec *httptest.ResponseRecorder) string {
	body := rec.Body.String()
	switch path {
	case "raw-route API create", "raw-route API update":
		if rec.Code != http.StatusBadRequest {
			return "want 400, got " + strconv.Itoa(rec.Code)
		}
	case "raw-route form create", "raw-route form update", "proxy host form create", "proxy host form update":
		if rec.Code == http.StatusSeeOther {
			return "the form was saved"
		}
	case "raw-route validate":
		var v struct {
			OK bool `json:"ok"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		if v.OK {
			return "validate said ok"
		}
	case "proxy host preview":
		var v struct {
			AdvancedError string `json:"advanced_error"`
			Error         string `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		if v.AdvancedError == "" && v.Error == "" {
			return "the preview reported no error"
		}
	}
	if strings.Contains(body, round8Marker) {
		return "the response carries the adapter's answer"
	}
	return ""
}

// Issue #184 round-8 review (1): a non-admin's `import <name>` of a name
// that is not one of the administrator's snippets makes Caddy read a file
// of that name from its working directory, at save, preview and validate,
// and echo it (or store it as header names). Such an import is refused on
// every path before Caddy sees the text — with and without administrator
// snippets defined.
func TestTenantImportOfANonSnippetNeverReachesCaddy(t *testing.T) {
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	cases := map[string][2]string{
		"plain name":      {"imp.example.test {\n\timport mysecret\n}", "import mysecret"},
		"inside a header": {"imp.example.test {\n\theader {\n\t\timport secrets\n\t}\n}", "header {\n\timport secrets\n}"},
		"a directory":     {"imp.example.test {\n\timport d\n}", "import d"},
	}
	for _, withSnippets := range []bool{false, true} {
		if withSnippets {
			s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
			if err := os.WriteFile(s.CaddyfilePath, []byte("(tag) {\n\theader X-Tag yes\n}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for name, c := range cases {
			what := name
			if withSnippets {
				what += " (administrator snippets defined)"
			}
			rec.reset()
			for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, c[0], c[1]) {
				if why := tenantPathRefused(path, resp); why != "" {
					t.Errorf("%s: %s: %s: %s", what, path, why, resp.Body.String())
				}
			}
			if seen := rec.seen(); len(seen) > 0 {
				t.Errorf("%s: %d Caddyfile(s) reached the adapter, first:\n%s", what, len(seen), seen[0])
			}
		}
	}
}

// nestedHandles is depth `handle {` blocks with a respond in the middle.
func nestedHandles(depth int) string {
	return strings.Repeat("handle {\n", depth) + "respond 1\n" + strings.Repeat("}\n", depth)
}

// Issue #184 round-8 review (2): deeply nested text made Caddy's adapter
// run out of memory (4000 levels in 44 KB took more than 3 GB). A
// non-admin's text nested too deeply is refused on every path before Caddy
// sees it, and so is an administrator's, at a much higher limit.
func TestDeeplyNestedTenantTextNeverReachesCaddy(t *testing.T) {
	s, conn, sid, rec, admin, tenant := newAdaptRecorderFixture(t)
	for _, depth := range []int{100, 4000} {
		inner := nestedHandles(depth)
		raw := "deep.example.test {\n" + inner + "}\n"
		rec.reset()
		for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, raw, inner) {
			if why := tenantPathRefused(path, resp); why != "" {
				t.Errorf("depth %d: %s: %s: %.300s", depth, path, why, resp.Body.String())
			}
		}
		if seen := rec.seen(); len(seen) > 0 {
			t.Errorf("depth %d: %d Caddyfile(s) reached the adapter (largest first one %d bytes)", depth, len(seen), len(seen[0]))
		}
	}

	// An administrator's text is held to a limit that no real
	// configuration reaches, but that keeps 4000 levels from Caddy too.
	rec.reset()
	raw := "deep.example.test {\n" + nestedHandles(4000) + "}\n"
	body, _ := json.Marshal(map[string]any{"label": "deep", "enabled": true, "caddyfile_src": raw})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, admin, nil)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.apiV1CreateRawRoute(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("admin, depth 4000: want 400, got %d", resp.Code)
	}
	if seen := rec.seen(); len(seen) > 0 {
		t.Errorf("admin, depth 4000: the text reached the adapter")
	}
	rec.reset()
	raw = "deep.example.test {\n" + nestedHandles(20) + "}\n"
	body, _ = json.Marshal(map[string]any{"label": "deep", "enabled": true, "caddyfile_src": raw})
	req = asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, admin, nil)
	req.Header.Set("Content-Type", "application/json")
	s.apiV1CreateRawRoute(httptest.NewRecorder(), req)
	if seen := rec.seen(); len(seen) != 1 {
		t.Errorf("admin, depth 20: want the text adapted once, got %d adapt calls", len(seen))
	}
}

// Issue #184 round-8 review (2): a non-admin's Advanced route Caddyfile had
// no size limit at all. It now has the Advanced config's 64 KiB limit,
// checked before the text is adapted; an administrator's is not limited.
func TestOversizedTenantRawRouteIsRefused(t *testing.T) {
	s, _, sid, rec, admin, tenant := newAdaptRecorderFixture(t)
	big := "big.example.test {\n" + strings.Repeat("\theader X-A \"aaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n", (64<<10)/40+10) + "}\n"
	if len(big) <= 64<<10 {
		t.Fatalf("fixture: %d bytes is not over the limit", len(big))
	}
	body, _ := json.Marshal(map[string]any{"label": "big", "enabled": true, "caddyfile_src": big})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	s.apiV1CreateRawRoute(resp, req)
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "too large") {
		t.Errorf("tenant raw-route API: want 400 too large, got %d %s", resp.Code, resp.Body.String())
	}
	resp = httptest.NewRecorder()
	s.createRawRoute(resp, asUser(postForm(t, "/raw-routes", url.Values{"label": {"big"}, "enabled": {"on"}, "caddyfile_src": {big}}), sid, tenant, nil))
	if resp.Code == http.StatusSeeOther || !strings.Contains(formError(resp.Body.String()), "too large") {
		t.Errorf("tenant raw-route form: want a too-large error, got %d %s", resp.Code, formError(resp.Body.String()))
	}
	resp = httptest.NewRecorder()
	s.apiValidateRawRoute(resp, asUser(postForm(t, "/api/raw-routes/validate", url.Values{"caddyfile_src": {big}}), sid, tenant, nil))
	if !strings.Contains(resp.Body.String(), "too large") {
		t.Errorf("tenant validate: want a too-large error, got %s", resp.Body.String())
	}
	if seen := rec.seen(); len(seen) > 0 {
		t.Errorf("an oversized tenant Caddyfile reached the adapter %d time(s)", len(seen))
	}
	rec.reset()
	req = asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, admin, nil)
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	s.apiV1CreateRawRoute(resp, req)
	if strings.Contains(resp.Body.String(), "too large") || len(rec.seen()) != 1 {
		t.Errorf("admin raw-route API: the size limit is for non-admins only, got %d %s (adapt calls %d)", resp.Code, resp.Body.String(), len(rec.seen()))
	}
}

// Issue #184 round-8 review (4): Caddy drops empty and comma-only address
// keys, so `"" (s) {` and `, (s) {` define snippet s. A non-admin's text
// doing so is refused before Caddy sees it.
func TestTenantGroupedSnippetDefinitionNeverReachesCaddy(t *testing.T) {
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	for name, def := range map[string]string{
		"empty address":   "\"\" (s) {\n\theader X-A a\n}\n",
		"comma address":   ", (s) {\n\theader X-A a\n}\n",
		"comma then line": "\"\",\n(s) {\n\theader X-A a\n}\n",
	} {
		raw := def + "grp.example.test {\n\timport s\n}\n"
		adv := "header X-B b\n}\n" + def + "zz.example.test {\n\timport s"
		rec.reset()
		for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, raw, adv) {
			if why := tenantPathRefused(path, resp); why != "" {
				t.Errorf("%s: %s: %s: %s", name, path, why, resp.Body.String())
			}
		}
		if seen := rec.seen(); len(seen) > 0 {
			t.Errorf("%s: %d Caddyfile(s) reached the adapter, first:\n%s", name, len(seen), seen[0])
		}
	}
}

// Issue #184 round-8 review (5): a non-admin's redirect could be saved with
// a port, a scheme or a trailing dot. A port or a scheme is now refused at
// save; a trailing dot or capitals are accepted, and the export writes the
// host names the live route matches. Rows stored before the rule export
// the same way, and one with a port is left out.
func TestTenantRedirectDomainsAtSaveAndInTheExport(t *testing.T) {
	s, conn, sid, _, admin, tenant := newAdaptRecorderFixture(t)
	save := func(domain string) *httptest.ResponseRecorder {
		rf := url.Values{"domains": {domain}, "forward_scheme": {"https"}, "forward_domain": {"new.example.test"},
			"forward_http_code": {"301"}, "enabled": {"on"}, "ssl_enabled": {"on"}}
		rec := httptest.NewRecorder()
		s.createRedirectionHost(rec, asUser(postForm(t, "/redirection-hosts", rf), sid, tenant, nil))
		return rec
	}
	for _, d := range []string{"PortRedir.example.test:8443", "https://sch.example.test", "sch2.example.test/path"} {
		if rec := save(d); rec.Code == http.StatusSeeOther {
			t.Errorf("tenant redirect domain %q: want refused at save", d)
		}
	}
	if rec := save("Dot.Example.test."); rec.Code != http.StatusSeeOther {
		t.Errorf("tenant redirect domain with a trailing dot: want saved, got %d %s", rec.Code, formError(rec.Body.String()))
	}
	for _, d := range []string{"legacy-dot.example.test.", "https://legacy-sch.example.test", "legacy-port.example.test:8443"} {
		if _, err := models.CreateRedirectionHost(conn, sid, tenant.ID, &models.RedirectionHost{Domains: d, ForwardScheme: "https",
			ForwardDomain: "new.example.test", ForwardHTTPCode: 301, Enabled: true, SSLEnabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	export := exportAs(t, s, sid, admin)
	for _, want := range []string{"\ndot.example.test {\n", "\nlegacy-dot.example.test {\n", "\nhttps {\n"} {
		if !strings.Contains(export, want) {
			t.Errorf("export: want a site %q (the name the live route matches):\n%s", strings.TrimSpace(want), export)
		}
	}
	if strings.Contains(export, "8443") || !strings.Contains(export, "omitted") {
		t.Errorf("export: the redirect with a port must be left out:\n%s", export)
	}
	// The live route matches exactly the names the export writes.
	redirs, _ := models.ListRedirectionHosts(conn, sid, admin.ID, true, nil)
	for _, rh := range redirs {
		route := caddy.BuildRedirectRoute(rh)
		b, _ := json.Marshal(route)
		if strings.Contains(rh.Domains, "legacy-sch") && !strings.Contains(string(b), `"host":["https"]`) {
			t.Errorf("fixture: the live route for %q no longer matches host \"https\": %s", rh.Domains, b)
		}
	}
}

// Issue #184 round-8 review (1): a non-admin's Advanced route stored by an
// earlier version from text that imported a file carries what Caddy read
// into its JSON. Such a route is no longer deployed; an administrator's is,
// and so is a non-admin's that imports an administrator snippet.
func TestStoredTenantRawRouteBreakingTheRulesIsNotDeployed(t *testing.T) {
	s, _, _, _, admin, tenant := newAdaptRecorderFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte("(tag) {\n\theader X-Tag yes\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	route := func(id int64, owner int64, src, marker string) models.RawRoute {
		return models.RawRoute{ID: id, Label: marker, Enabled: true, CaddyfileSrc: src, OwnerID: sql.NullInt64{Int64: owner, Valid: true},
			JSONData: `{"match":[{"host":["` + marker + `.example.test"]}],"handle":[{"handler":"headers","response":{"set":{"` + marker + `":["x"]}}}]}`}
	}
	raws := []models.RawRoute{
		route(1, tenant.ID, "leak.example.test {\n\theader {\n\t\timport secrets\n\t}\n}", "leaked"),
		route(2, tenant.ID, "ok.example.test {\n\timport tag\n}", "tenantsnippet"),
		route(3, admin.ID, "adm.example.test {\n\theader {\n\t\timport secrets\n\t}\n}", "adminroute"),
	}
	b, _ := json.Marshal(s.buildMergedRoutes(nil, nil, raws))
	got := string(b)
	if strings.Contains(got, "leaked") {
		t.Errorf("a non-admin's route whose Caddyfile imports a file was deployed: %s", got)
	}
	for _, want := range []string{"tenantsnippet", "adminroute"} {
		if !strings.Contains(got, want) {
			t.Errorf("route %s is missing from the live config: %s", want, got)
		}
	}
}

// Issue #184 round-8 review (2): the live sync adapts a proxy host's
// Advanced config with the live Caddy. A non-admin's stored Advanced config
// that is nested too deeply or too large — saved by an earlier version, or
// through a path without the form's size check — is not adapted; an
// administrator's is.
func TestSyncNeverAdaptsAnOversizedOrDeepTenantAdvancedConfig(t *testing.T) {
	s, _, _, rec, admin, tenant := newAdaptRecorderFixture(t)
	host := func(owner int64, adv string) models.ProxyHost {
		return models.ProxyHost{ID: 5, Domains: "sync.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, AdvancedConfig: adv, OwnerID: sql.NullInt64{Int64: owner, Valid: true}}
	}
	big := strings.Repeat("header X-A \"aaaaaaaaaaaaaaaaaaaaaaaaaa\"\n", (64<<10)/36+10)
	for name, adv := range map[string]string{"depth 100": nestedHandles(100), "depth 4000": nestedHandles(4000), "over 64 KiB": big} {
		rec.reset()
		s.buildMergedRoutes([]models.ProxyHost{host(tenant.ID, adv)}, nil, nil)
		if n := len(rec.seen()); n > 0 {
			t.Errorf("tenant, %s: the live sync sent the Advanced config to the adapter %d time(s)", name, n)
		}
	}
	rec.reset()
	s.buildMergedRoutes([]models.ProxyHost{host(admin.ID, nestedHandles(50))}, nil, nil)
	if n := len(rec.seen()); n != 1 {
		t.Errorf("admin, depth 50: want the Advanced config adapted once, got %d", n)
	}
}

// Issue #184 round 8 (3): the false positives of the raw-text placeholder
// check, end to end with Caddy: the tenant's raw route saves, the export
// writes the hosts instead of failing them closed, and the live route keeps
// the Advanced handler.
func TestRound7FalsePositivesExportAndServe(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the raw route and the Advanced config are adapted with Caddy")

	raw := "docs.example.test {\n\trewrite * /args.html\n\treverse_proxy 203.0.113.10:8080\n}"
	body, _ := json.Marshal(map[string]any{"label": "docs", "enabled": true, "caddyfile_src": raw})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.apiV1CreateRawRoute(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("raw route rewriting to /args.html: want 201, got %d %s", rec.Code, rec.Body.String())
	}

	hostForm := func(domain string, extra url.Values) url.Values {
		f := url.Values{"domains": {domain}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"},
			"forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	hosts := map[string]url.Values{
		"path.example.test": {"path_matcher": {"/args.php"}},
		"link.example.test": {"header_resp_key": {"Link"}, "header_resp_val": {"</static/kwargs.css>; rel=preload"}},
		"tags.example.test": {"tags": {"data import 2024.q1"}},
		"adv.example.test":  {"advanced_config": {"handle /docs {\n\trewrite * /args.html\n}"}},
		"js.example.test":   {"advanced_config": {"header X-Script \"function f(args){ return args[0] }\""}},
	}
	for dom, extra := range hosts {
		rec := httptest.NewRecorder()
		s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", hostForm(dom, extra)), sid, tenant, nil))
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s: want saved, got %d %s", dom, rec.Code, formError(rec.Body.String()))
		}
	}
	rf := url.Values{"domains": {"old.example.test"}, "forward_scheme": {"https"}, "forward_domain": {"new.example.test/args.html"},
		"forward_http_code": {"301"}, "enabled": {"on"}, "ssl_enabled": {"on"}}
	rec = httptest.NewRecorder()
	s.createRedirectionHost(rec, asUser(postForm(t, "/redirection-hosts", rf), sid, tenant, nil))
	if rec.Code != http.StatusSeeOther {
		t.Errorf("redirect to /args.html: want saved, got %d %s", rec.Code, formError(rec.Body.String()))
	}

	export := exportAs(t, s, sid, admin)
	for _, site := range []string{"path.example.test", "link.example.test", "tags.example.test", "adv.example.test", "js.example.test", "old.example.test"} {
		block := exportedSite(export, site)
		if block == "" || strings.Contains(block, "respond 503") {
			t.Errorf("%s: want exported, got:\n%s\n--- export:\n%s", site, block, export)
		}
	}
	if !strings.Contains(export, "rewrite * /args.html") {
		t.Errorf("the raw route rewriting to /args.html is missing from the export:\n%s", export)
	}

	// The live route of the host with the Advanced config keeps its handler.
	list, _ := models.ListProxyHosts(conn, sid, admin.ID, true, nil)
	for _, p := range list {
		if p.Domains != "adv.example.test" {
			continue
		}
		b, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil))
		if !strings.Contains(string(b), "/args.html") {
			t.Errorf("the live route dropped the Advanced handler: %s", b)
		}
	}
}

// exportedSite returns the block for site in export, or "".
func exportedSite(export, site string) string {
	i := strings.Index(export, "\n"+site+" {\n")
	if i < 0 {
		return ""
	}
	rest := export[i+1:]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j+2]
	}
	return rest
}

// Issue #184 round 8 (6): the Advanced config size limit is for non-admins
// only, and a refusal is a form error that keeps what was typed.
func TestAdvancedConfigSizeLimitIsForNonAdmins(t *testing.T) {
	s, _, sid, rec8, admin, tenant := newAdaptRecorderFixture(t)
	big := strings.Repeat("header X-A \"a\"\n", maxProxyAdvancedConfigBytes/15+10)
	form := url.Values{"domains": {"big.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"},
		"forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {big}}
	rec := httptest.NewRecorder()
	s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form), sid, tenant, nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(formError(rec.Body.String()), "too large") {
		t.Errorf("tenant save: want 400 with a too-large form error, got %d %q", rec.Code, formError(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "big.example.test") || !strings.Contains(rec.Body.String(), "header X-A") {
		t.Errorf("tenant save: the re-rendered form must keep the input")
	}
	rec = httptest.NewRecorder()
	s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", form), sid, tenant, nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too large") {
		t.Errorf("tenant preview: want 400 too large, got %d %s", rec.Code, rec.Body.String())
	}
	if n := len(rec8.seen()); n > 0 {
		t.Errorf("an oversized tenant Advanced config reached the adapter %d time(s)", n)
	}
	rec = httptest.NewRecorder()
	s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", form), sid, admin, nil))
	if strings.Contains(rec.Body.String(), "too large") {
		t.Errorf("admin preview: no size limit for administrators, got %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form), sid, admin, nil))
	if strings.Contains(formError(rec.Body.String()), "too large") {
		t.Errorf("admin save: no size limit for administrators, got %q", formError(rec.Body.String()))
	}
}

// Issue #184 round 8 (7): the export's adapt client stops calling Caddy
// once a call has failed to get a response, and a new export starts fresh.
func TestExportAdaptClientFailsClosedAfterATransportError(t *testing.T) {
	var calls atomic.Int64
	var down atomic.Bool
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if down.Load() {
			// A response that never arrives: hijack and drop the connection.
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		if strings.Contains(r.URL.Path, "adapt") {
			b, _ := io.ReadAll(r.Body)
			if strings.Contains(string(b), "bad") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"bad"}`)
				return
			}
			_, _ = io.WriteString(w, `{"result":{}}`)
		}
	}))
	defer fake.Close()
	s := &Server{Caddy: caddy.New(fake.URL, "", "")}

	next := s.exportAdaptClient(1)
	cl := next()
	if cl == nil || next() != cl {
		t.Fatalf("one export must share one client")
	}
	if _, err := cl.Adapt("bad.example.test {\n\trespond 1\n}\n"); err == nil {
		t.Fatalf("want Caddy's 400 as an error")
	}
	if _, err := cl.Adapt("ok.example.test {\n\trespond 1\n}\n"); err != nil {
		t.Errorf("a 400 from Caddy must not trip the transport: %v", err)
	}
	down.Store(true)
	if _, err := cl.Adapt("ok.example.test {\n\trespond 1\n}\n"); err == nil {
		t.Fatalf("want the dropped connection as an error")
	}
	down.Store(false)
	before := calls.Load()
	_, err := cl.Adapt("ok.example.test {\n\trespond 1\n}\n")
	if !errors.Is(err, errExportAdapterDown) {
		t.Errorf("after a transport error: want errExportAdapterDown, got %v", err)
	}
	if calls.Load() != before {
		t.Errorf("after a transport error the client must not contact Caddy again")
	}
	fresh := s.exportAdaptClient(1)()
	if fresh == cl {
		t.Fatalf("a new export must get a new client")
	}
	if _, err := fresh.Adapt("ok.example.test {\n\trespond 1\n}\n"); err != nil {
		t.Errorf("a new export starts with a working client: %v", err)
	}
	if s.Caddy.HTTP != nil {
		if _, ok := s.Caddy.HTTP.Transport.(*stickyFailTransport); ok {
			t.Errorf("the server's own client must not be changed")
		}
	}
}

// Issue #184 round 8 (1): an administrator's snippet is still importable by
// name in a tenant's Advanced route, and a name the administrator has not
// defined is refused even with snippets present.
func TestTenantImportsOnlyAdministratorSnippets(t *testing.T) {
	s, _, sid, caddyBin, _, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the raw route is adapted with Caddy")
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte("(tag) {\n\theader X-Tag yes\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for src, want := range map[string]int{
		"snip.example.test {\n\timport tag\n\trespond 1\n}":   http.StatusCreated,
		"snip2.example.test {\n\timport tags\n\trespond 1\n}": http.StatusBadRequest,
	} {
		body, _ := json.Marshal(map[string]any{"label": "snip", "enabled": true, "caddyfile_src": src})
		req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.apiV1CreateRawRoute(rec, req)
		if rec.Code != want {
			t.Errorf("%q: want %d, got %d %s", src, want, rec.Code, rec.Body.String())
		}
		// Issue #184 round 10 (6): the refusal is CaddyUI's own, made
		// before Caddy is asked — not Caddy's file-not-found error.
		if want == http.StatusBadRequest {
			if b := rec.Body.String(); !strings.Contains(b, `the snippet \"tags\" is not available`) || strings.Contains(b, "File to import not found") {
				t.Errorf("%q: want CaddyUI's own refusal, got %s", src, b)
			}
		}
	}
	// The live sync keeps a tenant's Advanced config that imports one.
	p := models.ProxyHost{ID: 9, Domains: "snipadv.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
		Enabled: true, SSLEnabled: true, AdvancedConfig: "import tag", OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true}}
	b, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil))
	if !strings.Contains(string(b), "X-Tag") {
		t.Errorf("the live route dropped the administrator snippet the tenant imports: %s", b)
	}
	p.AdvancedConfig = "import tags"
	b, _ = json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil))
	if strings.Contains(string(b), "X-Tag") {
		t.Errorf("an import of an undefined name must not reach the live route: %s", b)
	}
}
