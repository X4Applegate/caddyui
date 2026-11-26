// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// newAdaptingFakeAdmin is a Caddy admin API stand-in whose /adapt runs the
// real `caddy adapt` when a caddy binary is on PATH (raw routes are adapted
// at save time). Everything else answers 200.
func newAdaptingFakeAdmin(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	bin, _ := exec.LookPath("caddy")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/adapt":
			body, _ := io.ReadAll(r.Body)
			if bin == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"no caddy binary in this test run"}`)
				return
			}
			out, err := adaptWithCaddy(bin, body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_, _ = fmt.Fprintf(w, `{"result":%s}`, out)
		default:
			_, _ = io.WriteString(w, "{}")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, bin
}

func adaptWithCaddy(bin string, caddyfile []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "caddyui-adapt-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(file, caddyfile, 0o644); err != nil {
		return nil, err
	}
	out, err := exec.Command(bin, "adapt", "--config", file, "--adapter", "caddyfile").Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("%v: %s", err, ee.Stderr)
	}
	return out, err
}

func asUser(req *http.Request, serverID int64, u *models.User, urlParams map[string]string) *http.Request {
	req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(serverID, 10)})
	ctx := context.WithValue(req.Context(), auth.ContextUserKey, u)
	if len(urlParams) > 0 {
		rctx := chi.NewRouteContext()
		for k, v := range urlParams {
			rctx.URLParams.Add(k, v)
		}
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	return req.WithContext(ctx)
}

func newExportFixture(t *testing.T) (*Server, *sql.DB, int64, string, *models.User, *models.User) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	admin, bin := newAdaptingFakeAdmin(t)
	sid, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Primary", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged})
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
	s.Caddy = caddy.New(admin.URL, "", "")
	return s, conn, sid, bin,
		&models.User{ID: adminID, Email: "admin@example.test", Role: models.RoleAdmin, IsAdmin: true},
		&models.User{ID: tenantID, Email: "tenant@example.test", Role: models.RoleUser}
}

// Issue #184 review (C): the reviewers' three attacks on the server-wide
// export, end to end. A non-admin saves through the real handlers — a raw
// route whose label is `{$` (Caddy expands it across the raw file, eating
// into the route's own text), an Advanced config that closes its site and
// opens another, and a response header name that does the same — then an
// admin downloads /proxy-hosts/export-all.caddyfile. The export must hold
// only the tenant's own sites.
func TestNonAdminCannotInjectSitesIntoTheServerCaddyfileExport(t *testing.T) {
	s, _, sid, caddyBin, admin, tenant := newExportFixture(t)
	evil := func(name string) string { return "\n}\n" + name + " {\n\treverse_proxy 127.0.0.1:2019\n}\n" }

	if caddyBin == "" {
		t.Run("raw route attack and caddy adapt", func(t *testing.T) {
			t.Skip("SKIPPED: no `caddy` binary on PATH — the raw-route attack (Caddy adapts the route at save time) and the `caddy adapt` check of the export did NOT run; only the proxy-host attacks and the text checks did.")
		})
	} else {
		form := url.Values{"label": {"{$"}, "enabled": {"on"},
			"caddyfile_src": {"t2.example.com {\n\trespond \"}\nevil.example.test {\n\treverse_proxy 127.0.0.1:2019\n}\nz.example.com {\n\trespond x\" 200\n}"}}
		rec := httptest.NewRecorder()
		s.createRawRoute(rec, asUser(postForm(t, "/raw-routes", form), sid, tenant, nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("raw route save: %d %s", rec.Code, rec.Body.String())
		}
	}

	hostForm := func(domain string) url.Values {
		return url.Values{"domains": {domain}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"}}
	}
	adv := hostForm("tenant-adv.example.test")
	// The save path adapts `localhost { <advanced> }` and checks only the
	// first route, which Caddy sorts by hostname length — so the injected
	// sites use names shorter than "localhost" and are never looked at.
	// forward_auth, because an Advanced reverse_proxy naming an upstream is
	// refused by name.
	adv.Set("advanced_config", "encode gzip\n}\nevil.ad {\n\tforward_auth 127.0.0.1:2019 {\n\t\turi /config/\n\t}\n}\nx2.te {\n\theader X-C 1")
	hdr := hostForm("tenant-hdr.example.test")
	hdr["header_resp_key"] = []string{"X-A" + evil("evil-hdr.example.test") + "x3.example.test {\n\theader X-B"}
	hdr["header_resp_val"] = []string{"v"}
	for _, form := range []url.Values{adv, hdr} {
		rec := httptest.NewRecorder()
		s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form), sid, tenant, nil))
		if rec.Code != http.StatusSeeOther {
			t.Logf("%s refused at save (%d) — fine, the export is still checked: %s", form.Get("domains"), rec.Code, formError(rec.Body.String()))
		}
	}

	rec := httptest.NewRecorder()
	req := asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/export-all.caddyfile", nil), sid, admin, nil)
	s.exportServerCaddyfile(rec, req)
	export := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, export)
	}
	for _, line := range strings.Split(export, "\n") {
		// The raw-route attack's text sits inside a quoted string when the
		// export is read correctly, so only the adapt check below judges it.
		if strings.HasPrefix(line, "evil.ad") || strings.HasPrefix(line, "evil-hdr") || strings.HasPrefix(line, "x2.te") || strings.HasPrefix(line, "x3.example.test") {
			t.Errorf("export opens an injected site: %q\n%s", line, export)
		}
	}
	if strings.Contains(export, "{$") {
		t.Errorf("export contains {$, which Caddy expands across the whole file:\n%s", export)
	}
	if caddyBin == "" {
		return
	}
	out, err := adaptWithCaddy(caddyBin, []byte(export))
	if err != nil {
		t.Fatalf("export does not adapt: %v\n%s", err, export)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
						} `json:"match"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, srv := range cfg.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			for _, m := range r.Match {
				hosts = append(hosts, m.Host...)
			}
		}
	}
	sort.Strings(hosts)
	allowed := map[string]bool{"t2.example.com": true, "tenant-adv.example.test": true, "tenant-hdr.example.test": true}
	for _, h := range hosts {
		if !allowed[h] {
			t.Errorf("adapted export serves %q (all hosts: %v)\n%s", h, hosts, export)
		}
	}
	if strings.Contains(string(out), `"dial":"127.0.0.1:2019"`) {
		t.Errorf("adapted export proxies to the Caddy admin API:\n%s", out)
	}
}

// Issue #184 review (F): a host saved before the Path matcher check existed
// can hold a matcher that check now refuses. Toggle, bulk enable/disable,
// maintenance and delete must keep working on it; editing shows the
// translated error rather than a 500; the export fails closed.
func TestLegacyInvalidPathMatcherHostStaysManageable(t *testing.T) {
	s, conn, sid, _, admin, _ := newExportFixture(t)
	id, err := models.CreateProxyHost(conn, sid, 0, &models.ProxyHost{Domains: "legacy.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE proxy_hosts SET path_matcher=?, path_matcher_type='regexp' WHERE id=?`, "^/(unclosed\n", id); err != nil {
		t.Fatal(err)
	}
	idStr := strconv.FormatInt(id, 10)
	param := map[string]string{"id": idStr}
	enabled := func() bool {
		ph, err := models.GetProxyHost(conn, id)
		if err != nil {
			t.Fatal(err)
		}
		return ph.Enabled
	}

	rec := httptest.NewRecorder()
	s.editProxyHost(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/"+idStr+"/edit", nil), sid, admin, param))
	if rec.Code != http.StatusOK {
		t.Fatalf("edit page: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.toggleProxyHost(rec, asUser(postForm(t, "/proxy-hosts/"+idStr+"/toggle", url.Values{}), sid, admin, param))
	if rec.Code >= 400 || enabled() {
		t.Fatalf("toggle: %d, enabled=%v", rec.Code, enabled())
	}
	rec = httptest.NewRecorder()
	s.bulkToggleProxyHosts(rec, asUser(postForm(t, "/proxy-hosts/bulk-toggle", url.Values{"action": {"enable"}, "ids[]": {idStr}}), sid, admin, nil))
	if rec.Code >= 400 || !enabled() {
		t.Fatalf("bulk enable: %d, enabled=%v", rec.Code, enabled())
	}
	rec = httptest.NewRecorder()
	s.toggleMaintenanceMode(rec, asUser(postForm(t, "/proxy-hosts/"+idStr+"/maintenance", url.Values{}), sid, admin, param))
	if ph, _ := models.GetProxyHost(conn, id); rec.Code >= 400 || !ph.MaintenanceMode {
		t.Fatalf("maintenance toggle: %d", rec.Code)
	}

	form := url.Values{"domains": {"legacy.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"},
		"enabled": {"on"}, "path_matcher": {"^/(unclosed"}, "path_matcher_type": {"regexp"}}
	rec = httptest.NewRecorder()
	s.updateProxyHost(rec, asUser(postForm(t, "/proxy-hosts/"+idStr, form), sid, admin, param))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not a valid regular expression") {
		t.Fatalf("edit with the stored invalid matcher: want the form with the translated error, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.exportProxyHostCaddyfile(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/"+idStr+"/export.caddyfile", nil), sid, admin, param))
	if body := rec.Body.String(); !strings.Contains(body, "respond 503") || strings.Contains(body, "reverse_proxy") {
		t.Fatalf("export must fail closed:\n%s", body)
	}

	rec = httptest.NewRecorder()
	s.deleteProxyHost(rec, asUser(postForm(t, "/proxy-hosts/"+idStr+"/delete", url.Values{}), sid, admin, param))
	if _, err := models.GetProxyHost(conn, id); rec.Code >= 400 || err == nil {
		t.Fatalf("delete: %d, still present=%v", rec.Code, err == nil)
	}
}

// formError pulls the error banner text out of a re-rendered form.
func formError(body string) string {
	const marker = `data-toast="error"`
	i := strings.Index(body, marker)
	if i < 0 {
		return "(no error banner)"
	}
	rest := body[i:]
	if j := strings.Index(rest, ">"); j >= 0 {
		rest = rest[j+1:]
	}
	if j := strings.Index(rest, "</div>"); j >= 0 {
		rest = rest[:j]
	}
	return strings.Join(strings.Fields(rest), " ")
}

// Issue #184 round-3 review: the v1 API took json_data and caddyfile_src
// separately, and the tenant checks only saw the JSON, so a tenant could
// store JSON for its own host next to Caddyfile text claiming an admin's
// host (or a new listener) — text the server-wide export then wrote
// verbatim. The API must derive json_data from the text, and the export must
// refuse text its stored JSON does not serve (rows written before the fix).
func TestNonAdminRawRouteTextCannotClaimAnotherHostInTheExport(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	if _, err := models.CreateProxyHost(conn, sid, 0, &models.ProxyHost{Domains: "victim.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.20", ForwardPort: 8080, Enabled: true, SSLEnabled: true}); err != nil {
		t.Fatal(err)
	}
	ownJSON := `{"match":[{"host":["tenant-raw.example.test"]}],"handle":[{"handler":"static_response","body":"hi"}]}`
	api := func(method, path string, body map[string]any, params map[string]string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := asUser(httptest.NewRequest(method, path, strings.NewReader(string(raw))), sid, tenant, params)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if method == http.MethodPost {
			s.apiV1CreateRawRoute(rec, req)
		} else {
			s.apiV1UpdateRawRoute(rec, req)
		}
		return rec
	}
	hijack := "victim.example.test/admin* {\n\treverse_proxy 127.0.0.1:2019\n}"
	listener := ":2019 {\n\treverse_proxy 127.0.0.1:2019\n}"

	for _, text := range []string{hijack, listener} {
		rec := api(http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "x", "enabled": true, "json_data": ownJSON, "caddyfile_src": text}, nil)
		if rec.Code == http.StatusCreated {
			t.Errorf("create with mismatched caddyfile_src accepted:\n%s\n%s", text, rec.Body.String())
		}
		t.Logf("create refused (%d): %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	// A text-only update re-derives the JSON, so the same text is refused.
	rec := api(http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "own", "enabled": true, "json_data": ownJSON}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create JSON-only raw route: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	rec = api(http.MethodPut, "/api/v1/raw-routes/x", map[string]any{"enabled": true, "caddyfile_src": hijack}, map[string]string{"id": strconv.FormatInt(created.ID, 10)})
	if rec.Code == http.StatusOK {
		t.Errorf("text-only update with a hijacking caddyfile_src accepted: %s", rec.Body.String())
	}
	t.Logf("text-only update refused (%d): %s", rec.Code, strings.TrimSpace(rec.Body.String()))

	// Rows already stored by the old API: JSON for the tenant's host, text
	// for the victim's — and for a new listener.
	for _, text := range []string{hijack, listener} {
		rr := &models.RawRoute{Label: "legacy", Enabled: true, JSONData: ownJSON, CaddyfileSrc: text}
		if _, err := models.CreateRawRoute(conn, sid, tenant.ID, rr); err != nil {
			t.Fatal(err)
		}
	}

	rec = httptest.NewRecorder()
	s.exportServerCaddyfile(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/export-all.caddyfile", nil), sid, admin, nil))
	export := rec.Body.String()
	for _, line := range strings.Split(export, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue // the omission notes name the address; comments are inert
		}
		if strings.Contains(line, "victim.example.test/admin*") || strings.Contains(line, ":2019 {") || strings.Contains(line, "reverse_proxy 127.0.0.1:2019") {
			t.Fatalf("export carries the mismatched raw-route text (%q):\n%s", line, export)
		}
	}
	if caddyBin == "" {
		t.Run("caddy adapt", func(t *testing.T) {
			t.Skip("SKIPPED: no `caddy` binary on PATH — the API create/update checks above ran against a fake admin that cannot adapt, and the `caddy adapt` check of the export did NOT run.")
		})
		return
	}
	out, err := adaptWithCaddy(caddyBin, []byte(export))
	if err != nil {
		t.Fatalf("export does not adapt: %v\n%s", err, export)
	}
	if strings.Contains(string(out), `"dial":"127.0.0.1:2019"`) || strings.Contains(string(out), `":2019"`) {
		t.Fatalf("adapted export routes to or listens on the admin API port:\n%s", out)
	}
}

// Issue #184 round-3 review (4): cloning a host saved before the Path
// matcher check existed shows the copy in the form with the translated
// error, not a raw 500.
func TestCloneOfLegacyInvalidPathMatcherShowsTheFormError(t *testing.T) {
	s, conn, sid, _, admin, _ := newExportFixture(t)
	id, err := models.CreateProxyHost(conn, sid, 0, &models.ProxyHost{Domains: "legacy.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE proxy_hosts SET path_matcher='^/(unclosed', path_matcher_type='regexp' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	idStr := strconv.FormatInt(id, 10)
	rec := httptest.NewRecorder()
	s.cloneProxyHost(rec, asUser(postForm(t, "/proxy-hosts/"+idStr+"/clone", url.Values{}), sid, admin, map[string]string{"id": idStr}))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not a valid regular expression") {
		t.Fatalf("clone: want the form with the translated error, got %d: %.300s", rec.Code, rec.Body.String())
	}
}
