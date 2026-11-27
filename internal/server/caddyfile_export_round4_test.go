// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// exportLines returns the non-comment lines of a Caddyfile export: comments
// are inert, and the omission notes may name what was left out.
func exportLines(export string) []string {
	var out []string
	for _, line := range strings.Split(export, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, line)
		}
	}
	return out
}

// exportHas reports whether a non-comment line of export contains s.
func exportHas(export, s string) bool {
	for _, line := range exportLines(export) {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}

func exportAs(t *testing.T, s *Server, sid int64, u *models.User) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.exportServerCaddyfile(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/export-all.caddyfile", nil), sid, u, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func requireCaddy(t *testing.T, bin, what string) {
	t.Helper()
	if bin == "" {
		t.Skip("SKIPPED: no `caddy` binary on PATH — " + what + " needs Caddy's adapter and did NOT run. Put caddy on PATH to run it.")
	}
}

// tenantSiteLevelTexts are site-level directives the live config drops (it
// keeps only routes) but a verbatim export would bring back: a log file
// anywhere on the Caddy host, a unix-socket listener, a custom ACME
// directory, certificate files read from disk.
var tenantSiteLevelTexts = map[string]string{
	"log":      "\tlog {\n\t\toutput file /etc/cron.d/caddyui-x\n\t}\n",
	"bind":     "\tbind unix//run/caddyui-x.sock\n",
	"tls dir":  "\ttls {\n\t\tissuer acme {\n\t\t\tdir https://acme.caddyui-x.invalid/dir\n\t\t}\n\t}\n",
	"tls file": "\ttls /etc/caddyui-x/cert.pem /etc/caddyui-x/key.pem\n",
}

var tenantSiteLevelMarkers = []string{"/etc/cron.d/caddyui-x", "unix//run/caddyui-x.sock", "acme.caddyui-x.invalid", "/etc/caddyui-x/"}

// Issue #184 round-4 review (1): a tenant's raw-route Caddyfile or proxy
// host Advanced config with a site-level directive (log, bind, tls) passed
// every check — the live config drops those directives — and the export
// wrote it verbatim. The export must leave such text out, and the save
// paths must refuse it; an admin's text is unaffected.
func TestTenantSiteLevelDirectivesAreNotExported(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "re-adapting the tenant text at export and at save")
	const rawHost = "tenant-raw.example.test"
	rawJSON := `{"match":[{"host":["` + rawHost + `"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"body":"hi","handler":"static_response"}]}]}],"terminal":true}`

	// Rows already stored (by an older version, or by an admin for a tenant).
	for name, directive := range tenantSiteLevelTexts {
		rr := &models.RawRoute{Label: "legacy " + name, Enabled: true, JSONData: rawJSON,
			CaddyfileSrc: rawHost + " {\n" + directive + "\trespond hi\n}"}
		if _, err := models.CreateRawRoute(conn, sid, tenant.ID, rr); err != nil {
			t.Fatal(err)
		}
		ph := &models.ProxyHost{Domains: "adv-" + strings.ReplaceAll(name, " ", "-") + ".example.test", ForwardScheme: "http",
			ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true,
			AdvancedConfig: strings.ReplaceAll(strings.TrimSuffix(directive, "\n"), "\n\t", "\n")[1:]}
		if _, err := models.CreateProxyHost(conn, sid, tenant.ID, ph); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []*models.User{admin, tenant} {
		export := exportAs(t, s, sid, u)
		for _, m := range tenantSiteLevelMarkers {
			if exportHas(export, m) {
				t.Errorf("export for %s writes a tenant's site-level directive (%s):\n%s", u.Email, m, export)
			}
		}
	}

	// Save paths: the API, the Advanced route form and the proxy host form.
	for name, directive := range tenantSiteLevelTexts {
		text := rawHost + " {\n" + directive + "\trespond hi\n}"
		raw, _ := json.Marshal(map[string]any{"label": name, "enabled": true, "caddyfile_src": text})
		req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(raw))), sid, tenant, nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.apiV1CreateRawRoute(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("API create of a tenant raw route with %s: want 400, got %d %s", name, rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		s.createRawRoute(rec, asUser(postForm(t, "/raw-routes", url.Values{"label": {name}, "enabled": {"on"}, "caddyfile_src": {text}}), sid, tenant, nil))
		if rec.Code == http.StatusSeeOther || !strings.Contains(formError(rec.Body.String()), "Not allowed for a non-admin account") {
			t.Errorf("Advanced route form with %s: want a form error, got %d %s", name, rec.Code, formError(rec.Body.String()))
		}

		adv := strings.ReplaceAll(strings.TrimSuffix(directive, "\n"), "\n\t", "\n")[1:]
		rec = httptest.NewRecorder()
		s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", url.Values{"domains": {"new-" + strings.ReplaceAll(name, " ", "-") + ".example.test"},
			"forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"}, "advanced_config": {adv}}), sid, tenant, nil))
		if rec.Code == http.StatusSeeOther {
			t.Errorf("proxy host form with Advanced %s: accepted", name)
		}
	}

	// An administrator's own text is unaffected.
	adminText := "admin-raw.example.test {\n" + tenantSiteLevelTexts["log"] + "\trespond hi\n}"
	raw, _ := json.Marshal(map[string]any{"label": "admin", "enabled": true, "caddyfile_src": adminText})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(raw))), sid, admin, nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.apiV1CreateRawRoute(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin API create with a log directive: %d %s", rec.Code, rec.Body.String())
	}
	if export := exportAs(t, s, sid, admin); !exportHas(export, "output file /etc/cron.d/caddyui-x") || !exportHas(export, "admin-raw.example.test {") {
		t.Errorf("an admin's raw route must still be exported verbatim:\n%s", export)
	}
}

// Issue #184 round-4 review (2): every snippet from CADDYFILE_PATH was
// written into every server-wide export, a tenant's included. Only an
// administrator's export may carry snippets, and only those it imports.
func TestCaddyfileExportCarriesOnlyImportedSnippetsAndNoneForTenants(t *testing.T) {
	s, conn, sid, _, admin, tenant := newExportFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	snippets := "(secrets) {\n\theader X-Api-Key caddyui-topsecret\n}\n\n(common) {\n\theader X-Frame-Options DENY\n}\n"
	if err := os.WriteFile(s.CaddyfilePath, []byte(snippets), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(conn, sid, tenant.ID, &models.ProxyHost{Domains: "tenant.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(conn, sid, 0, &models.ProxyHost{Domains: "admin.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.11", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: "import common"}); err != nil {
		t.Fatal(err)
	}

	tenantExport := exportAs(t, s, sid, tenant)
	if strings.Contains(tenantExport, "caddyui-topsecret") || strings.Contains(tenantExport, "(secrets)") || strings.Contains(tenantExport, "(common)") {
		t.Errorf("a tenant's export carries the administrator's snippets:\n%s", tenantExport)
	}
	if !strings.Contains(tenantExport, "tenant.example.test {") {
		t.Errorf("the tenant's own host is missing:\n%s", tenantExport)
	}

	adminExport := exportAs(t, s, sid, admin)
	if strings.Contains(adminExport, "caddyui-topsecret") || strings.Contains(adminExport, "(secrets)") {
		t.Errorf("the admin export carries a snippet nothing imports:\n%s", adminExport)
	}
	if !strings.Contains(adminExport, "(common) {") || !strings.Contains(adminExport, "\timport common\n") {
		t.Errorf("the admin export must carry the imported snippet and keep the import:\n%s", adminExport)
	}
}

// Issue #184 round-4 review (3): a tenant's proxy-host Advanced config had
// no export veto — `{$ENV}` (which Caddy expands while loading the file)
// and file_server nested in a block went out verbatim, although the live
// route refuses both. With Caddy unreachable the export cannot re-check the
// text, so it fails closed.
func TestTenantProxyHostAdvancedConfigIsVetoedInExport(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	for i, adv := range []string{"header X-Leak {$CADDYUI_SECRET}", "handle /x {\n\troot * /\n\tfile_server browse\n}"} {
		if _, err := models.CreateProxyHost(conn, sid, tenant.ID, &models.ProxyHost{Domains: "veto" + strconv.Itoa(i) + ".example.test", ForwardScheme: "http",
			ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: adv}); err != nil {
			t.Fatal(err)
		}
	}
	benign, err := models.CreateProxyHost(conn, sid, tenant.ID, &models.ProxyHost{Domains: "benign.example.test", ForwardScheme: "http",
		ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: "header X-Benign yes"})
	if err != nil {
		t.Fatal(err)
	}
	check := func(export string) {
		t.Helper()
		for _, bad := range []string{"{$CADDYUI_SECRET}", "file_server", "root * /"} {
			if exportHas(export, bad) {
				t.Errorf("export carries a tenant's refused Advanced config (%s):\n%s", bad, export)
			}
		}
		for _, host := range []string{"veto0.example.test {", "veto1.example.test {"} {
			if !exportHas(export, host) || !strings.Contains(export, "respond 503") {
				t.Errorf("want %s to fail closed:\n%s", host, export)
			}
		}
	}
	export := exportAs(t, s, sid, admin)
	check(export)
	if caddyBin != "" && !exportHas(export, "header X-Benign yes") {
		t.Errorf("a tenant's ordinary Advanced config must still export:\n%s", export)
	}

	// The single-host export takes the same path.
	idStr := strconv.FormatInt(benign, 10)
	if _, err := conn.Exec(`UPDATE caddy_servers SET admin_url='http://127.0.0.1:1' WHERE id=?`, sid); err != nil {
		t.Fatal(err)
	}
	export = exportAs(t, s, sid, admin)
	check(export)
	if exportHas(export, "X-Benign") {
		t.Errorf("with Caddy unreachable a tenant's Advanced config must fail closed:\n%s", export)
	}
	rec := httptest.NewRecorder()
	s.exportProxyHostCaddyfile(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/"+idStr+"/export.caddyfile", nil), sid, tenant, map[string]string{"id": idStr}))
	if body := rec.Body.String(); exportHas(body, "X-Benign") || !strings.Contains(body, "respond 503") {
		t.Errorf("single-host export with Caddy unreachable must fail closed:\n%s", body)
	}
}

// Issue #184 round-4 review (5): the single-host export and the preview
// kept `import <snippet>` but not the snippet, so the text did not load on
// its own. An administrator's copy carries the definitions it imports.
func TestSingleHostCaddyfileCarriesImportedSnippets(t *testing.T) {
	s, conn, sid, _, admin, _ := newExportFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte("(secrets) {\n\theader X-Api-Key caddyui-topsecret\n}\n\n(common) {\n\theader X-Frame-Options DENY\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := models.CreateProxyHost(conn, sid, 0, &models.ProxyHost{Domains: "admin.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.11", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: "import common"})
	if err != nil {
		t.Fatal(err)
	}
	idStr := strconv.FormatInt(id, 10)
	rec := httptest.NewRecorder()
	s.exportProxyHostCaddyfile(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/"+idStr+"/export.caddyfile", nil), sid, admin, map[string]string{"id": idStr}))
	want := func(what, body string) {
		t.Helper()
		if !strings.Contains(body, "(common) {") || !strings.Contains(body, "import common") || strings.Contains(body, "caddyui-topsecret") {
			t.Errorf("%s must carry the imported snippet (and only it):\n%s", what, body)
		}
	}
	want("single-host export", rec.Body.String())

	form := url.Values{"domains": {"admin.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.11"}, "forward_port": {"8080"},
		"ssl_enabled": {"on"}, "advanced_config": {"import common"}}
	rec = httptest.NewRecorder()
	s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", form), sid, admin, nil))
	var preview struct {
		Caddyfile string `json:"caddyfile"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatalf("preview: %v %s", err, rec.Body.String())
	}
	want("preview", preview.Caddyfile)
}

// Issue #184 round-4 review (6a): a text-only PUT kept the old listen set
// when the new text named only the standard ports, so the route went on
// serving on a port its text no longer mentioned.
func TestRawRouteTextOnlyUpdateClearsCustomListen(t *testing.T) {
	s, conn, sid, caddyBin, admin, _ := newExportFixture(t)
	requireCaddy(t, caddyBin, "deriving the listen set from caddyfile_src")
	api := func(method, path string, body map[string]any, params map[string]string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := asUser(httptest.NewRequest(method, path, strings.NewReader(string(raw))), sid, admin, params)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		if method == http.MethodPost {
			s.apiV1CreateRawRoute(rec, req)
		} else {
			s.apiV1UpdateRawRoute(rec, req)
		}
		return rec
	}
	rec := api(http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "port", "enabled": true, "caddyfile_src": "listen.example.test:7070 {\n\trespond hi\n}"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if rr, _ := models.GetRawRoute(conn, created.ID); rr == nil || rr.Listen != `[":7070"]` {
		t.Fatalf("create: want listen [\":7070\"], got %+v", rr)
	}
	rec = api(http.MethodPut, "/api/v1/raw-routes/x", map[string]any{"enabled": true, "caddyfile_src": "listen.example.test {\n\trespond hi\n}"}, map[string]string{"id": strconv.FormatInt(created.ID, 10)})
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
	}
	if rr, _ := models.GetRawRoute(conn, created.ID); rr == nil || rr.Listen != "" {
		t.Fatalf("text-only update to the standard ports must clear the listen set, got %q", rr.Listen)
	}
}
