// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// round6Markers are what the review's payloads turn into when the export
// splits a quoted string: a file server rooted at / and an upstream on the
// Caddy admin API.
var round6Markers = []string{`"handler":"file_server"`, `"dial":"127.0.0.1:2019"`, `"root":"/"`}

func adaptedHasMarker(t *testing.T, caddyBin, what, text string) {
	t.Helper()
	out, err := adaptWithCaddy(caddyBin, []byte(text))
	if err != nil {
		t.Errorf("%s does not adapt: %v\n%s", what, err, text)
		return
	}
	for _, m := range round6Markers {
		if strings.Contains(string(out), m) {
			t.Errorf("%s adapts to %s:\n%s\n%s", what, m, text, out)
		}
	}
}

// Issue #184 round-5 review (1): a tenant's Advanced config holding
// `reverse_proxy {` inside a quoted string adapted (and went live) as a
// harmless `vars`, but the exporter split the string and wrote its content
// as reverse_proxy sub-directives. Saved through the real form with SSL on;
// export-all, the single-host export and the preview must all adapt to
// nothing the payload spells out.
func TestTenantQuotedReverseProxyTextStaysTextInExport(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "saving the Advanced config and adapting the exports")
	payloads := map[string]string{
		"fs.example.test":  "vars caddyui_note \"\nreverse_proxy {\n\thandle_response {\n\t\troot * /\n\t\tfile_server browse\n\t}\n}\n\"",
		"adm.example.test": "vars caddyui_note \"\nreverse_proxy {\n\tto 127.0.0.1:2019\n}\n\"",
	}
	form := func(dom, adv string) url.Values {
		return url.Values{"domains": {dom}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"},
			"enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {adv}}
	}
	for dom, adv := range payloads {
		rec := httptest.NewRecorder()
		s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form(dom, adv)), sid, tenant, nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("save %s: %d %s", dom, rec.Code, formError(rec.Body.String()))
		}
	}
	for _, u := range []*models.User{admin, tenant} {
		export := exportAs(t, s, sid, u)
		adaptedHasMarker(t, caddyBin, "export-all for "+u.Email, export)
		for dom := range payloads {
			if !exportHas(export, dom+" {") || strings.Contains(export, "respond 503") {
				t.Errorf("export for %s: %s should export (its text is harmless):\n%s", u.Email, dom, export)
			}
		}
	}
	hosts, _ := models.ListProxyHosts(conn, sid, admin.ID, true, nil)
	for _, h := range hosts {
		idStr := strconv.FormatInt(h.ID, 10)
		rec := httptest.NewRecorder()
		s.exportProxyHostCaddyfile(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/"+idStr+"/export.caddyfile", nil), sid, tenant, map[string]string{"id": idStr}))
		adaptedHasMarker(t, caddyBin, "single-host export of "+h.Domains, rec.Body.String())
	}
	for dom, adv := range payloads {
		rec := httptest.NewRecorder()
		s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", form(dom, adv)), sid, tenant, nil))
		var preview struct {
			Caddyfile string `json:"caddyfile"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
			t.Fatalf("preview: %v %s", err, rec.Body.String())
		}
		adaptedHasMarker(t, caddyBin, "preview of "+dom, preview.Caddyfile)
	}
}

// Issue #184 round-5 review (1a): the export veto judges the block that is
// written, not the Advanced text on its own. Fed a block that carries the
// payload as real directives while the stored Advanced config is the
// harmless quoted form, it objects; the block as actually rendered passes;
// and a host whose own client-certificate setting puts TLS in the block
// still exports.
func TestTenantProxyHostExportVetoJudgesTheRenderedBlock(t *testing.T) {
	s, _, _, caddyBin, _, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "adapting the rendered block")
	p := models.ProxyHost{ID: 7, Domains: "fs.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true,
		AdvancedConfig: "vars caddyui_note \"\nreverse_proxy {\n\tto 127.0.0.1:2019\n}\n\""}
	p.OwnerID.Valid, p.OwnerID.Int64 = true, tenant.ID
	for name, site := range map[string]string{
		"admin API upstream": "fs.example.test {\n\treverse_proxy 203.0.113.10:8080 {\n\t\tto 127.0.0.1:2019\n\t}\n}\n",
		"file_server":        "fs.example.test {\n\treverse_proxy 203.0.113.10:8080 {\n\t\thandle_response {\n\t\t\troot * /\n\t\t\tfile_server browse\n\t\t}\n\t}\n}\n",
		"another host":       "fs.example.test, other.example.test {\n\treverse_proxy 203.0.113.10:8080\n}\n",
		"log":                "fs.example.test {\n\tlog {\n\t\toutput file /etc/cron.d/x\n\t}\n\treverse_proxy 203.0.113.10:8080\n}\n",
		"does not adapt":     "fs.example.test {\n\ttls off\n\treverse_proxy 203.0.113.10:8080\n}\n",
	} {
		if why := s.proxyAdvancedExportVeto(s.Caddy, p, site); why == "" {
			t.Errorf("%s: the veto must object to\n%s", name, site)
		}
	}
	rendered := caddy.RenderProxyHostCaddyfile(p)
	if why := s.proxyAdvancedExportVeto(s.Caddy, p, rendered); why != "" {
		t.Errorf("the rendered block is harmless, got %q:\n%s", why, rendered)
	}
	if why := s.proxyAdvancedExportVeto(nil, p, rendered); why == "" {
		t.Errorf("without Caddy the veto must fail closed")
	}

	ca := models.ProxyHost{ID: 8, Domains: "mtls.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true,
		ClientAuthMode: "require_and_verify", ClientAuthCAFiles: "/etc/caddy/ca.pem", AdvancedConfig: "header X-Benign yes"}
	ca.OwnerID = p.OwnerID
	rendered = caddy.RenderProxyHostCaddyfile(ca)
	if !strings.Contains(rendered, "client_auth") {
		t.Fatalf("fixture: want a client_auth block:\n%s", rendered)
	}
	if why := s.proxyAdvancedExportVeto(s.Caddy, ca, rendered); why != "" {
		t.Errorf("the host's own client_auth must not block its export, got %q:\n%s", why, rendered)
	}
	// …but TLS beyond the host's own settings still does.
	extra := strings.Replace(rendered, "\t\t\tmode require_and_verify\n", "\t\t\tmode request\n", 1)
	if why := s.proxyAdvancedExportVeto(s.Caddy, ca, extra); why == "" {
		t.Errorf("TLS settings that differ from the host's own must be refused:\n%s", extra)
	}
}

// Issue #184 round-5 review (2): the generated matcher names collided with
// ones an Advanced config may define, and the duplicate made Caddy refuse
// the whole export. An admin's and a tenant's host with a path matcher and
// `@caddyui_path` / `@blocked` in the Advanced config: the export adapts.
func TestAdvancedMatcherNamesDoNotBreakTheExport(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "adapting the export")
	adv := "@caddyui_path path /zzz\n@blocked path /private\nheader @caddyui_path X-Z 1\nheader @blocked X-B 1"
	for i, owner := range []int64{0, tenant.ID} {
		if _, err := models.CreateProxyHost(conn, sid, owner, &models.ProxyHost{Domains: "match" + strconv.Itoa(i) + ".example.test", ForwardScheme: "http",
			ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true, BlockCommonExploits: true, PathMatcher: "/api", AdvancedConfig: adv}); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []*models.User{admin, tenant} {
		export := exportAs(t, s, sid, u)
		if _, err := adaptWithCaddy(caddyBin, []byte(export)); err != nil {
			t.Errorf("export for %s does not adapt: %v\n%s", u.Email, err, export)
		}
		if strings.Contains(export, "respond 503") {
			t.Errorf("export for %s: these hosts should export:\n%s", u.Email, export)
		}
	}
}

// Issue #184 round-5 review (3a): the validate button runs the same
// allowlist as the save for a tenant's Advanced route Caddyfile.
func TestTenantValidateRawRouteRefusesSiteLevelDirectives(t *testing.T) {
	s, _, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the validate button adapts with Caddy")
	validate := func(u *models.User, text string) (bool, string) {
		rec := httptest.NewRecorder()
		s.apiValidateRawRoute(rec, asUser(postForm(t, "/api/raw-routes/validate", url.Values{"caddyfile_src": {text}}), sid, u, nil))
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("validate: %v %s", err, rec.Body.String())
		}
		return out.OK, out.Error
	}
	for name, directive := range tenantSiteLevelTexts {
		text := "tenant-raw.example.test {\n" + directive + "\trespond hi\n}"
		if ok, msg := validate(tenant, text); ok || !strings.Contains(msg, "Not allowed for a non-admin account") {
			t.Errorf("tenant validate with %s: want refused, got ok=%v %q", name, ok, msg)
		}
		if name == "log" {
			if ok, msg := validate(admin, text); !ok {
				t.Errorf("admin validate with %s: want ok, got %q", name, msg)
			}
		}
	}
	if ok, msg := validate(tenant, "tenant-raw.example.test {\n\trespond hi\n}"); !ok {
		t.Errorf("tenant validate of a plain site: want ok, got %q", msg)
	}
}

// Issue #184 round-5 review (3b): an Advanced config that closes the
// synthetic site and opens a second one for the same name adapts to two
// routes, every listener and host of which the other checks accept; only
// the route count catches it.
func TestProxyAdvancedAdaptedProblemRefusesASecondRoute(t *testing.T) {
	s, _, _, caddyBin, _, _ := newExportFixture(t)
	requireCaddy(t, caddyBin, "adapting the Advanced config")
	p := models.ProxyHost{Domains: "two.example.test", AdvancedConfig: "header X-One 1\n}\nhttp://localhost {\n\theader X-Two 2"}
	result, err := s.adaptProxyAdvancedResult(s.Caddy, p)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if n := len(extractAdaptedRoutes(result)); n != 2 {
		t.Fatalf("fixture: want two routes, got %d", n)
	}
	if why := s.tenantAdaptedConfigProblem(result, map[string]bool{proxyAdvancedSite: true}, nil); why != "" {
		t.Fatalf("fixture: only the route count should object, but %q", why)
	}
	if why := s.proxyAdvancedAdaptedProblem(result); !strings.Contains(why, "adds routes beyond the host's own") {
		t.Errorf("want the second route refused, got %q", why)
	}
	single := p
	single.AdvancedConfig = "header X-One 1"
	if result, err = s.adaptProxyAdvancedResult(s.Caddy, single); err != nil {
		t.Fatal(err)
	}
	if why := s.proxyAdvancedAdaptedProblem(result); why != "" {
		t.Errorf("one route is fine, got %q", why)
	}
}

// Issue #184 round-5 review (4): `import` with a quoted name token got past
// the tenant text check, so Caddy read the named file and echoed its first
// line in the error. The save must refuse it before Caddy sees it.
func TestTenantQuotedImportNeverReachesCaddy(t *testing.T) {
	s, _, sid, caddyBin, _, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the import would be expanded by Caddy's adapter")
	for _, imp := range []string{`"import"`, "`import`", "<<I\n\timport\n\tI"} {
		text := "quoted-import.example.test {\n\t" + imp + " /etc/passwd\n}"
		raw, _ := json.Marshal(map[string]any{"label": "imp", "enabled": true, "caddyfile_src": text})
		req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(raw))), sid, tenant, nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.apiV1CreateRawRoute(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d %s", imp, rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); strings.Contains(body, "root:") || strings.Contains(body, "/bin/") {
			t.Errorf("%s: the response carries file content: %s", imp, body)
		}

		rec = httptest.NewRecorder()
		s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", url.Values{"domains": {"quoted-import.example.test"}, "forward_scheme": {"http"},
			"forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {imp + " /etc/passwd"}}), sid, tenant, nil))
		if rec.Code == http.StatusSeeOther {
			t.Errorf("%s: proxy host form accepted the import", imp)
		}
		if body := formError(rec.Body.String()); strings.Contains(body, "root:") || strings.Contains(body, "/bin/") {
			t.Errorf("%s: the form error carries file content: %s", imp, body)
		}
	}
	if why := tenantTextViolation("x.test {\n\t`import` /etc/passwd\n}"); why == "" {
		t.Errorf("tenantTextViolation must refuse a quoted import")
	}
}
