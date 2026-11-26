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

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// round7FileMarkers are what the content of the files the round-7 payloads
// name looks like: the process environment and the password file.
var round7FileMarkers = []string{"PATH=", "HOSTNAME=", "root:x:"}

func round7Leaks(body string) string {
	for _, m := range round7FileMarkers {
		if strings.Contains(body, m) {
			return m
		}
	}
	return ""
}

// round7SnippetSmuggles are the issue #184 round-7 review's payloads: a
// snippet defined in the tenant's own text whose {args…} turn an argument
// into a nested `import` of a file. Each value is {definition, call}; the
// call names FILE.
var round7SnippetSmuggles = map[string][2]string{
	"quoted":   {"(s) {\n\t{args[0]} {args[1]}\n}\n", "import s \"import\" FILE"},
	"backtick": {"(s) {\n\t{args[0]} {args[1]}\n}\n", "import s `import` FILE"},
	"heredoc":  {"(s) {\n\t{args[0]} {args[1]}\n}\n", "import s <<X\n\timport\n\tX FILE"},
	"args-dot": {"(s) {\n\t{args.0} {args.1}\n}\n", "import s \"import\" FILE"},
	"spread":   {"(s) {\n\t{args[:]}\n}\n", "import s \"import\" FILE"},
	"glob":     {"(s) {\n\t{args[0]} {args[1]}\n}\n", "import s \"import\" GLOB"},
}

// Issue #184 round-7 review (1): a tenant defined a snippet whose
// arguments become a second `import`, and Caddy read the named file and
// echoed it in the adapt error. Through every path that adapts a tenant's
// text — the raw-route API and form, the proxy host Advanced config (which
// closes the synthetic site to define the snippet), the preview and the
// validate button — the text is refused before Caddy sees it, and no
// response carries the file.
func TestTenantSnippetArgumentImportNeverReachesCaddy(t *testing.T) {
	s, _, sid, caddyBin, _, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "Caddy's adapter would expand the import")
	files := map[string][2]string{
		"environ": {"/proc/self/environ", "/proc/self/enviro*"},
		"passwd":  {"/etc/passwd", "/etc/pass*"},
	}
	for fname, file := range files {
		for name, p := range round7SnippetSmuggles {
			call := strings.NewReplacer("FILE", file[0], "GLOB", file[1]).Replace(p[1])
			what := name + "/" + fname
			raw := p[0] + "snip.example.test {\n\t" + call + "\n}"
			adv := "header X-A a\n}\n" + p[0] + "zz.example.test {\n\t" + call

			if why := tenantTextViolation(raw); why == "" {
				t.Errorf("%s: tenantTextViolation accepts the raw route text", what)
			}
			if why := tenantTextViolation(adv); why == "" {
				t.Errorf("%s: tenantTextViolation accepts the Advanced config", what)
			}

			body, _ := json.Marshal(map[string]any{"label": "imp", "enabled": true, "caddyfile_src": raw})
			req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			s.apiV1CreateRawRoute(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: raw-route API: want 400, got %d", what, rec.Code)
			}
			if m := round7Leaks(rec.Body.String()); m != "" {
				t.Errorf("%s: raw-route API response carries file content (%s): %s", what, m, rec.Body.String())
			}

			rec = httptest.NewRecorder()
			s.createRawRoute(rec, asUser(postForm(t, "/raw-routes", url.Values{"label": {"x"}, "enabled": {"on"}, "caddyfile_src": {raw}}), sid, tenant, nil))
			if rec.Code == http.StatusSeeOther {
				t.Errorf("%s: raw-route form accepted the text", what)
			}
			if m := round7Leaks(rec.Body.String()); m != "" {
				t.Errorf("%s: raw-route form carries file content (%s): %s", what, m, formError(rec.Body.String()))
			}

			form := url.Values{"domains": {"pa.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"},
				"forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {adv}}
			rec = httptest.NewRecorder()
			s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form), sid, tenant, nil))
			if rec.Code == http.StatusSeeOther {
				t.Errorf("%s: proxy host form accepted the Advanced config", what)
			}
			if m := round7Leaks(rec.Body.String()); m != "" {
				t.Errorf("%s: proxy host form carries file content (%s): %s", what, m, formError(rec.Body.String()))
			}

			rec = httptest.NewRecorder()
			s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", form), sid, tenant, nil))
			var preview struct {
				AdvancedError string `json:"advanced_error"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &preview)
			if !strings.Contains(preview.AdvancedError, "Not allowed for a non-admin account") {
				t.Errorf("%s: preview: want the Advanced config refused, got advanced_error=%q", what, preview.AdvancedError)
			}
			if m := round7Leaks(rec.Body.String()); m != "" {
				t.Errorf("%s: preview carries file content (%s): %s", what, m, rec.Body.String())
			}

			rec = httptest.NewRecorder()
			s.apiValidateRawRoute(rec, asUser(postForm(t, "/api/raw-routes/validate", url.Values{"caddyfile_src": {raw}}), sid, tenant, nil))
			var validate struct {
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &validate)
			if validate.OK || !strings.Contains(validate.Error, "Not allowed for a non-admin account") {
				t.Errorf("%s: validate: want refused, got ok=%v %q", what, validate.OK, validate.Error)
			}
			if m := round7Leaks(rec.Body.String()); m != "" {
				t.Errorf("%s: validate carries file content (%s): %s", what, m, rec.Body.String())
			}
		}
	}
}

// The round-7 import rules, one at a time, on text with nothing else
// wrong — and the forms that stay allowed.
func TestTenantTextViolationImportRules(t *testing.T) {
	for name, txt := range map[string]string{
		"snippet definition":      "(s) {\n\theader X-A a\n}\nx.test {\n\trespond hi\n}",
		"quoted snippet def":      "\"(s)\" {\n\theader X-A a\n}",
		"args placeholder":        "x.test {\n\theader X-A {args[0]}\n}",
		"args in a longer key":    "x.test {\n\theader X-A {foo args.1}\n}",
		"block placeholder":       "x.test {\n\t{block}\n}",
		"blocks placeholder":      "x.test {\n\theader X-A {blocks.a}\n}",
		"import as an argument":   "x.test {\n\timport common import\n}",
		"quoted import argument":  "x.test {\n\theader X-A \"import\"\n}",
		"import mid-line":         "x.test {\n\theader X-A b import common\n}",
		"import after open brace": "x.test { import common\n}",
	} {
		if why := tenantTextViolation(txt); why == "" {
			t.Errorf("%s: want refused:\n%s", name, txt)
		}
	}
	for name, txt := range map[string]string{
		"snippet import":          "x.test {\n\timport common\n}",
		"snippet import with arg": "x.test {\n\timport common v1\n}",
		"word containing import":  "x.test {\n\theader X-Important yes\n}",
		"placeholder":             "x.test {\n\theader X-A {http.request.uri}\n}",
		"parenthesised argument":  "x.test {\n\t@m path_regexp (a|b)\n}",
	} {
		if why := tenantTextViolation(txt); why != "" {
			t.Errorf("%s: want allowed, got %q:\n%s", name, why, txt)
		}
	}
}

// The administrator's snippets that withAutoLoadedSnippets puts ahead of a
// tenant's text are the administrator's: their definitions and {args…} do
// not count against the tenant, so a tenant can still import one by name.
// A tenant's own definition is refused even when it shares a name with one.
func TestTenantAdaptTextCheckSetsAdminSnippetsAside(t *testing.T) {
	s, _, sid, caddyBin, _, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the Advanced config is adapted with Caddy")
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte("(tag) {\n\theader X-Tag {args[0]}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	form := func(adv string) url.Values {
		return url.Values{"domains": {"snip.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"},
			"forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {adv}}
	}
	rec := httptest.NewRecorder()
	s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form("import tag v1")), sid, tenant, nil))
	if rec.Code != http.StatusSeeOther {
		t.Errorf("a tenant importing an administrator's snippet by name: want saved, got %d %s", rec.Code, formError(rec.Body.String()))
	}
	full := s.withAutoLoadedSnippets("localhost {\nheader X-B b\n}\n")
	if why := s.tenantAdaptTextViolation(full); why != "" {
		t.Errorf("the administrator's snippet prefix counted against the tenant: %q", why)
	}
	own := s.withAutoLoadedSnippets("(tag) {\n\theader X-Mine 1\n}\nlocalhost {\nimport tag\n}\n")
	if why := s.tenantAdaptTextViolation(own); why == "" {
		t.Errorf("a tenant's own snippet definition must be refused:\n%s", own)
	}
}

// Issue #184 round-7 review (2): caddyfileIndent compared every line with
// every token. A large Advanced config now renders in linear time, and
// the form refuses one over the size limit.
func TestLargeAdvancedConfigRendersQuicklyAndIsCapped(t *testing.T) {
	s, _, sid, _, admin, _ := newExportFixture(t)
	big := strings.Repeat("header X-A \"a\"\n", maxProxyAdvancedConfigBytes/15+10)
	if len(big) <= maxProxyAdvancedConfigBytes {
		t.Fatalf("fixture: %d bytes is not over the limit", len(big))
	}
	form := url.Values{"domains": {"big.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"},
		"forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {big}}
	rec := httptest.NewRecorder()
	s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form), sid, admin, nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too large") {
		t.Errorf("save: want 400 too large, got %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", form), sid, admin, nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too large") {
		t.Errorf("preview: want 400 too large, got %d %s", rec.Code, rec.Body.String())
	}
	form.Set("advanced_config", big[:maxProxyAdvancedConfigBytes-100])
	rec = httptest.NewRecorder()
	s.apiPreviewProxyHost(rec, asUser(postForm(t, "/api/proxy-hosts/preview", form), sid, admin, nil))
	if rec.Code == http.StatusBadRequest {
		t.Errorf("preview under the limit: got 400 %s", rec.Body.String())
	}
}

// Issue #184 round-7 review (3): a tenant's row stored without the save
// checks (an older version, a path that skipped them) and WITHOUT an
// Advanced config exported its fields verbatim, while the live sync
// neutralises or skips them. Every tenant host and redirect is now held to
// the live sync's rules; export-all (admin and tenant) and the single-host
// export fail closed for the bad rows, and the rest still adapts.
func TestLegacyTenantRowsFailClosedInExport(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	bad := map[string]*models.ProxyHost{
		"resp.example.test":      {CustomRespHeaders: `{"X-Leak":"{env.SECRET}","X-File":"{file./etc/hostname}"}`},
		"req.example.test":       {CustomReqHeaders: `{"X-Up":"{env.SECRET}"}`},
		"hostovr.example.test":   {UpstreamHostOverride: "{env.SECRET}"},
		"upstream.example.test":  {ForwardHost: "127.0.0.1", ForwardPort: 2019},
		"port.example.test:2019": {},
	}
	for dom, h := range bad {
		h.Domains, h.ForwardScheme, h.Enabled, h.SSLEnabled = dom, "http", true, true
		if h.ForwardHost == "" {
			h.ForwardHost, h.ForwardPort = "203.0.113.10", 8080
		}
		if _, err := models.CreateProxyHost(conn, sid, tenant.ID, h); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := models.CreateProxyHost(conn, sid, tenant.ID, &models.ProxyHost{Domains: "good.example.test", ForwardScheme: "http",
		ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true, CustomRespHeaders: `{"X-Ok":"fine"}`}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateRedirectionHost(conn, sid, tenant.ID, &models.RedirectionHost{Domains: "redir.example.test", ForwardScheme: "https",
		ForwardDomain: "{env.SECRET}", ForwardHTTPCode: 302, Enabled: true, SSLEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateRedirectionHost(conn, sid, tenant.ID, &models.RedirectionHost{Domains: "goodredir.example.test", ForwardScheme: "https",
		ForwardDomain: "target.example.test", ForwardHTTPCode: 302, Enabled: true, SSLEnabled: true}); err != nil {
		t.Fatal(err)
	}
	// An administrator's own row may use what it likes.
	if _, err := models.CreateProxyHost(conn, sid, 0, &models.ProxyHost{Domains: "adminenv.example.test", ForwardScheme: "http",
		ForwardHost: "127.0.0.1", ForwardPort: 9000, Enabled: true, SSLEnabled: true, CustomRespHeaders: `{"X-Env":"{env.HOME}"}`}); err != nil {
		t.Fatal(err)
	}
	secrets := []string{"{env.SECRET}", "{file./etc/hostname}", "127.0.0.1:2019"}
	failedClosed := func(export, dom string) bool {
		export = "\n" + export
		i := strings.Index(export, "\n"+dom+" {\n")
		return i >= 0 && strings.HasPrefix(export[i+len(dom)+4:], "\t# Not exported: ") &&
			strings.Contains(export[i:], "respond 503")
	}
	for _, u := range []*models.User{admin, tenant} {
		export := exportAs(t, s, sid, u)
		for _, sec := range secrets {
			if strings.Contains(export, sec) {
				t.Errorf("export for %s carries %s:\n%s", u.Email, sec, export)
			}
		}
		for dom := range bad {
			if dom == "port.example.test:2019" {
				if strings.Contains(export, dom+" {") || !strings.Contains(export, "omitted: its domains are not plain host names") {
					t.Errorf("export for %s: %s must be left out (its address would open a listener):\n%s", u.Email, dom, export)
				}
				continue
			}
			if !failedClosed(export, dom) {
				t.Errorf("export for %s: %s must fail closed:\n%s", u.Email, dom, export)
			}
		}
		if !failedClosed(export, "redir.example.test") {
			t.Errorf("export for %s: the redirect must fail closed:\n%s", u.Email, export)
		}
		for _, dom := range []string{"good.example.test", "goodredir.example.test"} {
			if failedClosed(export, dom) || !exportHas(export, dom+" {") {
				t.Errorf("export for %s: %s should export:\n%s", u.Email, dom, export)
			}
		}
		if u == admin && !strings.Contains(export, "{env.HOME}") {
			t.Errorf("an administrator's own host must export as it is:\n%s", export)
		}
		if caddyBin != "" {
			out, err := adaptWithCaddy(caddyBin, []byte(export))
			if err != nil {
				t.Errorf("export for %s does not adapt: %v\n%s", u.Email, err, export)
			} else if strings.Contains(string(out), "{env.SECRET}") || strings.Contains(string(out), "/etc/hostname") {
				t.Errorf("export for %s adapts to a live placeholder", u.Email)
			}
		}
	}
	hosts, _ := models.ListProxyHosts(conn, sid, admin.ID, true, nil)
	for _, h := range hosts {
		if bad[h.Domains] == nil || h.Domains == "port.example.test:2019" {
			continue
		}
		idStr := strconv.FormatInt(h.ID, 10)
		for _, u := range []*models.User{admin, tenant} {
			rec := httptest.NewRecorder()
			s.exportProxyHostCaddyfile(rec, asUser(httptest.NewRequest(http.MethodGet, "/proxy-hosts/"+idStr+"/export.caddyfile", nil), sid, u, map[string]string{"id": idStr}))
			if !failedClosed(rec.Body.String(), h.Domains) {
				t.Errorf("single-host export of %s for %s must fail closed:\n%s", h.Domains, u.Email, rec.Body.String())
			}
		}
	}
	if caddyBin == "" {
		t.Log("SKIPPED part: no `caddy` binary on PATH — the exports were not adapted")
	}
}

// Issue #184 round-7 review (4): forward_auth and php_fastcgi take response
// matchers of their own, like reverse_proxy, and a block's own matcher
// definitions are seen by the blocks nested in it wherever they sit.
// checkCaddyfileSites must agree with Caddy on both — checked through the
// export of an admin host (whose Advanced config is kept verbatim) and
// against `caddy adapt`.
func TestExportMatcherNamespacesAgreeWithCaddy(t *testing.T) {
	_, _, _, caddyBin, _, _ := newExportFixture(t)
	requireCaddy(t, caddyBin, "comparing with Caddy's adapter")
	for name, c := range map[string]struct {
		adv   string
		valid bool
	}{
		"forward_auth response matcher": {"@a path /a\nheader @a X-A 1\nforward_auth 203.0.113.20:9000 {\n\turi /auth\n\t@a status 2xx\n\thandle_response @a {\n\t\trespond ok\n\t}\n}", true},
		"php_fastcgi response matcher":  {"@a path /a\nheader @a X-A 1\nphp_fastcgi 203.0.113.20:9000 {\n\t@a status 2xx\n\thandle_response @a {\n\t\trespond ok\n\t}\n}", true},
		"nested before outer":           {"handle /h {\n\t@x path /h/x\n\trespond @x 1\n}\n@x path /y\nheader @x X-Y 1", false},
		"nested after outer":            {"@x path /y\nheader @x X-Y 1\nhandle /h {\n\t@x path /h/x\n\trespond @x 1\n}", false},
		"nested, distinct names":        {"handle /h {\n\t@x path /h/x\n\trespond @x 1\n}\n@y path /y\nheader @y X-Y 1", true},
	} {
		p := models.ProxyHost{ID: 1, Domains: "ns.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, AdvancedConfig: c.adv}
		out := caddy.RenderProxyHostCaddyfile(p)
		_, adaptErr := adaptWithCaddy(caddyBin, []byte(out))
		if adaptErr != nil && !strings.Contains(out, "respond 503") {
			t.Errorf("%s: the export does not load in Caddy (%v):\n%s", name, adaptErr, out)
		}
		if c.valid {
			if adaptErr != nil || strings.Contains(out, "Not exported") {
				t.Errorf("%s: want exported as written (adapt err %v):\n%s", name, adaptErr, out)
			}
			continue
		}
		if !strings.Contains(out, "Not exported") {
			t.Errorf("%s: Caddy refuses this text; want it fail closed:\n%s", name, out)
		}
		site := "x.test {\n" + c.adv + "\n}\n"
		if _, err := adaptWithCaddy(caddyBin, []byte(site)); err == nil {
			t.Errorf("%s: fixture: Caddy accepts the text on its own", name)
		}
	}
}

// Issue #184 round-7 review (5): an administrator's snippet that defines
// @blocked, imported by a host with Block common exploits on, broke the
// whole export: the generated matcher took the same name. Generated names
// now avoid names defined in imported snippets too.
func TestSnippetMatcherNamesDoNotBreakTheExport(t *testing.T) {
	s, conn, sid, caddyBin, admin, _ := newExportFixture(t)
	requireCaddy(t, caddyBin, "adapting the export")
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte("(blk) {\n\t@blocked path /x\n\trespond @blocked 404\n}\n\n(pth) {\n\t@caddyui_path path /p\n\theader @caddyui_path X-P 1\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i, adv := range []string{"import blk", "import pth"} {
		if _, err := models.CreateProxyHost(conn, sid, 0, &models.ProxyHost{Domains: "snipm" + strconv.Itoa(i) + ".example.test", ForwardScheme: "http",
			ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true, BlockCommonExploits: true, PathMatcher: "/api", AdvancedConfig: adv}); err != nil {
			t.Fatal(err)
		}
	}
	export := exportAs(t, s, sid, admin)
	if strings.Contains(export, "respond 503") {
		t.Errorf("these hosts should export:\n%s", export)
	}
	if _, err := adaptWithCaddy(caddyBin, []byte(export)); err != nil {
		t.Errorf("the export does not adapt: %v\n%s", err, export)
	}
}

// Issue #184 round-7 review (6): end to end, the export veto must judge the
// block as written, not the Advanced text on its own. A tenant's
// `reverse_proxy { lb_policy … }` block is merged into the host's own
// handler live, and adapts fine on its own; written into the generated
// reverse_proxy block of a host that sets its own policy, it is a second
// lb_policy, which Caddy refuses. Judged in place, the host fails closed
// and export-all still loads; judged alone, it would be written and the
// whole export would fail to load.
func TestTenantExportVetoSeesTheAdvancedTextInPlace(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the export veto adapts with Caddy")
	h := &models.ProxyHost{Domains: "inplace.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
		ExtraUpstreams: `["203.0.113.11:8080"]`, LBPolicy: "round_robin", Enabled: true, SSLEnabled: true,
		AdvancedConfig: "reverse_proxy {\n\tlb_policy first\n}"}
	if _, err := models.CreateProxyHost(conn, sid, tenant.ID, h); err != nil {
		t.Fatal(err)
	}
	alone := "inplace.example.test {\n" + h.AdvancedConfig + "\n}\n"
	if _, err := adaptWithCaddy(caddyBin, []byte(alone)); err != nil {
		t.Fatalf("fixture: the Advanced config should adapt on its own: %v", err)
	}
	if _, err := models.CreateProxyHost(conn, sid, tenant.ID, &models.ProxyHost{Domains: "plain.example.test", ForwardScheme: "http",
		ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*models.User{admin, tenant} {
		export := exportAs(t, s, sid, u)
		if !strings.Contains(export, "inplace.example.test {\n\t# Not exported: ") {
			t.Errorf("export for %s: the host must fail closed:\n%s", u.Email, export)
		}
		if _, err := adaptWithCaddy(caddyBin, []byte(export)); err != nil {
			t.Errorf("export for %s does not load: %v\n%s", u.Email, err, export)
		}
	}
}
