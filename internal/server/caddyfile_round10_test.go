// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// round10Secret is the content of a file planted where Caddy resolves a
// relative `import`: it shows up in a result only if Caddy read the file.
const round10Secret = "planted-secret-184"

// round10AdminSnippet is the administrator's snippet the lookalikes shadow.
const round10AdminSnippet = "(tag) {\n\tX-Tag yes\n}"

// round10Lookalikes are a non-admin's texts — [raw route, Advanced config]
// — holding a value that looks like a `(tag) { }` definition to a scanner
// that does not read quotes the way Caddy does, and importing the
// administrator's snippet tag. Before the fix the snippet was then left
// out of the text sent to Caddy, which read a file named tag instead.
var round10Lookalikes = map[string][2]string{
	"backtick": {
		"bt.example.test {\n\trespond `}\n(tag) {\n}\n{` 200\n\theader {\n\t\timport tag\n\t}\n}",
		"header X-Note `}\n(tag) {\n}\n{`\nheader {\n\timport tag\n}",
	},
	"heredoc": {
		"hd.example.test {\n\trespond <<EOF\n\t}\n\t(tag) {\n\t}\n\t{\n\tEOF 200\n\theader {\n\t\timport tag\n\t}\n}",
		"header X-Note <<EOF\n}\n(tag) {\n}\n{\nEOF\nheader {\n\timport tag\n}",
	},
}

// newPlantedAdaptFixture is newAdaptRecorderFixture whose /adapt also runs
// the real Caddy (when on PATH) on the text, next to a file named tag
// holding round10Secret — where Caddy resolves `import tag` when no
// snippet tag is defined. The administrator's Caddyfile defines tag.
func newPlantedAdaptFixture(t *testing.T) (*Server, *sql.DB, int64, *adaptRecorder, string, *models.User, *models.User) {
	t.Helper()
	s, conn, sid, rec, admin, tenant := newAdaptRecorderFixture(t)
	bin, _ := lookPathCaddy()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config"):
			_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
		case r.URL.Path == "/adapt":
			b, _ := io.ReadAll(r.Body)
			rec.mu.Lock()
			rec.bodies = append(rec.bodies, string(b))
			rec.mu.Unlock()
			if bin == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"`+round8Marker+`"}`)
				return
			}
			out, err := adaptWithCaddyFiles(bin, b, map[string]string{"tag": "X-Planted " + round10Secret + "\n"})
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
	t.Cleanup(fake.Close)
	if _, err := conn.Exec(`UPDATE caddy_servers SET admin_url = ? WHERE id = ?`, fake.URL, sid); err != nil {
		t.Fatal(err)
	}
	s.Caddy = caddy.New(fake.URL, "", "")
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(round10AdminSnippet+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return s, conn, sid, rec, bin, admin, tenant
}

// adaptWithCaddyFiles is adaptWithCaddy with extra files next to the
// Caddyfile.
func adaptWithCaddyFiles(bin string, caddyfile []byte, files map[string]string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "caddyui-adapt-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	return adaptWithCaddyIn(bin, dir, caddyfile)
}

func lookPathCaddy() (string, error) { return exec.LookPath("caddy") }

// adaptWithCaddyIn runs `caddy adapt` on caddyfile written into dir.
func adaptWithCaddyIn(bin, dir string, caddyfile []byte) ([]byte, error) {
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

// Issue #184 round-9 review (1): a non-admin's value that looks like a
// definition of the administrator's snippet no longer keeps that snippet
// out of what Caddy adapts. On every path the text reaches Caddy, and
// every text that does carries the administrator's definition.
func TestTenantSnippetLookalikeNeverHidesTheAdminSnippet(t *testing.T) {
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(round10AdminSnippet+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, c := range round10Lookalikes {
		rec.reset()
		resps := tenantCaddyfilePaths(t, s, conn, sid, tenant, c[0], c[1])
		seen := rec.seen()
		if len(seen) < len(resps) {
			t.Errorf("%s: want every path to reach the adapter, got %d adapt calls for %d paths", name, len(seen), len(resps))
			for path, resp := range resps {
				t.Logf("%s: %s: %d %.300s", name, path, resp.Code, formError(resp.Body.String())+resp.Body.String())
			}
		}
		for _, body := range seen {
			if !strings.Contains(body, round10AdminSnippet) {
				t.Errorf("%s: the administrator's snippet is missing from a text sent to Caddy:\n%s", name, body)
			}
		}
	}
}

// Issue #184 round-9 review (1), end to end with Caddy: the lookalike
// never makes Caddy read a file named after the snippet — not into a
// response, a stored route, or the live config — and the administrator's
// snippet is what the text gets.
func TestTenantSnippetLookalikeNeverReadsAFile(t *testing.T) {
	for name, c := range round10Lookalikes {
		t.Run(name, func(t *testing.T) { lookalikeNeverReadsAFile(t, name, c) })
	}
}

func lookalikeNeverReadsAFile(t *testing.T, name string, c [2]string) {
	s, conn, sid, _, bin, admin, tenant := newPlantedAdaptFixture(t)
	requireCaddy(t, bin, "the tenant's text is adapted with Caddy next to a planted file")
	{
		resps := tenantCaddyfilePaths(t, s, conn, sid, tenant, c[0], c[1])
		for path, resp := range resps {
			body := resp.Body.String()
			if strings.Contains(body, round10Secret) {
				t.Errorf("%s: %s: the planted file's content is in the response: %.400s", name, path, body)
			}
			switch path {
			case "raw-route API create":
				if resp.Code != http.StatusCreated {
					t.Errorf("%s: %s: want 201, got %d %s", name, path, resp.Code, body)
				}
			case "raw-route form create", "proxy host form create":
				if resp.Code != http.StatusSeeOther {
					t.Errorf("%s: %s: want saved, got %d %s", name, path, resp.Code, formError(body))
				}
			case "proxy host form update":
				// tenantCaddyfilePaths updates a second host to the domain
				// the form create just took; only that may stop it.
				if resp.Code != http.StatusSeeOther && !strings.Contains(formError(body), "already in use") {
					t.Errorf("%s: %s: want saved, got %d %s", name, path, resp.Code, formError(body))
				}
			case "raw-route validate":
				if !strings.Contains(body, `"ok":true`) {
					t.Errorf("%s: %s: want ok, got %s", name, path, body)
				}
			}
		}
	}
	raws, _ := models.ListRawRoutes(conn, sid, admin.ID, true, nil)
	proxies, _ := models.ListProxyHosts(conn, sid, admin.ID, true, nil)
	tagged := 0
	for _, rr := range raws {
		if strings.Contains(rr.JSONData, round10Secret) {
			t.Errorf("raw route %d stored the planted file's content: %s", rr.ID, rr.JSONData)
		}
		if strings.Contains(rr.JSONData, "X-Tag") {
			tagged++
		}
	}
	if tagged == 0 {
		t.Errorf("no stored raw route carries the administrator's snippet")
	}
	live, _ := json.Marshal(s.buildMergedRoutes(proxies, nil, raws))
	if strings.Contains(string(live), round10Secret) || !strings.Contains(string(live), "X-Tag") {
		t.Errorf("live routes: want the administrator's snippet and no planted content: %s", live)
	}
	if export := exportAs(t, s, sid, admin); strings.Contains(export, round10Secret) {
		t.Errorf("the export carries the planted file's content:\n%s", export)
	}
}

// Issue #184 round-9 review (1): a non-admin's Advanced route stored by an
// earlier version from such a text carries the planted file in its JSON.
// The live sync adapts its text again, the way a save does now, and
// deploys only that; when that cannot be done the route is not deployed,
// on srv0 or on its own listener.
func TestStoredTenantRouteThatHidTheAdminSnippetIsAdaptedAgain(t *testing.T) {
	leaked := func(id int64, owner int64, listen string) models.RawRoute {
		return models.RawRoute{ID: id, Label: "legacy", Enabled: true, Listen: models.NormalizeRawRouteListen([]string{listen}), OwnerID: sql.NullInt64{Int64: owner, Valid: true},
			CaddyfileSrc: strings.Replace(round10Lookalikes["backtick"][0], "bt.example.test", "bt.example.test"+listen, 1),
			JSONData:     `{"match":[{"host":["bt.example.test"]}],"handle":[{"handler":"headers","response":{"set":{"X-Planted":["` + round10Secret + `"]}}}]}`}
	}
	// Without a working adapter: not deployed, and no listener.
	s, _, _, rec, _, tenant := newAdaptRecorderFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(round10AdminSnippet+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raws := []models.RawRoute{leaked(1, tenant.ID, ""), leaked(2, tenant.ID, ":7070")}
	live, _ := json.Marshal(s.buildMergedRoutes(nil, nil, raws))
	listeners, _ := json.Marshal(s.buildRawListenServers(raws))
	if strings.Contains(string(live)+string(listeners), round10Secret) {
		t.Errorf("a stored route carrying a file Caddy read was deployed: %s %s", live, listeners)
	}
	if strings.Contains(string(listeners), "7070") {
		t.Errorf("a route that is not deployed opened its listener: %s", listeners)
	}
	for _, body := range rec.seen() {
		if !strings.Contains(body, round10AdminSnippet) {
			t.Errorf("the text adapted again lacks the administrator's snippet:\n%s", body)
		}
	}
	// With Caddy: the route is deployed as its text adapts today.
	s2, _, _, _, bin, _, tenant2 := newPlantedAdaptFixture(t)
	requireCaddy(t, bin, "the stored route is adapted again with Caddy")
	live, _ = json.Marshal(s2.buildMergedRoutes(nil, nil, []models.RawRoute{leaked(1, tenant2.ID, "")}))
	if strings.Contains(string(live), round10Secret) || !strings.Contains(string(live), "X-Tag") {
		t.Errorf("want the route adapted again with the administrator's snippet: %s", live)
	}
}

// Issue #184 round-9 review (3): a non-admin's Advanced route that is not
// deployed opens no listener of its own; an administrator's, and a
// non-admin's that is deployed, still do.
func TestNotDeployedTenantRawRouteOpensNoListener(t *testing.T) {
	s, _, _, _, admin, tenant := newAdaptRecorderFixture(t)
	route := func(id, owner int64, listen, src, handler string) models.RawRoute {
		return models.RawRoute{ID: id, Label: "l", Enabled: true, Listen: models.NormalizeRawRouteListen([]string{listen}), CaddyfileSrc: src, OwnerID: sql.NullInt64{Int64: owner, Valid: true},
			JSONData: `{"handle":[{"handler":"` + handler + `"}]}`}
	}
	raws := []models.RawRoute{
		route(1, tenant.ID, ":7070", ":7070 {\n\timport secrets\n}", "static_response"), // text refused
		route(2, tenant.ID, ":7071", "", "file_server"),                                 // route refused
		route(3, admin.ID, ":7072", ":7072 {\n\timport secrets\n}", "file_server"),
		route(4, tenant.ID, ":7073", "", "static_response"),
	}
	got := s.buildRawListenServers(raws)
	for _, want := range []struct {
		port string
		open bool
	}{{"7070", false}, {"7071", false}, {"7072", true}, {"7073", true}} {
		found := false
		for name := range got {
			if strings.HasSuffix(name, want.port) {
				found = true
			}
		}
		if found != want.open {
			t.Errorf(":%s: listener open=%v, want %v (servers %v)", want.port, found, want.open, got)
		}
	}
}

// round10BudgetSnippets are administrator snippets for the import budget:
// sec is about 2 KB, big about 20 KB, outer imports big twice, deep nests
// ten blocks, c1/c2 import each other, f imports a file.
func round10BudgetSnippets() string {
	var b strings.Builder
	b.WriteString("(sec) {\n")
	for i := range 50 {
		fmt.Fprintf(&b, "\theader X-Sec-%02d \"aaaaaaaaaaaaaaaaaaaaa\"\n", i)
	}
	b.WriteString("}\n(big) {\n")
	for i := range 500 {
		fmt.Fprintf(&b, "\theader X-Big-%03d \"bbbbbbbbbbbbbbbbbbbbb\"\n", i)
	}
	b.WriteString("}\n(outer) {\n\timport big\n\timport big\n}\n")
	b.WriteString("(small) {\n\theader X-Small s\n}\n")
	b.WriteString("(deep) {\n" + strings.Repeat("route {\n", 10) + "respond 1\n" + strings.Repeat("}\n", 10) + "}\n")
	b.WriteString("(c1) {\n\timport c2\n}\n(c2) {\n\timport c1\n}\n(f) {\n\timport common\n}\n")
	return b.String()
}

// Issue #184 round-9 review (2): imports multiplied a non-admin's text
// past the size and depth bounds (one adapt peaked at 1.3 GB). Each import
// now counts as the snippet it expands to, and the number of imports is
// capped; text over the budget is refused on every path before Caddy sees
// it, and is neither adapted by the live sync nor deployed from storage.
func TestImportAmplificationNeverReachesCaddy(t *testing.T) {
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(round10BudgetSnippets()), 0o644); err != nil {
		t.Fatal(err)
	}
	sizes := map[string]int{}
	for _, sn := range caddy.CaddyfileSnippets(round10BudgetSnippets()) {
		sizes[sn.Name] = sn.BodyBytes
	}
	if sizes["sec"] < 1800 || sizes["big"] < 18000 {
		t.Fatalf("fixture: snippet sizes %v", sizes)
	}
	// No newline after the site: the save paths trim the text.
	site := func(body string) string { return "amp.example.test {\n" + body + "}" }
	// The review's shape: 31 nested routes holding ~5,900 imports.
	repro := strings.Repeat("route {\n", 31) + strings.Repeat("import sec\n", 5900) + strings.Repeat("}\n", 31)
	// Just over: three imports of big plus own text past 64 KiB in all.
	overBy := func(wrapper int) string {
		imports := "import big\nimport big\nimport big\n"
		pad := maxTenantCaddyfileBytes - 3*sizes["big"] - len(imports) - wrapper + 1
		return imports + "header X-Pad \"" + strings.Repeat("p", pad-len("header X-Pad \"\"\n")) + "\"\n"
	}
	wrapper := len(site(""))
	if n := len(site(overBy(wrapper))) + 3*sizes["big"]; n != maxTenantCaddyfileBytes+1 {
		t.Fatalf("fixture: the just-over text expands to %d bytes", n)
	}
	cases := map[string][2]string{
		"the review's repro":             {site(repro), repro},
		"just over 64 KiB once expanded": {site(overBy(wrapper)), overBy(0)},
		"17 imports":                     {site(strings.Repeat("import small\n", 17)), strings.Repeat("import small\n", 17)},
		"snippet importing a snippet":    {site("import outer\nimport outer\n"), "import outer\nimport outer\n"},
		"depth once expanded":            {site(strings.Repeat("route {\n", 24) + "import deep\n" + strings.Repeat("}\n", 24)), strings.Repeat("route {\n", 24) + "import deep\n" + strings.Repeat("}\n", 24)},
		"snippets importing each other":  {site("import c1\n"), "import c1\n"},
		"a snippet importing a file":     {site("import f\n"), "import f\n"},
	}
	for name, c := range cases {
		rec.reset()
		for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, c[0], c[1]) {
			if why := tenantPathRefused(path, resp); why != "" {
				t.Errorf("%s: %s: %s: %.300s", name, path, why, resp.Body.String())
			}
		}
		if seen := rec.seen(); len(seen) > 0 {
			t.Errorf("%s: %d Caddyfile(s) reached the adapter (first %d bytes)", name, len(seen), len(seen[0]))
		}
		// Rows stored by an earlier version: the sync neither adapts the
		// Advanced config nor deploys the route.
		rec.reset()
		p := models.ProxyHost{ID: 7, Domains: "amp.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, AdvancedConfig: c[1], OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true}}
		rr := models.RawRoute{ID: 8, Label: "amp", Enabled: true, CaddyfileSrc: c[0], OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true},
			JSONData: `{"match":[{"host":["amp-stored.example.test"]}],"handle":[{"handler":"static_response","body":"stored"}]}`}
		live, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, []models.RawRoute{rr}))
		if n := len(rec.seen()); n > 0 {
			t.Errorf("%s: the live sync sent the Advanced config to the adapter %d time(s)", name, n)
		}
		if strings.Contains(string(live), "amp-stored") {
			t.Errorf("%s: the stored route was deployed", name)
		}
	}
}

// Issue #184 round 10 (2): a non-admin importing the administrator's
// snippets within the budget still saves, through Caddy, on the raw-route
// and Advanced-config paths, and the live route carries them.
func TestTenantImportingAdminSnippetsWithinBudgetSaves(t *testing.T) {
	s, conn, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the tenant's text is adapted with Caddy")
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	snips := "(sec) {\n" + strings.Repeat("\theader X-Sec \"aaaaaaaaaaaaaaaaaaaa\"\n", 50) + "}\n(small) {\n\theader X-Small s\n}\n(both) {\n\timport small\n\timport sec\n}\n"
	if err := os.WriteFile(s.CaddyfilePath, []byte(snips), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := "ok.example.test {\n\timport sec\n\troute {\n\t\timport small\n\t}\n\timport both\n\timport both\n\trespond 1\n}"
	body, _ := json.Marshal(map[string]any{"label": "ok", "enabled": true, "caddyfile_src": raw})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.apiV1CreateRawRoute(rec, req)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "X-Small") {
		t.Errorf("raw route importing snippets four times: want 201, got %d %s", rec.Code, rec.Body.String())
	}
	form := hostFormValues("okadv.example.test", "import sec\nimport small\nimport both")
	rec = httptest.NewRecorder()
	s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form), sid, tenant, nil))
	if rec.Code != http.StatusSeeOther {
		t.Errorf("Advanced config importing snippets: want saved, got %d %s", rec.Code, formError(rec.Body.String()))
	}
	proxies, _ := models.ListProxyHosts(conn, sid, admin.ID, true, nil)
	live, _ := json.Marshal(s.buildMergedRoutes(proxies, nil, nil))
	if !strings.Contains(string(live), "X-Sec") || !strings.Contains(string(live), "X-Small") {
		t.Errorf("the live route dropped the administrator's snippets: %s", live)
	}
}

// hostFormValues is a minimal proxy host form with an Advanced config.
func hostFormValues(domain, adv string) map[string][]string {
	return map[string][]string{"domains": {domain}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"},
		"forward_port": {"8080"}, "enabled": {"on"}, "ssl_enabled": {"on"}, "advanced_config": {adv}}
}

// Issue #184 round 10 (2): the budget arithmetic, exactly at its limits.
func TestImportBudgetLimits(t *testing.T) {
	set := tenantSnippetSet{
		"a":    {Name: "a", BodyBytes: 1000, Depth: 2},
		"b":    {Name: "b", BodyBytes: 500, Depth: 1, Imports: []caddy.CaddyfileImport{{Name: "a", Depth: 1}, {Name: "a", Depth: 3}}},
		"loop": {Name: "loop", Imports: []caddy.CaddyfileImport{{Name: "loop"}}},
		"file": {Name: "file", Imports: []caddy.CaddyfileImport{{Name: "secrets"}}},
		"tiny": {Name: "tiny"},
	}
	limit := 4096
	fill := func(n int) string { return "header X \"" + strings.Repeat("x", n-len("header X \"\"\n")) + "\"\n" }
	own := "import b\n"
	// b = 500 + 2×1000; depth = max(1, 1+2, 3+2) = 5.
	at := own + fill(limit-2500-len(own))
	if len(at)+2500 != limit {
		t.Fatalf("fixture: %d", len(at)+2500)
	}
	if why := tenantTextRules(at, set, 32, limit); why != "" {
		t.Errorf("exactly at the budget: %q", why)
	}
	if why := tenantTextRules(at+"#\n", set, 32, limit); !strings.Contains(why, "once the snippets it imports are counted") {
		t.Errorf("one byte over: %q", why)
	}
	nested := func(levels int, line string) string {
		return strings.Repeat("route {\n", levels) + line + strings.Repeat("}\n", levels)
	}
	if why := tenantTextRules(nested(27, "import b\n"), set, 32, 0); why != "" {
		t.Errorf("depth 27+5: %q", why)
	}
	if why := tenantTextRules(nested(28, "import b\n"), set, 32, 0); !strings.Contains(why, "33 levels deep once") {
		t.Errorf("depth 28+5: %q", why)
	}
	if why := tenantTextRules(strings.Repeat("import tiny\n", tenantMaxImports), set, 32, limit); why != "" {
		t.Errorf("%d imports: %q", tenantMaxImports, why)
	}
	if why := tenantTextRules(strings.Repeat("import tiny\n", tenantMaxImports+1), set, 32, limit); !strings.Contains(why, "`import` lines") {
		t.Errorf("%d imports: %q", tenantMaxImports+1, why)
	}
	if why := tenantTextRules("import loop\n", set, 32, limit); !strings.Contains(why, "imports itself") {
		t.Errorf("a cycle: %q", why)
	}
	if why := tenantTextRules("import file\n", set, 32, limit); !strings.Contains(why, "not a snippet") {
		t.Errorf("a file import inside a snippet: %q", why)
	}
}

// Issue #184 round-9 review (6): nesting is bounded for every kind of
// block — not only `handle` — on every path, before Caddy sees the text;
// text at the limit is accepted.
func TestNestingOfEveryBlockKindIsBounded(t *testing.T) {
	kinds := map[string]string{
		"route": "route {", "handle_path": "handle_path /p/* {", "matcher": "@m {", "header": "header {", "reverse_proxy": "reverse_proxy {",
	}
	for name, k := range kinds {
		nest := func(n int) string { return strings.Repeat(k+"\n", n) + "respond 1\n" + strings.Repeat("}\n", n) }
		if why := tenantTextViolation("x.test {\n" + nest(tenantMaxNestingDepth-1) + "}\n"); why != "" {
			t.Errorf("%s at the limit: %q", name, why)
		}
		if why := tenantTextViolation("x.test {\n" + nest(tenantMaxNestingDepth) + "}\n"); !strings.Contains(why, "levels deep") {
			t.Errorf("%s one over the limit: %q", name, why)
		}
	}
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	for name, k := range kinds {
		inner := strings.Repeat(k+"\n", 60) + "respond 1\n" + strings.Repeat("}\n", 60)
		rec.reset()
		for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, "deep.example.test {\n"+inner+"}\n", inner) {
			if why := tenantPathRefused(path, resp); why != "" {
				t.Errorf("%s ×60: %s: %s", name, path, why)
			}
		}
		if n := len(rec.seen()); n > 0 {
			t.Errorf("%s ×60: %d Caddyfile(s) reached the adapter", name, n)
		}
	}
	// A snippet body's nesting counts where it is imported.
	set := tenantSnippetSet{"deep": {Name: "deep", Depth: 20}}
	if why := tenantTextRules("x.test {\n"+strings.Repeat("header {\n", 12)+"import deep\n"+strings.Repeat("}\n", 12)+"}\n", set, tenantMaxNestingDepth, 0); !strings.Contains(why, "33 levels deep once") {
		t.Errorf("a deep snippet imported deep: %q", why)
	}
}
