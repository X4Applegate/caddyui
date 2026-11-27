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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// round11Secret is the content of files planted where Caddy resolves a
// relative `import`.
const round11Secret = "planted-secret-r11"

// newRound11Fixture is newAdaptRecorderFixture whose /adapt runs the real
// Caddy (when on PATH) next to the planted files, with adminCaddyfile as
// the administrator's Caddyfile (CADDYFILE_PATH).
func newRound11Fixture(t *testing.T, adminCaddyfile string, files map[string]string) (*Server, *sql.DB, int64, *adaptRecorder, string, *models.User, *models.User) {
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
			out, err := adaptWithCaddyFiles(bin, b, files)
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
	if err := os.WriteFile(s.CaddyfilePath, []byte(adminCaddyfile), 0o644); err != nil {
		t.Fatal(err)
	}
	return s, conn, sid, rec, bin, admin, tenant
}

// round11HiddenImportSnippets are administrator snippets whose `import`
// does not start a line but runs when the snippet is imported: as the
// first token of the body, and after an `import … { … }` block on its
// closing line.
const round11HiddenImportSnippets = "(x) {\n\tX-A {block}\n}\n" +
	"(hid1) { import inc }\n" +
	"(hid2) {\n\timport x {\n\t\ty\n\t} import inc\n}\n" +
	"(ok) {\n\tX-Ok yes\n}\n"

// Issue #184 round-11 review (1): an administrator snippet that imports a
// file through an `import` that does not start a line is not importable
// by a non-admin — on any path, before Caddy sees the text — and the file
// never reaches a response, a stored route or the live config. A snippet
// without one still is.
func TestHiddenImportInAdminSnippetNeverReadsAFile(t *testing.T) {
	s, conn, sid, rec, bin, admin, tenant := newRound11Fixture(t, round11HiddenImportSnippets, map[string]string{"inc": "X-Planted " + round11Secret + "\n"})
	requireCaddy(t, bin, "the hidden imports are adapted with Caddy next to a planted file")
	for _, name := range []string{"hid1", "hid2"} {
		rec.reset()
		raw := "h.example.test {\n\theader {\n\t\timport " + name + "\n\t}\n\trespond 1\n}"
		adv := "header {\n\timport " + name + "\n}"
		for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, raw, adv) {
			if why := tenantPathRefused(path, resp); why != "" {
				t.Errorf("%s: %s: %s: %.300s", name, path, why, resp.Body.String())
			}
			if strings.Contains(resp.Body.String(), round11Secret) {
				t.Errorf("%s: %s: the planted file is in the response", name, path)
			}
		}
		if seen := rec.seen(); len(seen) > 0 {
			t.Errorf("%s: %d text(s) reached Caddy", name, len(seen))
		}
	}
	raws, _ := models.ListRawRoutes(conn, sid, admin.ID, true, nil)
	proxies, _ := models.ListProxyHosts(conn, sid, admin.ID, true, nil)
	live, _ := json.Marshal(s.buildMergedRoutes(proxies, nil, raws))
	if strings.Contains(string(live), round11Secret) {
		t.Errorf("the live routes carry the planted file: %s", live)
	}
	for _, rr := range raws {
		if strings.Contains(rr.JSONData, round11Secret) {
			t.Errorf("raw route %d stored the planted file", rr.ID)
		}
	}
	// The administrator's other snippets stay importable.
	body, _ := json.Marshal(map[string]any{"label": "ok", "enabled": true, "caddyfile_src": "okr.example.test {\n\theader {\n\t\timport ok\n\t}\n\trespond 1\n}"})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiV1CreateRawRoute(w, req)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "X-Ok") {
		t.Errorf("import ok: want 201 with the snippet, got %d %s", w.Code, w.Body.String())
	}
}

// Issue #184 round-11 review (1): a snippet whose body is an `import` of
// another counts that snippet's size; sixteen imports of a 20 KB snippet
// through such a wrapper are over the budget.
func TestHiddenImportCountsInTheBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString("(big) {\n")
	for i := range 500 {
		fmt.Fprintf(&b, "\theader X-Big-%03d \"bbbbbbbbbbbbbbbbbbbbb\"\n", i)
	}
	b.WriteString("}\n(w) { import big }\n")
	s, _, _, _, _, _ := newAdaptRecorderFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	text := "w.example.test {\n" + strings.Repeat("\timport w\n", tenantMaxImports) + "}\n"
	if why := s.tenantOwnTextViolation(text); !strings.Contains(why, "once the snippets it imports are counted") {
		t.Errorf("16 imports of a wrapper around a 20 KB snippet: %q", why)
	}
	if why := s.tenantOwnTextViolation("w.example.test {\n\timport w\n}\n"); why != "" {
		t.Errorf("one import: %q", why)
	}
}

// Issue #184 round-11 review (1): the adapt hook's check that every
// snippet the text imports is defined in it follows imports through the
// snippets themselves. (Removing the transitive step makes this fail.)
func TestAdaptHookChecksImportsTransitively(t *testing.T) {
	set := tenantSnippetSet{
		"a": {Name: "a", Imports: []caddy.CaddyfileImport{{Name: "b"}}},
		"b": {Name: "b", Imports: []caddy.CaddyfileImport{{Name: "c"}}},
		"c": {Name: "c"},
	}
	for defined, want := range map[string]string{
		"a":     `"b"`,
		"a b":   `"c"`,
		"a b c": "",
	} {
		names := map[string]bool{}
		for _, n := range strings.Fields(defined) {
			names[n] = true
		}
		why := undefinedSnippetImport([]string{"a"}, set, names)
		if (want == "") != (why == "") || !strings.Contains(why, want) {
			t.Errorf("defined %q: %q, want one naming %s", defined, why, want)
		}
	}
}

// round11AuthAdvanced is an administrator's Advanced config that relies on
// the repairs: a bare reverse_proxy sub-directive next to a value that
// spans lines, behind basic authentication.
const round11AuthAdvanced = "basic_auth {\n\tadmin $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG\n}\nrespond /down \"line1\nline2\" 503\nflush_interval -1"

// Issue #184 round-11 review (2): the Advanced config repairs run on text
// with values that span lines, and never edit inside a value.
func TestAdvancedRepairsLeaveValuesAlone(t *testing.T) {
	got := normalizeProxyAdvancedConfig(round11AuthAdvanced)
	for _, want := range []string{"respond /down \"line1\nline2\" 503", "reverse_proxy {\n\tflush_interval -1\n}", "basic_auth {"} {
		if !strings.Contains(got, want) {
			t.Errorf("sample: %q missing from\n%s", want, got)
		}
	}
	for name, c := range map[string]struct{ src, keep, want string }{
		"backtick":       {"respond `a\nflush_interval -1\nb` 200\nflush_interval -1", "`a\nflush_interval -1\nb`", "reverse_proxy {\n\tflush_interval -1\n}"},
		"heredoc":        {"respond <<EOF\n\tread_buffer_size 4k\n\t}\n\tEOF 200\nreverse_proxy {\n\tread_buffer_size 4k\n}", "<<EOF\n\tread_buffer_size 4k\n\t}\n\tEOF", "transport http {\n\t\tread_buffer 4k"},
		"quoted #":       {"header X-Hash \"a # {\"\nflush_interval -1", "\"a # {\"", "reverse_proxy {\n\tflush_interval -1\n}"},
		"continued line": {"header_up X-A \\\n\tb\nflush_interval -1", "header_up X-A \\\n\tb", "reverse_proxy {\n\theader_up X-A \\\n\tb\n\tflush_interval -1\n}"},
	} {
		got := normalizeProxyAdvancedConfig(c.src)
		if !strings.Contains(got, c.keep) || !strings.Contains(got, c.want) {
			t.Errorf("%s: want %q kept and %q, got\n%s", name, c.keep, c.want, got)
		}
	}
}

// Issue #184 round-11 review (2), with Caddy: the administrator's host
// above keeps its authentication handler live, and its other repaired
// configs adapt.
func TestAdvancedRepairsAdaptWithCaddy(t *testing.T) {
	s, _, _, caddyBin, _, _ := newExportFixture(t)
	requireCaddy(t, caddyBin, "the repaired Advanced configs are adapted with Caddy")
	p := models.ProxyHost{ID: 31, Domains: "auth.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
		Enabled: true, SSLEnabled: true, AdvancedConfig: round11AuthAdvanced}
	live, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil))
	for _, want := range []string{`"authentication"`, `"flush_interval":-1`, `"reverse_proxy"`, `line1\nline2`} {
		if !strings.Contains(string(live), want) {
			t.Errorf("live route lacks %s: %s", want, live)
		}
	}
	for i, adv := range []string{
		"respond /a `a\nflush_interval -1\nb` 200\nflush_interval -1",
		"respond /b <<EOF\n\tread_buffer_size 4k\n\t}\n\tEOF 200\nreverse_proxy {\n\tread_buffer_size 4k\n}",
	} {
		p := models.ProxyHost{ID: int64(40 + i), Domains: fmt.Sprintf("rep%d.example.test", i), ForwardScheme: "http", ForwardHost: "203.0.113.10",
			ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: adv}
		live, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil))
		if strings.Contains(string(live), `"status_code":503`) || !strings.Contains(string(live), `"reverse_proxy"`) {
			t.Errorf("%d: the repaired config did not apply: %s", i, live)
		}
	}
}

// Issue #184 round-11 review (2): a host whose Advanced config cannot be
// applied at sync answers 503 for its own hosts — for every owner — rather
// than proxying without what the config added; the administrator sees it
// in the activity log.
func TestAdvancedConfigThatDoesNotApplyServes503(t *testing.T) {
	s, conn, sid, rec, admin, tenant := newAdaptRecorderFixture(t)
	hosts := []models.ProxyHost{
		{ID: 51, ServerID: sid, Domains: "a503.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, AdvancedConfig: "basic_auth {\n\tadmin x\n}", OwnerID: sql.NullInt64{Int64: admin.ID, Valid: true}},
		{ID: 52, ServerID: sid, Domains: "t503.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, AdvancedConfig: "import secrets", OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true}},
	}
	routes := s.buildMergedRoutes(hosts, nil, nil)
	live, _ := json.Marshal(routes)
	if strings.Contains(string(live), "reverse_proxy") {
		t.Errorf("a host whose Advanced config did not apply is proxied: %s", live)
	}
	for _, h := range []string{"a503.example.test", "t503.example.test"} {
		found := false
		for _, r := range routes {
			b, _ := json.Marshal(r)
			if strings.Contains(string(b), h) && strings.Contains(string(b), `"status_code":503`) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want a 503 route for the host: %s", h, live)
		}
	}
	if n := len(rec.seen()); n != 1 {
		t.Errorf("want only the administrator's config sent to Caddy, got %d", n)
	}
	var logged int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM activity_log WHERE action = 'proxy_advanced_failed'`).Scan(&logged)
	if logged != 2 {
		t.Errorf("want 2 activity log entries, got %d", logged)
	}
	s.buildMergedRoutes(hosts, nil, nil)
	_ = conn.QueryRow(`SELECT COUNT(*) FROM activity_log WHERE action = 'proxy_advanced_failed'`).Scan(&logged)
	if logged != 2 {
		t.Errorf("an unchanged failure is logged again on the next sync: %d entries", logged)
	}
}

// Issue #184 round-11 review (3): the `{args.` scan is linear on the
// raw-route save path too.
func TestArgsPlaceholderScanIsLinearOnSave(t *testing.T) {
	s, _, sid, _, _, tenant := newAdaptRecorderFixture(t)
	src := "args.example.test {\n\trespond `" + strings.Repeat("{args.", 5400) + strings.Repeat("}", 33000) + "` 200\n}"
	if len(src) > maxTenantCaddyfileBytes {
		t.Fatalf("fixture: %d bytes", len(src))
	}
	body, _ := json.Marshal(map[string]any{"label": "args", "enabled": true, "caddyfile_src": src})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	start := time.Now()
	s.apiV1CreateRawRoute(w, req)
	if took := time.Since(start); took > time.Second {
		t.Errorf("the save took %v", took)
	}
}

// round11StoredRow is a non-admin's Advanced route as an earlier version
// stored it: its JSON carries what Caddy read from a file.
func round11StoredRow(t *testing.T, conn *sql.DB, sid, owner int64, label, src, host, listen string) int64 {
	t.Helper()
	id, err := models.CreateRawRoute(conn, sid, owner, &models.RawRoute{Label: label, Enabled: true, CaddyfileSrc: src,
		Listen:   models.NormalizeRawRouteListen(models.ParseRawRouteListenInput(listen)),
		JSONData: `{"match":[{"host":["` + host + `"]}],"handle":[{"handler":"headers","response":{"set":{"X-Planted":["` + round11Secret + `"]}}}]}`})
	if err != nil {
		t.Fatal(err)
	}
	markPreUpgrade(t, conn, id)
	return id
}

// markPreUpgrade makes a row read as one an earlier version stored
// (issue #184 round 13: rows this version writes are marked rules_184).
func markPreUpgrade(t *testing.T, conn *sql.DB, id int64) {
	t.Helper()
	if _, err := conn.Exec(`UPDATE raw_routes SET rules_184 = 0 WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
}

// liveFor is the live config the sync would build from the stored rows.
func liveFor(t *testing.T, s *Server, conn *sql.DB, sid, admin int64) string {
	t.Helper()
	raws, _ := models.ListRawRoutes(conn, sid, admin, true, nil)
	live, _ := json.Marshal(s.buildMergedRoutes(nil, nil, raws))
	listeners, _ := json.Marshal(s.buildRawListenServers(raws))
	return string(live) + string(listeners)
}

// Issue #184 round-11 review (4): non-admin Advanced routes stored by an
// earlier version from text whose `import` read a file — (a) through a
// snippet that imports the shadowed one, (b) stored by the paste import
// whose lookalike sat in another block, (c) importing a snippet the old
// splitter never loaded (it followed a comment line) — are adapted again
// by the upgrade migration; neither the stored JSON nor the live routes
// keep the file, and the migration runs once.
func TestUpgradeMigrationAdaptsStoredTenantRoutesAgain(t *testing.T) {
	cases := map[string]struct{ admin, src string }{
		"(a) transitive": {"(tag) {\n\tX-Tag yes\n}\n(both) {\n\timport tag\n}\n",
			"ta.example.test {\n\trespond `}\n(tag) {\n}\n{` 200\n\theader {\n\t\timport both\n\t}\n}"},
		"(b) paste import": {"(tag) {\n\tX-Tag yes\n}\n",
			"ta.example.test {\n\theader {\n\t\timport tag\n\t}\n\trespond 1\n}"},
		"(c) after a comment": {"# headers\n(tag) {\n\tX-Tag yes\n}\n",
			"ta.example.test {\n\theader {\n\t\timport tag\n\t}\n\trespond 1\n}"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, conn, sid, rec, bin, admin, tenant := newRound11Fixture(t, c.admin, map[string]string{"tag": "X-Planted " + round11Secret + "\n"})
			requireCaddy(t, bin, "the stored route is adapted again with Caddy")
			id := round11StoredRow(t, conn, sid, tenant.ID, "legacy", c.src, "ta.example.test", "")
			if live := liveFor(t, s, conn, sid, admin.ID); strings.Contains(live, round11Secret) {
				t.Fatalf("a row waiting for the migration was deployed: %s", live)
			}
			s.migrateTenantRawRoutes(sid, s.Caddy)
			// Round 13: its stored routes are not what its text adapts to
			// today, so it is held, the routes kept for an administrator.
			rr, _ := models.GetRawRoute(conn, id)
			if strings.Contains(rr.JSONData, round11Secret) || rr.Enabled {
				t.Errorf("stored route after the migration: enabled=%v %s", rr.Enabled, rr.JSONData)
			}
			if held, _ := models.GetRawRouteHeldJSON(conn, id); !strings.Contains(held, round11Secret) {
				t.Errorf("held routes: %q", held)
			}
			if live := liveFor(t, s, conn, sid, admin.ID); strings.Contains(live, round11Secret) || strings.Contains(live, "ta.example.test") {
				t.Errorf("live routes after the migration: %s", live)
			}
			if v, _ := models.GetSetting(conn, settingTenantRawRouteMigration); v != "done" {
				t.Errorf("migration state %q, want done", v)
			}
			// Once done it never runs again.
			rec.reset()
			s.rawMig = tenantRawMigration{}
			s.migrateTenantRawRoutes(sid, s.Caddy)
			if n := len(rec.seen()); n != 0 {
				t.Errorf("the migration ran again: %d adapt(s)", n)
			}
			if again, _ := models.GetRawRoute(conn, id); again.JSONData != rr.JSONData {
				t.Errorf("the second run changed the row")
			}
		})
	}
}

// Issue #184 round-11 review (4): while Caddy cannot be reached the rows
// waiting for the migration stay undeployed — on srv0 and on their own
// listener — and the migration is retried; rows with no text are disabled
// and their stored JSON cleared; an administrator's rows are not touched.
// Round 12: a row that imports a name the administrator has not defined
// is refused because of the server Caddyfile, which may change, so it
// stays pending — undeployed — rather than being disabled.
func TestUpgradeMigrationFailsClosed(t *testing.T) {
	s, conn, sid, rec, bin, admin, tenant := newRound11Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", map[string]string{"tag": "X-Planted " + round11Secret + "\n"})
	requireCaddy(t, bin, "the stored routes are adapted again with Caddy")
	site := func(host string) string { return host + " {\n\theader {\n\t\timport tag\n\t}\n\trespond 1\n}" }
	// Round 13: these two hold what their text adapts to today, so only
	// reaching Caddy decides whether they are kept.
	onSrv0 := round13Fresh(t, s, conn, sid, tenant.ID, "srv0", site("m1.example.test"))
	onPort := round13Fresh(t, s, conn, sid, tenant.ID, "port", site("m2.example.test:7070"))
	refused := round11StoredRow(t, conn, sid, tenant.ID, "refused", "m3.example.test {\n\timport secrets\n}", "m3.example.test", "")
	textless := round11StoredRow(t, conn, sid, tenant.ID, "route[0] (no host match)", "", "m4.example.test", "")
	adminRow := round11StoredRow(t, conn, sid, admin.ID, "admin", site("m5.example.test"), "m5.example.test", "")

	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	s.migrateTenantRawRoutes(sid, caddy.New(dead.URL, "", ""))
	live := liveFor(t, s, conn, sid, admin.ID)
	for _, h := range []string{"m1.example.test", "m2.example.test", "7070"} {
		if strings.Contains(live, h) {
			t.Errorf("Caddy unreachable: %s was deployed: %s", h, live)
		}
	}
	if !strings.Contains(live, "m5.example.test") {
		t.Errorf("the administrator's row is not deployed: %s", live)
	}
	for _, id := range []int64{onSrv0, onPort} {
		if rr, _ := models.GetRawRoute(conn, id); !s.rawRouteMigrationPending(*rr) {
			t.Errorf("row %d: no longer waiting although Caddy was not reached", id)
		}
	}
	if rr, _ := models.GetRawRoute(conn, textless); rr.Enabled || strings.Contains(rr.JSONData, round11Secret) {
		t.Errorf("row %d (%s): want disabled with its JSON cleared, got enabled=%v %s", textless, rr.Label, rr.Enabled, rr.JSONData)
	}
	if rr, _ := models.GetRawRoute(conn, refused); !s.rawRouteMigrationPending(*rr) || strings.Contains(live, "m3.example.test") {
		t.Errorf("row %d (%s): want it pending and undeployed", refused, rr.Label)
	}
	if a, _ := models.GetRawRoute(conn, adminRow); !a.Enabled || !strings.Contains(a.JSONData, round11Secret) {
		t.Errorf("the administrator's row was changed")
	}
	rec.reset()
	s.migrateTenantRawRoutes(sid, s.Caddy)
	live = liveFor(t, s, conn, sid, admin.ID)
	for _, h := range []string{"m1.example.test", "m2.example.test", "7070", "X-Tag"} {
		if !strings.Contains(live, h) {
			t.Errorf("Caddy reachable: %s missing: %s", h, live)
		}
	}
	if strings.Count(live, round11Secret) != 1 { // the administrator's own row
		t.Errorf("the planted content is deployed for a non-admin row: %s", live)
	}
	// The state also carries the row's snippet-wait counters (T-0935).
	v, _ := models.GetSetting(conn, settingTenantRawRouteMigration)
	var st rawMigSavedState
	if err := json.Unmarshal([]byte(v), &st); err != nil || len(st.Pending) != 1 || st.Pending[0] != refused {
		t.Errorf("migration state %q, want only the row importing an undefined name left", v)
	}
}

// round11WithheldSnippets are administrator snippets a non-admin may not
// import — one reads the environment, one imports a file, one imports that
// one — and one they may.
const round11WithheldSnippets = "(cf) {\n\ttls {\n\t\tdns cloudflare {env.CF_API_TOKEN}\n\t}\n}\n" +
	"(filey) {\n\timport secrets\n}\n(viafile) {\n\timport filey\n}\n(ok) {\n\theader X-Ok yes\n}\n"

// Issue #184 round-11 review (5): an administrator snippet a non-admin may
// not import no longer makes every non-admin's Advanced config fail at
// sync: it is left out of the text adapted for them. Importing it is
// refused, with a message that says why.
func TestWithheldAdminSnippetsDoNotBreakTenantText(t *testing.T) {
	s, _, _, rec, bin, _, tenant := newRound11Fixture(t, round11WithheldSnippets, nil)
	p := models.ProxyHost{ID: 61, Domains: "custom.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
		Enabled: true, SSLEnabled: true, AdvancedConfig: "header X-Custom hi\nimport ok", OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true}}
	live, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil))
	seen := rec.seen()
	if len(seen) != 1 {
		t.Fatalf("want the Advanced config adapted once, got %d", len(seen))
	}
	if strings.Contains(seen[0], "{env.") || strings.Contains(seen[0], "(filey)") || !strings.Contains(seen[0], "(ok)") {
		t.Errorf("the text adapted for the non-admin: %s", seen[0])
	}
	if bin != "" && (!strings.Contains(string(live), "X-Custom") || !strings.Contains(string(live), "X-Ok")) {
		t.Errorf("the live route dropped the non-admin's headers: %s", live)
	}
	for _, name := range []string{"cf", "filey", "viafile"} {
		if why := s.tenantOwnTextViolation("import " + name); why != tenantSnippetUnavailable(name) {
			t.Errorf("import %s: %q", name, why)
		}
	}
	if why := s.tenantOwnTextViolation("import ok"); why != "" {
		t.Errorf("import ok: %q", why)
	}
}

// round11CostSnippets exercise the import cost model: a4 puts all the
// importer's arguments in four times, b3 its block three times, deepb its
// block three levels down, fw forwards its arguments to a4, big is ~20 KB.
func round11CostSnippets() string {
	var b strings.Builder
	b.WriteString("(a4) {\n\theader X-A {args[:]}\n\theader X-B {args[:]}\n\theader X-C {args[:]}\n\theader X-D {args[:]}\n}\n")
	b.WriteString("(b3) {\n\troute {\n\t\t{block}\n\t}\n\troute {\n\t\t{block}\n\t}\n\troute {\n\t\t{block}\n\t}\n}\n")
	b.WriteString("(b1) {\n\troute {\n\t\t{block}\n\t}\n}\n")
	b.WriteString("(deepb) {\n\troute {\n\t\troute {\n\t\t\troute {\n\t\t\t\t{block}\n\t\t\t}\n\t\t}\n\t}\n}\n")
	b.WriteString("(fw) {\n\timport a4 {args[:]}\n}\n")
	b.WriteString("(big) {\n")
	for i := range 500 {
		fmt.Fprintf(&b, "\theader X-Big-%03d \"bbbbbbbbbbbbbbbbbbbbb\"\n", i)
	}
	b.WriteString("}\n")
	return b.String()
}

// Issue #184 round-11 review (6): the import budget is an upper bound on
// what Caddy expands — the importer's arguments count once per `{args…}`
// in the snippet (transitively), its block where the snippet puts it, a
// block's nesting where the snippet puts it — and an argument may not be
// a lone brace. Round 12: a snippet that puts the block in more than once
// is withheld, and an import inside an import's block is refused.
func TestImportCostCountsArgumentsAndBlocks(t *testing.T) {
	s, _, _, _, _, _ := newAdaptRecorderFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(round11CostSnippets()), 0o644); err != nil {
		t.Fatal(err)
	}
	args := func(n int) string { return strings.Repeat("aaaaaaaaa ", n/10) }
	block := func(n int) string { return strings.Repeat("\t\theader X-Blk-0000 vvvvvvvvvvvvvvvvvvvvvv\n", n/40) }
	nest := func(n int, inner string) string {
		return strings.Repeat("route {\n", n) + inner + strings.Repeat("}\n", n)
	}
	site := func(body string) string { return "c.example.test {\n" + body + "}\n" }
	for name, c := range map[string]struct {
		text, want string
	}{
		"arguments ×4 within":      {site("\timport a4 " + args(8000) + "\n"), ""},
		"arguments ×4 over":        {site("\timport a4 " + args(15000) + "\n"), "once the snippets it imports are counted"},
		"forwarded arguments over": {site("\timport fw " + args(15000) + "\n"), "once the snippets it imports are counted"},
		"block within":             {site("\timport b1 {\n" + block(30000) + "\t}\n"), ""},
		"block over":               {site("\timport b1 {\n" + block(40000) + "\t}\n"), "once the snippets it imports are counted"},
		"block ×3 (withheld)":      {site("\timport b3 {\n" + block(400) + "\t}\n"), `snippet "b3" is not available`},
		"import in a block":        {site("\timport deepb {\n\t\timport big\n\t}\n"), "inside the block of another `import`"},
		"block depth within":       {site("\timport deepb {\n" + nest(27, "respond 1\n") + "\t}\n"), ""},
		"block depth over":         {site("\timport deepb {\n" + nest(29, "respond 1\n") + "\t}\n"), "levels deep once"},
		"brace argument":           {site("\timport a4 \"{\"\n"), "lone `{` or `}`"},
		"closing brace argument":   {site("\timport a4 x \"}\"\n"), "lone `{` or `}`"},
	} {
		why := s.tenantOwnTextViolation(c.text)
		if (c.want == "") != (why == "") || !strings.Contains(why, c.want) {
			t.Errorf("%s: %q, want %q", name, why, c.want)
		}
	}
}

// Issue #184 round-11 review (7): a non-admin's snippet definition after a
// block's `}` on the same line is refused like any other.
func TestTenantSnippetDefinitionAfterABlockIsRefused(t *testing.T) {
	if why := tenantTextViolation("a.test {\n\trespond 1\n} (x) {\n\theader X 1\n}\n"); !strings.Contains(why, "snippet definitions") {
		t.Errorf("`} (x) {`: %q", why)
	}
}

// Issue #184 round-11 review (8): an administrator's Advanced route that
// defines a snippet with its `{` on the next line, named like one in the
// server Caddyfile, is not given the server's definition as well (which
// Caddy refuses as a redeclaration).
func TestAdminSnippetWithBraceOnNextLineIsCounted(t *testing.T) {
	s, _, sid, caddyBin, admin, _ := newExportFixture(t)
	requireCaddy(t, caddyBin, "the administrator's route is adapted with Caddy")
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte("(tag) {\n\theader X-Server yes\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := "(tag)\n{\n\theader X-Mine yes\n}\nnl.example.test {\n\timport tag\n\trespond 1\n}"
	body, _ := json.Marshal(map[string]any{"label": "nl", "enabled": true, "caddyfile_src": src})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, admin, nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiV1CreateRawRoute(w, req)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "X-Mine") {
		t.Errorf("want 201 with the route's own snippet, got %d %s", w.Code, w.Body.String())
	}
}

// Issue #184 round-11 review (4): the sync of a server runs the migration
// for its rows, with that server's Caddy, before it builds the config —
// which is how the startup retry loop brings the rows back.
func TestSyncRunsTheUpgradeMigration(t *testing.T) {
	s, conn, sid, _, bin, _, tenant := newRound11Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", map[string]string{"tag": "X-Planted " + round11Secret + "\n"})
	requireCaddy(t, bin, "the stored route is adapted again with Caddy")
	id := round11StoredRow(t, conn, sid, tenant.ID, "legacy", "sy.example.test {\n\theader {\n\t\timport tag\n\t}\n\trespond 1\n}", "sy.example.test", "")
	if got, _ := s.rawRouteMigrationServers(); len(got) != 1 || got[0] != sid {
		t.Errorf("servers waiting for the migration: %v, want [%d]", got, sid)
	}
	_ = s.syncCaddy(sid, false) // the push itself may fail against the stand-in; the migration runs first
	rr, _ := models.GetRawRoute(conn, id)
	if strings.Contains(rr.JSONData, round11Secret) || rr.Enabled { // round 13: held, its routes differ from its text's
		t.Errorf("the sync did not migrate the row: enabled=%v %s", rr.Enabled, rr.JSONData)
	}
	if got, _ := s.rawRouteMigrationServers(); len(got) != 0 {
		t.Errorf("servers still waiting: %v", got)
	}
}
