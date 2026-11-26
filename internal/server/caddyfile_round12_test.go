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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// round12Secret stands for what an earlier version read from a file into
// a stored route.
const round12Secret = "planted-secret-r12"

// round12Caddy is a stand-in Caddy admin API that records what it is sent
// and answers /adapt with adapt(body).
type round12Caddy struct {
	mu     sync.Mutex
	adapts []string
	loads  []string
	adapt  func(body string) (int, string)
}

func (c *round12Caddy) seenAdapts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.adapts...)
}

func (c *round12Caddy) seenLoads() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.loads, "\n")
}

// round12Adapted is an /adapt answer: one site on :443 whose route sets
// header on host.
func round12Adapted(host, header string) string {
	return `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["` + host +
		`"]}],"handle":[{"handler":"headers","response":{"set":{"` + header + `":["yes"]}}}],"terminal":true}]}}}}}}`
}

// newRound12Fixture is newAdaptRecorderFixture with a round12Caddy as the
// server's Caddy admin API and adminCaddyfile as CADDYFILE_PATH.
func newRound12Fixture(t *testing.T, adminCaddyfile string, adapt func(string) (int, string)) (*Server, *sql.DB, int64, *round12Caddy, *models.User, *models.User) {
	t.Helper()
	s, conn, sid, _, admin, tenant := newAdaptRecorderFixture(t)
	fc := &round12Caddy{adapt: adapt}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/adapt":
			fc.mu.Lock()
			fc.adapts = append(fc.adapts, string(b))
			fn := fc.adapt
			fc.mu.Unlock()
			if fn == nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"`+round8Marker+`"}`)
				return
			}
			code, body := fn(string(b))
			if code == -1 { // break the connection, as a panicking handler does
				if hj, ok := w.(http.Hijacker); ok {
					c, _, _ := hj.Hijack()
					_ = c.Close()
				}
				return
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, body)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config"):
			_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
		default:
			fc.mu.Lock()
			fc.loads = append(fc.loads, r.URL.Path+" "+string(b))
			fc.mu.Unlock()
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
	return s, conn, sid, fc, admin, tenant
}

// round12StoredRow is a non-admin's Advanced route as an earlier version
// stored it, with the planted header in its JSON.
func round12StoredRow(t *testing.T, conn *sql.DB, sid, owner int64, label, src, host, listen string) int64 {
	t.Helper()
	id, err := models.CreateRawRoute(conn, sid, owner, &models.RawRoute{Label: label, Enabled: true, CaddyfileSrc: src, Listen: listen,
		JSONData: `{"match":[{"host":["` + host + `"]}],"handle":[{"handler":"headers","response":{"set":{"X-Planted":["` + round12Secret + `"]}}}]}`})
	if err != nil {
		t.Fatal(err)
	}
	markPreUpgrade(t, conn, id)
	return id
}

// The round-12 reproductions of the unbounded expansion: an administrator
// snippet that puts the importer's block in twice, and a tenant import
// written inside another import's block.
const (
	round12DoubleBlock = "(bk) {\n{block}\n{block}\n}\n"
	round12Chain       = "(s0) {\nimport s1 {\n{block}\n{block}\n}\n}\n(s1) {\n{block}\n{block}\n}\n"
)

// Issue #184 round-12 review (1): both reproductions are refused before
// Caddy sees anything — 0 adapts — on every path that adapts a non-admin's
// text, the raw-route save and the proxy host's Advanced save among them.
func TestNestedImportBlocksAreRefusedBeforeCaddy(t *testing.T) {
	for name, c := range map[string]struct{ admin, raw, adv string }{
		"double block": {round12DoubleBlock,
			"t.example {\nimport bk {\nimport bk {\nimport bk {\nheader X-Z z\n}\n}\n}\n}\n",
			"import bk {\nimport bk {\nimport bk {\nheader X-Z z\n}\n}\n}\n"},
		"through a snippet": {round12Chain,
			"h.example.test {\nimport s0 {\na {\nb\n}\nimport s1 aa {\nc\n}\n}\n}\n",
			"import s0 {\na {\nb\n}\nimport s1 aa {\nc\n}\n}\n"},
		// The tenant's own nesting alone, with a snippet that puts the
		// block in once: refused too.
		"nested import, single block": {"(one) {\nroute {\n{block}\n}\n}\n",
			"n.example.test {\nimport one {\nimport one {\nheader X-Z z\n}\n}\n}\n",
			"import one {\nimport one {\nheader X-Z z\n}\n}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
			s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
			if err := os.WriteFile(s.CaddyfilePath, []byte(c.admin), 0o644); err != nil {
				t.Fatal(err)
			}
			for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, c.raw, c.adv) {
				if why := tenantPathRefused(path, resp); why != "" {
					t.Errorf("%s: %s", path, why)
				}
			}
			if seen := rec.seen(); len(seen) != 0 {
				t.Errorf("%d text(s) reached Caddy's adapter", len(seen))
			}
			if why := s.tenantOwnTextViolation(c.raw); why == "" {
				t.Errorf("the raw text is allowed")
			}
		})
	}
}

// Issue #184 round-12 review (1): which administrator snippets a
// non-admin may import — one block placement is fine; two (`{block}` and
// `{blocks.…}` counted together), a placement on a line with other text,
// one passed on inside an import's block, and a `}` followed by more text
// on its line (the differential test against Caddy found Caddy then runs
// the block on into the importer's text) are withheld; and the message a
// non-admin gets is the same as for an undefined name (review (8)). Round
// 13: a snippet that starts with the block is available again (inside a
// site; see TestSnippetPlaceholderPlacement).
func TestSnippetsThatRepeatTheImportersBlockAreWithheld(t *testing.T) {
	admin := "(one) {\n\troute {\n\t\t{block}\n\t}\n}\n" +
		"(two) {\n\troute {\n\t\t{block}\n\t}\n\thandle {\n\t\t{block}\n\t}\n}\n" +
		"(ab) {\n\troute {\n\t\t{blocks.a}\n\t}\n\thandle {\n\t\t{blocks.b}\n\t}\n}\n" +
		"(adj) {\n\troute {\n\t\t{block} {args[0]}\n\t}\n}\n" +
		"(first) {\n\t{block}\n\theader X 1\n}\n" +
		"(pass) {\n\timport one {\n\t\t{block}\n\t}\n}\n" +
		"(passargs) {\n\timport one {\n\t\theader X {args[0]}\n\t}\n}\n" +
		"(fixed) {\n\timport one {\n\t\theader X 1\n\t}\n}\n" +
		"(midline) {\n\timport one {\n\t\theader X 1\n\t} import fixed\n}\n"
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets(admin))
	for name, withheld := range map[string]bool{"one": false, "fixed": false, "first": false, "two": true, "ab": true, "adj": true, "pass": true, "passargs": true, "midline": true} {
		if got := set[name].Withheld != ""; got != withheld {
			t.Errorf("%s: withheld=%v (%q), want %v", name, got, set[name].Withheld, withheld)
		}
		if withheld && strings.Contains(tenantSnippetPrefix(set), "("+name+")") {
			t.Errorf("%s: in the text adapted for a non-admin", name)
		}
	}
	for _, name := range []string{"two", "ab", "adj", "pass", "passargs", "midline", "nosuch"} {
		why, _, _ := tenantTextCheck("x.test {\n\timport "+name+" {\n\t\theader X 1\n\t}\n}\n", set, tenantTextLimits{maxDepth: 32, maxBytes: maxTenantCaddyfileBytes})
		if why != tenantSnippetUnavailable(name) {
			t.Errorf("import %s: %q", name, why)
		}
	}
}

// Issue #184 round-12 review (7): a snippet whose first token expands to
// nothing, or that runs an `import` of its own outside any block, is not
// imported at the top level of a non-admin's Caddyfile (Caddy's parser
// fails there with an index out of range, and the client sees EOF); inside
// a site it is. With Caddy on PATH, the shape is shown to break Caddy's
// parser when sent anyway.
//
// Round 13: a snippet whose first token is a placeholder is withheld
// outright (an {args…} placeholder may not start a line), so `va` and the
// snippets importing it are no longer available anywhere; the top-level
// rule still applies to a snippet that starts with an `import` or the
// importer's block, or runs an `import` outside any block of its own.
func TestTopLevelImportsThatBreakCaddysParserAreRefused(t *testing.T) {
	admin := "(va) {\n\t{args[:]}\n\theader X 1\n}\n(wrap) {\n\timport ok\n}\n(late) {\n\ta.test {\n\t}\n\timport ok\n}\n(blk) {\n\t{block}\n\theader X 1\n}\n(ok) {\n\theader X 1\n}\n"
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(admin), 0o644); err != nil {
		t.Fatal(err)
	}
	if why := s.tenantAdaptTextViolation(s.withTenantSnippets("t.example.test {\n\timport va\n}\n")); why != tenantSnippetUnavailable("va") {
		t.Errorf("import va: %q", why)
	}
	for _, name := range []string{"wrap", "late", "blk"} {
		rec.reset()
		raw := "import " + name + "\nt.example.test {\n\trespond 1\n}\n"
		for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, raw, "respond 1") {
			if !strings.HasPrefix(path, "raw-route") {
				continue
			}
			if why := tenantPathRefused(path, resp); why != "" {
				t.Errorf("%s: %s: %s", name, path, why)
			}
			if !strings.Contains(resp.Body.String(), "can only be imported inside a site block") && strings.HasPrefix(path, "raw-route API") {
				t.Errorf("%s: %s: %.300s", name, path, resp.Body.String())
			}
		}
		for _, seen := range rec.seen() {
			if strings.Contains(seen, "import "+name) {
				t.Errorf("%s: the text reached Caddy's adapter", name)
			}
		}
	}
	// Inside a site it is fine.
	for _, name := range []string{"wrap", "late", "blk"} {
		text := s.withTenantSnippets("t.example.test {\n\timport " + name + "\n}\n")
		if why := s.tenantAdaptTextViolation(text); why != "" {
			t.Errorf("import %s inside a site: %q", name, why)
		}
	}
	if why := s.tenantAdaptTextViolation(s.withTenantSnippets("import ok\n")); why != "" {
		t.Errorf("import ok at the top level: %q", why)
	}
	bin, _ := lookPathCaddy()
	requireCaddy(t, bin, "the unfiltered shape is sent to the (memory-capped) Caddy")
	out, err := adaptWithCaddyFiles(bin, []byte(admin+"import va\n"), nil)
	if err == nil || !strings.Contains(string(out)+err.Error(), "index out of range") {
		t.Errorf("want Caddy's parser to fail on the shape, got %v %.300s", err, out)
	}
}

// Issue #184 round-12 review (2): a text-less row the v2.68.16 paste
// import labelled with its host name — not "route[N] (no host match)" —
// whose JSON carries a file's content is held by the upgrade migration:
// not deployed, the secret in no /load body, disabled with its JSON
// cleared. The migration then reads done.
func TestMigrationHoldsTextlessRowsWhateverTheirLabel(t *testing.T) {
	s, conn, sid, fc, admin, tenant := newRound12Fixture(t, "(tag) {\n\theader X-Tag yes\n}\n", nil)
	id := round12StoredRow(t, conn, sid, tenant.ID, "leak.example.test", "", "leak.example.test", "")
	_ = s.syncCaddy(sid, false)
	if loads := fc.seenLoads(); strings.Contains(loads, round12Secret) {
		t.Errorf("the planted content was pushed to Caddy: %.400s", loads)
	}
	if live := liveFor(t, s, conn, sid, admin.ID); strings.Contains(live, round12Secret) {
		t.Errorf("the planted content is in the live routes: %s", live)
	}
	rr, _ := models.GetRawRoute(conn, id)
	if rr.Enabled || strings.Contains(rr.JSONData, round12Secret) {
		t.Errorf("row: enabled=%v json=%s", rr.Enabled, rr.JSONData)
	}
	var logged int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM activity_log WHERE action = 'rawroute_migration_disabled'`).Scan(&logged)
	if logged != 1 {
		t.Errorf("activity log entries: %d", logged)
	}
	if v, _ := models.GetSetting(conn, settingTenantRawRouteMigration); v != "done" {
		t.Errorf("migration state %q", v)
	}
	// An administrator's text-less row is not touched.
	aid := round12StoredRow(t, conn, sid, admin.ID, "admin.example.test", "", "admin.example.test", "")
	s.rawMig = tenantRawMigration{}
	_ = models.SetSetting(conn, settingTenantRawRouteMigration, "")
	s.migrateTenantRawRoutes(sid, s.Caddy)
	if a, _ := models.GetRawRoute(conn, aid); !a.Enabled {
		t.Errorf("the administrator's row was held")
	}
}

// Issue #184 round-12 review (3): a row still waiting for the migration is
// not copied by a fleet sync into a new, deployable row; it is reported as
// skipped. Once migrated, it is copied.
func TestFleetSyncSkipsRowsWaitingForTheMigration(t *testing.T) {
	s, conn, sid, _, admin, tenant := newRound12Fixture(t, "(tag) {\n\theader X-Tag yes\n}\n", func(string) (int, string) {
		return 200, round12Adapted("fl.example.test", "X-Tag")
	})
	target, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Secondary", AdminURL: "http://127.0.0.1:1", Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	round12StoredRow(t, conn, sid, tenant.ID, "legacy", "fl.example.test {\n\theader {\n\t\timport tag\n\t}\n}", "fl.example.test", "")
	sum, err := s.syncFleetConfiguration("admin@example.test", sid, target)
	if err != nil {
		t.Fatal(err)
	}
	if sum.RawRoutesPending != 1 || sum.RawRoutesCreated != 0 {
		t.Errorf("summary: %+v", sum)
	}
	if !strings.Contains(sum.String(), "upgrade migration") {
		t.Errorf("summary text: %s", sum.String())
	}
	raws, _ := models.ListRawRoutes(conn, target, admin.ID, true, nil)
	for _, rr := range raws {
		if strings.Contains(rr.JSONData, round12Secret) {
			t.Errorf("the target holds the pending row's JSON: %s", rr.JSONData)
		}
	}
	live, _ := json.Marshal(s.buildMergedRoutes(nil, nil, raws))
	if strings.Contains(string(live), round12Secret) {
		t.Errorf("the target's live routes carry the planted content: %s", live)
	}
	s.migrateTenantRawRoutes(sid, s.Caddy)
	sum, err = s.syncFleetConfiguration("admin@example.test", sid, target)
	if err != nil {
		t.Fatal(err)
	}
	if sum.RawRoutesCreated != 1 || sum.RawRoutesPending != 0 {
		t.Errorf("after the migration: %+v", sum)
	}
}

// Issue #184 round-12 review (4): the 503 route of a non-admin's host whose
// Advanced config cannot be applied is held to the same rules as its
// normal route: a stored path matcher with an {env.…} placeholder is
// neutralised there too.
func TestAdvancedFailureRouteIsSanitised(t *testing.T) {
	s, _, sid, _, _, tenant := newAdaptRecorderFixture(t)
	p := models.ProxyHost{ID: 71, ServerID: sid, Domains: "p503.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
		Enabled: true, SSLEnabled: true, PathMatcher: "/{env.HOME}*", AdvancedConfig: "import secrets", OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true}}
	live, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil))
	if !strings.Contains(string(live), `"status_code":503`) {
		t.Fatalf("want the 503 route: %s", live)
	}
	if strings.Contains(string(live), "{env.") {
		t.Errorf("the 503 route carries an {env.…} placeholder: %s", live)
	}
}

// Issue #184 round-12 review (5): the migration does not write back over
// a change made while it adapted a row — an administrator disabling it, its
// owner saving new text — and a row changed meanwhile without a save
// stays pending.
func TestMigrationDoesNotOverwriteConcurrentChanges(t *testing.T) {
	// Round 13 (code 6): each subtest has its own channels, and every
	// wait is bounded, so a failure ends the test instead of hanging it.
	type gate struct {
		arrived, release chan struct{}
		slow             func(body string) (int, string)
	}
	newGate := func() *gate {
		g := &gate{arrived: make(chan struct{}, 4), release: make(chan struct{}, 4)}
		g.slow = func(body string) (int, string) {
			if strings.Contains(body, "respond new") { // the owner's save
				return 200, round12Adapted("cc.example.test", "X-New")
			}
			if !strings.Contains(body, "import tag") { // anything else a sync adapts
				return 200, round12Adapted("other.example.test", "X-Other")
			}
			g.arrived <- struct{}{}
			select {
			case <-g.release:
			case <-time.After(10 * time.Second):
			}
			return 200, round12Adapted("cc.example.test", "X-Tag")
		}
		return g
	}
	wait := func(t *testing.T, ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for %s", what)
		}
	}
	src := "cc.example.test {\n\theader {\n\t\timport tag\n\t}\n}"

	t.Run("administrator disables", func(t *testing.T) {
		g := newGate()
		s, conn, sid, _, admin, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", g.slow)
		id := round12StoredRow(t, conn, sid, tenant.ID, "cc", src, "cc.example.test", "")
		done := make(chan struct{})
		go func() { s.migrateTenantRawRoutes(sid, s.Caddy); close(done) }()
		wait(t, g.arrived, "the migration's adapt")
		if _, err := conn.Exec(`UPDATE raw_routes SET enabled = 0 WHERE id = ?`, id); err != nil {
			t.Fatal(err)
		}
		g.release <- struct{}{}
		wait(t, done, "the migration run")
		rr, _ := models.GetRawRoute(conn, id)
		if rr.Enabled {
			t.Errorf("the administrator's disable was overwritten")
		}
		if !s.rawRouteMigrationPending(*rr) {
			t.Errorf("a row changed during the migration (not by a save) is no longer pending")
		}
		if live := liveFor(t, s, conn, sid, admin.ID); strings.Contains(live, round12Secret) {
			t.Errorf("deployed: %s", live)
		}
		// The next run adapts it again and keeps it disabled (round 13:
		// held, its stored routes are not what its text adapts to).
		g.release <- struct{}{}
		s.migrateTenantRawRoutes(sid, s.Caddy)
		rr, _ = models.GetRawRoute(conn, id)
		if rr.Enabled || strings.Contains(rr.JSONData, round12Secret) || s.rawRouteMigrationPending(*rr) {
			t.Errorf("after the next run: enabled=%v %s", rr.Enabled, rr.JSONData)
		}
	})

	t.Run("owner saves new text", func(t *testing.T) {
		g := newGate()
		s, conn, sid, _, _, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", g.slow)
		id := round12StoredRow(t, conn, sid, tenant.ID, "cc", src, "cc.example.test", "")
		done := make(chan struct{})
		go func() { s.migrateTenantRawRoutes(sid, s.Caddy); close(done) }()
		wait(t, g.arrived, "the migration's adapt")
		// The owner saves new text, adapted under today's rules, while the
		// migration waits on Caddy; the save's own sync does not wait for
		// the migration run.
		newSrc := "cc.example.test {\n\trespond new 200\n}"
		body, _ := json.Marshal(map[string]any{"caddyfile_src": newSrc, "enabled": true})
		req := asUser(httptest.NewRequest(http.MethodPut, "/api/v1/raw-routes/1", strings.NewReader(string(body))), sid, tenant, map[string]string{"id": fmt.Sprint(id)})
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.apiV1UpdateRawRoute(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("save: %d %s", w.Code, w.Body.String())
		}
		g.release <- struct{}{}
		wait(t, done, "the migration run")
		rr, _ := models.GetRawRoute(conn, id)
		if rr.CaddyfileSrc != newSrc {
			t.Errorf("the owner's new text was overwritten: %q", rr.CaddyfileSrc)
		}
		if s.rawRouteMigrationPending(*rr) {
			t.Errorf("a row saved through the current path is still pending")
		}
	})
}

// Issue #184 round-12 review (6): a refusal that depends on the
// administrator's Caddyfile — here it cannot be read — keeps the row
// pending (not disabled); once the file is back the row is migrated and
// stays enabled. A refusal for the row's own text disables it.
func TestMigrationRetriesRefusalsThatDependOnTheAdministrator(t *testing.T) {
	s, conn, sid, _, _, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", func(string) (int, string) {
		return 200, round12Adapted("tr.example.test", "X-Tag")
	})
	// Round 13: the row holds what its text adapts to (a row whose routes
	// differ is held whatever the snippets say).
	id := round13Fresh(t, s, conn, sid, tenant.ID, "tr", "tr.example.test {\n\theader {\n\t\timport tag\n\t}\n}")
	own := round12StoredRow(t, conn, sid, tenant.ID, "own", "ow.example.test {\n\timport tag\n\trespond {env.HOME}\n}", "ow.example.test", "")
	path := s.CaddyfilePath
	s.CaddyfilePath = path + ".missing"
	s.migrateTenantRawRoutes(sid, s.Caddy)
	rr, _ := models.GetRawRoute(conn, id)
	if !rr.Enabled || !s.rawRouteMigrationPending(*rr) {
		t.Errorf("with the snippets unreadable: enabled=%v pending=%v %s", rr.Enabled, s.rawRouteMigrationPending(*rr), rr.JSONData)
	}
	if o, _ := models.GetRawRoute(conn, own); o.Enabled || strings.Contains(o.JSONData, round12Secret) {
		t.Errorf("a row refused for its own text is not held: enabled=%v", o.Enabled)
	}
	s.CaddyfilePath = path
	s.migrateTenantRawRoutes(sid, s.Caddy)
	rr, _ = models.GetRawRoute(conn, id)
	if !rr.Enabled || !strings.Contains(rr.JSONData, "X-Tag") || s.rawRouteMigrationPending(*rr) {
		t.Errorf("with the snippets back: enabled=%v %s", rr.Enabled, rr.JSONData)
	}
}

// Issue #184 round-12 review (7): a corrupt migration state is rebuilt
// from the database — rows without `import` are never held back, rows
// with one are — and the retry loop still finds the servers to sync.
func TestCorruptMigrationStateIsRebuilt(t *testing.T) {
	s, conn, sid, _, _, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", nil)
	plain, _ := models.CreateRawRoute(conn, sid, tenant.ID, &models.RawRoute{Label: "plain", Enabled: true, CaddyfileSrc: "pl.example.test {\n\trespond 1\n}",
		JSONData: `{"match":[{"host":["pl.example.test"]}],"handle":[{"handler":"static_response","body":"1"}]}`})
	legacy := round12StoredRow(t, conn, sid, tenant.ID, "legacy", "lg.example.test {\n\timport tag\n}", "lg.example.test", "")
	if err := models.SetSetting(conn, settingTenantRawRouteMigration, "{not json"); err != nil {
		t.Fatal(err)
	}
	p, _ := models.GetRawRoute(conn, plain)
	l, _ := models.GetRawRoute(conn, legacy)
	if s.rawRouteMigrationPending(*p) {
		t.Errorf("a row without `import` is held back")
	}
	if !s.rawRouteMigrationPending(*l) {
		t.Errorf("a legacy row is deployed")
	}
	if got, err := s.rawRouteMigrationServers(); err != nil || len(got) != 1 || got[0] != sid {
		t.Errorf("servers to sync: %v %v", got, err)
	}
	if v, _ := models.GetSetting(conn, settingTenantRawRouteMigration); !strings.HasPrefix(v, `{"pending":[`) {
		t.Errorf("the state was not rewritten: %q", v)
	}
}

// Issue #184 round-12 review (7): a row whose adapt breaks the connection
// to Caddy, while Caddy answers otherwise, is held after a few runs
// rather than retried for ever; while Caddy does not answer at all it
// stays pending.
func TestMigrationHoldsARowThatBreaksCaddy(t *testing.T) {
	var down atomic.Bool
	s, conn, sid, _, _, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", nil)
	id := round12StoredRow(t, conn, sid, tenant.ID, "crash", "cr.example.test {\n\theader {\n\t\timport tag\n\t}\n}", "cr.example.test", "")
	fc := func(body string) (int, string) {
		if down.Load() || strings.Contains(body, "cr.example.test") {
			return -1, ""
		}
		return 200, round12Adapted("probe.invalid", "X")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		code, out := fc(string(b))
		if code == -1 {
			c, _, _ := w.(http.Hijacker).Hijack()
			_ = c.Close()
			return
		}
		w.WriteHeader(code)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(srv.Close)
	cl := caddy.New(srv.URL, "", "")
	down.Store(true)
	for range rawMigMaxStrikes + 1 {
		s.migrateTenantRawRoutes(sid, cl)
	}
	if rr, _ := models.GetRawRoute(conn, id); !rr.Enabled || !s.rawRouteMigrationPending(*rr) {
		t.Fatalf("Caddy down: the row was held")
	}
	down.Store(false)
	for range rawMigMaxStrikes {
		s.migrateTenantRawRoutes(sid, cl)
	}
	rr, _ := models.GetRawRoute(conn, id)
	if rr.Enabled || strings.Contains(rr.JSONData, round12Secret) || s.rawRouteMigrationPending(*rr) {
		t.Errorf("after %d runs that broke Caddy: enabled=%v pending=%v", rawMigMaxStrikes, rr.Enabled, s.rawRouteMigrationPending(*rr))
	}
}

// Issue #184 round-12 review (7): when Caddy cannot be reached at sync, a
// host keeps the Advanced config output it last applied — an
// administrator's and a non-admin's alike — rather than answering 503; a
// real refusal (a 400) still answers 503, as does a host with no output
// to keep.
func TestTransientAdaptErrorKeepsTheLastAppliedAdvancedConfig(t *testing.T) {
	mode := "ok"
	var mu sync.Mutex
	s, _, sid, _, admin, tenant := newRound12Fixture(t, "", func(body string) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		switch mode {
		case "down":
			return http.StatusBadGateway, "upstream unavailable"
		case "refuse":
			return http.StatusBadRequest, `{"error":"no"}`
		}
		return 200, `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["localhost"]}],"handle":[{"handler":"headers","response":{"set":{"X-Adv":["kept"]}}}]}]}}}}}}`
	})
	set := func(m string) { mu.Lock(); mode = m; mu.Unlock() }
	hosts := []models.ProxyHost{
		{ID: 81, ServerID: sid, Domains: "ka.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, AdvancedConfig: "header X-Adv kept", OwnerID: sql.NullInt64{Int64: admin.ID, Valid: true}},
		{ID: 82, ServerID: sid, Domains: "kt.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, AdvancedConfig: "header X-Adv kept", OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true}},
	}
	routes := func() string {
		b, _ := json.Marshal(s.buildMergedRoutes(hosts, nil, nil))
		return string(b)
	}
	if live := routes(); strings.Contains(live, `"status_code":503`) || strings.Count(live, "X-Adv") != 2 {
		t.Fatalf("Caddy up: %s", live)
	}
	set("down")
	if live := routes(); strings.Contains(live, `"status_code":503`) || strings.Count(live, "X-Adv") != 2 {
		t.Errorf("Caddy unreachable: want the last applied config kept: %s", live)
	}
	fresh := hosts[0]
	fresh.ID, fresh.Domains = 83, "kn.example.test"
	b, _ := json.Marshal(s.buildMergedRoutes([]models.ProxyHost{fresh}, nil, nil))
	if !strings.Contains(string(b), `"status_code":503`) {
		t.Errorf("Caddy unreachable, nothing to keep: want 503: %s", b)
	}
	set("refuse")
	if live := routes(); strings.Count(live, `"status_code":503`) != 2 {
		t.Errorf("Caddy refuses the config: want 503 for both: %s", live)
	}
}

// Issue #184 round-12 review (9): the migration holds a row whose text now
// adapts to other listen addresses than it was stored with (removing that
// check makes this fail).
func TestMigrationHoldsARowWhoseListenSetChanged(t *testing.T) {
	s, conn, sid, _, admin, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", func(string) (int, string) {
		return 200, round12Adapted("ls.example.test", "X-Tag") // on :443, the standard listener
	})
	// Round 13 (code 6): the stored routes are exactly what the text
	// adapts to today, so only the listen-set check can hold the row.
	src := "ls.example.test:7070 {\n\theader {\n\t\timport tag\n\t}\n}"
	js, _, _, err := s.adaptRawRouteCaddyfileResult(s.tenantAdaptClient(s.Caddy), src)
	if err != nil {
		t.Fatal(err)
	}
	id, err := models.CreateRawRoute(conn, sid, tenant.ID, &models.RawRoute{Label: "ls", Enabled: true, CaddyfileSrc: src, JSONData: js,
		Listen: models.NormalizeRawRouteListen(models.ParseRawRouteListenInput(":7070"))})
	if err != nil {
		t.Fatal(err)
	}
	markPreUpgrade(t, conn, id)
	s.migrateTenantRawRoutes(sid, s.Caddy)
	rr, _ := models.GetRawRoute(conn, id)
	if rr.Enabled || strings.Contains(rr.JSONData, "X-Tag") {
		t.Errorf("a row whose listen set changed was kept: enabled=%v %s", rr.Enabled, rr.JSONData)
	}
	if live := liveFor(t, s, conn, sid, admin.ID); strings.Contains(live, "ls.example.test") {
		t.Errorf("deployed: %s", live)
	}
}

// Issue #184 round-12 review (9): withholding is a fixpoint — in a chain
// a → b → c where only c holds something a non-admin may not import, a and
// b are withheld too, whatever order the set is walked in (Go randomises
// it, so the set is built many times), and they are left out of the text
// adapted for a non-admin. This checks the set itself, not the refusal
// the import cost would give anyway.
func TestWithheldSnippetsAreAFixpoint(t *testing.T) {
	defs := caddy.CaddyfileSnippets("(a) {\n\timport b\n}\n(b) {\n\timport c\n}\n(c) {\n\theader X {env.HOME}\n}\n(d) {\n\theader X 1\n}\n")
	for range 64 {
		set := tenantSnippetSetFrom(defs)
		for _, name := range []string{"a", "b", "c"} {
			if set[name].Withheld == "" {
				t.Fatalf("%s is not withheld", name)
			}
		}
		if set["d"].Withheld != "" {
			t.Fatalf("d is withheld: %s", set["d"].Withheld)
		}
		if prefix := tenantSnippetPrefix(set); strings.Contains(prefix, "(a)") || strings.Contains(prefix, "(b)") || !strings.Contains(prefix, "(d)") {
			t.Fatalf("prefix: %s", prefix)
		}
	}
}

// Issue #184 round-12 review (8): a non-admin is told only that a snippet
// is not available — the same words as for a name the administrator never
// defined — not that it exists, why it is withheld, or what it imports.
func TestWithheldSnippetMessagesRevealNothing(t *testing.T) {
	s, _, sid, _, _, tenant := newRound12Fixture(t, round11WithheldSnippets, nil)
	for _, name := range []string{"cf", "filey", "viafile", "nosuch"} {
		why := s.tenantOwnTextViolation("import " + name)
		if why != tenantSnippetUnavailable(name) {
			t.Errorf("import %s: %q", name, why)
		}
		body, _ := json.Marshal(map[string]any{"label": "w", "enabled": true, "caddyfile_src": "w.example.test {\n\timport " + name + "\n}"})
		req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.apiV1CreateRawRoute(w, req)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "secrets") || strings.Contains(w.Body.String(), "CF_API_TOKEN") ||
			strings.Contains(w.Body.String(), "environment") || (name == "viafile" && strings.Contains(w.Body.String(), "filey")) {
			t.Errorf("import %s via the API: %d %s", name, w.Code, w.Body.String())
		}
	}
}
