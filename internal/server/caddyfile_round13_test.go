// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// round13Admin writes adminCaddyfile as the server's CADDYFILE_PATH.
func round13Admin(t *testing.T, s *Server, adminCaddyfile string) {
	t.Helper()
	s.CaddyfilePath = filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(s.CaddyfilePath, []byte(adminCaddyfile), 0o644); err != nil {
		t.Fatal(err)
	}
}

// round13RefusedEverywhere drives raw and adv through every path that
// adapts a non-admin's text and checks each refuses it before Caddy's
// adapter sees anything.
func round13RefusedEverywhere(t *testing.T, admin, raw, adv string) {
	t.Helper()
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	round13Admin(t, s, admin)
	for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, raw, adv) {
		if why := tenantPathRefused(path, resp); why != "" {
			t.Errorf("%s: %s (%.300s)", path, why, resp.Body.String())
		}
	}
	if seen := rec.seen(); len(seen) != 0 {
		t.Errorf("%d text(s) reached Caddy's adapter", len(seen))
	}
}

// Issue #184 round-13 review (security 1): an administrator snippet whose
// line starts with a token built from the importer's arguments lets a
// non-admin choose that line's directive — `import` of a file among them.
// Refused before Caddy on every path (0 adapts), the raw-route save and
// the proxy host's Advanced save among them; with Caddy on PATH (the
// memory-capped shim), the unfiltered shape is shown to read a file.
func TestArgumentBuiltImportsAreRefusedBeforeCaddy(t *testing.T) {
	for name, admin := range map[string]string{
		"built word":   "(s) {\n\tim{args[0]} {args[1]}\n}\n",
		"placeholders": "(s) {\n\t{args[0]} {args[1]}\n}\n",
		"variadic":     "(s) {\n\t{args[:]}\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			args := "port /etc/passwd"
			if name != "built word" {
				args = "import /etc/passwd"
			}
			round13RefusedEverywhere(t, admin,
				"t.example.test {\n\timport s "+args+"\n}\n",
				"import s "+args+"\n")
		})
	}
	// Tenant arguments that hold `import` or a line break are refused
	// whatever the snippet does with them.
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets("(rp) {\n\treverse_proxy {args[0]}\n}\n"))
	for _, own := range []string{"x.test {\n\timport rp important\n}\n", "x.test {\n\timport rp \"a\nb\"\n}\n"} {
		if why, _, _ := tenantTextCheck(own, set, tenantTextLimits{maxDepth: 32, maxBytes: maxTenantCaddyfileBytes}); why == "" {
			t.Errorf("%q is allowed", own)
		}
	}
	bin, _ := lookPathCaddy()
	requireCaddy(t, bin, "the unfiltered shape is sent to the (memory-capped) Caddy")
	out, err := adaptWithCaddyFiles(bin, []byte("(s) {\n\tim{args[0]} {args[1]}\n}\nt.example.test {\n\timport s port inc\n}\n"),
		map[string]string{"inc": "header X-From-File yes\n"})
	if err != nil || !strings.Contains(string(out), "X-From-File") {
		t.Errorf("want Caddy to read the file through the snippet, got %v %.300s", err, out)
	}
}

// Issue #184 round 13 (1, 7, 8): which administrator snippets a non-admin
// may import, by where their placeholders sit. A placeholder after a
// token that Caddy always puts in on its line is fine; one that can start
// a line, a token made of placeholders and braces alone, a {block} that
// shares its line, or one inside a matcher definition is withheld. A
// {block} alone on its line — before or after the snippet's directives —
// is available (round 12 withheld both shapes).
func TestSnippetPlaceholderPlacement(t *testing.T) {
	admin := "" +
		"(rp) {\n\treverse_proxy {args[0]}\n}\n" +
		"(auth) {\n\theader Authorization \"Bearer {args[0]}\"\n}\n" +
		"(hp) {\n\treverse_proxy {args[0]}:{args[1]}\n}\n" +
		"(cors) {\n\t@cors header Origin {args[0]}\n\theader @cors Access-Control-Allow-Origin \"{args[0]}\"\n}\n" +
		"(hdrs) {\n\theader {args[:]}\n}\n" +
		"(blockafter) {\n\treverse_proxy {args[0]}\n\t{block}\n}\n" +
		"(blockfirst) {\n\t{block}\n\treverse_proxy {args[0]}\n}\n" +
		"(blockinner) {\n\treverse_proxy {args[0]} {\n\t\t{block}\n\t}\n}\n" +
		"(builtword) {\n\tim{args[0]} {args[1]}\n}\n" +
		"(linestart) {\n\t{args[0]} {args[1]}\n}\n" +
		"(emptyvariadic) {\n\t{args[:0]} {\n\t\theader X 1\n\t}\n}\n" +
		"(variadicfirst) {\n\t{args[:]} x\n}\n" +
		"(afterblock) {\n\troute {\n\t\t{block}\n\t}\n\theader X 1\n}\n" +
		"(bracebuilt) {\n\theader X {args[0]}{\n}\n" +
		"(twoonly) {\n\theader X {args[0]}{args[1]}\n}\n" +
		"(blockline) {\n\treverse_proxy {args[0]} {block}\n}\n" +
		"(blockthen) {\n\t{block} header\n}\n" +
		"(defblock) {\n\t@m {\n\t\t{block}\n\t}\n}\n" +
		"(defimport) {\n\t@m {\n\t\timport rp a\n\t}\n}\n" +
		"(braceimport) {\n\timport rp \"{\"\n}\n"
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets(admin))
	available := []string{"rp", "auth", "hp", "cors", "hdrs", "blockafter", "blockfirst", "blockinner", "afterblock"}
	withheld := []string{"builtword", "linestart", "emptyvariadic", "variadicfirst", "bracebuilt", "twoonly", "blockline", "blockthen", "defblock", "defimport", "braceimport"}
	for _, name := range available {
		if why := set[name].Withheld; why != "" {
			t.Errorf("%s is withheld: %s", name, why)
		}
	}
	for _, name := range withheld {
		if set[name].Withheld == "" {
			t.Errorf("%s is available", name)
		}
		if strings.Contains(tenantSnippetPrefix(set), "("+name+")") {
			t.Errorf("%s is in the text adapted for a non-admin", name)
		}
	}
	// Inside a site, a snippet that starts with the importer's block
	// may be imported; at the top level of a whole Caddyfile it may not
	// (Caddy's parser fails there when the block is empty).
	in := "b.example.test {\n\timport blockfirst 127.0.0.1:8080 {\n\t\theader X 1\n\t}\n}\n"
	if why := tenantAdaptTextRules(tenantSnippetPrefix(set)+in, set); why != "" {
		t.Errorf("import blockfirst inside a site: %q", why)
	}
	if why := tenantAdaptTextRules(tenantSnippetPrefix(set)+"import blockfirst x\n"+in, set); why == "" {
		t.Errorf("import blockfirst at the top level is allowed")
	}
	bin, _ := lookPathCaddy()
	requireCaddy(t, bin, "the available {block} shapes are adapted by the (memory-capped) Caddy")
	for _, name := range []string{"blockafter", "blockfirst", "blockinner"} {
		own := strings.Replace(in, "blockfirst", name, 1)
		if name == "blockinner" { // the block goes inside reverse_proxy
			own = strings.Replace(own, "header X 1", "header_up X-Y 1", 1)
		}
		text := tenantSnippetPrefix(set) + own
		out, err := adaptWithCaddyFiles(bin, []byte(text), nil)
		if err != nil || !strings.Contains(string(out), "127.0.0.1:8080") {
			t.Errorf("%s: %v %.300s", name, err, out)
		}
	}
}

// Issue #184 round-13 review (security 4): an administrator snippet that
// starts with a variadic placeholder expanding to nothing before a `{`
// closes the non-admin's site block early, and the import after it then
// runs at the top level, where Caddy's parser panics. Refused before
// Caddy (0 adapts); with Caddy on PATH (capped), the shape is shown to
// break Caddy's parser when sent anyway.
func TestEmptyVariadicSnippetCannotEndTheSiteEarly(t *testing.T) {
	admin := "(s) {\n\t{args[:0]} {\n\t\theader X 1\n\t}\n}\n(t) {\n\t{args[:]} {\n\t\theader X 1\n\t}\n}\n"
	raw := "t.example.test {\n\timport s\n\timport t\n}\n"
	round13RefusedEverywhere(t, admin, raw, "import s\nimport t\n")
	bin, _ := lookPathCaddy()
	requireCaddy(t, bin, "the unfiltered shape is sent to the (memory-capped) Caddy")
	out, err := adaptWithCaddyFiles(bin, []byte(admin+raw), nil)
	if err == nil {
		t.Errorf("want Caddy to fail on the shape, got %.300s", out)
	} else {
		t.Logf("Caddy on the unfiltered shape: %.200v", err)
	}
}

// round13MatcherRepro is the round-13 review's text: two 8000-token path
// matchers, each named 1860 times inside a route block — 65,517 bytes,
// within 64 KiB, adapted to 119 MB of JSON. adv is the same without the
// site block.
func round13MatcherRepro() (raw, adv string) {
	var b strings.Builder
	for _, m := range []string{"@a", "@b"} {
		b.WriteString(m + " path")
		b.WriteString(strings.Repeat(" /", 8000))
		b.WriteString("\n")
	}
	b.WriteString("route {\n")
	for i := 0; i < 1860; i++ {
		b.WriteString("abort @a\nabort @b\n")
	}
	b.WriteString("}\n")
	adv = b.String()
	return "m.example.test {\n" + adv + "}\n", adv
}

// Issue #184 round-13 review (code 1): naming a matcher copies its whole
// definition into the adapted config, so text that names large matchers
// many times is refused before Caddy (0 adapts) on every path, the
// review's 65,517-byte text among them; and so is a much smaller one whose
// size alone is fine. A few references to short matchers are fine.
func TestMatcherReuseIsChargedBeforeCaddy(t *testing.T) {
	raw, adv := round13MatcherRepro()
	t.Run("review text", func(t *testing.T) { round13RefusedEverywhere(t, "", raw, adv) })
	var b strings.Builder
	b.WriteString("@big path")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, " /p%04d", i)
	}
	b.WriteString("\nroute {\n")
	for i := 0; i < 500; i++ {
		b.WriteString("abort @big\n")
	}
	b.WriteString("}\n")
	small := b.String()
	if len(small) > 16<<10 {
		t.Fatalf("the small case is %d bytes", len(small))
	}
	t.Run("small text", func(t *testing.T) { round13RefusedEverywhere(t, "", "m.example.test {\n"+small+"}\n", small) })
	ok := "@api path /api/*\n@static path /static/*\nhandle @api {\n\treverse_proxy 203.0.113.10:8080\n}\nhandle @static {\n\theader Cache-Control max-age=3600\n}\nrespond @api 200\n"
	if why := tenantTextRules(ok, nil, tenantMaxNestingDepth, maxTenantCaddyfileBytes); why != "" {
		t.Errorf("ordinary matcher use is refused: %s", why)
	}
}

// Issue #184 round-13 review (code 1b): an adapted config larger than a
// non-admin may have is refused as the text's own fault (not stored, not
// a transient error), and the client stops reading it.
func TestOversizedAdaptAnswerIsRefusedNotStored(t *testing.T) {
	huge := `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["big.example.test"]}],"handle":[{"handler":"static_response","body":"` +
		strings.Repeat("x", 5<<20) + `"}]}]}}}}}}`
	s, conn, sid, _, _, tenant := newRound12Fixture(t, "", func(string) (int, string) { return 200, huge })
	body, _ := json.Marshal(map[string]any{"label": "big", "enabled": true, "caddyfile_src": "big.example.test {\n\trespond hi\n}"})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiV1CreateRawRoute(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("save: %d %.200s", w.Code, w.Body.String())
	}
	var n int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM raw_routes WHERE label = 'big'`).Scan(&n)
	if n != 0 {
		t.Errorf("%d row(s) stored", n)
	}
	_, err := s.tenantAdaptClient(s.Caddy).Adapt("big.example.test {\n\trespond hi\n}")
	if err == nil || !caddy.IsCaddyfileRejected(err) {
		t.Errorf("adapt: %v (rejected=%v)", err, caddy.IsCaddyfileRejected(err))
	}
	// A JSON-only save over the stored size is refused too.
	big := `{"match":[{"host":["big.example.test"]}],"handle":[{"handler":"static_response","body":"` + strings.Repeat("y", 3<<20) + `"}]}`
	body, _ = json.Marshal(map[string]any{"label": "bigjson", "enabled": true, "json_data": big})
	req = asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.apiV1CreateRawRoute(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("JSON-only save: %d %.200s", w.Code, w.Body.String())
	}
}

// Issue #184 round-13 review (security 2): empty tokens cost Caddy as
// much as short ones, so a snippet that fans a thousand empty arguments
// out sixty times, under 31 nested blocks, is refused before Caddy on
// every path (0 adapts), though its bytes fit.
func TestEmptyTokensAreCharged(t *testing.T) {
	admin := "(s) {\n" + strings.Repeat("\theader {args[:]}\n", 60) + "}\n"
	inner := strings.Repeat("route {\n", 31) + "import s" + strings.Repeat(` ""`, 1000) + "\n" + strings.Repeat("}\n", 31)
	round13RefusedEverywhere(t, admin, "e.example.test {\n"+inner+"}\n", inner)
}

// round13Fresh stores src as a non-admin's Advanced route the way an
// earlier version did, with the routes the fake Caddy adapts it to today
// (so only what the test changes can make the migration hold it).
func round13Fresh(t *testing.T, s *Server, conn *sql.DB, sid, owner int64, label, src string) int64 {
	t.Helper()
	js, listen, _, err := s.adaptRawRouteCaddyfileResult(s.tenantAdaptClient(s.Caddy), src)
	if err != nil {
		t.Fatal(err)
	}
	id, err := models.CreateRawRoute(conn, sid, owner, &models.RawRoute{Label: label, Enabled: true, CaddyfileSrc: src, Listen: listen, JSONData: js})
	if err != nil {
		t.Fatal(err)
	}
	markPreUpgrade(t, conn, id)
	return id
}

// Issue #184 round-13 review (security 3): a row v2.68.16 stored with
// harmless text but routes that came from elsewhere (a file another block
// of its paste imported) is held by the upgrade migration whatever its
// text holds — no `import` needed, and none hidden by a carriage return —
// and its routes are kept for an administrator only. A row whose routes
// are what its text adapts to is kept.
func TestMigrationHoldsRowsWhoseRoutesDoNotMatchTheirText(t *testing.T) {
	s, conn, sid, fc, admin, tenant := newRound12Fixture(t, "(sites) {\n\theader X-Sites yes\n}\n", func(body string) (int, string) {
		switch {
		case strings.Contains(body, "leak.example.test"):
			return 200, round12Adapted("leak.example.test", "X-Decoy")
		case strings.Contains(body, "cr.example.test"):
			return 200, round12Adapted("cr.example.test", "X-Sites")
		}
		return 200, round12Adapted("fine.example.test", "X-Fine")
	})
	decoy := round12StoredRow(t, conn, sid, tenant.ID, "leak", "leak.example.test {\n\trespond \"decoy\"\n}", "leak.example.test", "")
	cr := round12StoredRow(t, conn, sid, tenant.ID, "cr", "cr.example.test {\n\theader {\n\t\timp\rort sites\n\t}\n}", "cr.example.test", "")
	fine := round13Fresh(t, s, conn, sid, tenant.ID, "fine", "fine.example.test {\n\theader X-Fine yes\n}")
	_ = s.syncCaddy(sid, false)
	if loads := fc.seenLoads(); strings.Contains(loads, round12Secret) {
		t.Errorf("the planted content was pushed to Caddy: %.400s", loads)
	}
	if live := liveFor(t, s, conn, sid, admin.ID); strings.Contains(live, round12Secret) || !strings.Contains(live, "fine.example.test") {
		t.Errorf("live routes: %s", live)
	}
	for _, id := range []int64{decoy, cr} {
		rr, _ := models.GetRawRoute(conn, id)
		if rr.Enabled || strings.Contains(rr.JSONData, round12Secret) {
			t.Errorf("row %d: enabled=%v %s", id, rr.Enabled, rr.JSONData)
		}
		held, _ := models.GetRawRouteHeldJSON(conn, id)
		if !strings.Contains(held, round12Secret) {
			t.Errorf("row %d: the held routes were not kept: %q", id, held)
		}
	}
	if rr, _ := models.GetRawRoute(conn, fine); !rr.Enabled {
		t.Errorf("a row whose routes match its text was held")
	}
	// The held routes are for an administrator only.
	get := func(u *models.User, id int64) *httptest.ResponseRecorder {
		sid := strconv.FormatInt(id, 10)
		w := httptest.NewRecorder()
		s.apiV1HeldRawRouteJSON(w, asUser(httptest.NewRequest(http.MethodGet, "/api/v1/raw-routes/"+sid+"/held-json", nil), 1, u, map[string]string{"id": sid}))
		return w
	}
	if w := get(admin, decoy); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), round12Secret) {
		t.Errorf("administrator: %d %.200s", w.Code, w.Body.String())
	}
	if w := get(tenant, decoy); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), round12Secret) {
		t.Errorf("owner: %d %.200s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	s.apiV1GetRawRoute(w, asUser(httptest.NewRequest(http.MethodGet, "/api/v1/raw-routes/x", nil), sid, tenant, map[string]string{"id": strconv.FormatInt(decoy, 10)}))
	if strings.Contains(w.Body.String(), round12Secret) {
		t.Errorf("the owner's API view holds the held routes: %.300s", w.Body.String())
	}
}

// Issue #184 round-13 review (code 2): a sync that read a pending row
// before the migration (or a save) let it go must not deploy the copy it
// read — the routes stored before the upgrade.
func TestSyncDoesNotDeployAStaleCopyOfAMigratedRow(t *testing.T) {
	s, conn, sid, _, admin, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", func(string) (int, string) {
		return 200, round12Adapted("st.example.test", "X-Tag")
	})
	round12StoredRow(t, conn, sid, tenant.ID, "st", "st.example.test {\n\theader {\n\t\timport tag\n\t}\n}", "st.example.test", "")
	// The sync's copy, read while the row waits.
	stale, err := models.ListRawRoutes(conn, sid, admin.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if live, _ := json.Marshal(s.buildMergedRoutes(nil, nil, stale)); strings.Contains(string(live), round12Secret) {
		t.Fatalf("deployed while pending: %s", live)
	}
	// Another sync's migration holds it meanwhile.
	s.migrateTenantRawRoutes(sid, s.Caddy)
	if live, _ := json.Marshal(s.buildMergedRoutes(nil, nil, stale)); strings.Contains(string(live), round12Secret) {
		t.Errorf("the stale copy was deployed: %s", live)
	}
	listeners, _ := json.Marshal(s.buildRawListenServers(stale))
	if strings.Contains(string(listeners), round12Secret) {
		t.Errorf("the stale copy opened a listener: %s", listeners)
	}
}

// Issue #184 round-13 review (code 2), under -race: syncs of one server
// run at once while the migration adapts slowly; no /load ever carries a
// pending row's planted routes.
func TestConcurrentSyncsNeverDeployPendingRows(t *testing.T) {
	s, conn, sid, fc, _, tenant := newRound12Fixture(t, "(tag) {\n\tX-Tag yes\n}\n", func(body string) (int, string) {
		time.Sleep(3 * time.Millisecond)
		for i := 0; i < 6; i++ {
			if strings.Contains(body, fmt.Sprintf("c%d.example.test", i)) {
				return 200, round12Adapted(fmt.Sprintf("c%d.example.test", i), "X-Tag")
			}
		}
		return 200, round12Adapted("other.example.test", "X-Other")
	})
	for i := 0; i < 6; i++ {
		h := fmt.Sprintf("c%d.example.test", i)
		round12StoredRow(t, conn, sid, tenant.ID, h, h+" {\n\theader {\n\t\timport tag\n\t}\n}", h, "")
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 3; k++ {
				_ = s.syncCaddy(sid, false)
			}
		}()
	}
	wg.Wait()
	if loads := fc.seenLoads(); strings.Contains(loads, round12Secret) {
		t.Errorf("a pending row's planted routes were pushed: %.300s", loads)
	}
}

// Issue #184 round-13 review (code 3): a non-admin's JSON-only row stored
// before the upgrade is held (it cannot be checked against text), but its
// routes are kept for an administrator, who can restore them; a JSON-only
// row created through the current API is not taken by a rebuild of a
// corrupt migration state.
func TestJSONOnlyRowsAreKeptForReview(t *testing.T) {
	s, conn, sid, _, admin, tenant := newRound12Fixture(t, "", nil)
	old := round12StoredRow(t, conn, sid, tenant.ID, "jo.example.test", "", "jo.example.test", "")
	before, _ := models.GetRawRoute(conn, old)
	s.migrateTenantRawRoutes(sid, s.Caddy)
	rr, _ := models.GetRawRoute(conn, old)
	held, _ := models.GetRawRouteHeldJSON(conn, old)
	if rr.Enabled || rr.JSONData != "[]" || held != before.JSONData {
		t.Fatalf("after the migration: enabled=%v json=%s held=%q", rr.Enabled, rr.JSONData, held)
	}
	// The administrator restores the reviewed routes.
	body, _ := json.Marshal(map[string]any{"json_data": held, "enabled": true})
	id := strconv.FormatInt(old, 10)
	req := asUser(httptest.NewRequest(http.MethodPut, "/api/v1/raw-routes/"+id, strings.NewReader(string(body))), sid, admin, map[string]string{"id": id})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.apiV1UpdateRawRoute(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	if live := liveFor(t, s, conn, sid, admin.ID); !strings.Contains(live, "jo.example.test") {
		t.Errorf("the restored row is not deployed: %s", live)
	}
	// A JSON-only row made through today's API, then a corrupt state.
	body, _ = json.Marshal(map[string]any{"label": "new", "enabled": true,
		"json_data": `{"match":[{"host":["nj.example.test"]}],"handle":[{"handler":"static_response","body":"ok"}]}`})
	req = asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.apiV1CreateRawRoute(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	_ = models.SetSetting(conn, settingTenantRawRouteMigration, "{corrupt")
	s.rawMig = tenantRawMigration{}
	s.migrateTenantRawRoutes(sid, s.Caddy)
	if live := liveFor(t, s, conn, sid, admin.ID); !strings.Contains(live, "nj.example.test") || !strings.Contains(live, "jo.example.test") {
		t.Errorf("after a rebuild of the state: %s", live)
	}
}

// Issue #184 round-13 review (code 5), under -race: a sync swaps s.Caddy
// for its server's client while requests read it (the tenant guard's
// admin hosts, a save's adapt client).
func TestCaddyClientSwapIsRaceFree(t *testing.T) {
	s, _, sid, _, _, _ := newRound12Fixture(t, "", func(string) (int, string) {
		return 200, round12Adapted("rc.example.test", "X-Now")
	})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k := 0; k < 20; k++ {
			_ = s.syncCaddy(sid, false)
		}
		close(stop)
	}()
	// Each reader in its own goroutine: one that takes the lock would
	// otherwise order the others' reads after the swap.
	for _, read := range []func(){
		func() { _ = s.adminHostSet() },
		func() { _ = s.caddyForServer(sid + 1000) },
		func() { _ = s.exportCaddyClient(sid + 1000) },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				read()
			}
		}()
	}
	wg.Wait()
	// The swap itself against each reader, with nothing else between them
	// to order the two (a reader that skips caddyClient races here).
	cl := s.caddyClient()
	for _, read := range []func(){
		func() { _ = s.adminHostSet() },
		func() { _ = s.caddyForServer(sid + 1000) },
	} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for k := 0; k < 200; k++ {
				s.setCaddyClient(caddy.New(cl.AdminURL, "", ""))
			}
		}()
		for k := 0; k < 200; k++ {
			read()
		}
		<-done
	}
}

// Issue #184 round 13 (code 1c, measured): Caddy adapts a site block once
// for every listener port its addresses name — a 20 KB site on 300 ports
// adapted to 18.8 MB of JSON and peaked at 223 MB — so a whole Caddyfile
// is charged once per port of its widest site block. The review-shaped
// text is refused on the raw-route paths before Caddy (0 adapts); a site
// on http:// and https:// is fine; a snippet that opens a site on several
// addresses cannot be imported at the top level.
func TestSiteOnManyPortsIsCharged(t *testing.T) {
	var keys []string
	for i := 0; i < 300; i++ {
		keys = append(keys, fmt.Sprintf(":%d", 10000+i))
	}
	var body strings.Builder
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&body, "\theader /p%d/* X-H%d \"v%d\"\n", i, i, i)
	}
	raw := strings.Join(keys, ", ") + " {\n" + body.String() + "}\n"
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, raw, "respond 1") {
		if !strings.HasPrefix(path, "raw-route") {
			continue
		}
		if why := tenantPathRefused(path, resp); why != "" {
			t.Errorf("%s: %s", path, why)
		}
	}
	for _, seen := range rec.seen() {
		if strings.Contains(seen, ":10000") {
			t.Errorf("the text reached Caddy's adapter")
		}
	}
	if why := s.tenantRawRouteTextProblem("http://two.example.test, https://two.example.test {\n\trespond 1\n}\n"); why != "" {
		t.Errorf("http and https: %q", why)
	}
	round13Admin(t, s, "(multi) {\n\t:1 :2 {\n\t\trespond 1\n\t}\n}\n(one) {\n\tone.example.test {\n\t\trespond 1\n\t}\n}\n")
	if why := s.tenantRawRouteTextProblem("import multi\n"); !strings.Contains(why, "inside a site block") {
		t.Errorf("import multi at the top level: %q", why)
	}
	if why := s.tenantRawRouteTextProblem("import one\n"); why != "" {
		t.Errorf("import one at the top level: %q", why)
	}
}
