// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// round14Admin holds the administrator snippets the round-14 review used:
// one that puts the importer's block in after its own line (kept on purpose
// in round 13), and one that puts a keyed part of it in the same place.
const round14Admin = "(blockafter) {\n\treverse_proxy {args[0]}\n\t{block}\n}\n" +
	"(keyed) {\n\treverse_proxy {args[0]}\n\t{blocks.extra}\n}\n"

// round14HiddenMatchers is the round-14 review's shape: two named matchers
// of 2000 tokens written where Caddy, but not the text, starts a line
// (after an import's `{`, or after a {blocks.…} key), named 1664 times
// each. keyed selects the {blocks.extra} form.
func round14HiddenMatchers(keyed bool) (raw, adv string) {
	var b strings.Builder
	for _, m := range []string{"@m", "@n"} {
		def := m + " path" + strings.Repeat(" /x", 2000)
		if keyed {
			b.WriteString("import keyed 127.0.0.1:1 {\n\textra " + def + "\n}\n")
		} else {
			b.WriteString("import blockafter 127.0.0.1:1 { " + def + " }\n")
		}
	}
	b.WriteString("route {\n")
	for i := 0; i < 1664; i++ {
		b.WriteString("\tabort @m\n\tabort @n\n")
	}
	b.WriteString("}\n")
	adv = b.String()
	return "h.example.test {\n" + adv + "}\n", adv
}

// Issue #184 round-14 review (security 1): a matcher definition hidden in
// an import's block — on the line of its `{`, or after a {blocks.…} key —
// starts a line in Caddy (the block keeps the importer's import chain, so
// its first token, or a key's first value, starts a new line wherever the
// snippet puts it) but not in the text, so the matcher-copy limit charged
// it as one reference. Both shapes are refused before Caddy (0 adapts) on
// every path, the raw-route and proxy-host Advanced saves among them.
func TestMatchersHiddenInImportBlocksAreRefusedBeforeCaddy(t *testing.T) {
	for name, keyed := range map[string]bool{"block line": false, "blocks key": true} {
		t.Run(name, func(t *testing.T) {
			raw, adv := round14HiddenMatchers(keyed)
			if len(raw) > maxTenantCaddyfileBytes {
				t.Fatalf("the repro is %d bytes", len(raw))
			}
			round13RefusedEverywhere(t, round14Admin, raw, adv)
		})
	}
}

// Issue #184 round 14: inside an import's block every `{` and `}` must end
// its line — Caddy's dispenser takes a token after the import's `{` (or a
// nested one) into the block where the snippet puts it, as the start of a
// line, and skips a `}` with more after it — and, for a snippet that uses
// {blocks.…}, the word after a key may not be one that starts a matcher,
// snippet or `import` (Caddy starts a line with it). Everything else a
// block holds stays available: references to matchers anywhere, keyed
// values that are ordinary words, blocks written over several lines.
func TestImportBlockLineStarts(t *testing.T) {
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets(round14Admin))
	for _, name := range []string{"blockafter", "keyed"} {
		if why := set[name].Withheld; why != "" {
			t.Fatalf("%s is withheld: %s", name, why)
		}
	}
	lim := tenantTextLimits{maxDepth: tenantMaxNestingDepth, maxBytes: maxTenantCaddyfileBytes}
	refused := map[string]string{
		"content after the import's {":    "import blockafter a { @m path /x\n}\n",
		"one-line block":                  "import blockafter a { header X 1 }\n",
		"content after a nested {":        "import blockafter a {\n\theader {\n\t\tX 1\n\t}\n\thandle { @m path /x\n\t}\n}\n",
		"a } with more after it":          "import blockafter a {\n\theader X 1 } @m path /x\n}\n",
		"a } then a {":                    "import blockafter a {\n\theader } {\n\t\tX 1\n\t}\n}\n",
		"matcher after a key":             "import keyed a {\n\textra @m path /x\n}\n",
		"matcher after a key and a brace": "import keyed a {\n\textra {\n\t}\n\textra2 @m path /x\n}\n",
		"snippet name after a key":        "import keyed a {\n\textra (x) {\n\t\ty\n\t}\n}\n",
		"named route after a key":         "import keyed a {\n\textra &(x) {\n\t\ty\n\t}\n}\n",
	}
	for name, own := range refused {
		if why, _, _ := tenantTextCheck(own, set, lim); why == "" {
			t.Errorf("%s: %q is allowed", name, own)
		}
	}
	allowed := map[string]string{
		"block over several lines":     "import blockafter a {\n\theader_up X-Y 1\n}\n",
		"a reference after a word":     "@m path /x\nimport blockafter a {\n\trespond @m 403\n}\n",
		"keyed value, ordinary words":  "import keyed a {\n\textra header X 1\n}\n",
		"keyed block":                  "import keyed a {\n\textra {\n\t\theader X 1\n\t}\n}\n",
		"a matcher on its own line":    "import blockafter a {\n\t@m path /x\n\trespond @m 403\n}\n",
		"a keyed matcher on its line":  "import keyed a {\n\textra {\n\t\t@m path /x\n\t}\n}\n",
		"quoted brace after a word":    "import blockafter a {\n\theader X \"{\" \n}\n",
		"no block at all":              "import blockafter a\n",
		"a } that ends the import's":   "import blockafter a {\n\theader X 1\n\t}\n",
		"matcher after a {block} word": "import blockafter a {\n\theader @m X 1\n}\n",
	}
	for name, own := range allowed {
		if why, _, _ := tenantTextCheck(own, set, lim); why != "" {
			t.Errorf("%s: %q is refused: %s", name, own, why)
		}
	}
	// An administrator snippet whose own import block hides a definition
	// the same way is withheld.
	adm := tenantSnippetSetFrom(caddy.CaddyfileSnippets(round14Admin +
		"(hide) {\n\timport blockafter a { @h path /x\n\t}\n}\n" +
		"(hidekey) {\n\timport keyed a {\n\t\textra @h path /x\n\t}\n}\n" +
		"(hidenest) {\n\timport blockafter a {\n\t\timport keyed b {\n\t\t\textra @h path /x\n\t\t}\n\t}\n}\n"))
	for _, name := range []string{"hide", "hidekey", "hidenest"} {
		if adm[name].Withheld == "" {
			t.Errorf("%s is available", name)
		}
	}
	// At the top level of a whole Caddyfile, a snippet that puts the
	// importer's block at its own top level cannot be imported: the
	// block's lines would be site addresses there.
	top := tenantTextLimits{maxDepth: tenantMaxNestingDepth, maxBytes: maxTenantCaddyfileBytes, topLevel: true}
	if why, _, _ := tenantTextCheck("import blockafter a {\n\tb.example.test:1 b.example.test:2 {\n\t\trespond 1\n\t}\n}\n", set, top); !strings.Contains(why, "inside a site block") {
		t.Errorf("block at the top level: %q", why)
	}
	// With Caddy on PATH (the memory-capped shim): Caddy does define the
	// matcher written after the import's `{` — a small one, sent as is.
	bin, _ := lookPathCaddy()
	requireCaddy(t, bin, "the hidden definition is shown to Caddy (memory-capped)")
	out, err := adaptWithCaddyFiles(bin, []byte(round14Admin+"h.example.test {\n\timport blockafter 127.0.0.1:1 { @m path /hidden-def\n\t}\n\tabort @m\n}\n"), nil)
	if err != nil || !strings.Contains(string(out), "/hidden-def") {
		t.Errorf("want Caddy to use the hidden definition, got %v %.300s", err, out)
	}
}

// round14Adapted is an /adapt answer: one site on listen whose route sets
// X-Tag on host.
func round14Adapted(host, listen string) string {
	return `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":["` + listen + `"],"routes":[{"match":[{"host":["` + host +
		`"]}],"handle":[{"handler":"headers","response":{"set":{"X-Tag":["yes"]}}}],"terminal":true}]}}}}}}`
}

// Issue #184 round-14 review (code 1a): a save keeps a listen set typed in
// the form (a :7070 health-check listener) when the text names only the
// standard ports, so the upgrade migration keeps such a row — enabled, its
// routes and its listener deployed — as a fresh save would.
func TestMigrationKeepsAFormTypedListener(t *testing.T) {
	s, conn, sid, _, admin, tenant := newRound12Fixture(t, "", func(string) (int, string) {
		return 200, round14Adapted("fl.example.test", ":443")
	})
	src := "fl.example.test {\n\theader X-Tag yes\n}"
	js, listen, _, err := s.adaptRawRouteCaddyfileResult(s.tenantAdaptClient(s.Caddy), src)
	if err != nil || listen != "" {
		t.Fatalf("adapt: %v listen=%q", err, listen)
	}
	id, err := models.CreateRawRoute(conn, sid, tenant.ID, &models.RawRoute{Label: "fl", Enabled: true, CaddyfileSrc: src, JSONData: js,
		Listen: models.NormalizeRawRouteListen(models.ParseRawRouteListenInput(":7070"))})
	if err != nil {
		t.Fatal(err)
	}
	markPreUpgrade(t, conn, id)
	s.migrateTenantRawRoutes(sid, s.Caddy)
	rr, _ := models.GetRawRoute(conn, id)
	if !rr.Enabled || !strings.Contains(rr.JSONData, "X-Tag") || !strings.Contains(rr.Listen, ":7070") {
		t.Fatalf("the row was held: enabled=%v listen=%q %s", rr.Enabled, rr.Listen, rr.JSONData)
	}
	if live := liveFor(t, s, conn, sid, admin.ID); !strings.Contains(live, "fl.example.test") {
		t.Errorf("not deployed: %s", live)
	}
	rows, _ := models.ListRawRoutes(conn, sid, admin.ID, true, nil)
	if servers, _ := json.Marshal(s.buildRawListenServers(rows)); !strings.Contains(string(servers), ":7070") {
		t.Errorf("the :7070 listener is gone: %s", servers)
	}
}

// Issue #184 round-14 review (code 1b): v2.68.16's API stored json_data as
// sent, so a row may hold a one-route list where today's adapter answers a
// single route. The same routes: the migration keeps the row.
func TestMigrationKeepsAOneRouteListRow(t *testing.T) {
	s, conn, sid, _, admin, tenant := newRound12Fixture(t, "", func(string) (int, string) {
		return 200, round14Adapted("ol.example.test", ":443")
	})
	src := "ol.example.test {\n\theader X-Tag yes\n}"
	js, _, _, err := s.adaptRawRouteCaddyfileResult(s.tenantAdaptClient(s.Caddy), src)
	if err != nil || !strings.HasPrefix(js, "{") {
		t.Fatalf("adapt: %v %s", err, js)
	}
	id, err := models.CreateRawRoute(conn, sid, tenant.ID, &models.RawRoute{Label: "ol", Enabled: true, CaddyfileSrc: src, JSONData: "[" + js + "]"})
	if err != nil {
		t.Fatal(err)
	}
	markPreUpgrade(t, conn, id)
	s.migrateTenantRawRoutes(sid, s.Caddy)
	if rr, _ := models.GetRawRoute(conn, id); !rr.Enabled || !strings.Contains(rr.JSONData, "X-Tag") {
		t.Fatalf("the row was held: enabled=%v %s", rr.Enabled, rr.JSONData)
	}
	if live := liveFor(t, s, conn, sid, admin.ID); !strings.Contains(live, "ol.example.test") {
		t.Errorf("not deployed: %s", live)
	}
	// Different routes are still held.
	if rawRoutesJSONEqual("["+js+","+js+"]", js) || rawRoutesJSONEqual(`{"a":1}`, `[{"a":2}]`) || !rawRoutesJSONEqual(js, "["+js+"]") {
		t.Errorf("rawRoutesJSONEqual")
	}
}

// Issue #184 round-14 review (code 2): common administrator snippets that
// name a matcher after their arguments — `@{args[0]} host
// {args[0]}.example.com`, `@{args[0]} path {args[1]}` — are available to
// non-admins: a line-start token that begins with `@` is a matcher's name
// whatever the arguments are. A site address built from arguments stays
// withheld. With Caddy on PATH (capped), the subdomain snippet adapts to
// the host the argument names.
func TestMatcherNamedAfterArgumentsIsAvailable(t *testing.T) {
	admin := "(sub) {\n\t@{args[0]} host {args[0]}.example.com\n\thandle @{args[0]} {\n\t\treverse_proxy {args[1]}\n\t}\n}\n" +
		"(pm) {\n\t@{args[0]} path {args[1]}\n\trespond @{args[0]} 404\n}\n" +
		"(site) {\n\t{args[0]}.example.com {\n\t\trespond 1\n\t}\n}\n" +
		"(bare) {\n\t{args[0]} x\n}\n" +
		"(at) {\n\t@ {args[0]}\n}\n"
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets(admin))
	for _, name := range []string{"sub", "pm"} {
		if why := set[name].Withheld; why != "" {
			t.Errorf("%s is withheld: %s", name, why)
		}
	}
	for _, name := range []string{"site", "bare"} {
		if set[name].Withheld == "" {
			t.Errorf("%s is available", name)
		}
	}
	own := "w.example.test {\n\timport sub app 203.0.113.10:8080\n\timport pm old /old/*\n}\n"
	if why := tenantAdaptTextRules(tenantSnippetPrefix(set)+own, set); why != "" {
		t.Fatalf("refused: %s", why)
	}
	bin, _ := lookPathCaddy()
	requireCaddy(t, bin, "the subdomain snippet is adapted by the (memory-capped) Caddy")
	out, err := adaptWithCaddyFiles(bin, []byte(tenantSnippetPrefix(set)+own), nil)
	if err != nil || !strings.Contains(string(out), "app.example.com") || !strings.Contains(string(out), "/old/*") {
		t.Errorf("adapt: %v %.400s", err, out)
	}
}

// Issue #184 round-14 review (code 2): a row that waits only because the
// administrator's snippets do not allow its text (here: it imports a
// withheld snippet) is not tried again for ever — after rawMigSnippetRuns
// runs (and rawMigSnippetGrace, zero here) it is held like any refused
// row, with the reason; a row waiting for an unreachable Caddy is not.
func TestRowWaitingOnASnippetSettlesHeld(t *testing.T) {
	defer func(g time.Duration) { rawMigSnippetGrace = g }(rawMigSnippetGrace)
	rawMigSnippetGrace = 0
	s, conn, sid, _, _, tenant := newRound12Fixture(t, "(w) {\n\t{args[0]} x\n}\n", func(string) (int, string) {
		return 200, round14Adapted("sw.example.test", ":443")
	})
	id := round12StoredRow(t, conn, sid, tenant.ID, "sw", "sw.example.test {\n\timport w header\n}", "sw.example.test", "")
	for run := 1; run < rawMigSnippetRuns; run++ {
		s.migrateTenantRawRoutes(sid, s.Caddy)
		rr, _ := models.GetRawRoute(conn, id)
		if !s.rawRouteMigrationPending(*rr) {
			t.Fatalf("run %d: no longer pending: enabled=%v", run, rr.Enabled)
		}
	}
	s.migrateTenantRawRoutes(sid, s.Caddy)
	rr, _ := models.GetRawRoute(conn, id)
	if s.rawRouteMigrationPending(*rr) || rr.Enabled || strings.Contains(rr.JSONData, round12Secret) {
		t.Fatalf("after %d runs: pending=%v enabled=%v %s", rawMigSnippetRuns, s.rawRouteMigrationPending(*rr), rr.Enabled, rr.JSONData)
	}
	if held, _ := models.GetRawRouteHeldJSON(conn, id); !strings.Contains(held, round12Secret) {
		t.Errorf("the held routes were not kept: %q", held)
	}
	var detail string
	_ = conn.QueryRow(`SELECT COALESCE(detail, '') FROM activity_log WHERE action = 'rawroute_migration_disabled' ORDER BY id DESC LIMIT 1`).Scan(&detail)
	if !strings.Contains(detail, "snippet unavailable") {
		t.Errorf("activity log: %q", detail)
	}
	// Caddy unreachable: the row stays pending however often it is tried.
	s2, conn2, sid2, _, _, tenant2 := newRound12Fixture(t, "", nil)
	if _, err := conn2.Exec(`UPDATE caddy_servers SET admin_url = 'http://127.0.0.1:1' WHERE id = ?`, sid2); err != nil {
		t.Fatal(err)
	}
	s2.Caddy = caddy.New("http://127.0.0.1:1", "", "")
	id2 := round12StoredRow(t, conn2, sid2, tenant2.ID, "dn", "dn.example.test {\n\theader X 1\n}", "dn.example.test", "")
	for run := 0; run < 2*rawMigSnippetRuns; run++ {
		s2.migrateTenantRawRoutes(sid2, s2.Caddy)
	}
	if rr, _ := models.GetRawRoute(conn2, id2); !s2.rawRouteMigrationPending(*rr) {
		t.Errorf("a row waiting for Caddy was settled: enabled=%v", rr.Enabled)
	}
}

// round14StreamingAdapter is a Caddy admin API whose /adapt answers with a
// 128 MiB result, written in 64 KiB pieces; written() is how much of it
// the client let it write before closing the connection.
func round14StreamingAdapter(t *testing.T) (url string, written func() int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adapt" {
			_, _ = io.WriteString(w, "{}")
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		head := `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"handle":[{"handler":"static_response","body":"`
		if k, err := io.WriteString(w, head); err == nil {
			n.Add(int64(k))
		}
		chunk := strings.Repeat("x", 64<<10)
		for i := 0; i < 2048; i++ {
			k, err := io.WriteString(w, chunk)
			n.Add(int64(k))
			if err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		_, _ = io.WriteString(w, `"}]}]}}}}}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, n.Load
}

// round14WrittenLimit is the most of the 128 MiB answer a client that reads
// at most maxTenantAdaptBytes may let the server write: the cap, plus what
// the socket buffers hold.
const round14WrittenLimit = maxTenantAdaptBytes + 24<<20

// Issue #184 round-14 review (code 3a): the adapt client stops reading at
// its cap — it does not buffer the whole answer and then measure it (a
// size check after io.ReadAll passes the round-13 test, not this one).
func TestAdaptClientStopsReadingAtTheCap(t *testing.T) {
	url, written := round14StreamingAdapter(t)
	var s Server
	cl := s.tenantAdaptClient(caddy.New(url, "", ""))
	_, err := cl.Adapt("big.example.test {\n\trespond hi\n}")
	if err == nil || !caddy.IsCaddyfileRejected(err) {
		t.Errorf("adapt: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	w := written()
	t.Logf("the server wrote %d bytes of a 128 MiB answer", w)
	if w > round14WrittenLimit {
		t.Errorf("the client let the server write %d bytes (cap %d)", w, maxTenantAdaptBytes)
	}
}

// Issue #184 round-14 review (security 2): the export re-checks a
// non-admin's text through Caddy with the same 4 MiB cap on the answer as
// every other path; the row fails closed.
func TestExportAdaptClientIsCapped(t *testing.T) {
	url, written := round14StreamingAdapter(t)
	s, conn, sid, _, _, tenant := newAdaptRecorderFixture(t)
	if _, err := conn.Exec(`UPDATE caddy_servers SET admin_url = ? WHERE id = ?`, url, sid); err != nil {
		t.Fatal(err)
	}
	s.Caddy = caddy.New(url, "", "")
	cl := s.exportAdaptClient(sid)()
	if cl == nil || cl.MaxAdaptBytes != maxTenantAdaptBytes {
		t.Fatalf("export adapt client: %+v", cl)
	}
	src := "ex.example.test {\n\trespond hi\n}"
	rr := models.RawRoute{Label: "ex", Enabled: true, CaddyfileSrc: src, OwnerID: sql.NullInt64{Int64: tenant.ID, Valid: true},
		JSONData: `{"match":[{"host":["ex.example.test"]}],"handle":[{"handler":"static_response","body":"hi"}]}`}
	if why := s.caddyfileExportOptions(sid, false).RawRouteVeto(rr, src+"\n"); why == "" {
		t.Errorf("the row was exported")
	}
	time.Sleep(100 * time.Millisecond)
	w := written()
	t.Logf("Caddy wrote %d bytes of a 128 MiB answer", w)
	if w > round14WrittenLimit {
		t.Errorf("the export let Caddy write %d bytes (cap %d)", w, maxTenantAdaptBytes)
	}
}

// Issue #184 round 14: a site block is adapted once per listener port its
// addresses name, matcher copies included, so an Advanced route's matcher
// references × definitions are charged once per port, like its size: text
// within the limit on one port is refused on two.
func TestMatcherCopiesCountPerListener(t *testing.T) {
	body := "\t@m path" + strings.Repeat(" /x", 1000) + "\n\troute {\n" + strings.Repeat("\t\tabort @m\n", 200) + "\t}\n"
	top := tenantTextLimits{maxDepth: tenantMaxNestingDepth, maxBytes: maxTenantCaddyfileBytes, topLevel: true}
	if why, _, _ := tenantTextCheck(":10000 {\n"+body+"}\n", nil, top); why != "" {
		t.Fatalf("one port: %s", why)
	}
	if why, _, _ := tenantTextCheck(":10000, :10001 {\n"+body+"}\n", nil, top); !strings.Contains(why, "named matchers") {
		t.Errorf("two ports: %q", why)
	}
}

// Issue #184 round 14 (found by the differential's matcher invariant):
// Caddy records only the innermost import in a token's import chain, so
// two expansions of one `import` line of a snippet that end up back to
// back are compared by line numbers, and inside a block the second one's
// first line continues the first one's last line — `@m path …` after
// `header` reads as `header @m path …`, a reference to the matcher the
// first expansion defined. A snippet's first token is now charged as a
// possible reference, so text that fans such expansions out against a
// large definition is refused before Caddy (0 adapts) on every path.
// With Caddy on PATH (capped), a small version shows the reference.
func TestBackToBackSnippetExpansionsAreCharged(t *testing.T) {
	admin := "(s0) {\n\t@m path {args[:]}\n\theader\n}\n(s2) {\n\timport s0 {args[:]}\n}\n" +
		"(s3) {\n" + strings.Repeat("\timport s2 {args[:]}\n", 8) + "}\n" +
		"(s4) {\n" + strings.Repeat("\timport s3 {args[:]}\n", 8) + "}\n"
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets(admin))
	if sn := set["s0"]; sn.Withheld != "" || sn.BodyRefs < 1 {
		t.Fatalf("s0: withheld=%q refs=%d", sn.Withheld, sn.BodyRefs)
	}
	// A snippet whose last line is a matcher definition: the next copy's
	// first line (and its block) would join that definition, so the whole
	// body counts as definition.
	last := caddy.CaddyfileSnippets("(d) {\n\thandle {\n\t\trespond 1\n\t}\n\t@z path {args[:]}\n}\n")
	if len(last) != 1 || last[0].BodyDefWeight != last[0].BodyWeight || last[0].DefArgUses != last[0].ArgUses {
		t.Errorf("last-line definition: %+v", last)
	}
	adv := "route {\n\timport s2" + strings.Repeat(" /x", 2000) + "\n\timport s4 /s\n\timport s4 /s\n}\n"
	round13RefusedEverywhere(t, admin, "b.example.test {\n"+adv+"}\n", adv)
	bin, _ := lookPathCaddy()
	requireCaddy(t, bin, "the joined line is shown to Caddy (memory-capped)")
	small := "(s0) {\n\t@m path {args[:]}\n\theader\n}\n(s2) {\n\timport s0 {args[:]}\n}\n" +
		"b.example.test {\n\troute {\n\t\timport s2 /big\n\t\timport s2 /s\n\t}\n}\n"
	out, err := adaptWithCaddyFiles(bin, []byte(small), nil)
	if err != nil || !strings.Contains(string(out), `"Path":["/s"]`) {
		t.Errorf("want Caddy to read the second definition as a header with @m, got %v %.400s", err, out)
	}
}
