// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Follow-ups to #184 (T-0935).

func TestHeldJSONIsClearedWhenTheRouteIsSavedAgain(t *testing.T) {
	e := newSecEnv(t)
	id, err := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "held", JSONData: "[]", Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	old := claimRoute("held.example.test", "203.0.113.1:80")
	if _, err := e.db.Exec(`UPDATE raw_routes SET held_json = ? WHERE id = ?`, old, id); err != nil {
		t.Fatal(err)
	}
	rec := e.apiJSON(t, "alice", http.MethodPut, fmt.Sprintf("/api/v1/raw-routes/%d", id), map[string]any{"json_data": claimRoute("held.example.test", "203.0.113.2:80"), "enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-save: %d %s", rec.Code, rec.Body.String())
	}
	if held, _ := models.GetRawRouteHeldJSON(e.db, id); held != "" {
		t.Errorf("held_json kept after the owner saved the route again: %s", held)
	}
}

func TestImportArgumentsCannotCompleteAPlaceholder(t *testing.T) {
	admin := "(site) {\n\theader X-Site {args[0]}.{args[1]}\n}\n\n(sub) {\n\t@{args[0]} host {args[0]}.example.com\n\trespond @{args[0]} 200\n}\n"
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets(admin))
	for _, sn := range []string{"site", "sub"} {
		if set[sn].Withheld != "" {
			t.Fatalf("fixture snippet %q withheld: %s", sn, set[sn].Withheld)
		}
	}
	check := func(text string) string {
		return tenantTextRules(text, set, tenantMaxNestingDepth, maxTenantCaddyfileBytes)
	}
	for _, text := range []string{
		"import site {file /etc/hostname}",
		"import site {env HOME}",
		"import site {ENV HOME}",
		"import site \"{ $\" HOME}",
		"import site a{ env.HOME}",
		"import site \"x{\" y",
		"import sub \"\"",
	} {
		if why := check(text); why == "" {
			t.Errorf("%q: allowed", text)
		}
	}
	for _, text := range []string{
		"import site a b",
		"import site \"{http.request.host}\" b",
		"import site a.b c-d",
		"import sub app",
		"import site \"\" b", // no matcher name made from it
	} {
		if why := check(text); why != "" {
			t.Errorf("%q: refused: %s", text, why)
		}
	}
}

func TestSanitizeCaddyError(t *testing.T) {
	dump := `{"error":"PANIC: runtime error: index out of range [3] with length 3\n\ngoroutine 1 [running]:\ngithub.com/caddyserver/caddy/v2/caddyconfig/caddyfile.(*parser).doImport(...)\n\t/go/pkg/mod/github.com/caddyserver/caddy/v2@v2.11.9/caddyconfig/caddyfile/parse.go:525 +0x1a4"}`
	if got := caddy.SanitizeCaddyError(dump); strings.Contains(got, "goroutine") || strings.Contains(got, "parse.go") || strings.Contains(got, "github.com") {
		t.Errorf("panic dump not removed: %q", got)
	}
	plain := `{"error":"adapting config using caddyfile: parsing caddyfile tokens for 'respond': wrong argument count, at Caddyfile:3 (github.com/caddyserver/caddy/v2/modules/caddyhttp/staticresp.go:123)"}`
	got := caddy.SanitizeCaddyError(plain)
	if !strings.Contains(got, "wrong argument count, at Caddyfile:3") || strings.Contains(got, "github.com") || strings.Contains(got, ".go:") {
		t.Errorf("plain error: %q", got)
	}
	if got := caddy.SanitizeCaddyError(strings.Repeat("x", 5000)); len(got) > 700 {
		t.Errorf("not shortened: %d bytes", len(got))
	}
}

func TestTenantAdaptErrorsCarryNoCaddyInternals(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"PANIC: boom\n\ngoroutine 7 [running]:\ngithub.com/caddyserver/caddy/v2/caddyconfig/caddyfile.(*parser).doImport()\n\t/go/pkg/mod/x/parse.go:525"}`)
	}))
	defer fake.Close()
	e := newSecEnv(t)
	base := caddy.New(fake.URL, "", "")
	_, err := e.s.tenantAdaptClient(base).Adapt("x.example.test {\n\trespond 1\n}\n")
	if err == nil || strings.Contains(err.Error(), "goroutine") || strings.Contains(err.Error(), "parse.go") {
		t.Errorf("tenant error: %v", err)
	}
	// An administrator still sees Caddy's own words.
	if _, err := base.Adapt("x.example.test {\n\trespond 1\n}\n"); err == nil || !strings.Contains(err.Error(), "goroutine") {
		t.Errorf("admin error changed: %v", err)
	}
}

func TestSnippetWaitSurvivesARestart(t *testing.T) {
	e := newSecEnv(t)
	since := time.Now().Add(-50 * time.Minute).Truncate(time.Second)
	e.s.rawMigMu.Lock()
	e.s.rawMig = tenantRawMigration{loaded: true, pending: map[int64]bool{5: true, 6: true},
		snippetWaits: map[int64]int{5: 3}, snippetSince: map[int64]time.Time{5: since}}
	if err := e.s.saveRawRouteMigrationLocked(); err != nil {
		t.Fatal(err)
	}
	// A restart: nothing in memory.
	e.s.rawMig = tenantRawMigration{}
	if err := e.s.loadRawRouteMigrationLocked(); err != nil {
		t.Fatal(err)
	}
	waits, got := e.s.rawMig.snippetWaits[5], e.s.rawMig.snippetSince[5]
	pending := e.s.rawMig.pending[5] && e.s.rawMig.pending[6]
	e.s.rawMigMu.Unlock()
	if !pending || waits != 3 || !got.Equal(since) {
		t.Errorf("after a restart: pending=%v waits=%d since=%v, want 3 since %v", pending, waits, got, since)
	}
}
