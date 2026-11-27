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

	"github.com/X4Applegate/caddyui/internal/models"
)

// claimRoute is an Advanced route's JSON matching host (or no host when
// host is ""), proxying to dial.
func claimRoute(host, dial string) string {
	r := map[string]any{"handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": dial}}}}}
	if host != "" {
		r["match"] = []any{map[string]any{"host": []any{host}}}
	}
	b, _ := json.Marshal(r)
	return string(b)
}

func (e *secEnv) apiJSON(t *testing.T, who, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	e.attachSession(req, who)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func rawRouteCount(t *testing.T, e *secEnv) int {
	t.Helper()
	rows, err := models.ListRawRoutes(e.db, 1, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// claimEnv seeds an administrator's proxy host and Advanced route and bob's
// Advanced route, each on a host of its own.
func claimEnv(t *testing.T) *secEnv {
	t.Helper()
	e := newSecEnv(t)
	if _, err := models.CreateProxyHost(e.db, 1, 0, &models.ProxyHost{Domains: "admin.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateRawRoute(e.db, 1, 0, &models.RawRoute{Label: "admin raw", JSONData: claimRoute("adminraw.example.test", "10.0.0.6:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob", JSONData: claimRoute("bob.example.test", "10.0.0.7:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestTenantRawRouteCannotClaimAnotherOwnersHost(t *testing.T) {
	refused := map[string]string{
		"an administrator's proxy host":              claimRoute("admin.example.test", "203.0.113.9:80"),
		"the same host in capitals":                  claimRoute("ADMIN.example.test.", "203.0.113.9:80"),
		"an administrator's Advanced route":          claimRoute("adminraw.example.test", "203.0.113.9:80"),
		"another tenant's Advanced route":            claimRoute("bob.example.test", "203.0.113.9:80"),
		"no host matcher":                            claimRoute("", "203.0.113.9:80"),
		"a catch-all host":                           claimRoute("*", "203.0.113.9:80"),
		"a two-label wildcard":                       claimRoute("*.*", "203.0.113.9:80"),
		"a placeholder host":                         claimRoute("{http.request.host}", "203.0.113.9:80"),
		"one host matcher set of two without a host": `{"match":[{"host":["alice.example.test"]},{"path":["/x"]}],"handle":[{"handler":"static_response","body":"x"}]}`,
		"a second route without a host":              `[` + claimRoute("alice.example.test", "203.0.113.9:80") + `,` + claimRoute("", "203.0.113.9:80") + `]`,
	}
	for name, js := range refused {
		t.Run("form/"+name, func(t *testing.T) {
			e := claimEnv(t)
			before := rawRouteCount(t, e)
			rec := e.do(t, "alice", http.MethodPost, "/raw-routes", url.Values{"label": {"x"}, "json_data": {js}, "enabled": {"on"}})
			if rec.Code == http.StatusSeeOther {
				t.Fatalf("accepted (redirect to %s)", rec.Header().Get("Location"))
			}
			if !strings.Contains(rec.Body.String(), "Not allowed for a non-admin account") {
				t.Errorf("no reason shown: %s", excerpt(rec.Body.String(), "rror"))
			}
			if n := rawRouteCount(t, e); n != before {
				t.Errorf("%d route(s) stored, want %d", n, before)
			}
		})
		t.Run("api/"+name, func(t *testing.T) {
			e := claimEnv(t)
			before := rawRouteCount(t, e)
			rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "x", "json_data": js, "enabled": true})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if n := rawRouteCount(t, e); n != before {
				t.Errorf("%d route(s) stored, want %d", n, before)
			}
		})
	}

	// Updates: alice's own route may not be moved onto a claimed host.
	e := claimEnv(t)
	id, err := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "alice", JSONData: claimRoute("alice.example.test", "203.0.113.9:80"), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	path := "/raw-routes/" + strconv.FormatInt(id, 10)
	rec := e.do(t, "alice", http.MethodPost, path, url.Values{"label": {"alice"}, "json_data": {claimRoute("admin.example.test", "203.0.113.9:80")}, "enabled": {"on"}})
	if rec.Code == http.StatusSeeOther {
		t.Errorf("form update onto an administrator's host was accepted")
	}
	rec = e.apiJSON(t, "alice", http.MethodPut, "/api/v1/raw-routes/"+strconv.FormatInt(id, 10), map[string]any{"json_data": claimRoute("bob.example.test", "203.0.113.9:80"), "enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("API update onto another tenant's host: status %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got, _ := models.GetRawRoute(e.db, id); got == nil || !strings.Contains(got.JSONData, "alice.example.test") {
		t.Errorf("the stored route changed: %+v", got)
	}
}

func TestTenantRawRouteMayUseItsOwnHosts(t *testing.T) {
	e := claimEnv(t)
	// alice's own proxy host's name, a fresh name, and a wildcard of her own.
	if _, err := models.CreateProxyHost(e.db, 1, e.ids["alice"], &models.ProxyHost{Domains: "own.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.8", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"own.example.test", "fresh.example.test", "*.alice.example.test"} {
		rec := e.do(t, "alice", http.MethodPost, "/raw-routes", url.Values{"label": {host}, "json_data": {claimRoute(host, "203.0.113.9:80")}, "enabled": {"on"}})
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s: status %d, want a redirect: %s", host, rec.Code, excerpt(rec.Body.String(), "rror"))
		}
	}
	// Re-saving a route unchanged is not a conflict with itself.
	rows, _ := models.ListRawRoutes(e.db, 1, e.ids["alice"], false, nil)
	if len(rows) == 0 {
		t.Fatal("no route stored")
	}
	rec := e.apiJSON(t, "alice", http.MethodPut, "/api/v1/raw-routes/"+strconv.FormatInt(rows[0].ID, 10), map[string]any{"json_data": rows[0].JSONData, "enabled": true})
	if rec.Code != http.StatusOK {
		t.Errorf("re-save: status %d: %s", rec.Code, rec.Body.String())
	}
	// The administrator is not restricted.
	rec = e.do(t, "admin", http.MethodPost, "/raw-routes", url.Values{"label": {"a"}, "json_data": {claimRoute("bob.example.test", "10.0.0.9:80")}, "enabled": {"on"}})
	if rec.Code != http.StatusSeeOther {
		t.Errorf("admin: status %d, want a redirect", rec.Code)
	}
}

func TestTenantHostlessRouteNeedsAListenerOfItsOwn(t *testing.T) {
	e := claimEnv(t)
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "x", "json_data": claimRoute("", "203.0.113.9:80"), "listen": ":7070", "enabled": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("own port: status %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob port", JSONData: claimRoute("bobport.example.test", "10.0.0.7:80"), Listen: `[":7171"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec = e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "y", "json_data": claimRoute("", "203.0.113.9:80"), "listen": "127.0.0.1:7171", "enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("port shared with bob: status %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestSyncDoesNotDeployForeignHostClaims(t *testing.T) {
	e := claimEnv(t)
	alice := e.ids["alice"]
	// Stored by a path that did not check (or before the rule).
	bad := []models.RawRoute{
		{Label: "admin host", JSONData: claimRoute("admin.example.test", "203.0.113.11:80")},
		{Label: "admin raw host", JSONData: claimRoute("adminraw.example.test", "203.0.113.12:80")},
		{Label: "older tenant host", JSONData: claimRoute("bob.example.test", "203.0.113.13:80")},
		{Label: "catch-all", JSONData: claimRoute("", "203.0.113.14:80")},
	}
	for i := range bad {
		bad[i].Enabled = true
		if _, err := models.CreateRawRoute(e.db, 1, alice, &bad[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := models.CreateRawRoute(e.db, 1, alice, &models.RawRoute{Label: "fine", JSONData: claimRoute("alice.example.test", "203.0.113.15:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	proxies, redirs, raws, _, _ := e.s.serverResources(1)
	_, _, kept := e.s.withoutForeignHostClaims(0, proxies, redirs, raws)
	b, _ := json.Marshal(e.s.buildMergedRoutes(proxies, redirs, kept))
	out := string(b)
	for _, dial := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"} {
		if strings.Contains(out, dial) {
			t.Errorf("a route of alice claiming another owner's host (%s) is deployed", dial)
		}
	}
	for _, dial := range []string{"203.0.113.15", "10.0.0.6", "10.0.0.7"} {
		if !strings.Contains(out, dial) {
			t.Errorf("route to %s is missing:\n%s", dial, out)
		}
	}

	// Through a real sync: nothing pushed to Caddy carries the held routes.
	e.mu.Lock()
	e.reqs = nil
	e.mu.Unlock()
	if err := e.s.syncCaddy(1, false); err != nil {
		t.Logf("sync: %v", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	pushed := false
	for _, rq := range e.reqs {
		if strings.Contains(rq, "203.0.113.15") {
			pushed = true
		}
		for _, dial := range []string{"203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"} {
			if strings.Contains(rq, dial) {
				t.Errorf("the sync pushed a held route (%s): %s", dial, excerpt(rq, dial))
			}
		}
	}
	if !pushed {
		t.Errorf("the sync did not push alice's own route; requests: %d", len(e.reqs))
	}
}

func TestSyncClaimTieBreaksBetweenTenants(t *testing.T) {
	e := newSecEnv(t)
	older, _ := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob", JSONData: claimRoute("shared.example.test", "203.0.113.21:80"), Enabled: true})
	newer, _ := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "alice", JSONData: claimRoute("shared.example.test", "203.0.113.22:80"), Enabled: true})
	own, _ := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "alice 2", JSONData: claimRoute("shared.example.test", "203.0.113.23:80"), Enabled: true})
	_, _, raws, _, _ := e.s.serverResources(1)
	ids := map[int64]bool{}
	_, _, kept := e.s.withoutForeignHostClaims(0, nil, nil, raws)
	for _, rr := range kept {
		ids[rr.ID] = true
	}
	if !ids[older] || ids[newer] || ids[own] {
		t.Errorf("kept %v; want only bob's older route %d (alice's %d and %d name his host)", ids, older, newer, own)
	}
	// Disabled rows hold nothing at sync.
	_, _ = models.ToggleRawRoute(e.db, older)
	_, _, raws, _, _ = e.s.serverResources(1)
	ids = map[int64]bool{}
	_, _, kept = e.s.withoutForeignHostClaims(0, nil, nil, raws)
	for _, rr := range kept {
		if rr.Enabled {
			ids[rr.ID] = true
		}
	}
	if !ids[newer] || !ids[own] {
		t.Errorf("with bob's route disabled, alice's routes on one host of hers should deploy: %v", ids)
	}
}

func TestListenPortRanges(t *testing.T) {
	for _, c := range []struct {
		a, b []string
		want bool
	}{
		{[]string{":7070"}, []string{"127.0.0.1:7070"}, true},
		{[]string{":7070"}, []string{":7071"}, false},
		{[]string{":7070-7080"}, []string{"tcp/:7075"}, true},
		{[]string{"weird"}, []string{":1"}, true},
	} {
		if got := listenSetsOverlap(c.a, c.b); got != c.want {
			t.Errorf("listenSetsOverlap(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
