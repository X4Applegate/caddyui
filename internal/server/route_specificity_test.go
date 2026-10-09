// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.61.3 (issue #129): a wildcard host created after a specific host used to
// come first and serve it — skipping that host's IP allowlist (and its auth,
// profile and WAF). Verified on a real Caddy before the fix.

func hostsOf(t *testing.T, routes []any) []string {
	t.Helper()
	var out []string
	for _, r := range routes {
		b, _ := json.Marshal(r)
		s := string(b)
		switch {
		case strings.Contains(s, `"host":`):
			i := strings.Index(s, `"host":[`)
			j := strings.Index(s[i:], "]")
			out = append(out, s[i+8:i+j])
		default:
			out = append(out, "<no host>")
		}
	}
	return out
}

func TestExactHostsRunBeforeWildcardsWhateverTheCreationOrder(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	// List order as the database returns it: newest first, so the wildcard leads.
	hosts := []models.ProxyHost{
		{ID: 3, Domains: "*.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.9", ForwardPort: 80, Enabled: true},
		{ID: 2, Domains: "*.a.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.8", ForwardPort: 80, Enabled: true},
		{ID: 1, Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true, AccessList: "203.0.113.0/24"},
	}
	got := hostsOf(t, s.buildMergedRoutes(hosts, nil, nil))
	want := []string{`"app.example.com"`, `"*.a.example.com"`, `"*.example.com"`}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("HTTPS route order = %v, want %v", got, want)
	}
	httpGot := hostsOf(t, s.buildHTTPRoutes(hosts, nil, nil))
	if httpGot[0] != `"app.example.com"` {
		t.Errorf(":80 route order = %v — the allowlisted exact host must come first", httpGot)
	}
	// The allowlisted host's own route (with its allowlist) is the one that runs.
	first, _ := json.Marshal(s.buildMergedRoutes(hosts, nil, nil)[0])
	if !strings.Contains(string(first), "203.0.113.0/24") {
		t.Errorf("the first route is not the allowlisted host's: %s", first)
	}
}

func TestARouteCarryingAWildcardRunsAfterExactNamesItCovers(t *testing.T) {
	routes := []any{
		map[string]any{"match": []any{map[string]any{"host": []any{"example.com", "*.example.com"}}}},
		map[string]any{"match": []any{map[string]any{"host": []any{"app.example.com"}}}},
	}
	got := hostsOf(t, sortRoutesBySpecificity(routes))
	if got[0] != `"app.example.com"` {
		t.Errorf("order = %v: a route that also matches *.example.com must not run before app.example.com", got)
	}
}

func TestRoutesWithoutAHostKeepTheirPlaceAndEqualRoutesKeepTheirOrder(t *testing.T) {
	maint := map[string]any{"handle": []any{"maintenance"}}
	fallback := map[string]any{"handle": []any{"fallback"}}
	catchAllRaw := map[string]any{"match": []any{map[string]any{"path": []any{"/x"}}}}
	routes := []any{
		maint,
		map[string]any{"match": []any{map[string]any{"host": []any{"*.example.com"}}}},
		catchAllRaw,
		map[string]any{"match": []any{map[string]any{"host": []any{"b.example.com"}}}},
		map[string]any{"match": []any{map[string]any{"host": []any{"a.example.com"}}}},
		fallback,
	}
	got := hostsOf(t, sortRoutesBySpecificity(routes))
	want := []string{"<no host>", `"b.example.com"`, "<no host>", `"a.example.com"`, `"*.example.com"`, "<no host>"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("order = %v, want %v (host-less routes stay put; exact names keep their manual order)", got, want)
	}
	out := sortRoutesBySpecificity(routes)
	if out[0].(map[string]any)["handle"].([]any)[0] != "maintenance" || out[2].(map[string]any)["match"] == nil || out[5].(map[string]any)["handle"].([]any)[0] != "fallback" {
		t.Error("a route without a host matcher moved")
	}
}

func TestAPathScopedRouteRunsBeforeTheSameHostsCatchAll(t *testing.T) {
	routes := []any{
		map[string]any{"match": []any{map[string]any{"host": []any{"app.example.com"}}}},
		map[string]any{"match": []any{map[string]any{"host": []any{"app.example.com"}, "path": []any{"/api", "/api/*"}}}},
	}
	out := sortRoutesBySpecificity(routes)
	b, _ := json.Marshal(out[0])
	if !strings.Contains(string(b), `"/api"`) {
		t.Errorf("the /api route must run before the host-wide route: %s", b)
	}
}

func TestForcedHTTPSRedirectBeatsAWildcardServedOnPlainHTTP(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	hosts := []models.ProxyHost{
		{ID: 2, Domains: "*.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.9", ForwardPort: 80, Enabled: true},
		{ID: 1, Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true, SSLEnabled: true, SSLForced: true, AccessList: "203.0.113.0/24"},
	}
	routes := s.buildHTTPRoutes(hosts, nil, nil)
	first, _ := json.Marshal(routes[0])
	if !strings.Contains(string(first), "app.example.com") || !strings.Contains(string(first), "Location") {
		t.Errorf("on :80 the forced host's HTTPS redirect must run before the wildcard: %s", first)
	}
}
