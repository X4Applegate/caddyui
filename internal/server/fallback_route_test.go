// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.59.4 (issue #123): a request that matches no host used to get an empty
// 200 OK from Caddy (a fallback existed only when custom 404 HTML was saved).
// Both listeners now end with a real 404.

func lastRouteJSON(t *testing.T, routes []any) string {
	t.Helper()
	if len(routes) == 0 {
		t.Fatal("no routes")
	}
	b, _ := json.Marshal(routes[len(routes)-1])
	return string(b)
}

func proxyRow(domain string, forceSSL bool) models.ProxyHost {
	return models.ProxyHost{ID: 1, Domains: domain, ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true, SSLEnabled: true, SSLForced: forceSSL}
}

func TestDefaultFallbackIsAnErrorHandler404OnBothListeners(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	hosts := []models.ProxyHost{proxyRow("app.example.com", false)}

	https := s.withFallbackRoute(s.buildMergedRoutes(hosts, nil, nil))
	httpR := s.buildHTTPRoutes(hosts, nil, nil)
	for name, routes := range map[string][]any{"HTTPS": https, "HTTP": httpR} {
		last := lastRouteJSON(t, routes)
		if !strings.Contains(last, `"handler":"error"`) || !strings.Contains(last, `"status_code":404`) {
			t.Errorf("%s: the last route is not a 404 fallback: %s", name, last)
		}
		if strings.Contains(last, `"match"`) {
			t.Errorf("%s: the fallback must match every request: %s", name, last)
		}
	}
}

func TestCustomFallbackHTMLStillWinsAndStaysA404(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	if err := models.SetSetting(s.DB, settingCatchAll404HTML, "<h1>nope</h1>"); err != nil {
		t.Fatal(err)
	}
	hosts := []models.ProxyHost{proxyRow("app.example.com", false)}
	for name, routes := range map[string][]any{
		"HTTPS": s.withFallbackRoute(s.buildMergedRoutes(hosts, nil, nil)),
		"HTTP":  s.buildHTTPRoutes(hosts, nil, nil),
	} {
		last := lastRouteJSON(t, routes)
		if !strings.Contains(last, `\u003ch1\u003enope\u003c/h1\u003e`) || !strings.Contains(last, `"status_code":404`) || !strings.Contains(last, "static_response") {
			t.Errorf("%s: custom fallback page lost: %s", name, last)
		}
	}
}

// A forced-SSL host must still be redirected, not answered by the fallback:
// the redirect has to sit BEFORE the catch-all on :80.
func TestHTTPSRedirectStaysAheadOfTheFallbackOnPlainHTTP(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	routes := s.buildHTTPRoutes([]models.ProxyHost{proxyRow("secure.example.com", true)}, nil, nil)
	if len(routes) != 2 {
		t.Fatalf("routes = %d, want redirect + fallback: %v", len(routes), routes)
	}
	first, _ := json.Marshal(routes[0])
	if !strings.Contains(string(first), "secure.example.com") || !strings.Contains(string(first), "Location") {
		t.Errorf("first route is not the HTTPS redirect: %s", first)
	}
	if last := lastRouteJSON(t, routes); !strings.Contains(last, `"handler":"error"`) {
		t.Errorf("the fallback is not last: %s", last)
	}
}

// With nothing configured CaddyUI must keep owning nothing: no fallback route,
// no taking over of :80 / :443 for an empty server.
func TestNoFallbackWhenThereAreNoRoutes(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	if r := s.withFallbackRoute(nil); len(r) != 0 {
		t.Errorf("a fallback was added to an empty route list: %v", r)
	}
	if r := s.buildHTTPRoutes(nil, nil, nil); len(r) != 0 {
		t.Errorf("an empty :80 server got routes: %v", r)
	}
}

func TestFallbackSitsAfterGlobalMaintenanceAndRoutes(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	if err := models.SetSetting(s.DB, settingGlobalMaintenance, "1"); err != nil {
		t.Fatal(err)
	}
	routes := s.withFallbackRoute(s.buildMergedRoutes([]models.ProxyHost{proxyRow("app.example.com", false)}, nil, nil))
	first, _ := json.Marshal(routes[0])
	if !strings.Contains(string(first), "Maintenance") {
		t.Errorf("maintenance is no longer first: %s", first)
	}
	if last := lastRouteJSON(t, routes); !strings.Contains(last, `"handler":"error"`) {
		t.Errorf("fallback not last: %s", last)
	}
}

// End to end through syncCaddy: what is written to the live Caddy.
func TestSyncWritesTheFallbackToBothServers(t *testing.T) {
	f := newL4Fleet(t)
	f.createProxy(t, "app.example.com", nil)
	f.fSource.mu.Lock()
	defer f.fSource.mu.Unlock()
	var srv0, plain string
	for _, w := range f.fSource.writes {
		switch {
		case strings.HasPrefix(w, "PATCH /config/apps/http/servers/srv0/routes"):
			srv0 = w
		case strings.Contains(w, "/servers/caddyui_http") && !strings.HasPrefix(w, "DELETE"):
			plain = w
		}
	}
	for name, w := range map[string]string{"srv0": srv0, "caddyui_http": plain} {
		if !strings.Contains(w, `"handler":"error"`) || !strings.Contains(w, `"status_code":404`) {
			t.Errorf("%s was written without the 404 fallback: %.300s", name, w)
		}
	}
}
