package caddy

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Golden-file coverage for BuildProxyRoute — the function that turns a stored
// proxy host into the Caddy route JSON that is actually pushed to the admin
// API. It is the highest-consequence code in the repo: a regression here
// silently changes how every site is served, and until v2.30.0 nothing
// exercised it (the package's existing tests all cover logging).
//
// These lock in *current* behaviour rather than independently asserting what
// correct output is. That is the point: the value is catching an unintended
// change to a live config shape. When a diff here is intentional, review it
// carefully — every line is something Caddy will act on — then regenerate:
//
//	go test ./internal/caddy -update-golden
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata golden files")

func goldenCase(t *testing.T, name string, p models.ProxyHost, advanced []any) {
	t.Helper()
	route := BuildProxyRoute(p, advanced)
	got, err := json.MarshalIndent(route, "", "  ")
	if err != nil {
		t.Fatalf("marshal route: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", name+".json")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\nRun: go test ./internal/caddy -update-golden", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("route JSON changed for %q.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func baseHost() models.ProxyHost {
	return models.ProxyHost{
		ID:            1,
		Domains:       "app.example.com",
		ForwardScheme: "http",
		ForwardHost:   "backend",
		ForwardPort:   8080,
		Enabled:       true,
	}
}

func TestBuildProxyRouteGolden(t *testing.T) {
	t.Run("minimal", func(t *testing.T) {
		goldenCase(t, "route_minimal", baseHost(), nil)
	})

	// SSL/TLS settings deliberately produce no change here: they are emitted
	// as TLS connection policies (BuildTLSConnectionPolicies) and Caddy's
	// automatic_https, not as part of the route. This case pins that
	// separation — if TLS state ever starts leaking into the route, the
	// golden diff will say so.
	t.Run("tls_settings_do_not_affect_the_route", func(t *testing.T) {
		p := baseHost()
		p.SSLEnabled = true
		p.SSLForced = true
		p.HTTP2Support = true
		goldenCase(t, "route_tls_forced", p, nil)
	})

	t.Run("websocket_and_exploit_blocking", func(t *testing.T) {
		p := baseHost()
		p.WebsocketSupport = true
		p.BlockCommonExploits = true
		goldenCase(t, "route_websocket_exploits", p, nil)
	})

	t.Run("active_health_check", func(t *testing.T) {
		p := baseHost()
		p.HealthCheckURI = "/healthz"
		p.HealthCheckIntervalSec = 30
		p.HealthCheckMethod = "GET"
		p.HealthCheckTimeoutSec = 5
		p.HealthCheckExpectStatus = 200
		goldenCase(t, "route_health_check", p, nil)
	})

	// BuildProxyRoute does not construct the basicauth handler itself — the
	// caller builds it (server.buildBasicAuthHandler) and passes it in. What
	// matters here is that supplied handlers are placed *before* the
	// reverse_proxy, since a handler ordered after it would never run.
	t.Run("advanced_handlers_precede_reverse_proxy", func(t *testing.T) {
		p := baseHost()
		advanced := []any{
			map[string]any{
				"handler": "authentication",
				"providers": map[string]any{
					"http_basic": map[string]any{
						"accounts": []any{
							map[string]any{"username": "admin", "password": "$2a$10$fixedhashforgoldenstability000000000000000000000000000"},
						},
					},
				},
			},
		}
		goldenCase(t, "route_advanced_handlers", p, advanced)
	})

	t.Run("headers_and_compression", func(t *testing.T) {
		p := baseHost()
		p.CompressionEnabled = true
		p.SecurityHeadersEnabled = true
		p.CustomReqHeaders = `{"X-Real-IP":"{http.request.remote.host}"}`
		p.CustomRespHeaders = `{"X-Served-By":"caddyui"}`
		goldenCase(t, "route_headers_compression", p, nil)
	})

	t.Run("multiple_domains_and_upstreams", func(t *testing.T) {
		p := baseHost()
		p.Domains = "app.example.com, www.app.example.com"
		p.ExtraUpstreams = `["backend-2:8080","backend-3:8080"]`
		p.LBPolicy = "round_robin"
		goldenCase(t, "route_multi_upstream", p, nil)
	})
}

// A disabled host must never contribute a route — if it did, turning a host
// off in the UI would leave it serving.
func TestBuildRoutesSkipsDisabledHosts(t *testing.T) {
	on := baseHost()
	off := baseHost()
	off.ID = 2
	off.Domains = "disabled.example.com"
	off.Enabled = false

	routes := BuildRoutes([]models.ProxyHost{on, off}, nil)
	blob, err := json.Marshal(routes)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(blob); contains(got, "disabled.example.com") {
		t.Errorf("a disabled host reached the generated config:\n%s", got)
	}
	if got := string(blob); !contains(got, "app.example.com") {
		t.Errorf("the enabled host is missing from the generated config:\n%s", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	}()
}
