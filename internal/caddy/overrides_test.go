package caddy

import (
	"reflect"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.40.0: a reverse_proxy block from the Advanced config is folded into the
// host's generated handler — nested maps merge, the override wins on
// conflicts, and the upstream is never taken from it.
func TestMergeReverseProxyOverrides(t *testing.T) {
	p := models.ProxyHost{Domains: "app.example.test", ForwardScheme: "https", ForwardHost: "app", ForwardPort: 8443, Enabled: true, SSLEnabled: true}
	route := BuildProxyRoute(p, nil)
	overrides := map[string]any{
		"handler":        "reverse_proxy",
		"upstreams":      []any{map[string]any{"dial": "evil:1"}},
		"flush_interval": -1,
		"transport":      map[string]any{"protocol": "http", "read_timeout": 30000000000, "tls": map[string]any{"server_name": "inner.example.test"}},
		"headers":        map[string]any{"request": map[string]any{"set": map[string]any{"X-Real-Ip": []any{"{http.request.remote.host}"}}}},
	}
	if !MergeReverseProxyOverrides(route, overrides) {
		t.Fatal("expected the reverse_proxy handler to be found")
	}
	rp := findReverseProxyHandler(route)
	if rp["flush_interval"] != -1 {
		t.Errorf("flush_interval = %v", rp["flush_interval"])
	}
	if ups := rp["upstreams"].([]any); !reflect.DeepEqual(ups[0], map[string]any{"dial": "app:8443"}) {
		t.Errorf("upstreams must stay as generated, got %v", ups)
	}
	transport := rp["transport"].(map[string]any)
	tlsCfg := transport["tls"].(map[string]any)
	if transport["read_timeout"] != 30000000000 || tlsCfg["server_name"] != "inner.example.test" || tlsCfg["insecure_skip_verify"] != true {
		t.Errorf("transport should merge generated TLS settings with the override: %v", transport)
	}
	set := rp["headers"].(map[string]any)["request"].(map[string]any)["set"].(map[string]any)
	if _, ok := set["X-Real-Ip"]; !ok {
		t.Errorf("header_up should be merged into headers.request.set: %v", set)
	}
	if !MergeReverseProxyOverrides(map[string]any{"handle": []any{map[string]any{"handler": "subroute", "routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "reverse_proxy"}}}}}}}, map[string]any{"flush_interval": -1}) {
		t.Error("a reverse_proxy inside a subroute should be found")
	}
	if MergeReverseProxyOverrides(map[string]any{"handle": []any{map[string]any{"handler": "static_response"}}}, overrides) {
		t.Error("no reverse_proxy handler means nothing to merge")
	}
	if MergeReverseProxyOverrides(route, nil) {
		t.Error("empty overrides must be a no-op")
	}
}
