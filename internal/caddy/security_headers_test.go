package caddy

import "testing"

// v2.45.2: the Security Headers bundle must never emit a delete for a
// header it also sets (Caddy runs delete after set, which removed the
// header entirely), and a per-host strip_response_headers entry must win
// over the bundle.
func TestSecurityHeadersBundleSetOnlyAndHonoursPerHostStrip(t *testing.T) {
	p := baseHost()
	p.SecurityHeadersEnabled = true
	p.StripResponseHeaders = "X-Frame-Options"
	route := BuildProxyRoute(p, nil)
	found := false
	for _, h := range route["handle"].([]any) {
		m, ok := h.(map[string]any)
		if !ok || m["handler"] != "headers" {
			continue
		}
		resp, _ := m["response"].(map[string]any)
		set, _ := resp["set"].(map[string]any)
		if _, ok := set["Strict-Transport-Security"]; !ok {
			continue
		}
		found = true
		if _, hasDel := resp["delete"]; hasDel {
			t.Fatalf("bundle handler must not carry a delete list: %v", resp)
		}
		if _, ok := set["X-Frame-Options"]; ok {
			t.Fatalf("bundle re-set X-Frame-Options despite per-host strip: %v", set)
		}
	}
	if !found {
		t.Fatal("security headers bundle handler not emitted")
	}
}
