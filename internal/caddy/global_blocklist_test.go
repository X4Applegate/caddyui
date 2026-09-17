package caddy

import "testing"

func TestBuildGlobalBlocklistRoute(t *testing.T) {
	if got := BuildGlobalBlocklistRoute(""); got != nil {
		t.Fatalf("empty list should yield nil, got %#v", got)
	}
	if got := BuildGlobalBlocklistRoute("  ,  "); got != nil {
		t.Fatalf("blank-only list should yield nil, got %#v", got)
	}

	route := BuildGlobalBlocklistRoute("203.0.113.5/32, 198.51.100.0/24")
	if route == nil {
		t.Fatal("expected a route")
	}
	if route["terminal"] != true {
		t.Fatalf("route must be terminal, got %#v", route["terminal"])
	}
	match := route["match"].([]any)[0].(map[string]any)
	ranges := match["remote_ip"].(map[string]any)["ranges"].([]any)
	if len(ranges) != 2 || ranges[0] != "203.0.113.5/32" || ranges[1] != "198.51.100.0/24" {
		t.Fatalf("ranges = %#v, want the two CIDRs in order", ranges)
	}
	handle := route["handle"].([]any)[0].(map[string]any)
	if handle["handler"] != "static_response" || handle["status_code"] != 403 {
		t.Fatalf("handle = %#v, want static_response 403", handle)
	}
}
