package server

import "testing"

func TestApplyFleetAccessLogPreservesAnalytics(t *testing.T) {
	cfg := map[string]any{
		"logging": map[string]any{"logs": map[string]any{
			"caddyui_access": map[string]any{"include": []any{"http.log.access"}},
		}},
		"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
			"srv0":         map[string]any{"logs": map[string]any{"default_logger_name": "caddyui_access"}},
			"caddyui_http": map[string]any{"listen": []any{":80"}},
		}}},
	}
	access := fleetAccessLogConfig{
		Enabled: true, Path: "/var/log/caddy/access.log", Format: "json", Scope: "all",
		RollSizeMB: 100, RollKeep: 10, RollKeepDays: 90, ServerIDs: map[int64]bool{7: true},
	}
	applyFleetAccessLog(cfg, access, true, 7)

	logging := cfg["logging"].(map[string]any)
	logs := logging["logs"].(map[string]any)
	if _, ok := logs["caddyui_access"]; !ok {
		t.Fatal("analytics logger was removed")
	}
	if _, ok := logs[fleetAccessLoggerName]; !ok {
		t.Fatal("file access logger was not added")
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	srv0Logs := servers["srv0"].(map[string]any)["logs"].(map[string]any)
	if got := srv0Logs["default_logger_name"]; got != "caddyui_access" {
		t.Fatalf("analytics default logger changed: %v", got)
	}
	if _, ok := servers["caddyui_http"].(map[string]any)["logs"].(map[string]any); !ok {
		t.Fatal("HTTP server access logs were not enabled")
	}
}

func TestApplyFleetAccessLogScopeAndRemoval(t *testing.T) {
	cfg := map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
		"srv0":         map[string]any{},
		"caddyui_http": map[string]any{},
	}}}}
	access := fleetAccessLogConfig{
		Enabled: true, Path: "/tmp/access.log", Format: "json", Scope: "https",
		RollSizeMB: 10, RollKeep: 2, RollKeepDays: 3, ServerIDs: map[int64]bool{1: true},
	}
	applyFleetAccessLog(cfg, access, false, 1)
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	if _, ok := servers["srv0"].(map[string]any)["logs"]; !ok {
		t.Fatal("HTTPS logs were not enabled")
	}
	if _, ok := servers["caddyui_http"].(map[string]any)["logs"]; ok {
		t.Fatal("HTTP logs were enabled for HTTPS-only scope")
	}

	access.Enabled = false
	applyFleetAccessLog(cfg, access, false, 1)
	if _, ok := cfg["logging"]; ok {
		t.Fatal("owned logging tree remained after disabling")
	}
	if _, ok := servers["srv0"].(map[string]any)["logs"]; ok {
		t.Fatal("owned server logs remained after disabling")
	}
}

func TestProtectRoutesWithCrowdSec(t *testing.T) {
	routes := []any{
		map[string]any{
			"match":  []any{map[string]any{"host": []any{"app.example.com"}}},
			"handle": []any{map[string]any{"handler": "reverse_proxy"}},
		},
		map[string]any{
			"match":  []any{map[string]any{"host": []any{"health.example.com"}}},
			"handle": []any{map[string]any{"handler": "static_response"}},
		},
	}
	crowd := crowdSecConfig{
		Enabled: true, ServerIDs: map[int64]bool{1: true},
		ExcludedHosts: map[string]bool{"health.example.com": true},
		ExcludedPaths: []string{"/health*"},
	}
	protected := protectRoutesWithCrowdSec(routes, crowd, 1)
	first := protected[0].(map[string]any)["handle"].([]any)
	guard := first[0].(map[string]any)
	if guard["handler"] != "subroute" {
		t.Fatalf("expected exclusion subroute first, got %v", guard)
	}
	if first[1].(map[string]any)["handler"] != "reverse_proxy" {
		t.Fatal("CrowdSec guard was not inserted before reverse_proxy")
	}
	second := protected[1].(map[string]any)["handle"].([]any)
	if len(second) != 1 || second[0].(map[string]any)["handler"] != "static_response" {
		t.Fatal("excluded host was modified")
	}
}

func TestFleetIntegrationValidation(t *testing.T) {
	if err := validateFleetAccessLogConfig(fleetAccessLogConfig{Enabled: true, Path: "relative.log", ServerIDs: map[int64]bool{1: true}, RollSizeMB: 1}); err == nil {
		t.Fatal("relative access-log path was accepted")
	}
	if err := validateCrowdSecConfig(crowdSecConfig{Enabled: true, APIURL: "http://crowdsec:8080/", APIKey: "key", Ticker: "0s", ServerIDs: map[int64]bool{1: true}}); err == nil {
		t.Fatal("zero CrowdSec refresh interval was accepted")
	}
}
