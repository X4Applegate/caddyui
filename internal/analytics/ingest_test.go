package analytics

import "testing"

func TestParseLineCarriesFleetServerIdentity(t *testing.T) {
	event, ok := parseLine([]byte(`{
		"level":"info","ts":1700000000.25,"logger":"http.log.access.caddyui_access",
		"msg":"handled request","caddyui_server_id":42,"caddyui_server_name":"edge-west",
		"request":{"client_ip":"192.0.2.10","method":"GET","host":"example.test","uri":"/health?secret=no","headers":{"User-Agent":["test-agent"]}},
		"status":200,"size":123,"duration":0.025
	}`))
	if !ok {
		t.Fatal("parseLine rejected a valid access event")
	}
	if event.ServerID != 42 || event.ServerName != "edge-west" {
		t.Fatalf("server identity = %d/%q, want 42/edge-west", event.ServerID, event.ServerName)
	}
	if event.Path != "/health" {
		t.Fatalf("path = %q, want query string removed", event.Path)
	}
	if event.DurationMs != 25 {
		t.Fatalf("duration = %dms, want 25ms", event.DurationMs)
	}
}

func TestParseLineAcceptsStringServerID(t *testing.T) {
	event, ok := parseLine([]byte(`{"ts":1700000000,"caddyui_server_id":"7","request":{"host":"example.test","uri":"/"},"status":204}`))
	if !ok || event.ServerID != 7 {
		t.Fatalf("event = %#v, ok=%t; want server_id 7", event, ok)
	}
}
