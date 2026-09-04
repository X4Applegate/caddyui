package models

import (
	"strings"
	"testing"
)

// v2.37.0: one fleet-wide ingest target defaulted to "caddyui:9019", a Docker
// service name only containers on the same network can resolve, so every
// node on another host silently shipped nothing. Each node now has its own
// target, and the unambiguous misconfiguration is called out.
func TestEffectiveIngestTarget(t *testing.T) {
	if got := (CaddyServer{}).EffectiveIngestTarget(" caddyui:9019 "); got != "caddyui:9019" {
		t.Errorf("blank per-node target should fall back to the global one, got %q", got)
	}
	if got := (CaddyServer{IngestTarget: " 10.8.0.1:9019 "}).EffectiveIngestTarget("caddyui:9019"); got != "10.8.0.1:9019" {
		t.Errorf("per-node target should win, got %q", got)
	}
}

func TestLooksDockerInternalHost(t *testing.T) {
	for in, want := range map[string]bool{
		"caddyui:9019": true, "caddyui": true, "CaddyUI:9019": true,
		"localhost:9019": false, "10.8.0.1:9019": false, "[::1]:9019": false,
		"host.docker.internal:9019": false, "ingest.example.com:9019": false,
		"unix//run/ingest.sock": false, "": false,
	} {
		if got := LooksDockerInternalHost(in); got != want {
			t.Errorf("LooksDockerInternalHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIngestTargetWarningFlagsOnlyRemoteNodesWithDockerNames(t *testing.T) {
	remote := CaddyServer{Name: "Richard Prod", AdminURL: "http://10.8.0.3:2019"}
	if w := remote.IngestTargetWarning("caddyui:9019"); !strings.Contains(w, "10.8.0.3") || !strings.Contains(w, `"caddyui:9019"`) {
		t.Errorf("remote node + Docker name must warn and name both sides, got %q", w)
	}
	if w := remote.IngestTargetWarning("10.8.0.1:9019"); w != "" {
		t.Errorf("remote node with a reachable target must not warn, got %q", w)
	}
	for _, local := range []CaddyServer{
		{AdminURL: "http://caddy:2019"},            // same Docker network as CaddyUI
		{AdminURL: "http://localhost:2019"},        // same host
		{AdminURL: "unix:///run/caddy-admin.sock"}, // ambiguous placement: leave alone
		{AdminURL: "http://edge.example.com:2019", Type: "external"},
	} {
		if w := local.IngestTargetWarning("caddyui:9019"); (local.AdminURL == "http://edge.example.com:2019") != (w != "") {
			t.Errorf("AdminURL %q: warning = %q", local.AdminURL, w)
		}
	}
}
