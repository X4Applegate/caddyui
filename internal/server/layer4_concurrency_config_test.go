// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// T-0631: emit the layer4 listener-wrapper config the concurrency harness drives.
//
// The point of generating it HERE, from buildLayer4ListenerWrappers, rather than
// hand-writing a layer4 server in the harness, is that the caddy-l4 #483 race
// lives only on the listener-wrapper hijacked path. A hand-written `layer4` app
// with its own listener exercises a different code path and cannot reproduce it —
// that is exactly why the T-0620 release e2e suite could not have caught the bug.
//
// Run with CADDYUI_L4_EMIT=<path> to write the config; without it the test is a
// no-op shape check so `go test ./...` stays unaffected.
func TestEmitLayer4ConcurrencyConfig(t *testing.T) {
	out := os.Getenv("CADDYUI_L4_EMIT")

	// One SSH-matcher route on the shared HTTPS port. Everything that is not an
	// SSH handshake falls through the wrapper to Caddy's own TLS + HTTP handling,
	// which is the pass-through (hijacked) path the race is on.
	sshProxy := models.Layer4Proxy{
		ID: 1, Name: "ssh-shared", Protocol: models.Layer4ProtocolTCP,
		Mode: models.Layer4ModeShared, WrapServer: models.Layer4WrapHTTPS,
		MatchKind: models.Layer4MatchSSH,
		// The harness runs its SSH-banner sink on this port.
		UpstreamHost: "127.0.0.1", UpstreamPort: 22222, Enabled: true,
	}
	if msg := validateLayer4Proxy(&sshProxy); msg != "" {
		t.Fatalf("the harness proxy is not a valid shared proxy: %s", msg)
	}

	wrappers := buildLayer4ListenerWrappers([]models.Layer4Proxy{sshProxy})
	srv0 := wrappers["srv0"]
	if srv0 == nil {
		t.Fatal("no srv0 wrapper generated")
	}
	if srv0["wrapper"] != "layer4" {
		t.Fatalf("wrapper is not layer4: %v", srv0["wrapper"])
	}
	routes, _ := srv0["routes"].([]any)
	if len(routes) != 1 {
		t.Fatalf("want exactly 1 layer4 route, got %d", len(routes))
	}

	// mergeListenerWrappers is what decides the ORDER, and order is the whole
	// point: layer4 must precede tls or the matchers read decrypted bytes.
	merged := mergeListenerWrappers(nil, srv0, false, true)
	if len(merged) != 2 || !isLayer4Wrapper(merged[0]) || !isTLSWrapper(merged[1]) {
		b, _ := json.Marshal(merged)
		t.Fatalf("listener_wrappers order is not [layer4, tls]: %s", b)
	}

	if out == "" {
		return
	}

	// remote_ip_list is added as a SECOND route so the l4remoteiplist module is
	// actually loaded and provisioned. #482/#492 is a goroutine leak in that
	// module's StopMonitoring, and the T-0620 e2e config never loaded it, so the
	// release could not exercise it either. The file is created by the harness.
	ipFile := os.Getenv("CADDYUI_L4_IPFILE")
	if ipFile != "" {
		routes = append(routes, map[string]any{
			"match": []any{map[string]any{
				"remote_ip_list": map[string]any{"remote_ip_file": ipFile},
				"ssh":            map[string]any{},
			}},
			"handle": []any{map[string]any{
				"handler":   "proxy",
				"upstreams": []any{map[string]any{"dial": []any{"tcp/127.0.0.1:22222"}}},
			}},
		})
		srv0["routes"] = routes
	}

	// On-demand issuance from the internal CA is what lets ~500 unique SNIs each
	// get their own certificate without pre-generating 500 of them. This build
	// carries only tls.permission.http (no http_any), so the ask endpoint is a
	// plain always-200 HTTP server Caddy itself runs on the loopback.
	askPort := os.Getenv("CADDYUI_L4_ASKPORT")
	cfg := map[string]any{
		"admin": map[string]any{"listen": os.Getenv("CADDYUI_L4_ADMIN")},
		"logging": map[string]any{
			"logs": map[string]any{"default": map[string]any{"level": "ERROR"}},
		},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":            []any{":" + os.Getenv("CADDYUI_L4_PORT")},
						"listener_wrappers": mergeListenerWrappers(nil, srv0, false, true),
						"routes": []any{map[string]any{
							"handle": []any{map[string]any{
								"handler": "static_response",
								// Echo the SNI back, so a client can prove the
								// handshake it got is the one it asked for.
								"body":        "SNI={http.request.tls.server_name}\n",
								"status_code": 200,
							}},
						}},
						"tls_connection_policies": []any{map[string]any{}},
						// No HTTP->HTTPS redirect server: it would bind :80, which
						// is already in use on the host running this harness.
						"automatic_https": map[string]any{"disable_redirects": true},
					},
					// The on-demand ask endpoint: always allow. Not wrapped, so it
					// never interacts with the layer4 wrapper under test.
					"ask": map[string]any{
						"listen": []any{"127.0.0.1:" + askPort},
						"routes": []any{map[string]any{
							"handle": []any{map[string]any{
								"handler": "static_response", "status_code": 200,
							}},
						}},
						"automatic_https": map[string]any{"disable": true},
					},
				},
			},
			"tls": map[string]any{
				"automation": map[string]any{
					"policies": []any{map[string]any{
						"issuers":   []any{map[string]any{"module": "internal"}},
						"on_demand": true,
					}},
					"on_demand": map[string]any{
						"permission": map[string]any{
							"module":   "http",
							"endpoint": "http://127.0.0.1:" + askPort + "/ask",
						},
					},
				},
			},
			"pki": map[string]any{
				"certificate_authorities": map[string]any{
					"local": map[string]any{"install_trust": false},
				},
			},
		},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"wrapper": "layer4"`) {
		t.Fatal("emitted config carries no layer4 wrapper")
	}
	t.Logf("wrote %s (%d bytes)", out, len(b))
}
