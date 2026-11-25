// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// T-0713: emit the MULTI-ROUTE config the precedence harness drives.
//
// WHAT THIS COVERS THAT T-0631 DELIBERATELY DID NOT
// -------------------------------------------------
// T-0631's harness drives ONE layer4 route (SSH) plus pass-through, which is
// enough for the #483 buffer race and the #482/#492 reload deadlock but says
// nothing about *precedence*: with a single route there is no second route for
// it to be ordered against.
//
// caddy-l4 v0.1.3 changed the matching loop itself (layer4/routes.go). v0.1.2
// tracked pending routes with a single watermark, `lastNeedsMoreIdx`; v0.1.3
// adds `anyRouteNeedsMore(before)`, which consults `routesStatus` directly:
//
//	anyRouteNeedsMore := func(before int) bool {
//		for i, s := range routesStatus {
//			if s == routeNeedsMore && i > lastMatchedRouteIdx && i < before {
//				return true
//			}
//		}
//		return false
//	}
//
// and uses it in two places — the catch-all guard (line ~187) and the
// keep-looping decision (line ~238). The upstream comment names the defect the
// watermark had: "a conclusively unmatched route can bury an earlier one that is
// still waiting for data".
//
// THE SHAPE THAT DISTINGUISHES THE TWO VERSIONS
// ---------------------------------------------
// A watermark is a single number, so it cannot represent "route 0 is pending AND
// route 1 is decided". Three routes in this order produce the divergence:
//
//	route 0  a matcher that needs MORE bytes than arrived in the first packet
//	route 1  a matcher that conclusively does NOT match those bytes
//	route 2  a route that matches anything
//
// Walking v0.1.2's loop: route 0 returns ErrConsumedAllPrefetchedBytes, so
// `lastNeedsMoreIdx = 0`. Route 1 returns false, and since `i(1) >=
// lastNeedsMoreIdx(0)` it advances the watermark to `i+1 = 2` — route 0's
// pending state is now *buried*, because the watermark no longer points at it.
// Route 2's catch-all guard asks `i(2) > lastNeedsMoreIdx(2)`, which is FALSE,
// so the catch-all matches immediately and route 0 never gets its bytes.
//
// v0.1.3 asks the same guard plus `anyRouteNeedsMore(2)`, which scans the status
// map, finds route 0 still `routeNeedsMore`, and defers the catch-all. Matching
// loops, prefetches more bytes, and route 0 wins the connection it should have.
//
// So the SAME first bytes can land on a DIFFERENT route depending on version.
// That is a behaviour change, not a bug fix in the sense the other two are, and
// it is the one part of the v0.1.3 delta with no test on either side.
//
// WHY THIS IS A DIFFERENTIAL, NOT A PASS/FAIL GATE
// ------------------------------------------------
// There is no "buggy image" here: for a behaviour change, neither answer is
// self-evidently wrong until the intended behaviour is established. So the
// harness RECORDS which route each byte sequence landed on, per image, and
// reports the differences as a table. It exits non-zero only on things that are
// unambiguously broken regardless of version (a connection that reached no
// route at all, or a route that answered for a protocol it does not match).
//
// WHAT CADDYUI CAN AND CANNOT GENERATE
// ------------------------------------
// Load-bearing, and the reason this file asserts it rather than assuming it:
// buildLayer4ListenerWrappers NEVER emits a catch-all. layer4MatcherFor returns
// nil for an unknown MatchKind and the builder skips that proxy, so every route
// CaddyUI writes carries exactly one matcher. The empty-matcherSets guard at
// routes.go:187 is therefore UNREACHABLE from a CaddyUI config.
//
// The second use of anyRouteNeedsMore — the keep-looping decision at
// routes.go:238 — is reachable, because that one does not need a catch-all: it
// decides whether a connection keeps waiting for bytes or falls through to the
// wrapped listener (Caddy's own TLS/HTTP). On the listener-wrapper path
// "fall through" IS a destination, so an over-eager fall-through is a real
// precedence change for a CaddyUI deployment.
//
// Both are emitted. The CaddyUI-shaped config (routes from the real builder) is
// the one that matters for the product; the catch-all variant is appended by
// hand, clearly marked, so the guard CaddyUI cannot reach is still measured
// rather than assumed harmless.
//
// Run with CADDYUI_L4P_EMIT=<path> to write the config; without it the test is a
// shape check that keeps `go test ./...` meaningful but fast.

// precedenceUpstreams assigns each route its own sink port, so the landing route
// is OBSERVED (which sink answered) rather than inferred from a success/failure
// pattern. Inferring it was the first design and it could not tell "route 2
// matched" from "route 0 matched and the upstream was down".
const (
	precSinkSSH      = 22301 // route 0: ssh matcher
	precSinkPostgres = 22302 // route 1: postgres matcher
	precSinkRDP      = 22303 // route 2: rdp matcher
	precSinkTLSSNI   = 22304 // route 3: tls sni matcher
	precSinkCatchAll = 22305 // appended by hand; CaddyUI cannot emit this
)

// TestEmitLayer4PrecedenceConfig writes the multi-route precedence config.
func TestEmitLayer4PrecedenceConfig(t *testing.T) {
	out := os.Getenv("CADDYUI_L4P_EMIT")

	// Four competing routes on ONE shared HTTPS port, in the order CaddyUI
	// itself would order them. That order is not arbitrary and not operator
	// controlled: ListLayer4Proxies sorts by `protocol, listen_port, id`, so for
	// proxies on the same shared port the route order is CREATION order (id).
	// An operator cannot reorder them from the UI, which means precedence here
	// is decided by which proxy was added first — worth knowing on its own.
	//
	// The byte thresholds are what create the divergence window, and they differ
	// per matcher (measured from the v0.1.3 matcher sources):
	//
	//	ssh       4 bytes   bytes.Equal(p, []byte("SSH-"))
	//	postgres  8 bytes   4-byte length + 4-byte code (readFirstMessage)
	//	rdp      19 bytes   TPKTHeaderBytesTotal + X224CrqBytesTotal
	//	tls      full ClientHello
	//
	// So a 5-byte first packet is conclusive for ssh, conclusive for postgres
	// (too short to be a valid message), and INCONCLUSIVE for rdp and tls — they
	// return ErrConsumedAllPrefetchedBytes and become `routeNeedsMore`.
	proxies := []models.Layer4Proxy{
		{
			ID: 1, Name: "prec-ssh", Protocol: models.Layer4ProtocolTCP,
			Mode: models.Layer4ModeShared, WrapServer: models.Layer4WrapHTTPS,
			MatchKind:    models.Layer4MatchSSH,
			UpstreamHost: "127.0.0.1", UpstreamPort: precSinkSSH, Enabled: true,
		},
		{
			ID: 2, Name: "prec-postgres", Protocol: models.Layer4ProtocolTCP,
			Mode: models.Layer4ModeShared, WrapServer: models.Layer4WrapHTTPS,
			MatchKind:    models.Layer4MatchPostgres,
			UpstreamHost: "127.0.0.1", UpstreamPort: precSinkPostgres, Enabled: true,
		},
		{
			ID: 3, Name: "prec-rdp", Protocol: models.Layer4ProtocolTCP,
			Mode: models.Layer4ModeShared, WrapServer: models.Layer4WrapHTTPS,
			MatchKind:    models.Layer4MatchRDP,
			UpstreamHost: "127.0.0.1", UpstreamPort: precSinkRDP, Enabled: true,
		},
		{
			ID: 4, Name: "prec-tls-sni", Protocol: models.Layer4ProtocolTCP,
			Mode: models.Layer4ModeShared, WrapServer: models.Layer4WrapHTTPS,
			MatchKind:    models.Layer4MatchTLSSNI,
			MatchHosts:   "l4prec-sni.l4test",
			UpstreamHost: "127.0.0.1", UpstreamPort: precSinkTLSSNI, Enabled: true,
		},
	}
	for i := range proxies {
		if msg := validateLayer4Proxy(&proxies[i]); msg != "" {
			t.Fatalf("proxy %q is not a valid shared proxy: %s", proxies[i].Name, msg)
		}
	}

	wrappers := buildLayer4ListenerWrappers(proxies)
	srv0 := wrappers["srv0"]
	if srv0 == nil {
		t.Fatal("no srv0 wrapper generated")
	}
	if srv0["wrapper"] != "layer4" {
		t.Fatalf("wrapper is not layer4: %v", srv0["wrapper"])
	}
	routes, _ := srv0["routes"].([]any)
	if len(routes) != 4 {
		t.Fatalf("want 4 competing layer4 routes, got %d", len(routes))
	}

	// The whole point of generating this from the real builder: assert the route
	// ORDER is the one CaddyUI produces, and that each route is distinguishable
	// by its upstream. A harness that hand-wrote these routes would be testing
	// its own ordering rather than CaddyUI's.
	wantOrder := []struct {
		matcher  string
		upstream int
	}{
		{"ssh", precSinkSSH},
		{"postgres", precSinkPostgres},
		{"rdp", precSinkRDP},
		{"tls", precSinkTLSSNI},
	}
	for i, want := range wantOrder {
		r, _ := routes[i].(map[string]any)
		if r == nil {
			t.Fatalf("route %d is not an object", i)
		}
		ms, _ := r["match"].([]any)
		if len(ms) != 1 {
			t.Fatalf("route %d: want exactly 1 matcher set, got %d", i, len(ms))
		}
		m, _ := ms[0].(map[string]any)
		if _, ok := m[want.matcher]; !ok {
			b, _ := json.Marshal(m)
			t.Fatalf("route %d: want matcher %q, got %s", i, want.matcher, b)
		}
		// Exactly one matcher key, or "which route matched" stops being
		// attributable to one protocol.
		if len(m) != 1 {
			b, _ := json.Marshal(m)
			t.Fatalf("route %d: want a single matcher key, got %s", i, b)
		}
		dial := routeDial(t, r)
		if !strings.HasSuffix(dial, ":"+strconv.Itoa(want.upstream)) {
			t.Fatalf("route %d (%s): want upstream port %d, dials %q",
				i, want.matcher, want.upstream, dial)
		}
	}

	// CaddyUI emits NO catch-all. This is the fact that decides which half of
	// the v0.1.3 change the product can actually reach, so it is asserted rather
	// than stated in a comment: every generated route carries a matcher, so the
	// empty-matcherSets guard at routes.go:187 is unreachable from CaddyUI's own
	// output. If a future MatchKind ever emitted a bare route, this fails and
	// the precedence analysis has to be redone.
	for i, r := range routes {
		rm, _ := r.(map[string]any)
		ms, _ := rm["match"].([]any)
		if len(ms) == 0 {
			t.Fatalf("route %d has no matcher: CaddyUI emitted a catch-all, which "+
				"makes routes.go:187 reachable and invalidates this harness's analysis", i)
		}
	}

	// Order within listener_wrappers: layer4 before tls, or the matchers read
	// decrypted bytes instead of the raw first packet the test is about.
	merged := mergeListenerWrappers(nil, srv0, false, true)
	if len(merged) != 2 || !isLayer4Wrapper(merged[0]) || !isTLSWrapper(merged[1]) {
		b, _ := json.Marshal(merged)
		t.Fatalf("listener_wrappers order is not [layer4, tls]: %s", b)
	}

	if out == "" {
		return
	}

	// ---- the catch-all variant --------------------------------------------
	// Appended BY HAND, and marked as such, because CaddyUI cannot generate it.
	// Without it the routes.go:187 guard — the more dramatic half of the change
	// — would go unmeasured, and "CaddyUI can't reach it" would be an untested
	// assumption about caddy-l4's behaviour rather than a measured one.
	//
	// It goes LAST, which is the only position where it is interesting: a
	// catch-all ahead of a pending route would match on the first pass under
	// both versions.
	withCatchAll := os.Getenv("CADDYUI_L4P_CATCHALL") == "1"
	if withCatchAll {
		routes = append(routes, map[string]any{
			// No "match" key at all: len(route.matcherSets) == 0, which is what
			// the guard tests for.
			"handle": []any{map[string]any{
				"handler": "proxy",
				"upstreams": []any{map[string]any{
					"dial": []any{fmt.Sprintf("tcp/127.0.0.1:%d", precSinkCatchAll)},
				}},
			}},
		})
		srv0["routes"] = routes
	}

	port := os.Getenv("CADDYUI_L4P_PORT")
	askPort := os.Getenv("CADDYUI_L4P_ASKPORT")
	cfg := map[string]any{
		"admin": map[string]any{"listen": os.Getenv("CADDYUI_L4P_ADMIN")},
		"logging": map[string]any{
			"logs": map[string]any{"default": map[string]any{"level": "ERROR"}},
		},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":            []any{":" + port},
						"listener_wrappers": mergeListenerWrappers(nil, srv0, false, true),
						// The pass-through destination. A connection that reaches
						// HERE matched no layer4 route and fell through to Caddy's
						// own TLS+HTTP — which on the listener-wrapper path is a
						// legitimate landing place, and one of the outcomes the
						// differential has to be able to name.
						"routes": []any{map[string]any{
							"handle": []any{map[string]any{
								"handler":     "static_response",
								"body":        "LANDED=passthrough SNI={http.request.tls.server_name}\n",
								"status_code": 200,
							}},
						}},
						"tls_connection_policies": []any{map[string]any{}},
						"automatic_https":         map[string]any{"disable_redirects": true},
					},
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
	s := string(b)
	for _, must := range []string{`"wrapper": "layer4"`, `"ssh"`, `"postgres"`, `"rdp"`, `"sni"`} {
		if !strings.Contains(s, must) {
			t.Fatalf("emitted config is missing %s", must)
		}
	}
	t.Logf("wrote %s (%d bytes, %d layer4 routes, catch-all=%v)",
		out, len(b), len(routes), withCatchAll)
}

// routeDial returns the single upstream dial address of a generated route, so a
// test failure names the port rather than dumping JSON.
func routeDial(t *testing.T, route map[string]any) string {
	t.Helper()
	handles, _ := route["handle"].([]any)
	if len(handles) == 0 {
		t.Fatalf("route has no handlers: %v", route)
	}
	h, _ := handles[len(handles)-1].(map[string]any)
	if h["handler"] != "proxy" {
		t.Fatalf("last handler is not proxy: %v", h)
	}
	ups, _ := h["upstreams"].([]any)
	if len(ups) != 1 {
		t.Fatalf("want 1 upstream, got %d", len(ups))
	}
	u, _ := ups[0].(map[string]any)
	dials, _ := u["dial"].([]any)
	if len(dials) != 1 {
		t.Fatalf("want 1 dial, got %d", len(dials))
	}
	d, _ := dials[0].(string)
	return d
}
