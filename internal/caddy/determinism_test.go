package caddy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Generated Caddy config must be byte-identical for identical input.
//
// v2.30.0: it wasn't. Several handlers built a JSON *array* by ranging a Go
// map — the security-headers "delete" list, and the request/response header
// delete lists — and Go randomises map iteration. A host with Security Headers
// enabled produced 5 distinct payloads across 300 identical calls. Because
// Caddy compares configs structurally, every sync of an unchanged host looked
// like a real change: a needless config reload each time, and a spurious diff
// in every config snapshot.
//
// Anything that turns a map into a JSON array needs a sort. This test fails if
// one is ever added without it.
func TestBuildProxyRouteIsDeterministic(t *testing.T) {
	base := models.ProxyHost{
		ID: 1, Domains: "app.example.com", ForwardScheme: "http",
		ForwardHost: "backend", ForwardPort: 8080, Enabled: true,
	}

	cases := map[string]func(*models.ProxyHost){
		"baseline":            func(p *models.ProxyHost) {},
		"security_headers":    func(p *models.ProxyHost) { p.SecurityHeadersEnabled = true },
		"compression":         func(p *models.ProxyHost) { p.CompressionEnabled = true },
		"websocket":           func(p *models.ProxyHost) { p.WebsocketSupport = true },
		"block_exploits":      func(p *models.ProxyHost) { p.BlockCommonExploits = true },
		"req_header_sets":     func(p *models.ProxyHost) { p.CustomReqHeaders = `{"A":"1","B":"2","C":"3","D":"4","E":"5"}` },
		"resp_header_sets":    func(p *models.ProxyHost) { p.CustomRespHeaders = `{"A":"1","B":"2","C":"3","D":"4","E":"5"}` },
		"req_header_deletes":  func(p *models.ProxyHost) { p.CustomReqHeaders = `{"A":"","B":"","C":"","D":"","E":""}` },
		"resp_header_deletes": func(p *models.ProxyHost) { p.CustomRespHeaders = `{"A":"","B":"","C":"","D":"","E":""}` },
		"everything": func(p *models.ProxyHost) {
			p.SecurityHeadersEnabled = true
			p.CompressionEnabled = true
			p.WebsocketSupport = true
			p.BlockCommonExploits = true
			p.CustomReqHeaders = `{"A":"1","B":"","C":"3","D":"","E":"5"}`
			p.CustomRespHeaders = `{"F":"1","G":"","H":"3","I":"","J":"5"}`
			p.ExtraUpstreams = `["b2:8080","b3:8080"]`
			p.LBPolicy = "round_robin"
		},
	}

	// 200 iterations: Go's map-iteration randomisation is per-range, so a
	// single comparison would pass by luck often enough to be useless.
	const iterations = 200

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)

			seen := map[string]bool{}
			var sample string
			for i := 0; i < iterations; i++ {
				blob, err := json.Marshal(BuildProxyRoute(p, nil))
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				seen[fmt.Sprintf("%x", sha256.Sum256(blob))] = true
				if i == 0 {
					sample = string(blob)
				}
			}
			if len(seen) != 1 {
				t.Errorf("BuildProxyRoute produced %d distinct payloads from %d identical inputs; "+
					"something builds a JSON array from a map without sorting.\nfirst payload: %s",
					len(seen), iterations, sample)
			}
		})
	}
}
