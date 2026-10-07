// SPDX-License-Identifier: Apache-2.0

package server

import (
	"path/filepath"
	"strings"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.59.3 (issue #121, follow-up): an Advanced route written with explicit
// http:// addresses must exist only on the plain :80 server. It used to be
// generated on :443 as well, where Caddy served it over HTTPS and issued an
// internal certificate for its host.

const httpOnlySrc = "http://127.0.0.1 {\n\trespond /health \"OK\" 200\n}"
const httpOnlyJSON = `{"match":[{"host":["127.0.0.1"]}],"handle":[{"handler":"static_response","status_code":200,"body":"OK"}]}`

func newHTTPOnlyTestServer(t *testing.T) *Server {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return newRenderingTestServer(t, conn)
}

func rawRow(label, src, js string) models.RawRoute {
	return models.RawRoute{ID: 1, Label: label, CaddyfileSrc: src, JSONData: js, Enabled: true}
}

func TestHTTPSRawRoutesDropsOnlyExplicitHTTPRoutes(t *testing.T) {
	https := rawRow("secure", "app.example.com {\n\trespond OK\n}", `{"match":[{"host":["app.example.com"]}],"handle":[]}`)
	mixed := rawRow("mixed", "http://a.example.com {\n\trespond A\n}\nhttps://b.example.com {\n\trespond B\n}", `{}`)
	jsonOnly := rawRow("json", "", `{"match":[{"host":["j.example.com"]}],"handle":[]}`)
	plain := rawRow("httponly", httpOnlySrc, httpOnlyJSON)
	ownPort := rawRow("ownport", httpOnlySrc, httpOnlyJSON)
	ownPort.Listen = ":8080"

	got := httpsRawRoutes([]models.RawRoute{https, mixed, jsonOnly, plain, ownPort})
	var labels []string
	for _, r := range got {
		labels = append(labels, r.Label)
	}
	want := "secure,mixed,json,ownport"
	if strings.Join(labels, ",") != want {
		t.Errorf("HTTPS-side routes = %v, want %s (only the explicit http:// route is dropped; routes with their own listener stay)", labels, want)
	}
}

func TestHTTPOnlyRouteIsOnPlainHTTPServerButNotOnHTTPS(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	plain := rawRow("httponly", httpOnlySrc, httpOnlyJSON)
	raws := []models.RawRoute{plain}

	httpsRoutes := s.buildMergedRoutes(nil, nil, httpsRawRoutes(raws))
	if len(httpsRoutes) != 0 {
		t.Errorf("an http:// route appears on the HTTPS server: %v", httpsRoutes)
	}
	httpRoutes := s.buildHTTPRoutes(nil, nil, raws)
	if len(httpRoutes) != 1 {
		t.Fatalf("the http:// route is missing from the :80 server: %v", httpRoutes)
	}
}

// An older save may have left Force SSL on for an http:// route; it must still
// be served as plain HTTP on :80, never turned into a redirect to HTTPS (which
// would now point at nothing).
func TestHTTPOnlyRouteWithForceSSLLeftOnIsStillServedOnPlainHTTP(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	plain := rawRow("httponly", httpOnlySrc, httpOnlyJSON)
	plain.ForceSSL = true
	httpRoutes := s.buildHTTPRoutes(nil, nil, []models.RawRoute{plain})
	if len(httpRoutes) != 1 {
		t.Fatalf("routes = %v", httpRoutes)
	}
	if m, _ := httpRoutes[0].(map[string]any); m != nil {
		if h, _ := m["handle"].([]any); len(h) > 0 {
			if hm, _ := h[0].(map[string]any); hm != nil && hm["status_code"] == 308 {
				t.Error("an http:// route with a stale Force SSL flag was turned into an HTTPS redirect")
			}
		}
	}
}

func TestHTTPOnlyRouteGetsNoCertificateSubjects(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	plain := rawRow("httponly", httpOnlySrc, httpOnlyJSON)
	plain.DNSProvider, plain.DNSZoneID = "cloudflare", "z1" // would otherwise ask for a DNS-01 certificate
	policies := s.buildDNSAutomationPolicies(nil, nil, httpsRawRoutes([]models.RawRoute{plain}), nil)
	if len(policies) != 0 {
		t.Errorf("an http:// route produced TLS automation policies: %v", policies)
	}
}

// End to end through syncCaddy: what is written to the live Caddy.
func TestSyncKeepsHTTPOnlyRouteOffTheHTTPSServer(t *testing.T) {
	f := newL4Fleet(t)
	if _, err := models.CreateRawRoute(f.conn, f.source, 0, &models.RawRoute{Label: "health", CaddyfileSrc: httpOnlySrc, JSONData: httpOnlyJSON, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateRawRoute(f.conn, f.source, 0, &models.RawRoute{Label: "secure", CaddyfileSrc: "app.example.com {\n\trespond OK\n}", JSONData: `{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"static_response","body":"OK"}]}`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.syncCaddy(f.source, false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	f.fSource.mu.Lock()
	defer f.fSource.mu.Unlock()
	var srv0, plainHTTP string
	for _, w := range f.fSource.writes {
		switch {
		case strings.HasPrefix(w, "PATCH /config/apps/http/servers/srv0/routes"):
			srv0 = w
		case strings.Contains(w, "/servers/caddyui_http"):
			plainHTTP += w
		}
	}
	if srv0 == "" {
		for _, w := range f.fSource.writes {
			if len(w) > 90 {
				w = w[:90]
			}
			t.Log(w)
		}
		t.Fatalf("no write to srv0 routes")
	}
	if strings.Contains(srv0, "127.0.0.1") {
		t.Errorf("the http:// route was written to the HTTPS server: %s", srv0)
	}
	if !strings.Contains(srv0, "app.example.com") {
		t.Errorf("the normal route is missing from the HTTPS server: %s", srv0)
	}
	if !strings.Contains(plainHTTP, "127.0.0.1") {
		t.Errorf("the http:// route is missing from the plain :80 server: %s", plainHTTP)
	}
}
