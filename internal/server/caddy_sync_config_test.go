package server

import (
	"path/filepath"
	"reflect"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestHTTPRoutesReplaceUnsupportedSkipRedirectsWithoutPortConflict(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn}
	proxies := []models.ProxyHost{
		{Domains: "open.example.com", Enabled: true, SSLEnabled: true, SSLForced: false, ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080},
		{Domains: "forced.example.com", Enabled: true, SSLEnabled: true, SSLForced: true, ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080},
	}

	routes := s.buildHTTPRoutes(proxies, nil, nil)
	if len(routes) != 2 {
		t.Fatalf("HTTP routes = %d, want open route plus forced redirect", len(routes))
	}

	cfg := map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"automatic_https": map[string]any{
							"skip_redirects":    []any{"open.example.com"},
							"skip_certificates": []any{"plain.example.com"},
						},
					},
				},
			},
		},
	}
	removeUnsupportedSkipRedirects(cfg)
	applyPlainHTTPServer(cfg, routes)
	applyDisableAutomaticHTTPSRedirects(cfg, true)

	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	auto := servers["srv0"].(map[string]any)["automatic_https"].(map[string]any)
	if _, exists := auto["skip_redirects"]; exists {
		t.Fatal("unsupported automatic_https.skip_redirects was not removed")
	}
	if disabled, _ := auto["disable_redirects"].(bool); !disabled {
		t.Fatal("automatic HTTPS redirects were not disabled")
	}
	httpServer := servers["caddyui_http"].(map[string]any)
	if !reflect.DeepEqual(httpServer["listen"], []any{":80"}) {
		t.Fatalf("HTTP listen = %#v, want [:80]", httpServer["listen"])
	}
	redirect := routes[1].(map[string]any)
	handler := redirect["handle"].([]any)[0].(map[string]any)
	if handler["status_code"] != 308 {
		t.Fatalf("forced HTTP status = %#v, want 308", handler["status_code"])
	}
}

func TestHTTPRoutesIncludeRawRouteForceSSLBehavior(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn}
	raws := []models.RawRoute{
		{Enabled: true, ForceSSL: false, JSONData: `{"match":[{"host":["open-raw.example.com"]}],"handle":[{"handler":"static_response","status_code":200}]}`},
		{Enabled: true, ForceSSL: true, JSONData: `{"match":[{"host":["forced-raw.example.com"]}],"handle":[{"handler":"static_response","status_code":200}]}`},
	}

	routes := s.buildHTTPRoutes(nil, nil, raws)
	if len(routes) != 2 {
		t.Fatalf("HTTP routes = %d, want open raw route plus forced redirect", len(routes))
	}
	redirect := routes[1].(map[string]any)
	match := redirect["match"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(match["host"], []any{"forced-raw.example.com"}) {
		t.Fatalf("forced raw redirect hosts = %#v", match["host"])
	}
}

func TestCaddyDNSProviderConfig(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		creds    map[string]string
		want     map[string]any
	}{
		{"cloudflare", dns.Cloudflare, map[string]string{"cf_api_token": "token"}, map[string]any{"name": "cloudflare", "api_token": "token"}},
		{"porkbun", dns.Porkbun, map[string]string{"pb_api_key": "key", "pb_secret_key": "secret"}, map[string]any{"name": "porkbun", "api_key": "key", "api_secret_key": "secret"}},
		{"namecheap", dns.Namecheap, map[string]string{"nc_api_user": "user", "nc_api_key": "key", "nc_client_ip": "192.0.2.1"}, map[string]any{"name": "namecheap", "user": "user", "api_key": "key", "client_ip": "192.0.2.1"}},
		{"godaddy", dns.GoDaddy, map[string]string{"gd_api_key": "key", "gd_api_secret": "secret"}, map[string]any{"name": "godaddy", "api_token": "key:secret"}},
		{"digitalocean", dns.DigitalOcean, map[string]string{"do_api_token": "token"}, map[string]any{"name": "digitalocean", "auth_token": "token"}},
		{"hetzner", dns.Hetzner, map[string]string{"hetzner_api_token": "token"}, map[string]any{"name": "hetzner", "api_token": "token"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := caddyDNSProviderConfig(tt.provider, tt.creds); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("config = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestCaddyDNSProviderConfigRejectsIncompleteCredentials(t *testing.T) {
	if got := caddyDNSProviderConfig(dns.Porkbun, map[string]string{"pb_api_key": "key"}); got != nil {
		t.Fatalf("incomplete credentials returned config %#v", got)
	}
}
