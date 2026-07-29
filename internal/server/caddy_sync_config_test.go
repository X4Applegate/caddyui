package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
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

func TestManagedCertificateRoutesTriggerAutomaticHTTPS(t *testing.T) {
	certs := []models.Certificate{
		{ID: 1, Source: models.CertSourcePEM, Domains: "*.ignored.example.com"},
		{ID: 2, Source: models.CertSourceManaged, Domains: "*.example.com, *.sub.example.com"},
	}
	routes := buildManagedCertificateRoutes(certs)
	if len(routes) != 1 {
		t.Fatalf("routes = %d, want 1 managed-certificate route", len(routes))
	}
	route := routes[0].(map[string]any)
	match := route["match"].([]any)[0].(map[string]any)
	wantHosts := []any{"*.example.com", "*.sub.example.com"}
	if !reflect.DeepEqual(match["host"], wantHosts) {
		t.Fatalf("hosts = %#v, want %#v", match["host"], wantHosts)
	}
	handler := route["handle"].([]any)[0].(map[string]any)
	if handler["status_code"] != 404 || route["terminal"] != true {
		t.Fatalf("managed fallback = %#v, want terminal 404", route)
	}
}

func TestManagedCertificatePersistsDNSSelectionAndIsNotCustomOption(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	id, err := models.CreateCertificate(conn, 1, 0, &models.Certificate{
		Name:         "wildcard",
		Domains:      "*.example.com",
		Source:       models.CertSourceManaged,
		DNSProvider:  dns.Cloudflare,
		DNSProfileID: "profile-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := models.GetCertificate(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != models.CertSourceManaged || got.DNSProvider != dns.Cloudflare || got.DNSProfileID != "profile-1" {
		t.Fatalf("managed certificate round trip = %#v", got)
	}
	options, err := models.ListCertificateOptionsForUser(conn, 1, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 0 {
		t.Fatalf("custom certificate options = %#v, managed certificate must not be assignable as uploaded PEM", options)
	}
}

func TestManagedCertificateCoverageUsesSingleLabelWildcards(t *testing.T) {
	tests := []struct {
		cert string
		host string
		want bool
	}{
		{"*.example.com", "app.example.com", true},
		{"*.example.com", "APP.EXAMPLE.COM.", true},
		{"*.example.com", "deep.app.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.sub.example.com", "app.sub.example.com", true},
		{"app.example.com", "app.example.com", true},
		{"*.example.com", "*.example.com", true},
	}
	for _, tt := range tests {
		if got := managedCertificateCovers(tt.cert, tt.host); got != tt.want {
			t.Errorf("managedCertificateCovers(%q, %q) = %v, want %v", tt.cert, tt.host, got, tt.want)
		}
	}
}

func TestManagedWildcardSkipsCoveredExactCertificateIssuance(t *testing.T) {
	proxies := []models.ProxyHost{
		{Domains: "project.sub.example.com", Enabled: true, SSLEnabled: true},
		{Domains: "deep.project.sub.example.com", Enabled: true, SSLEnabled: true},
		{Domains: "sub.example.com", Enabled: true, SSLEnabled: true},
	}
	certs := []models.Certificate{
		{Source: models.CertSourceManaged, Domains: "*.sub.example.com"},
	}
	got := buildSkipCertificates(proxies, nil, nil, certs)
	if !reflect.DeepEqual(got, []any{"project.sub.example.com"}) {
		t.Fatalf("skip certificates = %#v, want only wildcard-covered exact hostname", got)
	}
}

func TestManagedWildcardSubjectItselfIsNeverSkipped(t *testing.T) {
	proxies := []models.ProxyHost{
		{Domains: "*.sub.example.com", Enabled: true, SSLEnabled: true},
	}
	certs := []models.Certificate{
		{Source: models.CertSourceManaged, Domains: "*.sub.example.com"},
	}
	if got := buildSkipCertificates(proxies, nil, nil, certs); len(got) != 0 {
		t.Fatalf("skip certificates = %#v, wildcard subject must remain eligible for issuance", got)
	}
}

func TestManagedCertificateProbeNameUsesSyntheticWildcardChild(t *testing.T) {
	cert := models.Certificate{Domains: "example.com, *.sub.example.com"}
	if got := managedCertificateProbeName(cert); got != "caddyui-probe.sub.example.com" {
		t.Fatalf("probe name = %q", got)
	}
}

func TestEnsureManagedCertificateOnServerDeduplicatesEquivalentSubjects(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	targetID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "target", AdminURL: "http://target:2019", Type: models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn}
	source := models.Certificate{
		Name: "wildcard", Domains: "*.example.com, example.com", Source: models.CertSourceManaged,
		DNSProvider: dns.Cloudflare,
	}
	created, err := s.ensureManagedCertificateOnServer("test", targetID, source)
	if err != nil || !created {
		t.Fatalf("first ensure = created %v, err %v; want created", created, err)
	}
	source.Domains = "example.com, *.example.com"
	created, err = s.ensureManagedCertificateOnServer("test", targetID, source)
	if err != nil || created {
		t.Fatalf("second ensure = created %v, err %v; want existing equivalent", created, err)
	}
	certs, err := models.ListCertificates(conn, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("target certificates = %d, want 1", len(certs))
	}
}

func TestCaddyDNSProviderConfigRejectsIncompleteCredentials(t *testing.T) {
	if got := caddyDNSProviderConfig(dns.Porkbun, map[string]string{"pb_api_key": "key"}); got != nil {
		t.Fatalf("incomplete credentials returned config %#v", got)
	}
}

func TestPushAutomationPoliciesCreatesMissingTLSApp(t *testing.T) {
	var postedPath string
	var posted map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apps": map[string]any{"http": map[string]any{}},
			})
		case r.Method == http.MethodPost:
			postedPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Errorf("decode POST: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer admin.Close()

	incoming := []map[string]any{{
		"subjects": []any{"example.com"},
		"issuers":  []any{map[string]any{"module": "acme"}},
	}}
	if err := pushAutomationPoliciesVia(caddy.New(admin.URL, "", ""), incoming); err != nil {
		t.Fatal(err)
	}
	if postedPath != "/config/apps/tls" {
		t.Fatalf("POST path = %q, want /config/apps/tls", postedPath)
	}
	automation, _ := posted["automation"].(map[string]any)
	policies, _ := automation["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("posted policies = %#v, want one policy", policies)
	}
}

func TestPushAutomationPoliciesPreservesExistingTLSAndUsesAutomationPath(t *testing.T) {
	var postedPath string
	var posted map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apps": map[string]any{
					"http": map[string]any{},
					"tls": map[string]any{
						"automation": map[string]any{"on_demand": map[string]any{}},
					},
				},
			})
		case r.Method == http.MethodPost:
			postedPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Errorf("decode POST: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer admin.Close()

	incoming := []map[string]any{{"subjects": []any{"example.com"}}}
	if err := pushAutomationPoliciesVia(caddy.New(admin.URL, "", ""), incoming); err != nil {
		t.Fatal(err)
	}
	if postedPath != "/config/apps/tls/automation" {
		t.Fatalf("POST path = %q, want /config/apps/tls/automation", postedPath)
	}
	if _, ok := posted["on_demand"]; !ok {
		t.Fatalf("existing automation fields were not preserved: %#v", posted)
	}
}
