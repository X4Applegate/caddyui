package server

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func newFleetSyncTestServer(t *testing.T) (*Server, int64, int64) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	sourceID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: "http://primary:2019", Type: models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	targetID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Secondary", AdminURL: "http://secondary:2019", Type: models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{DB: conn}, sourceID, targetID
}

func TestFleetProxyUpsertTracksSourceAndPreservesTargetPolicy(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	source := models.ProxyHost{
		Domains:       "app.example.com",
		ForwardScheme: "http",
		ForwardHost:   "app-v1",
		ForwardPort:   8080,
		SSLEnabled:    true,
		SSLForced:     true,
		Enabled:       true,
		DNSProvider:   "source-provider",
		DNSZoneID:     "source-zone",
		DNSRecordID:   "source-record",
	}
	var err error
	source.ID, err = models.CreateProxyHost(s.DB, sourceServerID, 0, &source)
	if err != nil {
		t.Fatal(err)
	}

	first, err := s.upsertFleetProxyHost(sourceServerID, targetServerID, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || !first.Changed {
		t.Fatalf("first upsert = %#v, want created and changed", first)
	}
	targetCertID, err := models.CreateCertificate(s.DB, targetServerID, 0, &models.Certificate{
		Name: "secondary-only", Domains: "app.example.com", Source: models.CertSourcePath,
		CertPath: "/target/cert.pem", KeyPath: "/target/key.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := models.GetProxyHost(s.DB, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	target.CertificateID = targetCertID
	target.DNSProvider = "target-provider"
	target.DNSProfileID = "target-profile"
	target.DNSZoneID = "target-zone"
	target.DNSZoneName = "example.com"
	target.DNSRecordID = "target-record"
	if err := models.UpdateProxyHost(s.DB, target); err != nil {
		t.Fatal(err)
	}
	if err := models.UpdateProxyHostDNSProfile(s.DB, target.ID, target.DNSProfileID); err != nil {
		t.Fatal(err)
	}

	source.Domains = "renamed.example.com"
	source.ForwardHost = "app-v2"
	updated, err := s.upsertFleetProxyHost(sourceServerID, targetServerID, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Created || !updated.Changed || updated.ID != first.ID {
		t.Fatalf("tracked update = %#v, want same changed target row", updated)
	}
	hosts, err := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("target proxy rows = %d, want 1", len(hosts))
	}
	got := hosts[0]
	if got.Domains != "renamed.example.com" || got.ForwardHost != "app-v2" {
		t.Fatalf("target route = %#v, want renamed app-v2 route", got)
	}
	if got.CertificateID != targetCertID || got.DNSProvider != "target-provider" || got.DNSProfileID != "target-profile" || got.DNSRecordID != "target-record" {
		t.Fatalf("target-specific policy was overwritten: %#v", got)
	}

	unchanged, err := s.upsertFleetProxyHost(sourceServerID, targetServerID, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Created || unchanged.Changed || unchanged.ID != first.ID {
		t.Fatalf("repeat upsert = %#v, want idempotent no-op", unchanged)
	}
}

func TestFleetProxyUpsertRejectsTargetDomainCollision(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	redirect := models.RedirectionHost{
		Domains: "claimed.example.com", ForwardDomain: "elsewhere.example.com",
		ForwardHTTPCode: 301, Enabled: true,
	}
	if _, err := models.CreateRedirectionHost(s.DB, targetServerID, 0, &redirect); err != nil {
		t.Fatal(err)
	}
	proxy := models.ProxyHost{
		Domains: "claimed.example.com", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true,
	}
	var err error
	proxy.ID, err = models.CreateProxyHost(s.DB, sourceServerID, 0, &proxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.upsertFleetProxyHost(sourceServerID, targetServerID, proxy, 0); err == nil {
		t.Fatal("upsert succeeded despite redirect domain collision")
	}
	hosts, err := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Fatalf("target proxy rows = %d, want 0", len(hosts))
	}
}

func TestSyncFleetConfigurationCopiesEveryManagedRouteIdempotently(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	certificate := models.Certificate{
		Name: "wildcard", Domains: "*.example.com", Source: models.CertSourceManaged,
		DNSProvider: "cloudflare", DNSProfileID: "profile-1",
	}
	if _, err := models.CreateCertificate(s.DB, sourceServerID, 0, &certificate); err != nil {
		t.Fatal(err)
	}
	proxy := models.ProxyHost{
		Domains: "proxy.example.com", ForwardScheme: "http", ForwardHost: "proxy-app", ForwardPort: 8080, Enabled: true,
	}
	if _, err := models.CreateProxyHost(s.DB, sourceServerID, 0, &proxy); err != nil {
		t.Fatal(err)
	}
	redirect := models.RedirectionHost{
		Domains: "old.example.com", ForwardScheme: "https", ForwardDomain: "new.example.com",
		ForwardHTTPCode: 301, Enabled: true,
	}
	if _, err := models.CreateRedirectionHost(s.DB, sourceServerID, 0, &redirect); err != nil {
		t.Fatal(err)
	}
	raw := models.RawRoute{
		Label: "advanced", JSONData: `[{"match":[{"host":["raw.example.com"]}],"handle":[{"handler":"static_response","status_code":200}]}]`, Enabled: true,
	}
	raw.ID, _ = models.CreateRawRoute(s.DB, sourceServerID, 0, &raw)
	if raw.ID == 0 {
		t.Fatal("create source raw route returned zero ID")
	}
	targetOnly := models.ProxyHost{
		Domains: "target-only.example.com", ForwardScheme: "http", ForwardHost: "target-only", ForwardPort: 9000, Enabled: true,
	}
	if _, err := models.CreateProxyHost(s.DB, targetServerID, 0, &targetOnly); err != nil {
		t.Fatal(err)
	}

	first, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if first.CertificatesCreated != 1 || first.ProxiesCreated != 1 || first.RedirectsCreated != 1 || first.RawRoutesCreated != 1 {
		t.Fatalf("first sync summary = %#v", first)
	}
	second, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed() != 0 {
		t.Fatalf("repeat sync changed %d resources: %#v", second.Changed(), second)
	}

	hosts, _ := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
	redirects, _ := models.ListRedirectionHosts(s.DB, targetServerID, 0, true, nil)
	rawRoutes, _ := models.ListRawRoutes(s.DB, targetServerID, 0, true, nil)
	certificates, _ := models.ListCertificates(s.DB, targetServerID)
	if len(hosts) != 2 || len(redirects) != 1 || len(rawRoutes) != 1 || len(certificates) != 1 {
		t.Fatalf("target counts proxies=%d redirects=%d raw=%d certs=%d, want 2/1/1/1", len(hosts), len(redirects), len(rawRoutes), len(certificates))
	}

	raw.JSONData = `[{"match":[{"host":["renamed-raw.example.com"]}],"handle":[{"handler":"static_response","status_code":204}]}]`
	if err := models.UpdateRawRoute(s.DB, &raw); err != nil {
		t.Fatal(err)
	}
	third, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if third.RawRoutesUpdated != 1 || third.Changed() != 1 {
		t.Fatalf("raw rename sync summary = %#v, want one update", third)
	}
	rawRoutes, _ = models.ListRawRoutes(s.DB, targetServerID, 0, true, nil)
	if len(rawRoutes) != 1 || !sameDomainSet(rawRouteHosts(rawRoutes[0]), []string{"renamed-raw.example.com"}) {
		t.Fatalf("tracked raw routes = %#v, want one renamed route", rawRoutes)
	}
}
