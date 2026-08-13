package models_test

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestDNSSkipRecordPersistsAcrossManagedRouteTypes(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	proxy := &models.ProxyHost{
		Domains: "proxy.example.com", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 80,
		DNSProvider: "route53", DNSZoneID: "Z1", DNSSkipRecord: true,
	}
	proxyID, err := models.CreateProxyHost(conn, 1, 0, proxy)
	if err != nil {
		t.Fatal(err)
	}
	gotProxy, err := models.GetProxyHost(conn, proxyID)
	if err != nil || !gotProxy.DNSSkipRecord {
		t.Fatalf("proxy DNS-only mode = %v, err = %v", gotProxy != nil && gotProxy.DNSSkipRecord, err)
	}
	gotProxy.DNSSkipRecord = false
	if err := models.UpdateProxyHost(conn, gotProxy); err != nil {
		t.Fatal(err)
	}
	gotProxy, _ = models.GetProxyHost(conn, proxyID)
	if gotProxy.DNSSkipRecord {
		t.Fatal("proxy DNS-only mode was not cleared")
	}

	redirect := &models.RedirectionHost{
		Domains: "redirect.example.com", ForwardDomain: "example.com", Enabled: true,
		DNSProvider: "route53", DNSZoneID: "Z1", DNSSkipRecord: true,
	}
	redirectID, err := models.CreateRedirectionHost(conn, 1, 0, redirect)
	if err != nil {
		t.Fatal(err)
	}
	gotRedirect, err := models.GetRedirectionHost(conn, redirectID)
	if err != nil || !gotRedirect.DNSSkipRecord {
		t.Fatalf("redirect DNS-only mode = %v, err = %v", gotRedirect != nil && gotRedirect.DNSSkipRecord, err)
	}

	raw := &models.RawRoute{
		Label: "raw", JSONData: `{"match":[{"host":["raw.example.com"]}]}`, Enabled: true,
		DNSProvider: "route53", DNSZoneID: "Z1", DNSSkipRecord: true,
	}
	rawID, err := models.CreateRawRoute(conn, 1, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	gotRaw, err := models.GetRawRoute(conn, rawID)
	if err != nil || !gotRaw.DNSSkipRecord {
		t.Fatalf("raw-route DNS-only mode = %v, err = %v", gotRaw != nil && gotRaw.DNSSkipRecord, err)
	}
}
