package models_test

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestListProxyHostSummariesLoadsListFieldsOnly(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ownerID, err := models.CreateUser(conn, "owner@example.com", "hash", "Owner", models.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	host := &models.ProxyHost{
		Domains:          "app.example.com",
		ForwardScheme:    "http",
		ForwardHost:      "app",
		ForwardPort:      8080,
		SSLEnabled:       true,
		SSLForced:        false,
		Enabled:          true,
		BasicAuthEnabled: true,
		MaintenanceMode:  true,
		Tags:             "production,customer",
		Notes:            "shown on the list",
		Color:            "blue",
		DNSProvider:      "cloudflare",
		DNSRecordID:      "record-id",
		AdvancedConfig:   "large field intentionally omitted from summaries",
	}
	if _, err := models.CreateProxyHost(conn, 1, ownerID, host); err != nil {
		t.Fatal(err)
	}

	got, err := models.ListProxyHostSummaries(conn, 1, ownerID, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("summaries = %d, want 1", len(got))
	}
	row := got[0]
	if row.Domains != host.Domains || row.ForwardHost != host.ForwardHost || row.ForwardPort != host.ForwardPort {
		t.Fatalf("summary core fields = %#v", row)
	}
	if !row.SSLEnabled || row.SSLForced || !row.Enabled || !row.BasicAuthEnabled || !row.MaintenanceMode {
		t.Fatalf("summary boolean fields = %#v", row)
	}
	if row.OwnerEmail != "owner@example.com" || !row.OwnerID.Valid || row.OwnerID.Int64 != ownerID {
		t.Fatalf("summary ownership = %#v", row)
	}
	if row.CFDNSRecordID != "record-id" {
		t.Fatalf("Cloudflare display record = %q, want record-id", row.CFDNSRecordID)
	}
	if row.AdvancedConfig != "" {
		t.Fatalf("summary unexpectedly loaded AdvancedConfig: %q", row.AdvancedConfig)
	}
}
