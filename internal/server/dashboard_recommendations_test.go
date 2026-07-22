package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

func TestBuildDashboardRecommendationsOperationalRisks(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	lastSync := now.Add(-10 * 24 * time.Hour)
	recs := buildDashboardRecommendations(dashboardRecommendationInput{
		ProxyHosts: []models.ProxyHost{
			{ID: 1, Domains: "plain.example.com", Enabled: true, SSLEnabled: false, DNSProvider: "cloudflare", CertificateID: 2},
			{ID: 2, Domains: "dns.example.com", Enabled: true, SSLEnabled: true, DNSProvider: "cloudflare", DNSProfileID: "deleted-profile"},
		},
		Certificates: []models.Certificate{
			{ID: 2, Source: models.CertSourcePEM, CertPEM: testCertificatePEM(t, now.Add(-24*time.Hour))},
		},
		DNSProfileIDs: map[string]bool{"active-profile": true},
		LastSync:      &lastSync,
		DownCount:     1,
		Now:           now,
	})

	want := []string{
		"Upstreams are down",
		"Enabled hosts have SSL off",
		"Managed DNS is incomplete",
		"DNS profile references are missing",
		"Custom certificates are expired",
		"Last sync is over a week old",
	}
	for _, title := range want {
		if !hasRecommendation(recs, title) {
			t.Fatalf("missing recommendation %q in %#v", title, recs)
		}
	}
	if len(recs) != len(want) {
		t.Fatalf("expected %d recommendations, got %d: %#v", len(want), len(recs), recs)
	}
}

func TestBuildDashboardRecommendationsAdminHardening(t *testing.T) {
	recs := buildDashboardRecommendations(dashboardRecommendationInput{
		IsAdmin:       true,
		AutoSnapshots: true,
		Now:           time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC),
	})

	for _, title := range []string{
		"2FA is not required",
		"Admin IP allowlist is empty",
		"No config snapshots yet",
	} {
		if !hasRecommendation(recs, title) {
			t.Fatalf("missing recommendation %q in %#v", title, recs)
		}
	}
}

func TestBuildDashboardRecommendationsCapsNoise(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	recs := buildDashboardRecommendations(dashboardRecommendationInput{
		IsAdmin:           true,
		ProxyHosts:        []models.ProxyHost{{ID: 1, Enabled: true, SSLEnabled: false, DNSProvider: "cloudflare", DNSProfileID: "deleted-profile"}},
		Certificates:      []models.Certificate{{ID: 9, Source: models.CertSourcePEM, CertPEM: testCertificatePEM(t, now.Add(-24*time.Hour))}},
		DNSProfileIDs:     map[string]bool{},
		DownCount:         2,
		MaintenanceCount:  1,
		Require2FA:        false,
		AdminAllowlistSet: false,
		AutoSnapshots:     false,
		Now:               now,
	})

	if len(recs) != 6 {
		t.Fatalf("expected recommendations to be capped at 6, got %d: %#v", len(recs), recs)
	}
}

func hasRecommendation(recs []dashboardRecommendation, title string) bool {
	for _, rec := range recs {
		if rec.Title == title {
			return true
		}
	}
	return false
}

func testCertificatePEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
