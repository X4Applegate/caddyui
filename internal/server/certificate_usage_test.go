package server

import (
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

func TestUnusedCustomCertificatesExcludeManagedACME(t *testing.T) {
	referenced := referencedCertificateIDs(
		[]models.ProxyHost{{CertificateID: 1}},
		[]models.RedirectionHost{{CertificateID: 2}},
		[]models.RawRoute{{CertificateID: 3}},
	)

	tests := []struct {
		name string
		cert models.Certificate
		want bool
	}{
		{name: "referenced pem", cert: models.Certificate{ID: 1, Source: models.CertSourcePEM}, want: false},
		{name: "referenced path", cert: models.Certificate{ID: 2, Source: models.CertSourcePath}, want: false},
		{name: "unused pem", cert: models.Certificate{ID: 4, Source: models.CertSourcePEM}, want: true},
		{name: "unused path", cert: models.Certificate{ID: 5, Source: models.CertSourcePath}, want: true},
		{name: "standalone managed", cert: models.Certificate{ID: 6, Source: models.CertSourceManaged}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUnusedCustomCertificate(tt.cert, referenced); got != tt.want {
				t.Fatalf("isUnusedCustomCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSummarizeCertificateNames(t *testing.T) {
	certs := []models.Certificate{
		{ID: 1, Name: "legacy-api"},
		{ID: 2, Name: "old-wildcard"},
		{ID: 3},
	}
	if got, want := summarizeCertificateNames(certs, 2), "legacy-api, old-wildcard and 1 more"; got != want {
		t.Fatalf("summarizeCertificateNames() = %q, want %q", got, want)
	}
}

func TestUnusedCertificateFingerprintIsStableAndChangesWithSet(t *testing.T) {
	certs := []models.Certificate{
		{ID: 8, Source: models.CertSourcePEM},
		{ID: 3, Source: models.CertSourcePath},
		{ID: 5, Source: models.CertSourceManaged},
	}
	if got, want := unusedCertificateFingerprint(certs, nil), "3,8"; got != want {
		t.Fatalf("unusedCertificateFingerprint() = %q, want %q", got, want)
	}
	if got, want := unusedCertificateFingerprint(certs, map[int64]bool{3: true}), "8"; got != want {
		t.Fatalf("unusedCertificateFingerprint() after assignment = %q, want %q", got, want)
	}
}
