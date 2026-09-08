package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// writeStorageCertificate lays out one certificate the way certmagic does:
// <root>/<issuer>/<safe name>/<safe name>.crt|.key. Returns the serial.
func writeStorageCertificate(t *testing.T, root, issuer, subject string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(time.Now().UnixNano())
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: subject}, DNSNames: []string{subject}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	name := storageSafeName(subject)
	dir := filepath.Join(root, issuer, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return serial.Text(16)
}

// v2.42.0: the newest stored certificate for the definition's domains is
// exported atomically with a private key readable by owner only; unchanged
// serials are not rewritten; a renewal in storage is picked up; the node
// event hook and Export now both drive it; a missing data dir is explained.
func TestExportCertificateFromCaddyStorage(t *testing.T) {
	s, sourceServerID, _ := newFleetSyncTestServer(t)
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	oldSerial := writeStorageCertificate(t, root, "acme.zerossl.com-v2-DV90", "*.example.com", time.Now().Add(20*24*time.Hour))
	newSerial := writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(80*24*time.Hour))
	srv, _ := models.GetCaddyServer(s.DB, sourceServerID)
	srv.DataDir = dataDir
	if err := models.UpdateCaddyServer(s.DB, srv); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "mail")
	exportJSON, err := models.NormalizeCertificateExportJSON(models.CertificateExport{Dir: outDir, CertFile: "cert.pem", KeyFile: "key.pem"})
	if err != nil {
		t.Fatal(err)
	}
	cert := models.Certificate{Name: "wildcard", Domains: "*.example.com, example.com", Source: models.CertSourceManaged, DNSProvider: "cloudflare", DNSProfileID: "p", Export: exportJSON}
	cert.ID, err = models.CreateCertificate(s.DB, sourceServerID, 0, &cert)
	if err != nil {
		t.Fatal(err)
	}
	loaded, _ := models.GetCertificate(s.DB, cert.ID)
	if loaded.Export != exportJSON || !loaded.ExportConfig().Enabled() || loaded.ExportConfig().CertFile != "cert.pem" {
		t.Fatalf("export settings did not round-trip: %+v", loaded)
	}

	st, err := s.exportCertificate(sourceServerID, *loaded, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.SerialNumber != newSerial || st.SerialNumber == oldSerial || st.ExportedAt == nil || len(st.Files) != 2 {
		t.Fatalf("status = %+v, want the newer certificate (serial %s) exported", st, newSerial)
	}
	certOut, keyOut := filepath.Join(outDir, "cert.pem"), filepath.Join(outDir, "key.pem")
	certBytes, err := os.ReadFile(certOut)
	if err != nil || parsePEMLeaf(string(certBytes)) == nil || parsePEMLeaf(string(certBytes)).SerialNumber.Text(16) != newSerial {
		t.Fatalf("exported certificate wrong: %v", err)
	}
	keyInfo, err := os.Stat(keyOut)
	if err != nil || keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("exported key mode = %v, err %v; want 0600", keyInfo, err)
	}
	if got := s.certificateExportStatusFor(cert.ID); got == nil || got.SerialNumber != newSerial {
		t.Fatalf("status not stored: %+v", got)
	}

	// Unchanged storage → nothing rewritten (ExportedAt stays).
	firstExport := *st.ExportedAt
	time.Sleep(10 * time.Millisecond)
	st, err = s.exportCertificate(sourceServerID, *loaded, false)
	if err != nil || !st.ExportedAt.Equal(firstExport) {
		t.Fatalf("unchanged serial should not re-export: %+v, %v", st, err)
	}
	// Export now forces a rewrite.
	st, err = s.exportCertificate(sourceServerID, *loaded, true)
	if err != nil || !st.ExportedAt.After(firstExport) {
		t.Fatalf("forced export should rewrite: %+v, %v", st, err)
	}

	// A renewal lands in storage → the node's event picks it up.
	renewedSerial := writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(90*24*time.Hour))
	if n := s.exportCertificatesForIdentifier(sourceServerID, "*.example.com"); n != 1 {
		t.Fatalf("event hook exported %d certificates, want 1", n)
	}
	if got := s.certificateExportStatusFor(cert.ID); got == nil || got.SerialNumber != renewedSerial {
		t.Fatalf("renewal not exported: %+v", got)
	}
	if n := s.exportCertificatesForIdentifier(sourceServerID, "unrelated.example.net"); n != 0 {
		t.Errorf("unrelated identifier must not trigger, got %d", n)
	}

	// The scheduled pass covers it too, and skips certificates without export settings.
	plain := models.Certificate{Name: "plain", Domains: "plain.example.com", Source: models.CertSourceManaged, DNSProvider: "cloudflare", DNSProfileID: "p"}
	if _, err := models.CreateCertificate(s.DB, sourceServerID, 0, &plain); err != nil {
		t.Fatal(err)
	}
	if n, err := s.runCertificateExports(0, false); err != nil || n != 1 {
		t.Fatalf("scheduled pass checked %d (%v), want 1", n, err)
	}

	// No data directory → a message that says what to configure.
	srv.DataDir = ""
	_ = models.UpdateCaddyServer(s.DB, srv)
	if _, err := s.exportCertificate(sourceServerID, *loaded, true); err == nil || !strings.Contains(err.Error(), "Data directory") {
		t.Fatalf("missing data dir should be explained, got %v", err)
	}
	s.deleteCertificateExportStatus(cert.ID)
	if s.certificateExportStatusFor(cert.ID) != nil {
		t.Error("status should be gone after delete")
	}
}

func TestFindStorageCertificateExplainsMisses(t *testing.T) {
	if _, err := findStorageCertificate(filepath.Join(t.TempDir(), "nope"), []string{"a.example.com"}); err == nil || !strings.Contains(err.Error(), "mounted") {
		t.Errorf("missing storage should mention the mount, got %v", err)
	}
	dataDir := t.TempDir()
	writeStorageCertificate(t, filepath.Join(dataDir, "caddy", "certificates"), "acme-v02.api.letsencrypt.org-directory", "other.example.com", time.Now().Add(time.Hour))
	if _, err := findStorageCertificate(dataDir, []string{"a.example.com"}); err == nil || !strings.Contains(err.Error(), "has not stored") {
		t.Errorf("unknown domain should say Caddy has not stored it, got %v", err)
	}
	// The certificates directory itself is accepted as the data dir too.
	if found, err := findStorageCertificate(filepath.Join(dataDir, "caddy", "certificates"), []string{"other.example.com"}); err != nil || found == nil {
		t.Errorf("certificates dir as root: %v", err)
	}
	if storageSafeName("*.Example.COM") != "wildcard_.example.com" {
		t.Errorf("safe name = %q", storageSafeName("*.Example.COM"))
	}
}
