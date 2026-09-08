package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

const fleetTestKeyPEM = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----"

// v2.41.0: a PEM certificate travels with its content, a host created on
// the target references the copy, a replaced PEM propagates on the next
// sync, and an existing target host keeps its own certificate choice.
func TestSyncFleetConfigurationCopiesPEMCertificatesAndMapsReferences(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	_, _, certPEM := startTLSFixture(t, time.Now().Add(30*24*time.Hour), "pem.example.com")
	pemCert := models.Certificate{Name: "uploaded", Domains: "pem.example.com", Source: models.CertSourcePEM, CertPEM: strings.TrimSpace(string(certPEM)), KeyPEM: fleetTestKeyPEM}
	pemID, err := models.CreateCertificate(s.DB, sourceServerID, 0, &pemCert)
	if err != nil {
		t.Fatal(err)
	}
	proxy := models.ProxyHost{Domains: "pem.example.com", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true, SSLEnabled: true, CertificateID: pemID}
	if _, err := models.CreateProxyHost(s.DB, sourceServerID, 0, &proxy); err != nil {
		t.Fatal(err)
	}
	// A target host that already exists keeps whatever it had (no certificate).
	preexisting := models.ProxyHost{Domains: "kept.example.com", ForwardScheme: "http", ForwardHost: "kept", ForwardPort: 1, Enabled: true}
	if _, err := models.CreateProxyHost(s.DB, targetServerID, 0, &preexisting); err != nil {
		t.Fatal(err)
	}
	keptSource := models.ProxyHost{Domains: "kept.example.com", ForwardScheme: "http", ForwardHost: "kept", ForwardPort: 1, Enabled: true, CertificateID: pemID}
	if _, err := models.CreateProxyHost(s.DB, sourceServerID, 0, &keptSource); err != nil {
		t.Fatal(err)
	}

	first, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if first.CertificatesCreated != 1 || first.CertificatesByPath != 0 || first.ProxiesCreated != 1 || first.ProxiesUpdated != 0 {
		t.Fatalf("first sync = %#v", first)
	}
	targetCerts, _ := models.ListCertificates(s.DB, targetServerID)
	if len(targetCerts) != 1 || targetCerts[0].Source != models.CertSourcePEM || targetCerts[0].CertPEM != pemCert.CertPEM || targetCerts[0].KeyPEM != fleetTestKeyPEM || targetCerts[0].Name != "uploaded" {
		t.Fatalf("target certificate = %+v, want the PEM copied verbatim", targetCerts)
	}
	targetCertID := targetCerts[0].ID
	hosts, _ := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
	byDomain := map[string]models.ProxyHost{}
	for _, h := range hosts {
		byDomain[h.Domains] = h
	}
	if byDomain["pem.example.com"].CertificateID != targetCertID {
		t.Errorf("created target host should reference the copied certificate %d, got %d", targetCertID, byDomain["pem.example.com"].CertificateID)
	}
	if byDomain["kept.example.com"].CertificateID != 0 {
		t.Errorf("pre-existing target host must keep its own certificate choice, got %d", byDomain["kept.example.com"].CertificateID)
	}
	if !strings.Contains(first.String(), "certificates: 1 added") {
		t.Errorf("summary = %q", first.String())
	}

	second, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil || second.Changed() != 0 {
		t.Fatalf("repeat sync should be idempotent: %#v, %v", second, err)
	}

	// Replace the PEM (a renewal) → the copy is updated, nothing else moves.
	_, _, renewed := startTLSFixture(t, time.Now().Add(90*24*time.Hour), "pem.example.com")
	pemCert.ID = pemID
	pemCert.CertPEM = strings.TrimSpace(string(renewed))
	if err := models.UpdateCertificate(s.DB, &pemCert); err != nil {
		t.Fatal(err)
	}
	third, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil || third.CertificatesUpdated != 1 || third.Changed() != 1 {
		t.Fatalf("renewal sync = %#v, %v; want exactly one certificate update", third, err)
	}
	targetCerts, _ = models.ListCertificates(s.DB, targetServerID)
	if len(targetCerts) != 1 || targetCerts[0].ID != targetCertID || targetCerts[0].CertPEM != pemCert.CertPEM {
		t.Fatalf("renewed PEM should land on the same target row: %+v", targetCerts)
	}
}

// A file-path certificate is copied as stored PEM when CaddyUI can read the
// files, and by path reference (counted, flagged) when it cannot.
func TestSyncFleetConfigurationCopiesFilePathCertificates(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	_, _, certPEM := startTLSFixture(t, time.Now().Add(30*24*time.Hour), "files.example.com")
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(fleetTestKeyPEM+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	readable := models.Certificate{Name: "readable", Domains: "files.example.com", Source: models.CertSourcePath, CertPath: certFile, KeyPath: keyFile}
	if _, err := models.CreateCertificate(s.DB, sourceServerID, 0, &readable); err != nil {
		t.Fatal(err)
	}
	unreadable := models.Certificate{Name: "remote-only", Domains: "remote.example.com", Source: models.CertSourcePath, CertPath: "/certs/remote/fullchain.pem", KeyPath: "/certs/remote/privkey.pem"}
	if _, err := models.CreateCertificate(s.DB, sourceServerID, 0, &unreadable); err != nil {
		t.Fatal(err)
	}

	summary, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.CertificatesCreated != 2 || summary.CertificatesByPath != 1 || !strings.Contains(summary.String(), "1 certificate(s) copied by file path only") {
		t.Fatalf("summary = %#v (%s)", summary, summary.String())
	}
	targets, _ := models.ListCertificates(s.DB, targetServerID)
	byName := map[string]models.Certificate{}
	for _, c := range targets {
		byName[c.Name] = c
	}
	got := byName["readable"]
	if got.Source != models.CertSourcePEM || got.CertPEM != strings.TrimSpace(string(certPEM)) || got.KeyPEM != fleetTestKeyPEM || got.CertPath != "" {
		t.Errorf("readable file-path certificate should be copied as PEM: %+v", got)
	}
	got = byName["remote-only"]
	if got.Source != models.CertSourcePath || got.CertPath != unreadable.CertPath || got.KeyPath != unreadable.KeyPath || got.CertPEM != "" {
		t.Errorf("unreadable file-path certificate should be copied by reference: %+v", got)
	}

	again, err := s.syncFleetConfiguration("admin@example.com", sourceServerID, targetServerID)
	if err != nil || again.Changed() != 0 || again.CertificatesByPath != 1 {
		t.Fatalf("repeat sync = %#v, %v; want no changes (the by-path count is informational)", again, err)
	}
}

// "Also configure on" from the certificate form copies custom certificates
// too, and a host cross-deployed with a custom certificate brings it along.
func TestCrossDeployCertificateAndReferencedCertificate(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	_, _, certPEM := startTLSFixture(t, time.Now().Add(30*24*time.Hour), "x.example.com")
	cert := models.Certificate{Name: "x", Domains: "x.example.com", Source: models.CertSourcePEM, CertPEM: strings.TrimSpace(string(certPEM)), KeyPEM: fleetTestKeyPEM}
	certID, err := models.CreateCertificate(s.DB, sourceServerID, 0, &cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.ID = certID
	s.crossDeployCertificate("admin@example.com", sourceServerID, cert, []int64{targetServerID})
	targets, _ := models.ListCertificates(s.DB, targetServerID)
	if len(targets) != 1 || targets[0].CertPEM != cert.CertPEM {
		t.Fatalf("cross-deployed PEM certificate = %+v", targets)
	}

	// A second, unrelated PEM certificate is referenced by a proxy host that is
	// cross-deployed on its own: the certificate must be copied first and the
	// created host must point at the copy.
	other := models.Certificate{Name: "y", Domains: "y.example.com", Source: models.CertSourcePEM, CertPEM: strings.TrimSpace(string(certPEM)), KeyPEM: fleetTestKeyPEM}
	otherID, err := models.CreateCertificate(s.DB, sourceServerID, 0, &other)
	if err != nil {
		t.Fatal(err)
	}
	host := models.ProxyHost{Domains: "y.example.com", ForwardScheme: "http", ForwardHost: "y", ForwardPort: 80, Enabled: true, SSLEnabled: true, CertificateID: otherID}
	host.ID, err = models.CreateProxyHost(s.DB, sourceServerID, 0, &host)
	if err != nil {
		t.Fatal(err)
	}
	s.crossDeployProxyHost("admin@example.com", sourceServerID, &host, []int64{targetServerID})
	targets, _ = models.ListCertificates(s.DB, targetServerID)
	var copied int64
	for _, c := range targets {
		if c.Name == "y" {
			copied = c.ID
		}
	}
	if copied == 0 {
		t.Fatalf("the referenced certificate should have been copied first: %+v", targets)
	}
	hosts, _ := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
	if len(hosts) != 1 || hosts[0].CertificateID != copied {
		t.Fatalf("cross-deployed host = %+v, want certificate_id %d", hosts, copied)
	}
}
