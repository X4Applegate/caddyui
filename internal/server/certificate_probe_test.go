package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// startTLSFixture serves a self-signed certificate for dnsNames on a
// loopback port and returns the address plus the certificate it presents.
func startTLSFixture(t *testing.T, notAfter time.Time, dnsNames ...string) (string, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0], Organization: []string{"CaddyUI test fixture"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newProbeTestServer(t *testing.T, target string) *Server {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Primary", AdminURL: "http://127.0.0.1:2019", Type: models.CaddyServerTypeManaged}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn}
	s.certProbeTargetFn = func(int64, string) string { return target }
	return s
}

// v2.39.0: a file-path certificate CaddyUI cannot read is described from what
// the node serves for its domain; the result round-trips through settings,
// the scheduled refresh updates it, and deleting the certificate clears it.
func TestProbeCustomCertificateReadsServedLeaf(t *testing.T) {
	notAfter := time.Now().Add(40 * 24 * time.Hour).Truncate(time.Second)
	addr, leaf, _ := startTLSFixture(t, notAfter, "files.example.test", "www.files.example.test")
	s := newProbeTestServer(t, addr)
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil || len(servers) != 1 {
		t.Fatalf("servers = %+v, err=%v", servers, err)
	}
	serverID := servers[0].ID
	cert := models.Certificate{Name: "wildcard-files", Domains: "files.example.test", Source: models.CertSourcePath,
		CertPath: "/nonexistent/fullchain.pem", KeyPath: "/nonexistent/privkey.pem"}
	id, err := models.CreateCertificate(s.DB, serverID, 0, &cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.ID = id

	info := s.probeCustomCertificate(serverID, cert)
	if info.Status != "healthy" || !info.HasCertificate() {
		t.Fatalf("status = %q (%s), want healthy", info.Status, info.Error)
	}
	if info.ProbeName != "files.example.test" || info.Target != addr || info.ServerName != "Primary" {
		t.Errorf("probe name/target/server = %q/%q/%q", info.ProbeName, info.Target, info.ServerName)
	}
	if !info.NotAfter.Equal(leaf.NotAfter) || info.DaysLeft() < 38 || info.DaysLeft() > 40 {
		t.Errorf("NotAfter = %v (%d days), want %v", info.NotAfter, info.DaysLeft(), leaf.NotAfter)
	}
	want := summarizeX509(leaf)
	if info.Fingerprint != want.Fingerprint || info.SerialNumber != want.SerialNumber || info.IssuerCN != "files.example.test" || info.KeyType != "ECDSA" || info.KeyBits != 256 {
		t.Errorf("summary mismatch: %+v vs %+v", info, want)
	}
	if strings.Join(info.SANs, ",") != "files.example.test,www.files.example.test" {
		t.Errorf("SANs = %v", info.SANs)
	}

	if s.certificateProbeFor(id) != nil {
		t.Fatal("nothing should be stored before the first store")
	}
	if err := s.storeCertificateProbe(info); err != nil {
		t.Fatal(err)
	}
	stored := s.certificateProbeFor(id)
	if stored == nil || stored.Fingerprint != info.Fingerprint || !stored.NotAfter.Equal(*info.NotAfter) || stored.Status != "healthy" {
		t.Fatalf("stored = %+v, want the probe result back", stored)
	}

	// Scheduled/manual refresh probes every custom certificate on the server.
	before := stored.CheckedAt
	time.Sleep(10 * time.Millisecond)
	n, err := s.refreshCertificateProbes(serverID)
	if err != nil || n != 1 {
		t.Fatalf("refresh = %d, %v; want 1 certificate probed", n, err)
	}
	if again := s.certificateProbeFor(id); again == nil || !again.CheckedAt.After(before) {
		t.Fatalf("refresh should have re-probed and stored a newer result, got %+v", again)
	}

	// Expiry for the dashboard comes from the probe when the file is unreadable.
	if exp := s.customCertificateExpiries([]models.Certificate{cert}); !exp[id].Equal(leaf.NotAfter) {
		t.Errorf("customCertificateExpiries = %v, want %v from the probe", exp, leaf.NotAfter)
	}

	s.deleteCertificateProbe(id)
	if s.certificateProbeFor(id) != nil {
		t.Fatal("probe result should be gone after delete")
	}
}

// A node that answers with a certificate for another name is reported as a
// mismatch (with the served names in the error), and one that cannot be
// reached as unavailable; neither counts as a certificate for the row.
func TestProbeCustomCertificateMismatchAndUnavailable(t *testing.T) {
	addr, _, _ := startTLSFixture(t, time.Now().Add(24*time.Hour), "other.example.test")
	s := newProbeTestServer(t, addr)
	cert := models.Certificate{ID: 7, Name: "x", Domains: "files.example.test", Source: models.CertSourcePath, CertPath: "/nope.pem", KeyPath: "/nope.key"}

	info := s.probeCustomCertificate(1, cert)
	if info.Status != "mismatch" || info.HasCertificate() || !strings.Contains(info.Error, "other.example.test") || !strings.Contains(info.Error, "files.example.test") {
		t.Fatalf("mismatch probe = %+v", info)
	}
	if info.NotAfter == nil {
		t.Error("the served certificate's dates should still be reported on a mismatch")
	}

	s.certProbeTargetFn = func(int64, string) string { return "127.0.0.1:1" }
	info = s.probeCustomCertificate(1, cert)
	if info.Status != "unavailable" || info.HasCertificate() || info.Error == "" || info.NotAfter != nil {
		t.Fatalf("unavailable probe = %+v", info)
	}

	// Wildcard-only definitions are probed through a synthetic child name.
	wild := models.Certificate{ID: 8, Domains: "*.example.test", Source: models.CertSourcePEM}
	if got := s.probeCustomCertificate(1, wild).ProbeName; got != "caddyui-probe.example.test" {
		t.Errorf("wildcard probe name = %q", got)
	}
}

// Inspect prefers what CaddyUI can read itself and marks the probe fallback;
// when both are known it says whether Caddy serves the same certificate.
func TestFillCertificateInspectDataFallsBackToProbe(t *testing.T) {
	addr, leaf, leafPEM := startTLSFixture(t, time.Now().Add(10*24*time.Hour), "files.example.test")
	s := newProbeTestServer(t, addr)
	servers, _ := models.ListCaddyServers(s.DB)
	serverID := servers[0].ID

	unreadable := models.Certificate{Name: "path", Domains: "files.example.test", Source: models.CertSourcePath, CertPath: "/nonexistent/fullchain.pem", KeyPath: "/nonexistent/privkey.pem"}
	unreadableID, err := models.CreateCertificate(s.DB, serverID, 0, &unreadable)
	if err != nil {
		t.Fatal(err)
	}
	unreadable.ID = unreadableID
	data := map[string]any{}
	s.fillCertificateInspectData(data, unreadableID, unreadable)
	if data["FromProbe"] != true || data["Fingerprint"] != summarizeX509(leaf).Fingerprint || data["Issuer"] == "" || data["ReadError"] == nil {
		t.Fatalf("unreadable path should be described from the probe, got %+v", data)
	}
	if days, _ := data["DaysLeft"].(int); days < 8 || days > 10 {
		t.Errorf("DaysLeft = %v, want ~9", data["DaysLeft"])
	}
	if s.certificateProbeFor(unreadableID) == nil {
		t.Error("the fresh probe should have been stored for the list page")
	}

	// Stored PEM identical to what Caddy serves: read locally, served matches.
	stored := models.Certificate{Name: "pem", Domains: "files.example.test", Source: models.CertSourcePEM, CertPEM: string(leafPEM), KeyPEM: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"}
	storedID, err := models.CreateCertificate(s.DB, serverID, 0, &stored)
	if err != nil {
		t.Fatal(err)
	}
	stored.ID = storedID
	data = map[string]any{}
	s.fillCertificateInspectData(data, storedID, stored)
	if data["FromProbe"] != nil || data["ServedKnown"] != true || data["ServedMatches"] != true {
		t.Fatalf("stored PEM matching the served leaf: %+v", data)
	}

	// A different served certificate is flagged, not silently accepted.
	otherAddr, _, _ := startTLSFixture(t, time.Now().Add(90*24*time.Hour), "files.example.test")
	s.certProbeTargetFn = func(int64, string) string { return otherAddr }
	s.deleteCertificateProbe(storedID)
	data = map[string]any{}
	s.fillCertificateInspectData(data, storedID, stored)
	if data["ServedKnown"] != true || data["ServedMatches"] != false {
		t.Fatalf("a renewed-but-not-reloaded certificate should show as different: %+v", data)
	}
	if exp := s.customCertificateExpiries([]models.Certificate{{ID: storedID, Source: models.CertSourcePEM, CertPEM: string(leafPEM)}}); !exp[storedID].Equal(leaf.NotAfter) {
		t.Errorf("a readable PEM wins over the probe for expiry: %v", exp)
	}
}

// The Operations dashboard counts file-path certificates once their expiry
// is known through the probe; stored PEMs still work without the map.
func TestDashboardRecommendationsCountPathCertificates(t *testing.T) {
	now := time.Now()
	pathCert := models.Certificate{ID: 1, Name: "path", Domains: "a.example.test", Source: models.CertSourcePath, CertPath: "/x.pem", KeyPath: "/x.key"}
	recs := buildDashboardRecommendations(dashboardRecommendationInput{
		Certificates:      []models.Certificate{pathCert},
		CertificateExpiry: map[int64]time.Time{1: now.Add(10 * 24 * time.Hour)},
		Now:               now,
	})
	found := false
	for _, r := range recs {
		if r.Title == "Custom certificates expire soon" && strings.Contains(r.Detail, "1 custom certificate(s)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an expiring-soon recommendation for the probed path certificate, got %+v", recs)
	}
	// Unknown expiry → no claim either way.
	for _, r := range buildDashboardRecommendations(dashboardRecommendationInput{Certificates: []models.Certificate{pathCert}, Now: now}) {
		if strings.HasPrefix(r.Title, "Custom certificates") {
			t.Fatalf("no expiry known, so no expiry recommendation expected: %+v", r)
		}
	}
}
