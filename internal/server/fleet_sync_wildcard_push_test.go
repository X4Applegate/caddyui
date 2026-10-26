// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// leafFromPEM parses the certificate a push left on the target.
func leafFromPEM(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("target certificate is not PEM: %q", certPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// Issue #153: a Managed ACME certificate listing both the wildcard and the
// apex is stored by Caddy as two separate certificates. Source Push used to
// send whichever expired latest — normally the apex, because it was added
// later — so the target stopped serving every subdomain.
func TestSourcePushPrefersWildcardOverApexWhenBothAreStored(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	issuer := "acme-v02.api.letsencrypt.org-directory"

	// The apex was obtained later, so it expires later.
	writeStorageCertificate(t, root, issuer, "*.example.com", time.Now().Add(40*24*time.Hour))
	writeStorageCertificate(t, root, issuer, "example.com", time.Now().Add(80*24*time.Hour))

	srv, _ := models.GetCaddyServer(s.DB, sourceServerID)
	srv.DataDir = dataDir
	if err := models.UpdateCaddyServer(s.DB, srv); err != nil {
		t.Fatal(err)
	}

	cert := newSourcePushCertificate(t, s, sourceServerID, "*.example.com,example.com", targetServerID)
	s.crossDeployCertificate("admin@example.com", sourceServerID, cert, cert.FleetPushTargetIDs())

	targets, err := models.ListCertificates(s.DB, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("target certificates = %d, want exactly one pushed copy", len(targets))
	}
	leaf := leafFromPEM(t, targets[0].CertPEM)
	if !certificateCoversName(leaf, "app.example.com") {
		t.Fatalf("pushed certificate presents %v — it does not cover a subdomain, so HTTPS breaks on the target", leaf.DNSNames)
	}

	// The operator must be told that the apex is not in this push, rather than
	// discovering it when the apex stops resolving.
	activity, err := models.ListActivity(s.DB, sourceServerID, 50)
	if err != nil {
		t.Fatal(err)
	}
	var warned bool
	for _, entry := range activity {
		if entry.Action == "cert_source_push" && strings.Contains(entry.Detail, "example.com") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("no activity entry warned that the push does not cover every name")
	}
}

// A wildcard-only definition still pushes cleanly and warns about nothing.
func TestSourcePushWildcardOnlyDefinitionWarnsAboutNothing(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(60*24*time.Hour))

	srv, _ := models.GetCaddyServer(s.DB, sourceServerID)
	srv.DataDir = dataDir
	if err := models.UpdateCaddyServer(s.DB, srv); err != nil {
		t.Fatal(err)
	}

	cert := newSourcePushCertificate(t, s, sourceServerID, "*.example.com", targetServerID)
	s.crossDeployCertificate("admin@example.com", sourceServerID, cert, cert.FleetPushTargetIDs())

	activity, err := models.ListActivity(s.DB, sourceServerID, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range activity {
		if entry.Action == "cert_source_push" {
			t.Fatalf("unexpected coverage warning for a fully covered push: %s", entry.Detail)
		}
	}
}
