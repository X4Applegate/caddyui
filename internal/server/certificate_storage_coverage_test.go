// SPDX-License-Identifier: Apache-2.0

package server

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Issue #153: when a Managed ACME definition lists both a wildcard and the
// apex, Caddy stores TWO separate certificates. findStorageCertificate used to
// return whichever merely expired latest, so the apex certificate — normally
// the newer one, because it was added later — was chosen and pushed to fleet
// targets. Every subdomain then failed TLS on the target.
//
// Selection must follow domain coverage, not expiry.
func TestFindStorageCertificatePrefersBroadestCoverage(t *testing.T) {
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	roots := []string{dataDir}
	issuer := "acme-v02.api.letsencrypt.org-directory"
	domains := []string{"*.example.com", "example.com"}

	// The apex is obtained later, so it expires later. That must not win.
	writeStorageCertificate(t, root, issuer, "*.example.com", time.Now().Add(40*24*time.Hour))
	writeStorageCertificate(t, root, issuer, "example.com", time.Now().Add(80*24*time.Hour))

	found, err := findStorageCertificate(dataDir, domains, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(found.CertPath, "wildcard_.example.com") {
		t.Fatalf("selected %s, want the wildcard certificate", found.CertPath)
	}

	// Order in the definition must not change the answer.
	found, err = findStorageCertificate(dataDir, []string{"example.com", "*.example.com"}, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(found.CertPath, "wildcard_.example.com") {
		t.Fatalf("reversed domain order selected %s, want the wildcard", found.CertPath)
	}
}

// With equal coverage the newest certificate still wins, which is what the
// v2.42.0 export feature and renewal pickup rely on.
func TestFindStorageCertificateBreaksCoverageTiesByExpiry(t *testing.T) {
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	roots := []string{dataDir}

	writeStorageCertificate(t, root, "acme.zerossl.com-v2-DV90", "*.example.com", time.Now().Add(20*24*time.Hour))
	writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(80*24*time.Hour))

	found, err := findStorageCertificate(dataDir, []string{"*.example.com"}, roots)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(found.CertPath, "acme-v02.api.letsencrypt.org-directory") {
		t.Fatalf("selected %s, want the later-expiring issuer", found.CertPath)
	}
}

// A single stored certificate that covers every name is reported as complete,
// so callers can tell a full push from a partial one.
func TestFindStorageCertificateReportsFullCoverage(t *testing.T) {
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	roots := []string{dataDir}

	writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(60*24*time.Hour))

	found, err := findStorageCertificate(dataDir, []string{"*.example.com", "a.example.com"}, roots)
	if err != nil {
		t.Fatal(err)
	}
	// One wildcard certificate covers both the wildcard name and a subdomain.
	if len(found.Uncovered) != 0 {
		t.Fatalf("uncovered = %v, want none: a wildcard covers its subdomains", found.Uncovered)
	}
}

// When no single stored certificate covers every name, the gap is reported so
// the operator is told instead of being silently handed a partial certificate.
func TestFindStorageCertificateReportsUncoveredNames(t *testing.T) {
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	roots := []string{dataDir}
	issuer := "acme-v02.api.letsencrypt.org-directory"

	writeStorageCertificate(t, root, issuer, "*.example.com", time.Now().Add(40*24*time.Hour))
	writeStorageCertificate(t, root, issuer, "example.com", time.Now().Add(80*24*time.Hour))

	found, err := findStorageCertificate(dataDir, []string{"*.example.com", "example.com"}, roots)
	if err != nil {
		t.Fatal(err)
	}
	// The wildcard wins on coverage, but it does not cover the apex: *.example.com
	// matches one label, never the bare domain.
	if len(found.Uncovered) != 1 || found.Uncovered[0] != "example.com" {
		t.Fatalf("uncovered = %v, want [example.com]", found.Uncovered)
	}
}
