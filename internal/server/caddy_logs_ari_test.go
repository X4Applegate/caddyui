// SPDX-License-Identifier: Apache-2.0

package server

import (
	"path/filepath"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #151: a long-past ACME failure must not outlive the live evidence. The
// reporter's certificate failed one renewal-information update on 2026-10-11
// and was still shown as Issuance error on 2026-10-25 while serving fine.
func TestReconcileCertificateLifecycleHealsLongStaleFailure(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "edge", AdminURL: "http://edge:2019", Type: models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateCertificate(conn, serverID, 0, &models.Certificate{
		Name: "wildcard", Domains: "*.example.com", Source: models.CertSourceManaged,
	}); err != nil {
		t.Fatal(err)
	}
	if err := models.UpsertCertificateLifecycle(conn, models.CertificateLifecycleStatus{
		ServerID: serverID, ServerName: "edge", Identifier: "*.example.com",
		Phase: "error", Level: "ERROR",
		Message: "failed updating renewal info from ACME CA",
		Error:   "dial tcp: lookup acme-v02.api.letsencrypt.org: server misbehaving",
		// Two weeks stale, as in the report.
		UpdatedAt: time.Now().Add(-14 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	probeCalls := 0
	s := &Server{DB: conn, certificateProbeFn: func(server models.CaddyServer, cert models.Certificate) managedCertificateServerStatus {
		probeCalls++
		return managedCertificateServerStatus{
			ServerID: server.ID, ServerName: server.Name, Status: "healthy", Issuer: "Test CA",
		}
	}}
	updated, err := s.reconcileCertificateLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if updated != 1 || probeCalls != 1 {
		t.Fatalf("stale failure was not re-probed: updated=%d probeCalls=%d, want 1/1", updated, probeCalls)
	}
	states, err := models.ListCertificateLifecycle(conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "active" {
		t.Fatalf("healed state = %#v, want active", states)
	}
	if states[0].Error != "" {
		t.Fatalf("stale error text survived a healthy probe: %q", states[0].Error)
	}
}

// A failure must still be honoured while it is recent, so a real outage is not
// painted over by a probe against a certificate that is still valid on disk.
func TestReconcileCertificateLifecyclePreservesRecentFailure(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "edge", AdminURL: "http://edge:2019", Type: models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateCertificate(conn, serverID, 0, &models.Certificate{
		Name: "wildcard", Domains: "*.example.com", Source: models.CertSourceManaged,
	}); err != nil {
		t.Fatal(err)
	}
	if err := models.UpsertCertificateLifecycle(conn, models.CertificateLifecycleStatus{
		ServerID: serverID, ServerName: "edge", Identifier: "*.example.com",
		Phase: "error", Level: "ERROR", Message: "could not get certificate from issuer",
		Error: "challenge failed", UpdatedAt: time.Now().Add(-5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	probeCalls := 0
	s := &Server{DB: conn, certificateProbeFn: func(server models.CaddyServer, cert models.Certificate) managedCertificateServerStatus {
		probeCalls++
		return managedCertificateServerStatus{ServerID: server.ID, Status: "healthy"}
	}}
	updated, err := s.reconcileCertificateLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if updated != 0 || probeCalls != 0 {
		t.Fatalf("recent failure was overwritten: updated=%d probeCalls=%d", updated, probeCalls)
	}
	states, err := models.ListCertificateLifecycle(conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "error" {
		t.Fatalf("recent failure state = %#v, want error retained", states)
	}
}

// Revocation is a CA decision; no local TLS probe may clear it.
func TestReconcileCertificateLifecycleNeverHealsRevoked(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "edge", AdminURL: "http://edge:2019", Type: models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateCertificate(conn, serverID, 0, &models.Certificate{
		Name: "wildcard", Domains: "*.example.com", Source: models.CertSourceManaged,
	}); err != nil {
		t.Fatal(err)
	}
	if err := models.UpsertCertificateLifecycle(conn, models.CertificateLifecycleStatus{
		ServerID: serverID, ServerName: "edge", Identifier: "*.example.com",
		Phase: "revoked", Level: "ERROR", Message: "certificate revoked",
		UpdatedAt: time.Now().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	probeCalls := 0
	s := &Server{DB: conn, certificateProbeFn: func(server models.CaddyServer, cert models.Certificate) managedCertificateServerStatus {
		probeCalls++
		return managedCertificateServerStatus{ServerID: server.ID, Status: "healthy"}
	}}
	if _, err := s.reconcileCertificateLifecycle(); err != nil {
		t.Fatal(err)
	}
	if probeCalls != 0 {
		t.Fatalf("revoked certificate was re-probed %d time(s)", probeCalls)
	}
	states, err := models.ListCertificateLifecycle(conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "revoked" {
		t.Fatalf("revoked state = %#v, want revoked retained", states)
	}
}
