package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddylogs"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestReconcileCertificateLifecycleHealsStaleObtainingButPreservesRetry(t *testing.T) {
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
		Name: "example", Domains: "example.test", Source: models.CertSourceManaged,
	}); err != nil {
		t.Fatal(err)
	}
	if err := models.UpsertCertificateLifecycle(conn, models.CertificateLifecycleStatus{
		ServerID: serverID, ServerName: "edge", Identifier: "example.test",
		Phase: "obtaining", Level: "INFO", Message: "obtaining certificate",
		UpdatedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	probeCalls := 0
	s := &Server{DB: conn, certificateProbeFn: func(server models.CaddyServer, cert models.Certificate) managedCertificateServerStatus {
		probeCalls++
		return managedCertificateServerStatus{ServerID: server.ID, ServerName: server.Name, Status: "healthy", Issuer: "Test CA"}
	}}
	updated, err := s.reconcileCertificateLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if updated != 1 || probeCalls != 1 {
		t.Fatalf("updated=%d probeCalls=%d, want 1/1", updated, probeCalls)
	}
	states, err := models.ListCertificateLifecycle(conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "active" || states[0].Identifier != "example.test" {
		t.Fatalf("reconciled state = %#v", states)
	}

	if err := models.UpsertCertificateLifecycle(conn, models.CertificateLifecycleStatus{
		ServerID: serverID, ServerName: "edge", Identifier: "example.test",
		Phase: "retrying", Level: "ERROR", Message: "will retry", Error: "challenge failed",
		UpdatedAt: time.Now().Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	probeCalls = 0
	updated, err = s.reconcileCertificateLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	if updated != 0 || probeCalls != 0 {
		t.Fatalf("retry state was probed/overwritten: updated=%d probeCalls=%d", updated, probeCalls)
	}
	states, err = models.ListCertificateLifecycle(conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "retrying" {
		t.Fatalf("retry state changed: %#v", states)
	}
}

func TestDisableRuntimeLogCaptureRetainsStateAfterRemoteFailure(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer admin.Close()

	hub := caddylogs.New(nil)
	hub.SetCapture(caddylogs.CaptureState{
		ServerID: 4, ServerName: "edge", Level: "INFO", ExpiresAt: time.Now().Add(time.Minute),
	})
	timer := time.NewTimer(time.Hour)
	t.Cleanup(func() { timer.Stop() })
	s := &Server{
		caddyLogHub:      hub,
		runtimeLogTimers: map[int64]*time.Timer{4: timer},
	}
	server := models.CaddyServer{ID: 4, Name: "edge", AdminURL: admin.URL}
	if err := s.disableRuntimeLogCapture(server); err == nil {
		t.Fatal("disable returned nil after the Caddy admin API rejected cleanup")
	}
	if _, active := hub.Capture(server.ID); !active {
		t.Fatal("capture state was cleared even though the remote logger is still installed")
	}
	if s.runtimeLogTimers[server.ID] != timer {
		t.Fatal("cleanup timer was discarded after a failed remote disable")
	}
}

func TestDisableRuntimeLogCaptureClearsStateAfterSuccess(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()

	hub := caddylogs.New(nil)
	hub.SetCapture(caddylogs.CaptureState{ServerID: 8, ServerName: "edge"})
	timer := time.NewTimer(time.Hour)
	s := &Server{
		caddyLogHub:      hub,
		runtimeLogTimers: map[int64]*time.Timer{8: timer},
	}
	server := models.CaddyServer{ID: 8, Name: "edge", AdminURL: admin.URL}
	if err := s.disableRuntimeLogCapture(server); err != nil {
		t.Fatal(err)
	}
	if _, active := hub.Capture(server.ID); active {
		t.Fatal("capture state remains after successful remote cleanup")
	}
	if _, found := s.runtimeLogTimers[server.ID]; found {
		t.Fatal("cleanup timer remains after successful remote cleanup")
	}
}
