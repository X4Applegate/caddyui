package caddylogs

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestHubPersistsCertificateLifecycleAndKeepsRuntimeLogsInMemory(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	hub := New(conn)
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000000,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"example.test","caddyui_server_id":2,"caddyui_server_name":"edge"}`))
	states, err := models.ListCertificateLifecycle(conn, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "obtaining" || states[0].Identifier != "example.test" {
		t.Fatalf("states = %#v, want obtaining example.test", states)
	}

	// CertMagic's retry line often omits identifier and embeds it at the
	// beginning of the error. The projection must retain that failure.
	hub.AcceptLine([]byte(`{"level":"error","ts":1700000001,"logger":"tls.obtain","msg":"will retry","error":"[example.test] Obtain: DNS challenge failed","attempt":1,"retrying_in":60,"caddyui_server_id":2,"caddyui_server_name":"edge"}`))
	states, err = models.ListCertificateLifecycle(conn, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "retrying" || states[0].Error == "" {
		t.Fatalf("retry state = %#v", states)
	}

	// A delayed line from another connection must not overwrite a newer
	// lifecycle projection that has already reached the UI.
	hub.AcceptLine([]byte(`{"level":"info","ts":1699999999,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"example.test","caddyui_server_id":2,"caddyui_server_name":"edge"}`))
	states, err = models.ListCertificateLifecycle(conn, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "retrying" {
		t.Fatalf("stale event replaced newer lifecycle state: %#v", states)
	}
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000002,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"example.test","caddyui_server_id":2,"caddyui_server_name":"edge"}`))
	states, err = models.ListCertificateLifecycle(conn, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "active" || states[0].Error != "" {
		t.Fatalf("success state = %#v, want active without an error", states)
	}

	entries := hub.Since(0, 2, 20)
	if len(entries) != 4 {
		t.Fatalf("runtime entries = %d, want 4", len(entries))
	}
	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM certificate_lifecycle`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("persisted lifecycle rows = %d, want compact single row", count)
	}
}

func TestHubDropsAccessLogsFromRuntimeRing(t *testing.T) {
	hub := New(nil)
	hub.AcceptLine([]byte(`{"level":"info","logger":"http.log.access.caddyui_access","msg":"handled request","request":{"host":"example.test"}}`))
	if entries := hub.Since(0, 0, 20); len(entries) != 0 {
		t.Fatalf("access events leaked into runtime ring: %#v", entries)
	}
}
