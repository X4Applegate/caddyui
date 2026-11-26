// SPDX-License-Identifier: Apache-2.0

package caddylogs

import (
	"database/sql"
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #164: runtime logs and certificate events attributed through an
// operator-chosen caddyui_source_id.

func newSourceHub(t *testing.T) (*Hub, *sql.DB, int64) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Primary", AdminURL: "http://caddy:2019"}); err != nil {
		t.Fatal(err)
	}
	edgeID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Edge Home", AdminURL: "http://edge:2019", Type: models.CaddyServerTypeExternal, LogSourceID: "edge-home",
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(conn), conn, edgeID
}

func lifecycleFor(t *testing.T, conn *sql.DB, serverID int64) []models.CertificateLifecycleStatus {
	t.Helper()
	states, err := models.ListCertificateLifecycle(conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	return states
}

func TestHubAttributesCertificateEventsBySourceID(t *testing.T) {
	hub, conn, edgeID := newSourceHub(t)

	// Source ID only.
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000000,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"source.example","caddyui_source_id":"edge-home"}`))
	// Both: the custom identifier wins over caddyui_server_id=1.
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000001,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"both.example","caddyui_server_id":1,"caddyui_server_name":"Primary","caddyui_source_id":"edge-home"}`))
	// Numeric only: unchanged.
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000002,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"numeric.example","caddyui_server_id":1,"caddyui_server_name":"Primary"}`))

	edge := lifecycleFor(t, conn, edgeID)
	if len(edge) != 2 {
		t.Fatalf("edge lifecycle rows = %#v, want source.example and both.example", edge)
	}
	for _, st := range edge {
		if st.ServerName != "Edge Home" {
			t.Errorf("%s stored with server name %q, want the fleet entry's name", st.Identifier, st.ServerName)
		}
	}
	primary := lifecycleFor(t, conn, 1)
	if len(primary) != 1 || primary[0].Identifier != "numeric.example" {
		t.Fatalf("primary lifecycle rows = %#v, want only numeric.example", primary)
	}

	// Runtime ring: entries carry the resolved numeric ID, so the per-server
	// Server Logs filter finds them, and the consumed metadata is not echoed.
	entries := hub.Since(0, edgeID, 50)
	if len(entries) != 2 {
		t.Fatalf("ring entries for edge = %d, want 2", len(entries))
	}
	for _, e := range entries {
		if _, ok := e.Fields["caddyui_source_id"]; ok {
			t.Errorf("resolved caddyui_source_id left in fields: %#v", e.Fields)
		}
	}
}

func TestHubUnknownSourceIDCreatesNothing(t *testing.T) {
	hub, conn, _ := newSourceHub(t)
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000000,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"ghost.example","caddyui_source_id":"not-registered"}`))
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000000,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"digits.example","caddyui_source_id":"2"}`))
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000000,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"typed.example","caddyui_source_id":2}`))

	var rows int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM certificate_lifecycle`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("certificate_lifecycle rows = %d, want 0 for unresolvable source IDs", rows)
	}
	if n, _ := models.CountCaddyServers(conn); n != 2 {
		t.Fatalf("servers = %d, want 2", n)
	}
	// The line is still visible, unattributed, with the unmatched identifier
	// kept so an operator can spot the typo.
	entries := hub.Since(0, 0, 50)
	if len(entries) != 3 || entries[0].ServerID != 0 || entries[0].Fields["caddyui_source_id"] != "not-registered" {
		t.Fatalf("ring = %#v, want 3 unattributed entries keeping the unmatched identifier", entries)
	}

	// An unknown identifier alongside a numeric ID falls back to the numeric one.
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000001,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"fallback.example","caddyui_server_id":1,"caddyui_source_id":"not-registered"}`))
	if got := lifecycleFor(t, conn, 1); len(got) != 1 || got[0].Identifier != "fallback.example" {
		t.Fatalf("fallback lifecycle = %#v, want fallback.example on server 1", got)
	}
}

func TestHubKeepsCertificateStateAttributedAfterSourceIDRename(t *testing.T) {
	hub, conn, edgeID := newSourceHub(t)
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000000,"logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"kept.example","caddyui_source_id":"edge-home"}`))

	edge, err := models.GetCaddyServer(conn, edgeID)
	if err != nil {
		t.Fatal(err)
	}
	edge.LogSourceID = "edge-house"
	if err := models.UpdateCaddyServer(conn, edge); err != nil {
		t.Fatal(err)
	}
	if got := lifecycleFor(t, conn, edgeID); len(got) != 1 || got[0].Identifier != "kept.example" {
		t.Fatalf("lifecycle after rename = %#v, want kept.example still on the edge server", got)
	}
	hub.AcceptLine([]byte(`{"level":"info","ts":1700000001,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"new.example","caddyui_source_id":"edge-house"}`))
	if got := lifecycleFor(t, conn, edgeID); len(got) != 2 {
		t.Fatalf("lifecycle rows for edge after rename = %#v, want 2", got)
	}
}
