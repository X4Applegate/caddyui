package server

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.37.0: the per-node ingest target must survive create → get → list →
// update, and the migration must add the column to an existing database.
func TestCaddyServerIngestTargetRoundTrips(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	id, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Richard Prod", AdminURL: "http://10.8.0.3:2019", Type: "managed", IngestTarget: " 10.8.0.1:9019 "})
	if err != nil {
		t.Fatal(err)
	}
	got, err := models.GetCaddyServer(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.IngestTarget != "10.8.0.1:9019" {
		t.Fatalf("GetCaddyServer ingest target = %q, want trimmed 10.8.0.1:9019", got.IngestTarget)
	}
	if got.EffectiveIngestTarget("caddyui:9019") != "10.8.0.1:9019" || got.IngestTargetWarning(got.EffectiveIngestTarget("caddyui:9019")) != "" {
		t.Errorf("configured node should use its own target with no warning: %+v", got)
	}
	list, err := models.ListCaddyServers(conn)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, sr := range list {
		if sr.ID == id {
			found = sr.IngestTarget == "10.8.0.1:9019"
		}
	}
	if !found {
		t.Fatalf("ListCaddyServers lost the ingest target: %+v", list)
	}
	got.IngestTarget = ""
	if err := models.UpdateCaddyServer(conn, got); err != nil {
		t.Fatal(err)
	}
	again, _ := models.GetCaddyServer(conn, id)
	if again.IngestTarget != "" {
		t.Errorf("after clearing, ingest target = %q", again.IngestTarget)
	}
	if w := again.IngestTargetWarning(again.EffectiveIngestTarget("caddyui:9019")); w == "" {
		t.Error("a remote node back on the Docker-name default must be warned about")
	}
}
