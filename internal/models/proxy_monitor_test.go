package models_test

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.28.0 (issue #39): the monitoring columns must survive a full
// create → read → update → read round trip, and must reach the summary
// projection that /api/upstream-health reads.

func newMonitorTestHost() *models.ProxyHost {
	return &models.ProxyHost{
		Domains:       "app.example.com",
		ForwardScheme: "http",
		ForwardHost:   "app",
		ForwardPort:   8080,
		Enabled:       true,
	}
}

func TestProxyHostMonitorFieldsRoundTrip(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	host := newMonitorTestHost()
	host.MonitorMode = "custom"
	host.MonitorPath = "/healthz"
	host.MonitorMethod = "HEAD"
	host.MonitorExpectStatus = 204
	host.MonitorIntervalSec = 300
	host.MonitorTimeoutSec = 12

	id, err := models.CreateProxyHost(conn, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}
	got, err := models.GetProxyHost(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.MonitorMode != "custom" || got.MonitorPath != "/healthz" || got.MonitorMethod != "HEAD" {
		t.Errorf("after create: mode=%q path=%q method=%q", got.MonitorMode, got.MonitorPath, got.MonitorMethod)
	}
	if got.MonitorExpectStatus != 204 || got.MonitorIntervalSec != 300 || got.MonitorTimeoutSec != 12 {
		t.Errorf("after create: expect=%d interval=%d timeout=%d",
			got.MonitorExpectStatus, got.MonitorIntervalSec, got.MonitorTimeoutSec)
	}

	got.MonitorMode = "off"
	got.MonitorExpectStatus = 0
	if err := models.UpdateProxyHost(conn, got); err != nil {
		t.Fatal(err)
	}
	got2, err := models.GetProxyHost(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got2.MonitorMode != "off" {
		t.Errorf("after update: mode = %q, want off", got2.MonitorMode)
	}
	if !got2.MonitoringDisabled() {
		t.Error("MonitoringDisabled() should be true after switching to off")
	}
	if got2.MonitorExpectStatus != 0 {
		t.Errorf("after update: expect = %d, want 0 (cleared)", got2.MonitorExpectStatus)
	}
	// Overrides the user typed earlier survive a switch away from custom, so
	// flipping back does not lose them.
	if got2.MonitorPath != "/healthz" {
		t.Errorf("after update: path = %q, want /healthz preserved", got2.MonitorPath)
	}
}

// A host created without touching the monitoring fields must read back as
// "auto" behaviour — this is what keeps every pre-v2.28.0 row unchanged.
func TestProxyHostMonitorDefaultsToAuto(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	id, err := models.CreateProxyHost(conn, 1, 0, newMonitorTestHost())
	if err != nil {
		t.Fatal(err)
	}
	got, err := models.GetProxyHost(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.MonitoringDisabled() {
		t.Error("a host that never set a monitor mode must not be disabled")
	}
	if models.NormalizeMonitorMode(got.MonitorMode) != "auto" {
		t.Errorf("normalized mode = %q, want auto", models.NormalizeMonitorMode(got.MonitorMode))
	}
}

// /api/upstream-health decides whether to probe from the summary rows, so
// monitor_mode has to be part of that projection. Without it every host
// silently resolves to "auto" and the off switch does nothing.
func TestListProxyHostSummariesIncludesMonitorMode(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	host := newMonitorTestHost()
	host.MonitorMode = "off"
	if _, err := models.CreateProxyHost(conn, 1, 0, host); err != nil {
		t.Fatal(err)
	}

	summaries, err := models.ListProxyHostSummaries(conn, 1, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(summaries))
	}
	if !summaries[0].MonitoringDisabled() {
		t.Errorf("summary MonitorMode = %q; the off switch would be ignored by /api/upstream-health",
			summaries[0].MonitorMode)
	}
}
