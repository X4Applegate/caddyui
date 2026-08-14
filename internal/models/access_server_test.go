package models_test

import (
	"path/filepath"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestAccessQueriesFilterByActualFleetServer(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	now := time.Now().UTC()
	events := []models.AccessEvent{
		{TS: now, ServerID: 1, ServerName: "edge-a", Host: "shared.test", Path: "/a", Method: "GET", Status: 200, ClientIP: "192.0.2.1", UserAgent: "Firefox", DurationMs: 11, BytesOut: 10},
		{TS: now.Add(time.Second), ServerID: 2, ServerName: "edge-b", Host: "shared.test", Path: "/b", Method: "POST", Status: 503, ClientIP: "192.0.2.2", UserAgent: "Chrome", DurationMs: 22, BytesOut: 20},
		{TS: now.Add(2 * time.Second), ServerID: 2, ServerName: "edge-b", Host: "other.test", Path: "/c", Method: "GET", Status: 200, ClientIP: "192.0.2.3", UserAgent: "curl", DurationMs: 33, BytesOut: 30},
	}
	for _, event := range events {
		if err := models.InsertAccessEvent(conn, event); err != nil {
			t.Fatal(err)
		}
	}

	totals, err := models.AccessTotalsSince(conn, now.Add(-time.Minute), "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if totals.Views != 2 || totals.Visitors != 2 {
		t.Fatalf("server 2 totals = %#v, want 2/2", totals)
	}
	shared, err := models.AccessTotalsSince(conn, now.Add(-time.Minute), "shared.test", 2)
	if err != nil {
		t.Fatal(err)
	}
	if shared.Views != 1 {
		t.Fatalf("server 2 shared.test views = %d, want 1", shared.Views)
	}
	status, err := models.StatusBucketsSince(conn, now.Add(-time.Minute), "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if status.S2xx != 1 || status.S5xx != 1 {
		t.Fatalf("server 2 status = %#v, want one 2xx and one 5xx", status)
	}
	recent, err := models.RecentAccessEvents(conn, 0, 20, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 1 || recent[0].ServerName != "edge-a" || recent[0].Path != "/a" {
		t.Fatalf("server 1 recent = %#v", recent)
	}
	paths, err := models.TopPaths(conn, now.Add(-time.Minute), "shared.test", 20, 1)
	if err != nil || len(paths) != 1 || paths[0].Path != "/a" {
		t.Fatalf("server 1 paths = %#v, err=%v", paths, err)
	}
	clients, err := models.TopClientIPs(conn, now.Add(-time.Minute), "shared.test", 20, 1)
	if err != nil || len(clients) != 1 || clients[0].ClientIP != "192.0.2.1" {
		t.Fatalf("server 1 clients = %#v, err=%v", clients, err)
	}
	responseTime, err := models.ResponseTimeSince(conn, now.Add(-time.Minute), "shared.test", 1)
	if err != nil || responseTime.AvgMs != 11 || responseTime.MaxMs != 11 {
		t.Fatalf("server 1 response time = %#v, err=%v", responseTime, err)
	}
	errors, err := models.TopErrorPaths(conn, now.Add(-time.Minute), "shared.test", 20, 1)
	if err != nil || len(errors) != 0 {
		t.Fatalf("server 1 errors = %#v, err=%v", errors, err)
	}
	browsers, err := models.TopBrowsers(conn, now.Add(-time.Minute), "shared.test", 20, 1)
	if err != nil || len(browsers) != 1 || browsers[0].Browser != "Firefox" {
		t.Fatalf("server 1 browsers = %#v, err=%v", browsers, err)
	}
	bandwidth, err := models.BandwidthSince(conn, now.Add(-time.Minute), "shared.test", 1)
	if err != nil || bandwidth != 10 {
		t.Fatalf("server 1 bandwidth = %d, err=%v", bandwidth, err)
	}
}
