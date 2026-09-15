package models_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func seedDrilldownEvents(t *testing.T) (*sql.DB, time.Time) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	now := time.Now()
	ev := func(host, path, method string, status int, ip, ua string) {
		if err := models.InsertAccessEvent(conn, models.AccessEvent{
			TS: now, Host: host, Path: path, Method: method,
			Status: status, ClientIP: ip, UserAgent: ua,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// host a.example.com
	ev("a.example.com", "/login", "GET", 200, "1.1.1.1", "curl/8")
	ev("a.example.com", "/login", "GET", 200, "1.1.1.1", "curl/8")
	ev("a.example.com", "/admin", "GET", 404, "1.1.1.1", "curl/8")
	ev("a.example.com", "/api", "POST", 500, "1.1.1.1", "curl/8")
	ev("a.example.com", "/login", "GET", 200, "2.2.2.2", "Mozilla/5.0")
	ev("a.example.com", "/wp-login.php", "GET", 404, "2.2.2.2", "Mozilla/5.0")
	ev("a.example.com", "/wp-login.php", "GET", 404, "2.2.2.2", "Mozilla/5.0")
	// different host — must never leak into a.example.com scoping
	ev("b.example.com", "/login", "GET", 200, "1.1.1.1", "curl/8")
	return conn, now.Add(-time.Hour)
}

func TestVisitorDrilldownScopedToHostAndIP(t *testing.T) {
	conn, since := seedDrilldownEvents(t)

	views, err := models.VisitorTotals(conn, since, "a.example.com", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if views != 4 {
		t.Fatalf("VisitorTotals = %d, want 4 (the b.example.com hit must be excluded)", views)
	}

	paths, err := models.VisitorPaths(conn, since, "a.example.com", "1.1.1.1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 || paths[0].Path != "/login" || paths[0].Views != 2 {
		t.Fatalf("VisitorPaths top = %#v, want /login x2 first", paths)
	}

	status, err := models.VisitorStatusBuckets(conn, since, "a.example.com", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if status.S2xx != 2 || status.S4xx != 1 || status.S5xx != 1 {
		t.Fatalf("VisitorStatusBuckets = %+v, want 2xx=2 4xx=1 5xx=1", status)
	}

	errs, err := models.VisitorErrorDetails(conn, since, "a.example.com", "1.1.1.1", 10)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]string{}
	for _, e := range errs {
		got[e.Status] = e.Path
	}
	if got[404] != "/admin" || got[500] != "/api" {
		t.Fatalf("VisitorErrorDetails = %#v, want 404 /admin and 500 /api", errs)
	}

	agents, err := models.VisitorUserAgents(conn, since, "a.example.com", "1.1.1.1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].UserAgent != "curl/8" || agents[0].Count != 4 {
		t.Fatalf("VisitorUserAgents = %#v, want curl/8 x4", agents)
	}
}

func TestPathDrilldownVisitorsAndTotals(t *testing.T) {
	conn, since := seedDrilldownEvents(t)

	totals, err := models.PathTotals(conn, since, "a.example.com", "/login")
	if err != nil {
		t.Fatal(err)
	}
	if totals.Views != 3 || totals.Visitors != 2 {
		t.Fatalf("PathTotals = %+v, want views=3 visitors=2", totals)
	}

	clients, err := models.PathClients(conn, since, "a.example.com", "/login", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 || clients[0].ClientIP != "1.1.1.1" || clients[0].Views != 2 {
		t.Fatalf("PathClients = %#v, want 1.1.1.1 x2 first, two IPs", clients)
	}

	status, err := models.PathStatusBuckets(conn, since, "a.example.com", "/login")
	if err != nil {
		t.Fatal(err)
	}
	if status.S2xx != 3 || status.S4xx != 0 {
		t.Fatalf("PathStatusBuckets = %+v, want 2xx=3", status)
	}
}

func TestTopErrorDetailsGroupsByStatusAndPath(t *testing.T) {
	conn, since := seedDrilldownEvents(t)

	details, err := models.TopErrorDetails(conn, since, "a.example.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(details) == 0 {
		t.Fatal("TopErrorDetails returned nothing")
	}
	// Most frequent error is 404 /wp-login.php (x2).
	if details[0].Status != 404 || details[0].Path != "/wp-login.php" || details[0].Count != 2 {
		t.Fatalf("TopErrorDetails top = %#v, want 404 /wp-login.php x2", details[0])
	}
	// Only 4xx/5xx are included — no 200s.
	for _, d := range details {
		if d.Status < 400 {
			t.Fatalf("TopErrorDetails included non-error status %d", d.Status)
		}
	}
}
