package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.35.0 (issue #39 follow-up): the "Public" health checker — the persisted,
// 24h-history probe behind /proxy-hosts/{id}/health and the left-most dot on
// the proxy hosts list — was a *third* CaddyUI-run probe alongside the App and
// Port dots v2.28.0 made configurable. It was never wired to MonitorMode: a
// host set to "Off" (promised to stop "all outbound probes for this host")
// kept getting hit here every 5 minutes regardless, and a host in "Custom"
// mode with a non-default path or expected status still showed this dot red
// because the check always requested "/" with the default classification.
// These tests pin the fix.

// newPublicHealthTestServer builds a Server plus a registered CaddyServer
// (serverID 1). checkAllProxyHosts walks models.ListCaddyServers before it
// ever looks at a host, so a test that skips this and creates hosts under a
// bare serverID with no matching caddy_servers row silently checks nothing —
// the loop body never runs. That previously hung a test outright: it blocked
// forever reading from an httptest handler's channel that was never fed
// because checkAllProxyHosts had zero servers to iterate.
func newPublicHealthTestServer(t *testing.T) *Server {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: "http://primary:2019", Type: models.CaddyServerTypeManaged,
	}); err != nil {
		t.Fatal(err)
	}
	return &Server{DB: conn}
}

func hostportOfURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse test server URL %q: %v", raw, err)
	}
	return u.Host
}

func TestCheckAllProxyHostsSkipsMonitoringOff(t *testing.T) {
	s := newPublicHealthTestServer(t)

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := &models.ProxyHost{
		Domains: hostportOfURL(t, srv.URL), ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: false, MonitorMode: "off",
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}

	s.checkAllProxyHosts()

	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("probe made %d request(s) to a monitoring-off host, want 0", n)
	}
	history, err := models.GetProxyHealthHistory(s.DB, id, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 0 {
		t.Errorf("monitoring-off host has %d persisted health row(s), want 0", len(history))
	}
}

func TestCheckAllProxyHostsUsesCustomPathMethodAndExpectStatus(t *testing.T) {
	s := newPublicHealthTestServer(t)

	gotPath := make(chan string, 1)
	gotMethod := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath <- r.URL.Path
		gotMethod <- r.Method
		w.WriteHeader(http.StatusNoContent) // 204: "up" only because expectStatus says so
	}))
	defer srv.Close()

	host := &models.ProxyHost{
		Domains: hostportOfURL(t, srv.URL), ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: false,
		MonitorMode: "custom", MonitorPath: "/healthz", MonitorMethod: "HEAD", MonitorExpectStatus: 204,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}

	s.checkAllProxyHosts()

	if p := <-gotPath; p != "/healthz" {
		t.Errorf("probed path = %q, want /healthz", p)
	}
	if m := <-gotMethod; m != "HEAD" {
		t.Errorf("probed method = %q, want HEAD", m)
	}
	history, err := models.GetProxyHealthHistory(s.DB, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("history rows = %d, want 1", len(history))
	}
	if !history[0].OK {
		t.Error("204 with expectStatus=204 should record OK, got not-OK")
	}
	if history[0].StatusCode != 204 {
		t.Errorf("recorded status = %d, want 204", history[0].StatusCode)
	}
}

// v2.36.0 (issue #59): the same POST-only scenario for the persisted Public
// check. The stored method is lowercase on purpose — rows written by hand or
// by an older build must still resolve, since only the form parser canonicalises.
func TestCheckAllProxyHostsReachesPostOnlyRouteWithPost(t *testing.T) {
	s := newPublicHealthTestServer(t)

	gotMethod := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod <- r.Method
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := &models.ProxyHost{
		Domains: hostportOfURL(t, srv.URL), ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: false,
		MonitorMode: "custom", MonitorPath: "/api/ping", MonitorMethod: "post",
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}

	s.checkAllProxyHosts()

	if m := <-gotMethod; m != "POST" {
		t.Errorf("probed method = %q, want POST", m)
	}
	history, err := models.GetProxyHealthHistory(s.DB, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || !history[0].OK || history[0].StatusCode != 200 {
		t.Fatalf("history = %+v, want one OK row with HTTP 200 — the POST probe must reach the upstream", history)
	}
}

// The pre-existing failure mode: a custom health path answering something
// other than the default-accepted codes (2xx/3xx/401/403) must show as down
// when no expectStatus is set, matching the App-dot semantics exactly.
func TestCheckAllProxyHostsWithoutExpectStatusUsesDefaultHeuristic(t *testing.T) {
	s := newPublicHealthTestServer(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // 418: outside the default-accepted set
	}))
	defer srv.Close()

	host := &models.ProxyHost{
		Domains: hostportOfURL(t, srv.URL), ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: false,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}

	s.checkAllProxyHosts()

	history, err := models.GetProxyHealthHistory(s.DB, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatalf("history rows = %d, want 1", len(history))
	}
	if history[0].OK {
		t.Error("418 with no expectStatus should record not-OK")
	}
}

func TestCheckAllProxyHostsStillChecksAutomaticHosts(t *testing.T) {
	s := newPublicHealthTestServer(t)

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := &models.ProxyHost{
		Domains: hostportOfURL(t, srv.URL), ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true, SSLEnabled: false, // MonitorMode left unset — must behave as before this fix
	}
	if _, err := models.CreateProxyHost(s.DB, 1, 0, host); err != nil {
		t.Fatal(err)
	}

	s.checkAllProxyHosts()

	if n := atomic.LoadInt64(&hits); n != 1 {
		t.Errorf("automatic-mode host got %d probe(s), want 1 — the flag is opt-in and must not change default behaviour", n)
	}
}

func TestPublicHealthDueRespectsCustomInterval(t *testing.T) {
	s := newPublicHealthTestServer(t)

	host := &models.ProxyHost{
		Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 80, Enabled: true,
	}
	id, err := models.CreateProxyHost(s.DB, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}

	// No history yet: always due, regardless of interval.
	if !s.publicHealthDue(id, 30*time.Minute) {
		t.Error("never-checked host should be due")
	}
	// At or below the native 5-minute tick: always due (can't run faster than
	// the ticker itself).
	if !s.publicHealthDue(id, publicHealthCheckerInterval) {
		t.Error("a host at the native interval should always be due")
	}

	if err := models.InsertProxyHealth(s.DB, id, true, 200, 10, ""); err != nil {
		t.Fatal(err)
	}
	if s.publicHealthDue(id, 30*time.Minute) {
		t.Error("a host just checked with a 30-minute interval should not be due yet")
	}
}

func TestPublicHealthCadenceLabel(t *testing.T) {
	cases := []struct {
		name string
		h    models.ProxyHost
		want string
	}{
		{"auto", models.ProxyHost{MonitorMode: "auto"}, "every 5 min"},
		{"blank", models.ProxyHost{}, "every 5 min"},
		{"off", models.ProxyHost{MonitorMode: "off"}, "every 5 min"},
		{"custom no interval", models.ProxyHost{MonitorMode: "custom"}, "every 5 min"},
		{"custom below native tick", models.ProxyHost{MonitorMode: "custom", MonitorIntervalSec: 60}, "every 5 min"},
		{"custom 30 min", models.ProxyHost{MonitorMode: "custom", MonitorIntervalSec: 1800}, "roughly every 30 min (custom)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := publicHealthCadenceLabel(c.h); got != c.want {
				t.Errorf("publicHealthCadenceLabel(%+v) = %q, want %q", c.h, got, c.want)
			}
		})
	}
}
