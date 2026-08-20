package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// hostportOf extracts "127.0.0.1:port" from an httptest server URL so it can
// be used as a ProxyHost domain. probeApp builds its own scheme, so the
// domain must not carry one.
func hostportOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server URL %q: %v", rawURL, err)
	}
	return u.Host
}

// v2.28.0 (issue #39): per-host control over CaddyUI's own monitoring probes.

func TestMonitorSettingsDefaultsMatchPreIssue39Behaviour(t *testing.T) {
	for _, mode := range []string{"", "auto", "AUTO", "nonsense"} {
		p := models.ProxyHost{MonitorMode: mode, MonitorPath: "/ignored", MonitorMethod: "HEAD", MonitorIntervalSec: 900}
		path, method, expect, interval, timeout := p.MonitorSettings(60*time.Second, 5*time.Second)
		if path != "/" || method != "GET" || expect != 0 {
			t.Errorf("mode %q: got %s %s expect=%d, want GET / expect=0", mode, method, path, expect)
		}
		if interval != 60*time.Second || timeout != 5*time.Second {
			t.Errorf("mode %q: got interval=%v timeout=%v, want 60s/5s", mode, interval, timeout)
		}
	}
}

func TestMonitorSettingsCustomOverrides(t *testing.T) {
	p := models.ProxyHost{
		MonitorMode:         "custom",
		MonitorPath:         "healthz", // no leading slash on purpose
		MonitorMethod:       "head",
		MonitorExpectStatus: 204,
		MonitorIntervalSec:  300,
		MonitorTimeoutSec:   12,
	}
	path, method, expect, interval, timeout := p.MonitorSettings(60*time.Second, 5*time.Second)
	if path != "/healthz" {
		t.Errorf("path = %q, want /healthz (leading slash added)", path)
	}
	if method != "HEAD" {
		t.Errorf("method = %q, want HEAD", method)
	}
	if expect != 204 || interval != 300*time.Second || timeout != 12*time.Second {
		t.Errorf("expect=%d interval=%v timeout=%v, want 204/300s/12s", expect, interval, timeout)
	}
}

func TestMonitorSettingsCustomFallsBackPerField(t *testing.T) {
	// A custom-mode host that overrides only the path keeps every other default.
	p := models.ProxyHost{MonitorMode: "custom", MonitorPath: "/up"}
	path, method, expect, interval, timeout := p.MonitorSettings(60*time.Second, 5*time.Second)
	if path != "/up" || method != "GET" || expect != 0 || interval != 60*time.Second || timeout != 5*time.Second {
		t.Errorf("got %s %s expect=%d interval=%v timeout=%v; only the path should change",
			method, path, expect, interval, timeout)
	}
}

func TestMonitoringDisabledOnlyForOff(t *testing.T) {
	for mode, want := range map[string]bool{"": false, "auto": false, "custom": false, "off": true, "OFF": true, " off ": true} {
		if got := (&models.ProxyHost{MonitorMode: mode}).MonitoringDisabled(); got != want {
			t.Errorf("MonitoringDisabled(%q) = %v, want %v", mode, got, want)
		}
	}
}

// probeApp must emit no outbound request at all when monitoring is off. The
// whole point of the off switch is to stop traffic toward a backend that is
// deliberately unreachable, not merely to hide the dot.
func TestProbeAppMakesNoRequestWhenMonitoringOff(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &Server{appHealth: map[int64]appHealthEntry{}}
	host := models.ProxyHost{
		ID:          1,
		Enabled:     true,
		Domains:     hostportOf(t, srv.URL),
		SSLEnabled:  false,
		MonitorMode: "off",
	}
	entry := s.probeApp(context.Background(), host)
	if entry.Status != "off" {
		t.Errorf("status = %q, want off", entry.Status)
	}
	if n := atomic.LoadInt64(&hits); n != 0 {
		t.Errorf("probe made %d request(s) with monitoring off, want 0", n)
	}
}

// A custom probe must actually use the configured path and method.
func TestProbeAppUsesCustomPathAndMethod(t *testing.T) {
	gotPath := make(chan string, 4)
	gotMethod := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath <- r.URL.Path
		gotMethod <- r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := &Server{appHealth: map[int64]appHealthEntry{}}
	host := models.ProxyHost{
		ID:                  1,
		Enabled:             true,
		Domains:             hostportOf(t, srv.URL),
		SSLEnabled:          false,
		MonitorMode:         "custom",
		MonitorPath:         "/healthz",
		MonitorMethod:       "HEAD",
		MonitorExpectStatus: 204,
	}
	entry := s.probeApp(context.Background(), host)
	if p := <-gotPath; p != "/healthz" {
		t.Errorf("probed path = %q, want /healthz", p)
	}
	if m := <-gotMethod; m != "HEAD" {
		t.Errorf("probed method = %q, want HEAD", m)
	}
	// 204 is neither 2xx-with-body nor an error; without the expect-status
	// override the default classifier calls it ok too, so assert the code
	// round-tripped and the verdict is ok.
	if entry.Status != "ok" || entry.Code != 204 {
		t.Errorf("entry = %+v, want ok/204", entry)
	}
}

// An unexpected status under an explicit expectation is unambiguously down.
func TestProbeAppExpectStatusMismatchIsDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200, but the host demands 204
	}))
	defer srv.Close()

	s := &Server{appHealth: map[int64]appHealthEntry{}}
	host := models.ProxyHost{
		ID:                  1,
		Enabled:             true,
		Domains:             hostportOf(t, srv.URL),
		SSLEnabled:          false,
		MonitorMode:         "custom",
		MonitorExpectStatus: 204,
	}
	entry := s.probeApp(context.Background(), host)
	if entry.Status != "down" {
		t.Errorf("status = %q, want down (200 received, 204 expected)", entry.Status)
	}
	if entry.Code != 200 {
		t.Errorf("code = %d, want 200", entry.Code)
	}
}

// appProbeDue paces hosts that asked for a longer interval, and never delays
// hosts on the default.
func TestAppProbeDueRespectsCustomInterval(t *testing.T) {
	s := &Server{appHealth: map[int64]appHealthEntry{}}

	def := models.ProxyHost{ID: 1}
	if !s.appProbeDue(def) {
		t.Error("default-interval host should always be due")
	}

	slow := models.ProxyHost{ID: 2, MonitorMode: "custom", MonitorIntervalSec: 600}
	if !s.appProbeDue(slow) {
		t.Error("never-probed host should be due")
	}

	s.appHealth[2] = appHealthEntry{Status: "ok", CheckedAt: time.Now()}
	if s.appProbeDue(slow) {
		t.Error("host probed just now with a 600s interval should not be due")
	}

	s.appHealth[2] = appHealthEntry{Status: "ok", CheckedAt: time.Now().Add(-11 * time.Minute)}
	if !s.appProbeDue(slow) {
		t.Error("host last probed 11m ago with a 600s interval should be due")
	}
}
