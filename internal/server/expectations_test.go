package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.38.0: expectations are real requests, judged on status, Location and latency.
func TestEvaluateExpectation(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(200)
		case "/redir":
			w.Header().Set("Location", "https://example.test/x")
			w.WriteHeader(308)
		case "/slow":
			time.Sleep(80 * time.Millisecond)
			w.WriteHeader(200)
		case "/post-only":
			if r.Method != http.MethodPost {
				w.WriteHeader(405)
				return
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer site.Close()
	host := hostportOf(t, site.URL)

	for _, tc := range []struct {
		name string
		e    models.HostExpectation
		ok   bool
		err  string
	}{
		{"any 2xx", models.HostExpectation{Scheme: "http", Path: "/ok"}, true, ""},
		{"exact status mismatch", models.HostExpectation{Scheme: "http", Path: "/ok", ExpectStatus: 204}, false, "HTTP 200, expected 204"},
		{"redirect with location prefix", models.HostExpectation{Scheme: "http", Path: "/redir", ExpectStatus: 308, ExpectLocation: "https://example.test/"}, true, ""},
		{"redirect to the wrong place", models.HostExpectation{Scheme: "http", Path: "/redir", ExpectStatus: 308, ExpectLocation: "https://other/"}, false, "does not start with"},
		{"too slow", models.HostExpectation{Scheme: "http", Path: "/slow", MaxLatencyMS: 10}, false, "limit 10 ms"},
		{"method honoured", models.HostExpectation{Scheme: "http", Method: "POST", Path: "/post-only", ExpectStatus: 200}, true, ""},
		{"method matters", models.HostExpectation{Scheme: "http", Method: "GET", Path: "/post-only"}, false, "HTTP 405"},
		{"404 is a failure by default", models.HostExpectation{Scheme: "http", Path: "/missing"}, false, "HTTP 404"},
		{"connection refused is a failure", models.HostExpectation{Scheme: "http", Path: "/"}, false, "connection refused"},
	} {
		h := host
		if tc.name == "connection refused is a failure" {
			h = "127.0.0.1:1"
		}
		r := evaluateExpectation(t.Context(), h, tc.e)
		if r.OK != tc.ok || (tc.err != "" && !strings.Contains(r.Error, tc.err)) {
			t.Errorf("%s: ok=%v err=%q (status %d), want ok=%v err~%q", tc.name, r.OK, r.Error, r.Status, tc.ok, tc.err)
		}
		if !strings.Contains(r.Summary(), tc.e.Normalized().Path) {
			t.Errorf("%s: Summary %q should name the path", tc.name, r.Summary())
		}
	}
}

// A failed post-apply check must load the previous config back into Caddy,
// record a hold, and keep the results; report-only mode must do neither;
// a passing host must be left alone.
func TestVerifyAppliedConfigRollsBackAndHolds(t *testing.T) {
	var mu sync.Mutex
	var loads []map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			loads = append(loads, body)
			mu.Unlock()
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{}"))
	}))
	defer admin.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer broken.Close()
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer healthy.Close()

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn}
	host := &models.ProxyHost{
		Domains: hostportOf(t, broken.URL), ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true, SSLEnabled: false,
		Expectations: `[{"label":"home","method":"GET","scheme":"http","path":"/","expect_status":200}]`,
	}
	id, err := models.CreateProxyHost(conn, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}
	previous := map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{"listen": []any{":443"}}}}}}
	client := newCaddyClient(admin.URL, "", "")

	err = s.verifyAppliedConfig(1, "Primary", client, previous)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected a rolled-back error, got %v", err)
	}
	mu.Lock()
	n := len(loads)
	mu.Unlock()
	if n != 1 || !reflect.DeepEqual(loads[0], previous) {
		t.Fatalf("Caddy should have been sent exactly the previous config once, got %d load(s): %+v", n, loads)
	}
	hold := s.syncHoldFor(1)
	if hold == nil || !hold.RolledBack || len(hold.Failed) != 1 || !strings.Contains(hold.Failed[0], "home") {
		t.Fatalf("hold = %+v, want a rolled-back hold naming the failed check", hold)
	}
	if got := s.expectationResultsFor(id); len(got) != 1 || got[0].OK || got[0].Status != 503 {
		t.Errorf("results for host = %+v, want one failed 503 result", got)
	}
	if holds := s.activeSyncHolds([]models.CaddyServer{{ID: 1, Name: "Primary"}, {ID: 2, Name: "Other"}}); len(holds) != 1 || holds[0].ServerID != 1 {
		t.Errorf("activeSyncHolds = %+v, want only server 1", holds)
	}

	// Report-only: nothing is rolled back and no hold is recorded.
	s.clearSyncHold(1)
	if err := models.SetSetting(conn, settingExpectationsAutoRollback, "0"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	loads = nil
	mu.Unlock()
	if err := s.verifyAppliedConfig(1, "Primary", client, previous); err != nil {
		t.Fatalf("report-only mode must not return an error, got %v", err)
	}
	mu.Lock()
	n = len(loads)
	mu.Unlock()
	if n != 0 || s.syncHoldFor(1) != nil {
		t.Fatalf("report-only mode must not roll back (loads=%d) or hold (%+v)", n, s.syncHoldFor(1))
	}

	// A passing host: no rollback either way.
	if err := models.SetSetting(conn, settingExpectationsAutoRollback, "1"); err != nil {
		t.Fatal(err)
	}
	got, _ := models.GetProxyHost(conn, id)
	got.Domains = hostportOf(t, healthy.URL)
	if err := models.UpdateProxyHost(conn, got); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyAppliedConfig(1, "Primary", client, previous); err != nil {
		t.Fatalf("passing checks must not error, got %v", err)
	}
	mu.Lock()
	n = len(loads)
	mu.Unlock()
	if n != 0 || s.syncHoldFor(1) != nil {
		t.Errorf("passing checks must not roll back or hold")
	}
	if got := s.expectationResultsFor(id); len(got) != 1 || !got[0].OK {
		t.Errorf("results after a passing run = %+v", got)
	}
}
