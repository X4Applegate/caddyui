// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// previewFixture is a fake Caddy admin API plus a server row pointing at it.
// lockedDuring records, for each admin request, whether syncMu was held.
type previewFixture struct {
	s            *Server
	id           int64
	loads        []string
	lockedDuring []bool
}

func newPreviewFixture(t *testing.T) *previewFixture {
	t.Helper()
	f := &previewFixture{}
	live := `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		free := f.s.syncMu.TryLock()
		if free {
			f.s.syncMu.Unlock()
		}
		f.lockedDuring = append(f.lockedDuring, !free)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = io.WriteString(w, live)
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			b, _ := io.ReadAll(r.Body)
			f.loads = append(f.loads, string(b))
			live = string(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(admin.Close)
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f.id, err = models.CreateCaddyServer(conn, &models.CaddyServer{Name: "edge", AdminURL: admin.URL})
	if err != nil {
		t.Fatal(err)
	}
	f.s = &Server{DB: conn}
	return f
}

func (f *previewFixture) assertLocked(t *testing.T) {
	t.Helper()
	if len(f.lockedDuring) == 0 {
		t.Fatal("no admin requests were made")
	}
	for i, locked := range f.lockedDuring {
		if !locked {
			t.Errorf("admin request %d ran without syncMu; a concurrent sync could be rolled back", i)
		}
	}
}

// T-0966: the metrics probe reads, loads and restores under syncMu.
func TestPrometheusProbeHoldsSyncLock(t *testing.T) {
	f := newPreviewFixture(t)
	err := f.s.validatePrometheusMetricsServers(prometheusMetricsConfig{
		Enabled: true, PerHost: true, ServerIDs: map[int64]bool{f.id: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.assertLocked(t)
}

// T-0966: the save preview is live, so it runs under syncMu and carries the
// same CrowdSec wrapping the sync adds.
func TestSavePreviewHoldsSyncLockAndKeepsCrowdSec(t *testing.T) {
	f := newPreviewFixture(t)
	for k, v := range map[string]string{
		settingCrowdSecEnabled:   "1",
		settingCrowdSecAPIKey:    "test-key",
		settingCrowdSecServerIDs: strconv.FormatInt(f.id, 10),
	} {
		if err := models.SetSetting(f.s.DB, k, v); err != nil {
			t.Fatal(err)
		}
	}
	proxies := []models.ProxyHost{{Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true}}
	if msg := f.s.validateProposedConfig(f.id, proxies, nil, nil, nil); msg != "" {
		t.Fatal(msg)
	}
	f.assertLocked(t)
	if len(f.loads) != 1 {
		t.Fatalf("loads = %d, want 1", len(f.loads))
	}
	if !strings.Contains(f.loads[0], `"handler":"crowdsec"`) {
		t.Fatalf("preview config has no crowdsec handler; it would switch CrowdSec off until the next sync:\n%s", f.loads[0])
	}
}

// T-0966: while a post-apply hold is set the sync is skipped, so a live
// preview would never be replaced. The preview must not load anything.
func TestSavePreviewSkippedWhileHeld(t *testing.T) {
	f := newPreviewFixture(t)
	f.s.setSyncHold(syncHold{ServerID: f.id, ServerName: "edge", At: time.Now()})
	if msg := f.s.validateProposedConfig(f.id, nil, nil, nil, nil); msg != "" {
		t.Fatal(msg)
	}
	if len(f.loads) != 0 {
		t.Fatalf("preview loaded %d configs into a held server", len(f.loads))
	}
}
