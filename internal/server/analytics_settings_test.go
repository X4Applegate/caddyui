package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestLoadAnalyticsConfigSoftStartDefaultsAndOverrides(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	cfg := loadAnalyticsConfig(conn)
	if !cfg.SoftStart {
		t.Fatal("SoftStart = false on an unset configuration, want true")
	}
	if cfg.DialTimeout != 5*time.Second {
		t.Fatalf("DialTimeout = %s, want 5s", cfg.DialTimeout)
	}

	if err := models.SetSetting(conn, settingAnalyticsSoftStart, "0"); err != nil {
		t.Fatal(err)
	}
	if err := models.SetSetting(conn, settingAnalyticsDialTimeoutSec, "12"); err != nil {
		t.Fatal(err)
	}
	cfg = loadAnalyticsConfig(conn)
	if cfg.SoftStart {
		t.Fatal("SoftStart = true after explicit disable, want false")
	}
	if cfg.DialTimeout != 12*time.Second {
		t.Fatalf("DialTimeout = %s, want 12s", cfg.DialTimeout)
	}
}

func TestReconcileAnalyticsAccessLogsAppliesSafeUpgradeDefaults(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var writer map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging/logs/caddyui_access":
			var logger map[string]any
			if err := json.NewDecoder(r.Body).Decode(&logger); err != nil {
				t.Fatalf("decode logger: %v", err)
			}
			writer, _ = logger["writer"].(map[string]any)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{}}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/config/apps/http/servers/srv0/logs":
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer admin.Close()

	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged,
	}); err != nil {
		t.Fatal(err)
	}
	if err := models.SetSetting(conn, settingAnalyticsEnabled, "1"); err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}
	if err := s.ReconcileAnalyticsAccessLogs(); err != nil {
		t.Fatal(err)
	}
	if writer["soft_start"] != true {
		t.Fatalf("soft_start = %#v, want true", writer["soft_start"])
	}
	if writer["dial_timeout"] != "5s" {
		t.Fatalf("dial_timeout = %#v, want 5s", writer["dial_timeout"])
	}
}
