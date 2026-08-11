package caddy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnableAccessLogsConfiguresSoftStartAndDialTimeout(t *testing.T) {
	var logger map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging/logs/"+AccessLogLoggerName:
			if err := json.NewDecoder(r.Body).Decode(&logger); err != nil {
				t.Fatalf("decode logger: %v", err)
			}
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

	client := New(admin.URL, "", "")
	if err := client.EnableAccessLogs("caddyui:9019", AccessLogOptions{
		SoftStart:   true,
		DialTimeout: 5 * time.Second,
	}); err != nil {
		t.Fatal(err)
	}

	writer, ok := logger["writer"].(map[string]any)
	if !ok {
		t.Fatalf("writer = %#v", logger["writer"])
	}
	if writer["output"] != "net" || writer["address"] != "caddyui:9019" {
		t.Fatalf("writer target = %#v", writer)
	}
	if writer["soft_start"] != true {
		t.Fatalf("soft_start = %#v, want true", writer["soft_start"])
	}
	if writer["dial_timeout"] != "5s" {
		t.Fatalf("dial_timeout = %#v, want 5s", writer["dial_timeout"])
	}
}
