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
		ServerID:    9,
		ServerName:  "edge-west",
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
	encoder, ok := logger["encoder"].(map[string]any)
	if !ok || encoder["format"] != "append" {
		t.Fatalf("encoder = %#v, want append", logger["encoder"])
	}
	fields, _ := encoder["fields"].(map[string]any)
	if fields["caddyui_server_id"] != float64(9) || fields["caddyui_server_name"] != "edge-west" {
		t.Fatalf("source fields = %#v", fields)
	}
}

func TestRuntimeAndCertificateLoggersAreAdditiveAndScoped(t *testing.T) {
	loggers := map[string]map[string]any{}
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := ""
		switch r.URL.Path {
		case "/config/logging/logs/" + RuntimeLogLoggerName:
			name = RuntimeLogLoggerName
		case "/config/logging/logs/" + CertificateLogLoggerName:
			name = CertificateLogLoggerName
		}
		if r.Method != http.MethodPost || name == "" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		var logger map[string]any
		if err := json.NewDecoder(r.Body).Decode(&logger); err != nil {
			t.Fatal(err)
		}
		loggers[name] = logger
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()

	client := New(admin.URL, "", "")
	opts := AccessLogOptions{SoftStart: true, DialTimeout: time.Second, ServerID: 3, ServerName: "edge"}
	if err := client.EnableCertificateLogs("caddyui:9019", opts); err != nil {
		t.Fatal(err)
	}
	if err := client.EnableRuntimeLogs("caddyui:9019", "debug", opts); err != nil {
		t.Fatal(err)
	}
	certificate := loggers[CertificateLogLoggerName]
	include, _ := certificate["include"].([]any)
	if len(include) != 1 || include[0] != "tls" {
		t.Fatalf("certificate include = %#v", certificate["include"])
	}
	runtime := loggers[RuntimeLogLoggerName]
	if runtime["level"] != "DEBUG" {
		t.Fatalf("runtime level = %#v, want DEBUG", runtime["level"])
	}
	exclude, _ := runtime["exclude"].([]any)
	if len(exclude) != 2 || exclude[0] != "http.log.access" || exclude[1] != "tls" {
		t.Fatalf("runtime excludes = %#v", runtime["exclude"])
	}
}
