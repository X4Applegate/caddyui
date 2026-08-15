package caddy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnableAccessLogsConfiguresSoftStartAndDialTimeout(t *testing.T) {
	var logger map[string]any
	var serverLogs map[string]any
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
			if err := json.NewDecoder(r.Body).Decode(&serverLogs); err != nil {
				t.Fatalf("decode server logs: %v", err)
			}
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
	if len(serverLogs) != 0 {
		t.Fatalf("server logs = %#v, want empty block preserving default console output", serverLogs)
	}
}

func TestInstallNamedLogFallbackPreservesWholeLoggingConfig(t *testing.T) {
	var installed map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging/logs/"+CertificateLogLoggerName:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"config path not found"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"logging":{"sink":{"writer":{"output":"stderr"}},"logs":{"default":{"level":"DEBUG"}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging":
			if err := json.NewDecoder(r.Body).Decode(&installed); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging/logs/"+CertificateEventLogLoggerName:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer admin.Close()

	client := New(admin.URL, "", "")
	if err := client.EnableCertificateLogs("caddyui:9019", AccessLogOptions{ServerID: 1, ServerName: "edge"}); err != nil {
		t.Fatal(err)
	}
	if installed["sink"] == nil {
		t.Fatalf("logging sink was discarded: %#v", installed)
	}
	logs, _ := installed["logs"].(map[string]any)
	if logs["default"] == nil || logs[CertificateLogLoggerName] == nil {
		t.Fatalf("logging entries were not merged: %#v", logs)
	}
}

func TestInstallNamedLogDoesNotReplaceLoggingWhenFallbackFetchFails(t *testing.T) {
	var replaced bool
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging/logs/"+CertificateLogLoggerName:
			http.Error(w, `{"error":"config path not found"}`, http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			http.Error(w, "temporary failure", http.StatusBadGateway)
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging":
			replaced = true
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer admin.Close()

	client := New(admin.URL, "", "")
	if err := client.EnableCertificateLogs("caddyui:9019", AccessLogOptions{}); err == nil {
		t.Fatal("expected fallback fetch error")
	}
	if replaced {
		t.Fatal("logging subtree was replaced without first reading the existing config")
	}
}

func TestEnableAccessLogsRepairsOwnedDefaultAndPreservesCustomLogger(t *testing.T) {
	var deleted []string
	var serverLogsWrites int
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/config/logging/logs/"+AccessLogLoggerName:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apps":{"http":{"servers":{"legacy":{"logs":{"default_logger_name":"caddyui_access","logger_names":{"host.example":"custom"}}},"custom":{"logs":{"default_logger_name":"console_access"}}}}}}`))
		case r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/config/apps/http/servers/"):
			serverLogsWrites++
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer admin.Close()

	client := New(admin.URL, "", "")
	if err := client.EnableAccessLogs("caddyui:9019", AccessLogOptions{ServerID: 1, ServerName: "edge"}); err != nil {
		t.Fatal(err)
	}
	if serverLogsWrites != 0 {
		t.Fatalf("existing server logging was replaced %d time(s)", serverLogsWrites)
	}
	want := "/config/apps/http/servers/legacy/logs/default_logger_name"
	if len(deleted) != 1 || deleted[0] != want {
		t.Fatalf("deleted paths = %#v, want [%q]", deleted, want)
	}
}

func TestRepairDefaultLoggerOverridesRemovesOnlyOwnedSelections(t *testing.T) {
	var deleted []string
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apps":{"http":{"servers":{"analytics":{"logs":{"default_logger_name":"caddyui_access"}},"fleet":{"logs":{"default_logger_name":"caddyui_file_access"}},"custom":{"logs":{"default_logger_name":"customer_file","logger_names":{"app.example":"app_logger"}}}}}}}`))
		case r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer admin.Close()

	client := New(admin.URL, "", "")
	if err := client.RepairDefaultLoggerOverrides(AccessLogLoggerName, "caddyui_file_access"); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/config/apps/http/servers/analytics/logs/default_logger_name": true,
		"/config/apps/http/servers/fleet/logs/default_logger_name":     true,
	}
	if len(deleted) != len(want) {
		t.Fatalf("deleted paths = %#v", deleted)
	}
	for _, path := range deleted {
		if !want[path] {
			t.Fatalf("unexpected deletion %q; custom logger must be preserved", path)
		}
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
		case "/config/logging/logs/" + CertificateEventLogLoggerName:
			name = CertificateEventLogLoggerName
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
	if certificate["level"] != "INFO" {
		t.Fatalf("certificate level = %#v, want INFO", certificate["level"])
	}
	events := loggers[CertificateEventLogLoggerName]
	eventInclude, _ := events["include"].([]any)
	if len(eventInclude) != 1 || eventInclude[0] != "events" || events["level"] != "DEBUG" {
		t.Fatalf("certificate event logger = %#v", events)
	}
	eventEncoder, _ := events["encoder"].(map[string]any)
	eventFields, _ := eventEncoder["fields"].(map[string]any)
	if eventFields["caddyui_stream"] != "certificates" {
		t.Fatalf("certificate event stream field = %#v", eventFields)
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
