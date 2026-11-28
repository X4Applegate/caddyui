// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestApplyPrometheusMetricsPreservesUnmanagedGlobalConfig(t *testing.T) {
	want := map[string]any{
		"apps": map[string]any{"http": map[string]any{
			"metrics": map[string]any{
				"per_host":               true,
				"observe_catchall_hosts": true,
				"otlp":                   true,
			},
			"servers": map[string]any{"srv0": map[string]any{}},
		}},
	}
	got, err := deepCopyMap(want)
	if err != nil {
		t.Fatal(err)
	}
	applyPrometheusMetrics(got, prometheusMetricsConfig{
		Enabled: true, PerHost: false, ServerIDs: map[int64]bool{2: true},
	}, 1)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unmanaged metrics changed:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestApplyPrometheusMetricsManagesDetailedFieldsAndPreservesOTLP(t *testing.T) {
	cfg := map[string]any{"apps": map[string]any{"http": map[string]any{
		"metrics": map[string]any{"otlp": true},
	}}}
	managed := prometheusMetricsConfig{
		Enabled: true, PerHost: true, ObserveCatchAllHost: true,
		ServerIDs: map[int64]bool{1: true},
	}
	applyPrometheusMetrics(cfg, managed, 1)
	metrics := cfg["apps"].(map[string]any)["http"].(map[string]any)["metrics"].(map[string]any)
	for _, key := range []string{"per_host", "observe_catchall_hosts", "otlp"} {
		if metrics[key] != true {
			t.Fatalf("metrics[%q] = %#v, want true", key, metrics[key])
		}
	}

	managed.Enabled = false
	applyPrometheusMetrics(cfg, managed, 1)
	metrics = cfg["apps"].(map[string]any)["http"].(map[string]any)["metrics"].(map[string]any)
	if !reflect.DeepEqual(metrics, map[string]any{"otlp": true}) {
		t.Fatalf("disable removed externally-owned metrics fields: %#v", metrics)
	}
}

func TestApplyPrometheusMetricsDisabledRemovesEmptyObject(t *testing.T) {
	cfg := map[string]any{"apps": map[string]any{"http": map[string]any{
		"metrics": map[string]any{"per_host": true, "observe_catchall_hosts": true},
	}}}
	applyPrometheusMetrics(cfg, prometheusMetricsConfig{
		ServerIDs: map[int64]bool{1: true},
	}, 1)
	httpApp := cfg["apps"].(map[string]any)["http"].(map[string]any)
	if _, ok := httpApp["metrics"]; ok {
		t.Fatalf("empty metrics object remained after disable: %#v", httpApp["metrics"])
	}
}

func TestPrometheusMetricsFormValidation(t *testing.T) {
	request := func(values url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(values.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		return r
	}

	if _, err := prometheusMetricsConfigFromForm(request(url.Values{
		"prometheus_metrics_enabled":                {"1"},
		"prometheus_metrics_observe_catchall_hosts": {"1"},
		"prometheus_metrics_server_ids":             {"1"},
	})); err == nil || !strings.Contains(err.Error(), "requires per-host") {
		t.Fatalf("catch-all without per-host error = %v", err)
	}
	if _, err := prometheusMetricsConfigFromForm(request(url.Values{
		"prometheus_metrics_enabled":  {"1"},
		"prometheus_metrics_per_host": {"1"},
	})); err == nil || !strings.Contains(err.Error(), "select at least one") {
		t.Fatalf("enabled without servers error = %v", err)
	}
	got, err := prometheusMetricsConfigFromForm(request(url.Values{
		"prometheus_metrics_enabled":                {"0", "1"},
		"prometheus_metrics_per_host":               {"0", "1"},
		"prometheus_metrics_observe_catchall_hosts": {"0", "1"},
		"prometheus_metrics_server_ids":             {"7"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || !got.PerHost || !got.ObserveCatchAllHost || !got.ServerIDs[7] {
		t.Fatalf("parsed metrics config = %#v", got)
	}
}

// T-0965: the metrics check provisions the proposed config through
// ProbeLoad, so Caddy checks its own schema, and then always loads the
// original config back. Before T-0965 it posted /load?validate_only=true,
// which Caddy ignores, so metrics stayed live before the settings were saved.
func TestValidatePrometheusMetricsServersUsesCaddySchema(t *testing.T) {
	original := map[string]any{
		"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"srv0": map[string]any{}}}},
	}
	live := original
	var loads []map[string]any
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_ = json.NewEncoder(w).Encode(live)
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			if r.URL.Query().Has("validate_only") {
				t.Errorf("/load sent with validate_only; Caddy ignores it")
			}
			var cfg map[string]any
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			loads = append(loads, cfg)
			live = cfg
		default:
			http.NotFound(w, r)
		}
	}))
	defer admin.Close()

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	id, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "edge", AdminURL: admin.URL})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn}
	err = s.validatePrometheusMetricsServers(prometheusMetricsConfig{
		Enabled: true, PerHost: true, ObserveCatchAllHost: true,
		ServerIDs: map[int64]bool{id: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(loads) != 2 {
		t.Fatalf("loads = %d, want 2 (probe, then restore)", len(loads))
	}
	metrics := loads[0]["apps"].(map[string]any)["http"].(map[string]any)["metrics"].(map[string]any)
	if metrics["per_host"] != true || metrics["observe_catchall_hosts"] != true {
		t.Fatalf("probed metrics = %#v", metrics)
	}
	if !configValuesEqual(live, original) {
		t.Fatalf("live config after the check = %#v, want the original %#v", live, original)
	}
}

func TestPrometheusScrapeTargetUsesProtectedAdminEndpoint(t *testing.T) {
	if got := prometheusScrapeTarget("http://10.0.0.2:2019/"); got != "http://10.0.0.2:2019/metrics" {
		t.Fatalf("scrape target = %q", got)
	}
	if got := prometheusScrapeTarget("unix:///run/caddy/admin.sock"); got != "unix:///run/caddy/admin.sock (/metrics)" {
		t.Fatalf("unix scrape target = %q", got)
	}
}
