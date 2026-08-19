package web

import (
	"strings"
	"testing"
)

func TestToastAutoConversionRequiresExplicitMarker(t *testing.T) {
	appJS, err := FS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	js := string(appJS)
	if !strings.Contains(js, "main.querySelectorAll('[data-toast]')") {
		t.Fatal("toast auto-conversion must select explicit data-toast markers")
	}
	for _, broadSelector := range []string{
		"querySelectorAll('.bg-brand-50.border-brand-200')",
		"querySelectorAll('.bg-red-50.border-red-200')",
		"querySelectorAll('.bg-amber-50.border-amber-200')",
	} {
		if strings.Contains(js, broadSelector) {
			t.Fatalf("toast auto-conversion still uses presentation selector %q", broadSelector)
		}
	}
}

func TestSettingsGuidanceStaysInline(t *testing.T) {
	settingsHTML, err := FS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings.html: %v", err)
	}
	html := string(settingsHTML)
	for _, guidance := range []string{
		"Pick a big enough model.",
		"Before each domain works:",
		"Use a dedicated IAM principal:",
		"Requires a custom Caddy build containing",
	} {
		at := strings.Index(html, guidance)
		if at < 0 {
			t.Fatalf("missing settings guidance %q", guidance)
		}
		open := strings.LastIndex(html[:at], "<div")
		if open < 0 {
			t.Fatalf("could not locate container for %q", guidance)
		}
		close := strings.Index(html[open:at], ">")
		if close < 0 {
			t.Fatalf("could not locate container for %q", guidance)
		}
		openingTag := html[open : open+close+1]
		if strings.Contains(openingTag, "data-toast=") {
			t.Fatalf("permanent guidance %q must remain inline, got %s", guidance, openingTag)
		}
	}
}

func TestSettingsPrometheusMetricsControls(t *testing.T) {
	settingsHTML, err := FS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings.html: %v", err)
	}
	html := string(settingsHTML)
	for _, field := range []string{
		`name="prometheus_metrics_enabled"`,
		`name="prometheus_metrics_per_host"`,
		`name="prometheus_metrics_observe_catchall_hosts"`,
		`name="prometheus_metrics_server_ids"`,
		`{{index $.MetricsScrapeTargets .ID}}`,
	} {
		if !strings.Contains(html, field) {
			t.Fatalf("settings template missing metrics control %s", field)
		}
	}
}

func TestOperationalTablesExposeRefreshAndSortingControls(t *testing.T) {
	certificatesHTML, err := FS.ReadFile("templates/certificates.html")
	if err != nil {
		t.Fatalf("read certificates.html: %v", err)
	}
	certificates := string(certificatesHTML)
	for _, marker := range []string{
		`id="refresh-certificate-status"`,
		`id="certificates-table"`,
		`id="auto-certificates-table"`,
		`data-sort-table`,
		`data-sort-index=`,
	} {
		if !strings.Contains(certificates, marker) {
			t.Fatalf("certificates template missing %s", marker)
		}
	}

	serverLogsHTML, err := FS.ReadFile("templates/server_logs.html")
	if err != nil {
		t.Fatalf("read server_logs.html: %v", err)
	}
	serverLogs := string(serverLogsHTML)
	for _, marker := range []string{
		`id="stream-status"`,
		`id="refresh-logs"`,
		`data-log-sort="0"`,
		`data-log-sort="5"`,
		`source.onopen`,
		`body.querySelectorAll('[data-entry-id]')`,
		`Number(item.dataset.entryId)`,
	} {
		if !strings.Contains(serverLogs, marker) {
			t.Fatalf("server logs template missing %s", marker)
		}
	}
	if strings.Contains(serverLogs, "removeChild(body.firstChild)") {
		t.Fatal("server log retention must evict by entry ID, not visual sort order")
	}
}

func TestDashboardClarifiesFleetTelemetryScopes(t *testing.T) {
	dashboardHTML, err := FS.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatalf("read dashboard.html: %v", err)
	}
	dashboard := string(dashboardHTML)
	for _, marker := range []string{
		"Certificate definitions",
		"CaddyUI host resources · Caddy telemetry from",
		"CaddyUI host uptime",
		"Node active requests",
		"fetch('/api/system-stats')",
	} {
		if !strings.Contains(dashboard, marker) {
			t.Fatalf("dashboard template missing scope marker %q", marker)
		}
	}
	if strings.Contains(dashboard, "/api/system-stats?sid=") {
		t.Fatal("dashboard system stats must follow the active-server cookie, not a separate query parameter")
	}
}

func TestProxyHostFormHasLiveCaddyfilePreviewAndConfiguredFilter(t *testing.T) {
	formHTML, err := FS.ReadFile("templates/proxy_host_form.html")
	if err != nil {
		t.Fatalf("read proxy host form: %v", err)
	}
	form := string(formHTML)
	for _, marker := range []string{
		`id="mode-configured"`,
		`id="ph-preview-caddyfile"`,
		`id="ph-preview-json"`,
		`id="ph-preview-tab-caddyfile"`,
		`document.getElementById('ph-preview')`,
		`d.caddyfile`,
		`dataset.configuredCount`,
	} {
		if !strings.Contains(form, marker) {
			t.Fatalf("proxy host form missing preview/filter marker %q", marker)
		}
	}
	if strings.Contains(form, `document.getElementById('ph-preview-details')`) {
		t.Fatal("proxy host preview still looks up the stale ph-preview-details ID")
	}
}
