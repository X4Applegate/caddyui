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
