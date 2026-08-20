package web

import (
	"io/fs"
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
		`data-config-default="*"`,
		`data-config-default="30"`,
		`data-config-default="5"`,
		`data-config-default="Restricted"`,
		`data-config-default="{}"`,
		`data-config-default="checked"`,
		`t === 'number' && value !== '' && Number(value) === 0`,
		`setProxyFormMode(window.currentProxyFormMode)`,
		`window.applyProxyFormSearch = applyFilter`,
		`configuredDefault === '{}' && (value === '' || value === '{}')`,
		`var requestGeneration = 0`,
		`generation !== requestGeneration`,
		`new MutationObserver`,
		`This configuration cannot be saved:`,
	} {
		if !strings.Contains(form, marker) {
			t.Fatalf("proxy host form missing preview/filter marker %q", marker)
		}
	}
	if strings.Contains(form, `document.getElementById('ph-preview-details')`) {
		t.Fatal("proxy host preview still looks up the stale ph-preview-details ID")
	}
}

// TestVendoredStaticAssetsAreCommitted guards the class of bug behind issue
// #37: htmx and the Inter font were downloaded by the Dockerfile at image
// build time rather than committed, so `go build` from a plain checkout
// produced a binary whose embed.FS silently lacked them. A missing file
// inside an embedded *directory* is not a compile error, so nothing caught
// it — every GitHub release archive shipped a UI that 404'd on those paths.
//
// Any asset a template references must be committed under web/static.
func TestVendoredStaticAssetsAreCommitted(t *testing.T) {
	for _, path := range []string{
		"static/fonts/InterVariable.woff2",
		"static/app.css",
		"static/app.js",
		"static/auth.css",
	} {
		info, err := fs.Stat(FS, path)
		if err != nil {
			t.Errorf("%s must be committed and embedded, not fetched at build time: %v", path, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is embedded but empty", path)
		}
	}
}

// TestNoExternalScriptTags keeps third-party JavaScript out of the templates.
// The qrcode CDN path in totp_setup.html started returning 404 (and was
// blocked by CORB besides), which silently broke 2FA enrolment for everyone.
// CaddyUI is self-hosted and must render its own admin UI without reaching
// out to the public internet.
func TestNoExternalScriptTags(t *testing.T) {
	entries, err := fs.ReadDir(FS, "templates")
	if err != nil {
		t.Fatalf("read templates dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		body, err := FS.ReadFile("templates/" + entry.Name())
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		html := string(body)
		for _, host := range []string{"cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com"} {
			if strings.Contains(html, host) {
				t.Errorf("%s loads a script from %s — vendor it under web/static instead", entry.Name(), host)
			}
		}
		if strings.Contains(html, "htmx.min.js") {
			t.Errorf("%s still references htmx, which was removed in v2.27.0", entry.Name())
		}
	}
}

// TestTOTPSetupRendersServerSideQR asserts the 2FA page uses the server-rendered
// PNG data URI rather than a client-side QR library. See issue #37.
func TestTOTPSetupRendersServerSideQR(t *testing.T) {
	body, err := FS.ReadFile("templates/totp_setup.html")
	if err != nil {
		t.Fatalf("read totp_setup.html: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, "{{.OTPQRCode}}") {
		t.Error("totp_setup.html must render the server-generated QR data URI")
	}
	if strings.Contains(html, "QRCode.toCanvas") {
		t.Error("totp_setup.html still uses the client-side qrcode library")
	}
}

// TestAdvancedRouteFormOffersCrossDeploy covers issue #38: advanced (raw)
// routes were the only resource type without an "Also deploy to" picker, so
// the only way to mirror one onto another node was a full fleet sync that
// clobbered the destination's other config.
func TestAdvancedRouteFormOffersCrossDeploy(t *testing.T) {
	body, err := FS.ReadFile("templates/raw_route_form.html")
	if err != nil {
		t.Fatalf("read raw_route_form.html: %v", err)
	}
	html := string(body)
	for _, marker := range []string{
		"{{if .OtherServers}}",
		`name="deploy_to"`,
		"Also deploy to",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("raw route form missing cross-deploy marker %q", marker)
		}
	}
}

// TestMonitoringControlsAndOffStateAreWired covers issue #39. Two halves have
// to stay in sync: the form must offer the mode selector, and every status-dot
// painter must special-case "off". If a painter loses its "off" branch the
// status falls through to the red "down" dot — the precise opposite of what
// switching monitoring off is supposed to convey.
func TestMonitoringControlsAndOffStateAreWired(t *testing.T) {
	form, err := FS.ReadFile("templates/proxy_host_form.html")
	if err != nil {
		t.Fatalf("read proxy_host_form.html: %v", err)
	}
	formHTML := string(form)
	for _, marker := range []string{
		`name="monitor_mode"`,
		`name="monitor_path"`,
		`name="monitor_method"`,
		`name="monitor_expect_status"`,
		`name="monitor_interval_sec"`,
		`name="monitor_timeout_sec"`,
		`id="monitor-custom"`,
		"CaddyUI status monitoring",
	} {
		if !strings.Contains(formHTML, marker) {
			t.Errorf("proxy host form missing monitoring control %q", marker)
		}
	}

	for _, name := range []string{"templates/proxy_hosts.html", "templates/dashboard.html"} {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		html := string(body)
		// Both painters live in each file: the Port dot keys off h.status and
		// the App dot off a local `s`, so require both spellings.
		for _, branch := range []string{`h.status === 'off'`, `s === 'off'`} {
			if !strings.Contains(html, branch) {
				t.Errorf("%s missing status-dot branch %q — an off host would paint red", name, branch)
			}
		}
	}
}

// TestCSRFClientPlumbing guards the two client-side halves of CSRF protection.
// The hidden form input is stamped into rendered HTML server-side (see
// csrfInjectForms), but scripted callers depend on these two pieces: the meta
// tag carrying the token, and the fetch wrapper that turns it into a header.
// Lose either and every fetch()-based mutation starts returning 403.
func TestCSRFClientPlumbing(t *testing.T) {
	layout, err := FS.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("read layout.html: %v", err)
	}
	if !strings.Contains(string(layout), `name="csrf-token"`) {
		t.Error("layout.html must emit the csrf-token meta tag for app.js to read")
	}

	appJS, err := FS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	js := string(appJS)
	for _, marker := range []string{
		`meta[name="csrf-token"]`,
		"X-CSRF-Token",
		"window.fetch =",
	} {
		if !strings.Contains(js, marker) {
			t.Errorf("app.js missing CSRF fetch-wrapper marker %q", marker)
		}
	}
	// The wrapper must not attach the token to cross-origin requests, or it
	// leaks the token to whatever third-party host a future call talks to.
	if !strings.Contains(js, "sameOrigin") {
		t.Error("app.js fetch wrapper must gate the token on a same-origin check")
	}
}

// TestCaptchaSecretsNeverRenderIntoTheDOM covers the settings-page leak where
// turnstile_secret_key / recaptcha_secret_key were emitted as input values.
// type="password" masks them visually, but the plaintext is readable via
// DevTools or document.querySelector(...).value. Matches the pattern already
// used for the SMTP password and the AI provider API keys.
func TestCaptchaSecretsNeverRenderIntoTheDOM(t *testing.T) {
	body, err := FS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings.html: %v", err)
	}
	html := string(body)
	for _, leak := range []string{
		`value="{{.TurnstileSecretKey}}"`,
		`value="{{.RecaptchaSecretKey}}"`,
	} {
		if strings.Contains(html, leak) {
			t.Errorf("settings.html leaks a captcha secret into the DOM: %s", leak)
		}
	}
	for _, marker := range []string{
		`name="turnstile_secret_key"`,
		`name="recaptcha_secret_key"`,
		"{{if .TurnstileSecretKeySet}}",
		"{{if .RecaptchaSecretKeySet}}",
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("settings.html missing captcha secret marker %s", marker)
		}
	}
}
