// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.60.0 (issue #123): the fallback status for unmatched requests is
// configurable (4xx/5xx), consistent on HTTP, HTTPS and the wildcard route.

func TestParseFallbackStatus(t *testing.T) {
	for in, want := range map[string]int{"404": 404, " 403 ": 403, "418": 418, "421": 421, "400": 400, "599": 599, "503": 503} {
		if got, ok := parseFallbackStatus(in); !ok || got != want {
			t.Errorf("%q -> %d,%v want %d,true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "200", "301", "399", "600", "0", "-404", "abc", "40 4", "4040"} {
		if _, ok := parseFallbackStatus(bad); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestFallbackStatusDefaultsTo404AndIgnoresGarbage(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	if got := s.fallbackStatusCode(); got != 404 {
		t.Errorf("default = %d", got)
	}
	for _, stored := range []string{"abc", "200", "700"} {
		_ = models.SetSetting(s.DB, settingFallbackStatus, stored)
		if got := s.fallbackStatusCode(); got != 404 {
			t.Errorf("stored %q -> %d, want the 404 default", stored, got)
		}
	}
	_ = models.SetSetting(s.DB, settingFallbackStatus, "421")
	if got := s.fallbackStatusCode(); got != 421 {
		t.Errorf("stored 421 -> %d", got)
	}
}

func TestConfiguredFallbackStatusIsUsedEverywhere(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	_ = models.SetSetting(s.DB, settingFallbackStatus, "418")
	hosts := []models.ProxyHost{proxyRow("app.example.com", false)}

	// Default (no custom HTML): Caddy's error handler with the chosen status,
	// on both listeners.
	for name, routes := range map[string][]any{
		"HTTPS": s.withFallbackRoute(s.buildMergedRoutes(hosts, nil, nil)),
		"HTTP":  s.buildHTTPRoutes(hosts, nil, nil),
	} {
		last := lastRouteJSON(t, routes)
		if !strings.Contains(last, `"handler":"error"`) || !strings.Contains(last, `"status_code":418`) {
			t.Errorf("%s: fallback is not an error handler with 418: %s", name, last)
		}
	}

	// With custom HTML the same status is sent with the page.
	_ = models.SetSetting(s.DB, settingCatchAll404HTML, "<p>teapot</p>")
	last := lastRouteJSON(t, s.buildHTTPRoutes(hosts, nil, nil))
	if !strings.Contains(last, "static_response") || !strings.Contains(last, `"status_code":418`) || !strings.Contains(last, "teapot") {
		t.Errorf("custom page not sent with the configured status: %s", last)
	}

	// The managed wildcard-certificate route answers exactly like every other
	// unknown host, instead of a hardcoded 404.
	certs := []models.Certificate{{ID: 2, Source: models.CertSourceManaged, Domains: "*.example.com"}}
	routes := buildManagedCertificateRoutes(certs, s.fallbackRoute()["handle"].([]any))
	b, _ := json.Marshal(routes)
	if !strings.Contains(string(b), `"status_code":418`) || strings.Contains(string(b), `"status_code":404`) {
		t.Errorf("wildcard-certificate route does not follow the fallback: %s", b)
	}
}

func TestSettingsSavesAndValidatesTheFallbackStatus(t *testing.T) {
	s, _ := newPreflightTestServer(t)
	rec := postSettingsPage(t, s, url.Values{"settings_section": {"general"}, "fallback_status_code": {"403"}, "catch_all_404_html": {"<p>nope</p>"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save -> %d: %s", rec.Code, rec.Body.String())
	}
	if got := setting(t, s, settingFallbackStatus); got != "403" {
		t.Errorf("stored %q, want 403", got)
	}
	// Another section's save must not touch it.
	_ = postSettingsPage(t, s, url.Values{"settings_section": {"security"}})
	if got := setting(t, s, settingFallbackStatus); got != "403" {
		t.Errorf("a different section's save changed it to %q", got)
	}
	// Invalid values are refused and nothing is changed.
	for _, bad := range []string{"200", "302", "700", "abc"} {
		rec := postSettingsPage(t, s, url.Values{"settings_section": {"general"}, "fallback_status_code": {bad}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q -> %d, want 400", bad, rec.Code)
		}
	}
	if got := setting(t, s, settingFallbackStatus); got != "403" {
		t.Errorf("an invalid save changed it to %q", got)
	}
	// Blank resets to the default.
	_ = postSettingsPage(t, s, url.Values{"settings_section": {"general"}, "fallback_status_code": {""}})
	if got := setting(t, s, settingFallbackStatus); got != "" {
		t.Errorf("blank stored %q, want empty (= 404)", got)
	}
}
