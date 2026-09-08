package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/models"
)

func postSettingsPage(t *testing.T, s *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, &models.User{ID: 1, Email: "admin@example.com", IsAdmin: true, Role: models.RoleAdmin}))
	rec := httptest.NewRecorder()
	s.postSettings(rec, req)
	return rec
}

func setting(t *testing.T, s *Server, key string) string {
	t.Helper()
	v, err := models.GetSetting(s.DB, key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// v2.44.0: a page saves its own keys and leaves every other page's values
// alone; the legacy whole-form post (no page) still saves everything.
func TestSettingsPagesSaveOnlyTheirOwnKeys(t *testing.T) {
	s, _ := newPreflightTestServer(t)
	seed := map[string]string{
		settingSiteTitle:              "Old title",
		settingTimezone:               "Europe/Paris",
		settingSMTPHost:               "mail.example.test",
		settingNotifyWebhookURL:       "https://hooks.example.test/x",
		settingAnalyticsIngestTarget:  "10.8.0.1:9019",
		settingAnalyticsRetentionDays: "45",
		settingAdminAllowlist:         "10.0.0.0/8",
		settingAIProvider:             "anthropic",
		settingServerIP:               "203.0.113.5",
		settingClientIPHeaders:        "CF-Connecting-IP",
	}
	for k, v := range seed {
		if err := models.SetSetting(s.DB, k, v); err != nil {
			t.Fatal(err)
		}
	}

	// General page: only General keys change.
	rec := postSettingsPage(t, s, url.Values{"settings_section": {"general"}, "site_title": {"New title"}, "timezone": {"UTC"}, "auto_sync_hours": {"6"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings/general?saved=1" {
		t.Fatalf("general save → %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if got := setting(t, s, settingSiteTitle); got != "New title" {
		t.Errorf("site title = %q", got)
	}
	if got := setting(t, s, settingTimezone); got != "UTC" {
		t.Errorf("timezone = %q", got)
	}
	for _, k := range []string{settingSMTPHost, settingNotifyWebhookURL, settingAnalyticsIngestTarget, settingAnalyticsRetentionDays, settingAdminAllowlist, settingAIProvider, settingServerIP, settingClientIPHeaders} {
		if got := setting(t, s, k); got != seed[k] {
			t.Errorf("General save changed %s: %q → %q", k, seed[k], got)
		}
	}

	// Analytics page: its keys change, General and the rest stay.
	rec = postSettingsPage(t, s, url.Values{"settings_section": {"analytics"}, "analytics_enabled": {"0", "1"}, "analytics_ingest_target": {"caddyui:9019"}, "analytics_retention_days": {"14"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings/analytics?saved=1" {
		t.Fatalf("analytics save → %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if got := setting(t, s, settingAnalyticsIngestTarget); got != "caddyui:9019" {
		t.Errorf("analytics target = %q", got)
	}
	if got := setting(t, s, settingAnalyticsRetentionDays); got != "14" {
		t.Errorf("retention = %q", got)
	}
	if got := setting(t, s, settingSiteTitle); got != "New title" {
		t.Errorf("Analytics save changed the site title: %q", got)
	}
	if got := setting(t, s, settingSMTPHost); got != seed[settingSMTPHost] {
		t.Errorf("Analytics save changed SMTP host: %q", got)
	}

	// Security page owns client_ip_headers even though integrations bundle it.
	rec = postSettingsPage(t, s, url.Values{"settings_section": {"security"}, "client_ip_headers": {"X-Real-IP"}, "admin_allowlist": {"192.168.0.0/16"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("security save → %d %s", rec.Code, rec.Body.String())
	}
	if got := setting(t, s, settingClientIPHeaders); got != "X-Real-IP" {
		t.Errorf("client_ip_headers = %q", got)
	}
	if got := setting(t, s, settingAdminAllowlist); got != "192.168.0.0/16" {
		t.Errorf("admin allowlist = %q", got)
	}
	if got := setting(t, s, settingServerIP); got != seed[settingServerIP] {
		t.Errorf("Security save changed the DNS server IP: %q", got)
	}

	// Notifications page: SMTP changes; a blank password keeps the stored one.
	if err := models.SetSetting(s.DB, settingSMTPPassword, "secret"); err != nil {
		t.Fatal(err)
	}
	rec = postSettingsPage(t, s, url.Values{"settings_section": {"notifications"}, "smtp_host": {"smtp.new.test"}, "smtp_password": {""}, "webhook_url": {""}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("notifications save → %d", rec.Code)
	}
	if got := setting(t, s, settingSMTPHost); got != "smtp.new.test" || setting(t, s, settingSMTPPassword) != "secret" || setting(t, s, settingNotifyWebhookURL) != "" {
		t.Errorf("notifications save: host=%q password kept=%v webhook=%q", got, setting(t, s, settingSMTPPassword) == "secret", setting(t, s, settingNotifyWebhookURL))
	}
	if got := setting(t, s, settingAnalyticsIngestTarget); got != "caddyui:9019" {
		t.Errorf("Notifications save changed the analytics target: %q", got)
	}

	// Legacy whole-form post (no page): everything it carries is saved, as before.
	rec = postSettingsPage(t, s, url.Values{"site_title": {"Legacy"}, "analytics_ingest_target": {"legacy:9019"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings?saved=1" {
		t.Fatalf("legacy save → %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if setting(t, s, settingSiteTitle) != "Legacy" || setting(t, s, settingAnalyticsIngestTarget) != "legacy:9019" {
		t.Errorf("legacy save should write every page's keys")
	}

	// Unknown page slug → treated as legacy; unknown GET page → 404.
	if settingsSectionSlug("bogus") != "" || settingsSectionSlug(" DNS ") != "dns" {
		t.Errorf("slug validation")
	}
	req := httptest.NewRequest(http.MethodGet, "/settings/bogus", nil)
	rec = httptest.NewRecorder()
	// chi URL params are not set outside a router; exercise the slug check directly.
	if settingsSectionLabel("bogus") != "Settings" || settingsSectionLabel("dns") != "DNS" {
		t.Errorf("labels")
	}
	_ = req
	for anchor, page := range settingsAnchorSection {
		if settingsSectionSlug(page) == "" {
			t.Errorf("anchor %s points at unknown page %q", anchor, page)
		}
	}
	for key, page := range settingsKeySection {
		if settingsSectionSlug(page) == "" {
			t.Errorf("key %s owned by unknown page %q", key, page)
		}
	}
}
