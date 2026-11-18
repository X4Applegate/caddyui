package server

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

func TestI18nSMTPSettingsFallbackAndForm(t *testing.T) {
	e := newSecEnv(t)
	for _, lang := range []string{"en", "fr", "ru", "zh-CN"} {
		t.Run(lang, func(t *testing.T) {
			e.do(t, "admin", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {lang}})
			rec := e.do(t, "admin", http.MethodGet, "/settings/notifications", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d", rec.Code)
			}
			body := rec.Body.String()
			for _, key := range []string{"title", "help", "host", "keep_password", "skip_verify_help", "recipients_help", "test_hint"} {
				want := html.EscapeString(translations().T(lang, "settings.smtp."+key))
				if !strings.Contains(body, want) {
					t.Errorf("missing %s", key)
				}
			}
			for _, contract := range []string{`name="smtp_host"`, `name="smtp_security" value="starttls"`, `name="smtp_security" value="tls"`, `name="smtp_security" value="none"`, `name="smtp_password" value=""`, `name="smtp_skip_verify" value="0"`} {
				if !strings.Contains(body, contract) {
					t.Errorf("lost form contract %s", contract)
				}
			}
			if strings.Contains(body, ">settings.smtp.") {
				t.Error("raw key rendered")
			}
		})
	}
}

func TestI18nSMTPSettingsEscapesValuesAndHidesPassword(t *testing.T) {
	e := newSecEnv(t)
	const unsafe = `<img src=x onerror=alert(1)>`
	for key, value := range map[string]string{"smtp_host": unsafe, "smtp_password": "fixture-smtp-secret-never-render"} {
		if err := models.SetSetting(e.db, key, value); err != nil {
			t.Fatal(err)
		}
	}
	body := e.do(t, "admin", http.MethodGet, "/settings/notifications", nil).Body.String()
	if strings.Contains(body, unsafe) || !strings.Contains(body, html.EscapeString(unsafe)) {
		t.Error("SMTP host escaping changed")
	}
	if strings.Contains(body, "fixture-smtp-secret-never-render") {
		t.Error("SMTP password exposed")
	}
}
