// SPDX-License-Identifier: Apache-2.0

package server

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// A partial catalog must retain usable security controls through English
// fallback. Changing display language must never translate submitted values.
func TestI18nSecuritySettingsFallbackAndControls(t *testing.T) {
	e := newSecEnv(t)
	for _, lang := range []string{"en", "fr", "ru", "zh-CN"} {
		t.Run(lang, func(t *testing.T) {
			e.do(t, "admin", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {lang}})
			rec := e.do(t, "admin", http.MethodGet, "/settings/security", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("security settings: HTTP %d", rec.Code)
			}
			body := rec.Body.String()
			for _, key := range []string{"settings.security.captcha.title", "settings.security.allowlist.label", "settings.security.oidc.label", "settings.security.totp.require"} {
				want := html.EscapeString(translations().T(lang, key))
				if !strings.Contains(body, want) {
					t.Errorf("missing localized security text %q", want)
				}
			}
			for _, contract := range []string{`name="captcha_provider" value="off"`, `name="captcha_provider" value="turnstile"`, `name="captcha_provider" value="recaptcha"`, `data-captcha-panel="turnstile"`, `data-captcha-panel="recaptcha"`, `name="admin_allowlist"`, `name="global_ip_blocklist"`, `name="oidc_default_role"`, `value="view"`, `value="user"`, `value="admin"`, `name="session_duration_days"`, `name="recaptcha_min_score"`, `CADDYUI_ADMIN_ALLOWLIST=off`, `group|role`} {
				if !strings.Contains(body, contract) {
					t.Errorf("security form contract lost: %s", contract)
				}
			}
			if strings.Contains(body, ">settings.security.") || strings.Contains(body, `title="settings.security.`) {
				t.Error("raw translation key rendered")
			}
			if lang == "ru" || lang == "zh-CN" {
				if !strings.Contains(body, "CAPTCHA protection") || !strings.Contains(body, "Security policy") {
					t.Error("partial catalog did not fall back to English")
				}
			}
		})
	}
}

func TestI18nSecuritySettingsEscapesStoredValues(t *testing.T) {
	e := newSecEnv(t)
	const unsafe = `<img src=x onerror=alert(1)>`
	if err := models.SetSetting(e.db, "oidc_issuer", unsafe); err != nil {
		t.Fatal(err)
	}
	body := e.do(t, "admin", http.MethodGet, "/settings/security", nil).Body.String()
	if strings.Contains(body, unsafe) || !strings.Contains(body, html.EscapeString(unsafe)) {
		t.Error("stored issuer must remain escaped in the translated form")
	}
}

// These messages must remain whole so translators can move technical values
// and the profile-menu label to the position their language requires.
func TestI18nSecuritySettingsInterpolatesCompleteHelp(t *testing.T) {
	e := newSecEnv(t)
	for _, lang := range []string{"en", "fr", "ru", "zh-CN"} {
		t.Run(lang, func(t *testing.T) {
			e.do(t, "admin", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {lang}})
			rec := e.do(t, "admin", http.MethodGet, "/settings/security", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("security settings: HTTP %d", rec.Code)
			}
			body := rec.Body.String()
			for _, message := range []struct {
				key  string
				args []any
			}{
				{"settings.security.oidc.redirect_help", []any{"suffix", "/callback"}},
				{"settings.security.oidc.groups_help", []any{"claim", "groups"}},
				{"settings.security.totp.help", []any{"profile", translations().T(lang, "settings.security.totp.profile_link")}},
			} {
				want := html.EscapeString(translations().T(lang, message.key, message.args...))
				if !strings.Contains(body, want) {
					t.Errorf("complete help missing for %s: %q", message.key, want)
				}
			}
			for _, placeholder := range []string{"{suffix}", "{claim}", "{profile}"} {
				if strings.Contains(body, placeholder) {
					t.Errorf("unresolved help placeholder: %s", placeholder)
				}
			}
			if !strings.Contains(body, "https://") || !strings.Contains(body, "/auth/oidc/callback") {
				t.Error("technical callback example lost")
			}
		})
	}
}

// Exercise the conditional labels too: a default empty form cannot cover
// configured providers or the environment override, and secrets must stay private.
func TestI18nSecuritySettingsCaptchaStates(t *testing.T) {
	t.Setenv(envCaptchaDisable, "")
	e := newSecEnv(t)
	for _, tc := range []struct {
		name, provider, site, secret, override, key string
	}{
		{"off", "off", "", "", "", "status.disabled"},
		{"turnstile_missing", "turnstile", "", "", "", "settings.security.captcha.turnstile_missing"},
		{"turnstile_active", "turnstile", "fixture-site", "fixture-secret-not-for-html", "", "settings.security.captcha.turnstile_active"},
		{"recaptcha_missing", "recaptcha", "", "", "", "settings.security.captcha.recaptcha_missing"},
		{"recaptcha_active", "recaptcha", "fixture-site", "fixture-secret-not-for-html", "", "settings.security.captcha.recaptcha_active"},
		{"override", "turnstile", "fixture-site", "fixture-secret-not-for-html", "1", "settings.security.captcha.overridden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envCaptchaDisable, tc.override)
			for key, value := range map[string]string{
				settingCaptchaProvider:    tc.provider,
				settingTurnstileSiteKey:   tc.site,
				settingTurnstileSecretKey: tc.secret,
				settingRecaptchaSiteKey:   tc.site,
				settingRecaptchaSecretKey: tc.secret,
			} {
				if err := models.SetSetting(e.db, key, value); err != nil {
					t.Fatal(err)
				}
			}
			for _, lang := range []string{"en", "fr", "ru", "zh-CN"} {
				e.do(t, "admin", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {lang}})
				rec := e.do(t, "admin", http.MethodGet, "/settings/security", nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: security settings HTTP %d", lang, rec.Code)
				}
				body := rec.Body.String()
				want := html.EscapeString(translations().T(lang, tc.key))
				if !strings.Contains(body, want) {
					t.Errorf("%s: missing CAPTCHA state %q", lang, want)
				}
				if tc.override != "" && !strings.Contains(body, "CADDYUI_CAPTCHA_DISABLE") {
					t.Errorf("%s: missing override recovery variable", lang)
				}
				if strings.Contains(body, "fixture-secret-not-for-html") {
					t.Errorf("%s: CAPTCHA secret leaked into HTML", lang)
				}
			}
		})
	}
}
