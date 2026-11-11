// SPDX-License-Identifier: Apache-2.0

package server

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Anonymous pages use the site or browser language, not an account selected
// by an untrusted email field. Partial catalogs keep working through English.
func TestI18nLoginAnonymousLocaleAndMessages(t *testing.T) {
	e := newSecEnv(t)
	for _, tc := range []struct{ name, site, browser, lang string }{
		{"browser_french", "", "fr-FR,fr;q=0.9,en;q=0.8", "fr"},
		{"site_over_browser", "fr", "en-US", "fr"},
		{"english", "en", "fr-FR", "en"},
		{"russian_fallback", "ru", "en-US", "ru"},
		{"chinese_fallback", "zh-CN", "en-US", "zh-CN"},
		{"unknown_browser", "", "xx-YY", "en"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := models.SetSetting(e.db, settingDefaultLocale, tc.site); err != nil {
				t.Fatal(err)
			}
			for _, page := range []struct{ query, key string }{
				{"", "login.heading"},
				{"?reset=1", "login.password_updated"},
				{"?invited=1", "login.account_activated"},
				{"?error=sso_nouser", "login.error.sso_no_user"},
				{"?error=sso_email", "login.error.sso_email"},
				{"?error=sso_denied", "login.error.sso_cancelled"},
				{"?error=sso_domain", "login.error.sso_domain"},
				{"?error=sso_unknown", "login.error.sso_failed"},
			} {
				req := httptest.NewRequest(http.MethodGet, "/login"+page.query, nil)
				req.Header.Set("Accept-Language", tc.browser)
				rec := httptest.NewRecorder()
				e.h.ServeHTTP(rec, req)
				body := rec.Body.String()
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: HTTP %d", page.query, rec.Code)
				}
				if !strings.Contains(body, `<html lang="`+tc.lang+`"`) {
					t.Errorf("wrong page language for %s", page.query)
				}
				want := html.EscapeString(translations().T(tc.lang, page.key))
				if !strings.Contains(body, want) {
					t.Errorf("missing %s: %q", page.key, want)
				}
				for _, value := range []string{`id="login-form"`, `action="/login"`, `name="email"`, `name="password"`, `autocomplete="current-password"`, `href="/forgot-password"`} {
					if !strings.Contains(body, value) {
						t.Errorf("login form contract lost: %s", value)
					}
				}
				if strings.Contains(body, ">login.") {
					t.Error("raw login key rendered")
				}
			}
		})
	}
}

func TestI18nLoginErrorsAndSuccessfulSession(t *testing.T) {
	t.Setenv(envCaptchaDisable, "")
	e := newSecEnv(t)
	if err := models.SetSetting(e.db, settingDefaultLocale, "fr"); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"admin@t", "unknown@t"} {
		rec := e.do(t, "", http.MethodPost, "/login", url.Values{"email": {email}, "password": {"wrong-password"}})
		want := html.EscapeString(translations().T("fr", "login.error.invalid_credentials"))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("invalid login should show generic localized error, HTTP %d", rec.Code)
		}
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == auth.SessionCookie && cookie.Value != "" {
				t.Error("failed login created a session")
			}
		}
	}
	rec := e.do(t, "", http.MethodPost, "/login", url.Values{"email": {"admin@t"}, "password": {"password-123"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("successful login changed: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	hasSession := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.SessionCookie && cookie.Value != "" {
			hasSession = true
		}
	}
	if !hasSession {
		t.Error("successful login did not create a session")
	}
	if err := models.SetSetting(e.db, settingMaxLoginAttempts, "1"); err != nil {
		t.Fatal(err)
	}
	rec = e.do(t, "", http.MethodPost, "/login", url.Values{"email": {"admin@t"}, "password": {"wrong-password"}})
	if !strings.Contains(rec.Body.String(), html.EscapeString(translations().T("fr", "login.error.login_limit"))) {
		t.Error("localized lockout message missing")
	}
}

func TestI18nLoginSSOOnlyTranslatesBuiltInLabel(t *testing.T) {
	e := newSecEnv(t)
	for key, value := range map[string]string{settingDefaultLocale: "fr", settingOIDCEnabled: "1", settingOIDCIssuer: "https://idp.example.test", settingOIDCClientID: "fixture-client", settingOIDCClientSecret: "fixture-secret", settingOIDCRedirectURL: "https://caddyui.example.test/auth/oidc/callback"} {
		if err := models.SetSetting(e.db, key, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, label := range []string{"", "Sign in with SSO", `<img src=x onerror=alert(1)>`} {
		if err := models.SetSetting(e.db, settingOIDCButtonLabel, label); err != nil {
			t.Fatal(err)
		}
		rec := e.do(t, "", http.MethodGet, "/login", nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `href="/auth/oidc/login"`) {
			t.Fatalf("configured SSO button missing: HTTP %d", rec.Code)
		}
		want := label
		if label == "" {
			want = translations().T("fr", "login.sso_default")
		}
		if !strings.Contains(rec.Body.String(), html.EscapeString(want)) {
			t.Errorf("SSO label not preserved/translated: %q", want)
		}
		if strings.Contains(rec.Body.String(), `<img src=x onerror=alert(1)>`) {
			t.Error("custom SSO label was not escaped")
		}
	}
}
