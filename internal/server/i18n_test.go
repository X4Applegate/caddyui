// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/X4Applegate/caddyui/internal/i18n"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/X4Applegate/caddyui/web"
)

// v2.62.0 (issue #128): localization plumbing.

var tKeyRe = regexp.MustCompile(`\{\{-?\s*t \$ "([a-z0-9_.]+)"|\(t \$ "([a-z0-9_.]+)"\)|caddyuiT\(['"]([a-z0-9_.]+)['"]`)

// Every key a template or script uses must exist in English — a typo would
// otherwise show the raw key on the page.
func TestEveryTranslationKeyUsedExistsInEnglish(t *testing.T) {
	en := translations().Catalog("en")
	if len(en) < 10 {
		t.Fatalf("the embedded English catalog did not load (%d keys)", len(en))
	}
	used := 0
	err := fs.WalkDir(web.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".js")) {
			return err
		}
		raw, _ := fs.ReadFile(web.FS, path)
		for _, m := range tKeyRe.FindAllStringSubmatch(string(raw), -1) {
			key := m[1] + m[2] + m[3]
			used++
			if _, ok := en[key]; !ok {
				t.Errorf("%s uses %q, which en.json does not define", path, key)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if used < 30 {
		t.Errorf("only %d translated strings found — the template scan is probably broken", used)
	}
}

// A translation may only use keys English has, and must keep the same {placeholders}.
func TestEveryCatalogMatchesEnglishKeysAndPlaceholders(t *testing.T) {
	b := translations()
	en := b.Catalog("en")
	for _, l := range b.Locales() {
		if l.Code == "en" {
			continue
		}
		for k, v := range b.Catalog(l.Code) {
			if strings.HasPrefix(k, "_meta.") {
				continue
			}
			ev, ok := en[k]
			if !ok {
				t.Errorf("%s.json has %q, which en.json does not define", l.Code, k)
				continue
			}
			if v != "" && !reflect.DeepEqual(i18n.Placeholders(v), i18n.Placeholders(ev)) {
				t.Errorf("%s.json %q has placeholders %v, English has %v", l.Code, k, i18n.Placeholders(v), i18n.Placeholders(ev))
			}
		}
	}
}

func TestRequestLocalePrefersUserThenSiteDefaultThenBrowser(t *testing.T) {
	s := newHTTPOnlyTestServer(t)
	en, _ := fs.ReadFile(web.FS, "i18n/en.json")
	b, err := i18n.Load(fstest.MapFS{
		"i18n/en.json":    {Data: en},
		"i18n/zh-CN.json": {Data: []byte(`{"_meta.name":"简体中文"}`)},
		"i18n/de.json":    {Data: []byte(`{"_meta.name":"Deutsch"}`)},
	}, "i18n")
	if err != nil {
		t.Fatal(err)
	}
	translations()
	orig := i18nBundle
	i18nBundle = b
	t.Cleanup(func() { i18nBundle = orig })

	req := func(accept string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if accept != "" {
			r.Header.Set("Accept-Language", accept)
		}
		return r
	}
	// No default set: the browser decides, else English.
	if got := s.requestLocale(req("de-DE,de;q=0.9"), nil); got != "de" {
		t.Errorf("browser de → %q", got)
	}
	if got := s.requestLocale(req("fr-FR"), nil); got != "en" {
		t.Errorf("nothing matches → %q, want en", got)
	}
	// An administrator's default beats the browser — even an English browser.
	_ = models.SetSetting(s.DB, settingDefaultLocale, "zh-CN")
	if got := s.requestLocale(req("en-US,en;q=0.9"), nil); got != "zh-CN" {
		t.Errorf("site default zh-CN with an English browser → %q (the bug: the default never applied)", got)
	}
	// …but a person's own choice beats the default.
	if got := s.requestLocale(req("en-US"), &models.User{Locale: "de"}); got != "de" {
		t.Errorf("own choice → %q", got)
	}
	// An unknown own choice or default is ignored rather than breaking the page.
	if got := s.requestLocale(req(""), &models.User{Locale: "xx-YY"}); got != "zh-CN" {
		t.Errorf("unknown own choice → %q, want the site default", got)
	}
	_ = models.SetSetting(s.DB, settingDefaultLocale, "klingon")
	if got := s.requestLocale(req("de"), nil); got != "de" {
		t.Errorf("unknown default → %q, want the browser's", got)
	}
}

func TestTemplateHelperTakesThePageDataOrALocale(t *testing.T) {
	if got := tFunc(map[string]any{"Lang": "en"}, "nav.proxy_hosts"); got != "Proxy Hosts" {
		t.Errorf("t $ → %q", got)
	}
	if got := tFunc("en", "nav.proxy_hosts"); got != "Proxy Hosts" {
		t.Errorf("t \"en\" → %q", got)
	}
	if got := tFunc(nil, "nav.proxy_hosts"); got != "Proxy Hosts" {
		t.Errorf("t with no context → %q", got)
	}
}

// English pages render exactly as before: the translated navigation and
// headings read the same, and <html lang> plus the browser-side helper exist.
func TestRenderedPagesStayEnglishAndCarryTheLanguage(t *testing.T) {
	e := newSecEnv(t)
	body := e.do(t, "admin", http.MethodGet, "/proxy-hosts", nil).Body.String()
	for _, want := range []string{`<html lang="en"`, ">Proxy Hosts<", ">Middleware Profiles<", "<h1>Proxy hosts</h1>", "Search resources and actions", "window.CADDYUI_I18N", `"js.copied":"Copied"`, "Sign out"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
	if strings.Contains(body, "nav.proxy_hosts") || strings.Contains(body, "topbar.") {
		t.Error("a raw translation key leaked into the page")
	}
}

func TestProfileLanguageChoiceIsSavedAndValidated(t *testing.T) {
	e := newSecEnv(t)
	page := e.do(t, "alice", http.MethodGet, "/profile", nil).Body.String()
	if !strings.Contains(page, `name="locale"`) || !strings.Contains(page, ">English<") || !strings.Contains(page, "Use my browser") {
		t.Fatalf("the profile page has no language picker")
	}
	rec := e.do(t, "alice", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {"en"}})
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "flash=") {
		t.Fatalf("save → %d %s", rec.Code, rec.Header().Get("Location"))
	}
	u, _ := models.GetUserByID(e.db, e.ids["alice"])
	if u.Locale != "en" {
		t.Errorf("stored locale = %q", u.Locale)
	}
	rec = e.do(t, "alice", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {"../../etc"}})
	if !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Errorf("an unknown language was accepted: %s", rec.Header().Get("Location"))
	}
	u, _ = models.GetUserByID(e.db, e.ids["alice"])
	if u.Locale != "en" {
		t.Errorf("a refused value changed the stored locale to %q", u.Locale)
	}
	// Back to "follow the browser".
	e.do(t, "alice", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {""}})
	if u, _ = models.GetUserByID(e.db, e.ids["alice"]); u.Locale != "" {
		t.Errorf("clearing the choice left %q", u.Locale)
	}
}

func TestSettingsDefaultLanguageIsValidated(t *testing.T) {
	s, _ := newPreflightTestServer(t)
	if rec := postSettingsPage(t, s, url.Values{"settings_section": {"general"}, "default_locale": {"en"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save → %d", rec.Code)
	}
	if got := setting(t, s, settingDefaultLocale); got != "en" {
		t.Errorf("stored %q", got)
	}
	if rec := postSettingsPage(t, s, url.Values{"settings_section": {"general"}, "default_locale": {"klingon"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown default language → %d, want 400", rec.Code)
	}
}

// With a second catalog present, a user who prefers it gets translated
// navigation, and anything that catalog lacks stays English.
func TestASecondLanguageActuallyRenders(t *testing.T) {
	en, _ := fs.ReadFile(web.FS, "i18n/en.json")
	test := fstest.MapFS{
		"i18n/en.json":    {Data: en},
		"i18n/zh-CN.json": {Data: []byte(`{"_meta.name":"简体中文","nav.proxy_hosts":"代理主机","page.proxy_hosts.heading":"代理主机列表","js.copied":"已复制"}`)},
	}
	b, err := i18n.Load(test, "i18n")
	if err != nil {
		t.Fatal(err)
	}
	translations() // make sure the real bundle is loaded first
	orig := i18nBundle
	i18nBundle = b
	t.Cleanup(func() { i18nBundle = orig })

	e := newSecEnv(t)
	if rec := e.do(t, "alice", http.MethodPost, "/profile", url.Values{"action": {"update_locale"}, "locale": {"zh-CN"}}); !strings.Contains(rec.Header().Get("Location"), "flash=") {
		t.Fatalf("choosing zh-CN failed: %s", rec.Header().Get("Location"))
	}
	body := e.do(t, "alice", http.MethodGet, "/proxy-hosts", nil).Body.String()
	for _, want := range []string{`<html lang="zh-CN"`, ">代理主机<", "代理主机列表", `"js.copied":"已复制"`, ">Redirections<"} {
		if !strings.Contains(body, want) {
			t.Errorf("zh-CN page is missing %q", want)
		}
	}
	// Another user with no choice keeps English.
	if other := e.do(t, "admin", http.MethodGet, "/proxy-hosts", nil).Body.String(); !strings.Contains(other, `<html lang="en"`) || strings.Contains(other, "代理主机") {
		t.Error("one user's language leaked to another")
	}
}
