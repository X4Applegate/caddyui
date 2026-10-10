// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log"
	"net/http"
	"sync"

	"github.com/X4Applegate/caddyui/internal/i18n"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/X4Applegate/caddyui/web"
)

// v2.62.0 (issue #128): localization plumbing. See internal/i18n for the catalog
// format; this file picks each request's language and exposes the translate
// helper to the templates.

// settingDefaultLocale is the site-wide fallback language ("" = none).
const settingDefaultLocale = "default_locale"

var (
	i18nOnce   sync.Once
	i18nBundle *i18n.Bundle
)

// translations returns the catalogs embedded in the binary. A broken catalog is
// a build mistake (the tests load every one), so it is logged and the app keeps
// running in English rather than refusing to start.
func translations() *i18n.Bundle {
	i18nOnce.Do(func() {
		b, err := i18n.Load(web.FS, "i18n")
		if err != nil {
			log.Printf("i18n: %v — falling back to built-in English keys", err)
			b, _ = i18n.LoadFallback()
		}
		i18nBundle = b
	})
	return i18nBundle
}

// tFunc is the template helper: {{t $ "nav.proxy_hosts"}} — or with
// placeholders, {{t $ "x.count" "count" 3}}. The first argument is the page's
// root data (which carries "Lang") or a locale code; anything else means English.
func tFunc(ctx any, key string, args ...any) string {
	lang := i18n.Default
	switch v := ctx.(type) {
	case map[string]any:
		if l, ok := v["Lang"].(string); ok && l != "" {
			lang = l
		}
	case string:
		if v != "" {
			lang = v
		}
	}
	return translations().T(lang, key, args...)
}

// requestLocale picks the language for a request: the signed-in user's own
// choice, then the site default an administrator set, then the browser's
// Accept-Language, then English. Only languages with a catalog are returned.
//
// v2.62.2: the site default used to come AFTER the browser, so for anyone whose
// browser asks for English (which always exists) it never applied — choosing a
// default language in Settings visibly did nothing. An explicit default now
// wins over the browser; leaving it on "follow each browser" keeps the browser.
func (s *Server) requestLocale(r *http.Request, u *models.User) string {
	b := translations()
	if u != nil && u.Locale != "" && b.Has(u.Locale) {
		return u.Locale
	}
	if s != nil && s.DB != nil {
		if d := mustGetSetting(s.DB, settingDefaultLocale); d != "" && b.Has(d) {
			return d
		}
	}
	if r != nil {
		if l := b.Match(i18n.ParseAcceptLanguage(r.Header.Get("Accept-Language"))...); l != "" {
			return l
		}
	}
	return i18n.Default
}

// tr translates key for the request's language — for messages built in Go,
// such as the flash and error texts handed to a page through a redirect.
func (s *Server) tr(r *http.Request, key string, args ...any) string {
	return translations().T(s.requestLocale(r, s.currentUser(r)), key, args...)
}
