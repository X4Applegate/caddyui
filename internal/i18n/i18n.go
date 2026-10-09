// SPDX-License-Identifier: Apache-2.0

// Package i18n is CaddyUI's localization (v2.62.0, issue #128).
//
// Translations are flat JSON catalogs, one file per locale, named by its BCP 47
// code (web/i18n/en.json, web/i18n/zh-CN.json, …) and embedded in the binary.
// en.json is the source of truth: every key a template or script uses must exist
// there, and any key a translation does not have falls back to English, so a
// partial catalog never breaks a page. Keys are stable dotted names such as
// "nav.proxy_hosts"; values may contain named placeholders like {count}, filled
// from key/value arguments. Keys starting with "_meta." describe the catalog
// itself ("_meta.name" is the language's own name for the picker).
package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Default is the locale every other one falls back to.
const Default = "en"

// Locale is one available language.
type Locale struct {
	Code string // BCP 47, e.g. "en", "zh-CN"
	Name string // the language's own name, e.g. "English", "简体中文"
}

// Bundle holds every loaded catalog.
type Bundle struct {
	catalogs map[string]map[string]string // code -> key -> text
	locales  []Locale
}

var placeholderRe = regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_]*\}`)

// Load reads every *.json catalog in dir of fsys. The default (English) catalog
// is required.
func Load(fsys fs.FS, dir string) (*Bundle, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	b := &Bundle{catalogs: map[string]map[string]string{}}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		code := strings.TrimSuffix(e.Name(), ".json")
		raw, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		cat := map[string]string{}
		if err := json.Unmarshal(raw, &cat); err != nil {
			return nil, fmt.Errorf("i18n: %s: %w", e.Name(), err)
		}
		b.catalogs[code] = cat
	}
	if _, ok := b.catalogs[Default]; !ok {
		return nil, fmt.Errorf("i18n: the %s catalog is missing", Default)
	}
	for code, cat := range b.catalogs {
		name := cat["_meta.name"]
		if name == "" {
			name = code
		}
		b.locales = append(b.locales, Locale{Code: code, Name: name})
	}
	sort.Slice(b.locales, func(i, j int) bool {
		if b.locales[i].Code == Default {
			return true
		}
		if b.locales[j].Code == Default {
			return false
		}
		return b.locales[i].Code < b.locales[j].Code
	})
	return b, nil
}

// Locales lists the available languages, English first.
func (b *Bundle) Locales() []Locale { return append([]Locale(nil), b.locales...) }

// Has reports whether code is an available locale (exact code).
func (b *Bundle) Has(code string) bool { _, ok := b.catalogs[code]; return ok }

// T returns the text for key in lang, falling back to English and finally to
// the key itself (so a missing key is visible rather than blank). args are
// alternating placeholder names and values: T("en", "x.y", "count", 3).
func (b *Bundle) T(lang, key string, args ...any) string {
	text, ok := b.catalogs[lang][key]
	if !ok || text == "" {
		text, ok = b.catalogs[Default][key]
		if !ok {
			return key
		}
	}
	for i := 0; i+1 < len(args); i += 2 {
		name, _ := args[i].(string)
		text = strings.ReplaceAll(text, "{"+name+"}", fmt.Sprint(args[i+1]))
	}
	return text
}

// Subset returns every key with the given prefix, translated to lang with
// English filling the gaps — what the browser-side scripts need.
func (b *Bundle) Subset(lang, prefix string) map[string]string {
	out := map[string]string{}
	for k, v := range b.catalogs[Default] {
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	for k, v := range b.catalogs[lang] {
		if strings.HasPrefix(k, prefix) && v != "" {
			out[k] = v
		}
	}
	return out
}

// Match returns the best available locale for the given preferences, in order
// (each an exact code like "zh-CN" or a bare language like "zh"), or "" when
// none fits. An exact code wins; otherwise the first locale with the same
// language part ("zh-TW" or "zh" can match "zh-CN").
func (b *Bundle) Match(prefs ...string) string {
	for _, p := range prefs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		for _, l := range b.locales {
			if strings.EqualFold(l.Code, p) {
				return l.Code
			}
		}
		base := strings.ToLower(strings.SplitN(strings.ReplaceAll(p, "_", "-"), "-", 2)[0])
		for _, l := range b.locales {
			if strings.ToLower(strings.SplitN(l.Code, "-", 2)[0]) == base {
				return l.Code
			}
		}
	}
	return ""
}

// ParseAcceptLanguage returns the tags of an Accept-Language header, most
// preferred first (q-values honoured, q=0 dropped, "*" ignored).
func ParseAcceptLanguage(header string) []string {
	type tag struct {
		code string
		q    float64
		pos  int
	}
	var tags []tag
	for i, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		code := strings.TrimSpace(fields[0])
		if code == "" || code == "*" {
			continue
		}
		q := 1.0
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if strings.HasPrefix(f, "q=") {
				if _, err := fmt.Sscanf(f[2:], "%g", &q); err != nil {
					q = 0
				}
			}
		}
		if q <= 0 {
			continue
		}
		tags = append(tags, tag{code, q, i})
	}
	sort.SliceStable(tags, func(i, j int) bool { return tags[i].q > tags[j].q })
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = t.code
	}
	return out
}

// Placeholders returns the {name} placeholders in a text, sorted — used to check
// that a translation keeps the same ones as English.
func Placeholders(text string) []string {
	found := placeholderRe.FindAllString(text, -1)
	sort.Strings(found)
	return found
}

// Catalog returns a copy of one locale's raw catalog (nil if unknown).
func (b *Bundle) Catalog(code string) map[string]string {
	cat, ok := b.catalogs[code]
	if !ok {
		return nil
	}
	out := make(map[string]string, len(cat))
	for k, v := range cat {
		out[k] = v
	}
	return out
}

// LoadFallback returns a bundle with an empty English catalog, so T falls back
// to showing keys. Only used if the embedded catalogs cannot be read.
func LoadFallback() (*Bundle, error) {
	return &Bundle{
		catalogs: map[string]map[string]string{Default: {"_meta.name": "English"}},
		locales:  []Locale{{Code: Default, Name: "English"}},
	}, nil
}
