// SPDX-License-Identifier: Apache-2.0

package i18n

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func testBundle(t *testing.T) *Bundle {
	t.Helper()
	fs := fstest.MapFS{
		"i18n/en.json":    {Data: []byte(`{"_meta.name":"English","nav.home":"Home","x.count":"{count} hosts","js.copied":"Copied","only.en":"English only"}`)},
		"i18n/zh-CN.json": {Data: []byte(`{"_meta.name":"简体中文","nav.home":"首页","x.count":"{count} 个主机","js.copied":"已复制"}`)},
		"i18n/de.json":    {Data: []byte(`{"_meta.name":"Deutsch","nav.home":""}`)},
		"i18n/README.md":  {Data: []byte("not a catalog")},
	}
	b, err := Load(fs, "i18n")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTranslateFallsBackToEnglishThenTheKey(t *testing.T) {
	b := testBundle(t)
	for _, c := range []struct{ lang, key, want string }{
		{"zh-CN", "nav.home", "首页"},
		{"zh-CN", "only.en", "English only"}, // missing in zh-CN → English
		{"de", "nav.home", "Home"},           // empty string counts as missing
		{"xx", "nav.home", "Home"},           // unknown locale → English
		{"en", "no.such.key", "no.such.key"}, // missing everywhere → the key, visible
	} {
		if got := b.T(c.lang, c.key); got != c.want {
			t.Errorf("T(%q,%q) = %q, want %q", c.lang, c.key, got, c.want)
		}
	}
	if got := b.T("zh-CN", "x.count", "count", 3); got != "3 个主机" {
		t.Errorf("placeholder: %q", got)
	}
}

func TestLocalesListsEnglishFirstWithOwnNames(t *testing.T) {
	got := testBundle(t).Locales()
	want := []Locale{{"en", "English"}, {"de", "Deutsch"}, {"zh-CN", "简体中文"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Locales = %v, want %v", got, want)
	}
}

func TestMatchAndAcceptLanguage(t *testing.T) {
	b := testBundle(t)
	for header, want := range map[string]string{
		"zh-CN,zh;q=0.9,en;q=0.8": "zh-CN",
		"zh-TW":                   "zh-CN", // same language part
		"zh":                      "zh-CN",
		"fr-FR,de;q=0.5":          "de",
		"fr-FR":                   "",
		"en;q=0.1, zh-CN;q=0.9":   "zh-CN", // q-values honoured
		"zh-CN;q=0, en":           "en",    // q=0 means "not this"
		"*":                       "",
		"":                        "",
	} {
		if got := b.Match(ParseAcceptLanguage(header)...); got != want {
			t.Errorf("Accept-Language %q → %q, want %q", header, got, want)
		}
	}
}

func TestSubsetMergesEnglishUnderTheLocale(t *testing.T) {
	got := testBundle(t).Subset("zh-CN", "js.")
	if got["js.copied"] != "已复制" || len(got) != 1 {
		t.Errorf("subset = %v", got)
	}
	if testBundle(t).Subset("de", "js.")["js.copied"] != "Copied" {
		t.Error("missing js keys must fall back to English")
	}
}

func TestLoadRequiresEnglishAndValidJSON(t *testing.T) {
	if _, err := Load(fstest.MapFS{"i18n/de.json": {Data: []byte(`{}`)}}, "i18n"); err == nil {
		t.Error("a bundle without en.json loaded")
	}
	if _, err := Load(fstest.MapFS{"i18n/en.json": {Data: []byte(`{not json`)}}, "i18n"); err == nil || !strings.Contains(err.Error(), "en.json") {
		t.Errorf("a broken catalog must be refused naming the file: %v", err)
	}
}

func TestPlaceholders(t *testing.T) {
	if got := Placeholders("{b} and {a} of {count}"); !reflect.DeepEqual(got, []string{"{a}", "{b}", "{count}"}) {
		t.Errorf("Placeholders = %v", got)
	}
}
