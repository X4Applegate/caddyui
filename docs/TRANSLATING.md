# Translating CaddyUI

CaddyUI's interface can be shown in other languages (since v2.62.0, issue #128). English is the source; every other language is a JSON file of translations. **Adding or updating a language is a data-only change — no Go, template or JavaScript edits.**

## Available languages

| Code | Language | Maintainer |
|---|---|---|
| `en` | English (source) | — |
| `zh-CN` | 简体中文 (Simplified Chinese) | @chongfenglaosiji (since v2.62.1) |

## The catalog files

Catalogs live in [`web/i18n/`](../web/i18n/), one file per language, named by its [BCP 47](https://www.rfc-editor.org/info/bcp47) code:

```
web/i18n/en.json      ← English: the source of truth
web/i18n/zh-CN.json   ← Simplified Chinese
web/i18n/de.json      ← German
```

Each file is a flat JSON object of **key → text**:

```json
{
  "_meta.name": "简体中文",
  "nav.proxy_hosts": "代理主机",
  "page.proxy_hosts.heading": "代理主机",
  "profile.language.saved": "语言已保存。"
}
```

- **`_meta.name`** is the language's own name, shown in the language picker.
- **Keys** are stable dotted names. Copy them exactly from `en.json`; never invent new ones in a translation — the build test rejects keys English does not have.
- **Missing keys fall back to English**, so a catalog can be partial. An empty string also counts as missing. Translate what you can; the rest stays English until it is done.
- **Placeholders** look like `{count}` or `{name}`. Keep every placeholder English uses, spelled the same (you may move them within the sentence). The build test checks this.
- Keys starting with `js.` are also available to the browser-side scripts.
- Text is plain text — no HTML. It is escaped when rendered.

## Choosing the language

- Each person picks a language under **Profile → Language** (or *Use my browser's language*, the default).
- Otherwise the browser's `Accept-Language` decides (`zh-TW` or `zh` will use `zh-CN` if that is the closest available).
- Otherwise the **Settings → General → Default language**, otherwise English.

## Checking your work

```bash
go test ./internal/i18n/ ./internal/server/ -run 'Translation|Catalog|Language|Locale'
```

This loads every catalog and fails if a file is not valid JSON, uses a key English lacks, or changes a placeholder. To see it, run CaddyUI, pick the language on your profile and browse.

## What is translated so far

The plumbing landed in v2.62.0 with English for the navigation, the top bar and its menus, the user menu, the list-page titles, the profile language picker and the default-language setting. More of the interface is moved onto keys release by release — the large proxy-host form last. When new keys appear in `en.json`, a translation simply shows English for them until it is updated.

## Sending a translation

Open a pull request that only adds or edits `web/i18n/<code>.json`. If you maintain a language, mention it in the PR so you can be pinged when new keys appear.
