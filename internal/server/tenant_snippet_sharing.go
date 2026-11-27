// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Which of the administrator's snippets non-admin accounts may import.
//
// Up to v2.68.17 every snippet in the server Caddyfile (CADDYFILE_PATH) that
// passed the #184 rules was available to non-admin accounts. A snippet is
// pasted into the text Caddy adapts for them, and what it adapts to is
// stored in their route and shown back to them, so whatever it holds — a
// basic_auth hash, an API key in a header, an internal upstream — was theirs
// to read and to use. A snippet is now shared with non-admin accounts only
// when the administrator says so:
//
//   - CADDYFILE_TENANT_SNIPPETS, when set, is the list (names separated by
//     commas or spaces; "*" shares every snippet; "none", or an empty value,
//     shares none);
//   - otherwise the list stored in the tenant_snippets_shared setting. On
//     the first start of a version with this rule, that setting is seeded
//     with the snippets non-admin accounts' stored text already imports, so
//     nothing that works stops working; any other snippet, and any snippet
//     added later, is the administrator's alone.
//
// A snippet that is not shared is Withheld (tenant_guard.go): it is left
// out of the text adapted for a non-admin, an `import` of it is refused
// with the same words as for a name that does not exist, and a snippet
// that imports it is withheld too.

// envTenantSnippets names the environment variable.
const envTenantSnippets = "CADDYFILE_TENANT_SNIPPETS"

// settingTenantSnippetsShared is where the seeded list is kept.
const settingTenantSnippetsShared = "tenant_snippets_shared"

// tenantSnippetPolicy is which snippets are shared. The zero value — no
// policy loaded, which only a Server built without New has — shares every
// snippet, as before this rule.
type tenantSnippetPolicy struct {
	loaded bool
	all    bool
	names  map[string]bool
}

func (p tenantSnippetPolicy) shares(name string) bool {
	return !p.loaded || p.all || p.names[name]
}

// parseTenantSnippetList reads a list in the CADDYFILE_TENANT_SNIPPETS form.
func parseTenantSnippetList(v string) tenantSnippetPolicy {
	p := tenantSnippetPolicy{loaded: true, names: map[string]bool{}}
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		switch f {
		case "*":
			p.all = true
		case "none":
		default:
			p.names[f] = true
		}
	}
	return p
}

func (p tenantSnippetPolicy) String() string {
	if p.all {
		return "*"
	}
	if len(p.names) == 0 {
		return "none"
	}
	out := make([]string, 0, len(p.names))
	for n := range p.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// loadTenantSnippetPolicy decides the policy at start-up (see above).
// caddyfilePath is the server Caddyfile, whose snippets the seed follows:
// a seeded snippet that imports another needs that one shared too.
func loadTenantSnippetPolicy(db *sql.DB, caddyfilePath string) tenantSnippetPolicy {
	if v, ok := os.LookupEnv(envTenantSnippets); ok {
		p := parseTenantSnippetList(v)
		log.Printf("caddyfile snippets: shared with non-admin accounts (%s): %s", envTenantSnippets, p)
		return p
	}
	if db == nil {
		return parseTenantSnippetList("")
	}
	var stored string
	err := db.QueryRow("SELECT value FROM settings WHERE `key` = ?", settingTenantSnippetsShared).Scan(&stored)
	if err == nil {
		return parseTenantSnippetList(stored)
	}
	if err != sql.ErrNoRows {
		log.Printf("caddyfile snippets: could not read %s, so no snippet is shared with non-admin accounts: %v", settingTenantSnippetsShared, err)
		return parseTenantSnippetList("")
	}
	imported, err := tenantImportedNames(db)
	if err != nil {
		// Not stored: the seed is taken again at the next start.
		log.Printf("caddyfile snippets: could not read which snippets non-admin accounts import, so none is shared until the next start: %v", err)
		return parseTenantSnippetList("")
	}
	p := tenantSnippetPolicy{loaded: true, names: withSnippetImports(imported, caddyfilePath)}
	if err := models.SetSetting(db, settingTenantSnippetsShared, p.String()); err != nil {
		log.Printf("caddyfile snippets: could not store %s: %v", settingTenantSnippetsShared, err)
	}
	log.Printf("caddyfile snippets: shared with non-admin accounts, the ones their routes already import: %s (set %s to change)", p, envTenantSnippets)
	return p
}

// tenantImportedNames is every name non-admin accounts' stored Caddyfile
// text — Advanced routes and proxy hosts' Advanced configs — imports.
func tenantImportedNames(db *sql.DB) (map[string]bool, error) {
	names := map[string]bool{}
	admins := map[int64]bool{}
	rows, err := db.Query(`SELECT id FROM users WHERE COALESCE(role, CASE WHEN is_admin=1 THEN 'admin' ELSE 'view' END) = ? OR is_admin = 1`, models.RoleAdmin)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		admins[id] = true
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	collect := func(query string) error {
		rows, err := db.Query(query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var owner int64
			var text string
			if err := rows.Scan(&owner, &text); err != nil {
				return err
			}
			if admins[owner] {
				continue
			}
			args, _ := caddy.CaddyfileImportArguments(text)
			for _, a := range args {
				names[a] = true
			}
		}
		return rows.Err()
	}
	if err := collect(`SELECT owner_id, COALESCE(caddyfile_src, '') FROM raw_routes WHERE owner_id IS NOT NULL AND COALESCE(caddyfile_src, '') <> ''`); err != nil {
		return nil, err
	}
	if err := collect(`SELECT owner_id, COALESCE(advanced_config, '') FROM proxy_hosts WHERE owner_id IS NOT NULL AND COALESCE(advanced_config, '') <> ''`); err != nil {
		return nil, err
	}
	return names, nil
}

// withSnippetImports keeps of names those the server Caddyfile defines as
// snippets, and adds every snippet those import, directly or in turn. When
// the Caddyfile cannot be read, names are kept as they are.
func withSnippetImports(names map[string]bool, caddyfilePath string) map[string]bool {
	if caddyfilePath == "" {
		return names
	}
	b, err := os.ReadFile(caddyfilePath)
	if err != nil {
		return names
	}
	imports := map[string][]string{}
	for _, sn := range caddy.CaddyfileSnippets(string(b)) {
		imports[sn.Name] = append(imports[sn.Name], "")
		for _, imp := range sn.Imports {
			imports[sn.Name] = append(imports[sn.Name], imp.Name)
		}
	}
	// Only names the server Caddyfile defines: a name that is not a
	// snippet now must not become one that is shared later.
	for n := range names {
		if _, ok := imports[n]; !ok {
			delete(names, n)
		}
	}
	pending := make([]string, 0, len(names))
	for n := range names {
		pending = append(pending, n)
	}
	for len(pending) > 0 {
		n := pending[0]
		pending = pending[1:]
		for _, m := range imports[n] {
			if m != "" && !names[m] {
				names[m] = true
				pending = append(pending, m)
			}
		}
	}
	return names
}
