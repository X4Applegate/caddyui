// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Caddyfile export safety (issue #184 review). The exporter concatenates
// text from many owners into one file, and Caddy expands {$ENV} across the
// raw file before lexing, so a value that is harmless inside its own block
// can still rewrite a neighbour's. Every emitted block is therefore checked
// with checkCaddyfileSites, which mirrors Caddy's own lexer, and every
// user value written outside a comment goes through caddyfileToken or
// caddyfileBareSafe. Anything that fails is emitted fail-closed.

// errCaddyfileUnsafe is returned by the structural checks below.
var errCaddyfileUnsafe = errors.New("caddyfile text is not self-contained")

// caddyfileEnvRe is the only {$…} form allowed in verbatim text: a plain
// name closed in the same token. Caddy's replaceEnvVars (parse.go) runs over
// the raw file before lexing and pairs each `{$` with the NEXT `}` anywhere
// after it, so an unclosed `{$`, or one whose `}` lies past whitespace,
// swallows whatever text follows — the neighbouring blocks included. A
// closed `{$NAME}` only splices in the value of an environment variable of
// the host that loads the file, and the live route was adapted by Caddy
// with the same substitution. `{$NAME:default}` is refused: the default
// runs to the next `}` too.
var caddyfileEnvRe = regexp.MustCompile(`\{\$[A-Za-z_][A-Za-z0-9_]*\}`)

// caddyfileEnvSafe reports whether every `{$` in src is a closed {$NAME}.
func caddyfileEnvSafe(src string) bool {
	return !strings.Contains(caddyfileEnvRe.ReplaceAllString(src, ""), "{$")
}

// cfSite is one site block found by checkCaddyfileSites.
type cfSite struct {
	addrs []string
}

// checkCaddyfileSites parses src the way Caddy's parser (caddyfile/parse.go)
// splits a file into blocks and returns the sites when src is safe to
// concatenate with other such text:
//   - every `{$` is a closed {$NAME} (see caddyfileEnvRe);
//   - every top-level block is a site: addresses — which end at the end of
//     their line unless it ends with a comma — then `{ … }`. A site without
//     braces would run to the end of the file, and a block without
//     addresses, `(snippet)` or `&(named-route)` is not a site;
//   - braces balance, `{` ends its line and a closing `}` starts its line,
//     as Caddy requires;
//   - `import` as a directive (first token of a line) only names a snippet
//     in imports; Caddy expands imports during parsing.
//
// Lexing is a port of Caddy's own lexer (caddyfile_lexer.go), and
// TestCheckCaddyfileSitesAgreesWithCaddy checks the result against
// `caddy adapt`.
func checkCaddyfileSites(src string, imports map[string]bool) ([]cfSite, error) {
	if !caddyfileEnvSafe(src) {
		return nil, errCaddyfileUnsafe
	}
	toks, err := lexCaddyfile(src)
	if err != nil {
		return nil, err
	}
	open := func(i int) bool { return toks[i].text == "{" && !toks[i].quoted }
	closing := func(i int) bool { return toks[i].text == "}" && !toks[i].quoted }
	var sites []cfSite
	for i := 0; i < len(toks); {
		// addresses (parse.go addresses())
		var site cfSite
		expecting := false
		for {
			t := toks[i]
			if open(i) {
				if expecting {
					return nil, errCaddyfileUnsafe
				}
				break
			}
			v := t.text
			if t.text == "import" && cfIsNewLine(toks, i) || strings.HasPrefix(v, "@") || (!t.quoted && strings.HasSuffix(v, "{")) || closing(i) {
				return nil, errCaddyfileUnsafe
			}
			if v != "" {
				expecting = strings.HasSuffix(v, ",")
				v = strings.TrimSuffix(v, ",")
				if strings.Contains(v, ",") {
					return nil, errCaddyfileUnsafe
				}
				if v != "" {
					site.addrs = append(site.addrs, v)
				}
			}
			i++
			if i >= len(toks) {
				return nil, errCaddyfileUnsafe // addresses with no block
			}
			if !expecting && cfIsNewLine(toks, i) && !open(i) {
				return nil, errCaddyfileUnsafe // a site without braces
			}
		}
		if len(site.addrs) == 0 || strings.HasPrefix(site.addrs[0], "(") || strings.HasPrefix(site.addrs[0], "&(") {
			return nil, errCaddyfileUnsafe
		}
		if i+1 < len(toks) && !cfIsNewLine(toks, i+1) {
			return nil, errCaddyfileUnsafe // `{` must end its line
		}
		// block contents, up to the matching close brace
		depth := 1
		for i++; depth > 0; i++ {
			if i >= len(toks) {
				return nil, errCaddyfileUnsafe
			}
			newLine := cfIsNewLine(toks, i)
			switch {
			case open(i):
				if newLine || (i+1 < len(toks) && !cfIsNewLine(toks, i+1)) {
					return nil, errCaddyfileUnsafe
				}
				depth++
			case closing(i):
				if !newLine {
					return nil, errCaddyfileUnsafe
				}
				depth--
			case toks[i].text == "import" && newLine:
				if i+1 >= len(toks) || cfIsNewLine(toks, i+1) || !imports[toks[i+1].text] {
					return nil, errCaddyfileUnsafe
				}
			}
		}
		sites = append(sites, site)
	}
	return sites, nil
}

// caddyfileSimpleShorthands and caddyfileComplexShorthands mirror the
// placeholder shorthands Caddy's HTTP Caddyfile adapter rewrites in every
// token (caddyconfig/httpcaddyfile/shorthands.go, v2.11). The JSON route
// carries values verbatim, so a value containing one of these would mean
// something different once exported.
var caddyfileSimpleShorthands = []string{
	"{host}", "{hostport}", "{port}", "{orig_method}", "{orig_uri}", "{orig_path}",
	"{orig_dir}", "{orig_file}", "{orig_query}", "{orig_?query}", "{method}", "{uri}",
	"{%uri}", "{path}", "{%path}", "{dir}", "{file}", "{query}", "{%query}", "{?query}",
	"{remote}", "{remote_host}", "{remote_port}", "{scheme}", "{uuid}", "{tls_cipher}",
	"{tls_version}", "{tls_client_fingerprint}", "{tls_client_issuer}", "{tls_client_serial}",
	"{tls_client_subject}", "{tls_client_certificate_pem}", "{tls_client_certificate_der_base64}",
	"{upstream_hostport}", "{client_ip}",
}

var caddyfileComplexShorthands = regexp.MustCompile(`{(header|cookie|labels|path|file|query|vars|file_match)\.[\w-]*}|{(re|rp|resp|err)\.[\w-.]*}`)

// caddyfileRewritesValue reports whether Caddy would not read s back
// verbatim from a Caddyfile token: {$ENV} expansion or a placeholder
// shorthand. Regexp syntax such as \p{L}, {2,3} or \{host\} is untouched.
func caddyfileRewritesValue(s string) bool {
	return caddyfileRewriteIn(s) != ""
}

// caddyfileRewriteIn names what in s the Caddyfile adapter would rewrite —
// "$" for {$ENV} expansion, else the placeholder shorthand without its
// braces — or returns "".
func caddyfileRewriteIn(s string) string {
	if strings.Contains(s, "{$") {
		return "$"
	}
	if m := caddyfileComplexShorthands.FindString(s); m != "" {
		return strings.Trim(m, "{}")
	}
	for _, sh := range caddyfileSimpleShorthands {
		if strings.Contains(s, sh) {
			return strings.Trim(sh, "{}")
		}
	}
	return ""
}

// caddyfileTokenProblem explains why s has no faithful Caddyfile token, in
// words fit for the comment of a fail-closed site, or returns "".
func caddyfileTokenProblem(s string) string {
	switch {
	case s == "":
		return "is empty"
	case !utf8.ValidString(s):
		return "is not valid UTF-8"
	}
	switch rw := caddyfileRewriteIn(s); rw {
	case "":
	case "$":
		return "contains an environment reference ($…), which Caddy would expand while loading the Caddyfile but the live route keeps as text"
	default:
		return "contains the placeholder shorthand " + rw + ", which a Caddyfile expands but the live route passes through literally — write the full placeholder (http.request.…) in CaddyUI to export it"
	}
	for _, r := range s {
		switch {
		case r == '`':
			return "contains a backtick, which no Caddyfile token can hold unchanged"
		case unicode.IsControl(r), r == '\u2028', r == '\u2029':
			return "contains a line break or control character"
		}
	}
	return ""
}

// caddyfileToken renders s as one Caddyfile token whose value Caddy reads
// back unchanged. Plain text is left bare; anything else is wrapped in
// backticks, which the lexer takes literally up to the next backtick. ok is
// false — and the caller must fail closed — when caddyfileTokenProblem
// finds a reason; backslash escaping is deliberately never attempted.
func caddyfileToken(s string) (string, bool) {
	if caddyfileTokenProblem(s) != "" {
		return "", false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("/.-_*^$()[]|+?:~!%&=,;", r):
		default:
			return "`" + s + "`", true
		}
	}
	return s, true
}

// caddyfileBareSafe reports whether every value can be written as one
// unquoted Caddyfile token that Caddy reads back unchanged: no whitespace,
// control characters or backslashes (which split or escape), nothing the
// adapter rewrites, and no token-initial `"`, backtick, `#`, `@`, `<<` or a
// lone brace, which open a quote, comment, matcher, heredoc or block.
func caddyfileBareSafe(values ...string) bool {
	for _, s := range values {
		if s == "" || !utf8.ValidString(s) || s == "{" || s == "}" ||
			strings.ContainsAny(s[:1], "\"`#@") || strings.HasPrefix(s, "<<") ||
			strings.ContainsRune(s, '\\') || caddyfileRewritesValue(s) {
			return false
		}
		for _, r := range s {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
				return false
			}
		}
	}
	return true
}

// caddyfileAddressSafe is caddyfileBareSafe for site addresses, which also
// must not start with `(` or `&(` — that would define a snippet or a named
// route instead of a site — nor be `import`, hold a brace (a token ending
// in `{` opens the block early) or a comma (which splits the address).
// Every caller writes these addresses at least into the fail-closed
// stand-in, so that stand-in must itself parse as exactly one site with
// exactly these addresses; otherwise one bad host would break the export.
func caddyfileAddressSafe(values ...string) bool {
	if len(values) == 0 {
		return false
	}
	for _, s := range values {
		if !caddyfileBareSafe(s) || strings.HasPrefix(s, "(") || strings.HasPrefix(s, "&") ||
			s == "import" || strings.ContainsAny(s, "{},") {
			return false
		}
	}
	sites, err := checkCaddyfileSites(strings.Join(values, ", ")+" {\n\trespond 503\n}\n", nil)
	return err == nil && len(sites) == 1 && slices.Equal(sites[0].addrs, values)
}

// caddyfileHeaderNameRe is an RFC 9110 field name that starts with a letter
// or digit, so it cannot be read as a matcher (`@`, `/`, `*`) or as one of
// the header directive's operation prefixes (`+`, `-`, `?`, `>`).
var caddyfileHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$%&'*+.^_|~-]*$`)

// caddyfileWordRe matches the fixed keywords CaddyUI stores for options such
// as the load-balancing policy and the client-auth mode.
var caddyfileWordRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// caddyfileComment makes s safe inside a `#` comment line: anything that
// could end the line becomes a space, and braces become parentheses so the
// comment can never hold `{$`, which Caddy expands before it sees comments.
func caddyfileComment(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), r == '\u2028', r == '\u2029':
			return ' '
		case r == '{':
			return '('
		case r == '}':
			return ')'
		}
		return r
	}, s)
}

// caddyfileDirectiveOrder is Caddy v2.11's default HTTP handler directive
// order (caddyconfig/httpcaddyfile/directives.go).
var caddyfileDirectiveOrder = []string{
	"tracing", "map", "vars", "fs", "root", "log_append", "skip_log", "log_skip", "log_name", "log_level",
	"header", "copy_response_headers", "request_body", "timeouts", "redir", "method", "rewrite", "uri",
	"try_files", "basicauth", "basic_auth", "forward_auth", "request_header", "encode", "push",
	"intercept", "templates", "invoke", "handle", "handle_path", "route", "abort", "error",
	"copy_response", "respond", "metrics", "reverse_proxy", "php_fastcgi", "file_server", "acme_server",
}

// caddyfileSiteOnlyDirectives configure the site rather than add handlers,
// so their position does not matter and they cannot go inside `route`.
var caddyfileSiteOnlyDirectives = map[string]bool{"tls": true, "bind": true, "log": true}

// splitAdvancedForRoute splits an Advanced config into the lines that must
// stay at site level (tls/bind/log) and the lines that can be moved inside
// a `route { }` block without changing their order. ok is false when moving
// them would change behaviour: inside `route` directives run as written,
// while the JSON route ran them in Caddy's sorted order
// (httpcaddyfile/directives.go sortRoutes). That order is the literal order
// when the handler directives are known and in non-decreasing directive
// order, and repeats of one directive carry no matcher — Caddy's stable
// sort only reorders same-name directives by their matchers.
func splitAdvancedForRoute(src string) (site, inRoute string, ok bool) {
	toks, err := lexCaddyfile(src)
	if err != nil {
		return "", "", false
	}
	lines := strings.Split(src, "\n")
	type segment struct {
		name       string
		startLine  int
		hasMatcher bool
	}
	var segs []segment
	depth := 0
	for i, t := range toks {
		if depth == 0 && cfIsNewLine(toks, i) && !(t.text == "}" && !t.quoted) {
			sg := segment{name: t.text, startLine: t.line}
			if i+1 < len(toks) && !cfIsNewLine(toks, i+1) {
				arg := toks[i+1].text
				sg.hasMatcher = strings.HasPrefix(arg, "@") || strings.HasPrefix(arg, "/") || arg == "*"
			}
			segs = append(segs, sg)
		}
		if !t.quoted && t.text == "{" {
			depth++
		} else if !t.quoted && t.text == "}" {
			if depth == 0 {
				return "", "", false
			}
			depth--
		}
	}
	if depth != 0 {
		return "", "", false
	}
	order := map[string]int{}
	for i, d := range caddyfileDirectiveOrder {
		order[d] = i
	}
	var siteB, routeB strings.Builder
	last, lastHadMatcher := -1, false
	for i, sg := range segs {
		end := len(lines)
		if i+1 < len(segs) {
			end = segs[i+1].startLine - 1
		}
		text := strings.Join(lines[sg.startLine-1:end], "\n") + "\n"
		switch idx, known := order[sg.name]; {
		case strings.HasPrefix(sg.name, "@"):
			routeB.WriteString(text) // matcher definition
		case caddyfileSiteOnlyDirectives[sg.name]:
			siteB.WriteString(text)
		case !known || idx < last || (idx == last && (sg.hasMatcher || lastHadMatcher)):
			return "", "", false
		default:
			last, lastHadMatcher = idx, sg.hasMatcher
			routeB.WriteString(text)
		}
	}
	return siteB.String(), routeB.String(), true
}

// ExportOptions carries what only the server knows to the Caddyfile
// renderers. The zero value is the strictest: no snippet imports, nothing
// treated as tenant-owned, no extra raw-route checks.
type ExportOptions struct {
	// Snippets are the `(name) { … }` blocks from the server's Caddyfile
	// (CADDYFILE_PATH, issue #119). Those that pass checkCaddyfileSnippet
	// may be imported by admin-owned content.
	Snippets []string
	// IncludeSnippets writes the definitions of the snippets the exported
	// text imports, so the file is complete. Set it only when the export
	// is for an administrator: snippets are the administrator's and may
	// hold anything. Without it, an import of a snippet cannot be kept.
	IncludeSnippets bool
	// TenantOwned reports whether a resource belongs to a non-admin. Such
	// content never keeps an `import`, even of a known snippet.
	TenantOwned func(owner sql.NullInt64) bool
	// RawRouteVeto returns why a tenant-owned raw route's Caddyfile must
	// not be exported (for example, it does not adapt to its stored
	// routes, or adapts to more than routes), or "". It is consulted only
	// for content TenantOwned reports as a tenant's.
	RawRouteVeto func(models.RawRoute) string
	// ProxyHostVeto is RawRouteVeto for a tenant-owned proxy host's
	// Advanced config; it is consulted only when that config is not empty.
	ProxyHostVeto func(models.ProxyHost) string
}

// tenant reports whether content owned by owner is a tenant's.
func (o ExportOptions) tenant(owner sql.NullInt64) bool {
	return o.TenantOwned != nil && o.TenantOwned(owner)
}

// snippetNameRe is the snippet name form CaddyUI accepts in `import`.
var snippetNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// validSnippets returns the snippets that are one self-contained
// `(name) { … }` block with no import and no unsafe {$, keyed by name.
func (o ExportOptions) validSnippets() (map[string]string, []string) {
	byName := map[string]string{}
	var order []string
	for _, snip := range o.Snippets {
		name, ok := checkCaddyfileSnippet(snip)
		if !ok || byName[name] != "" {
			continue
		}
		byName[name] = strings.TrimSpace(snip)
		order = append(order, name)
	}
	return byName, order
}

// importsFor is the snippet-name set content owned by owner may import:
// none for a tenant, and none unless the export carries the definitions.
func (o ExportOptions) importsFor(owner sql.NullInt64) map[string]bool {
	if o.tenant(owner) || !o.IncludeSnippets {
		return nil
	}
	byName, _ := o.validSnippets()
	out := make(map[string]bool, len(byName))
	for n := range byName {
		out[n] = true
	}
	return out
}

// checkCaddyfileSnippet reports the name of a snippet that is exactly one
// `(name) { … }` block obeying the same rules as checkCaddyfileSites, with
// no import inside.
func checkCaddyfileSnippet(src string) (string, bool) {
	toks, err := lexCaddyfile(src)
	if err != nil || len(toks) < 3 || !caddyfileEnvSafe(src) {
		return "", false
	}
	head := toks[0].text
	if toks[0].quoted || !strings.HasPrefix(head, "(") || !strings.HasSuffix(head, ")") || !snippetNameRe.MatchString(head[1:len(head)-1]) {
		return "", false
	}
	site := "snippet.invalid " + src[strings.Index(src, head)+len(head):]
	sites, err := checkCaddyfileSites(site, nil)
	if err != nil || len(sites) != 1 || len(sites[0].addrs) != 1 {
		return "", false
	}
	return head[1 : len(head)-1], true
}

// withSnippetDefinitions prepends to body the definitions of the snippets
// its `import` lines name — and of those the snippets themselves import —
// when the export carries snippets. Only snippets body actually uses are
// written: the others may hold anything the administrator put there.
func (o ExportOptions) withSnippetDefinitions(body string) string {
	if !o.IncludeSnippets {
		return body
	}
	byName, order := o.validSnippets()
	used := map[string]bool{}
	for pending := []string{body}; len(pending) > 0; {
		src := pending[0]
		pending = pending[1:]
		for _, name := range caddyfileImportedNames(src) {
			if byName[name] != "" && !used[name] {
				used[name] = true
				pending = append(pending, byName[name])
			}
		}
	}
	if len(used) == 0 {
		return body
	}
	var b strings.Builder
	b.WriteString("# Snippets from the server Caddyfile, for the `import` lines below.\n")
	for _, name := range order {
		if used[name] {
			b.WriteString(byName[name])
			b.WriteString("\n\n")
		}
	}
	b.WriteString(body)
	return b.String()
}

// caddyfileImportedNames returns the argument of every `import` directive
// (the first token of a line) in src.
func caddyfileImportedNames(src string) []string {
	toks, err := lexCaddyfile(src)
	if err != nil {
		return nil
	}
	var names []string
	for i, t := range toks {
		if t.text == "import" && !t.quoted && cfIsNewLine(toks, i) && i+1 < len(toks) && !cfIsNewLine(toks, i+1) {
			names = append(names, toks[i+1].text)
		}
	}
	return names
}

// importProblem explains why the `import` directives in src, owned by
// owner, cannot be kept, or returns "".
func (o ExportOptions) importProblem(src string, owner sql.NullInt64) string {
	allowed := o.importsFor(owner)
	if !o.tenant(owner) && !o.IncludeSnippets {
		byName, _ := o.validSnippets()
		for _, name := range caddyfileImportedNames(src) {
			if byName[name] != "" {
				return "it imports snippet " + name + ", whose definition only an administrator's export includes"
			}
		}
	}
	return caddyfileImportProblem(src, allowed, o.tenant(owner))
}

// caddyfileImportProblem explains why the `import` directives in src cannot
// be kept, or returns "".
func caddyfileImportProblem(src string, allowed map[string]bool, tenant bool) string {
	toks, err := lexCaddyfile(src)
	if err != nil {
		return ""
	}
	for i, t := range toks {
		if t.text != "import" || !cfIsNewLine(toks, i) {
			continue
		}
		name := ""
		if i+1 < len(toks) && !cfIsNewLine(toks, i+1) {
			name = toks[i+1].text
		}
		switch {
		case allowed[name]:
		case tenant:
			return "it imports " + caddyfileComment(name) + "; imports are kept only for admin-owned hosts"
		case snippetNameRe.MatchString(name):
			return "it imports snippet " + name + ", which is not a self-contained snippet in the server Caddyfile (CADDYFILE_PATH)"
		default:
			return "it imports " + caddyfileComment(name) + ", which is not a snippet; file imports are never exported"
		}
	}
	return ""
}

// rawRouteTextProblem ties a raw route's verbatim Caddyfile to its stored
// JSON: every site address must name a host the stored routes match (or,
// for an address without a host, the stored routes must match no host and
// its port must be one of the route's own listeners), on a standard port or
// one of the route's listeners. Otherwise the text could claim another
// host's traffic or open a new listener while the live config does not.
func rawRouteTextProblem(r models.RawRoute, sites []cfSite) string {
	hosts, hostless, ok := rawRouteJSONHosts(r.JSONData)
	if !ok {
		return "its stored routes could not be read"
	}
	ports := map[string]bool{"": true, "80": true, "443": true}
	listenPorts := map[string]bool{}
	for _, a := range r.ListenAddrs() {
		if i := strings.LastIndex(a, ":"); i >= 0 {
			ports[a[i+1:]] = true
			listenPorts[a[i+1:]] = true
		}
	}
	for _, s := range sites {
		for _, a := range s.addrs {
			host, port, ok := caddyfileAddressHostPort(a)
			switch {
			case !ok:
				return "site address " + caddyfileComment(a) + " could not be understood"
			case !ports[port]:
				return "site address " + caddyfileComment(a) + " uses a port the route does not listen on"
			case host == "" && !(hostless && listenPorts[port]):
				return "site address " + caddyfileComment(a) + " has no host, but the stored routes do not match every host on that listener"
			case host != "" && !hosts[host]:
				return "site address " + caddyfileComment(a) + " names a host the stored routes do not match"
			}
		}
	}
	return ""
}

// rawRouteJSONHosts returns the lower-cased hosts matched by the top-level
// routes of a raw route's JSON, and whether every route matches any host.
func rawRouteJSONHosts(jsonData string) (hosts map[string]bool, allHostless bool, ok bool) {
	var decoded any
	if err := json.Unmarshal([]byte(jsonData), &decoded); err != nil {
		return nil, false, false
	}
	var routes []any
	switch v := decoded.(type) {
	case []any:
		routes = v
	case map[string]any:
		routes = []any{v}
	default:
		return nil, false, false
	}
	hosts = map[string]bool{}
	allHostless = len(routes) > 0
	for _, rt := range routes {
		m, _ := rt.(map[string]any)
		sets, _ := m["match"].([]any)
		routeHasHost := false
		for _, set := range sets {
			sm, _ := set.(map[string]any)
			hs, _ := sm["host"].([]any)
			for _, h := range hs {
				if hs, ok := h.(string); ok {
					hosts[strings.ToLower(hs)] = true
					routeHasHost = true
				}
			}
		}
		if routeHasHost {
			allHostless = false
		}
	}
	return hosts, allHostless, true
}

// caddyfileAddressHostPort splits a site address into its lower-cased host
// and port; ok is false for forms this check does not model.
func caddyfileAddressHostPort(addr string) (host, port string, ok bool) {
	a := strings.ToLower(addr)
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(a, scheme) {
			a = a[len(scheme):]
			if scheme == "http://" {
				port = "80"
			}
			break
		}
	}
	if strings.Contains(a, "://") {
		return "", "", false
	}
	if i := strings.Index(a, "/"); i >= 0 {
		a = a[:i]
	}
	if strings.HasPrefix(a, "[") {
		end := strings.Index(a, "]")
		if end < 0 {
			return "", "", false
		}
		host, a = a[1:end], a[end+1:]
		if a != "" {
			if !strings.HasPrefix(a, ":") {
				return "", "", false
			}
			port = a[1:]
		}
	} else if i := strings.LastIndex(a, ":"); i >= 0 {
		host, port = a[:i], a[i+1:]
	} else {
		host = a
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}
	return host, port, true
}
