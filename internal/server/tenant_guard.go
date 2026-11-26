// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Tenant route guard (v2.57.1).
//
// Resources owned by a NON-ADMIN account (owner_id set: customer accounts and
// access-group members) become Caddy routes that run with the full power of
// the Caddy process. Earlier fixes guarded individual save paths for individual
// fields (the proxy host upstream guard of GHSA-r4wm-rgc5-q834), and each audit
// since has found another path or field that missed it. This guard instead
// inspects the FINAL Caddy route that CaddyUI generates, which is where every
// path — UI forms, REST API, imports, the AI tool, clone, fleet copies of a
// row — and every field — upstreams, Host overrides, forward-proxy and
// forward-auth URLs, additional upstream rules, redirection and Advanced-route
// JSON — ends up. It is used two ways:
//
//   - at save time, to refuse a route with a clear message (tenantRouteViolation);
//   - at sync time, as enforcement for rows already stored or saved by a path
//     that forgot to check (sanitizeTenantRoute): the route is neutralised or
//     skipped, so a bad row can never reach the live config.
//
// Admin-owned (global) rows are never restricted: admins are trusted.

// dangerousPlaceholderRe matches the Caddy placeholders that read from the
// Caddy PROCESS rather than the request: {env.NAME} (any environment variable,
// where the shipped compose puts the DNS API token), {file.<path>} (any file
// the Caddy container can read, including its certificate storage), and the
// Caddyfile adapt-time {$NAME}. Verified against Caddy 2.11: a response header
// or body of "{env.SECRET}" is expanded at request time and served to whoever
// requests the route.
var dangerousPlaceholderRe = regexp.MustCompile(`(?i)\{\s*(?:env|file)\s*\.|\{\s*\$`)

// neutralisedPlaceholderRe is dangerousPlaceholderRe's runtime form: it is
// replaced rather than rejected when sanitising a stored route.
var neutralisedPlaceholderRe = regexp.MustCompile(`(?i)\{(\s*)(env|file)(\s*)\.`)

func containsDangerousPlaceholder(s string) bool { return dangerousPlaceholderRe.MatchString(s) }

// forbiddenTenantHandlers are Caddy handlers a non-admin may never use: they
// read files from the Caddy container (file_server, templates), or run an ACME
// CA (acme_server).
var forbiddenTenantHandlers = map[string]bool{
	"file_server": true,
	"templates":   true,
	"acme_server": true,
}

// obscureIPHostRe matches host spellings that some resolvers read as an IPv4
// address but net.ParseIP does not: bare integers (2130706433) and hex forms.
var obscureIPHostRe = regexp.MustCompile(`^(?:0x[0-9a-f.]+|[0-9]+)$`)

// extraBlockedIPs are cloud metadata / management endpoints that are not in
// the link-local range ipBlockedForNonAdmin already covers.
var extraBlockedIPs = []net.IP{
	net.ParseIP("100.100.100.200"), // Alibaba Cloud metadata
	net.ParseIP("192.0.0.192"),     // Oracle Cloud metadata
	net.ParseIP("168.63.129.16"),   // Azure WireServer
	net.ParseIP("fd00:ec2::254"),   // AWS IMDS over IPv6
}

func extraBlockedIP(ip net.IP) bool {
	for _, b := range extraBlockedIPs {
		if b.Equal(ip) {
			return true
		}
	}
	return false
}

// adminHostSet returns the hostnames of every Caddy admin endpoint CaddyUI
// knows about — the primary client and every registered fleet node — so a
// tenant cannot aim a route at ANY node's admin API, not just the primary's.
func (s *Server) adminHostSet() map[string]bool {
	out := map[string]bool{}
	if s == nil {
		return out
	}
	add := func(adminURL string) {
		if h := strings.ToLower(adminHostFromURL(adminURL)); h != "" {
			out[h] = true
		}
	}
	if s.Caddy != nil {
		add(s.Caddy.AdminURL)
	}
	if s.DB != nil {
		if servers, err := models.ListCaddyServers(s.DB); err == nil {
			for _, srv := range servers {
				add(srv.AdminURL)
			}
		}
	}
	return out
}

// dialBlockedForTenant reports why a Caddy dial/host string may not be used by
// a non-admin, or "" when it may. dial may be "host", "host:port",
// "tcp/host:port", a URL, or something stranger; anything that cannot be
// understood as a plain network address is refused.
func dialBlockedForTenant(dial string, adminHosts map[string]bool) string {
	d := strings.TrimSpace(dial)
	if d == "" {
		return ""
	}
	if strings.ContainsAny(d, "{}") {
		return "placeholders cannot be used in an upstream address"
	}
	if i := strings.Index(d, "://"); i >= 0 {
		u, err := url.Parse(d)
		if err != nil || u.Hostname() == "" {
			return "unreadable upstream address"
		}
		d = u.Host
	} else if i := strings.Index(d, "/"); i >= 0 {
		// Caddy network prefix: "tcp/host:port", "unix//path/to.sock".
		network := strings.ToLower(d[:i])
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return fmt.Sprintf("network %q is not allowed for an upstream", network)
		}
		d = d[i+1:]
	}
	host := strings.ToLower(hostFromUpstream(d))
	if host == "" {
		return ""
	}
	if obscureIPHostRe.MatchString(host) {
		return "numeric-only host names are not allowed"
	}
	if ip := net.ParseIP(host); ip != nil && extraBlockedIP(ip) {
		return "cloud metadata and management addresses are not allowed"
	}
	if upstreamHostBlockedForNonAdminSet(host, adminHosts) {
		return "loopback, link-local, and internal management addresses (such as the Caddy admin API) are not allowed"
	}
	return ""
}

// tenantRouteViolation returns why a generated Caddy route owned by a
// non-admin must not be deployed, or "" when it is fine. It walks the whole
// route, including nested subroutes and handle_response routes.
func (s *Server) tenantRouteViolation(route any) string {
	adminHosts := s.adminHostSet()
	var reason string
	var walk func(v any)
	walk = func(v any) {
		if reason != "" {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if h, _ := t["handler"].(string); h != "" {
				if forbiddenTenantHandlers[h] {
					reason = fmt.Sprintf("the %q handler can read files from the Caddy server and is admin-only", h)
					return
				}
				if h == "reverse_proxy" {
					reason = reverseProxyViolation(t, adminHosts)
					if reason != "" {
						return
					}
				}
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		case []map[string]any:
			for _, child := range t {
				walk(child)
			}
		case string:
			if containsDangerousPlaceholder(t) {
				reason = "{env.…}, {file.…} and {$…} placeholders read the Caddy server's environment and files and are admin-only"
			}
		}
	}
	walk(route)
	return reason
}

// reverseProxyViolation checks one reverse_proxy handler: every dial, the Host
// header it sets, dynamic upstream discovery, and an upstream forward proxy.
func reverseProxyViolation(h map[string]any, adminHosts map[string]bool) string {
	if _, ok := h["dynamic_upstreams"]; ok {
		return "dynamic upstreams are admin-only"
	}
	check := func(dial string) string {
		if why := dialBlockedForTenant(dial, adminHosts); why != "" {
			return fmt.Sprintf("upstream %q: %s", dial, why)
		}
		return ""
	}
	for _, up := range asAnySlice(h["upstreams"]) {
		if m, ok := up.(map[string]any); ok {
			if dial, _ := m["dial"].(string); dial != "" {
				if why := check(dial); why != "" {
					return why
				}
			}
		}
	}
	if headers, ok := h["headers"].(map[string]any); ok {
		if req, ok := headers["request"].(map[string]any); ok {
			if set, ok := req["set"].(map[string]any); ok {
				for k, v := range set {
					if strings.EqualFold(k, "Host") {
						for _, hv := range asAnySlice(v) {
							if sv, _ := hv.(string); sv != "" {
								if why := check(sv); why != "" {
									return "Host override " + why
								}
							}
						}
					}
				}
			}
		}
	}
	if tr, ok := h["transport"].(map[string]any); ok {
		if np, ok := tr["network_proxy"].(map[string]any); ok {
			if u, _ := np["url"].(string); u != "" {
				if why := check(u); why != "" {
					return "forward proxy " + why
				}
			}
		}
	}
	return ""
}

func asAnySlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	case []map[string]any:
		out := make([]any, len(t))
		for i, m := range t {
			out[i] = m
		}
		return out
	}
	return nil
}

// neutraliseTenantPlaceholders rewrites {env.X} / {file.X} inside every string
// of v (in place, for maps and slices) to a form Caddy leaves as literal text.
// It reports whether anything changed.
func neutraliseTenantPlaceholders(v any) (any, bool) {
	changed := false
	var rec func(x any) any
	rec = func(x any) any {
		switch t := x.(type) {
		case string:
			if neutralisedPlaceholderRe.MatchString(t) {
				changed = true
				return neutralisedPlaceholderRe.ReplaceAllString(t, "{blocked-$2.")
			}
			return t
		case map[string]any:
			for k, child := range t {
				t[k] = rec(child)
			}
			return t
		case []any:
			for i, child := range t {
				t[i] = rec(child)
			}
			return t
		case []map[string]any:
			for i, child := range t {
				rec(child)
				t[i] = child
			}
			return t
		}
		return x
	}
	return rec(v), changed
}

// isTenantOwner reports whether a row's owner is a NON-admin account — the only
// owners the tenant guard restricts. An empty owner (global, admin-managed) is
// trusted; so is a row owned by an administrator's own user id, which some paths
// create (the JSON import assigns the importing user). A row owned by a user
// that no longer exists is treated as a tenant: restricting it is the safe
// reading of "we cannot tell".
func (s *Server) isTenantOwner(owner sql.NullInt64) bool {
	if !owner.Valid {
		return false
	}
	if s == nil || s.DB == nil {
		return true
	}
	u, err := models.GetUserByID(s.DB, owner.Int64)
	if err != nil || u == nil {
		return true
	}
	return !isAdminUser(u)
}

// sanitizeTenantRoute is the sync-time enforcement. For a row owned by a
// non-admin (owner.Valid) it neutralises process-reading placeholders and
// refuses a route that fails tenantRouteViolation; admin-owned rows pass
// through untouched. ok=false means: do not deploy this route.
func (s *Server) sanitizeTenantRoute(owner sql.NullInt64, what string, route any) (any, bool) {
	if route == nil || !s.isTenantOwner(owner) {
		return route, true
	}
	route, changed := neutraliseTenantPlaceholders(route)
	if changed {
		log.Printf("caddy sync: %s: neutralised {env.…}/{file.…} placeholders in a non-admin-owned route", what)
	}
	if why := s.tenantRouteViolation(route); why != "" {
		// why is derived from the route, which carries header and API-key
		// values, so it is not written to the log; the owner sees the full
		// reason as a form error when saving the resource.
		log.Printf("caddy sync: %s: route skipped, not allowed for a non-admin owner", what)
		return nil, false
	}
	return route, true
}

// tenantMaxNestingDepth is how deeply a non-admin's own Caddyfile text (an
// Advanced route's source, a proxy host's Advanced config) may nest blocks
// (issue #184 round 8). Caddy's adapter copies a block's tokens once per
// enclosing block, so deep nesting costs memory out of proportion to the
// text's size. Real configurations nest a handful of levels; 32 leaves room
// for anything hand-written. tenantMaxBlockNestingDepth applies to the text
// CaddyUI builds around it (the synthetic site an Advanced config is
// adapted in, the exported block, which may place it inside `route` or the
// generated reverse_proxy), so text that passed at save time is never
// refused later for the wrapping alone.
const (
	tenantMaxNestingDepth      = 32
	tenantMaxBlockNestingDepth = tenantMaxNestingDepth + 8
)

// maxTenantCaddyfileBytes caps a non-admin's own Caddyfile text: a proxy
// host's Advanced config (parseProxyHostForm) and an Advanced route's
// source (issue #184 round 8), checked before the text is adapted.
const maxTenantCaddyfileBytes = caddy.MaxTenantCaddyfileBytes

// tenantCaddyfileTooLarge is the refusal for text over maxTenantCaddyfileBytes.
func tenantCaddyfileTooLarge(what string) string {
	return fmt.Sprintf("Not allowed for a non-admin account: %s is too large (the limit is %d KiB). Ask an administrator.", what, maxTenantCaddyfileBytes>>10)
}

// tenantTextViolation checks free text a non-admin submits that Caddy will
// parse as a Caddyfile, for an account that may import no snippet at all.
// Server code holds tenant text to the administrator's snippets with
// s.tenantOwnTextViolation / s.tenantBlockTextViolation instead.
func tenantTextViolation(text string) string {
	return tenantTextViolationWith(text, nil, tenantMaxNestingDepth, maxTenantCaddyfileBytes)
}

// tenantMaxImports is how many `import` lines a non-admin's own text may
// hold (issue #184 round 10). A snippet is imported where it is needed —
// a site's headers, its logging, its TLS — so real configurations import a
// few; 16 leaves ample room. Each import is also charged its expanded
// size and depth (tenantImportCost).
const tenantMaxImports = 16

// tenantTextViolationWith is tenantTextRules for text whose imports may
// only name the snippets in names, each counted as empty.
func tenantTextViolationWith(text string, names map[string]bool, maxDepth, maxBytes int) string {
	snippets := tenantSnippetSet{}
	for n := range names {
		snippets[n] = caddy.CaddyfileSnippet{Name: n}
	}
	return tenantTextRules(text, snippets, maxDepth, maxBytes)
}

// tenantSnippetSet is the administrator's snippets, by name, as the tenant
// text rules see them: what a non-admin may import, and what each import
// costs.
type tenantSnippetSet map[string]caddy.CaddyfileSnippet

// tenantTextRules checks free text a non-admin submits that Caddy will
// parse as a Caddyfile (a proxy host's Advanced config, an Advanced
// route's Caddyfile source, a pasted Caddyfile), reading it the way
// Caddy's lexer does. It refuses:
//   - env/file placeholders and {$…}, anywhere in the raw text ({$…} is
//     expanded before Caddy lexes the file);
//   - text over maxBytes, when maxBytes is not 0, and blocks nested deeper
//     than maxDepth (issue #184 round 8): Caddy's adapter needs memory in
//     proportion to the text's tokens times their depth, and a non-admin's
//     text is adapted by the live Caddy on every sync. An `import` counts
//     as the snippet it expands to (round 10): its size is added to the
//     text's, and its nesting to the depth the import sits at;
//   - more than tenantMaxImports `import` lines (round 10);
//   - text that cannot be read as a Caddyfile, so nothing CaddyUI cannot
//     read that way reaches Caddy;
//   - snippet definitions, in any form Caddy reads as one, and the
//     placeholders Caddy replaces in a snippet's tokens on import — a
//     snippet defined in the same text can turn an argument into a second,
//     nested `import` of a file (round 7);
//   - the word `import` anywhere but at the head of a line;
//   - an `import` of anything but a snippet the administrator defined
//     (snippets: the definitions in CADDYFILE_PATH, see adminSnippetSet).
//     Caddy reads any other name as a file path relative to its working
//     directory, so `import secrets` reads a file there and a parse error
//     echoes it (round 8). With no administrator snippets, every `import`
//     is refused.
//
// The checks that need tokens run on tokens, so a comment, or text inside
// one quoted value, is never mistaken for a directive.
func tenantTextRules(text string, snippets tenantSnippetSet, maxDepth, maxBytes int) string {
	if maxBytes > 0 && len(text) > maxBytes {
		return fmt.Sprintf("the text is too large (the limit is %d KiB)", maxBytes>>10)
	}
	if containsDangerousPlaceholder(text) {
		return "{env.…}, {file.…} and {$…} placeholders read the Caddy server's environment and files and are admin-only"
	}
	use, ok := caddy.CaddyfileImportUse(text)
	if !ok {
		return "the text could not be read as a Caddyfile (check for an unclosed quote or heredoc, or a trailing backslash)"
	}
	if use.MaxDepth > maxDepth {
		return fmt.Sprintf("blocks are nested %d levels deep; the limit is %d", use.MaxDepth, maxDepth)
	}
	if use.SnippetDefined {
		return "snippet definitions — `(name) { … }` — are admin-only"
	}
	if use.SnippetPlaceholder {
		return "{args…} and {block…} placeholders are for snippets, which non-admin accounts cannot define"
	}
	if use.ImportAsArgument {
		return "`import` may only start a line that imports a snippet by name"
	}
	for _, arg := range use.Arguments {
		sn, ok := snippets[arg]
		if ok && sn.Withheld != "" {
			return fmt.Sprintf("the administrator's snippet %q is not available to non-admin accounts: %s", arg, sn.Withheld)
		}
		if !ok || !snippetNameRe.MatchString(arg) {
			return "`import` may only name a snippet the administrator defined in the server Caddyfile; any other name is read as a file on the Caddy server"
		}
	}
	if len(use.Arguments) > tenantMaxImports {
		return fmt.Sprintf("the text has %d `import` lines; the limit is %d", len(use.Arguments), tenantMaxImports)
	}
	for _, imp := range use.Imports {
		if imp.BraceArg {
			return "an `import` argument may not be a lone `{` or `}`: in the snippet it opens or closes a block"
		}
	}
	size, depth, why := snippets.importsCost(use.Imports)
	if why != "" {
		return why
	}
	size = satAdd(size, int64(len(text)))
	depth = max(depth, use.MaxDepth)
	if maxBytes > 0 && size > int64(maxBytes) {
		return fmt.Sprintf("the text is too large once the snippets it imports are counted (%d KiB; the limit is %d KiB)", (size+1023)>>10, maxBytes>>10)
	}
	if depth > maxDepth {
		return fmt.Sprintf("blocks are nested %d levels deep once the snippets it imports are counted; the limit is %d", depth, maxDepth)
	}
	return ""
}

// Import cost (issue #184 round 10, rebuilt in round 11). An `import` of
// a snippet costs Caddy's adapter what the snippet expands to there: its
// body; the importer's arguments once for every `{args…}` placeholder in
// it (a variadic `{args[:]}` puts all of them in); the importer's block
// once for every `{block}` / `{blocks.…}` token; and, in turn, what every
// import in the body costs with the arguments and block the body passes
// it — which may themselves hold placeholders. The bound for a snippet is
// therefore linear in the importer's argument bytes A and block bytes B:
// k + a·A + b·B. Depth is bounded the same way in max-plus form: the
// snippet nests d0 levels below the import, or d1 levels plus the
// nesting of the importer's block, whichever is deeper. Sizes are token
// bytes (each token's text and a separator), the unit the importer's
// arguments and block are measured in; a snippet's own body counts its
// source bytes, which is never less. Every sum saturates, so a pathological
// chain cannot overflow — it is just refused.

// tenantImportCost is the cost of one snippet as a function of what an
// import passes it; see above.
type tenantImportCost struct {
	k, a, b int64 // bytes: k + a·A + b·B
	d0, d1  int   // depth below the import: max(d0, d1 + nesting of B); d1 < 0 when B is not used
}

// noDepth marks a d1 that does not apply.
const noDepth = -1 << 30

const satLimit = int64(1) << 50

func satAdd(x, y int64) int64 {
	if x+y > satLimit {
		return satLimit
	}
	return x + y
}

func satMul(x, y int64) int64 {
	if x == 0 || y == 0 {
		return 0
	}
	if x > satLimit/y {
		return satLimit
	}
	return min(x*y, satLimit)
}

// linear is k + a·A + b·B.
type linear struct{ k, a, b int64 }

func (l linear) add(m linear) linear {
	return linear{satAdd(l.k, m.k), satAdd(l.a, m.a), satAdd(l.b, m.b)}
}

func (l linear) scale(x int64) linear {
	return linear{satMul(l.k, x), satMul(l.a, x), satMul(l.b, x)}
}

// apply is c's bytes for an import that passes arguments A and block B,
// themselves linear in the enclosing A and B.
func (c tenantImportCost) apply(args, block linear) linear {
	return linear{k: c.k}.add(args.scale(c.a)).add(block.scale(c.b))
}

// depthWith is c's depth below the import for a block nesting nest (a
// max-plus pair: max(n0, n1 + enclosing block's nesting)).
func (c tenantImportCost) depthWith(n0, n1 int) (int, int) {
	if c.d1 == noDepth {
		return c.d0, noDepth
	}
	d1 := noDepth
	if n1 != noDepth {
		d1 = c.d1 + n1
	}
	return max(c.d0, c.d1+n0), d1
}

// cost returns what importing name costs, or why it cannot be counted:
// an `import` inside the administrator's snippets that names no snippet
// reads a file whose size is unknown, one placed where its expansion
// cannot be bounded is refused too, and snippets that import each other
// in a cycle never finish expanding (Caddy refuses those too).
func (set tenantSnippetSet) cost(name string, memo map[string]tenantImportCost, visiting map[string]bool) (tenantImportCost, string) {
	if c, ok := memo[name]; ok {
		return c, ""
	}
	sn, ok := set[name]
	if !ok {
		return tenantImportCost{}, fmt.Sprintf("an administrator snippet imports %q, which is not a snippet, so what it adds cannot be counted", name)
	}
	if sn.Withheld != "" {
		return tenantImportCost{}, fmt.Sprintf("the administrator's snippet %q is not available to non-admin accounts: %s", name, sn.Withheld)
	}
	if visiting[name] {
		return tenantImportCost{}, fmt.Sprintf("the administrator's snippet %q imports itself, directly or through another snippet", name)
	}
	visiting[name] = true
	defer delete(visiting, name)
	c := tenantImportCost{k: int64(sn.BodyBytes), a: int64(sn.ArgUses), b: int64(sn.BlockUses), d0: sn.Depth, d1: noDepth}
	if sn.BlockDepth >= 0 {
		c.d1 = sn.BlockDepth
	}
	sites := make([]siteCost, len(sn.Imports))
	for i := len(sn.Imports) - 1; i >= 0; i-- {
		imp := sn.Imports[i]
		if imp.Opaque || imp.Name == "" {
			return tenantImportCost{}, fmt.Sprintf("the administrator's snippet %q places an `import` where what it adds cannot be counted", name)
		}
		t, why := set.cost(imp.Name, memo, visiting)
		if why != "" {
			return tenantImportCost{}, why
		}
		sites[i] = sites[i].finish(t, imp,
			linear{int64(imp.ArgBytes), int64(imp.ArgArgUses), int64(imp.ArgBlockUses)},
			linear{int64(imp.BlockBytes), int64(imp.BlockArgUses), int64(imp.BlockBlockUses)})
		if p := imp.Within - 1; p >= 0 {
			sites[p] = sites[p].withChild(sites[i], imp.Depth-sn.Imports[p].Depth-1)
		}
	}
	for i, imp := range sn.Imports {
		if imp.Within > 0 {
			continue
		}
		bytes := linear{c.k, c.a, c.b}.add(sites[i].bytes)
		c.k, c.a, c.b = bytes.k, bytes.a, bytes.b
		c.d0 = max(c.d0, imp.Depth+sites[i].d0)
		if sites[i].d1 != noDepth {
			c.d1 = max(c.d1, imp.Depth+sites[i].d1)
		}
	}
	memo[name] = c
	return c, ""
}

// siteCost is one import site's cost while a snippet's imports are added
// up: the imports nested in its block (children) are gathered first.
type siteCost struct {
	childBytes linear
	childN0    int // nesting the children add to the block: max(n0, n1 + B)
	childN1    int
	hasKids    bool
	bytes      linear
	d0, d1     int
}

func (sc siteCost) withChild(child siteCost, rel int) siteCost {
	sc.childBytes = sc.childBytes.add(child.bytes)
	if !sc.hasKids {
		sc.childN0, sc.childN1, sc.hasKids = rel+child.d0, noDepth, true
	} else {
		sc.childN0 = max(sc.childN0, rel+child.d0)
	}
	if child.d1 != noDepth {
		sc.childN1 = max(sc.childN1, rel+child.d1)
	}
	return sc
}

// finish computes the site's own cost once its children are known.
func (sc siteCost) finish(t tenantImportCost, imp caddy.CaddyfileImport, args, block linear) siteCost {
	block = block.add(sc.childBytes)
	sc.bytes = t.apply(args, block)
	n0, n1 := imp.BlockNest, noDepth
	if imp.BlockPlaceholderDepth >= 0 {
		n1 = imp.BlockPlaceholderDepth
	}
	if sc.hasKids {
		n0 = max(n0, sc.childN0)
		if sc.childN1 != noDepth {
			n1 = max(n1, sc.childN1)
		}
	}
	sc.d0, sc.d1 = t.depthWith(n0, n1)
	return sc
}

// importsCost is what a non-admin's imports add: the expanded bytes of
// every import outside another import's block (those inside one count
// where that block is put), and the deepest nesting any of them reaches.
func (set tenantSnippetSet) importsCost(imports []caddy.CaddyfileImport) (int64, int, string) {
	memo := map[string]tenantImportCost{}
	sites := make([]siteCost, len(imports))
	for i := len(imports) - 1; i >= 0; i-- {
		imp := imports[i]
		t, why := set.cost(imp.Name, memo, map[string]bool{})
		if why != "" {
			return 0, 0, why
		}
		sites[i] = sites[i].finish(t, imp, linear{k: int64(imp.ArgBytes)}, linear{k: int64(imp.BlockBytes)})
		if p := imp.Within - 1; p >= 0 {
			sites[p] = sites[p].withChild(sites[i], imp.Depth-imports[p].Depth-1)
		}
	}
	var size int64
	depth := 0
	for i, imp := range imports {
		if imp.Within > 0 {
			continue
		}
		size = satAdd(size, sites[i].bytes.k)
		depth = max(depth, imp.Depth+sites[i].d0)
	}
	return size, depth, ""
}

// tenantOwnTextViolation is tenantTextViolationWith for a non-admin's own
// Caddyfile text as written — an Advanced config, an Advanced route's
// source — which may import the administrator's snippets by name.
func (s *Server) tenantOwnTextViolation(text string) string {
	return tenantTextRules(text, s.adminSnippetSet(), tenantMaxNestingDepth, maxTenantCaddyfileBytes)
}

// tenantBlockTextViolation is tenantOwnTextViolation for text CaddyUI
// built around a non-admin's own text (the synthetic site it is adapted
// in, the block the export writes), which nests a few levels deeper and
// holds CaddyUI's own directives besides; the size of the non-admin's part
// is checked where that text is taken in.
func (s *Server) tenantBlockTextViolation(text string) string {
	return tenantTextRules(text, s.adminSnippetSet(), tenantMaxBlockNestingDepth, 0)
}

// tenantAdaptTextViolation is the check for text on its way to Caddy's
// adapter on a non-admin's behalf, which starts with the administrator's
// snippet definitions from CADDYFILE_PATH (withTenantSnippets). The
// placeholder and file-import rules apply to the whole text, as they
// always have; the rest apply to the part after exactly that prefix, which
// is the non-admin's own (plus the synthetic site CaddyUI may have wrapped
// it in). When the prefix is not found the whole text is the non-admin's,
// so the stricter reading wins.
//
// Issue #184 round 10: it then checks the text as Caddy will receive it —
// every snippet the non-admin's part imports, directly or through another
// snippet, must be defined in that text, read the way Caddy's parser
// reads it. Whatever built the prefix, an import that would fall through
// to a file is refused here, before Caddy sees it.
func (s *Server) tenantAdaptTextViolation(text string) string {
	own := text
	snippets := s.adminSnippetSet()
	if prefix := tenantSnippetPrefix(snippets); prefix != "" && strings.HasPrefix(text, prefix) {
		own = text[len(prefix):]
		if containsDangerousPlaceholder(prefix) {
			return s.tenantBlockTextViolation(text)
		}
		for _, m := range caddyfileImportRe.FindAllStringSubmatch(prefix, -1) {
			if !snippetNameRe.MatchString(m[1]) {
				return s.tenantBlockTextViolation(text)
			}
		}
	}
	// Issue #184 round 8: every path that adapts a non-admin's text checks
	// its size where it takes the text in; this bounds any path that does
	// not, leaving room for the synthetic site around an Advanced config.
	// Round 10: imports count at their expanded size.
	if why := tenantTextRules(own, snippets, tenantMaxBlockNestingDepth, maxTenantCaddyfileBytes+4<<10); why != "" {
		if strings.HasPrefix(why, "the text is too large") {
			return fmt.Sprintf("the text is too large (the limit is %d KiB)", maxTenantCaddyfileBytes>>10)
		}
		return why
	}
	args, _ := caddy.CaddyfileImportArguments(own)
	if len(args) == 0 {
		return ""
	}
	defined := map[string]bool{}
	for _, sn := range caddy.CaddyfileSnippets(text) {
		defined[sn.Name] = true
	}
	return undefinedSnippetImport(args, snippets, defined)
}

// undefinedSnippetImport returns why the text Caddy would adapt does not
// define a snippet that args import — directly, or through the snippets
// they import, transitively (snippets says what each imports) — or "".
// defined holds the snippet names that text defines. An import of a name
// that text does not define reads a file of that name.
func undefinedSnippetImport(args []string, snippets tenantSnippetSet, defined map[string]bool) string {
	for pending, seen := args, map[string]bool{}; len(pending) > 0; {
		name := pending[0]
		pending = pending[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !defined[name] {
			return fmt.Sprintf("the administrator's snippet %q is not defined ahead of the text Caddy would adapt, so its `import` would read a file", name)
		}
		for _, imp := range snippets[name].Imports {
			pending = append(pending, imp.Name)
		}
	}
	return ""
}

// tenantSnippetPrefix is what withTenantSnippets puts ahead of a
// non-admin's text: every administrator snippet a non-admin may import
// (none Withheld), or "".
func tenantSnippetPrefix(snippets tenantSnippetSet) string {
	return snippetPrefix(snippets.ordered())
}

// snippetPrefix joins snippet definitions into the prefix put ahead of
// text sent to the adapter.
func snippetPrefix(texts []string) string {
	if len(texts) == 0 {
		return ""
	}
	return strings.Join(texts, "\n\n") + "\n\n"
}

// ordered returns the snippets' definitions in the order of the
// administrator's Caddyfile.
func (set tenantSnippetSet) ordered() []string {
	list := make([]caddy.CaddyfileSnippet, 0, len(set))
	for _, sn := range set {
		if sn.Withheld == "" {
			list = append(list, sn)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Order < list[j].Order })
	out := make([]string, 0, len(list))
	for _, sn := range list {
		out = append(out, sn.Text)
	}
	return out
}

// autoLoadedSnippetPrefix is what withTenantSnippets prepends, or "".
func (s *Server) autoLoadedSnippetPrefix() string {
	return tenantSnippetPrefix(s.adminSnippetSet())
}

// adminSnippetDefs returns the snippet definitions in the administrator's
// Caddyfile (CADDYFILE_PATH), read the way Caddy reads them, or nil.
func (s *Server) adminSnippetDefs() []caddy.CaddyfileSnippet {
	if s == nil || s.CaddyfilePath == "" {
		return nil
	}
	b, err := os.ReadFile(s.CaddyfilePath)
	if err != nil {
		return nil
	}
	return caddy.CaddyfileSnippets(string(b))
}

// adminSnippets returns the text of the administrator's snippet
// definitions, or nil.
func (s *Server) adminSnippets() []string {
	var out []string
	for _, sn := range s.adminSnippetDefs() {
		out = append(out, sn.Text)
	}
	return out
}

// adminSnippetSet returns the administrator's snippets by name — the only
// names a non-admin may `import` (issue #184 round 8) — with what each
// costs (round 10). Caddy refuses a name defined twice, so does this:
// such a name is left out, and an import of it is refused.
//
// Issue #184 round 11: a snippet a non-admin may not import is marked
// Withheld, and left out of the text CaddyUI adapts for one (the prefix
// of withTenantSnippets), so it never makes a non-admin's text fail: one
// that holds an {env.…}, {file.…} or {$…} placeholder, one whose
// `import`s name anything but another snippet (a file), or one placed
// where what it adds cannot be counted, and — transitively — one that
// imports a withheld snippet.
func (s *Server) adminSnippetSet() tenantSnippetSet {
	set := tenantSnippetSet{}
	dup := map[string]bool{}
	for _, sn := range s.adminSnippetDefs() {
		if _, ok := set[sn.Name]; ok {
			dup[sn.Name] = true
		}
		set[sn.Name] = sn
	}
	for n := range dup {
		delete(set, n)
	}
	withhold := func(name, why string) {
		sn := set[name]
		sn.Withheld = why
		set[name] = sn
	}
	for name, sn := range set {
		if containsDangerousPlaceholder(sn.Text) {
			withhold(name, "it reads the Caddy server's environment or files ({env.…}, {file.…} or {$…})")
			continue
		}
		for _, imp := range sn.Imports {
			if _, ok := set[imp.Name]; imp.Opaque || !ok {
				withhold(name, "it imports something other than a snippet, such as a file")
				break
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for name, sn := range set {
			if sn.Withheld != "" {
				continue
			}
			for _, imp := range sn.Imports {
				if set[imp.Name].Withheld != "" {
					withhold(name, fmt.Sprintf("it imports the snippet %q, which is not available to them", imp.Name))
					changed = true
					break
				}
			}
		}
	}
	return set
}

var (
	// caddyfileImportRe finds `import` in the administrator's snippet
	// prefix (tenantAdaptTextViolation).
	caddyfileImportRe = regexp.MustCompile(`(?m)(?:^|[\s{;])import\s+(\S+)`)
	snippetNameRe     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// isAdminUser reports whether cu is an administrator. A nil user is treated as
// NOT an admin, so a missing session can never widen what is allowed.
func isAdminUser(cu *models.User) bool {
	return cu != nil && (cu.IsAdmin || cu.Role == models.RoleAdmin)
}

// validateRedirectionForUser is the save-time check for a redirection host: a
// non-admin's redirect is held to the same rules as the route it generates
// (placeholders in the target, the rh_advanced_config JSON, ...).
func (s *Server) validateRedirectionForUser(cu *models.User, rh *models.RedirectionHost) string {
	if isAdminUser(cu) || rh == nil {
		return ""
	}
	if msg := s.certificateRefusal(cu, rh.CertificateID); msg != "" {
		return msg
	}
	// Issue #184 round 8: a plain host name, as for a proxy host, except
	// that a trailing dot and capitals are accepted — the live route
	// matches the name without them, and so does the Caddyfile export. A
	// port, scheme or path is refused: the live route would match a
	// different name than the one typed, and a port in the export would
	// open a listener.
	for _, d := range rh.DomainList() {
		if !tenantHostnameRe.MatchString(strings.TrimSuffix(d, ".")) {
			return fmt.Sprintf("Domain %q is not a plain hostname — ports, schemes, paths and special characters are not allowed for non-admin accounts.", d)
		}
	}
	return s.validateTenantRoute(caddy.BuildRedirectRoute(*rh))
}

// validateRawRouteForUser is the save-time check for an Advanced route. For a
// non-admin it covers the Caddyfile text (env/file placeholders, file imports)
// and every route in the JSON that will be pushed to Caddy.
func (s *Server) validateRawRouteForUser(cu *models.User, rr *models.RawRoute) string {
	if isAdminUser(cu) || rr == nil {
		return ""
	}
	if msg := s.certificateRefusal(cu, rr.CertificateID); msg != "" {
		return msg
	}
	if len(rr.CaddyfileSrc) > maxTenantCaddyfileBytes {
		return tenantCaddyfileTooLarge("the Caddyfile")
	}
	if why := s.tenantOwnTextViolation(rr.CaddyfileSrc); why != "" {
		return "Not allowed for a non-admin account: " + why + ". Ask an administrator."
	}
	for _, entry := range rawRouteEntries(*rr) {
		if msg := s.validateTenantRoute(entry); msg != "" {
			return msg
		}
	}
	return ""
}

// certificateRefusal returns an error message when a NON-admin references a
// certificate they may not use: another tenant's private certificate. Global
// (admin-owned) certificates are shared on purpose and stay selectable. The
// forms only offer visible certificates, but the ID arrives as a plain number,
// so it has to be checked on the server (v2.57.1).
func (s *Server) certificateRefusal(cu *models.User, certID int64) string {
	if certID == 0 || isAdminUser(cu) || s == nil || s.DB == nil {
		return ""
	}
	cert, err := models.GetCertificate(s.DB, certID)
	if err != nil || cert == nil {
		return "Certificate not found."
	}
	if cert.OwnerID.Valid && !s.canManageOwned(cu, cert.OwnerID) {
		return "Certificate not found."
	}
	return ""
}

// tenantHostnameRe is what a non-admin may use as a proxy host DOMAIN: plain DNS
// labels with an optional leading "*." — no port, path, userinfo or
// placeholder. CaddyUI's own probes (health monitor, app monitor, post-sync
// expectations, certificate probe) build their URLs from the first domain, so
// "10.8.0.2:2019" as a domain turned the probes into requests to an arbitrary
// internal address.
var tenantHostnameRe = regexp.MustCompile(`(?i)^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// tenantMonitorPathRe limits a custom health-check path to URL path characters.
var tenantMonitorPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$`)

// tenantProbeViolation checks the fields of a proxy host that CaddyUI's own
// probes turn into outbound requests, for a non-admin owner.
func (s *Server) tenantProbeViolation(p *models.ProxyHost) string {
	adminHosts := s.adminHostSet()
	for _, d := range p.DomainList() {
		if !tenantHostnameRe.MatchString(d) {
			return fmt.Sprintf("Domain %q is not a plain hostname — ports, paths and special characters are not allowed for non-admin accounts.", d)
		}
		if why := dialBlockedForTenant(strings.TrimPrefix(d, "*."), adminHosts); why != "" {
			return fmt.Sprintf("Domain %q is not allowed: %s.", d, why)
		}
	}
	if p.MonitorMode == "custom" {
		switch strings.ToUpper(strings.TrimSpace(p.MonitorMethod)) {
		case "", "GET", "HEAD":
		default:
			return "Custom health checks are limited to GET and HEAD for non-admin accounts."
		}
		if path := strings.TrimSpace(p.MonitorPath); path != "" && !tenantMonitorPathRe.MatchString(path) {
			return "The health-check path contains characters that are not allowed."
		}
	}
	return ""
}

// tenantRawRouteTextProblem is the check of a non-admin's Advanced route
// Caddyfile made before it is adapted (issue #184 round 8): the size
// limit, then the tenant text rules. It returns a message for the user.
func (s *Server) tenantRawRouteTextProblem(src string) string {
	if len(src) > maxTenantCaddyfileBytes {
		return tenantCaddyfileTooLarge("the Caddyfile")
	}
	if why := s.tenantOwnTextViolation(src); why != "" {
		return "Not allowed for a non-admin account: " + why + ". Ask an administrator."
	}
	return ""
}
