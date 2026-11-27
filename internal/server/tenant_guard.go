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

// forbiddenTenantHandlers are Caddy handlers a non-admin may never use, with
// why: they read files from the Caddy container (file_server, templates), run
// an ACME CA (acme_server), or serve data about the whole server (metrics).
var forbiddenTenantHandlers = map[string]string{
	"file_server": "can read files from the Caddy server",
	"templates":   "can read files from the Caddy server",
	"acme_server": "runs a certificate authority on the Caddy server",
	// metrics serves the Prometheus metrics of the whole Caddy process:
	// every site's request counts and every upstream's address.
	"metrics": "serves the metrics of every site on the Caddy server",
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
	if cl := s.caddyClient(); cl != nil {
		add(cl.AdminURL)
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
				if why, ok := forbiddenTenantHandlers[h]; ok {
					reason = fmt.Sprintf("the %q handler %s and is admin-only", h, why)
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

// tenantSnippetUnavailable is the refusal for an `import` of a name a
// non-admin may not import: one the administrator did not define, or one
// withheld from non-admins (issue #184 round 12: the same words for both,
// so the message does not tell a non-admin what the administrator's
// Caddyfile holds; adminSnippetSet logs why a snippet is withheld).
func tenantSnippetUnavailable(name string) string {
	return fmt.Sprintf("the snippet %q is not available; `import` may only name a snippet the administrator made available in the server Caddyfile (any other name is read as a file on the Caddy server)", name)
}

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
//   - a `}` with another token after it on its line (round 15; a comment
//     may follow it);
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
//     is refused;
//   - an `import` inside another `import`'s block (round 12): Caddy ends
//     an import's block by comparing line numbers, which the copies a
//     snippet makes of the importer's block repeat, so an import inside
//     one can take the following copy as its own block, at every level —
//     an expansion without bound;
//   - in an `import`'s block, a `{` or `}` with more on its line, and, for
//     a snippet that uses `{blocks.…}`, a matcher definition, snippet name
//     or `import` right after a key (round 14): Caddy starts a line with
//     the first word of the block, and with a key's first value, wherever
//     the snippet puts them, so the rules must see those words where a
//     line starts too.
//
// The checks that need tokens run on tokens, so a comment, or text inside
// one quoted value, is never mistaken for a directive.
func tenantTextRules(text string, snippets tenantSnippetSet, maxDepth, maxBytes int) string {
	why, _, _ := tenantTextCheck(text, snippets, tenantTextLimits{maxDepth: maxDepth, maxBytes: maxBytes})
	return why
}

// tenantTextLimits are the limits tenantTextCheck applies.
type tenantTextLimits struct {
	maxDepth, maxBytes int
	// topLevel says that an import at block depth 0 of the text is at the
	// top level of the file Caddy parses (the text is a whole Caddyfile,
	// or exactly what is sent to the adapter), not inside a site block
	// CaddyUI wraps around it.
	topLevel bool
}

// tenantTextCheck is tenantTextRules; it also returns the size and depth
// the text was counted at (what the limits were held against), for the
// differential test of the cost model.
func tenantTextCheck(text string, snippets tenantSnippetSet, lim tenantTextLimits) (string, int64, int) {
	maxDepth, maxBytes := lim.maxDepth, lim.maxBytes
	if maxBytes > 0 && len(text) > maxBytes {
		return fmt.Sprintf("the text is too large (the limit is %d KiB)", maxBytes>>10), 0, 0
	}
	if containsDangerousPlaceholder(text) {
		return "{env.…}, {file.…} and {$…} placeholders read the Caddy server's environment and files and are admin-only", 0, 0
	}
	use, ok := caddy.CaddyfileImportUse(text)
	if !ok {
		return "the text could not be read as a Caddyfile (check for an unclosed quote or heredoc, or a trailing backslash)", 0, 0
	}
	if use.MaxDepth > maxDepth {
		return fmt.Sprintf("blocks are nested %d levels deep; the limit is %d", use.MaxDepth, maxDepth), 0, 0
	}
	if use.SnippetDefined {
		return "snippet definitions — `(name) { … }` — are admin-only", 0, 0
	}
	if use.SnippetPlaceholder {
		return "{args…} and {block…} placeholders are for snippets, which non-admin accounts cannot define", 0, 0
	}
	// Issue #184 round 15: Caddy closes a block at a `}` wherever it sits
	// on its line; text in which a `}` is followed by more on its line is
	// refused, so the rules below read every block where Caddy does.
	if use.CloseNotLast {
		return "a closing `}` must end its line; put what follows it on the next line", 0, 0
	}
	if use.ImportAsArgument {
		return "`import` may only start a line that imports a snippet by name", 0, 0
	}
	for _, arg := range use.Arguments {
		sn, ok := snippets[arg]
		if !ok || sn.Withheld != "" || !snippetNameRe.MatchString(arg) {
			return tenantSnippetUnavailable(arg), 0, 0
		}
	}
	if len(use.Arguments) > tenantMaxImports {
		return fmt.Sprintf("the text has %d `import` lines; the limit is %d", len(use.Arguments), tenantMaxImports), 0, 0
	}
	for _, imp := range use.Imports {
		if imp.BraceArg {
			return "an `import` argument may not be a lone `{` or `}`: in the snippet it opens or closes a block", 0, 0
		}
		if imp.ArgImport {
			return "an `import` argument may not hold the word `import`", 0, 0
		}
		if imp.ArgNewline {
			return "an `import` argument may not hold a line break", 0, 0
		}
		if imp.InMatcherDef {
			return "an `import` may not be written inside a matcher definition", 0, 0
		}
		if imp.Within != 0 {
			return "an `import` may not be written inside the block of another `import`", 0, 0
		}
		// Issue #184 round 14: what Caddy reads as the start of a line in
		// an import's block must start one in the text too.
		if imp.BlockBraceNotLast {
			return "in the block of an `import`, `{` and `}` must end their line (the block's content starts on the line after the `{`)", 0, 0
		}
		if snippets[imp.Name].BlockKeyed {
			for _, a := range imp.KeyArgs {
				if caddy.CaddyfileLineStartSensitive(a.Text) {
					return fmt.Sprintf("the snippet %q puts the rest of a line of the `import`'s block where a line starts, so a matcher definition (`@name`), a snippet name or `import` may not follow the line's first word there; write it on a line of its own", imp.Name), 0, 0
				}
			}
		}
		if lim.topLevel && imp.Depth == 0 && snippetUnsafeAtTopLevel(snippets[imp.Name], imp.ArgCount) {
			return fmt.Sprintf("the snippet %q can only be imported inside a site block", imp.Name), 0, 0
		}
	}
	size, depth, why := snippets.importsCost(use.Imports, viewSize)
	if why != "" {
		return why, 0, 0
	}
	// Issue #184 round 13: the text's own tokens are weighed too (an
	// empty token costs Caddy as much as a short one).
	size = satAdd(size, int64(max(len(text), use.Weight)))
	// Issue #184 round 13: a site block is adapted once for every listener
	// port its addresses name, so a whole Caddyfile is charged that many
	// times over (a site on both http:// and https:// counts twice).
	if lim.topLevel && use.SiteListeners > 1 {
		size = satMul(size, int64(use.SiteListeners))
	}
	depth = max(depth, use.MaxDepth)
	if maxBytes > 0 && size > int64(maxBytes) {
		return fmt.Sprintf("the text is too large once the snippets it imports are counted (%d KiB; the limit is %d KiB, and every token counts as at least %d bytes)", (size+1023)>>10, maxBytes>>10, caddy.CaddyfileMinTokenWeight), size, depth
	}
	if depth > maxDepth {
		return fmt.Sprintf("blocks are nested %d levels deep once the snippets it imports are counted; the limit is %d", depth, maxDepth), size, depth
	}
	copies := tenantMatcherCopies(use, snippets)
	// Issue #184 round 14: like the size, matcher copies are made once per
	// listener port of the widest site block.
	if lim.topLevel && use.SiteListeners > 1 {
		copies = satMul(copies, int64(use.SiteListeners))
	}
	if copies > tenantMaxMatcherCopyBytes {
		return fmt.Sprintf("named matchers would be copied into the adapted config too often (%d KiB of matcher definitions times references; the limit is %d KiB) — reference each named matcher fewer times, or keep matcher definitions short", (copies+1023)>>10, tenantMaxMatcherCopyBytes>>10), size, depth
	}
	return "", size, depth
}

// tenantMaxMatcherCopyBytes bounds how much named-matcher definition text
// a non-admin's text may have Caddy copy (issue #184 round 13): Caddy puts
// a named matcher's whole definition into every handler that names it, so
// 3720 references to two 8000-token path matchers in 64 KiB of text
// adapted to 119 MB of JSON and peaked at 2.6 GB. The product of every
// reference and the weight of every definition (an upper bound: a
// reference copies one definition) is held to this; see
// MaxCaddyfileNestingDepth in the caddy package for the measurement.
const tenantMaxMatcherCopyBytes = 1 << 20

// tenantMatcherCopies is references × definition weight for text, the
// snippets it imports included (viewRefs, viewDefs). Errors in the import
// cost were already reported by the size view, which runs first.
func tenantMatcherCopies(use caddy.CaddyfileImports, snippets tenantSnippetSet) int64 {
	refs, _, _ := snippets.importsCost(use.Imports, viewRefs)
	defs, _, _ := snippets.importsCost(use.Imports, viewDefs)
	refs = satAdd(refs, int64(use.Refs))
	defs = satAdd(defs, int64(use.DefWeight))
	return satMul(refs, defs)
}

// snippetUnsafeAtTopLevel reports whether importing sn with nargs
// arguments at the top level of the file, outside any site block, can make
// Caddy's parser fail (issue #184 round 12), or opens a site block on more
// than one address there (round 13: the block is adapted once per
// listener, which the size limit does not count): at the top level Caddy's
// parser fails with an index out of range when the snippet's first token
// expands to nothing (a variadic `{args[…]}` with an empty range, or the
// importer's block), and an `import` the snippet holds outside any block
// of its own runs at the top level too, with arguments that may expand to
// any number of tokens.
func snippetUnsafeAtTopLevel(sn caddy.CaddyfileSnippet, nargs int) bool {
	if sn.First == "import" || caddy.CaddyfileVariadicEmpty(sn.First, nargs) ||
		sn.First == "{block}" || strings.HasPrefix(sn.First, "{blocks.") {
		return true
	}
	// Round 13: a block it opens there is a site block, adapted once per
	// listener its addresses name; only a single address is counted for.
	if sn.HeadKeys > 1 {
		return true
	}
	// Round 14: the importer's block put in at the snippet's own top level
	// lands at the top level of the file, where its lines are site
	// addresses and site blocks the rules counted as nested ones.
	if sn.BlockDepth == 0 {
		return true
	}
	for _, imp := range sn.Imports {
		if imp.Depth == 0 {
			return true
		}
	}
	return false
}

// tenantTextRefusalIsOwn reports whether text is refused by the tenant
// rules on its own — whatever the administrator's snippets hold — rather
// than because of them (issue #184 round 12, for the upgrade migration):
// it is checked again with every name it imports defined as an empty
// snippet. A refusal that goes away then depends on the administrator's
// Caddyfile (a snippet missing, withheld, too large), which may change.
func tenantTextRefusalIsOwn(text string, lim tenantTextLimits) bool {
	names := map[string]bool{}
	if args, ok := caddy.CaddyfileImportArguments(text); ok {
		for _, a := range args {
			names[a] = true
		}
	}
	snippets := tenantSnippetSet{}
	for n := range names {
		snippets[n] = caddy.CaddyfileSnippet{Name: n, BlockDepth: -1}
	}
	why, _, _ := tenantTextCheck(text, snippets, lim)
	return why != ""
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

// costView is what the import cost model adds up (issue #184 round 13).
// The same linear model serves three measures:
//
//   - viewSize: the tokens' weight (caddy.CaddyfileTokenWeight: bytes,
//     but at least a few per token, since Caddy's adapter spends memory
//     per token), what the size limit holds;
//   - viewRefs: tokens that may name a matcher (cfMatcherFacts in the
//     caddy package); each `{args…}` placeholder puts the importer's
//     references in again, as it does the importer's bytes;
//   - viewDefs: the weight of matcher definitions. A placeholder on a
//     definition's line puts the importer's arguments — their whole
//     weight — into the definition, so in this view A is the arguments'
//     weight (as in viewSize) and B the definitions in the importer's
//     block.
//
// Caddy copies a named matcher into every handler that names it, so the
// adapted config grows with references × definitions; tenantTextCheck
// bounds that product.
type costView int

const (
	viewSize costView = iota
	viewRefs
	viewDefs
)

// snippet is k, a and b of the snippet's own body in view v.
func (v costView) snippet(sn caddy.CaddyfileSnippet) (k, a, b int64) {
	switch v {
	case viewRefs:
		return int64(sn.BodyRefs), int64(sn.ArgUses), int64(sn.BlockUses)
	case viewDefs:
		return int64(sn.BodyDefWeight), int64(sn.DefArgUses), int64(sn.BlockUses)
	}
	return int64(max(sn.BodyWeight, sn.BodyBytes)), int64(sn.ArgUses), int64(sn.BlockUses)
}

// inner is what an import inside a snippet's body passes its snippet,
// as linear forms in the importing snippet's own A and B.
func (v costView) inner(imp caddy.CaddyfileImport) (args, block linear) {
	switch v {
	case viewRefs:
		return linear{int64(imp.ArgRefs), int64(imp.ArgArgUses), int64(imp.ArgBlockUses)},
			linear{int64(imp.BlockRefs), int64(imp.BlockArgUses), int64(imp.BlockBlockUses)}
	case viewDefs:
		// A is a weight in this view; the block passes its definitions
		// (a snippet that puts placeholders in an import's block is
		// withheld, so the coefficients only err high).
		return linear{int64(imp.ArgWeight), int64(imp.ArgArgUses), int64(imp.ArgBlockUses)},
			linear{int64(imp.BlockDefWeight), int64(imp.BlockArgUses), int64(imp.BlockBlockUses)}
	}
	return linear{int64(imp.ArgWeight), int64(imp.ArgArgUses), int64(imp.ArgBlockUses)},
		linear{int64(imp.BlockWeight), int64(imp.BlockArgUses), int64(imp.BlockBlockUses)}
}

// top is what a non-admin's own import passes its snippet.
func (v costView) top(imp caddy.CaddyfileImport) (args, block linear) {
	switch v {
	case viewRefs:
		return linear{k: int64(imp.ArgRefs)}, linear{k: int64(imp.BlockRefs)}
	case viewDefs:
		return linear{k: int64(imp.ArgWeight)}, linear{k: int64(imp.BlockDefWeight)}
	}
	return linear{k: int64(imp.ArgWeight)}, linear{k: int64(imp.BlockWeight)}
}

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
func (set tenantSnippetSet) cost(name string, v costView, memo map[string]tenantImportCost, visiting map[string]bool) (tenantImportCost, string) {
	if c, ok := memo[name]; ok {
		return c, ""
	}
	sn, ok := set[name]
	if !ok {
		return tenantImportCost{}, tenantSnippetUnavailable(name)
	}
	if sn.Withheld != "" || visiting[name] {
		// adminSnippetSet withholds a snippet that imports a withheld one
		// or itself, so a non-admin's import never gets here; the message
		// is the same as for any unavailable name.
		return tenantImportCost{}, tenantSnippetUnavailable(name)
	}
	visiting[name] = true
	defer delete(visiting, name)
	k, a, b := v.snippet(sn)
	c := tenantImportCost{k: k, a: a, b: b, d0: sn.Depth, d1: noDepth}
	if sn.BlockDepth >= 0 {
		c.d1 = sn.BlockDepth
	}
	sites := make([]siteCost, len(sn.Imports))
	for i := len(sn.Imports) - 1; i >= 0; i-- {
		imp := sn.Imports[i]
		if imp.Opaque || imp.Name == "" {
			return tenantImportCost{}, tenantSnippetUnavailable(name)
		}
		t, why := set.cost(imp.Name, v, memo, visiting)
		if why != "" {
			return tenantImportCost{}, why
		}
		args, block := v.inner(imp)
		sites[i] = sites[i].finish(t, imp, args, block)
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
func (set tenantSnippetSet) importsCost(imports []caddy.CaddyfileImport, v costView) (int64, int, string) {
	memo := map[string]tenantImportCost{}
	sites := make([]siteCost, len(imports))
	for i := len(imports) - 1; i >= 0; i-- {
		imp := imports[i]
		t, why := set.cost(imp.Name, v, memo, map[string]bool{})
		if why != "" {
			return 0, 0, why
		}
		args, block := v.top(imp)
		sites[i] = sites[i].finish(t, imp, args, block)
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
	return tenantAdaptTextRules(text, s.adminSnippetSet())
}

// tenantAdaptTextRules is tenantAdaptTextViolation for the administrator's
// snippets as given.
func tenantAdaptTextRules(text string, snippets tenantSnippetSet) string {
	own := text
	if prefix := tenantSnippetPrefix(snippets); prefix != "" && strings.HasPrefix(text, prefix) {
		own = text[len(prefix):]
		if containsDangerousPlaceholder(prefix) {
			return tenantTextRules(text, snippets, tenantMaxBlockNestingDepth, 0)
		}
		for _, m := range caddyfileImportRe.FindAllStringSubmatch(prefix, -1) {
			if !snippetNameRe.MatchString(m[1]) {
				return tenantTextRules(text, snippets, tenantMaxBlockNestingDepth, 0)
			}
		}
	}
	// Issue #184 round 8: every path that adapts a non-admin's text checks
	// its size where it takes the text in; this bounds any path that does
	// not, leaving room for the synthetic site around an Advanced config.
	// Round 10: imports count at their expanded size. Round 12: this is
	// the text exactly as Caddy parses it, so an import at depth 0 is at
	// the top level of the file.
	lim := tenantTextLimits{maxDepth: tenantMaxBlockNestingDepth, maxBytes: maxTenantCaddyfileBytes + 4<<10, topLevel: true}
	if why, _, _ := tenantTextCheck(own, snippets, lim); why != "" {
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
			// Not defined ahead of the text Caddy would adapt, so its
			// `import` would read a file.
			return tenantSnippetUnavailable(name)
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
// costs (round 10); see tenantSnippetSetFrom. A snippet withheld from
// non-admins is logged with the reason, once per change, for the
// administrator: a non-admin is only told it is not available.
func (s *Server) adminSnippetSet() tenantSnippetSet {
	set := tenantSnippetSetShared(s.adminSnippetDefs(), s.tenantSnippets.shares)
	s.logWithheldSnippets(set)
	return set
}

// logWithheldSnippets logs each withheld snippet and why, when that
// changes.
func (s *Server) logWithheldSnippets(set tenantSnippetSet) {
	if s == nil {
		return
	}
	now := map[string]string{}
	for name, sn := range set {
		if sn.Withheld != "" {
			now[name] = sn.Withheld
		}
	}
	s.withheldMu.Lock()
	defer s.withheldMu.Unlock()
	for _, name := range sortedStringKeys(now) {
		if s.withheld[name] != now[name] {
			log.Printf("caddyfile snippets: the administrator's snippet %q is not available to non-admin accounts: %s", name, now[name])
		}
	}
	s.withheld = now
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tenantSnippetSetFrom builds the tenant view of the administrator's
// snippet definitions. Caddy refuses a name defined twice, so does this:
// such a name is left out, and an import of it is refused.
//
// Issue #184 round 11: a snippet a non-admin may not import is marked
// Withheld, and left out of the text CaddyUI adapts for one (the prefix
// of withTenantSnippets), so it never makes a non-admin's text fail: one
// that holds an {env.…}, {file.…} or {$…} placeholder, one whose
// `import`s name anything but another snippet (a file), or one placed
// where what it adds cannot be counted, and — transitively — one that
// imports a withheld snippet.
//
// Issue #184 round 12: Caddy ends the block an import passes by comparing
// line numbers, and the importer's block keeps its own line numbers
// wherever a snippet puts it; two copies of it back to back read as one
// line, so the `}` ending the first does not end anything, and an
// `import` written in the block swallows the next copy — which expands
// without bound. So a snippet is also withheld when it puts the
// importer's block in more than once (`{block}` and `{blocks.…}` counted
// together), passes the importer's block or arguments on inside an
// `import`'s block, holds a `}` with more text after it on its line (the
// block it closes then runs on into the importer's text, as Caddy reads
// it), or imports itself.
//
// Issue #184 round 13: Caddy replaces a snippet's `{args…}` placeholders
// before it looks for directives, so a placeholder where a line starts —
// or a token such as `im{args[0]}` there — lets the importer's arguments
// choose the directive, `import` of any file among them, and a variadic
// placeholder that expands to nothing there can end the importer's site
// block early. A snippet is therefore withheld when an `{args…}` token
// can start a line (cfSnippetPlacement in the caddy package: a token
// before it on its line must always be put in, as one token); when a
// token is made of placeholders and braces alone (the arguments would
// decide whether it is `{` or `}`); when `{block}` / `{blocks.…}` shares
// its line with any other token (round 12 looked at neighbouring tokens
// across lines, which withheld snippets Caddy reads correctly; the
// importer's block may start a snippet, inside a site block — at the top
// level snippetUnsafeAtTopLevel refuses that import); when the block is
// put inside a matcher definition, or an `import` is written in one; and
// when an `import` in it passes a lone brace or a line break as an
// argument. A placeholder inside a token after the first of its line
// (`header Authorization "Bearer {args[0]}"`, `{args[0]}:{args[1]}`)
// stays available, and (round 14) so does a line-start token that begins
// with `@` (`@{args[0]} host {args[0]}.example.com`): it is a matcher
// definition's name whatever the arguments are, and counted as one.
//
// Issue #184 round 14: a snippet whose own `import` blocks hold a `{` or
// `}` with more on its line, or a matcher, snippet or `import` word after a
// key, is withheld, as such text is refused in a non-admin's own imports.
func tenantSnippetSetFrom(defs []caddy.CaddyfileSnippet) tenantSnippetSet {
	return tenantSnippetSetShared(defs, nil)
}

// tenantSnippetSetShared is tenantSnippetSetFrom with the snippets shared
// reports false for withheld as well (tenant_snippet_sharing.go); nil
// shares all.
func tenantSnippetSetShared(defs []caddy.CaddyfileSnippet, shared func(string) bool) tenantSnippetSet {
	set := tenantSnippetSet{}
	dup := map[string]bool{}
	for _, sn := range defs {
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
		switch {
		case shared != nil && !shared(name):
			withhold(name, "the administrator has not shared it with non-admin accounts ("+envTenantSnippets+")")
			continue
		case containsDangerousPlaceholder(sn.Text):
			withhold(name, "it reads the Caddy server's environment or files ({env.…}, {file.…} or {$…})")
			continue
		case sn.BlockUses > 1:
			withhold(name, "it puts the importer's block ({block} / {blocks.…}) in more than once")
			continue
		case sn.BlockNotAlone:
			withhold(name, "it puts the importer's block ({block} / {blocks.…}) on a line with other text")
			continue
		case sn.PlaceholderLineStart:
			withhold(name, "an {args…} placeholder in it can start a line, where the importer's arguments would choose the directive")
			continue
		case sn.PlaceholderNoLiteral:
			withhold(name, "a token in it is made of {args…} placeholders alone, so the importer's arguments decide what it is")
			continue
		case sn.DefBlock:
			withhold(name, "it puts the importer's block ({block} / {blocks.…}) inside a matcher definition")
			continue
		case sn.MidLineClose:
			withhold(name, "a `}` in it is followed by more text on its line, so Caddy reads the block it closes as running on past the snippet")
			continue
		}
		for _, imp := range sn.Imports {
			if _, ok := set[imp.Name]; imp.Opaque || !ok {
				withhold(name, "it imports something other than a snippet, such as a file")
				break
			}
			if imp.BlockBlockUses > 0 || imp.BlockArgUses > 0 {
				withhold(name, "it passes the importer's block or arguments on inside the block of an `import`")
				break
			}
			if imp.BraceArg || imp.ArgNewline {
				withhold(name, "it passes a lone `{` or `}`, or a line break, as an argument of an `import`")
				break
			}
			if imp.InMatcherDef {
				withhold(name, "it imports a snippet inside a matcher definition")
				break
			}
			// Issue #184 round 14: as for a non-admin's own imports.
			if imp.BlockBraceNotLast {
				withhold(name, "a `{` or `}` in the block of an `import` in it has more text after it on its line")
				break
			}
			if keyArgSensitive(imp) {
				withhold(name, "a line of the block of an `import` in it continues with a matcher, snippet or `import` word after its first word")
				break
			}
		}
	}
	// A snippet that imports itself, directly or through others, never
	// finishes expanding (Caddy refuses it too).
	const (
		unseen = iota
		onPath
		finished
	)
	state := map[string]int{}
	var visit func(name string) bool
	visit = func(name string) bool {
		switch state[name] {
		case onPath:
			return true
		case finished:
			return false
		}
		state[name] = onPath
		cyclic := false
		for _, imp := range set[name].Imports {
			if _, ok := set[imp.Name]; ok && visit(imp.Name) {
				cyclic = true
			}
		}
		state[name] = finished
		return cyclic
	}
	for _, name := range sortedSnippetNames(set) {
		state = map[string]int{}
		if visit(name) && set[name].Withheld == "" {
			withhold(name, "it imports itself, directly or through another snippet")
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

// keyArgSensitive reports whether a line of imp's block continues, after
// its first word, with a token that means something else where a line
// starts (issue #184 round 14; see caddy.CaddyfileImport.KeyArgs).
func keyArgSensitive(imp caddy.CaddyfileImport) bool {
	for _, a := range imp.KeyArgs {
		if caddy.CaddyfileLineStartSensitive(a.Text) {
			return true
		}
	}
	return false
}

func sortedSnippetNames(set tenantSnippetSet) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
	// Issue #184 round 13: the stored routes are deployed on every sync.
	if len(rr.JSONData) > maxTenantRawJSONBytes {
		return fmt.Sprintf("Not allowed for a non-admin account: the route JSON is too large (the limit is %d MiB). Ask an administrator.", maxTenantRawJSONBytes>>20)
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
	// Issue #184 round 12: an Advanced route's text is a whole Caddyfile,
	// so an import at its depth 0 is at the top level of the file.
	lim := tenantTextLimits{maxDepth: tenantMaxNestingDepth, maxBytes: maxTenantCaddyfileBytes, topLevel: true}
	if why, _, _ := tenantTextCheck(src, s.adminSnippetSet(), lim); why != "" {
		return "Not allowed for a non-admin account: " + why + ". Ask an administrator."
	}
	return ""
}
