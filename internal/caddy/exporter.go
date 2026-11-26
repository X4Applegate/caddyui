// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Exporter — v2.12.49: render CaddyUI's database state back to Caddyfile
// text. Inverse of the Caddyfile-paste import flow. Produces output that
// round-trips cleanly through the existing /caddyfile-import handler for
// the fields it covers — anything CaddyUI stores beyond what fits cleanly
// into a Caddyfile site block (per-host maintenance schedules, upstream
// retry counts, app-level analytics toggles, etc.) is summarised in a
// `# Notes:` comment block at the top of each affected site so users can
// see what was elided rather than silently losing it.

// RenderServerCaddyfile produces a complete Caddyfile snapshot of one
// CaddyUI-managed Caddy server's enabled routes: every proxy host, every
// redirection, plus any raw routes whose source is Caddyfile-typed
// (advanced JSON routes get a # comment pointing the reader at the UI).
//
// `serverName` is just metadata for the file header banner. Disabled hosts
// are skipped — the export is "what's actually serving traffic", not "every
// row in the DB". Pass an empty serverName to omit the banner.
func RenderServerCaddyfile(serverName string, hosts []models.ProxyHost, redirects []models.RedirectionHost, raws []models.RawRoute, certs []models.Certificate) string {
	certByID := make(map[int64]*models.Certificate, len(certs))
	for i := range certs {
		certByID[certs[i].ID] = &certs[i]
	}
	var b strings.Builder
	if serverName != "" {
		fmt.Fprintf(&b, "# CaddyUI export — %s\n", caddyfileComment(serverName))
	}
	fmt.Fprintf(&b, "# Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	b.WriteString("# Hosts/redirects/raw routes that are disabled in the UI are not included.\n")
	b.WriteString("# This output is round-trip safe via /caddyfile-import for the directives it contains.\n\n")

	// Stable ordering across runs so two exports of the same DB diff cleanly.
	sort.SliceStable(hosts, func(i, j int) bool {
		return strings.ToLower(hosts[i].Domains) < strings.ToLower(hosts[j].Domains)
	})
	sort.SliceStable(redirects, func(i, j int) bool {
		return strings.ToLower(redirects[i].Domains) < strings.ToLower(redirects[j].Domains)
	})
	sort.SliceStable(raws, func(i, j int) bool { return raws[i].ID < raws[j].ID })

	for _, ph := range hosts {
		if !ph.Enabled {
			continue
		}
		b.WriteString(RenderProxyHostCaddyfileWithCertificate(ph, certByID[ph.CertificateID]))
		b.WriteString("\n")
	}
	for _, rh := range redirects {
		if !rh.Enabled {
			continue
		}
		b.WriteString(RenderRedirectionCaddyfile(rh))
		b.WriteString("\n")
	}
	for _, rr := range raws {
		if !rr.Enabled {
			continue
		}
		b.WriteString(RenderRawRouteCaddyfile(rr))
		b.WriteString("\n")
	}
	return b.String()
}

// RenderProxyHostCaddyfile emits a single proxy host as a Caddyfile site
// block. Covers the core directives: domains, tls, encode, header, block,
// reverse_proxy with header_up + transport. Skips long-tail toggles
// (maintenance windows, app health checks, scheduled blocks) and lists
// any non-default ones in a leading `# Notes:` comment so users know to
// re-set them in the UI after a round-trip.
func RenderProxyHostCaddyfile(p models.ProxyHost) string {
	return RenderProxyHostCaddyfileWithCertificate(p, nil)
}

// RenderProxyHostCaddyfileWithCertificate is RenderProxyHostCaddyfile with
// the host's custom certificate resolved (v2.42.1, issue #74): a file-path
// certificate renders as a real `tls <cert> <key>` line, a stored PEM or a
// managed definition as a comment saying how Caddy gets it.
func RenderProxyHostCaddyfileWithCertificate(p models.ProxyHost, cert *models.Certificate) string {
	var b strings.Builder

	// Site block header — space-separated hostname list per Caddyfile spec.
	domains := p.DomainList()
	if len(domains) == 0 {
		return ""
	}
	// Issue #184 review: fields written as bare tokens must not be able to
	// split into extra tokens, lines or blocks. When one can, the site is
	// left out (no directive at all is less permissive than a wrong one).
	if !proxyHostBareFieldsSafe(p, cert) {
		return fmt.Sprintf("# Proxy host #%d omitted: a value cannot be written safely as Caddyfile syntax; see it in CaddyUI.\n", p.ID)
	}

	// Note any non-roundtrippable settings up front so users see them.
	var elided []string
	if p.MaintenanceMode {
		elided = append(elided, "maintenance mode (re-enable in CaddyUI)")
	}
	if p.MaintenanceWindowStart != "" || p.MaintenanceWindowEnd != "" {
		elided = append(elided, "scheduled maintenance window")
	}
	if p.HealthCheckURI != "" {
		elided = append(elided, fmt.Sprintf("active health check on %s", caddyfileComment(p.HealthCheckURI)))
	}
	if p.BasicAuthEnabled {
		elided = append(elided, "basic auth users (passwords are bcrypt-hashed; not in plaintext form)")
	}
	if p.BlockedAgents != "" {
		elided = append(elided, "blocked user-agent patterns")
	}
	if p.IPBlocklist != "" {
		elided = append(elided, "IP blocklist")
	}
	if p.AccessList != "" {
		elided = append(elided, "IP allowlist")
	}
	if p.URLRewrites != "" && p.URLRewrites != "[]" {
		elided = append(elided, "URL rewrite rules")
	}
	if p.AdditionalUpstreamRules != "" && p.AdditionalUpstreamRules != "[]" {
		elided = append(elided, "path-based upstream overrides")
	}
	if p.ProxyRedirectRules != "" && p.ProxyRedirectRules != "[]" {
		elided = append(elided, "path-based redirect rules")
	}
	if p.OwnerEmail != "" {
		fmt.Fprintf(&b, "# Owner: %s\n", caddyfileComment(p.OwnerEmail))
	}
	if p.Tags != "" {
		fmt.Fprintf(&b, "# Tags: %s\n", caddyfileComment(p.Tags))
	}
	if len(elided) > 0 {
		b.WriteString("# Notes (these settings live in CaddyUI but don't fit cleanly into Caddyfile syntax):\n")
		for _, n := range elided {
			fmt.Fprintf(&b, "#   - %s\n", n)
		}
	}

	fmt.Fprintf(&b, "%s {\n", strings.Join(domains, ", "))

	// TLS block — cert source. Auto (ACME) is implicit when the site has a
	// public hostname; we only need an explicit `tls` directive for custom
	// certs or specific CA hints.
	if p.CertificateID > 0 {
		switch {
		case cert != nil && cert.Source == models.CertSourcePath && cert.CertPath != "" && cert.KeyPath != "":
			fmt.Fprintf(&b, "\ttls %s %s\n", cert.CertPath, cert.KeyPath)
		case cert != nil && cert.Source == models.CertSourcePEM:
			fmt.Fprintf(&b, "\t# tls: stored PEM certificate %q — CaddyUI loads it into Caddy's certificate pool directly (load_pem); a Caddyfile would need the files on disk\n", cert.Name)
		case cert != nil && cert.Source == models.CertSourceManaged:
			fmt.Fprintf(&b, "\t# tls: managed certificate %q (%s) — Caddy obtains it via DNS-01 and serves it by SNI\n", cert.Name, caddyfileComment(cert.Domains))
		default:
			fmt.Fprintf(&b, "\t# Custom certificate ID %d (uploaded via CaddyUI; not represented in Caddyfile — Caddy will use its automatic cert resolution at runtime)\n", p.CertificateID)
		}
	} else if !p.SSLEnabled {
		// SSL explicitly off — site listens on HTTP only.
		b.WriteString("\ttls off\n")
	}

	// v2.64.0 (discussion #137): client certificate authentication. Emitted
	// as its own `tls` block rather than folded into the certificate line
	// above — the two are independent, and a site can require client
	// certificates whichever way its own certificate is obtained. Leaving
	// this out would make an exported Caddyfile look like the site is open
	// to anyone, which is the one thing an export must not get wrong.
	if p.ClientAuthEnabled() {
		b.WriteString("\ttls {\n\t\tclient_auth {\n")
		fmt.Fprintf(&b, "\t\t\tmode %s\n", p.ClientAuthMode)
		if files := p.ClientAuthCAFileList(); len(files) > 0 {
			// One directive taking every file — repeating `trust_pool`
			// is a duplicate-module error, not a second CA.
			fmt.Fprintf(&b, "\t\t\ttrust_pool file %s\n", strings.Join(files, " "))
		}
		b.WriteString("\t\t}\n\t}\n")
	}

	// Issue #184: the Path matcher narrows the JSON route to matching paths,
	// so the Caddyfile carries the same matcher on reverse_proxy. pathOK is
	// false when a value cannot be written as one safe Caddyfile token; the
	// site then fails closed below rather than proxying every path.
	pathDef, stripToken, pathOK := caddyfilePathMatcher(p)
	// With Strip prefix the order-sensitive directives go in a `route` block:
	// Caddyfile sorting would otherwise run `uri strip_prefix` before
	// `respond @blocked`, checking the exploit list against the stripped
	// path where the JSON route checks the original one.
	wrapInRoute := pathOK && stripToken != ""

	// Path blocking (the "block common exploits" toggle that defaults on in
	// CaddyUI v2.11+). Mirrors the CaddyUI prompt's standard block list.
	if p.BlockCommonExploits && !wrapInRoute {
		b.WriteString(caddyfileExploitBlocker)
	}

	// Compression
	if p.CompressionEnabled {
		// CaddyUI default is zstd gzip (matches the v2.12.33 prompt).
		b.WriteString("\tencode zstd gzip\n")
	}

	// Security headers bundle
	if p.SecurityHeadersEnabled {
		b.WriteString("\theader {\n")
		hstsMaxAge := p.HSTSMaxAgeSec
		if hstsMaxAge == 0 {
			hstsMaxAge = 31536000
		}
		hsts := fmt.Sprintf("max-age=%d; includeSubDomains", hstsMaxAge)
		if p.HSTSPreload {
			hsts += "; preload"
		}
		fmt.Fprintf(&b, "\t\tStrict-Transport-Security %q\n", hsts)
		b.WriteString("\t\tX-Content-Type-Options \"nosniff\"\n")
		b.WriteString("\t\tX-Frame-Options \"SAMEORIGIN\"\n")
		b.WriteString("\t\tReferrer-Policy \"strict-origin-when-cross-origin\"\n")
		b.WriteString("\t\tX-XSS-Protection \"1; mode=block\"\n")
		if p.CSPHeader != "" {
			fmt.Fprintf(&b, "\t\tContent-Security-Policy %q\n", p.CSPHeader)
		}
		b.WriteString("\t}\n")
	}

	// Custom response headers — set + delete via the same `header` block.
	respMap := p.CustomRespHeaderMap()
	if len(respMap) > 0 {
		b.WriteString("\theader {\n")
		// Stable ordering for diffability.
		keys := make([]string, 0, len(respMap))
		for k := range respMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := respMap[k]
			if v == "" {
				fmt.Fprintf(&b, "\t\t-%s\n", k)
			} else {
				fmt.Fprintf(&b, "\t\t%s %q\n", k, v)
			}
		}
		b.WriteString("\t}\n")
	}
	if p.StripRespHeaders != "" {
		for _, h := range splitCSV(p.StripRespHeaders) {
			fmt.Fprintf(&b, "\theader -%s\n", h)
		}
	}

	// Everything from here to the end of the reverse_proxy block is either
	// wrapped in `route { }` or replaced by the fail-closed response.
	proxyStart := b.Len()
	if wrapInRoute && p.BlockCommonExploits {
		b.WriteString(caddyfileExploitBlocker)
	}
	proxyMatcher := ""
	if pathDef != "" {
		fmt.Fprintf(&b, "\t@%s %s\n", caddyfilePathMatcherName, pathDef)
		proxyMatcher = "@" + caddyfilePathMatcherName + " "
		// Strip prefix mirrors the route's `rewrite strip_path_prefix`
		// handler under the same matcher.
		if stripToken != "" {
			fmt.Fprintf(&b, "\turi @%s strip_prefix %s\n", caddyfilePathMatcherName, stripToken)
		}
	}

	// reverse_proxy block — primary upstream + extras + transport tweaks.
	upstreamSpec := upstreamDial(p.ForwardScheme, p.ForwardHost, p.ForwardPort)
	for _, eu := range p.ExtraUpstreamList() {
		eu = strings.TrimSpace(eu)
		if eu != "" {
			upstreamSpec += " " + eu
		}
	}
	fmt.Fprintf(&b, "\treverse_proxy %s%s {\n", proxyMatcher, upstreamSpec)

	// header_up — custom request headers + the X-Forwarded-* trio.
	if p.UpstreamHostOverride != "" {
		fmt.Fprintf(&b, "\t\theader_up Host %q\n", p.UpstreamHostOverride)
	}
	// CaddyUI defaults: forward the X-Forwarded-* trio unless explicitly disabled.
	b.WriteString("\t\theader_up X-Forwarded-Host {host}\n")
	b.WriteString("\t\theader_up X-Forwarded-Proto {scheme}\n")
	b.WriteString("\t\theader_up X-Real-IP {remote_host}\n")

	// Custom request headers — set + delete.
	reqMap := p.CustomReqHeaderMap()
	if len(reqMap) > 0 {
		keys := make([]string, 0, len(reqMap))
		for k := range reqMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := reqMap[k]
			if v == "" {
				fmt.Fprintf(&b, "\t\theader_up -%s\n", k)
			} else {
				fmt.Fprintf(&b, "\t\theader_up %s %q\n", k, v)
			}
		}
	}
	if p.StripReqHeaders != "" {
		for _, h := range splitCSV(p.StripReqHeaders) {
			fmt.Fprintf(&b, "\t\theader_up -%s\n", h)
		}
	}

	// LB policy — only meaningful with multiple upstreams.
	if len(p.ExtraUpstreamList()) > 0 && p.LBPolicy != "" {
		fmt.Fprintf(&b, "\t\tlb_policy %s\n", p.LBPolicy)
	}

	// Streaming
	if p.FlushImmediate {
		b.WriteString("\t\tflush_interval -1\n")
	}

	// Transport block — only emit if anything inside is non-default.
	if p.ForwardScheme == "https" || p.UpstreamSNI != "" || p.KeepaliveConns > 0 || p.UpstreamTimeoutSec > 0 || p.DisableUpstreamCompression {
		b.WriteString("\t\ttransport http {\n")
		if p.ForwardScheme == "https" {
			b.WriteString("\t\t\ttls\n")
		}
		if p.UpstreamSNI != "" {
			fmt.Fprintf(&b, "\t\t\ttls_server_name %s\n", p.UpstreamSNI)
		}
		if p.KeepaliveConns > 0 {
			fmt.Fprintf(&b, "\t\t\tkeepalive_idle_conns %d\n", p.KeepaliveConns)
		}
		if p.UpstreamTimeoutSec > 0 {
			fmt.Fprintf(&b, "\t\t\tdial_timeout %ds\n", p.UpstreamTimeoutSec)
			fmt.Fprintf(&b, "\t\t\tresponse_header_timeout %ds\n", p.UpstreamTimeoutSec)
		}
		if p.DisableUpstreamCompression {
			b.WriteString("\t\t\tcompression off\n") // v2.12.52
		}
		b.WriteString("\t\t}\n")
	}

	// v2.42.1: a `reverse_proxy { … }` block in the Advanced config is merged
	// into the host's own handler at sync time (v2.40.0), so render its
	// sub-directives inside this block rather than as a second reverse_proxy.
	advancedRest, advancedInner := splitAdvancedReverseProxyBlock(p.AdvancedConfig)
	if len(advancedInner) > 0 {
		b.WriteString("\t\t# from Advanced config\n")
		for _, line := range advancedInner {
			fmt.Fprintf(&b, "\t\t%s\n", line)
		}
	}
	b.WriteString("\t}\n")
	if !pathOK || wrapInRoute {
		site := b.String()
		b.Reset()
		b.WriteString(site[:proxyStart])
		if !pathOK {
			// Dropping the matcher would make the excerpt less restrictive
			// than the live route, and quoting it risks breaking out of the
			// token, so the site refuses every request instead.
			b.WriteString("\t# Path matcher not representable in Caddyfile syntax; this excerpt fails closed instead of proxying.\n")
			b.WriteString("\trespond 503\n")
		} else {
			b.WriteString("\troute {\n")
			for _, line := range strings.SplitAfter(site[proxyStart:], "\n") {
				if line != "" {
					b.WriteString("\t" + line)
				}
			}
			b.WriteString("\t}\n")
		}
	}

	// Advanced raw config — verbatim user input, indented to match the site
	// block. Trailing newline preserved.
	if strings.TrimSpace(advancedRest) != "" {
		b.WriteString("\n\t# --- Advanced raw config (from CaddyUI) ---\n")
		for _, line := range strings.Split(advancedRest, "\n") {
			if line == "" {
				b.WriteString("\n")
			} else {
				fmt.Fprintf(&b, "\t%s\n", line)
			}
		}
	}

	b.WriteString("}\n")
	return b.String()
}

// RenderRedirectionCaddyfile emits a redirection host as a Caddyfile site
// block using the `redir` directive.
func RenderRedirectionCaddyfile(r models.RedirectionHost) string {
	var b strings.Builder
	domains := r.DomainList()
	if len(domains) == 0 {
		return ""
	}
	if !caddyfileBareSafe(append(append([]string{}, domains...), r.ForwardDomain)...) {
		return fmt.Sprintf("# Redirection host #%d omitted: a value cannot be written safely as Caddyfile syntax; see it in CaddyUI.\n", r.ID)
	}
	if r.OwnerEmail != "" {
		fmt.Fprintf(&b, "# Owner: %s\n", caddyfileComment(r.OwnerEmail))
	}
	fmt.Fprintf(&b, "%s {\n", strings.Join(domains, ", "))
	scheme := r.ForwardScheme
	if scheme == "" || scheme == "auto" {
		scheme = "{scheme}"
	} else {
		scheme = scheme + "://"
		// auto used "{scheme}" placeholder but explicit http/https becomes prefix
		// We need to undo that for the destination:
	}
	// Build destination URL.
	var dest string
	if r.ForwardScheme == "" || r.ForwardScheme == "auto" {
		dest = "{scheme}://" + r.ForwardDomain
	} else {
		dest = r.ForwardScheme + "://" + r.ForwardDomain
	}
	if r.PreservePath {
		dest += "{uri}"
	}
	code := r.ForwardHTTPCode
	if code == 0 {
		code = 301
	}
	fmt.Fprintf(&b, "\tredir %s %d\n", dest, code)
	b.WriteString("}\n")
	return b.String()
}

// RenderRawRouteCaddyfile emits a CaddyUI raw route. If the route stored
// the original Caddyfile source (CaddyfileSrc field), that's included
// verbatim. Otherwise we fall back to a comment pointing the reader at
// the CaddyUI Advanced page, since translating arbitrary Caddy JSON back
// to Caddyfile cleanly is a much bigger problem than this exporter wants
// to solve.
func RenderRawRouteCaddyfile(r models.RawRoute) string {
	var b strings.Builder
	label := r.Label
	if label == "" {
		label = fmt.Sprintf("raw-%d", r.ID)
	}
	fmt.Fprintf(&b, "# Raw route #%d — %s\n", r.ID, caddyfileComment(label))
	src := strings.TrimSpace(r.CaddyfileSrc)
	if src != "" {
		b.WriteString(src)
		if !strings.HasSuffix(src, "\n") {
			b.WriteString("\n")
		}
	} else {
		b.WriteString("# (JSON-typed raw route — open it in CaddyUI → Advanced to see / edit)\n")
	}
	return b.String()
}

// caddyfilePathMatcherName names the matcher that carries a proxy host's
// Path matcher in the Caddyfile excerpt (issue #184).
const caddyfilePathMatcherName = "caddyui_path"

// caddyfileExploitBlocker is the Caddyfile form of the "block common
// exploits" handler.
const caddyfileExploitBlocker = "\t@blocked path /.env* /wp-admin* /wp-login* /phpmyadmin* /.git/* /xmlrpc.php\n\trespond @blocked 403\n"

// caddyfilePathMatcher returns the Caddyfile matcher (without the @name)
// equivalent to the `path` / `path_regexp` match BuildProxyRoute adds for
// the host's Path matcher, and the token for its strip_path_prefix rewrite.
// def is "" when the route has no path matcher; ok is false when a value
// cannot be written as a single safe token. Keep the cases in step with
// BuildProxyRoute.
func caddyfilePathMatcher(p models.ProxyHost) (def, strip string, ok bool) {
	if p.PathMatcher == "" {
		return "", "", true
	}
	var tokens []string
	switch p.PathMatcherType {
	case "exact":
		def, tokens = "path", []string{p.PathMatcher}
	case "regexp":
		def, tokens = "path_regexp", []string{p.PathMatcher}
	default:
		prefix := strings.TrimRight(p.PathMatcher, "/*")
		if prefix == "" {
			return "", "", true
		}
		def, tokens = "path", []string{prefix, prefix + "/*"}
	}
	for _, t := range tokens {
		tok, safe := caddyfileToken(t)
		if !safe {
			return "", "", false
		}
		def += " " + tok
	}
	if p.StripPathPrefix {
		if prefix := strings.TrimRight(p.PathMatcher, "/*"); prefix != "" {
			if strip, ok = caddyfileToken(prefix); !ok {
				return "", "", false
			}
		}
	}
	return def, strip, true
}

// caddyfileToken renders s as one Caddyfile token whose value Caddy reads
// back unchanged. Plain path/regexp text is left bare; anything else is
// wrapped in backticks, which the lexer takes literally up to the next
// backtick. ok is false — and the caller must fail closed — when no such
// token exists: a backtick (would end the quote; backslash escaping is
// deliberately not attempted), control characters and Unicode line
// separators, invalid UTF-8, and `{` followed by a letter, `_` or `$`, which
// the Caddyfile adapter rewrites as an environment variable or placeholder
// shorthand ({$VAR}, {host}, …). Regexp quantifiers such as {2,3} are fine.
func caddyfileToken(s string) (string, bool) {
	if s == "" || !utf8.ValidString(s) {
		return "", false
	}
	bare := true
	for i, r := range s {
		switch {
		case r == '`', unicode.IsControl(r), r == ' ', r == ' ':
			return "", false
		case r == '{' && braceStartsPlaceholder(s[i+1:]):
			return "", false
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("/.-_*^$()[]|+?:~!%&=,;", r):
		default:
			bare = false
		}
	}
	if bare {
		return s, true
	}
	return "`" + s + "`", true
}

// braceStartsPlaceholder reports whether the text after a `{` would make
// the Caddyfile adapter read it as {$ENV} or a placeholder shorthand.
func braceStartsPlaceholder(rest string) bool {
	next, _ := utf8.DecodeRuneInString(rest)
	return next == '$' || next == '_' || unicode.IsLetter(next)
}

// caddyfileBareSafe reports whether every value can be written as one
// unquoted Caddyfile token that Caddy reads back unchanged: no whitespace,
// control characters or backslashes (which split or escape), no `{$` (env
// expansion), and no token-initial `"`, backtick, `#`, `@`, `<<` or a lone
// brace, which open a quote, comment, matcher, heredoc or block.
func caddyfileBareSafe(values ...string) bool {
	for _, s := range values {
		if s == "" || !utf8.ValidString(s) || s == "{" || s == "}" ||
			strings.ContainsAny(s[:1], "\"`#@") || strings.HasPrefix(s, "<<") ||
			strings.Contains(s, "{$") || strings.ContainsRune(s, '\\') {
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

// proxyHostBareFieldsSafe applies caddyfileBareSafe to every user-supplied
// value RenderProxyHostCaddyfileWithCertificate writes as a bare token.
// Values written with %q or inside comments are not covered here.
func proxyHostBareFieldsSafe(p models.ProxyHost, cert *models.Certificate) bool {
	vals := append([]string{}, p.DomainList()...)
	if p.ForwardHost != "" {
		vals = append(vals, p.ForwardHost)
	}
	for _, eu := range p.ExtraUpstreamList() {
		if eu = strings.TrimSpace(eu); eu != "" {
			vals = append(vals, eu)
		}
	}
	for _, v := range []string{p.UpstreamSNI, p.LBPolicy} {
		if v != "" {
			vals = append(vals, v)
		}
	}
	if p.ClientAuthEnabled() {
		vals = append(vals, p.ClientAuthMode)
		vals = append(vals, p.ClientAuthCAFileList()...)
	}
	for k := range p.CustomReqHeaderMap() {
		vals = append(vals, k)
	}
	for k := range p.CustomRespHeaderMap() {
		vals = append(vals, k)
	}
	vals = append(vals, splitCSV(p.StripReqHeaders)...)
	vals = append(vals, splitCSV(p.StripRespHeaders)...)
	if p.CertificateID > 0 && cert != nil && cert.Source == models.CertSourcePath && cert.CertPath != "" && cert.KeyPath != "" {
		vals = append(vals, cert.CertPath, cert.KeyPath)
	}
	return caddyfileBareSafe(vals...)
}

// caddyfileComment makes s safe inside a `#` comment line: anything that
// could end the line (or that a reader would take as a line break) becomes
// a space.
func caddyfileComment(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

// upstreamDial — produce a Caddyfile reverse_proxy upstream argument.
// HTTPS upstreams need the scheme prefix; HTTP is the default and omits it.
func upstreamDial(scheme, host string, port int) string {
	if scheme == "https" {
		return fmt.Sprintf("https://%s:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// splitCSV is a small comma-separated-value splitter that trims whitespace
// and drops empty tokens. Used for the strip_*_headers fields which are
// stored as CSV in the DB.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitAdvancedReverseProxyBlock separates a top-level `reverse_proxy { … }`
// block from the rest of an Advanced config. inner holds the block's lines
// with one level of indentation removed; rest is everything else, verbatim.
func splitAdvancedReverseProxyBlock(src string) (rest string, inner []string) {
	if strings.TrimSpace(src) == "" {
		return src, nil
	}
	stripped := func(line string) string {
		t := strings.TrimSpace(line)
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		return t
	}
	braces := func(line string) int {
		d := 0
		for _, ch := range stripped(line) {
			switch ch {
			case '{':
				d++
			case '}':
				d--
			}
		}
		return d
	}
	lines := strings.Split(src, "\n")
	var kept []string
	depth := 0
	for i := 0; i < len(lines); {
		line := lines[i]
		t := stripped(line)
		if depth == 0 && t != "" && strings.Fields(t)[0] == "reverse_proxy" && strings.HasSuffix(t, "{") {
			d := braces(line)
			j := i + 1
			var block []string
			for ; j < len(lines) && d > 0; j++ {
				d += braces(lines[j])
				if d > 0 {
					block = append(block, lines[j])
				}
			}
			if d == 0 {
				for _, bl := range block {
					if strings.TrimSpace(bl) != "" {
						inner = append(inner, strings.TrimPrefix(strings.TrimSpace(bl), "\t"))
					}
				}
				i = j
				continue
			}
		}
		kept = append(kept, line)
		depth += braces(line)
		i++
	}
	if inner == nil {
		return src, nil
	}
	return strings.Join(kept, "\n"), inner
}
