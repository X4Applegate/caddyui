// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
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
//
// opts (at most one is used) supplies the server's snippets, which owners
// count as tenants, and extra raw-route checks; see ExportOptions.
func RenderServerCaddyfile(serverName string, hosts []models.ProxyHost, redirects []models.RedirectionHost, raws []models.RawRoute, certs []models.Certificate, opts ...ExportOptions) string {
	var o ExportOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	certByID := make(map[int64]*models.Certificate, len(certs))
	for i := range certs {
		certByID[certs[i].ID] = &certs[i]
	}
	var head strings.Builder
	if serverName != "" {
		fmt.Fprintf(&head, "# CaddyUI export — %s\n", caddyfileComment(serverName))
	}
	fmt.Fprintf(&head, "# Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	head.WriteString("# Hosts/redirects/raw routes that are disabled in the UI are not included.\n")
	head.WriteString("# This output is round-trip safe via /caddyfile-import for the directives it contains.\n\n")
	// The sites are rendered first so that only the snippets they import
	// are written ahead of them (issue #184 review).
	var b strings.Builder

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
		b.WriteString(renderProxyHost(ph, certByID[ph.CertificateID], o))
		b.WriteString("\n")
	}
	for _, rh := range redirects {
		if !rh.Enabled {
			continue
		}
		b.WriteString(renderRedirection(rh, o))
		b.WriteString("\n")
	}
	for _, rr := range raws {
		if !rr.Enabled {
			continue
		}
		b.WriteString(renderRawRoute(rr, o))
		b.WriteString("\n")
	}
	return head.String() + o.withSnippetDefinitions(b.String())
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
//
// Issue #184 review: the result is always one self-contained site block (or
// a comment). A host whose values cannot be written faithfully renders as
// a site that answers 503 — never as a block that proxies more than the
// live route, and never as text that can reach a neighbouring block.
func RenderProxyHostCaddyfileWithCertificate(p models.ProxyHost, cert *models.Certificate) string {
	return RenderProxyHostCaddyfileWithOptions(p, cert, ExportOptions{})
}

// RenderProxyHostCaddyfileWithOptions is RenderProxyHostCaddyfileWithCertificate
// with the server's context: an admin-owned host's Advanced config may then
// keep `import <snippet>` for a snippet in opts.Snippets, whose definition
// is written ahead of the site when opts.IncludeSnippets is set, and a
// tenant's Advanced config is re-checked with opts.ProxyHostVeto.
func RenderProxyHostCaddyfileWithOptions(p models.ProxyHost, cert *models.Certificate, opts ExportOptions) string {
	return opts.withSnippetDefinitions(renderProxyHost(p, cert, opts))
}

func renderProxyHost(p models.ProxyHost, cert *models.Certificate, opts ExportOptions) string {
	domains := p.DomainList()
	if len(domains) == 0 {
		return ""
	}
	if !caddyfileAddressSafe(domains...) {
		// Without safe addresses there is no site to fail closed in.
		return fmt.Sprintf("# Proxy host #%d omitted: its domains cannot be written safely as Caddyfile syntax; see it in CaddyUI.\n", p.ID)
	}
	if opts.tenant(p.OwnerID) && !caddyfilePlainHosts(domains) {
		// Not even a fail-closed site: its address would open a listener.
		return fmt.Sprintf("# Proxy host #%d omitted: its domains are not plain host names, which a non-admin owner cannot use; see it in CaddyUI.\n", p.ID)
	}
	if why := proxyHostFieldsProblem(p, cert); why != "" {
		return caddyfileFailClosedSite(domains, why)
	}
	// Issue #184 round 10: a tenant's oversized text (a row stored before
	// the limit) is refused before anything lexes it.
	if opts.tenant(p.OwnerID) && len(p.AdvancedConfig) > MaxTenantCaddyfileBytes {
		return caddyfileFailClosedSite(domains, "this host cannot be exported: its Advanced config is larger than a non-admin account may save")
	}
	imports := opts.importsFor(p.OwnerID)
	if why := opts.importProblem(p.AdvancedConfig, p.OwnerID); why != "" {
		return caddyfileFailClosedSite(domains, "the Advanced config cannot be exported: "+why)
	}
	out, why := renderProxyHostSite(p, cert, domains, opts.importedMatcherNames(p.AdvancedConfig))
	if why != "" {
		return caddyfileFailClosedSite(domains, why)
	}
	if sites, err := checkCaddyfileSites(out, imports); err != nil || len(sites) != 1 {
		return caddyfileFailClosedSite(domains, "the generated block would not stay self-contained (check the Advanced config)")
	}
	// Issue #184 review: every tenant host is re-checked by the server —
	// its fields against the rules the live sync enforces (rows written by
	// older versions, or by a path that skipped the save checks, may hold
	// values the live route neutralises), and an Advanced config through
	// Caddy, since the live route keeps only its handlers, and only when
	// they pass the tenant checks. The veto judges the block exactly as it
	// is written here, so how the exporter places the Advanced text (inside
	// the generated reverse_proxy, inside `route`, at site level) can never
	// make the file mean more than what was checked.
	if opts.tenant(p.OwnerID) {
		why := "it could not be re-checked"
		if opts.ProxyHostVeto != nil {
			why = opts.ProxyHostVeto(p, out)
		}
		if why != "" {
			return caddyfileFailClosedSite(domains, "this host cannot be exported: "+why)
		}
	}
	return out
}

// renderRedirection is RenderRedirectionCaddyfile with the server's
// context: a tenant's redirect is written only when opts.RedirectVeto has
// no objection to the block, and otherwise fails closed (issue #184 round 7).
//
// A tenant's redirect is written with the host names its live route
// matches (BuildRedirectRoute: lower-cased, trailing dot and scheme
// removed), so the site serves what the live route serves (round 8). A
// redirect whose domain carries a port is left out: the live route matches
// that host on the standard listeners, while a port in a site address
// opens a listener of its own, which a non-admin may not.
func renderRedirection(r models.RedirectionHost, opts ExportOptions) string {
	if !opts.tenant(r.OwnerID) || len(r.DomainList()) == 0 {
		return RenderRedirectionCaddyfile(r)
	}
	names, ok := redirectLiveHosts(r.DomainList())
	if !ok {
		return fmt.Sprintf("# Redirection host #%d omitted: its domains are not plain host names (a port, path or other address form), which a non-admin owner cannot use; see it in CaddyUI.\n", r.ID)
	}
	live := r
	live.Domains = strings.Join(names, ", ")
	out := RenderRedirectionCaddyfile(live)
	domains := live.DomainList()
	if out == "" || !caddyfileAddressSafe(domains...) {
		return out
	}
	why := "it could not be re-checked"
	if opts.RedirectVeto != nil {
		why = opts.RedirectVeto(r, out)
	}
	if why != "" {
		return caddyfileFailClosedSite(domains, "this redirect cannot be exported: "+why)
	}
	return out
}

// caddyfilePlainHostRe is a plain DNS name with an optional leading "*." —
// no scheme, port or path — the only proxy host domain form a non-admin
// may save. A row stored before that rule may hold more: such a domain
// matches nothing in the live route, but as a site address a port opens a
// listener (issue #184 round 7).
var caddyfilePlainHostRe = regexp.MustCompile(`(?i)^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// redirectLiveHosts returns the host names a redirection host's live route
// matches (models.NormalizeHostnames, as BuildRedirectRoute uses), without
// repeats, when every one is a plain host name and no domain carries a
// port; ok is false otherwise.
func redirectLiveHosts(domains []string) (names []string, ok bool) {
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if !strings.Contains(d, "://") {
			if _, port, err := net.SplitHostPort(d); err == nil && port != "" {
				return nil, false
			}
		}
		n := models.NormalizeHostname(d)
		if !caddyfilePlainHostRe.MatchString(n) {
			return nil, false
		}
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names, len(names) > 0
}

// caddyfilePlainHosts reports whether every domain matches caddyfilePlainHostRe.
func caddyfilePlainHosts(domains []string) bool {
	for _, d := range domains {
		if !caddyfilePlainHostRe.MatchString(d) {
			return false
		}
	}
	return true
}

// caddyfileFailClosedSite is the stand-in for a host that cannot be
// exported faithfully: its addresses answer 503. domains must already
// have passed caddyfileAddressSafe.
func caddyfileFailClosedSite(domains []string, why string) string {
	return fmt.Sprintf("%s {\n\t# Not exported: %s. This site fails closed instead.\n\trespond 503\n}\n", strings.Join(domains, ", "), caddyfileComment(why))
}

// renderProxyHostSite writes the site block for a host whose values passed
// proxyHostFieldsProblem. why is non-empty when the host still cannot be
// represented.
func renderProxyHostSite(p models.ProxyHost, cert *models.Certificate, domains []string, snippetMatchers map[string]bool) (string, string) {
	var b strings.Builder

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

	siteAddrs := domains
	if p.CertificateID == 0 && !p.SSLEnabled && !p.SSLForced {
		// SSL off: served on :443 and, without a redirect, on :80 (T-0927).
		siteAddrs = caddyfilePlainHTTPAddresses(domains)
	}
	fmt.Fprintf(&b, "%s {\n", strings.Join(siteAddrs, ", "))

	// TLS block — cert source. Auto (ACME) is implicit when the site has a
	// public hostname; we only need an explicit `tls` directive for custom
	// certs or specific CA hints.
	if p.CertificateID > 0 {
		switch {
		case cert != nil && cert.Source == models.CertSourcePath && cert.CertPath != "" && cert.KeyPath != "":
			fmt.Fprintf(&b, "\ttls %s %s\n", caddyfileValue(cert.CertPath), caddyfileValue(cert.KeyPath))
		case cert != nil && cert.Source == models.CertSourcePEM:
			fmt.Fprintf(&b, "\t# tls: stored PEM certificate %q — CaddyUI loads it into Caddy's certificate pool directly (load_pem); a Caddyfile would need the files on disk\n", caddyfileComment(cert.Name))
		case cert != nil && cert.Source == models.CertSourceManaged:
			fmt.Fprintf(&b, "\t# tls: managed certificate %q (%s) — Caddy obtains it via DNS-01 and serves it by SNI\n", caddyfileComment(cert.Name), caddyfileComment(cert.Domains))
		default:
			fmt.Fprintf(&b, "\t# Custom certificate ID %d (uploaded via CaddyUI; not represented in Caddyfile — Caddy will use its automatic cert resolution at runtime)\n", p.CertificateID)
		}
	}
	// SSL off with no certificate is expressed by the site addresses above
	// (caddyfilePlainHTTPAddresses); `tls off` is not a Caddy v2 form.

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
			toks := make([]string, len(files))
			for i, f := range files {
				toks[i] = caddyfileValue(f)
			}
			fmt.Fprintf(&b, "\t\t\ttrust_pool file %s\n", strings.Join(toks, " "))
		}
		b.WriteString("\t\t}\n\t}\n")
	}

	// Issue #184: the Path matcher narrows the JSON route to matching paths,
	// so the Caddyfile carries the same matcher on reverse_proxy.
	pathDef, stripToken, _ := caddyfilePathMatcher(p) // representable: checked by proxyHostFieldsProblem
	// The generated matchers take names the Advanced config does not use —
	// in its own text or in a snippet it imports — so the two can never
	// define one name twice (which Caddy rejects, taking the whole file
	// down with it).
	usedMatchers, ok := caddyfileMatcherNames(p.AdvancedConfig)
	if !ok {
		return "", "the Advanced config could not be read as Caddyfile syntax (an unclosed quote or heredoc, or a trailing backslash)"
	}
	for name := range snippetMatchers {
		usedMatchers[name] = true
	}
	blockedName := caddyfileFreeMatcherName("blocked", usedMatchers)
	pathName := caddyfileFreeMatcherName(caddyfilePathMatcherName, usedMatchers)
	// With Strip prefix the order-sensitive directives go in a `route` block
	// in the JSON route's order — blocker, Advanced config handlers, strip,
	// reverse_proxy. Caddyfile sorting would otherwise run `uri strip_prefix`
	// before `respond`/`abort`/`error`, so the exploit list and any Advanced
	// allowlist or maintenance response would see the stripped path, or run
	// after the proxy.
	wrapInRoute := stripToken != ""
	// v2.42.1: a `reverse_proxy { … }` block in the Advanced config is merged
	// into the host's own handler at sync time (v2.40.0), so its
	// sub-directives render inside the generated reverse_proxy block.
	advancedRest, advancedInner := splitAdvancedReverseProxyBlock(p.AdvancedConfig)
	// T-0931: one transport block, the generated options merged with the
	// Advanced block's own, as the live route merges them.
	transportLines := caddyfileTransportLines(p)
	var advTransport advancedTransport
	if len(transportLines) > 0 {
		advancedInner, advTransport = takeAdvancedTransport(advancedInner)
	}
	advancedInRoute := ""
	if wrapInRoute && strings.TrimSpace(advancedRest) != "" {
		var ok bool
		advancedRest, advancedInRoute, ok = splitAdvancedForRoute(advancedRest)
		if !ok {
			return "", "with Strip prefix on, this Advanced config cannot keep its handler order in Caddyfile syntax"
		}
	}

	// Path blocking (the "block common exploits" toggle that defaults on in
	// CaddyUI v2.11+). Mirrors the CaddyUI prompt's standard block list.
	if p.BlockCommonExploits && !wrapInRoute {
		b.WriteString(caddyfileExploitBlocker(blockedName))
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
			fmt.Fprintf(&b, "\t\tContent-Security-Policy %s\n", caddyfileValue(p.CSPHeader))
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
				fmt.Fprintf(&b, "\t\t%s %s\n", k, caddyfileValue(v))
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
		b.WriteString(caddyfileExploitBlocker(blockedName))
	}
	if advancedInRoute != "" {
		b.WriteString("\t# from Advanced config\n")
		b.WriteString(caddyfileIndent(strings.TrimRight(advancedInRoute, "\n")+"\n", "\t", false))
	}
	proxyMatcher := ""
	if pathDef != "" {
		fmt.Fprintf(&b, "\t@%s %s\n", pathName, pathDef)
		proxyMatcher = "@" + pathName + " "
		// Strip prefix mirrors the route's `rewrite strip_path_prefix`
		// handler under the same matcher.
		if stripToken != "" {
			fmt.Fprintf(&b, "\turi @%s strip_prefix %s\n", pathName, stripToken)
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
		fmt.Fprintf(&b, "\t\theader_up Host %s\n", caddyfileValue(p.UpstreamHostOverride))
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
				fmt.Fprintf(&b, "\t\theader_up %s %s\n", k, caddyfileValue(v))
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

	// Transport block — only emitted if anything inside is non-default.
	writeTransportBlock(&b, transportLines, advTransport)

	if strings.TrimSpace(advancedInner) != "" {
		b.WriteString("\t\t# from Advanced config\n")
		b.WriteString(caddyfileIndent(advancedInner, "\t\t", true))
	}
	b.WriteString("\t}\n")
	if wrapInRoute {
		site := b.String()
		b.Reset()
		b.WriteString(site[:proxyStart])
		b.WriteString("\troute {\n")
		b.WriteString(caddyfileIndent(site[proxyStart:], "\t", false))
		b.WriteString("\t}\n")
	}

	// Advanced raw config — verbatim user input, indented to match the site
	// block (lines that continue a quoted string are left as they are).
	if strings.TrimSpace(advancedRest) != "" {
		b.WriteString("\n\t# --- Advanced raw config (from CaddyUI) ---\n")
		b.WriteString(caddyfileIndent(strings.TrimRight(advancedRest, "\n")+"\n", "\t", false))
	}

	b.WriteString("}\n")
	return b.String(), ""
}

// RenderRedirectionCaddyfile emits a redirection host as a Caddyfile site
// block using the `redir` directive.
func RenderRedirectionCaddyfile(r models.RedirectionHost) string {
	var b strings.Builder
	domains := r.DomainList()
	if len(domains) == 0 {
		return ""
	}
	if !caddyfileAddressSafe(domains...) {
		return fmt.Sprintf("# Redirection host #%d omitted: its domains cannot be written safely as Caddyfile syntax; see it in CaddyUI.\n", r.ID)
	}
	// The destination is concatenated into one bare token with the scheme.
	switch r.ForwardScheme {
	case "", "auto", "http", "https":
	default:
		return caddyfileFailClosedSite(domains, "the redirect scheme cannot be written safely as Caddyfile syntax")
	}
	if !caddyfileBareSafe(r.ForwardDomain) {
		return caddyfileFailClosedSite(domains, "the redirect destination cannot be written safely as Caddyfile syntax")
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
	if sites, err := checkCaddyfileSites(b.String(), nil); err != nil || len(sites) != 1 {
		return caddyfileFailClosedSite(domains, "the generated block would not stay self-contained")
	}
	return b.String()
}

// RenderRawRouteCaddyfile emits a CaddyUI raw route. If the route stored
// the original Caddyfile source (CaddyfileSrc field), that's included
// verbatim. Otherwise we fall back to a comment pointing the reader at
// the CaddyUI Advanced page, since translating arbitrary Caddy JSON back
// to Caddyfile cleanly is a much bigger problem than this exporter wants
// to solve.
//
// Issue #184 review: the source is written only when it is complete,
// self-contained site blocks (checkCaddyfileSites) whose addresses the
// route's stored JSON actually serves (rawRouteTextProblem), and the
// server's veto (opts.RawRouteVeto) has no objection. Otherwise the route is
// left out with a comment saying why.
func RenderRawRouteCaddyfile(r models.RawRoute) string {
	return renderRawRoute(r, ExportOptions{})
}

func renderRawRoute(r models.RawRoute, opts ExportOptions) string {
	var b strings.Builder
	label := r.Label
	if label == "" {
		label = fmt.Sprintf("raw-%d", r.ID)
	}
	fmt.Fprintf(&b, "# Raw route #%d — %s\n", r.ID, caddyfileComment(label))
	src := strings.TrimSpace(r.CaddyfileSrc)
	if src != "" {
		src += "\n"
	}
	why := ""
	if src != "" && opts.tenant(r.OwnerID) && len(src) > MaxTenantCaddyfileBytes+1 {
		// Issue #184 round 10: a tenant's oversized text (a row stored
		// before the limit) is refused before anything lexes it; +1 is the
		// newline added above.
		why = "its Caddyfile is larger than a non-admin account may save"
	} else if src != "" {
		sites, err := checkCaddyfileSites(src, opts.importsFor(r.OwnerID))
		switch {
		case err != nil || len(sites) == 0:
			why = opts.importProblem(src, r.OwnerID)
			if why == "" {
				why = "its Caddyfile is not a set of self-contained site blocks"
			}
		default:
			why = rawRouteTextProblem(r, sites)
			if why == "" && opts.tenant(r.OwnerID) {
				if opts.RawRouteVeto == nil {
					why = "its Caddyfile could not be re-checked"
				} else {
					why = opts.RawRouteVeto(r, src)
				}
			}
		}
	}
	if why != "" {
		fmt.Fprintf(&b, "# (omitted: %s — open it in CaddyUI → Advanced)\n", caddyfileComment(why))
	} else if src != "" {
		b.WriteString(src) // exactly the text the veto judged
	} else {
		b.WriteString("# (JSON-typed raw route — open it in CaddyUI → Advanced to see / edit)\n")
	}
	return b.String()
}

// caddyfilePathMatcherName names the matcher that carries a proxy host's
// Path matcher in the Caddyfile excerpt (issue #184).
const caddyfilePathMatcherName = "caddyui_path"

// caddyfileExploitBlocker is the Caddyfile form of the "block common
// exploits" handler, with its matcher called name.
func caddyfileExploitBlocker(name string) string {
	return "\t@" + name + " path /.env* /wp-admin* /wp-login* /phpmyadmin* /.git/* /xmlrpc.php\n\trespond @" + name + " 403\n"
}

// caddyfileMatcherNames returns every name src refers to as `@name`, in any
// position (definitions and uses alike). ok is false when src does not lex.
func caddyfileMatcherNames(src string) (map[string]bool, bool) {
	toks, err := lexCaddyfile(src)
	if err != nil {
		return nil, false
	}
	names := map[string]bool{}
	for _, t := range toks {
		if strings.HasPrefix(t.text, "@") {
			names[t.text[1:]] = true
		}
	}
	return names, true
}

// importedMatcherNames returns every `@name` in the snippets src imports,
// directly or through another snippet: the names the generated matchers
// must also avoid.
func (o ExportOptions) importedMatcherNames(src string) map[string]bool {
	names := map[string]bool{}
	if len(o.Snippets) == 0 {
		return names
	}
	byName, _ := o.validSnippets()
	seen := map[string]bool{}
	for pending := []string{src}; len(pending) > 0; {
		text := pending[0]
		pending = pending[1:]
		for _, name := range caddyfileImportedNames(text) {
			if body := byName[name]; body != "" && !seen[name] {
				seen[name] = true
				pending = append(pending, body)
				if used, ok := caddyfileMatcherNames(body); ok {
					for n := range used {
						names[n] = true
					}
				}
			}
		}
	}
	return names
}

// caddyfileFreeMatcherName is base, or base_2, base_3, … — the first that
// is not in used.
func caddyfileFreeMatcherName(base string, used map[string]bool) string {
	name := base
	for n := 2; used[name]; n++ {
		name = fmt.Sprintf("%s_%d", base, n)
	}
	return name
}

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

// caddyfileValue is caddyfileToken for a value proxyHostFieldsProblem has
// already accepted.
func caddyfileValue(s string) string {
	t, _ := caddyfileToken(s)
	return t
}

// proxyHostFieldsProblem checks every user-supplied value the proxy host
// exporter writes outside a comment, by the rule for its position:
// caddyfileToken for free values (bare or backticked), caddyfileBareSafe
// for values concatenated into a larger token or written bare, an RFC 9110
// name for header fields, and a plain keyword for option names. It returns
// why the host cannot be exported, or "".
func proxyHostFieldsProblem(p models.ProxyHost, cert *models.Certificate) string {
	if _, _, ok := caddyfilePathMatcher(p); !ok {
		why := caddyfileTokenProblem(p.PathMatcher)
		if why == "" {
			why = "cannot be written safely as Caddyfile syntax"
		}
		return "the path matcher " + why
	}
	var bad []string
	token := func(field, v string) {
		if why := caddyfileTokenProblem(v); why != "" {
			bad = append(bad, field+" "+why)
		}
	}
	bare := func(field, v string) {
		if !caddyfileBareSafe(v) {
			if why := caddyfileTokenProblem(v); why != "" {
				bad = append(bad, field+" "+why)
			} else {
				bad = append(bad, field+" must be one plain word (no spaces, quotes or backslashes)")
			}
		}
	}
	// The primary upstream is the first reverse_proxy argument when there is
	// no path matcher, where `/`, `*` or `@` would make it a matcher.
	if p.ForwardHost != "" {
		bare("the upstream host", p.ForwardHost)
		if strings.ContainsAny(p.ForwardHost[:1], "/*") {
			bad = append(bad, "the upstream host starts like a request matcher")
		}
	}
	for _, eu := range p.ExtraUpstreamList() {
		if eu = strings.TrimSpace(eu); eu != "" {
			bare("an extra upstream", eu)
		}
	}
	if p.UpstreamSNI != "" {
		token("the upstream SNI", p.UpstreamSNI)
	}
	if len(p.ExtraUpstreamList()) > 0 && p.LBPolicy != "" && !caddyfileWordRe.MatchString(p.LBPolicy) {
		bad = append(bad, "the load-balancing policy is not a plain keyword")
	}
	if p.UpstreamHostOverride != "" {
		token("the upstream Host header", p.UpstreamHostOverride)
	}
	if p.SecurityHeadersEnabled && p.CSPHeader != "" {
		token("the Content-Security-Policy", p.CSPHeader)
	}
	if p.ClientAuthEnabled() {
		if !caddyfileWordRe.MatchString(p.ClientAuthMode) {
			bad = append(bad, "the client certificate mode is not a plain keyword")
		}
		for _, f := range p.ClientAuthCAFileList() {
			token("a client CA file path", f)
		}
	}
	if p.CertificateID > 0 && cert != nil && cert.Source == models.CertSourcePath && cert.CertPath != "" && cert.KeyPath != "" {
		token("the certificate file path", cert.CertPath)
		token("the certificate key path", cert.KeyPath)
	}
	for _, hm := range []struct {
		kind string
		m    map[string]string
	}{{"request", p.CustomReqHeaderMap()}, {"response", p.CustomRespHeaderMap()}} {
		keys := make([]string, 0, len(hm.m))
		for k := range hm.m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !caddyfileHeaderNameRe.MatchString(k) {
				bad = append(bad, "a custom "+hm.kind+" header name is not an HTTP field name starting with a letter or digit")
				continue
			}
			if v := hm.m[k]; v != "" {
				token("custom "+hm.kind+" header "+k+": its value", v)
			}
		}
	}
	for _, h := range append(splitCSV(p.StripReqHeaders), splitCSV(p.StripRespHeaders)...) {
		if !caddyfileHeaderNameRe.MatchString(h) {
			bad = append(bad, "a stripped header name is not an HTTP field name starting with a letter or digit")
		}
	}
	if len(bad) == 0 {
		return ""
	}
	bad = slices.Compact(bad)
	return strings.Join(bad, "; ")
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

// splitAdvancedReverseProxyBlock separates each top-level `reverse_proxy {`
// block from the rest of an Advanced config, reading src as Caddy's lexer
// does. A block counts only when `reverse_proxy` is the first token of a
// line at depth 0 and the only other token on that line is an unquoted `{`
// — the form the sync merges into the host's own handler (v2.40.0) — so
// text inside a quoted string, backtick string or heredoc is never taken
// apart. inner is the blocks' contents, verbatim; rest is everything else,
// verbatim. When src does not lex, or a block is laid out in a way this
// does not model, nothing is split: the text then stays at site level as
// written, where Caddy reads it the way the checks did.
func splitAdvancedReverseProxyBlock(src string) (rest, inner string) {
	if strings.TrimSpace(src) == "" {
		return src, ""
	}
	toks, err := lexCaddyfile(src)
	if err != nil {
		return src, ""
	}
	runes := []rune(src)
	// lineStart is the offset of the line holding offset off; blankBetween
	// reports whether runes[from:to] is only spaces and tabs.
	lineStart := func(off int) int {
		for off > 0 && runes[off-1] != '\n' {
			off--
		}
		return off
	}
	blankBetween := func(from, to int) bool {
		for _, r := range runes[from:to] {
			if r != ' ' && r != '\t' && r != '\r' {
				return false
			}
		}
		return true
	}
	// afterLine is the offset just past the newline that ends the line
	// holding off (or the end of src).
	afterLine := func(off int) int {
		for off < len(runes) && runes[off] != '\n' {
			off++
		}
		if off < len(runes) {
			off++
		}
		return off
	}
	brace := func(i int, b string) bool { return toks[i].text == b && !toks[i].quoted }
	var restB, innerB strings.Builder
	kept, depth := 0, 0
	for i := 0; i < len(toks); i++ {
		if depth == 0 && toks[i].text == "reverse_proxy" && cfIsNewLine(toks, i) &&
			i+1 < len(toks) && brace(i+1, "{") && cfIsNewLine(toks, i+2) {
			d, j := 1, i+2
			for ; j < len(toks) && d > 0; j++ {
				if brace(j, "{") {
					d++
				} else if brace(j, "}") {
					d--
				}
			}
			closeTok := j - 1
			from := lineStart(toks[i].start)
			bodyFrom := afterLine(toks[i+1].end)
			bodyTo := lineStart(toks[closeTok].start)
			if d == 0 && cfIsNewLine(toks, closeTok) && (j >= len(toks) || cfIsNewLine(toks, j)) &&
				blankBetween(from, toks[i].start) && blankBetween(bodyTo, toks[closeTok].start) && bodyFrom <= bodyTo {
				restB.WriteString(string(runes[kept:from]))
				innerB.WriteString(string(runes[bodyFrom:bodyTo]))
				kept = afterLine(toks[closeTok].end)
				i = closeTok
				continue
			}
			return src, ""
		}
		if brace(i, "{") {
			depth++
		} else if brace(i, "}") {
			depth--
		}
	}
	if kept == 0 {
		return src, ""
	}
	restB.WriteString(string(runes[kept:]))
	return restB.String(), innerB.String()
}

// caddyfileIndent prefixes every non-empty line of src with prefix, after
// removing the leading whitespace all of those lines share when dedent is
// set. A line that begins inside a quoted or backtick string is part of
// that string's value and is left exactly as it is; heredoc lines shift
// together with their closing marker, so the heredoc's value is unchanged.
// src must end with a newline. When src does not lex, every non-empty line
// is prefixed (the caller's self-containment check then refuses it).
func caddyfileIndent(src, prefix string, dedent bool) string {
	toks, err := lexCaddyfile(src)
	var lines []string
	if strings.HasSuffix(src, "\n") {
		lines = strings.SplitAfter(src[:len(src)-1], "\n")
		lines[len(lines)-1] += "\n"
	} else {
		lines = strings.SplitAfter(src, "\n")
	}
	// inString[i] reports whether line i begins inside a quoted string.
	// Tokens are in source order and do not overlap, so the only token that
	// can hold a line's first rune is the first one ending after it; one
	// pass over lines and tokens together keeps this linear (issue #184
	// round 7: a nested loop made a large Advanced config cost seconds).
	inString := make([]bool, len(lines))
	if err == nil {
		off, j := 0, 0
		for i, line := range lines {
			for j < len(toks) && toks[j].end <= off {
				j++
			}
			if j < len(toks) {
				t := toks[j]
				inString[i] = t.quoted && !t.heredoc && t.start < off
			}
			off += utf8.RuneCountInString(line)
		}
	}
	common := ""
	if dedent {
		first := true
		for i, line := range lines {
			body := strings.TrimRight(line, "\r\n")
			if inString[i] || body == "" {
				continue
			}
			lead := body[:len(body)-len(strings.TrimLeft(body, " \t"))]
			if first {
				common, first = lead, false
				continue
			}
			for !strings.HasPrefix(lead, common) {
				common = common[:len(common)-1]
			}
		}
	}
	var b strings.Builder
	for i, line := range lines {
		if inString[i] || strings.TrimRight(line, "\r\n") == "" {
			b.WriteString(line)
			continue
		}
		b.WriteString(prefix + strings.TrimPrefix(line, common))
	}
	return b.String()
}
