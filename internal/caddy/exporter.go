package caddy

import (
	"fmt"
	"sort"
	"strings"
	"time"

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
func RenderServerCaddyfile(serverName string, hosts []models.ProxyHost, redirects []models.RedirectionHost, raws []models.RawRoute) string {
	var b strings.Builder
	if serverName != "" {
		fmt.Fprintf(&b, "# CaddyUI export — %s\n", serverName)
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
		b.WriteString(RenderProxyHostCaddyfile(ph))
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
	var b strings.Builder

	// Site block header — space-separated hostname list per Caddyfile spec.
	domains := p.DomainList()
	if len(domains) == 0 {
		return ""
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
		elided = append(elided, fmt.Sprintf("active health check on %s", p.HealthCheckURI))
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
		fmt.Fprintf(&b, "# Owner: %s\n", p.OwnerEmail)
	}
	if p.Tags != "" {
		fmt.Fprintf(&b, "# Tags: %s\n", p.Tags)
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
		fmt.Fprintf(&b, "\t# Custom certificate ID %d (uploaded via CaddyUI; not represented in Caddyfile — Caddy will use its automatic cert resolution at runtime)\n", p.CertificateID)
	} else if !p.SSLEnabled {
		// SSL explicitly off — site listens on HTTP only.
		b.WriteString("\ttls off\n")
	}

	// Path blocking (the "block common exploits" toggle that defaults on in
	// CaddyUI v2.11+). Mirrors the CaddyUI prompt's standard block list.
	if p.BlockCommonExploits {
		b.WriteString("\t@blocked path /.env* /wp-admin* /wp-login* /phpmyadmin* /.git/* /xmlrpc.php\n")
		b.WriteString("\trespond @blocked 403\n")
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

	// reverse_proxy block — primary upstream + extras + transport tweaks.
	upstreamSpec := upstreamDial(p.ForwardScheme, p.ForwardHost, p.ForwardPort)
	for _, eu := range p.ExtraUpstreamList() {
		eu = strings.TrimSpace(eu)
		if eu != "" {
			upstreamSpec += " " + eu
		}
	}
	fmt.Fprintf(&b, "\treverse_proxy %s {\n", upstreamSpec)

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
	if p.ForwardScheme == "https" || p.UpstreamSNI != "" || p.KeepaliveConns > 0 || p.UpstreamTimeoutSec > 0 {
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
		b.WriteString("\t\t}\n")
	}

	b.WriteString("\t}\n")

	// Advanced raw config — verbatim user input, indented to match the site
	// block. Trailing newline preserved.
	if strings.TrimSpace(p.AdvancedConfig) != "" {
		b.WriteString("\n\t# --- Advanced raw config (from CaddyUI) ---\n")
		for _, line := range strings.Split(p.AdvancedConfig, "\n") {
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
	if r.OwnerEmail != "" {
		fmt.Fprintf(&b, "# Owner: %s\n", r.OwnerEmail)
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
	fmt.Fprintf(&b, "# Raw route #%d — %s\n", r.ID, label)
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
