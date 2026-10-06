// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
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
		log.Printf("caddy sync: %s: route skipped, not allowed for a non-admin owner: %s", what, why)
		return nil, false
	}
	return route, true
}

// tenantTextViolation checks free text a non-admin submits that Caddy will
// parse as a Caddyfile (a proxy host's Advanced config, an Advanced route's
// Caddyfile source, a pasted Caddyfile): env/file placeholders, and `import`
// of anything other than a snippet name (an import path reads a file inside the
// Caddy container, and a parse error echoes its first token).
func tenantTextViolation(text string) string {
	if containsDangerousPlaceholder(text) {
		return "{env.…}, {file.…} and {$…} placeholders read the Caddy server's environment and files and are admin-only"
	}
	for _, m := range caddyfileImportRe.FindAllStringSubmatch(text, -1) {
		if !snippetNameRe.MatchString(m[1]) {
			return fmt.Sprintf("`import %s` reads a file on the Caddy server — only snippet names may be imported", m[1])
		}
	}
	return ""
}

var (
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
	if why := tenantTextViolation(rr.CaddyfileSrc); why != "" {
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
