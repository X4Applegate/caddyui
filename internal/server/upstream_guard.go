// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Upstream SSRF guard (GHSA-r4wm-rgc5-q834, 3rd finding).
//
// A proxy host's ForwardHost/ForwardPort, its extra upstreams, and its upstream
// Host-header override all flow verbatim into Caddy's reverse_proxy `dial`
// (see caddy.BuildProxyRoute / client.go). Before v2.52.2 nothing constrained
// those values, so any account that can write a proxy host — including a
// low-privilege non-admin `user` account (per-row ownership, added in v2.52.1)
// — could point an upstream at the Caddy admin API (http://localhost:2019),
// the CaddyUI host's own loopback services, or cloud metadata
// (169.254.169.254) and read/alter internal state through the proxy. Combined
// with the user-settable upstream Host-header override, the admin API's origin
// check is defeated too, which is RCE-grade (POST /load rewrites Caddy).
//
// The guard is role-aware on purpose: proxying to loopback/LAN addresses is the
// primary, legitimate use of a reverse-proxy manager, so ADMINS are never
// restricted. Only NON-admin accounts are blocked from targeting loopback,
// unspecified, and link-local addresses (the SSRF-to-host / metadata vectors)
// and the configured Caddy admin endpoint. Private LAN ranges stay allowed so
// delegated users can still front their own internal apps.
//
// This is config-time validation. Caddy dials by the configured host on every
// request, so a determined attacker could still use DNS rebinding (resolve to a
// public IP at save time, loopback at dial time); defeating that needs
// per-dial enforcement Caddy does not expose here. The guard decisively closes
// the reported literal-address exploit and best-effort-resolves hostnames.

// ipBlockedForNonAdmin reports whether a resolved IP is one a non-admin account
// must not be able to reach as a proxy upstream.
func ipBlockedForNonAdmin(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || // 127.0.0.0/8, ::1
		ip.IsUnspecified() || // 0.0.0.0, ::
		ip.IsLinkLocalUnicast() || // 169.254.0.0/16 (incl. cloud metadata), fe80::/10
		ip.IsLinkLocalMulticast()
}

// hostFromUpstream extracts the host portion from an upstream value that may be
// a bare host, a "host:port" dial string, or a bracketed IPv6 literal.
func hostFromUpstream(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return h
}

// upstreamHostBlockedForNonAdmin classifies a single upstream host string.
// adminHost, when non-empty, is the configured Caddy admin endpoint host and is
// blocked outright (covers a remote admin endpoint that isn't loopback).
func upstreamHostBlockedForNonAdmin(host, adminHost string) bool {
	h := strings.ToLower(hostFromUpstream(host))
	if h == "" {
		return false
	}
	// Name-based loopback aliases that never resolve through ParseIP.
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if adminHost != "" && h == strings.ToLower(adminHost) {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ipBlockedForNonAdmin(ip)
	}
	// Hostname: best-effort resolve and block if ANY address is internal.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h)
	if err != nil {
		return false // unresolvable → don't block on an IP basis
	}
	for _, a := range addrs {
		if ipBlockedForNonAdmin(a.IP) {
			return true
		}
	}
	return false
}

// adminHostFromURL parses the host (no port) out of a Caddy admin URL. Returns
// "" for unix sockets or unparseable values.
func adminHostFromURL(adminURL string) string {
	adminURL = strings.TrimSpace(adminURL)
	if adminURL == "" || strings.HasPrefix(adminURL, "unix") || strings.Contains(adminURL, "unix") {
		return ""
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// validateProxyUpstreamsForUser returns a non-empty error message when a
// non-admin account tries to point any upstream (primary, extra, or Host
// override) at a blocked internal address. Admins are unrestricted.
func (s *Server) validateProxyUpstreamsForUser(cu *models.User, p *models.ProxyHost) string {
	if cu != nil && cu.Role == models.RoleAdmin {
		return ""
	}
	var adminHost string
	if s != nil && s.Caddy != nil {
		adminHost = adminHostFromURL(s.Caddy.AdminURL)
	}
	candidates := make([]string, 0, 4)
	candidates = append(candidates, p.ForwardHost)
	candidates = append(candidates, p.ExtraUpstreamList()...)
	if p.UpstreamHostOverride != "" {
		candidates = append(candidates, p.UpstreamHostOverride)
	}
	for _, c := range candidates {
		if strings.TrimSpace(c) == "" {
			continue
		}
		if upstreamHostBlockedForNonAdmin(c, adminHost) {
			return fmt.Sprintf("Upstream %q is not allowed: non-admin accounts cannot point a proxy at loopback, link-local, or internal management addresses (e.g. the Caddy admin API or cloud metadata). Ask an administrator if this upstream is legitimate.", strings.TrimSpace(c))
		}
	}
	return ""
}
