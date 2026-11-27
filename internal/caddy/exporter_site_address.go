// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"net"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

// caddyfileSiteAddresses returns domains as Caddyfile site addresses, each
// host written the way the live route matches it (models.NormalizeHostname,
// as BuildProxyRoute and BuildRedirectRoute use): lower-cased, a trailing
// dot removed, repeats left out. A stored `Old.Example.Test.` written
// verbatim makes Caddy refuse the whole file ("subject does not qualify for
// certificate"), while the live route serves old.example.test (T-0932). A
// port, scheme or path an admin's row carries stays as it is, as before;
// the live route ignores the port (it matches the host on CaddyUI's
// standard listeners) and matches a scheme literally, so such rows differ
// from live as they always have. A domain with no host and no port left
// (empty, or dots) is dropped.
func caddyfileSiteAddresses(domains []string) []string {
	out := make([]string, 0, len(domains))
	seen := map[string]bool{}
	for _, d := range domains {
		a := caddyfileSiteAddress(d)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// caddyfileSiteAddress is caddyfileSiteAddresses for one domain. A value
// holding a brace is left alone (lower-casing would rename a placeholder);
// caddyfileAddressSafe refuses it anyway.
func caddyfileSiteAddress(d string) string {
	d = strings.TrimSpace(d)
	if d == "" || strings.ContainsAny(d, "{}") {
		return d
	}
	scheme := ""
	if i := strings.Index(d, "://"); i >= 0 {
		scheme, d = strings.ToLower(d[:i+3]), d[i+3:]
	}
	path := ""
	if i := strings.IndexByte(d, '/'); i >= 0 {
		d, path = d[:i], d[i:]
	}
	host, port := d, ""
	if h, p, err := net.SplitHostPort(d); err == nil {
		host, port = h, p
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if port != "" {
		return scheme + net.JoinHostPort(host, port) + path
	}
	if strings.Trim(host, ".") == "" {
		return ""
	}
	return scheme + host + path
}

// caddyfilePlainHTTPAddresses returns the site addresses for a proxy host
// with SSL off, no certificate, no client-certificate auth and Force SSL
// off (caddyfileServesPlainHTTP). The live sync serves such a host from
// srv0 on :443 and from CaddyUI's plain :80 server without a redirect
// (buildHTTPRoutes); a Caddyfile says the same with both an http:// and an
// https:// address. `tls off`, which the export used to write, is not a
// Caddy v2 directive form, and Caddy refuses the whole file over it
// (T-0927). An address that already names a scheme stays as it is. One
// with a port (an admin's row may carry one) gets one
// scheme only — https:// on 443, http:// otherwise — since Caddy refuses
// http:// on 443 and an HTTP and HTTPS listener on one port. Repeats are
// left out.
func caddyfilePlainHTTPAddresses(addrs []string) []string {
	out := make([]string, 0, 2*len(addrs))
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range addrs {
		switch port := caddyfileAddressPort(a); {
		case strings.Contains(a, "://"):
			add(a)
		case port == "443":
			add("https://" + a)
		case port != "":
			add("http://" + a)
		default:
			add("http://" + a)
			add("https://" + a)
		}
	}
	return out
}

// caddyfileAddressPort returns the port of a scheme-less site address, or
// "" when it has none.
func caddyfileAddressPort(a string) string {
	if i := strings.IndexByte(a, '/'); i >= 0 {
		a = a[:i]
	}
	if _, port, err := net.SplitHostPort(a); err == nil {
		return port
	}
	return ""
}

// caddyfileServesPlainHTTP reports whether p is exported with http:// and
// https:// addresses (T-0927): SSL off, no certificate, Force SSL off, and
// no client-certificate auth, whose `tls { client_auth … }` block Caddy
// refuses in a site that also listens on plain HTTP ("server listening on
// [:80] is HTTP, but attempts to configure TLS connection policies").
func caddyfileServesPlainHTTP(p models.ProxyHost) bool {
	return p.CertificateID == 0 && !p.SSLEnabled && !p.SSLForced && !p.ClientAuthEnabled()
}
