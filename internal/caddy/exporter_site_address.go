// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"net"
	"strings"
)

// caddyfileSiteAddresses returns domains as Caddyfile site addresses, each
// written the way the live route matches it (models.NormalizeHostname, as
// BuildProxyRoute and BuildRedirectRoute use): the host lower-cased and a
// trailing dot removed, repeats dropped. A stored `Old.Example.Test.`
// written verbatim makes Caddy refuse the whole file ("subject does not
// qualify for certificate"), while the live route serves old.example.test
// (T-0932). A scheme, port or path an admin's row carries stays as it is.
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
	if host, port, err := net.SplitHostPort(d); err == nil {
		d = net.JoinHostPort(strings.TrimSuffix(strings.ToLower(host), "."), port)
	} else {
		d = strings.TrimSuffix(strings.ToLower(d), ".")
	}
	return scheme + d + path
}

// caddyfilePlainHTTPAddresses returns the site addresses for a proxy host
// with SSL off, no certificate and Force SSL off. The live sync serves such
// a host from srv0 on :443 and from CaddyUI's plain :80 server without a
// redirect (buildHTTPRoutes); a Caddyfile says the same with both an
// http:// and an https:// address. `tls off`, which the export used to
// write, is not a Caddy v2 directive form, and Caddy refuses the whole
// file over it (T-0927). An address that already names a scheme stays as
// it is; one with a port gets http:// only, so it is not a plain listener
// and an HTTPS listener on the same port.
func caddyfilePlainHTTPAddresses(addrs []string) []string {
	out := make([]string, 0, 2*len(addrs))
	for _, a := range addrs {
		switch {
		case strings.Contains(a, "://"):
			out = append(out, a)
		case caddyfileAddressHasPort(a):
			out = append(out, "http://"+a)
		default:
			out = append(out, "http://"+a, "https://"+a)
		}
	}
	return out
}

// caddyfileAddressHasPort reports whether a scheme-less site address
// carries a port.
func caddyfileAddressHasPort(a string) bool {
	if i := strings.IndexByte(a, '/'); i >= 0 {
		a = a[:i]
	}
	_, port, err := net.SplitHostPort(a)
	return err == nil && port != ""
}
