// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"net"
	"strings"
)

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
