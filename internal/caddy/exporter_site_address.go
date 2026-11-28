// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"fmt"
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

// caddyfileServesPlainHTTP reports whether p is exported as served on
// plain HTTP as well as HTTPS: buildHTTPRoutes serves every host with
// Force SSL off on :80 without a redirect, whether SSL is on or not
// (T-0927, finding 10 of its review in T-0947). Not with client-certificate
// auth: Caddy refuses its `tls { client_auth … }` block in a site that also
// listens on plain HTTP ("server listening on [:80] is HTTP, but attempts
// to configure TLS connection policies"), and a client-certificate host
// must not be reachable without one (T-0967).
// Nor with a site-level `tls` directive in the Advanced config, which Caddy
// refuses in a site that also listens on HTTP for the same reason (T-0978
// review); the live route ignores those options, so the export keeps the
// host HTTPS-only and lists the :80 difference in its notes.
func caddyfileServesPlainHTTP(p models.ProxyHost, advancedTLS bool) bool {
	return !p.SSLForced && !p.ClientAuthEnabled() && !advancedTLS
}

// caddyfileAdvancedHasSiteTLS reports whether an Advanced config has a
// `tls` directive at site level, written there or brought in by a top-level
// `import` of one of snippets (name → `(name) { … }`). It fails safe to
// true when the text does not lex, an import names no known snippet, or a
// snippet places a directive from its arguments.
func caddyfileAdvancedHasSiteTLS(adv string, snippets map[string]string) bool {
	// Cheap pre-check: every case below needs one of these words, and a
	// large Advanced config is lexed by the exporter enough already.
	if !strings.Contains(adv, "tls") && !strings.Contains(adv, "import") && !strings.Contains(adv, "{args") {
		return false
	}
	toks, _, _, err := lexCaddyfileLenient(adv)
	if err != nil {
		return true
	}
	if caddyfileHasTLSAtDepth(toks, 0) {
		return true
	}
	depth := 0
	for i, t := range toks {
		switch {
		case t.quoted || t.heredoc:
		case t.text == "{":
			depth++
		case t.text == "}":
			depth--
		case depth == 0 && t.text == "import" && cfIsNewLine(toks, i):
			if i+1 >= len(toks) || cfIsNewLine(toks, i+1) {
				return true
			}
			body, ok := snippets[toks[i+1].text]
			if !ok {
				return true
			}
			stoks, _, _, err := lexCaddyfileLenient(body)
			if err != nil || caddyfileHasTLSAtDepth(stoks, 1) {
				return true
			}
		}
	}
	return false
}

// caddyfileHasTLSAtDepth reports whether toks has a `tls` directive (or a
// directive taken from snippet arguments) at line start at brace depth d.
func caddyfileHasTLSAtDepth(toks []cfToken, d int) bool {
	depth := 0
	for i, t := range toks {
		switch {
		case t.quoted || t.heredoc:
		case t.text == "{":
			depth++
		case t.text == "}":
			depth--
		case depth == d && cfIsNewLine(toks, i) && (t.text == "tls" || strings.HasPrefix(t.text, "{args")):
			return true
		}
	}
	return false
}

// caddyfileTLSFileLine returns the `tls <cert> <key>` line the export writes
// for p's certificate files, or "" when it writes none.
func caddyfileTLSFileLine(p models.ProxyHost, cert *models.Certificate) string {
	if p.CertificateID > 0 && cert != nil && cert.Source == models.CertSourcePath && cert.CertPath != "" && cert.KeyPath != "" {
		return fmt.Sprintf("\ttls %s %s\n", caddyfileValue(cert.CertPath), caddyfileValue(cert.KeyPath))
	}
	return ""
}

// caddyfilePlainHTTPTwinAddresses returns the http:// addresses of the
// plain-HTTP twin site a host with certificate files gets when Force SSL is
// off: one per address with no scheme and no port (an address with a port
// already names its one listener).
func caddyfilePlainHTTPTwinAddresses(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		if !strings.Contains(a, "://") && caddyfileAddressPort(a) == "" {
			out = append(out, "http://"+a)
		}
	}
	return out
}

// caddyfileSSLOnPlainHTTPAddresses returns the site addresses of a host
// with SSL on and Force SSL off (finding 10 of the T-0927 review): each
// address with no scheme and no port as http:// and https://, every other
// address unchanged.
func caddyfileSSLOnPlainHTTPAddresses(addrs []string) []string {
	out := make([]string, 0, 2*len(addrs))
	for _, a := range addrs {
		if !strings.Contains(a, "://") && caddyfileAddressPort(a) == "" {
			out = append(out, "http://"+a, "https://"+a)
		} else {
			out = append(out, a)
		}
	}
	return out
}

// caddyfileSiteCount is the number of sites renderProxyHostSite writes for
// p: two when it adds a plain-HTTP twin, otherwise one.
func caddyfileSiteCount(p models.ProxyHost, cert *models.Certificate, domains []string, advancedTLS bool) int {
	if caddyfileServesPlainHTTP(p, advancedTLS) && caddyfileTLSFileLine(p, cert) != "" && len(caddyfilePlainHTTPTwinAddresses(domains)) > 0 {
		return 2
	}
	return 1
}
