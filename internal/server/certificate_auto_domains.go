package server

import "github.com/X4Applegate/caddyui/internal/models"

// collectAutoManagedDomains lists every hostname Caddy obtains a certificate
// for automatically — enabled, TLS on, no custom certificate — across proxy
// hosts, redirects and, since v2.36.2 (issue #65), Advanced routes. Caddy's
// automatic HTTPS covers a route's host matchers exactly as it covers a proxy
// host's domains, and certificateProbeTargets already tracked them; the
// Certificates page simply never listed them, so an Advanced route's
// certificate was invisible there while the same domain on a proxy host
// showed up. Duplicates across kinds collapse to the first occurrence, in
// proxy → redirect → Advanced-route order, matching the previous behaviour.
func collectAutoManagedDomains(
	certs []models.Certificate,
	lifecycleStates []models.CertificateLifecycleStatus,
	hosts []models.ProxyHost,
	redirs []models.RedirectionHost,
	raws []models.RawRoute,
) []autoDomainView {
	seen := map[string]bool{}
	var out []autoDomainView
	add := func(domain string) {
		if domain == "" || seen[domain] {
			return
		}
		seen[domain] = true
		view := autoDomainView{Domain: domain, CertificateName: "Direct certificate"}
		statusDomains := []string{domain}
		if cert := managedWildcardForHost(certs, domain); cert != nil {
			view.CertificateName = cert.Name
			view.UsesWildcard = true
			statusDomains = cert.DomainList()
		}
		view.Lifecycle = certificateLifecycleForDomains(lifecycleStates, statusDomains)
		out = append(out, view)
	}
	for _, h := range hosts {
		if !h.Enabled || !h.SSLEnabled || h.CertificateID != 0 {
			continue
		}
		for _, d := range h.DomainList() {
			add(d)
		}
	}
	for _, rh := range redirs {
		if !rh.Enabled || !rh.SSLEnabled || rh.CertificateID != 0 {
			continue
		}
		for _, d := range rh.DomainList() {
			add(d)
		}
	}
	// Advanced routes have no SSL toggle: Caddy secures whatever host matchers
	// they carry unless a custom certificate is assigned — the same rule
	// certificateProbeTargets applies. A route with no host matcher (path- or
	// port-only) has nothing to secure and contributes nothing.
	for _, rr := range raws {
		if !rr.Enabled || rr.CertificateID != 0 {
			continue
		}
		for _, d := range rawRouteHosts(rr) {
			add(d)
		}
	}
	return out
}
