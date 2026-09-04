package server

import (
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.36.2 (issue #65): the Certificates page's "Caddy-managed (ACME)" list
// must include Advanced routes' hostnames under the same rule as proxy hosts
// and redirects — enabled, no custom certificate — with the same wildcard
// mapping and lifecycle status, and without listing anything twice.
func TestAutoManagedDomainsIncludeAdvancedRoutes(t *testing.T) {
	certs := []models.Certificate{
		{ID: 7, Name: "Example wildcard", Source: models.CertSourceManaged, Domains: "*.example.com"},
	}
	states := []models.CertificateLifecycleStatus{
		{Identifier: "health.example.net", Phase: "active", Level: "INFO", Message: "certificate obtained successfully"},
	}
	hosts := []models.ProxyHost{{Domains: "app.example.org", Enabled: true, SSLEnabled: true}}
	redirs := []models.RedirectionHost{{Domains: "old.example.org", Enabled: true, SSLEnabled: true}}
	route := func(host string) string {
		return `{"match":[{"host":["` + host + `"]}],"handle":[{"handler":"static_response","status_code":200}]}`
	}
	raws := []models.RawRoute{
		{Enabled: true, JSONData: route("health.example.net")},                                                                          // must appear
		{Enabled: true, JSONData: route("api.example.com")},                                                                             // must appear, covered by the wildcard
		{Enabled: true, JSONData: route("app.example.org")},                                                                             // same domain as the proxy host: listed once
		{Enabled: false, JSONData: route("off.example.net")},                                                                            // disabled: absent
		{Enabled: true, CertificateID: 3, JSONData: route("custom.example.net")},                                                        // custom cert: absent (it's a custom cert row instead)
		{Enabled: true, JSONData: `{"match":[{"path":["/lbhealthcheck"]}],"handle":[{"handler":"static_response","status_code":200}]}`}, // no host: nothing to secure
	}

	got := collectAutoManagedDomains(certs, states, hosts, redirs, raws)

	wantOrder := []string{"app.example.org", "old.example.org", "health.example.net", "api.example.com"}
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d auto-managed domains %v, want %v", len(got), domainsOf(got), wantOrder)
	}
	byDomain := map[string]autoDomainView{}
	for i, v := range got {
		byDomain[v.Domain] = v
		if v.Domain != wantOrder[i] {
			t.Errorf("position %d = %q, want %q (proxy → redirect → Advanced route order)", i, v.Domain, wantOrder[i])
		}
	}
	for _, absent := range []string{"off.example.net", "custom.example.net"} {
		if _, ok := byDomain[absent]; ok {
			t.Errorf("%s must not be listed as Caddy-managed", absent)
		}
	}
	if v := byDomain["health.example.net"]; v.Lifecycle == nil || v.Lifecycle.Phase != "active" {
		t.Errorf("lifecycle status not attached to an Advanced route's domain: %+v", v.Lifecycle)
	} else if v.UsesWildcard || v.CertificateName != "Direct certificate" {
		t.Errorf("health.example.net should be a direct certificate, got %+v", v)
	}
	if v := byDomain["api.example.com"]; !v.UsesWildcard || v.CertificateName != "Example wildcard" {
		t.Errorf("api.example.com should map to the managed wildcard, got %+v", v)
	}
}

func domainsOf(views []autoDomainView) []string {
	out := make([]string, 0, len(views))
	for _, v := range views {
		out = append(out, v.Domain)
	}
	return out
}
