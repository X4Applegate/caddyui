// SPDX-License-Identifier: Apache-2.0

package server

import (
	"path/filepath"
	"reflect"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestParsePlainDNSServers(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"blank", "", nil},
		{"whitespace", "   ", nil},
		{"single ip with port", "1.1.1.1:53", []string{"1.1.1.1:53"}},
		{"single ip default port", "1.1.1.1", []string{"1.1.1.1:53"}},
		{"comma list mixed ports", "1.1.1.1, 8.8.8.8:5353", []string{"1.1.1.1:53", "8.8.8.8:5353"}},
		{"newline list", "1.1.1.1\n8.8.8.8", []string{"1.1.1.1:53", "8.8.8.8:53"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePlainDNSServers(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("servers = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// issue #116: an admin-configured ACME DNS-01 resolver list must be emitted
// into every DNS-01 automation policy's challenges.dns.resolvers, so Caddy
// checks TXT-record propagation against those servers instead of the
// container's default resolver (the split-horizon DNS failure mode).
func TestBuildDNSAutomationPoliciesIncludesACMEResolvers(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for key, value := range map[string]string{
		settingRoute53AccessKeyID:     "AKIAEXAMPLE",
		settingRoute53SecretAccessKey: "secret",
		settingACMEDNSResolvers:       "1.1.1.1, 8.8.8.8:5353",
	} {
		if err := models.SetSetting(conn, key, value); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{DB: conn}
	policies := s.buildDNSAutomationPolicies([]models.ProxyHost{
		{Domains: "split.example.com", Enabled: true, SSLEnabled: true, DNSProvider: dns.Route53, DNSZoneID: "ZSPLIT"},
	}, nil, nil, nil)
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(policies))
	}
	issuers := policies[0]["issuers"].([]any)
	challenge := issuers[0].(map[string]any)["challenges"].(map[string]any)["dns"].(map[string]any)
	want := []any{"1.1.1.1:53", "8.8.8.8:5353"}
	if got, _ := challenge["resolvers"].([]any); !reflect.DeepEqual(got, want) {
		t.Fatalf("resolvers = %#v, want %#v", got, want)
	}
}

// Without the setting, Caddy's challenges.dns config must carry no resolvers
// key at all — not an empty list — so Caddy's own default resolver applies.
func TestBuildDNSAutomationPoliciesOmitsResolversWhenUnset(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	for key, value := range map[string]string{
		settingRoute53AccessKeyID:     "AKIAEXAMPLE",
		settingRoute53SecretAccessKey: "secret",
	} {
		if err := models.SetSetting(conn, key, value); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{DB: conn}
	policies := s.buildDNSAutomationPolicies([]models.ProxyHost{
		{Domains: "default.example.com", Enabled: true, SSLEnabled: true, DNSProvider: dns.Route53, DNSZoneID: "ZDEFAULT"},
	}, nil, nil, nil)
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(policies))
	}
	issuers := policies[0]["issuers"].([]any)
	challenge := issuers[0].(map[string]any)["challenges"].(map[string]any)["dns"].(map[string]any)
	if _, exists := challenge["resolvers"]; exists {
		t.Fatalf("resolvers = %#v, want key absent", challenge["resolvers"])
	}
}
