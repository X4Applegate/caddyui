package server

import (
	"reflect"
	"testing"
)

func TestClassifyVerifyResolver(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantMode    verifyResolverMode
		wantServers []string
	}{
		{"blank", "", verifyResolverDefault, nil},
		{"whitespace", "   ", verifyResolverDefault, nil},
		{"https DoH", "https://dns.google/dns-query", verifyResolverDoHURL, []string{"https://dns.google/dns-query"}},
		{"http DoH", "http://internal.doh/dns-query", verifyResolverDoHURL, []string{"http://internal.doh/dns-query"}},
		{"single ip with port", "192.168.1.10:53", verifyResolverPlainDNS, []string{"192.168.1.10:53"}},
		{"single ip default port", "192.168.1.10", verifyResolverPlainDNS, []string{"192.168.1.10:53"}},
		{"comma list mixed ports", "10.0.0.1, 10.0.0.2:5353", verifyResolverPlainDNS, []string{"10.0.0.1:53", "10.0.0.2:5353"}},
		{"newline list", "10.0.0.1\n10.0.0.2", verifyResolverPlainDNS, []string{"10.0.0.1:53", "10.0.0.2:53"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mode, servers := classifyVerifyResolver(tc.raw)
			if mode != tc.wantMode {
				t.Fatalf("mode = %d, want %d", mode, tc.wantMode)
			}
			if !reflect.DeepEqual(servers, tc.wantServers) {
				t.Fatalf("servers = %#v, want %#v", servers, tc.wantServers)
			}
		})
	}
}
