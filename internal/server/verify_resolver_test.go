// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
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

// A dead first server must fail over to the next one (issue #98) — the whole
// point of the feature is surviving a blocked/unreachable resolver.
func TestResolveViaPlainDNSFailsOverToNextServer(t *testing.T) {
	orig := plainDNSLookup
	t.Cleanup(func() { plainDNSLookup = orig })

	var tried []string
	plainDNSLookup = func(server, fqdn string) ([]string, bool, error) {
		tried = append(tried, server)
		if server == "10.0.0.1:53" {
			return nil, false, fmt.Errorf("i/o timeout")
		}
		return []string{"203.0.113.5"}, false, nil
	}

	ips, err := resolveViaPlainDNS([]string{"10.0.0.1:53", "10.0.0.2:53"}, "x.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.5" {
		t.Fatalf("ips = %#v, want the second server's answer", ips)
	}
	if !reflect.DeepEqual(tried, []string{"10.0.0.1:53", "10.0.0.2:53"}) {
		t.Fatalf("tried = %#v, want both servers in order", tried)
	}
}

// An authoritative "no such host" is a real answer, not a reason to fail over —
// it stops the search and reports "not live yet" (empty), like the DoH path.
func TestResolveViaPlainDNSNotFoundStops(t *testing.T) {
	orig := plainDNSLookup
	t.Cleanup(func() { plainDNSLookup = orig })

	var tried []string
	plainDNSLookup = func(server, fqdn string) ([]string, bool, error) {
		tried = append(tried, server)
		return []string{}, true, nil
	}

	ips, err := resolveViaPlainDNS([]string{"10.0.0.1:53", "10.0.0.2:53"}, "x.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 0 {
		t.Fatalf("ips = %#v, want empty", ips)
	}
	if len(tried) != 1 {
		t.Fatalf("tried = %#v, want to stop after the first definitive answer", tried)
	}
}
