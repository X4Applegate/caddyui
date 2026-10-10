// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.63.2 (issue #129): IP checks match client_ip, which honours the
// Settings › Security trusted proxies, never remote_ip, which only ever sees
// the load balancer in front of Caddy.
func TestIPChecksMatchTheClientIPNotTheConnection(t *testing.T) {
	ph := models.ProxyHost{ID: 1, Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080, Enabled: true,
		AccessList: "192.168.0.0/16", IPBlocklist: "203.0.113.0/24", BlockPrivateIPs: true,
		MaintenanceMode: true, MaintenanceAllowedIPs: "198.51.100.7/32"}
	rh := models.RedirectionHost{ID: 2, Domains: "old.example.com", ForwardDomain: "new.example.com", Enabled: true, AccessList: "192.168.0.0/16"}
	for name, v := range map[string]any{
		"proxy host":       BuildProxyRoute(ph, nil),
		"redirect":         BuildRedirectRoute(rh),
		"global blocklist": BuildGlobalBlocklistRoute("203.0.113.5/32"),
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"remote_ip"`) {
			t.Errorf("%s still matches remote_ip: %s", name, b)
		}
		if !strings.Contains(string(b), `"client_ip":{"ranges"`) {
			t.Errorf("%s has no client_ip check: %s", name, b)
		}
	}
	// Every range of the proxy host reaches a client_ip matcher.
	b, _ := json.Marshal(BuildProxyRoute(ph, nil))
	for _, cidr := range []string{"192.168.0.0/16", "203.0.113.0/24", "10.0.0.0/8", "198.51.100.7/32"} {
		if !strings.Contains(string(b), `"`+cidr+`"`) {
			t.Errorf("range %s missing from the proxy-host route", cidr)
		}
	}
}
