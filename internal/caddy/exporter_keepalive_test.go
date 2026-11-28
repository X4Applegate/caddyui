// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Keep-alive settings the export maps (T-0947). Probe count, max lifetime
// and max conns per host are left out of the live comparison: live writes
// them as keep_alive fields Caddy v2.11.9 rejects (T-0975).
var keepAliveCases = []struct {
	name string
	set  func(*models.ProxyHost)
	want []string
}{
	{"conns only", func(p *models.ProxyHost) { p.KeepaliveConns = 4 }, []string{"keepalive 90s", "keepalive_idle_conns_per_host 4"}},
	{"idle timeout only", func(p *models.ProxyHost) { p.KeepaliveIdleTimeoutSec = 45 }, []string{"keepalive 45s"}},
	{"conns and idle timeout", func(p *models.ProxyHost) { p.KeepaliveConns = 8; p.KeepaliveIdleTimeoutSec = 30 }, []string{"keepalive 30s", "keepalive_idle_conns_per_host 8"}},
	{"disabled", func(p *models.ProxyHost) { p.KeepaliveDisabled = true }, []string{"keepalive off"}},
	{"disabled but pool set", func(p *models.ProxyHost) { p.KeepaliveDisabled = true; p.KeepaliveConns = 2 }, []string{"keepalive 90s", "keepalive_idle_conns_per_host 2"}},
	{"pool-wide idle and probe interval", func(p *models.ProxyHost) { p.UpstreamMaxIdleConns = 50; p.UpstreamKeepAliveProbeIntervalSec = 15 }, []string{"keepalive_idle_conns 50", "keepalive_interval 15s"}},
	{"everything", func(p *models.ProxyHost) {
		p.KeepaliveConns = 6
		p.KeepaliveIdleTimeoutSec = 20
		p.UpstreamMaxIdleConns = 40
		p.UpstreamKeepAliveProbeIntervalSec = 10
	}, []string{"keepalive 20s", "keepalive_idle_conns_per_host 6", "keepalive_idle_conns 40", "keepalive_interval 10s"}},
}

func keepAliveHost(set func(*models.ProxyHost)) models.ProxyHost {
	p := httpsUpstreamHost("")
	set(&p)
	return p
}

func TestExportKeepAliveLines(t *testing.T) {
	for _, tc := range keepAliveCases {
		t.Run(tc.name, func(t *testing.T) {
			got := caddyfileKeepAliveLines(keepAliveHost(tc.set))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	p := keepAliveHost(func(p *models.ProxyHost) {
		p.MaxConnsPerHost = 9
		p.UpstreamKeepaliveProbes = 3
		p.UpstreamKeepaliveMaxLifetimeSec = 60
	})
	out := RenderProxyHostCaddyfile(p)
	for _, s := range []string{"max_conns_per_host 9", "keep-alive probe count", "keep-alive max lifetime"} {
		if !strings.Contains(out, s) {
			t.Errorf("export lacks %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "keepalive_probes") || strings.Contains(out, "lifetime 60") {
		t.Errorf("export writes an option Caddy has no such thing as:\n%s", out)
	}
}

// keepAliveOf returns the keep_alive object of a transport with
// "enabled": true dropped (Caddy's default, which adapt never writes).
func keepAliveOf(t *testing.T, rp map[string]any) any {
	t.Helper()
	tr, _ := rp["transport"].(map[string]any)
	ka, _ := tr["keep_alive"].(map[string]any)
	if ka == nil {
		return nil
	}
	if e, ok := ka["enabled"].(bool); ok && e {
		delete(ka, "enabled")
	}
	return normaliseJSON(t, ka)
}

func TestExportKeepAliveAdaptsLikeLiveRoute(t *testing.T) {
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	for _, tc := range keepAliveCases {
		t.Run(tc.name, func(t *testing.T) {
			p := keepAliveHost(tc.set)
			out := RenderProxyHostCaddyfile(p)
			exported := findReverseProxy(adaptText(t, bin, out))
			live := findReverseProxy(liveProxyRoute(t, bin, p))
			if exported == nil || live == nil {
				t.Fatalf("no reverse_proxy handler (exported %v, live %v)", exported, live)
			}
			got, want := keepAliveOf(t, exported), keepAliveOf(t, live)
			if !reflect.DeepEqual(got, want) {
				gb, _ := json.Marshal(got)
				wb, _ := json.Marshal(want)
				t.Fatalf("keep_alive differs from the live route\nexport: %s\n  live: %s\n%s", gb, wb, out)
			}
		})
	}
}
