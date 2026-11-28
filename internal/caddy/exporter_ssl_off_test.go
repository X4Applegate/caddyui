// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// adaptText writes src to a temp Caddyfile and runs the real `caddy adapt`
// on it (the test fails when Caddy rejects the file).
func adaptText(t *testing.T, bin, src string) map[string]any {
	t.Helper()
	file := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	adapted, raw := caddyAdapt(t, bin, file)
	m, ok := adapted.(map[string]any)
	if !ok {
		t.Fatalf("adapt output is not an object:\n%s", raw)
	}
	return m
}

// adaptedServers returns the adapted config's HTTP servers.
func adaptedServers(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	if len(servers) == 0 {
		t.Fatalf("adapted config has no HTTP servers: %v", cfg)
	}
	return servers
}

// serverListenHosts maps each adapted server's listen addresses (joined) to
// the sorted host names its routes match.
func serverListenHosts(t *testing.T, cfg map[string]any) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, v := range adaptedServers(t, cfg) {
		srv, _ := v.(map[string]any)
		var listen []string
		for _, l := range srv["listen"].([]any) {
			listen = append(listen, l.(string))
		}
		sort.Strings(listen)
		routes, _ := srv["routes"].([]any)
		var hosts []string
		for _, r := range routes {
			rm, _ := r.(map[string]any)
			for _, m := range asSlice(rm["match"]) {
				mm, _ := m.(map[string]any)
				for _, h := range asSlice(mm["host"]) {
					hosts = append(hosts, h.(string))
				}
			}
		}
		sort.Strings(hosts)
		out[strings.Join(listen, ",")] = hosts
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// findReverseProxy returns the first reverse_proxy handler anywhere in v.
func findReverseProxy(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		if x["handler"] == "reverse_proxy" {
			return x
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if found := findReverseProxy(x[k]); found != nil {
				return found
			}
		}
	case []any:
		for _, e := range x {
			if found := findReverseProxy(e); found != nil {
				return found
			}
		}
	}
	return nil
}

var durationValueRe = regexp.MustCompile(`^[0-9]+(?:ns|us|ms|s|m|h)$`)

// normaliseJSON round-trips v through JSON and writes every duration string
// ("7s") as the nanosecond number Caddy's adapter emits, so the generated
// JSON route and adapted Caddyfile output compare like for like.
func normaliseJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				x[k] = walk(e)
			}
		case []any:
			for i, e := range x {
				x[i] = walk(e)
			}
		case string:
			if durationValueRe.MatchString(x) {
				if d, err := time.ParseDuration(x); err == nil {
					return float64(d)
				}
			}
		}
		return v
	}
	return walk(out)
}

// T-0927: a proxy host with SSL off exported `tls off`, which Caddy v2.11
// rejects ("single argument must either be 'internal', 'force_automate', or
// an email address"), taking the whole export down with it.

func sslOffHost() models.ProxyHost {
	return models.ProxyHost{ID: 41, Domains: "plain.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true}
}

func TestExportSSLOffHostHasNoTLSOff(t *testing.T) {
	p := sslOffHost()
	out := RenderProxyHostCaddyfile(p)
	if strings.Contains(out, "tls off") {
		t.Fatalf("SSL-off host still exports `tls off`:\n%s", out)
	}
	// The live sync serves the host on srv0 (:443) and, Force SSL being
	// off, on the plain :80 server without a redirect: the Caddyfile form
	// of that is a site with both an http:// and an https:// address.
	if !strings.Contains(out, "http://plain.example.test, https://plain.example.test {\n") {
		t.Fatalf("SSL-off host: want http:// and https:// site addresses:\n%s", out)
	}

	// A legacy row with Force SSL on (the form refuses it now) is served
	// with an HTTPS redirect live, which is the plain address.
	forced := p
	forced.SSLForced = true
	out = RenderProxyHostCaddyfile(forced)
	if strings.Contains(out, "tls off") || strings.Contains(out, "http://") || !strings.HasPrefix(out, "plain.example.test {\n") {
		t.Fatalf("SSL-off + Force SSL host: want the plain address and no tls off:\n%s", out)
	}

	// A certificate still wins over the SSL flag, as before.
	withCert := p
	withCert.CertificateID = 3
	out = RenderProxyHostCaddyfileWithCertificate(withCert, &models.Certificate{ID: 3, Source: models.CertSourcePath, CertPath: "/c.pem", KeyPath: "/k.pem"})
	// Force SSL off: the HTTPS site keeps the tls line and a plain-HTTP
	// twin serves :80 without it (T-0947, finding 10).
	if !strings.HasPrefix(out, "plain.example.test {\n\ttls /c.pem /k.pem\n") || !strings.Contains(out, "}\nhttp://plain.example.test {\n") || strings.Count(out, "tls /c.pem") != 1 {
		t.Fatalf("SSL-off host with a certificate: want the tls line on the HTTPS site and a plain-HTTP twin:\n%s", out)
	}
}

func TestCaddyfilePlainHTTPAddresses(t *testing.T) {
	for _, tc := range []struct {
		in, want []string
	}{
		{[]string{"a.test"}, []string{"http://a.test", "https://a.test"}},
		{[]string{"a.test:8080"}, []string{"http://a.test:8080"}},
		{[]string{"a.test:443"}, []string{"https://a.test:443"}},
		{[]string{"[::1]:8080"}, []string{"http://[::1]:8080"}},
		{[]string{"http://a.test"}, []string{"http://a.test"}},
		{[]string{"a.test", "http://a.test", "*.b.test"}, []string{"http://a.test", "https://a.test", "http://*.b.test", "https://*.b.test"}},
	} {
		if got := caddyfilePlainHTTPAddresses(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("caddyfilePlainHTTPAddresses(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// With client-certificate auth an SSL-off host keeps its plain address:
// Caddy refuses TLS settings in a site that also listens on plain HTTP
// ("server listening on [:80] is HTTP, but attempts to configure TLS
// connection policies"), and serving :80 would drop the client certificate
// requirement. The export says what it left out.
func sslOffClientAuthHost() models.ProxyHost {
	return models.ProxyHost{ID: 43, Domains: "mtls.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.12", ForwardPort: 8080, Enabled: true,
		ClientAuthMode: "require_and_verify", ClientAuthCAFiles: "/etc/caddy/ca.pem"}
}

func TestExportSSLOffClientAuthHostKeepsHTTPS(t *testing.T) {
	out := RenderProxyHostCaddyfile(sslOffClientAuthHost())
	if strings.Contains(out, "http://") || strings.Contains(out, "tls off") || !strings.Contains(out, "\nmtls.example.test {\n") ||
		!strings.Contains(out, "client_auth") || !strings.Contains(out, "plain HTTP on :80") {
		t.Fatalf("SSL-off host with client auth: want the plain address, its client_auth block and a note on :80:\n%s", out)
	}
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	got := serverListenHosts(t, adaptText(t, bin, out))
	if want := map[string][]string{":443": {"mtls.example.test"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners/hosts: got %v, want %v\n%s", got, want, out)
	}
}

func TestExportSSLOffHostAdaptsLikeLiveRoute(t *testing.T) {
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	p := sslOffHost()
	on := models.ProxyHost{ID: 42, Domains: "secure.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.11", ForwardPort: 8080, Enabled: true, SSLEnabled: true, SSLForced: true}
	// The whole server export loads, not just the one block.
	// An admin's SSL-off domain with a port keeps it: on 443 it is written
	// https:// (Caddy refuses http:// there), on another port http://.
	p443 := sslOffHost()
	p443.ID, p443.Domains = 44, "port443.example.test:443"
	p8080 := sslOffHost()
	p8080.ID, p8080.Domains = 45, "port8080.example.test:8080"
	all := RenderServerCaddyfile("Primary", []models.ProxyHost{p, on, p443, p8080}, nil, nil, nil)
	cfg := adaptText(t, bin, all)
	got := serverListenHosts(t, cfg)
	want := map[string][]string{
		":443":  {"plain.example.test", "port443.example.test", "secure.example.test"},
		":80":   {"plain.example.test"},
		":8080": {"port8080.example.test"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners/hosts: got %v, want %v (srv0 on :443 for every host, plain :80 for the SSL-off host)\n%s", got, want, all)
	}
	// Caddy's own HTTP->HTTPS redirect must not take the SSL-off host:
	// the :80 server answers it with the proxy, not a redirect.
	for _, v := range adaptedServers(t, cfg) {
		srv := v.(map[string]any)
		if asSlice(srv["listen"])[0] != ":80" && asSlice(srv["listen"])[0] != ":8080" {
			continue
		}
		if findReverseProxy(srv) == nil {
			t.Fatalf("plain HTTP server does not proxy the SSL-off host: %v", srv)
		}
	}
}
