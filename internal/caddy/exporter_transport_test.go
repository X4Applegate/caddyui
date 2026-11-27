// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// T-0931: an https upstream plus an Advanced `reverse_proxy { transport … }`
// block exported two transport blocks; Caddy keeps only the last, so the
// export lost the generated upstream TLS settings. The live sync deep-merges
// the Advanced transport over the generated one (MergeReverseProxyOverrides).

func httpsUpstreamHost(advanced string) models.ProxyHost {
	return models.ProxyHost{ID: 51, Domains: "app.example.test", ForwardScheme: "https", ForwardHost: "203.0.113.20", ForwardPort: 8443,
		UpstreamSNI: "up.internal", UpstreamTimeoutSec: 30, Enabled: true, SSLEnabled: true, SSLForced: true, AdvancedConfig: advanced}
}

var transportMergeCases = []struct{ name, advanced string }{
	{"no Advanced config", ""},
	{"separate block", "reverse_proxy {\n\ttransport http {\n\t\tdial_timeout 7s\n\t\ttls_insecure_skip_verify\n\t}\n}\n"},
	{"overrides a generated value", "reverse_proxy {\n\ttransport http {\n\t\ttls_server_name other.internal\n\t}\n}\n"},
	{"between other options", "reverse_proxy {\n\tflush_interval -1\n\ttransport http {\n\t\tdial_timeout 7s\n\t\tresolvers 192.0.2.53\n\t}\n\theader_down -Server\n}\n"},
	{"bare transport http", "reverse_proxy {\n\ttransport http\n\tflush_interval -1\n}\n"},
	{"two transport blocks", "reverse_proxy {\n\ttransport http {\n\t\tdial_timeout 2s\n\t\ttls_insecure_skip_verify\n\t}\n\ttransport http {\n\t\tdial_timeout 7s\n\t}\n}\n"},
	{"comment after the opening brace", "reverse_proxy {\n\ttransport http { # upstream tuning\n\t\t\tdial_timeout 7s\n\t\t\tkeepalive 45s\n\t}\n}\n"},
	{"with site directives around", "header X-From-Advanced yes\nreverse_proxy {\n\ttransport http {\n\t\tkeepalive 45s\n\t}\n}\nencode gzip\n"},
}

func TestExportMergesAdvancedTransport(t *testing.T) {
	for _, tc := range transportMergeCases {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderProxyHostCaddyfile(httpsUpstreamHost(tc.advanced))
			if n := strings.Count(out, "transport http"); n != 1 {
				t.Fatalf("want exactly one transport block, got %d:\n%s", n, out)
			}
			if !strings.Contains(out, "tls_server_name up.internal") {
				t.Fatalf("generated upstream TLS settings lost:\n%s", out)
			}
			// The generated options come first, so an Advanced option that
			// sets the same thing wins, as it does live.
			gen := strings.Index(out, "\t\t\ttls_server_name up.internal\n")
			if adv := strings.Index(out, "# from Advanced config"); adv >= 0 && adv < gen {
				t.Fatalf("Advanced transport options must follow the generated ones:\n%s", out)
			}
			if !strings.Contains(out, "\t\t\ttls_insecure_skip_verify\n") {
				t.Fatalf("an https upstream without SSL verify upstream must say tls_insecure_skip_verify, as the live route does:\n%s", out)
			}
		})
	}
}

// Text-level checks that hold without a caddy binary (CI has none, so the
// adapt parity test above is skipped there).
func TestExportTransportBlockText(t *testing.T) {
	p := httpsUpstreamHost("")
	p.SSLVerifyUpstream = true
	if out := RenderProxyHostCaddyfile(p); strings.Contains(out, "tls_insecure_skip_verify") || !strings.Contains(out, "\t\t\ttls\n") {
		t.Fatalf("SSL verify upstream on: want tls without tls_insecure_skip_verify:\n%s", out)
	}
	// An Advanced option overriding a generated one is written after it.
	out := RenderProxyHostCaddyfile(httpsUpstreamHost("reverse_proxy {\n\ttransport http {\n\t\ttls_server_name other.internal\n\t}\n}\n"))
	want := "\t\ttransport http {\n\t\t\ttls\n\t\t\ttls_insecure_skip_verify\n\t\t\ttls_server_name up.internal\n\t\t\tdial_timeout 30s\n\t\t\tresponse_header_timeout 30s\n\t\t\t# from Advanced config\n\t\t\ttls_server_name other.internal\n\t\t}\n"
	if !strings.Contains(out, want) {
		t.Fatalf("want the merged block\n%s\ngot:\n%s", want, out)
	}
	// Two Advanced transport blocks: the last one is merged, as Caddy keeps
	// only the last; the earlier one is left out with a note.
	out = RenderProxyHostCaddyfile(httpsUpstreamHost("reverse_proxy {\n\ttransport http {\n\t\tdial_timeout 2s\n\t}\n\ttransport http {\n\t\tdial_timeout 7s\n\t}\n}\n"))
	if strings.Contains(out, "dial_timeout 2s") || !strings.Contains(out, "\t\t\tdial_timeout 7s\n") || !strings.Contains(out, "1 earlier transport block(s)") {
		t.Fatalf("two transports: want the last merged and the earlier one left out:\n%s", out)
	}
	// A comment after the opening brace gets its own line and does not
	// change the indentation of what follows.
	out = RenderProxyHostCaddyfile(httpsUpstreamHost("reverse_proxy {\n\ttransport http { # tuning }\n\t\tdial_timeout 7s\n\t}\n}\n"))
	if !strings.Contains(out, "\t\t\t# tuning }\n\t\t\tdial_timeout 7s\n\t\t}\n") {
		t.Fatalf("comment after the brace: want it on its own line, options indented like the rest:\n%s", out)
	}
}

// liveProxyRoute builds the route the live sync deploys for p: the
// generated JSON route with the Advanced reverse_proxy block, adapted by
// Caddy, merged in (syncAdaptProxyAdvanced + MergeReverseProxyOverrides).
func liveProxyRoute(t *testing.T, bin string, p models.ProxyHost) map[string]any {
	t.Helper()
	route := BuildProxyRoute(p, nil)
	_, inner := splitAdvancedReverseProxyBlock(p.AdvancedConfig)
	if strings.TrimSpace(inner) != "" {
		adv := adaptText(t, bin, "advanced.example.test {\n\treverse_proxy {\n"+inner+"\t}\n}\n")
		rp := findReverseProxy(adv)
		if rp == nil {
			t.Fatalf("Advanced reverse_proxy block did not adapt to a handler: %v", adv)
		}
		overrides := map[string]any{}
		for k, v := range rp {
			if k != "handler" && k != "upstreams" {
				overrides[k] = v
			}
		}
		MergeReverseProxyOverrides(route, overrides)
	}
	return route
}

func TestExportAdvancedTransportAdaptsLikeLiveRoute(t *testing.T) {
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	for _, verify := range []bool{false, true} {
		for _, tc := range transportMergeCases {
			name := tc.name
			if verify {
				name += " (verify upstream)"
			}
			t.Run(name, func(t *testing.T) {
				p := httpsUpstreamHost(tc.advanced)
				p.SSLVerifyUpstream = verify
				out := RenderProxyHostCaddyfile(p)
				exported := findReverseProxy(adaptText(t, bin, out))
				live := findReverseProxy(liveProxyRoute(t, bin, p))
				if exported == nil || live == nil {
					t.Fatalf("no reverse_proxy handler (exported %v, live %v)", exported, live)
				}
				got, want := normaliseJSON(t, exported["transport"]), normaliseJSON(t, live["transport"])
				if !reflect.DeepEqual(got, want) {
					gb, _ := json.Marshal(got)
					wb, _ := json.Marshal(want)
					t.Fatalf("transport differs from the live route\nexport: %s\n  live: %s\n%s", gb, wb, out)
				}
			})
		}
	}
}

// Text that only looks like a transport block — inside a quoted string or
// a heredoc, or nested deeper than the reverse_proxy block's top level — is
// never taken out of the Advanced config.
func TestTakeAdvancedTransportIgnoresNonDirectives(t *testing.T) {
	for name, inner := range map[string]string{
		"quoted":                "\theader_up X-Note \"\ntransport http {\n\tdial_timeout 1s\n}\n\"\n",
		"backtick":              "\theader_up X-Note `\ntransport http {\n}\n`\n",
		"heredoc":               "\theader_up X-Note <<EOF\n\ttransport http {\n\t}\n\tEOF\n",
		"nested":                "\thandle_response {\n\t\ttransport http {\n\t\t}\n\t}\n",
		"not first on its line": "\theader_up X-Mode transport http\n",
	} {
		rest, tr := takeAdvancedTransport(inner)
		if tr.found || rest != inner {
			t.Errorf("%s: took %+v out of\n%s", name, tr, inner)
		}
	}
	// Two transport sub-directives: both are taken out and the last one's
	// body is merged (Caddy keeps only the last).
	two := "\ttransport http {\n\t\tdial_timeout 1s\n\t}\n\theader_down -Server\n\ttransport http {\n\t\tdial_timeout 2s\n\t}\n"
	if rest, tr := takeAdvancedTransport(two); !tr.mergeable || tr.dropped != 1 || strings.TrimSpace(tr.body) != "dial_timeout 2s" || rest != "\theader_down -Server\n" {
		t.Errorf("two transports: got %+v, rest %q", tr, rest)
	}
	// Not taken out when one of them cannot be, or the last is another
	// module: rest unchanged.
	for name, in := range map[string]string{
		"token after the closing brace":    "\ttransport http {\n\t\tdial_timeout 1s\n\t} flush_interval -1\n",
		"earlier one unclosed on its line": "\ttransport http { dial_timeout 1s } x\n\ttransport http {\n\t}\n",
		"last one fastcgi":                 "\ttransport http {\n\t}\n\ttransport fastcgi {\n\t\tsplit .php\n\t}\n",
		"no module":                        "\ttransport {\n\t}\n",
	} {
		if rest, tr := takeAdvancedTransport(in); !tr.found || tr.mergeable || rest != in {
			t.Errorf("%s: got %+v, rest changed %v", name, tr, rest != in)
		}
	}
	// One is taken out exactly, the rest left as written.
	one := "\tflush_interval -1\n\ttransport http {\n\t\tdial_timeout 1s\n\t}\n\theader_down -Server\n"
	rest, tr := takeAdvancedTransport(one)
	if !tr.mergeable || rest != "\tflush_interval -1\n\theader_down -Server\n" || strings.TrimSpace(tr.body) != "dial_timeout 1s" {
		t.Errorf("one transport: got %+v, rest %q", tr, rest)
	}
}

// A transport module other than http cannot take the generated http
// options: the export writes only the Advanced one and says what it left out.
func TestExportNonHTTPAdvancedTransportWarns(t *testing.T) {
	out := RenderProxyHostCaddyfile(httpsUpstreamHost("reverse_proxy {\n\ttransport fastcgi {\n\t\tsplit .php\n\t}\n}\n"))
	if strings.Count(out, "\t\ttransport ") != 1 || strings.Contains(out, "transport http") {
		t.Fatalf("want only the Advanced fastcgi transport:\n%s", out)
	}
	if !strings.Contains(out, "# Upstream transport settings from CaddyUI") {
		t.Fatalf("want a comment naming the generated transport settings left out:\n%s", out)
	}
}
