// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// pathMatcherCases covers every Path Matcher Type the proxy host form offers
// (empty = prefix, "exact", "regexp"), each with and without strip prefix, plus
// patterns the Caddyfile lexer would otherwise split or misread.
var pathMatcherCases = []struct {
	name, matcher, typ string
	strip              bool
	wantMatcher        string // "" = no path matcher at all
	wantStrip          string // "" = no uri strip_prefix line
}{
	{name: "no matcher", matcher: "", typ: ""},
	{name: "prefix", matcher: "/api", typ: "", wantMatcher: "path /api /api/*"},
	{name: "prefix strip", matcher: "/api", typ: "", strip: true, wantMatcher: "path /api /api/*", wantStrip: "/api"},
	{name: "prefix with glob", matcher: "/api/*", typ: "", wantMatcher: "path /api /api/*"},
	{name: "prefix root is no matcher", matcher: "/", typ: "", strip: true},
	{name: "prefix explicit value", matcher: "/api", typ: "prefix", wantMatcher: "path /api /api/*"},
	{name: "exact", matcher: "/health", typ: "exact", wantMatcher: "path /health"},
	{name: "exact strip", matcher: "/health", typ: "exact", strip: true, wantMatcher: "path /health", wantStrip: "/health"},
	{name: "regexp issue 184", matcher: "^/backend/", typ: "regexp", wantMatcher: "path_regexp ^/backend/"},
	{name: "regexp strip", matcher: "^/backend/", typ: "regexp", strip: true, wantMatcher: "path_regexp ^/backend/", wantStrip: "^/backend"},
	{name: "regexp backslash", matcher: `^/v\d+/`, typ: "regexp", wantMatcher: "path_regexp `^/v\\d+/`"},
	{name: "regexp space quote brace hash", matcher: `^/a b{2}#"x`, typ: "regexp", wantMatcher: "path_regexp `^/a b{2}#\"x`"},
	{name: "regexp leading hash", matcher: `#frag`, typ: "regexp", wantMatcher: "path_regexp `#frag`"},
	{name: "regexp quantifier braces", matcher: `^/v{2,3}/`, typ: "regexp", wantMatcher: "path_regexp `^/v{2,3}/`"},
	{name: "regexp unicode class", matcher: `^/\p{L}+`, typ: "regexp", wantMatcher: "path_regexp `" + `^/\p{L}+` + "`"},
	{name: "regexp unicode script", matcher: `^/\p{Greek}`, typ: "regexp", wantMatcher: "path_regexp `" + `^/\p{Greek}` + "`"},
	{name: "regexp negated script", matcher: `^/\P{Han}`, typ: "regexp", wantMatcher: "path_regexp `" + `^/\P{Han}` + "`"},
	{name: "regexp escaped braces", matcher: `^/\{host\}`, typ: "regexp", wantMatcher: "path_regexp `" + `^/\{host\}` + "`"},
	{name: "regexp unknown placeholder", matcher: `^/{_x}`, typ: "regexp", wantMatcher: "path_regexp `^/{_x}`"},
	{name: "prefix with space", matcher: "/my docs", typ: "", strip: true, wantMatcher: "path `/my docs` `/my docs/*`", wantStrip: "`/my docs`"},
}

func pathMatcherHost(matcher, typ string, strip bool) models.ProxyHost {
	return models.ProxyHost{
		Domains: "*.sub.example.com", ForwardScheme: "http", ForwardHost: "192.0.2.10", ForwardPort: 8989,
		Enabled: true, SSLEnabled: true, PathMatcher: matcher, PathMatcherType: typ, StripPathPrefix: strip,
	}
}

// Issue #184: the Caddyfile excerpt must carry the route's path matcher on
// reverse_proxy (and on the strip-prefix rewrite) instead of proxying every
// path on the host.
func TestRenderProxyHostCaddyfilePathMatcher(t *testing.T) {
	for _, tc := range pathMatcherCases {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderProxyHostCaddyfile(pathMatcherHost(tc.matcher, tc.typ, tc.strip))
			if tc.wantMatcher == "" {
				if strings.Contains(out, "@caddyui_path") {
					t.Fatalf("no path matcher expected:\n%s", out)
				}
				if !strings.Contains(out, "\treverse_proxy 192.0.2.10:8989 {\n") || strings.Contains(out, "strip_prefix") {
					t.Fatalf("unmatched reverse_proxy expected:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, "\t@caddyui_path "+tc.wantMatcher+"\n") {
				t.Errorf("missing matcher %q:\n%s", tc.wantMatcher, out)
			}
			if !strings.Contains(out, "\treverse_proxy @caddyui_path 192.0.2.10:8989 {\n") {
				t.Errorf("reverse_proxy must use the path matcher:\n%s", out)
			}
			hasStrip := strings.Contains(out, "strip_prefix")
			if tc.wantStrip == "" && hasStrip {
				t.Errorf("unexpected strip_prefix:\n%s", out)
			}
			if tc.wantStrip != "" && !strings.Contains(out, "\turi @caddyui_path strip_prefix "+tc.wantStrip+"\n") {
				t.Errorf("missing uri strip_prefix %q:\n%s", tc.wantStrip, out)
			}
		})
	}
}

// TestCaddyfilePathMatcherAdaptsLikeJSONRoute proves the excerpt is
// semantically equivalent to the JSON route, not just textually present: it
// runs `caddy adapt` on each rendered Caddyfile and compares the matcher and
// strip_path_prefix rewrite guarding reverse_proxy with BuildProxyRoute's.
// Skipped when no `caddy` binary is on PATH.
func TestCaddyfilePathMatcherAdaptsLikeJSONRoute(t *testing.T) {
	caddyBin, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("SKIPPED: no `caddy` binary on PATH, so the `caddy adapt` equivalence check did not run — put caddy on PATH to run it")
	}
	dir := t.TempDir()
	for i, tc := range pathMatcherCases {
		t.Run(tc.name, func(t *testing.T) {
			p := pathMatcherHost(tc.matcher, tc.typ, tc.strip)
			file := filepath.Join(dir, "Caddyfile"+string(rune('a'+i)))
			if err := os.WriteFile(file, []byte(RenderProxyHostCaddyfile(p)), 0o644); err != nil {
				t.Fatal(err)
			}
			adapted, raw := caddyAdapt(t, caddyBin, file)
			gotMatch, gotStrip, ok := findProxyMatcher(adapted, nil)
			if !ok {
				t.Fatalf("no reverse_proxy in adapted config:\n%s", raw)
			}

			route := BuildProxyRoute(p, nil)
			want := map[string]any{}
			for k, v := range route["match"].([]any)[0].(map[string]any) {
				if k != "host" {
					want[k] = v
				}
			}
			wantStrip := ""
			for _, h := range route["handle"].([]any) {
				if hm, _ := h.(map[string]any); hm["handler"] == "rewrite" && hm["strip_path_prefix"] != nil {
					wantStrip = hm["strip_path_prefix"].(string)
				}
			}
			// Round-trip through JSON so both sides use the same types.
			if !reflect.DeepEqual(normaliseMatch(gotMatch), normaliseMatch(want)) {
				t.Errorf("adapted matcher differs from JSON route\n got: %v\nwant: %v", gotMatch, want)
			}
			if gotStrip != wantStrip {
				t.Errorf("strip_path_prefix: adapted %q, JSON route %q", gotStrip, wantStrip)
			}
		})
	}
}

// findProxyMatcher walks an adapted config and returns the non-host match
// conditions guarding the reverse_proxy handler plus any strip_path_prefix
// rewrite that runs under the same conditions.
func findProxyMatcher(node any, inherited map[string]any) (map[string]any, string, bool) {
	switch n := node.(type) {
	case map[string]any:
		if routes, ok := n["routes"].([]any); ok {
			for _, r := range routes {
				route, _ := r.(map[string]any)
				cond := map[string]any{}
				for k, v := range inherited {
					cond[k] = v
				}
				if ms, ok := route["match"].([]any); ok && len(ms) > 0 {
					for k, v := range ms[0].(map[string]any) {
						if k != "host" {
							cond[k] = v
						}
					}
				}
				strip := ""
				handles, _ := route["handle"].([]any)
				for _, h := range handles {
					if hm, _ := h.(map[string]any); hm["handler"] == "rewrite" {
						if s, ok := hm["strip_path_prefix"].(string); ok {
							strip = s
						}
					}
				}
				for _, h := range handles {
					hm, _ := h.(map[string]any)
					if hm["handler"] == "reverse_proxy" {
						return cond, strip, true
					}
					if got, s, ok := findProxyMatcher(hm, cond); ok {
						if s == "" {
							s = strip
						}
						return got, s, true
					}
				}
			}
		}
		for k, v := range n {
			if k == "routes" {
				continue
			}
			if got, s, ok := findProxyMatcher(v, inherited); ok {
				return got, s, true
			}
		}
	case []any:
		for _, v := range n {
			if got, s, ok := findProxyMatcher(v, inherited); ok {
				return got, s, true
			}
		}
	}
	return nil, "", false
}

// normaliseMatch JSON-round-trips a matcher set and drops path_regexp's
// capture name: the Caddyfile adapter names it after the @matcher, the JSON
// route leaves it unnamed, and the name only affects {re.*} placeholders.
func normaliseMatch(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if re, ok := out["path_regexp"].(map[string]any); ok {
		delete(re, "name")
	}
	return out
}

// caddyAdapt runs `caddy adapt` on a Caddyfile and returns the decoded JSON.
func caddyAdapt(t *testing.T, caddyBin, file string) (any, []byte) {
	t.Helper()
	raw, err := exec.Command(caddyBin, "adapt", "--config", file, "--adapter", "caddyfile").Output()
	if err != nil {
		src, _ := os.ReadFile(file)
		t.Fatalf("caddy adapt: %v\n%s", err, src)
	}
	var adapted any
	if err := json.Unmarshal(raw, &adapted); err != nil {
		t.Fatalf("adapt output: %v\n%s", err, raw)
	}
	return adapted, raw
}

// injectedSitePayload is the review's proof of concept: a backtick, a
// backslash and a quote end the old double-quoted token early, after which
// the rest of the value becomes a new site block proxying the Caddy admin
// API plus an import of the host's own Caddyfile.
const injectedSitePayload = "/x`\\\"\n}\nevil.example.test {\n\treverse_proxy 127.0.0.1:2019\n}\nimport /etc/caddy/Caddyfile\nx.example.test {\n\t@caddyui_path path /\n#"

// unrepresentableMatchers cannot be written as one safe Caddyfile token, so
// the export must fail closed for them instead of quoting or dropping them.
var unrepresentableMatchers = []struct{ name, matcher, typ string }{
	{"injected site via regexp", injectedSitePayload, "regexp"},
	{"injected site via exact", injectedSitePayload, "exact"},
	{"injected site via prefix", injectedSitePayload, ""},
	{"trailing backslash after backtick", "/x`\\", ""},
	{"backtick", "^/a`b", "regexp"},
	{"newline", "/a\nb", "exact"},
	{"tab", "/a\tb", ""},
	{"DEL", "/a\x7fb", ""},
	{"line separator", "/a\u2028b", "regexp"},
	{"paragraph separator", "/a\u2029b", ""},
	{"invalid UTF-8", "/a\xffb", ""},
	{"env var", "/{$HOME}", ""},
	{"placeholder shorthand", "^/x{host}", "regexp"},
	{"path shorthand", "/a{path}", "exact"},
	{"header shorthand", "^/{header.X}", "regexp"},
}

// Issue #184 review (blocking): values that cannot be one safe token make
// the site refuse every request — never a quoted token that can be broken
// out of, and never a dropped matcher that would proxy every path.
func TestCaddyfilePathMatcherFailsClosed(t *testing.T) {
	caddyBin := lookCaddy(t)
	dir := t.TempDir()
	for i, tc := range unrepresentableMatchers {
		for _, strip := range []bool{false, true} {
			name := tc.name
			if strip {
				name += " strip"
			}
			t.Run(name, func(t *testing.T) {
				p := pathMatcherHost(tc.matcher, tc.typ, strip)
				p.Domains = "a.example.test"
				out := RenderServerCaddyfile("", []models.ProxyHost{p}, nil, nil, nil)
				if strings.Contains(out, "reverse_proxy") || strings.Contains(out, "@caddyui_path") || strings.Contains(out, "evil.example.test") || strings.Contains(out, "import /etc") {
					t.Fatalf("unrepresentable matcher must not render a proxy or any part of the value:\n%s", out)
				}
				if !strings.Contains(out, "\trespond 503\n") {
					t.Fatalf("site must fail closed with respond 503:\n%s", out)
				}
				if caddyBin == "" {
					return
				}
				file := filepath.Join(dir, fmt.Sprintf("fc%d-%v", i, strip))
				if err := os.WriteFile(file, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
				_, raw := caddyAdapt(t, caddyBin, file)
				var cfg struct {
					Apps struct {
						HTTP struct {
							Servers map[string]struct {
								Routes []struct {
									Match []struct {
										Host []string `json:"host"`
									} `json:"match"`
								} `json:"routes"`
							} `json:"servers"`
						} `json:"http"`
					} `json:"apps"`
				}
				if err := json.Unmarshal(raw, &cfg); err != nil {
					t.Fatal(err)
				}
				var hosts []string
				for _, srv := range cfg.Apps.HTTP.Servers {
					for _, r := range srv.Routes {
						for _, m := range r.Match {
							hosts = append(hosts, m.Host...)
						}
					}
				}
				if !reflect.DeepEqual(hosts, []string{"a.example.test"}) {
					t.Errorf("adapted config serves hosts %v, want only a.example.test\n%s", hosts, raw)
				}
				if strings.Contains(string(raw), `"reverse_proxy"`) || !strings.Contains(string(raw), `"status_code":503`) {
					t.Errorf("adapted config must only respond 503:\n%s", raw)
				}
			})
		}
	}
}

// Issue #184 review: with Strip prefix the JSON route runs the exploit
// blocker on the ORIGINAL path and strips afterwards. Caddyfile directive
// sorting runs `uri` before `respond`, so the excerpt wraps them in `route`.
func TestCaddyfileStripPrefixKeepsExploitBlockerOnOriginalPath(t *testing.T) {
	for _, typ := range []string{"", "exact", "regexp"} {
		p := pathMatcherHost("/api", typ, true)
		p.BlockCommonExploits = true
		if typ == "regexp" {
			p.PathMatcher = "^/api"
		}

		jsonOrder := handlerOrder(BuildProxyRoute(p, nil))
		if jb, js := indexOf(jsonOrder, "blocked"), indexOf(jsonOrder, "strip"); jb < 0 || js < 0 || jb > js {
			t.Fatalf("type %q: JSON route order %v — expected the blocker before the strip rewrite", typ, jsonOrder)
		}

		out := RenderProxyHostCaddyfile(p)
		route := strings.Index(out, "\troute {\n")
		blocked := strings.Index(out, "respond @blocked 403")
		strip := strings.Index(out, "uri @caddyui_path strip_prefix")
		if route < 0 || blocked < route || strip < blocked {
			t.Fatalf("type %q: blocker and strip must sit in one route block, blocker first:\n%s", typ, out)
		}

		caddyBin := lookCaddy(t)
		if caddyBin == "" {
			continue
		}
		file := filepath.Join(t.TempDir(), "Caddyfile")
		if err := os.WriteFile(file, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		adapted, raw := caddyAdapt(t, caddyBin, file)
		got := handlerOrder(adapted)
		if gb, gs := indexOf(got, "blocked"), indexOf(got, "strip"); gb < 0 || gs < 0 || gb > gs {
			t.Errorf("type %q: adapted handler order %v — Caddy strips before blocking\n%s", typ, got, raw)
		}
	}
}

// handlerOrder flattens a route tree in execution order, labelling the
// exploit blocker's 403, strip_path_prefix rewrites and reverse_proxy.
func handlerOrder(node any) []string {
	var out []string
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			switch {
			case v["handler"] == "static_response" && fmt.Sprint(v["status_code"]) == "403":
				out = append(out, "blocked")
			case v["handler"] == "static_response" && v["abort"] == true:
				out = append(out, "abort")
			case v["handler"] == "static_response" && fmt.Sprint(v["status_code"]) == "503":
				out = append(out, "respond503")
			case v["handler"] == "rewrite" && v["strip_path_prefix"] != nil:
				out = append(out, "strip")
			case v["handler"] == "reverse_proxy":
				out = append(out, "proxy")
				return
			}
			for _, k := range []string{"apps", "http", "servers", "srv0", "routes", "handle"} {
				if c, ok := v[k]; ok {
					walk(c)
				}
			}
		case []any:
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(node)
	return out
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// Issue #184 review: every other user-supplied value the exporter writes
// outside a comment must not be able to add tokens, lines or blocks, nor be
// rewritten by the adapter. A host with such a value renders as a site that
// answers 503; comment text is flattened and loses its braces.
func TestCaddyfileExportContainsUnsafeFieldValues(t *testing.T) {
	const evil = "\n}\nevil.example.test {\n\treverse_proxy 127.0.0.1:2019\n}\n"
	base := func() models.ProxyHost {
		return models.ProxyHost{ID: 9, Domains: "a.example.test", ForwardScheme: "http", ForwardHost: "192.0.2.10", ForwardPort: 8989, Enabled: true, SSLEnabled: true}
	}
	failClosed := []struct {
		name string
		edit func(*models.ProxyHost)
	}{
		{"request header name", func(p *models.ProxyHost) { p.CustomReqHeaders = `{"X-A` + jsonEscape(evil) + `#":"v"}` }},
		{"response header name", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"X-A` + jsonEscape(evil) + `#":"v"}` }},
		{"response header value", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"X-A":"v` + jsonEscape(evil) + `"}` }},
		{"request header value with backtick", func(p *models.ProxyHost) { p.CustomReqHeaders = "{\"X-A\":\"a`b\"}" }},
		{"header value with env var", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"X-A":"{$HOME}"}` }},
		{"header value with shorthand", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"X-A":"{remote_host}"}` }},
		{"header name with env var", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"X-{$HOME}":"v"}` }},
		{"header name starting a matcher", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"@x":"v"}` }},
		{"header name with operation prefix", func(p *models.ProxyHost) { p.CustomReqHeaders = `{"+X":"v"}` }},
		{"header name with trailing backslash", func(p *models.ProxyHost) { p.CustomReqHeaders = `{"X-A\\":"v"}` }},
		{"strip request header", func(p *models.ProxyHost) { p.StripReqHeaders = "X-A" + evil + "#" }},
		{"strip response header", func(p *models.ProxyHost) { p.StripRespHeaders = "X-A" + evil + "#" }},
		{"upstream SNI", func(p *models.ProxyHost) { p.UpstreamSNI = "sni" + evil + "#" }},
		{"upstream Host override", func(p *models.ProxyHost) { p.UpstreamHostOverride = "h" + evil }},
		{"CSP", func(p *models.ProxyHost) { p.SecurityHeadersEnabled = true; p.CSPHeader = "default-src 'self'" + evil }},
		{"forward host", func(p *models.ProxyHost) { p.ForwardHost = "192.0.2.10" + evil + "#" }},
		{"forward host as matcher", func(p *models.ProxyHost) { p.ForwardHost = "/admin" }},
		{"extra upstream", func(p *models.ProxyHost) { p.ExtraUpstreams = `["192.0.2.11:80` + jsonEscape(evil) + `"]` }},
		{"lb policy", func(p *models.ProxyHost) { p.LBPolicy = "first" + evil + "#"; p.ExtraUpstreams = `["192.0.2.11:80"]` }},
		{"advanced config breakout", func(p *models.ProxyHost) { p.AdvancedConfig = "encode gzip" + evil + "x.example.test {" }},
		{"advanced config unclosed env var", func(p *models.ProxyHost) { p.AdvancedConfig = "header X-A {$HOME" }},
		{"advanced config env var with default", func(p *models.ProxyHost) { p.AdvancedConfig = "header X-A {$HOME:x}" }},
		{"advanced config file import", func(p *models.ProxyHost) { p.AdvancedConfig = "import /etc/caddy/*.caddy" }},
		{"advanced config braceless site", func(p *models.ProxyHost) {
			p.AdvancedConfig = "encode gzip\n}\nb.ad\nreverse_proxy 127.0.0.1:2019 {\n}\nx.te {"
		}},
		{"advanced config import", func(p *models.ProxyHost) { p.AdvancedConfig = "import /etc/caddy/Caddyfile" }},
		{"advanced config unterminated heredoc", func(p *models.ProxyHost) { p.AdvancedConfig = "header X-A <<EOF\n\t}\n\tevil {" }},
		{"advanced config heredoc with bad padding", func(p *models.ProxyHost) { p.AdvancedConfig = "header X-A <<EOF\nx\n\t}\n\tEOF" }},
		{"advanced config open quote", func(p *models.ProxyHost) { p.AdvancedConfig = "respond \"x 200" }},
	}
	for _, tc := range failClosed {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.edit(&p)
			out := RenderServerCaddyfile("", []models.ProxyHost{p}, nil, nil, nil)
			if strings.Contains(out, "evil.example.test") || strings.Contains(out, "reverse_proxy") || !strings.Contains(out, "a.example.test {\n\t# Not exported: ") || !strings.Contains(out, "\trespond 503\n") {
				t.Fatalf("host with an unsafe value must fail closed:\n%s", out)
			}
		})
	}
	snippet := base()
	snippet.Domains = "(evil)"
	if out := RenderProxyHostCaddyfile(snippet); !strings.HasPrefix(out, "# Proxy host #9 omitted") {
		t.Fatalf("a domain that would define a snippet must be omitted:\n%s", out)
	}
	unsafeDomain := base()
	unsafeDomain.Domains = "a.example.test" + evil
	if out := RenderProxyHostCaddyfile(unsafeDomain); strings.Contains(out, "evil.example.test") || !strings.HasPrefix(out, "# Proxy host #9 omitted") {
		t.Fatalf("host with unsafe domains must be omitted:\n%s", out)
	}
	redirect := models.RedirectionHost{ID: 4, Domains: "r.example.test", ForwardDomain: "new.example.test" + evil + "#", Enabled: true}
	if out := RenderRedirectionCaddyfile(redirect); strings.Contains(out, "evil.example.test") || !strings.Contains(out, "\trespond 503\n") {
		t.Fatalf("redirect with an unsafe destination must fail closed:\n%s", out)
	}
	if out := RenderRedirectionCaddyfile(models.RedirectionHost{ID: 5, Domains: "s.example.test", ForwardScheme: "https a", ForwardDomain: "new.example.test"}); !strings.Contains(out, "\trespond 503\n") {
		t.Fatalf("redirect with an unsafe scheme must fail closed:\n%s", out)
	}
	if out := RenderRedirectionCaddyfile(models.RedirectionHost{ID: 6, Domains: "u.example.test", ForwardScheme: "https", ForwardDomain: "new.example.test", PreservePath: true}); !strings.Contains(out, "\tredir https://new.example.test{uri} 301\n") {
		t.Fatalf("ordinary redirect must render normally:\n%s", out)
	}

	// Comment fields keep the site but cannot start a line or hold {$.
	p := base()
	p.Tags = "team{$HOME" + evil
	p.HealthCheckURI = "/health{$X}" + evil
	p.OwnerEmail = "o@example.test{$" + evil
	out := RenderServerCaddyfile("srv{$A", []models.ProxyHost{p}, nil, nil, nil)
	if strings.Contains(out, "\nevil.example.test {") || strings.Contains(out, "{$") || !strings.Contains(out, "a.example.test {") {
		t.Fatalf("comment fields must stay on their line without {$:\n%s", out)
	}
	// Legitimate values are untouched.
	ok := base()
	ok.CustomReqHeaders = `{"X-Request-Source":"caddyui {http.request.host}"}`
	ok.StripRespHeaders = "Server, X-Powered-By"
	ok.UpstreamSNI = "backend.internal"
	ok.Domains = "*.sub.example.test, b.example.test:8443"
	ok.AdvancedConfig = "encode gzip\nheader X-Frame-Options DENY"
	okOut := RenderProxyHostCaddyfile(ok)
	if !strings.Contains(okOut, "http://*.sub.example.test, https://*.sub.example.test, b.example.test:8443 {") || !strings.Contains(okOut, "header_up X-Request-Source `caddyui {http.request.host}`") || strings.Contains(okOut, "respond 503") {
		t.Fatalf("safe values must render normally:\n%s", okOut)
	}

	caddyBin := lookCaddy(t)
	if caddyBin == "" {
		return
	}
	file := filepath.Join(t.TempDir(), "Caddyfile")
	all := []models.ProxyHost{p, ok}
	for i, tc := range failClosed {
		q := base()
		q.ID = int64(100 + i)
		q.Domains = fmt.Sprintf("fc%d.example.test", i)
		tc.edit(&q)
		all = append(all, q)
	}
	if err := os.WriteFile(file, []byte(RenderServerCaddyfile("srv{$A", all, []models.RedirectionHost{redirect}, nil, nil)), 0o644); err != nil {
		t.Fatal(err)
	}
	adapted, raw := caddyAdapt(t, caddyBin, file)
	// Force SSL is off, so the two working hosts are served on :80 too
	// (T-0947, finding 10); fail-closed sites stay HTTPS-only.
	want := []string{"*.sub.example.test", "*.sub.example.test", "a.example.test", "a.example.test", "b.example.test", "r.example.test"}
	for i := range failClosed {
		want = append(want, fmt.Sprintf("fc%d.example.test", i))
	}
	sort.Strings(want)
	if got := adaptedHosts(adapted); strings.Contains(string(raw), "evil.example.test") || strings.Contains(string(raw), "127.0.0.1:2019") || !reflect.DeepEqual(got, want) {
		t.Fatalf("adapted export serves %v, want exactly %v:\n%s", got, want, raw)
	}
	if !strings.Contains(string(raw), `"a.example.test"`) || !strings.Contains(string(raw), `"fc0.example.test"`) {
		t.Fatalf("adapted export lost a site:\n%s", raw)
	}
}

// rawJSON is a stored raw-route JSON whose routes match the given hosts.
func rawJSON(hosts ...string) string {
	b, _ := json.Marshal(map[string]any{"match": []any{map[string]any{"host": hosts}}, "handle": []any{map[string]any{"handler": "static_response"}}})
	return string(b)
}

// Issue #184 review: raw-route Caddyfiles are written verbatim, so each one
// must be complete site blocks that cannot reach a neighbour, whose
// addresses the route's stored JSON actually serves. The review's attacks:
// a `{$` in the label comment swallowing text up to the next `}`; text that
// claims another owner's host, or opens a listener, while the stored JSON
// (which the tenant checks saw) matches only the tenant's own host.
func TestCaddyfileExportKeepsRawRoutesSelfContained(t *testing.T) {
	attack := models.RawRoute{ID: 3, Label: "{$", Enabled: true, JSONData: rawJSON("t2.example.com"),
		CaddyfileSrc: "t2.example.com {\n\trespond \"}\nevil.example.test {\n\treverse_proxy 127.0.0.1:2019\n}\nz.example.com {\n\trespond x\" 200\n}"}
	out := RenderRawRouteCaddyfile(attack)
	if strings.Contains(out, "{$") || !strings.Contains(out, "t2.example.com {") {
		t.Fatalf("label must lose {$ and the (self-contained) source stays:\n%s", out)
	}
	omitted := map[string]models.RawRoute{
		"unbalanced":         {CaddyfileSrc: "a.example.test {\n\trespond 200\n}\n}\nevil.example.test {\n\treverse_proxy 127.0.0.1:2019\n"},
		"unclosed env var":   {CaddyfileSrc: "a.example.test {\n\trespond \"{$HOME\" 200\n}"},
		"file import":        {CaddyfileSrc: "a.example.test {\n\timport /etc/caddy/Caddyfile\n}"},
		"global options":     {CaddyfileSrc: "{\n\tadmin 0.0.0.0:2019\n}\na.example.test {\n\trespond 200\n}"},
		"snippet":            {CaddyfileSrc: "(evil) {\n\treverse_proxy 127.0.0.1:2019\n}"},
		"open heredoc":       {CaddyfileSrc: "a.example.test {\n\trespond <<EOF\n\t}\n}"},
		"no braces":          {CaddyfileSrc: "a.example.test\nrespond 200"},
		"braceless second":   {CaddyfileSrc: "a.example.test {\n\trespond 200\n}\nb.example\nreverse_proxy 127.0.0.1:2019"},
		"open quote":         {CaddyfileSrc: "a.example.test {\n\trespond \"x 200\n}"},
		"claims victim host": {CaddyfileSrc: "victim.example.test/admin* {\n\treverse_proxy 127.0.0.1:2019\n}"},
		"claims extra host":  {CaddyfileSrc: "a.example.test, victim.example.test {\n\trespond 200\n}"},
		"opens a listener":   {CaddyfileSrc: ":2019 {\n\treverse_proxy 127.0.0.1:2019\n}"},
		"custom port":        {CaddyfileSrc: "a.example.test:2019 {\n\trespond 200\n}"},
		"no stored JSON":     {CaddyfileSrc: "a.example.test {\n\trespond 200\n}", JSONData: "-"},
	}
	for name, rr := range omitted {
		rr.ID, rr.Label = 5, name
		if rr.JSONData == "" {
			rr.JSONData = rawJSON("a.example.test")
		}
		out := RenderRawRouteCaddyfile(rr)
		if strings.Contains(out, "respond") || strings.Contains(out, "evil") || strings.Contains(out, "2019 {") || !strings.Contains(out, "# (omitted: ") {
			t.Errorf("%s: raw route must be omitted:\n%s", name, out)
		}
	}
	kept := map[string]models.RawRoute{
		"two sites":          {CaddyfileSrc: "a.example.test {\n\trespond \"}{\" 200\n}\nb.example.test {\n\trespond `x` 200\n}", JSONData: "[" + rawJSON("a.example.test") + "," + rawJSON("b.example.test") + "]"},
		"heredoc":            {CaddyfileSrc: "a.example.test {\n\trespond <<HTML\n\t\t<h1>}</h1>\n\t\tHTML 503\n}"},
		"import as argument": {CaddyfileSrc: "a.example.test {\n\trespond /x \"import\" 200\n}"},
		"closed env var":     {CaddyfileSrc: "a.example.test {\n\theader X-Env {$HOME}\n\trespond 200\n}"},
		"scheme and path":    {CaddyfileSrc: "https://a.example.test/api/* {\n\trespond 200\n}"},
		"own listener":       {CaddyfileSrc: "a.example.test:7070 {\n\trespond 200\n}", Listen: `[":7070"]`},
		"hostless listener":  {CaddyfileSrc: ":7070 {\n\trespond 200\n}", JSONData: `{"handle":[{"handler":"static_response"}]}`, Listen: `[":7070"]`},
		"brace on next line": {CaddyfileSrc: "a.example.test\n{\n\trespond 200\n}"},
		"comma across lines": {CaddyfileSrc: "a.example.test,\nb.example.test {\n\trespond 200\n}", JSONData: rawJSON("a.example.test", "b.example.test")},
		"case-insensitive":   {CaddyfileSrc: "A.Example.Test {\n\trespond 200\n}"},
	}
	var keptRoutes []models.RawRoute
	for name, rr := range kept {
		rr.ID, rr.Label, rr.Enabled = int64(10+len(keptRoutes)), name, true
		if rr.JSONData == "" {
			rr.JSONData = rawJSON("a.example.test")
		}
		if out := RenderRawRouteCaddyfile(rr); strings.Contains(out, "# (omitted: ") {
			t.Errorf("%s: well-formed raw route must stay:\n%s", name, out)
		}
		keptRoutes = append(keptRoutes, rr)
	}

	twoSites := kept["two sites"]
	twoSites.ID, twoSites.Enabled = 99, true
	caddyBin := lookCaddy(t)
	if caddyBin == "" {
		return
	}
	file := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(file, []byte(RenderServerCaddyfile("", nil, nil, []models.RawRoute{attack, twoSites}, nil)), 0o644); err != nil {
		t.Fatal(err)
	}
	adapted, raw := caddyAdapt(t, caddyBin, file)
	// In isolation the attack route is t2.example.com answering with a body
	// that merely contains the other text.
	if got := adaptedHosts(adapted); !reflect.DeepEqual(got, []string{"a.example.test", "b.example.test", "t2.example.com"}) || strings.Contains(string(raw), `"dial":"127.0.0.1:2019"`) {
		t.Fatalf("adapted export serves %v; want only the raw routes as written:\n%s", got, raw)
	}
	// Each kept route adapts on its own between neighbours.
	for _, rr := range keptRoutes {
		f := filepath.Join(t.TempDir(), "kept")
		_ = os.WriteFile(f, []byte(RenderServerCaddyfile("", nil, nil, []models.RawRoute{rr}, nil)), 0o644)
		caddyAdapt(t, caddyBin, f)
	}
}

// Issue #184 review (A): with Strip prefix the excerpt uses a `route` block,
// and Caddyfile sorts `route` before `abort`/`error`/`respond`. Advanced
// handlers must therefore move inside the route, in the JSON route's order —
// [blocker, Advanced, strip, reverse_proxy] — or the host fails closed.
func TestCaddyfileStripPrefixKeepsAdvancedHandlerOrder(t *testing.T) {
	cases := []struct {
		name, advanced string
		failClosed     bool
	}{
		{name: "allowlist", advanced: "@denied not remote_ip 10.0.0.0/8\nabort @denied"},
		{name: "maintenance", advanced: "respond \"down for maintenance\" 503"},
		{name: "site options stay outside", advanced: "tls internal\nheader X-A 1\nrespond /down 503"},
		{name: "out of order", advanced: "respond /x 503\nheader X-A 1", failClosed: true},
		{name: "repeated directive with matchers", advanced: "respond /x 503\nrespond /y 503", failClosed: true},
		{name: "repeated header without matchers", advanced: "header X-A 1\nheader X-B 2\nheader -Server"},
		{name: "repeated header, one with matcher", advanced: "header X-A 1\nheader /x X-B 2", failClosed: true},
		{name: "unknown directive", advanced: "rate_limit 10r/s", failClosed: true},
	}
	caddyBin := lookCaddy(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := pathMatcherHost("/api", "", true)
			p.BlockCommonExploits = true
			p.AdvancedConfig = tc.advanced
			out := RenderProxyHostCaddyfile(p)
			if tc.failClosed {
				if strings.Contains(out, "reverse_proxy") || !strings.Contains(out, "\trespond 503\n") {
					t.Fatalf("expected fail closed:\n%s", out)
				}
				return
			}
			route := strings.Index(out, "\troute {\n")
			adv := strings.Index(out, "# from Advanced config")
			strip := strings.Index(out, "uri @caddyui_path strip_prefix")
			if route < 0 || adv < route || strip < adv || strings.Contains(out, "Advanced raw config") && !strings.Contains(tc.advanced, "tls") {
				t.Fatalf("Advanced handlers must sit in the route before the strip:\n%s", out)
			}
			if caddyBin == "" {
				return
			}
			dir := t.TempDir()
			advFile := filepath.Join(dir, "adv")
			if err := os.WriteFile(advFile, []byte("localhost {\n"+tc.advanced+"\n}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			advAdapted, _ := caddyAdapt(t, caddyBin, advFile)
			handlers := advAdapted.(map[string]any)["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)["routes"].([]any)[0].(map[string]any)["handle"].([]any)
			want := handlerOrder(BuildProxyRoute(p, handlers))

			file := filepath.Join(dir, "Caddyfile")
			if err := os.WriteFile(file, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
			adapted, raw := caddyAdapt(t, caddyBin, file)
			if got := handlerOrder(adapted); !reflect.DeepEqual(got, want) {
				t.Errorf("adapted order %v, JSON route order %v\n%s", got, want, raw)
			}
		})
	}
}

// adaptedHosts lists, sorted, every host matched by a top-level route of an
// adapted config.
func adaptedHosts(adapted any) []string {
	var hosts []string
	servers, _ := adapted.(map[string]any)["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, srv := range servers {
		routes, _ := srv.(map[string]any)["routes"].([]any)
		for _, r := range routes {
			ms, _ := r.(map[string]any)["match"].([]any)
			for _, m := range ms {
				hs, _ := m.(map[string]any)["host"].([]any)
				for _, h := range hs {
					hosts = append(hosts, h.(string))
				}
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}

// lookCaddy returns the caddy binary for the `caddy adapt` checks. Without
// one it records an explicitly skipped "caddy adapt" subtest — visible with
// -v or -json — and returns "", and the caller runs only its text checks.
func lookCaddy(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("caddy")
	if err != nil {
		t.Run("caddy adapt", func(t *testing.T) {
			t.Skip("SKIPPED: no `caddy` binary on PATH, so this test's `caddy adapt` equivalence check did NOT run — only its text checks did. Put caddy on PATH to run it.")
		})
		return ""
	}
	return bin
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// checkCaddyfileSites must never accept text that Caddy would read
// differently once concatenated: for every accepted snippet, Caddy must
// parse `before + snippet + after` as exactly the snippet's own sites plus
// both neighbours. The corpus targets the lexer corners — quotes and
// backticks holding braces, escapes, comments, line continuations.
func TestCheckCaddyfileSitesAgreesWithCaddy(t *testing.T) {
	corpus := []string{
		"a.test {\n\trespond \"}\" 200\n}",
		"a.test {\n\trespond `}\n}\nevil.test {` 200\n}",
		"a.test {\n\trespond \"\\\"}\" 200\n}",
		"a.test {\n\trespond \"\\\\\" 200\n}",
		"a.test {\n\t# }\n\trespond 200\n}",
		"a.test {\n\trespond x#} 200\n}",
		"a.test {\n\trespond \\\n\t\t200\n}",
		"a.test {\n\theader X \\}\n}",
		"a.test {\n\theader X \\{\n}",
		"a.test {\n\theader X a\\ b\n}",
		"a.test {\n\trespond {http.request.host} 200\n}",
		"a.test b.test {\n\trespond 200\n}\nc.test {\n\troute {\n\t\trespond 200\n\t}\n}",
		"a.test {\n\trespond \"x\n}\nevil.test {\n\" 200\n}",
		"a.test {\n\trespond 200\n} # trailing",
		"a.test {\n\trespond \"}{\" 200 \\\n}",
		"a.test {\n\trespond \"a\" 200}\n}",
		"a.test {\n\trespond 200 }",
		"a.test {respond 200}",
		"a.test {\r\n\trespond 200\r\n}",
		"\uFEFFa.test {\n\trespond 200\n}",
		"a.test {\n\trespond \"\\\n}\nevil.test {\n\" 200\n}",
		"a.test {\n\trespond `\\` 200\n}",
		// round-3 review: addresses end at their line (parse.go addresses())
		"a.test {\n\trespond 200\n}\nb.example\nreverse_proxy 127.0.0.1:2019 {\n}",
		"b.example\nreverse_proxy 127.0.0.1:2019",
		"a.test\n{\n\trespond 200\n}",
		"a.test,\nb.test {\n\trespond 200\n}",
		"a.test, {\n\trespond 200\n}",
		"a.test b.test\nc.test {\n\trespond 200\n}",
		// heredocs, with Caddy's own termination and padding rules
		"a.test {\n\trespond <<EOF\n\t\t}\n\t\tevil.test {\n\t\tEOF 200\n}",
		"a.test {\n\trespond <<EOF\n\t}\nEOF 200\n}",
		"a.test {\n\trespond <<EOF\nx\n\t}\n\tEOF 200\n}",
		"a.test {\n\trespond <<EOF\n\t}\n}\n",
		"a.test {\n\trespond \\<<EOF 200\n}",
		"a.test {\n\trespond <<A-1\n\tfoo A-1 bar\n\tA-1 200\n}",
		// import only as a directive; well-formed {$NAME} only
		"a.test {\n\trespond /x \"import\" 200\n}",
		"a.test {\n\theader X import\n}",
		"a.test {\n\theader X {$HOME}\n}",
		"a.test {\n\theader X {$HOME\n}\nb.test {\n\trespond 200\n}",
		"a.test {\n\theader X {$HOME:d}\n}",
	}
	accepted := 0
	for i, src := range corpus {
		if _, err := checkCaddyfileSites(src, nil); err == nil {
			accepted++
		} else {
			corpus[i] = ""
		}
	}
	if accepted < 12 {
		t.Fatalf("only %d corpus entries accepted — the checker is refusing ordinary input", accepted)
	}
	caddyBin := lookCaddy(t)
	if caddyBin == "" {
		return
	}
	dir := t.TempDir()
	for i, src := range corpus {
		if src == "" {
			continue
		}
		alone := filepath.Join(dir, fmt.Sprintf("alone%d", i))
		both := filepath.Join(dir, fmt.Sprintf("both%d", i))
		_ = os.WriteFile(alone, []byte(src+"\n"), 0o644)
		_ = os.WriteFile(both, []byte("before.test {\n\trespond 201\n}\n"+src+"\nafter.test {\n\trespond 202\n}\n"), 0o644)
		raw, err := exec.Command(caddyBin, "adapt", "--config", alone, "--adapter", "caddyfile").Output()
		if err != nil {
			continue // Caddy rejects it alone; the exporter cannot make that worse
		}
		var a any
		_ = json.Unmarshal(raw, &a)
		want := append(adaptedHosts(a), "after.test", "before.test")
		sort.Strings(want)
		raw2, err := exec.Command(caddyBin, "adapt", "--config", both, "--adapter", "caddyfile").Output()
		if err != nil {
			t.Errorf("accepted snippet %q adapts alone but not between neighbours: %v", src, err)
			continue
		}
		var b any
		_ = json.Unmarshal(raw2, &b)
		if got := adaptedHosts(b); !reflect.DeepEqual(got, want) {
			t.Errorf("accepted snippet %q changes its neighbours: hosts %v, want %v", src, got, want)
		}
		if !strings.Contains(string(raw2), `"status_code":201`) || !strings.Contains(string(raw2), `"status_code":202`) {
			t.Errorf("accepted snippet %q swallowed a neighbour's handler:\n%s", src, raw2)
		}
	}
}

// Round-3 review: ordinary Advanced configs and raw routes must export, not
// fail closed. The count of this corpus that rendered as a 503 site or an
// omitted route was 9 of 24 on the round-2 code; it must now be 0.
func TestRealisticCaddyfileCorpusExports(t *testing.T) {
	snippets := []string{"(common_headers) {\n\theader X-Frame-Options DENY\n}"}
	admin := ExportOptions{Snippets: snippets, IncludeSnippets: true, TenantOwned: func(sql.NullInt64) bool { return false }}
	advanced := []string{
		"encode gzip zstd",
		"header {\n\t-Server\n\tX-Robots-Tag \"noindex\"\n}",
		"tls {\n\tdns cloudflare {$CF_API_TOKEN}\n}",
		"request_body {\n\tmax_size 10MB\n}",
		"reverse_proxy {\n\tflush_interval -1\n\ttransport http {\n\t\tread_timeout 300s\n\t}\n}",
		"@blocked not remote_ip 10.0.0.0/8 192.168.0.0/16\nabort @blocked",
		"header X-Frame-Options DENY\nheader X-Content-Type-Options nosniff",
		"import common_headers",
		"rewrite /old /new",
		"basic_auth /admin/* {\n\tadmin $2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG\n}",
		"header Content-Security-Policy \"default-src 'self'; img-src * data:\"",
		"log {\n\toutput file /var/log/caddy/app.log\n}",
		"uri strip_suffix .html",
		"header X-Info \"import\"",
		"handle_errors {\n\theader X-Status {err.status_code}\n}",
		"header /api/* Cache-Control no-store",
		"header X-Upstream {$UPSTREAM_NAME}",
	}
	strip := []string{
		"header X-A 1\nheader X-B 2",
		"@blocked not remote_ip 10.0.0.0/8\nabort @blocked",
		"tls {\n\tdns cloudflare {$CF_API_TOKEN}\n}\nencode gzip",
	}
	raws := []models.RawRoute{
		{CaddyfileSrc: "app.test {\n\treverse_proxy 10.0.0.5:8080\n}"},
		{CaddyfileSrc: "app.test {\n\trespond <<HTML\n\t\t<h1>Maintenance</h1>\n\t\tHTML 503\n}"},
		{CaddyfileSrc: "app.test {\n\trespond /x \"import\" 200\n}"},
		{CaddyfileSrc: "app.test {\n\theader X-Env {$HOME}\n\treverse_proxy 10.0.0.5:8080\n}"},
	}
	failed := 0
	for i, adv := range append(advanced, strip...) {
		p := models.ProxyHost{ID: int64(i), Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: adv}
		if i >= len(advanced) {
			p.PathMatcher, p.StripPathPrefix = "/api", true
		}
		if out := RenderProxyHostCaddyfileWithOptions(p, nil, admin); strings.Contains(out, "respond 503") || strings.Contains(out, "omitted") {
			failed++
			t.Errorf("Advanced config %q fails closed:\n%s", adv, out)
		}
	}
	for i, rr := range raws {
		rr.ID, rr.Enabled, rr.JSONData = int64(i), true, rawJSON("app.test")
		if out := renderRawRoute(rr, admin); strings.Contains(out, "# (omitted") {
			failed++
			t.Errorf("raw route %q is omitted:\n%s", rr.CaddyfileSrc, out)
		}
	}
	t.Logf("realistic corpus: %d of %d fail closed", failed, len(advanced)+len(strip)+len(raws))

	// The server-wide export carries the snippet the import needs.
	p := models.ProxyHost{ID: 1, Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: "import common_headers"}
	full := RenderServerCaddyfile("", []models.ProxyHost{p}, nil, nil, nil, admin)
	if !strings.Contains(full, "(common_headers) {") || !strings.Contains(full, "\timport common_headers\n") {
		t.Fatalf("export must carry the snippet and keep the import:\n%s", full)
	}
	// A tenant's import, an unknown snippet and a file import fail closed
	// and say why.
	tenant := admin
	tenant.TenantOwned = func(sql.NullInt64) bool { return true }
	for _, tc := range []struct {
		opts       ExportOptions
		adv, wants string
	}{
		{tenant, "import common_headers", "imports are kept only for admin-owned hosts"},
		{admin, "import missing_snippet", "not a self-contained snippet in the server Caddyfile"},
		{admin, "import /etc/caddy/*.caddy", "file imports are never exported"},
		{ExportOptions{Snippets: []string{"(bad) {\n\timport /etc/passwd\n}"}, IncludeSnippets: true}, "import bad", "not a self-contained snippet"},
	} {
		p.AdvancedConfig = tc.adv
		if out := RenderProxyHostCaddyfileWithOptions(p, nil, tc.opts); !strings.Contains(out, "respond 503") || !strings.Contains(out, tc.wants) {
			t.Errorf("%q: want a 503 site saying %q:\n%s", tc.adv, tc.wants, out)
		}
	}
	// Header-value shorthand stays fail-closed, with the reason spelled out.
	p.AdvancedConfig = ""
	p.CustomReqHeaders = `{"X-Real-IP":"{remote_host}"}`
	if out := RenderProxyHostCaddyfile(p); !strings.Contains(out, "custom request header X-Real-IP: its value contains the placeholder shorthand remote_host, which a Caddyfile expands but the live route passes through literally") {
		t.Errorf("shorthand reason must be explicit:\n%s", out)
	}

	caddyBin := lookCaddy(t)
	if caddyBin == "" {
		return
	}
	dir := t.TempDir()
	for i, adv := range append(advanced, strip...) {
		if strings.Contains(adv, "dns cloudflare") {
			continue // needs the cloudflare DNS module
		}
		p := models.ProxyHost{ID: int64(i), Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: adv}
		if i >= len(advanced) {
			p.PathMatcher, p.StripPathPrefix = "/api", true
		}
		f := filepath.Join(dir, fmt.Sprintf("adv%d", i))
		_ = os.WriteFile(f, []byte(RenderServerCaddyfile("", []models.ProxyHost{p}, nil, nil, nil, admin)), 0o644)
		caddyAdapt(t, caddyBin, f)
	}
}
