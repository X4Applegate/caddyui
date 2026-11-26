// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
		t.Skip("caddy binary not on PATH")
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
	{"underscore placeholder", "/{_x}", "exact"},
}

// Issue #184 review (blocking): values that cannot be one safe token make
// the site refuse every request — never a quoted token that can be broken
// out of, and never a dropped matcher that would proxy every path.
func TestCaddyfilePathMatcherFailsClosed(t *testing.T) {
	caddyBin, _ := exec.LookPath("caddy")
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

		caddyBin, err := exec.LookPath("caddy")
		if err != nil {
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

// Issue #184 review (audit): other user-supplied values the exporter writes
// as bare tokens or into comments must not be able to add lines or blocks.
// A bare value that cannot be one safe token leaves its site out entirely;
// comment text has line breaks flattened.
func TestCaddyfileExportContainsUnsafeFieldValues(t *testing.T) {
	const evil = "\n}\nevil.example.test {\n\treverse_proxy 127.0.0.1:2019\n}\n"
	base := func() models.ProxyHost {
		return models.ProxyHost{ID: 9, Domains: "a.example.test", ForwardScheme: "http", ForwardHost: "192.0.2.10", ForwardPort: 8989, Enabled: true, SSLEnabled: true}
	}
	omitted := []struct {
		name string
		edit func(*models.ProxyHost)
	}{
		{"request header name", func(p *models.ProxyHost) { p.CustomReqHeaders = `{"X-A` + jsonEscape(evil) + `#":"v"}` }},
		{"response header name", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"X-A` + jsonEscape(evil) + `#":"v"}` }},
		{"strip request header", func(p *models.ProxyHost) { p.StripReqHeaders = "X-A" + evil + "#" }},
		{"strip response header", func(p *models.ProxyHost) { p.StripRespHeaders = "X-A" + evil + "#" }},
		{"upstream SNI", func(p *models.ProxyHost) { p.UpstreamSNI = "sni" + evil + "#" }},
		{"forward host", func(p *models.ProxyHost) { p.ForwardHost = "192.0.2.10" + evil + "#" }},
		{"lb policy", func(p *models.ProxyHost) { p.LBPolicy = "first" + evil + "#"; p.ExtraUpstreams = `["192.0.2.11:80"]` }},
		{"header name with env var", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"X-{$HOME}":"v"}` }},
		{"header name starting a matcher", func(p *models.ProxyHost) { p.CustomRespHeaders = `{"@x":"v"}` }},
		{"header name with trailing backslash", func(p *models.ProxyHost) { p.CustomReqHeaders = `{"X-A\\":"v"}` }},
	}
	for _, tc := range omitted {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.edit(&p)
			out := RenderServerCaddyfile("", []models.ProxyHost{p}, nil, nil, nil)
			if strings.Contains(out, "evil.example.test") || strings.Contains(out, "a.example.test {") || !strings.Contains(out, "# Proxy host #9 omitted") {
				t.Fatalf("site with an unsafe bare value must be omitted:\n%s", out)
			}
		})
	}
	redirect := models.RedirectionHost{ID: 4, Domains: "r.example.test", ForwardDomain: "new.example.test" + evil + "#", Enabled: true}
	if out := RenderRedirectionCaddyfile(redirect); strings.Contains(out, "evil.example.test") || !strings.Contains(out, "# Redirection host #4 omitted") {
		t.Fatalf("redirect with an unsafe destination must be omitted:\n%s", out)
	}

	// Comment fields keep the site but cannot start a new line.
	p := base()
	p.Tags = "team" + evil
	p.HealthCheckURI = "/health" + evil
	p.OwnerEmail = "o@example.test" + evil
	out := RenderServerCaddyfile("", []models.ProxyHost{p}, nil, nil, nil)
	if strings.Contains(out, "\nevil.example.test {") || !strings.Contains(out, "a.example.test {") {
		t.Fatalf("comment fields must stay on their comment line:\n%s", out)
	}
	// Legitimate values are untouched.
	ok := base()
	ok.CustomReqHeaders = `{"X-Request-Source":"caddyui"}`
	ok.StripRespHeaders = "Server, X-Powered-By"
	ok.Domains = "*.sub.example.test, b.example.test:8443"
	if out := RenderProxyHostCaddyfile(ok); !strings.Contains(out, "*.sub.example.test, b.example.test:8443 {") || !strings.Contains(out, "header_up X-Request-Source") {
		t.Fatalf("safe values must render normally:\n%s", out)
	}

	caddyBin, err := exec.LookPath("caddy")
	if err != nil {
		return
	}
	file := filepath.Join(t.TempDir(), "Caddyfile")
	all := []models.ProxyHost{p}
	for _, tc := range omitted {
		q := base()
		q.Domains = "omitted-" + strings.ReplaceAll(tc.name, " ", "-") + ".example.test"
		tc.edit(&q)
		all = append(all, q)
	}
	if err := os.WriteFile(file, []byte(RenderServerCaddyfile("", all, []models.RedirectionHost{redirect}, nil, nil)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, raw := caddyAdapt(t, caddyBin, file)
	if strings.Contains(string(raw), "evil.example.test") || strings.Contains(string(raw), "127.0.0.1:2019") || strings.Contains(string(raw), "omitted-") {
		t.Fatalf("adapted export serves injected or omitted sites:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"a.example.test"`) {
		t.Fatalf("adapted export lost the safe site:\n%s", raw)
	}
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
