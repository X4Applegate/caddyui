// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
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
	{name: "regexp with backtick", matcher: "^/a`b\"c", typ: "regexp", wantMatcher: `path_regexp "^/a` + "`" + `b\"c"`},
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
			raw, err := exec.Command(caddyBin, "adapt", "--config", file, "--adapter", "caddyfile").Output()
			if err != nil {
				t.Fatalf("caddy adapt: %v\n%s", err, RenderProxyHostCaddyfile(p))
			}
			var adapted any
			if err := json.Unmarshal(raw, &adapted); err != nil {
				t.Fatalf("adapt output: %v\n%s", err, raw)
			}
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
