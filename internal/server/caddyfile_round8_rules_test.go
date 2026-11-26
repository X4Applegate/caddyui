// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Issue #184 round 8: the tenant text rules one at a time.
func TestTenantTextRulesRound8(t *testing.T) {
	snippets := map[string]bool{"common": true, "secure-headers": true}
	check := func(txt string) string {
		return tenantTextViolationWith(txt, snippets, tenantMaxNestingDepth, maxTenantCaddyfileBytes)
	}

	// (1) imports: only the administrator's snippets, by name.
	for name, txt := range map[string]string{
		"undefined name":     "x.test {\n\timport mysecret\n}",
		"inside a block":     "x.test {\n\theader {\n\t\timport secrets\n\t}\n}",
		"a path":             "x.test {\n\timport /etc/passwd\n}",
		"snippet name case":  "x.test {\n\timport Common\n}",
		"quoted file import": "x.test {\n\timport \"d\"\n}",
	} {
		if check(txt) == "" {
			t.Errorf("import, %s: want refused:\n%s", name, txt)
		}
	}
	for name, txt := range map[string]string{
		"snippet":          "x.test {\n\timport common\n}",
		"snippet with arg": "x.test {\n\timport secure-headers v1\n}",
		"nested":           "x.test {\n\thandle /a {\n\t\timport common\n\t}\n}",
	} {
		if why := check(txt); why != "" {
			t.Errorf("import, %s: want allowed, got %q", name, why)
		}
		if tenantTextViolation(txt) == "" {
			t.Errorf("import, %s: with no administrator snippets every import must be refused", name)
		}
	}

	// (2) nesting depth.
	site := func(depth int) string { return "x.test {\n" + nestedHandles(depth-1) + "}\n" }
	if why := check(site(tenantMaxNestingDepth)); why != "" {
		t.Errorf("depth %d: want allowed, got %q", tenantMaxNestingDepth, why)
	}
	for _, d := range []int{tenantMaxNestingDepth + 1, 100, 4000} {
		if why := check(site(d)); !strings.Contains(why, "nested") {
			t.Errorf("depth %d: want refused for nesting, got %q", d, why)
		}
	}
	if why := tenantTextViolationWith(site(tenantMaxNestingDepth+3), nil, tenantMaxBlockNestingDepth, 0); why != "" {
		t.Errorf("the wrapped-text limit must leave room for CaddyUI's own blocks: %q", why)
	}

	// (3) snippet placeholders: only the keys Caddy replaces, per token.
	for name, txt := range map[string]string{
		"args index":     "x.test {\n\theader X-A {args[0]}\n}",
		"args range":     "x.test {\n\theader X-A {args[:]}\n}",
		"args dot":       "x.test {\n\theader X-A {args.1}\n}",
		"args in a word": "x.test {\n\theader X-A pre{args[0]}post\n}",
		"args quoted":    "x.test {\n\trespond \"{args[0]}\"\n}",
		"block":          "x.test {\n\t{block}\n}",
		"blocks":         "x.test {\n\theader X-A {blocks.a}\n}",
	} {
		if check(txt) == "" {
			t.Errorf("placeholder, %s: want refused:\n%s", name, txt)
		}
	}
	for name, txt := range map[string]string{
		"rewrite args.html":  "handle /docs {\n\trewrite * /args.html\n}",
		"path args.php":      "@legacy path /cgi/args.php\nrewrite @legacy /new",
		"kwargs header":      "header Link \"</static/kwargs.css>; rel=preload\"",
		"json body":          "respond `{\"args.count\": 1}` 200",
		"script body":        "respond \"<script>function f(args){ return args[0] }</script>\"",
		"query placeholder":  "header X-Q {http.request.uri.query.args[0]}",
		"key with a prefix":  "header X-Q {x args.1}",
		"handle_path block":  "handle_path /block/* {\n\treverse_proxy 203.0.113.10:80\n}",
		"word block":         "respond \"{ blocks }\"",
		"import in a string": "respond \"see import guide v2.1\"",
		"comment":            "# Tags: data import 2024.q1 {args[0]}\nheader X-A a",
	} {
		if why := check(txt); why != "" {
			t.Errorf("placeholder, %s: want allowed, got %q:\n%s", name, why, txt)
		}
	}

	// (4) snippet definitions, however the address list is spelled.
	for name, txt := range map[string]string{
		"line start":      "(s) {\n\theader X-A a\n}\nx.test {\n\timport s\n}",
		"empty address":   "\"\" (s) {\n\theader X-A a\n}\n",
		"comma address":   ", (s) {\n\theader X-A a\n}\n",
		"comma then line": "\"\",\n(s) {\n\theader X-A a\n}\n",
		"after a close":   "header X-B b\n}\n\"\" (s) {\n\theader X-A a\n}\n",
	} {
		if why := check(txt); !strings.Contains(why, "snippet") {
			t.Errorf("snippet definition, %s: want refused, got %q:\n%s", name, why, txt)
		}
	}
	for name, txt := range map[string]string{
		"regexp group":    "@m path_regexp (a|b)\nrespond @m 200",
		"two addresses":   "a.test (b) {\n\trespond 1\n}",
		"in a site block": "x.test {\n\t@m path_regexp (a|b)\n}",
	} {
		if why := check(txt); strings.Contains(why, "snippet definition") {
			t.Errorf("not a snippet definition, %s: got %q", name, why)
		}
	}
}

// Caddy replaces a snippet placeholder only when the whole key is the
// placeholder (caddyfile/importargs.go): tenantTextViolation's per-token
// rule is checked here against Caddy itself, with an administrator snippet.
func TestSnippetPlaceholderKeysAgreeWithCaddy(t *testing.T) {
	_, _, _, caddyBin, _, _ := newExportFixture(t)
	requireCaddy(t, caddyBin, "the snippet is adapted with Caddy")
	// Issue #184 round 10 (7): `{args.x}` and `${args.x}` (a JavaScript
	// template literal) are text to Caddy, `{args.+0}` is not.
	values := map[string]string{"X-Exact": "{args[0]}", "X-Dot": "{args.0}", "X-Prefixed": "{x args.0}", "X-Query": "{http.request.uri.query.args[0]}",
		"X-Name": "{args.x}", "X-Js": "${args.x}", "X-Signed": "{args.+0}"}
	substituted := map[string]bool{"X-Exact": true, "X-Dot": true, "X-Prefixed": false, "X-Query": false,
		"X-Name": false, "X-Js": false, "X-Signed": true}
	var b strings.Builder
	b.WriteString("(s) {\n")
	for _, hdr := range []string{"X-Exact", "X-Dot", "X-Prefixed", "X-Query", "X-Name", "X-Js", "X-Signed"} {
		fmt.Fprintf(&b, "\theader %s \"%s\"\n", hdr, values[hdr])
	}
	b.WriteString("}\nk.example.test {\n\timport s SUBSTITUTED\n}\n")
	out, err := adaptWithCaddy(caddyBin, []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for hdr, want := range substituted {
		i := strings.Index(got, `"`+hdr+`"`)
		if i < 0 {
			t.Fatalf("%s missing from %s", hdr, got)
		}
		val := got[i:min(len(got), i+120)]
		if j := strings.Index(val, "]"); j >= 0 {
			val = val[:j] // this header's value only
		}
		if strings.Contains(val, "SUBSTITUTED") != want {
			t.Errorf("%s: Caddy substituted=%v, the tenant rule assumes %v: %s", hdr, !want, want, val)
		}
		line := fmt.Sprintf("header %s \"%s\"", hdr, values[hdr])
		if refused := tenantTextViolationWith(line, nil, tenantMaxNestingDepth, maxTenantCaddyfileBytes) != ""; refused != want {
			t.Errorf("%s: tenant rule refused=%v, Caddy substituted=%v", hdr, refused, want)
		}
	}
}

// The depth limit is not reached by real configurations: a tenant's Advanced
// route nested exactly to the limit adapts in Caddy and saves.
func TestTenantTextAtTheDepthLimitSaves(t *testing.T) {
	s, _, sid, caddyBin, _, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "the raw route is adapted with Caddy")
	raw := "limit.example.test {\n" + nestedHandles(tenantMaxNestingDepth-1) + "}\n"
	body, _ := json.Marshal(map[string]any{"label": "limit", "enabled": true, "caddyfile_src": raw})
	req := asUser(httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body))), sid, tenant, nil)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.apiV1CreateRawRoute(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("want 201, got %d %s", rec.Code, rec.Body.String())
	}
}

// Issue #184 round 8 (2): the adapt-time check bounds the size of any
// non-admin text, whatever path it came through, with room for the
// synthetic site around an Advanced config.
func TestTenantAdaptTextCheckBoundsSize(t *testing.T) {
	s := &Server{}
	line := "header X-A \"aaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n"
	fits := strings.Repeat(line, maxTenantCaddyfileBytes/len(line))
	if why := s.tenantAdaptTextViolation("localhost {\n" + fits + "\n}\n"); why != "" {
		t.Errorf("an Advanced config at the limit, wrapped: %q", why)
	}
	if why := s.tenantAdaptTextViolation("x.test {\n" + strings.Repeat(line, (maxTenantCaddyfileBytes+8<<10)/len(line)) + "}\n"); !strings.Contains(why, "too large") {
		t.Errorf("oversized text: want refused, got %q", why)
	}
}
