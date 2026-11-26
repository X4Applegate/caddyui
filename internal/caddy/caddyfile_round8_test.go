// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func round8Nested(depth int) string {
	return "x.test {\n" + strings.Repeat("handle {\n", depth-1) + "respond 1\n" + strings.Repeat("}\n", depth) + ""
}

// Issue #184 round 8: CaddyfileNestingDepth reads nesting the way Caddy's
// parser and dispenser do, erring high.
func TestCaddyfileNestingDepth(t *testing.T) {
	for src, want := range map[string]int{
		"x.test {\n\trespond 1\n}":                                1,
		round8Nested(5):                                           5,
		"x.test {\n\trespond \"{\"\n\trespond \"{\"\n}":           1, // quoted braces are text
		"x.test {\n\thandle {\n\t} respond 1\n\thandle {\n\t}\n}": 3, // a `}` that does not end its line closes nothing for the dispenser
		"a.test {\n}\nb.test {\n\thandle {\n\t}\n}":               2,
	} {
		got, ok := CaddyfileNestingDepth(src)
		if !ok || got != want {
			t.Errorf("%q: got %d ok=%v, want %d", src, got, ok, want)
		}
	}
	// Issue #184 round 10: only what Caddy's own lexer refuses is
	// reported; an unclosed quote at the end is a token for Caddy.
	if _, ok := CaddyfileNestingDepth("x.test {\n\trespond <<\n}"); ok {
		t.Errorf("text Caddy's lexer refuses must be reported")
	}
	if d, ok := CaddyfileNestingDepth("x.test {\n\thandle {\n\t\trespond \"open\n}"); !ok || d != 2 {
		t.Errorf("an unclosed quote at the end: got %d ok=%v, want 2 true", d, ok)
	}
}

// Issue #184 round 8 (3) and (4): placeholders are found per token and by
// exact key; snippet definitions also behind dropped address keys.
func TestCaddyfileImportUseRound8(t *testing.T) {
	for src, want := range map[string]bool{
		"x {\n\ta {args[0]}\n}":                              true,
		"x {\n\ta {args.2}\n}":                               true,
		"x {\n\ta {args[:]}\n}":                              true,
		"x {\n\ta \"{args[0]}\"\n}":                          true,
		"x {\n\t{block}\n}":                                  true,
		"x {\n\ta {blocks.k}\n}":                             true,
		"x {\n\ta {args.}\n}":                                false,
		"x {\n\ta {args[]}\n}":                               false,
		"x {\n\trewrite * /args.html\n}":                     false,
		"x {\n\ta {http.request.uri.query.args[0]}\n}":       false,
		"x {\n\ta \"function f(args){ return args[0] }\"\n}": false,
		"# {args[0]}\nx {\n\ta b\n}":                         false,
		"x {\n\ta </static/kwargs.css>\n}":                   false,
	} {
		use, ok := CaddyfileImportUse(src)
		if !ok || use.SnippetPlaceholder != want {
			t.Errorf("%q: SnippetPlaceholder=%v ok=%v, want %v", src, use.SnippetPlaceholder, ok, want)
		}
	}
	for src, want := range map[string]bool{
		"(s) {\n}":                         true,
		"\"\" (s) {\n}":                    true,
		", (s) {\n}":                       true,
		"\"\",\n(s) {\n}":                  true,
		"\"\" , \"\" (s) {\n}":             true,
		"a.test (s) {\n}":                  false,
		"a.test {\n\tp path_regexp (a)\n}": false,
		"a.test {\n}\n\"\" (s) {\n}":       true,
	} {
		use, ok := CaddyfileImportUse(src)
		if !ok || use.SnippetDefined != want {
			t.Errorf("%q: SnippetDefined=%v ok=%v, want %v", src, use.SnippetDefined, ok, want)
		}
	}
}

// Issue #184 round 8 (2): the export's site check and the adapt client
// refuse text nested deeper than MaxCaddyfileNestingDepth, for any owner;
// the client does so without calling Caddy.
func TestDeepNestingIsRefusedBeforeCaddy(t *testing.T) {
	if _, err := checkCaddyfileSites(round8Nested(MaxCaddyfileNestingDepth), nil); err != nil {
		t.Errorf("depth %d: %v", MaxCaddyfileNestingDepth, err)
	}
	if _, err := checkCaddyfileSites(round8Nested(MaxCaddyfileNestingDepth+1), nil); err == nil {
		t.Errorf("depth %d: want refused", MaxCaddyfileNestingDepth+1)
	}
	var calls atomic.Int64
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"result":{}}`)
	}))
	defer fake.Close()
	cl := New(fake.URL, "", "")
	if _, err := cl.Adapt(round8Nested(4000)); err == nil || !strings.Contains(err.Error(), "levels deep") {
		t.Errorf("depth 4000: want refused, got %v", err)
	}
	if calls.Load() != 0 {
		t.Errorf("depth 4000 reached the adapter")
	}
	if _, err := cl.Adapt(round8Nested(MaxCaddyfileNestingDepth)); err != nil || calls.Load() != 1 {
		t.Errorf("depth %d: want adapted, got %v (calls %d)", MaxCaddyfileNestingDepth, err, calls.Load())
	}
}

// Issue #184 round 8 (5): a tenant's redirect is exported with the host
// names its live route matches; one with a port is left out.
func TestTenantRedirectExportUsesLiveHostNames(t *testing.T) {
	names, ok := redirectLiveHosts([]string{"Dot.Example.test.", "dot.example.test", "https://sch.example.test"})
	if !ok || strings.Join(names, ",") != "dot.example.test,https" {
		t.Errorf("got %q ok=%v", names, ok)
	}
	for _, d := range []string{"p.example.test:8443", "http://a.example.test:8080", "[::1]:443"} {
		if _, ok := redirectLiveHosts([]string{d}); ok {
			t.Errorf("%q: want left out", d)
		}
	}
}
