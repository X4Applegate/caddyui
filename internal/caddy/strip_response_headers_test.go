// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// countResponseDeleteHandlers reports how many `headers` handlers in the route
// carry a response-side delete list, and the names they delete.
func countResponseDeleteHandlers(route map[string]any) (int, []string) {
	n := 0
	var names []string
	handle, _ := route["handle"].([]any)
	for _, h := range handle {
		m, ok := h.(map[string]any)
		if !ok || m["handler"] != "headers" {
			continue
		}
		resp, _ := m["response"].(map[string]any)
		// The two emitters built their delete lists with different static
		// types ([]any vs the []string from StripRespHeaderList), so accept
		// either rather than silently counting zero handlers.
		var got []string
		switch del := resp["delete"].(type) {
		case []any:
			for _, d := range del {
				if s, ok := d.(string); ok {
					got = append(got, s)
				}
			}
		case []string:
			got = append(got, del...)
		}
		if len(got) == 0 {
			continue
		}
		n++
		names = append(names, got...)
	}
	return n, names
}

// strip_response_headers (v2.9.168) and strip_resp_headers (v2.9.35) both
// emitted a deferred response-delete handler ahead of reverse_proxy. A host
// with both columns set therefore got two strip directives for one setting.
// strip_resp_headers is canonical, so exactly one handler must be emitted.
func TestStripResponseHeadersEmitsSingleHandler(t *testing.T) {
	p := baseHost()
	p.StripRespHeaders = "X-Powered-By, Server"
	route := BuildProxyRoute(p, nil)

	n, names := countResponseDeleteHandlers(route)
	if n != 1 {
		t.Fatalf("expected exactly 1 response-delete handler, got %d (names %v)", n, names)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"X-Powered-By", "Server"} {
		if !strings.Contains(joined, want) {
			t.Errorf("response-delete list %v missing %q", names, want)
		}
	}
}

// The legacy column is no longer read by the config builder. A value left there
// by an un-migrated row must not produce a second handler — the migration is
// what moves it, not a silent second code path.
func TestStripResponseHeadersLegacyColumnNotEmitted(t *testing.T) {
	p := baseHost()
	p.StripResponseHeaders = "X-Legacy-Only"
	route := BuildProxyRoute(p, nil)

	n, names := countResponseDeleteHandlers(route)
	if n != 0 {
		t.Fatalf("legacy strip_response_headers still emitted %d handler(s) (names %v); "+
			"the config builder must read only the canonical field", n, names)
	}
}

// With both set (an un-migrated row read by a new binary) there is still only
// one handler, built from the canonical field.
func TestStripResponseHeadersBothSetEmitsOneHandler(t *testing.T) {
	p := baseHost()
	p.StripRespHeaders = "Server"
	p.StripResponseHeaders = "X-Powered-By"
	route := BuildProxyRoute(p, nil)

	n, names := countResponseDeleteHandlers(route)
	if n != 1 {
		t.Fatalf("expected exactly 1 response-delete handler, got %d (names %v)", n, names)
	}
	if strings.Join(names, ",") != "Server" {
		t.Errorf("delete list = %v, want only the canonical [Server]", names)
	}
}

// Header names reaching the config must be canonicalised, which the v2.9.168
// path did not do. StripRespHeaderList applies http.CanonicalHeaderKey.
func TestStripResponseHeadersCanonicalisesNames(t *testing.T) {
	p := baseHost()
	p.StripRespHeaders = "x-powered-by, SERVER"
	route := BuildProxyRoute(p, nil)

	_, names := countResponseDeleteHandlers(route)
	got := strings.Join(names, ",")
	if want := "X-Powered-By,Server"; got != want {
		t.Errorf("delete list = %q, want canonicalised %q", got, want)
	}
}

// The SecurityHeaders bundle precedence used to be wired to the legacy column:
// a per-host strip of a bundle header stopped the bundle re-setting it. That
// behaviour must survive on the canonical field, or hosts that strip
// X-Frame-Options while the bundle is on get SAMEORIGIN back.
func TestSecurityHeadersBundleHonoursCanonicalPerHostStrip(t *testing.T) {
	p := baseHost()
	p.SecurityHeadersEnabled = true
	p.StripRespHeaders = "X-Frame-Options"
	route := BuildProxyRoute(p, nil)

	found := false
	for _, h := range route["handle"].([]any) {
		m, ok := h.(map[string]any)
		if !ok || m["handler"] != "headers" {
			continue
		}
		resp, _ := m["response"].(map[string]any)
		set, _ := resp["set"].(map[string]any)
		if _, ok := set["Strict-Transport-Security"]; !ok {
			continue
		}
		found = true
		if _, ok := set["X-Frame-Options"]; ok {
			t.Fatalf("bundle re-set X-Frame-Options despite canonical per-host strip: %v", set)
		}
	}
	if !found {
		t.Fatal("security headers bundle handler not emitted")
	}
}

// The same precedence must be case-insensitive: a user typing lowercase in the
// strip box still expects the bundle to stand down.
func TestSecurityHeadersBundleStripIsCaseInsensitive(t *testing.T) {
	p := baseHost()
	p.SecurityHeadersEnabled = true
	p.StripRespHeaders = "x-frame-options, referrer-policy"
	route := BuildProxyRoute(p, nil)

	for _, h := range route["handle"].([]any) {
		m, ok := h.(map[string]any)
		if !ok || m["handler"] != "headers" {
			continue
		}
		resp, _ := m["response"].(map[string]any)
		set, _ := resp["set"].(map[string]any)
		if _, ok := set["Strict-Transport-Security"]; !ok {
			continue
		}
		for _, name := range []string{"X-Frame-Options", "Referrer-Policy"} {
			if _, ok := set[name]; ok {
				t.Errorf("bundle re-set %s despite lowercase per-host strip", name)
			}
		}
	}
}

// The exporter is the reason strip_resp_headers is canonical: a value in the
// legacy column worked live and vanished from a Caddyfile export. After the
// consolidation every stored value reaches the export.
func TestStripResponseHeadersExportRoundTrip(t *testing.T) {
	p := baseHost()
	p.StripRespHeaders = models.MergeStripResponseHeaders("X-Powered-By", "Server")

	out := RenderProxyHostCaddyfile(p)
	for _, want := range []string{"header -X-Powered-By", "header -Server"} {
		if !strings.Contains(out, want) {
			t.Fatalf("exported Caddyfile missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "header -X-Powered-By"); n != 1 {
		t.Fatalf("header -X-Powered-By appears %d times, want 1:\n%s", n, out)
	}
}

func TestMergeStripResponseHeaders(t *testing.T) {
	cases := []struct {
		name      string
		canonical string
		legacy    string
		want      string
	}{
		{"both empty", "", "", ""},
		{"canonical only", "X-Powered-By, Server", "", "X-Powered-By, Server"},
		{"legacy only carries over", "", "X-Legacy", "X-Legacy"},
		{"identical values collapse", "Server", "Server", "Server"},
		{"different values merge", "Server", "X-Powered-By", "Server, X-Powered-By"},
		{"dedupe is case-insensitive", "X-Powered-By", "x-powered-by", "X-Powered-By"},
		{"canonical order wins, extras appended", "B, A", "C, A", "B, A, C"},
		{"blank entries dropped", "Server, , X-One", " , ", "Server, X-One"},
		{"whitespace trimmed", "  Server  ", "  X-One  ", "Server, X-One"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := models.MergeStripResponseHeaders(tc.canonical, tc.legacy); got != tc.want {
				t.Fatalf("MergeStripResponseHeaders(%q, %q) = %q, want %q",
					tc.canonical, tc.legacy, got, tc.want)
			}
		})
	}
}
