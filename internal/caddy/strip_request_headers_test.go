// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// issue #167: the host form carried two "Strip request headers" inputs backed
// by two columns (strip_req_headers and the v2.9.250 strip_request_headers).
// Each one emitted its own headers handler, so filling both produced two
// strip-request-headers directives, and only strip_req_headers reached the
// Caddyfile exporter. strip_req_headers is now canonical and the legacy value
// is merged into it; the route must carry exactly one request-delete handler.

// requestDeleteHandlers returns the delete lists of every "headers" handler in
// the route that carries a request delete.
func requestDeleteHandlers(t *testing.T, route map[string]any) [][]string {
	t.Helper()
	var out [][]string
	handle, _ := route["handle"].([]any)
	for _, h := range handle {
		m, ok := h.(map[string]any)
		if !ok || m["handler"] != "headers" {
			continue
		}
		req, ok := m["request"].(map[string]any)
		if !ok {
			continue
		}
		del, ok := req["delete"].([]any)
		if !ok || len(del) == 0 {
			continue
		}
		names := make([]string, 0, len(del))
		for _, d := range del {
			s, _ := d.(string)
			names = append(names, s)
		}
		out = append(out, names)
	}
	return out
}

func TestStripRequestHeadersEmitsExactlyOneDirective(t *testing.T) {
	// Canonical field only.
	t.Run("canonical_only", func(t *testing.T) {
		p := baseHost()
		p.StripReqHeaders = "X-Internal-Token, Authorization"
		got := requestDeleteHandlers(t, BuildProxyRoute(p, nil))
		if len(got) != 1 {
			t.Fatalf("want exactly 1 request-delete handler, got %d: %v", len(got), got)
		}
		want := []string{"X-Internal-Token", "Authorization"}
		if strings.Join(got[0], ",") != strings.Join(want, ",") {
			t.Fatalf("delete list = %v, want %v", got[0], want)
		}
	})

	// Legacy field only: a host whose value was migrated into the canonical
	// column must still strip, through the single canonical handler.
	t.Run("legacy_value_migrated_into_canonical", func(t *testing.T) {
		p := baseHost()
		p.StripReqHeaders = models.MergeStripRequestHeaders("", "X-Legacy-Only")
		got := requestDeleteHandlers(t, BuildProxyRoute(p, nil))
		if len(got) != 1 {
			t.Fatalf("want exactly 1 request-delete handler, got %d: %v", len(got), got)
		}
		if strings.Join(got[0], ",") != "X-Legacy-Only" {
			t.Fatalf("delete list = %v, want [X-Legacy-Only]", got[0])
		}
	})

	// Both filled: the merged canonical value must dedupe and still produce a
	// single handler, not one per column.
	t.Run("both_filled_merges_to_one_handler", func(t *testing.T) {
		p := baseHost()
		p.StripReqHeaders = models.MergeStripRequestHeaders("X-One, Authorization", "authorization, X-Two")
		got := requestDeleteHandlers(t, BuildProxyRoute(p, nil))
		if len(got) != 1 {
			t.Fatalf("want exactly 1 request-delete handler, got %d: %v", len(got), got)
		}
		want := "X-One,Authorization,X-Two"
		if strings.Join(got[0], ",") != want {
			t.Fatalf("delete list = %v, want %s", got[0], want)
		}
	})

	// The legacy column must no longer emit a directive of its own, even if a
	// stale value survives in memory on a host that was not migrated.
	t.Run("legacy_field_alone_emits_nothing", func(t *testing.T) {
		p := baseHost()
		p.StripRequestHeaders = "X-Should-Not-Appear"
		for _, del := range requestDeleteHandlers(t, BuildProxyRoute(p, nil)) {
			for _, name := range del {
				if name == "X-Should-Not-Appear" {
					t.Fatalf("legacy strip_request_headers still emitted a directive: %v", del)
				}
			}
		}
	})
}

// The Caddyfile exporter only ever knew about strip_req_headers. With the
// legacy value merged into it, an exported Caddyfile must round-trip the
// header names a user typed into either box.
func TestStripRequestHeadersExportRoundTrip(t *testing.T) {
	p := baseHost()
	p.StripReqHeaders = models.MergeStripRequestHeaders("X-One", "X-Two")

	out := RenderProxyHostCaddyfile(p)
	for _, want := range []string{"header_up -X-One", "header_up -X-Two"} {
		if !strings.Contains(out, want) {
			t.Fatalf("exported Caddyfile missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "header_up -X-One"); n != 1 {
		t.Fatalf("header_up -X-One appears %d times, want 1:\n%s", n, out)
	}
}

func TestMergeStripRequestHeaders(t *testing.T) {
	cases := []struct {
		name      string
		canonical string
		legacy    string
		want      string
	}{
		{"both empty", "", "", ""},
		{"canonical only", "X-One, X-Two", "", "X-One, X-Two"},
		{"legacy only carries over", "", "X-Legacy", "X-Legacy"},
		{"identical values collapse", "X-One", "X-One", "X-One"},
		{"different values merge", "X-One", "X-Two", "X-One, X-Two"},
		{"dedupe is case-insensitive", "Authorization", "authorization", "Authorization"},
		{"canonical order wins, extras appended", "B, A", "C, A", "B, A, C"},
		{"blank entries dropped", "X-One, , X-Two", " , ", "X-One, X-Two"},
		{"whitespace trimmed", "  X-One  ", "  X-Two  ", "X-One, X-Two"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := models.MergeStripRequestHeaders(tc.canonical, tc.legacy); got != tc.want {
				t.Fatalf("MergeStripRequestHeaders(%q, %q) = %q, want %q",
					tc.canonical, tc.legacy, got, tc.want)
			}
		})
	}
}
