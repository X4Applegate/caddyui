// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

// TestSafeAnalyticsReturn guards the open-redirect fix (CodeQL
// go/unvalidated-url-redirection): the user-supplied "return" value must only
// ever yield a same-origin /analytics/ path.
func TestSafeAnalyticsReturn(t *testing.T) {
	const host = "example.com"
	fallback := "/analytics/" + host

	cases := []struct {
		name string
		raw  string
		want string
	}{
		// Valid same-origin returns are preserved.
		{"empty falls back", "", fallback},
		{"host analytics page", "/analytics/example.com", "/analytics/example.com"},
		{"analytics root", "/analytics", "/analytics/"},
		{"drill-down with query", "/analytics/example.com?path=/foo&status=404", "/analytics/example.com?path=/foo&status=404"},

		// Open-redirect vectors must fall back.
		{"absolute url", "https://evil.com", fallback},
		{"scheme-relative", "//evil.com", fallback},
		{"javascript scheme", "javascript:alert(1)", fallback},
		{"traversal normalises off-origin", "/analytics/..//evil.com", fallback},
		{"traversal escapes analytics", "/analytics/../secret", fallback},
		{"not under analytics", "/login", fallback},
		{"backslash trick", "/\\evil.com", fallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeAnalyticsReturn(tc.raw, host); got != tc.want {
				t.Errorf("safeAnalyticsReturn(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
