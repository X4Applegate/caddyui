// SPDX-License-Identifier: Apache-2.0

package caddy

import "testing"

// Issue #121: a Caddyfile whose every site address is an explicit plain-HTTP
// address is an HTTP-only route; anything else is served over TLS by default.
func TestCaddyfileHTTPOnly(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"explicit http scheme", "http://127.0.0.1 {\n\trespond /health \"OK\" 200\n}", true},
		{"http with hostname", "http://health.example.com {\n\trespond \"ok\"\n}", true},
		{"uppercase scheme", "HTTP://Health.Example.com {\n\trespond \"ok\"\n}", true},
		{"port 80 only", ":80 {\n\trespond \"ok\"\n}", true},
		{"host and port 80", "example.com:80 {\n\trespond \"ok\"\n}", true},
		{"several http addresses", "http://a.example.com, http://b.example.com {\n\trespond \"ok\"\n}", true},
		{"several http site blocks", "http://a.example.com {\n\trespond \"a\"\n}\n\nhttp://b.example.com {\n\trespond \"b\"\n}", true},
		{"snippet and global options are ignored", "{\n\tadmin off\n}\n\n(common) {\n\theader X-A 1\n}\n\nhttp://a.example.com {\n\timport common\n}", true},
		{"comment mentioning https is ignored", "# was https://a.example.com\nhttp://a.example.com {\n\trespond \"ok\"\n}", true},

		{"bare hostname is served over TLS", "example.com {\n\trespond \"ok\"\n}", false},
		{"https scheme", "https://example.com {\n\trespond \"ok\"\n}", false},
		{"one http and one https address", "http://a.example.com, https://a.example.com {\n\trespond \"ok\"\n}", false},
		{"one http block and one default block", "http://a.example.com {\n\trespond \"a\"\n}\n\nb.example.com {\n\trespond \"b\"\n}", false},
		{"custom port is not plain http", ":8443 {\n\trespond \"ok\"\n}", false},
		{"port that merely ends in 80", ":8080 {\n\trespond \"ok\"\n}", false},
		{"no site block at all", "", false},
		{"only a snippet", "(common) {\n\theader X-A 1\n}", false},
		{"only global options", "{\n\tadmin off\n}", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CaddyfileHTTPOnly(c.src); got != c.want {
				t.Fatalf("CaddyfileHTTPOnly(%q) = %v, want %v", c.src, got, c.want)
			}
		})
	}
}
