// SPDX-License-Identifier: Apache-2.0

package models_test

import (
	"errors"
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #184 review: a Path matcher with control characters could break out
// of its Caddyfile token, and an invalid regexp is refused by Caddy anyway.
func TestPathMatcherProblem(t *testing.T) {
	for _, tc := range []struct {
		matcher, typ, want string
	}{
		{"", "", models.PathMatcherOK},
		{"/api", "", models.PathMatcherOK},
		{"/my docs", "exact", models.PathMatcherOK},
		{"^/backend/", "regexp", models.PathMatcherOK},
		{`^/a b{2}#"x`, "regexp", models.PathMatcherOK},
		{"/x`\\", "", models.PathMatcherOK}, // odd but harmless here; the exporter fails closed on it
		{"/x\n}\nevil.test {", "", models.PathMatcherHasControl},
		{"/x\r", "exact", models.PathMatcherHasControl},
		{"/x\t", "regexp", models.PathMatcherHasControl},
		{"/x\x00", "", models.PathMatcherHasControl},
		{"/x\x7f", "", models.PathMatcherHasControl},
		{"/x\u0085", "", models.PathMatcherHasControl},
		{"/x y", "", models.PathMatcherHasControl},
		{"/x y", "regexp", models.PathMatcherHasControl},
		{"/x\xff", "", models.PathMatcherBadEncoding},
		{"^/(unclosed", "regexp", models.PathMatcherBadRegexp},
		{"/x`\\", "regexp", models.PathMatcherBadRegexp}, // trailing backslash
		{"^/(unclosed", "", models.PathMatcherOK},        // only regexp type is compiled
	} {
		if got := models.PathMatcherProblem(tc.matcher, tc.typ); got != tc.want {
			t.Errorf("models.PathMatcherProblem(%q, %q) = %q, want %q", tc.matcher, tc.typ, got, tc.want)
		}
	}
}

// The storage layer refuses an invalid Path matcher on every entry path.
func TestCreateAndUpdateProxyHostRejectInvalidPathMatcher(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	sid, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	bad := &models.ProxyHost{Domains: "bad.example.test", ForwardHost: "203.0.113.10", ForwardPort: 80, PathMatcher: "/x\n}\nevil.example.test {", PathMatcherType: "regexp"}
	if _, err := models.CreateProxyHost(conn, sid, 0, bad); !errors.Is(err, models.ErrInvalidPathMatcher) {
		t.Fatalf("create with control characters: err = %v, want models.ErrInvalidPathMatcher", err)
	}
	ok := &models.ProxyHost{Domains: "ok.example.test", ForwardHost: "203.0.113.10", ForwardPort: 80, PathMatcher: "^/backend/", PathMatcherType: "regexp"}
	id, err := models.CreateProxyHost(conn, sid, 0, ok)
	if err != nil {
		t.Fatalf("valid regexp matcher: %v", err)
	}
	ok.ID = id
	ok.PathMatcher = "^/(unclosed"
	if err := models.UpdateProxyHost(conn, ok); !errors.Is(err, models.ErrInvalidPathMatcher) {
		t.Fatalf("update with invalid regexp: err = %v, want models.ErrInvalidPathMatcher", err)
	}
	got, err := models.GetProxyHost(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.PathMatcher != "^/backend/" {
		t.Fatalf("rejected update was stored: %q", got.PathMatcher)
	}
}
