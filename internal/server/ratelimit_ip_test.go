// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// TestRateLimitClientIPNotSpoofable is the regression test for the v2.52.4
// login-limiter hardening: the rate-limit key must not be forgeable via
// client-supplied X-Forwarded-For / X-Real-IP headers from a directly
// connected (untrusted) peer, while still resolving the real client IP when
// the request genuinely arrives through a trusted reverse proxy.
func TestRateLimitClientIPNotSpoofable(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn}

	req := func(remoteAddr string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/login", nil)
		r.RemoteAddr = remoteAddr
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}

	t.Run("direct public attacker cannot forge the key via XFF", func(t *testing.T) {
		got := s.rateLimitClientIP(req("203.0.113.7:44321", map[string]string{
			"X-Forwarded-For": "10.0.0.1",
			"X-Real-Ip":       "127.0.0.1",
		}))
		if got != "203.0.113.7" {
			t.Fatalf("spoofable: expected peer IP 203.0.113.7, got %q", got)
		}
	})

	t.Run("attacker rotating XFF still maps to the same peer key", func(t *testing.T) {
		a := s.rateLimitClientIP(req("203.0.113.7:1", map[string]string{"X-Forwarded-For": "1.1.1.1"}))
		b := s.rateLimitClientIP(req("203.0.113.7:2", map[string]string{"X-Forwarded-For": "2.2.2.2"}))
		if a != b || a != "203.0.113.7" {
			t.Fatalf("rotation bypass: keys %q and %q should both be 203.0.113.7", a, b)
		}
	})

	t.Run("trusted loopback proxy: X-Real-IP wins", func(t *testing.T) {
		got := s.rateLimitClientIP(req("127.0.0.1:2019", map[string]string{
			"X-Real-Ip":       "198.51.100.42",
			"X-Forwarded-For": "198.51.100.42, 127.0.0.1",
		}))
		if got != "198.51.100.42" {
			t.Fatalf("trusted proxy: expected real client 198.51.100.42, got %q", got)
		}
	})

	t.Run("trusted proxy XFF uses right-most (proxy-appended) entry", func(t *testing.T) {
		// Client forges a leading entry; the closest trusted proxy appends the
		// real one on the right. We must take the right-most.
		got := s.rateLimitClientIP(req("10.8.0.1:5000", map[string]string{
			"X-Forwarded-For": "1.2.3.4, 198.51.100.9",
		}))
		if got != "198.51.100.9" {
			t.Fatalf("expected right-most XFF 198.51.100.9, got %q", got)
		}
	})

	t.Run("configured trusted_proxies overrides the private-peer default", func(t *testing.T) {
		if err := models.SetSetting(conn, settingTrustedProxies, "192.0.2.0/24"); err != nil {
			t.Fatal(err)
		}
		// A private peer that is NOT in the configured list is no longer trusted.
		got := s.rateLimitClientIP(req("10.8.0.1:5000", map[string]string{"X-Real-Ip": "9.9.9.9"}))
		if got != "10.8.0.1" {
			t.Fatalf("private peer should be untrusted once list is set, got %q", got)
		}
		// A peer inside the configured range is trusted.
		got = s.rateLimitClientIP(req("192.0.2.5:5000", map[string]string{"X-Real-Ip": "9.9.9.9"}))
		if got != "9.9.9.9" {
			t.Fatalf("configured proxy should be trusted, got %q", got)
		}
	})
}
