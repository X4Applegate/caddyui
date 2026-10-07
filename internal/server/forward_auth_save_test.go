// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.59.5 (issues #124/#125): forward auth is now a real reverse_proxy to the
// auth service, so it is validated on save and held to the same upstream rules
// as every other upstream.

func TestValidateForwardAuthURL(t *testing.T) {
	for _, ok := range []string{"", "  ", "http://authentik:9000/outpost.goauthentik.io/auth/caddy", "https://auth.example.com", "http://10.0.0.7:9091/api/verify?x=1"} {
		if msg := validateForwardAuthURL(ok); msg != "" {
			t.Errorf("%q was refused: %s", ok, msg)
		}
	}
	for _, bad := range []string{"auth.example.com:9000", "/just/a/path", "ftp://auth/x", "http://", "not a url", "javascript:alert(1)"} {
		if msg := validateForwardAuthURL(bad); msg == "" {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestProxyHostFormRejectsAnUnusableForwardAuthURLAndKeepsNothing(t *testing.T) {
	e := newSecEnv(t)
	form := url.Values{"domains": {"fa.example.test"}, "forward_scheme": {"http"}, "forward_host": {"10.0.0.5"}, "forward_port": {"8080"}, "enabled": {"on"},
		"forward_auth_url": {"authentik:9000/outpost"}}
	rec := e.do(t, "admin", http.MethodPost, "/proxy-hosts", form)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("a forward auth URL without a scheme was accepted")
	}
	if hosts, _ := models.ListProxyHosts(e.db, 1, 0, true, nil); len(hosts) != 0 {
		t.Fatalf("%d host(s) stored", len(hosts))
	}
}

// The auth service is now an upstream the proxy dials, so a customer account
// must not be able to point it at an internal address (SSRF) — and a normal
// auth service is fine.
func TestNonAdminForwardAuthUpstreamIsHeldToTheUpstreamGuard(t *testing.T) {
	e := newSecEnv(t)
	n := 0
	form := func(authURL string) url.Values {
		n++
		return url.Values{"domains": {"fa" + strconv.Itoa(n) + ".example.test"}, "forward_scheme": {"http"}, "forward_host": {"10.0.0.5"}, "forward_port": {"8080"},
			"enabled": {"on"}, "forward_auth_url": {authURL}}
	}
	for _, bad := range []string{"http://169.254.169.254/latest", "http://127.0.0.1:2019/config/", "http://localhost:2019/load"} {
		if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", form(bad)); rec.Code == http.StatusSeeOther {
			t.Errorf("a non-admin pointed forward auth at %s", bad)
		}
	}
	if hosts, _ := models.ListProxyHosts(e.db, 1, 0, true, nil); len(hosts) != 0 {
		t.Fatalf("%d host(s) stored by refused requests", len(hosts))
	}
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", form("http://auth.example.test:9000/verify")); rec.Code != http.StatusSeeOther {
		t.Errorf("a normal forward auth URL was refused for a non-admin: %d", rec.Code)
	}
}
