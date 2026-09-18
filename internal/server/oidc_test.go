// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

func TestOIDCConfigReady(t *testing.T) {
	full := oidcConfig{
		Enabled: true, Issuer: "https://sso.example.com", ClientID: "cid",
		ClientSecret: "secret", RedirectURL: "https://caddyui.example.com/auth/oidc/callback",
	}
	if !full.ready() {
		t.Fatal("fully-configured OIDC should be ready")
	}
	// Each missing required field makes it not ready.
	cases := map[string]func(c *oidcConfig){
		"disabled":    func(c *oidcConfig) { c.Enabled = false },
		"no issuer":   func(c *oidcConfig) { c.Issuer = "" },
		"no clientID": func(c *oidcConfig) { c.ClientID = "" },
		"no secret":   func(c *oidcConfig) { c.ClientSecret = "" },
		"no redirect": func(c *oidcConfig) { c.RedirectURL = "" },
	}
	for name, mut := range cases {
		c := full
		mut(&c)
		if c.ready() {
			t.Fatalf("%s: expected not ready", name)
		}
	}
}

func TestOIDCRandomIsDistinctURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		v := oidcRandom()
		if v == "" || seen[v] {
			t.Fatalf("oidcRandom collision or empty: %q", v)
		}
		if strings.ContainsAny(v, "+/=") {
			t.Fatalf("oidcRandom not URL-safe: %q", v)
		}
		seen[v] = true
	}
}
