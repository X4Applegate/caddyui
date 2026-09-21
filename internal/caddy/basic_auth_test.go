// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// TestBuildProxyRouteEmitsBasicAuth is the regression test for issue #110:
// enabling per-host Basic Auth must emit Caddy's authentication/http_basic
// handler into the route JSON (previously it was stored but never rendered, so
// no login was ever enforced).
func TestBuildProxyRouteEmitsBasicAuth(t *testing.T) {
	const hash = "$2a$14$abcdefghijklmnopqrstuv0123456789ABCDEFGHIJKLMNOPQRSTU"

	find := func(route map[string]any) map[string]any {
		for _, h := range route["handle"].([]any) {
			m, ok := h.(map[string]any)
			if ok && m["handler"] == "authentication" {
				return m
			}
		}
		return nil
	}

	t.Run("enabled with a user emits http_basic before the proxy", func(t *testing.T) {
		p := baseHost()
		p.BasicAuthEnabled = true
		p.BasicAuthRealm = "Members Only"
		users, _ := json.Marshal([]models.BasicAuthUser{{Username: "alice", BcryptHash: hash}})
		p.BasicAuthUsers = string(users)

		route := BuildProxyRoute(p, nil)
		auth := find(route)
		if auth == nil {
			t.Fatal("no authentication handler emitted — basic auth is not enforced")
		}
		providers := auth["providers"].(map[string]any)
		hb, ok := providers["http_basic"].(map[string]any)
		if !ok {
			t.Fatal("http_basic provider missing")
		}
		if hb["realm"] != "Members Only" {
			t.Errorf("realm = %v, want %q", hb["realm"], "Members Only")
		}
		if alg, _ := hb["hash"].(map[string]any); alg["algorithm"] != "bcrypt" {
			t.Errorf("hash algorithm = %v, want bcrypt", alg["algorithm"])
		}
		accounts := hb["accounts"].([]any)
		if len(accounts) != 1 {
			t.Fatalf("accounts = %d, want 1", len(accounts))
		}
		acct := accounts[0].(map[string]any)
		if acct["username"] != "alice" || acct["password"] != hash {
			t.Errorf("account = %v, want alice/<bcrypt hash>", acct)
		}

		// The auth handler must precede the reverse_proxy in the chain.
		handlers := route["handle"].([]any)
		authIdx, proxyIdx := -1, -1
		for i, h := range handlers {
			if m, ok := h.(map[string]any); ok {
				switch m["handler"] {
				case "authentication":
					authIdx = i
				case "reverse_proxy":
					proxyIdx = i
				}
			}
		}
		if authIdx == -1 || proxyIdx == -1 || authIdx > proxyIdx {
			t.Fatalf("authentication (idx %d) must come before reverse_proxy (idx %d)", authIdx, proxyIdx)
		}
	})

	t.Run("enabled with no usable users emits nothing", func(t *testing.T) {
		p := baseHost()
		p.BasicAuthEnabled = true
		// A half-filled row (blank hash) must not create a broken credential.
		users, _ := json.Marshal([]models.BasicAuthUser{{Username: "bob", BcryptHash: ""}})
		p.BasicAuthUsers = string(users)
		if find(BuildProxyRoute(p, nil)) != nil {
			t.Fatal("authentication handler emitted with no valid accounts")
		}
	})

	t.Run("disabled emits nothing", func(t *testing.T) {
		p := baseHost()
		p.BasicAuthEnabled = false
		users, _ := json.Marshal([]models.BasicAuthUser{{Username: "alice", BcryptHash: hash}})
		p.BasicAuthUsers = string(users)
		if find(BuildProxyRoute(p, nil)) != nil {
			t.Fatal("authentication handler emitted while basic auth disabled")
		}
	})
}
