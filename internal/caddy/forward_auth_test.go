// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.59.5 (issues #124/#125): forward_auth is a Caddyfile directive, not a JSON
// handler module. CaddyUI emitted {"handler":"forward_auth"} and Caddy refused
// the config with "unknown module: http.handlers.forward_auth".

func faHost(url, copy, prefix, method, skip string) models.ProxyHost {
	return models.ProxyHost{
		Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true,
		ForwardAuthURL: url, ForwardAuthCopyHeaders: copy, ForwardAuthHeadersPrefix: prefix, ForwardAuthMethod: method, ForwardAuthSkipPaths: skip,
	}
}

func routeJSON(t *testing.T, p models.ProxyHost) string {
	t.Helper()
	b, err := json.Marshal(BuildProxyRoute(p, nil))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestForwardAuthNeverEmitsTheNonexistentHandlerModule(t *testing.T) {
	for _, p := range []models.ProxyHost{
		faHost("http://authentik:9000/outpost.goauthentik.io/auth/caddy", "X-Authentik-Username,X-Authentik-Groups", "", "", ""),
		faHost("https://auth.example.com/verify?mode=strict", "", "X-Auth-", "POST", "/health,/metrics"),
		faHost("not a url", "", "", "", ""),
	} {
		if strings.Contains(routeJSON(t, p), `"handler":"forward_auth"`) {
			t.Errorf("route for %q still uses the forward_auth handler, which Caddy does not have", p.ForwardAuthURL)
		}
	}
}

func TestForwardAuthIsTheDirectivesReverseProxyExpansion(t *testing.T) {
	h := buildForwardAuthHandler(faHost("http://authentik:9000/outpost.goauthentik.io/auth/caddy?x=1", "X-Authentik-Username", "", "", ""))
	b, _ := json.Marshal(h)
	got := string(b)
	for _, want := range []string{
		`"handler":"reverse_proxy"`,
		`"upstreams":[{"dial":"authentik:9000"}]`,
		`"rewrite":{"method":"GET","uri":"/outpost.goauthentik.io/auth/caddy?x=1"}`,
		`"X-Forwarded-Method":["{http.request.method}"]`,
		`"X-Forwarded-Uri":["{http.request.uri}"]`,
		`"status_code":[2]`,
		// the copied header is deleted from the client's request first (anti-spoofing) …
		`"request":{"delete":["X-Authentik-Username"]}`,
		// … then set from the auth response only when the auth service sent it
		`"set":{"X-Authentik-Username":["{http.reverse_proxy.header.X-Authentik-Username}"]}`,
		`{http.reverse_proxy.header.X-Authentik-Username}":[""]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("forward auth handler is missing %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"transport"`) {
		t.Errorf("a plain http auth service got a TLS transport: %s", got)
	}
}

func TestForwardAuthHTTPSMethodPrefixAndDefaults(t *testing.T) {
	https := buildForwardAuthHandler(faHost("https://auth.example.com", "Remote-User", "X-Auth-", "post", ""))
	b, _ := json.Marshal(https)
	got := string(b)
	for _, want := range []string{
		`"dial":"auth.example.com:443"`,
		`"transport":{"protocol":"http","tls":{}}`,
		`"method":"POST"`,
		`"uri":"/"`,
		// the prefix is applied to the header name placed on the upstream request
		`"request":{"delete":["X-Auth-Remote-User"]}`,
		`"set":{"X-Auth-Remote-User":["{http.reverse_proxy.header.Remote-User}"]}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s:\n%s", want, got)
		}
	}
	plain, _ := json.Marshal(buildForwardAuthHandler(faHost("http://auth.example.com/", "", "", "", "")))
	if !strings.Contains(string(plain), `"dial":"auth.example.com:80"`) || strings.Contains(string(plain), `"delete"`) {
		t.Errorf("default port or empty copy-headers wrong: %s", plain)
	}
}

// An unusable URL must fail CLOSED: a 503, never a host served without auth.
func TestForwardAuthWithAnUnusableURLFailsClosed(t *testing.T) {
	for _, bad := range []string{"not a url", "ftp://auth.example.com/x", "http://", "/just/a/path", "auth.example.com:9000"} {
		h := buildForwardAuthHandler(faHost(bad, "", "", "", ""))
		if h["handler"] != "static_response" || h["status_code"] != 503 {
			t.Errorf("%q -> %v, want a 503 static_response", bad, h)
		}
		route := routeJSON(t, faHost(bad, "", "", "", ""))
		if !strings.Contains(route, `"status_code":503`) || !strings.Contains(route, "reverse_proxy") {
			t.Errorf("%q: the 503 must come BEFORE the upstream proxy: %s", bad, route)
		}
		if strings.Index(route, `"status_code":503`) > strings.Index(route, `"upstreams":[{"dial":"10.0.0.5:80"}]`) {
			t.Errorf("%q: the guard handler is after the real upstream: %s", bad, route)
		}
	}
}

func TestForwardAuthSkipPathsStillWrapTheHandler(t *testing.T) {
	route := routeJSON(t, faHost("http://auth:9000/v", "", "", "", "/health,/metrics"))
	for _, want := range []string{`"handler":"subroute"`, `"not":[{"path":["/health*","/metrics*"]}]`, `"handle_response"`} {
		if !strings.Contains(route, want) {
			t.Errorf("skip-paths route missing %s:\n%s", want, route)
		}
	}
}
