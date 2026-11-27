// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Active health checks are requests Caddy sends on its own. A non-admin's
// reverse_proxy may not aim them, or redirect them, anywhere its upstreams
// could not go, nor make them write.

func healthRP(active map[string]any) map[string]any {
	return rp("203.0.113.5:80", map[string]any{"health_checks": map[string]any{"active": active}})
}

func TestTenantActiveHealthChecks(t *testing.T) {
	e := newSecEnv(t)
	bad := map[string]map[string]any{
		"health upstream at the admin API":  {"upstream": "127.0.0.1:2019", "uri": "/config/"},
		"health upstream at localhost":      {"upstream": "localhost:2019"},
		"health upstream placeholder":       {"upstream": "{http.request.header.X}:80"},
		"health upstream not a string":      {"upstream": 2019},
		"follow redirects":                  {"uri": "/", "follow_redirects": true},
		"POST":                              {"uri": "/load", "method": "POST"},
		"request body":                      {"uri": "/", "body": `{"apps":{}}`},
		"Host header at the admin API":      {"headers": map[string]any{"Host": []any{"127.0.0.1:2019"}}},
		"env placeholder in a header name":  {"headers": map[string]any{"{env.CF_API_TOKEN}": []any{"x"}}},
		"env placeholder in a header value": {"headers": map[string]any{"X-T": []any{"{env.CF_API_TOKEN}"}}},
	}
	for name, active := range bad {
		if why := e.s.tenantRouteViolation(route(healthRP(active))); why == "" {
			t.Errorf("%s: allowed", name)
		}
	}
	good := map[string]map[string]any{
		"uri and interval":   {"uri": "/healthz", "interval": "10s", "expect_status": 200},
		"port on upstream":   {"port": 8081, "uri": "/healthz"},
		"public upstream":    {"upstream": "203.0.113.6:8081"},
		"HEAD":               {"method": "HEAD"},
		"no follow":          {"follow_redirects": false},
		"plain header":       {"headers": map[string]any{"X-Probe": []any{"1"}}},
		"Host of the domain": {"headers": map[string]any{"Host": []any{"app.example.test"}}},
	}
	for name, active := range good {
		if why := e.s.tenantRouteViolation(route(healthRP(active))); why != "" {
			t.Errorf("%s: refused: %s", name, why)
		}
	}
	// Passive checks send nothing of their own.
	passive := rp("203.0.113.5:80", map[string]any{"health_checks": map[string]any{"passive": map[string]any{"max_fails": 3}}, "load_balancing": map[string]any{"retries": 2}})
	if why := e.s.tenantRouteViolation(route(passive)); why != "" {
		t.Errorf("passive checks refused: %s", why)
	}
}

// A placeholder in a map key — a header's field name, which Caddy expands
// — is held to the same rule as one in a value, and neutralised at sync.
func TestTenantPlaceholderInAHeaderName(t *testing.T) {
	e := newSecEnv(t)
	hdr := route(map[string]any{"handler": "headers", "response": map[string]any{"set": map[string]any{"{env.CF_API_TOKEN}": []any{"x"}}}})
	if why := e.s.tenantRouteViolation(hdr); why == "" {
		t.Error("a placeholder in a header name was allowed")
	}
	out, changed := neutraliseTenantPlaceholders(hdr)
	b, _ := json.Marshal(out)
	if !changed || strings.Contains(string(b), "{env.") {
		t.Errorf("not neutralised (changed=%v): %s", changed, b)
	}
}

const healthAdvancedAdapt = `{"result":{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":["localhost"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","health_checks":{"active":{"upstream":"127.0.0.1:2019","uri":"/load","method":"POST","body":"{}"}}}]}]}],"terminal":true}]}}}}}}`

func TestTenantProxyHostAdvancedHealthCheckIsRefused(t *testing.T) {
	e := newSecEnv(t)
	e.mu.Lock()
	e.adaptResponse = healthAdvancedAdapt
	e.mu.Unlock()
	form := url.Values{"domains": {"hc.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.5"}, "forward_port": {"8080"},
		"enabled": {"on"}, "advanced_config": {"reverse_proxy {\n\thealth_upstream 127.0.0.1:2019\n\thealth_uri /load\n\thealth_method POST\n\thealth_body {}\n}"}}
	rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", form)
	if rec.Code == http.StatusSeeOther {
		t.Fatalf("saved (redirect to %s)", rec.Header().Get("Location"))
	}
	if msg := formErrorToast(rec.Body.String()); !strings.Contains(msg, "health check") {
		t.Errorf("refused for another reason: %q", msg)
	}
	if p, _ := models.ListProxyHosts(e.db, 1, 0, true, nil); len(p) != 0 {
		t.Errorf("%d proxy host(s) stored", len(p))
	}
	// The administrator may.
	form.Set("domains", "hc2.example.test")
	if rec := e.do(t, "admin", http.MethodPost, "/proxy-hosts", form); rec.Code != http.StatusSeeOther {
		t.Errorf("admin: status %d", rec.Code)
	}
}

func TestTenantRawRouteHealthCheckIsRefusedAndNotDeployed(t *testing.T) {
	e := newSecEnv(t)
	b, _ := json.Marshal(route(healthRP(map[string]any{"upstream": "127.0.0.1:2019", "uri": "/config/"})))
	js := string(b)
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "hc", "json_data": js, "enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("API: status %d, want 400: %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "alice", http.MethodPost, "/raw-routes", url.Values{"label": {"hc"}, "json_data": {js}, "enabled": {"on"}})
	if rec.Code == http.StatusSeeOther {
		t.Error("form: accepted")
	}
	// A row stored by an older version is deployed without the health check.
	out, _ := json.Marshal(e.s.buildMergedRoutes(nil, nil, []models.RawRoute{{Label: "hc", JSONData: js, Enabled: true, OwnerID: ownerNull(e.ids["alice"])}}))
	if strings.Contains(string(out), "127.0.0.1:2019") {
		t.Errorf("deployed: %s", out)
	}
	// So is a proxy host whose stored Advanced config merges it in: the
	// sync builds the same merged route and the guard drops the check.
	p := models.ProxyHost{Domains: "hc.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.5", ForwardPort: 80, Enabled: true, OwnerID: ownerNull(e.ids["alice"])}
	r := buildProxyRouteWithOverrides(p, map[string]any{"health_checks": map[string]any{"active": map[string]any{"upstream": "127.0.0.1:2019"}}})
	safe, ok := e.s.sanitizeTenantRoute(p.OwnerID, "proxy host", r)
	if b, _ := json.Marshal(safe); !ok || strings.Contains(string(b), "127.0.0.1:2019") {
		t.Errorf("want the host deployed without the admin-API health check (ok=%v): %s", ok, b)
	}
}

func buildProxyRouteWithOverrides(p models.ProxyHost, overrides map[string]any) map[string]any {
	r := caddy.BuildProxyRoute(p, nil)
	caddy.MergeReverseProxyOverrides(r, overrides)
	return r
}

// formErrorToast is the text of a form page's error toast.
func formErrorToast(body string) string {
	i := strings.Index(body, `data-toast="error"`)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, ">"); j >= 0 {
		rest = rest[j+1:]
	}
	if k := strings.Index(rest, "</div>"); k >= 0 {
		rest = rest[:k]
	}
	return rest
}
