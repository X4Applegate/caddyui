// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

const sharingAdminCaddyfile = "(secrets) {\n\theader X-Upstream-Key \"s3cr3t-snippet-value\"\n}\n\n(shared) {\n\theader X-Shared 1\n}\n"

// unsetTenantSnippetsEnv makes sure CADDYFILE_TENANT_SNIPPETS is unset for
// the test, and restores it afterwards.
func unsetTenantSnippetsEnv(t *testing.T) {
	t.Helper()
	if v, ok := os.LookupEnv(envTenantSnippets); ok {
		t.Cleanup(func() { _ = os.Setenv(envTenantSnippets, v) })
		_ = os.Unsetenv(envTenantSnippets)
	}
}

func sharingEnv(t *testing.T) *secEnv {
	t.Helper()
	e := newSecEnv(t)
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte(sharingAdminCaddyfile), 0o600); err != nil {
		t.Fatal(err)
	}
	e.s.CaddyfilePath = path
	return e
}

func adaptRequestsHolding(e *secEnv, needle string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, rq := range e.reqs {
		if strings.Contains(rq, " /adapt") && strings.Contains(rq, needle) {
			n++
		}
	}
	return n
}

func TestTenantCannotImportAnUnsharedAdminSnippet(t *testing.T) {
	unsetTenantSnippetsEnv(t)
	e := sharingEnv(t)
	// A tenant row stored before this version imports `shared`: the seed
	// keeps that one available, and only that one.
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob", CaddyfileSrc: "bob.example.test {\n\timport shared\n}", JSONData: claimRoute("bob.example.test", "10.0.0.7:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	e.s.tenantSnippets = loadTenantSnippetPolicy(e.db, e.s.CaddyfilePath)
	if got := e.s.tenantSnippets.String(); got != "shared" {
		t.Fatalf("seeded policy %q, want %q", got, "shared")
	}

	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{
		"label": "x", "caddyfile_src": "x.example.test {\n\timport secrets\n\treverse_proxy 203.0.113.5:80\n}", "enabled": true,
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not available") {
		t.Errorf("import of an unshared snippet: status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Errorf("the snippet's content was returned: %s", rec.Body.String())
	}
	// The shared one still works, and the unshared one's text never goes
	// to Caddy for a non-admin.
	rec = e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{
		"label": "y", "caddyfile_src": "y.example.test {\n\timport shared\n\treverse_proxy 203.0.113.5:80\n}", "enabled": true,
	})
	if strings.Contains(rec.Body.String(), "not available") {
		t.Errorf("import of a shared snippet refused: %d %s", rec.Code, rec.Body.String())
	}
	if n := adaptRequestsHolding(e, "s3cr3t-snippet-value"); n != 0 {
		t.Errorf("%d adapt request(s) for a non-admin carried the unshared snippet", n)
	}
	// The administrator still has every snippet.
	e.mu.Lock()
	e.adaptResponse = `{"result":{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"host":["z.example.test"]}],"handle":[{"handler":"static_response"}]}]}}}}}}`
	e.mu.Unlock()
	rec = e.apiJSON(t, "admin", http.MethodPost, "/api/v1/raw-routes", map[string]any{
		"label": "z", "caddyfile_src": "z.example.test {\n\timport secrets\n\treverse_proxy 10.0.0.9:80\n}", "enabled": true,
	})
	if rec.Code != http.StatusCreated {
		t.Errorf("admin: status %d: %s", rec.Code, rec.Body.String())
	}
	if n := adaptRequestsHolding(e, "s3cr3t-snippet-value"); n == 0 {
		t.Error("the administrator's adapt did not carry the snippet")
	}
}

// Control for the test above: with every snippet shared (the behaviour up
// to v2.68.17), the snippet's text does go to Caddy for a non-admin.
func TestEverySnippetSharedSendsItForTenants(t *testing.T) {
	t.Setenv(envTenantSnippets, "*")
	e := sharingEnv(t)
	e.s.tenantSnippets = loadTenantSnippetPolicy(e.db, e.s.CaddyfilePath)
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{
		"label": "x", "caddyfile_src": "x.example.test {\n\timport secrets\n\treverse_proxy 203.0.113.5:80\n}", "enabled": true,
	})
	if n := adaptRequestsHolding(e, "s3cr3t-snippet-value"); n == 0 {
		t.Errorf("with %s=* the snippet was not sent (status %d: %s)", envTenantSnippets, rec.Code, rec.Body.String())
	}
}

func TestTenantSnippetPolicyLoading(t *testing.T) {
	unsetTenantSnippetsEnv(t)
	e := newSecEnv(t)
	_, _ = models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "a", CaddyfileSrc: "a.example.test {\n\timport one\n}", JSONData: "[]"})
	_, _ = models.CreateRawRoute(e.db, 1, e.ids["admin"], &models.RawRoute{Label: "b", CaddyfileSrc: "b.example.test {\n\timport adminonly\n}", JSONData: "[]"})
	_, _ = models.CreateRawRoute(e.db, 1, 0, &models.RawRoute{Label: "c", CaddyfileSrc: "c.example.test {\n\timport global\n}", JSONData: "[]"})
	if _, err := models.CreateProxyHost(e.db, 1, e.ids["bob"], &models.ProxyHost{Domains: "p.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, AdvancedConfig: "import two"}); err != nil {
		t.Fatal(err)
	}
	if got := loadTenantSnippetPolicy(e.db, e.s.CaddyfilePath).String(); got != "one,two" {
		t.Errorf("seed = %q, want one,two", got)
	}
	// Seeded once: a later tenant import does not widen it.
	_, _ = models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "d", CaddyfileSrc: "d.example.test {\n\timport three\n}", JSONData: "[]"})
	if got := loadTenantSnippetPolicy(e.db, e.s.CaddyfilePath).String(); got != "one,two" {
		t.Errorf("after reload = %q, want one,two", got)
	}
	for env, want := range map[string]string{"*": "*", "": "none", "none": "none", " a, b c ": "a,b,c"} {
		t.Setenv(envTenantSnippets, env)
		if got := loadTenantSnippetPolicy(e.db, e.s.CaddyfilePath).String(); got != want {
			t.Errorf("%s=%q: %q, want %q", envTenantSnippets, env, got, want)
		}
	}
	// The seed follows the server Caddyfile's own imports.
	_ = os.Unsetenv(envTenantSnippets)
	_ = models.DeleteSetting(e.db, settingTenantSnippetsShared)
	path := filepath.Join(t.TempDir(), "Caddyfile")
	_ = os.WriteFile(path, []byte("(one) {\n\timport inner\n}\n\n(inner) {\n\theader X 1\n}\n\n(other) {\n\theader Y 1\n}\n"), 0o600)
	if got := loadTenantSnippetPolicy(e.db, path).String(); got != "inner,one" {
		t.Errorf("seed with the server Caddyfile = %q, want inner,one (only names it defines, and what they import)", got)
	}
	// A Server built without New shares every snippet, as before.
	if !(tenantSnippetPolicy{}).shares("anything") {
		t.Error("the zero policy should share every snippet")
	}
}

func TestTenantMetricsHandlerIsRefused(t *testing.T) {
	e := newSecEnv(t)
	metrics := `{"match":[{"host":["m.example.test"]}],"handle":[{"handler":"metrics"}]}`
	if why := e.s.tenantRouteViolation(route(map[string]any{"handler": "metrics"})); !strings.Contains(why, "metrics") {
		t.Errorf("tenantRouteViolation = %q", why)
	}
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "m", "json_data": metrics, "enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("tenant: status %d, want 400: %s", rec.Code, rec.Body.String())
	}
	rec = e.apiJSON(t, "admin", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "m", "json_data": metrics, "enabled": true})
	if rec.Code != http.StatusCreated {
		t.Errorf("admin: status %d, want 201: %s", rec.Code, rec.Body.String())
	}
	// A stored tenant row with it is not deployed.
	out, _ := json.Marshal(e.s.buildMergedRoutes(nil, nil, []models.RawRoute{{Label: "m", JSONData: metrics, Enabled: true, OwnerID: ownerNull(e.ids["alice"])}}))
	if b := string(out); strings.Contains(b, `"metrics"`) {
		t.Errorf("a tenant's metrics route is deployed: %s", b)
	}
}
