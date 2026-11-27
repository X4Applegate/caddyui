// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Findings of the independent reviews of the tenant-security series.

// Health-check settings built by CaddyUI itself (typed header maps) are
// read like any other route, and settings a non-admin can no longer save
// are left out at sync rather than taking the host offline.
func TestTenantProxyHostHealthCheckFieldsStillDeploy(t *testing.T) {
	e := newSecEnv(t)
	base := func() models.ProxyHost {
		return models.ProxyHost{Domains: "hc.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.5", ForwardPort: 80,
			Enabled: true, OwnerID: ownerNull(e.ids["alice"]), HealthCheckURI: "/health"}
	}
	fields := map[string]func(*models.ProxyHost){
		"headers":      func(p *models.ProxyHost) { p.HealthCheckHeaders = `{"X-Probe":"1"}` },
		"content type": func(p *models.ProxyHost) { p.HealthCheckContentType = "application/json" },
		"user agent":   func(p *models.ProxyHost) { p.HealthCheckUserAgent = "probe/1" },
		"basic auth":   func(p *models.ProxyHost) { p.HealthCheckBasicAuth = "u:p" },
		"host":         func(p *models.ProxyHost) { p.HealthCheckHostOverride = "app.example.test" },
	}
	for name, set := range fields {
		p := base()
		set(&p)
		if msg := e.s.validateTenantRoute(caddy.BuildProxyRoute(p, nil)); msg != "" {
			t.Errorf("%s: refused at save: %s", name, msg)
		}
		if routes := e.s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil); len(routes) != 1 {
			t.Errorf("%s: not deployed", name)
		}
	}
	// Stored with settings a non-admin may no longer save: still deployed,
	// without them.
	p := base()
	p.HealthCheckMethod, p.HealthCheckBody, p.HealthCheckFollowRedirects = "POST", "{}", true
	if msg := e.s.validateTenantRoute(caddy.BuildProxyRoute(p, nil)); msg == "" {
		t.Error("POST/body/follow-redirects health check accepted at save")
	}
	routes := e.s.buildMergedRoutes([]models.ProxyHost{p}, nil, nil)
	b, _ := json.Marshal(routes)
	if len(routes) != 1 || strings.Contains(string(b), `"POST"`) || strings.Contains(string(b), "follow_redirects") || strings.Contains(string(b), `"body"`) {
		t.Errorf("want the host deployed without the refused settings: %s", b)
	}
	if !strings.Contains(string(b), "/health") {
		t.Errorf("the rest of the health check was dropped: %s", b)
	}
	// A refused health-check upstream drops the active check, not the host.
	raw := route(healthRP(map[string]any{"upstream": "127.0.0.1:2019", "uri": "/x"}))
	out, ok := e.s.sanitizeTenantRoute(ownerNull(e.ids["alice"]), "r", raw)
	ob, _ := json.Marshal(out)
	if !ok || strings.Contains(string(ob), "2019") || !strings.Contains(string(ob), "203.0.113.5") {
		t.Errorf("sanitised route %v: %s", ok, ob)
	}
}

func TestTenantHealthCheckHeaderNamesAndHostChanges(t *testing.T) {
	e := newSecEnv(t)
	for name, r := range map[string]map[string]any{
		"placeholder in a health check header name": route(healthRP(map[string]any{"headers": map[string]any{"Ho{x}st": []any{"127.0.0.1:2019"}}})),
		"add Host":     route(rp("203.0.113.5:80", map[string]any{"headers": map[string]any{"request": map[string]any{"add": map[string]any{"Host": []any{"127.0.0.1:2019"}}}}})),
		"replace Host": route(rp("203.0.113.5:80", map[string]any{"headers": map[string]any{"request": map[string]any{"replace": map[string]any{"Host": []any{map[string]any{"search": "a", "replace": "127.0.0.1:2019"}}}}}})),
		"set {x}Host":  route(rp("203.0.113.5:80", map[string]any{"headers": map[string]any{"request": map[string]any{"set": map[string]any{"{x}Host": []any{"127.0.0.1:2019"}}}}})),
	} {
		if why := e.s.tenantRouteViolation(r); why == "" {
			t.Errorf("%s: allowed", name)
		}
	}
}

func TestTenantWAFHandlerOnlyFromAProfile(t *testing.T) {
	e := newSecEnv(t)
	js := `{"match":[{"host":["w.example.test"]}],"handle":[{"handler":"waf","directives":"Include /proc/self/environ"}]}`
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "w", "json_data": js, "enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("tenant waf: status %d: %s", rec.Code, rec.Body.String())
	}
	if e.adaptOrLoadCarries("/proc/self/environ") {
		t.Error("the WAF directives reached Caddy")
	}
	// The handler a middleware profile builds is allowed.
	id, err := models.CreateMiddlewareProfile(e.db, &models.MiddlewareProfile{Name: "waf", WAFMode: models.WAFModeBlock, WAFParanoia: 1})
	if err != nil {
		t.Fatal(err)
	}
	prof, _ := models.GetMiddlewareProfile(e.db, id)
	var p models.ProxyHost
	applyProfileToHost(&p, prof)
	if p.WAF == nil {
		t.Fatal("the profile builds no WAF")
	}
	if why := e.s.tenantRouteViolation(route(caddy.BuildWAFHandler(p.WAF))); why != "" {
		t.Errorf("a profile's WAF handler was refused: %s", why)
	}
}

func (e *secEnv) adaptOrLoadCarries(needle string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rq := range e.reqs {
		if strings.Contains(rq, needle) {
			return true
		}
	}
	return false
}

func TestTenantListenAddresses(t *testing.T) {
	reserved := map[int]bool{80: true, 443: true, 2019: true}
	for _, a := range []string{"0.0.0.0:79-81", "0.0.0.0:0443", ":0443", "127.0.0.1:2019", ":2019", "unix//run/x.sock", "fd/3",
		"tcp/:1-65535", ":442-444", ":444", ":8080-8100", "udp/:9000", "[::1]:9000", ":", ":x"} {
		if why := tenantListenProblem([]string{a}, reserved); why == "" {
			t.Errorf("%q: allowed", a)
		}
	}
	for _, a := range []string{":8080", "tcp/:9000", ":7070-7085"} {
		if why := tenantListenProblem([]string{a}, reserved); why != "" {
			t.Errorf("%q: refused: %s", a, why)
		}
	}
	e := newSecEnv(t)
	for _, listen := range []string{"0.0.0.0:79-81", "127.0.0.1:2019", ":444"} {
		rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "l", "json_data": claimRoute("", "203.0.113.9:80"), "listen": listen, "enabled": true})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("listen %q: status %d: %s", listen, rec.Code, rec.Body.String())
		}
	}
	// A stored row is not deployed.
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "old", JSONData: claimRoute("", "203.0.113.9:80"), Listen: `["0.0.0.0:442-444"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, _, raws, _, _ := e.s.serverResources(1)
	if _, _, kept := e.s.withoutForeignHostClaims(0, nil, nil, raws); len(kept) != 0 {
		t.Errorf("a stored row listening on 0.0.0.0:442-444 is deployed")
	}
	// The administrator is not limited.
	rec := e.apiJSON(t, "admin", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "a", "json_data": claimRoute("", "10.0.0.9:80"), "listen": "127.0.0.1:9443", "enabled": true})
	if rec.Code != http.StatusCreated {
		t.Errorf("admin: %d %s", rec.Code, rec.Body.String())
	}
}

func TestListenSharingBothWaysAndPartialOverlap(t *testing.T) {
	e := newSecEnv(t)
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob", JSONData: claimRoute("", "10.0.0.7:80"), Listen: `[":7070"]`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]map[string]any{
		"host route on another account's host-less port": {"label": "a", "json_data": claimRoute("alice.example.test", "203.0.113.9:80"), "listen": ":7070", "enabled": true},
		"partial overlap": {"label": "b", "json_data": claimRoute("alice.example.test", "203.0.113.9:80"), "listen": ":7069-7071", "enabled": true},
	} {
		if rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d: %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestTenantProxyHostAndRedirectHonourHostClaims(t *testing.T) {
	e := claimEnv(t) // admin raw route adminraw.example.test, bob's raw route bob.example.test
	proxy := func(domain string) url.Values {
		return url.Values{"domains": {domain}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.9"}, "forward_port": {"80"}, "enabled": {"on"}}
	}
	for _, d := range []string{"adminraw.example.test", "bob.example.test", "ADMINRAW.example.test."} {
		if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", proxy(d)); rec.Code == http.StatusSeeOther {
			t.Errorf("proxy form: %s accepted", d)
		}
		rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/redirection-hosts", map[string]any{"domains": d, "forward_scheme": "https", "forward_domain": "example.org", "forward_http_code": 301, "enabled": true})
		if rec.Code < 400 {
			t.Errorf("redirect API: %s accepted (%d)", d, rec.Code)
		}
	}
	// Trailing dot of an existing redirect's name.
	if _, err := models.CreateRedirectionHost(e.db, 1, 0, &models.RedirectionHost{Domains: "go.example.test", ForwardScheme: "https", ForwardDomain: "example.org", ForwardHTTPCode: 301, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/redirection-hosts", map[string]any{"domains": "go.example.test.", "forward_scheme": "https", "forward_domain": "example.org", "forward_http_code": 301, "enabled": true}); rec.Code < 400 {
		t.Errorf("trailing-dot duplicate accepted (%d)", rec.Code)
	}
	// Stored by an older version: not deployed while an administrator's
	// Advanced route names the host.
	p := models.ProxyHost{ID: 999, Domains: "adminraw.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.9", ForwardPort: 80, Enabled: true, OwnerID: ownerNull(e.ids["alice"])}
	_, _, raws, _, _ := e.s.serverResources(1)
	if kept, _, _ := e.s.withoutForeignHostClaims(0, []models.ProxyHost{p}, nil, raws); len(kept) != 0 {
		t.Error("a tenant proxy host over an administrator's Advanced route is deployed")
	}
	// alice's own fresh host still works.
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", proxy("alice-fresh.example.test")); rec.Code != http.StatusSeeOther {
		t.Errorf("own host refused: %d %s", rec.Code, formErrorToast(rec.Body.String()))
	}
}

func TestWildcardClaims(t *testing.T) {
	e := newSecEnv(t)
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob", JSONData: claimRoute("*.bobcorp.example.test", "10.0.0.7:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob2", JSONData: claimRoute("shop.bobshop.example.test", "10.0.0.7:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"login.bobcorp.example.test", "*.bobshop.example.test", "*.com", "*.test"} {
		rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": host, "json_data": claimRoute(host, "203.0.113.9:80"), "enabled": true})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d: %s", host, rec.Code, rec.Body.String())
		}
	}
	// Two labels below the wildcard are not covered by it.
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "deep", "json_data": claimRoute("a.login.bobcorp.example.test", "203.0.113.9:80"), "enabled": true})
	if rec.Code != http.StatusCreated {
		t.Errorf("deep name: %d %s", rec.Code, rec.Body.String())
	}
}

func TestReclassifyKeepsTheClaimRules(t *testing.T) {
	e := claimEnv(t)
	// A simple proxy-shaped route of alice's on the admin's host, stored by
	// an older version.
	id, err := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "x", JSONData: `{"match":[{"host":["adminraw.example.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"203.0.113.9:80"}]}],"terminal":true}`, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	e.do(t, "alice", http.MethodPost, "/raw-routes/reclassify", url.Values{})
	if rr, _ := models.GetRawRoute(e.db, id); rr == nil {
		t.Error("the route was turned into a proxy host over the administrator's host")
	}
	if p, _ := models.ListProxyHosts(e.db, 1, 0, true, nil); len(p) != 1 {
		t.Errorf("%d proxy hosts, want only the administrator's", len(p))
	}
}

func TestTenantPreviewErrorsAreReduced(t *testing.T) {
	e := newSecEnv(t)
	alice, _ := models.GetUserByID(e.db, e.ids["alice"])
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), auth.ContextUserKey, alice))
	msg := `Caddy rejected the proposed config: loading module: unknown directive "SECRET=hunter2\x00HOME=/root" (github.com/corazawaf/coraza/v3/internal/seclang/parser.go:91)` + "\nsecond line"
	got := e.s.previewMessageFor(r, msg)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "parser.go") || strings.Contains(got, "second line") {
		t.Errorf("tenant sees %q", got)
	}
}

func TestAdaptConnectionErrorsAreSanitised(t *testing.T) {
	e := newSecEnv(t)
	cl := e.s.tenantAdaptClient(caddy.New("http://127.0.0.1:1", "", ""))
	_, err := cl.Adapt("x.example.test {\n\trespond 1\n}\n")
	if err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("tenant error: %v", err)
	}
}

func TestTenantPasteNeverPushesSubjectOnlyPolicies(t *testing.T) {
	adapt := `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["paste.example.test"]}],"handle":[{"handler":"static_response","body":"x"}],"terminal":true}]}}},"tls":{"automation":{"policies":[{"subjects":["paste.example.test"]}]}}}}}`
	src := "paste.example.test {\n\trespond x\n}"
	pushed := func(who string) bool {
		e := newSecEnv(t)
		e.adaptResponse = adapt
		e.do(t, who, http.MethodPost, "/caddyfile-import", url.Values{"caddyfile": {src}, "auto_classify": {"off"}})
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, rq := range e.reqs {
			if strings.Contains(rq, "/config/apps/tls/automation") && strings.Contains(rq, "paste.example.test") {
				return true
			}
		}
		return false
	}
	if pushed("alice") {
		t.Error("a non-admin's paste pushed a TLS policy")
	}
	if !pushed("admin") {
		t.Error("control: the administrator's paste did not push it")
	}
}

// The sync-time claim filter must stay cheap on a busy server: one read of
// the users table, and only rows sharing a name are compared.
func TestClaimFilterScales(t *testing.T) {
	e := newSecEnv(t)
	var raws []models.RawRoute
	owners := []int64{e.ids["alice"], e.ids["bob"]}
	for i := 0; i < 600; i++ {
		raws = append(raws, models.RawRoute{ID: int64(i + 1), Label: "r", JSONData: claimRoute(fmt.Sprintf("h%d.example.test", i), "203.0.113.9:80"), Enabled: true, OwnerID: ownerNull(owners[i%2])})
	}
	start := time.Now()
	_, _, kept := e.s.withoutForeignHostClaims(0, nil, nil, raws)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("600 routes took %v", d)
	}
	if len(kept) != 600 {
		t.Errorf("kept %d of 600", len(kept))
	}
}
