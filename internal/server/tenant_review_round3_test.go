// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Findings of the second round of independent reviews.

// bobRawEnv: bob's Advanced route on app.bob.test, an administrator's
// wildcard proxy host *.admin.test.
func bobRawEnv(t *testing.T) *secEnv {
	t.Helper()
	e := newSecEnv(t)
	if _, err := models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob", JSONData: claimRoute("app.bob.test", "10.0.0.7:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(e.db, 1, 0, &models.ProxyHost{Domains: "*.admin.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *secEnv) uploadProxyHost(t *testing.T, who string, ph map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("config_file", "host.json")
	_ = json.NewEncoder(fw).Encode(ph)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/proxy-hosts/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	e.attachSession(req, who)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// Every path that creates or enables a non-admin's proxy host or redirect
// refuses another account's name.
func TestEverySavePathHonoursHostClaims(t *testing.T) {
	refused := func(t *testing.T, e *secEnv, what string, rec *httptest.ResponseRecorder) {
		t.Helper()
		body := rec.Body.String()
		accepted := rec.Code == http.StatusSeeOther || rec.Code == http.StatusCreated ||
			(rec.Code == http.StatusOK && formErrorToast(body) == "" && !strings.Contains(body, `"error"`))
		if accepted {
			t.Errorf("%s: accepted (%d %s)", what, rec.Code, rec.Header().Get("Location"))
		}
	}
	proxyForm := func(d string) url.Values {
		return url.Values{"domains": {d}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.9"}, "forward_port": {"80"}, "enabled": {"on"}}
	}
	redirForm := func(d string) url.Values {
		return url.Values{"domains": {d}, "forward_scheme": {"https"}, "forward_domain": {"example.org"}, "forward_http_code": {"301"}, "enabled": {"on"}}
	}
	for _, name := range []string{"app.bob.test", "pay.admin.test", "*.bob.test", "*.test"} {
		t.Run(name, func(t *testing.T) {
			e := bobRawEnv(t)
			before := func() int {
				p, _ := models.ListProxyHosts(e.db, 1, 0, true, nil)
				rd, _ := models.ListRedirectionHosts(e.db, 1, 0, true, nil)
				return len(p) + len(rd)
			}
			n0 := before()
			refused(t, e, "proxy form create", e.do(t, "alice", http.MethodPost, "/proxy-hosts", proxyForm(name)))
			refused(t, e, "redirect form create", e.do(t, "alice", http.MethodPost, "/redirection-hosts", redirForm(name)))
			refused(t, e, "proxy API create", e.apiJSON(t, "alice", http.MethodPost, "/api/v1/proxy-hosts", map[string]any{"domains": name, "forward_scheme": "http", "forward_host": "203.0.113.9", "forward_port": 80, "enabled": true}))
			refused(t, e, "JSON upload", e.uploadProxyHost(t, "alice", map[string]any{"Domains": name, "ForwardScheme": "http", "ForwardHost": "203.0.113.9", "ForwardPort": 80}))
			if n := before(); n != n0 {
				t.Errorf("%d row(s) stored", n-n0)
			}

			// Updates and enabling of alice's existing rows.
			pid, _ := models.CreateProxyHost(e.db, 1, e.ids["alice"], &models.ProxyHost{Domains: "own.alice.test", ForwardScheme: "http", ForwardHost: "203.0.113.9", ForwardPort: 80, Enabled: true})
			rid, _ := models.CreateRedirectionHost(e.db, 1, e.ids["alice"], &models.RedirectionHost{Domains: "r.alice.test", ForwardScheme: "https", ForwardDomain: "example.org", ForwardHTTPCode: 301, Enabled: true})
			refused(t, e, "proxy form update", e.do(t, "alice", http.MethodPost, "/proxy-hosts/"+strconv.FormatInt(pid, 10), proxyForm(name)))
			refused(t, e, "redirect form update", e.do(t, "alice", http.MethodPost, "/redirection-hosts/"+strconv.FormatInt(rid, 10), redirForm(name)))
			refused(t, e, "proxy API update", e.apiJSON(t, "alice", http.MethodPut, "/api/v1/proxy-hosts/"+strconv.FormatInt(pid, 10), map[string]any{"domains": name}))
			refused(t, e, "redirect API update", e.apiJSON(t, "alice", http.MethodPut, "/api/v1/redirection-hosts/"+strconv.FormatInt(rid, 10), map[string]any{"domains": name, "enabled": true}))
			if p, _ := models.GetProxyHost(e.db, pid); p.Domains != "own.alice.test" {
				t.Errorf("proxy host renamed to %q", p.Domains)
			}

			// Disabled rows stored by an older version (or the upload path
			// before this fix) are not enabled. (An existing name under an
			// administrator's wildcard is not refused by the sync either, so
			// it may be enabled: TestExistingRowUnderAdminWildcardStaysEditable.)
			if name == "pay.admin.test" {
				return
			}
			dp, _ := models.CreateProxyHost(e.db, 1, e.ids["alice"], &models.ProxyHost{Domains: name, ForwardScheme: "http", ForwardHost: "203.0.113.9", ForwardPort: 80})
			refused(t, e, "proxy form toggle", e.do(t, "alice", http.MethodPost, "/proxy-hosts/"+strconv.FormatInt(dp, 10)+"/toggle", url.Values{}))
			refused(t, e, "proxy API toggle", e.apiJSON(t, "alice", http.MethodPost, "/api/v1/proxy-hosts/"+strconv.FormatInt(dp, 10)+"/toggle", nil))
			e.do(t, "alice", http.MethodPost, "/proxy-hosts/bulk-toggle", url.Values{"ids[]": {strconv.FormatInt(dp, 10)}, "action": {"enable"}})
			if p, _ := models.GetProxyHost(e.db, dp); p.Enabled {
				t.Error("a disabled proxy host on another account's name was enabled")
			}
			dr, _ := models.CreateRedirectionHost(e.db, 1, e.ids["alice"], &models.RedirectionHost{Domains: name, ForwardScheme: "https", ForwardDomain: "example.org", ForwardHTTPCode: 301})
			refused(t, e, "redirect form toggle", e.do(t, "alice", http.MethodPost, "/redirection-hosts/"+strconv.FormatInt(dr, 10)+"/toggle", url.Values{}))
			refused(t, e, "redirect API toggle", e.apiJSON(t, "alice", http.MethodPost, "/api/v1/redirection-hosts/"+strconv.FormatInt(dr, 10)+"/toggle", nil))
			if rd, _ := models.GetRedirectionHost(e.db, dr); rd.Enabled {
				t.Error("a disabled redirect on another account's name was enabled")
			}
		})
	}
}

// A non-admin's existing row under an administrator's wildcard stays
// editable (the sync keeps serving it); a new one there is refused.
func TestExistingRowUnderAdminWildcardStaysEditable(t *testing.T) {
	e := bobRawEnv(t)
	pid, _ := models.CreateProxyHost(e.db, 1, e.ids["alice"], &models.ProxyHost{Domains: "shop.admin.test", ForwardScheme: "http", ForwardHost: "203.0.113.9", ForwardPort: 80, Enabled: true})
	rec := e.apiJSON(t, "alice", http.MethodPut, "/api/v1/proxy-hosts/"+strconv.FormatInt(pid, 10), map[string]any{"forward_port": 8080})
	if rec.Code != http.StatusOK {
		t.Errorf("edit of a field other than the domain: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.apiJSON(t, "alice", http.MethodPost, "/api/v1/proxy-hosts/"+strconv.FormatInt(pid, 10)+"/toggle", nil)
	rec = e.apiJSON(t, "alice", http.MethodPost, "/api/v1/proxy-hosts/"+strconv.FormatInt(pid, 10)+"/toggle", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("re-enable: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.apiJSON(t, "alice", http.MethodPut, "/api/v1/proxy-hosts/"+strconv.FormatInt(pid, 10), map[string]any{"domains": "shop.admin.test,new.admin.test"})
	if rec.Code < 400 {
		t.Errorf("adding a new name under the administrator's wildcard: %d", rec.Code)
	}
}

func TestListenPortBudgets(t *testing.T) {
	reserved := map[int]bool{80: true, 443: true, 2019: true}
	var many []string
	for p := 20000; p < 20000+16*4; p += 16 {
		many = append(many, fmt.Sprintf(":%d-%d", p, p+15))
	}
	if why := tenantListenProblem(many, reserved); why == "" {
		t.Error("four 16-port ranges in one route allowed")
	}
	e := newSecEnv(t)
	for i := 0; i < 4; i++ {
		p := 30000 + i*16
		if _, err := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "l", JSONData: claimRoute(fmt.Sprintf("l%d.alice.test", i), "203.0.113.9:80"), Listen: fmt.Sprintf(`[":%d-%d"]`, p, p+15), Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "x", "json_data": claimRoute("x.alice.test", "203.0.113.9:80"), "listen": ":31000", "enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("65th port: %d %s", rec.Code, rec.Body.String())
	}
	// Stored over the budget: the newest is held.
	_, _ = models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "over", JSONData: claimRoute("over.alice.test", "203.0.113.9:80"), Listen: `[":32000"]`, Enabled: true})
	_, _, raws, _, _ := e.s.serverResources(1)
	if _, _, kept := e.s.withoutForeignHostClaims(0, nil, nil, raws); len(kept) != 4 {
		t.Errorf("kept %d routes, want 4", len(kept))
	}
}

func TestLayer4CaddyfilePortsAreReserved(t *testing.T) {
	e := newSecEnv(t)
	srv, _ := models.GetCaddyServer(e.db, 1)
	srv.Layer4Caddyfile = "{\n\tlayer4 {\n\t\t:5432 {\n\t\t\troute {\n\t\t\t\tproxy 10.0.0.5:5432\n\t\t\t}\n\t\t}\n\t}\n}\n"
	if err := models.UpdateCaddyServer(e.db, srv); err != nil {
		t.Fatal(err)
	}
	rec := e.apiJSON(t, "alice", http.MethodPost, "/api/v1/raw-routes", map[string]any{"label": "x", "json_data": claimRoute("x.alice.test", "203.0.113.9:80"), "listen": ":5432", "enabled": true})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("listen on the Layer4 port: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTenantSafeMessage(t *testing.T) {
	for _, msg := range []string{
		`Caddy rejected the proposed config: caddy POST /load?validate_only=true status 400: {"error":"loading: dial \"s3cr3t-admin-upstream.internal:9443\": x"}`,
		"read tcp 172.18.0.3:41234->10.20.30.40:2019: connection reset by peer",
		`unknown directive 's3cr3t'`,
	} {
		got := tenantSafeMessage(msg)
		for _, bad := range []string{"s3cr3t", "10.20.30.40", "2019", "172.18.0.3"} {
			if strings.Contains(got, bad) {
				t.Errorf("%q -> %q still holds %q", msg, got, bad)
			}
		}
	}
}

func TestAdminSocketListenerDoesNotHoldTenantPorts(t *testing.T) {
	e := newSecEnv(t)
	_, _ = models.CreateRawRoute(e.db, 1, 0, &models.RawRoute{Label: "sock", JSONData: claimRoute("", "10.0.0.5:80"), Listen: `["unix//run/caddy/x.sock"]`, Enabled: true})
	_, _ = models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "a", JSONData: claimRoute("a.alice.test", "203.0.113.9:80"), Listen: `[":9000"]`, Enabled: true})
	_, _, raws, _, _ := e.s.serverResources(1)
	if _, _, kept := e.s.withoutForeignHostClaims(0, nil, nil, raws); len(kept) != 2 {
		t.Errorf("kept %d of 2", len(kept))
	}
}

func TestCustomListenServersOrderExactBeforeWildcard(t *testing.T) {
	e := newSecEnv(t)
	raws := []models.RawRoute{
		{ID: 1, Label: "w", JSONData: claimRoute("*.corp.test", "203.0.113.9:80"), Listen: `[":8443"]`, Enabled: true},
		{ID: 2, Label: "x", JSONData: claimRoute("grafana.corp.test", "10.0.0.5:80"), Listen: `[":8443"]`, Enabled: true},
	}
	for _, srv := range e.s.buildRawListenServers(raws) {
		b, _ := json.Marshal(srv["routes"])
		if i, j := strings.Index(string(b), "grafana"), strings.Index(string(b), "*.corp"); i < 0 || j < 0 || i > j {
			t.Errorf("wildcard before the exact name: %s", b)
		}
	}
}

func TestTenantHealthCheckInterval(t *testing.T) {
	e := newSecEnv(t)
	if why := e.s.tenantRouteViolation(route(healthRP(map[string]any{"uri": "/h", "interval": "1ms"}))); why == "" {
		t.Error("1ms interval allowed")
	}
	if why := e.s.tenantRouteViolation(route(healthRP(map[string]any{"uri": "/h", "interval": "30s"}))); why != "" {
		t.Errorf("30s refused: %s", why)
	}
	out, ok := e.s.sanitizeTenantRoute(ownerNull(e.ids["alice"]), "r", route(healthRP(map[string]any{"uri": "/h", "interval": 1000})))
	if b, _ := json.Marshal(out); !ok || strings.Contains(string(b), "interval") {
		t.Errorf("1µs interval not stripped (ok=%v): %s", ok, b)
	}
}
