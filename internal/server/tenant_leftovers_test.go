// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The proxy-host form must not offer a non-admin the active health-check
// settings their save is refused for (POST, a request body, following
// redirects — see activeHealthCheckViolation). An admin still sees them.
func TestTenantProxyHostFormHidesRefusedHealthCheckFields(t *testing.T) {
	e := newSecEnv(t)
	markers := []string{`<option value="POST"`, `name="health_check_body"`, `name="health_check_follow_redirects"`}
	for _, who := range []string{"admin", "alice"} {
		req := httptest.NewRequest(http.MethodGet, "/proxy-hosts/new", nil)
		e.attachSession(req, who)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: GET /proxy-hosts/new = %d", who, rec.Code)
		}
		page := rec.Body.String()
		if !strings.Contains(page, `name="health_check_method"`) {
			t.Fatalf("%s: form rendered without the health-check section", who)
		}
		// The method marker is checked inside the health-check select only;
		// other selects on the form offer POST too.
		sel := page[strings.Index(page, `name="health_check_method"`):]
		sel = sel[:strings.Index(sel, "</select>")]
		for _, m := range markers {
			in := page
			if strings.HasPrefix(m, "<option") {
				in = sel
			}
			if got, want := strings.Contains(in, m), who == "admin"; got != want {
				t.Errorf("%s: %s shown = %v, want %v", who, m, got, want)
			}
		}
	}
}

// A cross-deploy failure notice (withDeployProblems) carries the target's
// raw error. A non-admin sees each reason reduced (tenantSafeMessage); an
// administrator sees it whole.
func TestTenantDeployErrorIsReduced(t *testing.T) {
	e := newSecEnv(t)
	target := withDeployProblems("/redirection-hosts", []string{
		`edge-1: saved there, but pushing it to Caddy failed: POST http://10.9.8.7:2019/load: {"error":"loading config: unknown directive \"secret-token-abc\""}`,
		`edge-2: dial tcp 192.0.2.44:2019: connection refused`,
	})
	for _, who := range []string{"admin", "alice"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		e.attachSession(req, who)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		page := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(page, "Saved, but not deployed to every server.") {
			t.Fatalf("%s: GET %s = %d without the notice", who, target, rec.Code)
		}
		for _, secret := range []string{"secret-token-abc", "10.9.8.7", "192.0.2.44"} {
			if got, want := strings.Contains(page, secret), who == "admin"; got != want {
				t.Errorf("%s: %s shown = %v, want %v", who, secret, got, want)
			}
		}
		if !strings.Contains(page, "dge-2: dial tcp") {
			t.Errorf("%s: second reason lost", who)
		}
	}
}
