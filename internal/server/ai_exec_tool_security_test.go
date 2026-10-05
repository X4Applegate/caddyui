// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// GHSA-5h8j-xxm3-7ggr: /api/ai/exec-tool was registered outside the
// requireWrite-protected route group, so a read-only viewer could reach it
// directly and create proxy hosts or redirections despite being blocked from
// every other write path. Fixed by moving the route into that group.
//
// This composes requireWrite around apiAIExecTool exactly as server.go's
// router now does, rather than exercising the full router (which would also
// require simulating session-cookie authentication) — it verifies the actual
// fix: a viewer-role context must never reach the handler at all.
func TestAIExecToolRequiresWriteRole(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	if err := models.SetSetting(conn, settingAIEnabled, "1"); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New("http://127.0.0.1:1", "", "")}
	protected := s.requireWrite(http.HandlerFunc(s.apiAIExecTool))

	viewer := &models.User{ID: 1, Email: "viewer@test", Role: models.RoleView}
	body := `{"name":"create_proxy_host","args":{"domains":"viewer-attempt.test","forward_scheme":"http","forward_host":"127.0.0.1","forward_port":2019}}`
	req := httptest.NewRequest(http.MethodPost, "/api/ai/exec-tool", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.ContextUserKey, viewer)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer exec-tool call: expected 403 from requireWrite, got %d: %s", rec.Code, rec.Body.String())
	}
	if hosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil); len(hosts) != 0 {
		t.Fatalf("viewer must not be able to create a proxy host via exec-tool, found %d", len(hosts))
	}

	// A write-capable role must still pass through requireWrite to the real
	// handler (regression guard: this is additive, not a new block on
	// everyone).
	user := &models.User{ID: 2, Email: "user@test", Role: models.RoleUser}
	req2 := httptest.NewRequest(http.MethodPost, "/api/ai/exec-tool", strings.NewReader(
		`{"name":"create_proxy_host","args":{"domains":"user-ok.test","forward_scheme":"http","forward_host":"203.0.113.10","forward_port":8080}}`))
	ctx2 := context.WithValue(req2.Context(), auth.ContextUserKey, user)
	rec2 := httptest.NewRecorder()
	protected.ServeHTTP(rec2, req2.WithContext(ctx2))
	var resp struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp); err != nil || !resp.Success {
		t.Fatalf("write-role exec-tool call should reach the handler and succeed, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// GHSA-5h8j-xxm3-7ggr (second finding): apiAIExecTool's create_proxy_host
// path skipped validateProxyUpstreamsForUser, the same non-admin SSRF guard
// every other proxy-host creation path applies (upstream_guard.go,
// GHSA-r4wm-rgc5-q834). This calls the handler directly — bypassing
// requireWrite deliberately, mirroring TestAPIV1ProxyHostSSRFGuard's style —
// to isolate the upstream-validation regression from the role-gate one
// covered above.
func TestAIExecToolCreateProxyHostSSRFGuard(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	if err := models.SetSetting(conn, settingAIEnabled, "1"); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New("http://127.0.0.1:1", "", "")}

	admin := &models.User{ID: 1, Email: "admin@test", IsAdmin: true, Role: models.RoleAdmin}
	user := &models.User{ID: 2, Email: "user@test", Role: models.RoleUser}

	exec := func(u *models.User, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/ai/exec-tool", strings.NewReader(body))
		ctx := context.WithValue(req.Context(), auth.ContextUserKey, u)
		rec := httptest.NewRecorder()
		s.apiAIExecTool(rec, req.WithContext(ctx))
		return rec
	}
	wantError := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		t.Helper()
		var resp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.Error
	}

	// 1. user-role, upstream = the Caddy admin API itself (the PoC's exact
	//    repro target) → rejected, nothing persisted.
	rec := exec(user, `{"name":"create_proxy_host","args":{"domains":"evil.test","forward_scheme":"http","forward_host":"127.0.0.1","forward_port":1}}`)
	if msg := wantError(t, rec); msg == "" {
		t.Fatalf("expected an SSRF-guard error for user-role admin-API upstream, got success: %s", rec.Body.String())
	}
	if hosts, _ := models.ListProxyHosts(conn, 1, 1, true, nil); len(hosts) != 0 {
		t.Fatalf("blocked upstream must not be persisted, found %d", len(hosts))
	}

	// 2. user-role, cloud-metadata-style link-local upstream → rejected.
	if rec := exec(user, `{"name":"create_proxy_host","args":{"domains":"evil2.test","forward_scheme":"http","forward_host":"169.254.169.254","forward_port":80}}`); wantError(t, rec) == "" {
		t.Fatalf("expected an SSRF-guard error for link-local upstream, got success: %s", rec.Body.String())
	}

	// 3. user-role, legitimate public upstream → still works (not a blanket
	//    regression — only internal/admin addresses are blocked).
	rec3 := exec(user, `{"name":"create_proxy_host","args":{"domains":"ok.test","forward_scheme":"http","forward_host":"203.0.113.10","forward_port":8080}}`)
	var resp3 struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(rec3.Body.Bytes(), &resp3); err != nil || !resp3.Success {
		t.Fatalf("legit user-role upstream should succeed, got %d: %s", rec3.Code, rec3.Body.String())
	}

	// 4. admin, loopback upstream → unrestricted (same invariant as the
	//    normal proxy-host creation paths — admins can proxy to localhost
	//    apps, the common single-admin deployment).
	rec4 := exec(admin, `{"name":"create_proxy_host","args":{"domains":"adminlocal.test","forward_scheme":"http","forward_host":"127.0.0.1","forward_port":3000}}`)
	var resp4 struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(rec4.Body.Bytes(), &resp4); err != nil || !resp4.Success {
		t.Fatalf("admin loopback upstream should succeed, got %d: %s", rec4.Code, rec4.Body.String())
	}
}
