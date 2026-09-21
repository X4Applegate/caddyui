// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// TestAPIV1PerRowOwnershipEnforced is the regression test for
// GHSA-r4wm-rgc5-q834: the REST JSON API v1 must enforce per-row ownership so
// that a lowest-privilege role cannot read another tenant's TLS private keys
// and a "user"-role account cannot touch another tenant's routing config.
func TestAPIV1PerRowOwnershipEnforced(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "primary", AdminURL: "http://primary.invalid:2019",
	})
	if err != nil {
		t.Fatal(err)
	}

	const user2ID = int64(2)
	admin := &models.User{ID: 1, Email: "admin@example.com", IsAdmin: true, Role: models.RoleAdmin}
	user2 := &models.User{ID: user2ID, Email: "user2@example.com", Role: models.RoleUser}
	viewer := &models.User{ID: 3, Email: "viewer@example.com", Role: models.RoleView}

	// Admin-owned resources (ownerID 0 persists as NULL owner).
	certAdmin, err := models.CreateCertificate(conn, serverID, 0, &models.Certificate{
		Name: "AdminSecretCert", Source: "pem",
		CertPEM: "-----BEGIN CERTIFICATE-----\nADMIN\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nSUPERSECRETADMINKEY\n-----END PRIVATE KEY-----",
	})
	if err != nil {
		t.Fatal(err)
	}
	rrAdmin, err := models.CreateRawRoute(conn, serverID, 0, &models.RawRoute{Label: "admin-rr", JSONData: "{}", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	rhAdmin, err := models.CreateRedirectionHost(conn, serverID, 0, &models.RedirectionHost{Domains: "admin.test", ForwardDomain: "dest.test", ForwardScheme: "auto", ForwardHTTPCode: 301, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	phAdmin, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{Domains: "admin.test", ForwardScheme: "http", ForwardHost: "backend", ForwardPort: 8080, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	// A resource that user2 legitimately owns, for the positive control.
	rrUser2, err := models.CreateRawRoute(conn, serverID, user2ID, &models.RawRoute{Label: "user2-rr", JSONData: "{}", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}

	call := func(method, id string, user *models.User, handler http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/x/"+id, strings.NewReader("{}"))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = context.WithValue(ctx, auth.ContextUserKey, user)
		rec := httptest.NewRecorder()
		handler(rec, req.WithContext(ctx))
		return rec
	}

	id := func(v int64) string { return strconv.FormatInt(v, 10) }

	// ── Finding 1: private-key disclosure to the lowest-privilege role ──────────
	t.Run("viewer cannot read admin certificate private key", func(t *testing.T) {
		rec := call(http.MethodGet, id(certAdmin), viewer, s.apiV1GetCertificate)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "SUPERSECRETADMINKEY") {
			t.Fatalf("private key leaked to viewer: %s", rec.Body.String())
		}
	})
	t.Run("admin can read own certificate", func(t *testing.T) {
		rec := call(http.MethodGet, id(certAdmin), admin, s.apiV1GetCertificate)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for admin, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	// ── Finding 2: cross-tenant read/write/delete/toggle by a user-role account ─
	forbidden := []struct {
		name    string
		method  string
		id      int64
		handler http.HandlerFunc
	}{
		{"get raw-route", http.MethodGet, rrAdmin, s.apiV1GetRawRoute},
		{"update raw-route", http.MethodPut, rrAdmin, s.apiV1UpdateRawRoute},
		{"delete raw-route", http.MethodDelete, rrAdmin, s.apiV1DeleteRawRoute},
		{"toggle raw-route", http.MethodPost, rrAdmin, s.apiV1ToggleRawRoute},
		{"get redirection-host", http.MethodGet, rhAdmin, s.apiV1GetRedirectionHost},
		{"update redirection-host", http.MethodPut, rhAdmin, s.apiV1UpdateRedirectionHost},
		{"delete redirection-host", http.MethodDelete, rhAdmin, s.apiV1DeleteRedirectionHost},
		{"toggle redirection-host", http.MethodPost, rhAdmin, s.apiV1ToggleRedirectionHost},
		{"toggle proxy-host", http.MethodPost, phAdmin, s.apiV1ToggleProxyHost},
		{"maintenance proxy-host", http.MethodPost, phAdmin, s.apiV1ToggleMaintenanceProxyHost},
		{"get certificate", http.MethodGet, certAdmin, s.apiV1GetCertificate},
		{"update certificate", http.MethodPut, certAdmin, s.apiV1UpdateCertificate},
		{"delete certificate", http.MethodDelete, certAdmin, s.apiV1DeleteCertificate},
	}
	for _, tc := range forbidden {
		t.Run("user2 forbidden: "+tc.name, func(t *testing.T) {
			rec := call(tc.method, id(tc.id), user2, tc.handler)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for %s, got %d: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}

	// The admin's raw route must still exist after user2's blocked DELETE.
	if got, _ := models.GetRawRoute(conn, rrAdmin); got == nil {
		t.Fatal("admin raw route was deleted by an unauthorized user")
	}

	// ── Positive control: user2 may access the row it actually owns ─────────────
	t.Run("user2 can read own raw-route", func(t *testing.T) {
		rec := call(http.MethodGet, id(rrUser2), user2, s.apiV1GetRawRoute)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for owner, got %d: %s", rec.Code, rec.Body.String())
		}
	})
}
