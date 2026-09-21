// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// TestGroupPeerCanManageSharedResources is the regression test for review
// finding #7 (v2.52.5): access-groups grant collaborative management. A
// user-role account may manage resources owned by a user who shares a group
// with them, while a user with no shared group still gets 403.
func TestGroupPeerCanManageSharedResources(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: "http://primary.invalid:2019"})
	if err != nil {
		t.Fatal(err)
	}

	pw, _ := auth.HashPassword("x")
	ownerID, err := models.CreateUser(conn, "owner@example.com", pw, "Owner", models.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := models.CreateUser(conn, "peer@example.com", pw, "Peer", models.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	strangerID, err := models.CreateUser(conn, "stranger@example.com", pw, "Stranger", models.RoleUser)
	if err != nil {
		t.Fatal(err)
	}

	// owner and peer share a group; stranger is in none.
	gid, err := models.CreateGroup(conn, "team-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := models.SetGroupMembers(conn, gid, []int64{ownerID, peerID}); err != nil {
		t.Fatal(err)
	}

	phID, err := models.CreateProxyHost(conn, serverID, ownerID, &models.ProxyHost{
		Domains: "owner.test", ForwardScheme: "http", ForwardHost: "backend", ForwardPort: 8080, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}
	owner := &models.User{ID: ownerID, Email: "owner@example.com", Role: models.RoleUser}
	peer := &models.User{ID: peerID, Email: "peer@example.com", Role: models.RoleUser}
	stranger := &models.User{ID: strangerID, Email: "stranger@example.com", Role: models.RoleUser}

	// Unit-level: the single authorization gate.
	ph, _ := models.GetProxyHost(conn, phID)
	if !s.canManageOwned(owner, ph.OwnerID) {
		t.Error("owner should manage their own host")
	}
	if !s.canManageOwned(peer, ph.OwnerID) {
		t.Error("group peer should be able to manage the shared host")
	}
	if s.canManageOwned(stranger, ph.OwnerID) {
		t.Error("a user with no shared group must NOT manage the host")
	}

	// End-to-end through a REST handler: peer gets 200, stranger 403.
	get := func(u *models.User) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/proxy-hosts/"+strconv.FormatInt(phID, 10), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", strconv.FormatInt(phID, 10))
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = context.WithValue(ctx, auth.ContextUserKey, u)
		rec := httptest.NewRecorder()
		s.apiV1GetProxyHost(rec, req.WithContext(ctx))
		return rec.Code
	}
	if code := get(peer); code != http.StatusOK {
		t.Errorf("group peer GET: expected 200, got %d", code)
	}
	if code := get(stranger); code != http.StatusForbidden {
		t.Errorf("stranger GET: expected 403, got %d", code)
	}
}
