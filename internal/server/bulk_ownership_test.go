// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// TestBulkProxyHostOwnershipEnforced is the regression test for the v2.52.3
// IDOR fix: the HTML bulk proxy-host endpoints (bulk-toggle, bulk-maintenance)
// must enforce per-row ownership just like the single-object handlers and the
// other bulk handlers (delete, certificate, raw-route toggle) already do. A
// non-admin "user"-role account must not be able to enable/disable or
// maintenance-flip a proxy host it does not own by supplying arbitrary ids[].
func TestBulkProxyHostOwnershipEnforced(t *testing.T) {
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
	user2 := &models.User{ID: user2ID, Email: "user2@example.com", Role: models.RoleUser}

	// Admin-owned proxy host (ownerID 0 persists as NULL owner), starting enabled
	// and not in maintenance mode.
	phAdmin, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{
		Domains: "admin.test", ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 8080, Enabled: true, MaintenanceMode: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A proxy host user2 legitimately owns, for the positive control.
	phUser2, err := models.CreateProxyHost(conn, serverID, user2ID, &models.ProxyHost{
		Domains: "user2.test", ForwardScheme: "http", ForwardHost: "backend",
		ForwardPort: 8081, Enabled: true, MaintenanceMode: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}

	postBulk := func(handler http.HandlerFunc, user *models.User, action string, ids ...int64) {
		form := url.Values{}
		form.Set("action", action)
		for _, id := range ids {
			form.Add("ids[]", strconv.FormatInt(id, 10))
		}
		req := httptest.NewRequest(http.MethodPost, "/proxy-hosts/bulk", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx := context.WithValue(req.Context(), auth.ContextUserKey, user)
		rec := httptest.NewRecorder()
		handler(rec, req.WithContext(ctx))
	}

	mustGet := func(id int64) *models.ProxyHost {
		ph, err := models.GetProxyHost(conn, id)
		if err != nil || ph == nil {
			t.Fatalf("GetProxyHost(%d): %v", id, err)
		}
		return ph
	}

	t.Run("user cannot bulk-disable an admin-owned host", func(t *testing.T) {
		postBulk(s.bulkToggleProxyHosts, user2, "disable", phAdmin)
		if got := mustGet(phAdmin); !got.Enabled {
			t.Fatalf("IDOR: non-owner disabled admin proxy host (Enabled=%v)", got.Enabled)
		}
	})

	t.Run("user cannot bulk-enable-maintenance an admin-owned host", func(t *testing.T) {
		postBulk(s.bulkMaintenanceProxyHosts, user2, "enable", phAdmin)
		if got := mustGet(phAdmin); got.MaintenanceMode {
			t.Fatalf("IDOR: non-owner set maintenance on admin proxy host (MaintenanceMode=%v)", got.MaintenanceMode)
		}
	})

	t.Run("user can still bulk-toggle their own host", func(t *testing.T) {
		postBulk(s.bulkToggleProxyHosts, user2, "disable", phUser2)
		if got := mustGet(phUser2); got.Enabled {
			t.Fatalf("owner could not disable their own proxy host (Enabled=%v)", got.Enabled)
		}
	})
}
