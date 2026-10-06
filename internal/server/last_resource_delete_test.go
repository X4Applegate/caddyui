// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.59.1 (issue #120): deleting the LAST resource on a server must reach that
// server's live Caddy. The empty-database guard ("refusing to push empty
// routes") used to swallow the sync, so the deleted route kept serving.

// emptySyncsPushed counts syncs that really ran with nothing left in the
// database (the activity log only records those when Caddy was written).
func emptySyncsPushed(t *testing.T, f *l4Fleet, serverID int64) int {
	t.Helper()
	var n int
	if err := f.conn.QueryRow(`SELECT COUNT(*) FROM activity_log WHERE server_id=? AND action='sync_applied' AND detail LIKE 'proxies=0 redirects=0 passthrough=0 certs=0%'`, serverID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDeletingTheLastHostPushesTheEmptyStateToCaddy(t *testing.T) {
	f := newL4Fleet(t)
	f.createProxy(t, "only.example.com", nil)
	if n := emptySyncsPushed(t, f, f.source); n != 0 {
		t.Fatalf("setup: %d empty syncs already", n)
	}
	f.deleteProxy(t, f.proxyHosts(t, f.source)[0].ID)
	if n := emptySyncsPushed(t, f, f.source); n != 1 {
		t.Errorf("deleting the last proxy host pushed %d empty syncs, want 1 (the route would stay live)", n)
	}
}

func TestDeletingTheLastRedirectAndRawRouteAlsoPush(t *testing.T) {
	f := newL4Fleet(t)
	rid, err := models.CreateRedirectionHost(f.conn, f.source, 0, &models.RedirectionHost{Domains: "old.example.com", ForwardScheme: "https", ForwardDomain: "new.example.com", ForwardHTTPCode: 301, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sid := strconv.FormatInt(rid, 10)
	rec := httptest.NewRecorder()
	f.s.deleteRedirectionHost(rec, withChiURLParam(cookieReq(t, "/redirection-hosts/"+sid+"/delete", url.Values{}, f.source), "id", sid))
	if n := emptySyncsPushed(t, f, f.source); n != 1 {
		t.Errorf("deleting the last redirection pushed %d empty syncs, want 1", n)
	}
}

// The guard itself must keep working: an ordinary sync of a server with no
// entries (fresh or wiped database) must NOT blank the live Caddy.
func TestPlainSyncOfAnEmptyDatabaseStillRefusesToPush(t *testing.T) {
	f := newL4Fleet(t)
	if err := f.s.syncCaddy(f.source, false); err != nil {
		t.Fatalf("plain sync: %v", err)
	}
	if n := emptySyncsPushed(t, f, f.source); n != 0 {
		t.Errorf("a plain sync with no entries pushed an empty config (%d)", n)
	}
}

// Propagated deletion: the target's last copy is removed AND its live Caddy
// converges to the empty state, not just its database.
func TestPropagatedDeletionOfTheTargetsLastCopyPushesTheEmptyState(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	enablePropagation(t, f, f.source, true)
	f.createProxy(t, "app.example.com", nil)
	if len(f.proxyHosts(t, f.edge1)) != 1 {
		t.Fatal("setup: no copy on the target")
	}
	f.deleteProxy(t, f.proxyHosts(t, f.source)[0].ID)
	if len(f.proxyHosts(t, f.edge1)) != 0 {
		t.Fatal("the copy was not deleted from the target")
	}
	if n := emptySyncsPushed(t, f, f.edge1); n != 1 {
		t.Errorf("the target converged with %d empty pushes, want 1 — its Caddy would keep serving the deleted route", n)
	}
	if pend, _ := models.ListFleetPendingDeletions(f.conn, 0); len(pend) != 0 {
		t.Errorf("%d pending deletions left", len(pend))
	}
}
