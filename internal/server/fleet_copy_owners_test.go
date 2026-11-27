// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"net/http"
	"net/url"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// A non-admin's "Also deploy to" copy belongs to the non-admin, so the rules
// for non-admin rows apply to it on the target server too.

func fleetEnv(t *testing.T) *secEnv {
	t.Helper()
	e := newSecEnv(t)
	var adminURL string
	_ = e.db.QueryRow(`SELECT admin_url FROM caddy_servers WHERE id=1`).Scan(&adminURL)
	if _, err := models.CreateCaddyServer(e.db, &models.CaddyServer{Name: "edge", AdminURL: adminURL, Type: models.CaddyServerTypeManaged}); err != nil {
		t.Fatal(err)
	}
	return e
}

func ownerOf(t *testing.T, e *secEnv, table, where string, args ...any) (int64, sql.NullInt64) {
	t.Helper()
	var id int64
	var owner sql.NullInt64
	if err := e.db.QueryRow(`SELECT id, owner_id FROM `+table+` WHERE server_id = 2 AND `+where, args...).Scan(&id, &owner); err != nil {
		t.Fatalf("%s copy on server 2: %v", table, err)
	}
	return id, owner
}

func TestTenantCrossDeployCopiesBelongToTheTenant(t *testing.T) {
	e := fleetEnv(t)
	alice := sql.NullInt64{Int64: e.ids["alice"], Valid: true}
	deploy := url.Values{"deploy_to": {"2"}, "enabled": {"on"}}
	with := func(extra url.Values) url.Values {
		v := url.Values{}
		for k, vs := range deploy {
			v[k] = vs
		}
		for k, vs := range extra {
			v[k] = vs
		}
		return v
	}

	e.do(t, "alice", http.MethodPost, "/raw-routes", with(url.Values{"label": {"r"}, "json_data": {claimRoute("raw.example.test", "203.0.113.9:80")}}))
	if _, owner := ownerOf(t, e, "raw_routes", "label = ?", "r"); owner != alice {
		t.Errorf("Advanced route copy owner = %v, want alice", owner)
	}
	e.do(t, "alice", http.MethodPost, "/proxy-hosts", with(url.Values{"domains": {"p.example.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.9"}, "forward_port": {"80"}}))
	if _, owner := ownerOf(t, e, "proxy_hosts", "domains = ?", "p.example.test"); owner != alice {
		t.Errorf("proxy host copy owner = %v, want alice", owner)
	}
	e.do(t, "alice", http.MethodPost, "/redirection-hosts", with(url.Values{"domains": {"rd.example.test"}, "forward_scheme": {"https"}, "forward_domain": {"example.org"}, "forward_http_code": {"301"}}))
	if _, owner := ownerOf(t, e, "redirection_hosts", "domains = ?", "rd.example.test"); owner != alice {
		t.Errorf("redirection copy owner = %v, want alice", owner)
	}
	// An administrator's copy stays the administrator's.
	e.do(t, "admin", http.MethodPost, "/raw-routes", with(url.Values{"label": {"a"}, "json_data": {claimRoute("admin-raw.example.test", "10.0.0.9:80")}}))
	if _, owner := ownerOf(t, e, "raw_routes", "label = ?", "a"); owner.Valid {
		t.Errorf("admin copy owner = %v, want none", owner)
	}
}

func TestTenantCrossDeployHonoursHostClaimsOnTheTarget(t *testing.T) {
	e := fleetEnv(t)
	if _, err := models.CreateProxyHost(e.db, 2, 0, &models.ProxyHost{Domains: "edge-admin.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateRawRoute(e.db, 2, e.ids["bob"], &models.RawRoute{Label: "bob", JSONData: claimRoute("edge-bob.example.test", "10.0.0.7:80"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"edge-admin.example.test", "edge-bob.example.test"} {
		e.do(t, "alice", http.MethodPost, "/raw-routes", url.Values{"label": {host}, "json_data": {claimRoute(host, "203.0.113.9:80")}, "enabled": {"on"}, "deploy_to": {"2"}})
		var n int
		_ = e.db.QueryRow(`SELECT COUNT(*) FROM raw_routes WHERE server_id = 2 AND label = ?`, host).Scan(&n)
		if n != 0 {
			t.Errorf("%s: alice's copy was written on the target, where the host is another account's", host)
		}
	}
}

func TestCrossDeployWaitsForTheUpgradeCheck(t *testing.T) {
	e := fleetEnv(t)
	id, err := models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "old", CaddyfileSrc: "old.example.test {\n\trespond 1\n}", JSONData: claimRoute("old.example.test", "203.0.113.9:80"), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// Stored by v2.68.16: still waiting for the #184 upgrade check.
	if _, err := e.db.Exec(`UPDATE raw_routes SET rules_184 = 0 WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	rr, _ := models.GetRawRoute(e.db, id)
	if !e.s.rawRouteMigrationBlocks(*rr) {
		t.Skip("the fixture is not pending for the upgrade check")
	}
	problems := e.s.crossDeployRawRoute("alice@t", 1, rr, []int64{2})
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM raw_routes WHERE server_id = 2`).Scan(&n)
	if n != 0 || len(problems) == 0 {
		t.Errorf("a row waiting for the upgrade check was copied (copies %d, problems %v)", n, problems)
	}
}

func TestRepairFleetCopyOwners(t *testing.T) {
	e := fleetEnv(t)
	alice := e.ids["alice"]
	// Copies made by v2.68.17: owned by nobody (the administrator).
	srcRaw, _ := models.CreateRawRoute(e.db, 1, alice, &models.RawRoute{Label: "same", JSONData: claimRoute("same.example.test", "203.0.113.9:80"), Enabled: true})
	dstRaw, _ := models.CreateRawRoute(e.db, 2, 0, &models.RawRoute{Label: "same", JSONData: claimRoute("same.example.test", "203.0.113.9:80"), Enabled: true})
	srcOld, _ := models.CreateRawRoute(e.db, 1, alice, &models.RawRoute{Label: "changed", JSONData: claimRoute("changed.example.test", "203.0.113.9:80"), Enabled: true})
	dstOld, _ := models.CreateRawRoute(e.db, 2, 0, &models.RawRoute{Label: "changed", JSONData: claimRoute("changed.example.test", "127.0.0.1:2019"), Enabled: true})
	srcPH, _ := models.CreateProxyHost(e.db, 1, alice, &models.ProxyHost{Domains: "ph.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.9", ForwardPort: 80, Enabled: true})
	dstPH, _ := models.CreateProxyHost(e.db, 2, 0, &models.ProxyHost{Domains: "ph.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.9", ForwardPort: 80, Enabled: true})
	srcAdm, _ := models.CreateRawRoute(e.db, 1, 0, &models.RawRoute{Label: "adm", JSONData: claimRoute("adm.example.test", "10.0.0.9:80"), Enabled: true})
	dstAdm, _ := models.CreateRawRoute(e.db, 2, 0, &models.RawRoute{Label: "adm", JSONData: claimRoute("adm.example.test", "10.0.0.8:80"), Enabled: true})
	for _, m := range []struct {
		kind     string
		src, dst int64
	}{
		{models.FleetResourceRawRoute, srcRaw, dstRaw},
		{models.FleetResourceRawRoute, srcOld, dstOld},
		{models.FleetResourceProxy, srcPH, dstPH},
		{models.FleetResourceRawRoute, srcAdm, dstAdm},
	} {
		if err := models.SaveFleetDeployment(e.db, 1, m.kind, m.src, 2, m.dst); err != nil {
			t.Fatal(err)
		}
	}
	e.s.repairFleetCopyOwners()

	want := sql.NullInt64{Int64: alice, Valid: true}
	for _, c := range []struct {
		table   string
		id      int64
		owner   sql.NullInt64
		enabled bool
	}{
		{"raw_routes", dstRaw, want, true},
		{"raw_routes", dstOld, want, false},
		{"proxy_hosts", dstPH, want, true},
		{"raw_routes", dstAdm, sql.NullInt64{}, true},
	} {
		var owner sql.NullInt64
		var enabled bool
		if err := e.db.QueryRow(`SELECT owner_id, enabled FROM `+c.table+` WHERE id = ?`, c.id).Scan(&owner, &enabled); err != nil {
			t.Fatal(err)
		}
		if owner != c.owner || enabled != c.enabled {
			t.Errorf("%s %d: owner %v enabled %v, want owner %v enabled %v", c.table, c.id, owner, enabled, c.owner, c.enabled)
		}
	}
	if v, _ := models.GetSetting(e.db, settingFleetCopyOwnersRepaired); v != "1" {
		t.Errorf("repair not recorded: %q", v)
	}
	// Once: a copy reassigned by an administrator afterwards is left alone.
	_ = models.SetProxyHostOwner(e.db, dstPH, 0)
	e.s.repairFleetCopyOwners()
	var owner sql.NullInt64
	_ = e.db.QueryRow(`SELECT owner_id FROM proxy_hosts WHERE id = ?`, dstPH).Scan(&owner)
	if owner.Valid {
		t.Errorf("the repair ran again: owner %v", owner)
	}
}
