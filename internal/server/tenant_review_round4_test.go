// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Findings of the third (final) round of independent reviews.

// A fleet copy may not add a name under an administrator's wildcard on the
// target server, for any kind of row.
func TestFleetCopyUnderAdminWildcard(t *testing.T) {
	e := fleetEnv(t)
	if _, err := models.CreateProxyHost(e.db, 2, 0, &models.ProxyHost{Domains: "*.admin.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	e.do(t, "alice", http.MethodPost, "/proxy-hosts", url.Values{"domains": {"pay.admin.test"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.9"}, "forward_port": {"80"}, "enabled": {"on"}, "deploy_to": {"2"}})
	e.do(t, "alice", http.MethodPost, "/redirection-hosts", url.Values{"domains": {"red.admin.test"}, "forward_scheme": {"https"}, "forward_domain": {"example.org"}, "forward_http_code": {"301"}, "enabled": {"on"}, "deploy_to": {"2"}})
	e.do(t, "alice", http.MethodPost, "/raw-routes", url.Values{"label": {"r"}, "json_data": {claimRoute("raw.admin.test", "203.0.113.9:80")}, "enabled": {"on"}, "deploy_to": {"2"}})
	for table, where := range map[string]string{"proxy_hosts": "domains = 'pay.admin.test'", "redirection_hosts": "domains = 'red.admin.test'", "raw_routes": "label = 'r'"} {
		var n int
		_ = e.db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE server_id = 2 AND ` + where).Scan(&n)
		if n != 0 {
			t.Errorf("%s: a copy under the administrator's wildcard was written on the target", table)
		}
	}
	// Control: on server 1, where there is no wildcard, the rows exist.
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM proxy_hosts WHERE server_id = 1 AND domains = 'pay.admin.test'`).Scan(&n)
	if n != 1 {
		t.Errorf("control: the source row is missing (%d)", n)
	}
}

func TestLayer4ReservesListenersOnly(t *testing.T) {
	e := newSecEnv(t)
	srv, _ := models.GetCaddyServer(e.db, 1)
	srv.Layer4Caddyfile = "{\n\tlayer4 {\n\t\t:5000 {\n\t\t\troute {\n\t\t\t\tproxy 10.0.0.9:8443 [fd00:1234:5678::1]:7000\n\t\t\t}\n\t\t}\n\t\tudp/:5353 tcp/[::]:6000-6002 {\n\t\t\troute {\n\t\t\t\tproxy 10.0.0.9:53\n\t\t\t}\n\t\t}\n\t}\n}\n"
	if err := models.UpdateCaddyServer(e.db, srv); err != nil {
		t.Fatal(err)
	}
	got := e.s.reservedListenPorts()
	for _, p := range []int{5000, 5353, 6000, 6001, 6002} {
		if !got[p] {
			t.Errorf("listener port %d not reserved", p)
		}
	}
	for _, p := range []int{8443, 1234, 5678, 7000} {
		if got[p] {
			t.Errorf("upstream port %d reserved", p)
		}
	}
}

func TestReloadErrorIsReducedForTenants(t *testing.T) {
	e := newSecEnv(t)
	const secret = "s3cr3t-admin-upstream.internal"
	rec := httptestReloadWithError(t, e, `{"error":"loading: dial \"`+secret+`:9443\": refused"}`)
	if strings.Contains(rec, secret) || strings.Contains(rec, "9443") {
		t.Errorf("tenant sees %q", rec)
	}
}

func TestTenantSafeMessageKeepsTheReason(t *testing.T) {
	got := tenantSafeMessage(`Caddy rejected the proposed config: caddy POST /load?validate_only=true status 400: {"error":"adapting config: wrong argument count, at Caddyfile:12 near \"x\""}`)
	if !strings.Contains(got, "wrong argument count") || !strings.Contains(got, "Caddyfile:12") {
		t.Errorf("reason lost: %q", got)
	}
	if got := tenantSafeMessage("dial tcp db.corp:5432: refused"); strings.Contains(got, "db.corp") {
		t.Errorf("host kept: %q", got)
	}
}

// The account's port budget is charged only for routes that are deployed.
func TestHeldRouteDoesNotUseTheBudget(t *testing.T) {
	e := newSecEnv(t)
	_, _ = models.CreateRawRoute(e.db, 1, e.ids["bob"], &models.RawRoute{Label: "bob", JSONData: claimRoute("taken.example.test", "10.0.0.7:80"), Enabled: true})
	// Stored before the rules: a route held for its host, with 16 ports...
	_, _ = models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "held", JSONData: claimRoute("taken.example.test", "203.0.113.9:80"),
		Listen: `[":40000-40015"]`, Enabled: true})
	// ...and four legitimate routes that use the whole budget of 64.
	for i, l := range []string{`[":41000-41015"]`, `[":41016-41031"]`, `[":41032-41047"]`, `[":41048-41063"]`} {
		_, _ = models.CreateRawRoute(e.db, 1, e.ids["alice"], &models.RawRoute{Label: "ok", JSONData: claimRoute(fmt.Sprintf("ok%d.alice.test", i), "203.0.113.9:80"), Listen: l, Enabled: true})
	}
	_, _, raws, _, _ := e.s.serverResources(1)
	_, _, kept := e.s.withoutForeignHostClaims(0, nil, nil, raws)
	ok, held := 0, 0
	for _, rr := range kept {
		switch rr.Label {
		case "ok":
			ok++
		case "held":
			held++
		}
	}
	if ok != 4 || held != 0 {
		t.Errorf("kept %d of 4 legitimate routes and %d held ones", ok, held)
	}
}

// httptestReloadWithError points server 1 at a Caddy whose /load answers
// 400 with body, has alice POST /caddy/reload, and returns the response.
func httptestReloadWithError(t *testing.T, e *secEnv, body string) string {
	t.Helper()
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"apps":{"http":{"servers":{"srv0":{"routes":[]}}}}}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/load") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, body)
			return
		}
		fmt.Fprint(w, `{}`)
	}))
	t.Cleanup(fake.Close)
	if _, err := e.db.Exec(`UPDATE caddy_servers SET admin_url = ? WHERE id = 1`, fake.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(e.db, 1, 0, &models.ProxyHost{Domains: "a.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "alice", http.MethodPost, "/caddy/reload", url.Values{})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("reload: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
