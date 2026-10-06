// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.59.0 (issue #120): opt-in deletion propagation to automatic targets.

func enablePropagation(t *testing.T, f *l4Fleet, serverID int64, on bool) {
	t.Helper()
	srv, err := models.GetCaddyServer(f.conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	srv.PropagateDeletions = on
	if err := models.UpdateCaddyServer(f.conn, srv); err != nil {
		t.Fatal(err)
	}
}

func (f *l4Fleet) proxyHosts(t *testing.T, serverID int64) []models.ProxyHost {
	t.Helper()
	rows, err := models.ListProxyHosts(f.conn, serverID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *l4Fleet) redirects(t *testing.T, serverID int64) []models.RedirectionHost {
	t.Helper()
	rows, err := models.ListRedirectionHosts(f.conn, serverID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *l4Fleet) createProxy(t *testing.T, domain string, extra url.Values) {
	t.Helper()
	form := url.Values{"domains": {domain}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"}}
	for k, v := range extra {
		form[k] = v
	}
	rec := httptest.NewRecorder()
	f.s.createProxyHost(rec, cookieReq(t, "/proxy-hosts", form, f.source))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create proxy host %s -> %d: %s", domain, rec.Code, excerpt(rec.Body.String(), "rror"))
	}
}

func (f *l4Fleet) deleteProxy(t *testing.T, id int64) {
	t.Helper()
	sid := strconv.FormatInt(id, 10)
	rec := httptest.NewRecorder()
	f.s.deleteProxyHost(rec, withChiURLParam(cookieReq(t, "/proxy-hosts/"+sid+"/delete", url.Values{}, f.source), "id", sid))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete proxy host -> %d", rec.Code)
	}
}

func hasDomain(hosts []models.ProxyHost, domain string) bool {
	for _, h := range hosts {
		if h.Domains == domain {
			return true
		}
	}
	return false
}

func TestDeletionIsNotPropagatedUnlessEnabled(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	f.createProxy(t, "app.example.com", nil)
	if !hasDomain(f.proxyHosts(t, f.edge1), "app.example.com") {
		t.Fatal("setup: the host was not deployed")
	}
	src := f.proxyHosts(t, f.source)[0]
	f.deleteProxy(t, src.ID)
	if len(f.proxyHosts(t, f.source)) != 0 {
		t.Fatal("source row not deleted")
	}
	if !hasDomain(f.proxyHosts(t, f.edge1), "app.example.com") {
		t.Error("with propagation off, a source deletion removed the target's copy")
	}
	if p, _ := models.ListFleetPendingDeletions(f.conn, 0); len(p) != 0 {
		t.Errorf("queued %d deletions with propagation off", len(p))
	}
	if m, _ := models.FleetDeploymentsForSource(f.conn, f.source, models.FleetResourceProxy, src.ID); len(m) != 0 {
		t.Error("the pairing of a deleted source row must be forgotten")
	}
}

func TestEnabledPropagationDeletesOnlyPairedCopiesOnAutomaticTargets(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1) // edge2 is not automatic
	enablePropagation(t, f, f.source, true)

	// Independent rows on the target: never touched.
	if _, err := models.CreateProxyHost(f.conn, f.edge1, 0, &models.ProxyHost{Domains: "target-local.example.com", ForwardScheme: "http", ForwardHost: "10.1.1.1", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// A one-off "Also deploy to" copy on a non-automatic server.
	f.createProxy(t, "app.example.com", url.Values{"deploy_to": {strconv.FormatInt(f.edge2, 10)}})
	// Node-local on the source: never deployed at all.
	f.createProxy(t, "local-only.example.com", url.Values{"node_local": {"on"}})
	if !hasDomain(f.proxyHosts(t, f.edge1), "app.example.com") || !hasDomain(f.proxyHosts(t, f.edge2), "app.example.com") {
		t.Fatal("setup: expected copies on both targets")
	}

	var appID int64
	for _, h := range f.proxyHosts(t, f.source) {
		if h.Domains == "app.example.com" {
			appID = h.ID
		}
	}
	f.deleteProxy(t, appID)

	if hasDomain(f.proxyHosts(t, f.edge1), "app.example.com") {
		t.Error("the paired copy on the automatic target was not deleted")
	}
	if !hasDomain(f.proxyHosts(t, f.edge1), "target-local.example.com") {
		t.Error("an independent target-local row was deleted")
	}
	if !hasDomain(f.proxyHosts(t, f.edge2), "app.example.com") {
		t.Error("a copy on a one-off (non-automatic) target was deleted")
	}
	if pend, _ := models.ListFleetPendingDeletions(f.conn, 0); len(pend) != 0 {
		t.Errorf("a reachable target left %d pending deletions", len(pend))
	}
	f.fEdge1.mu.Lock()
	defer f.fEdge1.mu.Unlock()
	if f.fEdge1.loadCalls == 0 && f.fEdge1.putCalls == 0 {
		t.Log("target Caddy was not pushed (it has no entries left: the empty-config guard applies)")
	}
}

func TestEnabledPropagationCoversRedirectsAndLayer4(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	enablePropagation(t, f, f.source, true)

	form := url.Values{"domains": {"old.example.com"}, "forward_scheme": {"https"}, "forward_domain": {"new.example.com"}, "forward_http_code": {"301"}, "enabled": {"on"}}
	rec := httptest.NewRecorder()
	f.s.createRedirectionHost(rec, cookieReq(t, "/redirection-hosts", form, f.source))
	f.create(t, f.source, f.form(nil))
	if len(f.redirects(t, f.edge1)) != 1 || len(f.rows(t, f.edge1)) != 1 {
		t.Fatalf("setup: redirects=%d layer4=%d on target", len(f.redirects(t, f.edge1)), len(f.rows(t, f.edge1)))
	}

	rid := strconv.FormatInt(f.redirects(t, f.source)[0].ID, 10)
	rec = httptest.NewRecorder()
	f.s.deleteRedirectionHost(rec, withChiURLParam(cookieReq(t, "/redirection-hosts/"+rid+"/delete", url.Values{}, f.source), "id", rid))
	lid := strconv.FormatInt(f.rows(t, f.source)[0].ID, 10)
	rec = httptest.NewRecorder()
	f.s.deleteLayer4Proxy(rec, withChiURLParam(cookieReq(t, "/layer4-proxies/"+lid+"/delete", url.Values{}, f.source), "id", lid))

	if n := len(f.redirects(t, f.edge1)); n != 0 {
		t.Errorf("redirect copy still on target (%d)", n)
	}
	if n := len(f.rows(t, f.edge1)); n != 0 {
		t.Errorf("layer4 copy still on target (%d)", n)
	}
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "were+not+removed") || strings.Contains(loc, "not%20removed") {
		t.Errorf("the flash claims copies were kept: %s", loc)
	}
}

func TestBulkDeleteAlsoPropagates(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	enablePropagation(t, f, f.source, true)
	f.createProxy(t, "a.example.com", nil)
	f.createProxy(t, "b.example.com", nil)
	var ids []string
	for _, h := range f.proxyHosts(t, f.source) {
		ids = append(ids, strconv.FormatInt(h.ID, 10))
	}
	rec := httptest.NewRecorder()
	f.s.bulkDeleteProxyHosts(rec, cookieReq(t, "/proxy-hosts/bulk-delete", url.Values{"ids[]": ids}, f.source))
	if len(f.proxyHosts(t, f.source)) != 0 || len(f.proxyHosts(t, f.edge1)) != 0 {
		t.Errorf("bulk delete left rows: source=%d target=%d", len(f.proxyHosts(t, f.source)), len(f.proxyHosts(t, f.edge1)))
	}
}

// An unreachable target keeps the deletion pending (the pairing is not
// forgotten) and the reconciler finishes it once the target answers again.
func TestUnreachableTargetKeepsTheDeletionPendingUntilItConverges(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	enablePropagation(t, f, f.source, true)
	f.createProxy(t, "app.example.com", nil)
	f.createProxy(t, "keep.example.com", nil) // keeps the target non-empty so a sync really pushes

	edge, _ := models.GetCaddyServer(f.conn, f.edge1)
	liveURL := edge.AdminURL
	edge.AdminURL = "http://127.0.0.1:1" // nothing listens here
	if err := models.UpdateCaddyServer(f.conn, edge); err != nil {
		t.Fatal(err)
	}

	var appID int64
	for _, h := range f.proxyHosts(t, f.source) {
		if h.Domains == "app.example.com" {
			appID = h.ID
		}
	}
	f.deleteProxy(t, appID)

	pend, err := models.ListFleetPendingDeletions(f.conn, f.source)
	if err != nil || len(pend) != 1 {
		t.Fatalf("pending = %+v err=%v, want exactly one", pend, err)
	}
	p := pend[0]
	if p.TargetServerID != f.edge1 || p.Attempts < 1 || p.LastError == "" || p.Label != "app.example.com" {
		t.Errorf("pending entry not recorded properly: %+v", p)
	}
	if hasDomain(f.proxyHosts(t, f.edge1), "app.example.com") {
		t.Error("the copy should already be gone from CaddyUI's own database")
	}
	if !hasDomain(f.proxyHosts(t, f.edge1), "keep.example.com") {
		t.Error("an unrelated copy was deleted")
	}

	// Still down: a retry keeps it pending and counts the attempt.
	if done, pending := f.s.processFleetPendingDeletions("system", 0); done != 0 || pending != 1 {
		t.Errorf("retry while down: done=%d pending=%d", done, pending)
	}
	if pend, _ = models.ListFleetPendingDeletions(f.conn, f.source); len(pend) != 1 || pend[0].Attempts < 2 {
		t.Errorf("attempt not counted: %+v", pend)
	}

	// Back up: converges and the entry disappears.
	edge, _ = models.GetCaddyServer(f.conn, f.edge1)
	edge.AdminURL = liveURL
	if err := models.UpdateCaddyServer(f.conn, edge); err != nil {
		t.Fatal(err)
	}
	if done, pending := f.s.processFleetPendingDeletions("system", 0); done != 1 || pending != 0 {
		t.Errorf("retry when up: done=%d pending=%d", done, pending)
	}
	if pend, _ = models.ListFleetPendingDeletions(f.conn, 0); len(pend) != 0 {
		t.Errorf("queue not empty after convergence: %+v", pend)
	}
}

// Two source resources paired to the same target row (identity adoption): the
// row stays while another source still wants it.
func TestSharedTargetRowIsNotDeleted(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	enablePropagation(t, f, f.source, true)
	f.createProxy(t, "app.example.com", nil)
	src := f.proxyHosts(t, f.source)[0]
	tgt := f.proxyHosts(t, f.edge1)[0]
	// A second source row (id 999) is also paired to the same target row.
	if err := models.SaveFleetDeployment(f.conn, f.source, models.FleetResourceProxy, 999, f.edge1, tgt.ID); err != nil {
		t.Fatal(err)
	}
	f.deleteProxy(t, src.ID)
	if !hasDomain(f.proxyHosts(t, f.edge1), "app.example.com") {
		t.Error("a target row that another source resource is still paired with was deleted")
	}
}

func TestPendingDeletionHelpersAreScopedAndIdempotent(t *testing.T) {
	f := newL4Fleet(t)
	p := models.FleetPendingDeletion{SourceServerID: f.source, ResourceKind: models.FleetResourceProxy, SourceResourceID: 5, TargetServerID: f.edge1, TargetResourceID: 7, Label: "x"}
	for i := 0; i < 2; i++ {
		if err := models.EnqueueFleetPendingDeletion(f.conn, p); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := models.ListFleetPendingDeletions(f.conn, f.source); len(got) != 1 {
		t.Fatalf("enqueue twice -> %d rows, want 1", len(got))
	}
	if err := models.EnqueueFleetPendingDeletion(f.conn, models.FleetPendingDeletion{ResourceKind: models.FleetResourceCertificate}); err == nil {
		t.Error("certificates must not be queueable")
	}
	// A row can only be removed from the server it lives on.
	if ok, err := models.DeleteFleetResourceRow(f.conn, models.FleetResourceProxy, 1, f.edge2); err != nil || ok {
		t.Errorf("wrong-server delete: ok=%v err=%v", ok, err)
	}
	// Deleting the target server drops its queue entries.
	if err := models.DeleteCaddyServer(f.conn, f.edge1); err != nil {
		t.Fatal(err)
	}
	if got, _ := models.ListFleetPendingDeletions(f.conn, 0); len(got) != 0 {
		t.Errorf("%d queue entries outlived their target server", len(got))
	}
}

func TestServerFormSavesAndShowsPropagationAndPendingList(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)

	srvID := strconv.FormatInt(f.source, 10)
	form := url.Values{"name": {"Source"}, "admin_url": {"http://x"}, "type": {"managed"}, "default_deploy_targets": {strconv.FormatInt(f.edge1, 10)}, "propagate_deletions": {"1"}}
	rec := httptest.NewRecorder()
	f.s.updateServer(rec, withChiURLParam(cookieReq(t, "/servers/"+srvID, form, f.source), "id", srvID))
	if got, _ := models.GetCaddyServer(f.conn, f.source); got == nil || !got.PropagateDeletions {
		t.Fatalf("the checkbox was not saved (status %d: %s)", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
	form.Del("propagate_deletions")
	rec = httptest.NewRecorder()
	f.s.updateServer(rec, withChiURLParam(cookieReq(t, "/servers/"+srvID, form, f.source), "id", srvID))
	if got, _ := models.GetCaddyServer(f.conn, f.source); got.PropagateDeletions {
		t.Error("unticking the box did not turn propagation off")
	}

	_ = models.EnqueueFleetPendingDeletion(f.conn, models.FleetPendingDeletion{SourceServerID: f.source, ResourceKind: models.FleetResourceProxy, SourceResourceID: 5, TargetServerID: f.edge1, TargetResourceID: 7, Label: "stuck.example.com"})
	rec = httptest.NewRecorder()
	f.s.editServerPage(rec, withChiURLParam(cookieReq(t, "/servers/"+srvID+"/edit", nil, f.source), "id", srvID))
	body := rec.Body.String()
	for _, want := range []string{`name="propagate_deletions"`, "data-pending-deletions", "stuck.example.com", "pending-deletions/retry", "pending-deletions/discard"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit page is missing %q", want)
		}
	}

	rec = httptest.NewRecorder()
	dis := url.Values{"kind": {models.FleetResourceProxy}, "source_resource_id": {"5"}, "target_server_id": {strconv.FormatInt(f.edge1, 10)}}
	f.s.discardFleetPendingDeletion(rec, withChiURLParam(cookieReq(t, "/servers/"+srvID+"/pending-deletions/discard", dis, f.source), "id", srvID))
	if got, _ := models.ListFleetPendingDeletions(f.conn, f.source); len(got) != 0 {
		t.Errorf("discard left %d entries", len(got))
	}
}

func TestPendingDeletionControlsAreAdminOnly(t *testing.T) {
	e := newSecEnv(t)
	for _, p := range []string{"/servers/1/pending-deletions/retry", "/servers/1/pending-deletions/discard"} {
		for _, who := range []string{"alice", "viewer"} {
			if rec := e.do(t, who, http.MethodPost, p, url.Values{"kind": {"proxy"}}); rec.Code != http.StatusForbidden {
				t.Errorf("%s POST %s -> %d, want 403", who, p, rec.Code)
			}
		}
	}
}
