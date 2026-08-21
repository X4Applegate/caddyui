package server

import (
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.33.0: node-local resources.
//
// Fleet sync copies a proxy host's upstream verbatim to the target node. That
// is correct for edge replication — several Caddy nodes fronting the same
// backends — and wrong for federated nodes, where each Caddy fronts its own
// local stack and the upstream is a Docker service name or a VPN address that
// only resolves on the node that owns it. Marking a resource node-local keeps
// it on its node.

func TestFleetSyncSkipsNodeLocalResources(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)

	// One host that should travel, one pinned to this node.
	shared := &models.ProxyHost{
		Domains: "shared.example.com", ForwardScheme: "https",
		ForwardHost: "origin.example.com", ForwardPort: 443, Enabled: true,
	}
	if _, err := models.CreateProxyHost(s.DB, sourceServerID, 0, shared); err != nil {
		t.Fatal(err)
	}
	local := &models.ProxyHost{
		Domains: "photos.example.com", ForwardScheme: "http",
		ForwardHost: "immich_server", ForwardPort: 2283, Enabled: true, NodeLocal: true,
	}
	if _, err := models.CreateProxyHost(s.DB, sourceServerID, 0, local); err != nil {
		t.Fatal(err)
	}

	localRoute := &models.RawRoute{
		Label: "local-route", JSONData: `{"handle":[]}`, Enabled: true, NodeLocal: true,
	}
	if _, err := models.CreateRawRoute(s.DB, sourceServerID, 0, localRoute); err != nil {
		t.Fatal(err)
	}

	summary, err := s.syncFleetConfiguration("tester", sourceServerID, targetServerID)
	if err != nil {
		t.Fatal(err)
	}

	if summary.ProxiesCreated != 1 {
		t.Errorf("ProxiesCreated = %d, want 1 (only the shared host should travel)", summary.ProxiesCreated)
	}
	if summary.ProxiesSkipped != 1 {
		t.Errorf("ProxiesSkipped = %d, want 1", summary.ProxiesSkipped)
	}
	if summary.RawRoutesCreated != 0 {
		t.Errorf("RawRoutesCreated = %d, want 0", summary.RawRoutesCreated)
	}
	if summary.RawRoutesSkipped != 1 {
		t.Errorf("RawRoutesSkipped = %d, want 1", summary.RawRoutesSkipped)
	}

	// The target must hold the shared host and nothing node-local — the whole
	// point is that immich_server never appears on a node that can't resolve it.
	targets, err := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("target has %d proxy hosts, want 1", len(targets))
	}
	if targets[0].Domains != "shared.example.com" {
		t.Errorf("target host = %q, want shared.example.com", targets[0].Domains)
	}
	for _, h := range targets {
		if h.ForwardHost == "immich_server" {
			t.Error("a node-local host reached the target node")
		}
	}

	targetRoutes, err := models.ListRawRoutes(s.DB, targetServerID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targetRoutes) != 0 {
		t.Errorf("target has %d advanced routes, want 0", len(targetRoutes))
	}
}

// Skipped resources must be reported. An operator reading "1 added" needs to
// know another was deliberately left behind, not silently lost.
func TestFleetSyncSummaryReportsSkips(t *testing.T) {
	withSkips := fleetSyncSummary{ProxiesCreated: 1, ProxiesSkipped: 3, RawRoutesSkipped: 2}
	got := withSkips.String()
	if !strings.Contains(got, "skipped as node-local: 3 proxies, 2 advanced routes") {
		t.Errorf("summary does not report skips: %s", got)
	}

	// No skips, no noise.
	clean := fleetSyncSummary{ProxiesCreated: 1}
	if strings.Contains(clean.String(), "skipped as node-local") {
		t.Errorf("summary mentions skips when there were none: %s", clean.String())
	}
}

// "Also deploy to" must refuse a node-local resource too, otherwise the
// per-host form becomes a way around the flag.
func TestCrossDeployRefusesNodeLocal(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)

	local := &models.ProxyHost{
		Domains: "photos.example.com", ForwardScheme: "http",
		ForwardHost: "immich_server", ForwardPort: 2283, Enabled: true, NodeLocal: true,
	}
	id, err := models.CreateProxyHost(s.DB, sourceServerID, 0, local)
	if err != nil {
		t.Fatal(err)
	}
	local.ID = id
	s.crossDeployProxyHost("tester", sourceServerID, local, []int64{targetServerID})

	targets, err := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Errorf("cross-deploy pushed a node-local host: %d row(s) on target", len(targets))
	}

	rr := &models.RawRoute{Label: "local", JSONData: `{"handle":[]}`, Enabled: true, NodeLocal: true}
	rrID, err := models.CreateRawRoute(s.DB, sourceServerID, 0, rr)
	if err != nil {
		t.Fatal(err)
	}
	rr.ID = rrID
	s.crossDeployRawRoute("tester", sourceServerID, rr, []int64{targetServerID})

	targetRoutes, err := models.ListRawRoutes(s.DB, targetServerID, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(targetRoutes) != 0 {
		t.Errorf("cross-deploy pushed a node-local advanced route: %d row(s) on target", len(targetRoutes))
	}
}

// A host that isn't marked node-local must still sync — the flag is opt-in and
// must not change behaviour for anyone who never sets it.
func TestFleetSyncStillCopiesNormalHosts(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)

	normal := &models.ProxyHost{
		Domains: "app.example.com", ForwardScheme: "https",
		ForwardHost: "origin.example.com", ForwardPort: 443, Enabled: true,
	}
	if _, err := models.CreateProxyHost(s.DB, sourceServerID, 0, normal); err != nil {
		t.Fatal(err)
	}

	summary, err := s.syncFleetConfiguration("tester", sourceServerID, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ProxiesCreated != 1 || summary.ProxiesSkipped != 0 {
		t.Errorf("created=%d skipped=%d, want 1/0", summary.ProxiesCreated, summary.ProxiesSkipped)
	}
}
