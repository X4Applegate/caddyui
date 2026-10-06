// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.59.0 (issue #120): opt-in deletion propagation for a source server's
// automatic deployment targets.
//
// When CaddyServer.PropagateDeletions is on, deleting a proxy host, redirection,
// advanced route or Layer4 proxy on the source also deletes the paired copies
// it previously deployed to the source's *current* DefaultDeployTargets — and
// only those copies. A target-local resource, one created independently on the
// target, a copy on a one-off "Also deploy to" server that is not an automatic
// target, and a row another source resource is still paired with are never
// touched.
//
// The pairing is not forgotten when a target cannot be reached: each deletion
// becomes a fleet_pending_deletions row that stays until the target's Caddy has
// converged, and a background reconciler retries it.

const fleetDeletionRetryEvery = time.Minute

// fleetKindLabel is the Activity Log / UI word for a resource kind.
func fleetKindLabel(kind string) string {
	switch kind {
	case models.FleetResourceProxy:
		return "proxy host"
	case models.FleetResourceRedirect:
		return "redirection"
	case models.FleetResourceRawRoute:
		return "advanced route"
	case models.FleetResourceLayer4:
		return "Layer4 proxy"
	}
	return kind
}

// propagateFleetDeletion is called after a source resource row has been
// deleted. It always forgets the source row's pairings (so a reused row ID can
// never inherit one); when the source has deletion propagation enabled it also
// queues and attempts the deletion of each paired copy on an automatic target.
// sourceServerID must be the server the row lived on (noted before deleting
// it); 0 means unknown and is a no-op.
func (s *Server) propagateFleetDeletion(actor string, sourceServerID int64, kind string, sourceID int64, label string) {
	if sourceServerID <= 0 || sourceID <= 0 {
		return
	}
	targets, err := models.FleetDeploymentsForSource(s.DB, sourceServerID, kind, sourceID)
	if err != nil {
		log.Printf("fleet deletion: list pairings for %s %d: %v", kind, sourceID, err)
		return
	}
	if len(targets) == 0 {
		return
	}
	if err := models.DeleteFleetDeploymentsForSource(s.DB, sourceServerID, kind, sourceID); err != nil {
		log.Printf("fleet deletion: forget pairings for %s %d: %v", kind, sourceID, err)
	}
	src, err := models.GetCaddyServer(s.DB, sourceServerID)
	if err != nil || src == nil || !src.PropagateDeletions {
		return
	}
	automatic := src.DefaultDeployTargetSet()
	queued := false
	for targetServerID, targetResourceID := range targets {
		if !automatic[targetServerID] {
			continue // a one-off "Also deploy to" copy: not ours to remove
		}
		// Another source resource still pairs with this very row (identity
		// adoption): it is still wanted, so leave it.
		if shared, err := fleetTargetStillPaired(s, kind, targetServerID, targetResourceID); err != nil || shared {
			continue
		}
		if err := models.EnqueueFleetPendingDeletion(s.DB, models.FleetPendingDeletion{
			SourceServerID: sourceServerID, ResourceKind: kind, SourceResourceID: sourceID,
			TargetServerID: targetServerID, TargetResourceID: targetResourceID, Label: label,
		}); err != nil {
			log.Printf("fleet deletion: queue %s %d -> server %d: %v", kind, sourceID, targetServerID, err)
			continue
		}
		queued = true
	}
	if queued {
		s.processFleetPendingDeletions(actor, sourceServerID)
	}
}

// fleetTargetStillPaired reports whether any fleet_deployments row still points
// at the given target row.
func fleetTargetStillPaired(s *Server, kind string, targetServerID, targetResourceID int64) (bool, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM fleet_deployments WHERE resource_kind=? AND target_server_id=? AND target_resource_id=?`,
		kind, targetServerID, targetResourceID).Scan(&n)
	return n > 0, err
}

// processFleetPendingDeletions attempts every queued deletion (of one source,
// or of all when sourceServerID is 0) and reports how many finished and how
// many are still pending.
func (s *Server) processFleetPendingDeletions(actor string, sourceServerID int64) (done, pending int) {
	items, err := models.ListFleetPendingDeletions(s.DB, sourceServerID)
	if err != nil {
		log.Printf("fleet deletion: list queue: %v", err)
		return 0, 0
	}
	for _, p := range items {
		if err := s.attemptFleetPendingDeletion(actor, p); err != nil {
			pending++
			continue
		}
		done++
	}
	return done, pending
}

// attemptFleetPendingDeletion removes one paired copy from the target's DB and
// pushes the target's Caddy. It returns nil only when the target has converged
// (or the target server no longer exists); any failure leaves the queue entry
// in place with the error recorded.
func (s *Server) attemptFleetPendingDeletion(actor string, p models.FleetPendingDeletion) error {
	s.fleetDeployMu.Lock()
	defer s.fleetDeployMu.Unlock()

	fail := func(err error) error {
		_ = models.RecordFleetPendingAttempt(s.DB, p, err.Error())
		_ = models.LogActivity(s.DB, p.TargetServerID, actor, "fleet_delete_pending", fmt.Sprintf("%s:%d", p.ResourceKind, p.TargetResourceID),
			fmt.Sprintf("%s %q: %v (will retry)", fleetKindLabel(p.ResourceKind), p.Label, err), false)
		return err
	}

	target, err := models.GetCaddyServer(s.DB, p.TargetServerID)
	if err != nil || target == nil {
		_ = models.DeleteFleetPendingDeletion(s.DB, p) // the target server was removed
		return nil
	}

	forceTLS := false
	exists, err := models.FleetDeploymentTargetExists(s.DB, p.ResourceKind, p.TargetResourceID, p.TargetServerID)
	if err != nil {
		return fail(err)
	}
	if exists {
		forceTLS = s.cleanupFleetCopy(p)
		if _, err := models.DeleteFleetResourceRow(s.DB, p.ResourceKind, p.TargetResourceID, p.TargetServerID); err != nil {
			return fail(err)
		}
	}
	if s.syncHoldFor(p.TargetServerID) != nil {
		return fail(fmt.Errorf("syncing %s is held after failed post-apply checks", target.Name))
	}
	// allowEmpty: if this was the target's last resource, the live Caddy must
	// converge to the empty state too, not keep serving the deleted route.
	if err := s.syncCaddyOpts(p.TargetServerID, forceTLS, true); err != nil {
		return fail(err)
	}
	_ = models.DeleteFleetPendingDeletion(s.DB, p)
	_ = models.LogActivity(s.DB, p.TargetServerID, actor, "fleet_delete", fmt.Sprintf("%s:%d", p.ResourceKind, p.TargetResourceID),
		fmt.Sprintf("deleted %s %q (source deleted it)", fleetKindLabel(p.ResourceKind), p.Label), true)
	return nil
}

// cleanupFleetCopy drops the managed DNS record of a copy about to be deleted,
// exactly as deleting that row by hand would, and reports whether it used a
// custom certificate (so the TLS section is rebuilt on the next sync).
func (s *Server) cleanupFleetCopy(p models.FleetPendingDeletion) (forceTLS bool) {
	switch p.ResourceKind {
	case models.FleetResourceProxy:
		if old, _ := models.GetProxyHost(s.DB, p.TargetResourceID); old != nil {
			s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
			return old.CertificateID != 0
		}
	case models.FleetResourceRedirect:
		if old, _ := models.GetRedirectionHost(s.DB, p.TargetResourceID); old != nil {
			s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
			return old.CertificateID != 0
		}
	case models.FleetResourceRawRoute:
		if old, _ := models.GetRawRoute(s.DB, p.TargetResourceID); old != nil {
			s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
			return old.CertificateID != 0
		}
	}
	return false
}

// runFleetDeletionReconciler retries queued deletions until their targets
// converge. Cheap when the queue is empty (one small query per tick).
func (s *Server) runFleetDeletionReconciler() {
	time.Sleep(30 * time.Second)
	ticker := time.NewTicker(fleetDeletionRetryEvery)
	defer ticker.Stop()
	for {
		if items, err := models.ListFleetPendingDeletions(s.DB, 0); err == nil && len(items) > 0 {
			done, pending := s.processFleetPendingDeletions("system", 0)
			log.Printf("fleet deletion reconcile: %d finished, %d still pending", done, pending)
		}
		<-ticker.C
	}
}

// retryFleetPendingDeletions is the "Retry now" button on the server edit page.
func (s *Server) retryFleetPendingDeletions(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	done, pending := s.processFleetPendingDeletions(s.currentUserEmail(r), id)
	msg := fmt.Sprintf("Retried pending deletions: %d finished, %d still pending.", done, pending)
	http.Redirect(w, r, "/servers/"+strconv.FormatInt(id, 10)+"/edit?flash="+urlQueryEscape(msg), http.StatusSeeOther)
}

// discardFleetPendingDeletion forgets one queued deletion without doing it —
// for a target that is gone for good. The copy, if it still exists, stays.
func (s *Server) discardFleetPendingDeletion(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	_ = r.ParseForm()
	kind := r.FormValue("kind")
	srcRes, _ := strconv.ParseInt(r.FormValue("source_resource_id"), 10, 64)
	tgt, _ := strconv.ParseInt(r.FormValue("target_server_id"), 10, 64)
	if err := models.DeleteFleetPendingDeletion(s.DB, models.FleetPendingDeletion{
		SourceServerID: id, ResourceKind: kind, SourceResourceID: srcRes, TargetServerID: tgt,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, id, s.currentUserEmail(r), "fleet_delete_discarded", fmt.Sprintf("%s:%d", kind, srcRes), "pending deletion discarded", true)
	http.Redirect(w, r, "/servers/"+strconv.FormatInt(id, 10)+"/edit", http.StatusSeeOther)
}

// fleetDeletionNote remembers, before a resource row is deleted, which server
// it lived on — the row is gone by the time the deletion is propagated.
type fleetDeletionNote struct {
	serverID int64
	kind     string
	id       int64
	label    string
}

func (s *Server) noteFleetDeletion(kind string, id int64, label string) fleetDeletionNote {
	return fleetDeletionNote{serverID: models.FleetResourceServerID(s.DB, kind, id), kind: kind, id: id, label: label}
}

func (s *Server) propagateNotedDeletion(actor string, n fleetDeletionNote) {
	s.propagateFleetDeletion(actor, n.serverID, n.kind, n.id, n.label)
}
