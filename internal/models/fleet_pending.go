// SPDX-License-Identifier: Apache-2.0

package models

import (
	"database/sql"
	"fmt"
	"time"
)

// FleetPendingDeletion is a paired fleet copy whose deletion was requested by
// its source server but whose target Caddy has not converged yet (v2.59.0,
// issue #120). The row survives until the target's sync succeeds, so an
// unreachable node does not make CaddyUI forget the pairing.
type FleetPendingDeletion struct {
	SourceServerID   int64
	ResourceKind     string
	SourceResourceID int64
	TargetServerID   int64
	TargetResourceID int64
	Label            string
	Attempts         int
	LastError        string
	LastAttemptAt    sql.NullTime
	CreatedAt        time.Time

	// TargetName is view state filled by ListFleetPendingDeletions.
	TargetName string
}

// fleetResourceTable maps a fleet resource kind to its table. Certificates are
// deliberately absent: they keep their own per-certificate targets.
func fleetResourceTable(kind string) (string, error) {
	switch kind {
	case FleetResourceProxy:
		return "proxy_hosts", nil
	case FleetResourceRedirect:
		return "redirection_hosts", nil
	case FleetResourceRawRoute:
		return "raw_routes", nil
	case FleetResourceLayer4:
		return "layer4_proxies", nil
	}
	return "", fmt.Errorf("fleet kind %q does not support deletion propagation", kind)
}

// FleetResourceServerID returns the server a resource row lives on, so a
// caller can note it before the row is deleted. 0 when the row is gone or the
// kind is not propagated.
func FleetResourceServerID(db *sql.DB, kind string, id int64) int64 {
	table, err := fleetResourceTable(kind)
	if err != nil || id <= 0 {
		return 0
	}
	var sid int64
	if err := db.QueryRow(`SELECT server_id FROM `+table+` WHERE id=?`, id).Scan(&sid); err != nil {
		return 0
	}
	return sid
}

// FleetDeploymentsForSource lists every target a source resource was deployed
// to, as target server ID -> target resource ID.
func FleetDeploymentsForSource(db *sql.DB, sourceServerID int64, kind string, sourceResourceID int64) (map[int64]int64, error) {
	rows, err := db.Query(`
		SELECT target_server_id, target_resource_id FROM fleet_deployments
		WHERE source_server_id=? AND resource_kind=? AND source_resource_id=?`,
		sourceServerID, kind, sourceResourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var tsid, trid int64
		if err := rows.Scan(&tsid, &trid); err != nil {
			return nil, err
		}
		out[tsid] = trid
	}
	return out, rows.Err()
}

// DeleteFleetDeploymentsForSource forgets every pairing of a source resource.
// Called when the source row is deleted so a reused row ID can never inherit a
// stale pairing.
func DeleteFleetDeploymentsForSource(db *sql.DB, sourceServerID int64, kind string, sourceResourceID int64) error {
	_, err := db.Exec(`DELETE FROM fleet_deployments WHERE source_server_id=? AND resource_kind=? AND source_resource_id=?`,
		sourceServerID, kind, sourceResourceID)
	return err
}

// EnqueueFleetPendingDeletion records a deletion to carry out on a target. It
// is idempotent: queueing the same pair again keeps the existing row.
func EnqueueFleetPendingDeletion(db *sql.DB, p FleetPendingDeletion) error {
	if _, err := fleetResourceTable(p.ResourceKind); err != nil {
		return err
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fleet_pending_deletions WHERE source_server_id=? AND resource_kind=? AND source_resource_id=? AND target_server_id=?`,
		p.SourceServerID, p.ResourceKind, p.SourceResourceID, p.TargetServerID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := db.Exec(`INSERT INTO fleet_pending_deletions
		(source_server_id, resource_kind, source_resource_id, target_server_id, target_resource_id, label, attempts, last_error)
		VALUES (?, ?, ?, ?, ?, ?, 0, '')`,
		p.SourceServerID, p.ResourceKind, p.SourceResourceID, p.TargetServerID, p.TargetResourceID, p.Label)
	return err
}

// ListFleetPendingDeletions returns the queue, oldest first. sourceServerID 0
// lists every source.
func ListFleetPendingDeletions(db *sql.DB, sourceServerID int64) ([]FleetPendingDeletion, error) {
	q := `SELECT p.source_server_id, p.resource_kind, p.source_resource_id, p.target_server_id, p.target_resource_id,
		COALESCE(p.label,''), p.attempts, COALESCE(p.last_error,''), p.last_attempt_at, p.created_at,
		COALESCE(c.name,'')
		FROM fleet_pending_deletions p LEFT JOIN caddy_servers c ON c.id = p.target_server_id`
	var args []any
	if sourceServerID > 0 {
		q += ` WHERE p.source_server_id=?`
		args = append(args, sourceServerID)
	}
	q += ` ORDER BY p.created_at, p.source_resource_id`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FleetPendingDeletion
	for rows.Next() {
		var p FleetPendingDeletion
		if err := rows.Scan(&p.SourceServerID, &p.ResourceKind, &p.SourceResourceID, &p.TargetServerID, &p.TargetResourceID,
			&p.Label, &p.Attempts, &p.LastError, &p.LastAttemptAt, &p.CreatedAt, &p.TargetName); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RecordFleetPendingAttempt notes a failed attempt.
func RecordFleetPendingAttempt(db *sql.DB, p FleetPendingDeletion, errMsg string) error {
	if len(errMsg) > 500 {
		errMsg = errMsg[:500]
	}
	_, err := db.Exec(`UPDATE fleet_pending_deletions SET attempts=attempts+1, last_error=?, last_attempt_at=CURRENT_TIMESTAMP
		WHERE source_server_id=? AND resource_kind=? AND source_resource_id=? AND target_server_id=?`,
		errMsg, p.SourceServerID, p.ResourceKind, p.SourceResourceID, p.TargetServerID)
	return err
}

// DeleteFleetPendingDeletion removes a queue entry (done, or discarded).
func DeleteFleetPendingDeletion(db *sql.DB, p FleetPendingDeletion) error {
	_, err := db.Exec(`DELETE FROM fleet_pending_deletions WHERE source_server_id=? AND resource_kind=? AND source_resource_id=? AND target_server_id=?`,
		p.SourceServerID, p.ResourceKind, p.SourceResourceID, p.TargetServerID)
	return err
}

// DeleteFleetPendingForServer drops every queue entry that involves a server
// that is being removed.
func DeleteFleetPendingForServer(db *sql.DB, serverID int64) error {
	_, err := db.Exec(`DELETE FROM fleet_pending_deletions WHERE source_server_id=? OR target_server_id=?`, serverID, serverID)
	return err
}

// DeleteFleetResourceRow deletes one resource row, but only if it lives on the
// expected server — a stale or wrong ID can never remove another server's row.
// Reports whether a row was removed.
func DeleteFleetResourceRow(db *sql.DB, kind string, id, serverID int64) (bool, error) {
	table, err := fleetResourceTable(kind)
	if err != nil {
		return false, err
	}
	res, err := db.Exec(`DELETE FROM `+table+` WHERE id=? AND server_id=?`, id, serverID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
