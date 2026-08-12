package models

import (
	"database/sql"
	"fmt"
)

const (
	FleetResourceProxy       = "proxy"
	FleetResourceRedirect    = "redirect"
	FleetResourceRawRoute    = "raw_route"
	FleetResourceCertificate = "certificate"
)

// FleetDeploymentTarget returns the target-side row previously paired with a
// source resource. The mapping lets a later deployment update the same row even
// when an edit changed the resource's hostname, label, or certificate subjects.
func FleetDeploymentTarget(db *sql.DB, sourceServerID int64, resourceKind string, sourceResourceID, targetServerID int64) (int64, error) {
	var targetResourceID int64
	err := db.QueryRow(`
		SELECT target_resource_id
		FROM fleet_deployments
		WHERE source_server_id=? AND resource_kind=? AND source_resource_id=? AND target_server_id=?`,
		sourceServerID, resourceKind, sourceResourceID, targetServerID,
	).Scan(&targetResourceID)
	return targetResourceID, err
}

// SaveFleetDeployment stores a source-to-target pairing without relying on a
// database-specific UPSERT syntax. The update/insert/retry pattern is shared by
// SQLite and MariaDB and is safe if two requests establish the same mapping.
func SaveFleetDeployment(db *sql.DB, sourceServerID int64, resourceKind string, sourceResourceID, targetServerID, targetResourceID int64) error {
	if sourceServerID <= 0 || sourceResourceID <= 0 || targetServerID <= 0 || targetResourceID <= 0 {
		return fmt.Errorf("fleet deployment IDs must be positive")
	}
	result, err := db.Exec(`
		UPDATE fleet_deployments
		SET target_resource_id=?, updated_at=CURRENT_TIMESTAMP
		WHERE source_server_id=? AND resource_kind=? AND source_resource_id=? AND target_server_id=?`,
		targetResourceID, sourceServerID, resourceKind, sourceResourceID, targetServerID,
	)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		return nil
	}
	_, insertErr := db.Exec(`
		INSERT INTO fleet_deployments
			(source_server_id, resource_kind, source_resource_id, target_server_id, target_resource_id)
		VALUES (?, ?, ?, ?, ?)`,
		sourceServerID, resourceKind, sourceResourceID, targetServerID, targetResourceID,
	)
	if insertErr == nil {
		return nil
	}
	result, err = db.Exec(`
		UPDATE fleet_deployments
		SET target_resource_id=?, updated_at=CURRENT_TIMESTAMP
		WHERE source_server_id=? AND resource_kind=? AND source_resource_id=? AND target_server_id=?`,
		targetResourceID, sourceServerID, resourceKind, sourceResourceID, targetServerID,
	)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		return nil
	}
	return insertErr
}

// FleetDeploymentTargetExists verifies that a mapped row still exists on the
// intended target server. Target resources can be deleted independently; a
// stale mapping must fall back to identity matching or create a fresh copy.
func FleetDeploymentTargetExists(db *sql.DB, resourceKind string, resourceID, targetServerID int64) (bool, error) {
	var table string
	switch resourceKind {
	case FleetResourceProxy:
		table = "proxy_hosts"
	case FleetResourceRedirect:
		table = "redirection_hosts"
	case FleetResourceRawRoute:
		table = "raw_routes"
	case FleetResourceCertificate:
		table = "certificates"
	default:
		return false, fmt.Errorf("unknown fleet resource kind %q", resourceKind)
	}
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE id=? AND server_id=?`, resourceID, targetServerID).Scan(&count)
	return count > 0, err
}

func DeleteFleetDeploymentsForServer(db *sql.DB, serverID int64) error {
	_, err := db.Exec(`DELETE FROM fleet_deployments WHERE source_server_id=? OR target_server_id=?`, serverID, serverID)
	return err
}
