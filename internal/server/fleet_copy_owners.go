// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Fleet copies of non-admin rows (one-time repair).
//
// Up to v2.68.17, "Also deploy to" created the copy of a proxy host,
// redirection or Advanced route on the target server without an owner —
// as the administrator's — whoever owned the source. Such a copy escaped
// every rule for non-admin rows on the target: the sync-time route guard,
// the upgrade check of #184 and the export's checks. Copies are now made
// for the source row's owner (upsertFleet*). This repairs the copies made
// before: once, at start-up, every copy whose source row belongs to a
// non-admin account and that still has no owner (as the old code left it;
// a copy an administrator gave to someone since is left alone) is given to
// that account, so the rules apply to it from
// the next sync on. An Advanced-route copy whose routes, Caddyfile or listen
// set no longer match its source's is also disabled: its routes were never
// checked under the current rules (the source's may have been held by the
// #184 upgrade check since). Saving the source again, with the target still
// selected, deploys a fresh copy.

const settingFleetCopyOwnersRepaired = "fleet_copy_owners_repaired"

// repairFleetCopyOwners runs the repair once; it records that it ran only
// when every copy was handled, so a failure is retried at the next start.
func (s *Server) repairFleetCopyOwners() {
	if s == nil || s.DB == nil {
		return
	}
	if v, _ := models.GetSetting(s.DB, settingFleetCopyOwnersRepaired); v == "1" {
		return
	}
	owned, disabled, err := s.repairFleetCopyOwnersOnce()
	if err != nil {
		log.Printf("fleet copies: could not give copies of non-admin rows to their owners (retried at the next start): %v", err)
		return
	}
	if owned > 0 {
		log.Printf("fleet copies: %d copy/copies of non-admin rows on other servers given to the source row's owner; %d Advanced-route copy/copies disabled because they no longer match their source", owned, disabled)
	}
	_ = models.SetSetting(s.DB, settingFleetCopyOwnersRepaired, "1")
}

type fleetCopy struct {
	sourceServer, sourceID, targetServer, targetID int64
	kind                                           string
}

func (s *Server) repairFleetCopyOwnersOnce() (owned, disabled int, err error) {
	rows, err := s.DB.Query(`SELECT source_server_id, resource_kind, source_resource_id, target_server_id, target_resource_id
		FROM fleet_deployments WHERE resource_kind IN (?, ?, ?)`,
		models.FleetResourceProxy, models.FleetResourceRedirect, models.FleetResourceRawRoute)
	if err != nil {
		return 0, 0, err
	}
	var copies []fleetCopy
	for rows.Next() {
		var c fleetCopy
		if err := rows.Scan(&c.sourceServer, &c.kind, &c.sourceID, &c.targetServer, &c.targetID); err != nil {
			_ = rows.Close()
			return 0, 0, err
		}
		copies = append(copies, c)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}
	for _, c := range copies {
		o, d, err := s.repairFleetCopy(c)
		if err != nil {
			return owned, disabled, fmt.Errorf("%s %d on server %d: %w", c.kind, c.targetID, c.targetServer, err)
		}
		if o {
			owned++
		}
		if d {
			disabled++
		}
	}
	return owned, disabled, nil
}

// repairFleetCopy handles one copy. A source or copy that no longer exists
// is skipped.
func (s *Server) repairFleetCopy(c fleetCopy) (owned, disabled bool, err error) {
	var srcOwner, dstOwner sql.NullInt64
	switch c.kind {
	case models.FleetResourceProxy:
		src, e1 := models.GetProxyHost(s.DB, c.sourceID)
		dst, e2 := models.GetProxyHost(s.DB, c.targetID)
		if e1 != nil || e2 != nil || src == nil || dst == nil || dst.ServerID != c.targetServer {
			return false, false, nil
		}
		srcOwner, dstOwner = src.OwnerID, dst.OwnerID
		if !s.isTenantOwner(srcOwner) || dstOwner.Valid {
			return false, false, nil
		}
		err = models.SetProxyHostOwner(s.DB, dst.ID, srcOwner.Int64)
	case models.FleetResourceRedirect:
		src, e1 := models.GetRedirectionHost(s.DB, c.sourceID)
		dst, e2 := models.GetRedirectionHost(s.DB, c.targetID)
		if e1 != nil || e2 != nil || src == nil || dst == nil {
			return false, false, nil
		}
		if sid, err := s.claimServerID(claimRedirect, dst.ID, 0); err != nil || sid != c.targetServer {
			return false, false, nil
		}
		srcOwner, dstOwner = src.OwnerID, dst.OwnerID
		if !s.isTenantOwner(srcOwner) || dstOwner.Valid {
			return false, false, nil
		}
		err = models.SetRedirectionHostOwner(s.DB, dst.ID, srcOwner.Int64)
	case models.FleetResourceRawRoute:
		src, e1 := models.GetRawRoute(s.DB, c.sourceID)
		dst, e2 := models.GetRawRoute(s.DB, c.targetID)
		if e1 != nil || e2 != nil || src == nil || dst == nil {
			return false, false, nil
		}
		if sid, err := models.RawRouteServerID(s.DB, dst.ID); err != nil || sid != c.targetServer {
			return false, false, nil
		}
		srcOwner, dstOwner = src.OwnerID, dst.OwnerID
		if !s.isTenantOwner(srcOwner) || dstOwner.Valid {
			return false, false, nil
		}
		if err = models.SetRawRouteOwner(s.DB, dst.ID, srcOwner.Int64); err != nil {
			return false, false, err
		}
		if dst.Enabled && (!jsonEqual(dst.JSONData, src.JSONData) || dst.CaddyfileSrc != src.CaddyfileSrc || dst.Listen != src.Listen || s.rawRouteMigrationBlocks(*src)) {
			if _, err = s.DB.Exec(`UPDATE raw_routes SET enabled = 0 WHERE id = ?`, dst.ID); err != nil {
				return true, false, err
			}
			_ = models.LogActivity(s.DB, c.targetServer, "system", "raw_fleet_copy_held", fmt.Sprintf("raw:%d", dst.ID),
				fmt.Sprintf("copy of advanced route %d disabled: it no longer matches its source; save the source again to deploy a fresh copy", src.ID), false)
			disabled = true
		}
	default:
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, disabled, nil
}
