// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"

	"github.com/X4Applegate/caddyui/internal/models"
)

// canManageOwned is the single authorization gate for per-row resources
// (proxy hosts, redirection hosts, raw routes, certificates). It reports
// whether the current user may read, edit, toggle, or delete a row with the
// given owner.
//
// Rules (v2.52.5 — access-groups grant collaborative management, per Richard's
// decision on review finding #7):
//   - admins may manage any row;
//   - a user may manage rows they own;
//   - a user may manage rows owned by any user who shares an access-group with
//     them (so a shared row that is visible in a list is also manageable);
//   - NULL-owner (global / admin-owned) rows stay admin-only for non-admins.
//
// This mirrors the visibility scope used by the list queries
// (models.GroupPeerIDs), closing the "can see it but gets 403 opening it"
// asymmetry. Every single-object and bulk handler funnels through here so a
// future endpoint cannot drift out of sync.
func (s *Server) canManageOwned(cu *models.User, ownerID sql.NullInt64) bool {
	if cu == nil {
		return false
	}
	if cu.IsAdmin || cu.Role == models.RoleAdmin {
		return true
	}
	if !ownerID.Valid {
		return false
	}
	if ownerID.Int64 == cu.ID {
		return true
	}
	shared, err := models.UsersShareGroup(s.DB, cu.ID, ownerID.Int64)
	if err != nil {
		return false
	}
	return shared
}
