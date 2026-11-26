// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// One-time upgrade migration of non-admin Advanced routes (issue #184
// round 11).
//
// An Advanced route stores the JSON Caddy adapted its Caddyfile text to,
// and the live sync deploys that JSON. Up to v2.68.16 the text was adapted
// with only some of the administrator's snippets put ahead of it — which
// ones depended on how a block splitter read the text, the paste around
// it and the administrator's Caddyfile — and an `import` of a snippet that
// was left out read a file of that name instead, into the stored JSON. No
// reading of the stored text can tell for sure which rows that happened
// to, so every such row is adapted again, once, the way a save adapts it
// today, and only the new JSON is kept.
//
// The rows concerned are the non-admin's Advanced routes whose Caddyfile
// text holds the word `import` (an `import` is the only way text reads a
// file at adapt time; {$…} is refused by the tenant rules on every sync),
// and those the paste import stored without any text: a block whose site
// has no host name could not be matched back to its text, so its row holds
// only the JSON the whole paste adapted to. The set is taken once, the
// first time this version reads it, and kept in the settings table; until
// a row has been migrated it is not deployed (fail closed): not on srv0,
// not on its own listener. The sync migrates the rows of the server it
// syncs, with that server's Caddy, before it builds the config:
//
//   - the text adapts under today's rules → its JSON is stored and the row
//     is deployed as before;
//   - the text is refused, by the tenant rules or by Caddy (a 400 from
//     /adapt), or adapts to another listen set, or the row has no text →
//     the row is disabled and its stored JSON cleared, with the reason in
//     the log and the activity log; the text is kept, so saving the row
//     again brings it back;
//   - Caddy cannot be reached (or answers anything but a result or a
//     400) → the row stays pending, and the next sync tries again.
//
// When no row is left, the migration is marked done and never runs again.

// settingTenantRawRouteMigration holds the migration's state: "done", or
// {"pending":[ids]}.
const settingTenantRawRouteMigration = "tenant_raw_route_migration_184"

// tenantRawMigration is the in-memory copy of the migration state.
type tenantRawMigration struct {
	loaded  bool
	done    bool
	pending map[int64]bool
}

// rawRouteMigrationPending reports whether the Advanced route id still
// waits for the migration, and so must not be deployed.
func (s *Server) rawRouteMigrationPending(id int64) bool {
	if s == nil || s.DB == nil {
		return false
	}
	s.rawMigMu.Lock()
	defer s.rawMigMu.Unlock()
	if err := s.loadRawRouteMigrationLocked(); err != nil {
		// The state cannot be read, so it cannot be told which rows are
		// safe: none of the candidates is deployed.
		log.Printf("advanced route migration: cannot read its state: %v", err)
		return true
	}
	return !s.rawMig.done && s.rawMig.pending[id]
}

// loadRawRouteMigrationLocked reads the state, taking the set of rows the
// first time this version runs. s.rawMigMu is held.
func (s *Server) loadRawRouteMigrationLocked() error {
	if s.rawMig.loaded {
		return nil
	}
	v, err := models.GetSetting(s.DB, settingTenantRawRouteMigration)
	if err != nil {
		return err
	}
	switch {
	case v == "done":
		s.rawMig = tenantRawMigration{loaded: true, done: true}
		return nil
	case v != "":
		var st struct {
			Pending []int64 `json:"pending"`
		}
		if err := json.Unmarshal([]byte(v), &st); err != nil {
			return fmt.Errorf("unreadable state %q: %w", v, err)
		}
		s.rawMig = tenantRawMigration{loaded: true, pending: map[int64]bool{}}
		for _, id := range st.Pending {
			s.rawMig.pending[id] = true
		}
		return nil
	}
	ids, err := s.rawRouteMigrationCandidates()
	if err != nil {
		return err
	}
	s.rawMig = tenantRawMigration{loaded: true, pending: map[int64]bool{}}
	for _, id := range ids {
		s.rawMig.pending[id] = true
	}
	if len(ids) > 0 {
		log.Printf("advanced route migration: %d non-admin Advanced route(s) will be adapted again before they are deployed (issue #184)", len(ids))
	}
	return s.saveRawRouteMigrationLocked()
}

// saveRawRouteMigrationLocked writes the state. s.rawMigMu is held.
func (s *Server) saveRawRouteMigrationLocked() error {
	if len(s.rawMig.pending) == 0 {
		s.rawMig.done = true
		return models.SetSetting(s.DB, settingTenantRawRouteMigration, "done")
	}
	ids := make([]int64, 0, len(s.rawMig.pending))
	for id := range s.rawMig.pending {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	b, _ := json.Marshal(map[string][]int64{"pending": ids})
	return models.SetSetting(s.DB, settingTenantRawRouteMigration, string(b))
}

// rawRouteMigrationCandidates returns the rows the migration covers; see
// the top of this file.
func (s *Server) rawRouteMigrationCandidates() ([]int64, error) {
	rows, err := s.DB.Query(`SELECT id, COALESCE(caddyfile_src, ''), COALESCE(owner_id, 0) FROM raw_routes`)
	if err != nil {
		return nil, err
	}
	type row struct {
		id    int64
		src   string
		owner int64
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.src, &r.owner); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var ids []int64
	for _, r := range all {
		owner := sql.NullInt64{Int64: r.owner, Valid: r.owner != 0}
		if !s.isTenantOwner(owner) {
			continue
		}
		if strings.Contains(r.src, "import") || strings.TrimSpace(r.src) == "" && pasteImportTextless(r.id, s.DB) {
			ids = append(ids, r.id)
		}
	}
	return ids, nil
}

// pasteImportTextless reports whether the row with no Caddyfile text was
// stored by the Caddyfile paste import: that importer labels a route it
// cannot match back to a block "route[N] (no host match)".
func pasteImportTextless(id int64, db *sql.DB) bool {
	var label string
	if err := db.QueryRow(`SELECT label FROM raw_routes WHERE id = ?`, id).Scan(&label); err != nil {
		return true // cannot tell: the safe reading
	}
	return strings.HasPrefix(label, "route[") && strings.HasSuffix(label, "(no host match)")
}

// migrateTenantRawRoutes runs the migration for the rows of serverID, with
// cl (that server's Caddy). It never fails the sync: a row it cannot
// migrate now stays pending, and is not deployed.
func (s *Server) migrateTenantRawRoutes(serverID int64, cl *caddy.Client) {
	if s == nil || s.DB == nil {
		return
	}
	s.rawMigMu.Lock()
	defer s.rawMigMu.Unlock()
	if err := s.loadRawRouteMigrationLocked(); err != nil {
		log.Printf("advanced route migration: cannot read its state: %v", err)
		return
	}
	if s.rawMig.done || len(s.rawMig.pending) == 0 {
		return
	}
	ids := make([]int64, 0, len(s.rawMig.pending))
	for id := range s.rawMig.pending {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	changed := false
	for _, id := range ids {
		var sid int64
		switch err := s.DB.QueryRow(`SELECT server_id FROM raw_routes WHERE id = ?`, id).Scan(&sid); {
		case errors.Is(err, sql.ErrNoRows):
			delete(s.rawMig.pending, id) // deleted since
			changed = true
			continue
		case err != nil:
			log.Printf("advanced route migration: route id=%d: %v", id, err)
			continue
		}
		if sid != serverID {
			continue
		}
		rr, err := models.GetRawRoute(s.DB, id)
		if err != nil {
			log.Printf("advanced route migration: route id=%d: %v", id, err)
			continue
		}
		if !s.isTenantOwner(rr.OwnerID) {
			// Now an administrator's: their rows are never restricted.
			delete(s.rawMig.pending, id)
			changed = true
			continue
		}
		jsonData, why, retry := s.readaptForMigration(*rr, cl)
		switch {
		case retry:
			log.Printf("advanced route migration: route id=%d: Caddy could not adapt it now (%s); it stays undeployed and is tried again on the next sync", id, why)
			continue
		case why != "":
			rr.Enabled = false
			rr.JSONData = "[]"
			if err := models.UpdateRawRoute(s.DB, rr); err != nil {
				log.Printf("advanced route migration: route id=%d: disable: %v", id, err)
				continue
			}
			log.Printf("advanced route migration: route id=%d (%q) disabled and its stored routes cleared: %s. Save it again to bring it back.", id, rr.Label, why)
			_ = models.LogActivity(s.DB, serverID, "system", "rawroute_migration_disabled", fmt.Sprintf("rr:%d", id), rr.Label+": "+why, false)
		default:
			rr.JSONData = jsonData
			if err := models.UpdateRawRoute(s.DB, rr); err != nil {
				log.Printf("advanced route migration: route id=%d: store: %v", id, err)
				continue
			}
			log.Printf("advanced route migration: route id=%d adapted again under the current rules", id)
		}
		delete(s.rawMig.pending, id)
		changed = true
	}
	if changed {
		if err := s.saveRawRouteMigrationLocked(); err != nil {
			log.Printf("advanced route migration: cannot save its state: %v", err)
		} else if s.rawMig.done {
			log.Printf("advanced route migration: done")
		}
	}
}

// readaptForMigration adapts a non-admin's Advanced route text the way a
// save does today. It returns the JSON to store; or why the row cannot be
// kept; or retry=true when Caddy could not be asked.
func (s *Server) readaptForMigration(rr models.RawRoute, cl *caddy.Client) (jsonData, why string, retry bool) {
	if strings.TrimSpace(rr.CaddyfileSrc) == "" {
		return "", "it was stored by the Caddyfile paste import without its Caddyfile text, so it cannot be adapted again", false
	}
	if msg := s.tenantRawRouteTextProblem(rr.CaddyfileSrc); msg != "" {
		return "", msg, false
	}
	tcl := s.tenantAdaptClient(cl)
	if tcl == nil {
		return "", "the Caddy adapter is unavailable", true
	}
	jsonData, listen, result, err := s.adaptRawRouteCaddyfileResult(tcl, rr.CaddyfileSrc)
	if err != nil {
		if caddy.IsCaddyfileRejected(err) || errors.Is(err, errClientAuthInRawRoute) || result != nil {
			return "", "its Caddyfile no longer adapts: " + err.Error(), false
		}
		return "", err.Error(), true
	}
	if listen != rr.Listen {
		return "", "its Caddyfile now adapts to other listen addresses than the stored route", false
	}
	if msg := s.tenantRawRouteAdaptedProblem(jsonData, listen, result); msg != "" {
		return "", msg, false
	}
	return jsonData, "", false
}

// runTenantRawRouteMigration syncs, shortly after startup and then every
// minute, each managed server that still has rows waiting for the
// migration: the sync migrates them first, then replaces whatever the
// live Caddy still carries from before the upgrade. It stops once no
// such row is left.
func (s *Server) runTenantRawRouteMigration() {
	time.Sleep(10 * time.Second)
	for {
		servers := s.rawRouteMigrationServers()
		if len(servers) == 0 {
			return
		}
		for _, sid := range servers {
			if err := s.syncCaddy(sid, false); err != nil {
				log.Printf("advanced route migration: sync of server %d: %v", sid, err)
			}
		}
		time.Sleep(time.Minute)
	}
}

// rawRouteMigrationServers returns the managed servers that hold rows
// still waiting for the migration.
func (s *Server) rawRouteMigrationServers() []int64 {
	s.rawMigMu.Lock()
	if err := s.loadRawRouteMigrationLocked(); err != nil {
		s.rawMigMu.Unlock()
		log.Printf("advanced route migration: cannot read its state: %v", err)
		return nil
	}
	ids := make([]int64, 0, len(s.rawMig.pending))
	for id := range s.rawMig.pending {
		ids = append(ids, id)
	}
	s.rawMigMu.Unlock()
	seen := map[int64]bool{}
	var out []int64
	for _, id := range ids {
		var sid int64
		if err := s.DB.QueryRow(`SELECT server_id FROM raw_routes WHERE id = ?`, id).Scan(&sid); err != nil || seen[sid] {
			continue
		}
		seen[sid] = true
		if srv, err := models.GetCaddyServer(s.DB, sid); err == nil && srv.Type != models.CaddyServerTypeExternal {
			out = append(out, sid)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
