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
// round 11, reworked in round 12).
//
// An Advanced route stores the JSON Caddy adapted its Caddyfile text to,
// and the live sync deploys that JSON. Up to v2.68.16 the text was adapted
// with only some of the administrator's snippets put ahead of it — which
// ones depended on how a block splitter read the text, the paste around
// it and the administrator's Caddyfile — and an `import` of a snippet that
// was left out read a file of that name instead, into the stored JSON. No
// reading of the stored text can tell for sure which rows that happened
// to, so every such row is adapted again, once, the way a save adapts it
// today, and kept only when that gives exactly its stored routes (round
// 13; round 12 stored the new JSON instead).
//
// The rows concerned (issue #184 round 13) are every non-admin Advanced
// route an earlier version stored — the rules_184 column marks the rows
// this version wrote, which are never taken. Up to round 12 only rows
// whose text held the word `import`, and rows with no text, were taken;
// but a row's stored routes need not match its text at all (the paste
// import could store routes another block of the paste produced, and a
// carriage return inside the word hides `import` from a substring test),
// so the text alone cannot clear a row.
//
// The set is taken the first time this version reads it, and kept in the
// settings table; until a row has been migrated it is not deployed (fail
// closed): not on srv0, not on its own listener, not copied by a fleet
// sync. Each sync migrates the rows of the server it syncs, with that
// server's Caddy, before it builds the config (outside the sync lock:
// adapting may take seconds per row):
//
//   - the text adapts under today's rules to exactly the stored routes →
//     the row is kept (and marked) and deployed as before;
//   - the stored routes differ from what the text adapts to now, the text
//     is refused for what it is — by the tenant rules on its own, or by
//     Caddy (a 400 from /adapt) — or it adapts to another listen set or to
//     more routes than a non-admin may store → the row is disabled and
//     its stored routes cleared, with the reason in the log and the
//     activity log; the text is kept, so saving the row again brings it
//     back, and the cleared routes are kept in held_json for an
//     administrator (GET /api/v1/raw-routes/{id}/held-json), who may
//     restore them;
//   - the row has no text (the paste import's text-less rows, JSON-only
//     rows made through the API) → it is held the same way, its routes
//     kept for an administrator;
//   - the text is refused because of the administrator's Caddyfile (a
//     snippet it imports is missing, unreadable, renamed or withheld), or
//     Caddy cannot be reached (or answers anything but a result or a 400)
//     → the row stays pending, and is tried again later; a row that is
//     still refused because of the administrator's snippets after
//     rawMigSnippetRuns runs and rawMigSnippetGrace is held (issue #184
//     round 14: "held: snippet unavailable"), so it is not tried again
//     every half hour for ever;
//   - the row changed while it was being adapted → nothing is written; it
//     stays pending unless the change was a save that adapted it under
//     today's rules (rawRouteMigrationSaved).
//
// When no row is left, the migration is marked done and never runs again.

// settingTenantRawRouteMigration holds the migration's state: "done", or
// {"pending":[ids]}.
const settingTenantRawRouteMigration = "tenant_raw_route_migration_184"

// rawMigMaxStrikes is how many runs may see one row break the connection
// to Caddy while Caddy answers otherwise, before the row is held (issue
// #184 round 12): text that crashes Caddy's parser is not retried for
// ever.
const rawMigMaxStrikes = 5

// rawMigSnippetRuns and rawMigSnippetGrace bound how long a row waits
// only because the administrator's snippets do not allow its text (issue
// #184 round 14): one that is still refused for that after this many runs
// and this long is held, as any refused row is, instead of being tried
// again every half hour for ever. The administrator's Caddyfile being
// unreadable for a moment at start-up does not hold anything.
const rawMigSnippetRuns = 4

var rawMigSnippetGrace = time.Hour

// rawMigProbeText is what the migration adapts to tell whether Caddy
// answers at all.
const rawMigProbeText = "http://caddyui-probe.invalid {\n\trespond 204\n}\n"

// tenantRawMigration is the in-memory copy of the migration state.
type tenantRawMigration struct {
	loaded  bool
	done    bool
	pending map[int64]bool
	// lastWhy is the last reason logged per row that stays pending, so
	// the log only says it again when it changes.
	lastWhy map[int64]string
	// strikes counts, per row, the runs in which adapting it failed to
	// reach Caddy while another row adapted.
	strikes map[int64]int
	// snippetWaits counts, per row, the runs in which only the
	// administrator's snippets kept it pending, and snippetSince is when
	// the first of them was (issue #184 round 14).
	snippetWaits map[int64]int
	snippetSince map[int64]time.Time
	// unreadable is set once a corrupt state has been logged.
	unreadable bool
	// everPending is set once this process has seen a row waiting (issue
	// #184 round 13): from then on a copy of a row read before the
	// migration or a save cleared it may be stale (rawRouteMigrationBlocks).
	everPending bool
}

// rawRouteMigrationShape reports whether a row is one the migration may
// cover: any non-admin's Advanced route (issue #184 round 13 — up to round
// 12 only rows whose text held `import`, or no text; but a row's stored
// routes need not match its text at all, whatever the text says).
func (s *Server) rawRouteMigrationShape(rr models.RawRoute) bool {
	return s.isTenantOwner(rr.OwnerID)
}

// rawRouteMigrationBlocks reports whether rr, a copy of a row read from
// the database, must not be deployed now: the row still waits for the
// migration, or (issue #184 round 13) the copy may predate the write that
// let it go. The migration and a save write the row first and only then
// clear it from the pending set, so a copy read before that write can be
// found not pending afterwards and still hold the routes stored before
// the upgrade; it is compared with the row as stored now. Design choice:
// this re-read, rather than taking the sync lock for the migration's
// writes, also covers the fleet copy and the save path, which do not run
// under that lock. A row that changed is left out of this sync; the sync
// of the write that changed it (the migration's own, or the save's)
// deploys it.
func (s *Server) rawRouteMigrationBlocks(rr models.RawRoute) bool {
	if s.rawRouteMigrationPending(rr) {
		return true
	}
	if s == nil || s.DB == nil || !s.rawRouteMigrationShape(rr) {
		return false
	}
	s.rawMigMu.Lock()
	ever := s.rawMig.everPending
	s.rawMigMu.Unlock()
	if !ever {
		return false
	}
	cur, err := models.GetRawRoute(s.DB, rr.ID)
	if err != nil || cur == nil {
		return true
	}
	return cur.JSONData != rr.JSONData || cur.CaddyfileSrc != rr.CaddyfileSrc || cur.Enabled != rr.Enabled || cur.Listen != rr.Listen
}

// rawRouteMigrationPending reports whether the Advanced route still waits
// for the migration, and so must not be deployed.
func (s *Server) rawRouteMigrationPending(rr models.RawRoute) bool {
	if s == nil || s.DB == nil || !s.rawRouteMigrationShape(rr) {
		return false
	}
	s.rawMigMu.Lock()
	defer s.rawMigMu.Unlock()
	if err := s.loadRawRouteMigrationLocked(); err != nil {
		// The database cannot be read now, so it cannot be told whether
		// this row is safe: it is not deployed.
		log.Printf("advanced route migration: cannot read its state: %v", err)
		return true
	}
	return !s.rawMig.done && s.rawMig.pending[rr.ID]
}

// rawRouteMigrationSaved notes that the Advanced route id was saved again
// through a path that adapts its text under today's rules (or replaced its
// JSON with new JSON), so the migration has nothing left to do for it.
func (s *Server) rawRouteMigrationSaved(id int64) {
	if s == nil || s.DB == nil {
		return
	}
	// Issue #184 round 13: the row is marked as written under today's
	// rules, so a state rebuild never takes it again.
	if err := models.MarkRawRouteCurrent(s.DB, id); err != nil {
		log.Printf("advanced route migration: route id=%d: %v", id, err)
	}
	s.rawMigMu.Lock()
	defer s.rawMigMu.Unlock()
	if err := s.loadRawRouteMigrationLocked(); err != nil || s.rawMig.done || !s.rawMig.pending[id] {
		return
	}
	delete(s.rawMig.pending, id)
	if err := s.saveRawRouteMigrationLocked(); err != nil {
		log.Printf("advanced route migration: cannot save its state: %v", err)
	}
}

// loadRawRouteMigrationLocked reads the state, taking the set of rows the
// first time this version runs. A state that cannot be read is logged
// once and taken again from the database (issue #184 round 12): every row
// the migration covers is adapted again, which is safe for a row already
// migrated. s.rawMigMu is held.
func (s *Server) loadRawRouteMigrationLocked() error {
	if s.rawMig.loaded {
		return nil
	}
	v, err := models.GetSetting(s.DB, settingTenantRawRouteMigration)
	if err != nil {
		return err
	}
	keep := s.rawMig
	fresh := func() tenantRawMigration {
		return tenantRawMigration{loaded: true, pending: map[int64]bool{}, lastWhy: keep.lastWhy, strikes: keep.strikes, unreadable: keep.unreadable,
			snippetWaits: keep.snippetWaits, snippetSince: keep.snippetSince}
	}
	switch {
	case v == "done":
		s.rawMig = fresh()
		s.rawMig.done = true
		s.rawMig.everPending = keep.everPending
		return nil
	case v != "":
		var st struct {
			Pending []int64 `json:"pending"`
		}
		if err := json.Unmarshal([]byte(v), &st); err == nil {
			s.rawMig = fresh()
			for _, id := range st.Pending {
				s.rawMig.pending[id] = true
			}
			s.rawMig.everPending = keep.everPending || len(st.Pending) > 0
			return nil
		} else if !keep.unreadable {
			log.Printf("advanced route migration: its saved state is unreadable (%v); the rows it covers are taken again from the database", err)
			keep.unreadable = true
		}
	}
	ids, err := s.rawRouteMigrationCandidates()
	if err != nil {
		return err
	}
	s.rawMig = fresh()
	for _, id := range ids {
		s.rawMig.pending[id] = true
	}
	s.rawMig.everPending = keep.everPending || len(ids) > 0
	if len(ids) > 0 {
		log.Printf("advanced route migration: %d non-admin Advanced route(s) will be adapted again, or held, before they are deployed (issue #184)", len(ids))
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
// the top of this file. A row this version wrote (rules_184) is never
// one (issue #184 round 13): a state rebuild must not take a row created
// or saved again under today's rules — a JSON-only row made through the
// API, for one — for a row stored before the upgrade.
func (s *Server) rawRouteMigrationCandidates() ([]int64, error) {
	rows, err := s.DB.Query(`SELECT id, COALESCE(caddyfile_src, ''), COALESCE(owner_id, 0) FROM raw_routes WHERE COALESCE(rules_184, 0) = 0`)
	if err != nil {
		return nil, err
	}
	var all []models.RawRoute
	for rows.Next() {
		var r models.RawRoute
		var owner int64
		if err := rows.Scan(&r.ID, &r.CaddyfileSrc, &owner); err != nil {
			rows.Close()
			return nil, err
		}
		r.OwnerID = sql.NullInt64{Int64: owner, Valid: owner != 0}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var ids []int64
	for _, r := range all {
		if s.rawRouteMigrationShape(r) {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

// rawMigOutcome is what adapting one row again came to.
type rawMigOutcome int

const (
	rawMigStore rawMigOutcome = iota // store the new JSON
	rawMigHold                       // disable the row, clear its JSON
	rawMigRetry                      // leave it pending
)

// migrateTenantRawRoutes runs the migration for the rows of serverID, with
// cl (that server's Caddy). It never fails the sync: a row it cannot
// migrate now stays pending, and is not deployed. It reports whether a
// row still waits.
func (s *Server) migrateTenantRawRoutes(serverID int64, cl *caddy.Client) bool {
	if s == nil || s.DB == nil {
		return false
	}
	// A run already in progress (another sync's) is not waited for: the
	// rows it has not finished stay undeployed, and the retry loop comes
	// back to them.
	if !s.rawMigRunMu.TryLock() {
		return true
	}
	defer s.rawMigRunMu.Unlock()
	s.rawMigMu.Lock()
	if err := s.loadRawRouteMigrationLocked(); err != nil {
		s.rawMigMu.Unlock()
		log.Printf("advanced route migration: cannot read its state: %v", err)
		return true
	}
	ids := make([]int64, 0, len(s.rawMig.pending))
	for id := range s.rawMig.pending {
		ids = append(ids, id)
	}
	s.rawMigMu.Unlock()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	type pendingRow struct {
		rr   models.RawRoute
		out  rawMigOutcome
		json string
		why  string
		// broke is set when adapting the row lost the connection to Caddy.
		broke bool
		// snippets is set when only the administrator's snippets keep
		// the row pending.
		snippets bool
	}
	var work []pendingRow
	drop := map[int64]bool{}
	reached := false // Caddy answered for at least one row
	for _, id := range ids {
		var sid int64
		switch err := s.DB.QueryRow(`SELECT server_id FROM raw_routes WHERE id = ?`, id).Scan(&sid); {
		case errors.Is(err, sql.ErrNoRows):
			drop[id] = true // deleted since
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
			drop[id] = true
			continue
		}
		jsonData, why, out, answered := s.readaptForMigration(*rr, cl)
		row := pendingRow{rr: *rr, out: out, json: jsonData, why: why}
		if out == rawMigRetry {
			row.broke = cl != nil && caddyConnectionLost(why)
			row.snippets = strings.HasPrefix(why, rawMigSnippetWhy)
		}
		reached = reached || answered
		work = append(work, row)
	}

	// A row that broke the connection, in a run where no other row was
	// answered: ask Caddy something harmless, to tell a row that breaks
	// Caddy's adapter from Caddy being down.
	if !reached && cl != nil {
		for _, w := range work {
			if w.broke {
				_, err := cl.Adapt(rawMigProbeText)
				reached = err == nil || caddy.IsCaddyfileRejected(err)
				break
			}
		}
	}

	s.rawMigMu.Lock()
	defer s.rawMigMu.Unlock()
	if s.rawMig.strikes == nil {
		s.rawMig.strikes = map[int64]int{}
	}
	if s.rawMig.lastWhy == nil {
		s.rawMig.lastWhy = map[int64]string{}
	}
	if s.rawMig.snippetWaits == nil {
		s.rawMig.snippetWaits = map[int64]int{}
		s.rawMig.snippetSince = map[int64]time.Time{}
	}
	changed := false
	for id := range drop {
		if s.rawMig.pending[id] {
			delete(s.rawMig.pending, id)
			changed = true
		}
	}
	for _, w := range work {
		id := w.rr.ID
		if !s.rawMig.pending[id] {
			continue // saved again meanwhile (rawRouteMigrationSaved)
		}
		out, why := w.out, w.why
		if out == rawMigRetry && w.broke && reached {
			// Caddy answers otherwise, so this row broke the connection
			// itself. After a few runs it is held.
			s.rawMig.strikes[id]++
			if s.rawMig.strikes[id] >= rawMigMaxStrikes {
				out = rawMigHold
				why = fmt.Sprintf("adapting it broke the connection to Caddy %d times while other routes adapted (%s)", s.rawMig.strikes[id], why)
			}
		}
		if out == rawMigRetry && w.snippets {
			if s.rawMig.snippetWaits[id] == 0 {
				s.rawMig.snippetSince[id] = time.Now()
			}
			s.rawMig.snippetWaits[id]++
			if s.rawMig.snippetWaits[id] >= rawMigSnippetRuns && time.Since(s.rawMig.snippetSince[id]) >= rawMigSnippetGrace {
				out = rawMigHold
				why = "held: snippet unavailable — " + why
			}
		} else {
			delete(s.rawMig.snippetWaits, id)
			delete(s.rawMig.snippetSince, id)
		}
		switch out {
		case rawMigRetry:
			if s.rawMig.lastWhy[id] != why {
				log.Printf("advanced route migration: route id=%d: it could not be adapted again now (%s); it stays undeployed and is tried again", id, why)
				s.rawMig.lastWhy[id] = why
			}
			continue
		case rawMigHold:
			ok, err := migrationWrite(s.DB, w.rr, "[]", false, true)
			if err != nil {
				log.Printf("advanced route migration: route id=%d: disable: %v", id, err)
				continue
			}
			if !ok {
				s.logRowChanged(id)
				continue
			}
			log.Printf("advanced route migration: route id=%d (%q) disabled and its stored routes cleared: %s. The routes it held are kept for an administrator (GET /api/v1/raw-routes/%d/held-json); saving its Caddyfile again, or an administrator restoring reviewed routes, brings it back.", id, w.rr.Label, strings.TrimSuffix(why, "."), id)
			_ = models.LogActivity(s.DB, serverID, "system", "rawroute_migration_disabled", fmt.Sprintf("rr:%d", id), w.rr.Label+": "+why, false)
		default:
			ok, err := migrationWrite(s.DB, w.rr, w.json, w.rr.Enabled, false)
			if err != nil {
				log.Printf("advanced route migration: route id=%d: store: %v", id, err)
				continue
			}
			if !ok {
				s.logRowChanged(id)
				continue
			}
			log.Printf("advanced route migration: route id=%d adapted again under the current rules", id)
		}
		delete(s.rawMig.pending, id)
		delete(s.rawMig.lastWhy, id)
		delete(s.rawMig.strikes, id)
		delete(s.rawMig.snippetWaits, id)
		delete(s.rawMig.snippetSince, id)
		changed = true
	}
	if changed {
		if err := s.saveRawRouteMigrationLocked(); err != nil {
			log.Printf("advanced route migration: cannot save its state: %v", err)
		} else if s.rawMig.done {
			log.Printf("advanced route migration: done")
		}
	}
	return !s.rawMig.done && len(s.rawMig.pending) > 0
}

// logRowChanged logs, once, that a row changed while it was adapted; it
// stays pending. s.rawMigMu is held.
func (s *Server) logRowChanged(id int64) {
	const why = "the route changed while it was being adapted"
	if s.rawMig.lastWhy[id] != why {
		log.Printf("advanced route migration: route id=%d: %s; it stays undeployed and is adapted again", id, why)
		s.rawMig.lastWhy[id] = why
	}
}

// migrationWrite stores jsonData and enabled on the row read as rr, only
// if the row still holds what rr holds (issue #184 round 12: adapting
// takes time, and an administrator may disable the row or its owner save
// new text meanwhile). It reports whether the row was written. The row is
// marked as handled under today's rules (rules_184); held says the row is
// being held, and its stored routes are then kept in held_json for an
// administrator (issue #184 round 13), unless an earlier hold kept some.
func migrationWrite(db *sql.DB, rr models.RawRoute, jsonData string, enabled, held bool) (bool, error) {
	owner := int64(0)
	if rr.OwnerID.Valid {
		owner = rr.OwnerID.Int64
	}
	// held_json is assigned first: MariaDB evaluates the assignments of an
	// UPDATE in order, so json_data on its right must still be the old one.
	res, err := db.Exec(`UPDATE raw_routes SET
			held_json = CASE WHEN ? = 1 AND COALESCE(held_json, '') = '' AND json_data NOT IN ('', '[]') THEN json_data ELSE COALESCE(held_json, '') END,
			json_data = ?, enabled = ?, rules_184 = 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND COALESCE(caddyfile_src, '') = ? AND json_data = ? AND enabled = ? AND COALESCE(listen, '') = ? AND COALESCE(owner_id, 0) = ?`,
		boolToInt(held), jsonData, boolToInt(enabled), rr.ID, rr.CaddyfileSrc, rr.JSONData, boolToInt(rr.Enabled), rr.Listen, owner)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// caddyConnectionLost reports whether an adapt error says the connection
// to Caddy broke mid-request (Caddy's handler panicked or the process
// died), rather than that Caddy could not be reached at all.
func caddyConnectionLost(why string) bool {
	return strings.Contains(why, "EOF") || strings.Contains(why, "connection reset")
}

// rawMigSnippetWhy starts the reason a row waits because of the
// administrator's snippets.
const rawMigSnippetWhy = "it depends on the administrator's snippets, which do not allow it now: "

// readaptForMigration adapts a non-admin's Advanced route text the way a
// save does today. It returns the JSON to store, or why the row cannot be
// kept (rawMigHold), or why it cannot be decided now (rawMigRetry);
// answered says Caddy's adapter answered (with a result or a 400).
func (s *Server) readaptForMigration(rr models.RawRoute, cl *caddy.Client) (jsonData, why string, out rawMigOutcome, answered bool) {
	if strings.TrimSpace(rr.CaddyfileSrc) == "" {
		return "", "it has no Caddyfile text to adapt again (the Caddyfile paste import of earlier versions stored some routes that way, and the API stores JSON-only routes), so its routes cannot be checked against what made them; it is held for an administrator's review", rawMigHold, false
	}
	if msg := s.tenantRawRouteTextProblem(rr.CaddyfileSrc); msg != "" {
		// Issue #184 round 12: a refusal that depends on the
		// administrator's Caddyfile — a snippet missing, unreadable,
		// renamed, withheld — may go away, so the row waits.
		if len(rr.CaddyfileSrc) > maxTenantCaddyfileBytes || tenantTextRefusalIsOwn(rr.CaddyfileSrc, tenantTextLimits{maxDepth: tenantMaxNestingDepth, maxBytes: maxTenantCaddyfileBytes, topLevel: true}) {
			return "", msg, rawMigHold, false
		}
		return "", rawMigSnippetWhy + msg, rawMigRetry, false
	}
	tcl := s.tenantAdaptClient(cl)
	if tcl == nil {
		return "", "the Caddy adapter is unavailable", rawMigRetry, false
	}
	jsonData, listen, result, err := s.adaptRawRouteCaddyfileResult(tcl, rr.CaddyfileSrc)
	if err != nil {
		if errors.Is(err, errClientAuthInRawRoute) || result != nil {
			return "", "its Caddyfile no longer adapts: " + err.Error(), rawMigHold, true
		}
		if caddy.IsCaddyfileRejected(err) {
			// The text passed the rules above; a refusal by the adapt
			// check now comes from the administrator's snippets changing
			// meanwhile. Anything else is Caddy's 400.
			if s.tenantAdaptTextViolation(s.snippetsFor(rr.CaddyfileSrc, true)) != "" {
				return "", rawMigSnippetWhy + err.Error(), rawMigRetry, false
			}
			return "", "its Caddyfile no longer adapts: " + err.Error(), rawMigHold, true
		}
		return "", err.Error(), rawMigRetry, false
	}
	// Issue #184 round 14: a save keeps a listen set typed in the form
	// when the text names only the standard ports (adapted listen ""), so
	// only text that names listeners of its own is held to the stored set.
	if listen != "" && listen != rr.Listen {
		return "", "its Caddyfile now adapts to other listen addresses than the stored route", rawMigHold, true
	}
	if msg := s.tenantRawRouteAdaptedProblem(jsonData, listen, result); msg != "" {
		return "", msg, rawMigHold, true
	}
	if len(jsonData) > maxTenantRawJSONBytes {
		return "", fmt.Sprintf("its Caddyfile adapts to more than %d MiB of routes", maxTenantRawJSONBytes>>20), rawMigHold, true
	}
	// Issue #184 round 13: stored routes that are not what the text
	// adapts to now did not come from that text the way a save makes them
	// today — up to v2.68.16 an `import` the text does not show (one of a
	// paste's other blocks, a file) could put them there — so the row is
	// held, and its routes are kept for an administrator's review.
	if !rawRoutesJSONEqual(rr.JSONData, jsonData) {
		return "", "its stored routes differ from what its Caddyfile adapts to now", rawMigHold, true
	}
	return jsonData, "", rawMigStore, true
}

// rawRoutesJSONEqual reports whether two raw-route JSON values hold the
// same routes (issue #184 round 14): a single route and a list holding
// just that route are the same, as the sync deploys them (rawRouteEntries);
// v2.68.16's API stored json_data as sent, often as a one-route list.
func rawRoutesJSONEqual(a, b string) bool {
	list := func(s string) (string, bool) {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return "", false
		}
		if m, ok := v.(map[string]any); ok {
			v = []any{m}
		}
		out, err := json.Marshal(v)
		return string(out), err == nil
	}
	la, oka := list(a)
	lb, okb := list(b)
	return oka && okb && la == lb
}

// migrateTenantRawRoutesFor runs the migration for serverID with its own
// Caddy, ahead of a sync (issue #184 round 12: outside the sync lock).
func (s *Server) migrateTenantRawRoutesFor(serverID int64) bool {
	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err != nil || srv == nil || srv.Type == models.CaddyServerTypeExternal {
		return false
	}
	return s.migrateTenantRawRoutes(serverID, newCaddyClient(srv.AdminURL, srv.AdminUsername, srv.AdminPassword))
}

// runTenantRawRouteMigration syncs, shortly after startup and then from
// time to time, each managed server that still has rows waiting for the
// migration: the sync migrates them first, then replaces whatever the
// live Caddy still carries from before the upgrade. While no row makes
// progress it waits longer between rounds (one minute, doubling up to
// thirty), and it logs a failing sync only when its error changes. It
// stops once no such row is left.
func (s *Server) runTenantRawRouteMigration() {
	time.Sleep(10 * time.Second)
	wait := time.Minute
	lastErr := map[int64]string{}
	for {
		servers, err := s.rawRouteMigrationServers()
		if err == nil && len(servers) == 0 {
			return
		}
		before := s.rawRouteMigrationLeft()
		for _, sid := range servers {
			err := s.syncCaddy(sid, false)
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			if msg != lastErr[sid] {
				if msg != "" {
					log.Printf("advanced route migration: sync of server %d: %v", sid, err)
				}
				lastErr[sid] = msg
			}
		}
		if after := s.rawRouteMigrationLeft(); err != nil || after >= before {
			wait = min(wait*2, 30*time.Minute)
		} else {
			wait = time.Minute
		}
		time.Sleep(wait)
	}
}

// rawRouteMigrationLeft is how many rows still wait, -1 when the state
// cannot be read.
func (s *Server) rawRouteMigrationLeft() int {
	s.rawMigMu.Lock()
	defer s.rawMigMu.Unlock()
	if err := s.loadRawRouteMigrationLocked(); err != nil {
		return -1
	}
	if s.rawMig.done {
		return 0
	}
	return len(s.rawMig.pending)
}

// rawRouteMigrationServers returns the managed servers that hold rows
// still waiting for the migration.
func (s *Server) rawRouteMigrationServers() ([]int64, error) {
	s.rawMigMu.Lock()
	if err := s.loadRawRouteMigrationLocked(); err != nil {
		s.rawMigMu.Unlock()
		log.Printf("advanced route migration: cannot read its state: %v", err)
		return nil, err
	}
	ids := make([]int64, 0, len(s.rawMig.pending))
	if !s.rawMig.done {
		for id := range s.rawMig.pending {
			ids = append(ids, id)
		}
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
	return out, nil
}
