// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"log"

	"github.com/X4Applegate/caddyui/internal/models"
)

// migrateStripRequestHeaders consolidates the two request-header strip columns
// introduced by issue #167.
//
// Background: v2.9.35 added strip_req_headers, and v2.9.250 independently added
// strip_request_headers. The host form grew an input for each, so which column a
// host used came down to which of two identical-looking boxes the user typed in.
// Both emitted a Caddy request-delete handler, but only strip_req_headers was
// read by the Caddyfile exporter — so values in the v2.9.250 column worked live
// and vanished from an export, and a host with both set got two strip directives.
//
// strip_req_headers is canonical: it owns the StripReqHeaderList helper (which
// canonicalises header names), the exporter support, and the paired
// strip_resp_headers UI. This migration carries every legacy value into it:
//
//   - canonical empty, legacy set  -> legacy value moves over verbatim
//   - both set and equal           -> collapses to one copy
//   - both set and different       -> header names merged, deduplicated
//     case-insensitively, canonical order first
//
// Nothing is discarded. The legacy column is blanked only after its value has
// been written into the canonical one, so a half-applied run cannot lose data:
// the UPDATE is a single statement per row, and re-running the migration over
// already-merged rows is a no-op because the legacy column is then empty.
//
// TODO(v2.70): once no supported upgrade path can still carry a value here,
// drop the strip_request_headers column, the ProxyHost.StripRequestHeaders
// field, and the legacy form fallback in internal/server/proxy_host_form.go.
func migrateStripRequestHeaders(db *sql.DB) {
	// Both columns are added by earlier migration steps. If either is missing
	// the step that creates it failed, and there is nothing to merge.
	if !columnExists2(db, "proxy_hosts", "strip_req_headers") ||
		!columnExists2(db, "proxy_hosts", "strip_request_headers") {
		return
	}

	rows, err := db.Query(`
		SELECT id, COALESCE(strip_req_headers,''), COALESCE(strip_request_headers,'')
		FROM proxy_hosts
		WHERE COALESCE(strip_request_headers,'') <> ''`)
	if err != nil {
		migrationFailures++
		log.Printf("db: MIGRATION FAILED: read strip_request_headers for issue #167 merge: %v", err)
		return
	}

	type merge struct {
		id     int64
		merged string
	}
	var pending []merge
	for rows.Next() {
		var id int64
		var canonical, legacy string
		if err := rows.Scan(&id, &canonical, &legacy); err != nil {
			rows.Close()
			migrationFailures++
			log.Printf("db: MIGRATION FAILED: scan proxy_hosts row for issue #167 merge: %v", err)
			return
		}
		pending = append(pending, merge{id: id, merged: models.MergeStripRequestHeaders(canonical, legacy)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		migrationFailures++
		log.Printf("db: MIGRATION FAILED: iterate proxy_hosts for issue #167 merge: %v", err)
		return
	}
	rows.Close()

	if len(pending) == 0 {
		return
	}

	for _, m := range pending {
		if _, err := db.Exec(
			`UPDATE proxy_hosts SET strip_req_headers=?, strip_request_headers='' WHERE id=?`,
			m.merged, m.id,
		); err != nil {
			migrationFailures++
			log.Printf("db: MIGRATION FAILED: merge strip_request_headers into strip_req_headers for host %d: %v", m.id, err)
		}
	}
	log.Printf("db: issue #167: merged legacy strip_request_headers into strip_req_headers for %d host(s)", len(pending))
}
