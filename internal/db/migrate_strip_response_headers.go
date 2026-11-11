// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"log"

	"github.com/X4Applegate/caddyui/internal/models"
)

// migrateStripResponseHeaders consolidates the two response-header strip
// columns — the response-side twin of the issue #167 request-side merge.
//
// Background: v2.9.35 added strip_resp_headers, and v2.9.168 independently
// added strip_response_headers. The host form grew an input for each, so which
// column a host used came down to which of two identical-looking boxes the user
// typed in. Both emitted a deferred Caddy response-delete handler ahead of
// reverse_proxy — two delete lists are commutative, so the columns were
// behaviourally identical — but only strip_resp_headers was read by the
// Caddyfile exporter. Values in the v2.9.168 column therefore worked live and
// vanished from an export, and a host with both set got two strip directives.
//
// strip_resp_headers is canonical: it owns the StripRespHeaderList helper
// (which canonicalises header names, something the v2.9.168 path did not do),
// the exporter support, and the paired strip_req_headers UI that issue #167
// settled on. The two integrations the legacy column owned — the global
// "Globally stripped response headers" setting and the SecurityHeaders bundle
// precedence — were moved onto the canonical field before this migration ran,
// so behaviour is preserved for users of either box.
//
// This migration carries every legacy value into the canonical column:
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
// drop the strip_response_headers column, the ProxyHost.StripResponseHeaders
// field, and the legacy form fallback in internal/server/proxy_host_form.go.
func migrateStripResponseHeaders(db *sql.DB) {
	// Both columns are added by earlier migration steps. If either is missing
	// the step that creates it failed, and there is nothing to merge.
	if !columnExists2(db, "proxy_hosts", "strip_resp_headers") ||
		!columnExists2(db, "proxy_hosts", "strip_response_headers") {
		return
	}

	rows, err := db.Query(`
		SELECT id, COALESCE(strip_resp_headers,''), COALESCE(strip_response_headers,'')
		FROM proxy_hosts
		WHERE COALESCE(strip_response_headers,'') <> ''`)
	if err != nil {
		migrationFailures++
		log.Printf("db: MIGRATION FAILED: read strip_response_headers for response-strip merge: %v", err)
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
			log.Printf("db: MIGRATION FAILED: scan proxy_hosts row for response-strip merge: %v", err)
			return
		}
		pending = append(pending, merge{id: id, merged: models.MergeStripResponseHeaders(canonical, legacy)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		migrationFailures++
		log.Printf("db: MIGRATION FAILED: iterate proxy_hosts for response-strip merge: %v", err)
		return
	}
	rows.Close()

	if len(pending) == 0 {
		return
	}

	for _, m := range pending {
		if _, err := db.Exec(
			`UPDATE proxy_hosts SET strip_resp_headers=?, strip_response_headers='' WHERE id=?`,
			m.merged, m.id,
		); err != nil {
			migrationFailures++
			log.Printf("db: MIGRATION FAILED: merge strip_response_headers into strip_resp_headers for host %d: %v", m.id, err)
		}
	}
	log.Printf("db: merged legacy strip_response_headers into strip_resp_headers for %d host(s)", len(pending))
}
