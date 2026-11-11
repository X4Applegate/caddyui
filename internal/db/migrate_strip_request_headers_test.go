// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// issue #167: strip_request_headers (v2.9.250) duplicated strip_req_headers
// (v2.9.35). Consolidating on strip_req_headers must not throw away values
// users already stored in the legacy column.
func TestMigrateStripRequestHeadersMergesLegacyValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strip.db")
	database, err := Open(path)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer database.Close()

	cases := []struct {
		name      string
		canonical string
		legacy    string
		want      string
	}{
		// The headline data-loss case: the value only exists in the legacy
		// column, so it must move over rather than disappear.
		{"legacy_only_carries_over", "", "X-Legacy-Only", "X-Legacy-Only"},
		// Both filled with different names: merge, do not discard either.
		{"both_set_merges", "X-One", "X-Two", "X-One, X-Two"},
		// Both filled with the same name in different case: one copy.
		{"duplicate_collapses", "Authorization", "authorization", "Authorization"},
		// Overlapping lists keep canonical order and append what is new.
		{"overlap_appends_extras", "B, A", "A, C", "B, A, C"},
		// Canonical already set, legacy empty: untouched (and not selected).
		{"canonical_only_untouched", "X-Keep", "", "X-Keep"},
		// Neither set: stays empty.
		{"both_empty", "", "", ""},
	}

	ids := make([]int64, len(cases))
	for i, tc := range cases {
		res, err := database.Exec(`
			INSERT INTO proxy_hosts
				(domains, forward_scheme, forward_host, forward_port,
				 strip_req_headers, strip_request_headers)
			VALUES (?, 'http', 'backend', 8080, ?, ?)`,
			tc.name+".example.com", tc.canonical, tc.legacy)
		if err != nil {
			t.Fatalf("insert %s: %v", tc.name, err)
		}
		if ids[i], err = res.LastInsertId(); err != nil {
			t.Fatalf("last insert id for %s: %v", tc.name, err)
		}
	}

	// Run the consolidation the way an upgrade would.
	migrationFailures = 0
	migrateStripRequestHeaders(database)
	if migrationFailures != 0 {
		t.Fatalf("migration reported %d failure(s)", migrationFailures)
	}

	for i, tc := range cases {
		var canonical, legacy string
		if err := database.QueryRow(
			`SELECT strip_req_headers, strip_request_headers FROM proxy_hosts WHERE id=?`,
			ids[i],
		).Scan(&canonical, &legacy); err != nil {
			t.Fatalf("read %s back: %v", tc.name, err)
		}
		if canonical != tc.want {
			t.Errorf("%s: strip_req_headers = %q, want %q", tc.name, canonical, tc.want)
		}
		// The legacy column is drained once its value is safely merged, so a
		// later release can drop it without a second migration.
		if legacy != "" {
			t.Errorf("%s: strip_request_headers = %q, want empty after merge", tc.name, legacy)
		}
	}
}

// Re-running the migration over already-merged rows must change nothing.
// Open() runs migrate() on every startup, so this is the normal second boot.
func TestMigrateStripRequestHeadersIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strip-idempotent.db")
	database, err := Open(path)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	if _, err := database.Exec(`
		INSERT INTO proxy_hosts
			(domains, forward_scheme, forward_host, forward_port,
			 strip_req_headers, strip_request_headers)
		VALUES ('idem.example.com', 'http', 'backend', 8080, 'X-One', 'X-Two')`); err != nil {
		database.Close()
		t.Fatalf("insert host: %v", err)
	}

	migrationFailures = 0
	migrateStripRequestHeaders(database)
	migrateStripRequestHeaders(database)
	if migrationFailures != 0 {
		t.Fatalf("migration reported %d failure(s)", migrationFailures)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	// A full reopen re-runs migrate() end to end, as a real restart does.
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer reopened.Close()

	var canonical, legacy string
	if err := reopened.QueryRow(
		`SELECT strip_req_headers, strip_request_headers FROM proxy_hosts WHERE domains='idem.example.com'`,
	).Scan(&canonical, &legacy); err != nil {
		t.Fatalf("read host back: %v", err)
	}
	if canonical != "X-One, X-Two" {
		t.Errorf("strip_req_headers = %q, want %q", canonical, "X-One, X-Two")
	}
	if legacy != "" {
		t.Errorf("strip_request_headers = %q, want empty", legacy)
	}
}

// An upgrade from before v2.9.250 has no strip_request_headers column at the
// point the merge runs if that ALTER failed. The merge must no-op, not error.
func TestMigrateStripRequestHeadersSkipsWhenLegacyColumnMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strip-nocol.db")
	legacyDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw database: %v", err)
	}
	if _, err := legacyDB.Exec(`
		CREATE TABLE proxy_hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			domains TEXT NOT NULL,
			strip_req_headers TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		legacyDB.Close()
		t.Fatalf("create table without legacy column: %v", err)
	}

	migrationFailures = 0
	migrateStripRequestHeaders(legacyDB)
	if migrationFailures != 0 {
		t.Fatalf("migration reported %d failure(s) when the legacy column is absent", migrationFailures)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}
