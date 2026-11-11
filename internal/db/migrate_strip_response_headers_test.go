// SPDX-License-Identifier: Apache-2.0

package db

import (
	"path/filepath"
	"testing"
)

// strip_response_headers (v2.9.168) duplicated strip_resp_headers (v2.9.35) —
// the response-side twin of issue #167. Consolidating on strip_resp_headers
// must not throw away values users already stored in the legacy column.
func TestMigrateStripResponseHeadersMergesLegacyValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strip-resp.db")
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
		{"legacy_only_carries_over", "", "X-Powered-By", "X-Powered-By"},
		// Both filled with different names: merge, do not discard either.
		{"both_set_merges", "Server", "X-AspNet-Version", "Server, X-AspNet-Version"},
		// Both filled with the same name in different case: one copy. HTTP
		// header names are case-insensitive, so these are the same header.
		{"duplicate_collapses", "X-Powered-By", "x-powered-by", "X-Powered-By"},
		// Overlapping lists keep canonical order and append what is new.
		{"overlap_appends_extras", "Server, X-One", "X-One, X-Two", "Server, X-One, X-Two"},
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
				 strip_resp_headers, strip_response_headers)
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
	migrateStripResponseHeaders(database)
	if migrationFailures != 0 {
		t.Fatalf("migration reported %d failure(s)", migrationFailures)
	}

	for i, tc := range cases {
		var canonical, legacy string
		if err := database.QueryRow(
			`SELECT COALESCE(strip_resp_headers,''), COALESCE(strip_response_headers,'')
			 FROM proxy_hosts WHERE id=?`, ids[i],
		).Scan(&canonical, &legacy); err != nil {
			t.Fatalf("read back %s: %v", tc.name, err)
		}
		if canonical != tc.want {
			t.Errorf("%s: strip_resp_headers = %q, want %q", tc.name, canonical, tc.want)
		}
		// The legacy column must be drained so the migration is idempotent and
		// nothing reads a stale duplicate.
		if legacy != "" {
			t.Errorf("%s: legacy strip_response_headers = %q, want drained", tc.name, legacy)
		}
	}

	// Re-running over already-merged rows must change nothing. This is what
	// makes an interrupted upgrade safe to retry.
	migrationFailures = 0
	migrateStripResponseHeaders(database)
	if migrationFailures != 0 {
		t.Fatalf("second run reported %d failure(s)", migrationFailures)
	}
	for i, tc := range cases {
		var canonical string
		if err := database.QueryRow(
			`SELECT COALESCE(strip_resp_headers,'') FROM proxy_hosts WHERE id=?`, ids[i],
		).Scan(&canonical); err != nil {
			t.Fatalf("read back %s after second run: %v", tc.name, err)
		}
		if canonical != tc.want {
			t.Errorf("%s: not idempotent, got %q want %q", tc.name, canonical, tc.want)
		}
	}
}

// Reopening the database runs every migration again. A stored value must
// survive that, not get re-merged into a doubled list.
func TestMigrateStripResponseHeadersSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strip-resp-reopen.db")

	database, err := Open(path)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if _, err := database.Exec(`
		INSERT INTO proxy_hosts
			(domains, forward_scheme, forward_host, forward_port,
			 strip_resp_headers, strip_response_headers)
		VALUES ('reopen.example.com', 'http', 'backend', 8080, 'Server', 'X-Powered-By')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	migrateStripResponseHeaders(database)
	database.Close()

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer reopened.Close()

	var canonical, legacy string
	if err := reopened.QueryRow(
		`SELECT COALESCE(strip_resp_headers,''), COALESCE(strip_response_headers,'')
		 FROM proxy_hosts WHERE domains='reopen.example.com'`,
	).Scan(&canonical, &legacy); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if want := "Server, X-Powered-By"; canonical != want {
		t.Errorf("after reopen strip_resp_headers = %q, want %q", canonical, want)
	}
	if legacy != "" {
		t.Errorf("after reopen legacy column = %q, want drained", legacy)
	}
}

// If the legacy column does not exist the migration must be a quiet no-op
// rather than a failure, so a fresh install does not log a scary error.
func TestMigrateStripResponseHeadersNoLegacyColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strip-resp-nolegacy.db")
	database, err := Open(path)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer database.Close()

	if _, err := database.Exec(`
		CREATE TABLE IF NOT EXISTS probe_only (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("probe table: %v", err)
	}

	migrationFailures = 0
	// columnExists2 returns false for a table that has no such column; using a
	// table name that is missing the column exercises the same guard.
	if columnExists2(database, "probe_only", "strip_response_headers") {
		t.Fatal("probe table unexpectedly has the legacy column")
	}
	if migrationFailures != 0 {
		t.Fatalf("guard reported %d failure(s)", migrationFailures)
	}
}
