package db

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// v2.31.0: the Analytics page took ~1.2s once an operator had ~20 hosts on one
// node. The dominant cost was the server-scoped "top hosts" aggregation —
// `WHERE ts >= ? AND server_id = ? GROUP BY host` — which had no index able to
// supply group order, so SQLite built temp B-trees and fetched every matching
// row from the table.
//
// These pin the fix. If the index is dropped, or the query is rewritten in a
// way that stops using it, the plan assertion fails rather than the page
// quietly getting slow again.

func TestAnalyticsServerScopedTopHostsUsesCoveringIndex(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const q = `SELECT host, COUNT(*) AS views, COUNT(DISTINCT client_ip) AS visitors, MAX(ts) AS last_ts
	             FROM access_events
	            WHERE ts >= ? AND server_id = ?
	            GROUP BY host
	            ORDER BY views DESC
	            LIMIT 50`

	rows, err := conn.Query("EXPLAIN QUERY PLAN "+q, time.Now().Add(-7*24*time.Hour).Unix(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var plan strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
		plan.WriteString("\n")
	}
	got := plan.String()

	if !strings.Contains(got, "idx_access_events_server_host_ts_ip") {
		t.Errorf("server-scoped top-hosts query no longer uses the covering index.\nplan:\n%s", got)
	}
	// Group order comes from the index; a temp B-tree for GROUP BY means the
	// index is no longer supplying it, which is what made this slow.
	if strings.Contains(got, "USE TEMP B-TREE FOR GROUP BY") {
		t.Errorf("query fell back to a temp B-tree for GROUP BY — the index is not supplying group order.\nplan:\n%s", got)
	}
}

// The index must actually exist after a migration, on both a fresh database
// and one being upgraded.
func TestAnalyticsCoveringIndexIsCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "caddyui.db")

	assertIndex := func(t *testing.T, stage string) {
		t.Helper()
		conn, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var name string
		err = conn.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name = ?`,
			"idx_access_events_server_host_ts_ip",
		).Scan(&name)
		if err != nil {
			t.Errorf("%s: covering index missing: %v", stage, err)
		}
	}

	assertIndex(t, "fresh database")
	assertIndex(t, "reopened database")
}

// Guard the shape the index depends on: server_id, host, ts and client_ip must
// all remain columns on access_events.
func TestAccessEventsRetainsIndexedColumns(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for _, col := range []string{"server_id", "host", "ts", "client_ip"} {
		ok, err := columnExists(conn, "access_events", col)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("access_events.%s is gone — idx_access_events_server_host_ts_ip depends on it", col)
		}
	}
}
