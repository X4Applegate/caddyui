// SPDX-License-Identifier: Apache-2.0

package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// Issue #164: upgrading a populated database whose caddy_servers table predates
// log_source_id adds the column as NULL on every existing row, adds the unique
// index, and leaves the rows otherwise untouched. Re-opening is a no-op.
func TestOpenUpgradesCaddyServersWithLogSourceID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`
		CREATE TABLE caddy_servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			admin_url TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'managed',
			tags TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown',
			last_contact_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO caddy_servers (name, admin_url, type) VALUES
			('Primary', 'http://caddy:2019', 'managed'),
			('Edge', 'http://edge:2019', 'external'),
			('Lab', 'http://lab:2019', 'external');
	`); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	for pass := 1; pass <= 2; pass++ { // second pass: migration must be idempotent
		conn, err := Open(path)
		if err != nil {
			t.Fatalf("open pass %d: %v", pass, err)
		}
		var rows, nulls int
		if err := conn.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN log_source_id IS NULL THEN 1 ELSE 0 END) FROM caddy_servers`).Scan(&rows, &nulls); err != nil {
			conn.Close()
			t.Fatalf("pass %d: read upgraded rows: %v", pass, err)
		}
		if pass == 1 && (rows != 3 || nulls != 3) {
			conn.Close()
			t.Fatalf("pass %d: rows=%d nulls=%d, want 3 existing rows all NULL", pass, rows, nulls)
		}
		var unique int
		if err := conn.QueryRow(`SELECT "unique" FROM pragma_index_list('caddy_servers') WHERE name = 'idx_caddy_servers_log_source_id'`).Scan(&unique); err != nil || unique != 1 {
			conn.Close()
			t.Fatalf("pass %d: unique index idx_caddy_servers_log_source_id missing (unique=%d err=%v)", pass, unique, err)
		}
		if pass == 1 {
			if _, err := conn.Exec(`UPDATE caddy_servers SET log_source_id='edge-home' WHERE name='Edge'`); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			if _, err := conn.Exec(`UPDATE caddy_servers SET log_source_id='edge-home' WHERE name='Lab'`); err == nil {
				conn.Close()
				t.Fatal("duplicate log_source_id accepted after upgrade")
			}
		} else {
			var name string
			if err := conn.QueryRow(`SELECT name FROM caddy_servers WHERE log_source_id='edge-home'`).Scan(&name); err != nil || name != "Edge" {
				conn.Close()
				t.Fatalf("pass 2: value set in pass 1 lost on re-open (name=%q err=%v)", name, err)
			}
		}
		conn.Close()
	}
}
