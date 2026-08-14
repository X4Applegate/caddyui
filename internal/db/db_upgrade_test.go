package db

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestOpenUpgradesLegacyAccessEventsSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`
		CREATE TABLE access_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts INTEGER NOT NULL,
			host TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			status INTEGER NOT NULL DEFAULT 0,
			client_ip TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			duration_ms INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO access_events (ts, host) VALUES (1700000000, 'legacy.example');
	`); err != nil {
		legacy.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	upgraded, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade legacy database: %v", err)
	}
	defer upgraded.Close()

	var serverID int64
	var serverName, host string
	if err := upgraded.QueryRow(`SELECT server_id, server_name, host FROM access_events WHERE id=1`).Scan(&serverID, &serverName, &host); err != nil {
		t.Fatalf("read upgraded event: %v", err)
	}
	if serverID != 0 || serverName != "" || host != "legacy.example" {
		t.Fatalf("upgraded event = (%d, %q, %q), want (0, \"\", \"legacy.example\")", serverID, serverName, host)
	}

	var indexName string
	if err := upgraded.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_access_events_server_ts'`).Scan(&indexName); err != nil {
		t.Fatalf("server index missing after upgrade: %v", err)
	}
}
