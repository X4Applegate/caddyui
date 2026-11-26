// SPDX-License-Identifier: Apache-2.0

package db_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #164 on MariaDB: upgrading a populated caddy_servers table adds
// log_source_id as NULL with a unique index, duplicates are rejected (also
// case-insensitively), resolution works, and the SQLite → MariaDB copy keeps
// the identifier.
func TestMariaDBLogSourceIDUpgradeUniquenessAndCopy(t *testing.T) {
	dsn := os.Getenv("CADDYUI_TEST_MARIADB_DSN")
	if dsn == "" {
		t.Skip("CADDYUI_TEST_MARIADB_DSN is not set")
	}
	conn, err := appdb.OpenConfig(appdb.Config{Backend: appdb.BackendMariaDB, MariaDBDSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	cleanMariaDBTestTables(t, conn)

	// Roll caddy_servers back to its pre-#164 shape and populate it.
	for _, stmt := range []string{
		`DROP INDEX idx_caddy_servers_log_source_id ON caddy_servers`,
		`ALTER TABLE caddy_servers DROP COLUMN log_source_id`,
		`INSERT INTO caddy_servers (name, admin_url, type, tags) VALUES ('Primary', 'http://caddy:2019', 'managed', ''), ('Edge', 'http://edge:2019', 'external', ''), ('Lab', 'http://lab:2019', 'external', '')`,
	} {
		if _, err := conn.Exec(stmt); err != nil {
			conn.Close()
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	conn.Close()

	conn, err = appdb.OpenConfig(appdb.Config{Backend: appdb.BackendMariaDB, MariaDBDSN: dsn})
	if err != nil {
		t.Fatalf("upgrade populated MariaDB: %v", err)
	}
	defer conn.Close()
	defer cleanMariaDBTestTables(t, conn)

	var rows, nulls int
	if err := conn.QueryRow(`SELECT COUNT(*), SUM(log_source_id IS NULL) FROM caddy_servers`).Scan(&rows, &nulls); err != nil {
		t.Fatal(err)
	}
	if rows != 3 || nulls != 3 {
		t.Fatalf("after upgrade rows=%d nulls=%d, want 3 rows all NULL", rows, nulls)
	}
	var nonUnique int
	if err := conn.QueryRow(`SELECT NON_UNIQUE FROM information_schema.statistics
		WHERE table_schema = DATABASE() AND table_name = 'caddy_servers' AND index_name = 'idx_caddy_servers_log_source_id'`).Scan(&nonUnique); err != nil || nonUnique != 0 {
		t.Fatalf("unique index missing after upgrade (non_unique=%d err=%v)", nonUnique, err)
	}

	servers, err := models.ListCaddyServers(conn)
	if err != nil {
		t.Fatal(err)
	}
	edge := servers[1]
	edge.LogSourceID = "Edge-Home"
	if err := models.UpdateCaddyServer(conn, &edge); err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Dup", AdminURL: "http://dup:2019", LogSourceID: "EDGE-HOME"}); !errors.Is(err, models.ErrLogSourceIDTaken) {
		t.Fatalf("duplicate on MariaDB: err = %v, want ErrLogSourceIDTaken", err)
	}
	if _, err := conn.Exec(`UPDATE caddy_servers SET log_source_id = 'edge-home' WHERE name = 'Lab'`); err == nil {
		t.Fatal("MariaDB accepted a duplicate log_source_id; the unique index is not enforced")
	}
	if id, name, via := models.ResolveLogServer(conn, "edge-home", 1); id != edge.ID || name != "Edge" || !via {
		t.Fatalf("ResolveLogServer on MariaDB = (%d, %q, %t), want (%d, Edge, true)", id, name, via, edge.ID)
	}
	if id, _, via := models.ResolveLogServer(conn, "unknown-node", 1); id != 1 || via {
		t.Fatalf("unknown source on MariaDB = (%d, %t), want numeric fallback 1", id, via)
	}

	// SQLite → MariaDB copy carries the identifier.
	cleanMariaDBTestTables(t, conn)
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	source, err := appdb.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateCaddyServer(source, &models.CaddyServer{Name: "Plain", AdminURL: "http://plain:2019"}); err != nil {
		t.Fatal(err)
	}
	copiedID, err := models.CreateCaddyServer(source, &models.CaddyServer{Name: "Copied", AdminURL: "http://copied:2019", LogSourceID: "copied-node"})
	if err != nil {
		t.Fatal(err)
	}
	source.Close()
	if err := appdb.MigrateSQLiteToMariaDB(context.Background(), sourcePath, dsn, appdb.DataMigrationOptions{}); err != nil {
		t.Fatal(err)
	}
	if id, _, via := models.ResolveLogServer(conn, "copied-node", 0); id != copiedID || !via {
		t.Fatalf("copied identifier resolves to (%d, %t), want (%d, true)", id, via, copiedID)
	}
	var plainNull bool
	if err := conn.QueryRow(`SELECT log_source_id IS NULL FROM caddy_servers WHERE name = 'Plain'`).Scan(&plainNull); err != nil || !plainNull {
		t.Fatalf("unset identifier did not copy as NULL (null=%t err=%v)", plainNull, err)
	}
}
