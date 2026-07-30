package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestMariaDBSchemaAndCoreQueries(t *testing.T) {
	dsn := os.Getenv("CADDYUI_TEST_MARIADB_DSN")
	if dsn == "" {
		t.Skip("CADDYUI_TEST_MARIADB_DSN is not set")
	}

	conn, err := appdb.OpenConfig(appdb.Config{
		Backend:    appdb.BackendMariaDB,
		MariaDBDSN: dsn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cleanMariaDBTestTables(t, conn)
	defer cleanMariaDBTestTables(t, conn)

	if got := appdb.BackendOf(conn); got != appdb.BackendMariaDB {
		t.Fatalf("backend = %q, want mariadb", got)
	}

	key := fmt.Sprintf("integration_%d", time.Now().UnixNano())
	if err := models.SetSetting(conn, key, "one"); err != nil {
		t.Fatal(err)
	}
	if err := models.SetSetting(conn, key, "two"); err != nil {
		t.Fatal(err)
	}
	value, err := models.GetSetting(conn, key)
	if err != nil {
		t.Fatal(err)
	}
	if value != "two" {
		t.Fatalf("setting = %q, want two", value)
	}

	host := fmt.Sprintf("integration-%d.example.test", time.Now().UnixNano())
	if err := models.InsertAccessEvent(conn, models.AccessEvent{
		TS:     time.Now().UTC(),
		Host:   host,
		Method: "GET",
		Status: 200,
	}); err != nil {
		t.Fatal(err)
	}
	counts, err := models.DomainRequestsTodayForDomains(conn, []string{host})
	if err != nil {
		t.Fatal(err)
	}
	if counts[host] != 1 {
		t.Fatalf("request count = %d, want 1", counts[host])
	}
	if err := models.InsertAccessEvent(conn, models.AccessEvent{
		TS:       time.Now().UTC().Truncate(24 * time.Hour).Add(-12 * time.Hour),
		Host:     host,
		Method:   "GET",
		Status:   200,
		ClientIP: "192.0.2.1",
	}); err != nil {
		t.Fatal(err)
	}
	if written, err := models.AggregateAccessDaily(conn); err != nil {
		t.Fatal(err)
	} else if written == 0 {
		t.Fatal("MariaDB daily rollup did not write yesterday")
	}

	var proxyColumnCount int
	if err := conn.QueryRow(`
		SELECT COUNT(*)
		  FROM information_schema.columns
		 WHERE table_schema = DATABASE() AND table_name = 'proxy_hosts'`,
	).Scan(&proxyColumnCount); err != nil {
		t.Fatal(err)
	}
	if proxyColumnCount < 200 {
		t.Fatalf("proxy_hosts has %d columns; migrations did not complete", proxyColumnCount)
	}
	assertMariaDBSchemaMatchesSQLite(t, conn)

	userID, err := models.CreateUser(
		conn,
		fmt.Sprintf("integration-%d@example.test", time.Now().UnixNano()),
		"not-a-real-password-hash",
		"Integration",
		models.RoleAdmin,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name:     "Integration",
		AdminURL: "http://127.0.0.1:29999",
		Type:     models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyID, err := models.CreateProxyHost(conn, serverID, userID, &models.ProxyHost{
		Domains:           "proxy.integration.example.test",
		ForwardScheme:     "http",
		ForwardHost:       "127.0.0.1",
		ForwardPort:       8080,
		Enabled:           true,
		BasicAuthUsers:    "[]",
		ExtraUpstreams:    "[]",
		CustomReqHeaders:  "{}",
		CustomRespHeaders: "{}",
		URLRewrites:       "[]",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := models.GetProxyHost(conn, proxyID)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Domains != "proxy.integration.example.test" || proxy.ServerID != serverID {
		t.Fatalf("unexpected MariaDB proxy row: %#v", proxy)
	}
}

func assertMariaDBSchemaMatchesSQLite(t *testing.T, maria *sql.DB) {
	t.Helper()
	sqlite, err := appdb.Open(filepath.Join(t.TempDir(), "schema.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlite.Close()

	tables := []string{
		"users", "sessions", "proxy_hosts", "redirection_hosts", "raw_routes",
		"settings", "config_snapshots", "activity_log", "certificates",
		"caddy_servers", "access_events", "access_daily", "groups",
		"user_groups", "api_tokens", "proxy_health",
	}
	for _, table := range tables {
		sqliteColumns := queryColumnNames(t, sqlite, "PRAGMA table_info(`"+table+"`)", true)
		mariaColumns := queryColumnNames(t, maria, `
			SELECT column_name
			  FROM information_schema.columns
			 WHERE table_schema = DATABASE() AND table_name = ?
			 ORDER BY ordinal_position`, false, table)
		if !slices.Equal(sqliteColumns, mariaColumns) {
			t.Fatalf("%s columns differ\nSQLite: %v\nMariaDB: %v", table, sqliteColumns, mariaColumns)
		}
	}
}

func queryColumnNames(t *testing.T, conn *sql.DB, query string, sqlite bool, args ...any) []string {
	t.Helper()
	rows, err := conn.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name string
		if sqlite {
			var cid, notNull, primaryKey int
			var columnType string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				t.Fatal(err)
			}
		} else if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}

func TestSQLiteToMariaDBMigration(t *testing.T) {
	dsn := os.Getenv("CADDYUI_TEST_MARIADB_DSN")
	if dsn == "" {
		t.Skip("CADDYUI_TEST_MARIADB_DSN is not set")
	}
	target, err := appdb.OpenConfig(appdb.Config{
		Backend:    appdb.BackendMariaDB,
		MariaDBDSN: dsn,
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanMariaDBTestTables(t, target)
	target.Close()

	sourcePath := filepath.Join(t.TempDir(), "source.db")
	source, err := appdb.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := models.SetSetting(source, "migration_marker", "copied"); err != nil {
		t.Fatal(err)
	}
	host := "migration.example.test"
	if err := models.InsertAccessEvent(source, models.AccessEvent{
		TS:     time.Now().UTC(),
		Host:   host,
		Method: "GET",
		Status: 204,
	}); err != nil {
		t.Fatal(err)
	}
	source.Close()

	if err := appdb.MigrateSQLiteToMariaDB(
		context.Background(),
		sourcePath,
		dsn,
		appdb.DataMigrationOptions{BatchSize: 2},
	); err != nil {
		t.Fatal(err)
	}

	target, err = appdb.OpenConfig(appdb.Config{
		Backend:    appdb.BackendMariaDB,
		MariaDBDSN: dsn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	defer cleanMariaDBTestTables(t, target)

	value, err := models.GetSetting(target, "migration_marker")
	if err != nil {
		t.Fatal(err)
	}
	if value != "copied" {
		t.Fatalf("migrated setting = %q, want copied", value)
	}
	counts, err := models.DomainRequestsTodayForDomains(target, []string{host})
	if err != nil {
		t.Fatal(err)
	}
	if counts[host] != 1 {
		t.Fatalf("migrated analytics count = %d, want 1", counts[host])
	}
}

func cleanMariaDBTestTables(t *testing.T, conn interface {
	Exec(query string, args ...any) (sql.Result, error)
}) {
	t.Helper()
	if _, err := conn.Exec(`SET FOREIGN_KEY_CHECKS=0`); err != nil {
		t.Fatal(err)
	}
	tables := []string{
		"access_events", "proxy_health", "access_daily", "activity_log",
		"config_snapshots", "api_tokens", "sessions", "user_groups",
		"raw_routes", "redirection_hosts", "proxy_hosts", "certificates",
		"settings", "caddy_servers", "groups", "users",
	}
	for _, table := range tables {
		if _, err := conn.Exec("DELETE FROM `" + table + "`"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(`SET FOREIGN_KEY_CHECKS=1`); err != nil {
		t.Fatal(err)
	}
}
