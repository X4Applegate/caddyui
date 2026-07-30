package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DataMigrationOptions controls a one-time SQLite → MariaDB copy.
type DataMigrationOptions struct {
	// SkipAnalytics omits access_events and access_daily. This is useful when
	// the SQLite database contains years of raw traffic and only CaddyUI
	// configuration, users, certificates, and operational history are needed.
	SkipAnalytics bool
	BatchSize     int
	Progress      func(table string, copied, total int64)
}

var migrationIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var migrationTableOrder = []string{
	"users",
	"groups",
	"caddy_servers",
	"settings",
	"certificates",
	"proxy_hosts",
	"redirection_hosts",
	"raw_routes",
	"user_groups",
	"sessions",
	"api_tokens",
	"config_snapshots",
	"activity_log",
	"access_daily",
	"proxy_health",
	"access_events",
}

// MigrateSQLiteToMariaDB copies an existing SQLite installation into a fresh
// MariaDB database. The source is opened read-only and is never modified.
// The destination must be empty so IDs and foreign-key relationships can be
// preserved without merging ambiguous state.
func MigrateSQLiteToMariaDB(ctx context.Context, sqlitePath, mariaDBDSN string, opts DataMigrationOptions) error {
	if strings.TrimSpace(sqlitePath) == "" {
		return fmt.Errorf("SQLite source path is required")
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 1000
	}

	sourceURL := (&url.URL{Scheme: "file", Path: sqlitePath}).String()
	source, err := sql.Open("sqlite", sourceURL+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		return fmt.Errorf("open SQLite source: %w", err)
	}
	defer source.Close()
	if err := source.PingContext(ctx); err != nil {
		return fmt.Errorf("read SQLite source: %w", err)
	}

	target, err := OpenConfig(Config{Backend: BackendMariaDB, MariaDBDSN: mariaDBDSN})
	if err != nil {
		return err
	}
	defer target.Close()
	targetConn, err := target.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve MariaDB migration connection: %w", err)
	}
	defer targetConn.Close()

	for _, table := range migrationTableOrder {
		if opts.SkipAnalytics && (table == "access_events" || table == "access_daily") {
			continue
		}
		var count int64
		if err := targetConn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteMigrationIdentifier(table)).Scan(&count); err != nil {
			return fmt.Errorf("check MariaDB table %s: %w", table, err)
		}
		if count != 0 {
			return fmt.Errorf("MariaDB destination is not empty: table %s contains %d row(s)", table, count)
		}
	}

	if _, err := targetConn.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS=0`); err != nil {
		return fmt.Errorf("disable MariaDB foreign-key checks: %w", err)
	}
	defer targetConn.ExecContext(context.Background(), `SET FOREIGN_KEY_CHECKS=1`)

	for _, table := range migrationTableOrder {
		if opts.SkipAnalytics && (table == "access_events" || table == "access_daily") {
			continue
		}
		if err := copyMigrationTable(ctx, source, targetConn, table, opts); err != nil {
			return err
		}
	}
	if _, err := targetConn.ExecContext(ctx, `SET FOREIGN_KEY_CHECKS=1`); err != nil {
		return fmt.Errorf("enable MariaDB foreign-key checks: %w", err)
	}
	return nil
}

func copyMigrationTable(ctx context.Context, source *sql.DB, target *sql.Conn, table string, opts DataMigrationOptions) error {
	sourceColumns, err := sqliteMigrationColumns(ctx, source, table)
	if err != nil {
		return err
	}
	targetColumns, err := mariaDBMigrationColumns(ctx, target, table)
	if err != nil {
		return err
	}
	targetSet := make(map[string]struct{}, len(targetColumns))
	for _, column := range targetColumns {
		targetSet[column] = struct{}{}
	}
	columns := make([]string, 0, len(sourceColumns))
	for _, column := range sourceColumns {
		if _, ok := targetSet[column]; ok {
			columns = append(columns, column)
		}
	}
	if len(columns) == 0 {
		return fmt.Errorf("table %s has no shared columns", table)
	}

	quotedTable := quoteMigrationIdentifier(table)
	quotedColumns := make([]string, len(columns))
	placeholders := make([]string, len(columns))
	for i, column := range columns {
		quotedColumns[i] = quoteMigrationIdentifier(column)
		placeholders[i] = "?"
	}
	selectSQL := "SELECT " + strings.Join(quotedColumns, ",") + " FROM " + quotedTable
	insertSQL := "INSERT INTO " + quotedTable + " (" + strings.Join(quotedColumns, ",") +
		") VALUES (" + strings.Join(placeholders, ",") + ")"

	var total int64
	if err := source.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quotedTable).Scan(&total); err != nil {
		return fmt.Errorf("count SQLite table %s: %w", table, err)
	}
	if opts.Progress != nil {
		opts.Progress(table, 0, total)
	}
	if total == 0 {
		return nil
	}

	rows, err := source.QueryContext(ctx, selectSQL)
	if err != nil {
		return fmt.Errorf("read SQLite table %s: %w", table, err)
	}
	defer rows.Close()

	tx, stmt, err := beginMigrationBatch(ctx, target, insertSQL)
	if err != nil {
		return fmt.Errorf("start MariaDB table %s: %w", table, err)
	}
	copied := int64(0)
	inBatch := 0
	for rows.Next() {
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			stmt.Close()
			tx.Rollback()
			return fmt.Errorf("scan SQLite table %s: %w", table, err)
		}
		if _, err := stmt.ExecContext(ctx, values...); err != nil {
			stmt.Close()
			tx.Rollback()
			return fmt.Errorf("insert MariaDB table %s after %d row(s): %w", table, copied, err)
		}
		copied++
		inBatch++
		if inBatch >= opts.BatchSize {
			if err := stmt.Close(); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("commit MariaDB table %s: %w", table, err)
			}
			if opts.Progress != nil {
				opts.Progress(table, copied, total)
			}
			tx, stmt, err = beginMigrationBatch(ctx, target, insertSQL)
			if err != nil {
				return fmt.Errorf("continue MariaDB table %s: %w", table, err)
			}
			inBatch = 0
		}
	}
	if err := rows.Err(); err != nil {
		stmt.Close()
		tx.Rollback()
		return fmt.Errorf("read SQLite table %s: %w", table, err)
	}
	if err := stmt.Close(); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit MariaDB table %s: %w", table, err)
	}
	if opts.Progress != nil {
		opts.Progress(table, copied, total)
	}
	return nil
}

func beginMigrationBatch(ctx context.Context, target *sql.Conn, insertSQL string) (*sql.Tx, *sql.Stmt, error) {
	tx, err := target.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		tx.Rollback()
		return nil, nil, err
	}
	return tx, stmt, nil
}

func sqliteMigrationColumns(ctx context.Context, conn *sql.DB, table string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "PRAGMA table_info("+quoteMigrationIdentifier(table)+")")
	if err != nil {
		return nil, fmt.Errorf("inspect SQLite table %s: %w", table, err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func mariaDBMigrationColumns(ctx context.Context, conn *sql.Conn, table string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT column_name
		  FROM information_schema.columns
		 WHERE table_schema = DATABASE() AND table_name = ?
		 ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, fmt.Errorf("inspect MariaDB table %s: %w", table, err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func quoteMigrationIdentifier(identifier string) string {
	if !migrationIdentifier.MatchString(identifier) {
		panic("unsafe SQL identifier: " + identifier)
	}
	return "`" + identifier + "`"
}
