package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	mysqlDriver "github.com/go-sql-driver/mysql"
)

// Backend identifies the SQL engine used by CaddyUI.
type Backend string

const (
	BackendSQLite  Backend = "sqlite"
	BackendMariaDB Backend = "mariadb"
)

// Config selects and configures a database backend.
type Config struct {
	Backend    Backend
	SQLitePath string
	MariaDBDSN string
}

var backendRegistry sync.Map // *sql.DB -> Backend

func registerBackend(conn *sql.DB, backend Backend) {
	backendRegistry.Store(conn, backend)
}

// BackendOf returns the backend associated with a connection opened by this
// package. Unknown connections are treated as SQLite for compatibility with
// tests that construct their own sql.DB.
func BackendOf(conn *sql.DB) Backend {
	if backend, ok := backendRegistry.Load(conn); ok {
		return backend.(Backend)
	}
	return BackendSQLite
}

func OpenConfig(cfg Config) (*sql.DB, error) {
	switch cfg.Backend {
	case "", BackendSQLite:
		if strings.TrimSpace(cfg.SQLitePath) == "" {
			return nil, errors.New("SQLite path is required")
		}
		return openSQLite(cfg.SQLitePath)
	case BackendMariaDB:
		return openMariaDB(cfg.MariaDBDSN)
	default:
		return nil, fmt.Errorf("unsupported database backend %q (use sqlite or mariadb)", cfg.Backend)
	}
}

func openMariaDB(dsn string) (*sql.DB, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, errors.New("CADDYUI_DB_DSN is required when CADDYUI_DB_DRIVER=mariadb")
	}
	cfg, err := mysqlDriver.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse MariaDB DSN: %w", err)
	}
	if cfg.DBName == "" {
		return nil, errors.New("MariaDB DSN must include a database name")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	if cfg.Collation == "" {
		cfg.Collation = "utf8mb4_unicode_ci"
	}
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	if _, ok := cfg.Params["charset"]; !ok {
		cfg.Params["charset"] = "utf8mb4"
	}

	conn, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open MariaDB: %w", err)
	}
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxLifetime(5 * time.Minute)
	conn.SetConnMaxIdleTime(2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect MariaDB: %w", err)
	}
	registerBackend(conn, BackendMariaDB)
	if err := applyMariaDBSchema(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("apply MariaDB schema: %w", err)
	}
	if err := migrate(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate MariaDB: %w", err)
	}
	return conn, nil
}

func applyMariaDBSchema(conn *sql.DB) error {
	for _, statement := range splitSchemaStatements(mariaDBSchema) {
		if _, err := conn.Exec(statement); err != nil {
			return fmt.Errorf("%w\nstatement: %s", err, statement)
		}
	}
	return nil
}

// splitSchemaStatements is intentionally small: the embedded schema contains
// no stored programs or semicolons inside string literals.
func splitSchemaStatements(schemaText string) []string {
	parts := strings.Split(schemaText, ";")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
