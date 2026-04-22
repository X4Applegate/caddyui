package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    is_admin INTEGER DEFAULT 0,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS proxy_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domains TEXT NOT NULL,
    forward_scheme TEXT NOT NULL DEFAULT 'http',
    forward_host TEXT NOT NULL,
    forward_port INTEGER NOT NULL,
    websocket_support INTEGER DEFAULT 0,
    block_common_exploits INTEGER DEFAULT 0,
    ssl_enabled INTEGER DEFAULT 1,
    ssl_forced INTEGER DEFAULT 1,
    http2_support INTEGER DEFAULT 1,
    advanced_config TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    basicauth_enabled INTEGER NOT NULL DEFAULT 0,
    basicauth_users TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS redirection_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domains TEXT NOT NULL,
    forward_scheme TEXT NOT NULL DEFAULT 'auto',
    forward_domain TEXT NOT NULL,
    forward_http_code INTEGER DEFAULT 301,
    preserve_path INTEGER DEFAULT 1,
    ssl_enabled INTEGER DEFAULT 1,
    ssl_forced INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS raw_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    json_data TEXT NOT NULL,
    caddyfile_src TEXT NOT NULL DEFAULT '',
    enabled INTEGER DEFAULT 1,
    certificate_id INTEGER,
    force_ssl INTEGER DEFAULT 0,
    block_common_exploits INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'auto',
    config_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domains TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'pem',
    cert_pem TEXT NOT NULL DEFAULT '',
    key_pem TEXT NOT NULL DEFAULT '',
    cert_path TEXT NOT NULL DEFAULT '',
    key_path TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS caddy_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    admin_url TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'managed',
    tags TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown',
    last_contact_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`

func Open(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite only supports one writer at a time. Limiting the pool to a single
	// connection prevents SQLITE_BUSY errors from concurrent goroutines within
	// the same process. The busy_timeout above handles contention from external
	// processes (e.g. a brief overlap during container restart).
	conn.SetMaxOpenConns(1)
	if err := conn.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(conn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return conn, nil
}

// migrate applies idempotent ALTER TABLEs for columns added after the initial schema.
func migrate(db *sql.DB) error {
	for _, tbl := range []string{"proxy_hosts", "redirection_hosts", "raw_routes"} {
		has, err := columnExists(db, tbl, "certificate_id")
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN certificate_id INTEGER`, tbl)); err != nil {
				return fmt.Errorf("add certificate_id to %s: %w", tbl, err)
			}
		}
	}
	has, err := columnExists(db, "raw_routes", "caddyfile_src")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE raw_routes ADD COLUMN caddyfile_src TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add caddyfile_src to raw_routes: %w", err)
		}
	}
	for _, col := range []string{"force_ssl", "block_common_exploits"} {
		has, err := columnExists(db, "raw_routes", col)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE raw_routes ADD COLUMN %s INTEGER DEFAULT 0`, col)); err != nil {
				return fmt.Errorf("add %s to raw_routes: %w", col, err)
			}
		}
	}
	has, err = columnExists(db, "users", "role")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'`); err != nil {
			return fmt.Errorf("add role to users: %w", err)
		}
		if _, err := db.Exec(`UPDATE users SET role = CASE WHEN is_admin=1 THEN 'admin' ELSE 'view' END`); err != nil {
			return fmt.Errorf("backfill users.role: %w", err)
		}
	}
	// Basic auth columns on proxy_hosts (added post v0.0.4).
	for _, col := range []struct{ name, def string }{
		{"basicauth_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"basicauth_users", "TEXT NOT NULL DEFAULT '[]'"},
		// Feature C: IP access list.
		{"access_list", "TEXT NOT NULL DEFAULT ''"},
		// Feature D: extra upstreams for load balancing.
		{"extra_upstreams", "TEXT NOT NULL DEFAULT '[]'"},
	} {
		has, err := columnExists(db, "proxy_hosts", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE proxy_hosts ADD COLUMN %s %s`, col.name, col.def)); err != nil {
				return fmt.Errorf("add %s to proxy_hosts: %w", col.name, err)
			}
		}
	}

	// TOTP 2FA columns on users.
	for _, col := range []struct{ name, def string }{
		{"totp_secret", "TEXT NOT NULL DEFAULT ''"},
		{"totp_enabled", "INTEGER NOT NULL DEFAULT 0"},
	} {
		has, err := columnExists(db, "users", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE users ADD COLUMN %s %s`, col.name, col.def)); err != nil {
				return fmt.Errorf("add %s to users: %w", col.name, err)
			}
		}
	}

	// Caddy version column on caddy_servers (fetched from admin API health poll).
	has, err = columnExists(db, "caddy_servers", "version")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE caddy_servers ADD COLUMN version TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add version to caddy_servers: %w", err)
		}
	}

	// Multi-server: every content row belongs to exactly one Caddy server.
	// Default 1 lets pre-upgrade rows bind to the bootstrap server seeded in server.New.
	for _, tbl := range []string{"proxy_hosts", "redirection_hosts", "raw_routes", "certificates", "config_snapshots", "activity_log"} {
		has, err := columnExists(db, tbl, "server_id")
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN server_id INTEGER NOT NULL DEFAULT 1`, tbl)); err != nil {
				return fmt.Errorf("add server_id to %s: %w", tbl, err)
			}
		}
	}

	// Per-user ownership: owner_id NULL = global/admin-owned; owner_id = user.ID = owned by that user.
	for _, tbl := range []string{"proxy_hosts", "redirection_hosts", "raw_routes"} {
		has, err := columnExists(db, tbl, "owner_id")
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN owner_id INTEGER`, tbl)); err != nil {
				return fmt.Errorf("add owner_id to %s: %w", tbl, err)
			}
		}
	}

	// Cloudflare DNS columns on proxy_hosts (CF DNS integration).
	for _, col := range []struct{ name, def string }{
		{"cf_dns_record_id", "TEXT NOT NULL DEFAULT ''"},
		{"cf_zone_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		has, err := columnExists(db, "proxy_hosts", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE proxy_hosts ADD COLUMN %s %s`, col.name, col.def)); err != nil {
				return fmt.Errorf("add %s to proxy_hosts: %w", col.name, err)
			}
		}
	}

	// Admin-API auth columns on caddy_servers. Lets users put Caddy's admin
	// endpoint behind HTTP Basic Auth (via a reverse proxy) when they can't
	// use WireGuard/Tailscale to hide port 2019 on a private network.
	for _, col := range []struct{ name, def string }{
		{"admin_username", "TEXT NOT NULL DEFAULT ''"},
		{"admin_password", "TEXT NOT NULL DEFAULT ''"},
	} {
		has, err := columnExists(db, "caddy_servers", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE caddy_servers ADD COLUMN %s %s`, col.name, col.def)); err != nil {
				return fmt.Errorf("add %s to caddy_servers: %w", col.name, err)
			}
		}
	}

	return nil
}

func columnExists(db *sql.DB, table, col string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}
