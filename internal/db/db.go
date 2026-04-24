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

-- v2.7.0: raw visitor-analytics events. One row per request handled by any
-- Caddy server shipping its JSON access log to the ingest TCP listener.
-- Retention defaults to 30 days (pruned by a background goroutine); the
-- access_daily rollup below keeps long-term counts without the per-request
-- detail or any IP-level data. Indexes below cover the three query shapes
-- the /analytics page hits: overall-in-window, per-host-in-window, and
-- "live now" (last N minutes, any host).
CREATE TABLE IF NOT EXISTS access_events (
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
CREATE INDEX IF NOT EXISTS idx_access_events_ts      ON access_events(ts);
CREATE INDEX IF NOT EXISTS idx_access_events_host_ts ON access_events(host, ts);

-- v2.7.0: long-term rollup keyed by (day, host). Populated by a nightly
-- aggregator once per UTC midnight so the /analytics page can show 30/90/365-day
-- trends without keeping per-request rows around. unique_visitors is best-effort:
-- distinct client_ip count on the day's events, which is close enough for a
-- dashboard without the overhead of HyperLogLog or similar. No IPs are stored
-- here, so retention is safe indefinitely.
CREATE TABLE IF NOT EXISTS access_daily (
    day TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    views INTEGER NOT NULL DEFAULT 0,
    unique_visitors INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, host)
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

	// Porkbun DNS columns on proxy_hosts (PB DNS integration). Parallel to the
	// Cloudflare pair — a host can have one provider active at a time, chosen
	// in the proxy host form. Porkbun has no "zone ID", so we store the bare
	// domain name the record lives under instead.
	for _, col := range []struct{ name, def string }{
		{"pb_dns_record_id", "TEXT NOT NULL DEFAULT ''"},
		{"pb_domain", "TEXT NOT NULL DEFAULT ''"},
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

	// v2.3.0: unified DNS columns on proxy_hosts. Replaces the per-provider
	// cf_*/pb_* pair with a single triple (provider + zone ID + record ID)
	// + a display-only zone name. Old columns stay for rollback safety;
	// the one-time copy below populates the new ones from whatever legacy
	// state the row is in. Further DNS providers (Namecheap, GoDaddy,
	// DigitalOcean, Hetzner) write only to the new columns.
	for _, col := range []struct{ name, def string }{
		{"dns_provider", "TEXT NOT NULL DEFAULT ''"},      // "" | cloudflare | porkbun | namecheap | godaddy | digitalocean | hetzner
		{"dns_zone_id", "TEXT NOT NULL DEFAULT ''"},       // provider-native zone ID (opaque or domain)
		{"dns_zone_name", "TEXT NOT NULL DEFAULT ''"},     // base domain for display
		{"dns_record_id", "TEXT NOT NULL DEFAULT ''"},     // record ID returned by the provider after create
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

	// v2.5.6: same unified DNS quad on raw_routes so advanced routes can
	// auto-create their A record the way proxy hosts do. Separate loop
	// (rather than a shared tables list) because only these two tables
	// participate in managed DNS — redirection_hosts don't create records.
	for _, col := range []struct{ name, def string }{
		{"dns_provider", "TEXT NOT NULL DEFAULT ''"},
		{"dns_zone_id", "TEXT NOT NULL DEFAULT ''"},
		{"dns_zone_name", "TEXT NOT NULL DEFAULT ''"},
		{"dns_record_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		has, err := columnExists(db, "raw_routes", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE raw_routes ADD COLUMN %s %s`, col.name, col.def)); err != nil {
				return fmt.Errorf("add %s to raw_routes: %w", col.name, err)
			}
		}
	}

	// One-time backfill: populate the unified columns from cf_*/pb_* state
	// for rows that were written by v2.2.x or earlier. We key on "dns_provider
	// is blank AND a legacy column is non-blank" so this is idempotent and
	// safe to run on every startup. (A future admin-UI "reset DNS" action
	// only clears the new columns, so rerunning this wouldn't resurrect a
	// cleared record — by then the legacy columns are stale anyway.)
	if _, err := db.Exec(`UPDATE proxy_hosts
		SET dns_provider = 'cloudflare',
		    dns_zone_id = cf_zone_id,
		    dns_zone_name = cf_zone_id,
		    dns_record_id = cf_dns_record_id
		WHERE dns_provider = '' AND cf_dns_record_id != '' AND cf_zone_id != ''`); err != nil {
		return fmt.Errorf("backfill cloudflare dns columns: %w", err)
	}
	if _, err := db.Exec(`UPDATE proxy_hosts
		SET dns_provider = 'porkbun',
		    dns_zone_id = pb_domain,
		    dns_zone_name = pb_domain,
		    dns_record_id = pb_dns_record_id
		WHERE dns_provider = '' AND pb_dns_record_id != '' AND pb_domain != ''`); err != nil {
		return fmt.Errorf("backfill porkbun dns columns: %w", err)
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

	// v2.4.0: per-server public IP. Every Caddy server can have a different
	// WAN IP, so the A-record target needs to be scoped to the server that
	// actually serves the proxy host — not a single global setting. If the
	// column is new, backfill every row from the legacy global cf_server_ip
	// setting so existing records keep pointing at the right place.
	hasPublicIP, err := columnExists(db, "caddy_servers", "public_ip")
	if err != nil {
		return err
	}
	if !hasPublicIP {
		if _, err := db.Exec(`ALTER TABLE caddy_servers ADD COLUMN public_ip TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add public_ip to caddy_servers: %w", err)
		}
		if _, err := db.Exec(`UPDATE caddy_servers SET public_ip = (SELECT value FROM settings WHERE key='cf_server_ip')
			WHERE public_ip = '' AND EXISTS (SELECT 1 FROM settings WHERE key='cf_server_ip' AND value != '')`); err != nil {
			return fmt.Errorf("backfill public_ip from legacy global setting: %w", err)
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
