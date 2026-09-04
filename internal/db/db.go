package db

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

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

-- Tracks one-way Caddy Fleet deployments so repeating "Also deploy to" or a
-- full configuration sync updates the same target row instead of inserting a
-- duplicate. Resource rows remain independently editable on each server.
CREATE TABLE IF NOT EXISTS fleet_deployments (
    source_server_id INTEGER NOT NULL,
    resource_kind VARCHAR(32) NOT NULL,
    source_resource_id INTEGER NOT NULL,
    target_server_id INTEGER NOT NULL,
    target_resource_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source_server_id, resource_kind, source_resource_id, target_server_id)
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
    server_id INTEGER NOT NULL DEFAULT 0,
    server_name TEXT NOT NULL DEFAULT '',
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
-- v2.9.206: indexes for status-code breakdown card and unique-visitor count.
-- (path, ts) intentionally omitted — path values are high-cardinality and the
-- index would be larger than the table itself; top-paths queries already use
-- the (host, ts) range scan + GROUP BY which is fast enough.
CREATE INDEX IF NOT EXISTS idx_access_events_status_ts    ON access_events(status, ts);
CREATE INDEX IF NOT EXISTS idx_access_events_client_ip_ts ON access_events(client_ip, ts);

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
    -- v2.9.207: per-day status-class buckets so StatusBucketsSince can read
    -- the rollup for long windows instead of scanning access_events. Five
    -- nullable-defaulted columns mirror the StatusBuckets struct so the
    -- aggregator just SUMs them. Older rollup rows pre-2.9.207 will report
    -- zero for these classes — first hourly aggregator pass repopulates the
    -- last 365 days, see AggregateAccessDaily.
    s2xx INTEGER NOT NULL DEFAULT 0,
    s3xx INTEGER NOT NULL DEFAULT 0,
    s4xx INTEGER NOT NULL DEFAULT 0,
    s5xx INTEGER NOT NULL DEFAULT 0,
    s_other INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, host)
);

-- Latest observed ACME lifecycle state for each certificate identifier on
-- each Caddy server. Runtime logs remain ephemeral; only this compact status
-- projection is persisted so issuance failures survive a UI refresh/restart.
CREATE TABLE IF NOT EXISTS certificate_lifecycle (
    server_id INTEGER NOT NULL,
    server_name TEXT NOT NULL DEFAULT '',
    identifier VARCHAR(255) NOT NULL,
    phase VARCHAR(32) NOT NULL DEFAULT '',
    level VARCHAR(16) NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_id, identifier)
);

-- v2.7.4: groups let admin bundle user-role accounts into a team. Every user
-- in a group sees every other member's proxy hosts / redirects / raw routes /
-- certificates in their own list (read-only — edit/delete stays owner-scoped
-- at the handler level). One user may belong to many groups; one group may
-- have many members. user_groups is the many-to-many join. ON DELETE CASCADE
-- on both sides so removing a user or a group cleans up its memberships.
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_groups (
    user_id  INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);

-- v2.9.1: API tokens for programmatic / headless access.
-- token_hash is SHA-256(raw_token) stored as lowercase hex.
-- expires_at NULL means the token never expires.
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- v2.9.1: per-proxy-host health check history.
-- checked_at is a Unix timestamp. ok=1 means the check succeeded (HTTP 2xx).
-- Keeps last 288 checks per host (24 hours at 5-minute intervals).
CREATE TABLE IF NOT EXISTS proxy_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_host_id INTEGER NOT NULL,
    checked_at INTEGER NOT NULL,
    ok INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    error_msg TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_proxy_health_host_ts ON proxy_health(proxy_host_id, checked_at);
`

// Open opens the default SQLite backend. It remains the compatibility entry
// point used by tests and existing installations; new multi-backend callers
// should use OpenConfig.
func Open(path string) (*sql.DB, error) {
	return openSQLite(path)
}

func openSQLite(path string) (*sql.DB, error) {
	// v2.9.206: tune SQLite for analytics workloads.
	//   cache_size=-262144  → 256 MiB page cache (default ~2 MiB)
	//   mmap_size=268435456 → 256 MiB mmap window for index scans
	//   synchronous=NORMAL  → safe with WAL, faster writes during analytics reads
	//   temp_store=MEMORY   → keep GROUP BY / DISTINCT temp tables in RAM
	dsn := path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=cache_size(-262144)" +
		"&_pragma=mmap_size(268435456)" +
		"&_pragma=temp_store(MEMORY)"
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
	registerBackend(conn, BackendSQLite)
	return conn, nil
}

// migrationStep runs one idempotent schema-upgrade statement, reporting
// failures instead of discarding them.
//
// These were historically written as `migrationStep(db, ...)`, which made a
// failed upgrade invisible: the column simply never appeared, and the app
// then failed at query time far from the real cause. Issue #30 was exactly
// this shape — an index built before the column it referenced existed.
//
// Failures are counted and logged rather than fatal. Every caller guards its
// statement with columnExists2, so a failure here is abnormal but not
// automatically unrecoverable, and aborting startup outright would take an
// otherwise-serviceable install offline. migrate() logs one loud summary at
// the end so a broken upgrade is visible in the first screen of logs.
func migrationStep(db *sql.DB, query string) {
	if _, err := db.Exec(query); err != nil {
		migrationFailures++
		log.Printf("db: MIGRATION FAILED: %v — %s", err, summarizeMigration(query))
	}
}

// migrationFailures counts steps that failed during the current migrate() run.
// migrate() is called once per process from Open, before any request is
// served, so a plain counter needs no synchronisation.
var migrationFailures int

// summarizeMigration collapses a schema statement to one line for logging, so
// a multi-line CREATE INDEX doesn't swamp the log.
func summarizeMigration(query string) string {
	fields := strings.Fields(query)
	if len(fields) > 12 {
		fields = append(fields[:12], "...")
	}
	return strings.Join(fields, " ")
}

// migrate applies idempotent ALTER TABLEs for columns added after the initial schema.
func migrate(db *sql.DB) error {
	migrationFailures = 0
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
	for _, tbl := range []string{"proxy_hosts", "redirection_hosts", "raw_routes"} {
		has, err := columnExists(db, tbl, "dns_profile_id")
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN dns_profile_id TEXT NOT NULL DEFAULT ''`, tbl)); err != nil {
				return fmt.Errorf("add dns_profile_id to %s: %w", tbl, err)
			}
		}
	}
	// Managed DNS can be used for ACME DNS-01 without publishing a public
	// A record. Defaulting to 0 preserves pre-v2.23.1 behaviour.
	for _, tbl := range []string{"proxy_hosts", "redirection_hosts", "raw_routes"} {
		has, err := columnExists(db, tbl, "dns_skip_record")
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN dns_skip_record INTEGER NOT NULL DEFAULT 0`, tbl)); err != nil {
				return fmt.Errorf("add dns_skip_record to %s: %w", tbl, err)
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
	//
	// v2.7.2: certificates joined the ownership model. Pre-2.7.2 rows migrate
	// with owner_id = NULL, i.e. admin-owned / global — any user-role account
	// can still pick them from the proxy-host dropdown, but only admin can
	// edit or delete them. New uploads from a user-role account get tagged
	// with that user's ID so they're private to the uploader + admin.
	for _, tbl := range []string{"proxy_hosts", "redirection_hosts", "raw_routes", "certificates"} {
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
		{"dns_provider", "TEXT NOT NULL DEFAULT ''"},  // "" | cloudflare | porkbun | namecheap | godaddy | digitalocean | hetzner | route53
		{"dns_zone_id", "TEXT NOT NULL DEFAULT ''"},   // provider-native zone ID (opaque or domain)
		{"dns_zone_name", "TEXT NOT NULL DEFAULT ''"}, // base domain for display
		{"dns_record_id", "TEXT NOT NULL DEFAULT ''"}, // record ID returned by the provider after create
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
	// (rather than a shared tables list) because only these tables
	// participate in managed DNS.
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

	// v2.12.2: extend the same unified DNS quad to redirection_hosts so
	// users can auto-create A records for redirect-only hostnames too.
	for _, col := range []struct{ name, def string }{
		{"dns_provider", "TEXT NOT NULL DEFAULT ''"},
		{"dns_zone_id", "TEXT NOT NULL DEFAULT ''"},
		{"dns_zone_name", "TEXT NOT NULL DEFAULT ''"},
		{"dns_record_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		has, err := columnExists(db, "redirection_hosts", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE redirection_hosts ADD COLUMN %s %s`, col.name, col.def)); err != nil {
				return fmt.Errorf("add %s to redirection_hosts: %w", col.name, err)
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
	// v2.37.0: per-node log ingest target (host:port). '' = the fleet-wide
	// Settings → Analytics target. Nodes on other hosts can't resolve the
	// default Docker service name, so they need their own.
	hasIngestTarget, err := columnExists(db, "caddy_servers", "ingest_target")
	if err != nil {
		return err
	}
	if !hasIngestTarget {
		if _, err := db.Exec(`ALTER TABLE caddy_servers ADD COLUMN ingest_target TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add ingest_target to caddy_servers: %w", err)
		}
	}
	hasPublicIP, err := columnExists(db, "caddy_servers", "public_ip")
	if err != nil {
		return err
	}
	if !hasPublicIP {
		if _, err := db.Exec(`ALTER TABLE caddy_servers ADD COLUMN public_ip TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add public_ip to caddy_servers: %w", err)
		}
		if _, err := db.Exec("UPDATE caddy_servers SET public_ip = (SELECT value FROM settings WHERE `key`='cf_server_ip') " +
			"WHERE public_ip = '' AND EXISTS (SELECT 1 FROM settings WHERE `key`='cf_server_ip' AND value != '')"); err != nil {
			return fmt.Errorf("backfill public_ip from legacy global setting: %w", err)
		}
	}

	// v2.9.0: per-host security settings — response compression, security
	// headers bundle, and TLS minimum version. All default to off / empty so
	// existing hosts are unaffected after upgrade.
	for _, col := range []struct{ name, def string }{
		{"compression_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"security_headers_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"tls_min_version", "TEXT NOT NULL DEFAULT ''"},
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

	// v2.9.1: per-host custom request/response headers.
	for _, col := range []struct{ name, def string }{
		{"custom_req_headers", "TEXT NOT NULL DEFAULT '{}'"},
		{"custom_resp_headers", "TEXT NOT NULL DEFAULT '{}'"},
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

	// v2.9.2: URL rewrite rules per proxy host.
	// Stored as JSON array of {type, from, to} objects.
	hasURLRewrites, err := columnExists(db, "proxy_hosts", "url_rewrites")
	if err != nil {
		return err
	}
	if !hasURLRewrites {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN url_rewrites TEXT NOT NULL DEFAULT '[]'`); err != nil {
			return fmt.Errorf("add url_rewrites: %w", err)
		}
	}

	// v2.9.3: maintenance mode per proxy host.
	hasMaintMode, err := columnExists(db, "proxy_hosts", "maintenance_mode")
	if err != nil {
		return err
	}
	if !hasMaintMode {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN maintenance_mode INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add maintenance_mode: %w", err)
		}
	}

	// v2.9.3: request body size limit in MiB (0 = unlimited).
	hasMaxBody, err := columnExists(db, "proxy_hosts", "max_request_body_mb")
	if err != nil {
		return err
	}
	if !hasMaxBody {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN max_request_body_mb INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add max_request_body_mb: %w", err)
		}
	}

	// v2.9.3: sticky sessions (cookie-based LB selection policy).
	hasStickySession, err := columnExists(db, "proxy_hosts", "sticky_sessions")
	if err != nil {
		return err
	}
	if !hasStickySession {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN sticky_sessions INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add sticky_sessions: %w", err)
		}
	}

	// v2.9.3: upstream response timeout in seconds (0 = use Caddy default).
	if !columnExists2(db, "proxy_hosts", "upstream_timeout_sec") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN upstream_timeout_sec INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add upstream_timeout_sec: %w", err)
		}
	}

	// v2.9.3: CORS — enabled flag + allowed origins string.
	if !columnExists2(db, "proxy_hosts", "cors_enabled") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN cors_enabled INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add cors_enabled: %w", err)
		}
	}
	if !columnExists2(db, "proxy_hosts", "cors_origins") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN cors_origins TEXT NOT NULL DEFAULT '*'`); err != nil {
			return fmt.Errorf("add cors_origins: %w", err)
		}
	}

	// v2.9.4: active upstream health check URI and interval.
	if !columnExists2(db, "proxy_hosts", "health_check_uri") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN health_check_uri TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add health_check_uri: %w", err)
		}
	}
	if !columnExists2(db, "proxy_hosts", "health_check_interval_sec") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN health_check_interval_sec INTEGER NOT NULL DEFAULT 30`); err != nil {
			return fmt.Errorf("add health_check_interval_sec: %w", err)
		}
	}
	// v2.9.4: keepalive connection pool size (0 = Caddy default).
	if !columnExists2(db, "proxy_hosts", "keepalive_conns") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN keepalive_conns INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add keepalive_conns: %w", err)
		}
	}

	// v2.9.4: proxy host tags (comma-separated, UI-only metadata).
	if !columnExists2(db, "proxy_hosts", "tags") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN tags TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add tags: %w", err)
		}
	}

	// v2.9.4: freeform notes per proxy host (UI-only metadata).
	if !columnExists2(db, "proxy_hosts", "notes") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN notes TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add notes: %w", err)
		}
	}

	// v2.9.5: disable access log collection for this host.
	if !columnExists2(db, "proxy_hosts", "disable_access_log") {
		if _, err := db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN disable_access_log INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add disable_access_log: %w", err)
		}
	}

	if !columnExists2(db, "proxy_hosts", "maintenance_msg") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_msg TEXT NOT NULL DEFAULT ''`)
	}

	if !columnExists2(db, "proxy_hosts", "add_request_id") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_request_id INTEGER NOT NULL DEFAULT 0`)
	}

	if !columnExists2(db, "proxy_hosts", "strip_resp_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_resp_headers TEXT NOT NULL DEFAULT ''`)
	}

	if !columnExists2(db, "proxy_hosts", "blocked_agents") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN blocked_agents TEXT NOT NULL DEFAULT ''`)
	}

	if !columnExists2(db, "proxy_hosts", "health_check_method") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_method TEXT NOT NULL DEFAULT 'GET'`)
	}

	if !columnExists2(db, "proxy_hosts", "maintenance_status_code") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_status_code INTEGER NOT NULL DEFAULT 503`)
	}

	if !columnExists2(db, "proxy_hosts", "response_cache_control") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN response_cache_control TEXT NOT NULL DEFAULT ''`)
	}

	if !columnExists2(db, "proxy_hosts", "upstream_sni") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_sni TEXT NOT NULL DEFAULT ''`)
	}

	if !columnExists2(db, "proxy_hosts", "hsts_preload") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN hsts_preload INTEGER NOT NULL DEFAULT 0`)
	}

	if !columnExists2(db, "proxy_hosts", "max_conns_per_host") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN max_conns_per_host INTEGER NOT NULL DEFAULT 0`)
	}

	if !columnExists2(db, "proxy_hosts", "health_check_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_timeout_sec INTEGER NOT NULL DEFAULT 5`)
	}

	if !columnExists2(db, "proxy_hosts", "upstream_retries") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_retries INTEGER NOT NULL DEFAULT 0`)
	}

	if !columnExists2(db, "proxy_hosts", "force_http1") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN force_http1 INTEGER NOT NULL DEFAULT 0`)
	}

	if !columnExists2(db, "proxy_hosts", "basicauth_realm") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN basicauth_realm TEXT NOT NULL DEFAULT 'Restricted'`)
	}

	// api_tokens: add scopes column
	if !columnExists2(db, "api_tokens", "scopes") {
		migrationStep(db, `ALTER TABLE api_tokens ADD COLUMN scopes TEXT NOT NULL DEFAULT 'full'`)
	}

	// TOTP backup codes: single-use recovery codes stored as JSON array of SHA-256 hashes.
	if !columnExists2(db, "users", "totp_backup_codes") {
		migrationStep(db, `ALTER TABLE users ADD COLUMN totp_backup_codes TEXT NOT NULL DEFAULT ''`)
	}

	// v2.12.27: per-user color theme. Empty string = use the default
	// slate-blue palette; "orange" = the carbon-orange palette added in
	// v2.12.22. Stored on users so the preference follows the account
	// across devices instead of being trapped in per-browser localStorage.
	if !columnExists2(db, "users", "color_theme") {
		migrationStep(db, `ALTER TABLE users ADD COLUMN color_theme TEXT NOT NULL DEFAULT ''`)
	}

	if !columnExists2(db, "proxy_hosts", "error_page_html") {
		_, err = db.Exec(`ALTER TABLE proxy_hosts ADD COLUMN error_page_html TEXT NOT NULL DEFAULT ''`)
		if err != nil {
			return err
		}
	}

	// v2.9.5: scheduled maintenance windows — auto-sync Caddy at window boundaries.
	if !columnExists2(db, "proxy_hosts", "maintenance_window_start") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_window_start TEXT NOT NULL DEFAULT ''`)
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_window_end TEXT NOT NULL DEFAULT ''`)
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_window_days TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.5: per-host IP blocklist — deny specific CIDR ranges with 403.
	if !columnExists2(db, "proxy_hosts", "ip_blocklist") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN ip_blocklist TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.5: load-balancer selection policy for multi-upstream hosts.
	if !columnExists2(db, "proxy_hosts", "lb_policy") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_policy TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.5: PROXY protocol version for upstream connections ("" | "v1" | "v2").
	if !columnExists2(db, "proxy_hosts", "proxy_protocol") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN proxy_protocol TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.5: custom robots.txt content to inject before the reverse proxy.
	if !columnExists2(db, "proxy_hosts", "robots_txt") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN robots_txt TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.5: tags and notes for redirection hosts — parity with proxy hosts.
	if !columnExists2(db, "redirection_hosts", "tags") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN tags TEXT NOT NULL DEFAULT ''`)
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN notes TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.5: passive health check configuration for upstream failure detection.
	if !columnExists2(db, "proxy_hosts", "passive_fail_duration_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN passive_fail_duration_sec INTEGER NOT NULL DEFAULT 0`)
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN passive_max_fails INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.5: HSTS max-age override and Content-Security-Policy header.
	if !columnExists2(db, "proxy_hosts", "hsts_max_age_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN hsts_max_age_sec INTEGER NOT NULL DEFAULT 0`)
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN csp_header TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.5: H2C (HTTP/2 cleartext) upstream transport for gRPC and similar.
	if !columnExists2(db, "proxy_hosts", "h2c_enabled") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN h2c_enabled INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.5: custom upstream health-check request headers.
	if !columnExists2(db, "proxy_hosts", "health_check_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_headers TEXT NOT NULL DEFAULT '{}'`)
	}

	// v2.9.6: streaming / flush mode, response buffering, per-host trusted proxies.
	if !columnExists2(db, "proxy_hosts", "flush_immediate") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN flush_immediate INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "buffer_responses") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN buffer_responses INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "trusted_proxies") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN trusted_proxies TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.7: upstream Host header override, response body read timeout, dotfile blocking.
	if !columnExists2(db, "proxy_hosts", "upstream_host_override") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_host_override TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "read_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN read_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "deny_dotfiles") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_dotfiles INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.8: request body buffering; CORS credentials and expose-headers.
	if !columnExists2(db, "proxy_hosts", "request_buffers_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN request_buffers_kb INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "cors_allow_credentials") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cors_allow_credentials INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "cors_expose_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cors_expose_headers TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.9: verify upstream TLS certificate (off by default to preserve
	// existing skip-verify behaviour); separate dial timeout.
	if !columnExists2(db, "proxy_hosts", "ssl_verify_upstream") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN ssl_verify_upstream INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "dial_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN dial_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.10: API key header authentication; block empty User-Agent.
	if !columnExists2(db, "proxy_hosts", "api_key_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN api_key_header TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "api_key_value") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN api_key_value TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "block_empty_user_agent") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_empty_user_agent INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.11: error redirect URL; granular security header overrides.
	if !columnExists2(db, "proxy_hosts", "error_redirect_url") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN error_redirect_url TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "permissions_policy") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN permissions_policy TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "x_frame_options") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN x_frame_options TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "referrer_policy") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN referrer_policy TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.13: IP access control, maintenance mode, and maintenance message
	// for redirection hosts — feature parity with proxy hosts.
	if !columnExists2(db, "redirection_hosts", "access_list") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN access_list TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "redirection_hosts", "maintenance_mode") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN maintenance_mode INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "redirection_hosts", "maintenance_msg") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN maintenance_msg TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.14: HSTS includeSubDomains toggle — DEFAULT 1 so existing hosts that
	// already relied on the previously-hardcoded includeSubDomains keep working.
	if !columnExists2(db, "proxy_hosts", "hsts_include_subdomains") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN hsts_include_subdomains INTEGER NOT NULL DEFAULT 1`)
	}
	// v2.9.14: Content-Security-Policy-Report-Only header (report-only mode).
	if !columnExists2(db, "proxy_hosts", "csp_report_only") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN csp_report_only TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.14: per-host keepalive idle timeout in seconds (0 = use default 90s).
	if !columnExists2(db, "proxy_hosts", "keepalive_idle_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN keepalive_idle_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.15: active health check expected status code and response body regexp.
	// expect_status 0 = accept any 2xx; >0 = require that exact code.
	if !columnExists2(db, "proxy_hosts", "health_check_expect_status") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_expect_status INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "health_check_expect_body") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_expect_body TEXT NOT NULL DEFAULT ''`)
	}
	// follow_redirects: when 1, Caddy follows HTTP redirects during health probes.
	if !columnExists2(db, "proxy_hosts", "health_check_follow_redirects") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_follow_redirects INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.16: path-based routing — restrict this proxy host to requests whose
	// path starts with path_matcher (e.g. "/api"). strip_path_prefix removes
	// the prefix before forwarding to the upstream when enabled.
	if !columnExists2(db, "proxy_hosts", "path_matcher") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN path_matcher TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "strip_path_prefix") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_path_prefix INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.17: load-balancer tuning — custom sticky-session cookie name,
	// try_duration (how long to keep retrying across upstreams before giving up),
	// and try_interval (delay between retry attempts in milliseconds).
	if !columnExists2(db, "proxy_hosts", "sticky_cookie_name") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN sticky_cookie_name TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "lb_try_duration_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_try_duration_sec INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "lb_try_interval_ms") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_try_interval_ms INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.18: compression minimum size — skip compressing responses smaller
	// than this many kilobytes (0 = compress everything, Caddy default).
	if !columnExists2(db, "proxy_hosts", "compression_min_size_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN compression_min_size_kb INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.18: forward real client IP as X-Real-IP header to upstream.
	if !columnExists2(db, "proxy_hosts", "forward_client_ip") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN forward_client_ip INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.19: CORS fine-tuning — custom preflight max-age, allowed methods,
	// and allowed headers. 0 / empty = use the existing defaults.
	if !columnExists2(db, "proxy_hosts", "cors_max_age_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cors_max_age_sec INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "cors_allow_methods") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cors_allow_methods TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "cors_allow_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cors_allow_headers TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.20: custom response headers on redirection hosts — allows operators
	// to inject headers (e.g. Cache-Control, X-Robots-Tag) into redirect responses.
	if !columnExists2(db, "redirection_hosts", "custom_resp_headers") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN custom_resp_headers TEXT NOT NULL DEFAULT '{}'`)
	}

	// v2.9.21: IP blocklist for redirection hosts — deny specific CIDRs
	// before the redirect fires (parity with proxy hosts which have ip_blocklist).
	if !columnExists2(db, "redirection_hosts", "ip_blocklist") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN ip_blocklist TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.22: retry on specific upstream HTTP status codes for proxy hosts.
	// Complements upstream_retries (connection failures) with status-code-based retry.
	if !columnExists2(db, "proxy_hosts", "retry_status_codes") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN retry_status_codes TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.22: write_timeout — time allowed to transmit the request body to the upstream.
	if !columnExists2(db, "proxy_hosts", "write_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN write_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.23: upstream TLS minimum version — enforce TLS 1.2 or 1.3 for upstream connections.
	if !columnExists2(db, "proxy_hosts", "upstream_tls_min_version") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_min_version TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.23: forward_proxy_url — chain outbound requests through an upstream HTTP proxy.
	if !columnExists2(db, "proxy_hosts", "forward_proxy_url") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN forward_proxy_url TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.24: HSTS for redirection hosts — inject Strict-Transport-Security on redirect
	// responses so browsers skip HTTP for subsequent visits after the first redirect.
	if !columnExists2(db, "redirection_hosts", "hsts_max_age_sec") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN hsts_max_age_sec INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "redirection_hosts", "hsts_include_subdomains") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN hsts_include_subdomains INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "redirection_hosts", "hsts_preload") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN hsts_preload INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.25: blocked_methods — comma-separated HTTP methods that return 405 before proxying.
	// Useful for hardening: TRACE, CONNECT, or custom methods you never want routed.
	if !columnExists2(db, "proxy_hosts", "blocked_methods") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN blocked_methods TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.26: advanced_config for redirection hosts — raw JSON array of Caddy handlers
	// injected before the redirect fires. Gives power users full control without
	// needing the Caddyfile adapter. Format: [{"handler":"...","...":"..."},...].
	if !columnExists2(db, "redirection_hosts", "advanced_config") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN advanced_config TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.27: forward_auth — delegate authentication to an external service
	// (e.g. Authelia, Authentik) before proxying. Only forwards if the auth
	// service returns 2xx; otherwise returns its response (typically 401/403).
	if !columnExists2(db, "proxy_hosts", "forward_auth_url") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN forward_auth_url TEXT NOT NULL DEFAULT ''`)
	}
	// forward_auth_copy_headers: comma-separated response headers from the auth
	// service that are copied to the proxied upstream request.
	if !columnExists2(db, "proxy_hosts", "forward_auth_copy_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN forward_auth_copy_headers TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.28: query string control for proxy hosts.
	// strip_query_string: remove the entire query string before forwarding.
	if !columnExists2(db, "proxy_hosts", "strip_query_string") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_query_string INTEGER NOT NULL DEFAULT 0`)
	}
	// delete_query_params: comma-separated query param names to remove before forwarding
	// (e.g. "utm_source,utm_medium,fbclid" strips common tracking parameters).
	if !columnExists2(db, "proxy_hosts", "delete_query_params") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN delete_query_params TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.29: request body read timeout — how long to wait for the client to
	// finish sending the request body. 0 = no limit. Guards against slow-body attacks.
	if !columnExists2(db, "proxy_hosts", "request_body_read_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN request_body_read_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.29: response_header_timeout_sec — independent control over how long
	// to wait for the upstream to start sending response headers, separate from
	// the combined upstream_timeout_sec. 0 = falls back to upstream_timeout_sec.
	if !columnExists2(db, "proxy_hosts", "response_header_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN response_header_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.31: max_conn_duration_sec — maximum lifetime of an upstream connection
	// before Caddy replaces it. 0 = unlimited. Useful with cloud load balancers
	// (e.g. AWS ALB) that forcibly close long-lived idle connections.
	if !columnExists2(db, "proxy_hosts", "max_conn_duration_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN max_conn_duration_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.32: decompress_response — when true, Caddy decompresses upstream
	// gzip/br responses before forwarding, enabling response-body transforms.
	if !columnExists2(db, "proxy_hosts", "decompress_response") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN decompress_response INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.33: color label — short color token for visual host grouping in the
	// list view (e.g. "red", "green", "blue"). No Caddy impact.
	if !columnExists2(db, "proxy_hosts", "color") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN color TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "redirection_hosts", "color") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN color TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.34: www_redirect — automatically redirect between www and bare
	// domain variants. Values: '' (disabled) | 'to_www' | 'to_bare'.
	if !columnExists2(db, "proxy_hosts", "www_redirect") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN www_redirect TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.35: strip_req_headers — comma-separated list of request header names
	// to delete before forwarding to the upstream. Companion to strip_resp_headers.
	if !columnExists2(db, "proxy_hosts", "strip_req_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_req_headers TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.36: upstream_path_prefix — static path prefix prepended to every
	// upstream request URI. Useful when the upstream app is mounted under a
	// subpath different from the public URL (e.g. proxy / → upstream /v2).
	if !columnExists2(db, "proxy_hosts", "upstream_path_prefix") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_path_prefix TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.37: compression_level — gzip compression level (0 = default, 1-9).
	// Higher levels compress more but use more CPU. zstd level: 0 = default, 1-22.
	if !columnExists2(db, "proxy_hosts", "compression_level") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN compression_level INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.37: compression_prefer_gzip — prefer gzip over zstd for broader
	// client compatibility (e.g. older Safari or caching proxies that don't
	// support zstd).
	if !columnExists2(db, "proxy_hosts", "compression_prefer_gzip") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN compression_prefer_gzip INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.38: maintenance_status_code for redirection hosts — parity with
	// proxy hosts. Defaults to 503; admin can use 429, 502, or 520.
	if !columnExists2(db, "redirection_hosts", "maintenance_status_code") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN maintenance_status_code INTEGER NOT NULL DEFAULT 503`)
	}

	// v2.9.39: sort_order — integer weight for manual ordering in the list
	// view. Lower values appear first. Default 0 keeps existing ordering.
	if !columnExists2(db, "proxy_hosts", "sort_order") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "redirection_hosts", "sort_order") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0`)
	}
	// List-page indexes. These keep ordering and last-sync lookups predictable
	// as an enterprise installation grows beyond a few dozen resources.
	migrationStep(db, `CREATE INDEX IF NOT EXISTS idx_proxy_hosts_server_sort
		ON proxy_hosts(server_id, sort_order, id DESC)`)
	migrationStep(db, `CREATE INDEX IF NOT EXISTS idx_raw_routes_server_id
		ON raw_routes(server_id, id)`)
	migrationStep(db, `CREATE INDEX IF NOT EXISTS idx_certificates_server_id
		ON certificates(server_id, id DESC)`)
	migrationStep(db, `CREATE INDEX IF NOT EXISTS idx_activity_log_server_action_id
		ON activity_log(server_id, action, id DESC)`)

	// v2.9.41: allowed_methods — HTTP method allowlist (empty = allow all; complement to blocked_methods denylist)
	if !columnExists2(db, "proxy_hosts", "allowed_methods") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN allowed_methods TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.42: upstream_max_resp_header_kb — cap on response header bytes from upstream (0 = Caddy default)
	if !columnExists2(db, "proxy_hosts", "upstream_max_resp_header_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_max_resp_header_kb INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.43: health_check_port — separate port for active health probes (0 = same port as traffic)
	if !columnExists2(db, "proxy_hosts", "health_check_port") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_port INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.44: request_id_header_name — custom header for injected request IDs ('' = X-Request-Id)
	if !columnExists2(db, "proxy_hosts", "request_id_header_name") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN request_id_header_name TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.45: lb_cookie_path — cookie path scope for sticky-session load balancing
	if !columnExists2(db, "proxy_hosts", "lb_cookie_path") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_cookie_path TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.46: passive_unhealthy_latency_ms — mark upstream unhealthy above this response latency
	if !columnExists2(db, "proxy_hosts", "passive_unhealthy_latency_ms") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN passive_unhealthy_latency_ms INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.47: tls_handshake_timeout_sec — TLS handshake timeout for upstream connections (0 = Caddy default)
	if !columnExists2(db, "proxy_hosts", "tls_handshake_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN tls_handshake_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.48: expect_continue_timeout_sec — wait for 100-Continue from upstream (0 = disabled)
	if !columnExists2(db, "proxy_hosts", "expect_continue_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN expect_continue_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.49: response_buffers_kb — per-connection response streaming buffer size (0 = Caddy default)
	if !columnExists2(db, "proxy_hosts", "response_buffers_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN response_buffers_kb INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.50: upstream_max_idle_conns — total idle upstream connections across all hosts (0 = Caddy default)
	if !columnExists2(db, "proxy_hosts", "upstream_max_idle_conns") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_max_idle_conns INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.51: upstream_keep_alive_probe_sec — keepalive probe interval in seconds (0 = no probing)
	if !columnExists2(db, "proxy_hosts", "upstream_keep_alive_probe_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_keep_alive_probe_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.52: forward_auth_method — HTTP method for the ForwardAuth subrequest ('' = GET default)
	if !columnExists2(db, "proxy_hosts", "forward_auth_method") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN forward_auth_method TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.53: grpc_web_enabled — enable gRPC-Web protocol transcoding for browser clients
	if !columnExists2(db, "proxy_hosts", "grpc_web_enabled") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN grpc_web_enabled INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.54: forward_auth_headers_prefix — prefix for headers copied from ForwardAuth response
	if !columnExists2(db, "proxy_hosts", "forward_auth_headers_prefix") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN forward_auth_headers_prefix TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.55: health_check_max_size_kb — max response body size read during active health checks
	if !columnExists2(db, "proxy_hosts", "health_check_max_size_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_max_size_kb INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.56: strip_path_suffix — strip a static suffix from the request path before forwarding
	if !columnExists2(db, "proxy_hosts", "strip_path_suffix") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_path_suffix TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.57: add_req_query_params — key=value pairs appended to upstream query string
	if !columnExists2(db, "proxy_hosts", "add_req_query_params") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_req_query_params TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.58: error_page_codes — comma-separated HTTP status codes that trigger the custom error page
	if !columnExists2(db, "proxy_hosts", "error_page_codes") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN error_page_codes TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.59: upstream_tls_ca_pem_file — path to CA bundle for upstream TLS cert verification
	if !columnExists2(db, "proxy_hosts", "upstream_tls_ca_pem_file") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_ca_pem_file TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.60: keepalive_disabled — completely disable upstream keepalive (e.g. for NTLM auth upstreams)
	if !columnExists2(db, "proxy_hosts", "keepalive_disabled") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN keepalive_disabled INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.61: trailing_slash_redirect — "" | "add" | "remove" — auto-redirect for trailing slash normalisation
	if !columnExists2(db, "proxy_hosts", "trailing_slash_redirect") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN trailing_slash_redirect TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.62: dial_fallback_delay_ms — time before falling back to next upstream after dial failure (0 = Caddy default)
	if !columnExists2(db, "proxy_hosts", "dial_fallback_delay_ms") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN dial_fallback_delay_ms INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.63: upstream_network — TCP network type for upstream dial ("" | "tcp4" | "tcp6")
	if !columnExists2(db, "proxy_hosts", "upstream_network") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_network TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.64: dns_resolver — custom DNS resolver for upstream name resolution ('' = system default)
	if !columnExists2(db, "proxy_hosts", "dns_resolver") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN dns_resolver TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.65: path_matcher_type — how PathMatcher is applied ('' = prefix | "exact" | "regexp")
	if !columnExists2(db, "proxy_hosts", "path_matcher_type") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN path_matcher_type TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.66: cors_allow_private_network — add Access-Control-Allow-Private-Network: true header
	if !columnExists2(db, "proxy_hosts", "cors_allow_private_network") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cors_allow_private_network INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.67: robots_txt_disallow_all — serve "Disallow: /" robots.txt without custom HTML body
	if !columnExists2(db, "proxy_hosts", "robots_txt_disallow_all") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN robots_txt_disallow_all INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.68: maintenance_retry_after_sec — Retry-After header value on maintenance 503 (0 = default 3600)
	if !columnExists2(db, "proxy_hosts", "maintenance_retry_after_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_retry_after_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.69: upstream_resolve_timeout_sec — DNS resolver timeout in seconds (0 = Caddy default)
	if !columnExists2(db, "proxy_hosts", "upstream_resolve_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_resolve_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.70: upstream_read_buffer_size_kb — transport read buffer in KB (0 = Caddy default 32KB)
	if !columnExists2(db, "proxy_hosts", "upstream_read_buffer_size_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_read_buffer_size_kb INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.71: upstream_write_buffer_size_kb — transport write buffer in KB (0 = Caddy default)
	if !columnExists2(db, "proxy_hosts", "upstream_write_buffer_size_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_write_buffer_size_kb INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.72: req_header_replace — newline-separated "Name|regexp|replacement" rules for request header values
	if !columnExists2(db, "proxy_hosts", "req_header_replace") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN req_header_replace TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.73: resp_header_replace — newline-separated "Name|regexp|replacement" rules for response header values
	if !columnExists2(db, "proxy_hosts", "resp_header_replace") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN resp_header_replace TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.74: upstream_http_versions — comma-separated HTTP versions for upstream transport ('' = Caddy default)
	if !columnExists2(db, "proxy_hosts", "upstream_http_versions") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_http_versions TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.75: health_check_body — request body to send with active health check probes
	if !columnExists2(db, "proxy_hosts", "health_check_body") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_body TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.76: add_canonical_link_header — inject Link: <canonical-url>; rel="canonical" response header
	if !columnExists2(db, "proxy_hosts", "add_canonical_link_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_canonical_link_header INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.77: http_basic_auth_upstream — "user:pass" credentials injected as Authorization: Basic to upstream
	if !columnExists2(db, "proxy_hosts", "http_basic_auth_upstream") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN http_basic_auth_upstream TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.78: block_ua_regexp — Go regexp; requests whose User-Agent matches get a 403 response
	if !columnExists2(db, "proxy_hosts", "block_ua_regexp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_ua_regexp TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.79: security_txt_body — serve custom security.txt at /.well-known/security.txt
	if !columnExists2(db, "proxy_hosts", "security_txt_body") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN security_txt_body TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.80: server_header_value — override the Server response header value ('' = keep upstream value)
	if !columnExists2(db, "proxy_hosts", "server_header_value") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN server_header_value TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.81: x_robots_tag — X-Robots-Tag response header value for search-engine indexing control
	if !columnExists2(db, "proxy_hosts", "x_robots_tag") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN x_robots_tag TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.82: add_forwarded_header — inject RFC 7239 Forwarded header on upstream requests
	if !columnExists2(db, "proxy_hosts", "add_forwarded_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_forwarded_header INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.83: lb_cookie_secret — HMAC secret for signed sticky-session cookies (prevents client tampering)
	if !columnExists2(db, "proxy_hosts", "lb_cookie_secret") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_cookie_secret TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.84: passive_unhealthy_status_codes — comma-separated HTTP codes triggering passive unhealthy state
	if !columnExists2(db, "proxy_hosts", "passive_unhealthy_status_codes") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN passive_unhealthy_status_codes TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.85: health_check_content_type — Content-Type header sent with active health check requests
	if !columnExists2(db, "proxy_hosts", "health_check_content_type") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_content_type TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.86: upstream_tls_client_cert_file — path to PEM certificate for mTLS to upstream
	if !columnExists2(db, "proxy_hosts", "upstream_tls_client_cert_file") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_client_cert_file TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.87: upstream_tls_client_key_file — path to PEM private key for mTLS to upstream
	if !columnExists2(db, "proxy_hosts", "upstream_tls_client_key_file") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_client_key_file TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.88: block_private_ips — reject incoming requests from RFC 1918 / loopback addresses (403)
	if !columnExists2(db, "proxy_hosts", "block_private_ips") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_private_ips INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.89: enable_brotli — add brotli (br) encoding to the compression handler alongside gzip/zstd
	if !columnExists2(db, "proxy_hosts", "enable_brotli") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN enable_brotli INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.90: vary_header — set Vary response header value for caching/CDN control
	if !columnExists2(db, "proxy_hosts", "vary_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN vary_header TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.91: strip_etag — delete ETag response header from upstream responses
	if !columnExists2(db, "proxy_hosts", "strip_etag") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_etag INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.92: http2_push_paths — newline-separated paths to push via HTTP/2 server push before response
	if !columnExists2(db, "proxy_hosts", "http2_push_paths") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN http2_push_paths TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.93: deny_content_types — comma-separated Content-Type prefixes that receive 415 Unsupported Media Type
	if !columnExists2(db, "proxy_hosts", "deny_content_types") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_content_types TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.94: upstream_local_addr — local IP address to bind for upstream connections
	if !columnExists2(db, "proxy_hosts", "upstream_local_addr") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_local_addr TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.95: upstream_tls_renegotiation — TLS renegotiation policy: '' (never) | 'once' | 'freely'
	if !columnExists2(db, "proxy_hosts", "upstream_tls_renegotiation") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_renegotiation TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.96: upstream_tls_curves — comma-separated TLS curve names for upstream connections ('' = Caddy default)
	if !columnExists2(db, "proxy_hosts", "upstream_tls_curves") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_curves TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.97: upstream_tls_max_version — maximum TLS version for upstream connections ('' | '1.2' | '1.3')
	if !columnExists2(db, "proxy_hosts", "upstream_tls_max_version") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_max_version TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.98: upstream_tls_pins — newline-separated SHA-256 SPKI fingerprints for upstream cert pinning
	if !columnExists2(db, "proxy_hosts", "upstream_tls_pins") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_pins TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.99: lb_header_field — request header name used by the 'header' LB selection policy
	if !columnExists2(db, "proxy_hosts", "lb_header_field") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_header_field TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.100: maintenance_custom_headers — newline-separated "Name: Value" extra headers on the 503 maintenance response
	if !columnExists2(db, "proxy_hosts", "maintenance_custom_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_custom_headers TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.101: deny_extensions — comma-separated file extensions to block (e.g. ".php,.asp") — returns 403
	if !columnExists2(db, "proxy_hosts", "deny_extensions") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_extensions TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.102: inject_request_timestamp — add X-Request-Timestamp header with UNIX epoch to upstream requests
	if !columnExists2(db, "proxy_hosts", "inject_request_timestamp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN inject_request_timestamp INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.103: add_resp_cookies — newline-separated Set-Cookie header values added to every response
	if !columnExists2(db, "proxy_hosts", "add_resp_cookies") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_resp_cookies TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.104: strip_accept_encoding — delete Accept-Encoding request header before forwarding to upstream
	if !columnExists2(db, "proxy_hosts", "strip_accept_encoding") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_accept_encoding INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.105: add_upstream_timing_header — inject X-Upstream-Time response header with upstream latency
	if !columnExists2(db, "proxy_hosts", "add_upstream_timing_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_upstream_timing_header INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.106: strip_server_header — delete Server response header from upstream replies
	if !columnExists2(db, "proxy_hosts", "strip_server_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_server_header INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.107: block_referer_regexp — Go regexp; requests whose Referer header matches receive 403
	if !columnExists2(db, "proxy_hosts", "block_referer_regexp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_referer_regexp TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.108: add_content_type_nosniff — add X-Content-Type-Options: nosniff response header
	if !columnExists2(db, "proxy_hosts", "add_content_type_nosniff") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_content_type_nosniff INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.109: strip_authorization_header — delete Authorization request header before forwarding to upstream
	if !columnExists2(db, "proxy_hosts", "strip_authorization_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_authorization_header INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.110: real_ip_from_header — copy real client IP from this request header name into X-Real-IP
	if !columnExists2(db, "proxy_hosts", "real_ip_from_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN real_ip_from_header TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.111: health_check_host_override — override Host header sent during active health check probes
	if !columnExists2(db, "proxy_hosts", "health_check_host_override") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_host_override TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.112: add_x_forwarded_port — add X-Forwarded-Port request header with the incoming request port
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_port") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_port INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.113: lb_retry_on — comma-separated retry triggers (e.g. "error,5xx") applied to upstream retries
	if !columnExists2(db, "proxy_hosts", "lb_retry_on") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_retry_on TEXT NOT NULL DEFAULT ''`)
	}

	// v2.9.114: max_buffer_size_kb — max response buffer size in KB when buffer_responses is enabled (0 = unlimited)
	if !columnExists2(db, "proxy_hosts", "max_buffer_size_kb") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN max_buffer_size_kb INTEGER NOT NULL DEFAULT 0`)
	}

	// v2.9.115: upstream_keepalive_probes — number of TCP keepalive probes before marking connection dead (0 = OS default)
	if !columnExists2(db, "proxy_hosts", "upstream_keepalive_probes") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_keepalive_probes INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.116: upstream_flush_interval_ms — flush_interval override in milliseconds (0 = default; -1 = immediate; positive = interval)
	if !columnExists2(db, "proxy_hosts", "upstream_flush_interval_ms") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_flush_interval_ms INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.117: add_x_forwarded_host — inject X-Forwarded-Host request header with the original Host value
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_host") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_host INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.118: maintenance_allowed_ips — comma-separated CIDR ranges that bypass maintenance mode
	if !columnExists2(db, "proxy_hosts", "maintenance_allowed_ips") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_allowed_ips TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.119: upstream_tls_cipher_suites — comma-separated TLS cipher suite names for upstream connections
	if !columnExists2(db, "proxy_hosts", "upstream_tls_cipher_suites") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_cipher_suites TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.120: add_cache_control_no_store — add Cache-Control: no-store response header
	if !columnExists2(db, "proxy_hosts", "add_cache_control_no_store") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_cache_control_no_store INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.121: deny_referer_empty — block requests with no Referer header (anti-hotlinking)
	if !columnExists2(db, "proxy_hosts", "deny_referer_empty") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_referer_empty INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.122: lb_cookie_httponly — set HttpOnly flag on the sticky-session cookie
	if !columnExists2(db, "proxy_hosts", "lb_cookie_httponly") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_cookie_httponly INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.123: lb_cookie_secure — set Secure flag on the sticky-session cookie
	if !columnExists2(db, "proxy_hosts", "lb_cookie_secure") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_cookie_secure INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.124: lb_cookie_same_site — SameSite attribute for the sticky-session cookie ("Strict","Lax","None")
	if !columnExists2(db, "proxy_hosts", "lb_cookie_same_site") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_cookie_same_site TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.125: upstream_tls_early_data — enable TLS 1.3 early data (0-RTT) for upstream connections
	if !columnExists2(db, "proxy_hosts", "upstream_tls_early_data") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_early_data INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.126: add_via_header — add Via response header identifying this proxy
	if !columnExists2(db, "proxy_hosts", "add_via_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_via_header INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.127: req_header_rename — newline-separated "OldName: NewName" pairs to rename request headers
	if !columnExists2(db, "proxy_hosts", "req_header_rename") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN req_header_rename TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.128: add_expect_ct_header — add Expect-CT response header for certificate transparency enforcement
	if !columnExists2(db, "proxy_hosts", "add_expect_ct_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_expect_ct_header INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.129: force_upstream_encoding — override Accept-Encoding header sent to upstream (e.g. "gzip","identity","br")
	if !columnExists2(db, "proxy_hosts", "force_upstream_encoding") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN force_upstream_encoding TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.130: passive_unhealthy_count — max concurrent in-flight requests per upstream before flagging overloaded
	if !columnExists2(db, "proxy_hosts", "passive_unhealthy_count") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN passive_unhealthy_count INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.131: strip_x_powered_by — delete X-Powered-By response header from upstream replies (privacy)
	if !columnExists2(db, "proxy_hosts", "strip_x_powered_by") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_x_powered_by INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.132: add_timing_allow_origin — value for Timing-Allow-Origin response header (e.g. "*")
	if !columnExists2(db, "proxy_hosts", "add_timing_allow_origin") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_timing_allow_origin TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.133: lb_cookie_max_age_sec — max-age in seconds for the sticky-session cookie
	if !columnExists2(db, "proxy_hosts", "lb_cookie_max_age_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_cookie_max_age_sec INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.134: cross_origin_opener_policy — Cross-Origin-Opener-Policy header value (e.g. "same-origin")
	if !columnExists2(db, "proxy_hosts", "cross_origin_opener_policy") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cross_origin_opener_policy TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.135: cross_origin_resource_policy — Cross-Origin-Resource-Policy header value (e.g. "same-site")
	if !columnExists2(db, "proxy_hosts", "cross_origin_resource_policy") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cross_origin_resource_policy TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.136: cross_origin_embedder_policy — Cross-Origin-Embedder-Policy header value (e.g. "require-corp")
	if !columnExists2(db, "proxy_hosts", "cross_origin_embedder_policy") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN cross_origin_embedder_policy TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.137: deny_request_content_type — comma-separated MIME types to block on request Content-Type (returns 415)
	if !columnExists2(db, "proxy_hosts", "deny_request_content_type") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_request_content_type TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.138: compression_exclude_regexp — regexp of paths to exclude from response compression
	if !columnExists2(db, "proxy_hosts", "compression_exclude_regexp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN compression_exclude_regexp TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.139: add_cache_control_public — add Cache-Control: public response header
	if !columnExists2(db, "proxy_hosts", "add_cache_control_public") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_cache_control_public INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.140: add_x_request_start — inject X-Request-Start header with Unix ms timestamp (APM timing)
	if !columnExists2(db, "proxy_hosts", "add_x_request_start") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_start INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.141: maintenance_window_timezone — IANA timezone name for the scheduled maintenance window
	if !columnExists2(db, "proxy_hosts", "maintenance_window_timezone") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_window_timezone TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.142: lb_random_choose_count — "choose" count for random_choice lb policy (min 2)
	if !columnExists2(db, "proxy_hosts", "lb_random_choose_count") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN lb_random_choose_count INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.143: add_x_forwarded_scheme — inject X-Forwarded-Scheme request header with the client-facing scheme
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_scheme") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_scheme INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.144: response_cache_ttl_sec — set Cache-Control: max-age=N on responses (0 = disabled)
	if !columnExists2(db, "proxy_hosts", "response_cache_ttl_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN response_cache_ttl_sec INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.145: add_link_preload — Link response header value for HTTP/2 preload hints (empty = disabled)
	if !columnExists2(db, "proxy_hosts", "add_link_preload") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_link_preload TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.146: deny_path_regexp — reject requests whose path matches this regex with 403 (empty = disabled)
	if !columnExists2(db, "proxy_hosts", "deny_path_regexp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_path_regexp TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.147: add_request_id_to_response — echo the request trace ID header in the response for client-side debugging
	if !columnExists2(db, "proxy_hosts", "add_request_id_to_response") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_request_id_to_response INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.148: health_check_tls_server_name — TLS SNI override for active health check connections (empty = use upstream host)
	if !columnExists2(db, "proxy_hosts", "health_check_tls_server_name") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_tls_server_name TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.149: add_x_real_ip — inject X-Real-IP header with the direct client IP address
	if !columnExists2(db, "proxy_hosts", "add_x_real_ip") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_real_ip INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.150: strip_incoming_x_forwarded_for — delete X-Forwarded-For from incoming requests to prevent IP spoofing
	if !columnExists2(db, "proxy_hosts", "strip_incoming_x_forwarded_for") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_incoming_x_forwarded_for INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.151: health_check_tls_insecure_skip_verify — skip TLS certificate verification for health check probes
	if !columnExists2(db, "proxy_hosts", "health_check_tls_insecure_skip_verify") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_tls_insecure_skip_verify INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.152: add_cors_vary_header — add Vary: Origin response header for correct CDN caching of CORS responses
	if !columnExists2(db, "proxy_hosts", "add_cors_vary_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_cors_vary_header INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.153: upstream_tls_alpn — comma-separated ALPN protocol list for upstream TLS connections
	if !columnExists2(db, "proxy_hosts", "upstream_tls_alpn") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_alpn TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.154: add_x_powered_by — custom X-Powered-By response header value (empty = disabled)
	if !columnExists2(db, "proxy_hosts", "add_x_powered_by") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_powered_by TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.155: block_query_params — comma-separated query parameter names to block (403 if any present)
	if !columnExists2(db, "proxy_hosts", "block_query_params") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_query_params TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.156: add_document_policy — Document-Policy response header value (empty = disabled)
	if !columnExists2(db, "proxy_hosts", "add_document_policy") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_document_policy TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.157: maintenance_redirect_url — redirect to this URL instead of serving inline 503 during maintenance
	if !columnExists2(db, "proxy_hosts", "maintenance_redirect_url") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN maintenance_redirect_url TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.158: upstream_keepalive_max_lifetime_sec — max lifetime for keepalive connections before being recycled (0 = no limit)
	if !columnExists2(db, "proxy_hosts", "upstream_keepalive_max_lifetime_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_keepalive_max_lifetime_sec INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.159: add_origin_header — inject Origin: <value> request header (for upstream APIs that require it)
	if !columnExists2(db, "proxy_hosts", "add_origin_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_origin_header TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.160: upstream_tls_ca_pem_inline — inline PEM CA certificate for upstream TLS verification
	if !columnExists2(db, "proxy_hosts", "upstream_tls_ca_pem_inline") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_ca_pem_inline TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.161: add_server_timing_header — inject Server-Timing response header with upstream duration
	if !columnExists2(db, "proxy_hosts", "add_server_timing_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_server_timing_header INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.162: add_clear_site_data — Clear-Site-Data response header value (e.g. "cache","cookies")
	if !columnExists2(db, "proxy_hosts", "add_clear_site_data") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_clear_site_data TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.163: add_x_dns_prefetch_control — set X-DNS-Prefetch-Control: off response header
	if !columnExists2(db, "proxy_hosts", "add_x_dns_prefetch_control") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_dns_prefetch_control INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.164: add_accept_ranges — set Accept-Ranges: bytes response header to signal byte-range support
	if !columnExists2(db, "proxy_hosts", "add_accept_ranges") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_accept_ranges INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.165: add_content_disposition — Content-Disposition response header value (empty = disabled)
	if !columnExists2(db, "proxy_hosts", "add_content_disposition") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_content_disposition TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.166: upstream_tls_server_name_from_host — use request Host header as upstream TLS SNI (dynamic)
	if !columnExists2(db, "proxy_hosts", "upstream_tls_server_name_from_host") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN upstream_tls_server_name_from_host INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.167: add_x_permitted_cross_domain_policies — X-Permitted-Cross-Domain-Policies response header value
	if !columnExists2(db, "proxy_hosts", "add_x_permitted_cross_domain_policies") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_permitted_cross_domain_policies TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.168: strip_response_headers — comma-separated list of response header names to delete
	if !columnExists2(db, "proxy_hosts", "strip_response_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_response_headers TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.169: add_report_to — Report-To response header value (JSON endpoint group for CSP/NEL reporting)
	if !columnExists2(db, "proxy_hosts", "add_report_to") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_report_to TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.170: add_nel_header — NEL (Network Error Logging) response header JSON config value
	if !columnExists2(db, "proxy_hosts", "add_nel_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_nel_header TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.171: block_http_methods — comma-separated HTTP methods to reject with 405 Method Not Allowed
	if !columnExists2(db, "proxy_hosts", "block_http_methods") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_http_methods TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.172: add_service_worker_allowed — Service-Worker-Allowed response header value (expand SW scope)
	if !columnExists2(db, "proxy_hosts", "add_service_worker_allowed") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_service_worker_allowed TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.173: add_accept_ch — Accept-CH response header to declare accepted client hints
	if !columnExists2(db, "proxy_hosts", "add_accept_ch") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_accept_ch TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.174: add_alt_svc — Alt-Svc response header value (advertise HTTP/2, HTTP/3 or other service)
	if !columnExists2(db, "proxy_hosts", "add_alt_svc") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_alt_svc TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.175: add_content_language — Content-Language response header value
	if !columnExists2(db, "proxy_hosts", "add_content_language") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_content_language TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.176: add_critical_ch — Critical-CH response header (lists client hints required before rendering)
	if !columnExists2(db, "proxy_hosts", "add_critical_ch") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_critical_ch TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.177: add_x_download_options — set X-Download-Options: noopen to prevent IE file auto-open
	if !columnExists2(db, "proxy_hosts", "add_x_download_options") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_download_options INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.178: deny_user_agent_regexp — block requests whose User-Agent matches this regexp with 403
	if !columnExists2(db, "proxy_hosts", "deny_user_agent_regexp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_user_agent_regexp TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.179: add_pragma_no_cache — set Pragma: no-cache response header (HTTP/1.0 cache directive)
	if !columnExists2(db, "proxy_hosts", "add_pragma_no_cache") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_pragma_no_cache INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.180: health_check_user_agent — custom User-Agent header value for active health check probes
	if !columnExists2(db, "proxy_hosts", "health_check_user_agent") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_user_agent TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.181: add_x_request_path — inject X-Request-Path header with the request URI path on upstream calls
	if !columnExists2(db, "proxy_hosts", "add_x_request_path") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_path INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.182: add_x_clacks_overhead — X-Clacks-Overhead response header (custom value, GNU Terry Pratchett tradition)
	if !columnExists2(db, "proxy_hosts", "add_x_clacks_overhead") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_clacks_overhead TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.183: add_x_ua_compatible — X-UA-Compatible response header (e.g. 'IE=edge' for legacy IE rendering)
	if !columnExists2(db, "proxy_hosts", "add_x_ua_compatible") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_ua_compatible TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.184: forward_auth_skip_paths — comma-separated path prefixes that bypass forward_auth (e.g. /health,/metrics)
	if !columnExists2(db, "proxy_hosts", "forward_auth_skip_paths") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN forward_auth_skip_paths TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.185: add_age_zero — set Age: 0 response header to signal a fresh response (CDN bypass)
	if !columnExists2(db, "proxy_hosts", "add_age_zero") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_age_zero INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.186: add_surrogate_control — Surrogate-Control response header value (CDN-only cache directive)
	if !columnExists2(db, "proxy_hosts", "add_surrogate_control") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_surrogate_control TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.187: add_warning_header — Warning response header value (RFC 7234 warning codes)
	if !columnExists2(db, "proxy_hosts", "add_warning_header") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_warning_header TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.188: add_x_request_method — forward X-Request-Method header (echoes the HTTP method) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_method") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_method INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.189: add_x_request_query — forward X-Request-Query header (echoes the query string) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_query") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_query INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.190: add_x_forwarded_user — static X-Forwarded-User request header value forwarded to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_user") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_user TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.191: add_x_real_scheme — forward X-Real-Scheme request header (http or https) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_real_scheme") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_real_scheme INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.192: add_origin_agent_cluster — set Origin-Agent-Cluster: ?1 response header for origin-keyed isolation
	if !columnExists2(db, "proxy_hosts", "add_origin_agent_cluster") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_origin_agent_cluster INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.193: add_x_forwarded_groups — static X-Forwarded-Groups request header value forwarded to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_groups") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_groups TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.194: add_x_forwarded_email — static X-Forwarded-Email request header value forwarded to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_email") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_email TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.195: add_x_forwarded_roles — static X-Forwarded-Roles request header value forwarded to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_roles") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_roles TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.196: block_query_param_regexp — block requests whose raw query string matches this regexp with 403
	if !columnExists2(db, "proxy_hosts", "block_query_param_regexp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_query_param_regexp TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.197: add_x_request_referer — forward X-Request-Referer header (echoes original Referer) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_referer") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_referer INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.198: add_x_request_origin — forward X-Request-Origin header (echoes original Origin) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_origin") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_origin INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.199: add_x_forwarded_uri — forward X-Forwarded-URI header (echoes original request URI) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_uri") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_uri INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.200: add_x_no_archive — set X-No-Archive: yes response header to block search-engine archive caching
	if !columnExists2(db, "proxy_hosts", "add_x_no_archive") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_no_archive INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.201: add_x_request_hostname — forward X-Request-Hostname header (echoes request hostname) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_hostname") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_hostname INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.202: add_x_xss_protection_disabled — set X-XSS-Protection: 0 response header (disable legacy XSS filter)
	if !columnExists2(db, "proxy_hosts", "add_x_xss_protection_disabled") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_xss_protection_disabled INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.207: status-class buckets on the daily rollup. Existing installs
	// running v2.7.0+ already have access_daily; they need these columns.
	for _, col := range []string{"s2xx", "s3xx", "s4xx", "s5xx", "s_other"} {
		if !columnExists2(db, "access_daily", col) {
			migrationStep(db, `ALTER TABLE access_daily ADD COLUMN `+col+` INTEGER NOT NULL DEFAULT 0`)
		}
	}
	// v2.9.212: add_x_request_remote_port — forward X-Request-Remote-Port header (echoes client port) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_remote_port") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_remote_port INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.213: add_x_request_protocol — forward X-Request-Protocol header (echoes HTTP/1.1, HTTP/2 etc.) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_protocol") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_protocol INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.214: add_save_data_vary — set Vary: Save-Data response header (client hint aware caching)
	if !columnExists2(db, "proxy_hosts", "add_save_data_vary") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_save_data_vary INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.217: add_x_environment — static X-Environment request header value (production/staging/dev)
	if !columnExists2(db, "proxy_hosts", "add_x_environment") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_environment TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.218: add_x_trace_id — forward X-Trace-ID request header (Caddy UUID per request) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_trace_id") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_trace_id INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.219: health_check_query_params — query string appended to active health check probe URL
	if !columnExists2(db, "proxy_hosts", "health_check_query_params") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_query_params TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.220: add_x_session_id — forward X-Session-ID request header (Caddy UUID per request) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_session_id") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_session_id INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.221: add_x_response_trace_id — set X-Response-Trace-ID response header (echoes the trace UUID)
	if !columnExists2(db, "proxy_hosts", "add_x_response_trace_id") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_response_trace_id INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.222: add_x_request_local_addr — forward X-Local-Addr header (Caddy's listening IP) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_local_addr") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_local_addr INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.223: add_x_request_local_port — forward X-Local-Port header (Caddy's listening port) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_local_port") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_local_port INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.224: add_x_request_path_info — forward X-PathInfo header (CGI-style PATH_INFO) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_path_info") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_path_info INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.234: add_x_authenticated_user — static X-Authenticated-User request header
	if !columnExists2(db, "proxy_hosts", "add_x_authenticated_user") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_authenticated_user TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.235: block_path_extensions — comma-separated file extensions to block with 403 (.php, .git, etc.)
	if !columnExists2(db, "proxy_hosts", "block_path_extensions") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_path_extensions TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.236: add_link_modulepreload — Link: <…>; rel=modulepreload response header
	if !columnExists2(db, "proxy_hosts", "add_link_modulepreload") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_link_modulepreload TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.237: add_x_remote_user — static X-Remote-User request header (Nginx-style auth identity)
	if !columnExists2(db, "proxy_hosts", "add_x_remote_user") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_remote_user TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.238: add_x_forwarded_path — forward X-Forwarded-Path header (request URI path) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_path") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_path INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.239: add_x_geo_country_code — static X-Geo-Country header (CDN convention, e.g. "US")
	if !columnExists2(db, "proxy_hosts", "add_x_geo_country_code") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_geo_country_code TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.240: add_x_request_priority — X-Request-Priority response header (RFC 9218 priority hints)
	if !columnExists2(db, "proxy_hosts", "add_x_request_priority") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_priority TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.241: health_check_basic_auth — "user:pass" credentials for active health check probes
	if !columnExists2(db, "proxy_hosts", "health_check_basic_auth") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN health_check_basic_auth TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.242: add_x_real_ssl_protocol — forward X-Real-SSL-Protocol header (TLS version) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_real_ssl_protocol") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_real_ssl_protocol INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.243: add_x_real_ssl_cipher — forward X-Real-SSL-Cipher header (negotiated cipher) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_real_ssl_cipher") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_real_ssl_cipher INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.244: add_x_cache_status — static X-Cache-Status response header value (e.g. "MISS")
	if !columnExists2(db, "proxy_hosts", "add_x_cache_status") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_cache_status TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.245: deny_referer_regexp — block requests whose Referer matches regexp with 403
	if !columnExists2(db, "proxy_hosts", "deny_referer_regexp") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN deny_referer_regexp TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.246: add_x_request_user_agent — forward X-Request-User-Agent header (echoes UA) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_user_agent") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_user_agent INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.247: add_reporting_endpoints — Reporting-Endpoints response header (RFC 8942)
	if !columnExists2(db, "proxy_hosts", "add_reporting_endpoints") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_reporting_endpoints TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.248: add_x_request_byte_count — forward X-Request-Byte-Count header (Content-Length) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_byte_count") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_byte_count INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.249: add_x_request_received_at — forward X-Request-Received-At header (timestamp) to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_received_at") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_received_at INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.250: strip_request_headers — comma-separated list of request header names to delete
	if !columnExists2(db, "proxy_hosts", "strip_request_headers") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN strip_request_headers TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.251: add_x_forwarded_method — forward X-Forwarded-Method (HTTP method) request header
	if !columnExists2(db, "proxy_hosts", "add_x_forwarded_method") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_forwarded_method INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.252: add_x_request_original_host — preserve original Host header before any rewrites
	if !columnExists2(db, "proxy_hosts", "add_x_request_original_host") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_original_host INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.253: add_x_request_dnt — forward DNT (Do Not Track) header to upstream
	if !columnExists2(db, "proxy_hosts", "add_x_request_dnt") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_dnt INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.254: add_x_geo_region — static X-Geo-Region request header (US-CA, GB-LND, etc.)
	if !columnExists2(db, "proxy_hosts", "add_x_geo_region") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_geo_region TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.255: add_x_request_secure — X-Request-Secure: on/off based on TLS state
	if !columnExists2(db, "proxy_hosts", "add_x_request_secure") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_secure INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.256: add_x_request_query_count — debug header with query parameter count
	if !columnExists2(db, "proxy_hosts", "add_x_request_query_count") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_query_count INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.257: add_x_request_id_header_response — echo the request UUID to the response header
	if !columnExists2(db, "proxy_hosts", "add_x_request_id_header_response") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_id_header_response INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.258: force_canonical_host — canonical host; any other request hostname is redirected to it
	if !columnExists2(db, "proxy_hosts", "force_canonical_host") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN force_canonical_host TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.259: add_x_robots_noindex_quick — quick X-Robots-Tag: noindex, nofollow toggle
	if !columnExists2(db, "proxy_hosts", "add_x_robots_noindex_quick") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_robots_noindex_quick INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.260: block_bot_user_agents — built-in bot blocklist (regexp matches common scrapers)
	if !columnExists2(db, "proxy_hosts", "block_bot_user_agents") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_bot_user_agents INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.261: block_admin_paths — 404 common admin paths (/wp-admin, /.git, /phpmyadmin, etc.)
	if !columnExists2(db, "proxy_hosts", "block_admin_paths") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN block_admin_paths INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.262: add_link_dns_prefetch — Link: <…>; rel=dns-prefetch response header
	if !columnExists2(db, "proxy_hosts", "add_link_dns_prefetch") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_link_dns_prefetch TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.263: add_link_preconnect — Link: <…>; rel=preconnect response header
	if !columnExists2(db, "proxy_hosts", "add_link_preconnect") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_link_preconnect TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.264: add_x_csp_disabled — set Content-Security-Policy: '' to explicitly disable CSP
	if !columnExists2(db, "proxy_hosts", "add_x_csp_disabled") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_csp_disabled INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.265: add_x_request_method_override — honor X-HTTP-Method-Override (rewrite method from header)
	if !columnExists2(db, "proxy_hosts", "add_x_request_method_override") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN add_x_request_method_override INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.266: proxy_redirect_rules — JSON array of path-based redirect rules
	// fired BEFORE the reverse_proxy. Mirrors redirection_hosts.redirect_rules
	// from v2.9.229 but on proxy hosts. Each rule: {path, code, destination}.
	// Use case: "redirect / to /webmail with 302, but proxy everything else
	// to backend" — common in Caddyfile as `@root path / + redir @root /webmail 302`.
	if !columnExists2(db, "proxy_hosts", "proxy_redirect_rules") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN proxy_redirect_rules TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.267: additional_upstream_rules — JSON array of path-based upstream
	// overrides. Each entry: {path, scheme, host, port, strip_prefix, add_x_real_ip}.
	// When matched, that path goes to the override upstream instead of the
	// host's main forward_*. Common case: Nextcloud + notify_push on /push/*
	// + AppAPI on /exapps/* + main app on everything else, all on one
	// hostname — previously expressible only via raw routes / Caddyfile.
	// Empty / "[]" keeps the legacy single-upstream behaviour.
	if !columnExists2(db, "proxy_hosts", "additional_upstream_rules") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN additional_upstream_rules TEXT NOT NULL DEFAULT ''`)
	}
	// v2.12.52: disable_upstream_compression — emit `transport http { compression off }`
	// in the reverse_proxy block. Useful when the upstream double-compresses
	// already-compressed responses (e.g., a node app behind Caddy where Caddy
	// will encode anyway).
	if !columnExists2(db, "proxy_hosts", "disable_upstream_compression") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN disable_upstream_compression INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.28.0 (issue #39): per-host control over CaddyUI's *own* monitoring
	// probes — the 60s app-health poller against the public domain and the
	// direct upstream fallback probe. Distinct from the health_check_* columns,
	// which configure Caddy's active upstream health checking.
	//
	// monitor_mode defaults to 'auto' so every existing row keeps the exact
	// behaviour it had before this migration. 'custom' honours the four
	// override columns; 'off' suppresses both probes entirely for hosts that
	// are deliberately unreachable from the CaddyUI container (split DNS,
	// firewalled backends) and were showing a misleading "down" plus
	// generating recurring firewall noise.
	// Stored as '' rather than 'auto' on existing rows: MariaDB is fussier
	// about non-empty DEFAULTs on TEXT columns than SQLite, and every other
	// TEXT migration here uses DEFAULT ''. Readers treat '' and 'auto'
	// identically (see models.normalizeMonitorMode).
	if !columnExists2(db, "proxy_hosts", "monitor_mode") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN monitor_mode TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "monitor_path") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN monitor_path TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "monitor_method") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN monitor_method TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "proxy_hosts", "monitor_expect_status") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN monitor_expect_status INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "monitor_interval_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN monitor_interval_sec INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "proxy_hosts", "monitor_timeout_sec") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN monitor_timeout_sec INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.33.0: node_local — exclude a resource from fleet sync entirely.
	//
	// Fleet sync copies a proxy host's upstream (forward_host/port) verbatim to
	// the target node. That is right for edge replication, where several Caddy
	// nodes front the same backends, but wrong for federated nodes where each
	// Caddy fronts its own local stack: a Docker service name like
	// "immich_server" only resolves inside one node's network, and a WireGuard
	// address like 10.8.0.1 may route somewhere else entirely.
	//
	// preserveProxyTargetPolicy already treats certificates, DNS records and
	// keys as node-specific; the upstream address was the one field most likely
	// to differ and was still being copied. Rather than invent per-node
	// upstream overrides, this lets an operator mark a resource as belonging to
	// one node, and both full sync and "Also deploy to" skip it.
	if !columnExists2(db, "proxy_hosts", "node_local") {
		migrationStep(db, `ALTER TABLE proxy_hosts ADD COLUMN node_local INTEGER NOT NULL DEFAULT 0`)
	}
	if !columnExists2(db, "raw_routes", "node_local") {
		migrationStep(db, `ALTER TABLE raw_routes ADD COLUMN node_local INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.36.1 (issue #64): JSON list of listen addresses for Advanced routes
	// that bind their own port(s), e.g. `[":7070"]`. '' = normal :443/:80.
	if !columnExists2(db, "raw_routes", "listen") {
		migrationStep(db, `ALTER TABLE raw_routes ADD COLUMN listen TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.230: redirect_strip_path_prefix — drop a leading path prefix from
	// the request URI before composing the Location header. Mirrors the
	// proxy-host strip_path_prefix option for redirects (e.g. on a partial
	// migration where /old-blog/* should redirect to newblog.com/*, not
	// newblog.com/old-blog/*).
	if !columnExists2(db, "redirection_hosts", "redirect_strip_path_prefix") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN redirect_strip_path_prefix TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.231: redirect_wildcard_subdomain — when on, the matched subdomain
	// label is preserved in the destination via the {http.request.host.labels.0}
	// placeholder. Useful for *.old.com → *.new.com en-masse.
	if !columnExists2(db, "redirection_hosts", "redirect_wildcard_subdomain") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN redirect_wildcard_subdomain INTEGER NOT NULL DEFAULT 0`)
	}
	// v2.9.232: sunset_at — ISO-8601 date (YYYY-MM-DD) after which the
	// redirect returns 410 Gone instead of redirecting. Compliance/cleanup
	// helper for "redirect from old domain until 2027-01-01, then drop it".
	if !columnExists2(db, "redirection_hosts", "sunset_at") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN sunset_at TEXT NOT NULL DEFAULT ''`)
	}
	// v2.9.229: redirect_rules — JSON array of path-based redirect rules.
	// Each rule: {"path":"/old/*","code":301,"destination":"https://new.example.com{uri}"}
	// When non-empty, the per-rule matchers run BEFORE the host-wide default
	// redirect, so users can ship partial-migration rewrites like
	// /old-blog/* → newblog.com without affecting the rest of the host.
	// Empty (the default) keeps the existing whole-host redirect behaviour.
	if !columnExists2(db, "redirection_hosts", "redirect_rules") {
		migrationStep(db, `ALTER TABLE redirection_hosts ADD COLUMN redirect_rules TEXT NOT NULL DEFAULT ''`)
	}
	// v2.17.0: standalone Caddy-managed ACME certificates reuse a saved DNS
	// credential profile for DNS-01 issuance and renewal.
	if !columnExists2(db, "certificates", "dns_provider") {
		migrationStep(db, `ALTER TABLE certificates ADD COLUMN dns_provider TEXT NOT NULL DEFAULT ''`)
	}
	if !columnExists2(db, "certificates", "dns_profile_id") {
		migrationStep(db, `ALTER TABLE certificates ADD COLUMN dns_profile_id TEXT NOT NULL DEFAULT ''`)
	}

	// Fleet observability: retain the actual Caddy node stamped into each
	// forwarded access event. Existing rows remain server_id=0 and render as
	// legacy/unattributed rather than being guessed from hostname ownership.
	if !columnExists2(db, "access_events", "server_id") {
		if _, err := db.Exec(`ALTER TABLE access_events ADD COLUMN server_id BIGINT NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add server_id to access_events: %w", err)
		}
	}
	if !columnExists2(db, "access_events", "server_name") {
		if _, err := db.Exec(`ALTER TABLE access_events ADD COLUMN server_name VARCHAR(255) NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add server_name to access_events: %w", err)
		}
	}
	// v2.31.0: covering index for the server-scoped "top hosts" aggregation
	// behind the Analytics page.
	//
	// That query is `WHERE ts >= ? AND server_id = ? GROUP BY host`. With only
	// (server_id, ts) available, SQLite scanned in timestamp order and then
	// built a temp B-tree to group by host, plus another for the DISTINCT —
	// and had to fetch every matching row from the table for `host` and
	// `client_ip`. Ordering by host *inside* the server lets the GROUP BY read
	// straight off the index, and carrying ts and client_ip makes it covering.
	//
	// Measured on 84k events across 21 hosts: 1068 ms → 109 ms. The unscoped
	// variant was always fast because (host, ts) already gave it group order —
	// which is why this only became visible to operators running several
	// hosts on one node.
	migrationStep(db, `CREATE INDEX IF NOT EXISTS idx_access_events_server_host_ts_ip ON access_events(server_id, host, ts, client_ip)`)
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_access_events_server_ts ON access_events(server_id, ts)`); err != nil {
		return fmt.Errorf("create access_events server index: %w", err)
	}

	// One loud summary rather than leaving the operator to spot individual
	// failures scattered through a long startup log.
	if migrationFailures > 0 {
		log.Printf("db: WARNING: %d schema migration step(s) failed — the database may be missing columns or indexes. "+
			"Search this log for 'MIGRATION FAILED' for the specific statements.", migrationFailures)
	}

	return nil
}

// columnExists2 is a bool-only wrapper around columnExists for callers that
// have already handled the error path and just need a true/false gate.
func columnExists2(db *sql.DB, table, col string) bool {
	ok, _ := columnExists(db, table, col)
	return ok
}

func columnExists(db *sql.DB, table, col string) (bool, error) {
	if BackendOf(db) == BackendMariaDB {
		var count int
		err := db.QueryRow(`
			SELECT COUNT(*)
			  FROM information_schema.columns
			 WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`,
			table, col,
		).Scan(&count)
		return count > 0, err
	}
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
