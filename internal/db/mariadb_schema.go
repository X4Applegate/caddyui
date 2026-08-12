package db

// mariaDBSchema creates the compact baseline schema. The shared migrate
// function then adds every feature column introduced over CaddyUI's lifetime,
// just as it does for a newly-created SQLite database.
const mariaDBSchema = `
CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(320) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    is_admin INTEGER DEFAULT 0,
    role VARCHAR(32) NOT NULL DEFAULT 'admin',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
    token VARCHAR(128) PRIMARY KEY,
    user_id BIGINT NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_hosts (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    domains TEXT NOT NULL,
    forward_scheme VARCHAR(16) NOT NULL DEFAULT 'http',
    forward_host TEXT NOT NULL,
    forward_port INTEGER NOT NULL,
    websocket_support INTEGER DEFAULT 0,
    block_common_exploits INTEGER DEFAULT 0,
    ssl_enabled INTEGER DEFAULT 1,
    ssl_forced INTEGER DEFAULT 1,
    http2_support INTEGER DEFAULT 1,
    advanced_config LONGTEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    basicauth_enabled INTEGER NOT NULL DEFAULT 0,
    basicauth_users LONGTEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS redirection_hosts (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    domains TEXT NOT NULL,
    forward_scheme VARCHAR(16) NOT NULL DEFAULT 'auto',
    forward_domain TEXT NOT NULL,
    forward_http_code INTEGER DEFAULT 301,
    preserve_path INTEGER DEFAULT 1,
    ssl_enabled INTEGER DEFAULT 1,
    ssl_forced INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS raw_routes (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    label TEXT NOT NULL,
    json_data LONGTEXT NOT NULL,
    caddyfile_src LONGTEXT NOT NULL DEFAULT '',
    enabled INTEGER DEFAULT 1,
    certificate_id BIGINT,
    force_ssl INTEGER DEFAULT 0,
    block_common_exploits INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
    ` + "`key`" + ` VARCHAR(191) PRIMARY KEY,
    value LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS config_snapshots (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    note TEXT NOT NULL DEFAULT '',
    source VARCHAR(32) NOT NULL DEFAULT 'auto',
    config_json LONGTEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS activity_log (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    actor TEXT NOT NULL DEFAULT 'system',
    action VARCHAR(191) NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail LONGTEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS certificates (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name TEXT NOT NULL,
    domains TEXT NOT NULL DEFAULT '',
    source VARCHAR(32) NOT NULL DEFAULT 'pem',
    cert_pem LONGTEXT NOT NULL,
    key_pem LONGTEXT NOT NULL,
    cert_path TEXT NOT NULL DEFAULT '',
    key_path TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS caddy_servers (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name TEXT NOT NULL,
    admin_url TEXT NOT NULL,
    type VARCHAR(32) NOT NULL DEFAULT 'managed',
    tags TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    last_contact_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS fleet_deployments (
    source_server_id BIGINT NOT NULL,
    resource_kind VARCHAR(32) NOT NULL,
    source_resource_id BIGINT NOT NULL,
    target_server_id BIGINT NOT NULL,
    target_resource_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (source_server_id, resource_kind, source_resource_id, target_server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS access_events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    ts BIGINT NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    method VARCHAR(16) NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    client_ip VARCHAR(64) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    duration_ms BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    INDEX idx_access_events_ts (ts),
    INDEX idx_access_events_host_ts (host, ts),
    INDEX idx_access_events_status_ts (status, ts),
    INDEX idx_access_events_client_ip_ts (client_ip, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS access_daily (
    day VARCHAR(10) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    views BIGINT NOT NULL DEFAULT 0,
    unique_visitors BIGINT NOT NULL DEFAULT 0,
    s2xx BIGINT NOT NULL DEFAULT 0,
    s3xx BIGINT NOT NULL DEFAULT 0,
    s4xx BIGINT NOT NULL DEFAULT 0,
    s5xx BIGINT NOT NULL DEFAULT 0,
    s_other BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (day, host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS groups (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_groups (
    user_id BIGINT NOT NULL,
    group_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, group_id),
    INDEX idx_user_groups_group (group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS api_tokens (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    last_used_at DATETIME NULL,
    expires_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_health (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    proxy_host_id BIGINT NOT NULL,
    checked_at BIGINT NOT NULL,
    ok INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER NOT NULL DEFAULT 0,
    latency_ms BIGINT NOT NULL DEFAULT 0,
    error_msg TEXT NOT NULL DEFAULT '',
    INDEX idx_proxy_health_host_ts (proxy_host_id, checked_at),
    FOREIGN KEY (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`
