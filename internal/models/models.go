package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BasicAuthUser is a single HTTP basic-auth credential stored per proxy host.
// BcryptHash is a standard bcrypt hash string (e.g. $2a$12$...).
type BasicAuthUser struct {
	Username   string `json:"user"`
	BcryptHash string `json:"hash"`
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Name         string
	IsAdmin      bool
	Role         string // "admin", "view", or "user"
	CreatedAt    time.Time
	TOTPSecret   string
	TOTPEnabled  bool
}

const (
	RoleAdmin = "admin"
	RoleView  = "view"
	RoleUser  = "user"
)

func (u *User) IsViewer() bool { return u != nil && u.Role == RoleView }
func (u *User) CanWrite() bool { return u != nil && u.Role != RoleView }

type ProxyHost struct {
	ID                  int64
	ServerID            int64 // v2.4.0: which caddy_servers row this host belongs to (for per-server public-IP lookup)
	Domains             string
	ForwardScheme       string
	ForwardHost         string
	ForwardPort         int
	WebsocketSupport    bool
	BlockCommonExploits bool
	SSLEnabled          bool
	SSLForced           bool
	HTTP2Support        bool
	AdvancedConfig      string
	Enabled             bool
	CertificateID       int64 // 0 = auto (ACME); >0 = use custom certificate with this ID
	BasicAuthEnabled    bool
	BasicAuthUsers      string // JSON: []BasicAuthUser
	AccessList          string // comma-separated CIDRs; empty = allow all
	ExtraUpstreams      string // JSON: []string of "host:port" entries
	OwnerID             sql.NullInt64
	OwnerEmail          string // populated via JOIN for display
	// v2.3.0 unified DNS columns. One record per proxy host; provider
	// identifies which adapter in internal/dns handles lifecycle calls.
	// Empty DNSProvider means "no managed DNS" — the host's A record is
	// whatever the user set manually.
	DNSProvider   string // "" | cloudflare | porkbun | namecheap | godaddy | digitalocean | hetzner
	DNSZoneID     string // provider-native zone ID (opaque for CF/Hetzner; domain for others)
	DNSZoneName   string // base domain, e.g. "example.com", for display
	DNSRecordID   string // record ID returned by the provider after create
	// Legacy CF/PB columns. Kept for rollback safety — the v2.3.0 migration
	// copies these into the unified columns above. New writes only touch
	// the unified columns, so these stay frozen at whatever the last v2.2.x
	// release left them as.
	CFDNSRecordID string
	CFZoneID      string
	PBDNSRecordID string
	PBDomain      string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// BasicAuthUserList parses the JSON-encoded BasicAuthUsers string into a slice.
// Returns nil if empty or unparseable.
func (p *ProxyHost) BasicAuthUserList() []BasicAuthUser {
	if p.BasicAuthUsers == "" || p.BasicAuthUsers == "[]" {
		return nil
	}
	var users []BasicAuthUser
	_ = json.Unmarshal([]byte(p.BasicAuthUsers), &users)
	return users
}

// ExtraUpstreamList parses the JSON-encoded ExtraUpstreams string into a slice.
// Returns nil if empty or unparseable.
func (p *ProxyHost) ExtraUpstreamList() []string {
	if p.ExtraUpstreams == "" || p.ExtraUpstreams == "[]" {
		return nil
	}
	var list []string
	_ = json.Unmarshal([]byte(p.ExtraUpstreams), &list)
	return list
}

func (p ProxyHost) DomainList() []string {
	parts := strings.Split(p.Domains, ",")
	out := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

type RedirectionHost struct {
	ID              int64
	Domains         string
	ForwardScheme   string
	ForwardDomain   string
	ForwardHTTPCode int
	PreservePath    bool
	SSLEnabled      bool
	SSLForced       bool
	Enabled         bool
	CertificateID   int64
	OwnerID         sql.NullInt64
	OwnerEmail      string // populated via JOIN for display
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (r RedirectionHost) DomainList() []string {
	parts := strings.Split(r.Domains, ",")
	out := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

const userCols = `id, email, password_hash, COALESCE(name,''), is_admin,
    COALESCE(role, CASE WHEN is_admin=1 THEN 'admin' ELSE 'view' END), created_at,
    COALESCE(totp_secret,''), COALESCE(totp_enabled,0)`

func scanUser(s interface {
	Scan(dest ...any) error
}) (*User, error) {
	u := &User{}
	var isAdmin, totpEnabled int
	if err := s.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &isAdmin, &u.Role, &u.CreatedAt, &u.TOTPSecret, &totpEnabled); err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin == 1
	u.TOTPEnabled = totpEnabled == 1
	if u.Role == "" {
		if u.IsAdmin {
			u.Role = RoleAdmin
		} else {
			u.Role = RoleView
		}
	}
	return u, nil
}

func SetUserTOTP(db *sql.DB, userID int64, secret string, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := db.Exec(`UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?`, secret, e, userID)
	return err
}

func GetUser(db *sql.DB, userID int64) (*User, error) {
	return GetUserByID(db, userID)
}

func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	return scanUser(db.QueryRow(`SELECT `+userCols+` FROM users WHERE email = ?`, strings.ToLower(email)))
}

func GetUserByID(db *sql.DB, id int64) (*User, error) {
	return scanUser(db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func ListUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func normalizeRole(role string) string {
	switch role {
	case RoleView:
		return RoleView
	case RoleUser:
		return RoleUser
	default:
		return RoleAdmin
	}
}

func CreateUser(db *sql.DB, email, passwordHash, name, role string) (int64, error) {
	role = normalizeRole(role)
	admin := 0
	if role == RoleAdmin {
		admin = 1
	}
	// RoleUser and RoleView are both non-admin
	res, err := db.Exec(
		`INSERT INTO users (email, password_hash, name, is_admin, role) VALUES (?, ?, ?, ?, ?)`,
		strings.ToLower(email), passwordHash, name, admin, role,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateUser(db *sql.DB, id int64, name, role string) error {
	role = normalizeRole(role)
	admin := 0
	if role == RoleAdmin {
		admin = 1
	}
	_, err := db.Exec(`UPDATE users SET name=?, role=?, is_admin=? WHERE id=?`, name, role, admin, id)
	return err
}

func UpdateUserPassword(db *sql.DB, id int64, passwordHash string) error {
	_, err := db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, passwordHash, id)
	return err
}

func DeleteUser(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func CountAdmins(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE COALESCE(role, CASE WHEN is_admin=1 THEN 'admin' ELSE 'view' END) = 'admin'`).Scan(&n)
	return n, err
}

func CountUsers(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// Column list shared between ListProxyHosts and GetProxyHost. Every column
// is qualified with the `ph` alias so the same string works inside the
// users-JOIN SELECTs in ListProxyHosts (where bare `id` would collide with
// users.id and raise SQLite "ambiguous column name: id"). Callers must
// alias proxy_hosts AS ph in the FROM clause. The unified dns_* columns
// sit at the end; cf_*/pb_* are not read — their data was copied into
// dns_* by the v2.3.0 migration in internal/db.
const proxyHostBaseCols = `ph.id, ph.server_id, ph.domains, ph.forward_scheme, ph.forward_host, ph.forward_port,
    ph.websocket_support, ph.block_common_exploits, ph.ssl_enabled, ph.ssl_forced,
    ph.http2_support, COALESCE(ph.advanced_config, ''), ph.enabled,
    COALESCE(ph.certificate_id, 0), ph.created_at, ph.updated_at,
    ph.basicauth_enabled, COALESCE(ph.basicauth_users, '[]'),
    COALESCE(ph.access_list, ''), COALESCE(ph.extra_upstreams, '[]'),
    COALESCE(ph.owner_id, 0),
    COALESCE(ph.dns_provider,''), COALESCE(ph.dns_zone_id,''),
    COALESCE(ph.dns_zone_name,''), COALESCE(ph.dns_record_id,'')`

// scanProxyHost pulls a single row into the struct. Centralises the
// bool-int unpack so each query site doesn't repeat it.
func scanProxyHost(s interface {
	Scan(dest ...any) error
}, p *ProxyHost, ownerEmail *string) error {
	var ws, bce, ssl, sslf, h2, en, bae int
	var ownerID int64
	dst := []any{
		&p.ID, &p.ServerID, &p.Domains, &p.ForwardScheme, &p.ForwardHost, &p.ForwardPort,
		&ws, &bce, &ssl, &sslf, &h2, &p.AdvancedConfig, &en, &p.CertificateID,
		&p.CreatedAt, &p.UpdatedAt,
		&bae, &p.BasicAuthUsers,
		&p.AccessList, &p.ExtraUpstreams,
		&ownerID,
		&p.DNSProvider, &p.DNSZoneID, &p.DNSZoneName, &p.DNSRecordID,
	}
	if ownerEmail != nil {
		dst = append(dst, ownerEmail)
	}
	if err := s.Scan(dst...); err != nil {
		return err
	}
	p.WebsocketSupport = ws == 1
	p.BlockCommonExploits = bce == 1
	p.SSLEnabled = ssl == 1
	p.SSLForced = sslf == 1
	p.HTTP2Support = h2 == 1
	p.Enabled = en == 1
	p.BasicAuthEnabled = bae == 1
	if ownerID != 0 {
		p.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
	}
	return nil
}

// ListProxyHosts returns proxy hosts for the given server.
// If isAdmin is true, all hosts are returned and owner email is populated via JOIN.
// If isAdmin is false, only hosts owned by viewerID are returned.
func ListProxyHosts(db *sql.DB, serverID int64, viewerID int64, isAdmin bool) ([]ProxyHost, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
        SELECT `+proxyHostBaseCols+`, COALESCE(u.email, '')
        FROM proxy_hosts ph
        LEFT JOIN users u ON u.id = ph.owner_id
        WHERE ph.server_id = ? ORDER BY ph.id DESC`, serverID)
	} else {
		rows, err = db.Query(`
        SELECT `+proxyHostBaseCols+`, COALESCE(u.email, '')
        FROM proxy_hosts ph
        LEFT JOIN users u ON u.id = ph.owner_id
        WHERE ph.server_id = ? AND ph.owner_id = ? ORDER BY ph.id DESC`, serverID, viewerID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ProxyHost
	for rows.Next() {
		var p ProxyHost
		var email string
		if err := scanProxyHost(rows, &p, &email); err != nil {
			return nil, err
		}
		p.OwnerEmail = email
		out = append(out, p)
	}
	return out, rows.Err()
}

func GetProxyHost(db *sql.DB, id int64) (*ProxyHost, error) {
	var p ProxyHost
	if err := scanProxyHost(
		db.QueryRow(`SELECT `+proxyHostBaseCols+` FROM proxy_hosts ph WHERE ph.id = ?`, id),
		&p, nil,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// nilIfZero returns nil for 0 so INSERT/UPDATE stores NULL in certificate_id.
func nilIfZero(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateProxyHost inserts a new proxy host. ownerID 0 means global/admin-owned (NULL in DB).
func CreateProxyHost(db *sql.DB, serverID int64, ownerID int64, p *ProxyHost) (int64, error) {
	if p.ForwardScheme == "" {
		p.ForwardScheme = "http"
	}
	if p.BasicAuthUsers == "" {
		p.BasicAuthUsers = "[]"
	}
	if p.ExtraUpstreams == "" {
		p.ExtraUpstreams = "[]"
	}
	res, err := db.Exec(`
        INSERT INTO proxy_hosts (server_id, domains, forward_scheme, forward_host, forward_port,
            websocket_support, block_common_exploits, ssl_enabled, ssl_forced,
            http2_support, advanced_config, enabled, certificate_id,
            basicauth_enabled, basicauth_users, access_list, extra_upstreams, owner_id,
            dns_provider, dns_zone_id, dns_zone_name, dns_record_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID,
		p.Domains, p.ForwardScheme, p.ForwardHost, p.ForwardPort,
		boolInt(p.WebsocketSupport), boolInt(p.BlockCommonExploits),
		boolInt(p.SSLEnabled), boolInt(p.SSLForced), boolInt(p.HTTP2Support),
		p.AdvancedConfig, boolInt(p.Enabled), nilIfZero(p.CertificateID),
		boolInt(p.BasicAuthEnabled), p.BasicAuthUsers,
		p.AccessList, p.ExtraUpstreams,
		nilIfZero(ownerID),
		p.DNSProvider, p.DNSZoneID, p.DNSZoneName, p.DNSRecordID,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateProxyHost(db *sql.DB, p *ProxyHost) error {
	if p.ForwardScheme == "" {
		p.ForwardScheme = "http"
	}
	if p.BasicAuthUsers == "" {
		p.BasicAuthUsers = "[]"
	}
	if p.ExtraUpstreams == "" {
		p.ExtraUpstreams = "[]"
	}
	_, err := db.Exec(`
        UPDATE proxy_hosts SET domains=?, forward_scheme=?, forward_host=?, forward_port=?,
            websocket_support=?, block_common_exploits=?, ssl_enabled=?, ssl_forced=?,
            http2_support=?, advanced_config=?, enabled=?, certificate_id=?,
            basicauth_enabled=?, basicauth_users=?,
            access_list=?, extra_upstreams=?,
            dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id = ?`,
		p.Domains, p.ForwardScheme, p.ForwardHost, p.ForwardPort,
		boolInt(p.WebsocketSupport), boolInt(p.BlockCommonExploits),
		boolInt(p.SSLEnabled), boolInt(p.SSLForced), boolInt(p.HTTP2Support),
		p.AdvancedConfig, boolInt(p.Enabled), nilIfZero(p.CertificateID),
		boolInt(p.BasicAuthEnabled), p.BasicAuthUsers,
		p.AccessList, p.ExtraUpstreams,
		p.DNSProvider, p.DNSZoneID, p.DNSZoneName, p.DNSRecordID,
		p.ID,
	)
	return err
}

// UpdateProxyHostDNSRecord persists the record ID + zone identifier after
// a successful provider create/delete. Kept as a minimal UPDATE (instead
// of round-tripping the full proxy host) so the IP-retarget goroutine and
// the post-create hook can both use it without racing the main form save.
//
// Pass empty strings for all four fields to clear DNS management on a host.
func UpdateProxyHostDNSRecord(db *sql.DB, id int64, provider, zoneID, zoneName, recordID string) error {
	_, err := db.Exec(`UPDATE proxy_hosts
		SET dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
		    updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		provider, zoneID, zoneName, recordID, id)
	return err
}

// ListProxyHostsWithDNSRecords returns a lightweight slice of all proxy
// hosts that have an active managed DNS record. Only the fields needed for
// lifecycle management (IP retarget, bulk delete) are populated — the
// counterpart to the pre-v2.3.0 ListProxyHostsWith{CF,PB}Records helpers.
// Pass serverID > 0 to restrict to that Caddy server (for per-server IP
// retargeting); 0 means "all servers".
func ListProxyHostsWithDNSRecords(db *sql.DB, serverID int64) ([]ProxyHost, error) {
	q := `SELECT id, server_id, domains, dns_provider, dns_zone_id, dns_zone_name, dns_record_id
		FROM proxy_hosts
		WHERE dns_provider != '' AND dns_record_id != ''`
	args := []any{}
	if serverID > 0 {
		q += ` AND server_id = ?`
		args = append(args, serverID)
	}
	q += ` ORDER BY id ASC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyHost
	for rows.Next() {
		var p ProxyHost
		if err := rows.Scan(&p.ID, &p.ServerID, &p.Domains, &p.DNSProvider, &p.DNSZoneID, &p.DNSZoneName, &p.DNSRecordID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ToggleProxyHost flips the enabled flag on a proxy host and returns the new state.
func ToggleProxyHost(db *sql.DB, id int64) (bool, error) {
	if _, err := db.Exec(`UPDATE proxy_hosts SET enabled = 1 - enabled, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return false, err
	}
	var en int
	if err := db.QueryRow(`SELECT enabled FROM proxy_hosts WHERE id = ?`, id).Scan(&en); err != nil {
		return false, err
	}
	return en == 1, nil
}

// ToggleRedirectionHost flips the enabled flag on a redirection host and returns the new state.
func ToggleRedirectionHost(db *sql.DB, id int64) (bool, error) {
	if _, err := db.Exec(`UPDATE redirection_hosts SET enabled = 1 - enabled, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return false, err
	}
	var en int
	if err := db.QueryRow(`SELECT enabled FROM redirection_hosts WHERE id = ?`, id).Scan(&en); err != nil {
		return false, err
	}
	return en == 1, nil
}

func DeleteProxyHost(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM proxy_hosts WHERE id = ?`, id)
	return err
}

// ListRedirectionHosts returns redirection hosts for the given server.
// If isAdmin is true, all hosts are returned with owner email via JOIN.
// If isAdmin is false, only hosts owned by viewerID are returned.
func ListRedirectionHosts(db *sql.DB, serverID int64, viewerID int64, isAdmin bool) ([]RedirectionHost, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
        SELECT rh.id, rh.domains, rh.forward_scheme, rh.forward_domain, rh.forward_http_code,
               rh.preserve_path, rh.ssl_enabled, rh.ssl_forced, rh.enabled,
               COALESCE(rh.certificate_id, 0), rh.created_at, rh.updated_at,
               COALESCE(rh.owner_id, 0), COALESCE(u.email, '')
        FROM redirection_hosts rh
        LEFT JOIN users u ON u.id = rh.owner_id
        WHERE rh.server_id = ? ORDER BY rh.id DESC`, serverID)
	} else {
		rows, err = db.Query(`
        SELECT rh.id, rh.domains, rh.forward_scheme, rh.forward_domain, rh.forward_http_code,
               rh.preserve_path, rh.ssl_enabled, rh.ssl_forced, rh.enabled,
               COALESCE(rh.certificate_id, 0), rh.created_at, rh.updated_at,
               COALESCE(rh.owner_id, 0), COALESCE(u.email, '')
        FROM redirection_hosts rh
        LEFT JOIN users u ON u.id = rh.owner_id
        WHERE rh.server_id = ? AND rh.owner_id = ? ORDER BY rh.id DESC`, serverID, viewerID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RedirectionHost
	for rows.Next() {
		var r RedirectionHost
		var pp, ssl, sslf, en int
		var ownerID int64
		if err := rows.Scan(&r.ID, &r.Domains, &r.ForwardScheme, &r.ForwardDomain,
			&r.ForwardHTTPCode, &pp, &ssl, &sslf, &en, &r.CertificateID,
			&r.CreatedAt, &r.UpdatedAt, &ownerID, &r.OwnerEmail); err != nil {
			return nil, err
		}
		r.PreservePath = pp == 1
		r.SSLEnabled = ssl == 1
		r.SSLForced = sslf == 1
		r.Enabled = en == 1
		if ownerID != 0 {
			r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func GetRedirectionHost(db *sql.DB, id int64) (*RedirectionHost, error) {
	var r RedirectionHost
	var pp, ssl, sslf, en int
	var ownerID int64
	err := db.QueryRow(`
        SELECT id, domains, forward_scheme, forward_domain, forward_http_code,
               preserve_path, ssl_enabled, ssl_forced, enabled,
               COALESCE(certificate_id, 0), created_at, updated_at,
               COALESCE(owner_id, 0)
        FROM redirection_hosts WHERE id = ?`, id).Scan(
		&r.ID, &r.Domains, &r.ForwardScheme, &r.ForwardDomain, &r.ForwardHTTPCode,
		&pp, &ssl, &sslf, &en, &r.CertificateID, &r.CreatedAt, &r.UpdatedAt,
		&ownerID,
	)
	if err != nil {
		return nil, err
	}
	r.PreservePath = pp == 1
	r.SSLEnabled = ssl == 1
	r.SSLForced = sslf == 1
	r.Enabled = en == 1
	if ownerID != 0 {
		r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
	}
	return &r, nil
}

// CreateRedirectionHost inserts a new redirection host. ownerID 0 means global/admin-owned (NULL in DB).
func CreateRedirectionHost(db *sql.DB, serverID int64, ownerID int64, r *RedirectionHost) (int64, error) {
	if r.ForwardScheme == "" {
		r.ForwardScheme = "auto"
	}
	if r.ForwardHTTPCode == 0 {
		r.ForwardHTTPCode = 301
	}
	res, err := db.Exec(`
        INSERT INTO redirection_hosts (server_id, domains, forward_scheme, forward_domain,
            forward_http_code, preserve_path, ssl_enabled, ssl_forced, enabled, certificate_id, owner_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID,
		r.Domains, r.ForwardScheme, r.ForwardDomain, r.ForwardHTTPCode,
		boolInt(r.PreservePath), boolInt(r.SSLEnabled), boolInt(r.SSLForced),
		boolInt(r.Enabled), nilIfZero(r.CertificateID),
		nilIfZero(ownerID),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateRedirectionHost(db *sql.DB, r *RedirectionHost) error {
	if r.ForwardScheme == "" {
		r.ForwardScheme = "auto"
	}
	_, err := db.Exec(`
        UPDATE redirection_hosts SET domains=?, forward_scheme=?, forward_domain=?,
            forward_http_code=?, preserve_path=?, ssl_enabled=?, ssl_forced=?, enabled=?,
            certificate_id=?, updated_at=CURRENT_TIMESTAMP WHERE id = ?`,
		r.Domains, r.ForwardScheme, r.ForwardDomain, r.ForwardHTTPCode,
		boolInt(r.PreservePath), boolInt(r.SSLEnabled), boolInt(r.SSLForced),
		boolInt(r.Enabled), nilIfZero(r.CertificateID), r.ID,
	)
	return err
}

func DeleteRedirectionHost(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM redirection_hosts WHERE id = ?`, id)
	return err
}

type RawRoute struct {
	ID                  int64
	Label               string
	JSONData            string
	CaddyfileSrc        string // optional: original Caddyfile block the JSON was adapted from
	Enabled             bool
	CertificateID       int64 // 0 = auto (ACME) / none; >0 = use custom certificate with this ID
	ForceSSL            bool  // cosmetic: Caddy's automatic_https handles http→https already
	BlockCommonExploits bool  // wrap route with /.env, /wp-admin, etc. → 403 subroute
	// v2.5.6: unified Managed DNS, mirroring the proxy-host DNS triple.
	// Populated on save when the user picks a provider + zone in the form;
	// empty means "no managed DNS, user wires A records manually." Same
	// semantics as the proxy-host columns — see models.ProxyHost.
	DNSProvider   string
	DNSZoneID     string
	DNSZoneName   string
	DNSRecordID   string
	OwnerID       sql.NullInt64
	OwnerEmail    string // populated via JOIN for display
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

const rawRouteCols = `id, label, json_data, COALESCE(caddyfile_src, ''), enabled,
    COALESCE(certificate_id, 0), COALESCE(force_ssl, 0), COALESCE(block_common_exploits, 0),
    COALESCE(dns_provider,''), COALESCE(dns_zone_id,''),
    COALESCE(dns_zone_name,''), COALESCE(dns_record_id,''),
    created_at, updated_at, COALESCE(owner_id, 0)`

func scanRawRoute(s interface {
	Scan(dest ...any) error
}) (RawRoute, error) {
	var r RawRoute
	var en, force, block int
	var ownerID int64
	err := s.Scan(&r.ID, &r.Label, &r.JSONData, &r.CaddyfileSrc, &en,
		&r.CertificateID, &force, &block,
		&r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID,
		&r.CreatedAt, &r.UpdatedAt, &ownerID)
	if err == nil {
		r.Enabled = en == 1
		r.ForceSSL = force == 1
		r.BlockCommonExploits = block == 1
		if ownerID != 0 {
			r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
		}
	}
	return r, err
}

// ListRawRoutes returns raw routes for the given server.
// If isAdmin is true, all routes are returned with owner email via JOIN.
// If isAdmin is false, only routes owned by viewerID are returned.
func ListRawRoutes(db *sql.DB, serverID int64, viewerID int64, isAdmin bool) ([]RawRoute, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
        SELECT rr.id, rr.label, rr.json_data, COALESCE(rr.caddyfile_src, ''), rr.enabled,
               COALESCE(rr.certificate_id, 0), COALESCE(rr.force_ssl, 0), COALESCE(rr.block_common_exploits, 0),
               COALESCE(rr.dns_provider,''), COALESCE(rr.dns_zone_id,''),
               COALESCE(rr.dns_zone_name,''), COALESCE(rr.dns_record_id,''),
               rr.created_at, rr.updated_at, COALESCE(rr.owner_id, 0), COALESCE(u.email, '')
        FROM raw_routes rr
        LEFT JOIN users u ON u.id = rr.owner_id
        WHERE rr.server_id = ? ORDER BY rr.id ASC`, serverID)
	} else {
		rows, err = db.Query(`
        SELECT rr.id, rr.label, rr.json_data, COALESCE(rr.caddyfile_src, ''), rr.enabled,
               COALESCE(rr.certificate_id, 0), COALESCE(rr.force_ssl, 0), COALESCE(rr.block_common_exploits, 0),
               COALESCE(rr.dns_provider,''), COALESCE(rr.dns_zone_id,''),
               COALESCE(rr.dns_zone_name,''), COALESCE(rr.dns_record_id,''),
               rr.created_at, rr.updated_at, COALESCE(rr.owner_id, 0), COALESCE(u.email, '')
        FROM raw_routes rr
        LEFT JOIN users u ON u.id = rr.owner_id
        WHERE rr.server_id = ? AND rr.owner_id = ? ORDER BY rr.id ASC`, serverID, viewerID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RawRoute
	for rows.Next() {
		var r RawRoute
		var en, force, block int
		var ownerID int64
		if err := rows.Scan(&r.ID, &r.Label, &r.JSONData, &r.CaddyfileSrc, &en,
			&r.CertificateID, &force, &block,
			&r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID,
			&r.CreatedAt, &r.UpdatedAt, &ownerID, &r.OwnerEmail); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.ForceSSL = force == 1
		r.BlockCommonExploits = block == 1
		if ownerID != 0 {
			r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateRawRoute inserts a new raw route. ownerID 0 means global/admin-owned (NULL in DB).
func CreateRawRoute(db *sql.DB, serverID int64, ownerID int64, r *RawRoute) (int64, error) {
	res, err := db.Exec(`INSERT INTO raw_routes (server_id, label, json_data, caddyfile_src, enabled,
            certificate_id, force_ssl, block_common_exploits,
            dns_provider, dns_zone_id, dns_zone_name, dns_record_id,
            owner_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID, r.Label, r.JSONData, r.CaddyfileSrc, boolInt(r.Enabled),
		nilIfZero(r.CertificateID), boolInt(r.ForceSSL), boolInt(r.BlockCommonExploits),
		r.DNSProvider, r.DNSZoneID, r.DNSZoneName, r.DNSRecordID,
		nilIfZero(ownerID))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func GetRawRoute(db *sql.DB, id int64) (*RawRoute, error) {
	r, err := scanRawRoute(db.QueryRow(`SELECT `+rawRouteCols+` FROM raw_routes WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func UpdateRawRoute(db *sql.DB, r *RawRoute) error {
	_, err := db.Exec(`UPDATE raw_routes SET label=?, json_data=?, caddyfile_src=?, enabled=?,
            certificate_id=?, force_ssl=?, block_common_exploits=?,
            dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
            updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		r.Label, r.JSONData, r.CaddyfileSrc, boolInt(r.Enabled),
		nilIfZero(r.CertificateID), boolInt(r.ForceSSL), boolInt(r.BlockCommonExploits),
		r.DNSProvider, r.DNSZoneID, r.DNSZoneName, r.DNSRecordID,
		r.ID)
	return err
}

// UpdateRawRouteDNSRecord persists the record ID + zone identifier after
// a successful provider create/delete. Mirrors UpdateProxyHostDNSRecord
// — kept as a minimal UPDATE so the post-create hook can write back
// without racing the main form save. Pass empty strings for all four
// fields to clear DNS management on a route.
func UpdateRawRouteDNSRecord(db *sql.DB, id int64, provider, zoneID, zoneName, recordID string) error {
	_, err := db.Exec(`UPDATE raw_routes
        SET dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?`,
		provider, zoneID, zoneName, recordID, id)
	return err
}

// ListRawRoutesWithDNSRecords returns a lightweight slice of all raw
// routes with an active managed DNS record. Only the fields needed for
// lifecycle management (IP retarget, bulk delete) are populated —
// mirrors ListProxyHostsWithDNSRecords. Pass serverID > 0 to restrict
// to that Caddy server; 0 means "all servers".
func ListRawRoutesWithDNSRecords(db *sql.DB, serverID int64) ([]RawRoute, error) {
	q := `SELECT id, label, json_data, dns_provider, dns_zone_id, dns_zone_name, dns_record_id
        FROM raw_routes
        WHERE dns_provider != '' AND dns_record_id != ''`
	args := []any{}
	if serverID > 0 {
		q += ` AND server_id = ?`
		args = append(args, serverID)
	}
	q += ` ORDER BY id ASC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RawRoute
	for rows.Next() {
		var r RawRoute
		if err := rows.Scan(&r.ID, &r.Label, &r.JSONData, &r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func DeleteRawRoute(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM raw_routes WHERE id = ?`, id)
	return err
}

func GetSetting(db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func SetSetting(db *sql.DB, key, value string) error {
	_, err := db.Exec(`
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func ProxyHostDomainsConflict(db *sql.DB, serverID int64, domains []string, excludeID int64) (string, error) {
	// Use admin view (isAdmin=true) so conflict checking is global across all owners.
	hosts, err := ListProxyHosts(db, serverID, 0, true)
	if err != nil {
		return "", err
	}
	redirs, err := ListRedirectionHosts(db, serverID, 0, true)
	if err != nil {
		return "", err
	}
	existing := map[string]int64{}
	for _, h := range hosts {
		if h.ID == excludeID {
			continue
		}
		for _, d := range h.DomainList() {
			existing[strings.ToLower(d)] = h.ID
		}
	}
	for _, r := range redirs {
		for _, d := range r.DomainList() {
			existing[strings.ToLower(d)] = r.ID
		}
	}
	for _, d := range domains {
		if _, ok := existing[strings.ToLower(d)]; ok {
			return d, nil
		}
	}
	return "", nil
}

func FormatSchemeHost(scheme, host string, port int) string {
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

const (
	CertSourcePEM  = "pem"
	CertSourcePath = "path"
)

type Certificate struct {
	ID        int64
	Name      string
	Domains   string // comma-separated hostnames the cert covers (for display / skip_certificates)
	Source    string // "pem" or "path"
	CertPEM   string
	KeyPEM    string
	CertPath  string
	KeyPath   string
	CreatedAt time.Time
	UpdatedAt time.Time

	// v2.7.2: per-user ownership. OwnerID.Valid == false means admin-owned /
	// global — any user-role account can reference it from the proxy-host
	// dropdown, but only admin can edit or delete it. OwnerID.Int64 == user.ID
	// means a user-role account uploaded it; only the uploader (or admin) can
	// see it in the dropdown, edit, or delete. OwnerEmail is populated by
	// ListCertificates when the caller is admin (for the Owner column); blank
	// otherwise to avoid a JOIN round-trip in the non-admin hot path.
	OwnerID    sql.NullInt64
	OwnerEmail string
}

func (c Certificate) DomainList() []string {
	parts := strings.Split(c.Domains, ",")
	out := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// ListCertificates returns every certificate configured on a server regardless
// of owner. Used by the Caddy sync path (which builds tls.certificates for the
// whole config) and by any other back-end path that needs a complete view.
// For user-facing lists and form dropdowns, use ListCertificatesForUser so
// non-admin accounts don't see another user's private TLS material.
func ListCertificates(db *sql.DB, serverID int64) ([]Certificate, error) {
	rows, err := db.Query(`
        SELECT id, name, domains, source, cert_pem, key_pem, cert_path, key_path, owner_id, created_at, updated_at
        FROM certificates WHERE server_id = ? ORDER BY id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Name, &c.Domains, &c.Source,
			&c.CertPEM, &c.KeyPEM, &c.CertPath, &c.KeyPath, &c.OwnerID,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListCertificatesForUser scopes the list to what the viewer is allowed to
// see. Admin gets every row plus the owner's email (for the Owner column on
// /certificates). A non-admin gets their own uploads plus global
// (admin-owned, owner_id IS NULL) certs — the latter so the proxy-host form's
// TLS dropdown still offers the shared wildcard etc. that admins maintain.
//
// OwnerEmail is populated only on the admin path; the non-admin path can't
// surface other users' emails and the column isn't shown to them anyway.
func ListCertificatesForUser(db *sql.DB, serverID int64, viewerID int64, isAdmin bool) ([]Certificate, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
            SELECT c.id, c.name, c.domains, c.source, c.cert_pem, c.key_pem, c.cert_path, c.key_path,
                   c.owner_id, c.created_at, c.updated_at, COALESCE(u.email, '')
            FROM certificates c
            LEFT JOIN users u ON u.id = c.owner_id
            WHERE c.server_id = ? ORDER BY c.id DESC`, serverID)
	} else {
		rows, err = db.Query(`
            SELECT id, name, domains, source, cert_pem, key_pem, cert_path, key_path,
                   owner_id, created_at, updated_at, ''
            FROM certificates
            WHERE server_id = ? AND (owner_id IS NULL OR owner_id = ?)
            ORDER BY id DESC`, serverID, viewerID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Name, &c.Domains, &c.Source,
			&c.CertPEM, &c.KeyPEM, &c.CertPath, &c.KeyPath, &c.OwnerID,
			&c.CreatedAt, &c.UpdatedAt, &c.OwnerEmail); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func GetCertificate(db *sql.DB, id int64) (*Certificate, error) {
	var c Certificate
	err := db.QueryRow(`
        SELECT id, name, domains, source, cert_pem, key_pem, cert_path, key_path, owner_id, created_at, updated_at
        FROM certificates WHERE id = ?`, id).Scan(
		&c.ID, &c.Name, &c.Domains, &c.Source,
		&c.CertPEM, &c.KeyPEM, &c.CertPath, &c.KeyPath, &c.OwnerID,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateCertificate inserts a new TLS cert. ownerID == 0 → global / admin
// (owner_id stored as NULL). ownerID > 0 → owned by that user (stored as-is).
// Pairs with nilIfZero so the ownership column is consistent with the other
// three tables that use the same sentinel.
func CreateCertificate(db *sql.DB, serverID int64, ownerID int64, c *Certificate) (int64, error) {
	if c.Source == "" {
		c.Source = CertSourcePEM
	}
	res, err := db.Exec(`
        INSERT INTO certificates (server_id, owner_id, name, domains, source, cert_pem, key_pem, cert_path, key_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID, nilIfZero(ownerID), c.Name, c.Domains, c.Source, c.CertPEM, c.KeyPEM, c.CertPath, c.KeyPath)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateCertificate(db *sql.DB, c *Certificate) error {
	if c.Source == "" {
		c.Source = CertSourcePEM
	}
	_, err := db.Exec(`
        UPDATE certificates SET name=?, domains=?, source=?, cert_pem=?, key_pem=?,
            cert_path=?, key_path=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		c.Name, c.Domains, c.Source, c.CertPEM, c.KeyPEM, c.CertPath, c.KeyPath, c.ID)
	return err
}

func DeleteCertificate(db *sql.DB, id int64) error {
	// NULL out references so we don't leave dangling FKs. No real FK so we do it manually.
	if _, err := db.Exec(`UPDATE proxy_hosts SET certificate_id=NULL WHERE certificate_id=?`, id); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE redirection_hosts SET certificate_id=NULL WHERE certificate_id=?`, id); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE raw_routes SET certificate_id=NULL WHERE certificate_id=?`, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM certificates WHERE id=?`, id)
	return err
}

// --- Config snapshots ---

const (
	SnapshotSourceAuto   = "auto"
	SnapshotSourceManual = "manual"
)

type ConfigSnapshot struct {
	ID         int64
	Note       string
	Source     string // "auto" (pre-sync) or "manual"
	ConfigJSON string
	CreatedAt  time.Time
}

// SizeKB is a convenience for templates.
func (s ConfigSnapshot) SizeKB() int { return (len(s.ConfigJSON) + 1023) / 1024 }

func ListSnapshots(db *sql.DB, serverID int64, limit int) ([]ConfigSnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.Query(`SELECT id, note, source, config_json, created_at
		FROM config_snapshots WHERE server_id = ? ORDER BY id DESC LIMIT ?`, serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigSnapshot
	for rows.Next() {
		var s ConfigSnapshot
		if err := rows.Scan(&s.ID, &s.Note, &s.Source, &s.ConfigJSON, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func GetSnapshot(db *sql.DB, id int64) (*ConfigSnapshot, error) {
	var s ConfigSnapshot
	err := db.QueryRow(`SELECT id, note, source, config_json, created_at
		FROM config_snapshots WHERE id=?`, id).
		Scan(&s.ID, &s.Note, &s.Source, &s.ConfigJSON, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func CreateSnapshot(db *sql.DB, serverID int64, source, note, configJSON string) (int64, error) {
	if source == "" {
		source = SnapshotSourceAuto
	}
	res, err := db.Exec(`INSERT INTO config_snapshots (server_id, note, source, config_json) VALUES (?, ?, ?, ?)`,
		serverID, note, source, configJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func DeleteSnapshot(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM config_snapshots WHERE id=?`, id)
	return err
}

// PruneAutoSnapshots keeps the most recent `keep` auto-snapshots per server and deletes older ones.
// Manual snapshots are never pruned.
func PruneAutoSnapshots(db *sql.DB, serverID int64, keep int) error {
	if keep < 1 {
		keep = 20
	}
	_, err := db.Exec(`
        DELETE FROM config_snapshots
        WHERE server_id = ? AND source = 'auto'
          AND id NOT IN (
            SELECT id FROM config_snapshots WHERE server_id = ? AND source='auto' ORDER BY id DESC LIMIT ?
          )`, serverID, serverID, keep)
	return err
}

// --- Activity log ---

type Activity struct {
	ID        int64
	Actor     string
	Action    string
	Target    string
	Detail    string
	Success   bool
	CreatedAt time.Time
}

func LogActivity(db *sql.DB, serverID int64, actor, action, target, detail string, success bool) error {
	if actor == "" {
		actor = "system"
	}
	ok := 1
	if !success {
		ok = 0
	}
	_, err := db.Exec(`INSERT INTO activity_log (server_id, actor, action, target, detail, success)
        VALUES (?, ?, ?, ?, ?, ?)`, serverID, actor, action, target, detail, ok)
	return err
}

func ListActivity(db *sql.DB, serverID int64, limit int) ([]Activity, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := db.Query(`SELECT id, actor, action, target, detail, success, created_at
        FROM activity_log WHERE server_id = ? ORDER BY id DESC LIMIT ?`, serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		var ok int
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &ok, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Success = ok == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// CertificateInUse returns the number of proxy/redirect/raw routes currently referencing this cert.
func CertificateInUse(db *sql.DB, id int64) (int, error) {
	var n int
	if err := db.QueryRow(`
        SELECT
          (SELECT COUNT(*) FROM proxy_hosts WHERE certificate_id=?) +
          (SELECT COUNT(*) FROM redirection_hosts WHERE certificate_id=?) +
          (SELECT COUNT(*) FROM raw_routes WHERE certificate_id=?)`,
		id, id, id).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CertificateInUseByOthers returns how many proxy/redirect/raw rows reference
// this cert AND are owned by someone other than excludeOwnerID (a NULL owner
// counts as "other" — those are admin/global sites). Used by the user-role
// delete path to block a cert-delete that would strip TLS off another
// tenant's site; the caller's own sites are allowed to fall back to auto-ssl.
func CertificateInUseByOthers(db *sql.DB, id int64, excludeOwnerID int64) (int, error) {
	var n int
	if err := db.QueryRow(`
        SELECT
          (SELECT COUNT(*) FROM proxy_hosts
             WHERE certificate_id=? AND (owner_id IS NULL OR owner_id != ?)) +
          (SELECT COUNT(*) FROM redirection_hosts
             WHERE certificate_id=? AND (owner_id IS NULL OR owner_id != ?)) +
          (SELECT COUNT(*) FROM raw_routes
             WHERE certificate_id=? AND (owner_id IS NULL OR owner_id != ?))`,
		id, excludeOwnerID, id, excludeOwnerID, id, excludeOwnerID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
