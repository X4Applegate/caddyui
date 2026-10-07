// SPDX-License-Identifier: Apache-2.0

package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MiddlewareProfile is a reusable bundle of HTTP policy — security headers,
// forward auth, IP restrictions, extra headers — attached to any number of
// proxy hosts (v2.60.0, issue #124). It is global: the controller database
// holds every fleet server, so one profile serves hosts on all of them. Every
// field is optional; a value set on the host itself wins over the profile's
// (empty host fields inherit it; header maps merge by name).
type MiddlewareProfile struct {
	ID          int64
	Name        string
	Description string

	SecurityHeaders   bool
	XFrameOptions     string
	ReferrerPolicy    string
	PermissionsPolicy string
	CSPHeader         string

	ForwardAuthURL           string
	ForwardAuthMethod        string
	ForwardAuthCopyHeaders   string
	ForwardAuthHeadersPrefix string
	ForwardAuthSkipPaths     string

	AccessList        string // CIDR allowlist; empty = no restriction from the profile
	IPBlocklist       string // CIDR blocklist
	CustomReqHeaders  string // JSON {"Name":"value"}
	CustomRespHeaders string // JSON {"Name":"value"}

	// Coraza WAF (v2.61.0). Needs a Caddy built with coraza-caddy
	// (applegater/caddyui-caddy from v2.61.0).
	WAFMode       string // "" (off) | "detect" | "block"
	WAFCRS        bool   // load the OWASP Core Rule Set
	WAFParanoia   int    // 1-4 (0 is treated as 1)
	WAFDirectives string // extra SecLang appended after the engine line

	CreatedAt time.Time
	UpdatedAt time.Time

	// HostCount is view state filled by ListMiddlewareProfiles.
	HostCount int
}

// WAF modes of a middleware profile (v2.61.0).
const (
	WAFModeOff    = ""
	WAFModeDetect = "detect" // Coraza logs what it would block, nothing is blocked
	WAFModeBlock  = "block"  // Coraza blocks requests that score as attacks
)

// WAFSettings is a profile's Coraza WAF choice carried to the route builder. It
// is applied to a COPY of a host at config-build time (never stored on the host
// row), so detaching the profile removes the WAF again.
type WAFSettings struct {
	Mode       string // WAFModeDetect or WAFModeBlock
	CRS        bool   // load the embedded OWASP Core Rule Set
	Paranoia   int    // CRS blocking paranoia level 1-4
	Directives string // extra SecLang appended after the engine line
}

// ErrProfileInUse is returned by DeleteMiddlewareProfile while hosts use it.
var ErrProfileInUse = errors.New("middleware profile is still attached to proxy hosts")

const middlewareProfileCols = `id, name, COALESCE(description,''), COALESCE(security_headers,0), COALESCE(x_frame_options,''), COALESCE(referrer_policy,''),
	COALESCE(permissions_policy,''), COALESCE(csp_header,''), COALESCE(forward_auth_url,''), COALESCE(forward_auth_method,''),
	COALESCE(forward_auth_copy_headers,''), COALESCE(forward_auth_headers_prefix,''), COALESCE(forward_auth_skip_paths,''),
	COALESCE(access_list,''), COALESCE(ip_blocklist,''), COALESCE(custom_req_headers,''), COALESCE(custom_resp_headers,''), created_at, updated_at,
	COALESCE(waf_mode,''), COALESCE(waf_crs,0), COALESCE(waf_paranoia,0), COALESCE(waf_directives,'')`

func scanMiddlewareProfile(sc interface{ Scan(...any) error }) (MiddlewareProfile, error) {
	var p MiddlewareProfile
	err := sc.Scan(&p.ID, &p.Name, &p.Description, &p.SecurityHeaders, &p.XFrameOptions, &p.ReferrerPolicy,
		&p.PermissionsPolicy, &p.CSPHeader, &p.ForwardAuthURL, &p.ForwardAuthMethod,
		&p.ForwardAuthCopyHeaders, &p.ForwardAuthHeadersPrefix, &p.ForwardAuthSkipPaths,
		&p.AccessList, &p.IPBlocklist, &p.CustomReqHeaders, &p.CustomRespHeaders, &p.CreatedAt, &p.UpdatedAt,
		&p.WAFMode, &p.WAFCRS, &p.WAFParanoia, &p.WAFDirectives)
	return p, err
}

// ListMiddlewareProfiles returns every profile by name, with how many hosts use it.
func ListMiddlewareProfiles(db *sql.DB) ([]MiddlewareProfile, error) {
	rows, err := db.Query(`SELECT ` + middlewareProfileCols + ` FROM middleware_profiles ORDER BY LOWER(name)`)
	if err != nil {
		return nil, err
	}
	var out []MiddlewareProfile
	for rows.Next() {
		p, err := scanMiddlewareProfile(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	counts, err := db.Query(`SELECT a.profile_id, COUNT(*) FROM proxy_host_profiles a JOIN proxy_hosts h ON h.id = a.proxy_host_id GROUP BY a.profile_id`)
	if err != nil {
		return nil, err
	}
	defer counts.Close()
	byID := map[int64]int{}
	for counts.Next() {
		var id int64
		var n int
		if err := counts.Scan(&id, &n); err != nil {
			return nil, err
		}
		byID[id] = n
	}
	for i := range out {
		out[i].HostCount = byID[out[i].ID]
	}
	return out, counts.Err()
}

// GetMiddlewareProfile returns nil, nil when there is no such profile.
func GetMiddlewareProfile(db *sql.DB, id int64) (*MiddlewareProfile, error) {
	if id <= 0 {
		return nil, nil
	}
	p, err := scanMiddlewareProfile(db.QueryRow(`SELECT `+middlewareProfileCols+` FROM middleware_profiles WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// MiddlewareProfileNameTaken reports whether another profile already has name
// (case-insensitive).
func MiddlewareProfileNameTaken(db *sql.DB, name string, exceptID int64) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM middleware_profiles WHERE LOWER(name)=LOWER(?) AND id<>?`, strings.TrimSpace(name), exceptID).Scan(&n)
	return n > 0, err
}

func CreateMiddlewareProfile(db *sql.DB, p *MiddlewareProfile) (int64, error) {
	res, err := db.Exec(`INSERT INTO middleware_profiles
		(name, description, security_headers, x_frame_options, referrer_policy, permissions_policy, csp_header,
		 forward_auth_url, forward_auth_method, forward_auth_copy_headers, forward_auth_headers_prefix, forward_auth_skip_paths,
		 access_list, ip_blocklist, custom_req_headers, custom_resp_headers, waf_mode, waf_crs, waf_paranoia, waf_directives)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		strings.TrimSpace(p.Name), p.Description, p.SecurityHeaders, p.XFrameOptions, p.ReferrerPolicy, p.PermissionsPolicy, p.CSPHeader,
		p.ForwardAuthURL, p.ForwardAuthMethod, p.ForwardAuthCopyHeaders, p.ForwardAuthHeadersPrefix, p.ForwardAuthSkipPaths,
		p.AccessList, p.IPBlocklist, p.CustomReqHeaders, p.CustomRespHeaders,
		p.WAFMode, p.WAFCRS, p.WAFParanoia, p.WAFDirectives)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateMiddlewareProfile(db *sql.DB, p *MiddlewareProfile) error {
	_, err := db.Exec(`UPDATE middleware_profiles SET name=?, description=?, security_headers=?, x_frame_options=?, referrer_policy=?,
		permissions_policy=?, csp_header=?, forward_auth_url=?, forward_auth_method=?, forward_auth_copy_headers=?,
		forward_auth_headers_prefix=?, forward_auth_skip_paths=?, access_list=?, ip_blocklist=?, custom_req_headers=?,
		custom_resp_headers=?, waf_mode=?, waf_crs=?, waf_paranoia=?, waf_directives=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		strings.TrimSpace(p.Name), p.Description, p.SecurityHeaders, p.XFrameOptions, p.ReferrerPolicy,
		p.PermissionsPolicy, p.CSPHeader, p.ForwardAuthURL, p.ForwardAuthMethod, p.ForwardAuthCopyHeaders,
		p.ForwardAuthHeadersPrefix, p.ForwardAuthSkipPaths, p.AccessList, p.IPBlocklist, p.CustomReqHeaders,
		p.CustomRespHeaders, p.WAFMode, p.WAFCRS, p.WAFParanoia, p.WAFDirectives, p.ID)
	return err
}

// DeleteMiddlewareProfile refuses while any host still uses the profile, so a
// delete can never silently drop policy (forward auth, IP restrictions) from a
// live host.
func DeleteMiddlewareProfile(db *sql.DB, id int64) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM proxy_host_profiles a JOIN proxy_hosts h ON h.id = a.proxy_host_id WHERE a.profile_id=?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w (%d host(s))", ErrProfileInUse, n)
	}
	// Drop attachments whose host no longer exists, then the profile.
	if _, err := db.Exec(`DELETE FROM proxy_host_profiles WHERE profile_id=?`, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM middleware_profiles WHERE id=?`, id)
	return err
}

// ProxyHostProfileID returns the profile attached to a host, 0 for none.
func ProxyHostProfileID(db *sql.DB, hostID int64) int64 {
	var id int64
	if err := db.QueryRow(`SELECT profile_id FROM proxy_host_profiles WHERE proxy_host_id=?`, hostID).Scan(&id); err != nil {
		return 0
	}
	return id
}

// SetProxyHostProfile attaches profileID to a host; 0 detaches it.
func SetProxyHostProfile(db *sql.DB, hostID, profileID int64) error {
	if hostID <= 0 {
		return fmt.Errorf("host ID must be positive")
	}
	if profileID <= 0 {
		_, err := db.Exec(`DELETE FROM proxy_host_profiles WHERE proxy_host_id=?`, hostID)
		return err
	}
	res, err := db.Exec(`UPDATE proxy_host_profiles SET profile_id=? WHERE proxy_host_id=?`, profileID, hostID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = db.Exec(`INSERT INTO proxy_host_profiles (proxy_host_id, profile_id) VALUES (?, ?)`, hostID, profileID)
	return err
}

// ProxyHostProfileMap returns host ID -> profile ID for every attached host.
func ProxyHostProfileMap(db *sql.DB) (map[int64]int64, error) {
	rows, err := db.Query(`SELECT proxy_host_id, profile_id FROM proxy_host_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int64{}
	for rows.Next() {
		var h, p int64
		if err := rows.Scan(&h, &p); err != nil {
			return nil, err
		}
		out[h] = p
	}
	return out, rows.Err()
}

// ServersUsingProfile lists the servers that have at least one host on the
// profile — the ones to re-sync when the profile changes.
func ServersUsingProfile(db *sql.DB, profileID int64) ([]int64, error) {
	rows, err := db.Query(`SELECT DISTINCT h.server_id FROM proxy_hosts h
		JOIN proxy_host_profiles a ON a.proxy_host_id = h.id WHERE a.profile_id=? ORDER BY h.server_id`, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
