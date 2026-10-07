// SPDX-License-Identifier: Apache-2.0

package models

import (
	"database/sql"
	"fmt"
	"strings"
)

// Layer4Proxy is one TCP or UDP forward — listen address/port to an upstream
// host/port — managed as its own resource (v2.58.0, issue #122). CaddyUI turns
// each enabled row into a caddy-l4 server; the raw per-server Layer4 Caddyfile
// block stays available for anything these rows cannot express.
type Layer4Proxy struct {
	ID           int64
	ServerID     int64
	Name         string
	Protocol     string // "tcp" or "udp"
	ListenAddr   string // "" = all interfaces, else an IP literal
	ListenPort   int
	UpstreamHost string
	UpstreamPort int
	Enabled      bool
	NodeLocal    bool // never deployed to other servers
	Notes        string
	CreatedAt    sql.NullTime
	UpdatedAt    sql.NullTime

	// Shared-port mode (v2.61.0, issue #126). Instead of its own listener, the
	// proxy becomes a route of a caddy-l4 LISTENER WRAPPER on one of CaddyUI's
	// HTTP servers, so it can share a port that is already bound — for example
	// SSH for ssh.example.com on :443 next to normal HTTPS. Mode "" (or
	// "listener") keeps the dedicated-listener behaviour of v2.58.0.
	Mode         string // "" | "listener" | "shared"
	WrapServer   string // shared only: "https" (srv0, :443) or "http" (:80)
	MatchKind    string // shared only: tls_sni | http_host | ssh | rdp | postgres
	MatchHosts   string // shared only: comma-separated hostnames for tls_sni / http_host
	TerminateTLS bool   // shared tls_sni only: Caddy terminates TLS, the upstream gets plain TCP
}

const (
	Layer4ProtocolTCP = "tcp"
	Layer4ProtocolUDP = "udp"

	Layer4ModeListener = "listener"
	Layer4ModeShared   = "shared"

	Layer4WrapHTTPS = "https"
	Layer4WrapHTTP  = "http"

	Layer4MatchTLSSNI   = "tls_sni"
	Layer4MatchHTTPHost = "http_host"
	Layer4MatchSSH      = "ssh"
	Layer4MatchRDP      = "rdp"
	Layer4MatchPostgres = "postgres"
)

// IsShared reports whether the proxy shares an HTTP server's listener.
func (p Layer4Proxy) IsShared() bool { return p.Mode == Layer4ModeShared }

// MatchHostList returns MatchHosts as a clean, lower-cased list.
func (p Layer4Proxy) MatchHostList() []string {
	var out []string
	for _, h := range strings.FieldsFunc(p.MatchHosts, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }) {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// WrapPort is the port a shared proxy rides on.
func (p Layer4Proxy) WrapPort() int {
	if p.WrapServer == Layer4WrapHTTP {
		return 80
	}
	return 443
}

// MatchDisplay describes what a shared proxy matches, for lists and logs.
func (p Layer4Proxy) MatchDisplay() string {
	switch p.MatchKind {
	case Layer4MatchTLSSNI:
		return "TLS SNI " + strings.Join(p.MatchHostList(), ", ")
	case Layer4MatchHTTPHost:
		return "HTTP host " + strings.Join(p.MatchHostList(), ", ")
	case Layer4MatchSSH:
		return "SSH"
	case Layer4MatchRDP:
		return "RDP"
	case Layer4MatchPostgres:
		return "PostgreSQL"
	}
	return p.MatchKind
}

// ConflictsWith reports whether two proxies on one server would fight over the
// same traffic: the same socket for dedicated listeners; for shared proxies the
// same wrapped server and protocol matcher (and, for host matchers, a common
// hostname).
func (p Layer4Proxy) ConflictsWith(o Layer4Proxy) bool {
	if p.IsShared() != o.IsShared() {
		return false
	}
	if !p.IsShared() {
		return p.ListenKey() == o.ListenKey()
	}
	if p.WrapServer != o.WrapServer || p.MatchKind != o.MatchKind {
		return false
	}
	if p.MatchKind != Layer4MatchTLSSNI && p.MatchKind != Layer4MatchHTTPHost {
		return true
	}
	seen := map[string]bool{}
	for _, h := range p.MatchHostList() {
		seen[h] = true
	}
	for _, h := range o.MatchHostList() {
		if seen[h] {
			return true
		}
	}
	return false
}

const layer4Cols = `id, server_id, name, protocol, listen_addr, listen_port, upstream_host, upstream_port, enabled, node_local, notes, created_at, updated_at, COALESCE(mode,''), COALESCE(wrap_server,''), COALESCE(match_kind,''), COALESCE(match_hosts,''), COALESCE(terminate_tls,0)`

func scanLayer4Proxy(row interface{ Scan(dest ...any) error }) (Layer4Proxy, error) {
	var p Layer4Proxy
	var enabled, nodeLocal, terminate int
	err := row.Scan(&p.ID, &p.ServerID, &p.Name, &p.Protocol, &p.ListenAddr, &p.ListenPort,
		&p.UpstreamHost, &p.UpstreamPort, &enabled, &nodeLocal, &p.Notes, &p.CreatedAt, &p.UpdatedAt,
		&p.Mode, &p.WrapServer, &p.MatchKind, &p.MatchHosts, &terminate)
	p.Enabled, p.NodeLocal, p.TerminateTLS = enabled != 0, nodeLocal != 0, terminate != 0
	return p, err
}

// NormalizeLayer4Protocol coerces a form value to "tcp" or "udp" (default tcp).
func NormalizeLayer4Protocol(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), Layer4ProtocolUDP) {
		return Layer4ProtocolUDP
	}
	return Layer4ProtocolTCP
}

// ListenDisplay is the listen side as an operator reads it: ":5432",
// "127.0.0.1:5432", "[::1]:5432".
func (p Layer4Proxy) ListenDisplay() string {
	if p.IsShared() {
		return fmt.Sprintf(":%d (shared)", p.WrapPort())
	}
	return joinHostPort(p.ListenAddr, p.ListenPort)
}

// UpstreamDisplay is the upstream side as host:port.
func (p Layer4Proxy) UpstreamDisplay() string { return joinHostPort(p.UpstreamHost, p.UpstreamPort) }

// ListenKey identifies the socket this proxy occupies on its server: two proxies
// of the same protocol on the same address and port cannot coexist.
func (p Layer4Proxy) ListenKey() string {
	if p.IsShared() {
		return fmt.Sprintf("shared/%s/%s/%s", p.WrapServer, p.MatchKind, strings.Join(p.MatchHostList(), ","))
	}
	return fmt.Sprintf("%s/%s", p.Protocol, p.ListenDisplay())
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") { // IPv6 literal
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func ListLayer4Proxies(db *sql.DB, serverID int64) ([]Layer4Proxy, error) {
	rows, err := db.Query(`SELECT `+layer4Cols+` FROM layer4_proxies WHERE server_id=? ORDER BY protocol, listen_port, id`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Layer4Proxy
	for rows.Next() {
		p, err := scanLayer4Proxy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func GetLayer4Proxy(db *sql.DB, id int64) (*Layer4Proxy, error) {
	p, err := scanLayer4Proxy(db.QueryRow(`SELECT `+layer4Cols+` FROM layer4_proxies WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func CreateLayer4Proxy(db *sql.DB, serverID int64, p *Layer4Proxy) (int64, error) {
	res, err := db.Exec(`INSERT INTO layer4_proxies (server_id, name, protocol, listen_addr, listen_port, upstream_host, upstream_port, enabled, node_local, notes,
		mode, wrap_server, match_kind, match_hosts, terminate_tls)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID, strings.TrimSpace(p.Name), NormalizeLayer4Protocol(p.Protocol), strings.TrimSpace(p.ListenAddr), p.ListenPort,
		strings.TrimSpace(p.UpstreamHost), p.UpstreamPort, b2i(p.Enabled), b2i(p.NodeLocal), p.Notes,
		p.Mode, p.WrapServer, p.MatchKind, p.MatchHosts, b2i(p.TerminateTLS))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateLayer4Proxy(db *sql.DB, p *Layer4Proxy) error {
	_, err := db.Exec(`UPDATE layer4_proxies SET name=?, protocol=?, listen_addr=?, listen_port=?, upstream_host=?, upstream_port=?,
		enabled=?, node_local=?, notes=?, mode=?, wrap_server=?, match_kind=?, match_hosts=?, terminate_tls=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		strings.TrimSpace(p.Name), NormalizeLayer4Protocol(p.Protocol), strings.TrimSpace(p.ListenAddr), p.ListenPort,
		strings.TrimSpace(p.UpstreamHost), p.UpstreamPort, b2i(p.Enabled), b2i(p.NodeLocal), p.Notes,
		p.Mode, p.WrapServer, p.MatchKind, p.MatchHosts, b2i(p.TerminateTLS), p.ID)
	return err
}

func DeleteLayer4Proxy(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM layer4_proxies WHERE id=?`, id)
	return err
}

// ToggleLayer4Proxy flips enabled and returns the new state.
func ToggleLayer4Proxy(db *sql.DB, id int64) (bool, error) {
	if _, err := db.Exec(`UPDATE layer4_proxies SET enabled = 1 - enabled, updated_at=CURRENT_TIMESTAMP WHERE id=?`, id); err != nil {
		return false, err
	}
	p, err := GetLayer4Proxy(db, id)
	if err != nil {
		return false, err
	}
	return p.Enabled, nil
}

// Layer4ListenConflict returns the existing proxy that already occupies p's
// listen socket on the same server (excluding p itself), or nil.
func Layer4ListenConflict(db *sql.DB, serverID int64, p Layer4Proxy) (*Layer4Proxy, error) {
	rows, err := ListLayer4Proxies(db, serverID)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].ID != p.ID && p.ConflictsWith(rows[i]) {
			return &rows[i], nil
		}
	}
	return nil, nil
}
