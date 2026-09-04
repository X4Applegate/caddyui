package models

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	CaddyServerTypeManaged  = "managed"
	CaddyServerTypeExternal = "external"

	CaddyServerStatusOnline  = "online"
	CaddyServerStatusOffline = "offline"
	CaddyServerStatusUnknown = "unknown"
)

type CaddyServer struct {
	ID       int64
	Name     string
	AdminURL string
	Type     string
	Tags     string
	Status   string
	Version  string
	// AdminUsername / AdminPassword are optional HTTP Basic Auth credentials
	// sent on every call to the Caddy admin API. Useful when the admin
	// endpoint is exposed through a reverse proxy that enforces basic auth.
	AdminUsername string
	AdminPassword string
	// PublicIP is the WAN IP this server answers on — written into the A
	// record content by every DNS provider when a proxy host is created on
	// this server. Empty = fall back to the legacy global setting.
	PublicIP string
	// IngestTarget (v2.37.0) is the host:port THIS node connects to to ship
	// access logs, certificate events and runtime logs to CaddyUI. Empty =
	// the fleet-wide target from Settings → Analytics. One global target
	// defaulted to "caddyui:9019" — a Docker service name only containers on
	// the same network can resolve — so every node on another host silently
	// shipped nothing: no analytics, no certificate status, no runtime logs.
	IngestTarget  string
	LastContactAt sql.NullTime
	CreatedAt     time.Time
}

func (c CaddyServer) TagList() []string {
	parts := strings.Split(c.Tags, ",")
	out := make([]string, 0, len(parts))
	for _, t := range parts {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

const caddyServerCols = `id, name, admin_url, type, tags, status, COALESCE(version,''), COALESCE(admin_username,''), COALESCE(admin_password,''), COALESCE(public_ip,''), COALESCE(ingest_target,''), last_contact_at, created_at`

func scanCaddyServer(s interface {
	Scan(dest ...any) error
}) (CaddyServer, error) {
	var c CaddyServer
	err := s.Scan(&c.ID, &c.Name, &c.AdminURL, &c.Type, &c.Tags, &c.Status, &c.Version, &c.AdminUsername, &c.AdminPassword, &c.PublicIP, &c.IngestTarget, &c.LastContactAt, &c.CreatedAt)
	return c, err
}

// EffectiveIngestTarget is where this node ships its logs: its own
// IngestTarget when set, otherwise the fleet-wide target from Settings →
// Analytics. v2.37.0.
func (c CaddyServer) EffectiveIngestTarget(global string) string {
	if t := strings.TrimSpace(c.IngestTarget); t != "" {
		return t
	}
	return strings.TrimSpace(global)
}

// LooksDockerInternalHost reports whether hostport names a bare, single-label
// host such as "caddyui:9019" — resolvable only inside the Docker network
// that defines it. IP addresses, "localhost", dotted names and unix sockets
// return false.
func LooksDockerInternalHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(strings.TrimSpace(hostport)); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "localhost" || strings.Contains(host, ".") || strings.Contains(host, "/") || net.ParseIP(host) != nil {
		return false
	}
	return true
}

// IngestTargetWarning explains, in one sentence, why this node very likely
// cannot deliver its logs to effectiveTarget, or returns "" when nothing looks
// wrong. Only the unambiguous case is flagged: a node whose admin API lives on
// another host (an IP address or a dotted name) that was handed a bare Docker
// service name. A node reached at a bare name itself ("http://caddy:2019")
// shares CaddyUI's Docker network, where the default target works; unix
// sockets are left alone because their placement is ambiguous.
func (c CaddyServer) IngestTargetWarning(effectiveTarget string) string {
	if !LooksDockerInternalHost(effectiveTarget) {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(c.AdminURL))
	if err != nil || u.Scheme == "unix" {
		return ""
	}
	adminHost := strings.ToLower(u.Hostname())
	if adminHost == "" || adminHost == "localhost" || (!strings.Contains(adminHost, ".") && net.ParseIP(adminHost) == nil) {
		return ""
	}
	return fmt.Sprintf("This node is reached at %s but was told to send its logs to %q — a Docker service name another host cannot resolve, so CaddyUI receives nothing from it (no analytics, certificate status or runtime logs). Give it an ingest target it can reach: the CaddyUI host as seen from that node, e.g. 192.168.1.10:9019 on a LAN or 10.8.0.1:9019 over a VPN.", adminHost, effectiveTarget)
}

func SetCaddyServerVersion(db *sql.DB, id int64, version string) error {
	_, err := db.Exec(`UPDATE caddy_servers SET version=? WHERE id=?`, version, id)
	return err
}

func ListCaddyServers(db *sql.DB) ([]CaddyServer, error) {
	rows, err := db.Query(`SELECT ` + caddyServerCols + ` FROM caddy_servers ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CaddyServer
	for rows.Next() {
		c, err := scanCaddyServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func GetCaddyServer(db *sql.DB, id int64) (*CaddyServer, error) {
	c, err := scanCaddyServer(db.QueryRow(`SELECT `+caddyServerCols+` FROM caddy_servers WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func CountCaddyServers(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM caddy_servers`).Scan(&n)
	return n, err
}

func normalizeServerType(t string) string {
	if t == CaddyServerTypeExternal {
		return CaddyServerTypeExternal
	}
	return CaddyServerTypeManaged
}

func CreateCaddyServer(db *sql.DB, c *CaddyServer) (int64, error) {
	c.Type = normalizeServerType(c.Type)
	if c.Status == "" {
		c.Status = CaddyServerStatusUnknown
	}
	res, err := db.Exec(
		`INSERT INTO caddy_servers (name, admin_url, type, tags, status, admin_username, admin_password, public_ip, ingest_target) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(c.Name), strings.TrimRight(strings.TrimSpace(c.AdminURL), "/"),
		c.Type, strings.TrimSpace(c.Tags), c.Status,
		strings.TrimSpace(c.AdminUsername), c.AdminPassword,
		strings.TrimSpace(c.PublicIP), strings.TrimSpace(c.IngestTarget),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateCaddyServer(db *sql.DB, c *CaddyServer) error {
	c.Type = normalizeServerType(c.Type)
	_, err := db.Exec(
		`UPDATE caddy_servers SET name=?, admin_url=?, type=?, tags=?, version=?, admin_username=?, admin_password=?, public_ip=?, ingest_target=? WHERE id=?`,
		strings.TrimSpace(c.Name), strings.TrimRight(strings.TrimSpace(c.AdminURL), "/"),
		c.Type, strings.TrimSpace(c.Tags), strings.TrimSpace(c.Version),
		strings.TrimSpace(c.AdminUsername), c.AdminPassword,
		strings.TrimSpace(c.PublicIP), strings.TrimSpace(c.IngestTarget), c.ID,
	)
	return err
}

// SetCaddyServerPublicIP updates only the public_ip column. Used by the
// settings page's per-server IP editor and returns the old value so the
// caller can decide whether to trigger DNS retargeting.
func SetCaddyServerPublicIP(db *sql.DB, id int64, ip string) (old string, err error) {
	if err := db.QueryRow(`SELECT COALESCE(public_ip,'') FROM caddy_servers WHERE id=?`, id).Scan(&old); err != nil {
		return "", err
	}
	_, err = db.Exec(`UPDATE caddy_servers SET public_ip=? WHERE id=?`, strings.TrimSpace(ip), id)
	return old, err
}

func DeleteCaddyServer(db *sql.DB, id int64) error {
	if err := DeleteFleetDeploymentsForServer(db, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM caddy_servers WHERE id=?`, id)
	return err
}

func SetCaddyServerStatus(db *sql.DB, id int64, status string, contactedAt *time.Time) error {
	if contactedAt != nil {
		_, err := db.Exec(`UPDATE caddy_servers SET status=?, last_contact_at=? WHERE id=?`, status, *contactedAt, id)
		return err
	}
	_, err := db.Exec(`UPDATE caddy_servers SET status=? WHERE id=?`, status, id)
	return err
}
