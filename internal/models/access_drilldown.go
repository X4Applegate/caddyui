package models

import (
	"database/sql"
	"strconv"
	"time"
)

// Deeper analytics drill-down (issue #94): per-visitor and per-path views, plus
// exact status-code + path error detail. All queries are scoped by host and the
// existing window/server filter and bounded to top-N, so they reuse the same
// (host, ts) / (client_ip, ts) range scans the overview already relies on.

// ErrorDetailStats is one exact (status, path, method) error group with its count.
type ErrorDetailStats struct {
	Status int
	Path   string
	Method string
	Count  int
}

// UAStat is one raw user-agent string with its request count.
type UAStat struct {
	UserAgent string
	Count     int
}

// statusBucketsWhere computes the 2xx/3xx/4xx/5xx/other distribution for the
// given WHERE fragment (which must begin with a leading " AND ..." or be empty)
// and args. COALESCE keeps a no-row result at zero rather than NULL.
func statusBucketsWhere(db *sql.DB, since time.Time, extra string, args []any, serverIDs ...int64) (StatusBuckets, error) {
	q := `SELECT
	        COALESCE(SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END),0),
	        COALESCE(SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END),0),
	        COALESCE(SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),0),
	        COALESCE(SUM(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END),0),
	        COALESCE(SUM(CASE WHEN status < 200 OR status >= 600 THEN 1 ELSE 0 END),0)
	      FROM access_events
	     WHERE ts >= ?`
	qargs := append([]any{since.Unix()}, args...)
	q += extra
	if serverClause, serverArgs := serverMatchClause(requestedServerID(serverIDs)); serverClause != "" {
		q += serverClause
		qargs = append(qargs, serverArgs...)
	}
	var b StatusBuckets
	err := db.QueryRow(q, qargs...).Scan(&b.S2xx, &b.S3xx, &b.S4xx, &b.S5xx, &b.SOther)
	return b, err
}

// --- Visitor drill-down (host + client_ip) ---

// VisitorTotals returns the total request count for a single client IP on a host.
func VisitorTotals(db *sql.DB, since time.Time, host, clientIP string, serverIDs ...int64) (int, error) {
	if host == "" || clientIP == "" {
		return 0, nil
	}
	q := `SELECT COUNT(*) FROM access_events WHERE ts >= ? AND host = ? AND client_ip = ?`
	args := []any{since.Unix(), host, clientIP}
	if serverClause, serverArgs := serverMatchClause(requestedServerID(serverIDs)); serverClause != "" {
		q += serverClause
		args = append(args, serverArgs...)
	}
	var n int
	err := db.QueryRow(q, args...).Scan(&n)
	return n, err
}

// VisitorPaths returns the top paths requested by a single client IP on a host.
func VisitorPaths(db *sql.DB, since time.Time, host, clientIP string, limit int, serverIDs ...int64) ([]PathStats, error) {
	if host == "" || clientIP == "" {
		return nil, nil
	}
	q := `SELECT path, method, COUNT(*) AS views
	        FROM access_events
	       WHERE ts >= ? AND host = ? AND client_ip = ?`
	args := []any{since.Unix(), host, clientIP}
	if serverClause, serverArgs := serverMatchClause(requestedServerID(serverIDs)); serverClause != "" {
		q += serverClause
		args = append(args, serverArgs...)
	}
	q += ` GROUP BY path, method ORDER BY views DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PathStats
	for rows.Next() {
		var p PathStats
		if err := rows.Scan(&p.Path, &p.Method, &p.Views); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// VisitorStatusBuckets returns the status-class distribution for a single client IP.
func VisitorStatusBuckets(db *sql.DB, since time.Time, host, clientIP string, serverIDs ...int64) (StatusBuckets, error) {
	if host == "" || clientIP == "" {
		return StatusBuckets{}, nil
	}
	return statusBucketsWhere(db, since, ` AND host = ? AND client_ip = ?`, []any{host, clientIP}, serverIDs...)
}

// VisitorErrorDetails returns the exact (status, path) error groups for a client IP.
func VisitorErrorDetails(db *sql.DB, since time.Time, host, clientIP string, limit int, serverIDs ...int64) ([]ErrorDetailStats, error) {
	if host == "" || clientIP == "" {
		return nil, nil
	}
	return errorDetails(db, since, ` AND host = ? AND client_ip = ?`, []any{host, clientIP}, limit, serverIDs...)
}

// VisitorUserAgents returns the top raw user-agent strings for a client IP.
func VisitorUserAgents(db *sql.DB, since time.Time, host, clientIP string, limit int, serverIDs ...int64) ([]UAStat, error) {
	if host == "" || clientIP == "" {
		return nil, nil
	}
	q := `SELECT user_agent, COUNT(*) AS cnt
	        FROM access_events
	       WHERE ts >= ? AND host = ? AND client_ip = ?`
	args := []any{since.Unix(), host, clientIP}
	if serverClause, serverArgs := serverMatchClause(requestedServerID(serverIDs)); serverClause != "" {
		q += serverClause
		args = append(args, serverArgs...)
	}
	q += ` GROUP BY user_agent ORDER BY cnt DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UAStat
	for rows.Next() {
		var u UAStat
		if err := rows.Scan(&u.UserAgent, &u.Count); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- Path drill-down (host + path) ---

// PathTotals returns total views and distinct visitors for a single path on a host.
func PathTotals(db *sql.DB, since time.Time, host, path string, serverIDs ...int64) (AccessTotals, error) {
	if host == "" {
		return AccessTotals{}, nil
	}
	q := `SELECT COUNT(*), COUNT(DISTINCT client_ip)
	        FROM access_events
	       WHERE ts >= ? AND host = ? AND path = ?`
	args := []any{since.Unix(), host, path}
	if serverClause, serverArgs := serverMatchClause(requestedServerID(serverIDs)); serverClause != "" {
		q += serverClause
		args = append(args, serverArgs...)
	}
	var t AccessTotals
	err := db.QueryRow(q, args...).Scan(&t.Views, &t.Visitors)
	return t, err
}

// PathClients returns the top client IPs that requested a single path on a host.
func PathClients(db *sql.DB, since time.Time, host, path string, limit int, serverIDs ...int64) ([]ClientIPStats, error) {
	if host == "" {
		return nil, nil
	}
	q := `SELECT client_ip, COUNT(*) AS views
	        FROM access_events
	       WHERE ts >= ? AND host = ? AND path = ? AND client_ip != ''`
	args := []any{since.Unix(), host, path}
	if serverClause, serverArgs := serverMatchClause(requestedServerID(serverIDs)); serverClause != "" {
		q += serverClause
		args = append(args, serverArgs...)
	}
	q += ` GROUP BY client_ip ORDER BY views DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientIPStats
	for rows.Next() {
		var c ClientIPStats
		if err := rows.Scan(&c.ClientIP, &c.Views); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PathStatusBuckets returns the status-class distribution for a single path.
func PathStatusBuckets(db *sql.DB, since time.Time, host, path string, serverIDs ...int64) (StatusBuckets, error) {
	if host == "" {
		return StatusBuckets{}, nil
	}
	return statusBucketsWhere(db, since, ` AND host = ? AND path = ?`, []any{host, path}, serverIDs...)
}

// --- Error detail (host) ---

// TopErrorDetails returns the top (status, path, method) error groups on a host,
// so operators see exactly which endpoint returns which error, not just a class.
func TopErrorDetails(db *sql.DB, since time.Time, host string, limit int, serverIDs ...int64) ([]ErrorDetailStats, error) {
	extra := ``
	args := []any{}
	if host != "" {
		extra = ` AND host = ?`
		args = append(args, host)
	}
	return errorDetails(db, since, extra, args, limit, serverIDs...)
}

// errorDetails is the shared implementation for status+path error breakdowns.
func errorDetails(db *sql.DB, since time.Time, extra string, extraArgs []any, limit int, serverIDs ...int64) ([]ErrorDetailStats, error) {
	q := `SELECT status, path, method, COUNT(*) AS cnt
	        FROM access_events
	       WHERE ts >= ? AND status >= 400`
	args := append([]any{since.Unix()}, extraArgs...)
	q += extra
	if serverClause, serverArgs := serverMatchClause(requestedServerID(serverIDs)); serverClause != "" {
		q += serverClause
		args = append(args, serverArgs...)
	}
	q += ` GROUP BY status, path, method ORDER BY cnt DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ErrorDetailStats
	for rows.Next() {
		var e ErrorDetailStats
		if err := rows.Scan(&e.Status, &e.Path, &e.Method, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
