package models

import (
	"database/sql"
	"time"
)

// AccessEvent is one request handled by Caddy, as shipped via the `net` log
// writer to CaddyUI's analytics ingest listener. One row per request. Fields
// mirror the subset of Caddy's access-log JSON we care about — no cookies, no
// query strings, no body. See internal/analytics/ingest.go for the JSON schema
// we parse these out of.
type AccessEvent struct {
	ID         int64
	TS         time.Time
	Host       string
	Path       string
	Method     string
	Status     int
	ClientIP   string
	UserAgent  string
	DurationMs int64
	BytesOut   int64
}

// InsertAccessEvent stores one event. Called from the ingest goroutine per
// request, so keep this lean — the TCP reader blocks until the insert returns
// and SQLite's single-writer cap (pool=1) means high request volume could
// backpressure the log stream. In practice a home/SMB Caddy handles <100 rps,
// well under SQLite's 1000+ inserts/sec capacity.
func InsertAccessEvent(db *sql.DB, e AccessEvent) error {
	_, err := db.Exec(`
        INSERT INTO access_events (ts, host, path, method, status, client_ip, user_agent, duration_ms, bytes_out)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.Unix(), e.Host, e.Path, e.Method, e.Status, e.ClientIP, e.UserAgent, e.DurationMs, e.BytesOut)
	return err
}

// PruneAccessEvents deletes events older than `olderThan`. Called daily by
// the maintenance goroutine. Returns rows-affected for logging.
func PruneAccessEvents(db *sql.DB, olderThan time.Time) (int64, error) {
	res, err := db.Exec(`DELETE FROM access_events WHERE ts < ?`, olderThan.Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// AccessTotals is a two-number snapshot over a fixed window. Used for the
// overview cards ("Visitors today: N · Pageviews today: M"). Computed with
// a single SQL round-trip so the analytics page stays fast even with
// millions of events — the (ts) index is the covering path.
type AccessTotals struct {
	Views    int
	Visitors int
}

// AccessTotalsSince returns total views + distinct client_ip count for events
// with ts >= since. Optionally scoped to a single host when host != "" (used
// by the per-site drill-down; the overview passes "").
func AccessTotalsSince(db *sql.DB, since time.Time, host string) (AccessTotals, error) {
	var t AccessTotals
	q := `SELECT COUNT(*), COUNT(DISTINCT client_ip) FROM access_events WHERE ts >= ?`
	args := []any{since.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	err := db.QueryRow(q, args...).Scan(&t.Views, &t.Visitors)
	if err == sql.ErrNoRows {
		return t, nil
	}
	return t, err
}

// AccessTotalsBetween is a variant of AccessTotalsSince with an explicit
// end time, for finite windows like "yesterday's visitors" where "now" is
// the wrong upper bound.
func AccessTotalsBetween(db *sql.DB, from, to time.Time, host string) (AccessTotals, error) {
	var t AccessTotals
	q := `SELECT COUNT(*), COUNT(DISTINCT client_ip) FROM access_events WHERE ts >= ? AND ts < ?`
	args := []any{from.Unix(), to.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	err := db.QueryRow(q, args...).Scan(&t.Views, &t.Visitors)
	if err == sql.ErrNoRows {
		return t, nil
	}
	return t, err
}

// AccessLiveVisitors returns the distinct-IP count over the last `window`
// (typically 5 minutes). This powers the "Live now" card on /analytics.
func AccessLiveVisitors(db *sql.DB, window time.Duration) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(DISTINCT client_ip) FROM access_events WHERE ts >= ?`,
		time.Now().Add(-window).Unix()).Scan(&n)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return n, err
}

// HostStats is one row in the /analytics per-host table. TopPath is the
// most-hit path on that host in the same window (strings.TrimSpace'd and
// empty-safe); LastVisit is the most recent ts for any event on the host.
type HostStats struct {
	Host      string
	Views     int
	Visitors  int
	TopPath   string
	LastVisit time.Time
}

// TopHostsSince returns per-host aggregates for events newer than `since`,
// ordered by view count. Limit caps the returned set; the per-host TopPath
// comes from a correlated subquery so we stay on one round-trip.
func TopHostsSince(db *sql.DB, since time.Time, limit int) ([]HostStats, error) {
	rows, err := db.Query(`
        SELECT host,
               COUNT(*) AS views,
               COUNT(DISTINCT client_ip) AS visitors,
               COALESCE((
                   SELECT path FROM access_events
                   WHERE host = outer_e.host AND ts >= ?
                   GROUP BY path ORDER BY COUNT(*) DESC LIMIT 1
               ), '') AS top_path,
               MAX(ts) AS last_ts
          FROM access_events outer_e
         WHERE ts >= ?
         GROUP BY host
         ORDER BY views DESC
         LIMIT ?`, since.Unix(), since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostStats
	for rows.Next() {
		var s HostStats
		var lastTs int64
		if err := rows.Scan(&s.Host, &s.Views, &s.Visitors, &s.TopPath, &lastTs); err != nil {
			return nil, err
		}
		s.LastVisit = time.Unix(lastTs, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

// HostStatsForHosts is the ownership-scoped variant of TopHostsSince. Pass
// the allowed host set (the caller computes it from the user's owned
// proxy/raw-route rows) and only those hosts are returned. Empty set returns
// nil (not an error) — a non-admin with no owned sites sees an empty table.
func HostStatsForHosts(db *sql.DB, since time.Time, hosts []string) ([]HostStats, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	// Build placeholders for the IN clause. SQLite has a 999-arg default
	// limit; proxy fleets in practice never approach it, but we cap at 500
	// to stay safely under the compile-time ceiling on older builds.
	if len(hosts) > 500 {
		hosts = hosts[:500]
	}
	placeholders := make([]byte, 0, len(hosts)*2)
	args := make([]any, 0, len(hosts)+2)
	args = append(args, since.Unix(), since.Unix())
	for i, h := range hosts {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, h)
	}
	q := `
        SELECT host,
               COUNT(*) AS views,
               COUNT(DISTINCT client_ip) AS visitors,
               COALESCE((
                   SELECT path FROM access_events
                   WHERE host = outer_e.host AND ts >= ?
                   GROUP BY path ORDER BY COUNT(*) DESC LIMIT 1
               ), '') AS top_path,
               MAX(ts) AS last_ts
          FROM access_events outer_e
         WHERE ts >= ? AND host IN (` + string(placeholders) + `)
         GROUP BY host
         ORDER BY views DESC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostStats
	for rows.Next() {
		var s HostStats
		var lastTs int64
		if err := rows.Scan(&s.Host, &s.Views, &s.Visitors, &s.TopPath, &lastTs); err != nil {
			return nil, err
		}
		s.LastVisit = time.Unix(lastTs, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

// HourlyBucket is one point in a time-series — used both for the overview
// sparkline (last 24h × 1h buckets) and the per-host drill-down (30d × 1d
// buckets, driven by the same struct with Hour interpreted as the bucket
// start timestamp regardless of granularity).
type HourlyBucket struct {
	Hour     time.Time
	Views    int
	Visitors int
}

// AccessBuckets returns equally-sized time buckets between `from` and `to`,
// each row covering `bucketSeconds` of events. Buckets with zero events are
// NOT returned — the caller reconstructs the full series by walking the
// expected range and filling gaps with zeros. Keeps the query cheap when
// a long/sparse window would otherwise scan millions of near-empty buckets.
func AccessBuckets(db *sql.DB, from, to time.Time, bucketSeconds int64, host string) ([]HourlyBucket, error) {
	if bucketSeconds <= 0 {
		bucketSeconds = 3600
	}
	q := `
        SELECT (ts / ?) * ? AS bucket,
               COUNT(*) AS views,
               COUNT(DISTINCT client_ip) AS visitors
          FROM access_events
         WHERE ts >= ? AND ts < ?`
	args := []any{bucketSeconds, bucketSeconds, from.Unix(), to.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	q += ` GROUP BY bucket ORDER BY bucket ASC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HourlyBucket
	for rows.Next() {
		var b HourlyBucket
		var bucket int64
		if err := rows.Scan(&bucket, &b.Views, &b.Visitors); err != nil {
			return nil, err
		}
		b.Hour = time.Unix(bucket, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}

// TopPaths returns the most-hit paths on a host in the given window. Used by
// the per-host drill-down page. Method is included so GET / and POST / show
// as separate entries, which matters for API-heavy sites.
type PathStats struct {
	Path   string
	Method string
	Views  int
}

func TopPaths(db *sql.DB, since time.Time, host string, limit int) ([]PathStats, error) {
	if host == "" {
		return nil, nil
	}
	rows, err := db.Query(`
        SELECT path, method, COUNT(*) AS views
          FROM access_events
         WHERE ts >= ? AND host = ?
         GROUP BY path, method
         ORDER BY views DESC
         LIMIT ?`, since.Unix(), host, limit)
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

// StatusBuckets returns the count of events in each HTTP-status class (2xx,
// 3xx, 4xx, 5xx) over the window. Drives the pie-chart on the overview.
type StatusBuckets struct {
	S2xx int
	S3xx int
	S4xx int
	S5xx int
	SOther int
}

func StatusBucketsSince(db *sql.DB, since time.Time, host string) (StatusBuckets, error) {
	var b StatusBuckets
	q := `SELECT status FROM access_events WHERE ts >= ?`
	args := []any{since.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return b, err
	}
	defer rows.Close()
	for rows.Next() {
		var s int
		if err := rows.Scan(&s); err != nil {
			return b, err
		}
		switch {
		case s >= 200 && s < 300:
			b.S2xx++
		case s >= 300 && s < 400:
			b.S3xx++
		case s >= 400 && s < 500:
			b.S4xx++
		case s >= 500 && s < 600:
			b.S5xx++
		default:
			b.SOther++
		}
	}
	return b, rows.Err()
}

// TopClientIPs returns the distinct client_ip values with the most events on
// a host, each with their hit count. For the per-host drill-down only; the
// overview doesn't show IPs directly to keep the summary privacy-safe.
type ClientIPStats struct {
	ClientIP string
	Views    int
}

func TopClientIPs(db *sql.DB, since time.Time, host string, limit int) ([]ClientIPStats, error) {
	q := `
        SELECT client_ip, COUNT(*) AS views
          FROM access_events
         WHERE ts >= ? AND client_ip != ''`
	args := []any{since.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	q += ` GROUP BY client_ip ORDER BY views DESC LIMIT ?`
	args = append(args, limit)
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
