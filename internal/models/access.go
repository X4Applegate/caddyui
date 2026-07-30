package models

import (
	"database/sql"
	"sort"
	"strconv"
	"strings"
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
//
// v2.9.206: long windows (≥ today's UTC midnight in the past) read past-day
// totals from the access_daily rollup and only scan access_events for today.
// This drops the cost of the "Last 30 days" / "Last 90 days" cards from
// O(rows-in-window) to O(rows-today) + O(days-in-window), turning multi-second
// scans into ~10ms lookups on installs with millions of events.
//
// Visitor counts from the rollup are approximate by design — same IP across
// multiple days is counted multiple times. The schema comment on access_daily
// already calls this out as best-effort. For an exact distinct count over a
// long window the caller can switch to the events table directly.
// hostMatchClause — v2.12.9: builds a SQL fragment that filters access_events
// (or access_daily) by `host`, with wildcard support. A leading `*.` means
// "any subdomain of foo.bar" — translates to `host LIKE '%.foo.bar'`. An
// exact hostname stays an `=` match. Empty host returns "" so callers can
// drop the filter entirely. Used by the dashboard + per-host analytics
// scoping when proxy_hosts.Domains contains wildcard SANs.
func hostMatchClause(host string) (string, []any) {
	if host == "" {
		return "", nil
	}
	if len(host) > 2 && host[0] == '*' && host[1] == '.' {
		return " AND host LIKE ?", []any{"%" + host[1:]}
	}
	return " AND host = ?", []any{host}
}

func AccessTotalsSince(db *sql.DB, since time.Time, host string) (AccessTotals, error) {
	todayStart := time.Now().UTC().Truncate(24 * time.Hour)
	if !since.UTC().Before(todayStart) {
		// Window starts today or in the future — events table is fast enough
		// (only today's slice of the (ts) index is touched).
		return accessTotalsFromEvents(db, since, time.Time{}, host)
	}
	// Past + today: rollup for past days, events for today.
	rollup, err := accessTotalsFromRollup(db, since, todayStart, host)
	if err != nil {
		return AccessTotals{}, err
	}
	today, err := accessTotalsFromEvents(db, todayStart, time.Time{}, host)
	if err != nil {
		return AccessTotals{}, err
	}
	return AccessTotals{
		Views:    rollup.Views + today.Views,
		Visitors: rollup.Visitors + today.Visitors,
	}, nil
}

// accessTotalsFromEvents scans access_events directly. When `to` is the zero
// value the upper bound is unbounded ("ts >= since" only).
func accessTotalsFromEvents(db *sql.DB, from, to time.Time, host string) (AccessTotals, error) {
	var t AccessTotals
	q := `SELECT COUNT(*), COUNT(DISTINCT client_ip) FROM access_events WHERE ts >= ?`
	args := []any{from.Unix()}
	if !to.IsZero() {
		q += ` AND ts < ?`
		args = append(args, to.Unix())
	}
	if hostClause, hostArgs := hostMatchClause(host); hostClause != "" {
		q += hostClause
		args = append(args, hostArgs...)
	}
	err := db.QueryRow(q, args...).Scan(&t.Views, &t.Visitors)
	if err == sql.ErrNoRows {
		return t, nil
	}
	return t, err
}

// accessTotalsFromRollup sums access_daily for [fromDay, toDay) where
// toDay is exclusive (typically today's UTC midnight).
func accessTotalsFromRollup(db *sql.DB, from, to time.Time, host string) (AccessTotals, error) {
	var t AccessTotals
	fromDay := from.UTC().Format("2006-01-02")
	toDay := to.UTC().Format("2006-01-02")
	q := `SELECT COALESCE(SUM(views),0), COALESCE(SUM(unique_visitors),0)
	      FROM access_daily WHERE day >= ? AND day < ?`
	args := []any{fromDay, toDay}
	if hostClause, hostArgs := hostMatchClause(host); hostClause != "" {
		q += hostClause
		args = append(args, hostArgs...)
	}
	err := db.QueryRow(q, args...).Scan(&t.Views, &t.Visitors)
	if err == sql.ErrNoRows {
		return t, nil
	}
	return t, err
}

// AggregateAccessDaily backfills the access_daily rollup for every UTC day
// that has access_events but no rollup row, up to (but excluding) today.
// Today's data is intentionally left out so the rollup only contains complete
// days — partial-day numbers would change as more events arrive and the
// rollup-vs-events math would double-count.
//
// Idempotent: re-runs only fill missing days, which makes it safe to invoke
// from a startup hook and again from a periodic ticker. REPLACE guarantees a
// consistent row even if the same day was partially inserted.
//
// v2.9.207: also populates per-status-class buckets (s2xx/s3xx/s4xx/s5xx/
// s_other) so StatusBucketsSince can read the rollup for past days.
//
// Returns the number of days written so callers can log progress.
func AggregateAccessDaily(db *sql.DB) (int, error) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	// v2.9.207: detect rollup rows that were written by a pre-status-bucket
	// build. Those rows have non-zero views but all zero status counters,
	// which can't be the real distribution unless the day was empty (and an
	// empty day wouldn't have a row at all). Re-aggregate them so the status
	// pie picks up real numbers.
	var staleDays []string
	if rows, err := db.Query(`
		SELECT day FROM access_daily
		 WHERE views > 0
		   AND s2xx = 0 AND s3xx = 0 AND s4xx = 0 AND s5xx = 0 AND s_other = 0
		 GROUP BY day
		 ORDER BY day
		 LIMIT 365`); err == nil {
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err == nil {
				staleDays = append(staleDays, d)
			}
		}
		rows.Close()
	}
	// Step 1: find the event date range and compare it with the small rollup
	// table in Go. This avoids engine-specific epoch/date functions and lets
	// both SQLite and MariaDB use the ts index.
	var firstTS sql.NullInt64
	err := db.QueryRow(
		`SELECT ts FROM access_events WHERE ts < ? ORDER BY ts ASC LIMIT 1`,
		today.Unix(),
	).Scan(&firstTS)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	existingDays := map[string]struct{}{}
	rows, err := db.Query(`SELECT DISTINCT day FROM access_daily`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var day string
		if err := rows.Scan(&day); err != nil {
			rows.Close()
			return 0, err
		}
		existingDays[day] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	var missingDays []string
	if firstTS.Valid {
		firstDay := time.Unix(firstTS.Int64, 0).UTC().Truncate(24 * time.Hour)
		for day := firstDay; day.Before(today) && len(missingDays) < 365; day = day.Add(24 * time.Hour) {
			dayText := day.Format("2006-01-02")
			if _, ok := existingDays[dayText]; !ok {
				missingDays = append(missingDays, dayText)
			}
		}
	}
	dedup := map[string]struct{}{}
	var todo []string
	for _, d := range append(staleDays, missingDays...) {
		if _, ok := dedup[d]; ok {
			continue
		}
		dedup[d] = struct{}{}
		todo = append(todo, d)
	}
	if len(todo) == 0 {
		return 0, nil
	}
	// Step 2: aggregate each day in its own statement so an early
	// failure doesn't lose the days already committed. Each day fits in one
	// INSERT…SELECT, no application-side accumulation needed.
	written := 0
	for _, day := range todo {
		dayStart, err := time.ParseInLocation("2006-01-02", day, time.UTC)
		if err != nil {
			return written, err
		}
		if _, err := db.Exec(`
			REPLACE INTO access_daily
			    (day, host, views, unique_visitors, s2xx, s3xx, s4xx, s5xx, s_other)
			SELECT ? AS day,
			       host,
			       COUNT(*) AS views,
			       COUNT(DISTINCT client_ip) AS unique_visitors,
			       SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) AS s2xx,
			       SUM(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END) AS s3xx,
			       SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS s4xx,
			       SUM(CASE WHEN status >= 500 AND status < 600 THEN 1 ELSE 0 END) AS s5xx,
			       SUM(CASE WHEN status <  200 OR  status >= 600 THEN 1 ELSE 0 END) AS s_other
			  FROM access_events
			 WHERE ts >= ? AND ts < ?
			 GROUP BY host`,
			day, dayStart.Unix(), dayStart.Add(24*time.Hour).Unix(),
		); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
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
// ordered by view count. Limit caps the returned set. TopPath is filled via
// a second pass (one query per host) to avoid a correlated subquery that
// produces empty results in modernc.org/sqlite when no host filter is present.
func TopHostsSince(db *sql.DB, since time.Time, limit int) ([]HostStats, error) {
	sinceUnix := since.Unix()
	// Step 1: aggregate by host — no correlated subquery, no alias in GROUP BY.
	rows, err := db.Query(
		`SELECT host, COUNT(*) AS views, COUNT(DISTINCT client_ip) AS visitors, MAX(ts) AS last_ts
		   FROM access_events
		  WHERE ts >= ?
		  GROUP BY host
		  ORDER BY views DESC
		  LIMIT `+strconv.Itoa(limit),
		sinceUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostStats
	for rows.Next() {
		var s HostStats
		var lastTs int64
		if err := rows.Scan(&s.Host, &s.Views, &s.Visitors, &lastTs); err != nil {
			return nil, err
		}
		s.LastVisit = time.Unix(lastTs, 0)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Step 2: fill TopPath for each host with a targeted single-host query.
	// Runs up to `limit` small indexed lookups — fast on the (host, ts) index.
	for i := range out {
		var p string
		_ = db.QueryRow(
			`SELECT path FROM access_events
			  WHERE host = ? AND ts >= ?
			  GROUP BY path
			  ORDER BY COUNT(*) DESC
			  LIMIT 1`,
			out[i].Host, sinceUnix).Scan(&p)
		out[i].TopPath = p
	}
	return out, nil
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
	q += ` GROUP BY 1 ORDER BY 1 ASC`
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
         LIMIT `+strconv.Itoa(limit), since.Unix(), host)
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
	S2xx   int
	S3xx   int
	S4xx   int
	S5xx   int
	SOther int
}

// StatusBucketsSince returns the per-class status-code distribution for
// events with ts >= since. v2.9.207: long windows (≥ today's UTC midnight in
// the past) read past-day buckets from the access_daily rollup and only scan
// access_events for today, dropping the cost from O(window-rows) to
// O(today-rows + days-in-window).
func StatusBucketsSince(db *sql.DB, since time.Time, host string) (StatusBuckets, error) {
	todayStart := time.Now().UTC().Truncate(24 * time.Hour)
	if !since.UTC().Before(todayStart) {
		return statusBucketsFromEvents(db, since, time.Time{}, host)
	}
	rollup, err := statusBucketsFromRollup(db, since, todayStart, host)
	if err != nil {
		return StatusBuckets{}, err
	}
	today, err := statusBucketsFromEvents(db, todayStart, time.Time{}, host)
	if err != nil {
		return StatusBuckets{}, err
	}
	return StatusBuckets{
		S2xx:   rollup.S2xx + today.S2xx,
		S3xx:   rollup.S3xx + today.S3xx,
		S4xx:   rollup.S4xx + today.S4xx,
		S5xx:   rollup.S5xx + today.S5xx,
		SOther: rollup.SOther + today.SOther,
	}, nil
}

func statusBucketsFromEvents(db *sql.DB, from, to time.Time, host string) (StatusBuckets, error) {
	var b StatusBuckets
	q := `SELECT
		COALESCE(SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status >= 500 AND status < 600 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status < 200 OR  status >= 600 THEN 1 ELSE 0 END), 0)
	FROM access_events WHERE ts >= ?`
	args := []any{from.Unix()}
	if !to.IsZero() {
		q += ` AND ts < ?`
		args = append(args, to.Unix())
	}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	err := db.QueryRow(q, args...).Scan(&b.S2xx, &b.S3xx, &b.S4xx, &b.S5xx, &b.SOther)
	if err == sql.ErrNoRows {
		return b, nil
	}
	return b, err
}

func statusBucketsFromRollup(db *sql.DB, from, to time.Time, host string) (StatusBuckets, error) {
	var b StatusBuckets
	q := `SELECT COALESCE(SUM(s2xx),0), COALESCE(SUM(s3xx),0),
	             COALESCE(SUM(s4xx),0), COALESCE(SUM(s5xx),0),
	             COALESCE(SUM(s_other),0)
	      FROM access_daily WHERE day >= ? AND day < ?`
	args := []any{from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02")}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	err := db.QueryRow(q, args...).Scan(&b.S2xx, &b.S3xx, &b.S4xx, &b.S5xx, &b.SOther)
	if err == sql.ErrNoRows {
		return b, nil
	}
	return b, err
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

// ResponseTimeStats holds aggregate duration metrics for a query window.
type ResponseTimeStats struct {
	AvgMs int64
	MinMs int64
	MaxMs int64
	P95Ms int64 // approximate 95th-percentile via sorted OFFSET
}

// ResponseTimeSince returns avg/min/max/p95 response times for events in the
// window. P95 is approximated with a second OFFSET query — close enough for a
// dashboard panel without a full window-function pass.
func ResponseTimeSince(db *sql.DB, since time.Time, host string) (ResponseTimeStats, error) {
	var s ResponseTimeStats
	args := []any{since.Unix()}
	hostFilter := ""
	if host != "" {
		hostFilter = " AND host = ?"
		args = append(args, host)
	}
	err := db.QueryRow(
		`SELECT COALESCE(AVG(duration_ms),0), COALESCE(MIN(duration_ms),0), COALESCE(MAX(duration_ms),0)
		   FROM access_events WHERE ts >= ?`+hostFilter, args...).Scan(&s.AvgMs, &s.MinMs, &s.MaxMs)
	if err != nil && err != sql.ErrNoRows {
		return s, err
	}
	// P95 approximation: the value at the 95th-percentile index.
	var count int64
	_ = db.QueryRow(`SELECT COUNT(*) FROM access_events WHERE ts >= ?`+hostFilter, args...).Scan(&count)
	if count > 0 {
		offset := count * 95 / 100
		p95args := make([]any, len(args)*2)
		copy(p95args, args)
		copy(p95args[len(args):], args)
		_ = db.QueryRow(
			`SELECT COALESCE(duration_ms,0) FROM access_events WHERE ts >= ?`+hostFilter+
				` ORDER BY duration_ms LIMIT 1 OFFSET `+strconv.FormatInt(offset, 10), args...).Scan(&s.P95Ms)
	}
	return s, nil
}

// BandwidthSince returns the total bytes_out for events newer than since,
// optionally scoped to a single host.
func BandwidthSince(db *sql.DB, since time.Time, host string) (int64, error) {
	var total int64
	q := `SELECT COALESCE(SUM(bytes_out),0) FROM access_events WHERE ts >= ?`
	args := []any{since.Unix()}
	if hostClause, hostArgs := hostMatchClause(host); hostClause != "" {
		q += hostClause
		args = append(args, hostArgs...)
	}
	err := db.QueryRow(q, args...).Scan(&total)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return total, err
}

// BandwidthBucket is one time-bucket of bytes transferred.
type BandwidthBucket struct {
	Hour     time.Time
	BytesOut int64
}

// BandwidthBuckets returns equally-sized time buckets of bytes_out between
// `from` and `to`, each covering `bucketSeconds`. Buckets with zero bytes are
// NOT returned — caller fills gaps. Same contract as AccessBuckets.
func BandwidthBuckets(db *sql.DB, from, to time.Time, bucketSeconds int64, host string) ([]BandwidthBucket, error) {
	if bucketSeconds <= 0 {
		bucketSeconds = 3600
	}
	q := `
        SELECT (ts / ?) * ? AS bucket,
               COALESCE(SUM(bytes_out), 0) AS total
          FROM access_events
         WHERE ts >= ? AND ts < ?`
	args := []any{bucketSeconds, bucketSeconds, from.Unix(), to.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	q += ` GROUP BY 1 ORDER BY 1 ASC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BandwidthBucket
	for rows.Next() {
		var b BandwidthBucket
		var bucket int64
		if err := rows.Scan(&bucket, &b.BytesOut); err != nil {
			return nil, err
		}
		b.Hour = time.Unix(bucket, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}

// RecentAccessEvents returns the most recent `limit` access events, ordered
// newest-first. Used by the live traffic feed page and its SSE stream.
func RecentAccessEvents(db *sql.DB, since int64, limit int) ([]AccessEvent, error) {
	q := `SELECT id, ts, host, path, method, status, client_ip, user_agent, duration_ms, bytes_out
	        FROM access_events
	       WHERE id > ?
	       ORDER BY id DESC
	       LIMIT ` + strconv.Itoa(limit)
	rows, err := db.Query(q, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessEvent
	for rows.Next() {
		var e AccessEvent
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Host, &e.Path, &e.Method, &e.Status, &e.ClientIP, &e.UserAgent, &e.DurationMs, &e.BytesOut); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExportAccessEvents returns up to `limit` access events newer than `since`,
// optionally scoped to one host. Used by the CSV export endpoint. Ordered
// oldest-first so the CSV reads chronologically.
func ExportAccessEvents(db *sql.DB, since time.Time, host string, limit int) ([]AccessEvent, error) {
	q := `SELECT id, ts, host, path, method, status, client_ip, user_agent, duration_ms, bytes_out
	        FROM access_events
	       WHERE ts >= ?`
	args := []any{since.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	q += ` ORDER BY ts ASC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessEvent
	for rows.Next() {
		var e AccessEvent
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Host, &e.Path, &e.Method, &e.Status,
			&e.ClientIP, &e.UserAgent, &e.DurationMs, &e.BytesOut); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ErrorPathStats is one row in the top-errors leaderboard.
type ErrorPathStats struct {
	Path   string
	Method string
	Count  int
}

// TopErrorPaths returns the paths+methods with the most 4xx/5xx responses
// in the window, ordered by error count descending.
func TopErrorPaths(db *sql.DB, since time.Time, host string, limit int) ([]ErrorPathStats, error) {
	q := `SELECT path, method, COUNT(*) AS cnt
		    FROM access_events
		   WHERE ts >= ? AND status >= 400`
	args := []any{since.Unix()}
	if host != "" {
		q += ` AND host = ?`
		args = append(args, host)
	}
	q += ` GROUP BY path, method ORDER BY cnt DESC LIMIT ` + strconv.Itoa(limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ErrorPathStats
	for rows.Next() {
		var e ErrorPathStats
		if err := rows.Scan(&e.Path, &e.Method, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UABucket is one browser/bot category with its request count.
type UABucket struct {
	Browser string
	Count   int
}

// parseUA classifies a user-agent string into a short browser/bot label.
// Order matters: check more-specific strings before less-specific ones.
func parseUA(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case u == "" || u == "-":
		return "Unknown"
	case strings.Contains(u, "googlebot"):
		return "Googlebot"
	case strings.Contains(u, "bingbot"):
		return "Bingbot"
	case strings.Contains(u, "bot") || strings.Contains(u, "crawler") || strings.Contains(u, "spider"):
		return "Bot/Crawler"
	case strings.Contains(u, "curl") || strings.Contains(u, "wget") || strings.Contains(u, "httpie"):
		return "CLI tool"
	case strings.Contains(u, "edg/") || strings.Contains(u, "edghtml"):
		return "Edge"
	case strings.Contains(u, "opr/") || strings.Contains(u, "opera"):
		return "Opera"
	case strings.Contains(u, "chrome") || strings.Contains(u, "chromium"):
		return "Chrome"
	case strings.Contains(u, "firefox"):
		return "Firefox"
	case strings.Contains(u, "safari"):
		return "Safari"
	case strings.Contains(u, "msie") || strings.Contains(u, "trident"):
		return "IE"
	case strings.Contains(u, "python") || strings.Contains(u, "go-http") || strings.Contains(u, "java") || strings.Contains(u, "php"):
		return "HTTP library"
	default:
		return "Other"
	}
}

// DomainRequestsTodayForDomains returns a map of lowercase hostname → request
// count for events since midnight UTC today, restricted to domains displayed
// by the caller.
//
// The restriction is important on installations with a large analytics
// history. An unscoped GROUP BY can make SQLite scan the complete
// (host, ts) index—even when only today's rows are requested. Supplying the
// visible domains turns the same index into a set of small host/time range
// scans and avoids making /proxy-hosts proportional to total database size.
func DomainRequestsTodayForDomains(db *sql.DB, domains []string) (map[string]int, error) {
	todayStart := time.Now().UTC().Truncate(24 * time.Hour).Unix()
	out := map[string]int{}

	unique := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		unique = append(unique, domain)
	}
	if len(unique) == 0 {
		return out, nil
	}

	// Stay below SQLite's default bind-variable limit and keep MariaDB
	// packets modest on unusually large installations.
	const chunkSize = 500
	for start := 0; start < len(unique); start += chunkSize {
		end := start + chunkSize
		if end > len(unique) {
			end = len(unique)
		}
		chunk := unique[start:end]
		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		for i, domain := range chunk {
			placeholders[i] = "?"
			args = append(args, domain)
		}
		args = append(args, todayStart)

		rows, err := db.Query(
			`SELECT host, COUNT(*) FROM access_events
			 WHERE host IN (`+strings.Join(placeholders, ",")+`) AND ts >= ?
			 GROUP BY host`,
			args...,
		)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var host string
			var count int
			if err := rows.Scan(&host, &count); err != nil {
				rows.Close()
				return nil, err
			}
			out[strings.ToLower(host)] += count
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

// TopBrowsers returns browser categories sorted by count descending for the
// given host and time window. Uses SQLite to fetch user_agent values grouped
// by a bucketed key so we don't pull millions of strings into Go.
// Since SQLite doesn't have a Go-callable UDF from SQL, we fetch the top
// user_agent strings with their counts and classify them in Go.
func TopBrowsers(db *sql.DB, since time.Time, host string, limit int) ([]UABucket, error) {
	// Fetch top N distinct user_agent values by count — 200 is enough to cover
	// all meaningful browsers while keeping the result set small.
	rows, err := db.Query(`
        SELECT user_agent, COUNT(*) AS cnt
        FROM access_events
        WHERE ts >= ? AND host = ?
        GROUP BY user_agent
        ORDER BY cnt DESC
        LIMIT 200`, since.Unix(), host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	totals := map[string]int{}
	for rows.Next() {
		var ua string
		var cnt int
		if err := rows.Scan(&ua, &cnt); err != nil {
			continue
		}
		totals[parseUA(ua)] += cnt
	}

	// Sort by count descending.
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range totals {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })

	out := make([]UABucket, 0, limit)
	for i, kv := range sorted {
		if i >= limit {
			break
		}
		out = append(out, UABucket{Browser: kv.k, Count: kv.v})
	}
	return out, nil
}
