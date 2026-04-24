// Package analytics implements the visitor-analytics ingest path: a TCP
// listener that accepts newline-delimited JSON (NDJSON) access-log events
// from one or more Caddy servers configured with the `net` log writer.
// Each line is a single JSON object matching Caddy's http.log.access schema;
// we extract the subset we care about (ts, host, path, method, status, etc.)
// and persist it via models.InsertAccessEvent.
//
// Wire shape — Caddy's `net` writer opens a single long-lived TCP connection
// to us and writes one JSON doc per line. On disconnect (caddy restart, TCP
// timeout, etc.) it reconnects automatically. We accept any number of such
// connections and just keep reading until each one ends. There is no reply
// traffic — the protocol is write-only from Caddy's side.
//
// Security model — the listener binds locally (or on a private docker
// network) and does NOT authenticate senders. Anyone who can reach the port
// can inject fake events. The default address is :9019 bound in a container
// that doesn't publish the port to the host, so only sidecar Caddy servers
// on the same docker network can reach it. If you're running Caddy on the
// same host without Docker, bind to 127.0.0.1:9019 via CADDYUI_INGEST_LISTEN.
package analytics

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// maxLineBytes caps the JSON doc size we'll accept on a single line. Caddy
// can log big headers (cookies, auth tokens) so we leave headroom well past
// the typical ~2KB line. Lines over this are skipped with a warning.
const maxLineBytes = 1 << 16 // 64 KiB

// Ingest is the NDJSON TCP listener. Create one with New, call Start(ctx) to
// begin accepting connections, and Stop() for a clean shutdown. Safe for
// concurrent use from any goroutine after Start has returned.
type Ingest struct {
	// DB is the sqlite handle events get inserted into. Required.
	DB *sql.DB

	// Addr is the TCP bind address, like ":9019" or "127.0.0.1:9019". If
	// empty, Start returns an error — we refuse to pick a default port
	// silently because binding 0.0.0.0 on a host machine would expose the
	// ingest to the LAN.
	Addr string

	// ExcludeFn, when set, is called for every incoming event; returning
	// true drops the event before the DB insert. Used for admin-supplied
	// IP-range exclusion (internal office IPs, uptime monitors, etc.) so
	// they don't skew the dashboards. Called on the ingest goroutine, so
	// keep it fast — no network I/O, no DB work. Consider using
	// SetExcludeIPs for the common case rather than setting this directly.
	ExcludeFn func(clientIP, host, path, userAgent string) bool

	// excludeMu guards the compiled CIDR slice below. Swapped out in whole
	// by SetExcludeIPs so the reader path (ExcludeFn) never blocks on a
	// lock — it takes a snapshot of the slice and evaluates against it.
	excludeMu     sync.RWMutex
	excludeNets   []*net.IPNet
	excludePlains []net.IP // plain IPs (no /mask)


	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
	cancel   context.CancelFunc
	running  bool

	// Stats — atomic so they can be read from any goroutine without
	// locking. Surfaced on the /analytics page's "health" card so the
	// admin can confirm the pipe is flowing.
	stats Stats
}

// Stats is a snapshot of ingest counters since process start. Populated by
// the ingest goroutines via atomic stores; read atomically by callers
// (typically a handler rendering the admin page). Values never reset and
// never decrement — they're process-lifetime cumulative.
type Stats struct {
	Connections atomic.Uint64 // count of accepted TCP connections
	Events      atomic.Uint64 // count of events persisted to access_events
	Excluded    atomic.Uint64 // count dropped by ExcludeFn before DB insert
	Errors      atomic.Uint64 // count of parse/DB errors (line-level)
	LastEventAt atomic.Int64  // unix seconds of the most recent persisted event
}

// Snapshot returns the current counter values without exposing the atomic
// wrappers. Safe to call from any goroutine.
type StatsSnapshot struct {
	Connections uint64
	Events      uint64
	Excluded    uint64
	Errors      uint64
	LastEventAt time.Time
}

func (s *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		Connections: s.Connections.Load(),
		Events:      s.Events.Load(),
		Excluded:    s.Excluded.Load(),
		Errors:      s.Errors.Load(),
		LastEventAt: time.Unix(s.LastEventAt.Load(), 0),
	}
}

// Stats returns a snapshot of the ingest counters.
func (i *Ingest) Stats() StatsSnapshot {
	return i.stats.Snapshot()
}

// SetExcludeIPs replaces the currently-configured IP exclusion list. Each
// entry is either a plain IP ("1.2.3.4") or a CIDR block ("10.0.0.0/8" /
// "fd00::/8"). Unparseable entries are silently dropped — the admin gets
// feedback via the settings form validation, not a crash here. After this
// returns, the next incoming event uses the new list; in-flight events
// already past the check aren't affected. Safe to call from any goroutine.
//
// Clears any ExcludeFn the caller set manually — the two are mutually
// exclusive, and in practice the settings-handler path always goes through
// SetExcludeIPs. If you need per-host or per-UA filtering, set ExcludeFn
// directly and don't call this.
func (i *Ingest) SetExcludeIPs(entries []string) {
	var nets []*net.IPNet
	var plains []net.IP
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err == nil && n != nil {
				nets = append(nets, n)
			}
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			plains = append(plains, ip)
		}
	}
	i.excludeMu.Lock()
	i.excludeNets = nets
	i.excludePlains = plains
	i.excludeMu.Unlock()
	// Install the fn if no custom one has been set. Checking for nil is
	// cheap; the alternative — installing unconditionally — would clobber
	// custom filters that test authors inject in unit tests.
	if i.ExcludeFn == nil {
		i.ExcludeFn = i.excludeByIP
	}
}

// excludeByIP is the default ExcludeFn installed by SetExcludeIPs. It only
// inspects the client IP and drops events whose IP matches any plain-IP or
// CIDR entry from the admin's exclude list. Host / path / user-agent are
// accepted as parameters for interface compatibility with custom filters
// but ignored here.
func (i *Ingest) excludeByIP(clientIP, _, _, _ string) bool {
	if clientIP == "" {
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	i.excludeMu.RLock()
	nets := i.excludeNets
	plains := i.excludePlains
	i.excludeMu.RUnlock()
	for _, p := range plains {
		if p.Equal(ip) {
			return true
		}
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Start begins accepting connections. Returns after the listener is bound
// (so port-in-use errors surface synchronously) but before any event has
// been handled. Safe to call only once — re-Start on a previously-Started
// Ingest returns an error.
func (i *Ingest) Start(ctx context.Context) error {
	if i.DB == nil {
		return errors.New("analytics.Ingest: DB is nil")
	}
	if i.Addr == "" {
		return errors.New("analytics.Ingest: Addr is empty")
	}
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return errors.New("analytics.Ingest: already running")
	}
	ln, err := net.Listen("tcp", i.Addr)
	if err != nil {
		i.mu.Unlock()
		return err
	}
	i.listener = ln
	i.running = true
	subCtx, cancel := context.WithCancel(ctx)
	i.cancel = cancel
	i.mu.Unlock()

	log.Printf("analytics: ingest listening on %s", i.Addr)

	i.wg.Add(1)
	go i.acceptLoop(subCtx)
	return nil
}

// Stop closes the listener and waits for in-flight connections to drain.
// Safe to call even on a never-Started Ingest (no-op). Blocks up to the
// context deadline of the shutdown — callers typically pass a 5s timeout.
func (i *Ingest) Stop() {
	i.mu.Lock()
	running := i.running
	ln := i.listener
	cancel := i.cancel
	i.running = false
	i.mu.Unlock()
	if !running {
		return
	}
	if cancel != nil {
		cancel()
	}
	if ln != nil {
		_ = ln.Close() // unblocks Accept in acceptLoop
	}
	i.wg.Wait()
	log.Printf("analytics: ingest stopped")
}

// acceptLoop is the goroutine kicked off by Start. It accepts connections
// and spawns a per-connection reader goroutine for each. Exits when the
// listener is closed (either by Stop or a fatal accept error).
func (i *Ingest) acceptLoop(ctx context.Context) {
	defer i.wg.Done()
	for {
		conn, err := i.listener.Accept()
		if err != nil {
			// After Stop closes the listener, Accept returns
			// net.ErrClosed — that's the normal shutdown path, not an
			// error. Anything else is logged as a real failure but we
			// still exit because the listener is unusable.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("analytics: accept error: %v", err)
			return
		}
		i.stats.Connections.Add(1)
		i.wg.Add(1)
		go i.handleConn(ctx, conn)
	}
}

// handleConn reads NDJSON lines from one Caddy connection until EOF or
// Stop. Each valid line becomes one row in access_events. Bad lines are
// counted + logged (rate-limited by the scanner skipping them) but don't
// terminate the connection — Caddy will keep writing, and one malformed
// log entry shouldn't sever the whole pipe.
func (i *Ingest) handleConn(ctx context.Context, conn net.Conn) {
	defer i.wg.Done()
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("analytics: ingest connection from %s", remote)

	// Close the conn when the context cancels so the scanner unblocks
	// even if Caddy is sitting idle. Otherwise Stop would hang until
	// the next log line arrived.
	doneReading := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-doneReading:
		}
	}()
	defer close(doneReading)

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		ev, ok := parseLine(line)
		if !ok {
			i.stats.Errors.Add(1)
			continue
		}
		if i.ExcludeFn != nil && i.ExcludeFn(ev.ClientIP, ev.Host, ev.Path, ev.UserAgent) {
			i.stats.Excluded.Add(1)
			continue
		}
		if err := models.InsertAccessEvent(i.DB, ev); err != nil {
			i.stats.Errors.Add(1)
			// Log but don't tear the connection down — a transient DB
			// busy (e.g. during backup) would otherwise break the stream.
			log.Printf("analytics: insert error: %v", err)
			continue
		}
		i.stats.Events.Add(1)
		i.stats.LastEventAt.Store(ev.TS.Unix())
	}
	if err := sc.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		// Scanner errors on connection reset are expected on Caddy restart;
		// only log when it's something more interesting.
		if !isClosedConnErr(err) {
			log.Printf("analytics: read error from %s: %v", remote, err)
		}
	}
	log.Printf("analytics: ingest connection from %s closed", remote)
}

// isClosedConnErr detects the benign "use of closed network connection" /
// "connection reset by peer" errors we get during shutdown or when Caddy
// restarts. Strings-matched because neither is typed in stdlib net.
func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}

// caddyAccessLog mirrors the subset of Caddy's http.log.access JSON we need.
// Caddy's actual schema has many more fields (tls details, resp_headers,
// etc.) — we ignore them with json's default "skip unknown fields" behavior.
// Ref: https://caddyserver.com/docs/logging#access-logs
type caddyAccessLog struct {
	// TS is a float seconds-since-epoch (e.g. 1702839400.1234). Caddy
	// emits this as a number, not a string, and json.Number lets us
	// preserve precision when converting to time.Time.
	TS      json.Number            `json:"ts"`
	Request caddyAccessLogRequest  `json:"request"`
	Status  int                    `json:"status"`
	Size    int64                  `json:"size"`
	// Duration is in seconds (float). We multiply by 1000 for ms.
	Duration json.Number `json:"duration"`
}

type caddyAccessLogRequest struct {
	RemoteIP string              `json:"remote_ip"`
	ClientIP string              `json:"client_ip"`
	Method   string              `json:"method"`
	Host     string              `json:"host"`
	URI      string              `json:"uri"`
	Headers  map[string][]string `json:"headers"`
}

// parseLine extracts an AccessEvent from one Caddy log line. Returns
// (event, true) on success, (zero, false) if the line isn't an access
// log entry or is missing required fields. "Required" is deliberately
// generous — a row with only a timestamp and status is still useful.
func parseLine(line []byte) (models.AccessEvent, bool) {
	// Filter out non-access-log JSON quickly. Caddy writes other logger
	// categories (http.log.error, admin, etc.) to the same writer when
	// multiple loggers share an output — we just drop them.
	if !strings.Contains(string(line), `"http.log.access`) && !strings.Contains(string(line), `"request":`) {
		return models.AccessEvent{}, false
	}

	var raw caddyAccessLog
	if err := json.Unmarshal(line, &raw); err != nil {
		return models.AccessEvent{}, false
	}

	// TS: Caddy uses unix seconds with fractional precision.
	var tsSec float64
	if s := raw.TS.String(); s != "" {
		if f, err := raw.TS.Float64(); err == nil {
			tsSec = f
		}
		_ = s
	}
	if tsSec == 0 {
		tsSec = float64(time.Now().Unix())
	}
	ts := time.Unix(int64(tsSec), int64((tsSec-float64(int64(tsSec)))*1e9))

	// Prefer client_ip (post-trusted-proxy resolution) over remote_ip
	// (TCP peer). Caddy only emits client_ip when `trusted_proxies` is
	// configured in the server block — fall back to remote_ip otherwise.
	clientIP := strings.TrimSpace(raw.Request.ClientIP)
	if clientIP == "" {
		clientIP = strings.TrimSpace(raw.Request.RemoteIP)
	}

	// User-Agent lives under headers; Caddy normalises header names to
	// their canonical form (User-Agent, not user-agent). Be defensive
	// anyway since custom log config might canonicalise differently.
	ua := ""
	for k, vs := range raw.Request.Headers {
		if strings.EqualFold(k, "User-Agent") && len(vs) > 0 {
			ua = vs[0]
			break
		}
	}

	// Strip query string — for the dashboard we group by path, and we
	// don't want per-query-string rows blowing up the top-paths table.
	// Admins who want query stats can add a future feature; for now
	// GDPR-leaning defaults say strip it.
	path := raw.Request.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	// Cap length to stop abusive 64KB URLs from bloating the DB.
	if len(path) > 2048 {
		path = path[:2048]
	}
	if len(ua) > 512 {
		ua = ua[:512]
	}
	host := strings.TrimSpace(raw.Request.Host)
	// Host can include :port for non-standard listener addresses; strip
	// for grouping sanity.
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}

	// Duration: seconds → milliseconds.
	durMs := int64(0)
	if f, err := raw.Duration.Float64(); err == nil {
		durMs = int64(f * 1000)
	}

	return models.AccessEvent{
		TS:         ts,
		Host:       host,
		Path:       path,
		Method:     raw.Request.Method,
		Status:     raw.Status,
		ClientIP:   clientIP,
		UserAgent:  ua,
		DurationMs: durMs,
		BytesOut:   raw.Size,
	}, true
}
