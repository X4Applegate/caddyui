// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"image/png"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/analytics"
	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/caddylogs"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	otplib "github.com/pquerna/otp"
	totplib "github.com/pquerna/otp/totp"
)

type Server struct {
	DB            *sql.DB
	Caddy         *caddy.Client
	Templates     map[string]*template.Template
	Static        fs.FS
	CaddyfilePath string
	Version       string
	// DBPath is the filesystem path to the SQLite DB. Stored so the backup
	// handler can write its VACUUM INTO temp file next to the real DB (same
	// volume, guaranteed writable by our UID) — `os.TempDir()` → /tmp doesn't
	// exist in the scratch final image, and creating it at runtime as a
	// non-root UID isn't allowed. v2.7.5.
	DBPath      string
	pendingTOTP sync.Map // token → userID (int64), auto-deleted after 5 min

	// CSRF HMAC key, loaded from (or generated into) the settings table on
	// first use. Per-Server rather than package-level so two Servers in the
	// same test binary don't share one another's key. v2.29.0.
	csrfSecretOnce  sync.Once
	csrfSecretCache []byte

	// version-check cache (Docker Hub, 1h TTL)
	versionMu        sync.Mutex
	latestVersion    string
	versionCheckedAt time.Time

	// health-poller hysteresis: count consecutive failed pings per server so
	// a single WG/network blip doesn't instantly flap a server to offline.
	// Only flip to offline after healthFailThreshold consecutive failures.
	healthMu       sync.Mutex
	healthFailures map[int64]int

	// app-response health cache — end-to-end HTTPS GET / result per proxy host,
	// refreshed by StartAppHealthPoller. Keyed by ProxyHost.ID. Independent of
	// the TCP/port health (which Caddy's admin API reports): this probes the
	// public domain through Caddy, so it catches cases where the port is open
	// but the app is wedged (e.g. DB unreachable, slow startup).
	appHealthMu sync.RWMutex
	appHealth   map[int64]appHealthEntry
	// v2.38.0: post-apply expectation results, per process (see expectations.go).
	expectationMu      sync.RWMutex
	expectationResults map[int64][]expectationResult
	expectationRuns    map[int64]expectationRun

	// Serializes source-to-target fleet copies inside this process. The
	// deployment mapping table supplies durable idempotency; this mutex closes
	// the check-then-create race between concurrent UI submissions.
	fleetDeployMu sync.Mutex

	// v2.7.0: handle to the analytics ingest listener. Wired by main.go
	// via SetAnalyticsIngest after Server construction (rather than as a
	// New() arg) so the wiring order stays readable — the ingest owns a
	// DB ref that has to exist before we hand it over.
	analyticsIngest *analytics.Ingest

	// Runtime Caddy logs share the analytics NDJSON socket but stay in a
	// bounded in-memory hub. Only the latest certificate lifecycle projection
	// is persisted. Temporary full-log captures are guarded by expiry timers.
	caddyLogHub        *caddylogs.Hub
	runtimeLogMu       sync.Mutex
	runtimeLogTimers   map[int64]*time.Timer
	certificateProbeFn func(models.CaddyServer, models.Certificate) managedCertificateServerStatus
	// v2.39.0: live TLS probes of custom (PEM / file-path) certificates, see
	// certificate_probe.go. certProbeTargetFn lets tests point the dial at a
	// local listener instead of <admin host>:443.
	certProbeRunMu    sync.Mutex
	certProbeTargetFn func(serverID int64, probeName string) string
	// v2.42.0: serializes certificate export passes (certificate_export.go).
	certExportRunMu sync.Mutex
	// v2.43.0: analytics retention — one prune and one VACUUM at a time.
	accessPruneMu sync.Mutex
	vacuumMu      sync.Mutex
}

type apiTokenScopeContextKey struct{}

// SetAnalyticsIngest plumbs the analytics ingest listener into the server
// so handlers can surface its stats on /analytics and /settings. Called
// once at startup from main.go after the ingest listener has bound.
// Passing nil is valid and disables the stats card — happens when the
// CADDYUI_INGEST_LISTEN env var is blank or the bind failed at startup.
func (s *Server) SetAnalyticsIngest(ing *analytics.Ingest) {
	s.analyticsIngest = ing
}

func (s *Server) SetCaddyLogHub(hub *caddylogs.Hub) {
	s.caddyLogHub = hub
	if hub != nil {
		// v2.42.0: an issuance/renewal reported by a node triggers the
		// export of every exporting certificate that covers the name.
		hub.OnCertificateActive = s.handleCertificateActive
	}
}

func New(db *sql.DB, caddyClient *caddy.Client, templates fs.FS, static fs.FS, caddyfilePath string, version string, dbPath string) (*Server, error) {
	tpl, err := parseTemplates(templates)
	if err != nil {
		return nil, err
	}
	// Resolve the active timezone once at startup so the very first render
	// uses the admin's picked zone (DB) rather than whatever time.Local
	// happens to be. Priority: DB value → TZ env var → UTC. See timezone.go.
	loc := loadActiveLocation(db)
	log.Printf("timezone: rendering timestamps in %s", loc)
	s := &Server{
		DB:               db,
		Caddy:            caddyClient,
		Templates:        tpl,
		Static:           static,
		CaddyfilePath:    caddyfilePath,
		Version:          version,
		DBPath:           dbPath,
		healthFailures:   map[int64]int{},
		appHealth:        map[int64]appHealthEntry{},
		runtimeLogTimers: map[int64]*time.Timer{},
	}
	go s.runHealthChecker()
	go s.runAutoSyncLoop()
	go s.runMaintenanceWindowLoop()
	go s.runActivityLogCleanup()
	go s.runAccessDailyAggregator()
	// v2.43.0: this loop existed since v2.7.0 but was never started, so
	// access_events grew without bound (analytics_retention.go).
	go s.pruneAccessLoop()
	return s, nil
}

// runAccessDailyAggregator backfills the access_daily rollup table once at
// startup (so a freshly-upgraded install picks up historical days) and then
// every hour to catch the previous day shortly after UTC midnight rolls over.
// All access_events older than today (UTC) are summarised into per-(day, host)
// rows that AccessTotalsSince consults for long windows. v2.9.206.
func (s *Server) runAccessDailyAggregator() {
	if n, err := models.AggregateAccessDaily(s.DB); err != nil {
		log.Printf("access_daily: initial backfill failed: %v", err)
	} else if n > 0 {
		log.Printf("access_daily: initial backfill aggregated %d day(s)", n)
	}
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for range t.C {
		if n, err := models.AggregateAccessDaily(s.DB); err != nil {
			log.Printf("access_daily: hourly backfill failed: %v", err)
		} else if n > 0 {
			log.Printf("access_daily: aggregated %d new day(s)", n)
		}
	}
}

// healthFailThreshold is the number of consecutive failed pings required
// before the health poller flips a server to "offline". Tunable here so WG
// blips don't cause the dashboard to flap.
const healthFailThreshold = 3

func parseTemplates(tplFS fs.FS) (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"join":  func(sep string, parts []string) string { return strings.Join(parts, sep) },
		"upper": strings.ToUpper,
		// dict builds a map from alternating key/value args so templates can pass
		// structured context to sub-templates (e.g. layout's navItem definition).
		"dict": func(kv ...any) (map[string]any, error) {
			if len(kv)%2 != 0 {
				return nil, fmt.Errorf("dict requires an even number of arguments")
			}
			m := make(map[string]any, len(kv)/2)
			for i := 0; i < len(kv); i += 2 {
				k, ok := kv[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict key at %d must be string", i)
				}
				m[k] = kv[i+1]
			}
			return m, nil
		},
		"splitDomains": func(s string) []string {
			parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' })
			out := make([]string, 0, len(parts))
			for _, d := range parts {
				d = strings.TrimSpace(d)
				if d != "" {
					out = append(out, d)
				}
			}
			return out
		},
		// rawRouteSourceHosts extracts the match.host[] entries from a raw
		// route's JSON blob so the /raw-routes table and the dashboard's
		// "Recent advanced routes" block can render hostname pills the same
		// way proxy hosts do. v2.7.9. Returns nil for path-only / port-only
		// routes (no host matcher) — templates fall back to the route label
		// in that case so the Source column never renders empty.
		"rawRouteSourceHosts": func(jsonData string) []string {
			return rawRouteHosts(models.RawRoute{JSONData: jsonData})
		},
		"prettyJSON": func(s string) string {
			var v any
			if err := json.Unmarshal([]byte(s), &v); err != nil {
				return s
			}
			out, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return s
			}
			return string(out)
		},
		// httpCodeName returns the standard reason phrase for common redirect
		// status codes so templates can surface human-readable descriptions
		// (e.g. "301 Moved Permanently") on hover/tooltip.
		"httpCodeName": func(code int) string {
			switch code {
			case 301:
				return "Moved Permanently"
			case 302:
				return "Found (Temporary)"
			case 303:
				return "See Other"
			case 307:
				return "Temporary Redirect"
			case 308:
				return "Permanent Redirect"
			}
			return ""
		},
		// Timezone-aware time formatters. Every visible timestamp pulled from
		// the DB should flow through one of these so the admin's picked zone
		// (Settings → Timezone) actually takes effect. activeLocation()
		// resolves DB → TZ env → UTC; see timezone.go.
		//
		// Templates pass a time.Time and get back a formatted string:
		//   {{ fmtDate .CreatedAt }}      → "2026-04-22"
		//   {{ fmtDateTime .CreatedAt }}  → "2026-04-22 14:30"
		//   {{ fmtTime .CreatedAt }}      → "14:30:45"
		//   {{ tzName }}                  → "America/New_York"
		//
		// Zero-value times render as an empty string so we don't surface
		// "0001-01-01" when a nullable DB column is NULL.
		"fmtDate": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.In(activeLocation()).Format("2006-01-02")
		},
		"fmtDateTime": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.In(activeLocation()).Format("2006-01-02 15:04")
		},
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.In(activeLocation()).Format("15:04:05")
		},
		// fmtIn is the escape-hatch: pass any Go time layout string and it
		// renders in the active zone. Used by templates that need a specific
		// visible format (e.g. "Jan 2, 2006 3:04 PM") that fmtDate/fmtDateTime
		// don't cover. Keeps the existing look of the page while switching
		// the underlying zone.
		"fmtIn": func(t time.Time, layout string) string {
			if t.IsZero() {
				return ""
			}
			return t.In(activeLocation()).Format(layout)
		},
		"tzName": func() string { return activeLocation().String() },
		// v2.11.12: hasPrefix / hasSuffix exposed for template-side action
		// string classification on the dashboard "Recently edited" widget.
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		// truncate returns the first n bytes of s, or s itself if shorter.
		// Used in sessions.html to display a shortened token prefix.
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n]
		},
		// httpCodeDesc returns a plain-English one-liner explaining what a
		// redirect status code means in practice. Used in tooltips.
		"httpCodeDesc": func(code int) string {
			switch code {
			case 301:
				return "301 Moved Permanently — cached forever by browsers & search engines. Best for SEO when a URL has permanently changed. May convert POST to GET."
			case 302:
				return "302 Found (Temporary) — not cached. Use when the redirect is temporary or might change. May convert POST to GET."
			case 303:
				return "303 See Other — always converts the request to GET. Used after form submissions (POST → GET)."
			case 307:
				return "307 Temporary Redirect — like 302 but preserves the HTTP method (POST stays POST). Safer for APIs."
			case 308:
				return "308 Permanent Redirect — like 301 but preserves the HTTP method. Modern replacement for 301."
			}
			return fmt.Sprintf("HTTP %d", code)
		},
		// Integer math helpers for SVG bar-chart rendering in the analytics
		// page. html/template doesn't support arithmetic on ints, so we ship
		// these three minimal operations rather than pulling in a full
		// expression language. Kept deliberately narrow — bar height = views
		// × maxPx / maxViews, bar y = chartHeight - barHeight, next bucket
		// = index + 1. Any more and we should wire up sprig.
		"mulDivInt": func(a, b, c int) int {
			if c == 0 {
				return 0
			}
			return (a * b) / c
		},
		"subInt": func(a, b int) int { return a - b },
		"addInt": func(a, b int) int { return a + b },
		// mulDivInt64 is the int64 analogue of mulDivInt for use with
		// BandwidthBucket.BytesOut (int64) SVG bar-height calculations.
		"mulDivInt64": func(a, b, c int64) int64 {
			if c == 0 {
				return 0
			}
			return (a * b) / c
		},
		"subInt64": func(a, b int64) int64 { return a - b },
		// fmtBytes renders a byte count as a human-readable size string.
		// Used in analytics cards to show bandwidth totals without overwhelming
		// the reader with raw byte counts (e.g. "1.4 GB" instead of "1503238553").
		"fmtBytes": func(b int64) string {
			switch {
			case b >= 1<<30:
				return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
			case b >= 1<<20:
				return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
			case b >= 1<<10:
				return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
			default:
				return fmt.Sprintf("%d B", b)
			}
		},
		// fmtRel renders a time as a short human-readable interval from now
		// ("3m", "2h", "4d"). Used in analytics tables where an absolute
		// timestamp would eat column width and the admin only cares how
		// stale the data is. Zero time → "never" so callers don't need to
		// bracket every use with {{if ...}}. Future times (clock skew)
		// render as "in <interval>" so we don't silently swallow bad data.
		"fmtRel": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			d := time.Since(t)
			prefix := ""
			if d < 0 {
				prefix = "in "
				d = -d
			} else {
				// Past — add "ago" suffix after formatting.
			}
			var body string
			switch {
			case d < time.Minute:
				body = fmt.Sprintf("%ds", int(d.Seconds()))
			case d < time.Hour:
				body = fmt.Sprintf("%dm", int(d.Minutes()))
			case d < 24*time.Hour:
				body = fmt.Sprintf("%dh", int(d.Hours()))
			case d < 30*24*time.Hour:
				body = fmt.Sprintf("%dd", int(d.Hours())/24)
			default:
				body = t.In(activeLocation()).Format("2006-01-02")
				return prefix + body
			}
			if prefix != "" {
				return prefix + body
			}
			return body + " ago"
		},
		// colorDotClass returns Tailwind bg-* classes for a host color label.
		// Returns an empty string when the color is blank so the dot can be
		// hidden entirely ({{ if .Host.Color }} guard in templates).
		"colorDotClass": func(c string) string {
			switch c {
			case "red":
				return "bg-red-400"
			case "orange":
				return "bg-orange-400"
			case "yellow":
				return "bg-yellow-400"
			case "green":
				return "bg-green-400"
			case "teal":
				return "bg-teal-400"
			case "blue":
				return "bg-blue-400"
			case "purple":
				return "bg-purple-400"
			case "pink":
				return "bg-pink-400"
			case "gray":
				return "bg-gray-400"
			default:
				return ""
			}
		},
	}
	entries, err := fs.ReadDir(tplFS, ".")
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "layout.html" || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		t, err := template.New("").Funcs(funcs).ParseFS(tplFS, "layout.html", e.Name())
		if err != nil {
			return nil, err
		}
		pages[e.Name()] = t
	}
	return pages, nil
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(s.adminIPGate)
	r.Use(s.securityHeaders)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	staticSub, err := fs.Sub(s.Static, ".")
	if err == nil {
		// v2.12.38: wrap the static FileServer with a Cache-Control header.
		// Without this, browsers refused to cache /static/app.css, the PWA
		// icons, etc. and re-fetched them on every cold navigation.
		//
		// 1 day (not 1 year) because the URLs aren't versioned — if we said
		// `immutable, max-age=31536000` then a docker pull to a newer
		// CaddyUI build wouldn't show up until users hard-refreshed. 86400
		// is the sweet spot: repeat visits within the same day are instant,
		// upgrades take effect within a day, and Ctrl-Shift-R always works.
		// (The PWA service worker does a separate cache-first pass at the
		// JS layer for assets it precaches — this header is the safety net
		// for first-visit / SW-not-yet-installed cases.)
		staticHandler := http.StripPrefix("/static/", http.FileServer(http.FS(staticSub)))
		r.Handle("/static/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=86400")
			staticHandler.ServeHTTP(w, req)
		}))
	}

	// PWA root files — must be served from / scope for the service worker to control the whole app.
	r.Get("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		f, err := s.Static.Open("manifest.json")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/manifest+json")
		io.Copy(w, f)
	})
	r.Get("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		f, err := s.Static.Open("sw.js")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Service-Worker-Allowed", "/")
		io.Copy(w, f)
	})

	r.Get("/setup", s.getSetup)
	r.Post("/setup", s.postSetup)
	r.Get("/login", s.getLogin)
	r.Post("/login", s.postLogin)
	r.Post("/logout", s.postLogout)
	r.Get("/auth/oidc/login", s.getOIDCLogin)       // issue #106 (SSO)
	r.Get("/auth/oidc/callback", s.getOIDCCallback) // issue #106 (SSO)
	r.Get("/login/totp", s.getTOTPVerify)
	r.Post("/login/totp", s.postTOTPVerify)
	r.Get("/forgot-password", s.getForgotPassword)
	r.Post("/forgot-password", s.postForgotPassword)
	r.Get("/reset-password", s.getResetPassword)
	r.Post("/reset-password", s.postResetPassword)
	r.Get("/accept-invite", s.getAcceptInvite)
	r.Post("/accept-invite", s.postAcceptInvite)

	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		// v2.29.0: CSRF must sit *inside* requireAuth — it reads the API-token
		// scope that requireAuth puts on the context to decide whether a
		// request is bearer-authenticated (and so not CSRF-reachable).
		r.Use(s.requireCSRF)
		r.Get("/", s.dashboard)
		r.Get("/onboarding", s.getOnboarding)

		// Read routes — open to both admin and viewer roles.
		r.Get("/proxy-hosts", s.listProxyHosts)
		r.Get("/redirection-hosts", s.listRedirectionHosts)
		r.Get("/import", s.getImport)
		r.Get("/caddyfile-import", s.getCaddyfileImport)
		r.Get("/snapshots", s.listSnapshots)
		r.Get("/snapshots/{id}/download", s.downloadSnapshot)
		r.Get("/snapshots/{id}/diff", s.getSnapshotDiff)
		r.Get("/activity", s.listActivityLog)
		r.Get("/activity/export.csv", s.exportActivityCSV)
		r.Get("/certificates", s.listCertificates)
		r.Get("/certificates/{id}/inspect", s.getCertificateInspect)
		r.Get("/certificates/{id}/managed-status", s.getManagedCertificateStatus)
		// v2.39.0: live TLS probes of custom certificates. Read-only towards
		// Caddy, so viewers may trigger them like the Refresh button before.
		r.Post("/certificates/probe", s.probeCertificatesHandler)
		r.Post("/certificates/{id}/probe", s.probeCertificateHandler)
		// v2.42.0: Export now — writes files, so write access is required.
		r.With(s.requireWrite).Post("/certificates/{id}/export", s.exportCertificateHandler)
		r.Get("/raw-routes", s.listRawRoutes)
		r.Get("/docs", s.getDocs)
		r.Get("/api/docs", s.getAPIDocs)
		r.Get("/caddy-config", s.getCaddyConfig)

		// Server picker — available to every authenticated role. The route
		// only flips the caddyui_server cookie (a per-user preference) so
		// viewers and non-admin users can switch between Caddy instances
		// the admin has registered without needing write access. Admin-only
		// CRUD on the server list still lives in the admin-gated group below.
		r.Post("/servers/{id}/select", s.selectServer)

		// Feature B: upstream health check API (authenticated, no requireWrite).
		r.Get("/api/upstream-health", s.apiUpstreamHealth)

		// v2.11.5: ⌘K command palette — returns every visible resource on the
		// active server in one flat list. Frontend caches per palette open.
		r.Get("/api/search", s.globalSearch)

		// v2.11.15: AI assistant — proxies prompts to the configured Ollama
		// instance. /api/ai/status reports whether AI is enabled so the
		// frontend can hide the floating button when not configured.
		r.Get("/api/ai/status", s.apiAIStatus)
		r.Post("/api/ai/chat", s.apiAIChat)
		// v2.12.11: AI tool calling — model proposes a proxy host or
		// redirection via tool_calls; user confirms; this endpoint actually
		// creates it.
		r.Post("/api/ai/exec-tool", s.apiAIExecTool)

		// v2.12.27: per-user color-theme persistence so the picker in
		// Settings follows the account across devices instead of being
		// trapped in per-browser localStorage.
		r.Post("/api/me/color-theme", s.postMyColorTheme)

		// Live upstream status — proxies Caddy's /reverse_proxy/upstreams response.
		r.Get("/api/caddy-upstreams", s.apiCaddyUpstreams)
		r.Post("/api/proxy-hosts/test-upstream", s.apiTestUpstream)
		// v2.11.13: live Caddyfile/JSON preview — takes the in-progress
		// proxy-host edit form and returns the route JSON Caddy would see.
		r.Post("/api/proxy-hosts/preview", s.apiPreviewProxyHost)
		// v2.9.228: validate a raw-route's Caddyfile/JSON via /load?validate_only=true
		// before saving the row. Lets the form catch syntax/schema errors at edit
		// time instead of waiting for the next sync to surface them.
		r.Post("/api/raw-routes/validate", s.apiValidateRawRoute)

		// Feature F: notifier status API (authenticated).
		r.Get("/api/notifier-status", s.apiNotifierStatus)

		// Phase 7: system stats API (authenticated, read-only).
		r.Get("/api/system-stats", s.apiSystemStats)

		// v2.15.0: dashboard sparklines — 7-day daily totals for the three
		// stat cards (views, visitors, bandwidth). Scoped to active server.
		r.Get("/api/dashboard-sparklines", s.apiDashboardSparklines)

		// Caddy version from the admin API root endpoint.
		r.Get("/api/caddy-version", s.apiCaddyVersion)

		// Update-check: fetches latest tag from Docker Hub (cached 1h).
		r.Get("/api/version-check", s.apiVersionCheck)

		// Unified DNS-provider zones endpoint — /api/dns-zones?provider=<id>.
		// Replaces the v2.2.x per-provider /api/cf-zones and /api/pb-domains
		// endpoints with a single handler that routes on ?provider=.
		r.Get("/api/dns-zones", s.apiDNSZones)

		// v2.4.8: warn when a proxy host would collide with a pre-existing
		// DNS record. Proxy-host form JS calls this after the user picks
		// provider + zone + first domain; response drives the "record
		// already exists — Cancel / Override?" dialog.
		r.Get("/api/dns-zones/check-record", s.apiDNSCheckRecord)

		// v2.5.2: post-save deployment status — drives the "deploying"
		// page's live checklist (DNS propagated, cert issued). Read-only,
		// so it lives outside the write-guarded group. v2.5.5 extends the
		// same checklist to advanced (raw) routes that have a host matcher.
		r.Get("/proxy-hosts/{id}/deploying", s.proxyHostDeploying)
		r.Get("/api/proxy-hosts/{id}/deploy-status", s.apiProxyHostDeployStatus)
		r.Get("/raw-routes/{id}/deploying", s.rawRouteDeploying)
		r.Get("/api/raw-routes/{id}/deploy-status", s.apiRawRouteDeployStatus)
		// v2.9.2: per-host health history page (read-only, authenticated).
		r.Get("/proxy-hosts/{id}/health", s.getProxyHostHealth)

		// v2.9.5: REST JSON API for proxy hosts and redirection hosts (read endpoints).
		r.Get("/api/v1/proxy-hosts", s.apiV1ListProxyHosts)
		r.Get("/api/v1/proxy-hosts/{id}", s.apiV1GetProxyHost)
		r.Get("/api/v1/redirection-hosts", s.apiV1ListRedirectionHosts)
		r.Get("/api/v1/redirection-hosts/{id}", s.apiV1GetRedirectionHost)
		r.Get("/api/v1/raw-routes", s.apiV1ListRawRoutes)
		r.Get("/api/v1/raw-routes/{id}", s.apiV1GetRawRoute)
		r.Get("/api/v1/certificates", s.apiV1ListCertificates)
		r.Get("/api/v1/certificates/{id}", s.apiV1GetCertificate)
		r.Get("/api/v1/servers", s.apiV1ListServers)

		// Write routes — admin-only in practice. Viewers get 403 via requireWrite.
		r.Group(func(r chi.Router) {
			r.Use(s.requireWrite)

			r.Get("/proxy-hosts/new", s.newProxyHost)
			r.Post("/proxy-hosts", s.createProxyHost)
			r.Get("/proxy-hosts/{id}/export.json", s.exportProxyHost)
			r.Get("/proxy-hosts/export-all.json", s.exportAllProxyHosts)
			// v2.12.49: Caddyfile export — inverse of /caddyfile-import paste flow.
			r.Get("/proxy-hosts/export-all.caddyfile", s.exportServerCaddyfile)
			// v2.12.50: per-host Caddyfile export.
			r.Get("/proxy-hosts/{id}/export.caddyfile", s.exportProxyHostCaddyfile)
			r.Post("/proxy-hosts/import", s.importProxyHost)
			r.Get("/proxy-hosts/{id}/edit", s.editProxyHost)
			r.Post("/proxy-hosts/{id}", s.updateProxyHost)
			r.Post("/proxy-hosts/{id}/delete", s.deleteProxyHost)
			r.Post("/proxy-hosts/{id}/clone", s.cloneProxyHost)
			r.Post("/proxy-hosts/{id}/toggle", s.toggleProxyHost)
			r.Post("/proxy-hosts/{id}/expectations/run", s.runProxyHostExpectationsHandler) // v2.38.0
			r.Post("/proxy-hosts/{id}/maintenance", s.toggleMaintenanceMode)
			r.Post("/proxy-hosts/bulk-toggle", s.bulkToggleProxyHosts)
			r.Post("/proxy-hosts/bulk-maintenance", s.bulkMaintenanceProxyHosts)
			r.Post("/proxy-hosts/bulk-certificate", s.bulkCertificateProxyHosts)
			r.Post("/proxy-hosts/bulk-delete", s.bulkDeleteProxyHosts)
			// v2.11.11: drag-to-reorder rows — accepts ids[] in desired
			// display order, writes sort_order = (index * 10) for each.
			r.Post("/proxy-hosts/reorder", s.reorderProxyHosts)

			// v2.9.5: REST JSON API write routes (write-scoped, honours requireWrite).
			r.Post("/api/v1/proxy-hosts", s.apiV1CreateProxyHost)
			r.Put("/api/v1/proxy-hosts/{id}", s.apiV1UpdateProxyHost)
			r.Delete("/api/v1/proxy-hosts/{id}", s.apiV1DeleteProxyHost)
			r.Post("/api/v1/proxy-hosts/{id}/toggle", s.apiV1ToggleProxyHost)
			r.Post("/api/v1/proxy-hosts/{id}/maintenance", s.apiV1ToggleMaintenanceProxyHost)
			r.Post("/api/v1/redirection-hosts", s.apiV1CreateRedirectionHost)
			r.Put("/api/v1/redirection-hosts/{id}", s.apiV1UpdateRedirectionHost)
			r.Delete("/api/v1/redirection-hosts/{id}", s.apiV1DeleteRedirectionHost)
			r.Post("/api/v1/redirection-hosts/{id}/toggle", s.apiV1ToggleRedirectionHost)
			r.Post("/api/v1/raw-routes", s.apiV1CreateRawRoute)
			r.Put("/api/v1/raw-routes/{id}", s.apiV1UpdateRawRoute)
			r.Delete("/api/v1/raw-routes/{id}", s.apiV1DeleteRawRoute)
			r.Post("/api/v1/raw-routes/{id}/toggle", s.apiV1ToggleRawRoute)
			r.Post("/api/v1/certificates", s.apiV1CreateCertificate)
			r.Put("/api/v1/certificates/{id}", s.apiV1UpdateCertificate)
			r.Delete("/api/v1/certificates/{id}", s.apiV1DeleteCertificate)

			r.Get("/redirection-hosts/new", s.newRedirectionHost)
			r.Post("/redirection-hosts", s.createRedirectionHost)
			r.Get("/redirection-hosts/{id}/edit", s.editRedirectionHost)
			r.Post("/redirection-hosts/{id}", s.updateRedirectionHost)
			r.Post("/redirection-hosts/{id}/delete", s.deleteRedirectionHost)
			r.Post("/redirection-hosts/{id}/toggle", s.toggleRedirectionHost)
			r.Post("/redirection-hosts/{id}/clone", s.cloneRedirectionHost)
			// v2.11.6: bulk operations on /redirection-hosts (parallel of proxy-host bulk).
			r.Post("/redirection-hosts/bulk-toggle", s.bulkToggleRedirectionHosts)
			r.Post("/redirection-hosts/bulk-delete", s.bulkDeleteRedirectionHosts)
			// v2.11.11: drag-to-reorder rows.
			r.Post("/redirection-hosts/reorder", s.reorderRedirectionHosts)

			r.Post("/caddy/reload", s.reloadCaddy)
			r.Post("/import", s.postImport)
			r.Post("/caddyfile-import", s.postCaddyfileImport)

			r.Post("/snapshots", s.createManualSnapshot)
			r.Post("/snapshots/upload", s.uploadSnapshot)
			r.Post("/snapshots/auto", s.setAutoSnapshots)
			r.Post("/snapshots/{id}/restore", s.restoreSnapshot)
			r.Post("/snapshots/{id}/delete", s.deleteSnapshot)

			// v2.7.2: certificate create + edit are writer-level, not admin-only.
			// Each cert now carries owner_id (NULL = global/admin, >0 = private
			// to a user). user-role uploads land with owner_id = cu.ID so they
			// don't collide with other tenants' TLS material. The per-handler
			// 403 in editCertificate / updateCertificate enforces ownership
			// defensively — route layer only filters view-role out.
			//
			// Delete stays admin-only (see /certificates/{id}/delete down in
			// the requireAdmin group) because its blast radius is NULL-ing
			// certificate_id on proxy_hosts/redirection_hosts/raw_routes across
			// owners. That check would be racy if we distributed it.
			r.Get("/certificates/new", s.newCertificate)
			r.Post("/certificates", s.createCertificate)
			r.Get("/certificates/{id}/edit", s.editCertificate)
			r.Post("/certificates/{id}", s.updateCertificate)
			r.Post("/certificates/{id}/delete", s.deleteCertificate)
			// v2.11.10: bulk delete on /certificates — same ownership / in-use
			// guards as the single-row deleteCertificate handler.
			r.Post("/certificates/bulk-delete", s.bulkDeleteCertificates)
			r.Get("/certificates/import/porkbun", s.importPorkbunCertificatePage)
			r.Post("/certificates/import/porkbun", s.importPorkbunCertificate)

			r.Get("/raw-routes/new", s.newRawRoute)
			r.Post("/raw-routes", s.createRawRoute)
			r.Get("/raw-routes/{id}/edit", s.editRawRoute)
			r.Post("/raw-routes/{id}", s.updateRawRoute)
			r.Post("/raw-routes/{id}/delete", s.deleteRawRoute)
			// v2.11.9: bulk operations on /raw-routes (parallel of /proxy-hosts).
			r.Post("/raw-routes/bulk-toggle", s.bulkToggleRawRoutes)
			r.Post("/raw-routes/bulk-delete", s.bulkDeleteRawRoutes)
			// v2.10.9: bulk re-run the classifier over Advanced routes —
			// useful for users who imported before v2.10.7 (auto-classify)
			// shipped, when every block landed in Advanced.
			r.Post("/raw-routes/reclassify", s.postReclassifyRawRoutes)

			// Phase 7: database backup download.
			r.Get("/backup", s.getBackup)
		})

		// TOTP setup — available to all authenticated users.
		r.Get("/totp/setup", s.getTOTPSetup)
		r.Post("/totp/setup", s.postTOTPSetup)
		r.Post("/totp/regenerate-backup-codes", s.postRegenerateBackupCodes)

		// v2.7.0: visitor analytics — read-only for every signed-in
		// user. userAllowedHosts scopes non-admins to their owned
		// sites so the page doesn't leak traffic for hosts they
		// don't have Edit permission on.
		r.Get("/analytics", s.getAnalytics)
		r.Get("/analytics/export.csv", s.exportAnalyticsCSV)
		r.Get("/analytics/{host}", s.getAnalyticsHost)
		r.Get("/analytics/{host}/visitor", s.getAnalyticsVisitor) // issue #94
		r.Get("/analytics/{host}/path", s.getAnalyticsPath)       // issue #94
		r.Get("/analytics/{host}/status", s.getAnalyticsStatus)   // issue #94 follow-up
		r.Post("/analytics/{host}/block", s.postAnalyticsBlock)   // issue #100
		r.Get("/live-traffic", s.getLiveTraffic)
		r.Get("/api/live-traffic/stream", s.liveTrafficStream)

		// Global search — read-only, available to every authenticated role.
		r.Get("/search", s.getSearch)

		// Session manager — every user can view and revoke their own sessions;
		// admins see all sessions across all users.
		r.Get("/sessions", s.getSessions)
		r.Post("/sessions/{token}/revoke", s.revokeSession)

		// API token manager — every authenticated user can create/revoke their
		// own tokens; admins see all users' tokens.
		r.Get("/api-tokens", s.listAPITokens)
		r.Post("/api-tokens", s.createAPIToken)
		r.Post("/api-tokens/{id}/revoke", s.revokeAPIToken)

		// Profile page — every authenticated user can update their own name/password.
		r.Get("/profile", s.getProfile)
		r.Post("/profile", s.postProfile)

		// User management and settings — admin-only (both read and write).
		r.Group(func(r chi.Router) {
			r.Use(s.requireAdmin)
			r.Get("/users", s.listUsers)
			r.Get("/users/new", s.newUser)
			r.Post("/users", s.createUser)
			r.Post("/users/invite", s.postInviteUser)
			r.Get("/users/{id}/edit", s.editUser)
			r.Post("/users/{id}", s.updateUser)
			r.Post("/users/{id}/delete", s.deleteUser)

			// v2.7.4: group CRUD. Admin puts user-role accounts into a shared
			// group; members then see each other's rows (proxy/redirect/raw/
			// certs) read-only in List* queries. Edit/delete still goes
			// through the per-row ownership gate inside each handler, so
			// "view teammates' work" doesn't imply "mutate teammates' work".
			r.Get("/groups", s.listGroups)
			r.Get("/groups/new", s.newGroup)
			r.Post("/groups", s.createGroup)
			r.Get("/groups/{id}/edit", s.editGroup)
			r.Post("/groups/{id}", s.updateGroup)
			r.Post("/groups/{id}/delete", s.deleteGroup)

			r.Get("/servers", s.listServersPage)
			r.Get("/servers/new", s.newServerPage)
			r.Post("/servers", s.createServer)
			r.Get("/servers/{id}/edit", s.editServerPage)
			r.Get("/servers/{id}/config", s.viewServerConfig)
			r.Post("/servers/{id}", s.updateServer)
			r.Post("/servers/{id}/sync-from-current", s.syncServerFromCurrent)
			r.Post("/servers/{id}/sync-reapply", s.reapplySyncHandler)        // v2.38.0
			r.Post("/servers/{id}/sync-hold/clear", s.clearSyncHoldHandler)   // v2.38.0
			r.Post("/servers/{id}/sync-error/clear", s.clearSyncErrorHandler) // v2.42.1
			r.Post("/servers/{id}/delete", s.deleteServer)
			r.Get("/server-logs", s.getServerLogs)
			r.Get("/api/server-logs/status", s.serverLogStatus)
			r.Get("/api/server-logs/stream", s.serverLogStream)
			r.Post("/api/server-logs/enable", s.enableServerLogs)
			r.Post("/api/server-logs/disable", s.disableServerLogs)
			r.Post("/api/server-logs/clear", s.clearServerLogs) // v2.35.5 (issue #60)
			r.Post("/dashboard/recommendations/unused-certificates/dismiss", s.dismissUnusedCertificateRecommendation)

			// v2.7.2: create/edit moved up to the requireWrite group so
			// user-role accounts can manage their own certs. The remaining
			// admin-only cert concern — whole-cert delete with its
			// cross-owner blast radius — is enforced by the inline role check
			// inside deleteCertificate, not by route gating, so a user-role
			// account can still delete a cert they own (see the ownership
			// branch in that handler).

			// Feature F: settings page (admin-only).
			r.Get("/settings", s.getSettings)
			r.Get("/settings/{section}", s.getSettings) // v2.44.0
			r.Post("/settings", s.postSettings)
			r.Post("/settings/analytics/prune", s.pruneAnalyticsHandler)   // v2.43.0
			r.Post("/settings/analytics/vacuum", s.vacuumAnalyticsHandler) // v2.43.0
			r.Post("/settings/backup/run", s.postBackupRun)                // v2.52.0 (issue #104)
			r.Post("/settings/test-webhook", s.postTestWebhook)
			r.Post("/settings/test-email", s.postTestEmail)
			r.Post("/settings/test-crowdsec", s.postTestCrowdSec)
			r.Post("/settings/dns-provider/{id}/clear", s.postClearDNSProvider)
		})
	})

	return r
}

// securityHeaders sets baseline response headers on every CaddyUI response
// regardless of whether the request reached us through a reverse proxy or
// directly. Defense-in-depth: even if you bypass Caddy and hit CaddyUI on
// its bound port (or behind a different proxy that doesn't add security
// headers), these still ship.
//
// Headers set:
//   - X-Frame-Options: SAMEORIGIN — page can only be iframed by itself,
//     mitigates clickjacking against the management UI.
//   - X-Content-Type-Options: nosniff — browser respects the Content-Type
//     header instead of MIME-sniffing, mitigates MIME confusion.
//   - Referrer-Policy: strict-origin-when-cross-origin — hides path/query
//     from cross-origin navigations.
//
// HSTS is intentionally NOT set here — CaddyUI may be served on plain HTTP
// when accessed via Tailscale / Wireguard / localhost during dev/test, and
// HSTS would make those flows uncomfortable. The fronting Caddy adds HSTS
// for public HTTPS access via the Security Headers checkbox on the
// proxy host fronting CaddyUI. v2.10.3.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// v2.12.15: honour Settings → "Globally stripped response headers"
		// for CaddyUI's own responses too (not just proxied upstream replies).
		// Without this, a user setting `X-Frame-Options` in the global-strip
		// field still saw SAMEORIGIN on CaddyUI-served pages (login redirect,
		// admin UI, etc.) because this middleware unconditionally set it.
		stripped := map[string]bool{}
		if globalStrip, _ := models.GetSetting(s.DB, settingGlobalStripResponseHeaders); strings.TrimSpace(globalStrip) != "" {
			for _, hh := range strings.Split(globalStrip, ",") {
				hh = strings.ToLower(strings.TrimSpace(hh))
				if hh != "" {
					stripped[hh] = true
				}
			}
		}
		h := w.Header()
		// Set-only-if-not-already-present so a more restrictive value from
		// a fronting proxy (e.g. X-Frame-Options: DENY) still wins. Skip
		// entirely if the header is in the global-strip list — user has
		// explicitly told us to drop it everywhere.
		if !stripped["x-frame-options"] && h.Get("X-Frame-Options") == "" {
			h.Set("X-Frame-Options", "SAMEORIGIN")
		}
		if !stripped["x-content-type-options"] && h.Get("X-Content-Type-Options") == "" {
			h.Set("X-Content-Type-Options", "nosniff")
		}
		if !stripped["referrer-policy"] && h.Get("Referrer-Policy") == "" {
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		}
		// v2.30.0: Content-Security-Policy and Permissions-Policy, following
		// the same strip-aware, set-only-if-absent rules as the three above.
		// See security_headers.go for the allowlist and why each origin is on
		// it; CADDYUI_CSP=off disables the policy without a redeploy.
		if csp := cspPolicy(); csp != "" &&
			!stripped["content-security-policy"] && h.Get("Content-Security-Policy") == "" {
			h.Set("Content-Security-Policy", csp)
		}
		if !stripped["permissions-policy"] && h.Get("Permissions-Policy") == "" {
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		}
		// v2.12.18: previously wrapped w in a stripHeaderWriter so headers
		// set by downstream handlers (templates / 404 / Caddy-static) could
		// also be stripped. Reverted — the wrapper didn't implement
		// http.Flusher / http.Hijacker so streaming responses degraded into
		// browser-side "save as" downloads (no detected Content-Type
		// flushing). The conditional skips above on the three headers this
		// middleware unconditionally sets are enough; downstream handlers
		// don't add X-Frame-Options / etc. on their own.
		next.ServeHTTP(w, r)
	})
}

// adminIPGate returns a middleware that enforces the admin_allowlist setting.
// If the setting is empty, all IPs are allowed. Non-matching IPs get 403.
func (s *Server) adminIPGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := models.GetSetting(s.DB, settingAdminAllowlist)
		if raw == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Parse the allowlist.
		var allowedNets []*net.IPNet
		var allowedIPs []net.IP
		for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
			cidr := strings.TrimSpace(line)
			if cidr == "" {
				continue
			}
			if strings.Contains(cidr, "/") {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err == nil {
					allowedNets = append(allowedNets, ipnet)
				}
			} else {
				if ip := net.ParseIP(cidr); ip != nil {
					allowedIPs = append(allowedIPs, ip)
				}
			}
		}
		if len(allowedNets) == 0 && len(allowedIPs) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		// Extract client IP.
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(clientIP)
		if ip == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// Check against allowlist.
		for _, allowed := range allowedIPs {
			if allowed.Equal(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		for _, ipnet := range allowedNets {
			if ipnet.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "403 Forbidden — your IP is not on the admin allowlist", http.StatusForbidden)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := models.CountUsers(s.DB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		cookie, err := r.Cookie(auth.SessionCookie)
		if err != nil {
			// No session cookie — try bearer token before redirecting.
			if u, tokenScopes := s.bearerTokenUser(r); u != nil {
				// Enforce read-only scope: block mutating methods.
				if tokenScopes == models.TokenScopeReadOnly &&
					r.Method != http.MethodGet && r.Method != http.MethodHead {
					http.Error(w, "token scope is read-only", http.StatusForbidden)
					return
				}
				ctx := context.WithValue(r.Context(), auth.ContextUserKey, u)
				ctx = context.WithValue(ctx, apiTokenScopeContextKey{}, tokenScopes)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, err := auth.UserFromSession(s.DB, cookie.Value)
		if err != nil || u == nil {
			auth.ClearSessionCookie(w, r)
			// Session invalid — try bearer token before redirecting.
			if u, tokenScopes := s.bearerTokenUser(r); u != nil {
				// Enforce read-only scope: block mutating methods.
				if tokenScopes == models.TokenScopeReadOnly &&
					r.Method != http.MethodGet && r.Method != http.MethodHead {
					http.Error(w, "token scope is read-only", http.StatusForbidden)
					return
				}
				ctx := context.WithValue(r.Context(), auth.ContextUserKey, u)
				ctx = context.WithValue(ctx, apiTokenScopeContextKey{}, tokenScopes)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Enforce 2FA policy if enabled.
		if !u.TOTPEnabled {
			if v, _ := models.GetSetting(s.DB, settingRequire2FA); v == "1" {
				// Allow the TOTP setup pages and static assets through.
				path := r.URL.Path
				if !strings.HasPrefix(path, "/totp/") && !strings.HasPrefix(path, "/static/") &&
					!strings.HasPrefix(path, "/api/") && path != "/logout" {
					http.Redirect(w, r, "/totp/setup?required=1", http.StatusSeeOther)
					return
				}
			}
		}
		// TOTP enforcement: if the admin has enabled require_totp and this user
		// has TOTP disabled, redirect them to TOTP setup before granting access.
		// Skip the check for the TOTP setup page itself to avoid a redirect loop.
		if mustGetSetting(s.DB, settingRequireTOTP) == "1" {
			if !u.TOTPEnabled {
				// Allow /totp/setup and /logout through so the user can complete enrollment.
				path := r.URL.Path
				if path != "/totp/setup" && path != "/logout" && !strings.HasPrefix(path, "/static/") {
					http.Redirect(w, r, "/totp/setup?enforce=1", http.StatusFound)
					return
				}
			}
		}
		ctx := context.WithValue(r.Context(), auth.ContextUserKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerTokenUser checks for an Authorization: Bearer header and resolves
// it to a User via the api_tokens table. Returns (nil, "") if no header is
// present or the token is invalid/expired. Callers that already resolved a
// session user should skip this (session wins over bearer).
func (s *Server) bearerTokenUser(r *http.Request) (*models.User, string) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, ""
	}
	raw := strings.TrimPrefix(authHeader, "Bearer ")
	if raw == "" {
		return nil, ""
	}
	h := sha256.Sum256([]byte(raw))
	hash := fmt.Sprintf("%x", h)
	tok, err := models.GetAPITokenByHash(s.DB, hash)
	if err != nil || tok == nil {
		return nil, ""
	}
	if tok.Expired() {
		return nil, ""
	}
	u, err := models.GetUserByID(s.DB, tok.UserID)
	if err != nil {
		return nil, ""
	}
	models.TouchAPIToken(s.DB, tok.ID)
	return u, tok.Scopes
}

func (s *Server) currentUser(r *http.Request) *models.User {
	u, _ := r.Context().Value(auth.ContextUserKey).(*models.User)
	return u
}

func currentAPITokenScope(r *http.Request) string {
	scope, _ := r.Context().Value(apiTokenScopeContextKey{}).(string)
	return scope
}

func proxyWriteTokenCanWritePath(path string) bool {
	return path == "/api/v1/proxy-hosts" || strings.HasPrefix(path, "/api/v1/proxy-hosts/")
}

// sessionTTL returns the configured session duration, defaulting to 7 days.
func (s *Server) sessionTTL() time.Duration {
	v, _ := models.GetSetting(s.DB, settingSessionDays)
	if v == "" {
		return 7 * 24 * time.Hour
	}
	days, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || days <= 0 || days > 365 {
		return 7 * 24 * time.Hour
	}
	return time.Duration(days) * 24 * time.Hour
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	// Always inject app version.
	data["AppVersion"] = s.Version
	// v2.29.0: CSRF token for every rendered page. CSRFField is the ready-made
	// hidden input each POST form embeds; CSRFToken is the raw value, surfaced
	// as a <meta> tag so the fetch wrapper in app.js can pick it up for JSON
	// calls. Both are empty for anonymous pages, which have no session to
	// protect. Injected here so no page can forget it.
	if _, ok := data["CSRFField"]; !ok {
		data["CSRFField"] = s.csrfField(r)
	}
	if _, ok := data["CSRFToken"]; !ok {
		data["CSRFToken"] = s.csrfTokenForRequest(r)
	}
	// Inject site title for every page so layout.html can use it.
	if _, ok := data["SiteTitle"]; !ok {
		data["SiteTitle"] = mustGetSetting(s.DB, settingSiteTitle)
	}
	// Inject custom favicon URL for every page so layout.html can override the default icon.
	if _, ok := data["FaviconURL"]; !ok {
		data["FaviconURL"] = mustGetSetting(s.DB, settingFaviconURL)
	}
	// Auto-inject server picker data (best-effort; non-fatal if DB unavailable).
	if _, ok := data["Servers"]; !ok {
		if servers, err := models.ListCaddyServers(s.DB); err == nil {
			data["Servers"] = servers
		}
	}
	// v2.38.0: servers held after a failed post-apply check — layout banner.
	if _, ok := data["SyncHolds"]; !ok {
		if servers, ok := data["Servers"].([]models.CaddyServer); ok && len(servers) > 0 {
			data["SyncHolds"] = s.activeSyncHolds(servers)
		}
	}
	// v2.42.1: servers whose last sync failed — layout banner.
	if _, ok := data["SyncErrors"]; !ok {
		if servers, ok := data["Servers"].([]models.CaddyServer); ok && len(servers) > 0 {
			data["SyncErrors"] = s.activeSyncErrors(servers)
		}
	}
	if _, ok := data["CurrentServer"]; !ok {
		if r != nil {
			sid := s.currentServerID(r)
			if srv, err := models.GetCaddyServer(s.DB, sid); err == nil {
				data["CurrentServer"] = srv
			}
		}
	}
	tpl, ok := s.Templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	// v2.29.0: render into a buffer so the CSRF hidden input can be stamped
	// into every POST form before anything reaches the client. Buffering also
	// means a mid-template error produces a clean 500 instead of a truncated
	// page followed by an error string, which is what happened when this wrote
	// to the ResponseWriter directly.
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		log.Printf("template %s: %v", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page := buf.Bytes()
	if field, _ := data["CSRFField"].(template.HTML); field != "" {
		page = csrfInjectForms(page, []byte(field))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(page); err != nil {
		log.Printf("template %s: write: %v", name, err)
	}
}

// --- Setup (first-run) ---
func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	n, err := models.CountUsers(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup.html", nil)
}

func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	n, err := models.CountUsers(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	email := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	pw := r.FormValue("password")
	pw2 := r.FormValue("password_confirm")
	if email == "" || pw == "" {
		s.render(w, r, "setup.html", map[string]any{"Error": "Email and password required"})
		return
	}
	if pw != pw2 {
		s.render(w, r, "setup.html", map[string]any{"Error": "Passwords do not match"})
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id, err := models.CreateUser(s.DB, email, hash, name, models.RoleAdmin)
	if err != nil {
		s.render(w, r, "setup.html", map[string]any{"Error": err.Error()})
		return
	}
	tok, exp, err := auth.CreateSessionWithTTL(s.DB, id, s.sessionTTL())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, r, tok, exp)
	http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
}

// getOnboarding renders the guided first-run journey. It deliberately uses
// live product state instead of a dismissible "completed" flag: returning
// admins can open the page at any time and immediately see which operational
// foundations are configured, without onboarding state drifting away from
// the real Caddy/server/DNS/security configuration.
func (s *Server) getOnboarding(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	sid := s.currentServerID(r)
	currentServer, _ := models.GetCaddyServer(s.DB, sid)
	serverConnected := currentServer != nil && currentServer.Status == models.CaddyServerStatusOnline
	dnsConfigured := len(s.loadDNSProfiles()) > 0

	var proxyCount int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM proxy_hosts WHERE server_id = ?`, sid).Scan(&proxyCount)

	completed := requiredReadinessSteps(serverConnected, cu.TOTPEnabled, proxyCount > 0)

	s.render(w, r, "onboarding.html", map[string]any{
		"User":            cu,
		"CurrentServer":   currentServer,
		"ServerConnected": serverConnected,
		"DNSConfigured":   dnsConfigured,
		"TOTPEnabled":     cu.TOTPEnabled,
		"ProxyCount":      proxyCount,
		"CompletedSteps":  completed,
		"Section":         "onboarding",
	})
}

// --- Login ---

const (
	settingTurnstileSiteKey   = "turnstile_site_key"
	settingTurnstileSecretKey = "turnstile_secret_key"

	// Shared A-record target — the public IP every DNS provider writes as
	// its record content. The key name starts with "cf_" for historical
	// reasons (Cloudflare was the first provider); it's the single source
	// of truth now regardless of which provider is active.
	settingServerIP = "cf_server_ip"

	// Cloudflare-specific.
	settingCFAPIToken = "cf_api_token"
	settingCFProxied  = "cf_proxied"

	// v2.49.0 (issue #98): resolver used for external verification lookups on
	// the deploy/readiness checks. Empty = Cloudflare DoH (default). May be a
	// DoH URL (https://…/dns-query) or a comma-separated list of plain DNS
	// servers (e.g. "192.168.1.10:53") for filtered/split-horizon networks.
	settingDNSVerifyResolver = "dns_verify_resolver"

	// Legacy alias kept so pre-v2.3.0 code paths referencing
	// settingCFServerIP continue to compile. Points at the shared key.
	settingCFServerIP = settingServerIP

	// Porkbun.
	settingPBAPIKey    = "pb_api_key"
	settingPBSecretKey = "pb_secret_key"

	// Namecheap (v2.3.0).
	settingNCAPIUser  = "nc_api_user"
	settingNCAPIKey   = "nc_api_key"
	settingNCClientIP = "nc_client_ip"

	// GoDaddy (v2.3.0).
	settingGDAPIKey    = "gd_api_key"
	settingGDAPISecret = "gd_api_secret"

	// DigitalOcean (v2.3.0).
	settingDOAPIToken = "do_api_token"

	// Hetzner DNS (v2.3.0).
	settingHetznerAPIToken = "hetzner_api_token"
	// v2.45.0: Gandi LiveDNS personal access token (discussion #72).
	settingGandiAPIToken = "gandi_api_token"

	// Amazon Route 53 (v2.23.0). Region defaults to us-east-1 in both the
	// CaddyUI API adapter and the caddy-dns/route53 module. Session token is
	// optional and supports temporary STS credentials.
	settingRoute53AccessKeyID     = "route53_access_key_id"
	settingRoute53SecretAccessKey = "route53_secret_access_key"
	settingRoute53SessionToken    = "route53_session_token"
	settingRoute53Region          = "route53_region"

	// Multiple DNS credential profiles (v2.16.0). JSON array of
	// dnsCredentialProfile. Empty/missing means legacy per-provider
	// settings remain the only credential source.
	settingDNSProfilesJSON = "dns_profiles_json"
)

// dnsProviderCredKeys lists every settings-table key that belongs to a DNS
// provider's credential set. Used by postSettings to walk the new unified
// form section without hardcoding a branch per provider.
//
// Key order mirrors dns.Descriptors() so the Settings page renders cards
// in the same order credentials are saved.
var dnsProviderCredKeys = map[string][]string{
	dns.Cloudflare:   {settingCFAPIToken},
	dns.Porkbun:      {settingPBAPIKey, settingPBSecretKey},
	dns.Namecheap:    {settingNCAPIUser, settingNCAPIKey, settingNCClientIP},
	dns.GoDaddy:      {settingGDAPIKey, settingGDAPISecret},
	dns.DigitalOcean: {settingDOAPIToken},
	dns.Hetzner:      {settingHetznerAPIToken},
	dns.Route53:      {settingRoute53AccessKeyID, settingRoute53SecretAccessKey, settingRoute53SessionToken, settingRoute53Region},
	dns.Gandi:        {settingGandiAPIToken}, // v2.45.0
}

type dnsCredentialProfile struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	ProviderID    string            `json:"provider_id"`
	Credentials   map[string]string `json:"credentials"`
	ZoneAllowlist []string          `json:"zone_allowlist,omitempty"`
}

type dnsProfileView struct {
	ID               string
	Name             string
	ProviderID       string
	ProviderName     string
	TokenSet         bool
	Proxied          bool
	ZoneAllowlistRaw string
}

// zoneAllowlistKey returns the settings-table key where the per-provider
// zone allow-list is stored. Format on disk: comma-separated lowercase base
// domains (e.g. "example.com, other.com"). An empty value means "no
// restriction" — every zone the credentials can see is usable, which is
// the original v2.4.5-and-earlier behaviour.
//
// v2.4.7: introduced so users whose API keys have broad account access
// (especially GoDaddy, where a single key can touch every domain on the
// account) can pin CaddyUI to one or a few zones and guarantee it won't
// ever touch the rest.
func zoneAllowlistKey(providerID string) string {
	return strings.ToLower(strings.TrimSpace(providerID)) + "_zone_allowlist"
}

// parseZoneAllowlist normalises a raw textarea/CSV value into a slice of
// lowercase, trimmed base-domain names with duplicates removed. Accepts
// commas, whitespace, and newlines as separators so the textarea can be
// line-per-domain or CSV with no difference in behaviour.
func parseZoneAllowlist(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ';'
	})
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// zoneAllowlist returns the configured allow-list for providerID. An empty
// slice means "no restriction" (explicitly or implicitly unset).
func (s *Server) zoneAllowlist(providerID string) []string {
	raw, _ := models.GetSetting(s.DB, zoneAllowlistKey(providerID))
	return parseZoneAllowlist(raw)
}

// zoneAllowed is the single decision point for "is CaddyUI permitted to
// touch this zone on this provider". Every CreateRecord / DeleteRecord
// call path should guard on it — filtering the dropdown alone isn't
// enough, because the dns_zone_name column on a proxy_hosts row could have
// been written before the allow-list was tightened (or via direct DB
// editing / API).
//
// Matching is case-insensitive and trailing-dot tolerant. An empty
// allow-list allows everything.
func (s *Server) zoneAllowed(providerID, zoneName string) bool {
	allow := s.zoneAllowlist(providerID)
	if len(allow) == 0 {
		return true
	}
	zoneName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zoneName)), ".")
	if zoneName == "" {
		// Defensive: an unset zone name can't be verified against the
		// allow-list, so refuse. A properly configured proxy host always
		// has dns_zone_name populated when dns_provider is non-empty.
		return false
	}
	for _, z := range allow {
		if z == zoneName {
			return true
		}
	}
	return false
}

// validateZoneMatchesHostname returns "" if the (provider, zoneID, zoneName,
// domains) combination is consistent — either no DNS is configured (provider
// or zoneID empty, in which case the row is opting out of managed DNS), or
// the first hostname in `domains` lives inside `zoneName`. Returns a
// user-facing error message ready to surface on the form when the pairing is
// inconsistent.
//
// Why "first hostname" and not all of them: a single proxy host row can serve
// several hostnames (the comma-separated Domains field), but managed DNS only
// provisions records for the *primary* hostname today. The other entries are
// SAN aliases on the same TLS cert. Validating just the primary keeps the
// check aligned with what dnsCreateRecord actually does.
//
// v2.7.8.
func validateZoneMatchesHostname(provider, zoneID, zoneName string, domains []string) string {
	if strings.TrimSpace(provider) == "" || strings.TrimSpace(zoneID) == "" {
		return "" // no managed DNS configured — nothing to validate
	}
	if len(domains) == 0 {
		return "" // can't validate without a hostname; other validators catch empty-domain saves
	}
	first := strings.TrimSpace(domains[0])
	if first == "" {
		return ""
	}
	if domainInZone(first, zoneName) {
		return ""
	}
	return fmt.Sprintf("Hostname %q doesn't live in DNS zone %q. Pick a zone whose apex matches the hostname (e.g. zone %q for hostname %q), or change the DNS provider to (none) if you don't want CaddyUI to manage the A record.",
		first, zoneName, guessApex(first), first)
}

// guessApex returns a "good enough" suggested zone name for an FQDN — the
// rightmost two labels (e.g. "richardapplegate.io" for
// "api.richardapplegate.io"). Used only inside the v2.7.8 mismatch error
// message; doesn't influence routing decisions. A real public-suffix-aware
// implementation would handle .co.uk etc., but the suggestion is just a hint
// for the user reading the error — they pick the actual zone from the
// dropdown.
func guessApex(fqdn string) string {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), "."), ".")
	if len(parts) < 2 {
		return fqdn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// domainInZone reports whether fqdn belongs to the DNS zone named zoneName.
// True iff fqdn is the apex (fqdn == zoneName) or a subdomain of zoneName
// (fqdn ends in "." + zoneName). Comparison is case-insensitive and strips a
// trailing dot from either side, matching how Caddy and every DNS provider we
// integrate with normalises FQDNs.
//
// Empty inputs return false — callers must decide whether "no zone configured"
// is an error (it isn't for the create-record path; it is for the form
// validators added in v2.7.8 that reject saving a non-matching pairing).
//
// v2.7.8: introduced so the proxy-host and raw-route save handlers can reject
// "you typed richardapplegate.io but picked the applegatecloud.com zone"
// before the row hits the DB. Without this guard the save would succeed, the
// front-end's amber mismatch warning would be the only feedback, and the
// subsequent dnsCreateRecord call would either fail at the provider API or
// silently put the A record in the wrong zone.
func domainInZone(fqdn, zoneName string) bool {
	f := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	z := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zoneName)), ".")
	if f == "" || z == "" {
		return false
	}
	return f == z || strings.HasSuffix(f, "."+z)
}

// dnsCreds returns the current credential map for a provider, reading from
// the settings table. Pass it straight to dns.Build.
func (s *Server) dnsCreds(providerID string) map[string]string {
	creds := map[string]string{}
	for _, k := range dnsProviderCredKeys[providerID] {
		v, _ := models.GetSetting(s.DB, k)
		creds[k] = v
	}
	// Cloudflare also needs the proxied flag — it lives alongside the
	// token in the settings table but isn't a credential field proper.
	if providerID == dns.Cloudflare {
		creds["cf_proxied"], _ = models.GetSetting(s.DB, settingCFProxied)
	}
	return creds
}

func randomDNSProfileID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("dnsprof_%d", time.Now().UnixNano())
	}
	return "dnsprof_" + hex.EncodeToString(b[:])
}

func normalizeDNSProfile(p dnsCredentialProfile) dnsCredentialProfile {
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	p.ProviderID = strings.ToLower(strings.TrimSpace(p.ProviderID))
	if p.Credentials == nil {
		p.Credentials = map[string]string{}
	}
	p.ZoneAllowlist = parseZoneAllowlist(strings.Join(p.ZoneAllowlist, ","))
	return p
}

func (s *Server) loadDNSProfiles() []dnsCredentialProfile {
	raw, _ := models.GetSetting(s.DB, settingDNSProfilesJSON)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var stored []dnsCredentialProfile
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		log.Printf("settings: decode DNS profiles: %v", err)
		return nil
	}
	out := make([]dnsCredentialProfile, 0, len(stored))
	seen := map[string]struct{}{}
	for _, p := range stored {
		p = normalizeDNSProfile(p)
		if p.ID == "" || p.Name == "" || p.ProviderID == "" {
			continue
		}
		if _, ok := dns.Lookup(p.ProviderID); !ok {
			continue
		}
		if _, dup := seen[p.ID]; dup {
			continue
		}
		seen[p.ID] = struct{}{}
		out = append(out, p)
	}
	return out
}

func (s *Server) saveDNSProfiles(profiles []dnsCredentialProfile) error {
	cleaned := make([]dnsCredentialProfile, 0, len(profiles))
	for _, p := range profiles {
		p = normalizeDNSProfile(p)
		if p.ID == "" || p.Name == "" || p.ProviderID == "" {
			continue
		}
		if _, ok := dns.Lookup(p.ProviderID); !ok {
			continue
		}
		if !dns.CredsComplete(p.ProviderID, p.Credentials) {
			continue
		}
		cleaned = append(cleaned, p)
	}
	body, err := json.Marshal(cleaned)
	if err != nil {
		return err
	}
	return models.SetSetting(s.DB, settingDNSProfilesJSON, string(body))
}

func (s *Server) dnsProfileByID(profileID string) (dnsCredentialProfile, bool) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return dnsCredentialProfile{}, false
	}
	for _, p := range s.loadDNSProfiles() {
		if p.ID == profileID {
			return p, true
		}
	}
	return dnsCredentialProfile{}, false
}

func (s *Server) dnsCredsFor(providerID, profileID string) map[string]string {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	profileID = strings.TrimSpace(profileID)
	if profileID != "" {
		if p, ok := s.dnsProfileByID(profileID); ok && p.ProviderID == providerID {
			creds := map[string]string{}
			for k, v := range p.Credentials {
				creds[k] = v
			}
			return creds
		}
		return map[string]string{}
	}
	return s.dnsCreds(providerID)
}

func (s *Server) dnsClientFor(providerID, profileID string) dns.Provider {
	if strings.TrimSpace(providerID) == "" {
		return nil
	}
	return dns.Build(providerID, s.dnsCredsFor(providerID, profileID))
}

func (s *Server) zoneAllowlistFor(providerID, profileID string) []string {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	profileID = strings.TrimSpace(profileID)
	if profileID != "" {
		if p, ok := s.dnsProfileByID(profileID); ok && p.ProviderID == providerID {
			return p.ZoneAllowlist
		}
		return []string{"__missing_dns_profile__"}
	}
	return s.zoneAllowlist(providerID)
}

func (s *Server) zoneAllowedFor(providerID, profileID, zoneName string) bool {
	allow := s.zoneAllowlistFor(providerID, profileID)
	if len(allow) == 0 {
		return true
	}
	zoneName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zoneName)), ".")
	if zoneName == "" {
		return false
	}
	for _, z := range allow {
		if z == zoneName {
			return true
		}
	}
	return false
}

func (s *Server) normalizeDNSFormSelection(providerID, profileID string) (string, string) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	profileID = strings.TrimSpace(profileID)
	if strings.HasPrefix(profileID, "legacy:") {
		return strings.TrimPrefix(profileID, "legacy:"), ""
	}
	if p, ok := s.dnsProfileByID(profileID); ok {
		return p.ProviderID, p.ID
	}
	if _, ok := dns.Lookup(providerID); ok {
		return providerID, ""
	}
	return "", ""
}

func (s *Server) applyDNSFormSelection(p *models.ProxyHost) {
	provider, profileID := s.normalizeDNSFormSelection(p.DNSProvider, p.DNSProfileID)
	p.DNSProvider, p.DNSProfileID = provider, profileID
	if provider == "" {
		p.DNSZoneID, p.DNSZoneName, p.DNSRecordID = "", "", ""
		p.DNSSkipRecord = false
	}
}

func (s *Server) applyRedirectionDNSFormSelection(rh *models.RedirectionHost) {
	provider, profileID := s.normalizeDNSFormSelection(rh.DNSProvider, rh.DNSProfileID)
	rh.DNSProvider, rh.DNSProfileID = provider, profileID
	if provider == "" {
		rh.DNSZoneID, rh.DNSZoneName, rh.DNSRecordID = "", "", ""
		rh.DNSSkipRecord = false
	}
}

func (s *Server) applyRawDNSFormSelection(rr *models.RawRoute) {
	provider, profileID := s.normalizeDNSFormSelection(rr.DNSProvider, rr.DNSProfileID)
	rr.DNSProvider, rr.DNSProfileID = provider, profileID
	if provider == "" {
		rr.DNSZoneID, rr.DNSZoneName, rr.DNSRecordID = "", "", ""
		rr.DNSSkipRecord = false
	}
}

func (s *Server) validateManagedDNSRecordTarget(serverID int64, providerID, zoneID string, skipRecord bool) string {
	if providerID == "" || zoneID == "" || skipRecord || strings.TrimSpace(s.serverIPFor(serverID)) != "" {
		return ""
	}
	return "Managed DNS cannot create a public A record because this Caddy server has no public IP configured. Set its public IP under Settings → DNS, or turn off “Create public A records” to use DNS-01 only."
}

func (s *Server) dnsProfileViews() []dnsProfileView {
	profiles := s.loadDNSProfiles()
	out := make([]dnsProfileView, 0, len(profiles)+1)
	for _, p := range profiles {
		providerName := p.ProviderID
		if d, ok := dns.Lookup(p.ProviderID); ok {
			providerName = d.DisplayName
		}
		out = append(out, dnsProfileView{
			ID:               p.ID,
			Name:             p.Name,
			ProviderID:       p.ProviderID,
			ProviderName:     providerName,
			TokenSet:         strings.TrimSpace(p.Credentials[settingCFAPIToken]) != "",
			Proxied:          p.Credentials[settingCFProxied] == "1",
			ZoneAllowlistRaw: strings.Join(p.ZoneAllowlist, "\n"),
		})
	}
	out = append(out, dnsProfileView{ProviderID: dns.Cloudflare, ProviderName: "Cloudflare"})
	return out
}

func (s *Server) parseDNSProfilesForm(r *http.Request) []dnsCredentialProfile {
	existing := map[string]dnsCredentialProfile{}
	for _, p := range s.loadDNSProfiles() {
		existing[p.ID] = p
	}
	deleted := map[string]struct{}{}
	for _, id := range r.PostForm["dns_profile_delete"] {
		if id = strings.TrimSpace(id); id != "" {
			deleted[id] = struct{}{}
		}
	}
	ids := r.PostForm["dns_profile_id"]
	names := r.PostForm["dns_profile_name"]
	tokens := r.PostForm["dns_profile_token"]
	proxied := r.PostForm["dns_profile_proxied"]
	allows := r.PostForm["dns_profile_zone_allowlist"]
	out := make([]dnsCredentialProfile, 0, len(names))
	for i := range names {
		id := ""
		if i < len(ids) {
			id = strings.TrimSpace(ids[i])
		}
		if _, drop := deleted[id]; drop && id != "" {
			continue
		}
		name := strings.TrimSpace(names[i])
		token := ""
		if i < len(tokens) {
			token = strings.TrimSpace(tokens[i])
		}
		if token == "" && id != "" {
			if prev, ok := existing[id]; ok {
				token = strings.TrimSpace(prev.Credentials[settingCFAPIToken])
			}
		}
		if name == "" && token == "" {
			continue
		}
		if name == "" || token == "" {
			continue
		}
		if id == "" {
			id = randomDNSProfileID()
		}
		proxyFlag := "0"
		if i < len(proxied) && proxied[i] == "1" {
			proxyFlag = "1"
		}
		allowRaw := ""
		if i < len(allows) {
			allowRaw = allows[i]
		}
		out = append(out, dnsCredentialProfile{
			ID:         id,
			Name:       name,
			ProviderID: dns.Cloudflare,
			Credentials: map[string]string{
				settingCFAPIToken: token,
				settingCFProxied:  proxyFlag,
			},
			ZoneAllowlist: parseZoneAllowlist(allowRaw),
		})
	}
	return out
}

// dnsClient returns a ready-to-use Provider for the given ID, or nil if
// credentials aren't configured. Replaces the per-provider cfClient /
// pbClient helpers.
func (s *Server) dnsClient(providerID string) dns.Provider {
	if providerID == "" {
		return nil
	}
	return dns.Build(providerID, s.dnsCreds(providerID))
}

// serverIP returns the legacy global IP. Kept for the backwards-compat
// fallback path — new code should use serverIPFor(serverID) instead.
func (s *Server) serverIP() string {
	ip, _ := models.GetSetting(s.DB, settingServerIP)
	return ip
}

// serverIPFor returns the public IP to use as the A-record target for
// proxy hosts that live on serverID. Reads caddy_servers.public_ip first,
// then falls back to the legacy global setting so pre-v2.4.0 databases
// still resolve to *some* IP while users fill in the per-server column.
func (s *Server) serverIPFor(serverID int64) string {
	if serverID > 0 {
		if srv, err := models.GetCaddyServer(s.DB, serverID); err == nil && strings.TrimSpace(srv.PublicIP) != "" {
			return strings.TrimSpace(srv.PublicIP)
		}
	}
	return s.serverIP()
}

// verifyTurnstile calls the Cloudflare Turnstile siteverify endpoint.
// Returns true when the challenge token is valid. Error-codes and the
// hostname Cloudflare echoes back are logged on failure so an admin
// reading `docker logs caddyui` can tell a wrong-key mistake from a
// domain-not-registered one — matches what verifyRecaptcha does for
// the Google siteverify path. (v2.6.1 — previously a failure looked
// identical to every other "Security check failed" in the UI.)
func verifyTurnstile(secretKey, token, remoteIP string) (bool, error) {
	if token == "" {
		log.Printf("turnstile: reject — no token in form (widget may not have loaded)")
		return false, nil
	}
	if strings.TrimSpace(secretKey) == "" {
		log.Printf("turnstile: reject — secret key is blank in DB (check Settings → CAPTCHA → Turnstile)")
		return false, nil
	}
	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify",
		url.Values{
			"secret":   {secretKey},
			"response": {token},
			"remoteip": {remoteIP},
		})
	if err != nil {
		log.Printf("turnstile: network error talking to Cloudflare: %v", err)
		return false, err
	}
	defer resp.Body.Close()
	var result struct {
		Success    bool     `json:"success"`
		Hostname   string   `json:"hostname"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("turnstile: decode Cloudflare response: %v", err)
		return false, err
	}
	if !result.Success {
		log.Printf("turnstile: Cloudflare rejected token — error-codes=%v hostname=%q (check Settings → CAPTCHA if this is a keys mismatch)",
			result.ErrorCodes, result.Hostname)
		return false, nil
	}
	return true, nil
}

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	n, err := models.CountUsers(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	data := captchaTemplateData(loadCaptchaConfig(s.DB))
	if r.URL.Query().Get("reset") == "1" {
		data["Reset"] = true
	}
	if r.URL.Query().Get("invited") == "1" {
		data["Invited"] = true
	}
	// issue #106: offer the SSO button when OIDC is configured; surface any
	// SSO error the callback bounced back with a friendly message.
	if oc := s.oidcConfig(); oc.ready() {
		data["OIDCEnabled"] = true
		data["OIDCButtonLabel"] = oc.ButtonLabel
	}
	if e := r.URL.Query().Get("error"); strings.HasPrefix(e, "sso") {
		msg := "Single sign-on failed. Try again or use your password."
		switch e {
		case "sso_nouser":
			msg = "No CaddyUI account matches your SSO identity. Ask an admin to add you."
		case "sso_email":
			msg = "Your identity provider didn't return a verified email address."
		case "sso_denied":
			msg = "Single sign-on was cancelled."
		}
		data["Error"] = msg
	}
	s.render(w, r, "login.html", data)
}

// sanitizeForLog escapes CR/LF in user-controlled strings before they land
// in a log line so an attacker can't smuggle a forged log entry by typing
// `victim@example.com\n[CRITICAL] system compromised` into a form field.
// Replaces newlines with their literal escape sequence so the original
// content is still readable for diagnosis without breaking line boundaries.
// v2.9.225 — addresses CodeQL "Log entries created from user input" finding
// on the forgot-password and invite handlers' log.Printf calls.
func sanitizeForLog(s string) string {
	return strings.NewReplacer("\n", "\\n", "\r", "\\r").Replace(s)
}

// clientIPFromRequest extracts the real client IP, preferring forwarded
// headers when present so installs behind a reverse proxy (the typical
// CaddyUI deployment — it sits behind the very Caddy it manages) record
// the actual visitor IP in activity_log instead of 127.0.0.1. Order:
// X-Real-IP → first entry of X-Forwarded-For → r.RemoteAddr (host portion).
// Returns the raw string with no normalisation; activity log just stores
// it as text for the operator to read. v2.9.210.
func clientIPFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-Ip")); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// Left-most entry is the original client; rest are intermediate hops.
		if i := strings.Index(v, ","); i >= 0 {
			v = v[:i]
		}
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// peerHost returns the immediate TCP peer's IP (the host portion of
// RemoteAddr, no port).
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// peerIsTrustedProxy reports whether the immediate peer may be trusted to have
// set X-Forwarded-For / X-Real-IP. When the admin has configured
// trusted_proxies, only those CIDRs/IPs are trusted. When it is empty we fall
// back to the standard CaddyUI topology — a reverse proxy sharing the host or
// LAN — and trust loopback and private/link-local peers only. A directly
// connected public client is never trusted, so it cannot forge the header.
func (s *Server) peerIsTrustedProxy(peerIP net.IP) bool {
	if peerIP == nil {
		return false
	}
	raw, _ := models.GetSetting(s.DB, settingTrustedProxies)
	if strings.TrimSpace(raw) == "" {
		return peerIP.IsLoopback() || peerIP.IsPrivate() || peerIP.IsLinkLocalUnicast()
	}
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, ipnet, err := net.ParseCIDR(entry); err == nil && ipnet.Contains(peerIP) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil && ip.Equal(peerIP) {
			return true
		}
	}
	return false
}

// rateLimitClientIP returns a client IP suitable as a security rate-limit key
// (e.g. the login brute-force limiter). Unlike clientIPFromRequest — which
// trusts forwarding headers unconditionally for activity-log display — this
// only honours X-Real-IP / X-Forwarded-For when the immediate peer is a trusted
// proxy, so a directly connected attacker cannot rotate a forged header to
// reset the lockout counter. When trusted, X-Real-IP (a single proxy-set value)
// wins; otherwise the right-most X-Forwarded-For entry is used, since that is
// the hop appended by the closest trusted proxy and is not client-spoofable.
func (s *Server) rateLimitClientIP(r *http.Request) string {
	peer := peerHost(r)
	if s.peerIsTrustedProxy(net.ParseIP(peer)) {
		if v := strings.TrimSpace(r.Header.Get("X-Real-Ip")); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			parts := strings.Split(v, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if p := strings.TrimSpace(parts[i]); p != "" {
					return p
				}
			}
		}
	}
	return peer
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	// v2.5.0: unified captcha (Turnstile OR reCAPTCHA v3, driven by the
	// captcha_provider setting). verifyCaptcha no-ops when disabled, so
	// handlers can call it unconditionally.
	captchaCfg := loadCaptchaConfig(s.DB)
	tplData := captchaTemplateData(captchaCfg)
	renderLoginErr := func(msg string) {
		data := map[string]any{"Error": msg}
		for k, v := range tplData {
			data[k] = v
		}
		s.render(w, r, "login.html", data)
	}
	if ok, err := verifyCaptcha(captchaCfg, r); err != nil || !ok {
		renderLoginErr("Security check failed. Please try again.")
		return
	}

	// v2.9.5: brute-force protection — check recent failed login attempts from this IP.
	// v2.9.210: use clientIPFromRequest so installs behind a reverse proxy
	// match by the actual visitor IP, not the proxy's loopback address.
	// v2.52.4: the rate-limit key uses rateLimitClientIP, which only trusts the
	// forwarded IP when the peer is a trusted proxy — a directly connected
	// attacker can no longer forge X-Forwarded-For / X-Real-IP to bypass the
	// lockout. Activity-log display below keeps clientIPFromRequest.
	clientIP := s.rateLimitClientIP(r)
	if maxStr, _ := models.GetSetting(s.DB, settingMaxLoginAttempts); maxStr != "" {
		if maxAttempts, err := strconv.Atoi(strings.TrimSpace(maxStr)); err == nil && maxAttempts > 0 {
			var failCount int
			_ = s.DB.QueryRow(
				`SELECT COUNT(*) FROM activity_log WHERE action = 'login_fail' AND detail LIKE ? AND created_at > ?`,
				"%ip:"+clientIP+"%",
				time.Now().UTC().Add(-15*time.Minute),
			).Scan(&failCount)
			if failCount >= maxAttempts {
				renderLoginErr("Too many failed login attempts. Please wait 15 minutes and try again.")
				return
			}
		}
	}

	email := strings.TrimSpace(r.FormValue("email"))
	pw := r.FormValue("password")
	u, err := models.GetUserByEmail(s.DB, email)
	if err != nil || !auth.CheckPassword(u.PasswordHash, pw) {
		_ = models.LogActivity(s.DB, 0, email, "login_fail", "ip:"+clientIP, "invalid credentials", false)
		renderLoginErr("Invalid email or password")
		return
	}
	if u.TOTPEnabled && u.TOTPSecret != "" {
		// Generate a pre-auth token and redirect to TOTP verification.
		b := make([]byte, 16)
		rand.Read(b)
		tok := hex.EncodeToString(b)
		s.pendingTOTP.Store(tok, u.ID)
		// Auto-expire after 5 minutes.
		go func() {
			time.Sleep(5 * time.Minute)
			s.pendingTOTP.Delete(tok)
		}()
		http.Redirect(w, r, "/login/totp?t="+tok, http.StatusSeeOther)
		return
	}
	tok, exp, err := auth.CreateSessionWithTTL(s.DB, u.ID, s.sessionTTL())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, r, tok, exp)
	// v2.9.210: surface successful logins in the activity feed so admins can
	// see who signed in from where. Detail carries the User-Agent for forensic
	// context (browser fingerprint mismatch on a teammate's account is useful
	// signal during an incident).
	_ = models.LogActivity(s.DB, 0, u.Email, "login_success", "ip:"+clientIP, r.UserAgent(), true)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	// v2.9.210: capture the actor before deleting the session so the activity
	// row gets the actual user's email rather than empty.
	cu := s.currentUser(r)
	actor := ""
	if cu != nil {
		actor = cu.Email
	}
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		_ = auth.DeleteSession(s.DB, c.Value)
	}
	auth.ClearSessionCookie(w, r)
	if actor != "" {
		_ = models.LogActivity(s.DB, 0, actor, "logout", "ip:"+clientIPFromRequest(r), "", true)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- TOTP / 2FA ---

// getTOTPVerify shows the TOTP code entry page.
func (s *Server) getTOTPVerify(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("t")
	if tok == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	data := captchaTemplateData(loadCaptchaConfig(s.DB))
	data["Token"] = tok
	s.render(w, r, "totp_verify.html", data)
}

// postTOTPVerify validates the TOTP code and creates a session.
func (s *Server) postTOTPVerify(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok := r.FormValue("token")
	code := strings.TrimSpace(r.FormValue("code"))

	// v2.5.0: captcha also gates the TOTP step. Rationale: /login and
	// /login/totp are separate endpoints, so a bot that cracks a password
	// without captcha here could still pound TOTP codes (1M combos) if
	// TOTP had no challenge. Cheap to add, meaningfully raises the floor.
	captchaCfg := loadCaptchaConfig(s.DB)
	tplData := captchaTemplateData(captchaCfg)
	renderTOTPErr := func(msg string) {
		data := map[string]any{"Token": tok, "Error": msg}
		for k, v := range tplData {
			data[k] = v
		}
		s.render(w, r, "totp_verify.html", data)
	}

	val, ok := s.pendingTOTP.Load(tok)
	if !ok {
		renderTOTPErr("Session expired. Please log in again.")
		return
	}

	if ok2, err := verifyCaptcha(captchaCfg, r); err != nil || !ok2 {
		// Don't delete the pendingTOTP token on captcha fail — let the
		// user retry with a fresh challenge. Captcha being wrong is an
		// "I am a bot probably" signal, not an "I burned my TOTP slot"
		// one. The 5-min auto-expire still caps abuse.
		renderTOTPErr("Security check failed. Please try again.")
		return
	}

	s.pendingTOTP.Delete(tok)

	userID := val.(int64)
	u, err := models.GetUserByID(s.DB, userID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	validTOTP := totplib.Validate(code, u.TOTPSecret)
	if !validTOTP {
		// Try as a single-use backup code.
		if u2, _ := models.GetUserByID(s.DB, userID); u2 != nil {
			if ok, _ := models.ConsumeBackupCode(s.DB, userID, u2.BackupCodes, code); ok {
				validTOTP = true
			}
		}
	}
	if !validTOTP {
		// Put token back so user can retry.
		s.pendingTOTP.Store(tok, userID)
		// v2.9.210: log failed TOTP attempts for the same forensic reason
		// as login_fail — repeated login_totp_fail rows from one IP signal
		// somebody got past the password but is brute-forcing the 2FA code.
		_ = models.LogActivity(s.DB, 0, u.Email, "login_totp_fail", "ip:"+clientIPFromRequest(r), "invalid TOTP code", false)
		renderTOTPErr("Invalid code. Try again.")
		return
	}

	sessionTok, exp, err := auth.CreateSessionWithTTL(s.DB, userID, s.sessionTTL())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, r, sessionTok, exp)
	// v2.9.210: log the second-factor success so the audit trail mirrors
	// the password-only login_success path.
	_ = models.LogActivity(s.DB, 0, u.Email, "login_totp_success", "ip:"+clientIPFromRequest(r), r.UserAgent(), true)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getTOTPSetup shows the TOTP setup page for the current user.
// totpQRDataURI renders an otpauth:// URI as a base64 PNG data URI so the 2FA
// setup page can show the QR code without loading a script from a CDN.
//
// v2.27.0: replaces the cdn.jsdelivr.net/npm/qrcode client-side render, which
// broke when that CDN path started returning 404 (issue #37) and was blocked
// by CORB besides. Rendering server-side also means 2FA setup works on an
// air-gapped install. github.com/boombuler/barcode already ships as an
// indirect dependency of pquerna/otp, so this adds no new module.
//
// The return type is template.URL, not string: html/template's contextual
// autoescaper rejects the data: scheme in a src attribute and substitutes
// "#ZgotmplZ", which renders as a broken image. Marking it safe is correct
// here — the value is built entirely server-side from base64-encoded PNG
// bytes, with no user-controlled input reaching the URL.
//
// Returns "" on error; the template falls back to the manual-entry secret,
// which is always displayed alongside the QR.
func totpQRDataURI(otpauthURI string) template.URL {
	key, err := otplib.NewKeyFromURL(otpauthURI)
	if err != nil {
		return ""
	}
	img, err := key.Image(320, 320)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()))
}

func (s *Server) getTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	key, err := totplib.Generate(totplib.GenerateOpts{
		Issuer:      "CaddyUI",
		AccountName: u.Email,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Backup codes passed as a one-time query param after enabling/regenerating.
	backupCodes := strings.Split(r.URL.Query().Get("backup_codes"), ",")
	if len(backupCodes) == 1 && backupCodes[0] == "" {
		backupCodes = nil
	}

	// Count remaining backup codes stored for this user.
	var backupCodeCount int
	if cu := s.currentUser(r); cu != nil && cu.BackupCodes != "" {
		var hashes []string
		if json.Unmarshal([]byte(cu.BackupCodes), &hashes) == nil {
			backupCodeCount = len(hashes)
		}
	}

	s.render(w, r, "totp_setup.html", map[string]any{
		"User":            u,
		"Secret":          key.Secret(),
		"OTPAuth":         key.URL(),
		"OTPQRCode":       totpQRDataURI(key.URL()),
		"TOTPEnabled":     u.TOTPEnabled,
		"Required":        r.URL.Query().Get("required") == "1",
		"Enforce":         r.URL.Query().Get("enforce") == "1",
		"BackupCodes":     backupCodes,
		"BackupCodeCount": backupCodeCount,
	})
}

// postTOTPSetup enables or disables TOTP for the current user.
func (s *Server) postTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	_ = r.ParseForm()
	action := r.FormValue("action")

	if action == "disable" {
		if err := models.SetUserTOTP(s.DB, u.ID, "", false); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/totp/setup?disabled=1", http.StatusSeeOther)
		return
	}

	// action == "enable": verify the submitted code against the submitted secret.
	secret := r.FormValue("secret")
	code := strings.TrimSpace(r.FormValue("code"))
	if !totplib.Validate(code, secret) {
		otpAuth := "otpauth://totp/CaddyUI:" + u.Email + "?secret=" + secret + "&issuer=CaddyUI"
		s.render(w, r, "totp_setup.html", map[string]any{
			"User":        u,
			"Secret":      secret,
			"OTPAuth":     otpAuth,
			"OTPQRCode":   totpQRDataURI(otpAuth),
			"Error":       "Invalid code — try again.",
			"TOTPEnabled": u.TOTPEnabled,
		})
		return
	}
	if err := models.SetUserTOTP(s.DB, u.ID, secret, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Generate fresh backup codes when TOTP is first enabled.
	if backupCodes, err := models.GenerateBackupCodes(10); err == nil {
		if err := models.SaveBackupCodes(s.DB, u.ID, backupCodes); err == nil {
			// Store codes in session flash or query param for one-time display.
			// Encode as comma-separated for URL safety.
			codesParam := strings.Join(backupCodes, ",")
			http.Redirect(w, r, "/totp/setup?enabled=1&backup_codes="+url.QueryEscape(codesParam), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/totp/setup?enabled=1", http.StatusSeeOther)
}

func (s *Server) postRegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil || !cu.TOTPEnabled {
		http.Redirect(w, r, "/totp/setup", http.StatusSeeOther)
		return
	}
	codes, err := models.GenerateBackupCodes(10)
	if err != nil {
		http.Error(w, "failed to generate codes", http.StatusInternalServerError)
		return
	}
	if err := models.SaveBackupCodes(s.DB, cu.ID, codes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	codesParam := strings.Join(codes, ",")
	http.Redirect(w, r, "/totp/setup?regen=1&backup_codes="+url.QueryEscape(codesParam), http.StatusSeeOther)
}

// --- Dashboard ---

type dashboardRecommendation struct {
	Severity string // "critical" | "warning" | "info"
	Title    string
	Detail   string
	URL      string
	Action   string
}

type dashboardRecommendationInput struct {
	IsAdmin           bool
	ProxyHosts        []models.ProxyHost
	RedirectionHosts  []models.RedirectionHost
	RawRoutes         []models.RawRoute
	Certificates      []models.Certificate
	Snapshots         []models.ConfigSnapshot
	DNSProfileIDs     map[string]bool
	LastSync          *time.Time
	DownCount         int
	MaintenanceCount  int
	GlobalMaintenance bool
	Require2FA        bool
	RequireTOTP       bool
	AdminAllowlistSet bool
	AutoSnapshots     bool
	DismissedUnused   string
	Now               time.Time
	// v2.39.0: best-known expiry per custom certificate (stored PEM, readable
	// file, or the last live TLS probe) — see customCertificateExpiries.
	// Callers that leave it nil still get stored-PEM expiries.
	CertificateExpiry map[int64]time.Time
}

func buildDashboardRecommendations(in dashboardRecommendationInput) []dashboardRecommendation {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	var out []dashboardRecommendation
	add := func(severity, title, detail, url, action string) {
		out = append(out, dashboardRecommendation{
			Severity: severity,
			Title:    title,
			Detail:   detail,
			URL:      url,
			Action:   action,
		})
	}

	if in.GlobalMaintenance {
		add("critical", "Global maintenance mode is active", "Every proxy host is serving the maintenance response until this is turned off and Caddy is synced.", "/settings/general", "Open settings")
	} else if in.MaintenanceCount > 0 {
		add("warning", "Proxy hosts are in maintenance", fmt.Sprintf("%d enabled proxy host(s) are currently serving maintenance responses.", in.MaintenanceCount), "/proxy-hosts?status=maintenance", "Review hosts")
	}
	if in.DownCount > 0 {
		add("critical", "Upstreams are down", fmt.Sprintf("%d enabled proxy host(s) have failing health checks.", in.DownCount), "/proxy-hosts", "View health")
	}

	sslOff := 0
	incompleteDNS := 0
	missingProfiles := 0
	referencedCerts := referencedCertificateIDs(in.ProxyHosts, in.RedirectionHosts, in.RawRoutes)
	for _, h := range in.ProxyHosts {
		if h.Enabled && !h.SSLEnabled {
			sslOff++
		}
		if h.DNSProvider != "" && h.DNSZoneID == "" {
			incompleteDNS++
		}
		if h.DNSProfileID != "" && !in.DNSProfileIDs[h.DNSProfileID] {
			missingProfiles++
		}
	}
	for _, h := range in.RedirectionHosts {
		if h.DNSProvider != "" && h.DNSZoneID == "" {
			incompleteDNS++
		}
		if h.DNSProfileID != "" && !in.DNSProfileIDs[h.DNSProfileID] {
			missingProfiles++
		}
	}
	for _, rr := range in.RawRoutes {
		if rr.DNSProvider != "" && rr.DNSZoneID == "" {
			incompleteDNS++
		}
		if rr.DNSProfileID != "" && !in.DNSProfileIDs[rr.DNSProfileID] {
			missingProfiles++
		}
	}
	if sslOff > 0 {
		add("warning", "Enabled hosts have SSL off", fmt.Sprintf("%d enabled proxy host(s) are reachable without Caddy-managed TLS.", sslOff), "/proxy-hosts", "Review TLS")
	}
	if incompleteDNS > 0 {
		add("warning", "Managed DNS is incomplete", fmt.Sprintf("%d resource(s) have a DNS provider selected but no zone saved yet.", incompleteDNS), "/proxy-hosts", "Review DNS")
	}
	if missingProfiles > 0 {
		add("critical", "DNS profile references are missing", fmt.Sprintf("%d resource(s) reference a deleted or unavailable DNS credential profile.", missingProfiles), "/settings/dns", "Fix profiles")
	}

	expiringSoon := 0
	expired := 0
	var unusedCustomCerts []models.Certificate
	for _, c := range in.Certificates {
		if isUnusedCustomCertificate(c, referencedCerts) {
			unusedCustomCerts = append(unusedCustomCerts, c)
		}
		if !isCustomCertificate(c) {
			continue
		}
		t, known := in.CertificateExpiry[c.ID]
		if !known && c.Source == models.CertSourcePEM {
			if e := parsePEMExpiry(c.CertPEM); e != nil {
				t, known = *e, true
			}
		}
		if !known {
			continue
		}
		if t.Before(now) {
			expired++
		} else if t.Sub(now) < 30*24*time.Hour {
			expiringSoon++
		}
	}
	if expired > 0 {
		add("critical", "Custom certificates are expired", fmt.Sprintf("%d custom certificate(s) are already expired.", expired), "/certificates", "Review certs")
	} else if expiringSoon > 0 {
		add("warning", "Custom certificates expire soon", fmt.Sprintf("%d custom certificate(s) expire within 30 days.", expiringSoon), "/certificates", "Review certs")
	}
	unusedFingerprint := unusedCertificateFingerprint(in.Certificates, referencedCerts)
	if in.IsAdmin && len(unusedCustomCerts) > 0 && unusedFingerprint != in.DismissedUnused {
		add(
			"info",
			"Unused custom certificates",
			fmt.Sprintf("%d certificate(s) are not assigned to any resource: %s.", len(unusedCustomCerts), summarizeCertificateNames(unusedCustomCerts, 3)),
			"/certificates?usage=unused",
			"Show unused",
		)
	}

	resourceCount := len(in.ProxyHosts) + len(in.RedirectionHosts) + len(in.RawRoutes)
	if resourceCount > 0 {
		if in.LastSync == nil {
			add("warning", "No successful sync recorded", "Resources exist, but the activity log has no successful Caddy sync for this server.", "/", "Sync Caddy")
		} else if now.Sub(*in.LastSync) > 7*24*time.Hour {
			add("info", "Last sync is over a week old", fmt.Sprintf("Last successful sync was %s ago.", humanDuration(now.Sub(*in.LastSync))), "/", "Sync Caddy")
		}
	}

	if in.IsAdmin {
		if !in.Require2FA && !in.RequireTOTP {
			add("warning", "2FA is not required", "Admins can enable required TOTP enrollment to reduce account-takeover risk.", "/settings/security", "Open security")
		}
		if !in.AdminAllowlistSet {
			add("info", "Admin IP allowlist is empty", "Restricting CaddyUI to trusted IPs or CIDRs can reduce exposure for homelab installs.", "/settings/security", "Open security")
		}
		if len(in.Snapshots) == 0 {
			add("warning", "No config snapshots yet", "Take a manual snapshot so there is a known-good Caddy config to restore.", "/snapshots", "Take snapshot")
		} else if !in.AutoSnapshots {
			add("info", "Auto-snapshots are disabled", "Manual snapshots still work, but pre-sync restore points will not be captured automatically.", "/snapshots", "Review snapshots")
		}
	}

	if len(out) > 6 {
		return out[:6]
	}
	return out
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d.Hours() / 24)
	if days >= 1 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	hours := int(d.Hours())
	if hours >= 1 {
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	minutes := int(d.Minutes())
	if minutes <= 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	sid := s.currentServerID(r)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	peers := s.groupPeerIDs(r)
	hosts, _ := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin, peers)
	redirs, _ := models.ListRedirectionHosts(s.DB, sid, viewerID, isAdmin, peers)
	raws, _ := models.ListRawRoutes(s.DB, sid, viewerID, isAdmin, peers)
	// v2.7.2: cert card count matches what the /certificates page will show —
	// admin sees every cert, user-role sees their uploads + globals.
	// v2.7.4: ...plus any teammate uploads from groups they share.
	certs, _ := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin, peers)

	// Most-recent sync timestamp from activity log (best-effort).
	var lastSync *time.Time
	var ls time.Time
	if err := s.DB.QueryRow(
		`SELECT created_at FROM activity_log WHERE server_id = ? AND action = 'sync_applied' ORDER BY id DESC LIMIT 1`, sid,
	).Scan(&ls); err == nil {
		lastSync = &ls
	}

	// Feature A: compute enabled/disabled counts and certs expiring within 30 days.
	var enabledHosts, disabledHosts, expiringSoon int
	for _, h := range hosts {
		if h.Enabled {
			enabledHosts++
		} else {
			disabledHosts++
		}
	}
	now := time.Now()
	for _, c := range certs {
		if t := parsePEMExpiry(c.CertPEM); t != nil {
			if t.Sub(now) < 30*24*time.Hour && t.After(now) {
				expiringSoon++
			}
		}
	}

	// v2.9.2: health summary — count hosts by latest check result.
	var healthyCount, downCount, unknownCount int
	if len(hosts) > 0 {
		var hostIDs []int64
		for _, h := range hosts {
			hostIDs = append(hostIDs, h.ID)
		}
		healthMap, _ := models.LatestProxyHealth(s.DB, hostIDs)
		for _, h := range hosts {
			if !h.Enabled {
				continue // only count enabled hosts
			}
			if chk, ok := healthMap[h.ID]; ok {
				if chk.OK {
					healthyCount++
				} else {
					downCount++
				}
			} else {
				unknownCount++
			}
		}
	}

	// Today's analytics stats are scoped by both visible hostname and the
	// selected fleet server. Hostname-only filtering is insufficient when two
	// nodes serve the same domain: it would merge both nodes back together even
	// after the operator switched environments.
	todayStart := time.Now().UTC().Truncate(24 * time.Hour)
	todayViews, todayVisitors := 0, 0
	var todayBandwidth int64
	hostsForActive := make([]string, 0, len(hosts)+len(redirs)+len(raws))
	for _, h := range hosts {
		hostsForActive = append(hostsForActive, h.DomainList()...)
	}
	for _, rh := range redirs {
		hostsForActive = append(hostsForActive, rh.DomainList()...)
	}
	for _, rr := range raws {
		hostsForActive = append(hostsForActive, rawRouteHosts(rr)...)
	}
	seenTrafficHosts := map[string]struct{}{}
	for _, host := range hostsForActive {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		hostKey := strings.ToLower(host)
		if _, seen := seenTrafficHosts[hostKey]; seen {
			continue
		}
		seenTrafficHosts[hostKey] = struct{}{}
		if t, err := models.AccessTotalsSince(s.DB, todayStart, host, sid); err == nil {
			todayViews += t.Views
			todayVisitors += t.Visitors
		}
		if bw, err := models.BandwidthSince(s.DB, todayStart, host, sid); err == nil {
			todayBandwidth += bw
		}
	}

	// Count hosts in maintenance mode for the dashboard banner.
	maintenanceCount := 0
	for _, h := range hosts {
		if h.MaintenanceMode {
			maintenanceCount++
		}
	}
	globalMaintenance, _ := models.GetSetting(s.DB, settingGlobalMaintenance)

	// v2.11.16: per-server health summary — one card per Caddy server
	// the user has registered, showing status / host count / last contact.
	// Aggregated cross-server (not just the active picker) so users with
	// 4+ servers don't have to flip the picker to spot a down node.
	type serverHealthRow struct {
		ID            int64
		Name          string
		AdminURL      string
		Status        string // "online" | "offline" | "unknown"
		Version       string
		HostCount     int
		LastContactAt time.Time // zero = never; fmtRel handles that
		IsExternal    bool
		IsActive      bool // matches the active server picker
	}
	var serverHealth []serverHealthRow
	if servers, err := models.ListCaddyServers(s.DB); err == nil && len(servers) > 1 {
		// Only render the widget when there's more than one server — single-
		// server installs don't benefit from a fleet view.
		for _, sr := range servers {
			row := serverHealthRow{
				ID: sr.ID, Name: sr.Name, AdminURL: sr.AdminURL,
				Status: sr.Status, Version: sr.Version,
				IsExternal: sr.Type == models.CaddyServerTypeExternal,
				IsActive:   sr.ID == sid,
			}
			if sr.LastContactAt.Valid {
				row.LastContactAt = sr.LastContactAt.Time
			}
			// Cheap host count — admin sees every host on every server.
			var n int
			_ = s.DB.QueryRow(`SELECT COUNT(*) FROM proxy_hosts WHERE server_id=?`, sr.ID).Scan(&n)
			row.HostCount = n
			serverHealth = append(serverHealth, row)
		}
	}

	// v2.11.12: "Recently edited" widget — pulls the last few CRUD events
	// from the activity log (skips login/sync/snapshot noise) so users
	// landing on the dashboard see at a glance what just changed.
	var recentEdits []models.Activity
	if all, err := models.ListActivity(s.DB, sid, 60); err == nil {
		for _, a := range all {
			if !a.Success {
				continue
			}
			if !isEditAction(a.Action) {
				continue
			}
			recentEdits = append(recentEdits, a)
			if len(recentEdits) >= 8 {
				break
			}
		}
	}

	dnsProfileIDs := map[string]bool{}
	for _, p := range s.loadDNSProfiles() {
		dnsProfileIDs[p.ID] = true
	}
	currentServer, _ := models.GetCaddyServer(s.DB, sid)
	serverReady := currentServer != nil && currentServer.Status == models.CaddyServerStatusOnline
	readinessSteps := requiredReadinessSteps(serverReady, cu != nil && cu.TOTPEnabled, len(hosts) > 0)
	showReadiness := isAdmin && (!serverReady || len(hosts) == 0 || cu == nil || !cu.TOTPEnabled)
	snapshots, _ := models.ListSnapshots(s.DB, sid, 1)
	require2FA := mustGetSetting(s.DB, settingRequire2FA) == "1"
	requireTOTP := mustGetSetting(s.DB, settingRequireTOTP) == "1"
	adminAllowlistSet := strings.TrimSpace(mustGetSetting(s.DB, settingAdminAllowlist)) != ""
	dismissedUnused := mustGetSetting(s.DB, unusedCertificateDismissalKey(sid))
	recommendations := buildDashboardRecommendations(dashboardRecommendationInput{
		IsAdmin:           isAdmin,
		ProxyHosts:        hosts,
		RedirectionHosts:  redirs,
		RawRoutes:         raws,
		Certificates:      certs,
		Snapshots:         snapshots,
		DNSProfileIDs:     dnsProfileIDs,
		LastSync:          lastSync,
		DownCount:         downCount,
		MaintenanceCount:  maintenanceCount,
		GlobalMaintenance: globalMaintenance == "1",
		Require2FA:        require2FA,
		RequireTOTP:       requireTOTP,
		AdminAllowlistSet: adminAllowlistSet,
		AutoSnapshots:     s.autoSnapshotsEnabled(),
		DismissedUnused:   dismissedUnused,
		CertificateExpiry: s.customCertificateExpiries(certs),
		Now:               time.Now(),
	})

	s.render(w, r, "dashboard.html", map[string]any{
		"User":                 s.currentUser(r),
		"ProxyHosts":           hosts,
		"RedirectionHosts":     redirs,
		"RawRoutes":            raws,
		"RawCount":             len(raws),
		"CertCount":            len(certs),
		"LastSync":             lastSync,
		"EnabledHosts":         enabledHosts,
		"DisabledHosts":        disabledHosts,
		"ExpiringSoon":         expiringSoon,
		"HealthyCount":         healthyCount,
		"DownCount":            downCount,
		"UnknownCount":         unknownCount,
		"TodayViews":           todayViews,
		"TodayVisitors":        todayVisitors,
		"TodayBandwidth":       todayBandwidth,
		"MaintenanceCount":     maintenanceCount,
		"GlobalMaintenance":    globalMaintenance,
		"EnabledHostCount":     enabledHosts,
		"MaintenanceHostCount": maintenanceCount,
		"RecentEdits":          recentEdits,
		"ServerHealth":         serverHealth,
		"Recommendations":      recommendations,
		"ShowReadiness":        showReadiness,
		"ReadinessSteps":       readinessSteps,
		"Section":              "dashboard",
	})
}

// isEditAction — v2.11.12: returns true when the activity-log action is a
// resource CRUD event the dashboard's "Recently edited" widget should
// surface. Skips login/logout, sync_applied, snapshot_*, profile_*, etc.
func isEditAction(action string) bool {
	prefixes := []string{"proxy_", "redirect_", "raw_", "cert_", "group_", "api_token_"}
	for _, p := range prefixes {
		if strings.HasPrefix(action, p) {
			return true
		}
	}
	return action == "caddyfile_import" || action == "import"
}

// --- Redirection Hosts ---
func (s *Server) listRedirectionHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	hosts, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "redirection_hosts.html", map[string]any{
		"User":     s.currentUser(r),
		"Hosts":    hosts,
		"Section":  "redirect",
		"ViewerID": viewerID,
	})
}

func (s *Server) newRedirectionHost(w http.ResponseWriter, r *http.Request) {
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "redirection_host_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         &models.RedirectionHost{Enabled: true, PreservePath: true, ForwardHTTPCode: 301, ForwardScheme: "auto", SSLEnabled: true, SSLForced: true},
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Section":      "redirect",
	}))
}

func parseRedirectionHostForm(r *http.Request) (*models.RedirectionHost, error) {
	_ = r.ParseForm()
	code, err := strconv.Atoi(r.FormValue("forward_http_code"))
	if err != nil {
		code = 301
	}
	certID, _ := strconv.ParseInt(r.FormValue("certificate_id"), 10, 64)
	// v2.12.2: Managed DNS triple — same shape as proxy hosts and raw routes.
	provider := strings.ToLower(strings.TrimSpace(r.FormValue("dns_provider")))
	profileID := strings.TrimSpace(r.FormValue("dns_profile_id"))
	zoneID := ""
	zoneName := ""
	if provider != "" {
		if _, ok := dns.Lookup(provider); !ok {
			provider = ""
		} else {
			zoneID = strings.TrimSpace(r.FormValue("dns_zone_id"))
			zoneName = strings.TrimSpace(r.FormValue("dns_zone_name"))
			if zoneID == "" {
				provider = ""
				zoneName = ""
			}
			if zoneName == "" {
				zoneName = zoneID
			}
		}
	}
	return &models.RedirectionHost{
		Domains:         strings.TrimSpace(r.FormValue("domains")),
		ForwardScheme:   r.FormValue("forward_scheme"),
		ForwardDomain:   strings.TrimSpace(r.FormValue("forward_domain")),
		ForwardHTTPCode: code,
		PreservePath:    r.FormValue("preserve_path") == "on",
		SSLEnabled:      r.FormValue("ssl_enabled") == "on",
		SSLForced:       r.FormValue("ssl_forced") == "on",
		Enabled:         r.FormValue("enabled") == "on",
		CertificateID:   certID,
		Tags:            strings.TrimSpace(r.FormValue("rh_tags")),
		Notes:           r.FormValue("rh_notes"),
		// v2.9.13: access control + maintenance mode
		AccessList:      strings.TrimSpace(r.FormValue("access_list")),
		MaintenanceMode: r.FormValue("maintenance_mode") == "on",
		MaintenanceMsg:  strings.TrimSpace(r.FormValue("maintenance_msg")),
		// v2.9.20: custom response headers
		CustomRespHeaders: func() string {
			v := strings.TrimSpace(r.FormValue("custom_resp_headers"))
			if v == "" {
				return "{}"
			}
			return v
		}(),
		// v2.9.21: IP blocklist
		IPBlocklist: strings.TrimSpace(r.FormValue("ip_blocklist")),
		// v2.9.24: HSTS
		HSTSMaxAgeSec:         func() int { v, _ := strconv.Atoi(r.FormValue("hsts_max_age_sec")); return v }(),
		HSTSIncludeSubdomains: r.FormValue("hsts_include_subdomains") == "on",
		HSTSPreload:           r.FormValue("hsts_preload") == "on",
		// v2.9.26: advanced config (raw JSON handlers)
		AdvancedConfig: strings.TrimSpace(r.FormValue("rh_advanced_config")),
		// v2.9.33: color label
		Color: strings.TrimSpace(r.FormValue("color")),
		// v2.9.38: maintenance status code
		MaintenanceStatusCode: func() int {
			v, _ := strconv.Atoi(r.FormValue("maintenance_status_code"))
			if v == 0 {
				return 503
			}
			return v
		}(),
		// v2.9.39: sort order
		SortOrder: func() int { v, _ := strconv.Atoi(r.FormValue("sort_order")); return v }(),
		// v2.9.229: path-based redirect rules. Form posts a JSON array via
		// a hidden input populated by the JS in redirection_host_form.html;
		// the dynamic table UI is the user-facing surface. Empty / invalid
		// JSON collapses to "" so the row keeps the legacy whole-host
		// redirect behaviour.
		RedirectRules: func() string {
			v := strings.TrimSpace(r.FormValue("redirect_rules"))
			if v == "" || v == "[]" {
				return ""
			}
			// Probe-parse so we don't store garbage that
			// RedirectRuleList would silently drop on read.
			var probe []models.RedirectRule
			if err := json.Unmarshal([]byte(v), &probe); err != nil {
				return ""
			}
			return v
		}(),
		// v2.9.230: redirect_strip_path_prefix
		RedirectStripPathPrefix: strings.TrimSpace(r.FormValue("redirect_strip_path_prefix")),
		// v2.9.231: redirect_wildcard_subdomain
		RedirectWildcardSubdomain: r.FormValue("redirect_wildcard_subdomain") == "on",
		// v2.9.232: sunset_at — accept ISO date YYYY-MM-DD; empty disables.
		SunsetAt: strings.TrimSpace(r.FormValue("sunset_at")),
		// v2.12.2: Managed DNS — wired to the same picker as proxy hosts.
		DNSProvider:   provider,
		DNSZoneID:     zoneID,
		DNSZoneName:   zoneName,
		DNSProfileID:  profileID,
		DNSSkipRecord: provider != "" && r.FormValue("dns_create_record") != "on",
	}, nil
}

func (s *Server) createRedirectionHost(w http.ResponseWriter, r *http.Request) {
	rh, err := parseRedirectionHostForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyRedirectionDNSFormSelection(rh)
	if errMsg := validateSSLFlags(rh.SSLEnabled, rh.SSLForced, rh.CertificateID); errMsg != "" {
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	// v2.7.7: same domain-conflict guard as proxy hosts. A redirect that
	// shadows an existing proxy (or vice versa) is a common mis-configuration
	// — Caddy keeps one route per hostname, so the older entry stops working
	// silently. Reject at save time instead.
	if conflict, err := models.DomainsConflict(s.DB, s.currentServerID(r), rh.DomainList(), 0, 0); err != nil {
		s.renderRedirectionHostFormError(w, r, rh, "Could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		s.renderRedirectionHostFormError(w, r, rh, fmt.Sprintf("Domain %q is already in use by another proxy or redirect on this server. Each domain can only be claimed once — edit the existing entry or remove it before reusing the name.", conflict))
		return
	}
	if errMsg := validateZoneMatchesHostname(rh.DNSProvider, rh.DNSZoneID, rh.DNSZoneName, rh.DomainList()); errMsg != "" {
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	if errMsg := s.validateManagedDNSRecordTarget(s.currentServerID(r), rh.DNSProvider, rh.DNSZoneID, rh.DNSSkipRecord); errMsg != "" {
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	deployTo := parseDeployTo(r)
	cu := s.currentUser(r)
	var rhOwnerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		rhOwnerID = cu.ID
	} else if cu != nil && cu.Role == models.RoleAdmin {
		// v2.7.3: admin can assign this redirect to a specific user at create
		// time via the form's Owner <select>. Same safety invariant as proxy
		// hosts — a non-admin never reaches this branch.
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				rhOwnerID = parsed
			}
		}
	}
	if errMsg := s.previewRedirectValidate(s.currentServerID(r), rh); errMsg != "" { // v2.42.1 (issue #74)
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	id, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), rhOwnerID, rh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rh.ID = id
	// v2.12.2: auto-create A record(s) per hostname when Managed DNS is set.
	if rh.DNSProvider != "" && rh.DNSZoneID != "" && !rh.DNSSkipRecord {
		s.dnsCreateRecordForRedirection(s.currentServerID(r), id, rh)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_create", fmt.Sprintf("redirect:%d", id), rh.Domains, true)
	s.trySyncCaddy(s.currentServerID(r), rh.CertificateID != 0)
	if len(deployTo) > 0 {
		s.crossDeployRedirectionHost(s.currentUserEmail(r), s.currentServerID(r), rh, deployTo)
	}
	http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
}

func (s *Server) editRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rh, err := models.GetRedirectionHost(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if !isAdmin {
		if !s.canManageOwned(cu, rh.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "redirection_host_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         rh,
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Section":      "redirect",
	}))
}

func (s *Server) updateRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	// Ownership check before parsing form
	if !isAdmin {
		existing, err := models.GetRedirectionHost(s.DB, id)
		if err != nil || existing == nil || !s.canManageOwned(cu, existing.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	rh, err := parseRedirectionHostForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rh.ID = id
	s.applyRedirectionDNSFormSelection(rh)
	if errMsg := validateSSLFlags(rh.SSLEnabled, rh.SSLForced, rh.CertificateID); errMsg != "" {
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	// v2.7.7: domain-conflict guard. excludeRedirectID=rh.ID keeps a no-op
	// edit (e.g. user toggling SSL on the same redirect) from flagging itself.
	if conflict, err := models.DomainsConflict(s.DB, s.currentServerID(r), rh.DomainList(), 0, rh.ID); err != nil {
		s.renderRedirectionHostFormError(w, r, rh, "Could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		s.renderRedirectionHostFormError(w, r, rh, fmt.Sprintf("Domain %q is already in use by another proxy or redirect on this server. Each domain can only be claimed once.", conflict))
		return
	}
	if errMsg := validateZoneMatchesHostname(rh.DNSProvider, rh.DNSZoneID, rh.DNSZoneName, rh.DomainList()); errMsg != "" {
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	if errMsg := s.validateManagedDNSRecordTarget(s.currentServerID(r), rh.DNSProvider, rh.DNSZoneID, rh.DNSSkipRecord); errMsg != "" {
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	deployTo := parseDeployTo(r)
	old, _ := models.GetRedirectionHost(s.DB, id)
	// v2.12.2: preserve existing record IDs across UPDATE so delete-on-change
	// still has them. parseRedirectionHostForm doesn't carry DNSRecordID
	// (the form has no hidden field for it — same as proxy hosts).
	if old != nil {
		rh.DNSRecordID = old.DNSRecordID
	}
	if errMsg := s.previewRedirectValidate(s.currentServerID(r), rh); errMsg != "" { // v2.42.1 (issue #74)
		s.renderRedirectionHostFormError(w, r, rh, errMsg)
		return
	}
	if err := models.UpdateRedirectionHost(s.DB, rh); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.12.2: DNS provider / zone changed → drop the old A records, create
	// fresh ones for the new triple. Same pattern as proxy hosts.
	if old != nil {
		oldKey := old.DNSProvider + "|" + old.DNSZoneID
		newKey := rh.DNSProvider + "|" + rh.DNSProfileID + "|" + rh.DNSZoneID
		oldKey = old.DNSProvider + "|" + old.DNSProfileID + "|" + old.DNSZoneID
		domainChanged := !slices.Equal(old.DomainList(), rh.DomainList())
		recordModeChanged := old.DNSSkipRecord != rh.DNSSkipRecord
		if oldKey != newKey || domainChanged || recordModeChanged {
			if old.DNSRecordID != "" {
				s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
				_ = models.UpdateRedirectionHostDNSRecord(s.DB, rh.ID, rh.DNSProvider, rh.DNSZoneID, rh.DNSZoneName, "")
				rh.DNSRecordID = ""
			}
			if rh.DNSProvider != "" && rh.DNSZoneID != "" && !rh.DNSSkipRecord {
				s.dnsCreateRecordForRedirection(s.currentServerID(r), rh.ID, rh)
			}
		} else if rh.DNSProvider != "" && rh.DNSZoneID != "" && !rh.DNSSkipRecord && rh.DNSRecordID == "" {
			// Same provider, but no record yet (first save with DNS chosen on edit).
			s.dnsCreateRecordForRedirection(s.currentServerID(r), rh.ID, rh)
		}
	}
	// v2.7.3: admin-only owner reassignment. Separate from UpdateRedirectionHost
	// so the user-role path (ownership-gated above) can never touch ownership.
	if isAdmin {
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				_ = models.SetRedirectionHostOwner(s.DB, rh.ID, parsed)
			}
		}
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_update", fmt.Sprintf("redirect:%d", id), rh.Domains, true)
	forceTLS := old != nil && old.CertificateID != rh.CertificateID
	s.trySyncCaddy(s.currentServerID(r), forceTLS)
	if len(deployTo) > 0 {
		s.crossDeployRedirectionHost(s.currentUserEmail(r), s.currentServerID(r), rh, deployTo)
	}
	http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
}

func (s *Server) deleteRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	old, _ := models.GetRedirectionHost(s.DB, id)
	if !isAdmin {
		if old == nil || !s.canManageOwned(cu, old.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	if err := models.DeleteRedirectionHost(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.12.2: drop the auto-created A record(s) so the row leaves nothing behind in DNS.
	if old != nil && old.DNSRecordID != "" {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_delete", fmt.Sprintf("redirect:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.trySyncCaddy(s.currentServerID(r), forceTLS)
	http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
}

// cloneRedirectionHost creates a copy of a redirection host with Enabled=false
// and a "(copy)" suffix on each domain, then redirects to its edit page.
func (s *Server) cloneRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	src, err := models.GetRedirectionHost(s.DB, id)
	if err != nil || src == nil {
		http.NotFound(w, r)
		return
	}
	// Append "(copy)" to each domain.
	domains := src.DomainList()
	cloned := make([]string, len(domains))
	for i, d := range domains {
		cloned[i] = d + " (copy)"
	}
	clone := *src
	clone.ID = 0
	clone.Domains = strings.Join(cloned, ",")
	clone.Enabled = false
	clone.MaintenanceMode = false
	clone.CreatedAt = time.Time{}
	clone.UpdatedAt = time.Time{}

	cu := s.currentUser(r)
	var ownerID int64
	if cu != nil {
		ownerID = cu.ID
	}
	newID, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), ownerID, &clone)
	if err != nil {
		http.Error(w, "clone failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/redirection-hosts/%d/edit", newID), http.StatusSeeOther)
}

func (s *Server) reloadCaddy(w http.ResponseWriter, r *http.Request) {
	if err := s.syncCaddy(s.currentServerID(r), true); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// v2.12.19: was returning 204 No Content + HX-Trigger header on the
	// assumption HTMX was driving the dashboard's "Sync Caddy" form. The
	// form is a plain <form method="post"> with no hx-* attributes, so
	// some browsers treated the empty Content-Type-less 204 from a form
	// POST as "save the URL's last segment as a file" — the user saw a
	// download named "reload" appear instead of a successful sync. Redirect
	// back to the dashboard (or the referrer if present) so the form-submit
	// completes cleanly without a body the browser has to interpret.
	//
	// v2.27.0: the leftover HX-Trigger header is gone too — htmx is no
	// longer loaded at all, so nothing was ever listening for it.
	dest := r.Header.Get("Referer")
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// --- Import from live Caddy ---

func (s *Server) getImport(w http.ResponseWriter, r *http.Request) {
	result, err := s.caddyForRequest(r).Import()
	data := map[string]any{
		"User":    s.currentUser(r),
		"Section": "import",
	}
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Result"] = result
	}
	s.render(w, r, "import.html", data)
}

func (s *Server) postImport(w http.ResponseWriter, r *http.Request) {
	result, err := s.caddyForRequest(r).Import()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Build a set of every hostname already represented in the DB — proxies,
	// redirects, AND raw routes. Re-import would otherwise duplicate raw routes
	// (they don't go through models.DomainsConflict) and re-creating conflicting
	// proxies/redirects would fail at sync when two entries claim the same host.
	// Use admin view (isAdmin=true) to see all existing entries for deduplication.
	taken := map[string]struct{}{}
	if existing, err := models.ListProxyHosts(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, h := range existing {
			for _, d := range h.DomainList() {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, h := range existing {
			for _, d := range h.DomainList() {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRawRoutes(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, rr := range existing {
			for _, d := range rawRouteHosts(rr) {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}
	claim := func(domains []string) bool {
		for _, d := range domains {
			if _, ok := taken[strings.ToLower(d)]; ok {
				return false
			}
		}
		for _, d := range domains {
			taken[strings.ToLower(d)] = struct{}{}
		}
		return true
	}

	// Import always creates global/admin-owned resources (ownerID=0).
	nProxy, nRedir, nRaw := 0, 0, 0
	for i := range result.Proxies {
		p := result.Proxies[i]
		if !claim(p.DomainList()) {
			continue
		}
		if _, err := models.CreateProxyHost(s.DB, s.currentServerID(r), 0, &p); err == nil {
			nProxy++
		}
	}
	for i := range result.Redirect {
		rd := result.Redirect[i]
		if !claim(rd.DomainList()) {
			continue
		}
		if _, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), 0, &rd); err == nil {
			nRedir++
		}
	}
	for i := range result.Passthrough {
		rr := result.Passthrough[i]
		if !claim(rawRouteHosts(rr)) {
			continue
		}
		if _, err := models.CreateRawRoute(s.DB, s.currentServerID(r), 0, &rr); err == nil {
			nRaw++
		}
	}
	detail := fmt.Sprintf("proxies=%d redirects=%d passthrough=%d", nProxy, nRedir, nRaw)
	log.Printf("import: %s imported", detail)
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "import", "", detail, true)
	// Don't sync to Caddy — user's existing config remains intact until they make a change
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

// rawRouteHosts pulls the top-level host matchers out of a RawRoute's JSONData.
// Handles both shapes: a single route object or an array of routes.
func rawRouteHosts(rr models.RawRoute) []string {
	var decoded any
	if err := json.Unmarshal([]byte(rr.JSONData), &decoded); err != nil {
		return nil
	}
	var hosts []string
	for _, route := range flattenToRouteMaps(decoded) {
		hosts = append(hosts, hostsFromRoute(route)...)
	}
	return hosts
}

// --- Caddyfile paste import ---
//
// Lets the user paste raw Caddyfile text. We call /adapt to convert each top-level
// site block to a single Caddy JSON route, then create one raw_route per block,
// storing both the JSON and the original Caddyfile snippet. The snippet is what
// the Advanced routes UI displays by default — users see the Caddyfile syntax
// they wrote, not Caddy's internal JSON.

func (s *Server) getCaddyfileImport(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "caddyfile_import.html", map[string]any{
		"User":    s.currentUser(r),
		"Section": "paste",
	})
}

type caddyfileImportResult struct {
	Head    string // site-address line (e.g. "example.com")
	Snippet string // original Caddyfile block
	Status  string // "created", "skipped", "error"
	// Kind, when Status == "created", is one of "proxy", "redirect", "raw" so
	// the import result table can show the user which list each block landed
	// in. Empty for skipped/error rows. v2.10.8.
	Kind     string
	Message  string // error message or ID info
	RouteIdx int
}

func (s *Server) postCaddyfileImport(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	src := strings.TrimSpace(r.FormValue("caddyfile"))
	if src == "" {
		s.render(w, r, "caddyfile_import.html", map[string]any{
			"User":    s.currentUser(r),
			"Section": "paste",
			"Error":   "Paste some Caddyfile text first.",
			"Input":   src,
		})
		return
	}

	// Auto-load snippet definitions from the mounted Caddyfile so users can use
	// `import <name>` without pasting the definition. We only prepend the
	// snippet blocks themselves — never site blocks or the global options block,
	// which would duplicate existing routes or clash with Caddy's single global
	// options restriction. Snippets the user already redefined in the paste are
	// skipped to avoid Caddy's duplicate-definition error.
	var loadedSnippets []string
	if s.CaddyfilePath != "" {
		if b, err := os.ReadFile(s.CaddyfilePath); err == nil {
			already := map[string]bool{}
			for _, snip := range caddy.ExtractSnippets(src) {
				already[caddy.HeadOfBlock(snip)] = true
			}
			for _, snip := range caddy.ExtractSnippets(string(b)) {
				if !already[caddy.HeadOfBlock(snip)] {
					loadedSnippets = append(loadedSnippets, snip)
				}
			}
		}
	}
	fullPaste := src
	if len(loadedSnippets) > 0 {
		fullPaste = strings.Join(loadedSnippets, "\n\n") + "\n\n" + src
	}

	// Adapt the ENTIRE paste as a single unit so cross-block references work:
	// `import <snippet>` must see `(<snippet>) { ... }` defined in the same paste,
	// and global options in `{ ... }` at the top apply to all site blocks below.
	// Adapting block-by-block would fail for any block using `import`.
	adapted, err := s.caddyForRequest(r).Adapt(fullPaste)
	if err != nil {
		hint := ""
		msg := err.Error()
		if strings.Contains(msg, "File to import not found") {
			hint = "This paste uses `import <name>` referring to a snippet that isn't included. " +
				"Paste the snippet definition `(<name>) { ... }` above the site block, or remove the `import` line."
		}
		s.render(w, r, "caddyfile_import.html", map[string]any{
			"User":    s.currentUser(r),
			"Section": "paste",
			"Error":   msg,
			"Hint":    hint,
			"Input":   src,
		})
		return
	}

	// v2.36.1 (issue #64): keep each route's server listen set so a block
	// like `:7070 { … }` lands on its own listener instead of :443/:80.
	adaptedRoutes := extractAdaptedServerRoutes(adapted.Result)
	routes := make([]map[string]any, 0, len(adaptedRoutes))
	routeListen := make([]string, 0, len(adaptedRoutes))
	for _, ar := range adaptedRoutes {
		routes = append(routes, ar.Route)
		routeListen = append(routeListen, models.NormalizeRawRouteListen(ar.Listen))
	}
	// v2.5.8: also pull per-site TLS automation policies (DNS-01 providers,
	// custom issuers) — these were previously dropped, so `tls { dns <p> ... }`
	// in a pasted block never reached Caddy and ACME fell back to HTTP-01.
	autoPolicies := extractAdaptedAutomationPolicies(adapted.Result)
	if len(routes) == 0 {
		s.render(w, r, "caddyfile_import.html", map[string]any{
			"User":    s.currentUser(r),
			"Section": "paste",
			"Error":   "Caddy adapted the text but it produced no HTTP routes. Make sure at least one site block is included.",
			"Input":   src,
		})
		return
	}

	// Build host -> original block map so each adapted route can be paired with
	// the source snippet the user typed. Snippet definitions and global-options
	// blocks have no host line and are ignored here.
	blockByHost := map[string]string{}
	for _, block := range caddy.SplitCaddyfileBlocks(src) {
		head := caddy.HeadOfBlock(block)
		if head == "" || strings.HasPrefix(head, "(") {
			continue
		}
		for _, h := range splitHostHeads(head) {
			blockByHost[h] = block
		}
	}

	// Build a set of every hostname already in the DB so re-pasting the same
	// Caddyfile is a no-op instead of silently creating duplicate raw_routes.
	// Mirrors the dedup logic in postImport — proxies, redirects, raw routes
	// all contribute. Admin view (isAdmin=true) so user-scoped rows are also
	// counted; Caddy resolves routes by host globally regardless of owner.
	taken := map[string]struct{}{}
	if existing, err := models.ListProxyHosts(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, h := range existing {
			for _, d := range h.DomainList() {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, h := range existing {
			for _, d := range h.DomainList() {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRawRoutes(s.DB, s.currentServerID(r), 0, true, nil); err == nil {
		for _, rr := range existing {
			for _, d := range rawRouteHosts(rr) {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}

	// v2.10.7: when auto_classify is on (default), each adapted route is
	// run through the same classifier the /import flow uses. Routes that
	// look like a simple host { reverse_proxy ... } become ProxyHost rows;
	// pure redir blocks become RedirectionHost rows; anything more exotic
	// (custom matchers, multiple handles the classifier can't decompose,
	// layer-4 stuff) falls back to RawRoute. Off → everything goes to raw,
	// matching the legacy behaviour.
	autoClassify := r.FormValue("auto_classify") != "off"

	var results []caddyfileImportResult
	created := 0
	cu := s.currentUser(r)
	var ownerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		ownerID = cu.ID
	}

	for idx, route := range routes {
		hosts := hostsFromRoute(route)
		var blockText string
		for _, h := range hosts {
			if b, ok := blockByHost[h]; ok {
				blockText = b
				break
			}
		}
		label := strings.Join(hosts, ",")
		if label == "" {
			label = fmt.Sprintf("route[%d] (no host match)", idx)
		}
		// Skip if any host on this route is already claimed elsewhere (proxy,
		// redirect, or another raw route). Report as "skipped" so the user can
		// see in the result table which blocks were no-ops vs. created.
		var conflict string
		for _, h := range hosts {
			if _, ok := taken[strings.ToLower(h)]; ok {
				conflict = h
				break
			}
		}
		if conflict != "" {
			results = append(results, caddyfileImportResult{
				Head: label, Snippet: blockText, RouteIdx: idx,
				Status:  "skipped",
				Message: fmt.Sprintf("hostname %q already claimed by an existing proxy, redirect, or raw route", conflict),
			})
			continue
		}
		// v2.10.7: try to classify this single route as proxy / redirect / raw
		// by wrapping it in a one-route synthetic server config and running
		// the same classifier the /import flow uses. The classifier returns
		// at most one entry per category for a single-route input — anything
		// it doesn't recognise falls through to RawRoute below.
		// v2.36.1 (issue #64): proxy hosts and redirects have no notion of a
		// listen port, so a block on a custom port must stay an Advanced route
		// or its port would be silently lost.
		if autoClassify && routeListen[idx] == "" {
			synth := map[string]any{
				"apps": map[string]any{
					"http": map[string]any{
						"servers": map[string]any{
							"_classify": map[string]any{
								"routes": []any{route},
							},
						},
					},
				},
			}
			classified := caddy.ClassifyConfig(synth)
			if len(classified.Proxies) == 1 {
				ph := classified.Proxies[0]
				ph.Enabled = true
				id, err := models.CreateProxyHost(s.DB, s.currentServerID(r), ownerID, &ph)
				if err != nil {
					results = append(results, caddyfileImportResult{
						Head: label, Snippet: blockText, RouteIdx: idx,
						Status: "error", Message: "create proxy host: " + err.Error(),
					})
					continue
				}
				for _, h := range hosts {
					taken[strings.ToLower(h)] = struct{}{}
				}
				created++
				results = append(results, caddyfileImportResult{
					Head: label, Snippet: blockText, RouteIdx: idx,
					Status: "created", Kind: "proxy",
					Message: fmt.Sprintf("proxy_host:%d", id),
				})
				continue
			}
			if len(classified.Redirect) == 1 {
				rh := classified.Redirect[0]
				rh.Enabled = true
				id, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), ownerID, &rh)
				if err != nil {
					results = append(results, caddyfileImportResult{
						Head: label, Snippet: blockText, RouteIdx: idx,
						Status: "error", Message: "create redirection: " + err.Error(),
					})
					continue
				}
				for _, h := range hosts {
					taken[strings.ToLower(h)] = struct{}{}
				}
				created++
				results = append(results, caddyfileImportResult{
					Head: label, Snippet: blockText, RouteIdx: idx,
					Status: "created", Kind: "redirect",
					Message: fmt.Sprintf("redirection:%d", id),
				})
				continue
			}
			// Classifier didn't recognise it as proxy or redirect — fall
			// through to raw_route below.
		}
		blob, err := json.Marshal(route)
		if err != nil {
			results = append(results, caddyfileImportResult{
				Head: label, Snippet: blockText, RouteIdx: idx,
				Status: "error", Message: "serialize route: " + err.Error(),
			})
			continue
		}
		id, err := models.CreateRawRoute(s.DB, s.currentServerID(r), ownerID, &models.RawRoute{
			Label:        label,
			JSONData:     string(blob),
			CaddyfileSrc: blockText,
			Enabled:      true,
			Listen:       routeListen[idx], // v2.36.1 (issue #64)
		})
		if err != nil {
			results = append(results, caddyfileImportResult{
				Head: label, Snippet: blockText, RouteIdx: idx,
				Status: "error", Message: err.Error(),
			})
			continue
		}
		// Reserve hosts of this newly-created route so a later block in the
		// same paste can't shadow it.
		for _, h := range hosts {
			taken[strings.ToLower(h)] = struct{}{}
		}
		created++
		results = append(results, caddyfileImportResult{
			Head: label, Snippet: blockText, RouteIdx: idx,
			Status: "created", Kind: "raw",
			Message: fmt.Sprintf("raw_route:%d", id),
		})
	}

	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "caddyfile_import", "",
		fmt.Sprintf("routes=%d created=%d", len(routes), created), created > 0)

	if created > 0 {
		// Sync so new routes take effect immediately. Don't force TLS — new
		// raw_routes don't change cert assignments.
		if err := s.syncCaddy(s.currentServerID(r), false); err != nil {
			s.render(w, r, "caddyfile_import.html", map[string]any{
				"User":    s.currentUser(r),
				"Section": "paste",
				"Error":   "Imported to DB but sync to Caddy failed: " + err.Error(),
				"Results": results,
				"Input":   src,
			})
			return
		}
		// v2.5.8: push any per-site TLS automation policies the adapter
		// emitted. Merged into live apps.tls.automation, deduped by subject
		// against existing policies so we never clobber hand-set config.
		// Non-fatal: if this fails, routes are still saved + synced, but
		// users should check Caddy logs since ACME may fall back to HTTP-01.
		if err := s.pushAutomationPolicies(r, autoPolicies); err != nil {
			log.Printf("caddyfile import: automation-policy push failed (%d policies): %v", len(autoPolicies), err)
		}
	}

	// v2.10.8: per-kind tallies for the result banner so users can see at
	// a glance "2 proxies, 1 redirection, 0 advanced" instead of a flat
	// "imported 3 routes". Kind is empty for skipped/error rows so they
	// don't inflate the success counts.
	var nProxy, nRedir, nRaw int
	for _, res := range results {
		switch res.Kind {
		case "proxy":
			nProxy++
		case "redirect":
			nRedir++
		case "raw":
			nRaw++
		}
	}
	s.render(w, r, "caddyfile_import.html", map[string]any{
		"User":         s.currentUser(r),
		"Section":      "paste",
		"Results":      results,
		"Created":      created,
		"CreatedProxy": nProxy,
		"CreatedRedir": nRedir,
		"CreatedRaw":   nRaw,
		"Input":        "",
	})
}

// splitHostHeads splits a Caddyfile site-address line into individual hosts.
// Caddyfile allows multiple addresses separated by commas or whitespace,
// e.g. "example.com, www.example.com" or "example.com www.example.com".
func splitHostHeads(head string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(head, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hostsFromRoute pulls hostnames out of a Caddy route's match array.
func hostsFromRoute(route map[string]any) []string {
	matches, _ := route["match"].([]any)
	var out []string
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		hs, _ := mm["host"].([]any)
		for _, h := range hs {
			if s, ok := h.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// adaptedServerRoute is one route from an adapted Caddy config together with
// the listen addresses of the server it came from. v2.36.1 (issue #64): the
// Caddyfile adapter emits one server per distinct site address — `:7070 { … }`
// becomes its own server on :7070 — and flattening every server's routes into
// one list silently dropped that port, so the route ended up on CaddyUI's
// :443/:80 servers and nothing ever listened on 7070.
type adaptedServerRoute struct {
	Route  map[string]any
	Listen []string
}

// extractAdaptedServerRoutes pulls every apps.http.servers.*.routes[] entry
// from an adapted Caddy config, tagged with its server's listen addresses.
// Servers are visited in name order so the result is deterministic.
func extractAdaptedServerRoutes(cfg map[string]any) []adaptedServerRoute {
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []adaptedServerRoute
	for _, name := range names {
		srv, _ := servers[name].(map[string]any)
		var listen []string
		if raw, ok := srv["listen"].([]any); ok {
			for _, v := range raw {
				if addr, ok := v.(string); ok && strings.TrimSpace(addr) != "" {
					listen = append(listen, strings.TrimSpace(addr))
				}
			}
		}
		routes, _ := srv["routes"].([]any)
		for _, r := range routes {
			if m, ok := r.(map[string]any); ok {
				out = append(out, adaptedServerRoute{Route: m, Listen: listen})
			}
		}
	}
	return out
}

// extractAdaptedRoutes is extractAdaptedServerRoutes without the listen
// addresses, for callers that only want handlers (proxy advanced_config) or a
// preview. Returns a possibly-empty slice.
func extractAdaptedRoutes(cfg map[string]any) []map[string]any {
	var out []map[string]any
	for _, ar := range extractAdaptedServerRoutes(cfg) {
		out = append(out, ar.Route)
	}
	return out
}

// extractAdaptedAutomationPolicies pulls apps.tls.automation.policies[] from an
// adapted Caddy config. These are emitted when a site block carries a per-site
// TLS directive like `tls { dns cloudflare {env.CF_API_TOKEN} }` or `tls { issuer ... }`.
// Without capturing them on paste-import the DNS-01 / custom-issuer config would
// be silently lost, since syncCaddy intentionally leaves apps.tls.automation
// untouched to avoid cancelling in-flight ACME challenges.
func extractAdaptedAutomationPolicies(cfg map[string]any) []map[string]any {
	apps, _ := cfg["apps"].(map[string]any)
	tlsApp, _ := apps["tls"].(map[string]any)
	automation, _ := tlsApp["automation"].(map[string]any)
	policies, _ := automation["policies"].([]any)
	var out []map[string]any
	for _, p := range policies {
		if m, ok := p.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// mergeAutomationPolicies makes incoming subject-scoped policies authoritative
// for those subjects while preserving unrelated and catch-all live policies.
// This is reconciliation rather than append-only merging: changing a Managed
// DNS provider/zone must replace the stale policy that previously owned a name.
func mergeAutomationPolicies(existing []any, incoming []map[string]any) []any {
	claimed := map[string]bool{}
	var prepend []any
	for _, p := range incoming {
		subs, _ := p["subjects"].([]any)
		var keptSubs []any
		for _, s := range subs {
			str, ok := s.(string)
			if !ok {
				continue
			}
			if !claimed[str] {
				keptSubs = append(keptSubs, str)
				claimed[str] = true
			}
		}
		if len(keptSubs) == 0 {
			continue
		}
		cp := map[string]any{}
		for k, v := range p {
			cp[k] = v
		}
		cp["subjects"] = keptSubs
		prepend = append(prepend, cp)
	}
	var preserved []any
	for _, policy := range existing {
		m, ok := policy.(map[string]any)
		if !ok {
			preserved = append(preserved, policy)
			continue
		}
		subs, hasSubjects := m["subjects"].([]any)
		if !hasSubjects {
			preserved = append(preserved, policy) // catch-all policy
			continue
		}
		kept := make([]any, 0, len(subs))
		for _, subject := range subs {
			name, ok := subject.(string)
			if !ok || !claimed[name] {
				kept = append(kept, subject)
			}
		}
		if len(kept) == 0 {
			continue
		}
		cp := map[string]any{}
		for k, v := range m {
			cp[k] = v
		}
		cp["subjects"] = kept
		preserved = append(preserved, cp)
	}
	return append(prepend, preserved...)
}

// buildDNSAutomationPolicies scans SSL-enabled hosts that have Managed DNS
// selected and emits an apps.tls.automation.policies[] entry per credential
// profile. This makes DNS-01 an explicit consequence of choosing Managed DNS,
// for ordinary names as well as wildcard SANs.
//
// Reuses the credentials already stored under each provider's settings
// keys for managed DNS, so users don't enter secrets twice. The connected
// Caddy build must include the corresponding caddy-dns provider module.
func (s *Server) buildDNSAutomationPolicies(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute, certs []models.Certificate) []map[string]any {
	type bucket struct {
		providerID string
		zoneID     string
		subjects   []string
		seen       map[string]bool
		creds      map[string]string
	}
	byProvider := map[string]*bucket{}

	add := func(domains []string, providerID, profileID, zoneID string, sslOn, enabled bool, certificateID int64) {
		if !enabled || !sslOn || certificateID != 0 || providerID == "" {
			return
		}
		for _, raw := range domains {
			d := models.NormalizeHostname(raw)
			if d == "" {
				continue
			}
			key := providerID + "|" + profileID
			if providerID == dns.Route53 {
				key += "|" + strings.TrimSpace(zoneID)
			}
			b, ok := byProvider[key]
			if !ok {
				if _, found := dns.Lookup(providerID); !found {
					return
				}
				b = &bucket{
					providerID: providerID,
					zoneID:     strings.TrimSpace(zoneID),
					creds:      s.dnsCredsFor(providerID, profileID),
					seen:       map[string]bool{},
				}
				byProvider[key] = b
			}
			if b.seen[d] {
				continue
			}
			b.seen[d] = true
			b.subjects = append(b.subjects, d)
		}
	}
	for _, p := range proxies {
		if p.InternalTLS {
			// v2.46.0: internal-CA hosts are issued by the internal issuer
			// (see buildInternalTLSAutomationPolicies), never DNS-01.
			continue
		}
		add(p.DomainList(), p.DNSProvider, p.DNSProfileID, p.DNSZoneID, p.SSLEnabled, p.Enabled, p.CertificateID)
	}
	for _, rd := range redirs {
		add(rd.DomainList(), rd.DNSProvider, rd.DNSProfileID, rd.DNSZoneID, rd.SSLEnabled, rd.Enabled, rd.CertificateID)
	}
	for _, rr := range raws {
		add(rawRouteHosts(rr), rr.DNSProvider, rr.DNSProfileID, rr.DNSZoneID, true, rr.Enabled, rr.CertificateID)
	}
	for _, cert := range certs {
		if cert.Source == models.CertSourceManaged {
			add(cert.DomainList(), cert.DNSProvider, cert.DNSProfileID, "", true, true, 0)
		}
	}

	var policies []map[string]any
	for _, b := range byProvider {
		if len(b.subjects) == 0 {
			continue
		}
		cfg := caddyDNSProviderConfig(b.providerID, b.creds, b.zoneID)
		if cfg == nil {
			log.Printf("automation: skipping provider %q — DNS-01 mapping not implemented or credentials missing", b.providerID)
			continue
		}
		// Convert []string → []any for the JSON marshaller.
		subj := make([]any, 0, len(b.subjects))
		for _, s := range b.subjects {
			subj = append(subj, s)
		}
		policies = append(policies, map[string]any{
			"subjects": subj,
			"issuers": []any{map[string]any{
				"module": "acme",
				"challenges": map[string]any{
					"dns": map[string]any{
						"provider": cfg,
					},
				},
			}},
		})
	}
	return policies
}

// buildInternalTLSAutomationPolicies emits a single apps.tls.automation
// policy that issues certificates from Caddy's internal (self-signed) CA for
// every enabled, SSL-enabled proxy host that opted into InternalTLS and is on
// Auto TLS (no custom certificate). The `internal` issuer is a core Caddy
// module, so — unlike DNS-01 — this needs no special Caddy build. Intended for
// local-network services where a publicly trusted certificate isn't wanted or
// possible. (discussion #91)
func buildInternalTLSAutomationPolicies(proxies []models.ProxyHost) []map[string]any {
	seen := map[string]bool{}
	var subjects []any
	for _, p := range proxies {
		if !p.Enabled || !p.SSLEnabled || !p.InternalTLS || p.CertificateID != 0 {
			continue
		}
		for _, raw := range p.DomainList() {
			d := models.NormalizeHostname(raw)
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			subjects = append(subjects, d)
		}
	}
	if len(subjects) == 0 {
		return nil
	}
	return []map[string]any{{
		"subjects": subjects,
		"issuers":  []any{map[string]any{"module": "internal"}},
	}}
}

// buildManagedCertificateRoutes gives standalone managed certificates a host
// matcher so Caddy's Automatic HTTPS machinery is instructed to obtain them.
// Automation-policy subjects alone are filters and do not trigger issuance.
// These 404 fallbacks are appended after real routes, so an actual proxy or
// redirect for the same hostname wins while otherwise-unhandled wildcard
// traffic fails closed.
func buildManagedCertificateRoutes(certs []models.Certificate) []any {
	var routes []any
	for _, cert := range certs {
		if cert.Source != models.CertSourceManaged {
			continue
		}
		hosts := cert.DomainList()
		if len(hosts) == 0 {
			continue
		}
		hostValues := make([]any, 0, len(hosts))
		for _, host := range hosts {
			if host = models.NormalizeHostname(host); host != "" {
				hostValues = append(hostValues, host)
			}
		}
		if len(hostValues) == 0 {
			continue
		}
		routes = append(routes, map[string]any{
			"match": []any{map[string]any{"host": hostValues}},
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": 404,
			}},
			"terminal": true,
		})
	}
	return routes
}

// caddyDNSProviderConfig maps an internal DNS-provider ID to the matching
// Caddy DNS plugin's JSON config block. Returns nil when the credential
// fields haven't been populated under Settings → DNS providers, OR when
// the internal provider has no caddy-dns plugin mapping yet.
//
// The Caddy build must include the matching `caddy-dns/<provider>` plugin
// (xcaddy or a custom Dockerfile). The default `caddy:2-alpine` image
// has no DNS plugins — Caddy will reject the config with "unknown module"
// at apply time, surfacing as a sync_apply_tls_failed activity log.
func caddyDNSProviderConfig(providerID string, creds map[string]string, zoneID string) map[string]any {
	switch providerID {
	case dns.Cloudflare:
		token := creds["cf_api_token"]
		if token == "" {
			return nil
		}
		return map[string]any{"name": "cloudflare", "api_token": token}
	case dns.Porkbun:
		key, secret := creds["pb_api_key"], creds["pb_secret_key"]
		if key == "" || secret == "" {
			return nil
		}
		return map[string]any{"name": "porkbun", "api_key": key, "api_secret_key": secret}
	case dns.Namecheap:
		user, key, clientIP := creds["nc_api_user"], creds["nc_api_key"], creds["nc_client_ip"]
		if user == "" || key == "" || clientIP == "" {
			return nil
		}
		return map[string]any{"name": "namecheap", "user": user, "api_key": key, "client_ip": clientIP}
	case dns.GoDaddy:
		key, secret := creds["gd_api_key"], creds["gd_api_secret"]
		if key == "" || secret == "" {
			return nil
		}
		return map[string]any{"name": "godaddy", "api_token": key + ":" + secret}
	case dns.DigitalOcean:
		token := creds["do_api_token"]
		if token == "" {
			return nil
		}
		return map[string]any{"name": "digitalocean", "auth_token": token}
	case dns.Hetzner:
		token := creds["hetzner_api_token"]
		if token == "" {
			return nil
		}
		return map[string]any{"name": "hetzner", "api_token": token}
	case dns.Gandi: // v2.45.0 — github.com/caddy-dns/gandi takes the same PAT as CaddyUI
		token := strings.TrimSpace(creds[settingGandiAPIToken])
		if token == "" {
			return nil
		}
		return map[string]any{"name": "gandi", "bearer_token": token}
	case dns.Route53:
		accessKey := strings.TrimSpace(creds[settingRoute53AccessKeyID])
		secretKey := strings.TrimSpace(creds[settingRoute53SecretAccessKey])
		if accessKey == "" || secretKey == "" {
			return nil
		}
		region := strings.TrimSpace(creds[settingRoute53Region])
		if region == "" {
			region = "us-east-1"
		}
		cfg := map[string]any{
			"name":              "route53",
			"access_key_id":     accessKey,
			"secret_access_key": secretKey,
			"region":            region,
		}
		if token := strings.TrimSpace(creds[settingRoute53SessionToken]); token != "" {
			cfg["session_token"] = token
		}
		if zoneID = strings.TrimSpace(zoneID); zoneID != "" {
			cfg["hosted_zone_id"] = zoneID
		}
		return cfg
	}
	return nil
}

// pushAutomationPolicies reads the live apps.tls.automation object, merges the
// given incoming policies in front of existing ones (deduped by subject), and
// POSTs the updated automation object back so Caddy applies the new DNS-01 /
// custom-issuer config without disturbing anything already in place.
func (s *Server) pushAutomationPolicies(r *http.Request, incoming []map[string]any) error {
	if len(incoming) == 0 {
		return nil
	}
	return pushAutomationPoliciesVia(s.caddyForRequest(r), incoming)
}

func applyAutomationPolicies(cfg map[string]any, incoming []map[string]any) {
	if len(incoming) == 0 {
		return
	}
	apps := ensureMap(cfg, "apps")
	tlsApp := ensureMap(apps, "tls")
	automation := ensureMap(tlsApp, "automation")
	existing, _ := automation["policies"].([]any)
	automation["policies"] = mergeAutomationPolicies(existing, incoming)
}

// pushAutomationPoliciesVia — v2.12.0: client-explicit variant of
// pushAutomationPolicies. syncCaddy already swaps s.Caddy to a per-server
// client and operates without an http.Request; this lets that path push
// auto-detected wildcard policies on the same client without re-deriving
// from a request cookie.
func pushAutomationPoliciesVia(cl *caddy.Client, incoming []map[string]any) error {
	if len(incoming) == 0 || cl == nil {
		return nil
	}
	cfg, _, err := cl.FetchConfig()
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}
	apps := ensureMap(cfg, "apps")
	tlsApp, tlsAppExists := apps["tls"].(map[string]any)
	if tlsApp == nil {
		tlsApp = map[string]any{}
	}
	automation, _ := tlsApp["automation"].(map[string]any)
	if automation == nil {
		automation = map[string]any{}
	}
	existing, _ := automation["policies"].([]any)
	automation["policies"] = mergeAutomationPolicies(existing, incoming)
	// A fresh Caddy JSON config commonly has apps.http but no apps.tls.
	// Caddy's admin API can create the final path segment with POST, but it
	// cannot traverse a missing parent, so POST /config/apps/tls/automation
	// fails with "invalid traversal path". Create the TLS app in that case.
	if !tlsAppExists {
		tlsApp["automation"] = automation
		return cl.PutPath("/config/apps/tls", tlsApp)
	}
	return cl.PutPath("/config/apps/tls/automation", automation)
}

// --- Snapshots ---

// settingAutoSnapshots gates creation of "auto" snapshots (pre-sync, pre-restore).
// Stored in the settings table; default ON ("1"). Users can turn off when they
// don't want a snapshot every sync filling the DB.
const settingAutoSnapshots = "auto_snapshots_enabled"

// settingRequire2FA gates 2FA enforcement: when "1", users without TOTP enabled
// are redirected to /totp/setup before accessing any page.
const settingRequire2FA = "require_2fa"

// settingRequireTOTP forces all users to enroll TOTP before accessing protected pages.
const settingRequireTOTP = "require_totp"

// settingSessionDays is the admin-configured session lifetime in days.
// Default is 7 days when empty or invalid.
const settingSessionDays = "session_duration_days"

// settingCatchAll404HTML holds optional HTML for a global catch-all 404 route
// appended last in the merged Caddy config so it fires only when no
// proxy/redirect/raw route matched.
const settingCatchAll404HTML = "catch_all_404_html"

// settingGlobalMaintenance puts ALL proxy hosts into maintenance mode when "1".
// A catch-all 503 route is prepended to the Caddy routes list so every request
// gets a maintenance page regardless of individual host settings.
const settingGlobalMaintenance = "global_maintenance"

// settingAutoSyncHours is the interval (in hours) for automatic periodic Caddy
// re-syncs. 0 or empty = disabled. The background loop checks once per hour
// and re-syncs if the elapsed time since the last sync_applied log entry
// exceeds this value.
const settingAutoSyncHours = "auto_sync_hours"

// settingTrustedProxies holds newline or comma-separated CIDRs/IPs of trusted
// reverse-proxies (e.g. Cloudflare, load balancers). When non-empty, CaddyUI
// injects trusted_proxies into the Caddy HTTP server config so that the real
// client IP is extracted from X-Forwarded-For.
const settingTrustedProxies = "trusted_proxies"

// settingSiteTitle is the custom display name shown in the browser tab title
// and the sidebar logo area. Falls back to "CaddyUI" when empty.
const settingSiteTitle = "site_title"

// settingFaviconURL is an optional URL for a custom favicon. When set, the
// layout <head> will use it instead of the default inline SVG favicon.
const settingFaviconURL = "favicon_url"

// settingAdminAllowlist holds newline or comma-separated IPs/CIDRs that are
// permitted to access the CaddyUI admin panel. When empty, all IPs are allowed.
const settingAdminAllowlist = "admin_allowlist"

// settingGlobalIPBlocklist holds newline or comma-separated IPs/CIDRs blocked
// across every host (v2.50.0, issue #100). Applied as a top-level 403 route on
// the main HTTP(S) servers, ahead of host routing. Empty = nothing blocked.
const settingGlobalIPBlocklist = "global_ip_blocklist"

// settingActivityLogDays specifies how many days to keep activity log entries.
// 0 or empty = keep forever (default).
const settingActivityLogDays = "activity_log_days"

// settingMaxLoginAttempts limits consecutive failed login attempts per IP within
// a 15-minute window. 0 or empty = no limit (default).
const settingMaxLoginAttempts = "max_login_attempts"

func (s *Server) autoSnapshotsEnabled() bool {
	v, err := models.GetSetting(s.DB, settingAutoSnapshots)
	if err != nil || v == "" {
		return true
	}
	return v == "1" || strings.EqualFold(v, "true")
}

func (s *Server) listSnapshots(w http.ResponseWriter, r *http.Request) {
	snaps, err := models.ListSnapshots(s.DB, s.currentServerID(r), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "snapshots.html", map[string]any{
		"User":          s.currentUser(r),
		"Snapshots":     snaps,
		"AutoSnapshots": s.autoSnapshotsEnabled(),
		"Section":       "snapshots",
	})
}

func (s *Server) setAutoSnapshots(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	on := r.FormValue("enabled") == "1"
	val := "0"
	if on {
		val = "1"
	}
	if err := models.SetSetting(s.DB, settingAutoSnapshots, val); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "auto_snapshots_toggled", "", val, true)
	http.Redirect(w, r, "/snapshots", http.StatusSeeOther)
}

func (s *Server) currentUserEmail(r *http.Request) string {
	u := s.currentUser(r)
	if u == nil {
		return "system"
	}
	return u.Email
}

const serverCookie = "caddyui_server"

// currentServerID returns the ID of the server selected via cookie, defaulting
// to 1 (the seeded primary server) if the cookie is absent or invalid.
func (s *Server) currentServerID(r *http.Request) int64 {
	if c, err := r.Cookie(serverCookie); err == nil {
		if id, err := strconv.ParseInt(c.Value, 10, 64); err == nil && id > 0 {
			return id
		}
	}
	return 1
}

// caddyForRequest returns a Caddy client pointed at the currently-selected
// server's admin API. Falls back to the primary client on any lookup error.
// Credentials (if set on the server row) are threaded into the client so
// admins can lock the admin API behind HTTP Basic Auth via a reverse proxy.
func (s *Server) caddyForRequest(r *http.Request) *caddy.Client {
	if srv, err := models.GetCaddyServer(s.DB, s.currentServerID(r)); err == nil {
		return caddy.New(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	}
	return s.Caddy
}

// caddyForServer returns a Caddy client for an explicit server ID.
func (s *Server) caddyForServer(serverID int64) *caddy.Client {
	if srv, err := models.GetCaddyServer(s.DB, serverID); err == nil {
		return caddy.New(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	}
	return s.Caddy
}

func (s *Server) createManualSnapshot(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	note := strings.TrimSpace(r.FormValue("note"))
	if note == "" {
		note = "manual snapshot"
	}
	_, raw, err := s.caddyForRequest(r).FetchConfig()
	if err != nil {
		http.Error(w, "fetch caddy config: "+err.Error(), http.StatusBadGateway)
		return
	}
	if raw == "" || raw == "null" {
		http.Error(w, "caddy has no active config to snapshot", http.StatusConflict)
		return
	}
	id, err := models.CreateSnapshot(s.DB, s.currentServerID(r), models.SnapshotSourceManual, note, raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "snapshot_created",
		fmt.Sprintf("snapshot:%d", id), note, true)
	http.Redirect(w, r, "/snapshots", http.StatusSeeOther)
}

func (s *Server) restoreSnapshot(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	snap, err := models.GetSnapshot(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(snap.ConfigJSON), &cfg); err != nil {
		http.Error(w, "snapshot is corrupted: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Validate before loading, even though it was valid at capture time —
	// the running Caddy might be a different version with different requirements.
	caddyCl := s.caddyForRequest(r)
	if err := caddyCl.Validate(cfg); err != nil {
		_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "snapshot_restore_failed",
			fmt.Sprintf("snapshot:%d", id), err.Error(), false)
		http.Error(w, "caddy rejected snapshot: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Snapshot the CURRENT config first so restoring is itself undoable.
	if s.autoSnapshotsEnabled() {
		if _, cur, err := caddyCl.FetchConfig(); err == nil && cur != "" && cur != "null" {
			_, _ = models.CreateSnapshot(s.DB, s.currentServerID(r), models.SnapshotSourceAuto,
				fmt.Sprintf("auto: before restoring snapshot #%d", id), cur)
			_ = models.PruneAutoSnapshots(s.DB, s.currentServerID(r), 20)
		}
	}
	if err := caddyCl.Load(cfg); err != nil {
		_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "snapshot_restore_failed",
			fmt.Sprintf("snapshot:%d", id), err.Error(), false)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "snapshot_restored",
		fmt.Sprintf("snapshot:%d", id), snap.Note, true)
	http.Redirect(w, r, "/snapshots", http.StatusSeeOther)
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err := models.DeleteSnapshot(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "snapshot_deleted",
		fmt.Sprintf("snapshot:%d", id), "", true)
	http.Redirect(w, r, "/snapshots", http.StatusSeeOther)
}

// downloadSnapshot streams the snapshot's config JSON as a .json file so users
// can keep off-host backups and later re-import via the upload form.
func (s *Server) downloadSnapshot(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	snap, err := models.GetSnapshot(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	filename := fmt.Sprintf("caddyui-snapshot-%d-%s.json", snap.ID, snap.CreatedAt.UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(snap.ConfigJSON))
}

// DiffLine represents a single line in a unified diff view.
type DiffLine struct {
	Type    string // "same", "add", "remove"
	Content string
	LineA   int // 1-based line number in snapshot (0 if added)
	LineB   int // 1-based line number in live config (0 if removed)
}

// diffLines performs a simple line-by-line diff between two strings.
// It zips the two line slices and marks each position as same/add/remove.
// This is not a full LCS diff but is effective for JSON config comparisons.
func diffLines(a, b string) []DiffLine {
	aLines := strings.Split(a, "\n")
	bLines := strings.Split(b, "\n")
	max := len(aLines)
	if len(bLines) > max {
		max = len(bLines)
	}
	var out []DiffLine
	for i := 0; i < max; i++ {
		la, lb := "", ""
		if i < len(aLines) {
			la = aLines[i]
		}
		if i < len(bLines) {
			lb = bLines[i]
		}
		if la == lb {
			out = append(out, DiffLine{Type: "same", Content: la, LineA: i + 1, LineB: i + 1})
		} else {
			if la != "" {
				out = append(out, DiffLine{Type: "remove", Content: la, LineA: i + 1})
			}
			if lb != "" {
				out = append(out, DiffLine{Type: "add", Content: lb, LineB: i + 1})
			}
		}
	}
	return out
}

// getSnapshotDiff shows a unified diff between a stored snapshot and the
// current live Caddy config. Admin-only: non-admin callers get 403.
func (s *Server) getSnapshotDiff(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil || cu.Role != models.RoleAdmin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	snap, err := models.GetSnapshot(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Pretty-print the snapshot JSON.
	var snapObj any
	if err := json.Unmarshal([]byte(snap.ConfigJSON), &snapObj); err != nil {
		http.Error(w, "snapshot is corrupted: "+err.Error(), http.StatusInternalServerError)
		return
	}
	snapPretty, err := json.MarshalIndent(snapObj, "", "  ")
	if err != nil {
		http.Error(w, "marshal snapshot: "+err.Error(), http.StatusInternalServerError)
		return
	}
	snapJSON := string(snapPretty)

	// Fetch and pretty-print the live config.
	var liveJSON string
	_, raw, fetchErr := s.caddyForRequest(r).FetchConfig()
	if fetchErr != nil || raw == "" || raw == "null" {
		liveJSON = ""
	} else {
		var liveObj any
		if err := json.Unmarshal([]byte(raw), &liveObj); err == nil {
			if b, err := json.MarshalIndent(liveObj, "", "  "); err == nil {
				liveJSON = string(b)
			} else {
				liveJSON = raw
			}
		} else {
			liveJSON = raw
		}
	}

	hasDiff := snapJSON != liveJSON
	var diffs []DiffLine
	addCount, removeCount := 0, 0
	if hasDiff {
		diffs = diffLines(snapJSON, liveJSON)
		for _, dl := range diffs {
			switch dl.Type {
			case "add":
				addCount++
			case "remove":
				removeCount++
			}
		}
	}

	s.render(w, r, "snapshot_diff.html", map[string]any{
		"User":        cu,
		"Snapshot":    snap,
		"SnapJSON":    snapJSON,
		"LiveJSON":    liveJSON,
		"DiffLines":   diffs,
		"HasDiff":     hasDiff,
		"AddCount":    addCount,
		"RemoveCount": removeCount,
		"Section":     "snapshots",
	})
}

// uploadSnapshot accepts a JSON file (typically a previously-downloaded
// snapshot, or any Caddy /config/ export) and stores it as a manual snapshot.
// The config is validated as JSON here but not run through Caddy — users
// restore explicitly, so we don't want upload to fail just because the running
// Caddy version rejects something.
func (s *Server) uploadSnapshot(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil { // 8 MiB
		http.Error(w, "upload too large or malformed: "+err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing 'file' upload", http.StatusBadRequest)
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 8<<20))
	if err != nil {
		http.Error(w, "read upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	var anyJSON any
	if err := json.Unmarshal(raw, &anyJSON); err != nil {
		http.Error(w, "file is not valid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	if note == "" {
		note = fmt.Sprintf("imported from %s", header.Filename)
	}
	id, err := models.CreateSnapshot(s.DB, s.currentServerID(r), models.SnapshotSourceManual, note, string(raw))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "snapshot_uploaded",
		fmt.Sprintf("snapshot:%d", id), header.Filename, true)
	http.Redirect(w, r, "/snapshots", http.StatusSeeOther)
}

// --- Activity log ---

// getDocs renders the in-app tutorial / quick-start guide.
// Everything here is static, so no DB call is needed.
func (s *Server) getDocs(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "docs.html", map[string]any{
		"User":            s.currentUser(r),
		"Section":         "docs",
		"DatabaseBackend": string(appdb.BackendOf(s.DB)),
	})
}

// getAPIDocs renders the v1 REST API reference page.
func (s *Server) getAPIDocs(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "api_docs.html", map[string]any{
		"User":    s.currentUser(r),
		"Section": "api_docs",
	})
}

func (s *Server) listActivityLog(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	actionFilter := strings.TrimSpace(r.URL.Query().Get("action"))
	entries, err := models.ListActivitySearch(s.DB, s.currentServerID(r), 500, search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if actionFilter != "" {
		filtered := entries[:0]
		for _, a := range entries {
			if strings.Contains(a.Action, actionFilter) {
				filtered = append(filtered, a)
			}
		}
		entries = filtered
	}
	s.render(w, r, "activity.html", map[string]any{
		"User":         s.currentUser(r),
		"Entries":      entries,
		"Section":      "activity",
		"Search":       search,
		"ActionFilter": actionFilter,
	})
}

func (s *Server) exportActivityCSV(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sid := s.currentServerID(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	entries, err := models.ListActivitySearch(s.DB, sid, 10000, search)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="activity.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ID", "Actor", "Action", "Target", "Detail", "Success", "Created At"})
	for _, a := range entries {
		succ := "false"
		if a.Success {
			succ = "true"
		}
		_ = cw.Write([]string{
			strconv.FormatInt(a.ID, 10),
			a.Actor,
			a.Action,
			a.Target,
			a.Detail,
			succ,
			a.CreatedAt.Format(time.RFC3339),
		})
	}
	cw.Flush()
}

// --- build helpers ---

func (s *Server) buildMergedRoutes(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute) []any {
	routes := []any{}
	for _, p := range proxies {
		if !p.Enabled || len(p.DomainList()) == 0 {
			continue
		}
		// Prepend basicauth authentication handler if enabled.
		var preHandlers []any
		if p.BasicAuthEnabled {
			if baUsers := p.BasicAuthUserList(); len(baUsers) > 0 {
				realm := p.BasicAuthRealm
				if realm == "" {
					realm = "Restricted"
				}
				if h := s.buildBasicAuthHandler(s.Caddy, baUsers, realm); h != nil {
					preHandlers = []any{h}
				}
			}
		}
		var advanced []any
		var advancedOverrides map[string]any
		if strings.TrimSpace(p.AdvancedConfig) != "" {
			h, overrides, err := s.adaptProxyAdvanced(p)
			if err != nil {
				// Don't fail the whole sync — log and push the route without advanced
				// handlers. The form-level validation should have caught bad syntax
				// before save, so this branch is for rare drift cases.
				log.Printf("caddy sync: proxy id=%d advanced_config adapt failed: %v", p.ID, err)
			} else {
				advanced, advancedOverrides = h, overrides
			}
		}
		route := caddy.BuildProxyRoute(p, append(preHandlers, advanced...))
		caddy.MergeReverseProxyOverrides(route, advancedOverrides)
		routes = append(routes, route)
	}
	for _, rd := range redirs {
		if !rd.Enabled || len(rd.DomainList()) == 0 {
			continue
		}
		routes = append(routes, caddy.BuildRedirectRoute(rd))
	}
	for _, rr := range raws {
		if !rr.Enabled {
			continue
		}
		// v2.36.1 (issue #64): routes bound to their own port(s) are emitted
		// as separate servers by buildRawListenServers, not on srv0.
		if rr.Listen != "" {
			continue
		}
		routes = append(routes, rawRouteEntries(rr)...)
	}

	// Append a catch-all 404 route when the admin has configured custom HTML.
	// This appears last so it only fires for requests that didn't match any
	// proxy/redirect/raw route above.
	if html, _ := models.GetSetting(s.DB, settingCatchAll404HTML); strings.TrimSpace(html) != "" {
		routes = append(routes, map[string]any{
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": 404,
				"headers": map[string]any{
					"Content-Type": []any{"text/html; charset=utf-8"},
				},
				"body": html,
			}},
			"terminal": true,
		})
	}

	// Global maintenance mode: prepend a catch-all 503 before all routes so
	// every incoming request receives the maintenance page regardless of which
	// virtual host it targets. The route has no host matcher (catches all),
	// and it's prepended so it fires before any per-host route.
	if gm, _ := models.GetSetting(s.DB, settingGlobalMaintenance); gm == "1" {
		globalMaintenanceBody := `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Maintenance</title><style>*{box-sizing:border-box}body{font-family:system-ui,sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#fff;border-radius:16px;padding:40px 48px;text-align:center;box-shadow:0 4px 32px rgba(0,0,0,.08);max-width:480px}h1{font-size:1.5rem;color:#1e293b;margin:16px 0 8px}p{color:#64748b;font-size:.95rem;line-height:1.6;margin:0}</style></head><body><div class="card"><svg width="48" height="48" fill="none" stroke="#f59e0b" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><h1>Down for Maintenance</h1><p>We're making improvements and will be back shortly. Thank you for your patience.</p></div></body></html>`
		routes = append([]any{map[string]any{
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": 503,
				"headers": map[string]any{
					"Content-Type": []any{"text/html; charset=utf-8"},
					"Retry-After":  []any{"3600"},
				},
				"body": globalMaintenanceBody,
			}},
			"terminal": true,
		}}, routes...)
	}

	return routes
}

func buildCertLoaders(certs []models.Certificate) (loadPEM, loadFiles []any) {
	for _, c := range certs {
		tag := "caddyui-" + strconv.FormatInt(c.ID, 10)
		switch c.Source {
		case models.CertSourcePEM:
			loadPEM = append(loadPEM, map[string]any{
				"certificate": c.CertPEM,
				"key":         c.KeyPEM,
				"tags":        []any{tag},
			})
		case models.CertSourcePath:
			loadFiles = append(loadFiles, map[string]any{
				"certificate": c.CertPath,
				"key":         c.KeyPath,
				"tags":        []any{tag},
			})
		}
	}
	return
}

func buildSkipCertificates(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute, certs []models.Certificate) []any {
	set := map[string]struct{}{}
	for _, p := range proxies {
		if p.CertificateID == 0 {
			continue
		}
		for _, d := range p.DomainList() {
			if d = models.NormalizeHostname(d); d != "" {
				set[d] = struct{}{}
			}
		}
	}
	for _, rd := range redirs {
		if rd.CertificateID == 0 {
			continue
		}
		for _, d := range rd.DomainList() {
			if d = models.NormalizeHostname(d); d != "" {
				set[d] = struct{}{}
			}
		}
	}
	// Raw routes don't store their domains as a separate field — the hosts live
	// inside the JSON match[].host[]. Pull them out so Caddy skips ACME for these
	// hostnames when the user bound a custom cert.
	for _, rr := range raws {
		if rr.CertificateID == 0 {
			continue
		}
		var decoded any
		if err := json.Unmarshal([]byte(rr.JSONData), &decoded); err != nil {
			continue
		}
		for _, route := range flattenToRouteMaps(decoded) {
			for _, h := range hostsFromRoute(route) {
				if h = models.NormalizeHostname(h); h != "" {
					set[h] = struct{}{}
				}
			}
		}
	}
	// Auto-selected exact hosts covered by a standalone managed wildcard must
	// remain HTTPS-enabled but must not trigger their own ACME order. Caddy's
	// skip_certificates setting provides exactly that behavior: the wildcard
	// route obtains the wildcard certificate, and the exact route reuses it
	// from Caddy's cache. Never skip wildcard subjects themselves, because
	// those are what command Caddy to obtain the managed certificate.
	addCoveredExact := func(hosts []string, enabled, sslEnabled bool, certificateID int64, internalTLS bool) {
		if !enabled || !sslEnabled || certificateID != 0 {
			return
		}
		// v2.46.0: an internal-CA host gets its own certificate from the
		// `internal` issuer (buildInternalTLSAutomationPolicies), so it is
		// never covered by a wildcard managed (DNS-01) certificate. Skipping
		// it here would tell Caddy not to manage the cert at all, leaving the
		// host with none.
		if internalTLS {
			return
		}
		for _, host := range hosts {
			host = models.NormalizeHostname(host)
			if host == "" || strings.HasPrefix(host, "*.") {
				continue
			}
			for _, cert := range certs {
				if cert.Source != models.CertSourceManaged {
					continue
				}
				covered := false
				for _, certDomain := range cert.DomainList() {
					if strings.HasPrefix(models.NormalizeHostname(certDomain), "*.") && managedCertificateCovers(certDomain, host) {
						covered = true
						break
					}
				}
				if covered {
					set[host] = struct{}{}
					break
				}
			}
		}
	}
	for _, proxy := range proxies {
		addCoveredExact(proxy.DomainList(), proxy.Enabled, proxy.SSLEnabled, proxy.CertificateID, proxy.InternalTLS)
	}
	for _, redirect := range redirs {
		addCoveredExact(redirect.DomainList(), redirect.Enabled, redirect.SSLEnabled, redirect.CertificateID, false)
	}
	for _, raw := range raws {
		addCoveredExact(rawRouteHosts(raw), raw.Enabled, true, raw.CertificateID, false)
	}
	out := make([]any, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	return out
}

// flattenToRouteMaps accepts the decoded JSON of a raw_route (may be a single
// route object or an array of routes) and returns the route maps found at the
// top level. Nested subroutes are not descended — host matches are expected on
// the top-level route for TLS binding purposes.
func flattenToRouteMaps(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		var out []map[string]any
		for _, item := range t {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// --- deep-copy + in-place merge helpers (operate on the proposed config map) ---

func deepCopyMap(m map[string]any) (map[string]any, error) {
	if m == nil {
		return map[string]any{}, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

func ensureMap(parent map[string]any, key string) map[string]any {
	if v, ok := parent[key].(map[string]any); ok {
		return v
	}
	m := map[string]any{}
	parent[key] = m
	return m
}

func applyRoutes(cfg map[string]any, routes []any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	srv["routes"] = routes
}

// applyPlainHTTPServer mirrors the Caddyfile adapter's representation of a
// site declared with both http:// and https:// addresses: HTTPS stays on srv0,
// while an explicit :80 server handles hosts whose Force SSL toggle is off.
// Caddy then excludes those hosts from its generated redirect routes without
// relying on the nonexistent automatic_https.skip_redirects JSON field.
func applyPlainHTTPServer(cfg map[string]any, routes []any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	if len(routes) == 0 {
		delete(servers, "caddyui_http")
		return
	}
	servers["caddyui_http"] = map[string]any{
		"listen": []any{":80"},
		"routes": routes,
	}
}

// rawRouteEntries decodes a raw_route's JSON into the route object(s) it
// contributes, applying the per-route wrapping (exploit blocker). A raw_route
// may hold a single route object or an array of routes; arrays are spread so
// we never emit a nested array (which Caddy rejects). Shared by srv0 assembly
// and by the per-port servers of v2.36.1 (issue #64).
func rawRouteEntries(rr models.RawRoute) []any {
	var decoded any
	if err := json.Unmarshal([]byte(rr.JSONData), &decoded); err != nil {
		log.Printf("caddy sync: skipping invalid raw_route id=%d label=%q: %v", rr.ID, rr.Label, err)
		return nil
	}
	wrap := func(route map[string]any) map[string]any {
		if rr.BlockCommonExploits {
			handle, _ := route["handle"].([]any)
			route["handle"] = append([]any{caddy.ExploitBlockerSubroute()}, handle...)
		}
		return route
	}
	var out []any
	switch v := decoded.(type) {
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				out = append(out, wrap(m))
			} else {
				out = append(out, item)
			}
		}
	case map[string]any:
		out = append(out, wrap(v))
	default:
		log.Printf("caddy sync: skipping raw_route id=%d label=%q: unexpected JSON shape %T", rr.ID, rr.Label, decoded)
	}
	return out
}

// rawListenServerPrefix names the apps.http.servers entries CaddyUI creates for
// Advanced routes with their own listen addresses (v2.36.1, issue #64). Only
// keys with this prefix are ever removed by the sync; a server the operator
// added by hand under any other name is left alone.
const rawListenServerPrefix = "caddyui_listen_"

// buildRawListenServers groups the enabled Advanced routes that carry a listen
// set into one server per distinct set: `:7070 { … }` pasted twice yields one
// "caddyui_listen_7070" server with both routes. Routes on the standard ports
// (Listen == "") are not included — they live on srv0 / caddyui_http as
// always. Insertion order is preserved so the routes keep the order the
// operator sees in the list.
func (s *Server) buildRawListenServers(raws []models.RawRoute) map[string]map[string]any {
	type group struct {
		addrs  []string
		routes []any
	}
	groups := map[string]*group{}
	for _, rr := range raws {
		if !rr.Enabled || rr.Listen == "" {
			continue
		}
		addrs := rr.ListenAddrs()
		name := models.RawRouteListenServerName(addrs)
		if name == "" {
			continue
		}
		g, ok := groups[name]
		if !ok {
			g = &group{addrs: addrs}
			groups[name] = g
		}
		g.routes = append(g.routes, rawRouteEntries(rr)...)
	}
	out := make(map[string]map[string]any, len(groups))
	for name, g := range groups {
		listen := make([]any, 0, len(g.addrs))
		for _, a := range g.addrs {
			listen = append(listen, a)
		}
		routes := g.routes
		if routes == nil {
			routes = []any{}
		}
		out[name] = map[string]any{"listen": listen, "routes": routes}
	}
	return out
}

// applyRawListenServers replaces every caddyui_listen_* server in the proposed
// config with the desired set, so a route whose port changed or that was
// deleted doesn't leave a stale listener behind.
func applyRawListenServers(cfg map[string]any, want map[string]map[string]any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	for name := range servers {
		if strings.HasPrefix(name, rawListenServerPrefix) {
			delete(servers, name)
		}
	}
	for name, srv := range want {
		servers[name] = srv
	}
}

// writeRawListenServersSubtree is the live-config counterpart of
// applyRawListenServers: stale caddyui_listen_* servers are deleted first so a
// port that moved between two names is never bound twice, then the desired
// servers are written in name order (PATCH when the key exists, PUT otherwise).
func (s *Server) writeRawListenServersSubtree(want map[string]map[string]any) error {
	raw, err := s.Caddy.FetchPath("/config/apps/http/servers")
	if err != nil {
		return err
	}
	existing, _ := raw.(map[string]any)
	for name := range existing {
		if !strings.HasPrefix(name, rawListenServerPrefix) {
			continue
		}
		if _, keep := want[name]; keep {
			continue
		}
		if err := s.Caddy.DeletePath("/config/apps/http/servers/" + name); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := "/config/apps/http/servers/" + name
		if _, exists := existing[name]; exists {
			if err := s.Caddy.PatchPath(path, want[name]); err != nil {
				return err
			}
			continue
		}
		if err := s.Caddy.PutPath(path, want[name]); err != nil {
			return err
		}
	}
	return nil
}

// applyListen forces srv0 to listen on :443. Without this, a Caddyfile with no
// site blocks produces a config where srv0.listen is null and Caddy only serves
// on :80 — the :443 port has no listener and HTTPS is unreachable. Setting :443
// explicitly lets us keep the Caddyfile reduced to globals+snippets while the
// DB drives all routes. The :80 HTTP→HTTPS redirect server is synthesised by
// Caddy's automatic_https module from the route hosts, so we don't manage it.
func applyListen(cfg map[string]any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	srv["listen"] = []any{":443"}
}

// applyProtocols restricts the Caddy HTTP server to h1+h2 when disable_http3
// is set, giving maximum compatibility with older Android clients. When the
// setting is off it removes any previously-written protocols key so Caddy
// reverts to its own default (h1, h2, h3).
func applyProtocols(cfg map[string]any, db *sql.DB) {
	apps, _ := cfg["apps"].(map[string]any)
	if apps == nil {
		return
	}
	httpApp, _ := apps["http"].(map[string]any)
	if httpApp == nil {
		return
	}
	servers, _ := httpApp["servers"].(map[string]any)
	if servers == nil {
		return
	}
	srv, _ := servers["srv0"].(map[string]any)
	if srv == nil {
		return
	}
	if v, _ := models.GetSetting(db, settingDisableHTTP3); v == "1" {
		srv["protocols"] = []any{"h1", "h2"}
	} else {
		delete(srv, "protocols")
	}
}

// applyTrustedProxies injects the trusted_proxies list into the Caddy HTTP
// server config. This allows Caddy to extract the real client IP from
// X-Forwarded-For when requests arrive via a trusted load balancer or CDN.
// No-op when the setting is empty.
func applyTrustedProxies(cfg map[string]any, db *sql.DB, serverID int64) {
	raw, _ := models.GetSetting(db, settingTrustedProxies)
	if raw == "" {
		return
	}
	var ranges []any
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		if cidr := strings.TrimSpace(line); cidr != "" {
			ranges = append(ranges, cidr)
		}
	}
	if len(ranges) == 0 {
		return
	}
	// Navigate to apps.http.servers.srv0 and set trusted_proxies.
	apps, _ := cfg["apps"].(map[string]any)
	if apps == nil {
		return
	}
	httpApp, _ := apps["http"].(map[string]any)
	if httpApp == nil {
		return
	}
	servers, _ := httpApp["servers"].(map[string]any)
	if servers == nil {
		return
	}
	srv, _ := servers["srv0"].(map[string]any)
	if srv == nil {
		return
	}
	srv["trusted_proxies"] = map[string]any{
		"source": "static",
		"ranges": ranges,
	}
}

func applyCertLoaders(cfg map[string]any, loadPEM, loadFiles []any) {
	apps := ensureMap(cfg, "apps")
	tlsBlock := ensureMap(apps, "tls")
	certsBlock := ensureMap(tlsBlock, "certificates")
	// Mirror writeTLSSubtree: merge caddyui-owned entries with any pre-existing
	// non-caddyui entries so validation reflects exactly what we'll push.
	existingPEM, _ := certsBlock["load_pem"].([]any)
	existingFiles, _ := certsBlock["load_files"].([]any)
	mergedPEM := append(filterNonCaddyUICerts(existingPEM), loadPEM...)
	mergedFiles := append(filterNonCaddyUICerts(existingFiles), loadFiles...)
	if len(mergedPEM) > 0 {
		certsBlock["load_pem"] = mergedPEM
	} else {
		delete(certsBlock, "load_pem")
	}
	if len(mergedFiles) > 0 {
		certsBlock["load_files"] = mergedFiles
	} else {
		delete(certsBlock, "load_files")
	}
	if len(certsBlock) == 0 {
		delete(tlsBlock, "certificates")
	}
	if len(tlsBlock) == 0 {
		delete(apps, "tls")
	}
}

func applySkipCertificates(cfg map[string]any, skipList []any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	auto := ensureMap(srv, "automatic_https")
	if len(skipList) > 0 {
		auto["skip_certificates"] = skipList
	} else {
		delete(auto, "skip_certificates")
	}
	if len(auto) == 0 {
		delete(srv, "automatic_https")
	}
}

// buildHTTPRoutes returns the complete route set for CaddyUI's explicit :80
// server. Hosts with Force SSL off keep their normal handlers; hosts with
// Force SSL on receive an HTTPS redirect. Owning both cases lets CaddyUI disable
// Caddy's generated redirect listener, avoiding two servers competing for :80.
func (s *Server) buildHTTPRoutes(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute) []any {
	httpProxies := make([]models.ProxyHost, 0)
	var forcedDomains []string
	for _, p := range proxies {
		if !p.Enabled {
			continue
		}
		if !p.SSLForced {
			httpProxies = append(httpProxies, p)
		} else {
			forcedDomains = append(forcedDomains, p.DomainList()...)
		}
	}
	httpRedirs := make([]models.RedirectionHost, 0)
	for _, rd := range redirs {
		if !rd.Enabled {
			continue
		}
		if !rd.SSLForced {
			httpRedirs = append(httpRedirs, rd)
		} else {
			forcedDomains = append(forcedDomains, rd.DomainList()...)
		}
	}
	httpRaws := make([]models.RawRoute, 0)
	for _, rr := range raws {
		if !rr.Enabled {
			continue
		}
		if rr.Listen != "" { // v2.36.1 (issue #64): served by its own listener, never on :80
			continue
		}
		if !rr.ForceSSL {
			httpRaws = append(httpRaws, rr)
		} else {
			forcedDomains = append(forcedDomains, rawRouteHosts(rr)...)
		}
	}
	routes := s.buildMergedRoutes(httpProxies, httpRedirs, httpRaws)
	if redirect := buildHTTPSRedirectRoute(forcedDomains); redirect != nil {
		// Keep a configured catch-all 404 last. Global maintenance, when on,
		// remains first because buildMergedRoutes prepends it.
		if html, _ := models.GetSetting(s.DB, settingCatchAll404HTML); strings.TrimSpace(html) != "" && len(routes) > 0 {
			routes = append(routes, nil)
			copy(routes[len(routes)-1:], routes[len(routes)-2:])
			routes[len(routes)-2] = redirect
		} else {
			routes = append(routes, redirect)
		}
	}
	return routes
}

func buildHTTPSRedirectRoute(domains []string) map[string]any {
	seen := map[string]bool{}
	hosts := make([]any, 0, len(domains))
	for _, raw := range domains {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return nil
	}
	return map[string]any{
		"match": []any{map[string]any{"host": hosts}},
		"handle": []any{map[string]any{
			"handler":     "static_response",
			"status_code": http.StatusPermanentRedirect,
			"headers": map[string]any{
				"Location": []any{"https://{http.request.host}{http.request.uri}"},
			},
		}},
		"terminal": true,
	}
}

// removeUnsupportedSkipRedirects cleans configs produced by affected CaddyUI
// versions before validation. Caddy's AutoHTTPSConfig has no skip_redirects
// field; per-host plain HTTP is represented by applyPlainHTTPServer instead.
func removeUnsupportedSkipRedirects(cfg map[string]any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	if auto, ok := srv["automatic_https"].(map[string]any); ok {
		delete(auto, "skip_redirects")
		if len(auto) == 0 {
			delete(srv, "automatic_https")
		}
	}
}

func applyDisableAutomaticHTTPSRedirects(cfg map[string]any, disabled bool) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	auto := ensureMap(srv, "automatic_https")
	if disabled {
		auto["disable_redirects"] = true
	} else {
		delete(auto, "disable_redirects")
	}
	if len(auto) == 0 {
		delete(srv, "automatic_https")
	}
}

// buildSkipAccessLogs collects domains from enabled proxy hosts where
// DisableAccessLog=true. These are written to srv0.logs.skip_hosts so Caddy
// omits access-log entries for those virtual hosts.
func buildSkipAccessLogs(proxies []models.ProxyHost) []any {
	set := map[string]struct{}{}
	for _, p := range proxies {
		if !p.Enabled || !p.DisableAccessLog {
			continue
		}
		for _, d := range p.DomainList() {
			set[d] = struct{}{}
		}
	}
	out := make([]any, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	return out
}

func applySkipAccessLogs(cfg map[string]any, skipHosts []any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	if len(skipHosts) > 0 {
		logsM := ensureMap(srv, "logs")
		logsM["skip_hosts"] = skipHosts
	} else {
		if logsM, ok := srv["logs"].(map[string]any); ok {
			delete(logsM, "skip_hosts")
			if len(logsM) == 0 {
				delete(srv, "logs")
			}
		}
	}
}

// applyTLSConnectionPolicies merges per-SNI TLS connection policies into the
// proposed config map used for pre-load validation. Mirrors the subtree-write
// helpers — changes here must match writeTLSConnectionPoliciesSubtree.
func applyTLSConnectionPolicies(cfg map[string]any, policies []any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	if len(policies) > 0 {
		srv["tls_connection_policies"] = policies
	} else {
		delete(srv, "tls_connection_policies")
	}
}

// filterNonCaddyUICerts returns the subset of cert loader entries that DON'T carry
// a caddyui ownership tag ("caddyui-*"). Used on sync to preserve TLS certs that
// were loaded from the user's Caddyfile or placed via direct /config edits, so
// caddyui only overwrites its own entries.
func filterNonCaddyUICerts(in []any) []any {
	out := make([]any, 0, len(in))
	for _, item := range in {
		entry, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		tags, _ := entry["tags"].([]any)
		owned := false
		for _, t := range tags {
			if s, ok := t.(string); ok && strings.HasPrefix(s, "caddyui-") {
				owned = true
				break
			}
		}
		if !owned {
			out = append(out, entry)
		}
	}
	return out
}

// --- real subtree writes (post-validation) ---

// writeRoutesSubtree replaces the srv0 routes array. Uses PATCH (replace) when routes
// already exist, since POST on an existing array path APPENDS the body as one element
// (which would produce [existing..., [new_routes]] — a nested array Caddy rejects).
// Falls back to POST when routes don't exist yet (PATCH 404s on missing paths).
func (s *Server) writeRoutesSubtree(routes []any) error {
	existing, err := s.Caddy.FetchPath("/config/apps/http/servers/srv0/routes")
	if err != nil {
		return err
	}
	if existing == nil {
		return s.Caddy.PutPath("/config/apps/http/servers/srv0/routes", routes)
	}
	return s.Caddy.PatchPath("/config/apps/http/servers/srv0/routes", routes)
}

// writeListenSubtree ensures srv0.listen is [":443"]. Uses PATCH when the path
// exists (replace semantic) and PUT/POST when it doesn't (first write). Array
// paths cannot use POST-append semantics, same reason writeRoutesSubtree splits.
func (s *Server) writeListenSubtree() error {
	want := []any{":443"}
	existing, err := s.Caddy.FetchPath("/config/apps/http/servers/srv0/listen")
	if err != nil {
		return err
	}
	if cur, ok := existing.([]any); ok && stringListsEqual(cur, want) {
		return nil
	}
	if existing == nil {
		return s.Caddy.PutPath("/config/apps/http/servers/srv0/listen", want)
	}
	return s.Caddy.PatchPath("/config/apps/http/servers/srv0/listen", want)
}

// writeProtocolsSubtree pushes the protocols list (or absence thereof) to
// the live Caddy config. When disable_http3 is on it writes ["h1","h2"];
// when off it deletes the key so Caddy reverts to its default h1+h2+h3.
func (s *Server) writeProtocolsSubtree(db *sql.DB) error {
	const path = "/config/apps/http/servers/srv0/protocols"
	if v, _ := models.GetSetting(db, settingDisableHTTP3); v == "1" {
		want := []any{"h1", "h2"}
		existing, err := s.Caddy.FetchPath(path)
		if err != nil {
			return err
		}
		if cur, ok := existing.([]any); ok && stringListsEqual(cur, want) {
			return nil
		}
		if existing == nil {
			return s.Caddy.PutPath(path, want)
		}
		return s.Caddy.PatchPath(path, want)
	}
	// Setting is off — remove the key if it exists so Caddy uses its default.
	existing, err := s.Caddy.FetchPath(path)
	if err != nil || existing == nil {
		return nil
	}
	return s.Caddy.DeletePath(path)
}

func (s *Server) writeTLSSubtree(loadPEM, loadFiles []any, force bool) error {
	raw, err := s.Caddy.FetchPath("/config/apps/tls")
	if err != nil {
		return err
	}
	tlsMap, _ := raw.(map[string]any)
	if tlsMap == nil {
		tlsMap = map[string]any{}
	}
	certsMap, _ := tlsMap["certificates"].(map[string]any)
	if certsMap == nil {
		certsMap = map[string]any{}
	}

	// Preserve any cert entries that weren't created by caddyui. We tag everything
	// we own with "caddyui-<id>" — other entries (from Caddyfile, manual /config PUTs,
	// etc.) must survive the sync so we don't silently disable user-managed TLS.
	existingPEM, _ := certsMap["load_pem"].([]any)
	existingFiles, _ := certsMap["load_files"].([]any)
	mergedPEM := append(filterNonCaddyUICerts(existingPEM), loadPEM...)
	mergedFiles := append(filterNonCaddyUICerts(existingFiles), loadFiles...)

	// CRITICAL: writing /config/apps/tls reprovisions the entire TLS module, which
	// cancels every in-flight ACME challenge ("context canceled" errors). Skip the
	// write when the effective cert loaders haven't changed — unless the caller
	// forces it, meaning a cert assignment or cert row actually changed and the
	// user expects Caddy to re-evaluate.
	if !force && certsEqual(existingPEM, mergedPEM) && certsEqual(existingFiles, mergedFiles) {
		return nil
	}

	if len(mergedPEM) > 0 {
		certsMap["load_pem"] = mergedPEM
	} else {
		delete(certsMap, "load_pem")
	}
	if len(mergedFiles) > 0 {
		certsMap["load_files"] = mergedFiles
	} else {
		delete(certsMap, "load_files")
	}
	if len(certsMap) > 0 {
		tlsMap["certificates"] = certsMap
	} else {
		delete(tlsMap, "certificates")
	}
	if raw == nil && len(tlsMap) == 0 {
		return nil
	}
	return s.Caddy.PutPath("/config/apps/tls", tlsMap)
}

func (s *Server) writeAutomaticHTTPSSubtree(skipCerts []any, disableRedirects, force bool) error {
	raw, err := s.Caddy.FetchPath("/config/apps/http/servers/srv0/automatic_https")
	if err != nil {
		return err
	}
	autoMap, _ := raw.(map[string]any)
	existed := autoMap != nil
	if autoMap == nil {
		autoMap = map[string]any{}
	}
	existingSkipCerts, _ := autoMap["skip_certificates"].([]any)
	existingDisableRedirects, _ := autoMap["disable_redirects"].(bool)
	// Skip the write when the effective lists are unchanged. Writing otherwise
	// reprovisions the server module and can interrupt in-flight ACME work.
	_, hasInvalidSkipRedirects := autoMap["skip_redirects"]
	if !force && !hasInvalidSkipRedirects && existingDisableRedirects == disableRedirects && stringListsEqual(existingSkipCerts, skipCerts) {
		return nil
	}
	if len(skipCerts) > 0 {
		autoMap["skip_certificates"] = skipCerts
	} else {
		delete(autoMap, "skip_certificates")
	}
	delete(autoMap, "skip_redirects")
	if disableRedirects {
		autoMap["disable_redirects"] = true
	} else {
		delete(autoMap, "disable_redirects")
	}
	if !existed && len(autoMap) == 0 {
		return nil
	}
	return s.Caddy.PutPath("/config/apps/http/servers/srv0/automatic_https", autoMap)
}

// writePlainHTTPServerSubtree owns only the caddyui_http server. Replacing the
// complete server map keeps its :80 listener and route list in sync atomically
// without touching user-managed HTTP servers.
func (s *Server) writePlainHTTPServerSubtree(routes []any) error {
	const path = "/config/apps/http/servers/caddyui_http"
	existing, err := s.Caddy.FetchPath(path)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		if existing == nil {
			return nil
		}
		return s.Caddy.DeletePath(path)
	}
	want := map[string]any{
		"listen": []any{":80"},
		"routes": routes,
	}
	if existing == nil {
		return s.Caddy.PutPath(path, want)
	}
	return s.Caddy.PatchPath(path, want)
}

// writeTLSConnectionPoliciesSubtree replaces srv0.tls_connection_policies.
// When policies is nil/empty and no existing policies are set this is a no-op.
// When policies is nil/empty but existing policies exist, the key is cleared
// (replaced with an empty array) so stale per-SNI min-version settings don't
// linger after the last host that used them is updated.
func (s *Server) writeTLSConnectionPoliciesSubtree(policies []any) error {
	path := "/config/apps/http/servers/srv0/tls_connection_policies"
	existing, err := s.Caddy.FetchPath(path)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		if existing == nil {
			return nil // nothing to write or clear
		}
		// Clear stale policies with an empty array (Caddy treats [] as "no policies").
		return s.Caddy.PatchPath(path, []any{})
	}
	if existing == nil {
		return s.Caddy.PutPath(path, policies)
	}
	return s.Caddy.PatchPath(path, policies)
}

// writeAccessLogsSubtree updates srv0.logs.skip_hosts to suppress access-log
// entries for proxy hosts with DisableAccessLog=true.
func (s *Server) writeAccessLogsSubtree(skipHosts []any) error {
	path := "/config/apps/http/servers/srv0/logs"
	raw, err := s.Caddy.FetchPath(path)
	if err != nil {
		return err
	}
	logsMap, _ := raw.(map[string]any)
	existed := logsMap != nil
	if logsMap == nil {
		logsMap = map[string]any{}
	}
	existingSkip, _ := logsMap["skip_hosts"].([]any)
	if stringListsEqual(existingSkip, skipHosts) {
		return nil
	}
	if len(skipHosts) > 0 {
		logsMap["skip_hosts"] = skipHosts
	} else {
		delete(logsMap, "skip_hosts")
	}
	if !existed && len(logsMap) == 0 {
		return nil
	}
	return s.Caddy.PutPath(path, logsMap)
}

// certsEqual compares two cert-loader arrays for semantic equality via JSON normalization.
func certsEqual(a, b []any) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

// stringListsEqual treats two []any of strings as sets (order-insensitive).
func stringListsEqual(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]struct{}{}
	for _, v := range a {
		if s, ok := v.(string); ok {
			set[s] = struct{}{}
		}
	}
	for _, v := range b {
		s, ok := v.(string)
		if !ok {
			return false
		}
		if _, present := set[s]; !present {
			return false
		}
	}
	return true
}

// --- Users ---

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := s.currentUser(r)
		if u == nil || u.Role != models.RoleAdmin {
			http.Error(w, "admin access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireWrite blocks mutating requests for viewer-role users. Reads still
// pass through, so viewers see the UI but can't change anything.
func (s *Server) requireWrite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch currentAPITokenScope(r) {
		case models.TokenScopeReadOnly:
			http.Error(w, "token scope is read-only", http.StatusForbidden)
			return
		case models.TokenScopeProxyWrite:
			if !proxyWriteTokenCanWritePath(r.URL.Path) {
				http.Error(w, "token scope allows proxy-host writes only", http.StatusForbidden)
				return
			}
		}
		u := s.currentUser(r)
		if u != nil && u.Role == models.RoleView {
			http.Error(w, "read-only account — ask an admin to make changes", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := models.ListUsers(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"User":    s.currentUser(r),
		"Users":   users,
		"Section": "users",
	}
	if r.URL.Query().Get("invited") == "1" {
		data["Invited"] = true
	}
	if e := r.URL.Query().Get("error"); e != "" {
		data["Error"] = e
	}
	s.render(w, r, "users.html", data)
}

func (s *Server) newUser(w http.ResponseWriter, r *http.Request) {
	data := captchaTemplateData(loadCaptchaConfig(s.DB))
	data["User"] = s.currentUser(r)
	data["Target"] = &models.User{Role: models.RoleView}
	data["Section"] = "users"
	s.render(w, r, "user_form.html", data)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	pw := r.FormValue("password")
	pw2 := r.FormValue("password_confirm")
	role := r.FormValue("role")
	target := &models.User{Email: email, Name: name, Role: role}

	// v2.5.0: captcha also gates user creation. This endpoint is admin-only
	// (wrapped in requireWrite), but /users/new forms are sometimes the
	// first thing an attacker hits after stealing an admin session cookie
	// — adding the challenge here raises the bar on scripted account
	// creation if credentials leak.
	captchaCfg := loadCaptchaConfig(s.DB)
	tplData := captchaTemplateData(captchaCfg)
	renderErr := func(msg string) {
		data := map[string]any{
			"User":    s.currentUser(r),
			"Target":  target,
			"Section": "users",
			"Error":   msg,
		}
		for k, v := range tplData {
			data[k] = v
		}
		s.render(w, r, "user_form.html", data)
	}
	if ok, err := verifyCaptcha(captchaCfg, r); err != nil || !ok {
		renderErr("Security check failed. Please try again.")
		return
	}
	if email == "" || pw == "" {
		renderErr("Email and password are required")
		return
	}
	if pw != pw2 {
		renderErr("Passwords do not match")
		return
	}
	if len(pw) < 8 {
		renderErr("Password must be at least 8 characters")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := models.CreateUser(s.DB, email, hash, name, role); err != nil {
		renderErr(err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "user_create", email, role, true)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) editUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	u, err := models.GetUserByID(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.render(w, r, "user_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Target":  u,
		"Section": "users",
	})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	u, err := models.GetUserByID(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	role := r.FormValue("role")
	pw := r.FormValue("password")
	pw2 := r.FormValue("password_confirm")
	renderErr := func(msg string) {
		u.Name = name
		u.Role = role
		s.render(w, r, "user_form.html", map[string]any{
			"User":    s.currentUser(r),
			"Target":  u,
			"Section": "users",
			"Error":   msg,
		})
	}
	// Prevent demoting the last admin — a view-only world locks the UI out of user mgmt.
	if u.Role == models.RoleAdmin && role != models.RoleAdmin {
		n, _ := models.CountAdmins(s.DB)
		if n <= 1 {
			renderErr("Can't demote the last admin — promote another user first")
			return
		}
	}
	if err := models.UpdateUser(s.DB, id, name, role); err != nil {
		renderErr(err.Error())
		return
	}
	if pw != "" {
		if pw != pw2 {
			renderErr("Passwords do not match")
			return
		}
		if len(pw) < 8 {
			renderErr("Password must be at least 8 characters")
			return
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			renderErr(err.Error())
			return
		}
		if err := models.UpdateUserPassword(s.DB, id, hash); err != nil {
			renderErr(err.Error())
			return
		}
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "user_update", u.Email, role, true)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	me := s.currentUser(r)
	if me != nil && me.ID == id {
		http.Error(w, "you can't delete your own account", http.StatusBadRequest)
		return
	}
	u, err := models.GetUserByID(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if u.Role == models.RoleAdmin {
		n, _ := models.CountAdmins(s.DB)
		if n <= 1 {
			http.Error(w, "can't delete the last admin", http.StatusBadRequest)
			return
		}
	}
	if err := models.DeleteUser(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "user_delete", u.Email, "", true)
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// --- v2.7.4: Groups ---
//
// Admin-only CRUD. A group is just a bag of user-role members; ListGroup-
// scoped List* queries OR members' IDs into the owner filter so teammates
// see each other's rows. No write permission: edit/delete stays per-row
// ownership-gated inside each Update*/Delete* handler.

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := models.ListGroups(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "groups.html", map[string]any{
		"User":    s.currentUser(r),
		"Groups":  groups,
		"Section": "groups",
	})
}

func (s *Server) newGroup(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "group_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Group":   &models.Group{},
		"Users":   s.adminUserList(r),
		"Members": map[int64]bool{},
		"Section": "groups",
	})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	renderErr := func(msg string) {
		members := map[int64]bool{}
		for _, v := range r.Form["member_ids"] {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil {
				members[id] = true
			}
		}
		s.render(w, r, "group_form.html", map[string]any{
			"User":    s.currentUser(r),
			"Group":   &models.Group{Name: name, Description: desc},
			"Users":   s.adminUserList(r),
			"Members": members,
			"Section": "groups",
			"Error":   msg,
		})
	}
	if name == "" {
		renderErr("Name is required")
		return
	}
	id, err := models.CreateGroup(s.DB, name, desc)
	if err != nil {
		renderErr(err.Error())
		return
	}
	// Member rows (user-role only — the form only offers those).
	var memberIDs []int64
	for _, v := range r.Form["member_ids"] {
		if uid, err := strconv.ParseInt(v, 10, 64); err == nil {
			memberIDs = append(memberIDs, uid)
		}
	}
	if err := models.SetGroupMembers(s.DB, id, memberIDs); err != nil {
		renderErr(err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "group_create", name, "", true)
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (s *Server) editGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	g, err := models.GetGroup(s.DB, id)
	if err != nil || g == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	members, _ := models.ListGroupMembers(s.DB, id)
	memberSet := map[int64]bool{}
	for _, m := range members {
		memberSet[m.ID] = true
	}
	s.render(w, r, "group_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Group":   g,
		"Users":   s.adminUserList(r),
		"Members": memberSet,
		"Section": "groups",
	})
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	g, err := models.GetGroup(s.DB, id)
	if err != nil || g == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	renderErr := func(msg string) {
		members := map[int64]bool{}
		for _, v := range r.Form["member_ids"] {
			if uid, err := strconv.ParseInt(v, 10, 64); err == nil {
				members[uid] = true
			}
		}
		g.Name = name
		g.Description = desc
		s.render(w, r, "group_form.html", map[string]any{
			"User":    s.currentUser(r),
			"Group":   g,
			"Users":   s.adminUserList(r),
			"Members": members,
			"Section": "groups",
			"Error":   msg,
		})
	}
	if name == "" {
		renderErr("Name is required")
		return
	}
	if err := models.UpdateGroup(s.DB, id, name, desc); err != nil {
		renderErr(err.Error())
		return
	}
	var memberIDs []int64
	for _, v := range r.Form["member_ids"] {
		if uid, err := strconv.ParseInt(v, 10, 64); err == nil {
			memberIDs = append(memberIDs, uid)
		}
	}
	if err := models.SetGroupMembers(s.DB, id, memberIDs); err != nil {
		renderErr(err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "group_update", name, "", true)
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	g, err := models.GetGroup(s.DB, id)
	if err != nil || g == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// ON DELETE CASCADE on user_groups cleans up membership rows for us.
	if err := models.DeleteGroup(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "group_delete", g.Name, "", true)
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

// --- Feature F: Notifications (webhook + SMTP email) ---

const (
	settingNotifyWebhookURL    = "notify_webhook_url"
	settingNotifyWebhookSecret = "notify_webhook_secret" // v2.9.12: HMAC-SHA256 signing secret
	settingNotifyDaysBefore    = "notify_days_before"
	defaultNotifyDaysBefore    = 14

	// v2.12.51: ntfy.sh push channel. Free, no account needed for public
	// topics on ntfy.sh; self-hostable for private topics. Most popular
	// notification channel in the homelab community.
	settingNotifyNtfyURL   = "notify_ntfy_url"   // full URL e.g. https://ntfy.sh/cert-alerts
	settingNotifyNtfyToken = "notify_ntfy_token" // optional bearer token for protected/self-hosted topics

	// SMTP settings (stored in the key-value settings table).
	settingSMTPHost       = "smtp_host"
	settingSMTPPort       = "smtp_port"
	settingSMTPUsername   = "smtp_username"
	settingSMTPPassword   = "smtp_password"
	settingSMTPFrom       = "smtp_from"
	settingSMTPTo         = "smtp_to"
	settingSMTPSecurity   = "smtp_security"    // "none" | "starttls" | "tls"
	settingSMTPSkipVerify = "smtp_skip_verify" // "1" to skip TLS cert validation

	// v2.11.15: AI assistant — proxies user prompts to a local Ollama
	// instance. Default URL points at the docker service name "ollama"
	// since most users running CaddyUI on a homelab GPU box co-locate
	// Ollama in the same compose network.
	settingAIEnabled      = "ai_enabled"       // "1" / "0"
	settingAIOllamaURL    = "ai_ollama_url"    // base URL, e.g. http://ollama:11434
	settingAIOllamaModel  = "ai_ollama_model"  // e.g. llama3.2:latest
	settingAISystemPrompt = "ai_system_prompt" // v2.12.10: optional override of the built-in system prompt

	// v2.12.36: multi-provider AI assistant. Provider selector picks one of
	// the four backends below; only the credentials for the active provider
	// are read on each chat turn.
	settingAIProvider          = "ai_provider"             // "ollama" | "ollama_cloud" | "anthropic" | "openai"; default "ollama"
	settingAIOllamaCloudAPIKey = "ai_ollama_cloud_api_key" // bearer token from ollama.com
	settingAIOllamaCloudModel  = "ai_ollama_cloud_model"   // e.g. gpt-oss:20b, qwen3-coder:480b-cloud
	settingAIAnthropicAPIKey   = "ai_anthropic_api_key"    // sk-ant-...
	settingAIAnthropicModel    = "ai_anthropic_model"      // e.g. claude-haiku-4-5-20251001
	settingAIOpenAIBaseURL     = "ai_openai_base_url"      // OpenAI-compatible endpoint root, defaults to https://api.openai.com/v1
	settingAIOpenAIAPIKey      = "ai_openai_api_key"       // bearer token (works with OpenAI, OpenRouter, Groq, Together, vLLM, LM Studio, etc.)
	settingAIOpenAIModel       = "ai_openai_model"         // e.g. gpt-4o-mini

	// v2.12.14: comma-separated list of response headers stripped from every
	// proxy-host's upstream response. Useful for blanket-removing things like
	// X-Frame-Options or X-Powered-By that an upstream insists on adding.
	// Concatenated with each proxy_host's own strip_response_headers in
	// syncCaddy before BuildProxyRoute fires.
	settingGlobalStripResponseHeaders = "global_strip_response_headers"

	// v2.14.4: when "1", restricts the Caddy HTTP server to h1 + h2 only
	// (removes h3/QUIC). Useful for clients that mishandle HTTP/3, e.g. older
	// Android Bitwarden builds.
	settingDisableHTTP3 = "disable_http3"
)

// sendEmail delivers a plain-text email via the SMTP settings stored in the DB.
// Returns an error if SMTP is not configured or delivery fails.
func sendEmail(db *sql.DB, subject, body string) error {
	host, _ := models.GetSetting(db, settingSMTPHost)
	if host == "" {
		return fmt.Errorf("SMTP not configured (no host)")
	}
	portStr, _ := models.GetSetting(db, settingSMTPPort)
	port := 587
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
		port = p
	}
	username, _ := models.GetSetting(db, settingSMTPUsername)
	password, _ := models.GetSetting(db, settingSMTPPassword)
	from, _ := models.GetSetting(db, settingSMTPFrom)
	toStr, _ := models.GetSetting(db, settingSMTPTo)
	security, _ := models.GetSetting(db, settingSMTPSecurity)
	skipVerifyStr, _ := models.GetSetting(db, settingSMTPSkipVerify)
	skipVerify := skipVerifyStr == "1"

	if from == "" {
		from = "caddyui@localhost"
	}
	if toStr == "" {
		return fmt.Errorf("SMTP not configured (no recipient)")
	}
	var recipients []string
	for _, addr := range strings.Split(toStr, ",") {
		if a := strings.TrimSpace(addr); a != "" {
			recipients = append(recipients, a)
		}
	}
	if len(recipients) == 0 {
		return fmt.Errorf("SMTP: no valid recipients")
	}

	serverAddr := fmt.Sprintf("%s:%d", host, port)
	// v2.9.209: strip CR/LF from any value that lands in a header line.
	// Without this, a user-controlled Subject of `hi\r\nBcc: attacker@evil`
	// would smuggle an extra header into the message envelope. Body is left
	// alone — newlines in body are just content, not header boundaries.
	stripCRLF := func(s string) string {
		return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	}
	from = stripCRLF(from)
	subject = stripCRLF(subject)
	safeRecipients := make([]string, len(recipients))
	for i, r := range recipients {
		safeRecipients[i] = stripCRLF(r)
	}
	msg := []byte(
		"From: CaddyUI <" + from + ">\r\n" +
			"To: " + strings.Join(safeRecipients, ", ") + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"\r\n" +
			body,
	)

	tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify} //nolint:gosec

	var authCfg smtp.Auth
	if username != "" {
		authCfg = smtp.PlainAuth("", username, password, host)
	}

	switch security {
	case "tls":
		// Implicit TLS (port 465): TLS handshake on connect.
		conn, err := tls.Dial("tcp", serverAddr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SMTP TLS dial: %w", err)
		}
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("SMTP client: %w", err)
		}
		defer c.Quit()
		if authCfg != nil {
			if err = c.Auth(authCfg); err != nil {
				return fmt.Errorf("SMTP auth: %w", err)
			}
		}
		if err = c.Mail(from); err != nil {
			return fmt.Errorf("SMTP MAIL FROM: %w", err)
		}
		for _, rcpt := range recipients {
			if err = c.Rcpt(rcpt); err != nil {
				return fmt.Errorf("SMTP RCPT TO %s: %w", rcpt, err)
			}
		}
		wc, err := c.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA: %w", err)
		}
		if _, err = wc.Write(msg); err != nil {
			return fmt.Errorf("SMTP write: %w", err)
		}
		return wc.Close()

	case "none":
		// Plain SMTP, no encryption.
		c, err := smtp.Dial(serverAddr)
		if err != nil {
			return fmt.Errorf("SMTP dial: %w", err)
		}
		defer c.Quit()
		if authCfg != nil {
			if err = c.Auth(authCfg); err != nil {
				return fmt.Errorf("SMTP auth: %w", err)
			}
		}
		if err = c.Mail(from); err != nil {
			return fmt.Errorf("SMTP MAIL FROM: %w", err)
		}
		for _, rcpt := range recipients {
			if err = c.Rcpt(rcpt); err != nil {
				return fmt.Errorf("SMTP RCPT TO %s: %w", rcpt, err)
			}
		}
		wc, err := c.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA: %w", err)
		}
		if _, err = wc.Write(msg); err != nil {
			return fmt.Errorf("SMTP write: %w", err)
		}
		return wc.Close()

	default:
		// STARTTLS (port 587): plain connect then upgrade.
		// We implement it manually so we can pass our tlsCfg (with optional skip verify).
		c, err := smtp.Dial(serverAddr)
		if err != nil {
			return fmt.Errorf("SMTP dial: %w", err)
		}
		defer c.Quit()
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err = c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("SMTP STARTTLS: %w", err)
			}
		}
		if authCfg != nil {
			if err = c.Auth(authCfg); err != nil {
				return fmt.Errorf("SMTP auth: %w", err)
			}
		}
		if err = c.Mail(from); err != nil {
			return fmt.Errorf("SMTP MAIL FROM: %w", err)
		}
		for _, rcpt := range recipients {
			if err = c.Rcpt(rcpt); err != nil {
				return fmt.Errorf("SMTP RCPT TO %s: %w", rcpt, err)
			}
		}
		wc, err := c.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA: %w", err)
		}
		if _, err = wc.Write(msg); err != nil {
			return fmt.Errorf("SMTP write: %w", err)
		}
		return wc.Close()
	}
}

// sendEmailTo is like sendEmail but sends to a specific address rather than
// the configured notification recipients.
func sendEmailTo(db *sql.DB, to, subject, body string) error {
	host, _ := models.GetSetting(db, settingSMTPHost)
	if host == "" {
		return fmt.Errorf("SMTP not configured (no host)")
	}
	portStr, _ := models.GetSetting(db, settingSMTPPort)
	port := 587
	if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
		port = p
	}
	username, _ := models.GetSetting(db, settingSMTPUsername)
	password, _ := models.GetSetting(db, settingSMTPPassword)
	from, _ := models.GetSetting(db, settingSMTPFrom)
	security, _ := models.GetSetting(db, settingSMTPSecurity)
	skipVerifyStr, _ := models.GetSetting(db, settingSMTPSkipVerify)
	skipVerify := skipVerifyStr == "1"

	if from == "" {
		from = "caddyui@localhost"
	}

	// v2.9.225: same CRLF strip applied to sendEmail (v2.9.209) — the second
	// SMTP code path in sendEmailTo also interpolated user-controlled values
	// straight into header lines, allowing header smuggling via \r\n in
	// `to`/`from`/`subject`. CodeQL flagged it as a separate "Email content
	// injection" finding from the v2.9.209 fix because the sites are distinct.
	stripCRLFTo := func(s string) string {
		return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	}
	from = stripCRLFTo(from)
	subject = stripCRLFTo(subject)
	to = stripCRLFTo(to)
	serverAddr := fmt.Sprintf("%s:%d", host, port)
	msg := []byte(
		"From: CaddyUI <" + from + ">\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"\r\n" +
			body,
	)

	tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify} //nolint:gosec

	var authCfg smtp.Auth
	if username != "" {
		authCfg = smtp.PlainAuth("", username, password, host)
	}

	switch security {
	case "tls":
		conn, err := tls.Dial("tcp", serverAddr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SMTP TLS dial: %w", err)
		}
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("SMTP client: %w", err)
		}
		defer c.Quit()
		if authCfg != nil {
			if err = c.Auth(authCfg); err != nil {
				return fmt.Errorf("SMTP auth: %w", err)
			}
		}
		if err = c.Mail(from); err != nil {
			return fmt.Errorf("SMTP MAIL FROM: %w", err)
		}
		if err = c.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT TO: %w", err)
		}
		wc, err := c.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA: %w", err)
		}
		_, _ = wc.Write(msg)
		_ = wc.Close()
	default: // "none" or "starttls"
		if err := smtp.SendMail(serverAddr, authCfg, from, []string{to}, msg); err != nil {
			return fmt.Errorf("SMTP SendMail: %w", err)
		}
	}
	return nil
}

// --- Password reset ---

// getForgotPassword renders the "forgot password" form.
func (s *Server) getForgotPassword(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "forgot_password.html", map[string]any{
		"Section": "",
		"Sent":    r.URL.Query().Get("sent") == "1",
		"Error":   r.URL.Query().Get("error"),
	})
}

// postForgotPassword processes the forgot-password form submission.
// Always shows the "check your email" message even if the address doesn't
// exist (prevents email enumeration).
func (s *Server) postForgotPassword(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	if email == "" {
		http.Redirect(w, r, "/forgot-password?error=Enter+your+email+address", http.StatusSeeOther)
		return
	}
	// Look up user — don't reveal if email exists.
	u, _ := models.GetUserByEmail(s.DB, email)
	if u != nil {
		// Generate token.
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		token := hex.EncodeToString(raw)
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
		expires := time.Now().Add(time.Hour).Unix()
		// Store token hash in settings: key=pw_reset_<hash>, value=<userID>:<expires>
		_ = models.SetSetting(s.DB, "pw_reset_"+hash, fmt.Sprintf("%d:%d", u.ID, expires))
		// Determine base URL for the reset link.
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		resetURL := fmt.Sprintf("%s://%s/reset-password?token=%s", scheme, r.Host, token)
		body := fmt.Sprintf(
			"Hello %s,\n\nA password reset was requested for your CaddyUI account.\n\n"+
				"Click the link below to set a new password (expires in 1 hour):\n\n"+
				"%s\n\n"+
				"If you did not request this, you can safely ignore this email.\n\n"+
				"— CaddyUI", u.Name, resetURL)
		if err := sendEmailTo(s.DB, email, "CaddyUI password reset", body); err != nil {
			log.Printf("forgot-password: sendEmail to %s: %v", sanitizeForLog(email), err)
		}
	}
	http.Redirect(w, r, "/forgot-password?sent=1", http.StatusSeeOther)
}

// getResetPassword renders the new-password form for a valid reset token.
func (s *Server) getResetPassword(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Redirect(w, r, "/forgot-password?error=Invalid+reset+link", http.StatusSeeOther)
		return
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "pw_reset_"+hash)
	if val == "" || !validResetToken(val) {
		s.render(w, r, "reset_password.html", map[string]any{"Section": "", "Invalid": true})
		return
	}
	s.render(w, r, "reset_password.html", map[string]any{
		"Section": "",
		"Token":   token,
		"Error":   r.URL.Query().Get("error"),
	})
}

// postResetPassword validates the token and sets the new password.
func (s *Server) postResetPassword(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.FormValue("token"))
	newPwd := r.FormValue("password")
	confirmPwd := r.FormValue("confirm_password")

	if token == "" {
		http.Redirect(w, r, "/forgot-password?error=Invalid+token", http.StatusSeeOther)
		return
	}
	if len(newPwd) < 8 {
		http.Redirect(w, r, "/reset-password?token="+url.QueryEscape(token)+"&error=Password+must+be+at+least+8+characters", http.StatusSeeOther)
		return
	}
	if newPwd != confirmPwd {
		http.Redirect(w, r, "/reset-password?token="+url.QueryEscape(token)+"&error=Passwords+do+not+match", http.StatusSeeOther)
		return
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "pw_reset_"+hash)
	if val == "" || !validResetToken(val) {
		s.render(w, r, "reset_password.html", map[string]any{"Section": "", "Invalid": true})
		return
	}

	// Parse userID from stored value.
	parts := strings.SplitN(val, ":", 2)
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		s.render(w, r, "reset_password.html", map[string]any{"Section": "", "Invalid": true})
		return
	}

	// Hash new password.
	pwHash, err := auth.HashPassword(newPwd)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := models.UpdateUserPassword(s.DB, userID, pwHash); err != nil {
		http.Error(w, "failed to update password", http.StatusInternalServerError)
		return
	}
	// Consume the token.
	_ = models.SetSetting(s.DB, "pw_reset_"+hash, "")
	http.Redirect(w, r, "/login?reset=1", http.StatusSeeOther)
}

// postInviteUser creates a stub user account and sends an invite email.
func (s *Server) postInviteUser(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.FormValue("invite_email")))
	role := r.FormValue("invite_role")
	if email == "" {
		http.Redirect(w, r, "/users?error=Email+required", http.StatusSeeOther)
		return
	}
	if role != models.RoleAdmin && role != models.RoleUser && role != models.RoleView {
		role = models.RoleUser
	}
	// Check not already registered.
	if u, _ := models.GetUserByEmail(s.DB, email); u != nil {
		http.Redirect(w, r, "/users?error=User+already+exists", http.StatusSeeOther)
		return
	}
	// Create disabled stub user with empty password hash.
	userID, err := models.CreateUser(s.DB, email, "", email, role)
	if err != nil {
		http.Error(w, "create user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Generate invite token.
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := hex.EncodeToString(raw)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	expires := time.Now().Add(7 * 24 * time.Hour).Unix()
	_ = models.SetSetting(s.DB, "invite_"+hash, fmt.Sprintf("%d:%d", userID, expires))

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	acceptURL := fmt.Sprintf("%s://%s/accept-invite?token=%s", scheme, r.Host, token)
	body := fmt.Sprintf(
		"You've been invited to CaddyUI.\n\n"+
			"Click the link below to set your password and activate your account (link expires in 7 days):\n\n"+
			"%s\n\n"+
			"— CaddyUI", acceptURL)
	if err := sendEmailTo(s.DB, email, "You're invited to CaddyUI", body); err != nil {
		log.Printf("invite: sendEmail to %s: %v", sanitizeForLog(email), err)
	}
	http.Redirect(w, r, "/users?invited=1", http.StatusSeeOther)
}

// getAcceptInvite renders the accept-invite form.
func (s *Server) getAcceptInvite(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "invite_"+hash)
	if val == "" || !validResetToken(val) {
		s.render(w, r, "accept_invite.html", map[string]any{"Section": "", "Invalid": true})
		return
	}
	s.render(w, r, "accept_invite.html", map[string]any{
		"Section": "",
		"Token":   token,
		"Error":   r.URL.Query().Get("error"),
	})
}

// postAcceptInvite validates the invite token and activates the account.
func (s *Server) postAcceptInvite(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.FormValue("token"))
	newPwd := r.FormValue("password")
	confirmPwd := r.FormValue("confirm_password")
	if token == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if len(newPwd) < 8 {
		http.Redirect(w, r, "/accept-invite?token="+url.QueryEscape(token)+"&error=Password+must+be+at+least+8+characters", http.StatusSeeOther)
		return
	}
	if newPwd != confirmPwd {
		http.Redirect(w, r, "/accept-invite?token="+url.QueryEscape(token)+"&error=Passwords+do+not+match", http.StatusSeeOther)
		return
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	val, _ := models.GetSetting(s.DB, "invite_"+hash)
	if val == "" || !validResetToken(val) {
		s.render(w, r, "accept_invite.html", map[string]any{"Section": "", "Invalid": true})
		return
	}
	parts := strings.SplitN(val, ":", 2)
	userID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	pwHash, err := auth.HashPassword(newPwd)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := models.UpdateUserPassword(s.DB, userID, pwHash); err != nil {
		http.Error(w, "update password: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.SetSetting(s.DB, "invite_"+hash, "")
	http.Redirect(w, r, "/login?invited=1", http.StatusSeeOther)
}

// exportProxyHost returns a proxy host's configuration as a JSON file download.
func (s *Server) exportProxyHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		http.NotFound(w, r)
		return
	}
	// Strip runtime fields before export.
	ph.ID = 0
	ph.OwnerID = sql.NullInt64{}
	ph.OwnerEmail = ""
	ph.DNSRecordID = ""
	ph.CreatedAt = time.Time{}
	ph.UpdatedAt = time.Time{}

	data, err := json.MarshalIndent(ph, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fname := strings.ReplaceAll(strings.SplitN(ph.Domains, ",", 2)[0], "*", "_")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, strings.TrimSpace(fname)))
	_, _ = w.Write(data)
}

// exportProxyHostCaddyfile — v2.12.50: download a single proxy host as a
// Caddyfile snippet (just the one site block, no banner). Useful for
// hand-off to other Caddy deployments or pasting into a colleague's
// Caddyfile without the rest of the server's config tagging along.
//
// Same RBAC visibility as the JSON variant — anyone who can view the
// host (admin, owner, or group peer) can export it.
func (s *Server) exportProxyHostCaddyfile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		http.NotFound(w, r)
		return
	}
	body := caddy.RenderProxyHostCaddyfileWithCertificate(*ph, s.certificateForCaddyfile(ph.CertificateID))
	fname := strings.ReplaceAll(strings.SplitN(ph.Domains, ",", 2)[0], "*", "_")
	fname = strings.TrimSpace(fname)
	if fname == "" {
		fname = fmt.Sprintf("proxy-host-%d", id)
	}
	w.Header().Set("Content-Type", "text/caddyfile; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.caddyfile"`, fname))
	_, _ = w.Write([]byte(body))
}

// exportAllProxyHosts downloads all proxy hosts for the current server as a JSON array.
// Admin exports the full list; non-admin exports only their own hosts.
func (s *Server) exportAllProxyHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	var viewerID int64
	if !isAdmin {
		viewerID = cu.ID
	}
	sid := s.currentServerID(r)
	hosts, err := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ts := time.Now().Format("20060102-150405")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxy-hosts-%s.json"`, ts))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(hosts)
}

// exportServerCaddyfile — v2.12.49: download every enabled proxy host,
// redirection, and raw route for the current server as a single Caddyfile
// snapshot. Inverse of the existing /caddyfile-import paste flow. Admin
// gets the full server config; non-admin gets only their own resources
// (same scoping the JSON exports use).
func (s *Server) exportServerCaddyfile(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	var viewerID int64
	if !isAdmin {
		viewerID = cu.ID
	}
	sid := s.currentServerID(r)
	peerIDs := s.groupPeerIDs(r)

	hosts, err := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin, peerIDs)
	if err != nil {
		http.Error(w, "list proxy hosts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	redirects, err := models.ListRedirectionHosts(s.DB, sid, viewerID, isAdmin, peerIDs)
	if err != nil {
		http.Error(w, "list redirections: "+err.Error(), http.StatusInternalServerError)
		return
	}
	raws, err := models.ListRawRoutes(s.DB, sid, viewerID, isAdmin, peerIDs)
	if err != nil {
		http.Error(w, "list raw routes: "+err.Error(), http.StatusInternalServerError)
		return
	}

	serverName := ""
	if srv, _ := models.GetCaddyServer(s.DB, sid); srv != nil {
		serverName = srv.Name
	}

	certs, _ := models.ListCertificates(s.DB, sid)
	body := caddy.RenderServerCaddyfile(serverName, hosts, redirects, raws, certs)
	ts := time.Now().Format("20060102-150405")
	fname := "Caddyfile"
	if serverName != "" {
		fname = fmt.Sprintf("Caddyfile-%s-%s", strings.ReplaceAll(serverName, " ", "_"), ts)
	} else {
		fname = fmt.Sprintf("Caddyfile-%s", ts)
	}
	w.Header().Set("Content-Type", "text/caddyfile; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, fname))
	_, _ = w.Write([]byte(body))
}

// importProxyHost creates a new proxy host from an uploaded JSON file.
func (s *Server) importProxyHost(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(1 << 20) // 1 MiB
	f, _, err := r.FormFile("config_file")
	if err != nil {
		http.Error(w, "no file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
		return
	}
	var ph models.ProxyHost
	if err := json.Unmarshal(data, &ph); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Force safe defaults.
	ph.ID = 0
	ph.Enabled = false
	cu := s.currentUser(r)
	var ownerID int64
	if cu != nil {
		ownerID = cu.ID
	}
	newID, err := models.CreateProxyHost(s.DB, s.currentServerID(r), ownerID, &ph)
	if err != nil {
		http.Error(w, "create: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/proxy-hosts/%d/edit", newID), http.StatusSeeOther)
}

// validResetToken checks the token value (format: "userID:expiresUnix") is still valid.
func validResetToken(val string) bool {
	parts := strings.SplitN(val, ":", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < exp
}

// --- API Tokens ---

func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	tokens, err := models.ListAPITokens(s.DB, cu.ID, isAdmin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	createdToken := r.URL.Query().Get("created")
	s.render(w, r, "api_tokens.html", map[string]any{
		"User":         cu,
		"Tokens":       tokens,
		"IsAdmin":      isAdmin,
		"Section":      "api_tokens",
		"CreatedToken": createdToken,
	})
}

func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "My token"
	}
	// Generate 32 random bytes → base64url → prefix "cadu_"
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		http.Error(w, "could not generate token", http.StatusInternalServerError)
		return
	}
	rawToken := "cadu_" + base64.RawURLEncoding.EncodeToString(rawBytes)
	h := sha256.Sum256([]byte(rawToken))
	hash := fmt.Sprintf("%x", h)
	// Optional expiry
	var expiresAt *time.Time
	if exp := strings.TrimSpace(r.FormValue("expires_at")); exp != "" {
		t, err := time.ParseInLocation("2006-01-02", exp, time.UTC)
		if err == nil {
			expiresAt = &t
		}
	}
	scopes := strings.TrimSpace(r.FormValue("scopes"))
	switch scopes {
	case models.TokenScopeReadOnly, models.TokenScopeProxyWrite:
		// valid
	default:
		scopes = models.TokenScopeFull
	}
	_, err := models.CreateAPIToken(s.DB, cu.ID, name, hash, scopes, expiresAt)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "api_token_create", "token", name, true)
	// Show the token once via a query param on redirect to the list page
	// (only used once, HTTPS only).
	http.Redirect(w, r, "/api-tokens?created="+url.QueryEscape(rawToken), http.StatusSeeOther)
}

func (s *Server) revokeAPIToken(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	// Admin can revoke any token; user can only revoke their own.
	ownerID := cu.ID
	if cu.Role == models.RoleAdmin {
		ownerID = 0 // skip ownership check
	}
	if err := models.DeleteAPIToken(s.DB, id, ownerID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "api_token_revoke", fmt.Sprintf("token:%d", id), "", true)
	http.Redirect(w, r, "/api-tokens", http.StatusSeeOther)
}

// getLiveTraffic renders the live traffic feed page.
func (s *Server) getLiveTraffic(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	serverID := s.currentServerID(r)
	if r.URL.Query().Has("server") {
		raw := strings.TrimSpace(r.URL.Query().Get("server"))
		if raw == "" || raw == "0" || raw == "all" {
			serverID = 0
		} else if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			serverID = parsed
		}
	}
	// Seed with last 50 events for initial load.
	events, err := models.RecentAccessEvents(s.DB, 0, 50, serverID)
	if err != nil {
		log.Printf("live-traffic: query: %v", err)
	}
	s.render(w, r, "live_traffic.html", map[string]any{
		"User": u, "Events": events,
		"AllServers":       func() []models.CaddyServer { servers, _ := models.ListCaddyServers(s.DB); return servers }(),
		"SelectedServerID": serverID, "Section": "live_traffic",
	})
}

// liveTrafficStream is an SSE endpoint that pushes new access events as they
// arrive. The client sends a ?since=<id> query param (the highest ID it has
// seen); the server polls every 2s and emits any rows with id > since as a
// JSON array in the SSE "data" field. The client advances its cursor.
func (s *Server) liveTrafficStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	var cursor int64
	if raw := r.URL.Query().Get("since"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			cursor = n
		}
	}
	var serverID int64
	if raw := strings.TrimSpace(r.URL.Query().Get("server")); raw != "" && raw != "0" && raw != "all" {
		serverID, _ = strconv.ParseInt(raw, 10, 64)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := models.RecentAccessEvents(s.DB, cursor, 100, serverID)
			if err != nil {
				log.Printf("live-traffic SSE: %v", err)
				continue
			}
			if len(events) == 0 {
				// heartbeat
				fmt.Fprintf(w, ": ping\n\n")
				flusher.Flush()
				continue
			}
			// Advance cursor to highest ID seen.
			for _, e := range events {
				if e.ID > cursor {
					cursor = e.ID
				}
			}
			// Events come newest-first; reverse so the client appends in order.
			for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
				events[i], events[j] = events[j], events[i]
			}
			type wireEvent struct {
				ID         int64  `json:"id"`
				TS         string `json:"ts"`
				ServerID   int64  `json:"server_id"`
				ServerName string `json:"server_name"`
				Host       string `json:"host"`
				Path       string `json:"path"`
				Method     string `json:"method"`
				Status     int    `json:"status"`
				ClientIP   string `json:"client_ip"`
				DurationMs int64  `json:"duration_ms"`
				BytesOut   int64  `json:"bytes_out"`
			}
			wire := make([]wireEvent, len(events))
			for i, e := range events {
				wire[i] = wireEvent{
					ID:         e.ID,
					TS:         e.TS.Format(time.RFC3339),
					ServerID:   e.ServerID,
					ServerName: e.ServerName,
					Host:       e.Host,
					Path:       e.Path,
					Method:     e.Method,
					Status:     e.Status,
					ClientIP:   e.ClientIP,
					DurationMs: e.DurationMs,
					BytesOut:   e.BytesOut,
				}
			}
			data, _ := json.Marshal(wire)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// getProfile renders the logged-in user's profile page (name + password change).
func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.render(w, r, "profile.html", map[string]any{
		"User":  cu,
		"Flash": r.URL.Query().Get("flash"),
		"Error": r.URL.Query().Get("error"),
	})
}

// postProfile handles name update and password change on the profile page.
func (s *Server) postProfile(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	action := r.FormValue("action")
	switch action {
	case "update_name":
		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" {
			http.Redirect(w, r, "/profile?error=Name+cannot+be+empty", http.StatusFound)
			return
		}
		if _, err := s.DB.Exec(`UPDATE users SET name=? WHERE id=?`, name, cu.ID); err != nil {
			log.Printf("profile update_name: %v", err)
			http.Redirect(w, r, "/profile?error=Failed+to+update+name", http.StatusFound)
			return
		}
		_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "profile_update_name", "", "", true)
		http.Redirect(w, r, "/profile?flash=Name+updated+successfully", http.StatusFound)
	case "change_password":
		currentPw := r.FormValue("current_password")
		newPw := r.FormValue("new_password")
		confirmPw := r.FormValue("confirm_password")
		if newPw != confirmPw {
			http.Redirect(w, r, "/profile?error=New+passwords+do+not+match", http.StatusFound)
			return
		}
		if len(newPw) < 8 {
			http.Redirect(w, r, "/profile?error=Password+must+be+at+least+8+characters", http.StatusFound)
			return
		}
		u, err := models.GetUserByEmail(s.DB, cu.Email)
		if err != nil || !auth.CheckPassword(u.PasswordHash, currentPw) {
			http.Redirect(w, r, "/profile?error=Current+password+is+incorrect", http.StatusFound)
			return
		}
		hash, err := auth.HashPassword(newPw)
		if err != nil {
			http.Redirect(w, r, "/profile?error=Failed+to+hash+password", http.StatusFound)
			return
		}
		if _, err := s.DB.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, cu.ID); err != nil {
			log.Printf("profile change_password: %v", err)
			http.Redirect(w, r, "/profile?error=Failed+to+update+password", http.StatusFound)
			return
		}
		_ = models.LogActivity(s.DB, s.currentServerID(r), cu.Email, "profile_change_password", "", "", true)
		http.Redirect(w, r, "/profile?flash=Password+changed+successfully", http.StatusFound)
	default:
		http.Redirect(w, r, "/profile", http.StatusFound)
	}
}

// getCaddyConfig fetches the live Caddy JSON config and renders it in a
// read-only prettified code block. Available to all authenticated users.
func (s *Server) getCaddyConfig(w http.ResponseWriter, r *http.Request) {
	_, rawJSON, err := s.caddyForRequest(r).FetchConfig()
	if err != nil {
		s.render(w, r, "caddy_config.html", map[string]any{
			"User":    s.currentUser(r),
			"Section": "caddy_config",
			"Error":   "Could not fetch Caddy config: " + err.Error(),
		})
		return
	}
	// Pretty-print the JSON for readability.
	var v any
	if err := json.Unmarshal([]byte(rawJSON), &v); err == nil {
		if b, err := json.MarshalIndent(v, "", "  "); err == nil {
			rawJSON = string(b)
		}
	}
	s.render(w, r, "caddy_config.html", map[string]any{
		"User":       s.currentUser(r),
		"Section":    "caddy_config",
		"ConfigJSON": rawJSON,
	})
}
