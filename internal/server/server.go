package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/analytics"
	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	DBPath string
	pendingTOTP   sync.Map // token → userID (int64), auto-deleted after 5 min

	// version-check cache (Docker Hub, 1h TTL)
	versionMu     sync.Mutex
	latestVersion string
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

	// v2.7.0: handle to the analytics ingest listener. Wired by main.go
	// via SetAnalyticsIngest after Server construction (rather than as a
	// New() arg) so the wiring order stays readable — the ingest owns a
	// DB ref that has to exist before we hand it over.
	analyticsIngest *analytics.Ingest

	// v2.9.2: HTTP client used by the background per-proxy-host health checker.
	healthClient *http.Client
}

// SetAnalyticsIngest plumbs the analytics ingest listener into the server
// so handlers can surface its stats on /analytics and /settings. Called
// once at startup from main.go after the ingest listener has bound.
// Passing nil is valid and disables the stats card — happens when the
// CADDYUI_INGEST_LISTEN env var is blank or the bind failed at startup.
func (s *Server) SetAnalyticsIngest(ing *analytics.Ingest) {
	s.analyticsIngest = ing
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
		DB:             db,
		Caddy:          caddyClient,
		Templates:      tpl,
		Static:         static,
		CaddyfilePath:  caddyfilePath,
		Version:        version,
		DBPath:         dbPath,
		healthFailures: map[int64]int{},
		appHealth:      map[int64]appHealthEntry{},
	}
	// Initialize health check HTTP client (short timeouts, no redirect following).
	s.healthClient = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // check reachability, not cert validity
		},
	}
	go s.runHealthChecker()
	go s.runAutoSyncLoop()
	go s.runMaintenanceWindowLoop()
	go s.runActivityLogCleanup()
	go s.runAccessDailyAggregator()
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
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
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
		r.Get("/", s.dashboard)

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

		// Write routes — admin-only in practice. Viewers get 403 via requireWrite.
		r.Group(func(r chi.Router) {
			r.Use(s.requireWrite)

			r.Get("/proxy-hosts/new", s.newProxyHost)
			r.Post("/proxy-hosts", s.createProxyHost)
			r.Get("/proxy-hosts/{id}/export.json", s.exportProxyHost)
			r.Get("/proxy-hosts/export-all.json", s.exportAllProxyHosts)
			r.Post("/proxy-hosts/import", s.importProxyHost)
			r.Get("/proxy-hosts/{id}/edit", s.editProxyHost)
			r.Post("/proxy-hosts/{id}", s.updateProxyHost)
			r.Post("/proxy-hosts/{id}/delete", s.deleteProxyHost)
			r.Post("/proxy-hosts/{id}/clone", s.cloneProxyHost)
			r.Post("/proxy-hosts/{id}/toggle", s.toggleProxyHost)
			r.Post("/proxy-hosts/{id}/maintenance", s.toggleMaintenanceMode)
			r.Post("/proxy-hosts/bulk-toggle", s.bulkToggleProxyHosts)
			r.Post("/proxy-hosts/bulk-maintenance", s.bulkMaintenanceProxyHosts)
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
			r.Post("/servers/{id}/delete", s.deleteServer)

			// v2.7.2: create/edit moved up to the requireWrite group so
			// user-role accounts can manage their own certs. The remaining
			// admin-only cert concern — whole-cert delete with its
			// cross-owner blast radius — is enforced by the inline role check
			// inside deleteCertificate, not by route gating, so a user-role
			// account can still delete a cert they own (see the ownership
			// branch in that handler).

			// Feature F: settings page (admin-only).
			r.Get("/settings", s.getSettings)
			r.Post("/settings", s.postSettings)
			r.Post("/settings/test-webhook", s.postTestWebhook)
			r.Post("/settings/test-email", s.postTestEmail)
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("template %s: %v", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	clientIP := clientIPFromRequest(r)
	if maxStr, _ := models.GetSetting(s.DB, settingMaxLoginAttempts); maxStr != "" {
		if maxAttempts, err := strconv.Atoi(strings.TrimSpace(maxStr)); err == nil && maxAttempts > 0 {
			var failCount int
			_ = s.DB.QueryRow(
				`SELECT COUNT(*) FROM activity_log WHERE action = 'login_fail' AND detail LIKE ? AND created_at > datetime('now', '-15 minutes')`,
				"%ip:"+clientIP+"%",
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
		s.render(w, r, "totp_setup.html", map[string]any{
			"User":        u,
			"Secret":      secret,
			"OTPAuth":     "otpauth://totp/CaddyUI:" + u.Email + "?secret=" + secret + "&issuer=CaddyUI",
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

	// Today's analytics stats — v2.12.8: scoped to the active server's
	// hostnames so the dashboard cards match what the picker has
	// selected. Previously called AccessTotalsSince("") which sums the
	// whole fleet, leaking other-server traffic into the active-server
	// view (confusing on multi-server installs). Sums per-host the way
	// /analytics already does when ?server=<id> is set.
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
	for _, host := range hostsForActive {
		if t, err := models.AccessTotalsSince(s.DB, todayStart, host); err == nil {
			todayViews += t.Views
			todayVisitors += t.Visitors
		}
		if bw, err := models.BandwidthSince(s.DB, todayStart, host); err == nil {
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

// --- Proxy Hosts ---
type advancedRouteRow struct {
	ID      int64
	Label   string
	Hosts   string // comma-joined hosts from match[].host[]
	Summary string // e.g. "3 upstreams · 3 redirects"
	Enabled bool
	// v2.7.4: ownership flags for template-side gating. CanEdit hides
	// Edit/Delete on rows the viewer is only seeing via group peer-ship;
	// OwnerEmail + IsTeamRow render the "Team: <email>" chip.
	OwnerEmail string
	CanEdit    bool
	IsTeamRow  bool
}

func (s *Server) listProxyHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	peers := s.groupPeerIDs(r)
	hosts, err := models.ListProxyHosts(s.DB, s.currentServerID(r), viewerID, isAdmin, peers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raws, _ := models.ListRawRoutes(s.DB, s.currentServerID(r), viewerID, isAdmin, peers)
	var advancedRows []advancedRouteRow
	for _, rr := range raws {
		var decoded any
		if err := json.Unmarshal([]byte(rr.JSONData), &decoded); err != nil {
			continue
		}
		hostSet := map[string]struct{}{}
		var up, redirs, files int
		for _, route := range flattenToRouteMaps(decoded) {
			for _, h := range hostsFromRoute(route) {
				hostSet[h] = struct{}{}
			}
			countHandlers(route, &up, &redirs, &files)
		}
		hosts := make([]string, 0, len(hostSet))
		for h := range hostSet {
			hosts = append(hosts, h)
		}
		var parts []string
		if up > 0 {
			parts = append(parts, pluralize(up, "upstream", "upstreams"))
		}
		if files > 0 {
			parts = append(parts, pluralize(files, "file server", "file servers"))
		}
		if redirs > 0 {
			parts = append(parts, pluralize(redirs, "redirect", "redirects"))
		}
		summary := strings.Join(parts, " · ")
		if summary == "" {
			summary = "custom handlers"
		}
		canEdit := isAdmin || (rr.OwnerID.Valid && viewerID != 0 && rr.OwnerID.Int64 == viewerID)
		isTeam := !isAdmin && rr.OwnerID.Valid && viewerID != 0 && rr.OwnerID.Int64 != viewerID
		advancedRows = append(advancedRows, advancedRouteRow{
			ID: rr.ID, Label: rr.Label, Hosts: strings.Join(hosts, ", "),
			Summary: summary, Enabled: rr.Enabled,
			OwnerEmail: rr.OwnerEmail, CanEdit: canEdit, IsTeamRow: isTeam,
		})
	}
	// Tag filtering: ?tag=production narrows the list to hosts bearing that tag.
	activeTag := strings.TrimSpace(r.URL.Query().Get("tag"))
	if activeTag != "" {
		filtered := hosts[:0]
		for _, h := range hosts {
			for _, t := range h.TagList() {
				if strings.EqualFold(t, activeTag) {
					filtered = append(filtered, h)
					break
				}
			}
		}
		hosts = filtered
	}

	// Status filter: ?status=enabled|disabled|maintenance|all
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	if statusFilter != "" && statusFilter != "all" {
		filtered := hosts[:0]
		for _, h := range hosts {
			switch statusFilter {
			case "enabled":
				if h.Enabled && !h.MaintenanceMode {
					filtered = append(filtered, h)
				}
			case "disabled":
				if !h.Enabled {
					filtered = append(filtered, h)
				}
			case "maintenance":
				if h.MaintenanceMode {
					filtered = append(filtered, h)
				}
			}
		}
		hosts = filtered
	}

	// Load latest health check for each host.
	hostIDs := make([]int64, len(hosts))
	for i, p := range hosts {
		hostIDs[i] = p.ID
	}
	healthMap, _ := models.LatestProxyHealth(s.DB, hostIDs)

	// Per-host today request counts (best-effort — zero if analytics disabled).
	hostRequestsToday := make(map[int64]int)
	if domainCounts, err := models.DomainRequestsToday(s.DB); err == nil {
		for _, h := range hosts {
			total := 0
			for _, d := range h.DomainList() {
				total += domainCounts[strings.ToLower(d)]
			}
			if total > 0 {
				hostRequestsToday[h.ID] = total
			}
		}
	}

	// Build a set of host IDs that have been modified since the last sync.
	// This lets the template show a warning badge on stale hosts.
	var lastSyncTime time.Time
	_ = s.DB.QueryRow(
		`SELECT created_at FROM activity_log WHERE server_id = ? AND action = 'sync_applied' ORDER BY id DESC LIMIT 1`,
		s.currentServerID(r),
	).Scan(&lastSyncTime)
	needsSync := make(map[int64]bool)
	if !lastSyncTime.IsZero() {
		for _, h := range hosts {
			if h.UpdatedAt.After(lastSyncTime) {
				needsSync[h.ID] = true
			}
		}
	}

	s.render(w, r, "proxy_hosts.html", map[string]any{
		"User":         s.currentUser(r),
		"Hosts":        hosts,
		"AdvancedRows": advancedRows,
		"Section":      "proxy",
		// v2.7.4: thread viewer ID so templates can hide Edit/Delete on rows
		// the user is only seeing via group peer-ship, and render a
		// "Team: <email>" chip instead. Security still enforced in the
		// update/delete handlers — this is UX clarity, not a gate.
		"ViewerID":          viewerID,
		"HealthMap":         healthMap,
		"ActiveTag":         activeTag,
		"StatusFilter":      statusFilter,
		"NeedsSync":         needsSync,
		"HostRequestsToday": hostRequestsToday,
	})
}

// getProxyHostHealth renders the per-host health history page (/proxy-hosts/{id}/health).
func (s *Server) getProxyHostHealth(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	host, err := models.GetProxyHost(s.DB, id)
	if err != nil || host == nil {
		http.NotFound(w, r)
		return
	}
	checks, err := models.GetProxyHealthHistory(s.DB, id, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Calculate uptime % for last 24 h: (ok checks / total checks) * 100.
	var total, okCount int
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, c := range checks {
		if c.CheckedAt.After(cutoff) {
			total++
			if c.OK {
				okCount++
			}
		}
	}
	var uptime float64
	if total > 0 {
		uptime = float64(okCount) / float64(total) * 100
	}
	s.render(w, r, "proxy_host_health.html", map[string]any{
		"User":    s.currentUser(r),
		"Host":    host,
		"Checks":  checks,
		"Uptime":  uptime,
		"Total":   total,
		"Section": "proxy",
	})
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// countHandlers walks a route's handle[] (and any nested subroute/handle_path
// routes) and tallies handler types so the proxy hosts list can show a quick
// summary of what an Advanced route does.
func countHandlers(route map[string]any, upstreams, redirects, fileServers *int) {
	handle, _ := route["handle"].([]any)
	for _, h := range handle {
		m, _ := h.(map[string]any)
		if m == nil {
			continue
		}
		switch m["handler"] {
		case "reverse_proxy":
			*upstreams++
		case "file_server":
			*fileServers++
		case "static_response":
			if sc, ok := m["status_code"].(float64); ok && sc >= 300 && sc < 400 {
				*redirects++
			} else if headers, ok := m["headers"].(map[string]any); ok {
				if _, hasLoc := headers["Location"]; hasLoc {
					*redirects++
				}
			}
		case "subroute":
			if sub, ok := m["routes"].([]any); ok {
				for _, r := range sub {
					if rm, ok := r.(map[string]any); ok {
						countHandlers(rm, upstreams, redirects, fileServers)
					}
				}
			}
		}
	}
}

// toggleProxyHost flips the enabled state on a proxy host and triggers a sync.
func (s *Server) toggleProxyHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if !isAdmin {
		host, err := models.GetProxyHost(s.DB, id)
		if err != nil || host == nil || !host.OwnerID.Valid || host.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	enabled, err := models.ToggleProxyHost(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "proxy_enable"
	if !enabled {
		action = "proxy_disable"
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), action, fmt.Sprintf("proxy:%d", id), "", true)
	s.syncCaddy(s.currentServerID(r), false)
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/proxy-hosts"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// bulkToggleProxyHosts enables or disables a set of proxy hosts in one shot.
// Expects form fields: ids[]={id,...} and action=enable|disable.
// Admin/write users only (the route is inside the requireWrite middleware block).
func (s *Server) bulkToggleProxyHosts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action") // "enable" or "disable"
	if action != "enable" && action != "disable" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	enabled := action == "enable"

	rawIDs := r.Form["ids[]"]
	if len(rawIDs) == 0 {
		http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
		return
	}

	var serverID int64
	for _, raw := range rawIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		ph, err := models.GetProxyHost(s.DB, id)
		if err != nil || ph == nil {
			continue
		}
		if ph.Enabled != enabled {
			ph.Enabled = enabled
			if err := models.UpdateProxyHost(s.DB, ph); err != nil {
				log.Printf("bulkToggle: update %d: %v", id, err)
				continue
			}
			if serverID == 0 {
				serverID = ph.ServerID
			}
		}
	}
	if serverID != 0 {
		if err := s.syncCaddy(serverID, false); err != nil {
			log.Printf("bulkToggle: syncCaddy(%d): %v", serverID, err)
		}
	}
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

// bulkMaintenanceProxyHosts enables or disables maintenance mode for a set of
// proxy hosts. Expects form fields: ids[]={id,...} and action=enable|disable.
func (s *Server) bulkMaintenanceProxyHosts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	if action != "enable" && action != "disable" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	maint := action == "enable"

	rawIDs := r.Form["ids[]"]
	if len(rawIDs) == 0 {
		http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
		return
	}

	var serverID int64
	for _, raw := range rawIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		ph, err := models.GetProxyHost(s.DB, id)
		if err != nil || ph == nil {
			continue
		}
		if ph.MaintenanceMode != maint {
			ph.MaintenanceMode = maint
			if err := models.UpdateProxyHost(s.DB, ph); err != nil {
				log.Printf("bulkMaintenance: update %d: %v", id, err)
				continue
			}
			if serverID == 0 {
				serverID = ph.ServerID
			}
		}
	}
	if serverID != 0 {
		if err := s.syncCaddy(serverID, false); err != nil {
			log.Printf("bulkMaintenance: syncCaddy(%d): %v", serverID, err)
		}
	}
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

// bulkDeleteProxyHosts deletes a set of proxy hosts in one shot.
// Expects form field: ids[]={id,...}.
// Admin can delete any host; non-admins can only delete their own.
func (s *Server) bulkDeleteProxyHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	_ = r.ParseForm()
	ids := r.Form["ids[]"]
	if len(ids) == 0 {
		http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
		return
	}
	sid := s.currentServerID(r)
	deleted := 0
	for _, raw := range ids {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		// Ownership check: admin can delete any, others only their own.
		if !isAdmin {
			ph, err := models.GetProxyHost(s.DB, id)
			if err != nil || ph == nil || !ph.OwnerID.Valid || ph.OwnerID.Int64 != cu.ID {
				continue
			}
		}
		if err := models.DeleteProxyHost(s.DB, id); err != nil {
			log.Printf("bulk-delete proxy host %d: %v", id, err)
			continue
		}
		deleted++
		_ = models.LogActivity(s.DB, sid, cu.Email, "proxy_host_delete", "id", strconv.FormatInt(id, 10), true)
	}
	if deleted > 0 {
		if err := s.syncCaddy(sid, false); err != nil {
			log.Printf("bulk-delete: sync error: %v", err)
		}
	}
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

// reorderProxyHosts — v2.11.11: writes a new sort_order for each proxy
// host based on its index in the submitted ids[] list. Multiplied by 10
// so future single-row Sort Order edits can wedge between drag-saved
// rows without a full re-renumber. Skips Caddy sync — list ordering is
// UI-only and doesn't change the generated config. Non-admins can only
// reorder rows they own; foreign rows in the list are silently ignored.
func (s *Server) reorderProxyHosts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	rawIDs := r.Form["ids[]"]
	if len(rawIDs) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	for i, raw := range rawIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		if !isAdmin {
			ph, err := models.GetProxyHost(s.DB, id)
			if err != nil || ph == nil || !ph.OwnerID.Valid || ph.OwnerID.Int64 != cu.ID {
				continue
			}
		}
		if _, err := s.DB.Exec(`UPDATE proxy_hosts SET sort_order=? WHERE id=?`, i*10, id); err != nil {
			log.Printf("reorderProxyHosts: update %d: %v", id, err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// reorderRedirectionHosts — v2.11.11: parallel of reorderProxyHosts for
// the /redirection-hosts list page.
func (s *Server) reorderRedirectionHosts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	rawIDs := r.Form["ids[]"]
	if len(rawIDs) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	for i, raw := range rawIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		if !isAdmin {
			rh, err := models.GetRedirectionHost(s.DB, id)
			if err != nil || rh == nil || !rh.OwnerID.Valid || rh.OwnerID.Int64 != cu.ID {
				continue
			}
		}
		if _, err := s.DB.Exec(`UPDATE redirection_hosts SET sort_order=? WHERE id=?`, i*10, id); err != nil {
			log.Printf("reorderRedirectionHosts: update %d: %v", id, err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// bulkDeleteCertificates — v2.11.10: deletes a set of certificates in one
// shot. Honours the same ownership + in-use checks as deleteCertificate:
// admin can delete any; non-admin can only delete their own AND only when
// no other user's site still references the cert. Rows that fail any
// guard are silently skipped so a partial bulk delete still succeeds for
// the rows that pass.
func (s *Server) bulkDeleteCertificates(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	_ = r.ParseForm()
	ids := r.Form["ids[]"]
	if len(ids) == 0 {
		http.Redirect(w, r, "/certificates", http.StatusSeeOther)
		return
	}
	sid := s.currentServerID(r)
	deleted := 0
	for _, raw := range ids {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		if !isAdmin {
			cert, err := models.GetCertificate(s.DB, id)
			if err != nil || cert == nil {
				continue
			}
			if !cert.OwnerID.Valid || cert.OwnerID.Int64 != cu.ID {
				continue
			}
			if foreign, _ := models.CertificateInUseByOthers(s.DB, id, cu.ID); foreign > 0 {
				continue
			}
		}
		if err := models.DeleteCertificate(s.DB, id); err != nil {
			log.Printf("bulk-delete cert %d: %v", id, err)
			continue
		}
		deleted++
		_ = models.LogActivity(s.DB, sid, cu.Email, "cert_delete", fmt.Sprintf("cert:%d", id), "", true)
	}
	if deleted > 0 {
		// forceTLS=true on cert delete (matches deleteCertificate) so any
		// host that was using the deleted cert reverts to auto-issuance.
		if err := s.syncCaddy(sid, true); err != nil {
			log.Printf("bulk-delete cert: sync error: %v", err)
		}
	}
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

// bulkToggleRawRoutes — v2.11.9: enables or disables a set of raw routes
// in one shot. Mirrors bulkToggleProxyHosts.
// Expects form fields: ids[]={id,...} and action=enable|disable.
func (s *Server) bulkToggleRawRoutes(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	if action != "enable" && action != "disable" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	enabled := action == "enable"
	rawIDs := r.Form["ids[]"]
	if len(rawIDs) == 0 {
		http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
		return
	}
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	sid := s.currentServerID(r)
	changed := 0
	for _, raw := range rawIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		rr, err := models.GetRawRoute(s.DB, id)
		if err != nil || rr == nil {
			continue
		}
		if !isAdmin && (cu == nil || !rr.OwnerID.Valid || rr.OwnerID.Int64 != cu.ID) {
			continue
		}
		if rr.Enabled != enabled {
			rr.Enabled = enabled
			if err := models.UpdateRawRoute(s.DB, rr); err != nil {
				log.Printf("bulkToggleRaw: update %d: %v", id, err)
				continue
			}
			changed++
		}
	}
	if changed > 0 {
		if err := s.syncCaddy(sid, false); err != nil {
			log.Printf("bulkToggleRaw: syncCaddy: %v", err)
		}
	}
	http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
}

// bulkDeleteRawRoutes — v2.11.9: deletes a set of raw routes in one shot.
// Admin can delete any; others only their own.
func (s *Server) bulkDeleteRawRoutes(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	_ = r.ParseForm()
	ids := r.Form["ids[]"]
	if len(ids) == 0 {
		http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
		return
	}
	sid := s.currentServerID(r)
	deleted := 0
	for _, raw := range ids {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		if !isAdmin {
			rr, err := models.GetRawRoute(s.DB, id)
			if err != nil || rr == nil || !rr.OwnerID.Valid || rr.OwnerID.Int64 != cu.ID {
				continue
			}
		}
		if err := models.DeleteRawRoute(s.DB, id); err != nil {
			log.Printf("bulk-delete raw route %d: %v", id, err)
			continue
		}
		deleted++
		_ = models.LogActivity(s.DB, sid, cu.Email, "raw_route_delete", "id", strconv.FormatInt(id, 10), true)
	}
	if deleted > 0 {
		if err := s.syncCaddy(sid, false); err != nil {
			log.Printf("bulk-delete raw: sync error: %v", err)
		}
	}
	http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
}

// bulkToggleRedirectionHosts — v2.11.6: enables or disables a set of
// redirection hosts in one shot. Mirrors bulkToggleProxyHosts.
// Expects form fields: ids[]={id,...} and action=enable|disable.
func (s *Server) bulkToggleRedirectionHosts(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	if action != "enable" && action != "disable" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}
	enabled := action == "enable"
	rawIDs := r.Form["ids[]"]
	if len(rawIDs) == 0 {
		http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
		return
	}
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	sid := s.currentServerID(r)
	changed := 0
	for _, raw := range rawIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		rh, err := models.GetRedirectionHost(s.DB, id)
		if err != nil || rh == nil {
			continue
		}
		if !isAdmin && (cu == nil || !rh.OwnerID.Valid || rh.OwnerID.Int64 != cu.ID) {
			continue
		}
		if rh.Enabled != enabled {
			rh.Enabled = enabled
			if err := models.UpdateRedirectionHost(s.DB, rh); err != nil {
				log.Printf("bulkToggleRedir: update %d: %v", id, err)
				continue
			}
			changed++
		}
	}
	if changed > 0 {
		if err := s.syncCaddy(sid, false); err != nil {
			log.Printf("bulkToggleRedir: syncCaddy: %v", err)
		}
	}
	http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
}

// bulkDeleteRedirectionHosts — v2.11.6: deletes a set of redirection hosts.
// Admin can delete any; others only their own.
func (s *Server) bulkDeleteRedirectionHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	_ = r.ParseForm()
	ids := r.Form["ids[]"]
	if len(ids) == 0 {
		http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
		return
	}
	sid := s.currentServerID(r)
	deleted := 0
	for _, raw := range ids {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		if !isAdmin {
			rh, err := models.GetRedirectionHost(s.DB, id)
			if err != nil || rh == nil || !rh.OwnerID.Valid || rh.OwnerID.Int64 != cu.ID {
				continue
			}
		}
		if err := models.DeleteRedirectionHost(s.DB, id); err != nil {
			log.Printf("bulk-delete redirection %d: %v", id, err)
			continue
		}
		deleted++
		_ = models.LogActivity(s.DB, sid, cu.Email, "redirect_delete", "id", strconv.FormatInt(id, 10), true)
	}
	if deleted > 0 {
		if err := s.syncCaddy(sid, false); err != nil {
			log.Printf("bulk-delete redir: sync error: %v", err)
		}
	}
	http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
}

// toggleMaintenanceMode flips the maintenance_mode flag for a proxy host.
func (s *Server) toggleMaintenanceMode(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ph.MaintenanceMode = !ph.MaintenanceMode
	if err := models.UpdateProxyHost(s.DB, ph); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.syncCaddy(ph.ServerID, false); err != nil {
		log.Printf("toggleMaintenanceMode: syncCaddy: %v", err)
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/proxy-hosts"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// toggleRedirectionHost flips the enabled state on a redirection host and triggers a sync.
func (s *Server) toggleRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if !isAdmin {
		rh, err := models.GetRedirectionHost(s.DB, id)
		if err != nil || rh == nil || !rh.OwnerID.Valid || rh.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	enabled, err := models.ToggleRedirectionHost(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action := "redirect_enable"
	if !enabled {
		action = "redirect_disable"
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), action, fmt.Sprintf("redirect:%d", id), "", true)
	s.syncCaddy(s.currentServerID(r), false)
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/redirection-hosts"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// parseBasicAuthUsers collects basicauth_user[], basicauth_pass[], and
// basicauth_hash[] form fields (indexed arrays, same name repeated per entry).
// For each user: if a new password is provided it's bcrypt-hashed; if the
// password field is empty the hidden existing hash is re-used (edit scenario).
// Users with neither a new password nor an existing hash are skipped.
func parseBasicAuthUsers(r *http.Request) ([]models.BasicAuthUser, error) {
	usernames := r.Form["basicauth_user"]
	passwords := r.Form["basicauth_pass"]
	hashes := r.Form["basicauth_hash"]

	var result []models.BasicAuthUser
	for i, username := range usernames {
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}
		pass := ""
		if i < len(passwords) {
			pass = strings.TrimSpace(passwords[i])
		}
		existingHash := ""
		if i < len(hashes) {
			existingHash = hashes[i]
		}

		var hash string
		if pass != "" {
			h, err := auth.HashPassword(pass)
			if err != nil {
				return nil, fmt.Errorf("hashing password for %q: %w", username, err)
			}
			hash = h
		} else if existingHash != "" {
			hash = existingHash
		} else {
			// New user row with no password — skip.
			continue
		}
		result = append(result, models.BasicAuthUser{Username: username, BcryptHash: hash})
	}
	return result, nil
}

// buildBasicAuthHandler adapts a Caddyfile basicauth block for the given users
// via Caddy's /adapt endpoint and returns the authentication JSON handler.
// Returns nil if the user list is empty or if adaptation fails (error is logged).
// realm is the HTTP Basic Auth realm string shown in the browser prompt.
func (s *Server) buildBasicAuthHandler(caddyCl *caddy.Client, users []models.BasicAuthUser, realm string) map[string]any {
	if len(users) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("localhost {\n  basicauth {\n")
	for _, u := range users {
		sb.WriteString(fmt.Sprintf("    %s %s\n", u.Username, u.BcryptHash))
	}
	sb.WriteString("  }\n}\n")

	result, err := caddyCl.Adapt(sb.String())
	if err != nil {
		log.Printf("caddy sync: basicauth adapt failed: %v", err)
		return nil
	}
	routes := extractAdaptedRoutes(result.Result)
	if len(routes) == 0 {
		return nil
	}
	handles, _ := routes[0]["handle"].([]any)
	for _, h := range handles {
		if m, ok := h.(map[string]any); ok && m["handler"] == "authentication" {
			if realm != "" && realm != "Restricted" {
				// Inject the custom realm into the http_basic provider map.
				if providers, ok := m["providers"].(map[string]any); ok {
					if httpBasic, ok := providers["http_basic"].(map[string]any); ok {
						httpBasic["realm"] = realm
					}
				}
			}
			return m
		}
	}
	return nil
}

// marshalExtraUpstreams reads the repeated "extra_upstream" form fields,
// filters empty values, and marshals the result to JSON (Feature D).
func marshalExtraUpstreams(r *http.Request) string {
	var list []string
	for _, v := range r.Form["extra_upstream"] {
		v = strings.TrimSpace(v)
		if v != "" {
			list = append(list, v)
		}
	}
	b, _ := json.Marshal(list)
	if b == nil {
		return "[]"
	}
	return string(b)
}

// otherManagedServers returns all managed Caddy servers except the one currently
// selected in the request cookie. Used to populate the cross-deploy checkbox list.
func (s *Server) otherManagedServers(r *http.Request) []models.CaddyServer {
	all, _ := models.ListCaddyServers(s.DB)
	cur := s.currentServerID(r)
	var out []models.CaddyServer
	for _, srv := range all {
		if srv.ID != cur && srv.Type == models.CaddyServerTypeManaged {
			out = append(out, srv)
		}
	}
	return out
}

// parseDeployTo reads the "deploy_to" multi-value form field and returns the
// list of server IDs the user wants to mirror the record to.
func parseDeployTo(r *http.Request) []int64 {
	var out []int64
	for _, v := range r.Form["deploy_to"] {
		id, err := strconv.ParseInt(v, 10, 64)
		if err == nil && id > 0 {
			out = append(out, id)
		}
	}
	return out
}

// crossDeployProxyHost creates a copy of the given proxy host on each target
// server and triggers a Caddy sync on each. It always creates a new record
// (ID=0) so the target server can manage it independently.
// Cross-deployed records are always global/admin-owned (ownerID=0).
func (s *Server) crossDeployProxyHost(actor string, p *models.ProxyHost, serverIDs []int64) {
	for _, sid := range serverIDs {
		cp := *p
		cp.ID = 0
		// Certificate IDs are per-server — don't carry them across
		cp.CertificateID = 0
		id, err := models.CreateProxyHost(s.DB, sid, 0, &cp)
		if err != nil {
			log.Printf("cross-deploy proxy to server %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sid, actor, "proxy_cross_deploy", "proxy:new", p.Domains, false)
			continue
		}
		_ = models.LogActivity(s.DB, sid, actor, "proxy_cross_deploy", fmt.Sprintf("proxy:%d", id), p.Domains, true)
		if err := s.syncCaddy(sid, false); err != nil {
			log.Printf("cross-deploy proxy sync server %d: %v", sid, err)
		}
	}
}

// crossDeployRedirectionHost creates a copy of the given redirect on each target
// server and triggers a Caddy sync on each.
// Cross-deployed records are always global/admin-owned (ownerID=0).
func (s *Server) crossDeployRedirectionHost(actor string, rh *models.RedirectionHost, serverIDs []int64) {
	for _, sid := range serverIDs {
		cp := *rh
		cp.ID = 0
		cp.CertificateID = 0
		id, err := models.CreateRedirectionHost(s.DB, sid, 0, &cp)
		if err != nil {
			log.Printf("cross-deploy redirect to server %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sid, actor, "redirect_cross_deploy", "redirect:new", rh.Domains, false)
			continue
		}
		_ = models.LogActivity(s.DB, sid, actor, "redirect_cross_deploy", fmt.Sprintf("redirect:%d", id), rh.Domains, true)
		if err := s.syncCaddy(sid, false); err != nil {
			log.Printf("cross-deploy redirect sync server %d: %v", sid, err)
		}
	}
}

// parsePEMExpiry decodes the first PEM certificate block in pemData and
// returns its NotAfter expiry time, or nil if it cannot be parsed.
func parsePEMExpiry(pemData string) *time.Time {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	t := cert.NotAfter
	return &t
}

// certView wraps a Certificate with computed expiry metadata for the template.
//
// CanEdit is the per-row ownership verdict precomputed server-side so the
// template doesn't have to re-do the (admin || owner.ID == viewer.ID) logic
// every row. True for admin on any row; true for user-role on their own
// uploads; false on another user's row or on a global/admin row that a
// user-role viewer is seeing through the dropdown scope.
type certView struct {
	models.Certificate
	ExpiresAt *time.Time
	DaysLeft  int  // positive = days until expiry; negative = already expired
	CanEdit   bool // per-row ownership (see above)
}

// dnsProviderViewData builds the template data describing which DNS
// providers have credentials configured. Shared by newProxyHost /
// editProxyHost / renderProxyHostFormError so the form picker renders
// consistently across all three entry points.
//
// Returns a list of descriptors for each enabled provider (keyed for
// direct use by the form's <select>) plus a boolean "AnyDNSEnabled"
// the template uses to hide the whole DNS section when nothing is
// configured. serverID is the Caddy server this proxy host will be
// created on — used to resolve the per-server public IP (v2.4.0) and
// expose it to the template so the user sees which IP will be written.
func (s *Server) dnsProviderViewData(serverID int64) map[string]any {
	ip := s.serverIPFor(serverID)
	type providerEntry struct {
		ID          string
		DisplayName string
	}
	enabled := []providerEntry{}
	if ip != "" {
		for _, d := range dns.Descriptors() {
			if dns.CredsComplete(d.ID, s.dnsCreds(d.ID)) {
				enabled = append(enabled, providerEntry{ID: d.ID, DisplayName: d.DisplayName})
			}
		}
	}
	return map[string]any{
		"DNSProviders":    enabled,
		"AnyDNSEnabled":   len(enabled) > 0,
		"CurrentServerIP": ip, // shown in the form so users see the A-record target
	}
}

// applyDNSViewData merges the DNS picker view data into the given map.
// serverID scopes the per-server IP lookup (v2.4.0) — pass the request's
// current server so the form renders the right A-record target.
func (s *Server) applyDNSViewData(serverID int64, m map[string]any) map[string]any {
	for k, v := range s.dnsProviderViewData(serverID) {
		m[k] = v
	}
	return m
}

func (s *Server) newProxyHost(w http.ResponseWriter, r *http.Request) {
	// v2.7.2: cert dropdown scoped to the current viewer — user-role sees
	// only their own + global admin-owned certs, not other users' private
	// material.
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "proxy_host_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         &models.ProxyHost{Enabled: true, SSLEnabled: true, SSLForced: true, HTTP2Support: true, ForwardScheme: "http"},
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Section":      "proxy",
	}))
}

func parseProxyHostForm(r *http.Request) (*models.ProxyHost, error) {
	_ = r.ParseForm()
	port, err := strconv.Atoi(r.FormValue("forward_port"))
	if err != nil {
		return nil, err
	}
	certID, _ := strconv.ParseInt(r.FormValue("certificate_id"), 10, 64)
	// DNS picker is now a two-field combo: dns_provider selects which
	// provider (or "" for none) and dns_zone_id is the provider-native
	// zone identifier. For human display the zone_name is also captured —
	// the form stashes it in a hidden input whenever the picker changes.
	provider := strings.ToLower(strings.TrimSpace(r.FormValue("dns_provider")))
	zoneID := ""
	zoneName := ""
	if provider != "" {
		if _, ok := dns.Lookup(provider); !ok {
			provider = "" // unknown ID → treat as "no DNS"
		} else {
			zoneID = strings.TrimSpace(r.FormValue("dns_zone_id"))
			zoneName = strings.TrimSpace(r.FormValue("dns_zone_name"))
			if zoneID == "" {
				// Picker never captured a zone; treat the whole thing as
				// unset so we don't try to create a record with no target.
				provider = ""
				zoneName = ""
			}
			if zoneName == "" {
				// PB/DO/GD/NC use ID == Name; fall back transparently.
				zoneName = zoneID
			}
		}
	}
	// v2.9.0: validate TLS min version — only accept known values.
	tlsMinVersion := strings.TrimSpace(r.FormValue("tls_min_version"))
	switch tlsMinVersion {
	case "", "1.0", "1.1", "1.2", "1.3":
		// valid
	default:
		tlsMinVersion = ""
	}
	// Parse custom request headers: parallel arrays header_req_key[] + header_req_val[]
	reqKeys := r.Form["header_req_key"]
	reqVals := r.Form["header_req_val"]
	reqMap := map[string]string{}
	for i, k := range reqKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v := ""
		if i < len(reqVals) {
			v = strings.TrimSpace(reqVals[i])
		}
		reqMap[k] = v
	}
	customReqHeaders := "{}"
	if len(reqMap) > 0 {
		if b, err := json.Marshal(reqMap); err == nil {
			customReqHeaders = string(b)
		}
	}

	// Parse custom response headers: parallel arrays header_resp_key[] + header_resp_val[]
	respKeys := r.Form["header_resp_key"]
	respVals := r.Form["header_resp_val"]
	respMap := map[string]string{}
	for i, k := range respKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v := ""
		if i < len(respVals) {
			v = strings.TrimSpace(respVals[i])
		}
		respMap[k] = v
	}
	customRespHeaders := "{}"
	if len(respMap) > 0 {
		if b, err := json.Marshal(respMap); err == nil {
			customRespHeaders = string(b)
		}
	}
	// v2.9.2: URL rewrite rules — submitted as parallel arrays:
	// rewrite_type[], rewrite_from[], rewrite_to[]
	rewriteTypes := r.Form["rewrite_type[]"]
	rewriteFroms := r.Form["rewrite_from[]"]
	rewriteTos   := r.Form["rewrite_to[]"]
	var urlRewrites string
	{
		type rule struct {
			Type string `json:"type"`
			From string `json:"from"`
			To   string `json:"to"`
		}
		var rules []rule
		for i := range rewriteTypes {
			from := ""
			to := ""
			if i < len(rewriteFroms) { from = strings.TrimSpace(rewriteFroms[i]) }
			if i < len(rewriteTos) { to = strings.TrimSpace(rewriteTos[i]) }
			t := strings.TrimSpace(rewriteTypes[i])
			if t == "" || from == "" { continue }
			rules = append(rules, rule{Type: t, From: from, To: to})
		}
		if len(rules) == 0 {
			urlRewrites = "[]"
		} else {
			b, _ := json.Marshal(rules)
			urlRewrites = string(b)
		}
	}
	var maxBodyMB int
	if v := strings.TrimSpace(r.FormValue("max_request_body_mb")); v != "" && v != "0" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxBodyMB = n
		}
	}
	var upstreamTimeoutSec int
	if v := strings.TrimSpace(r.FormValue("upstream_timeout_sec")); v != "" && v != "0" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			upstreamTimeoutSec = n
		}
	}
	var healthCheckIntervalSec int = 30
	if v := strings.TrimSpace(r.FormValue("health_check_interval_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			healthCheckIntervalSec = n
		}
	}
	var keepaliveConns int
	if v := strings.TrimSpace(r.FormValue("keepalive_conns")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			keepaliveConns = n
		}
	}
	ph := &models.ProxyHost{
		Domains:                strings.TrimSpace(r.FormValue("domains")),
		ForwardScheme:          r.FormValue("forward_scheme"),
		ForwardHost:            strings.TrimSpace(r.FormValue("forward_host")),
		ForwardPort:            port,
		WebsocketSupport:       r.FormValue("websocket_support") == "on",
		BlockCommonExploits:    r.FormValue("block_common_exploits") == "on",
		SSLEnabled:             r.FormValue("ssl_enabled") == "on",
		SSLForced:              r.FormValue("ssl_forced") == "on",
		HTTP2Support:           r.FormValue("http2_support") == "on",
		AdvancedConfig:         r.FormValue("advanced_config"),
		Enabled:                r.FormValue("enabled") == "on",
		CertificateID:          certID,
		AccessList:             strings.TrimSpace(r.FormValue("access_list")),
		DNSProvider:            provider,
		DNSZoneID:              zoneID,
		DNSZoneName:            zoneName,
		CompressionEnabled:     r.FormValue("compression_enabled") == "on",
		SecurityHeadersEnabled: r.FormValue("security_headers_enabled") == "on",
		MaintenanceMode:        r.FormValue("maintenance_mode") == "on",
		MaintenanceMsg:         strings.TrimSpace(r.FormValue("maintenance_msg")),
		MaintenanceStatusCode: func() int {
			if sc, err := strconv.Atoi(r.FormValue("maintenance_status_code")); err == nil && sc > 0 {
				return sc
			}
			return 503
		}(),
		StickySessions:         r.FormValue("sticky_sessions") == "on",
		TLSMinVersion:          tlsMinVersion,
		CustomReqHeaders:       customReqHeaders,
		CustomRespHeaders:      customRespHeaders,
		URLRewrites:            urlRewrites,
		MaxRequestBodyMB:       maxBodyMB,
		UpstreamTimeoutSec:     upstreamTimeoutSec,
		CORSEnabled:            r.FormValue("cors_enabled") == "on",
		CORSOrigins:            strings.TrimSpace(r.FormValue("cors_origins")),
		HealthCheckURI:         strings.TrimSpace(r.FormValue("health_check_uri")),
		HealthCheckIntervalSec: healthCheckIntervalSec,
		HealthCheckMethod: func() string {
			m := r.FormValue("health_check_method")
			if m == "" {
				return "GET"
			}
			return m
		}(),
		KeepaliveConns:         keepaliveConns,
		Tags:                   strings.TrimSpace(r.FormValue("tags")),
		Notes:                  r.FormValue("notes"),
		DisableAccessLog:       r.FormValue("disable_access_log") == "on",
		AddRequestID:           r.FormValue("add_request_id") == "on",
		StripRespHeaders:       strings.TrimSpace(r.FormValue("strip_resp_headers")),
		BlockedAgents:          strings.TrimSpace(r.FormValue("blocked_agents")),
		ResponseCacheControl:   strings.TrimSpace(r.FormValue("response_cache_control")),
		UpstreamSNI:            strings.TrimSpace(r.FormValue("upstream_sni")),
		HSTSPreload:            r.FormValue("hsts_preload") == "on",
		MaxConnsPerHost: func() int {
			n, _ := strconv.Atoi(r.FormValue("max_conns_per_host"))
			return n
		}(),
	}
	hcTimeout, _ := strconv.Atoi(r.FormValue("health_check_timeout_sec"))
	ph.HealthCheckTimeoutSec = hcTimeout
	retries, _ := strconv.Atoi(r.FormValue("upstream_retries"))
	ph.UpstreamRetries = retries
	ph.ForceHTTP1 = r.FormValue("force_http1") == "on"
	ph.BasicAuthRealm = strings.TrimSpace(r.FormValue("basicauth_realm"))
	if ph.BasicAuthRealm == "" {
		ph.BasicAuthRealm = "Restricted"
	}
	ph.ErrorPageHTML = r.FormValue("error_page_html")
	ph.MaintenanceWindowStart = strings.TrimSpace(r.FormValue("maintenance_window_start"))
	ph.MaintenanceWindowEnd = strings.TrimSpace(r.FormValue("maintenance_window_end"))
	ph.MaintenanceWindowDays = strings.Join(r.Form["maintenance_window_days"], ",")
	ph.IPBlocklist = strings.TrimSpace(r.FormValue("ip_blocklist"))
	ph.LBPolicy = r.FormValue("lb_policy")
	ph.ProxyProtocol = r.FormValue("proxy_protocol")
	ph.RobotsTxt = r.FormValue("robots_txt")
	ph.PassiveFailDurationSec, _ = strconv.Atoi(r.FormValue("passive_fail_duration_sec"))
	ph.PassiveMaxFails, _ = strconv.Atoi(r.FormValue("passive_max_fails"))
	ph.HSTSMaxAgeSec, _ = strconv.Atoi(r.FormValue("hsts_max_age_sec"))
	ph.CSPHeader = strings.TrimSpace(r.FormValue("csp_header"))
	ph.H2CEnabled = r.FormValue("h2c_enabled") == "on"
	if hch := strings.TrimSpace(r.FormValue("health_check_headers")); hch != "" {
		ph.HealthCheckHeaders = hch
	} else {
		ph.HealthCheckHeaders = "{}"
	}
	ph.FlushImmediate = r.FormValue("flush_immediate") == "on"
	ph.BufferResponses = r.FormValue("buffer_responses") == "on"
	ph.TrustedProxies = strings.TrimSpace(r.FormValue("trusted_proxies"))
	ph.UpstreamHostOverride = strings.TrimSpace(r.FormValue("upstream_host_override"))
	ph.ReadTimeoutSec, _ = strconv.Atoi(r.FormValue("read_timeout_sec"))
	ph.DenyDotfiles = r.FormValue("deny_dotfiles") == "on"
	ph.RequestBuffersKB, _ = strconv.Atoi(r.FormValue("request_buffers_kb"))
	ph.CORSAllowCredentials = r.FormValue("cors_allow_credentials") == "on"
	ph.CORSExposeHeaders = strings.TrimSpace(r.FormValue("cors_expose_headers"))
	ph.SSLVerifyUpstream = r.FormValue("ssl_verify_upstream") == "on"
	ph.DialTimeoutSec, _ = strconv.Atoi(r.FormValue("dial_timeout_sec"))
	ph.APIKeyHeader = strings.TrimSpace(r.FormValue("api_key_header"))
	ph.APIKeyValue = strings.TrimSpace(r.FormValue("api_key_value"))
	ph.BlockEmptyUserAgent = r.FormValue("block_empty_user_agent") == "on"
	ph.ErrorRedirectURL = strings.TrimSpace(r.FormValue("error_redirect_url"))
	ph.PermissionsPolicy = strings.TrimSpace(r.FormValue("permissions_policy"))
	ph.XFrameOptions = strings.TrimSpace(r.FormValue("x_frame_options"))
	ph.ReferrerPolicy = strings.TrimSpace(r.FormValue("referrer_policy"))
	ph.HSTSIncludeSubdomains = r.FormValue("hsts_include_subdomains") == "on"
	ph.CSPReportOnly = strings.TrimSpace(r.FormValue("csp_report_only"))
	ph.KeepaliveIdleTimeoutSec, _ = strconv.Atoi(r.FormValue("keepalive_idle_timeout_sec"))
	ph.HealthCheckExpectStatus, _ = strconv.Atoi(r.FormValue("health_check_expect_status"))
	ph.HealthCheckExpectBody = strings.TrimSpace(r.FormValue("health_check_expect_body"))
	ph.HealthCheckFollowRedirects = r.FormValue("health_check_follow_redirects") == "on"
	ph.PathMatcher = strings.TrimSpace(r.FormValue("path_matcher"))
	ph.StripPathPrefix = r.FormValue("strip_path_prefix") == "on"
	ph.StickyCookieName = strings.TrimSpace(r.FormValue("sticky_cookie_name"))
	ph.LBTryDurationSec, _ = strconv.Atoi(r.FormValue("lb_try_duration_sec"))
	ph.LBTryIntervalMS, _ = strconv.Atoi(r.FormValue("lb_try_interval_ms"))
	ph.CompressionMinSizeKB, _ = strconv.Atoi(r.FormValue("compression_min_size_kb"))
	ph.ForwardClientIP = r.FormValue("forward_client_ip") == "on"
	ph.CORSMaxAgeSec, _ = strconv.Atoi(r.FormValue("cors_max_age_sec"))
	ph.CORSAllowMethods = strings.TrimSpace(r.FormValue("cors_allow_methods"))
	ph.CORSAllowHeaders = strings.TrimSpace(r.FormValue("cors_allow_headers"))
	ph.RetryStatusCodes = strings.TrimSpace(r.FormValue("retry_status_codes"))
	ph.WriteTimeoutSec, _ = strconv.Atoi(r.FormValue("write_timeout_sec"))
	ph.UpstreamTLSMinVersion = r.FormValue("upstream_tls_min_version")
	ph.ForwardProxyURL = strings.TrimSpace(r.FormValue("forward_proxy_url"))
	ph.BlockedMethods = strings.TrimSpace(r.FormValue("blocked_methods"))
	ph.ForwardAuthURL = strings.TrimSpace(r.FormValue("forward_auth_url"))
	ph.ForwardAuthCopyHeaders = strings.TrimSpace(r.FormValue("forward_auth_copy_headers"))
	ph.StripQueryString = r.FormValue("strip_query_string") == "on"
	ph.DeleteQueryParams = strings.TrimSpace(r.FormValue("delete_query_params"))
	ph.RequestBodyReadTimeoutSec, _ = strconv.Atoi(r.FormValue("request_body_read_timeout_sec"))
	ph.ResponseHeaderTimeoutSec, _ = strconv.Atoi(r.FormValue("response_header_timeout_sec"))
	ph.MaxConnDurationSec, _ = strconv.Atoi(r.FormValue("max_conn_duration_sec"))
	ph.DecompressResponse = r.FormValue("decompress_response") == "on"
	ph.Color = strings.TrimSpace(r.FormValue("color"))
	ph.WWWRedirect = r.FormValue("www_redirect") // "" | "to_www" | "to_bare"
	ph.StripReqHeaders = strings.TrimSpace(r.FormValue("strip_req_headers"))
	ph.UpstreamPathPrefix = strings.TrimSpace(r.FormValue("upstream_path_prefix"))
	ph.CompressionLevel, _ = strconv.Atoi(r.FormValue("compression_level"))
	ph.CompressionPreferGzip = r.FormValue("compression_prefer_gzip") == "on"
	ph.SortOrder, _ = strconv.Atoi(r.FormValue("sort_order"))
	ph.AllowedMethods = strings.TrimSpace(r.FormValue("allowed_methods"))
	ph.UpstreamMaxRespHeaderKB, _ = strconv.Atoi(r.FormValue("upstream_max_resp_header_kb"))
	ph.HealthCheckPort, _ = strconv.Atoi(r.FormValue("health_check_port"))
	ph.RequestIDHeaderName = strings.TrimSpace(r.FormValue("request_id_header_name"))
	ph.LBCookiePath = strings.TrimSpace(r.FormValue("lb_cookie_path"))
	ph.PassiveUnhealthyLatencyMS, _ = strconv.Atoi(r.FormValue("passive_unhealthy_latency_ms"))
	ph.TLSHandshakeTimeoutSec, _ = strconv.Atoi(r.FormValue("tls_handshake_timeout_sec"))
	ph.ExpectContinueTimeoutSec, _ = strconv.Atoi(r.FormValue("expect_continue_timeout_sec"))
	ph.ResponseBuffersKB, _ = strconv.Atoi(r.FormValue("response_buffers_kb"))
	ph.UpstreamMaxIdleConns, _ = strconv.Atoi(r.FormValue("upstream_max_idle_conns"))
	ph.UpstreamKeepAliveProbeIntervalSec, _ = strconv.Atoi(r.FormValue("upstream_keep_alive_probe_sec"))
	ph.ForwardAuthMethod = strings.TrimSpace(r.FormValue("forward_auth_method"))
	ph.GRPCWebEnabled = r.FormValue("grpc_web_enabled") == "on"
	ph.ForwardAuthHeadersPrefix = strings.TrimSpace(r.FormValue("forward_auth_headers_prefix"))
	ph.HealthCheckMaxSizeKB, _ = strconv.Atoi(r.FormValue("health_check_max_size_kb"))
	ph.StripPathSuffix = strings.TrimSpace(r.FormValue("strip_path_suffix"))
	ph.AddReqQueryParams = strings.TrimSpace(r.FormValue("add_req_query_params"))
	ph.ErrorPageCodes = strings.TrimSpace(r.FormValue("error_page_codes"))
	ph.UpstreamTLSCAPEMFile = strings.TrimSpace(r.FormValue("upstream_tls_ca_pem_file"))
	ph.KeepaliveDisabled = r.FormValue("keepalive_disabled") == "on"
	ph.TrailingSlashRedirect = r.FormValue("trailing_slash_redirect")
	ph.DialFallbackDelayMS, _ = strconv.Atoi(r.FormValue("dial_fallback_delay_ms"))
	ph.UpstreamNetwork = strings.TrimSpace(r.FormValue("upstream_network"))
	ph.DNSResolver = strings.TrimSpace(r.FormValue("dns_resolver"))
	ph.PathMatcherType = r.FormValue("path_matcher_type")
	ph.CORSAllowPrivateNetwork = r.FormValue("cors_allow_private_network") == "on"
	ph.RobotsTxtDisallowAll = r.FormValue("robots_txt_disallow_all") == "on"
	ph.MaintenanceRetryAfterSec, _ = strconv.Atoi(r.FormValue("maintenance_retry_after_sec"))
	ph.UpstreamResolveTimeoutSec, _ = strconv.Atoi(r.FormValue("upstream_resolve_timeout_sec"))
	ph.UpstreamReadBufferSizeKB, _ = strconv.Atoi(r.FormValue("upstream_read_buffer_size_kb"))
	ph.UpstreamWriteBufferSizeKB, _ = strconv.Atoi(r.FormValue("upstream_write_buffer_size_kb"))
	ph.ReqHeaderReplace = strings.TrimSpace(r.FormValue("req_header_replace"))
	ph.RespHeaderReplace = strings.TrimSpace(r.FormValue("resp_header_replace"))
	ph.UpstreamHTTPVersions = strings.TrimSpace(r.FormValue("upstream_http_versions"))
	ph.HealthCheckBody = strings.TrimSpace(r.FormValue("health_check_body"))
	ph.AddCanonicalLinkHeader = r.FormValue("add_canonical_link_header") == "on"
	ph.HTTPBasicAuthUpstream = strings.TrimSpace(r.FormValue("http_basic_auth_upstream"))
	ph.BlockUARegexp = strings.TrimSpace(r.FormValue("block_ua_regexp"))
	ph.SecurityTxtBody = strings.TrimSpace(r.FormValue("security_txt_body"))
	ph.ServerHeaderValue = strings.TrimSpace(r.FormValue("server_header_value"))
	ph.XRobotsTag = strings.TrimSpace(r.FormValue("x_robots_tag"))
	ph.AddForwardedHeader = r.FormValue("add_forwarded_header") == "on"
	ph.LBCookieSecret = strings.TrimSpace(r.FormValue("lb_cookie_secret"))
	ph.PassiveUnhealthyStatusCodes = strings.TrimSpace(r.FormValue("passive_unhealthy_status_codes"))
	ph.HealthCheckContentType = strings.TrimSpace(r.FormValue("health_check_content_type"))
	ph.UpstreamTLSClientCertFile = strings.TrimSpace(r.FormValue("upstream_tls_client_cert_file"))
	ph.UpstreamTLSClientKeyFile = strings.TrimSpace(r.FormValue("upstream_tls_client_key_file"))
	ph.BlockPrivateIPs = r.FormValue("block_private_ips") == "on"
	ph.EnableBrotli = r.FormValue("enable_brotli") == "on"
	ph.VaryHeader = strings.TrimSpace(r.FormValue("vary_header"))
	ph.StripETag = r.FormValue("strip_etag") == "on"
	ph.HTTP2PushPaths = strings.TrimSpace(r.FormValue("http2_push_paths"))
	ph.DenyContentTypes = strings.TrimSpace(r.FormValue("deny_content_types"))
	ph.UpstreamLocalAddr = strings.TrimSpace(r.FormValue("upstream_local_addr"))
	ph.UpstreamTLSRenegotiation = r.FormValue("upstream_tls_renegotiation")
	ph.UpstreamTLSCurves = strings.TrimSpace(r.FormValue("upstream_tls_curves"))
	ph.UpstreamTLSMaxVersion = r.FormValue("upstream_tls_max_version")
	ph.UpstreamTLSPins = strings.TrimSpace(r.FormValue("upstream_tls_pins"))
	ph.LBHeaderField = strings.TrimSpace(r.FormValue("lb_header_field"))
	ph.MaintenanceCustomHeaders = strings.TrimSpace(r.FormValue("maintenance_custom_headers"))
	ph.DenyExtensions = strings.TrimSpace(r.FormValue("deny_extensions"))
	ph.InjectRequestTimestamp = r.FormValue("inject_request_timestamp") == "on"
	ph.AddRespCookies = strings.TrimSpace(r.FormValue("add_resp_cookies"))
	ph.StripAcceptEncoding = r.FormValue("strip_accept_encoding") == "on"
	ph.AddUpstreamTimingHeader = r.FormValue("add_upstream_timing_header") == "on"
	ph.StripServerHeader = r.FormValue("strip_server_header") == "on"
	ph.BlockRefererRegexp = strings.TrimSpace(r.FormValue("block_referer_regexp"))
	ph.AddContentTypeNosniff = r.FormValue("add_content_type_nosniff") == "on"
	ph.StripAuthorizationHeader = r.FormValue("strip_authorization_header") == "on"
	ph.RealIPFromHeader = strings.TrimSpace(r.FormValue("real_ip_from_header"))
	ph.HealthCheckHostOverride = strings.TrimSpace(r.FormValue("health_check_host_override"))
	ph.AddXForwardedPort = r.FormValue("add_x_forwarded_port") == "on"
	ph.LBRetryOn = strings.TrimSpace(r.FormValue("lb_retry_on"))
	if v := strings.TrimSpace(r.FormValue("max_buffer_size_kb")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.MaxBufferSizeKB = n
		}
	}
	if v := strings.TrimSpace(r.FormValue("upstream_keepalive_probes")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.UpstreamKeepaliveProbes = n
		}
	}
	if v := strings.TrimSpace(r.FormValue("upstream_flush_interval_ms")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ph.UpstreamFlushIntervalMS = n
		}
	}
	ph.AddXForwardedHost = r.FormValue("add_x_forwarded_host") == "on"
	ph.MaintenanceAllowedIPs = strings.TrimSpace(r.FormValue("maintenance_allowed_ips"))
	ph.UpstreamTLSCipherSuites = strings.TrimSpace(r.FormValue("upstream_tls_cipher_suites"))
	ph.AddCacheControlNoStore = r.FormValue("add_cache_control_no_store") == "on"
	ph.DenyRefererEmpty = r.FormValue("deny_referer_empty") == "on"
	ph.LBCookieHTTPOnly = r.FormValue("lb_cookie_httponly") == "on"
	ph.LBCookieSecure = r.FormValue("lb_cookie_secure") == "on"
	ph.LBCookieSameSite = r.FormValue("lb_cookie_same_site")
	ph.UpstreamTLSEarlyData = r.FormValue("upstream_tls_early_data") == "on"
	ph.AddViaHeader = r.FormValue("add_via_header") == "on"
	ph.ReqHeaderRename = strings.TrimSpace(r.FormValue("req_header_rename"))
	ph.AddExpectCTHeader = r.FormValue("add_expect_ct_header") == "on"
	ph.ForceUpstreamEncoding = strings.TrimSpace(r.FormValue("force_upstream_encoding"))
	if v := strings.TrimSpace(r.FormValue("passive_unhealthy_count")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.PassiveUnhealthyCount = n
		}
	}
	ph.StripXPoweredBy = r.FormValue("strip_x_powered_by") == "on"
	ph.AddTimingAllowOrigin = strings.TrimSpace(r.FormValue("add_timing_allow_origin"))
	if v := strings.TrimSpace(r.FormValue("lb_cookie_max_age_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.LBCookieMaxAgeSec = n
		}
	}
	ph.CrossOriginOpenerPolicy = strings.TrimSpace(r.FormValue("cross_origin_opener_policy"))
	ph.CrossOriginResourcePolicy = strings.TrimSpace(r.FormValue("cross_origin_resource_policy"))
	ph.CrossOriginEmbedderPolicy = strings.TrimSpace(r.FormValue("cross_origin_embedder_policy"))
	ph.DenyRequestContentType = strings.TrimSpace(r.FormValue("deny_request_content_type"))
	ph.CompressionExcludeRegexp = strings.TrimSpace(r.FormValue("compression_exclude_regexp"))
	ph.AddCacheControlPublic = r.FormValue("add_cache_control_public") == "on"
	// v2.9.140: add_x_request_start — inject X-Request-Start: t=<epoch_ms> for APM timing.
	ph.AddXRequestStart = r.FormValue("add_x_request_start") == "on"
	// v2.9.141: maintenance_window_timezone — IANA timezone for the scheduled maintenance window.
	ph.MaintenanceWindowTimezone = strings.TrimSpace(r.FormValue("maintenance_window_timezone"))
	// v2.9.142: lb_random_choose_count — "choose" count for the random_choice lb policy.
	if v := strings.TrimSpace(r.FormValue("lb_random_choose_count")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.LBRandomChooseCount = n
		}
	}
	// v2.9.143: add_x_forwarded_scheme — inject X-Forwarded-Scheme with the client-facing scheme.
	ph.AddXForwardedScheme = r.FormValue("add_x_forwarded_scheme") == "on"
	// v2.9.144: response_cache_ttl_sec — set Cache-Control: max-age=N (0 = disabled).
	if v := strings.TrimSpace(r.FormValue("response_cache_ttl_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.ResponseCacheTTLSec = n
		}
	}
	// v2.9.145: add_link_preload — Link response header for HTTP/2 preload hints.
	ph.AddLinkPreload = strings.TrimSpace(r.FormValue("add_link_preload"))
	// v2.9.146: deny_path_regexp — block requests whose path matches this regex (403).
	ph.DenyPathRegexp = strings.TrimSpace(r.FormValue("deny_path_regexp"))
	// v2.9.147: add_request_id_to_response — echo request trace ID in response header.
	ph.AddRequestIDToResponse = r.FormValue("add_request_id_to_response") == "on"
	// v2.9.148: health_check_tls_server_name — TLS SNI override for health check connections.
	ph.HealthCheckTLSServerName = strings.TrimSpace(r.FormValue("health_check_tls_server_name"))
	// v2.9.149: add_x_real_ip — inject X-Real-IP with the direct client IP.
	ph.AddXRealIP = r.FormValue("add_x_real_ip") == "on"
	// v2.9.150: strip_incoming_x_forwarded_for — delete incoming X-Forwarded-For.
	ph.StripIncomingXForwardedFor = r.FormValue("strip_incoming_x_forwarded_for") == "on"
	// v2.9.151: health_check_tls_insecure_skip_verify — skip TLS cert verification for health check probes.
	ph.HealthCheckTLSInsecureSkipVerify = r.FormValue("health_check_tls_insecure_skip_verify") == "on"
	// v2.9.152: add_cors_vary_header — add Vary: Origin response header for CDN caching of CORS responses.
	ph.AddCORSVaryHeader = r.FormValue("add_cors_vary_header") == "on"
	// v2.9.153: upstream_tls_alpn — ALPN protocol list for upstream TLS connections.
	ph.UpstreamTLSALPN = strings.TrimSpace(r.FormValue("upstream_tls_alpn"))
	// v2.9.154: add_x_powered_by — custom X-Powered-By response header value.
	ph.AddXPoweredBy = strings.TrimSpace(r.FormValue("add_x_powered_by"))
	// v2.9.155: block_query_params — comma-separated query param names to block (403).
	ph.BlockQueryParams = strings.TrimSpace(r.FormValue("block_query_params"))
	// v2.9.156: add_document_policy — Document-Policy response header value.
	ph.AddDocumentPolicy = strings.TrimSpace(r.FormValue("add_document_policy"))
	// v2.9.157: maintenance_redirect_url — redirect to this URL during maintenance.
	ph.MaintenanceRedirectURL = strings.TrimSpace(r.FormValue("maintenance_redirect_url"))
	// v2.9.158: upstream_keepalive_max_lifetime_sec — max keepalive connection lifetime.
	if v := strings.TrimSpace(r.FormValue("upstream_keepalive_max_lifetime_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.UpstreamKeepaliveMaxLifetimeSec = n
		}
	}
	// v2.9.159: add_origin_header — inject Origin request header.
	ph.AddOriginHeader = strings.TrimSpace(r.FormValue("add_origin_header"))
	// v2.9.160: upstream_tls_ca_pem_inline — inline PEM CA certificate for upstream TLS.
	ph.UpstreamTLSCAPEMInline = strings.TrimSpace(r.FormValue("upstream_tls_ca_pem_inline"))
	// v2.9.161: add_server_timing_header — inject Server-Timing with upstream duration.
	ph.AddServerTimingHeader = r.FormValue("add_server_timing_header") == "on"
	// v2.9.162: add_clear_site_data — Clear-Site-Data response header value.
	ph.AddClearSiteData = strings.TrimSpace(r.FormValue("add_clear_site_data"))
	// v2.9.163: add_x_dns_prefetch_control — set X-DNS-Prefetch-Control: off.
	ph.AddXDNSPrefetchControl = r.FormValue("add_x_dns_prefetch_control") == "on"
	// v2.9.164: add_accept_ranges — signal byte-range support with Accept-Ranges: bytes.
	ph.AddAcceptRanges = r.FormValue("add_accept_ranges") == "on"
	// v2.9.165: add_content_disposition — set a custom Content-Disposition response header.
	ph.AddContentDisposition = strings.TrimSpace(r.FormValue("add_content_disposition"))
	// v2.9.166: upstream_tls_server_name_from_host — use Host header value as upstream TLS SNI.
	ph.UpstreamTLSServerNameFromHost = r.FormValue("upstream_tls_server_name_from_host") == "on"
	// v2.9.167: add_x_permitted_cross_domain_policies — X-Permitted-Cross-Domain-Policies response header value.
	ph.AddXPermittedCrossDomainPolicies = strings.TrimSpace(r.FormValue("add_x_permitted_cross_domain_policies"))
	// v2.9.168: strip_response_headers — comma-separated list of response headers to delete.
	ph.StripResponseHeaders = strings.TrimSpace(r.FormValue("strip_response_headers"))
	// v2.9.169: add_report_to — Report-To response header value (JSON endpoint group config).
	ph.AddReportTo = strings.TrimSpace(r.FormValue("add_report_to"))
	// v2.9.170: add_nel_header — NEL response header JSON config for Network Error Logging.
	ph.AddNELHeader = strings.TrimSpace(r.FormValue("add_nel_header"))
	// v2.9.171: block_http_methods — comma-separated HTTP methods to reject with 405.
	ph.BlockHTTPMethods = strings.TrimSpace(r.FormValue("block_http_methods"))
	// v2.9.172: add_service_worker_allowed — Service-Worker-Allowed response header value.
	ph.AddServiceWorkerAllowed = strings.TrimSpace(r.FormValue("add_service_worker_allowed"))
	// v2.9.173: add_accept_ch — Accept-CH response header to declare accepted client hints.
	ph.AddAcceptCH = strings.TrimSpace(r.FormValue("add_accept_ch"))
	// v2.9.174: add_alt_svc — Alt-Svc response header for alternate service advertisement.
	ph.AddAltSvc = strings.TrimSpace(r.FormValue("add_alt_svc"))
	// v2.9.175: add_content_language — Content-Language response header value.
	ph.AddContentLanguage = strings.TrimSpace(r.FormValue("add_content_language"))
	// v2.9.176: add_critical_ch — Critical-CH response header (marks client hints required before rendering).
	ph.AddCriticalCH = strings.TrimSpace(r.FormValue("add_critical_ch"))
	// v2.9.177: add_x_download_options — set X-Download-Options: noopen (IE file open prevention).
	ph.AddXDownloadOptions = r.FormValue("add_x_download_options") == "on"
	// v2.9.178: deny_user_agent_regexp — block requests whose User-Agent matches this regexp with 403.
	ph.DenyUserAgentRegexp = strings.TrimSpace(r.FormValue("deny_user_agent_regexp"))
	// v2.9.179: add_pragma_no_cache — set Pragma: no-cache response header.
	ph.AddPragmaNoCache = r.FormValue("add_pragma_no_cache") == "on"
	// v2.9.180: health_check_user_agent — custom User-Agent for active health check probes.
	ph.HealthCheckUserAgent = strings.TrimSpace(r.FormValue("health_check_user_agent"))
	// v2.9.181: add_x_request_path — inject X-Request-Path request header on upstream calls.
	ph.AddXRequestPath = r.FormValue("add_x_request_path") == "on"
	// v2.9.182: add_x_clacks_overhead — X-Clacks-Overhead response header value.
	ph.AddXClacksOverhead = strings.TrimSpace(r.FormValue("add_x_clacks_overhead"))
	// v2.9.183: add_x_ua_compatible — X-UA-Compatible response header value.
	ph.AddXUACompatible = strings.TrimSpace(r.FormValue("add_x_ua_compatible"))
	// v2.9.184: forward_auth_skip_paths — comma-separated path prefixes that bypass forward_auth.
	ph.ForwardAuthSkipPaths = strings.TrimSpace(r.FormValue("forward_auth_skip_paths"))
	// v2.9.185: add_age_zero — set Age: 0 response header to signal a fresh response.
	ph.AddAgeZero = r.FormValue("add_age_zero") == "on"
	// v2.9.186: add_surrogate_control — Surrogate-Control response header value (CDN-only cache directive).
	ph.AddSurrogateControl = strings.TrimSpace(r.FormValue("add_surrogate_control"))
	// v2.9.187: add_warning_header — Warning response header value.
	ph.AddWarningHeader = strings.TrimSpace(r.FormValue("add_warning_header"))
	// v2.9.188: add_x_request_method — forward X-Request-Method header (echoes HTTP method) to upstream.
	ph.AddXRequestMethod = r.FormValue("add_x_request_method") == "on"
	// v2.9.189: add_x_request_query — forward X-Request-Query header (echoes query string) to upstream.
	ph.AddXRequestQuery = r.FormValue("add_x_request_query") == "on"
	// v2.9.190: add_x_forwarded_user — static X-Forwarded-User request header value.
	ph.AddXForwardedUser = strings.TrimSpace(r.FormValue("add_x_forwarded_user"))
	// v2.9.191: add_x_real_scheme — forward X-Real-Scheme request header to upstream.
	ph.AddXRealScheme = r.FormValue("add_x_real_scheme") == "on"
	// v2.9.192: add_origin_agent_cluster — set Origin-Agent-Cluster: ?1 response header.
	ph.AddOriginAgentCluster = r.FormValue("add_origin_agent_cluster") == "on"
	// v2.9.193: add_x_forwarded_groups — static X-Forwarded-Groups request header value.
	ph.AddXForwardedGroups = strings.TrimSpace(r.FormValue("add_x_forwarded_groups"))
	// v2.9.194: add_x_forwarded_email — static X-Forwarded-Email request header value.
	ph.AddXForwardedEmail = strings.TrimSpace(r.FormValue("add_x_forwarded_email"))
	// v2.9.195: add_x_forwarded_roles — static X-Forwarded-Roles request header value.
	ph.AddXForwardedRoles = strings.TrimSpace(r.FormValue("add_x_forwarded_roles"))
	// v2.9.196: block_query_param_regexp — block requests whose query string matches this regexp with 403.
	ph.BlockQueryParamRegexp = strings.TrimSpace(r.FormValue("block_query_param_regexp"))
	// v2.9.197: add_x_request_referer — forward X-Request-Referer header to upstream.
	ph.AddXRequestReferer = r.FormValue("add_x_request_referer") == "on"
	// v2.9.198: add_x_request_origin — forward X-Request-Origin header to upstream.
	ph.AddXRequestOrigin = r.FormValue("add_x_request_origin") == "on"
	// v2.9.199: add_x_forwarded_uri — forward X-Forwarded-URI header to upstream.
	ph.AddXForwardedURI = r.FormValue("add_x_forwarded_uri") == "on"
	// v2.9.200: add_x_no_archive — set X-No-Archive: yes response header.
	ph.AddXNoArchive = r.FormValue("add_x_no_archive") == "on"
	// v2.9.201: add_x_request_hostname — forward X-Request-Hostname header to upstream.
	ph.AddXRequestHostname = r.FormValue("add_x_request_hostname") == "on"
	// v2.9.202: add_x_xss_protection_disabled — set X-XSS-Protection: 0 response header.
	ph.AddXXSSProtectionDisabled = r.FormValue("add_x_xss_protection_disabled") == "on"
	// v2.9.212: add_x_request_remote_port — forward X-Request-Remote-Port header to upstream.
	ph.AddXRequestRemotePort = r.FormValue("add_x_request_remote_port") == "on"
	// v2.9.213: add_x_request_protocol — forward X-Request-Protocol header (HTTP version) to upstream.
	ph.AddXRequestProtocol = r.FormValue("add_x_request_protocol") == "on"
	// v2.9.214: add_save_data_vary — append Save-Data to Vary response header.
	ph.AddSaveDataVary = r.FormValue("add_save_data_vary") == "on"
	// v2.9.217: add_x_environment — static X-Environment request header value.
	ph.AddXEnvironment = strings.TrimSpace(r.FormValue("add_x_environment"))
	// v2.9.218: add_x_trace_id — forward X-Trace-ID header (Caddy UUID per request) to upstream.
	ph.AddXTraceID = r.FormValue("add_x_trace_id") == "on"
	// v2.9.219: health_check_query_params — query string appended to active health check URL.
	ph.HealthCheckQueryParams = strings.TrimSpace(r.FormValue("health_check_query_params"))
	// v2.9.220: add_x_session_id — forward X-Session-ID header to upstream.
	ph.AddXSessionID = r.FormValue("add_x_session_id") == "on"
	// v2.9.221: add_x_response_trace_id — set X-Response-Trace-ID response header.
	ph.AddXResponseTraceID = r.FormValue("add_x_response_trace_id") == "on"
	// v2.9.222: add_x_request_local_addr — forward X-Local-Addr header to upstream.
	ph.AddXRequestLocalAddr = r.FormValue("add_x_request_local_addr") == "on"
	// v2.9.223: add_x_request_local_port — forward X-Local-Port header to upstream.
	ph.AddXRequestLocalPort = r.FormValue("add_x_request_local_port") == "on"
	// v2.9.224: add_x_request_path_info — forward X-PathInfo header to upstream.
	ph.AddXRequestPathInfo = r.FormValue("add_x_request_path_info") == "on"
	// v2.9.234: add_x_authenticated_user — static X-Authenticated-User request header.
	ph.AddXAuthenticatedUser = strings.TrimSpace(r.FormValue("add_x_authenticated_user"))
	// v2.9.235: block_path_extensions — comma-separated extensions to 403.
	ph.BlockPathExtensions = strings.TrimSpace(r.FormValue("block_path_extensions"))
	// v2.9.236: add_link_modulepreload — Link rel=modulepreload value.
	ph.AddLinkModulePreload = strings.TrimSpace(r.FormValue("add_link_modulepreload"))
	// v2.9.237: add_x_remote_user — static X-Remote-User request header.
	ph.AddXRemoteUser = strings.TrimSpace(r.FormValue("add_x_remote_user"))
	// v2.9.238: add_x_forwarded_path — forward X-Forwarded-Path header.
	ph.AddXForwardedPath = r.FormValue("add_x_forwarded_path") == "on"
	// v2.9.239: add_x_geo_country_code — static X-Geo-Country header.
	ph.AddXGeoCountryCode = strings.TrimSpace(r.FormValue("add_x_geo_country_code"))
	// v2.9.240: add_x_request_priority — X-Request-Priority response header (RFC 9218).
	ph.AddXRequestPriority = strings.TrimSpace(r.FormValue("add_x_request_priority"))
	// v2.9.241: health_check_basic_auth — "user:pass" credentials for health check probes.
	ph.HealthCheckBasicAuth = strings.TrimSpace(r.FormValue("health_check_basic_auth"))
	// v2.9.242: add_x_real_ssl_protocol — forward TLS version header.
	ph.AddXRealSSLProtocol = r.FormValue("add_x_real_ssl_protocol") == "on"
	// v2.9.243: add_x_real_ssl_cipher — forward negotiated cipher header.
	ph.AddXRealSSLCipher = r.FormValue("add_x_real_ssl_cipher") == "on"
	// v2.9.244: add_x_cache_status — static X-Cache-Status response header.
	ph.AddXCacheStatus = strings.TrimSpace(r.FormValue("add_x_cache_status"))
	// v2.9.245: deny_referer_regexp — block by Referer regexp with 403.
	ph.DenyRefererRegexp = strings.TrimSpace(r.FormValue("deny_referer_regexp"))
	// v2.9.246: add_x_request_user_agent — echo UA to upstream (debug).
	ph.AddXRequestUserAgent = r.FormValue("add_x_request_user_agent") == "on"
	// v2.9.247: add_reporting_endpoints — Reporting-Endpoints response header (RFC 8942).
	ph.AddReportingEndpoints = strings.TrimSpace(r.FormValue("add_reporting_endpoints"))
	// v2.9.248: add_x_request_byte_count — forward Content-Length as X-Request-Byte-Count.
	ph.AddXRequestByteCount = r.FormValue("add_x_request_byte_count") == "on"
	// v2.9.249: add_x_request_received_at — forward server-side timestamp.
	ph.AddXRequestReceivedAt = r.FormValue("add_x_request_received_at") == "on"
	// v2.9.250: strip_request_headers — comma-separated list of request headers to delete.
	ph.StripRequestHeaders = strings.TrimSpace(r.FormValue("strip_request_headers"))
	// v2.9.251: add_x_forwarded_method — forward HTTP method header.
	ph.AddXForwardedMethod = r.FormValue("add_x_forwarded_method") == "on"
	// v2.9.252: add_x_request_original_host — preserve original Host header.
	ph.AddXRequestOriginalHost = r.FormValue("add_x_request_original_host") == "on"
	// v2.9.253: add_x_request_dnt — forward DNT header.
	ph.AddXRequestDNT = r.FormValue("add_x_request_dnt") == "on"
	// v2.9.254: add_x_geo_region — static X-Geo-Region request header.
	ph.AddXGeoRegion = strings.TrimSpace(r.FormValue("add_x_geo_region"))
	// v2.9.255: add_x_request_secure — X-Request-Secure header based on TLS state.
	ph.AddXRequestSecure = r.FormValue("add_x_request_secure") == "on"
	// v2.9.256: add_x_request_query_count — debug header for query parameters.
	ph.AddXRequestQueryCount = r.FormValue("add_x_request_query_count") == "on"
	// v2.9.257: add_x_request_id_header_response — echo trace UUID to response header.
	ph.AddXRequestIDHeaderResponse = r.FormValue("add_x_request_id_header_response") == "on"
	// v2.9.258: force_canonical_host — canonical host for SEO-style consolidation.
	ph.ForceCanonicalHost = strings.TrimSpace(r.FormValue("force_canonical_host"))
	// v2.9.259: add_x_robots_noindex_quick — X-Robots-Tag: noindex, nofollow.
	ph.AddXRobotsNoindexQuick = r.FormValue("add_x_robots_noindex_quick") == "on"
	// v2.9.260: block_bot_user_agents — built-in bot blocklist.
	ph.BlockBotUserAgents = r.FormValue("block_bot_user_agents") == "on"
	// v2.9.261: block_admin_paths — 404 common admin paths.
	ph.BlockAdminPaths = r.FormValue("block_admin_paths") == "on"
	// v2.9.262: add_link_dns_prefetch — Link rel=dns-prefetch header.
	ph.AddLinkDNSPrefetch = strings.TrimSpace(r.FormValue("add_link_dns_prefetch"))
	// v2.9.263: add_link_preconnect — Link rel=preconnect header.
	ph.AddLinkPreconnect = strings.TrimSpace(r.FormValue("add_link_preconnect"))
	// v2.9.264: add_x_csp_disabled — strip Content-Security-Policy from response.
	ph.AddXCSPDisabled = r.FormValue("add_x_csp_disabled") == "on"
	// v2.9.265: add_x_request_method_override — honor X-HTTP-Method-Override.
	ph.AddXRequestMethodOverride = r.FormValue("add_x_request_method_override") == "on"
	// v2.9.266: proxy_redirect_rules — JSON array of path-based redirects
	// fired before the reverse_proxy. Same shape as redirection_hosts.
	ph.ProxyRedirectRules = func() string {
		v := strings.TrimSpace(r.FormValue("proxy_redirect_rules"))
		if v == "" || v == "[]" {
			return ""
		}
		var probe []models.RedirectRule
		if err := json.Unmarshal([]byte(v), &probe); err != nil {
			return ""
		}
		return v
	}()
	// v2.9.267: additional_upstream_rules — JSON array of path-based upstream
	// overrides. Probe-parse to drop garbage that UpstreamRuleList would
	// silently ignore on read.
	ph.AdditionalUpstreamRules = func() string {
		v := strings.TrimSpace(r.FormValue("additional_upstream_rules"))
		if v == "" || v == "[]" {
			return ""
		}
		var probe []models.UpstreamRule
		if err := json.Unmarshal([]byte(v), &probe); err != nil {
			return ""
		}
		return v
	}()
	return ph, nil
}

func (s *Server) createProxyHost(w http.ResponseWriter, r *http.Request) {
	p, err := parseProxyHostForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errMsg := validateSSLFlags(p.SSLEnabled, p.SSLForced, p.CertificateID); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	if errMsg := s.validateProxyAdvanced(p); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	// v2.7.7: refuse to create a proxy whose domain list collides with an
	// existing proxy or redirect on the same server. Without this guard the
	// row goes in fine, but Caddy's route table only keeps one match per
	// hostname — so the newer entry silently shadows the older one and users
	// see "my domain got overridden" complaints. The check is global across
	// owners (admin view) because Caddy routes are resolved by hostname, not
	// by who owns the row in the UI.
	if conflict, err := models.DomainsConflict(s.DB, s.currentServerID(r), p.DomainList(), 0, 0); err != nil {
		s.renderProxyHostFormError(w, r, p, "Could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		s.renderProxyHostFormError(w, r, p, fmt.Sprintf("Domain %q is already in use by another proxy or redirect on this server. Each domain can only be claimed once — edit the existing entry or remove it before reusing the name.", conflict))
		return
	}
	// v2.7.8: refuse to save a proxy whose first hostname doesn't live in the
	// selected DNS zone. The form's amber mismatch warning was advisory only
	// — users were saving anyway and ending up with rows that either failed
	// at the provider API on the next dnsCreateRecord call or quietly put the
	// A record in the wrong zone. Validate at save time so the row never
	// reaches the DB in a half-broken state.
	if errMsg := validateZoneMatchesHostname(p.DNSProvider, p.DNSZoneID, p.DNSZoneName, p.DomainList()); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	// Parse and hash basic auth users.
	if r.FormValue("basicauth_enabled") == "on" {
		p.BasicAuthEnabled = true
		baUsers, err := parseBasicAuthUsers(r)
		if err != nil {
			s.renderProxyHostFormError(w, r, p, "Basic auth error: "+err.Error())
			return
		}
		usersJSON, _ := json.Marshal(baUsers)
		p.BasicAuthUsers = string(usersJSON)
	} else {
		p.BasicAuthEnabled = false
		p.BasicAuthUsers = "[]"
	}
	// Parse extra upstreams (Feature D).
	p.ExtraUpstreams = marshalExtraUpstreams(r)
	deployTo := parseDeployTo(r)
	cu := s.currentUser(r)
	var ownerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		ownerID = cu.ID
	} else if cu != nil && cu.Role == models.RoleAdmin {
		// v2.7.3: admin can assign the new host to a specific user at create
		// time via the Owner <select>. Empty/"0" means global (the default).
		// We never trust this field coming from a non-admin — the branch above
		// short-circuits them to their own ID regardless of what they posted.
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				ownerID = parsed
			}
		}
	}
	id, err := models.CreateProxyHost(s.DB, s.currentServerID(r), ownerID, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Unified DNS: create A record if a provider + zone was selected.
	// dnsCreateRecord is a no-op when DNSProvider is empty, so no branch
	// needed here — just call it unconditionally.
	//
	// v2.5.6: the override-existing-record path was removed. When the
	// form's pre-flight check-record sees a collision, the user now has
	// to clear it by hand in the provider console — CaddyUI never
	// deletes records it doesn't own. Safer on shared zones, and avoids
	// any chance of wiping an unrelated service's A record here.
	dnsCreated := false
	if p.DNSProvider != "" && p.DNSZoneID != "" {
		s.dnsCreateRecord(s.currentServerID(r), id, p)
		dnsCreated = true
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "proxy_create", fmt.Sprintf("proxy:%d", id), p.Domains, true)
	s.syncCaddy(s.currentServerID(r), p.CertificateID != 0)
	if whURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL); whURL != "" {
		domains := p.Domains
		db := s.DB
		go func() {
			payload, _ := json.Marshal(map[string]any{
				"event":   "proxy_host_created",
				"message": "Proxy host created: " + domains,
				"domains": domains,
			})
			sendWebhookPayload(db, whURL, payload)
		}()
	}
	if len(deployTo) > 0 {
		s.crossDeployProxyHost(s.currentUserEmail(r), p, deployTo)
	}
	// v2.5.2: when a managed DNS record was created, park the user on the
	// deploying page so they can watch DNS propagate + cert issue instead
	// of landing on an "active" row that can't actually be opened yet.
	if dnsCreated {
		http.Redirect(w, r, fmt.Sprintf("/proxy-hosts/%d/deploying", id), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

func (s *Server) editProxyHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := models.GetProxyHost(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if !isAdmin {
		if !p.OwnerID.Valid || p.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "proxy_host_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         p,
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Section":      "proxy",
	}))
}

func (s *Server) updateProxyHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	// Ownership check before parsing form
	if !isAdmin {
		existing, err := models.GetProxyHost(s.DB, id)
		if err != nil || existing == nil || !existing.OwnerID.Valid || existing.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	p, err := parseProxyHostForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.ID = id
	if errMsg := validateSSLFlags(p.SSLEnabled, p.SSLForced, p.CertificateID); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	if errMsg := s.validateProxyAdvanced(p); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	// v2.7.7: refuse to save when the new domain list collides with another
	// proxy or redirect. excludeProxyID=p.ID lets the user save their own
	// edit unchanged — only OTHER rows count as conflicts. Symmetric with the
	// create path above; same rationale (Caddy resolves routes by hostname).
	if conflict, err := models.DomainsConflict(s.DB, s.currentServerID(r), p.DomainList(), p.ID, 0); err != nil {
		s.renderProxyHostFormError(w, r, p, "Could not validate domains: "+err.Error())
		return
	} else if conflict != "" {
		s.renderProxyHostFormError(w, r, p, fmt.Sprintf("Domain %q is already in use by another proxy or redirect on this server. Each domain can only be claimed once.", conflict))
		return
	}
	// v2.7.8: zone/hostname match check — same as create path. Editing path
	// matters because users hit this most often when they renamed the
	// hostname on an existing row but the dropdown stayed on the old zone.
	if errMsg := validateZoneMatchesHostname(p.DNSProvider, p.DNSZoneID, p.DNSZoneName, p.DomainList()); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	// Parse and hash basic auth users; preserve existing hashes if password left blank.
	if r.FormValue("basicauth_enabled") == "on" {
		p.BasicAuthEnabled = true
		baUsers, err := parseBasicAuthUsers(r)
		if err != nil {
			s.renderProxyHostFormError(w, r, p, "Basic auth error: "+err.Error())
			return
		}
		usersJSON, _ := json.Marshal(baUsers)
		p.BasicAuthUsers = string(usersJSON)
	} else {
		p.BasicAuthEnabled = false
		p.BasicAuthUsers = "[]"
	}
	// Parse extra upstreams (Feature D).
	p.ExtraUpstreams = marshalExtraUpstreams(r)
	deployTo := parseDeployTo(r)
	old, _ := models.GetProxyHost(s.DB, id)

	// Unified DNS lifecycle. A record needs replacing when:
	//   1. The user switched provider or cleared DNS entirely
	//   2. The user picked a different zone on the same provider
	//   3. The Domains list changed in any way — added alias, removed
	//      alias, renamed primary, or reordered
	// In any of those cases we delete every old record and create a
	// fresh record per current hostname after the DB save succeeds.
	// v2.5.10: comparison widened from FirstDomain to the full list
	// so adding/removing an alias actually provisions/removes the
	// matching A record — pre-v2.5.10 only the first-domain change
	// triggered this path, leaving aliases with no DNS.
	var oldDomains []string
	if old != nil {
		oldDomains = old.DomainList()
	}
	newDomains := p.DomainList()
	domainChanged := !slices.Equal(oldDomains, newDomains)

	providerChanged := old != nil && old.DNSProvider != p.DNSProvider
	zoneChanged := old != nil && old.DNSZoneID != p.DNSZoneID
	needDelete := old != nil && old.DNSRecordID != "" &&
		(p.DNSProvider == "" || providerChanged || zoneChanged || domainChanged)
	if needDelete {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
		p.DNSRecordID = ""
	} else if old != nil {
		// Preserve existing record + zone metadata when nothing routing-
		// relevant changed. The form doesn't resubmit record IDs, so
		// without this the DB save would clear it.
		p.DNSRecordID = old.DNSRecordID
	}
	needCreate := p.DNSProvider != "" && p.DNSZoneID != "" &&
		(p.DNSRecordID == "" || providerChanged || zoneChanged || domainChanged)

	if err := models.UpdateProxyHost(s.DB, p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.7.3: admin-only owner reassignment. Handled here (not inside
	// UpdateProxyHost) so the user-role edit path — which never reaches this
	// branch — cannot touch ownership even if a non-admin forges owner_id in
	// the POST body. An absent/blank owner_id (old form, non-admin upgrade
	// path) leaves ownership untouched; an explicit "0" is the admin saying
	// "make it global".
	if isAdmin {
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				_ = models.SetProxyHostOwner(s.DB, p.ID, parsed)
			}
		}
	}
	if needCreate {
		// v2.5.6: the override path is gone — same rationale as
		// createProxyHost above. If a record exists at this FQDN the
		// create call fails and the user clears it manually.
		s.dnsCreateRecord(s.currentServerID(r), p.ID, p)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "proxy_update", fmt.Sprintf("proxy:%d", id), p.Domains, true)
	forceTLS := old != nil && old.CertificateID != p.CertificateID
	s.syncCaddy(s.currentServerID(r), forceTLS)
	if whURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL); whURL != "" {
		domains := p.Domains
		db := s.DB
		go func() {
			payload, _ := json.Marshal(map[string]any{
				"event":   "proxy_host_updated",
				"message": "Proxy host updated: " + domains,
				"domains": domains,
			})
			sendWebhookPayload(db, whURL, payload)
		}()
	}
	if len(deployTo) > 0 {
		s.crossDeployProxyHost(s.currentUserEmail(r), p, deployTo)
	}
	// v2.5.2: if this edit created a fresh DNS record (first time enabling
	// Managed DNS, or provider / zone / first-domain changed), show the
	// deploying page so the user can watch DNS + cert come up. A plain
	// edit that left DNS untouched goes back to the list as before.
	if needCreate {
		http.Redirect(w, r, fmt.Sprintf("/proxy-hosts/%d/deploying", p.ID), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

func (s *Server) deleteProxyHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	old, _ := models.GetProxyHost(s.DB, id)
	if !isAdmin {
		if old == nil || !old.OwnerID.Valid || old.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	// Unified DNS: delete any managed record before removing the host.
	// No-op when the host has no DNS-managed record.
	if old != nil && old.DNSRecordID != "" {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
	}
	if err := models.DeleteProxyHost(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "proxy_delete", fmt.Sprintf("proxy:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.syncCaddy(s.currentServerID(r), forceTLS)
	if whURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL); whURL != "" && old != nil {
		domains := old.Domains
		db := s.DB
		go func() {
			payload, _ := json.Marshal(map[string]any{
				"event":   "proxy_host_deleted",
				"message": "Proxy host deleted: " + domains,
				"domains": domains,
			})
			sendWebhookPayload(db, whURL, payload)
		}()
	}
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

// cloneProxyHost creates a copy of a proxy host with Enabled=false and
// a "(copy)" suffix on each domain, then redirects to its edit page.
func (s *Server) cloneProxyHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	src, err := models.GetProxyHost(s.DB, id)
	if err != nil || src == nil {
		http.NotFound(w, r)
		return
	}
	// Build cloned domain list — append "(copy)" to each domain.
	domains := src.DomainList()
	cloned := make([]string, len(domains))
	for i, d := range domains {
		cloned[i] = d + " (copy)"
	}
	clone := *src // value copy
	clone.ID = 0
	clone.Domains = strings.Join(cloned, ",")
	clone.Enabled = false // always disabled so it doesn't affect live traffic
	clone.MaintenanceMode = false
	clone.CreatedAt = time.Time{}
	clone.UpdatedAt = time.Time{}

	cu := s.currentUser(r)
	var ownerID int64
	if cu != nil {
		ownerID = cu.ID
	}
	newID, err := models.CreateProxyHost(s.DB, src.ServerID, ownerID, &clone)
	if err != nil {
		http.Error(w, "clone failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/proxy-hosts/%d/edit", newID), http.StatusSeeOther)
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
		DNSProvider: provider,
		DNSZoneID:   zoneID,
		DNSZoneName: zoneName,
	}, nil
}

func (s *Server) createRedirectionHost(w http.ResponseWriter, r *http.Request) {
	rh, err := parseRedirectionHostForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
	id, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), rhOwnerID, rh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.12.2: auto-create A record(s) per hostname when Managed DNS is set.
	if rh.DNSProvider != "" && rh.DNSZoneID != "" {
		s.dnsCreateRecordForRedirection(s.currentServerID(r), id, rh)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_create", fmt.Sprintf("redirect:%d", id), rh.Domains, true)
	s.syncCaddy(s.currentServerID(r), rh.CertificateID != 0)
	if len(deployTo) > 0 {
		s.crossDeployRedirectionHost(s.currentUserEmail(r), rh, deployTo)
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
		if !rh.OwnerID.Valid || rh.OwnerID.Int64 != cu.ID {
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
		if err != nil || existing == nil || !existing.OwnerID.Valid || existing.OwnerID.Int64 != cu.ID {
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
	deployTo := parseDeployTo(r)
	old, _ := models.GetRedirectionHost(s.DB, id)
	// v2.12.2: preserve existing record IDs across UPDATE so delete-on-change
	// still has them. parseRedirectionHostForm doesn't carry DNSRecordID
	// (the form has no hidden field for it — same as proxy hosts).
	if old != nil {
		rh.DNSRecordID = old.DNSRecordID
	}
	if err := models.UpdateRedirectionHost(s.DB, rh); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.12.2: DNS provider / zone changed → drop the old A records, create
	// fresh ones for the new triple. Same pattern as proxy hosts.
	if old != nil {
		oldKey := old.DNSProvider + "|" + old.DNSZoneID
		newKey := rh.DNSProvider + "|" + rh.DNSZoneID
		if oldKey != newKey {
			if old.DNSRecordID != "" {
				s.dnsDeleteRecord(old.DNSProvider, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
				_ = models.UpdateRedirectionHostDNSRecord(s.DB, rh.ID, rh.DNSProvider, rh.DNSZoneID, rh.DNSZoneName, "")
				rh.DNSRecordID = ""
			}
			if rh.DNSProvider != "" && rh.DNSZoneID != "" {
				s.dnsCreateRecordForRedirection(s.currentServerID(r), rh.ID, rh)
			}
		} else if rh.DNSProvider != "" && rh.DNSZoneID != "" && rh.DNSRecordID == "" {
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
	s.syncCaddy(s.currentServerID(r), forceTLS)
	if len(deployTo) > 0 {
		s.crossDeployRedirectionHost(s.currentUserEmail(r), rh, deployTo)
	}
	http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
}

func (s *Server) deleteRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	old, _ := models.GetRedirectionHost(s.DB, id)
	if !isAdmin {
		if old == nil || !old.OwnerID.Valid || old.OwnerID.Int64 != cu.ID {
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
		s.dnsDeleteRecord(old.DNSProvider, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_delete", fmt.Sprintf("redirect:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.syncCaddy(s.currentServerID(r), forceTLS)
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
	w.Header().Set("HX-Trigger", "caddy-reloaded")
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
	Head     string // site-address line (e.g. "example.com")
	Snippet  string // original Caddyfile block
	Status   string // "created", "skipped", "error"
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

	routes := extractAdaptedRoutes(adapted.Result)
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
		if autoClassify {
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
		"User":           s.currentUser(r),
		"Section":        "paste",
		"Results":        results,
		"Created":        created,
		"CreatedProxy":   nProxy,
		"CreatedRedir":   nRedir,
		"CreatedRaw":     nRaw,
		"Input":          "",
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

// extractAdaptedRoutes pulls apps.http.servers.<first server>.routes[] from an
// adapted Caddy config. Caddy's Caddyfile adapter emits one server (usually "srv0")
// containing all site blocks as routes. Returns a possibly-empty slice.
func extractAdaptedRoutes(cfg map[string]any) []map[string]any {
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	var out []map[string]any
	for _, s := range servers {
		srv, _ := s.(map[string]any)
		routes, _ := srv["routes"].([]any)
		for _, r := range routes {
			if m, ok := r.(map[string]any); ok {
				out = append(out, m)
			}
		}
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

// mergeAutomationPolicies combines adapter-emitted policies into the live
// apps.tls.automation.policies[] array without clobbering hosts that already
// have a policy. Subjects already covered by an existing per-subject policy
// are stripped from the incoming policy; a new policy whose subjects are all
// already covered is dropped entirely. Remaining new policies are prepended
// so more-specific (with-subject) policies are evaluated before any catch-all
// policy Caddy has in place. Caddy scans policies in order and uses the first
// match, so prepend order matters.
func mergeAutomationPolicies(existing []any, incoming []map[string]any) []any {
	existingSubjects := map[string]bool{}
	for _, p := range existing {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		subs, _ := m["subjects"].([]any)
		for _, s := range subs {
			if str, ok := s.(string); ok {
				existingSubjects[str] = true
			}
		}
	}
	var prepend []any
	for _, p := range incoming {
		subs, _ := p["subjects"].([]any)
		var keptSubs []any
		for _, s := range subs {
			str, ok := s.(string)
			if !ok {
				continue
			}
			if !existingSubjects[str] {
				keptSubs = append(keptSubs, str)
				existingSubjects[str] = true
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
	return append(prepend, existing...)
}

// buildWildcardAutomationPolicies — v2.12.0: scans the supplied proxy / raw
// route lists for hostnames that start with `*.` (wildcard SAN) on
// SSL-enabled rows, and emits an apps.tls.automation.policies[] entry per
// unique DNS provider so Caddy issues those wildcard certs via the ACME
// DNS-01 challenge instead of HTTP-01 (which can't validate wildcards).
//
// Reuses the credentials already stored under each provider's settings
// keys for managed DNS — users don't have to re-enter the token. If a
// wildcard host has no dns_provider picked, it's silently skipped here;
// the frontend wildcard callout is what tells the user they need to
// pick one.
//
// Currently emits config for Cloudflare only. The mapping of internal
// dns provider ID → caddy-dns plugin name + cred field schema is
// per-provider and can be extended in caddyDNSProviderConfig.
func (s *Server) buildWildcardAutomationPolicies(proxies []models.ProxyHost, raws []models.RawRoute) []map[string]any {
	type bucket struct {
		subjects []string
		creds    map[string]string
	}
	byProvider := map[string]*bucket{}

	add := func(domains, providerID string, sslOn, enabled bool) {
		if !enabled || !sslOn || providerID == "" {
			return
		}
		for _, raw := range strings.Split(domains, ",") {
			d := strings.TrimSpace(raw)
			if !strings.HasPrefix(d, "*.") {
				continue
			}
			b, ok := byProvider[providerID]
			if !ok {
				descriptor, found := dns.Lookup(providerID)
				if !found {
					return
				}
				creds := map[string]string{}
				for _, c := range descriptor.Credentials {
					v, _ := models.GetSetting(s.DB, c.Key)
					creds[c.Key] = v
				}
				b = &bucket{creds: creds}
				byProvider[providerID] = b
			}
			b.subjects = append(b.subjects, d)
		}
	}
	for _, p := range proxies {
		add(p.Domains, p.DNSProvider, p.SSLEnabled, p.Enabled)
	}
	for _, rr := range raws {
		// Raw routes can carry a managed-DNS provider too (v2.5.6 unified DNS).
		add("", rr.DNSProvider, false, rr.Enabled) // raw routes don't expose a domains field directly
		_ = rr
	}

	var policies []map[string]any
	for providerID, b := range byProvider {
		if len(b.subjects) == 0 {
			continue
		}
		cfg := caddyDNSProviderConfig(providerID, b.creds)
		if cfg == nil {
			log.Printf("automation: skipping provider %q — DNS-01 mapping not implemented or credentials missing", providerID)
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

// caddyDNSProviderConfig — v2.12.0: maps an internal dns-provider ID to the
// Caddy DNS plugin's JSON config block. Returns nil when the credential
// fields haven't been populated under Settings → DNS providers, OR when
// the internal provider has no caddy-dns plugin mapping yet.
//
// The Caddy build must include the matching `caddy-dns/<provider>` plugin
// (xcaddy or a custom Dockerfile). The default `caddy:2-alpine` image
// has no DNS plugins — Caddy will reject the config with "unknown module"
// at apply time, surfacing as a sync_apply_tls_failed activity log.
func caddyDNSProviderConfig(providerID string, creds map[string]string) map[string]any {
	switch providerID {
	case dns.Cloudflare:
		token := creds["cf_api_token"]
		if token == "" {
			return nil
		}
		return map[string]any{"name": "cloudflare", "api_token": token}
		// Other providers would slot in here as their caddy-dns/<id>
		// plugin schemas are confirmed. Skipping for v2.12.0 — Cloudflare
		// covers the most common DoH / wildcard / multi-tenant case.
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
	tlsApp := ensureMap(apps, "tls")
	automation, _ := tlsApp["automation"].(map[string]any)
	if automation == nil {
		automation = map[string]any{}
	}
	existing, _ := automation["policies"].([]any)
	automation["policies"] = mergeAutomationPolicies(existing, incoming)
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
		"User":    s.currentUser(r),
		"Section": "docs",
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

// --- Certificates ---

// adminUserList returns the full user list for admins (used by the admin-only
// Owner pickers on new/edit forms so an admin can provision a resource for a
// specific customer). Returns an empty slice for non-admin viewers so we
// don't waste a DB round-trip and so a template leak can't surface email
// addresses to non-admins. v2.7.3.
// groupPeerIDs returns the other user IDs that share at least one group with
// the viewer. Used to expand a non-admin viewer's visibility scope in every
// List* call: viewer sees their own rows + globals + any row owned by a peer.
// Admins skip this path entirely — their List* branch is unfiltered — so we
// return nil immediately for admin/view and for signed-out requests. DB
// errors are swallowed to nil so a transient groups-table hiccup degrades to
// "no group visibility" rather than breaking the whole list page.
func (s *Server) groupPeerIDs(r *http.Request) []int64 {
	cu := s.currentUser(r)
	if cu == nil || cu.Role != models.RoleUser {
		return nil
	}
	ids, err := models.GroupPeerIDs(s.DB, cu.ID)
	if err != nil {
		return nil
	}
	return ids
}

// adminUserList returns the user-role accounts an admin can assign resources
// to. Only admins see anything — nil for non-admin viewers so their templates
// can't accidentally leak the user roster via the Owner <select>. View-role
// and admin accounts are filtered out because neither can "own" a resource in
// the data model (admin ownership is represented as NULL / global; view can't
// manage anything at all), so they'd be dead options in the picker.
func (s *Server) adminUserList(r *http.Request) []models.User {
	cu := s.currentUser(r)
	if cu == nil || cu.Role != models.RoleAdmin {
		return nil
	}
	users, err := models.ListUsers(s.DB)
	if err != nil {
		return nil
	}
	out := users[:0]
	for _, u := range users {
		if u.Role == models.RoleUser {
			out = append(out, u)
		}
	}
	return out
}

// certListForRequest returns the certificate list scoped to the signed-in
// viewer. Admin sees every row; a user-role account sees their own uploads
// plus any global (admin-owned, owner_id IS NULL) certs. Used by the
// proxy-host / redirection / raw-route form dropdowns so a non-admin never
// sees another tenant's private TLS material in the picker.
//
// Back-end callers that build Caddy's tls.certificates config (sync paths,
// cert-expiry background job, dashboard across servers) should keep using
// models.ListCertificates — they need the complete set regardless of who's
// looking.
func (s *Server) certListForRequest(r *http.Request) ([]models.Certificate, error) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	return models.ListCertificatesForUser(s.DB, s.currentServerID(r), viewerID, isAdmin, s.groupPeerIDs(r))
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	sid := s.currentServerID(r)
	cu := s.currentUser(r)
	var viewerID int64
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if cu != nil {
		viewerID = cu.ID
	}
	// v2.7.2: non-admin sees only their own uploads + global (admin-owned)
	// certs. Admin view still gets every row plus the owner email via JOIN
	// for the Owner column in certificates.html.
	// v2.7.4: ...plus any certs owned by a teammate (shared group member).
	certs, err := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]certView, len(certs))
	for i, c := range certs {
		// Edit/delete predicate: admin → always; user-role → their own rows
		// only (not global admin-owned ones, even though they're visible in
		// the list for the dropdown-reference case).
		canEdit := isAdmin || (c.OwnerID.Valid && viewerID != 0 && c.OwnerID.Int64 == viewerID)
		views[i] = certView{Certificate: c, CanEdit: canEdit}
		var exp *time.Time
		switch c.Source {
		case models.CertSourcePEM:
			exp = parsePEMExpiry(c.CertPEM)
		case models.CertSourcePath:
			if data, readErr := os.ReadFile(c.CertPath); readErr == nil {
				exp = parsePEMExpiry(string(data))
			}
		}
		if exp != nil {
			views[i].ExpiresAt = exp
			views[i].DaysLeft = int(time.Until(*exp).Hours() / 24)
		}
	}

	// Collect domains auto-managed by Caddy (ssl_enabled, no custom cert).
	// Use admin view to see all hosts regardless of owner.
	hosts, _ := models.ListProxyHosts(s.DB, sid, 0, true, nil)
	redirs, _ := models.ListRedirectionHosts(s.DB, sid, 0, true, nil)
	seen := map[string]bool{}
	var autoDomains []string
	for _, h := range hosts {
		if !h.Enabled || !h.SSLEnabled || h.CertificateID != 0 {
			continue
		}
		for _, d := range h.DomainList() {
			if !seen[d] {
				seen[d] = true
				autoDomains = append(autoDomains, d)
			}
		}
	}
	for _, rh := range redirs {
		if !rh.Enabled || !rh.SSLEnabled || rh.CertificateID != 0 {
			continue
		}
		for _, d := range rh.DomainList() {
			if !seen[d] {
				seen[d] = true
				autoDomains = append(autoDomains, d)
			}
		}
	}

	s.render(w, r, "certificates.html", map[string]any{
		"User":        s.currentUser(r),
		"Certs":       views,
		"AutoDomains": autoDomains,
		"Section":     "certs",
	})
}

// getCertificateInspect parses the stored PEM and renders detailed certificate
// information (subject, issuer, SANs, validity window, key type, serial,
// SHA-256 fingerprint). Accessible to all authenticated users, not just admins,
// so each user can inspect certs they uploaded.
func (s *Server) getCertificateInspect(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	cert, err := models.GetCertificate(s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := map[string]any{
		"User":    s.currentUser(r),
		"Cert":    cert,
		"Section": "certs",
	}

	pemData := cert.CertPEM
	if pemData == "" && cert.Source == models.CertSourcePath {
		// Path-based cert: try reading the file so we can still parse it.
		if raw, readErr := os.ReadFile(cert.CertPath); readErr == nil {
			pemData = string(raw)
		}
	}

	if pemData == "" {
		s.render(w, r, "certificate_inspect.html", data)
		return
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		s.render(w, r, "certificate_inspect.html", data)
		return
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.render(w, r, "certificate_inspect.html", data)
		return
	}

	// Subject / Issuer
	data["Subject"] = parsed.Subject.String()
	data["Issuer"] = parsed.Issuer.String()

	// SANs: DNS names, IPs, URIs
	sans := make([]string, 0, len(parsed.DNSNames)+len(parsed.IPAddresses)+len(parsed.URIs))
	sans = append(sans, parsed.DNSNames...)
	for _, ip := range parsed.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range parsed.URIs {
		sans = append(sans, uri.String())
	}
	data["SANs"] = sans

	// Validity window
	data["NotBefore"] = parsed.NotBefore
	data["NotAfter"] = parsed.NotAfter
	data["DaysLeft"] = int(time.Until(parsed.NotAfter).Hours() / 24)

	// Key type and bits
	keyType := "Unknown"
	keyBits := 0
	switch k := parsed.PublicKey.(type) {
	case *rsa.PublicKey:
		keyType = "RSA"
		keyBits = k.N.BitLen()
	case *ecdsa.PublicKey:
		keyType = "ECDSA"
		keyBits = k.Curve.Params().BitSize
	case ed25519.PublicKey:
		keyType = "Ed25519"
	}
	data["KeyType"] = keyType
	data["KeyBits"] = keyBits

	// Serial number (hex)
	data["SerialNumber"] = parsed.SerialNumber.Text(16)

	// SHA-256 fingerprint over the raw DER bytes
	fp := sha256.Sum256(parsed.Raw)
	fpParts := make([]string, len(fp))
	for i, b := range fp {
		fpParts[i] = fmt.Sprintf("%02X", b)
	}
	data["Fingerprint"] = strings.Join(fpParts[:], ":")

	s.render(w, r, "certificate_inspect.html", data)
}

func (s *Server) newCertificate(w http.ResponseWriter, r *http.Request) {
	// v2.7.3: Users list fuels the admin-only Owner picker on the form.
	// Non-admins get nil — the template skips rendering the picker.
	s.render(w, r, "certificate_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Cert":    &models.Certificate{Source: models.CertSourcePEM},
		"Users":   s.adminUserList(r),
		"Section": "certs",
	})
}

func parseCertificateForm(r *http.Request) (*models.Certificate, string) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	domains := strings.TrimSpace(r.FormValue("domains"))
	source := r.FormValue("source")
	if source != models.CertSourcePEM && source != models.CertSourcePath {
		source = models.CertSourcePEM
	}
	c := &models.Certificate{
		Name:    name,
		Domains: domains,
		Source:  source,
	}
	if name == "" {
		return nil, "Name is required"
	}
	if domains == "" {
		return nil, "At least one domain is required (comma-separated)"
	}
	if source == models.CertSourcePEM {
		c.CertPEM = strings.TrimSpace(r.FormValue("cert_pem"))
		c.KeyPEM = strings.TrimSpace(r.FormValue("key_pem"))
		if c.CertPEM == "" || c.KeyPEM == "" {
			return nil, "Certificate PEM and Private key PEM are required when source is 'pem'"
		}
		if !strings.Contains(c.CertPEM, "BEGIN CERTIFICATE") {
			return nil, "Certificate PEM doesn't look like a PEM block"
		}
		if !strings.Contains(c.KeyPEM, "PRIVATE KEY") {
			return nil, "Private key PEM doesn't look like a PEM block"
		}
	} else {
		c.CertPath = strings.TrimSpace(r.FormValue("cert_path"))
		c.KeyPath = strings.TrimSpace(r.FormValue("key_path"))
		if c.CertPath == "" || c.KeyPath == "" {
			return nil, "Certificate path and Key path are required when source is 'path'"
		}
	}
	return c, ""
}

func (s *Server) createCertificate(w http.ResponseWriter, r *http.Request) {
	c, errMsg := parseCertificateForm(r)
	if errMsg != "" {
		// Re-render with whatever the user typed
		fallback := &models.Certificate{
			Name:     r.FormValue("name"),
			Domains:  r.FormValue("domains"),
			Source:   r.FormValue("source"),
			CertPEM:  r.FormValue("cert_pem"),
			KeyPEM:   r.FormValue("key_pem"),
			CertPath: r.FormValue("cert_path"),
			KeyPath:  r.FormValue("key_path"),
		}
		s.render(w, r, "certificate_form.html", map[string]any{
			"User":    s.currentUser(r),
			"Cert":    fallback,
			"Users":   s.adminUserList(r),
			"Error":   errMsg,
			"Section": "certs",
		})
		return
	}
	// v2.7.2: non-admin uploads are tagged with their user ID so they land in
	// their own scoped list. Admin uploads get owner_id = NULL → shared/global
	// (visible from every user's proxy-host dropdown). Matches the pattern
	// used by createProxyHost/createRedirectionHost/createRawRoute.
	cu := s.currentUser(r)
	var ownerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		ownerID = cu.ID
	} else if cu != nil && cu.Role == models.RoleAdmin {
		// v2.7.3: admin can upload-and-assign a cert directly to a specific
		// user from the new-cert form.
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				ownerID = parsed
			}
		}
	}
	id, err := models.CreateCertificate(s.DB, s.currentServerID(r), ownerID, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_create", fmt.Sprintf("cert:%d", id), c.Name, true)
	s.syncCaddy(s.currentServerID(r), true)
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

func (s *Server) editCertificate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	c, err := models.GetCertificate(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// v2.7.2: ownership gate. Admin edits anything; a user can edit a cert
	// they uploaded but not one owned by somebody else or a global/admin
	// cert (owner_id NULL). Mirrors the check pattern used by
	// editProxyHost / updateRedirectionHost etc. so all four resource types
	// enforce the same rule.
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if !isAdmin {
		if !c.OwnerID.Valid || cu == nil || c.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	s.render(w, r, "certificate_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Cert":    c,
		"Users":   s.adminUserList(r),
		"Section": "certs",
	})
}

func (s *Server) updateCertificate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	// Re-fetch to enforce ownership server-side — never trust the form.
	existing, err := models.GetCertificate(s.DB, id)
	if err != nil || existing == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if !isAdmin {
		if !existing.OwnerID.Valid || cu == nil || existing.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	c, errMsg := parseCertificateForm(r)
	if errMsg != "" {
		existing, _ := models.GetCertificate(s.DB, id)
		if existing == nil {
			existing = &models.Certificate{}
		}
		existing.Name = r.FormValue("name")
		existing.Domains = r.FormValue("domains")
		existing.Source = r.FormValue("source")
		existing.CertPEM = r.FormValue("cert_pem")
		existing.KeyPEM = r.FormValue("key_pem")
		existing.CertPath = r.FormValue("cert_path")
		existing.KeyPath = r.FormValue("key_path")
		s.render(w, r, "certificate_form.html", map[string]any{
			"User":    s.currentUser(r),
			"Cert":    existing,
			"Users":   s.adminUserList(r),
			"Error":   errMsg,
			"Section": "certs",
		})
		return
	}
	c.ID = id
	if err := models.UpdateCertificate(s.DB, c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.7.3: admin-only owner reassignment. Note: when admin moves a cert
	// from "global" to a specific user, any existing proxy/redirect/raw rows
	// referencing this cert continue to work — the syncCaddy call below
	// rewrites the running Caddy config from the DB, and cert references are
	// resolved by ID not ownership. This is by design: handing a cert off
	// should not break whatever's already using it.
	if isAdmin {
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				_ = models.SetCertificateOwner(s.DB, c.ID, parsed)
			}
		}
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_update", fmt.Sprintf("cert:%d", id), c.Name, true)
	s.syncCaddy(s.currentServerID(r), true)
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	// v2.7.2: ownership-aware delete. DeleteCertificate NULLs every
	// certificate_id that points at this row across proxy_hosts,
	// redirection_hosts, and raw_routes — cross-owner fan-out that we have
	// to gate carefully.
	//
	//   admin  → can delete anything (global + anyone's private).
	//   user   → can delete only a cert they own (owner_id = their ID) AND
	//            only when no site they don't own still references it.
	//            Global (owner_id NULL) stays admin-only because tearing
	//            it off the shared wildcard would silently break other
	//            tenants. The CertificateInUse check below is stricter
	//            than "zero refs" — it lets a user delete even if some of
	//            their own sites use it (they'll fall back to auto-ssl)
	//            but blocks delete when any other owner's site would be
	//            collaterally affected.
	//   view   → never reaches here; requireWrite already 403'd at the
	//            route layer.
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	if !isAdmin {
		cert, err := models.GetCertificate(s.DB, id)
		if err != nil || cert == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if !cert.OwnerID.Valid {
			http.Error(w, "only admins can delete global certificates", http.StatusForbidden)
			return
		}
		if cert.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Block when a site the caller doesn't own still references this
		// cert — prevents accidental TLS removal from a co-tenant's host.
		if foreign, _ := models.CertificateInUseByOthers(s.DB, id, cu.ID); foreign > 0 {
			http.Error(w, "this certificate is in use by another user's site — ask an admin to delete it", http.StatusForbidden)
			return
		}
	}
	if err := models.DeleteCertificate(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_delete", fmt.Sprintf("cert:%d", id), "", true)
	s.syncCaddy(s.currentServerID(r), true)
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

// --- Raw (passthrough) routes ---

func (s *Server) listRawRoutes(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	rows, err := models.ListRawRoutes(s.DB, s.currentServerID(r), viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "raw_routes.html", map[string]any{
		"User":     s.currentUser(r),
		"Rows":     rows,
		"Section":  "raw",
		"ViewerID": viewerID,
		// v2.10.9: surface the post-reclassify flash banner.
		"Flash": r.URL.Query().Get("flash"),
	})
}

func (s *Server) newRawRoute(w http.ResponseWriter, r *http.Request) {
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "raw_route_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Row":          &models.RawRoute{Enabled: true},
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"Section":      "raw",
	}))
}

func (s *Server) parseRawRouteForm(r *http.Request) (*models.RawRoute, string) {
	_ = r.ParseForm()
	label := strings.TrimSpace(r.FormValue("label"))
	body := strings.TrimSpace(r.FormValue("json_data"))
	cfSrc := strings.TrimSpace(r.FormValue("caddyfile_src"))
	if label == "" {
		return nil, "Label is required"
	}
	// If the Caddyfile source field is non-empty, it's authoritative — re-adapt
	// through Caddy and let the resulting JSON replace json_data. This is what
	// makes the Caddyfile block editable after import.
	if cfSrc != "" {
		jsonData, err := s.adaptRawRouteCaddyfile(s.caddyForRequest(r), cfSrc)
		if err != nil {
			return nil, "Caddyfile rejected by Caddy: " + err.Error()
		}
		body = jsonData
	}
	if body == "" {
		return nil, "JSON is required"
	}
	var probe any
	if err := json.Unmarshal([]byte(body), &probe); err != nil {
		return nil, "Invalid JSON: " + err.Error()
	}
	certID, _ := strconv.ParseInt(r.FormValue("certificate_id"), 10, 64)
	// v2.5.6: Managed DNS picker — mirrors parseProxyHostForm. Unknown
	// providers collapse to "none" so a stale dropdown value never writes
	// a bogus row.
	provider := strings.ToLower(strings.TrimSpace(r.FormValue("dns_provider")))
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
	return &models.RawRoute{
		Label:               label,
		JSONData:            body,
		CaddyfileSrc:        cfSrc,
		Enabled:             r.FormValue("enabled") == "on",
		CertificateID:       certID,
		ForceSSL:            r.FormValue("ssl_forced") == "on",
		BlockCommonExploits: r.FormValue("block_common_exploits") == "on",
		DNSProvider:         provider,
		DNSZoneID:           zoneID,
		DNSZoneName:         zoneName,
	}, ""
}

// adaptRawRouteCaddyfile sends a Caddyfile block (the `caddyfile_src` field of a
// raw_route) through Caddy's /adapt, prepending auto-loaded snippets from the
// mounted Caddyfile so `import <name>` references resolve. Returns the JSON to
// store in raw_routes.json_data — a single route object if the block produced
// exactly one route, or a JSON array otherwise (buildMergedRoutes handles both).
func (s *Server) adaptRawRouteCaddyfile(caddyCl *caddy.Client, src string) (string, error) {
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
	full := src
	if len(loadedSnippets) > 0 {
		full = strings.Join(loadedSnippets, "\n\n") + "\n\n" + src
	}
	adapted, err := caddyCl.Adapt(full)
	if err != nil {
		return "", err
	}
	routes := extractAdaptedRoutes(adapted.Result)
	if len(routes) == 0 {
		return "", fmt.Errorf("the Caddyfile adapted successfully but produced no HTTP routes — include at least one site block")
	}
	if len(routes) == 1 {
		blob, err := json.Marshal(routes[0])
		if err != nil {
			return "", fmt.Errorf("serialize route: %w", err)
		}
		return string(blob), nil
	}
	blob, err := json.Marshal(routes)
	if err != nil {
		return "", fmt.Errorf("serialize routes: %w", err)
	}
	return string(blob), nil
}

// previewRawRouteValidate simulates syncCaddy with rr swapped into the raw_routes
// list (replacing the entry with the same ID, or appended if new) and calls
// Caddy's /load?validate_only=true. Returns a non-empty message only when Caddy
// would reject the resulting config — so callers can refuse to save instead of
// committing a change that breaks the live config on next sync.
func (s *Server) previewRawRouteValidate(serverID int64, rr *models.RawRoute) string {
	proxies, err := models.ListProxyHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return ""
	}
	redirs, err := models.ListRedirectionHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return ""
	}
	raws, err := models.ListRawRoutes(s.DB, serverID, 0, true, nil)
	if err != nil {
		return ""
	}
	certs, err := models.ListCertificates(s.DB, serverID)
	if err != nil {
		return ""
	}
	replaced := false
	for i, existing := range raws {
		if existing.ID == rr.ID && rr.ID != 0 {
			raws[i] = *rr
			replaced = true
			break
		}
	}
	if !replaced {
		raws = append(raws, *rr)
	}
	caddyCl := s.caddyForServer(serverID)
	current, _, err := caddyCl.FetchConfig()
	if err != nil {
		return ""
	}
	proposed, err := deepCopyMap(current)
	if err != nil {
		return ""
	}
	applyRoutes(proposed, s.buildMergedRoutes(proxies, redirs, raws))
	loadPEM, loadFiles := buildCertLoaders(certs)
	applyCertLoaders(proposed, loadPEM, loadFiles)
	applySkipCertificates(proposed, buildSkipCertificates(proxies, redirs, raws))
	applySkipRedirects(proposed, buildSkipRedirects(proxies, redirs))
	applySkipAccessLogs(proposed, buildSkipAccessLogs(proxies))
	// Mirror syncCaddy: preview-validation must match the config we'd push
	// for real, otherwise a raw_route edit could validate clean here but
	// fail with errors.routes rejection at sync time.
	applyErrorPages(proposed)
	if err := caddyCl.Validate(proposed); err != nil {
		return "Caddy rejected the proposed config: " + err.Error()
	}
	return ""
}

func (s *Server) createRawRoute(w http.ResponseWriter, r *http.Request) {
	rr, errMsg := s.parseRawRouteForm(r)
	if errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	if errMsg := s.previewRawRouteValidate(s.currentServerID(r), rr); errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	// v2.7.8: refuse to save a raw route whose first match.host doesn't live
	// in the selected DNS zone. Same logic and rationale as the proxy-host
	// path. Routes with no host matcher (path- or port-only) skip the check
	// because there's no FQDN to validate against — those rows opt out of
	// managed DNS regardless of what the form had selected.
	if errMsg := validateZoneMatchesHostname(rr.DNSProvider, rr.DNSZoneID, rr.DNSZoneName, rawRouteHosts(*rr)); errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	cu := s.currentUser(r)
	var rrOwnerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		rrOwnerID = cu.ID
	} else if cu != nil && cu.Role == models.RoleAdmin {
		// v2.7.3: admin can assign this raw route to a specific user at create
		// time. Same pattern as proxy/redirect handlers.
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				rrOwnerID = parsed
			}
		}
	}
	id, err := models.CreateRawRoute(s.DB, s.currentServerID(r), rrOwnerID, rr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.5.6: Managed DNS parity with proxy hosts — auto-create the A
	// record when the user picked a provider + zone. No-op otherwise.
	// Skipped for routes without a host matcher (no FQDN to target).
	if rr.DNSProvider != "" && rr.DNSZoneID != "" && firstRawRouteHost(rr.JSONData) != "" {
		s.dnsCreateRecordForRaw(s.currentServerID(r), id, rr)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "raw_create", fmt.Sprintf("raw:%d", id), rr.Label, true)
	s.syncCaddy(s.currentServerID(r), rr.CertificateID != 0)
	// v2.5.5: park the user on the deploying checklist when the route has
	// a host matcher we can probe. Path-only / port-only routes have no
	// fqdn to verify, so we skip the page and bounce to the list like before.
	if firstRawRouteHost(rr.JSONData) != "" {
		http.Redirect(w, r, fmt.Sprintf("/raw-routes/%d/deploying", id), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
}

// renderRawRouteFormError re-renders the raw-route form with a validation or
// adapt error. rr may be nil when the form was missing required fields — in
// that case we reconstruct it from the raw form values so the user's input
// isn't wiped.
func (s *Server) renderRawRouteFormError(w http.ResponseWriter, r *http.Request, rr *models.RawRoute, errMsg string) {
	certs, _ := s.certListForRequest(r)
	if rr == nil {
		certID, _ := strconv.ParseInt(r.FormValue("certificate_id"), 10, 64)
		// Reconstruct DNS fields too so the picker state survives an error
		// reload — same shape parseRawRouteForm would have produced.
		provider := strings.ToLower(strings.TrimSpace(r.FormValue("dns_provider")))
		zoneID := strings.TrimSpace(r.FormValue("dns_zone_id"))
		zoneName := strings.TrimSpace(r.FormValue("dns_zone_name"))
		if zoneName == "" {
			zoneName = zoneID
		}
		rr = &models.RawRoute{
			Label:               r.FormValue("label"),
			JSONData:            r.FormValue("json_data"),
			CaddyfileSrc:        r.FormValue("caddyfile_src"),
			Enabled:             r.FormValue("enabled") == "on",
			CertificateID:       certID,
			ForceSSL:            r.FormValue("ssl_forced") == "on",
			BlockCommonExploits: r.FormValue("block_common_exploits") == "on",
			DNSProvider:         provider,
			DNSZoneID:           zoneID,
			DNSZoneName:         zoneName,
		}
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id != 0 {
		rr.ID = id
	}
	s.render(w, r, "raw_route_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Row":          rr,
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"Error":        errMsg,
		"Section":      "raw",
	}))
}

func (s *Server) editRawRoute(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rr, err := models.GetRawRoute(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	if !isAdmin {
		if !rr.OwnerID.Valid || rr.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "raw_route_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Row":          rr,
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"Section":      "raw",
	}))
}

func (s *Server) updateRawRoute(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	// Ownership check before parsing form
	if !isAdmin {
		existing, err := models.GetRawRoute(s.DB, id)
		if err != nil || existing == nil || !existing.OwnerID.Valid || existing.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	rr, errMsg := s.parseRawRouteForm(r)
	if errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	rr.ID = id
	// v2.7.8: zone/hostname match — same as create path. Routes with no host
	// matcher skip the check (rawRouteHosts returns nil → validator returns "").
	if errMsg := validateZoneMatchesHostname(rr.DNSProvider, rr.DNSZoneID, rr.DNSZoneName, rawRouteHosts(*rr)); errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	// Preserve the Caddyfile source on JSON-only edits: when the form didn't
	// submit caddyfile_src (textarea was hidden because the row had none, or
	// user cleared it), keep the existing snippet as long as the JSON matches
	// — otherwise clear it so we never show a stale Caddyfile that no longer
	// matches the committed JSON.
	forceTLS := false
	old, _ := models.GetRawRoute(s.DB, id)
	if old != nil {
		if rr.CaddyfileSrc == "" && old.CaddyfileSrc != "" && jsonEqual(old.JSONData, rr.JSONData) {
			rr.CaddyfileSrc = old.CaddyfileSrc
		}
		forceTLS = old.CertificateID != rr.CertificateID
	}

	// v2.5.6: Managed DNS lifecycle. Same rules as proxy-host update —
	// replace records when the provider, zone, or set of match[].host[]
	// entries changes. v2.5.10: comparison widened from the first host
	// to the full list so adding/removing a secondary hostname actually
	// provisions/removes the matching A record.
	var oldHosts []string
	if old != nil {
		oldHosts = rawRouteHosts(*old)
	}
	newHosts := rawRouteHosts(*rr)
	fqdnChanged := !slices.Equal(oldHosts, newHosts)
	newFQDN := ""
	if len(newHosts) > 0 {
		newFQDN = newHosts[0]
	}

	providerChanged := old != nil && old.DNSProvider != rr.DNSProvider
	zoneChanged := old != nil && old.DNSZoneID != rr.DNSZoneID
	needDelete := old != nil && old.DNSRecordID != "" &&
		(rr.DNSProvider == "" || providerChanged || zoneChanged || fqdnChanged)
	if needDelete {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
		rr.DNSRecordID = ""
	} else if old != nil {
		// Preserve existing record ID when nothing routing-relevant
		// changed. The form doesn't resubmit record IDs, so without this
		// the DB save would clear it.
		rr.DNSRecordID = old.DNSRecordID
	}
	needCreate := rr.DNSProvider != "" && rr.DNSZoneID != "" && len(newHosts) > 0 &&
		(rr.DNSRecordID == "" || providerChanged || zoneChanged || fqdnChanged)

	if errMsg := s.previewRawRouteValidate(s.currentServerID(r), rr); errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	if err := models.UpdateRawRoute(s.DB, rr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.7.3: admin-only owner reassignment. Kept out of UpdateRawRoute so the
	// user-role edit path can never touch ownership.
	if isAdmin {
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				_ = models.SetRawRouteOwner(s.DB, rr.ID, parsed)
			}
		}
	}
	if needCreate {
		s.dnsCreateRecordForRaw(s.currentServerID(r), rr.ID, rr)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "raw_update", fmt.Sprintf("raw:%d", id), rr.Label, true)
	s.syncCaddy(s.currentServerID(r), forceTLS)
	// v2.5.5: show the deploying checklist on edits too — changing the
	// host matcher or the backing service is the same "did it come back
	// up on HTTPS?" question the create flow asks. Routes without a host
	// matcher skip the page as in create.
	if newFQDN != "" {
		http.Redirect(w, r, fmt.Sprintf("/raw-routes/%d/deploying", id), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
}

// jsonEqual reports whether two JSON strings encode the same value (whitespace-insensitive).
func jsonEqual(a, b string) bool {
	var av, bv any
	if err := json.Unmarshal([]byte(a), &av); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &bv); err != nil {
		return false
	}
	aj, _ := json.Marshal(av)
	bj, _ := json.Marshal(bv)
	return string(aj) == string(bj)
}

func (s *Server) deleteRawRoute(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	old, _ := models.GetRawRoute(s.DB, id)
	if !isAdmin {
		if old == nil || !old.OwnerID.Valid || old.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	// v2.5.6: remove the managed DNS record before deleting the row so we
	// don't orphan it at the provider. No-op when the route has none.
	if old != nil && old.DNSRecordID != "" {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
	}
	if err := models.DeleteRawRoute(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "raw_delete", fmt.Sprintf("raw:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.syncCaddy(s.currentServerID(r), forceTLS)
	http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
}

// postReclassifyRawRoutes runs the same classifier the Caddyfile-import flow
// uses over every existing raw_route the caller is allowed to touch. Routes
// that the classifier now recognises as a simple proxy or redirect are
// converted: a new ProxyHost / RedirectionHost row is created, and the
// raw_route is deleted. Routes the classifier still can't simplify are left
// alone. Useful for cleaning up Advanced routes that pre-date v2.10.7.
// v2.10.9.
func (s *Server) postReclassifyRawRoutes(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	rows, err := models.ListRawRoutes(s.DB, s.currentServerID(r), viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var ownerID int64
	if !isAdmin && cu != nil {
		ownerID = cu.ID
	}
	var nProxy, nRedir, nKept int
	for _, row := range rows {
		// Edit-permission gate: non-admins only touch their own rows. The
		// list query above already filters to visible rows, but visibility
		// includes group peers — re-check ownership before mutating.
		if !isAdmin {
			if !row.OwnerID.Valid || row.OwnerID.Int64 != cu.ID {
				continue
			}
		}
		if row.JSONData == "" {
			nKept++
			continue
		}
		var route map[string]any
		if err := json.Unmarshal([]byte(row.JSONData), &route); err != nil {
			nKept++
			continue
		}
		synth := map[string]any{
			"apps": map[string]any{
				"http": map[string]any{
					"servers": map[string]any{
						"_reclassify": map[string]any{
							"routes": []any{route},
						},
					},
				},
			},
		}
		classified := caddy.ClassifyConfig(synth)
		if len(classified.Proxies) == 1 {
			ph := classified.Proxies[0]
			ph.Enabled = row.Enabled
			if _, err := models.CreateProxyHost(s.DB, s.currentServerID(r), ownerID, &ph); err != nil {
				nKept++
				continue
			}
			_ = models.DeleteRawRoute(s.DB, row.ID)
			nProxy++
			continue
		}
		if len(classified.Redirect) == 1 {
			rh := classified.Redirect[0]
			rh.Enabled = row.Enabled
			if _, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), ownerID, &rh); err != nil {
				nKept++
				continue
			}
			_ = models.DeleteRawRoute(s.DB, row.ID)
			nRedir++
			continue
		}
		nKept++
	}
	if nProxy > 0 || nRedir > 0 {
		_ = s.syncCaddy(s.currentServerID(r), false)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "raw_reclassify", "",
		fmt.Sprintf("proxies=%d redirects=%d kept=%d", nProxy, nRedir, nKept), true)
	flash := url.QueryEscape(fmt.Sprintf("Re-classified %d → Proxy Hosts · %d → Redirections · %d kept as Advanced",
		nProxy, nRedir, nKept))
	http.Redirect(w, r, "/raw-routes?flash="+flash, http.StatusSeeOther)
}

// newCaddyClient builds a fresh caddy.Client from any server's AdminURL plus
// optional HTTP Basic Auth credentials. Credentials are forwarded on every
// admin call so setups that gate port 2019 behind a reverse-proxy + basic auth
// (a simpler alternative to WireGuard/Tailscale for remote admin) keep working.
func newCaddyClient(adminURL, username, password string) *caddy.Client {
	return caddy.New(adminURL, username, password)
}

// SyncCaddy is the public entry-point used by external callers (e.g. /caddy/reload).
// It syncs the currently-selected server; serverID 1 is the safe default.
func (s *Server) SyncCaddy() error { return s.syncCaddy(1, false) }

// runAutoSyncLoop fires once per hour, checks the auto_sync_hours setting, and
// re-syncs all servers when the configured interval has elapsed since the last
// sync_applied activity log entry. Setting value 0 or empty = disabled.
func (s *Server) runAutoSyncLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		v, _ := models.GetSetting(s.DB, settingAutoSyncHours)
		hours, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || hours <= 0 {
			continue // disabled
		}
		// Check when any server was last synced.
		var lastSync time.Time
		_ = s.DB.QueryRow(
			`SELECT created_at FROM activity_log WHERE action = 'sync_applied' ORDER BY id DESC LIMIT 1`,
		).Scan(&lastSync)
		if time.Since(lastSync) < time.Duration(hours)*time.Hour {
			continue // synced recently enough
		}
		// Re-sync all registered servers.
		servers, err := models.ListCaddyServers(s.DB)
		if err != nil {
			log.Printf("auto-sync: list servers: %v", err)
			continue
		}
		for _, srv := range servers {
			if err := s.syncCaddy(srv.ID, false); err != nil {
				log.Printf("auto-sync: server %d (%s): %v", srv.ID, srv.Name, err)
			} else {
				log.Printf("auto-sync: synced server %d (%s)", srv.ID, srv.Name)
			}
		}
	}
}

// isMaintWindowDay reports whether t's day-of-week is in the comma-separated
// abbreviated day list (e.g. "mon,wed,fri"). An empty days string means every day.
func isMaintWindowDay(days string, t time.Time) bool {
	if days == "" {
		return true
	}
	abbr := strings.ToLower(t.Weekday().String()[:3])
	for _, d := range strings.Split(strings.ToLower(days), ",") {
		if strings.TrimSpace(d) == abbr {
			return true
		}
	}
	return false
}

// runMaintenanceWindowLoop wakes at every minute boundary and triggers a Caddy
// sync for any server whose proxy hosts have a scheduled maintenance window
// starting or ending at that exact minute. This keeps the scheduled state in
// sync without requiring continuous full re-syncs.
func (s *Server) runMaintenanceWindowLoop() {
	for {
		now := time.Now()
		// Sleep until 2 seconds past the next minute boundary to avoid edge-case
		// early fires when the goroutine starts right on the minute.
		nextFire := now.Truncate(time.Minute).Add(time.Minute + 2*time.Second)
		time.Sleep(time.Until(nextFire))

		now = time.Now()
		hhmm := now.Format("15:04")

		hosts, err := models.ListProxyHostsWithMaintenanceWindow(s.DB)
		if err != nil {
			log.Printf("maintenance-window loop: list hosts: %v", err)
			continue
		}

		serverSet := map[int64]bool{}
		for _, h := range hosts {
			if (h.MaintenanceWindowStart == hhmm || h.MaintenanceWindowEnd == hhmm) &&
				isMaintWindowDay(h.MaintenanceWindowDays, now) {
				serverSet[h.ServerID] = true
			}
		}
		for srvID := range serverSet {
			if err := s.syncCaddy(srvID, false); err != nil {
				log.Printf("maintenance-window sync: server %d: %v", srvID, err)
			} else {
				log.Printf("maintenance-window sync: server %d at window boundary %s", srvID, hhmm)
			}
		}
	}
}

// runActivityLogCleanup wakes once every 24 hours and purges activity_log rows
// older than the configured retention window (settingActivityLogDays). Disabled
// when the setting is 0 or empty.
func (s *Server) runActivityLogCleanup() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	// Run once on startup, then every 24 h.
	s.pruneActivityLog()
	for range ticker.C {
		s.pruneActivityLog()
	}
}

func (s *Server) pruneActivityLog() {
	v, _ := models.GetSetting(s.DB, settingActivityLogDays)
	days, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || days <= 0 {
		return // disabled
	}
	res, err := s.DB.Exec(
		`DELETE FROM activity_log WHERE created_at < datetime('now', ?)`,
		fmt.Sprintf("-%d days", days),
	)
	if err != nil {
		log.Printf("activity log cleanup: %v", err)
		return
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		log.Printf("activity log cleanup: deleted %d entries older than %d days", n, days)
	}
}

// syncCaddy applies CaddyUI's managed state to Caddy:
//
//  1. Reads the current live config and builds a "proposed" config with our routes,
//     tls.certificates, and automatic_https.skip_certificates merged in.
//  2. Validates the proposed config via /load?validate_only=true. Nothing is applied
//     if validation fails — Caddy's diagnostic is surfaced to the caller.
//  3. Snapshots the pre-change live config into config_snapshots (source='auto').
//  4. Writes the three subtrees (routes, tls, automatic_https) via POST /config/....
//     POST is Caddy's set-or-replace semantic; it leaves admin, acme, email,
//     and automation policies untouched.
//  5. Logs a row into activity_log with the outcome.
// syncCaddy pushes the current DB state to Caddy. If forceTLS is true, the tls
// and automatic_https subtrees are written unconditionally — used when a cert
// assignment changed, since the skip-when-unchanged optimization would otherwise
// mask the change from Caddy. Otherwise we skip tls/auto_https writes when
// effectively unchanged (avoids cancelling in-flight ACME challenges).
func (s *Server) syncCaddy(serverID int64, forceTLS bool) error {
	// Load the target server so we can use its AdminURL for the Caddy client.
	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err != nil {
		return fmt.Errorf("syncCaddy: unknown server %d: %w", serverID, err)
	}
	// External servers are read-only — skip push.
	if srv.Type == models.CaddyServerTypeExternal {
		log.Printf("caddy sync skipped: server %d (%s) is external", serverID, srv.Name)
		return nil
	}

	// Build a per-server caddy client and swap it in for the duration of this call.
	// syncCaddy is called from HTTP handlers (single goroutine per request) so this
	// temporary swap is safe as long as we don't sync the same server concurrently.
	origClient := s.Caddy
	s.Caddy = newCaddyClient(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	defer func() { s.Caddy = origClient }()

	// Use admin view for sync — all routes must be pushed to Caddy regardless of owner.
	proxies, err := models.ListProxyHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return err
	}
	redirs, err := models.ListRedirectionHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return err
	}
	raws, err := models.ListRawRoutes(s.DB, serverID, 0, true, nil)
	if err != nil {
		return err
	}
	certs, err := models.ListCertificates(s.DB, serverID)
	if err != nil {
		return err
	}
	if len(proxies) == 0 && len(redirs) == 0 && len(raws) == 0 && len(certs) == 0 {
		log.Printf("caddy sync skipped: no entries in DB for server %d (refusing to push empty routes)", serverID)
		return nil
	}

	// v2.12.14: prepend the global strip-response-headers list to each
	// proxy host's per-host list so the eventual BuildProxyRoute emits a
	// header-delete handler covering both. Mutating in-place is safe — the
	// proxies slice is a fresh ListProxyHosts call, not a long-lived cache.
	// v2.12.16: also populate GlobalStripHeaders so the SecurityHeaders
	// bundle can filter against it (otherwise the bundle's `set` would
	// fight the strip handler and X-Frame-Options would persist).
	if globalStrip, _ := models.GetSetting(s.DB, settingGlobalStripResponseHeaders); strings.TrimSpace(globalStrip) != "" {
		var stripList []string
		for _, h := range strings.Split(globalStrip, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				stripList = append(stripList, h)
			}
		}
		for i := range proxies {
			if strings.TrimSpace(proxies[i].StripResponseHeaders) == "" {
				proxies[i].StripResponseHeaders = globalStrip
			} else {
				proxies[i].StripResponseHeaders = globalStrip + "," + proxies[i].StripResponseHeaders
			}
			proxies[i].GlobalStripHeaders = stripList
		}
	}

	routes := s.buildMergedRoutes(proxies, redirs, raws)
	loadPEM, loadFiles := buildCertLoaders(certs)
	skipList := buildSkipCertificates(proxies, redirs, raws)
	// SSLForced=false + SSLEnabled=true → add to skip_redirects so Caddy
	// doesn't force HTTP→HTTPS for hosts that explicitly allow plain HTTP.
	skipRedirects := buildSkipRedirects(proxies, redirs)
	skipAccessLogs := buildSkipAccessLogs(proxies)
	// v2.9.0: per-SNI TLS minimum-version connection policies. nil when no
	// host has a min version configured — writeTLSConnectionPoliciesSubtree
	// handles the nil case by clearing stale policies that may exist.
	tlsConnPolicies := caddy.BuildTLSConnectionPolicies(proxies)

	current, currentJSON, err := s.Caddy.FetchConfig()
	if err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_fetch_failed", "", err.Error(), false)
		return fmt.Errorf("fetch current config: %w", err)
	}

	proposed, err := deepCopyMap(current)
	if err != nil {
		return fmt.Errorf("clone config: %w", err)
	}
	applyRoutes(proposed, routes)
	applyListen(proposed)
	applyCertLoaders(proposed, loadPEM, loadFiles)
	applySkipCertificates(proposed, skipList)
	applySkipRedirects(proposed, skipRedirects)
	applySkipAccessLogs(proposed, skipAccessLogs)
	applyTLSConnectionPolicies(proposed, tlsConnPolicies)
	applyTrustedProxies(proposed, s.DB, serverID)
	// v2.4.12: branded 404/502/503/504 pages with error ID + timestamp so
	// users hitting a restart window see something nicer than Caddy's
	// plaintext fallback and ops can correlate to access logs via {err.id}.
	applyErrorPages(proposed)

	// Validate before touching anything. Caddy runs full provisioning.
	if err := s.Caddy.Validate(proposed); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_validation_failed", "", err.Error(), false)
		return fmt.Errorf("caddy rejected proposed config: %w", err)
	}

	// Snapshot current state so we can roll back if anything goes wrong later.
	if s.autoSnapshotsEnabled() && currentJSON != "" && currentJSON != "null" {
		note := fmt.Sprintf("auto: before sync — %d proxies, %d redirects, %d passthrough, %d certs",
			len(proxies), len(redirs), len(raws), len(certs))
		if _, err := models.CreateSnapshot(s.DB, serverID, models.SnapshotSourceAuto, note, currentJSON); err != nil {
			log.Printf("snapshot failed (non-fatal): %v", err)
		}
		_ = models.PruneAutoSnapshots(s.DB, serverID, 20)
	}

	// Apply. Each subtree write is atomic in Caddy.
	if err := s.writeRoutesSubtree(routes); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_routes_failed", "", err.Error(), false)
		return err
	}
	if err := s.writeListenSubtree(); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_listen_failed", "", err.Error(), false)
		return err
	}
	if err := s.writeTLSSubtree(loadPEM, loadFiles, forceTLS); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_tls_failed", "", err.Error(), false)
		return err
	}
	if err := s.writeAutomaticHTTPSSubtree(skipList, skipRedirects, forceTLS); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_autohttps_failed", "", err.Error(), false)
		return err
	}
	if err := s.writeTLSConnectionPoliciesSubtree(tlsConnPolicies); err != nil {
		// Non-fatal: log but don't abort — routes and certs are already applied.
		// TLS version policy is a best-effort security enhancement; a sync
		// failure here shouldn't roll back the primary route push.
		log.Printf("caddy sync: tls_connection_policies write failed (non-fatal): %v", err)
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_tls_policies_failed", "", err.Error(), false)
	}
	if err := s.writeAccessLogsSubtree(skipAccessLogs); err != nil {
		// Non-fatal: access log skip is a UX feature; a failure here
		// shouldn't roll back the primary sync.
		log.Printf("caddy sync: access_logs write failed (non-fatal): %v", err)
	}

	// v2.12.0: auto-detect wildcard SAN hosts and push DNS-01 ACME automation
	// policies for them. Reuses each host's configured Managed-DNS provider
	// credentials. Non-fatal — Caddy will reject the policy if the right
	// caddy-dns plugin isn't compiled in, but routes + apex certs are
	// already applied above so the failure shouldn't cascade.
	if wildcardPolicies := s.buildWildcardAutomationPolicies(proxies, raws); len(wildcardPolicies) > 0 {
		if err := pushAutomationPoliciesVia(s.Caddy, wildcardPolicies); err != nil {
			log.Printf("caddy sync: wildcard automation-policy push failed (non-fatal): %v", err)
			_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_automation_failed", "", err.Error(), false)
		} else {
			log.Printf("caddy sync: pushed %d wildcard DNS-01 automation polic(ies)", len(wildcardPolicies))
		}
	}

	detail := fmt.Sprintf("proxies=%d redirects=%d passthrough=%d certs=%d",
		len(proxies), len(redirs), len(raws), len(certs))
	_ = models.LogActivity(s.DB, serverID, "system", "sync_applied", "", detail, true)
	log.Printf("caddy synced server %d (%s): %s", serverID, srv.Name, detail)
	return nil
}

// validateProxyAdvanced runs AdvancedConfig through Caddy's /adapt at save time
// so the user gets a form error instead of a silent sync failure later. Returns
// "" when empty or valid; otherwise a user-facing message.
// validateSSLFlags rejects the impossible state `ssl_forced=true` +
// `ssl_enabled=false` when there's no custom certificate attached. A custom
// cert (certID > 0) binds TLS for the host explicitly, so Force SSL is fine
// even with the "Auto SSL" checkbox unchecked.
func validateSSLFlags(enabled, forced bool, certID int64) string {
	if forced && !enabled && certID == 0 {
		return "Force SSL is on but SSL Enabled is off and no custom certificate is attached — pick a certificate, enable SSL, or turn off Force SSL."
	}
	return ""
}

func (s *Server) renderRedirectionHostFormError(w http.ResponseWriter, r *http.Request, rh *models.RedirectionHost, errMsg string) {
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "redirection_host_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         rh,
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Error":        errMsg,
		"Section":      "redirect",
	}))
}

func (s *Server) validateProxyAdvanced(p *models.ProxyHost) string {
	if strings.TrimSpace(p.AdvancedConfig) == "" {
		return ""
	}
	// Directives that terminate a route — reverse_proxy ships the request, redir
	// writes a 3xx, respond writes a fixed body, file_server serves from disk.
	// The proxy host route ALWAYS ends with its own reverse_proxy, so allowing
	// any of these as top-level directives here would splice a second terminal
	// handler before it, silently breaking routing. Reject at save time rather
	// than waiting for the sync to succeed with a broken result.
	banned := []string{"reverse_proxy", "redir", "respond", "file_server"}
	if bad := scanTopLevelDirective(p.AdvancedConfig, banned); bad != "" {
		return fmt.Sprintf("Advanced config can't contain `%s` — this field runs BEFORE the proxy's own reverse_proxy handler. Put request-side directives here (header, encode, request_body, rewrite, etc.) and let the Forward host/port handle the upstream.", bad)
	}
	if _, err := s.adaptProxyAdvanced(*p); err != nil {
		return "Advanced config rejected by Caddy: " + err.Error()
	}
	return ""
}

// scanTopLevelDirective returns the first top-level (brace-depth 0) directive
// in src whose name matches any entry in banned, or "" if none. Used to reject
// terminal handlers in per-host AdvancedConfig before they reach Caddy's
// adapter, which would happily accept them and produce a broken config.
func scanTopLevelDirective(src string, banned []string) string {
	depth := 0
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if i := strings.Index(trimmed, "#"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}
		if trimmed == "" {
			continue
		}
		if depth == 0 {
			first := strings.Fields(trimmed)[0]
			for _, b := range banned {
				if first == b {
					return b
				}
			}
		}
		for _, ch := range trimmed {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
	}
	return ""
}

func (s *Server) renderProxyHostFormError(w http.ResponseWriter, r *http.Request, p *models.ProxyHost, errMsg string) {
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "proxy_host_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         p,
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Error":        errMsg,
		"Section":      "proxy",
	}))
}

// adaptProxyAdvanced converts a proxy host's per-host AdvancedConfig (a Caddyfile
// snippet containing request/response directives like `header`, `encode`,
// `request_body`) into the Caddy JSON handlers those directives expand to. The
// handlers are intended to run BEFORE the reverse_proxy handler, so directives
// like `request_body` or header-stripping take effect on the proxied request.
//
// We wrap the snippet in a synthetic site block `(localhost) { ... }` so Caddy's
// adapter has a valid site-address context. The adapter normally enforces
// directive order inside the site block, so we get a handle[] list in the
// correct order — we return that list untouched for the caller to splice in.
func (s *Server) adaptProxyAdvanced(p models.ProxyHost) ([]any, error) {
	src := fmt.Sprintf("localhost {\n%s\n}\n", p.AdvancedConfig)
	adapted, err := s.Caddy.Adapt(src)
	if err != nil {
		return nil, err
	}
	routes := extractAdaptedRoutes(adapted.Result)
	if len(routes) == 0 {
		return nil, nil
	}
	handle, _ := routes[0]["handle"].([]any)
	return handle, nil
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
		if strings.TrimSpace(p.AdvancedConfig) != "" {
			h, err := s.adaptProxyAdvanced(p)
			if err != nil {
				// Don't fail the whole sync — log and push the route without advanced
				// handlers. The form-level validation should have caught bad syntax
				// before save, so this branch is for rare drift cases.
				log.Printf("caddy sync: proxy id=%d advanced_config adapt failed: %v", p.ID, err)
			} else {
				advanced = h
			}
		}
		routes = append(routes, caddy.BuildProxyRoute(p, append(preHandlers, advanced...)))
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
		var decoded any
		if err := json.Unmarshal([]byte(rr.JSONData), &decoded); err != nil {
			log.Printf("caddy sync: skipping invalid raw_route id=%d label=%q: %v", rr.ID, rr.Label, err)
			continue
		}
		wrap := func(route map[string]any) map[string]any {
			if rr.BlockCommonExploits {
				handle, _ := route["handle"].([]any)
				route["handle"] = append([]any{caddy.ExploitBlockerSubroute()}, handle...)
			}
			return route
		}
		// A raw_route may contain either a single route object or an array of routes;
		// spread arrays so we never emit a nested array (which Caddy rejects).
		switch v := decoded.(type) {
		case []any:
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					routes = append(routes, wrap(m))
				} else {
					routes = append(routes, item)
				}
			}
		case map[string]any:
			routes = append(routes, wrap(v))
		default:
			log.Printf("caddy sync: skipping raw_route id=%d label=%q: unexpected JSON shape %T", rr.ID, rr.Label, decoded)
		}
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

func buildSkipCertificates(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute) []any {
	set := map[string]struct{}{}
	for _, p := range proxies {
		if p.CertificateID == 0 {
			continue
		}
		for _, d := range p.DomainList() {
			set[d] = struct{}{}
		}
	}
	for _, rd := range redirs {
		if rd.CertificateID == 0 {
			continue
		}
		for _, d := range rd.DomainList() {
			set[d] = struct{}{}
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
				set[h] = struct{}{}
			}
		}
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

// buildSkipRedirects collects domains from hosts where SSL is enabled but
// Force SSL is OFF. Those domains get added to automatic_https.skip_redirects
// in Caddy, meaning HTTP traffic is not automatically redirected to HTTPS.
// Hosts with SSL fully disabled don't need an entry here — they're already
// in skip_certificates which also suppresses redirects.
func buildSkipRedirects(proxies []models.ProxyHost, redirs []models.RedirectionHost) []any {
	set := map[string]struct{}{}
	for _, p := range proxies {
		if !p.SSLEnabled || p.SSLForced {
			continue // SSL off or force-redirect on — default Caddy behavior
		}
		for _, d := range p.DomainList() {
			set[d] = struct{}{}
		}
	}
	for _, rd := range redirs {
		if !rd.SSLEnabled || rd.SSLForced {
			continue
		}
		for _, d := range rd.DomainList() {
			set[d] = struct{}{}
		}
	}
	out := make([]any, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	return out
}

func applySkipRedirects(cfg map[string]any, skipList []any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	auto := ensureMap(srv, "automatic_https")
	if len(skipList) > 0 {
		auto["skip_redirects"] = skipList
	} else {
		delete(auto, "skip_redirects")
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

func (s *Server) writeAutomaticHTTPSSubtree(skipCerts []any, skipRedirects []any, force bool) error {
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
	existingSkipRedir, _ := autoMap["skip_redirects"].([]any)
	// Skip the write when the effective lists are unchanged. Writing otherwise
	// reprovisions the server module and can interrupt in-flight ACME work.
	if !force && stringListsEqual(existingSkipCerts, skipCerts) && stringListsEqual(existingSkipRedir, skipRedirects) {
		return nil
	}
	if len(skipCerts) > 0 {
		autoMap["skip_certificates"] = skipCerts
	} else {
		delete(autoMap, "skip_certificates")
	}
	if len(skipRedirects) > 0 {
		autoMap["skip_redirects"] = skipRedirects
	} else {
		delete(autoMap, "skip_redirects")
	}
	if !existed && len(autoMap) == 0 {
		return nil
	}
	return s.Caddy.PutPath("/config/apps/http/servers/srv0/automatic_https", autoMap)
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

// --- Feature B: Upstream health checks ---

type upstreamHealthResult struct {
	ID        int64  `json:"id"`
	Domains   string `json:"domains"`
	// Status is the port-level (TCP) health: "ok", "error", "unknown", or
	// "disabled". Sourced from Caddy's /reverse_proxy/upstreams (authoritative
	// since Caddy is on the upstream's Docker network); falls back to a
	// direct dial for public/dotted hostnames not yet in Caddy's upstream map.
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`

	// AppStatus is the end-to-end HTTP-response health: "ok", "degraded",
	// "down", "unknown", or "disabled". Sourced from the app-health poller,
	// which does an HTTPS GET against the public domain every 60s. This is
	// what catches "port open but app wedged" (e.g. DB connection stuck) —
	// something Status (TCP) alone can't see.
	AppStatus    string `json:"app_status,omitempty"`
	AppCode      int    `json:"app_code,omitempty"`
	AppLatencyMS int64  `json:"app_latency_ms,omitempty"`
	AppError     string `json:"app_error,omitempty"`
}

// postMyColorTheme — v2.12.27: persist the signed-in user's preferred
// color theme to the DB so it follows the account across devices. The
// picker in Settings POSTs here on change. Body is form-encoded with a
// single `theme` field. Empty string and "default" both clear the
// preference (use the default palette); "orange" picks the carbon-orange
// palette. Anything else returns 400 so we don't store junk that the
// CSS layer wouldn't recognise.
func (s *Server) postMyColorTheme(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	theme := strings.TrimSpace(r.FormValue("theme"))
	// Normalise "default" to empty string in storage so the column reads
	// as "no opinion" by default and we don't carry a magic value around.
	if theme == "default" {
		theme = ""
	}
	switch theme {
	case "", "orange":
		// allowed
	default:
		http.Error(w, "unknown theme", http.StatusBadRequest)
		return
	}
	if err := models.UpdateUserColorTheme(s.DB, u.ID, theme); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiAIStatus — v2.11.15: reports whether AI assist is enabled and which
// model is configured. Frontend uses this to decide whether to render the
// floating AI button at page load.
func (s *Server) apiAIStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled, _ := models.GetSetting(s.DB, settingAIEnabled)
	model, _ := models.GetSetting(s.DB, settingAIOllamaModel)
	if model == "" {
		model = "llama3.2:latest"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled": enabled == "1",
		"model":   model,
	})
}

// apiAIChat — v2.11.15: proxies a user prompt to the configured Ollama
// /api/chat endpoint. Single-shot — no server-side conversation history.
// Streaming is disabled (stream=false) so we can return the full message
// in one JSON response.
//
// The system prompt frames Ollama as a CaddyUI assistant, so generic
// model knowledge gets steered toward Caddy / reverse-proxy / DNS / TLS
// answers without needing a fine-tuned model.
func (s *Server) apiAIChat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled, _ := models.GetSetting(s.DB, settingAIEnabled)
	if enabled != "1" {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "AI assist is disabled — turn it on under Settings."})
		return
	}
	baseURL, _ := models.GetSetting(s.DB, settingAIOllamaURL)
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "http://ollama:11434"
	}
	model, _ := models.GetSetting(s.DB, settingAIOllamaModel)
	if strings.TrimSpace(model) == "" {
		model = "llama3.2:latest"
	}

	// v2.12.10: accept multi-turn message arrays for conversation memory
	// while keeping back-compat with the single {message:""} shape.
	var body struct {
		Message  string              `json:"message"`
		Messages []map[string]string `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "could not parse JSON body"})
		return
	}
	turns := body.Messages
	if len(turns) == 0 && strings.TrimSpace(body.Message) != "" {
		turns = []map[string]string{{"role": "user", "content": body.Message}}
	}
	if len(turns) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "send {messages:[{role,content},...]} or {message:'...'}"})
		return
	}
	// Cap conversation length so a long-running tab doesn't blow past the
	// model's context window. ~20 messages = 5–10 conversational rounds.
	if len(turns) > 20 {
		turns = turns[len(turns)-20:]
	}

	// v2.12.5: beefed-up system prompt. Small models (e.g. llama3.2:3b) were
	// hallucinating Caddy v1 trivia and inventing directives. Concrete
	// Caddyfile examples plus an explicit "say I don't know" rule helps.
	// v2.12.10: relaxed the "be concise" constraint and added an explicit
	// rule about respecting prior conversation turns. Custom system prompt
	// (settingAISystemPrompt) overrides this default when the user sets one
	// in Settings.
	defaultSystemPrompt := `You are an assistant inside CaddyUI, a web app for managing the Caddy reverse proxy. Caddy v2 ONLY — never reference Caddy v1.

When the user asks for a Caddy config, output a valid Caddy v2 Caddyfile site block. Use this exact shape:

  hostname.example.com {
    reverse_proxy backend:8080
  }

Common patterns:

  # AdGuardHome (admin UI is HTTP on :3000):
  dns.example.com {
    reverse_proxy adguardhome:3000
  }

  # Nextcloud:
  cloud.example.com {
    reverse_proxy nextcloud:80
  }

  # 301/302 redirect:
  old.example.com {
    redir https://new.example.com{uri} 301
  }

  # Wildcard cert via DNS-01 (needs the caddy-dns/cloudflare plugin):
  *.example.com, example.com {
    tls {
      dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy backend:8080
  }

Rules:
- Site blocks ALWAYS start with hostnames followed by a space and an opening brace.
- NEVER invent directives. If you don't know the exact Caddy v2 directive name, say "I'm not certain — check https://caddyserver.com/docs" instead of guessing.
- Output valid Caddyfile syntax — directives like ` + "`" + `reverse_proxy` + "`" + `, ` + "`" + `redir` + "`" + `, ` + "`" + `tls` + "`" + `, ` + "`" + `header` + "`" + `, ` + "`" + `handle` + "`" + `, ` + "`" + `handle_path` + "`" + `, ` + "`" + `respond` + "`" + `, ` + "`" + `file_server` + "`" + `, ` + "`" + `encode gzip` + "`" + `. Don't make up new ones.
- Treat earlier messages in the conversation as binding context — when the user says "make one here" or "add to that", refer back to what was discussed instead of inventing an unrelated example.
- Be as detailed as the question warrants: short answers for simple questions; a full Caddyfile + a few sentences of explanation for setup walk-throughs. Skip filler preambles.
- The user is editing a config in CaddyUI alongside this chat. When relevant, point them at form fields: Domain names, Forward Host/Port, Auto SSL toggle, Managed DNS picker, Upstream Host Header, etc.

If you are NOT sure about a specific Caddy directive or behavior, say so. Hallucinated config is worse than "I don't know."

TOOLS:
You can call tools that ACTUALLY CREATE resources in CaddyUI. The user sees a confirmation card with the parameters and clicks Apply before anything happens — you don't have to ask permission, just call the tool when appropriate.

When to call ` + "`" + `create_proxy_host` + "`" + ` or ` + "`" + `create_redirection` + "`" + `:
- "create a proxy host for X" / "set up X" / "add X" / "make a proxy for X" → create_proxy_host
- "redirect old.com to new.com" / "set up a 301 from X" → create_redirection
- "what's the Caddyfile for X" / "explain X" / "show me how X looks" → just write a Caddyfile snippet, DO NOT call a tool

When you call a tool, do not also write a Caddyfile in the same response — the tool call is the response.`

	systemPrompt := defaultSystemPrompt
	if customPrompt, _ := models.GetSetting(s.DB, settingAISystemPrompt); strings.TrimSpace(customPrompt) != "" {
		systemPrompt = customPrompt
	}

	finalMessages := make([]map[string]string, 0, len(turns)+1)
	finalMessages = append(finalMessages, map[string]string{"role": "system", "content": systemPrompt})
	finalMessages = append(finalMessages, turns...)

	// v2.12.11: tool definitions sent on every chat turn. Models that
	// don't support tools (older / smaller ones) ignore the field; for
	// qwen2.5/llama3.1+/gemma2 the model can decide to emit tool_calls
	// in its response, which the frontend renders as a confirmation card.
	tools := aiToolDefinitions()

	payload := map[string]any{
		"model":    model,
		"stream":   false,
		"messages": finalMessages,
		"tools":    tools,
	}
	pb, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/chat", bytes.NewReader(pb))
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "build request: " + err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "ollama: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("ollama %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))})
		return
	}
	var out struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "decode ollama response: " + err.Error()})
		return
	}
	// v2.12.11: surface tool_calls separately so the frontend can render a
	// confirmation card. Reply text is whatever the model wrote alongside
	// (often empty on tool turns; some models still narrate).
	type frontendTC struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
	}
	calls := make([]frontendTC, 0, len(out.Message.ToolCalls))
	for _, tc := range out.Message.ToolCalls {
		calls = append(calls, frontendTC{Name: tc.Function.Name, Args: tc.Function.Arguments})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"reply":      strings.TrimSpace(out.Message.Content),
		"tool_calls": calls,
		"model":      model,
	})
}

// aiToolDefinitions — v2.12.11: schema for every AI-callable tool. Sent on
// every chat turn so the model knows what's available; models without tool
// support silently ignore the field.
func aiToolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"type": "function",
			"function": map[string]any{
				"name":        "create_proxy_host",
				"description": "Create a new proxy host in CaddyUI. Use this when the user asks to actually create / set up / add a proxy host (not just explain or show a config snippet). The user will see a confirmation card with the arguments before this runs.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"domains":        map[string]any{"type": "string", "description": "Comma-separated list of domain names. Wildcards allowed (e.g. '*.example.com,example.com')."},
						"forward_scheme": map[string]any{"type": "string", "enum": []string{"http", "https"}, "description": "Scheme used when proxying to the upstream. Default 'http'."},
						"forward_host":   map[string]any{"type": "string", "description": "Upstream hostname or IP (docker service name like 'adguardhome', or an IP)."},
						"forward_port":   map[string]any{"type": "integer", "description": "Upstream TCP port, 1–65535."},
						"ssl_enabled":    map[string]any{"type": "boolean", "description": "Enable Caddy automatic HTTPS via Let's Encrypt. Default true."},
						"ssl_forced":     map[string]any{"type": "boolean", "description": "Redirect plain HTTP requests to HTTPS. Default true."},
					},
					"required": []string{"domains", "forward_host", "forward_port"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "create_redirection",
				"description": "Create a new redirection (HTTP 301/302/307/308) in CaddyUI. Use this when the user asks to redirect one hostname to another.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"domains":           map[string]any{"type": "string", "description": "Comma-separated source domains (the old hostnames being redirected away)."},
						"forward_scheme":    map[string]any{"type": "string", "enum": []string{"auto", "http", "https"}, "description": "Scheme for the redirect target. 'auto' (default) preserves the request scheme."},
						"forward_domain":    map[string]any{"type": "string", "description": "Target hostname (where the user gets redirected to)."},
						"forward_http_code": map[string]any{"type": "integer", "enum": []int{301, 302, 307, 308}, "description": "Redirect status code. 301 = permanent (default), 302 = temporary, 307/308 preserve method."},
						"preserve_path":     map[string]any{"type": "boolean", "description": "Keep the path+query from the request when redirecting. Default true."},
					},
					"required": []string{"domains", "forward_domain"},
				},
			},
		},
	}
}

// apiAIExecTool — v2.12.11: executes a tool call the AI proposed. Called
// from the frontend after the user confirms via the chat-bubble card. All
// resources are created with admin / global ownership (or current user's
// ownership for non-admins). Every successful exec writes an
// `ai_tool_call` activity-log row so admins can audit what the AI did.
func (s *Server) apiAIExecTool(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled, _ := models.GetSetting(s.DB, settingAIEnabled)
	if enabled != "1" {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "AI assist is disabled."})
		return
	}
	cu := s.currentUser(r)
	if cu == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	var body struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "could not parse JSON body"})
		return
	}
	sid := s.currentServerID(r)
	var ownerID int64
	if cu.Role != models.RoleAdmin {
		ownerID = cu.ID
	}

	switch body.Name {
	case "create_proxy_host":
		ph := &models.ProxyHost{
			Domains:       toolStr(body.Args, "domains"),
			ForwardScheme: toolStrDefault(body.Args, "forward_scheme", "http"),
			ForwardHost:   toolStr(body.Args, "forward_host"),
			ForwardPort:   toolInt(body.Args, "forward_port"),
			SSLEnabled:    toolBoolDefault(body.Args, "ssl_enabled", true),
			SSLForced:     toolBoolDefault(body.Args, "ssl_forced", true),
			Enabled:       true,
		}
		if ph.Domains == "" || ph.ForwardHost == "" || ph.ForwardPort == 0 {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing required argument (domains, forward_host, forward_port)"})
			return
		}
		// Domain conflict guard — same as the form path.
		if conflict, err := models.DomainsConflict(s.DB, sid, ph.DomainList(), 0, 0); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "validate domains: " + err.Error()})
			return
		} else if conflict != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("domain %q is already used by another proxy or redirect on this server", conflict)})
			return
		}
		id, err := models.CreateProxyHost(s.DB, sid, ownerID, ph)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "create proxy host: " + err.Error()})
			return
		}
		_ = models.LogActivity(s.DB, sid, cu.Email, "ai_tool_call", fmt.Sprintf("proxy:%d", id), "create_proxy_host: "+ph.Domains, true)
		s.syncCaddy(sid, ph.CertificateID != 0)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"summary": fmt.Sprintf("✓ Created proxy host #%d — %s → %s:%d", id, ph.Domains, ph.ForwardHost, ph.ForwardPort),
			"url":     fmt.Sprintf("/proxy-hosts/%d/edit", id),
		})

	case "create_redirection":
		code := toolIntDefault(body.Args, "forward_http_code", 301)
		if code != 301 && code != 302 && code != 307 && code != 308 {
			code = 301
		}
		rh := &models.RedirectionHost{
			Domains:         toolStr(body.Args, "domains"),
			ForwardScheme:   toolStrDefault(body.Args, "forward_scheme", "auto"),
			ForwardDomain:   toolStr(body.Args, "forward_domain"),
			ForwardHTTPCode: code,
			PreservePath:    toolBoolDefault(body.Args, "preserve_path", true),
			SSLEnabled:      true,
			SSLForced:       true,
			Enabled:         true,
		}
		if rh.Domains == "" || rh.ForwardDomain == "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing required argument (domains, forward_domain)"})
			return
		}
		if conflict, err := models.DomainsConflict(s.DB, sid, rh.DomainList(), 0, 0); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "validate domains: " + err.Error()})
			return
		} else if conflict != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("domain %q is already used by another proxy or redirect on this server", conflict)})
			return
		}
		id, err := models.CreateRedirectionHost(s.DB, sid, ownerID, rh)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "create redirection: " + err.Error()})
			return
		}
		_ = models.LogActivity(s.DB, sid, cu.Email, "ai_tool_call", fmt.Sprintf("redirect:%d", id), "create_redirection: "+rh.Domains+" → "+rh.ForwardDomain, true)
		s.syncCaddy(sid, false)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"summary": fmt.Sprintf("✓ Created redirection #%d — %s → %s (%d)", id, rh.Domains, rh.ForwardDomain, code),
			"url":     fmt.Sprintf("/redirection-hosts/%d/edit", id),
		})

	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unknown tool: " + body.Name})
	}
}

// toolStr / toolInt / toolBool — v2.12.11: tiny helpers that pull strongly-
// typed values out of the model-supplied tool argument map. Models can be
// loose with types (numbers as strings, booleans as strings, etc.), so
// these tolerate the common drift cases.
func toolStr(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	if v, ok := args[key]; ok {
		switch s := v.(type) {
		case string:
			return strings.TrimSpace(s)
		case float64:
			return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", s), "0"), ".")
		case bool:
			if s {
				return "true"
			}
			return "false"
		}
	}
	return ""
}
func toolStrDefault(args map[string]any, key, def string) string {
	if v := toolStr(args, key); v != "" {
		return v
	}
	return def
}
func toolInt(args map[string]any, key string) int {
	if args == nil {
		return 0
	}
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case string:
			i, _ := strconv.Atoi(strings.TrimSpace(n))
			return i
		}
	}
	return 0
}
func toolIntDefault(args map[string]any, key string, def int) int {
	if v := toolInt(args, key); v != 0 {
		return v
	}
	return def
}
func toolBoolDefault(args map[string]any, key string, def bool) bool {
	if args == nil {
		return def
	}
	if v, ok := args[key]; ok {
		switch b := v.(type) {
		case bool:
			return b
		case string:
			s := strings.ToLower(strings.TrimSpace(b))
			if s == "true" || s == "1" || s == "yes" {
				return true
			}
			if s == "false" || s == "0" || s == "no" {
				return false
			}
		}
	}
	return def
}

// apiPreviewProxyHost — v2.11.13: live preview of the route JSON Caddy
// would receive for the in-progress proxy-host edit form. Reuses the
// same parseProxyHostForm + BuildProxyRoute path as createProxyHost so
// what the user sees here is exactly what gets pushed on save.
//
// v2.11.17: pads required fields with visible placeholders so a partly-
// filled form still renders a representative preview. The previous
// version leaked the raw `strconv.Atoi: parsing "": invalid syntax`
// from the strict parser into the user's face the moment they expanded
// the panel before filling in Forward port.
func (s *Server) apiPreviewProxyHost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// v2.11.18: the frontend sends FormData (multipart). r.ParseForm only
	// handles application/x-www-form-urlencoded bodies; for multipart we
	// also need ParseMultipartForm. Calling both means r.Form is populated
	// regardless of how the JS chose to encode the request.
	_ = r.ParseForm()
	_ = r.ParseMultipartForm(32 << 20)
	pad := func(key, fallback string) {
		if strings.TrimSpace(r.Form.Get(key)) == "" {
			r.Form.Set(key, fallback)
			if r.PostForm != nil {
				r.PostForm.Set(key, fallback)
			}
		}
	}
	pad("forward_port", "0")
	pad("forward_host", "(your-upstream)")
	pad("domains", "example.com")

	p, err := parseProxyHostForm(r)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	route := caddy.BuildProxyRoute(*p, nil)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"route": route})
}

// globalSearch — v2.11.5: ⌘K / Ctrl+K command palette. Returns a flat list of
// every proxy host, redirection, raw route, and certificate visible to the
// current user on the active server. The frontend caches the result and
// filters client-side; one fetch per palette open (with a 60-second
// freshness window).
func (s *Server) globalSearch(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	viewerID := cu.ID
	peers := s.groupPeerIDs(r)
	sid := s.currentServerID(r)

	type item struct {
		Type  string `json:"type"`
		ID    int64  `json:"id"`
		Label string `json:"label"`
		Sub   string `json:"sub"`
		URL   string `json:"url"`
	}
	items := make([]item, 0, 256)

	if hosts, err := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, h := range hosts {
			items = append(items, item{
				Type:  "proxy",
				ID:    h.ID,
				Label: h.Domains,
				Sub:   fmt.Sprintf("→ %s:%d", h.ForwardHost, h.ForwardPort),
				URL:   fmt.Sprintf("/proxy-hosts/%d/edit", h.ID),
			})
		}
	}
	if redirs, err := models.ListRedirectionHosts(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, h := range redirs {
			items = append(items, item{
				Type:  "redirect",
				ID:    h.ID,
				Label: h.Domains,
				Sub:   fmt.Sprintf("→ %s://%s (%d)", h.ForwardScheme, h.ForwardDomain, h.ForwardHTTPCode),
				URL:   fmt.Sprintf("/redirection-hosts/%d/edit", h.ID),
			})
		}
	}
	if raws, err := models.ListRawRoutes(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, rr := range raws {
			label := rr.Label
			if label == "" {
				label = fmt.Sprintf("Advanced route #%d", rr.ID)
			}
			items = append(items, item{
				Type:  "raw",
				ID:    rr.ID,
				Label: label,
				Sub:   "Advanced route",
				URL:   fmt.Sprintf("/raw-routes/%d/edit", rr.ID),
			})
		}
	}
	if certs, err := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, c := range certs {
			items = append(items, item{
				Type:  "cert",
				ID:    c.ID,
				Label: c.Name,
				Sub:   c.Domains,
				URL:   fmt.Sprintf("/certificates/%d/edit", c.ID),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": items})
}

func (s *Server) apiUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	sid := s.currentServerID(r)
	hosts, err := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Ask Caddy's admin API for its own upstream health data.
	// This is the authoritative source — Caddy can reach Docker-internal hosts
	// by name (e.g. "gitlab", "snipeit-app") that CaddyUI cannot resolve.
	// Falls back to direct probe only for upstreams not yet in Caddy's config.
	caddyUpstreams := map[string]caddyUpstreamInfo{}
	if srv, err := models.GetCaddyServer(s.DB, sid); err == nil {
		caddyUpstreams = fetchCaddyUpstreams(srv.AdminURL)
	}

	results := make([]upstreamHealthResult, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{Timeout: 3 * time.Second}

	for i, h := range hosts {
		results[i] = upstreamHealthResult{ID: h.ID, Domains: h.Domains}
		if !h.Enabled {
			results[i].Status = "disabled"
			continue
		}

		// Check Caddy's upstream map first (host:port key).
		key := fmt.Sprintf("%s:%d", h.ForwardHost, h.ForwardPort)
		if info, ok := caddyUpstreams[key]; ok {
			if info.Fails > 0 {
				results[i].Status = "error"
				results[i].Error = fmt.Sprintf("%d failed health check(s)", info.Fails)
			} else {
				results[i].Status = "ok"
			}
			continue
		}

		// Not in Caddy's upstream list yet (newly added / not yet synced,
		// or using an unmanaged handler the /reverse_proxy/upstreams API
		// doesn't expose). For Docker-internal backends (no dots in the
		// hostname — e.g. "status-server", "snipeit-app") a direct probe
		// from the caddyui container will fail with "no such host" since
		// caddyui usually isn't on the target's Docker network. Don't flag
		// that as error — mark it "unknown" (grey dot) so users don't see
		// a red "down" badge on a backend that's actually working. For
		// dotted hostnames (e.g. "api.example.com") we still try the probe.
		if isInternalHostname(h.ForwardHost) {
			results[i].Status = "unknown"
			results[i].Error = "caddyui cannot resolve " + h.ForwardHost + " — check via Caddy admin"
			continue
		}
		// Fall back to a direct probe for public / dotted hostnames.
		wg.Add(1)
		go func(idx int, h models.ProxyHost) {
			defer wg.Done()
			url := fmt.Sprintf("%s://%s:%d/", h.ForwardScheme, h.ForwardHost, h.ForwardPort)
			start := time.Now()
			resp, err2 := client.Head(url)
			if err2 != nil {
				resp, err2 = client.Get(url)
			}
			latency := time.Since(start).Milliseconds()
			if resp != nil {
				_ = resp.Body.Close()
			}
			mu.Lock()
			defer mu.Unlock()
			if err2 != nil {
				// DNS errors → "unknown" not "error": caddyui's network
				// namespace may legitimately not be able to resolve the
				// name even though Caddy can.
				if isDNSError(err2) {
					results[idx].Status = "unknown"
					results[idx].Error = err2.Error()
				} else {
					results[idx].Status = "error"
					results[idx].Error = err2.Error()
				}
			} else {
				results[idx].Status = "ok"
				results[idx].LatencyMS = latency
			}
		}(i, h)
	}

	wg.Wait()

	// Layer in cached app-response health (HTTPS GET / from the app-health
	// poller). Read under the RW lock; the poller writes on its own cadence
	// so this is a cheap map lookup per host. Hosts we haven't polled yet
	// (e.g. first ~60s after boot, or just-created hosts) simply leave
	// AppStatus empty — the UI renders "checking…" in that case.
	s.appHealthMu.RLock()
	for i := range results {
		if e, ok := s.appHealth[results[i].ID]; ok {
			results[i].AppStatus = e.Status
			results[i].AppCode = e.Code
			results[i].AppLatencyMS = e.LatencyMS
			results[i].AppError = e.Error
		}
	}
	s.appHealthMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

// caddyUpstreamInfo holds health data from Caddy's /reverse_proxy/upstreams API.
type caddyUpstreamInfo struct {
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
}

// isInternalHostname returns true when the forward host looks like a Docker
// service name or short intranet hostname — i.e. no dots, not an IP literal,
// not "localhost". In that case caddyui (in its own container) almost
// certainly cannot resolve it, but Caddy on the target network can. Use this
// to downgrade health-probe results from "error" to "unknown" so the UI
// doesn't flag working backends as down.
func isInternalHostname(host string) bool {
	if host == "" || host == "localhost" {
		return false
	}
	if strings.Contains(host, ".") {
		return false
	}
	// IPv6 without brackets or with scope? Anything with a colon is unusual
	// in ForwardHost (we store port separately) — treat as external.
	if strings.Contains(host, ":") {
		return false
	}
	return true
}

// isDNSError returns true when err is a DNS resolution failure (as opposed
// to a connection refused / timeout / TLS error). DNS failure from the
// caddyui container doesn't imply the backend is down — Caddy on a
// different Docker network may resolve it fine.
func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "server misbehaving") ||
		strings.Contains(s, "Temporary failure in name resolution")
}

// fetchCaddyUpstreams queries the Caddy admin API for current upstream health.
// Returns a map keyed by "host:port" (matching ProxyHost.ForwardHost:ForwardPort).
func fetchCaddyUpstreams(adminURL string) map[string]caddyUpstreamInfo {
	out := map[string]caddyUpstreamInfo{}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(adminURL + "/reverse_proxy/upstreams")
	if err != nil || resp.StatusCode != http.StatusOK {
		return out
	}
	defer resp.Body.Close()
	var list []caddyUpstreamInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err != nil {
		return out
	}
	for _, u := range list {
		out[u.Address] = u
	}
	return out
}

// apiCaddyUpstreams proxies Caddy's /reverse_proxy/upstreams endpoint, returning
// raw upstream health data from Caddy's admin API.
// Returns JSON: {"upstreams": [...], "error": "..."}
func (s *Server) apiCaddyUpstreams(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sid := s.currentServerID(r)
	srv, err := models.GetCaddyServer(s.DB, sid)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"upstreams": nil, "error": err.Error()})
		return
	}
	cl := caddy.New(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	upstreams, err := cl.GetUpstreamHealth(ctx)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"upstreams": nil, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"upstreams": upstreams})
}

// apiTestUpstream checks whether a given upstream host:port is reachable.
// Accepts POST with form fields: host, port, scheme (http/https).
// Returns JSON: {ok: bool, status: int, latency_ms: int, error: string}.
func (s *Server) apiTestUpstream(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Accept both multipart/form-data (FormData from JS) and
	// application/x-www-form-urlencoded. r.FormValue auto-detects when
	// r.Form is still nil — calling r.ParseForm() first would short-circuit
	// the multipart path and leave the fields empty.
	host := strings.TrimSpace(r.FormValue("host"))
	port := strings.TrimSpace(r.FormValue("port"))
	scheme := strings.TrimSpace(r.FormValue("scheme"))
	if host == "" || port == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "host and port are required"})
		return
	}
	if scheme != "https" {
		scheme = "http"
	}
	targetURL := fmt.Sprintf("%s://%s:%s/", scheme, host, port)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	resp, err := client.Get(targetURL)
	latencyMs := time.Since(start).Milliseconds()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		// v2.9.212: surface actionable hints for the most common failure
		// classes so users don't have to interpret raw Go net errors.
		// DNS failures from inside the caddyui container are extremely
		// common when targeting LAN device hostnames (NetBIOS / mDNS / a
		// router's DHCP-resolved name) — the Caddy that will actually
		// proxy to it may resolve fine while caddyui's container can't.
		hint := ""
		msg := err.Error()
		switch {
		case isDNSError(err):
			hint = "DNS lookup failed inside the CaddyUI container. The hostname may resolve fine for the actual Caddy server but not from CaddyUI's DNS resolver. Try the upstream's IP address directly, add `--add-host=" + host + ":<ip>` to the CaddyUI container, or point the container at your LAN DNS with `--dns=<router-ip>`."
		case strings.Contains(msg, "x509") || strings.Contains(msg, "tls:") || strings.Contains(msg, "certificate"):
			hint = "TLS handshake failed even with cert verification disabled. The upstream may not be listening on " + port + " over TLS, or it speaks plain HTTP. Try scheme=http instead of https."
		case strings.Contains(msg, "connection refused"):
			hint = "TCP connection refused — the upstream isn't listening on " + host + ":" + port + ", or a firewall is blocking the CaddyUI container from reaching it."
		case strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded"):
			hint = "Request timed out after 5s. Upstream may be unreachable from the CaddyUI container's network, or it's too slow to respond."
		}
		out := map[string]any{
			"ok":         false,
			"latency_ms": latencyMs,
			"error":      msg,
		}
		if hint != "" {
			out["hint"] = hint
		}
		json.NewEncoder(w).Encode(out)
		return
	}
	resp.Body.Close()
	json.NewEncoder(w).Encode(map[string]any{
		"ok":         resp.StatusCode < 500,
		"status":     resp.StatusCode,
		"latency_ms": latencyMs,
		"error":      "",
	})
}

// apiValidateRawRoute checks whether a draft raw route is shaped correctly
// before it's saved. Accepts either form field:
//   - caddyfile_src: a Caddyfile block — runs through Caddy's /adapt which
//     parses + validates Caddyfile syntax without applying anything.
//   - json_data: raw JSON — done client-side (well, server-side parse)
//     because Caddy's admin API has no JSON-only validate mode in v2.7+.
//     We surface JSON parse errors and structural-shape errors (must have
//     match/handle keys), but a route that's syntactically valid JSON yet
//     semantically wrong won't be caught here — that surfaces at sync time.
//
// v2.9.228 originally posted to /load?validate_only=true thinking that
// query param was honoured. Caddy ignores it entirely, so the synthetic
// config was applied to the running instance, polluting autosave.json
// with a `_caddyui_validate` ghost server. v2.9.233 drops that path.
func (s *Server) apiValidateRawRoute(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	respond := func(ok bool, msg string) {
		out := map[string]any{"ok": ok}
		if msg != "" {
			out["error"] = msg
		}
		_ = json.NewEncoder(w).Encode(out)
	}
	cfSrc := strings.TrimSpace(r.FormValue("caddyfile_src"))
	jsonData := strings.TrimSpace(r.FormValue("json_data"))
	if cfSrc != "" {
		// Caddy's /adapt parses Caddyfile syntax and runs the adapter
		// pipeline — that catches the bulk of bugs (unknown directives,
		// missing args, malformed blocks). It does NOT apply the config
		// to Caddy's running state.
		_, err := s.adaptRawRouteCaddyfile(s.caddyForRequest(r), cfSrc)
		if err != nil {
			respond(false, "Caddyfile rejected by Caddy: "+err.Error())
			return
		}
		// If Caddyfile is fine and JSON is empty (most common case), we're
		// done. If JSON is also filled, fall through to validate it too.
		if jsonData == "" {
			respond(true, "")
			return
		}
	}
	if jsonData == "" {
		respond(false, "Provide a Caddyfile block or JSON to validate.")
		return
	}
	// JSON-only validation: parse + structural check.
	var probe any
	if err := json.Unmarshal([]byte(jsonData), &probe); err != nil {
		respond(false, "Invalid JSON: "+err.Error())
		return
	}
	checkRoute := func(m map[string]any) string {
		if _, ok := m["handle"]; !ok {
			return `route is missing "handle" array`
		}
		if h, ok := m["handle"].([]any); !ok || len(h) == 0 {
			return `"handle" must be a non-empty array`
		}
		// match is optional — a route with no matcher matches everything.
		return ""
	}
	switch v := probe.(type) {
	case map[string]any:
		if msg := checkRoute(v); msg != "" {
			respond(false, msg)
			return
		}
	case []any:
		if len(v) == 0 {
			respond(false, "Route JSON array is empty.")
			return
		}
		for i, e := range v {
			m, ok := e.(map[string]any)
			if !ok {
				respond(false, fmt.Sprintf("entry %d is not an object", i))
				return
			}
			if msg := checkRoute(m); msg != "" {
				respond(false, fmt.Sprintf("entry %d: %s", i, msg))
				return
			}
		}
	default:
		respond(false, "Route JSON must be an object or array of route objects.")
		return
	}
	respond(true, "")
}

// --- Feature F: Notifications (webhook + SMTP email) ---

const (
	settingNotifyWebhookURL    = "notify_webhook_url"
	settingNotifyWebhookSecret = "notify_webhook_secret" // v2.9.12: HMAC-SHA256 signing secret
	settingNotifyDaysBefore    = "notify_days_before"
	defaultNotifyDaysBefore    = 14

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

	// v2.12.14: comma-separated list of response headers stripped from every
	// proxy-host's upstream response. Useful for blanket-removing things like
	// X-Frame-Options or X-Powered-By that an upstream insists on adding.
	// Concatenated with each proxy_host's own strip_response_headers in
	// syncCaddy before BuildProxyRoute fires.
	settingGlobalStripResponseHeaders = "global_strip_response_headers"
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

// --- Upstream health notifier ---

// upstreamAlertEntry records a single upstream state-change notification.
type upstreamAlertEntry struct {
	ServerName string    `json:"server"`
	Upstream   string    `json:"upstream"`
	Event      string    `json:"event"` // "down" or "recovered"
	AlertedAt  time.Time `json:"alerted_at"`
}

// upstreamNotifyState tracks upstream health across check intervals so we can
// detect transitions (healthy→down and down→recovered) and avoid duplicate alerts.
var upstreamNotifyState struct {
	mu        sync.Mutex
	prevFails map[string]bool // key "serverID:address" → was failing on last check?
	lastCheck time.Time
	recent    []upstreamAlertEntry
}

// runHealthChecker polls each enabled proxy host every 5 minutes and records
// the result in proxy_health. It checks the first domain of each host via HTTPS
// (falling back to HTTP if ssl_enabled is false). Runs until the process exits.
func (s *Server) runHealthChecker() {
	// Stagger the first check by 30 seconds so startup load doesn't spike.
	time.Sleep(30 * time.Second)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	s.checkAllProxyHosts()
	for range ticker.C {
		s.checkAllProxyHosts()
	}
}

func (s *Server) checkAllProxyHosts() {
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		log.Printf("health checker: list servers: %v", err)
		return
	}
	for _, srv := range servers {
		hosts, err := models.ListProxyHosts(s.DB, srv.ID, 0, true, nil)
		if err != nil {
			log.Printf("health checker: list hosts for server %d: %v", srv.ID, err)
			continue
		}
		for _, h := range hosts {
			if !h.Enabled {
				continue
			}
			domains := h.DomainList()
			if len(domains) == 0 {
				continue
			}
			domain := domains[0]
			scheme := "https"
			if !h.SSLEnabled {
				scheme = "http"
			}
			targetURL := scheme + "://" + domain + "/"
			s.checkProxyHost(h.ID, targetURL)
		}
	}
}

func (s *Server) checkProxyHost(hostID int64, targetURL string) {
	start := time.Now()
	resp, err := s.healthClient.Get(targetURL)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		errMsg := err.Error()
		if len(errMsg) > 200 {
			errMsg = errMsg[:200]
		}
		_ = models.InsertProxyHealth(s.DB, hostID, false, 0, latencyMs, errMsg)
		return
	}
	defer resp.Body.Close()
	// Drain body to free connection.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	ok := resp.StatusCode < 400 || resp.StatusCode == 401 || resp.StatusCode == 403
	_ = models.InsertProxyHealth(s.DB, hostID, ok, resp.StatusCode, latencyMs, "")
}

// StartUpstreamNotifier launches a goroutine that checks upstream health every 5 minutes.
func StartUpstreamNotifier(db *sql.DB) {
	upstreamNotifyState.prevFails = map[string]bool{}
	go func() {
		time.Sleep(20 * time.Second) // let the DB settle first
		for {
			runUpstreamCheck(db)
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runUpstreamCheck(db *sql.DB) {
	// Skip entirely if neither SMTP nor webhook is configured.
	webhookURL, _ := models.GetSetting(db, settingNotifyWebhookURL)
	smtpHost, _ := models.GetSetting(db, settingSMTPHost)
	smtpTo, _ := models.GetSetting(db, settingSMTPTo)
	emailOK := smtpHost != "" && smtpTo != ""
	if webhookURL == "" && !emailOK {
		return
	}

	servers, err := models.ListCaddyServers(db)
	if err != nil {
		log.Printf("upstream-notifier: list servers: %v", err)
		return
	}

	upstreamNotifyState.mu.Lock()
	upstreamNotifyState.lastCheck = time.Now()
	// Prune recent alerts older than 7 days.
	fresh := upstreamNotifyState.recent[:0]
	for _, e := range upstreamNotifyState.recent {
		if time.Since(e.AlertedAt) < 7*24*time.Hour {
			fresh = append(fresh, e)
		}
	}
	upstreamNotifyState.recent = fresh
	upstreamNotifyState.mu.Unlock()

	for _, srv := range servers {
		upstreams := fetchCaddyUpstreams(srv.AdminURL)
		for addr, info := range upstreams {
			key := fmt.Sprintf("%d:%s", srv.ID, addr)
			nowFailing := info.Fails > 0

			upstreamNotifyState.mu.Lock()
			wasFailing := upstreamNotifyState.prevFails[key]
			upstreamNotifyState.prevFails[key] = nowFailing
			upstreamNotifyState.mu.Unlock()

			if nowFailing == wasFailing {
				continue // no state change
			}

			event := "recovered"
			if nowFailing {
				event = "down"
			}

			subject := fmt.Sprintf("[CaddyUI] Upstream %s %s on %s", addr, event, srv.Name)
			body := fmt.Sprintf(
				"CaddyUI upstream health alert\n\nServer : %s (%s)\nUpstream: %s\nEvent   : %s\nTime    : %s\n",
				srv.Name, srv.AdminURL, addr, event, time.Now().UTC().Format(time.RFC3339),
			)

			// Send webhook.
			if webhookURL != "" {
				payload, _ := json.Marshal(map[string]any{
					"event":    "upstream_" + event,
					"server":   srv.Name,
					"upstream": addr,
				})
				sendWebhookPayload(db, webhookURL, payload)
			}
			// Send email.
			if emailOK {
				if err := sendEmail(db, subject, body); err != nil {
					log.Printf("upstream-notifier: send email: %v", err)
				}
			}

			upstreamNotifyState.mu.Lock()
			upstreamNotifyState.recent = append(upstreamNotifyState.recent, upstreamAlertEntry{
				ServerName: srv.Name,
				Upstream:   addr,
				Event:      event,
				AlertedAt:  time.Now(),
			})
			upstreamNotifyState.mu.Unlock()
			log.Printf("upstream-notifier: %s upstream %q on %q", event, addr, srv.Name)
		}
	}
}

// notifierState holds in-memory tracking for the cert-expiry notifier goroutine.
var notifierState struct {
	mu          sync.Mutex
	lastCheck   time.Time
	lastNotified []notifiedEntry
}

type notifiedEntry struct {
	Domain    string    `json:"domain"`
	DaysLeft  int       `json:"days_left"`
	NotifiedAt time.Time `json:"notified_at"`
}

// StartNotifier launches background goroutines:
//   - cert-expiry check every 24 h (webhook + email)
//   - upstream health check every 5 min (webhook + email)
func StartNotifier(db *sql.DB, _ *caddy.Client) {
	go func() {
		time.Sleep(10 * time.Second) // wait for DB to be ready
		for {
			runNotifierCheck(db)
			time.Sleep(24 * time.Hour)
		}
	}()
	StartUpstreamNotifier(db)
}

func runNotifierCheck(db *sql.DB) {
	notifierState.mu.Lock()
	notifierState.lastCheck = time.Now()
	notifierState.mu.Unlock()

	webhookURL, _ := models.GetSetting(db, settingNotifyWebhookURL)
	smtpHost, _ := models.GetSetting(db, settingSMTPHost)
	smtpTo, _ := models.GetSetting(db, settingSMTPTo)
	emailOK := smtpHost != "" && smtpTo != ""

	if webhookURL == "" && !emailOK {
		return // nothing configured
	}

	daysBeforeStr, _ := models.GetSetting(db, settingNotifyDaysBefore)
	daysBefore := defaultNotifyDaysBefore
	if d, err := strconv.Atoi(daysBeforeStr); err == nil && d > 0 {
		daysBefore = d
	}

	// Collect custom certs from all servers.
	servers, _ := models.ListCaddyServers(db)
	var certs []models.Certificate
	for _, srv := range servers {
		sc, err := models.ListCertificates(db, srv.ID)
		if err == nil {
			certs = append(certs, sc...)
		}
	}
	if len(servers) == 0 {
		// Fallback: server_id=1 if no servers table yet.
		certs, _ = models.ListCertificates(db, 1)
	}

	notifierState.mu.Lock()
	defer notifierState.mu.Unlock()

	// Prune stale notified entries (older than 24h) so we re-notify if still expiring.
	fresh := notifierState.lastNotified[:0]
	for _, e := range notifierState.lastNotified {
		if time.Since(e.NotifiedAt) < 24*time.Hour {
			fresh = append(fresh, e)
		}
	}
	notifierState.lastNotified = fresh

	alreadyNotified := map[string]struct{}{}
	for _, e := range notifierState.lastNotified {
		alreadyNotified[e.Domain] = struct{}{}
	}

	now := time.Now()
	threshold := time.Duration(daysBefore) * 24 * time.Hour

	for _, c := range certs {
		t := parsePEMExpiry(c.CertPEM)
		if t == nil || !t.After(now) {
			continue
		}
		remaining := t.Sub(now)
		if remaining > threshold {
			continue
		}
		domain := c.Name
		if _, seen := alreadyNotified[domain]; seen {
			continue
		}
		daysLeft := int(remaining.Hours() / 24)

		sent := false

		// Webhook notification.
		if webhookURL != "" {
			payload, _ := json.Marshal(map[string]any{
				"event":     "cert_expiring",
				"domain":    domain,
				"days_left": daysLeft,
			})
			sendWebhookPayload(db, webhookURL, payload)
			sent = true
		}

		// Email notification.
		if emailOK {
			subject := fmt.Sprintf("[CaddyUI] Certificate expiring: %s (%d days left)", domain, daysLeft)
			body := fmt.Sprintf(
				"CaddyUI certificate expiry alert\n\nDomain  : %s\nDays left: %d\nExpires  : %s\n\nGo to /certificates to renew or replace it.\n",
				domain, daysLeft, t.UTC().Format("2006-01-02"),
			)
			if err := sendEmail(db, subject, body); err != nil {
				log.Printf("notifier: send email for %q: %v", domain, err)
			} else {
				sent = true
			}
		}

		if sent {
			notifierState.lastNotified = append(notifierState.lastNotified, notifiedEntry{
				Domain:     domain,
				DaysLeft:   daysLeft,
				NotifiedAt: now,
			})
			log.Printf("notifier: sent cert-expiry notification for %q (%d days left)", domain, daysLeft)
		}
	}

	// v2.11.14: also alert on Let's Encrypt / ACME-managed certs by doing a
	// live TLS dial against each enabled, SSL-enabled proxy host's first
	// domain. Caddy stores ACME-issued certs in its own data dir (which
	// CaddyUI can't read without sharing the volume), so dialing the
	// public endpoint and reading the peer certificate is the most
	// reliable way to surface expiry across LE / ZeroSSL / custom alike.
	runProxyHostCertExpiryCheck(db, webhookURL, emailOK, daysBefore, alreadyNotified, now)
}

// runProxyHostCertExpiryCheck — v2.11.14: extension of runNotifierCheck that
// covers Caddy-managed (ACME / LE) certificates. For each enabled proxy host
// with SSLEnabled=true, dials the first domain at :443, reads the leaf cert,
// and fires the same webhook + email channels when expiry is within
// daysBefore. Dedup keys are prefixed "proxy:" so they don't collide with
// the custom-cert dedup keys used above.
func runProxyHostCertExpiryCheck(db *sql.DB, webhookURL string, emailOK bool, daysBefore int, alreadyNotified map[string]struct{}, now time.Time) {
	threshold := time.Duration(daysBefore) * 24 * time.Hour
	servers, _ := models.ListCaddyServers(db)
	if len(servers) == 0 {
		// Fallback for fresh installs that haven't seeded servers yet.
		servers = []models.CaddyServer{{ID: 1}}
	}
	for _, srv := range servers {
		hosts, err := models.ListProxyHosts(db, srv.ID, 0, true, nil)
		if err != nil {
			continue
		}
		for _, h := range hosts {
			if !h.Enabled || !h.SSLEnabled {
				continue
			}
			first := strings.TrimSpace(strings.SplitN(h.Domains, ",", 2)[0])
			if first == "" || strings.HasPrefix(first, "*.") {
				// Skip wildcards — can't dial a wildcard hostname directly.
				continue
			}
			key := "proxy:" + first
			if _, seen := alreadyNotified[key]; seen {
				continue
			}
			d := &net.Dialer{Timeout: 8 * time.Second}
			conn, err := tls.DialWithDialer(d, "tcp", first+":443", &tls.Config{
				ServerName: first,
				// We need the peer cert chain, not auth — system roots are
				// fine. If verification fails we still get the chain back
				// via PeerCertificates so we can read expiry; but we keep
				// strict verify on first to surface expired/invalid certs.
			})
			if err != nil {
				continue
			}
			peers := conn.ConnectionState().PeerCertificates
			conn.Close()
			if len(peers) == 0 {
				continue
			}
			leaf := peers[0]
			if !leaf.NotAfter.After(now) {
				continue
			}
			remaining := leaf.NotAfter.Sub(now)
			if remaining > threshold {
				continue
			}
			daysLeft := int(remaining.Hours() / 24)

			sent := false
			if webhookURL != "" {
				payload, _ := json.Marshal(map[string]any{
					"event":     "proxy_cert_expiring",
					"domain":    first,
					"days_left": daysLeft,
					"issuer":    leaf.Issuer.CommonName,
				})
				sendWebhookPayload(db, webhookURL, payload)
				sent = true
			}
			if emailOK {
				subject := fmt.Sprintf("[CaddyUI] Live cert expiring: %s (%d days left)", first, daysLeft)
				body := fmt.Sprintf(
					"CaddyUI live-cert expiry alert\n\nDomain  : %s\nDays left: %d\nExpires  : %s\nIssuer  : %s\n\nThis is the certificate Caddy is currently serving for the host. Check /certificates and the host's TLS settings if a renewal hasn't fired.\n",
					first, daysLeft, leaf.NotAfter.UTC().Format("2006-01-02"), leaf.Issuer.CommonName,
				)
				if err := sendEmail(db, subject, body); err != nil {
					log.Printf("notifier: send email for live cert %q: %v", first, err)
				} else {
					sent = true
				}
			}
			if sent {
				notifierState.lastNotified = append(notifierState.lastNotified, notifiedEntry{
					Domain:     key,
					DaysLeft:   daysLeft,
					NotifiedAt: now,
				})
				log.Printf("notifier: sent live-cert-expiry notification for %q (%d days left, issuer %q)", first, daysLeft, leaf.Issuer.CommonName)
			}
		}
	}
}

// sendWebhookPayload POSTs a JSON payload to webhookURL. If a secret is configured
// in the DB (settingNotifyWebhookSecret), it adds an X-Signature-256 header
// containing the HMAC-SHA256 of the payload body in hex, prefixed "sha256=".
// The format is compatible with GitHub's webhook delivery signature.
func sendWebhookPayload(db *sql.DB, webhookURL string, payload []byte) {
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("sendWebhook: create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret, _ := models.GetSetting(db, settingNotifyWebhookSecret); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		req.Header.Set("X-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("sendWebhook: POST %s: %v", webhookURL, err)
		return
	}
	_ = resp.Body.Close()
}

func (s *Server) apiNotifierStatus(w http.ResponseWriter, r *http.Request) {
	webhookURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL)
	notifierState.mu.Lock()
	certLastCheck := notifierState.lastCheck
	certNotified := notifierState.lastNotified
	notifierState.mu.Unlock()

	upstreamNotifyState.mu.Lock()
	upLastCheck := upstreamNotifyState.lastCheck
	upRecent := upstreamNotifyState.recent
	upstreamNotifyState.mu.Unlock()

	status := map[string]any{
		"webhook_url":      webhookURL,
		"last_check":       certLastCheck,
		"last_notified":    certNotified,
		"upstream_check":   upLastCheck,
		"upstream_alerts":  upRecent,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) apiSystemStats(w http.ResponseWriter, r *http.Request) {
	// Admin-only. The dashboard template hides these cards for user/viewer
	// roles (see dashboard.html "System stats" block), but the endpoint is
	// still reachable via direct URL — so gate it here too. Host-level data
	// (uptime, RAM, load avg, Caddy-wide upstream totals) reflects the box
	// and Caddy as a whole, not anything a regular user owns, so exposing
	// it to non-admin roles leaks infrastructure details unnecessarily.
	cu := s.currentUser(r)
	if cu == nil || cu.Role != models.RoleAdmin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}

	stats := map[string]any{}

	// Uptime from /proc/uptime (always the CaddyUI host machine).
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				d := time.Duration(secs) * time.Second
				days := int(d.Hours()) / 24
				hours := int(d.Hours()) % 24
				mins := int(d.Minutes()) % 60
				stats["uptime"] = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
			}
		}
	}

	// CPU load from /proc/loadavg.
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			stats["load1"] = fields[0]
			stats["load5"] = fields[1]
			stats["load15"] = fields[2]
		}
	}

	// Memory from /proc/meminfo.
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		memInfo := map[string]uint64{}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
					memInfo[key] = val
				}
			}
		}
		total := memInfo["MemTotal"]
		avail := memInfo["MemAvailable"]
		if total > 0 {
			used := total - avail
			stats["mem_total_mb"] = total / 1024
			stats["mem_used_mb"] = used / 1024
			stats["mem_pct"] = int(float64(used) / float64(total) * 100)
		}
	}

	// Per-server Caddy stats: active upstream requests + healthy upstream count.
	// Uses the server ID from the ?sid query param, falling back to the cookie.
	sidStr := r.URL.Query().Get("sid")
	sid, err := strconv.ParseInt(sidStr, 10, 64)
	if err != nil || sid <= 0 {
		sid = s.currentServerID(r)
	}
	if srv, err := models.GetCaddyServer(s.DB, sid); err == nil {
		upstreams := fetchCaddyUpstreams(srv.AdminURL)
		activeReqs := 0
		healthy := 0
		for _, u := range upstreams {
			activeReqs += u.NumRequests
			if u.Fails == 0 {
				healthy++
			}
		}
		stats["active_requests"]  = activeReqs
		stats["healthy_upstreams"] = healthy
		stats["total_upstreams"]   = len(upstreams)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// apiCaddyVersion returns the running Caddy version from the admin API.
func (s *Server) apiCaddyVersion(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	version, err := s.Caddy.GetVersion(ctx)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"version": "unknown", "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"version": version})
}

// apiVersionCheck returns the running version and the latest Docker Hub tag,
// so the UI can show an "update available" notice. Result is cached for 1 hour.
func (s *Server) apiVersionCheck(w http.ResponseWriter, r *http.Request) {
	s.versionMu.Lock()
	cached := s.latestVersion
	checkedAt := s.versionCheckedAt
	s.versionMu.Unlock()

	latest := cached
	if latest == "" || time.Since(checkedAt) > time.Hour {
		if v, err := fetchLatestDockerTag("applegater", "caddyui"); err == nil {
			latest = v
			s.versionMu.Lock()
			s.latestVersion = v
			s.versionCheckedAt = time.Now()
			s.versionMu.Unlock()
		}
	}

	current := s.Version
	hasUpdate := latest != "" && current != "" && current != "dev" && semverGT(latest, current)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"current":    current,
		"latest":     latest,
		"has_update": hasUpdate,
	})
}

// fetchLatestDockerTag queries Docker Hub for the highest vX.Y.Z tag of image.
func fetchLatestDockerTag(namespace, image string) (string, error) {
	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/%s/tags/?page_size=50&ordering=-last_updated", namespace, image)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&result); err != nil {
		return "", err
	}
	best := ""
	for _, t := range result.Results {
		if semverValid(t.Name) {
			if best == "" || semverGT(t.Name, best) {
				best = t.Name
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("no semver tags found")
	}
	return best, nil
}

// --- Unified DNS helpers ---
//
// Replaces the v2.2.x per-provider helpers (cfClient/cfCreateDNSRecord/...,
// pbClient/pbCreateDNSRecord/...) with a single code path driven by the
// dns.Provider registry. A proxy_hosts row carries four DNS columns:
//   dns_provider  — the provider ID ("cloudflare", "porkbun", ...)
//   dns_zone_id   — the provider-native zone ID (opaque for CF/Hetzner;
//                   domain name for PB/DO/GD/NC)
//   dns_zone_name — the base domain in human-readable form ("example.com")
//   dns_record_id — the record identifier returned by the provider
// All mutations happen through dnsCreateRecord / dnsDeleteRecord /
// dnsUpdateAllRecords — no provider-specific branch lives above this line.

// dnsCreateRecordForFQDN creates an A record at fqdn pointing at the
// per-server public IP and returns (recordID, resolvedZoneName). Returns
// ("","") on any precondition failure or provider error; all failures are
// logged but not returned — DNS is non-fatal to the caller's main save
// path. Shared by the proxy-host and raw-route create paths; the caller
// persists the returned record ID via its own Update*DNSRecord helper.
//
// serverID is the Caddy server the caller lives on — v2.4.0 reads the
// per-server public_ip first and falls back to the global setting so
// multi-server setups get the right A-record content instead of always
// pointing at server #1's IP.
func (s *Server) dnsCreateRecordForFQDN(serverID int64, provider, zoneID, zoneName, fqdn string) (string, string) {
	if provider == "" || zoneID == "" || fqdn == "" {
		return "", ""
	}
	client := s.dnsClient(provider)
	if client == nil {
		return "", ""
	}
	ip := s.serverIPFor(serverID)
	if ip == "" {
		log.Printf("DNS: server IP not configured for server %d — skipping record creation for %s", serverID, fqdn)
		return "", ""
	}
	zone := dns.Zone{ID: zoneID, Name: zoneName}
	if zone.Name == "" {
		// Older rows (pre-migration) may not have zone_name populated —
		// it's optional metadata for most providers. Fall back to the
		// zone ID which doubles as the domain for PB/DO/GD/NC.
		zone.Name = zoneID
	}
	// v2.4.7: honour the per-provider zone allow-list as a last-line guard.
	// The dropdown is already filtered, but the zone name on the row could
	// have come from an older config / direct DB edit / a user who
	// tightened the allow-list after the host was created. Refusing here
	// makes the allow-list a hard safety rail, not just a UI filter.
	if !s.zoneAllowed(provider, zone.Name) {
		log.Printf("DNS %s: zone %q not in allow-list — skipping record creation for %s", provider, zone.Name, fqdn)
		return "", ""
	}
	rec, err := client.CreateRecord(zone, fqdn, ip, "A", 0)
	if err != nil {
		log.Printf("DNS %s: create record for %s: %v", provider, fqdn, err)
		return "", ""
	}
	return rec.ID, zone.Name
}

// splitDNSRecordIDs splits the comma-separated DNSRecordID column value into
// individual provider record IDs. v2.5.9 introduced the comma-separated
// encoding so routes with multiple hostnames (e.g. `example.com, *.example.com`)
// can track one provider record per hostname. Empty / single-ID values still
// parse cleanly — a pre-v2.5.9 row with "abc123" returns []string{"abc123"}.
func splitDNSRecordIDs(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dnsCreateRecord creates an A record for every domain on the proxy host.
// p.DNSProvider / p.DNSZoneID must be set before calling. The set of
// provider-returned record IDs is persisted to the proxy_hosts row as a
// comma-separated string via models.UpdateProxyHostDNSRecord.
// v2.5.9: previously only the first domain got a record — multi-domain hosts
// (aliases + primary, or wildcard + apex) now get one record per hostname so
// clients resolving any alias actually reach the origin.
func (s *Server) dnsCreateRecord(serverID, hostID int64, p *models.ProxyHost) {
	domains := p.DomainList()
	if len(domains) == 0 {
		return
	}
	var ids []string
	var zname string
	for _, fqdn := range domains {
		recID, zn := s.dnsCreateRecordForFQDN(serverID, p.DNSProvider, p.DNSZoneID, p.DNSZoneName, fqdn)
		if recID == "" {
			continue
		}
		ids = append(ids, recID)
		if zname == "" {
			zname = zn
		}
	}
	if len(ids) == 0 {
		return
	}
	if err := models.UpdateProxyHostDNSRecord(s.DB, hostID, p.DNSProvider, p.DNSZoneID, zname, strings.Join(ids, ",")); err != nil {
		log.Printf("DNS %s: store record IDs for host %d: %v", p.DNSProvider, hostID, err)
	}
}

// dnsCreateRecordForRedirection — v2.12.2: creates an A record per hostname
// in the redirection host's Domains CSV, mirroring dnsCreateRecord on the
// proxy-host side. Persists the comma-separated provider IDs to the
// redirection_hosts row via UpdateRedirectionHostDNSRecord.
func (s *Server) dnsCreateRecordForRedirection(serverID, hostID int64, rh *models.RedirectionHost) {
	domains := rh.DomainList()
	if len(domains) == 0 {
		return
	}
	var ids []string
	var zname string
	for _, fqdn := range domains {
		recID, zn := s.dnsCreateRecordForFQDN(serverID, rh.DNSProvider, rh.DNSZoneID, rh.DNSZoneName, fqdn)
		if recID == "" {
			continue
		}
		ids = append(ids, recID)
		if zname == "" {
			zname = zn
		}
	}
	if len(ids) == 0 {
		return
	}
	if err := models.UpdateRedirectionHostDNSRecord(s.DB, hostID, rh.DNSProvider, rh.DNSZoneID, zname, strings.Join(ids, ",")); err != nil {
		log.Printf("DNS %s: store record IDs for redirection %d: %v", rh.DNSProvider, hostID, err)
	}
}

// dnsCreateRecordForRaw is the raw-route twin of dnsCreateRecord.
// v2.5.6: raw routes don't carry a Domains CSV, so hostnames are pulled
// from the JSON blob's match.host[] via rawRouteHosts.
// v2.5.9: creates a record for EVERY hostname in match[].host[] rather than
// only the first — so an advanced route covering `example.com, *.example.com`
// gets both A records provisioned. Record IDs are persisted to the raw_routes
// row as a comma-separated string via models.UpdateRawRouteDNSRecord. No-op
// when DNS fields are unset or the JSON has no host matcher.
func (s *Server) dnsCreateRecordForRaw(serverID, routeID int64, rr *models.RawRoute) {
	hosts := rawRouteHosts(*rr)
	if len(hosts) == 0 {
		return
	}
	var ids []string
	var zname string
	for _, fqdn := range hosts {
		recID, zn := s.dnsCreateRecordForFQDN(serverID, rr.DNSProvider, rr.DNSZoneID, rr.DNSZoneName, fqdn)
		if recID == "" {
			continue
		}
		ids = append(ids, recID)
		if zname == "" {
			zname = zn
		}
	}
	if len(ids) == 0 {
		return
	}
	if err := models.UpdateRawRouteDNSRecord(s.DB, routeID, rr.DNSProvider, rr.DNSZoneID, zname, strings.Join(ids, ",")); err != nil {
		log.Printf("DNS %s: store record IDs for raw route %d: %v", rr.DNSProvider, routeID, err)
	}
}

// dnsDeleteRecord removes previously-created records for the given row.
// v2.5.9: recordIDs may be a single ID ("abc123") or a comma-separated list
// ("abc123,def456") — loops internally so callers can keep passing the raw
// DNSRecordID column value regardless of how many records are behind it.
// Best-effort: errors are logged, not returned (the row is being deleted
// anyway; a leftover record is a minor annoyance, not a correctness issue).
func (s *Server) dnsDeleteRecord(providerID, zoneID, zoneName, recordIDs string) {
	if providerID == "" || recordIDs == "" {
		return
	}
	client := s.dnsClient(providerID)
	if client == nil {
		return
	}
	zone := dns.Zone{ID: zoneID, Name: zoneName}
	if zone.Name == "" {
		zone.Name = zoneID
	}
	// v2.4.7: refuse to delete records in zones the allow-list excludes.
	// Intentionally symmetric with dnsCreateRecord — "touching a record"
	// in an excluded zone is exactly what the allow-list is meant to
	// prevent, even when the touch is a cleanup. Leaves the record in
	// place; the user can remove it by hand via the provider's console.
	if !s.zoneAllowed(providerID, zone.Name) {
		log.Printf("DNS %s: zone %q not in allow-list — leaving records %s in place", providerID, zone.Name, recordIDs)
		return
	}
	for _, recordID := range splitDNSRecordIDs(recordIDs) {
		if err := client.DeleteRecord(zone, recordID); err != nil {
			log.Printf("DNS %s: delete record %s: %v", providerID, recordID, err)
		}
	}
}

// dnsUpdateAllRecords retargets managed DNS records at newIP. Pass
// serverID > 0 to scope the retarget to content rows that live on that
// Caddy server (v2.4.0 per-server public-IP flow); 0 retargets every
// managed record regardless of server (used by the legacy global-IP
// fallback path so pre-v2.4.0 databases still work).
//
// We cache provider clients by ID so we build each at most once per call.
// Records for providers with missing credentials are skipped rather than
// cleared, so partial credential removal doesn't destroy working records.
//
// v2.5.6: also retargets raw-route records alongside proxy-host records.
func (s *Server) dnsUpdateAllRecords(serverID int64, newIP string) {
	hosts, err := models.ListProxyHostsWithDNSRecords(s.DB, serverID)
	if err != nil {
		log.Printf("DNS: list managed hosts for IP update: %v", err)
	}
	rawRoutes, err := models.ListRawRoutesWithDNSRecords(s.DB, serverID)
	if err != nil {
		log.Printf("DNS: list managed raw routes for IP update: %v", err)
	}
	if len(hosts) == 0 && len(rawRoutes) == 0 {
		return
	}
	clients := map[string]dns.Provider{}
	getClient := func(id string) dns.Provider {
		if c, ok := clients[id]; ok {
			return c
		}
		c := s.dnsClient(id)
		clients[id] = c
		return c
	}
	log.Printf("DNS: retargeting %d proxy-host record(s) + %d raw-route record(s) to %s", len(hosts), len(rawRoutes), newIP)

	// retarget is the shared delete-then-create worker. kind is a tag for
	// the log line ("proxy"/"raw"); persist is the row-specific updater
	// that writes the fresh record ID(s) (or clears on failure). fqdns are
	// pulled differently per row type (Domains CSV vs match[].host[]), so
	// the caller hands them in.
	// v2.5.9: accepts multiple fqdns + multiple old record IDs to match
	// the multi-hostname create path. Deletes every old record, creates
	// one new record per current hostname, persists the joined ID list.
	// Rows created pre-v2.5.9 (one ID, multiple hostnames) self-heal on
	// the first retarget — the missing-alias records get created fresh.
	retarget := func(kind string, rowID int64, provider, zoneID, zoneName, recordIDs string, fqdns []string, persist func(zoneID, zoneName, recordID string)) {
		client := getClient(provider)
		if client == nil {
			log.Printf("DNS %s: credentials missing — skipping %s %d retarget", provider, kind, rowID)
			return
		}
		if len(fqdns) == 0 {
			return
		}
		zone := dns.Zone{ID: zoneID, Name: zoneName}
		if zone.Name == "" {
			zone.Name = zoneID
		}
		// v2.4.7: guard IP retargets against the allow-list too. If a zone
		// was valid when the record was created but the user has since
		// tightened the list, the retarget job leaves that record alone —
		// same policy as dnsCreateRecord / dnsDeleteRecord.
		if !s.zoneAllowed(provider, zone.Name) {
			log.Printf("DNS %s: zone %q not in allow-list — skipping retarget for %v", provider, zone.Name, fqdns)
			return
		}
		// Delete-then-create semantic. Every provider implementation is
		// idempotent on delete (silently succeeds if the record is gone),
		// and recreate gives us a fresh record ID — cleanest across the
		// whole provider set, even if a tiny window exists where the
		// record is absent. Users are already dealing with a live IP
		// change when this runs; a few seconds of DNS flutter is noise.
		for _, recordID := range splitDNSRecordIDs(recordIDs) {
			if err := client.DeleteRecord(zone, recordID); err != nil {
				log.Printf("DNS %s: delete old record %s: %v", provider, recordID, err)
			}
		}
		var newIDs []string
		for _, fqdn := range fqdns {
			rec, err := client.CreateRecord(zone, fqdn, newIP, "A", 0)
			if err != nil {
				log.Printf("DNS %s: create new record for %s: %v", provider, fqdn, err)
				continue
			}
			newIDs = append(newIDs, rec.ID)
			log.Printf("DNS %s: updated %s → %s (record %s)", provider, fqdn, newIP, rec.ID)
		}
		if len(newIDs) == 0 {
			persist("", "", "")
			return
		}
		persist(zone.ID, zone.Name, strings.Join(newIDs, ","))
	}

	for _, h := range hosts {
		h := h
		retarget("proxy", h.ID, h.DNSProvider, h.DNSZoneID, h.DNSZoneName, h.DNSRecordID,
			h.DomainList(),
			func(zoneID, zoneName, recordID string) {
				provider := h.DNSProvider
				if recordID == "" {
					provider = ""
				}
				_ = models.UpdateProxyHostDNSRecord(s.DB, h.ID, provider, zoneID, zoneName, recordID)
			})
	}
	for _, rr := range rawRoutes {
		rr := rr
		retarget("raw", rr.ID, rr.DNSProvider, rr.DNSZoneID, rr.DNSZoneName, rr.DNSRecordID,
			rawRouteHosts(rr),
			func(zoneID, zoneName, recordID string) {
				provider := rr.DNSProvider
				if recordID == "" {
					provider = ""
				}
				_ = models.UpdateRawRouteDNSRecord(s.DB, rr.ID, provider, zoneID, zoneName, recordID)
			})
	}
}

// apiDNSZones returns the list of zones for the provider specified in the
// ?provider= query string. Replaces the per-provider apiCFZones /
// apiPBDomains endpoints with a single handler.
//
// Response shape is always [{id, name}] so the form's zone-picker JS
// renders every provider with the same code path. Cloudflare and Hetzner
// return real opaque zone IDs; for Porkbun/DO/GoDaddy/Namecheap the ID
// and name are the same string (the bare domain).
func (s *Server) apiDNSZones(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider")))
	w.Header().Set("Content-Type", "application/json")
	if provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing provider parameter"})
		return
	}
	client := s.dnsClient(provider)
	if client == nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "credentials for provider \"" + provider + "\" not configured in Settings"})
		return
	}
	zones, err := client.ListZones()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	// v2.4.7: apply the per-provider zone allow-list. If it's set, only
	// zones whose name is on the list are returned — the proxy-host form's
	// zone dropdown then literally cannot offer domains the user has
	// excluded. Empty allow-list = unrestricted (every zone the credentials
	// can see), which preserves the original behaviour.
	if allow := s.zoneAllowlist(provider); len(allow) > 0 {
		allowSet := make(map[string]struct{}, len(allow))
		for _, a := range allow {
			allowSet[a] = struct{}{}
		}
		filtered := zones[:0]
		for _, z := range zones {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z.Name)), ".")
			if _, ok := allowSet[name]; ok {
				filtered = append(filtered, z)
			}
		}
		zones = filtered
	}
	_ = json.NewEncoder(w).Encode(zones)
}

// apiDNSCheckRecord looks up existing records for an (provider, zone, fqdn)
// triple so the proxy-host form can warn when saving would collide with
// something already in DNS. Called by the form JS after the user has picked
// provider + zone and typed a first domain.
//
// Query string: provider=<id>&zone=<zoneID>&zone_name=<zoneName>&fqdn=<host>
//
// Response shape (always 200 when inputs are valid — errors go in the body):
//
//	{"ok":true, "exists":true, "records":[{id,type,name,content,ttl},...]}
//	{"ok":true, "exists":false}
//	{"ok":false, "error":"..."}
//
// The `exists` flag is the only thing the UI needs to branch on; the full
// record list is included so the warning dialog can show the user what
// they're about to clobber. 200-with-body-error (rather than 4xx/5xx) keeps
// the form JS simple — one JSON parse, branch on `ok`.
func (s *Server) apiDNSCheckRecord(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query()
	provider := strings.ToLower(strings.TrimSpace(q.Get("provider")))
	zoneID := strings.TrimSpace(q.Get("zone"))
	zoneName := strings.TrimSpace(q.Get("zone_name"))
	fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(q.Get("fqdn"))), ".")
	if provider == "" || zoneID == "" || fqdn == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "missing provider/zone/fqdn"})
		return
	}
	// Zone name is optional on the wire — most providers use ID==Name so
	// we can recover it. Cloudflare and Hetzner have opaque IDs, so when
	// the client omits zone_name we fall back to zoneID (which will fail
	// SubdomainOf but still works for Cloudflare's server-side filter).
	if zoneName == "" {
		zoneName = zoneID
	}
	client := s.dnsClient(provider)
	if client == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "credentials for provider \"" + provider + "\" not configured"})
		return
	}
	// Allow-list guard: don't leak record listings for zones the user has
	// excluded from management. Symmetrical with apiDNSZones' filter.
	if !s.zoneAllowed(provider, zoneName) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "zone not in allow-list"})
		return
	}
	zone := dns.Zone{ID: zoneID, Name: zoneName}
	records, err := client.FindRecord(zone, fqdn)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// Scope the warning to record types that actually conflict with the
	// A/AAAA/CNAME we're about to write. MX / TXT / SRV / CAA routinely
	// cohabit with the web endpoint (email, SPF, cert issuance) and
	// alarming on them would scare users into clicking Override — which
	// used to wipe their mail records. See IsProxyConflictingType.
	filtered := records[:0]
	for _, rec := range records {
		if dns.IsProxyConflictingType(rec.Type) {
			filtered = append(filtered, rec)
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"exists":  len(filtered) > 0,
		"records": filtered,
	})
}

// ─────────────────────────────────────────────────────────────────────
// v2.5.2: post-save "deploying" flow.
// ─────────────────────────────────────────────────────────────────────
//
// When a proxy-host save creates or changes a managed-DNS A record, we
// redirect to /proxy-hosts/{id}/deploying instead of bouncing straight
// back to the list. That page polls apiProxyHostDeployStatus every few
// seconds and draws a live checklist — DNS propagated, TLS handshake
// succeeded — so the user actually knows when their site is enterable.
// ─────────────────────────────────────────────────────────────────────

// apiProxyHostDeployStatus returns the real-time deployment status for a
// freshly-saved proxy host. Response:
//
//	{
//	  "fqdn":         "test.example.com",
//	  "expected_ip":  "203.0.113.10",
//	  "resolved_ips": ["203.0.113.10"],
//	  "ssl_enabled":  true,
//	  "proxied":      false,
//	  "dns_ready":    true,
//	  "cert_ready":   false,
//	  "error":        ""
//	}
//
// For non-proxied records dns_ready is true only when a public resolver
// returns an A record matching the server's configured public IP. For
// Cloudflare-proxied records (orange cloud) the record points at CF's
// edge IPs, so we relax to "any A record" — the record is live in DNS
// and CF is handling the rest. Cert check is a plain TLS handshake via
// tls.Dial against fqdn:443 with system-trust verification enabled, so
// a Caddy-internal self-signed fallback correctly reports not-ready.
func (s *Server) apiProxyHostDeployStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad id"})
		return
	}
	host, err := models.GetProxyHost(s.DB, id)
	if err != nil || host == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "not found"})
		return
	}
	// Ownership: non-admins can only poll their own hosts.
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !host.OwnerID.Valid || host.OwnerID.Int64 != cu.ID {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden"})
			return
		}
	}
	fqdn := dns.FirstDomain(host.Domains)
	expectedIP := s.serverIPFor(host.ServerID)
	resp := map[string]any{
		"fqdn":         fqdn,
		"expected_ip":  expectedIP,
		"ssl_enabled":  host.SSLEnabled,
		"proxied":      false,
		"dns_ready":    false,
		"cert_ready":   false,
		"resolved_ips": []string{},
	}
	if fqdn == "" {
		resp["error"] = "host has no domain"
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	// Proxied flag applies to Cloudflare only; other providers always
	// resolve to the configured server IP.
	if host.DNSProvider == dns.Cloudflare {
		if v, _ := models.GetSetting(s.DB, settingCFProxied); v == "1" {
			resp["proxied"] = true
		}
	}
	// DNS check via Cloudflare DNS-over-HTTPS. Silent on error — the
	// client keeps polling, and a transient DoH failure should just
	// look like "not ready yet".
	if ips, dnsErr := resolveViaDoH(fqdn); dnsErr == nil {
		resp["resolved_ips"] = ips
		if resp["proxied"] == true {
			resp["dns_ready"] = len(ips) > 0
		} else if expectedIP != "" {
			for _, ip := range ips {
				if ip == expectedIP {
					resp["dns_ready"] = true
					break
				}
			}
		} else {
			// No expected IP configured — fall back to "any A record".
			// Otherwise we'd always report not-ready.
			resp["dns_ready"] = len(ips) > 0
		}
	}
	// Cert check: skipped when SSL is off on the host, and deferred
	// until DNS is ready (otherwise the dial is guaranteed to fail on
	// hostname resolution).
	resolvedIPs, _ := resp["resolved_ips"].([]string)
	proxied, _ := resp["proxied"].(bool)
	if !host.SSLEnabled {
		resp["cert_ready"] = true
	} else if resp["dns_ready"] == true {
		resp["cert_ready"] = s.tlsHandshakeOK(host.ServerID, fqdn, proxied, resolvedIPs)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// resolveViaDoH queries Cloudflare DNS-over-HTTPS for A records for fqdn.
// Returns the list of IPs, or an empty slice if the record doesn't exist
// yet. 6-second timeout so a slow upstream doesn't stall the poll.
func resolveViaDoH(fqdn string) ([]string, error) {
	req, err := http.NewRequest("GET",
		"https://cloudflare-dns.com/dns-query?name="+url.QueryEscape(fqdn)+"&type=A",
		nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(data.Answer))
	for _, a := range data.Answer {
		if a.Type == 1 { // A record
			ips = append(ips, strings.TrimSpace(a.Data))
		}
	}
	return ips, nil
}

// tlsHandshakeOK performs a full TLS handshake with SNI set to fqdn and
// validates the returned chain against the system trust store. Returns
// true only when the cert chain verifies — which is what users actually
// care about ("can I open the site in a browser"). A Caddy-internal
// self-signed fallback cert, an ACME-staging cert, or an expired cert
// all correctly report false.
//
// Dial target depends on how the record is served, to avoid the WAN
// hairpin NAT problem most consumer routers have (resolving fqdn to the
// public IP and dialing it from inside the LAN fails even when the site
// is live for real users). We pick the dial target in priority order:
//
//   1. **Cloudflare-proxied** (orange cloud): dial the CF edge IP we just
//      resolved via DoH. CF edge IPs are always public + outside the LAN,
//      so hairpin never applies; SNI = fqdn makes CF serve the right
//      customer cert from its Universal SSL / Advanced Certs pool. This
//      is v2.5.5 — previously we tried to dial Caddy internally, which
//      is wrong for proxied hosts because the user's browser sees CF's
//      cert, not Caddy's origin cert.
//   2. **Direct**: dial the Caddy server by its admin-URL hostname
//      (docker service name `caddy` for single-host, admin host for
//      remote servers). Bypasses public DNS + WAN hairpin; SNI = fqdn
//      makes Caddy serve the right cert. This is the v2.5.4 path and
//      remains the default for non-proxied providers.
//   3. **Fallback**: dial the public fqdn directly. Used when we can't
//      figure out an internal dial target (e.g. admin URL is a unix
//      socket, or the server row is unreadable).
func (s *Server) tlsHandshakeOK(serverID int64, fqdn string, proxied bool, resolvedIPs []string) bool {
	target := fqdn + ":443"
	switch {
	case proxied && len(resolvedIPs) > 0:
		target = resolvedIPs[0] + ":443"
	default:
		if host := s.caddyDialHost(serverID); host != "" {
			target = host + ":443"
		}
	}
	d := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", target, &tls.Config{
		ServerName: fqdn,
	})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// caddyDialHost returns the hostname (no port) to use when dialing the
// Caddy server for serverID. Pulled from the admin URL so single-host
// setups resolve to "caddy" (the docker service name) and remote-server
// setups resolve to whatever address admin is configured on. Falls back
// to the primary client's admin URL when serverID isn't usable. Returns
// "" when nothing sensible can be extracted — callers then dial the
// public fqdn directly as a last resort.
func (s *Server) caddyDialHost(serverID int64) string {
	adminURL := ""
	if serverID > 0 {
		if srv, err := models.GetCaddyServer(s.DB, serverID); err == nil {
			adminURL = srv.AdminURL
		}
	}
	if adminURL == "" && s.Caddy != nil {
		adminURL = s.Caddy.AdminURL
	}
	if adminURL == "" {
		return ""
	}
	u, err := url.Parse(adminURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	// Unix-socket admins ("http://unix") give an empty hostname above;
	// belt-and-braces skip them too since we can't dial :443 via a
	// socket path.
	if strings.EqualFold(u.Scheme, "unix") || strings.EqualFold(u.Host, "unix") {
		return ""
	}
	return u.Hostname()
}

// proxyHostDeploying renders the post-save "deploying" checklist page.
// Shown after a create/update that created or changed a managed-DNS
// record. The page JS polls /api/proxy-hosts/{id}/deploy-status every
// few seconds and auto-redirects to /proxy-hosts once both DNS and
// cert checks pass — or after the hard 120s timeout.
func (s *Server) proxyHostDeploying(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	host, err := models.GetProxyHost(s.DB, id)
	if err != nil || host == nil {
		http.NotFound(w, r)
		return
	}
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !host.OwnerID.Valid || host.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	providerName := host.DNSProvider
	if d, ok := dns.Lookup(host.DNSProvider); ok {
		providerName = d.DisplayName
	}
	s.render(w, r, "proxy_host_deploying.html", map[string]any{
		"User":         cu,
		"Host":         host,
		"FirstDomain":  dns.FirstDomain(host.Domains),
		"ProviderName": providerName,
		"ExpectedIP":   s.serverIPFor(host.ServerID),
		"Section":      "proxy",
	})
}

// firstRawRouteHost pulls the first hostname out of a raw-route JSON
// blob's match.host[] array. v2.5.5 uses this to drive the post-save
// deploying page for advanced routes — if the route has no host matcher
// (path-only, port-only, etc.) we return "" and the caller skips the
// deploying page entirely since there's nothing DNS- or TLS-shaped to
// probe.
//
// Parsing is defensive: any shape mismatch in the JSON returns empty
// rather than panicking, because raw routes intentionally accept arbitrary
// Caddy JSON and we don't want a malformed blob to break the post-save
// redirect. The save path already runs the config through Caddy's adapter
// before we get here, so well-formed routes reach this function with the
// canonical match[].host[] shape.
func firstRawRouteHost(jsonData string) string {
	if strings.TrimSpace(jsonData) == "" {
		return ""
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		return ""
	}
	matches, _ := cfg["match"].([]any)
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		hosts, _ := mm["host"].([]any)
		for _, h := range hosts {
			if s, ok := h.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// apiRawRouteDeployStatus mirrors apiProxyHostDeployStatus for advanced
// routes. Raw routes don't manage their own DNS records (the user wires
// A records manually), so the "record created in <provider>" step is
// absent — but DNS propagation + TLS handshake still apply and are
// exactly the signal the user wants after saving.
func (s *Server) apiRawRouteDeployStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad id"})
		return
	}
	rr, err := models.GetRawRoute(s.DB, id)
	if err != nil || rr == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "not found"})
		return
	}
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !rr.OwnerID.Valid || rr.OwnerID.Int64 != cu.ID {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden"})
			return
		}
	}
	fqdn := firstRawRouteHost(rr.JSONData)
	serverID := s.currentServerID(r)
	expectedIP := s.serverIPFor(serverID)
	// Raw routes are always HTTPS-capable in Caddy (automatic_https is
	// on by default) unless the user manually carved it out — we treat
	// SSL as always-on for the cert check. A custom cert (CertificateID > 0)
	// skips ACME but still terminates TLS, so the probe applies either way.
	resp := map[string]any{
		"fqdn":         fqdn,
		"expected_ip":  expectedIP,
		"ssl_enabled":  true,
		"proxied":      false,
		"dns_ready":    false,
		"cert_ready":   false,
		"resolved_ips": []string{},
	}
	if fqdn == "" {
		resp["error"] = "route has no host matcher"
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	// Raw routes don't carry a DNS provider, but the Cloudflare-proxied
	// toggle is a server-wide setting — if the user has CF proxy on and
	// the domain happens to sit in a CF zone, their A record resolves to
	// CF edge IPs even though the raw route doesn't know about it. Trust
	// the resolved IP shape rather than the setting: if DoH returns a CF
	// edge IP (known-proxied ranges), treat it as proxied.
	var ips []string
	if got, dnsErr := resolveViaDoH(fqdn); dnsErr == nil {
		ips = got
		resp["resolved_ips"] = got
		if looksLikeCloudflareEdge(got) {
			resp["proxied"] = true
			resp["dns_ready"] = len(got) > 0
		} else if expectedIP != "" {
			for _, ip := range got {
				if ip == expectedIP {
					resp["dns_ready"] = true
					break
				}
			}
		} else {
			resp["dns_ready"] = len(got) > 0
		}
	}
	if resp["dns_ready"] == true {
		proxied, _ := resp["proxied"].(bool)
		resp["cert_ready"] = s.tlsHandshakeOK(serverID, fqdn, proxied, ips)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// rawRouteDeploying renders the deploying-checklist page for advanced
// routes. If the route has no host matcher we fall through to the list —
// there's nothing meaningful to poll on a port-only / path-only route.
func (s *Server) rawRouteDeploying(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rr, err := models.GetRawRoute(s.DB, id)
	if err != nil || rr == nil {
		http.NotFound(w, r)
		return
	}
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !rr.OwnerID.Valid || rr.OwnerID.Int64 != cu.ID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	fqdn := firstRawRouteHost(rr.JSONData)
	if fqdn == "" {
		http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
		return
	}
	// v2.5.6: if Managed DNS is active on this route, render the "DNS
	// record created in <provider>" step by passing the display name.
	providerName := rr.DNSProvider
	if d, ok := dns.Lookup(rr.DNSProvider); ok {
		providerName = d.DisplayName
	}
	serverID := s.currentServerID(r)
	s.render(w, r, "raw_route_deploying.html", map[string]any{
		"User":         cu,
		"Route":        rr,
		"FirstDomain":  fqdn,
		"ProviderName": providerName,
		"ExpectedIP":   s.serverIPFor(serverID),
		"Section":      "raw",
	})
}

// looksLikeCloudflareEdge is a coarse heuristic to spot CF-proxied A
// records from their resolved IP. We use it on raw routes where the
// explicit "proxied" setting is on proxy hosts only. The ranges below
// are Cloudflare's published IPv4 edge set as of 2024 — keeping this
// small + local (vs. fetching cloudflare.com/ips-v4) avoids a network
// dependency on the deploy-status poll. False positives here just mean
// we dial CF edge with SNI=fqdn instead of Caddy internally, which is
// harmless when the domain really is on CF and correctly fails to
// verify when it isn't.
func looksLikeCloudflareEdge(ips []string) bool {
	// Canonical CF v4 edge CIDRs (from https://www.cloudflare.com/ips-v4).
	cfRanges := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		for _, cidr := range cfRanges {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if n.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

// semverValid returns true for tags like v1.2.3.
func semverValid(v string) bool {
	if len(v) < 6 || v[0] != 'v' {
		return false
	}
	parts := strings.SplitN(v[1:], ".", 3)
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// semverGT returns true when a > b (both must be valid semver like v1.2.3).
func semverGT(a, b string) bool {
	pa := semverParts(a)
	pb := semverParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] > pb[i] {
			return true
		}
		if pa[i] < pb[i] {
			return false
		}
	}
	return false
}

func semverParts(v string) [3]int {
	var out [3]int
	if len(v) > 0 && v[0] == 'v' {
		v = v[1:]
	}
	parts := strings.SplitN(v, ".", 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		out[i], _ = strconv.Atoi(parts[i])
	}
	return out
}

func (s *Server) getBackup(w http.ResponseWriter, r *http.Request) {
	// Write the VACUUM INTO temp file next to the live DB rather than /tmp.
	// Rationale: the scratch-based final image has no /tmp directory and the
	// process runs as a non-root UID, so `os.TempDir()` returns "/tmp" but
	// SQLite's sqlite3_open_v2 gets CANTOPEN (errcode 14). The directory
	// containing the DB is guaranteed to exist (we just opened the DB from
	// there) and is writable by our UID (we write WAL + SHM there every
	// transaction). Falls back to os.TempDir() only if DBPath wasn't plumbed
	// through — every call site in main.go does plumb it, so the fallback is
	// defence-in-depth against a future constructor regression. v2.7.5.
	ts := time.Now().Format("20060102-150405")
	backupDir := os.TempDir()
	if s.DBPath != "" {
		backupDir = filepath.Dir(s.DBPath)
	}
	tmpPath := filepath.Join(backupDir, fmt.Sprintf("caddyui-backup-%s.db", ts))
	defer os.Remove(tmpPath)

	if _, err := s.DB.Exec("VACUUM INTO ?", tmpPath); err != nil {
		http.Error(w, "backup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		http.Error(w, "open backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="caddyui-backup-`+ts+`.db"`)
	io.Copy(w, f)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	webhookURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL)
	daysBeforeStr, _ := models.GetSetting(s.DB, settingNotifyDaysBefore)
	daysBefore := defaultNotifyDaysBefore
	if d, err := strconv.Atoi(daysBeforeStr); err == nil && d > 0 {
		daysBefore = d
	}

	// v2.11.15: AI assistant settings.
	aiEnabledStr, _ := models.GetSetting(s.DB, settingAIEnabled)
	aiOllamaURL, _ := models.GetSetting(s.DB, settingAIOllamaURL)
	if aiOllamaURL == "" {
		aiOllamaURL = "http://ollama:11434"
	}
	aiOllamaModel, _ := models.GetSetting(s.DB, settingAIOllamaModel)
	if aiOllamaModel == "" {
		aiOllamaModel = "llama3.2:latest"
	}
	aiSystemPrompt, _ := models.GetSetting(s.DB, settingAISystemPrompt)
	globalStripHdrs, _ := models.GetSetting(s.DB, settingGlobalStripResponseHeaders)

	smtpHost, _ := models.GetSetting(s.DB, settingSMTPHost)
	smtpPort, _ := models.GetSetting(s.DB, settingSMTPPort)
	smtpUsername, _ := models.GetSetting(s.DB, settingSMTPUsername)
	smtpFrom, _ := models.GetSetting(s.DB, settingSMTPFrom)
	smtpTo, _ := models.GetSetting(s.DB, settingSMTPTo)
	smtpSecurity, _ := models.GetSetting(s.DB, settingSMTPSecurity)
	smtpSkipVerify, _ := models.GetSetting(s.DB, settingSMTPSkipVerify)
	if smtpPort == "" {
		smtpPort = "587"
	}
	if smtpSecurity == "" {
		smtpSecurity = "starttls"
	}
	smtpConfigured := smtpHost != "" && smtpTo != ""

	turnstileSiteKey, _ := models.GetSetting(s.DB, settingTurnstileSiteKey)
	turnstileSecretKey, _ := models.GetSetting(s.DB, settingTurnstileSecretKey)

	// v2.5.0: captcha provider selector + reCAPTCHA keys alongside the
	// existing Turnstile keys. The UI renders a radio (Off / Turnstile /
	// reCAPTCHA); only the active provider's key fields are interactable.
	captchaProvider := normalizeCaptchaProvider(mustGetSetting(s.DB, settingCaptchaProvider))
	recaptchaSiteKey := mustGetSetting(s.DB, settingRecaptchaSiteKey)
	recaptchaSecretKey := mustGetSetting(s.DB, settingRecaptchaSecretKey)
	recaptchaMinScoreRaw := mustGetSetting(s.DB, settingRecaptchaMinScore)
	if strings.TrimSpace(recaptchaMinScoreRaw) == "" {
		recaptchaMinScoreRaw = fmt.Sprintf("%.1f", captchaDefaultMinScore)
	}

	// Timezone — admin-picked IANA zone for rendering timestamps. Empty =
	// fall back to TZ env var then UTC. See timezone.go for the priority
	// order and the dropdown options (commonTimezones).
	timezoneSaved, _ := models.GetSetting(s.DB, settingTimezone)

	serverIP := s.serverIP()
	cfProxiedStr, _ := models.GetSetting(s.DB, settingCFProxied)

	// v2.4.0: per-server public IPs. Load every Caddy server so the DNS
	// card can render one IP input per server. At least one IP is required
	// for managed DNS to work — either a server row has public_ip set or
	// the legacy global fallback is populated.
	caddyServers, _ := models.ListCaddyServers(s.DB)
	hasAnyServerIP := strings.TrimSpace(serverIP) != ""
	for _, sr := range caddyServers {
		if strings.TrimSpace(sr.PublicIP) != "" {
			hasAnyServerIP = true
			break
		}
	}

	// Build a view-model row per registered DNS provider so the template
	// can render the cards in a simple range loop. Each card gets:
	//   ID, DisplayName, DocsAnchor, Credentials (with "Configured" bool),
	//   Configured (bool summing all credential fields).
	type credView struct {
		dns.CredentialField
		Configured bool
		// Value is the stored plaintext. Only rendered for non-secret fields
		// (Namecheap's API user + whitelisted IP) — secret fields are never
		// echoed back to the page.
		Value string
	}
	type providerView struct {
		ID             string
		DisplayName    string
		DocsAnchor     string
		Credentials    []credView
		Configured     bool   // every field non-empty
		Enabled        bool   // Configured AND serverIP set
		ExtraFlags     map[string]any // per-provider extras (e.g. Cloudflare proxied toggle)
		// v2.4.7: zone allow-list. ZoneAllowlistRaw is the textarea value
		// (one domain per line for readability); ZoneAllowlist is the parsed
		// slice used to render the "N of M zones visible" hint.
		ZoneAllowlistRaw string
		ZoneAllowlist    []string
	}
	var providers []providerView
	for _, d := range dns.Descriptors() {
		pv := providerView{
			ID:          d.ID,
			DisplayName: d.DisplayName,
			DocsAnchor:  d.DocsAnchor,
			ExtraFlags:  map[string]any{},
		}
		allFilled := true
		for _, c := range d.Credentials {
			v, _ := models.GetSetting(s.DB, c.Key)
			set := v != ""
			if !set {
				allFilled = false
			}
			cv := credView{CredentialField: c, Configured: set}
			// Only expose stored value back to the page for non-secret fields.
			// Secrets stay keep-blank-to-preserve so they're never rendered
			// even in a password input's value attribute.
			if !c.Secret {
				cv.Value = v
			}
			pv.Credentials = append(pv.Credentials, cv)
		}
		pv.Configured = allFilled
		pv.Enabled = allFilled && hasAnyServerIP
		if d.ID == dns.Cloudflare {
			pv.ExtraFlags["Proxied"] = cfProxiedStr == "1"
		}
		// v2.4.7: load the zone allow-list for this provider so the
		// textarea renders with the current value. Render one domain per
		// line (nicer than CSV for hand-editing).
		pv.ZoneAllowlist = s.zoneAllowlist(d.ID)
		if len(pv.ZoneAllowlist) > 0 {
			pv.ZoneAllowlistRaw = strings.Join(pv.ZoneAllowlist, "\n")
		}
		providers = append(providers, pv)
	}

	// v2.7.0: visitor analytics toggle + IP-exclusion list. Loaded via a
	// helper in analytics.go so both the settings page and the POST handler
	// see the same field names.
	analyticsCfg := loadAnalyticsConfig(s.DB)
	var analyticsIngestSnap map[string]any
	if s.analyticsIngest != nil {
		snap := s.analyticsIngest.Stats()
		analyticsIngestSnap = map[string]any{
			"Connections": snap.Connections,
			"Events":      snap.Events,
			"Excluded":    snap.Excluded,
			"Errors":      snap.Errors,
			"LastEvent":   snap.LastEventAt,
			"Healthy":     snap.Events > 0 && time.Since(snap.LastEventAt) < 10*time.Minute,
		}
	}

	success := r.URL.Query().Get("saved") == "1"
	// "cleared=<provider-id>" is set by postClearDNSProvider's redirect.
	// Resolve it back to the pretty display name so the banner can say
	// "Cloudflare credentials cleared" instead of "cloudflare credentials
	// cleared". Unknown IDs are ignored silently.
	var clearedName string
	if cid := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("cleared"))); cid != "" {
		for _, pv := range providers {
			if pv.ID == cid {
				clearedName = pv.DisplayName
				break
			}
		}
	}
	s.render(w, r, "settings.html", map[string]any{
		"User":               s.currentUser(r),
		"WebhookURL":         webhookURL,
		"WebhookSecret":      mustGetSetting(s.DB, settingNotifyWebhookSecret),
		"DaysBefore":         daysBefore,
		"AIEnabled":          aiEnabledStr == "1",
		"AIOllamaURL":        aiOllamaURL,
		"AIOllamaModel":      aiOllamaModel,
		"AISystemPrompt":     aiSystemPrompt,
		"GlobalStripHeaders": globalStripHdrs,
		"SMTPHost":           smtpHost,
		"SMTPPort":           smtpPort,
		"SMTPUsername":       smtpUsername,
		"SMTPFrom":           smtpFrom,
		"SMTPTo":             smtpTo,
		"SMTPSecurity":       smtpSecurity,
		"SMTPSkipVerify":     smtpSkipVerify == "1",
		"SMTPConfigured":     smtpConfigured,
		"TurnstileSiteKey":   turnstileSiteKey,
		"TurnstileSecretKey": turnstileSecretKey,
		"TurnstileEnabled":   turnstileSiteKey != "" && turnstileSecretKey != "",
		// v2.5.0: captcha provider + reCAPTCHA keys
		"CaptchaProvider":        captchaProvider,
		"CaptchaDisabledByEnv":   captchaDisabledByEnv(),
		"RecaptchaSiteKey":       recaptchaSiteKey,
		"RecaptchaSecretKey":     recaptchaSecretKey,
		"RecaptchaMinScore":      recaptchaMinScoreRaw,
		"RecaptchaEnabled":       recaptchaSiteKey != "" && recaptchaSecretKey != "",
		// Timezone: Timezone is the saved DB value (may be ""). TimezoneActive
		// is what the server is *actually* rendering in right now — useful as
		// a "(currently: UTC)" hint when the DB value is empty.
		"Timezone":       timezoneSaved,
		"TimezoneActive": activeLocation().String(),
		"TimezoneOptions": commonTimezones,
		"ServerIP":           serverIP,
		"Servers":            caddyServers,
		"DNSProviders":       providers,
		// Back-compat aliases for any embed that still references the old
		// CF-centric keys. The template itself now uses DNSProviders +
		// ServerIP; these stay so custom layouts built against v2.2.x
		// don't crash during the upgrade cycle.
		"CFServerIP":  serverIP,
		"CFProxied":   cfProxiedStr == "1",
		"Success":     success,
		"ClearedName": clearedName,
		// v2.7.0: analytics card
		"AnalyticsEnabled":      analyticsCfg.Enabled,
		"AnalyticsTarget":       analyticsCfg.TargetRaw,
		"AnalyticsTargetPlaceholder": defaultAnalyticsIngestTarget,
		"AnalyticsExcludeRaw":   analyticsCfg.ExcludeRaw,
		"AnalyticsIngestStats":  analyticsIngestSnap,
		// v2.9.5: 2FA enforcement policy
		"Require2FA":      mustGetSetting(s.DB, settingRequire2FA),
		"RequireTOTP":     mustGetSetting(s.DB, settingRequireTOTP),
		// v2.10.0: trusted proxies + custom site title
		"TrustedProxies":  mustGetSetting(s.DB, settingTrustedProxies),
		"SiteTitle":       mustGetSetting(s.DB, settingSiteTitle),
		// v2.11.0: custom favicon + admin IP allowlist
		"FaviconURL":      mustGetSetting(s.DB, settingFaviconURL),
		"AdminAllowlist":  mustGetSetting(s.DB, settingAdminAllowlist),
		// v2.12.0: configurable session duration + global catch-all 404
		"SessionDays":        mustGetSetting(s.DB, settingSessionDays),
		"CatchAll404HTML":    mustGetSetting(s.DB, settingCatchAll404HTML),
		"GlobalMaintenance":    mustGetSetting(s.DB, settingGlobalMaintenance),
		"AutoSyncHours":        mustGetSetting(s.DB, settingAutoSyncHours),
		"ActivityLogDays":      mustGetSetting(s.DB, settingActivityLogDays),
		"MaxLoginAttempts":     mustGetSetting(s.DB, settingMaxLoginAttempts),
		"Section":              "settings",
	})
}

func (s *Server) postSettings(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	webhookURL := strings.TrimSpace(r.FormValue("webhook_url"))
	webhookSecret := strings.TrimSpace(r.FormValue("webhook_secret"))
	daysBeforeStr := strings.TrimSpace(r.FormValue("days_before"))
	daysBefore := defaultNotifyDaysBefore
	if d, err := strconv.Atoi(daysBeforeStr); err == nil && d > 0 {
		daysBefore = d
	}

	smtpHost := strings.TrimSpace(r.FormValue("smtp_host"))
	smtpPort := strings.TrimSpace(r.FormValue("smtp_port"))
	smtpUsername := strings.TrimSpace(r.FormValue("smtp_username"))
	smtpPassword := r.FormValue("smtp_password") // keep as-is (may contain spaces)
	smtpFrom := strings.TrimSpace(r.FormValue("smtp_from"))
	smtpTo := strings.TrimSpace(r.FormValue("smtp_to"))
	smtpSecurity := strings.TrimSpace(r.FormValue("smtp_security"))
	// Same hidden+checkbox pattern as analytics_enabled below — scan the
	// full PostForm slice for "1" because FormValue always returns the
	// hidden input's "0" when both are submitted. See note on
	// analytics_enabled for the full story. This toggle had the bug from
	// day one; v2.7.1 fixes it here too so anyone who actually needs to
	// disable TLS cert verification (self-signed SMTP host) can finally
	// persist the setting.
	smtpSkipVerify := "0"
	for _, v := range r.PostForm["smtp_skip_verify"] {
		if v == "1" {
			smtpSkipVerify = "1"
			break
		}
	}
	if smtpPort == "" {
		smtpPort = "587"
	}
	if smtpSecurity == "" {
		smtpSecurity = "starttls"
	}

	turnstileSiteKey := strings.TrimSpace(r.FormValue("turnstile_site_key"))
	turnstileSecretKey := strings.TrimSpace(r.FormValue("turnstile_secret_key"))

	// v2.5.0: captcha provider + reCAPTCHA keys. The provider radio
	// submits "off" / "turnstile" / "recaptcha"; normalizeCaptchaProvider
	// coerces anything else to "off" so a tampered POST can't set an
	// unknown mode that would 500 loadCaptchaConfig.
	captchaProvider := normalizeCaptchaProvider(r.FormValue("captcha_provider"))
	recaptchaSiteKey := strings.TrimSpace(r.FormValue("recaptcha_site_key"))
	recaptchaSecretKey := strings.TrimSpace(r.FormValue("recaptcha_secret_key"))
	// reCAPTCHA v3 threshold. Accept any 0.0–1.0 float; out-of-range or
	// unparseable values fall back to the default at load time. We still
	// store what the admin typed (after trim) so the next render of the
	// settings page shows their input, not the silent coercion.
	recaptchaMinScore := strings.TrimSpace(r.FormValue("recaptcha_min_score"))
	if recaptchaMinScore != "" {
		if _, err := strconv.ParseFloat(recaptchaMinScore, 64); err != nil {
			http.Error(w, "invalid recaptcha_min_score: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Timezone — the dropdown submits an IANA zone name (or empty string
	// for "use TZ env / UTC"). The "Other…" option in the UI falls back to
	// a free-text input that submits the same field. Validate via
	// time.LoadLocation; if bad, bail with 400 so we don't silently save
	// garbage the next boot can't decode.
	timezone := strings.TrimSpace(r.FormValue("timezone"))
	if timezone != "" {
		if _, err := time.LoadLocation(timezone); err != nil {
			http.Error(w, "invalid timezone: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// v2.7.0: analytics toggle + ingest target + exclude-IPs. The target
	// may be blank — loadAnalyticsConfig substitutes the default at read
	// time, so we store the admin's literal input (possibly "").
	//
	// The hidden+checkbox pattern in the template submits
	// "analytics_enabled=0&analytics_enabled=1" when checked (hidden wins
	// submission order per HTML5 tree-order, checkbox is appended after).
	// r.FormValue returns the FIRST value, which is always the hidden "0",
	// so we have to scan the full r.PostForm slice to find the checkbox's
	// "1" when present. Matches the browser's "checked box overrides its
	// hidden sibling" intent. v2.7.1 fix — v2.7.0 used FormValue and the
	// toggle silently always stayed off.
	analyticsEnabled := "0"
	for _, v := range r.PostForm["analytics_enabled"] {
		if v == "1" {
			analyticsEnabled = "1"
			break
		}
	}
	analyticsTarget := strings.TrimSpace(r.FormValue("analytics_ingest_target"))
	analyticsExclude := r.FormValue("analytics_exclude_ips") // preserve whitespace for textarea re-render

	// Shared server IP — the public IP every DNS provider writes as its
	// record content. Form field name stays as "cf_server_ip" for
	// backwards compatibility with bookmarked form submissions; the
	// template can submit it under either name.
	newServerIP := strings.TrimSpace(r.FormValue("server_ip"))
	if newServerIP == "" {
		newServerIP = strings.TrimSpace(r.FormValue("cf_server_ip"))
	}
	// Same FormValue/hidden-checkbox bug fix as the other two toggles above.
	// v2.7.1 — previously admins could tick the Cloudflare orange-cloud box
	// and hit Save, and the setting would silently remain off.
	cfProxied := "0"
	for _, v := range r.PostForm["cf_proxied"] {
		if v == "1" {
			cfProxied = "1"
			break
		}
	}
	// Snapshot the current server IP before overwriting — used below to
	// detect whether we need to retarget every managed DNS record.
	oldServerIP := s.serverIP()

	kv := map[string]string{
		settingNotifyWebhookURL:    webhookURL,
		settingNotifyWebhookSecret: webhookSecret,
		settingNotifyDaysBefore:    strconv.Itoa(daysBefore),
		settingSMTPHost: smtpHost,
		// v2.11.15: AI assistant settings.
		settingAIEnabled: func() string {
			for _, v := range r.PostForm["ai_enabled"] {
				if v == "1" {
					return "1"
				}
			}
			return "0"
		}(),
		settingAIOllamaURL:    strings.TrimSpace(r.FormValue("ai_ollama_url")),
		settingAIOllamaModel:  strings.TrimSpace(r.FormValue("ai_ollama_model")),
		settingAISystemPrompt:             r.FormValue("ai_system_prompt"), // preserve whitespace + newlines
		settingGlobalStripResponseHeaders: strings.TrimSpace(r.FormValue("global_strip_response_headers")),
		// v2.9.5: 2FA enforcement policy (checkbox → "on" when checked).
		settingRequire2FA: func() string {
			if r.FormValue("require_2fa") == "on" {
				return "1"
			}
			return "0"
		}(),
		// require_totp toggle uses value="1" checkbox pattern.
		settingRequireTOTP: func() string {
			if r.FormValue("require_totp") == "1" {
				return "1"
			}
			return "0"
		}(),
		settingSMTPPort:           smtpPort,
		settingSMTPUsername:       smtpUsername,
		settingSMTPFrom:           smtpFrom,
		settingSMTPTo:             smtpTo,
		settingSMTPSecurity:       smtpSecurity,
		settingSMTPSkipVerify:     smtpSkipVerify,
		settingTurnstileSiteKey:   turnstileSiteKey,
		settingTurnstileSecretKey: turnstileSecretKey,
		settingCaptchaProvider:    captchaProvider,
		settingRecaptchaSiteKey:   recaptchaSiteKey,
		settingRecaptchaSecretKey: recaptchaSecretKey,
		settingRecaptchaMinScore:  recaptchaMinScore,
		settingTimezone:           timezone,
		settingServerIP:           newServerIP,
		settingCFProxied:          cfProxied,
		// v2.7.0: visitor analytics
		settingAnalyticsEnabled:      analyticsEnabled,
		settingAnalyticsIngestTarget: analyticsTarget,
		settingAnalyticsExcludeIPs:   analyticsExclude,
		// v2.10.0: trusted proxies + custom site title
		settingTrustedProxies: strings.TrimSpace(r.FormValue("trusted_proxies")),
		settingSiteTitle:      strings.TrimSpace(r.FormValue("site_title")),
		// v2.11.0: custom favicon + admin IP allowlist
		settingFaviconURL:     strings.TrimSpace(r.FormValue("favicon_url")),
		settingAdminAllowlist: strings.TrimSpace(r.FormValue("admin_allowlist")),
		// v2.12.0: configurable session duration + global catch-all 404
		settingCatchAll404HTML: strings.TrimSpace(r.FormValue("catch_all_404_html")),
		// Global maintenance mode: checkbox → "1"/"0"
		settingGlobalMaintenance: func() string {
			if r.FormValue("global_maintenance") == "1" {
				return "1"
			}
			return "0"
		}(),
	}
	if sessionDays := strings.TrimSpace(r.FormValue("session_duration_days")); sessionDays != "" {
		kv[settingSessionDays] = sessionDays
	}
	// Auto-sync hours: "0" or empty = disabled.
	if autoSyncHours := strings.TrimSpace(r.FormValue("auto_sync_hours")); autoSyncHours != "" {
		if h, err := strconv.Atoi(autoSyncHours); err == nil && h >= 0 {
			kv[settingAutoSyncHours] = strconv.Itoa(h)
		}
	} else {
		kv[settingAutoSyncHours] = "0"
	}
	// Activity log retention days: 0 = keep forever.
	if aldStr := strings.TrimSpace(r.FormValue("activity_log_days")); aldStr != "" {
		if d, err := strconv.Atoi(aldStr); err == nil && d >= 0 {
			kv[settingActivityLogDays] = strconv.Itoa(d)
		}
	} else {
		kv[settingActivityLogDays] = "0"
	}
	// Max login attempts per IP: 0 = no limit.
	if mlaStr := strings.TrimSpace(r.FormValue("max_login_attempts")); mlaStr != "" {
		if n, err := strconv.Atoi(mlaStr); err == nil && n >= 0 {
			kv[settingMaxLoginAttempts] = strconv.Itoa(n)
		}
	} else {
		kv[settingMaxLoginAttempts] = "0"
	}

	// Walk every registered DNS provider and pick up credential fields
	// from the form. Same keep-blank-to-preserve UX as SMTP password:
	// leaving a field empty keeps the stored value, so users don't have
	// to re-enter secrets just to toggle a checkbox. The one exception
	// is the Namecheap client IP — it's not a secret and users will
	// expect to edit it inline, so we always overwrite that field.
	nonSecretKeys := map[string]bool{
		settingNCAPIUser:  true,
		settingNCClientIP: true,
	}
	for _, d := range dns.Descriptors() {
		for _, c := range d.Credentials {
			v := strings.TrimSpace(r.FormValue(c.Key))
			if v == "" && !nonSecretKeys[c.Key] {
				// Empty + secret field → preserve existing value.
				continue
			}
			kv[c.Key] = v
		}
		// v2.4.7: per-provider zone allow-list. Always overwrite — an
		// empty textarea means "remove the allow-list, accept every zone
		// again". Normalised form (lowercase, deduped, comma-separated)
		// is what we persist, even though the textarea offers lines for
		// readability.
		allowRaw := r.FormValue(d.ID + "_zone_allowlist")
		kv[zoneAllowlistKey(d.ID)] = strings.Join(parseZoneAllowlist(allowRaw), ",")
	}

	// SMTP password stays keep-blank-to-preserve.
	if smtpPassword != "" {
		kv[settingSMTPPassword] = smtpPassword
	}
	for k, v := range kv {
		if err := models.SetSetting(s.DB, k, v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Hot-apply the timezone: updates the atomic pointer every template
	// fmtDate call reads from, so the redirect back to /settings below
	// already renders in the new zone without waiting for a restart. Error
	// is ignored — we already validated above, so LoadLocation can't fail
	// here barring a race with tzdata being unloaded (won't happen in a
	// container with /usr/share/zoneinfo baked in).
	_ = setActiveLocation(timezone)
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "settings_update", "notify+smtp", smtpHost, true)

	// v2.7.0: push the analytics toggle through to the live ingest +
	// Caddy admin API after saving to the settings table. Errors are
	// logged but not surfaced as a page error — the saved row stays, and
	// the Settings page's "Analytics" card reflects the current wiring
	// state so the admin can retry. This avoids a half-saved "settings
	// didn't persist, Caddy pivoted anyway" that would be very confusing.
	if err := s.applyAnalyticsToggle(loadAnalyticsConfig(s.DB)); err != nil {
		log.Printf("settings: analytics toggle: %v", err)
	}

	// v2.4.0: per-server public IP update. The settings form submits one
	// server_ip_<id> field per Caddy server. For each one that changed,
	// retarget only that server's managed DNS records in the background.
	//
	// We collect both the IDs whose IP changed and the new IP each maps to,
	// then fan out one goroutine per server. No fan-out if nothing changed.
	if servers, err := models.ListCaddyServers(s.DB); err == nil {
		type retarget struct {
			serverID int64
			newIP    string
		}
		var pending []retarget
		for _, sr := range servers {
			field := fmt.Sprintf("server_ip_%d", sr.ID)
			// Only act if the form actually submitted this field — guards
			// against accidental wipes from partial form POSTs.
			if _, ok := r.Form[field]; !ok {
				continue
			}
			newIP := strings.TrimSpace(r.FormValue(field))
			old, err := models.SetCaddyServerPublicIP(s.DB, sr.ID, newIP)
			if err != nil {
				log.Printf("settings: save public_ip for server %d: %v", sr.ID, err)
				continue
			}
			if newIP != "" && newIP != strings.TrimSpace(old) {
				pending = append(pending, retarget{serverID: sr.ID, newIP: newIP})
			}
		}
		for _, t := range pending {
			sid, ip := t.serverID, t.newIP
			go s.dnsUpdateAllRecords(sid, ip)
		}
	}

	// Legacy global-IP fallback retarget: only fires when the per-server
	// table is empty (brand-new databases or users who haven't filled in
	// the new per-server column). Passing serverID=0 walks every managed
	// host so pre-v2.4.0 behaviour still works.
	if newServerIP != "" && newServerIP != oldServerIP {
		go s.dnsUpdateAllRecords(0, newServerIP)
	}

	// v2.12.18: auto-sync Caddy after a settings save so changes that
	// affect the live config (global strip-headers, catch-all 404 HTML,
	// global maintenance toggle, etc.) take effect immediately. Without
	// this, users had to manually click Sync Caddy after Save and
	// wondered why their setting "didn't work." Best-effort — failures
	// are logged but don't block the redirect.
	go func(serverID int64) {
		if err := s.syncCaddy(serverID, false); err != nil {
			log.Printf("settings: auto-sync after save failed (non-fatal): %v", err)
		}
	}(s.currentServerID(r))

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// postClearDNSProvider wipes every stored credential for a single DNS
// provider (and its provider-specific flags, e.g. Cloudflare's cf_proxied
// toggle). The provider ID comes from the URL path. Storing an empty string
// via SetSetting is how we "delete" — GetSetting returns "" for both
// "never written" and "written as empty", and every dns.Build call treats
// empty strings as "provider not configured".
//
// Admin-gated at the router level; also logs an audit entry so a
// credential wipe is traceable the same way a save is.
func (s *Server) postClearDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "id")))
	keys, ok := dnsProviderCredKeys[id]
	if !ok {
		http.Error(w, "unknown DNS provider", http.StatusBadRequest)
		return
	}

	for _, k := range keys {
		if err := models.SetSetting(s.DB, k, ""); err != nil {
			http.Error(w, "failed to clear credentials: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Cloudflare also stores a per-provider flag (orange-cloud proxied) that
	// should be reset alongside the API token — otherwise re-entering a
	// token later would silently inherit the previous proxied state.
	if id == dns.Cloudflare {
		_ = models.SetSetting(s.DB, settingCFProxied, "")
	}
	// v2.4.7: also clear the zone allow-list. A user wiping the credentials
	// usually wants a clean slate — a stale allow-list sitting around means
	// the next set of keys they enter would silently be restricted by rules
	// they've forgotten about.
	_ = models.SetSetting(s.DB, zoneAllowlistKey(id), "")

	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r),
		"dns_provider_clear", "dns:"+id, "", true)

	http.Redirect(w, r, "/settings?cleared="+url.QueryEscape(id), http.StatusSeeOther)
}

func (s *Server) postTestWebhook(w http.ResponseWriter, r *http.Request) {
	// Always read the webhook URL from the trusted database — never from the
	// request body — to prevent server-side request forgery (SSRF).
	webhookURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL)
	if webhookURL == "" {
		http.Error(w, "No webhook URL configured. Save your settings first.", http.StatusBadRequest)
		return
	}
	// Validate that the stored URL is a safe http/https endpoint.
	parsedWebhook, parseErr := url.Parse(webhookURL)
	if parseErr != nil || (parsedWebhook.Scheme != "http" && parsedWebhook.Scheme != "https") || parsedWebhook.Host == "" {
		http.Error(w, "Invalid webhook URL in settings — must begin with http:// or https://", http.StatusBadRequest)
		return
	}
	payload := map[string]any{
		"event":     "test",
		"message":   "CaddyUI webhook test",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(parsedWebhook.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Webhook POST failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"status_code": resp.StatusCode,
	})
}

func (s *Server) postTestEmail(w http.ResponseWriter, r *http.Request) {
	subject := "[CaddyUI] Test email"
	body := fmt.Sprintf(
		"This is a test notification from CaddyUI.\n\nIf you received this, your SMTP configuration is working correctly.\n\nSent at: %s\n",
		time.Now().UTC().Format(time.RFC3339),
	)
	if err := sendEmail(s.DB, subject, body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
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
	// Seed with last 50 events for initial load.
	events, err := models.RecentAccessEvents(s.DB, 0, 50)
	if err != nil {
		log.Printf("live-traffic: query: %v", err)
	}
	s.render(w, r, "live_traffic.html", map[string]any{
		"User":    u,
		"Events":  events,
		"Section": "live_traffic",
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

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, err := models.RecentAccessEvents(s.DB, cursor, 100)
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

// ─── REST JSON API v1 ─────────────────────────────────────────────────────────
//
// All endpoints are under /api/v1/ and live inside the requireAuth middleware
// group, so both session cookies and Bearer API tokens are accepted.
// Write endpoints (POST/PUT/DELETE) additionally require a write-scoped token
// or an admin/write role — the requireWrite middleware enforces that at the
// chi group level.

// apiProxyHostInput is the JSON request body for create / update.
type apiProxyHostInput struct {
	Domains                string `json:"domains"`
	ForwardScheme          string `json:"forward_scheme"`
	ForwardHost            string `json:"forward_host"`
	ForwardPort            int    `json:"forward_port"`
	WebsocketSupport       bool   `json:"websocket_support"`
	BlockCommonExploits    bool   `json:"block_common_exploits"`
	SSLEnabled             bool   `json:"ssl_enabled"`
	SSLForced              bool   `json:"ssl_forced"`
	HTTP2Support           bool   `json:"http2_support"`
	Enabled                bool   `json:"enabled"`
	CertificateID          int64  `json:"certificate_id"`
	BasicAuthEnabled       bool   `json:"basicauth_enabled"`
	AccessList             string `json:"access_list"`
	IPBlocklist            string `json:"ip_blocklist"`
	ExtraUpstreams         string `json:"extra_upstreams"`
	CompressionEnabled     bool   `json:"compression_enabled"`
	SecurityHeadersEnabled bool   `json:"security_headers_enabled"`
	TLSMinVersion          string `json:"tls_min_version"`
	MaintenanceMode        bool   `json:"maintenance_mode"`
	MaintenanceMsg         string `json:"maintenance_msg"`
	MaxRequestBodyMB       int    `json:"max_request_body_mb"`
	StickySessions         bool   `json:"sticky_sessions"`
	LBPolicy               string `json:"lb_policy"`
	UpstreamTimeoutSec     int    `json:"upstream_timeout_sec"`
	CORSEnabled            bool   `json:"cors_enabled"`
	CORSOrigins            string `json:"cors_origins"`
	HealthCheckURI         string `json:"health_check_uri"`
	HealthCheckIntervalSec int    `json:"health_check_interval_sec"`
	HealthCheckMethod      string `json:"health_check_method"`
	KeepaliveConns         int    `json:"keepalive_conns"`
	Tags                   string `json:"tags"`
	Notes                  string `json:"notes"`
	DisableAccessLog       bool   `json:"disable_access_log"`
	AddRequestID           bool   `json:"add_request_id"`
	StripRespHeaders       string `json:"strip_resp_headers"`
	BlockedAgents          string `json:"blocked_agents"`
	UpstreamSNI            string `json:"upstream_sni"`
	HSTSPreload            bool   `json:"hsts_preload"`
	MaxConnsPerHost        int    `json:"max_conns_per_host"`
	UpstreamRetries        int    `json:"upstream_retries"`
	ForceHTTP1             bool   `json:"force_http1"`
	ProxyProtocol          string `json:"proxy_protocol"`
}

// proxyHostToAPIMap converts a ProxyHost to a JSON-serialisable map.
func proxyHostToAPIMap(p *models.ProxyHost) map[string]any {
	return map[string]any{
		"id":                       p.ID,
		"server_id":                p.ServerID,
		"domains":                  p.Domains,
		"forward_scheme":           p.ForwardScheme,
		"forward_host":             p.ForwardHost,
		"forward_port":             p.ForwardPort,
		"websocket_support":        p.WebsocketSupport,
		"block_common_exploits":    p.BlockCommonExploits,
		"ssl_enabled":              p.SSLEnabled,
		"ssl_forced":               p.SSLForced,
		"http2_support":            p.HTTP2Support,
		"enabled":                  p.Enabled,
		"certificate_id":           p.CertificateID,
		"basicauth_enabled":        p.BasicAuthEnabled,
		"access_list":              p.AccessList,
		"ip_blocklist":             p.IPBlocklist,
		"extra_upstreams":          p.ExtraUpstreams,
		"compression_enabled":      p.CompressionEnabled,
		"security_headers_enabled": p.SecurityHeadersEnabled,
		"tls_min_version":          p.TLSMinVersion,
		"maintenance_mode":         p.MaintenanceMode,
		"maintenance_msg":          p.MaintenanceMsg,
		"max_request_body_mb":      p.MaxRequestBodyMB,
		"sticky_sessions":          p.StickySessions,
		"lb_policy":                p.LBPolicy,
		"upstream_timeout_sec":     p.UpstreamTimeoutSec,
		"cors_enabled":             p.CORSEnabled,
		"cors_origins":             p.CORSOrigins,
		"health_check_uri":         p.HealthCheckURI,
		"health_check_interval_sec": p.HealthCheckIntervalSec,
		"health_check_method":      p.HealthCheckMethod,
		"keepalive_conns":          p.KeepaliveConns,
		"tags":                     p.Tags,
		"notes":                    p.Notes,
		"disable_access_log":       p.DisableAccessLog,
		"add_request_id":           p.AddRequestID,
		"strip_resp_headers":       p.StripRespHeaders,
		"blocked_agents":           p.BlockedAgents,
		"upstream_sni":             p.UpstreamSNI,
		"hsts_preload":             p.HSTSPreload,
		"max_conns_per_host":       p.MaxConnsPerHost,
		"upstream_retries":         p.UpstreamRetries,
		"force_http1":              p.ForceHTTP1,
		"proxy_protocol":           p.ProxyProtocol,
		"owner_email":              p.OwnerEmail,
		"created_at":               p.CreatedAt,
		"updated_at":               p.UpdatedAt,
	}
}

// writeJSON is a convenience wrapper that sets Content-Type and encodes v as JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// GET /api/v1/proxy-hosts
func (s *Server) apiV1ListProxyHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	serverID := s.currentServerID(r)
	hosts, err := models.ListProxyHosts(s.DB, serverID, cu.ID, cu.IsAdmin, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(hosts))
	for i := range hosts {
		out = append(out, proxyHostToAPIMap(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/proxy-hosts/{id}
func (s *Server) apiV1GetProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if cu == nil || (!cu.IsAdmin && ph.OwnerID.Valid && ph.OwnerID.Int64 != cu.ID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, proxyHostToAPIMap(ph))
}

// POST /api/v1/proxy-hosts
func (s *Server) apiV1CreateProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp apiProxyHostInput
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Domains == "" || inp.ForwardHost == "" || inp.ForwardPort == 0 {
		writeJSONError(w, http.StatusBadRequest, "domains, forward_host, and forward_port are required")
		return
	}
	if inp.ForwardScheme == "" {
		inp.ForwardScheme = "http"
	}
	if inp.HealthCheckMethod == "" {
		inp.HealthCheckMethod = "GET"
	}
	ph := &models.ProxyHost{
		Domains: inp.Domains, ForwardScheme: inp.ForwardScheme,
		ForwardHost: inp.ForwardHost, ForwardPort: inp.ForwardPort,
		WebsocketSupport: inp.WebsocketSupport, BlockCommonExploits: inp.BlockCommonExploits,
		SSLEnabled: inp.SSLEnabled, SSLForced: inp.SSLForced, HTTP2Support: inp.HTTP2Support,
		Enabled: inp.Enabled, CertificateID: inp.CertificateID,
		BasicAuthEnabled: inp.BasicAuthEnabled, BasicAuthUsers: "[]",
		AccessList: inp.AccessList, IPBlocklist: inp.IPBlocklist,
		ExtraUpstreams: func() string {
			if inp.ExtraUpstreams == "" {
				return "[]"
			}
			return inp.ExtraUpstreams
		}(),
		CompressionEnabled: inp.CompressionEnabled, SecurityHeadersEnabled: inp.SecurityHeadersEnabled,
		TLSMinVersion: inp.TLSMinVersion,
		MaintenanceMode: inp.MaintenanceMode, MaintenanceMsg: inp.MaintenanceMsg,
		MaxRequestBodyMB: inp.MaxRequestBodyMB, StickySessions: inp.StickySessions,
		LBPolicy: inp.LBPolicy, UpstreamTimeoutSec: inp.UpstreamTimeoutSec,
		CORSEnabled: inp.CORSEnabled, CORSOrigins: func() string {
			if inp.CORSOrigins == "" { return "*" }; return inp.CORSOrigins
		}(),
		HealthCheckURI: inp.HealthCheckURI, HealthCheckIntervalSec: func() int {
			if inp.HealthCheckIntervalSec <= 0 { return 30 }; return inp.HealthCheckIntervalSec
		}(),
		HealthCheckMethod: inp.HealthCheckMethod, KeepaliveConns: inp.KeepaliveConns,
		Tags: inp.Tags, Notes: inp.Notes,
		DisableAccessLog: inp.DisableAccessLog, AddRequestID: inp.AddRequestID,
		StripRespHeaders: inp.StripRespHeaders, BlockedAgents: inp.BlockedAgents,
		UpstreamSNI: inp.UpstreamSNI, HSTSPreload: inp.HSTSPreload,
		MaxConnsPerHost: inp.MaxConnsPerHost, UpstreamRetries: inp.UpstreamRetries,
		ForceHTTP1: inp.ForceHTTP1, ProxyProtocol: inp.ProxyProtocol,
		BasicAuthRealm: "Restricted", CustomReqHeaders: "{}", CustomRespHeaders: "{}",
		URLRewrites: "[]",
	}
	serverID := s.currentServerID(r)
	ownerID := cu.ID
	if cu.IsAdmin {
		ownerID = 0
	}
	newID, err := models.CreateProxyHost(s.DB, serverID, ownerID, ph)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ph.ID = newID
	ph.ServerID = serverID
	_ = models.LogActivity(s.DB, serverID, cu.Email, "proxy_create", fmt.Sprintf("proxy:%d", newID), ph.Domains, true)
	s.syncCaddy(serverID, false)
	created, _ := models.GetProxyHost(s.DB, newID)
	if created == nil {
		created = ph
	}
	writeJSON(w, http.StatusCreated, proxyHostToAPIMap(created))
}

// PUT /api/v1/proxy-hosts/{id}
func (s *Server) apiV1UpdateProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetProxyHost(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if cu != nil && !cu.IsAdmin && existing.OwnerID.Valid && existing.OwnerID.Int64 != cu.ID {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp apiProxyHostInput
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	// Merge: any field not supplied keeps the existing value.
	if inp.Domains != "" { existing.Domains = inp.Domains }
	if inp.ForwardScheme != "" { existing.ForwardScheme = inp.ForwardScheme }
	if inp.ForwardHost != "" { existing.ForwardHost = inp.ForwardHost }
	if inp.ForwardPort != 0 { existing.ForwardPort = inp.ForwardPort }
	existing.WebsocketSupport = inp.WebsocketSupport
	existing.BlockCommonExploits = inp.BlockCommonExploits
	existing.SSLEnabled = inp.SSLEnabled
	existing.SSLForced = inp.SSLForced
	existing.HTTP2Support = inp.HTTP2Support
	existing.Enabled = inp.Enabled
	existing.MaintenanceMode = inp.MaintenanceMode
	if inp.Tags != "" { existing.Tags = inp.Tags }
	if inp.Notes != "" { existing.Notes = inp.Notes }
	if inp.AccessList != "" { existing.AccessList = inp.AccessList }
	if inp.IPBlocklist != "" { existing.IPBlocklist = inp.IPBlocklist }
	if inp.LBPolicy != "" { existing.LBPolicy = inp.LBPolicy }
	if err := models.UpdateProxyHost(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, existing.ServerID, s.currentUserEmail(r), "proxy_update", fmt.Sprintf("proxy:%d", id), existing.Domains, true)
	s.syncCaddy(existing.ServerID, existing.CertificateID != 0)
	updated, _ := models.GetProxyHost(s.DB, id)
	if updated == nil { updated = existing }
	writeJSON(w, http.StatusOK, proxyHostToAPIMap(updated))
}

// DELETE /api/v1/proxy-hosts/{id}
func (s *Server) apiV1DeleteProxyHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if cu != nil && !cu.IsAdmin && ph.OwnerID.Valid && ph.OwnerID.Int64 != cu.ID {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if ph.DNSRecordID != "" {
		s.dnsDeleteRecord(ph.DNSProvider, ph.DNSZoneID, ph.DNSZoneName, ph.DNSRecordID)
	}
	if err := models.DeleteProxyHost(s.DB, id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, ph.ServerID, s.currentUserEmail(r), "proxy_delete", fmt.Sprintf("proxy:%d", id), ph.Domains, true)
	s.syncCaddy(ph.ServerID, false)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// POST /api/v1/proxy-hosts/{id}/toggle
func (s *Server) apiV1ToggleProxyHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	ph.Enabled = !ph.Enabled
	if err := models.UpdateProxyHost(s.DB, ph); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.syncCaddy(ph.ServerID, false)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": ph.Enabled})
}

// POST /api/v1/proxy-hosts/{id}/maintenance
func (s *Server) apiV1ToggleMaintenanceProxyHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ph, err := models.GetProxyHost(s.DB, id)
	if err != nil || ph == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	// Accept optional JSON body {"maintenance": true/false}; default = toggle.
	var body struct {
		Maintenance *bool `json:"maintenance"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Maintenance != nil {
		ph.MaintenanceMode = *body.Maintenance
	} else {
		ph.MaintenanceMode = !ph.MaintenanceMode
	}
	if err := models.UpdateProxyHost(s.DB, ph); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.syncCaddy(ph.ServerID, false)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "maintenance_mode": ph.MaintenanceMode})
}

// ─── Redirection Host REST API ────────────────────────────────────────────────

func redirectionHostToAPIMap(r *models.RedirectionHost) map[string]any {
	return map[string]any{
		"id":                r.ID,
		"domains":           r.Domains,
		"forward_scheme":    r.ForwardScheme,
		"forward_domain":    r.ForwardDomain,
		"forward_http_code": r.ForwardHTTPCode,
		"preserve_path":     r.PreservePath,
		"ssl_enabled":       r.SSLEnabled,
		"ssl_forced":        r.SSLForced,
		"enabled":           r.Enabled,
		"certificate_id":    r.CertificateID,
		"tags":              r.Tags,
		"notes":             r.Notes,
		"owner_email":       r.OwnerEmail,
		"created_at":        r.CreatedAt,
		"updated_at":        r.UpdatedAt,
	}
}

// GET /api/v1/redirection-hosts
func (s *Server) apiV1ListRedirectionHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	hosts, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), cu.ID, cu.IsAdmin, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(hosts))
	for i := range hosts {
		out = append(out, redirectionHostToAPIMap(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/redirection-hosts/{id}
func (s *Server) apiV1GetRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rh, err := models.GetRedirectionHost(s.DB, id)
	if err != nil || rh == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, redirectionHostToAPIMap(rh))
}

// POST /api/v1/redirection-hosts
func (s *Server) apiV1CreateRedirectionHost(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp struct {
		Domains         string `json:"domains"`
		ForwardScheme   string `json:"forward_scheme"`
		ForwardDomain   string `json:"forward_domain"`
		ForwardHTTPCode int    `json:"forward_http_code"`
		PreservePath    bool   `json:"preserve_path"`
		SSLEnabled      bool   `json:"ssl_enabled"`
		SSLForced       bool   `json:"ssl_forced"`
		Enabled         bool   `json:"enabled"`
		CertificateID   int64  `json:"certificate_id"`
		Tags            string `json:"tags"`
		Notes           string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Domains == "" || inp.ForwardDomain == "" {
		writeJSONError(w, http.StatusBadRequest, "domains and forward_domain are required")
		return
	}
	if inp.ForwardScheme == "" { inp.ForwardScheme = "auto" }
	if inp.ForwardHTTPCode == 0 { inp.ForwardHTTPCode = 301 }
	rh := &models.RedirectionHost{
		Domains: inp.Domains, ForwardScheme: inp.ForwardScheme,
		ForwardDomain: inp.ForwardDomain, ForwardHTTPCode: inp.ForwardHTTPCode,
		PreservePath: inp.PreservePath, SSLEnabled: inp.SSLEnabled, SSLForced: inp.SSLForced,
		Enabled: inp.Enabled, CertificateID: inp.CertificateID,
		Tags: inp.Tags, Notes: inp.Notes,
	}
	serverID := s.currentServerID(r)
	ownerID := int64(0)
	if !cu.IsAdmin { ownerID = cu.ID }
	newID, err := models.CreateRedirectionHost(s.DB, serverID, ownerID, rh)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "redirect_create", fmt.Sprintf("redir:%d", newID), rh.Domains, true)
	s.syncCaddy(serverID, false)
	created, _ := models.GetRedirectionHost(s.DB, newID)
	if created == nil { created = rh; created.ID = newID }
	writeJSON(w, http.StatusCreated, redirectionHostToAPIMap(created))
}

// PUT /api/v1/redirection-hosts/{id}
func (s *Server) apiV1UpdateRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRedirectionHost(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	var inp struct {
		Domains         string `json:"domains"`
		ForwardScheme   string `json:"forward_scheme"`
		ForwardDomain   string `json:"forward_domain"`
		ForwardHTTPCode int    `json:"forward_http_code"`
		PreservePath    bool   `json:"preserve_path"`
		SSLEnabled      bool   `json:"ssl_enabled"`
		SSLForced       bool   `json:"ssl_forced"`
		Enabled         bool   `json:"enabled"`
		Tags            string `json:"tags"`
		Notes           string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Domains != "" { existing.Domains = inp.Domains }
	if inp.ForwardScheme != "" { existing.ForwardScheme = inp.ForwardScheme }
	if inp.ForwardDomain != "" { existing.ForwardDomain = inp.ForwardDomain }
	if inp.ForwardHTTPCode != 0 { existing.ForwardHTTPCode = inp.ForwardHTTPCode }
	existing.PreservePath = inp.PreservePath
	existing.SSLEnabled = inp.SSLEnabled
	existing.SSLForced = inp.SSLForced
	existing.Enabled = inp.Enabled
	if inp.Tags != "" { existing.Tags = inp.Tags }
	if inp.Notes != "" { existing.Notes = inp.Notes }
	if err := models.UpdateRedirectionHost(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_update", fmt.Sprintf("redir:%d", id), existing.Domains, true)
	s.syncCaddy(s.currentServerID(r), false)
	updated, _ := models.GetRedirectionHost(s.DB, id)
	if updated == nil { updated = existing }
	writeJSON(w, http.StatusOK, redirectionHostToAPIMap(updated))
}

// DELETE /api/v1/redirection-hosts/{id}
func (s *Server) apiV1DeleteRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := models.DeleteRedirectionHost(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_delete", fmt.Sprintf("redir:%d", id), "", true)
	s.syncCaddy(s.currentServerID(r), false)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// POST /api/v1/redirection-hosts/{id}/toggle
func (s *Server) apiV1ToggleRedirectionHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	enabled, err := models.ToggleRedirectionHost(s.DB, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found or error: "+err.Error())
		return
	}
	rh, _ := models.GetRedirectionHost(s.DB, id)
	if rh != nil { s.syncCaddy(s.currentServerID(r), false) }
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": enabled})
}


