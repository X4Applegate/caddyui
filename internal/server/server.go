package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
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
}

// SetAnalyticsIngest plumbs the analytics ingest listener into the server
// so handlers can surface its stats on /analytics and /settings. Called
// once at startup from main.go after the ingest listener has bound.
// Passing nil is valid and disables the stats card — happens when the
// CADDYUI_INGEST_LISTEN env var is blank or the bind failed at startup.
func (s *Server) SetAnalyticsIngest(ing *analytics.Ingest) {
	s.analyticsIngest = ing
}

func New(db *sql.DB, caddyClient *caddy.Client, templates fs.FS, static fs.FS, caddyfilePath string, version string) (*Server, error) {
	tpl, err := parseTemplates(templates)
	if err != nil {
		return nil, err
	}
	// Resolve the active timezone once at startup so the very first render
	// uses the admin's picked zone (DB) rather than whatever time.Local
	// happens to be. Priority: DB value → TZ env var → UTC. See timezone.go.
	loc := loadActiveLocation(db)
	log.Printf("timezone: rendering timestamps in %s", loc)
	return &Server{
		DB:             db,
		Caddy:          caddyClient,
		Templates:      tpl,
		Static:         static,
		CaddyfilePath:  caddyfilePath,
		Version:        version,
		healthFailures: map[int64]int{},
		appHealth:      map[int64]appHealthEntry{},
	}, nil
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
		r.Get("/activity", s.listActivityLog)
		r.Get("/certificates", s.listCertificates)
		r.Get("/raw-routes", s.listRawRoutes)
		r.Get("/docs", s.getDocs)

		// Server picker — available to every authenticated role. The route
		// only flips the caddyui_server cookie (a per-user preference) so
		// viewers and non-admin users can switch between Caddy instances
		// the admin has registered without needing write access. Admin-only
		// CRUD on the server list still lives in the admin-gated group below.
		r.Post("/servers/{id}/select", s.selectServer)

		// Feature B: upstream health check API (authenticated, no requireWrite).
		r.Get("/api/upstream-health", s.apiUpstreamHealth)

		// Feature F: notifier status API (authenticated).
		r.Get("/api/notifier-status", s.apiNotifierStatus)

		// Phase 7: system stats API (authenticated, read-only).
		r.Get("/api/system-stats", s.apiSystemStats)

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

		// Write routes — admin-only in practice. Viewers get 403 via requireWrite.
		r.Group(func(r chi.Router) {
			r.Use(s.requireWrite)

			r.Get("/proxy-hosts/new", s.newProxyHost)
			r.Post("/proxy-hosts", s.createProxyHost)
			r.Get("/proxy-hosts/{id}/edit", s.editProxyHost)
			r.Post("/proxy-hosts/{id}", s.updateProxyHost)
			r.Post("/proxy-hosts/{id}/delete", s.deleteProxyHost)
			r.Post("/proxy-hosts/{id}/toggle", s.toggleProxyHost)

			r.Get("/redirection-hosts/new", s.newRedirectionHost)
			r.Post("/redirection-hosts", s.createRedirectionHost)
			r.Get("/redirection-hosts/{id}/edit", s.editRedirectionHost)
			r.Post("/redirection-hosts/{id}", s.updateRedirectionHost)
			r.Post("/redirection-hosts/{id}/delete", s.deleteRedirectionHost)
			r.Post("/redirection-hosts/{id}/toggle", s.toggleRedirectionHost)

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

			r.Get("/raw-routes/new", s.newRawRoute)
			r.Post("/raw-routes", s.createRawRoute)
			r.Get("/raw-routes/{id}/edit", s.editRawRoute)
			r.Post("/raw-routes/{id}", s.updateRawRoute)
			r.Post("/raw-routes/{id}/delete", s.deleteRawRoute)

			// Phase 7: database backup download.
			r.Get("/backup", s.getBackup)
		})

		// TOTP setup — available to all authenticated users.
		r.Get("/totp/setup", s.getTOTPSetup)
		r.Post("/totp/setup", s.postTOTPSetup)

		// v2.7.0: visitor analytics — read-only for every signed-in
		// user. userAllowedHosts scopes non-admins to their owned
		// sites so the page doesn't leak traffic for hosts they
		// don't have Edit permission on.
		r.Get("/analytics", s.getAnalytics)
		r.Get("/analytics/{host}", s.getAnalyticsHost)

		// User management and settings — admin-only (both read and write).
		r.Group(func(r chi.Router) {
			r.Use(s.requireAdmin)
			r.Get("/users", s.listUsers)
			r.Get("/users/new", s.newUser)
			r.Post("/users", s.createUser)
			r.Get("/users/{id}/edit", s.editUser)
			r.Post("/users/{id}", s.updateUser)
			r.Post("/users/{id}/delete", s.deleteUser)

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
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, err := auth.UserFromSession(s.DB, cookie.Value)
		if err != nil || u == nil {
			auth.ClearSessionCookie(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), auth.ContextUserKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) currentUser(r *http.Request) *models.User {
	u, _ := r.Context().Value(auth.ContextUserKey).(*models.User)
	return u
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	// Always inject app version.
	data["AppVersion"] = s.Version
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
	tok, exp, err := auth.CreateSession(s.DB, id)
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
	s.render(w, r, "login.html", captchaTemplateData(loadCaptchaConfig(s.DB)))
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

	email := strings.TrimSpace(r.FormValue("email"))
	pw := r.FormValue("password")
	u, err := models.GetUserByEmail(s.DB, email)
	if err != nil || !auth.CheckPassword(u.PasswordHash, pw) {
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
	tok, exp, err := auth.CreateSession(s.DB, u.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, r, tok, exp)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		_ = auth.DeleteSession(s.DB, c.Value)
	}
	auth.ClearSessionCookie(w, r)
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

	valid := totplib.Validate(code, u.TOTPSecret)
	if !valid {
		// Put token back so user can retry.
		s.pendingTOTP.Store(tok, userID)
		renderTOTPErr("Invalid code. Try again.")
		return
	}

	sessionTok, exp, err := auth.CreateSession(s.DB, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, r, sessionTok, exp)
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
	s.render(w, r, "totp_setup.html", map[string]any{
		"User":        u,
		"Secret":      key.Secret(),
		"OTPAuth":     key.URL(),
		"TOTPEnabled": u.TOTPEnabled,
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
	http.Redirect(w, r, "/totp/setup?enabled=1", http.StatusSeeOther)
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
	hosts, _ := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin)
	redirs, _ := models.ListRedirectionHosts(s.DB, sid, viewerID, isAdmin)
	raws, _ := models.ListRawRoutes(s.DB, sid, viewerID, isAdmin)
	// v2.7.2: cert card count matches what the /certificates page will show —
	// admin sees every cert, user-role sees their uploads + globals.
	certs, _ := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin)

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

	s.render(w, r, "dashboard.html", map[string]any{
		"User":             s.currentUser(r),
		"ProxyHosts":       hosts,
		"RedirectionHosts": redirs,
		"RawCount":         len(raws),
		"CertCount":        len(certs),
		"LastSync":         lastSync,
		"EnabledHosts":     enabledHosts,
		"DisabledHosts":    disabledHosts,
		"ExpiringSoon":     expiringSoon,
		"Section":          "dashboard",
	})
}

// --- Proxy Hosts ---
type advancedRouteRow struct {
	ID      int64
	Label   string
	Hosts   string // comma-joined hosts from match[].host[]
	Summary string // e.g. "3 upstreams · 3 redirects"
	Enabled bool
}

func (s *Server) listProxyHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	hosts, err := models.ListProxyHosts(s.DB, s.currentServerID(r), viewerID, isAdmin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raws, _ := models.ListRawRoutes(s.DB, s.currentServerID(r), viewerID, isAdmin)
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
		advancedRows = append(advancedRows, advancedRouteRow{
			ID: rr.ID, Label: rr.Label, Hosts: strings.Join(hosts, ", "),
			Summary: summary, Enabled: rr.Enabled,
		})
	}
	s.render(w, r, "proxy_hosts.html", map[string]any{
		"User":         s.currentUser(r),
		"Hosts":        hosts,
		"AdvancedRows": advancedRows,
		"Section":      "proxy",
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
func (s *Server) buildBasicAuthHandler(caddyCl *caddy.Client, users []models.BasicAuthUser) map[string]any {
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
	return &models.ProxyHost{
		Domains:             strings.TrimSpace(r.FormValue("domains")),
		ForwardScheme:       r.FormValue("forward_scheme"),
		ForwardHost:         strings.TrimSpace(r.FormValue("forward_host")),
		ForwardPort:         port,
		WebsocketSupport:    r.FormValue("websocket_support") == "on",
		BlockCommonExploits: r.FormValue("block_common_exploits") == "on",
		SSLEnabled:          r.FormValue("ssl_enabled") == "on",
		SSLForced:           r.FormValue("ssl_forced") == "on",
		HTTP2Support:        r.FormValue("http2_support") == "on",
		AdvancedConfig:      r.FormValue("advanced_config"),
		Enabled:             r.FormValue("enabled") == "on",
		CertificateID:       certID,
		AccessList:          strings.TrimSpace(r.FormValue("access_list")),
		DNSProvider:         provider,
		DNSZoneID:           zoneID,
		DNSZoneName:         zoneName,
	}, nil
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
	if needCreate {
		// v2.5.6: the override path is gone — same rationale as
		// createProxyHost above. If a record exists at this FQDN the
		// create call fails and the user clears it manually.
		s.dnsCreateRecord(s.currentServerID(r), p.ID, p)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "proxy_update", fmt.Sprintf("proxy:%d", id), p.Domains, true)
	forceTLS := old != nil && old.CertificateID != p.CertificateID
	s.syncCaddy(s.currentServerID(r), forceTLS)
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
	http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
}

// --- Redirection Hosts ---
func (s *Server) listRedirectionHosts(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	hosts, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), viewerID, isAdmin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "redirection_hosts.html", map[string]any{
		"User":    s.currentUser(r),
		"Hosts":   hosts,
		"Section": "redirect",
	})
}

func (s *Server) newRedirectionHost(w http.ResponseWriter, r *http.Request) {
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "redirection_host_form.html", map[string]any{
		"User":         s.currentUser(r),
		"Host":         &models.RedirectionHost{Enabled: true, PreservePath: true, ForwardHTTPCode: 301, ForwardScheme: "auto", SSLEnabled: true, SSLForced: true},
		"Certificates": certs,
		"OtherServers": s.otherManagedServers(r),
		"Section":      "redirect",
	})
}

func parseRedirectionHostForm(r *http.Request) (*models.RedirectionHost, error) {
	_ = r.ParseForm()
	code, err := strconv.Atoi(r.FormValue("forward_http_code"))
	if err != nil {
		code = 301
	}
	certID, _ := strconv.ParseInt(r.FormValue("certificate_id"), 10, 64)
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
	deployTo := parseDeployTo(r)
	cu := s.currentUser(r)
	var rhOwnerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		rhOwnerID = cu.ID
	}
	id, err := models.CreateRedirectionHost(s.DB, s.currentServerID(r), rhOwnerID, rh)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	s.render(w, r, "redirection_host_form.html", map[string]any{
		"User":         s.currentUser(r),
		"Host":         rh,
		"Certificates": certs,
		"OtherServers": s.otherManagedServers(r),
		"Section":      "redirect",
	})
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
	deployTo := parseDeployTo(r)
	old, _ := models.GetRedirectionHost(s.DB, id)
	if err := models.UpdateRedirectionHost(s.DB, rh); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_delete", fmt.Sprintf("redirect:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.syncCaddy(s.currentServerID(r), forceTLS)
	http.Redirect(w, r, "/redirection-hosts", http.StatusSeeOther)
}

func (s *Server) reloadCaddy(w http.ResponseWriter, r *http.Request) {
	if err := s.syncCaddy(s.currentServerID(r), true); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("HX-Trigger", "caddy-reloaded")
	w.WriteHeader(http.StatusNoContent)
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
	// (they don't go through ProxyHostDomainsConflict) and re-creating conflicting
	// proxies/redirects would fail at sync when two entries claim the same host.
	// Use admin view (isAdmin=true) to see all existing entries for deduplication.
	taken := map[string]struct{}{}
	if existing, err := models.ListProxyHosts(s.DB, s.currentServerID(r), 0, true); err == nil {
		for _, h := range existing {
			for _, d := range h.DomainList() {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRedirectionHosts(s.DB, s.currentServerID(r), 0, true); err == nil {
		for _, h := range existing {
			for _, d := range h.DomainList() {
				taken[strings.ToLower(d)] = struct{}{}
			}
		}
	}
	if existing, err := models.ListRawRoutes(s.DB, s.currentServerID(r), 0, true); err == nil {
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

	var results []caddyfileImportResult
	created := 0

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
		blob, err := json.Marshal(route)
		if err != nil {
			results = append(results, caddyfileImportResult{
				Head: label, Snippet: blockText, RouteIdx: idx,
				Status: "error", Message: "serialize route: " + err.Error(),
			})
			continue
		}
		id, err := models.CreateRawRoute(s.DB, s.currentServerID(r), 0, &models.RawRoute{
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
		created++
		results = append(results, caddyfileImportResult{
			Head: label, Snippet: blockText, RouteIdx: idx,
			Status: "created", Message: fmt.Sprintf("raw_route:%d", id),
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

	s.render(w, r, "caddyfile_import.html", map[string]any{
		"User":    s.currentUser(r),
		"Section": "paste",
		"Results": results,
		"Created": created,
		"Input":   "",
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

// pushAutomationPolicies reads the live apps.tls.automation object, merges the
// given incoming policies in front of existing ones (deduped by subject), and
// POSTs the updated automation object back so Caddy applies the new DNS-01 /
// custom-issuer config without disturbing anything already in place.
func (s *Server) pushAutomationPolicies(r *http.Request, incoming []map[string]any) error {
	if len(incoming) == 0 {
		return nil
	}
	cl := s.caddyForRequest(r)
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

func (s *Server) listActivityLog(w http.ResponseWriter, r *http.Request) {
	entries, err := models.ListActivity(s.DB, s.currentServerID(r), 500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "activity.html", map[string]any{
		"User":    s.currentUser(r),
		"Entries": entries,
		"Section": "activity",
	})
}

// --- Certificates ---

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
	return models.ListCertificatesForUser(s.DB, s.currentServerID(r), viewerID, isAdmin)
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
	certs, err := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin)
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
	hosts, _ := models.ListProxyHosts(s.DB, sid, 0, true)
	redirs, _ := models.ListRedirectionHosts(s.DB, sid, 0, true)
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

func (s *Server) newCertificate(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "certificate_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Cert":    &models.Certificate{Source: models.CertSourcePEM},
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
	rows, err := models.ListRawRoutes(s.DB, s.currentServerID(r), viewerID, isAdmin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "raw_routes.html", map[string]any{
		"User":    s.currentUser(r),
		"Rows":    rows,
		"Section": "raw",
	})
}

func (s *Server) newRawRoute(w http.ResponseWriter, r *http.Request) {
	certs, _ := s.certListForRequest(r)
	s.render(w, r, "raw_route_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Row":          &models.RawRoute{Enabled: true},
		"Certificates": certs,
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
	proxies, err := models.ListProxyHosts(s.DB, serverID, 0, true)
	if err != nil {
		return ""
	}
	redirs, err := models.ListRedirectionHosts(s.DB, serverID, 0, true)
	if err != nil {
		return ""
	}
	raws, err := models.ListRawRoutes(s.DB, serverID, 0, true)
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
	cu := s.currentUser(r)
	var rrOwnerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		rrOwnerID = cu.ID
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
	proxies, err := models.ListProxyHosts(s.DB, serverID, 0, true)
	if err != nil {
		return err
	}
	redirs, err := models.ListRedirectionHosts(s.DB, serverID, 0, true)
	if err != nil {
		return err
	}
	raws, err := models.ListRawRoutes(s.DB, serverID, 0, true)
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

	routes := s.buildMergedRoutes(proxies, redirs, raws)
	loadPEM, loadFiles := buildCertLoaders(certs)
	skipList := buildSkipCertificates(proxies, redirs, raws)

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
	if err := s.writeAutomaticHTTPSSubtree(skipList, forceTLS); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_autohttps_failed", "", err.Error(), false)
		return err
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
	s.render(w, r, "redirection_host_form.html", map[string]any{
		"User":         s.currentUser(r),
		"Host":         rh,
		"Certificates": certs,
		"OtherServers": s.otherManagedServers(r),
		"Error":        errMsg,
		"Section":      "redirect",
	})
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
				if h := s.buildBasicAuthHandler(s.Caddy, baUsers); h != nil {
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

func (s *Server) writeAutomaticHTTPSSubtree(skipList []any, force bool) error {
	raw, err := s.Caddy.FetchPath("/config/apps/http/servers/srv0/automatic_https")
	if err != nil {
		return err
	}
	autoMap, _ := raw.(map[string]any)
	existed := autoMap != nil
	if autoMap == nil {
		autoMap = map[string]any{}
	}
	existingSkip, _ := autoMap["skip_certificates"].([]any)
	// Skip the write when the effective skip list is unchanged. Writing it otherwise
	// reprovisions the server module and can interrupt in-flight ACME work. Caller
	// can force the write when a cert-touching mutation demands Caddy re-evaluate.
	if !force && stringListsEqual(existingSkip, skipList) {
		return nil
	}
	if len(skipList) > 0 {
		autoMap["skip_certificates"] = skipList
	} else {
		delete(autoMap, "skip_certificates")
	}
	if !existed && len(autoMap) == 0 {
		return nil
	}
	return s.Caddy.PutPath("/config/apps/http/servers/srv0/automatic_https", autoMap)
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
	s.render(w, r, "users.html", map[string]any{
		"User":    s.currentUser(r),
		"Users":   users,
		"Section": "users",
	})
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

func (s *Server) apiUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	sid := s.currentServerID(r)
	hosts, err := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin)
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

// --- Feature F: Notifications (webhook + SMTP email) ---

const (
	settingNotifyWebhookURL    = "notify_webhook_url"
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
	msg := []byte(
		"From: CaddyUI <" + from + ">\r\n" +
			"To: " + strings.Join(recipients, ", ") + "\r\n" +
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
				if resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(payload)); err == nil {
					_ = resp.Body.Close()
				}
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
			resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(payload))
			if err != nil {
				log.Printf("notifier: webhook POST failed: %v", err)
			} else {
				_ = resp.Body.Close()
				sent = true
			}
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
	tmpPath := fmt.Sprintf("%s/caddyui-backup-%s.db", os.TempDir(), time.Now().Format("20060102-150405"))
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
	w.Header().Set("Content-Disposition", `attachment; filename="caddyui-backup-`+time.Now().Format("20060102-150405")+`.db"`)
	io.Copy(w, f)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	webhookURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL)
	daysBeforeStr, _ := models.GetSetting(s.DB, settingNotifyDaysBefore)
	daysBefore := defaultNotifyDaysBefore
	if d, err := strconv.Atoi(daysBeforeStr); err == nil && d > 0 {
		daysBefore = d
	}

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
		"DaysBefore":         daysBefore,
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
		"Section":     "settings",
	})
}

func (s *Server) postSettings(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	webhookURL := strings.TrimSpace(r.FormValue("webhook_url"))
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
		settingNotifyWebhookURL:   webhookURL,
		settingNotifyDaysBefore:   strconv.Itoa(daysBefore),
		settingSMTPHost:           smtpHost,
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
