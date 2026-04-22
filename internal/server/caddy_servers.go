package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// isValidAdminURL returns true for URLs CaddyUI knows how to dial:
//   - http:// and https:// for standard TCP (optionally wrapped in TLS)
//   - unix:// for a Unix domain socket path (e.g. unix:///run/caddy-admin.sock)
//
// Empty strings and anything else (file://, ftp://, bare hostnames) are rejected.
func isValidAdminURL(u string) bool {
	return strings.HasPrefix(u, "http://") ||
		strings.HasPrefix(u, "https://") ||
		strings.HasPrefix(u, "unix://")
}

// SeedBootstrapServer inserts the first Caddy server using the admin URL the
// process was launched with. No-op once any server row exists — idempotent so
// restarts don't resurrect deleted rows. Optional username/password seed the
// bootstrap server with HTTP Basic Auth credentials (from CADDY_ADMIN_USER /
// CADDY_ADMIN_PASS env vars) for setups that gate port 2019 behind a reverse
// proxy that enforces basic auth.
func (s *Server) SeedBootstrapServer(adminURL, username, password string) error {
	n, err := models.CountCaddyServers(s.DB)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = models.CreateCaddyServer(s.DB, &models.CaddyServer{
		Name:          "Primary",
		AdminURL:      adminURL,
		Type:          models.CaddyServerTypeManaged,
		AdminUsername: username,
		AdminPassword: password,
	})
	return err
}

// --- Handlers ---

func (s *Server) listServersPage(w http.ResponseWriter, r *http.Request) {
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "servers.html", map[string]any{
		"User":    s.currentUser(r),
		"Servers": servers,
		"Section": "servers",
	})
}

func (s *Server) newServerPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "server_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Target":  &models.CaddyServer{Type: models.CaddyServerTypeManaged},
		"Section": "servers",
	})
}

func (s *Server) createServer(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	c := &models.CaddyServer{
		Name:          strings.TrimSpace(r.FormValue("name")),
		AdminURL:      strings.TrimSpace(r.FormValue("admin_url")),
		Type:          r.FormValue("type"),
		Tags:          strings.TrimSpace(r.FormValue("tags")),
		Version:       strings.TrimSpace(r.FormValue("version")),
		AdminUsername: strings.TrimSpace(r.FormValue("admin_username")),
		AdminPassword: r.FormValue("admin_password"),
	}
	renderErr := func(msg string) {
		s.render(w, r, "server_form.html", map[string]any{
			"User":    s.currentUser(r),
			"Target":  c,
			"Section": "servers",
			"Error":   msg,
		})
	}
	if c.Name == "" {
		renderErr("Name is required")
		return
	}
	if c.AdminURL == "" {
		renderErr("Admin URL is required (e.g. http://10.0.0.2:2019 or unix:///run/caddy-admin.sock)")
		return
	}
	if !isValidAdminURL(c.AdminURL) {
		renderErr("Admin URL must start with http://, https://, or unix:///")
		return
	}
	id, err := models.CreateCaddyServer(s.DB, c)
	if err != nil {
		renderErr(err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "server_create", fmt.Sprintf("server:%d", id), c.Name, true)
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}

func (s *Server) editServerPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	c, err := models.GetCaddyServer(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.render(w, r, "server_form.html", map[string]any{
		"User":    s.currentUser(r),
		"Target":  c,
		"Section": "servers",
	})
}

func (s *Server) updateServer(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	existing, err := models.GetCaddyServer(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_ = r.ParseForm()
	existing.Name = strings.TrimSpace(r.FormValue("name"))
	existing.AdminURL = strings.TrimSpace(r.FormValue("admin_url"))
	existing.Type = r.FormValue("type")
	existing.Tags = strings.TrimSpace(r.FormValue("tags"))
	existing.Version = strings.TrimSpace(r.FormValue("version"))
	existing.AdminUsername = strings.TrimSpace(r.FormValue("admin_username"))
	// Password: if the form submitted a blank value AND the user didn't explicitly
	// check the "clear password" box, keep the existing one. Protects against
	// masked-field UX where the password isn't re-typed on every edit.
	if newPw := r.FormValue("admin_password"); newPw != "" {
		existing.AdminPassword = newPw
	} else if r.FormValue("clear_admin_password") == "1" {
		existing.AdminPassword = ""
	}
	renderErr := func(msg string) {
		s.render(w, r, "server_form.html", map[string]any{
			"User":    s.currentUser(r),
			"Target":  existing,
			"Section": "servers",
			"Error":   msg,
		})
	}
	if existing.Name == "" {
		renderErr("Name is required")
		return
	}
	if existing.AdminURL == "" || !isValidAdminURL(existing.AdminURL) {
		renderErr("Admin URL must start with http://, https://, or unix:///")
		return
	}
	if err := models.UpdateCaddyServer(s.DB, existing); err != nil {
		renderErr(err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "server_update", fmt.Sprintf("server:%d", id), existing.Name, true)
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}

func (s *Server) deleteServer(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	n, _ := models.CountCaddyServers(s.DB)
	if n <= 1 {
		http.Error(w, "can't delete the last server — add another first", http.StatusBadRequest)
		return
	}
	c, err := models.GetCaddyServer(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := models.DeleteCaddyServer(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "server_delete", fmt.Sprintf("server:%d", id), c.Name, true)
	http.Redirect(w, r, "/servers", http.StatusSeeOther)
}

// selectServer sets the caddyui_server cookie to the given server ID and
// redirects back to wherever the user came from (or "/" if Referer is absent).
func (s *Server) selectServer(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// Validate the server actually exists.
	if _, err := models.GetCaddyServer(s.DB, id); err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     serverCookie,
		Value:    strconv.FormatInt(id, 10),
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 365, // 1 year
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// viewServerConfig streams the live /config/ JSON from the selected Caddy server so
// the operator can eyeball what's actually running on that box without SSH-ing.
func (s *Server) viewServerConfig(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	c, err := models.GetCaddyServer(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// Use a caddy.Client so the read respects auth + unix-socket transport.
	cc := caddy.New(c.AdminURL, c.AdminUsername, c.AdminPassword)
	_, raw, err := cc.FetchConfig()
	if err != nil {
		s.render(w, r, "server_config.html", map[string]any{
			"User":    s.currentUser(r),
			"Target":  c,
			"Error":   err.Error(),
			"Section": "servers",
		})
		return
	}
	pretty := raw
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err == nil {
		if b, err := json.MarshalIndent(v, "", "  "); err == nil {
			pretty = string(b)
		}
	}
	s.render(w, r, "server_config.html", map[string]any{
		"User":    s.currentUser(r),
		"Target":  c,
		"Config":  pretty,
		"Status":  200,
		"Section": "servers",
	})
}

// --- Health poller ---

// StartHealthPoller launches a goroutine that pings every server's admin API on
// an interval and records status + last-contact. Cheap — one GET per server per tick.
// Runs until ctx cancels. Cadence is fixed at 30s; easy to env-ify later if needed.
func (s *Server) StartHealthPoller(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		s.pollAllServers(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.pollAllServers(ctx)
			}
		}
	}()
}

func (s *Server) pollAllServers(ctx context.Context) {
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		log.Printf("health poller: list servers: %v", err)
		return
	}
	for _, srv := range servers {
		s.pollOneServer(ctx, srv)
	}
}

func (s *Server) pollOneServer(ctx context.Context, srv models.CaddyServer) {
	// Build a caddy.Client per ping so we pick up any admin URL / credential
	// changes made via the UI since the last tick, and so the ping goes
	// through the same transport + auth path as real requests (unix sockets
	// and basic-auth-wrapped endpoints both work out of the box).
	client := caddy.New(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	code, err := client.Ping(pingCtx)
	if err != nil {
		_ = models.SetCaddyServerStatus(s.DB, srv.ID, models.CaddyServerStatusOffline, nil)
		return
	}
	status := models.CaddyServerStatusOnline
	if code >= 500 {
		status = models.CaddyServerStatusOffline
	}
	now := time.Now()
	_ = models.SetCaddyServerStatus(s.DB, srv.ID, status, &now)
}
