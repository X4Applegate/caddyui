package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// SeedBootstrapServer inserts the first Caddy server using the admin URL the
// process was launched with. No-op once any server row exists — idempotent so
// restarts don't resurrect deleted rows.
func (s *Server) SeedBootstrapServer(adminURL string) error {
	n, err := models.CountCaddyServers(s.DB)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = models.CreateCaddyServer(s.DB, &models.CaddyServer{
		Name:     "Primary",
		AdminURL: adminURL,
		Type:     models.CaddyServerTypeManaged,
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
		Name:     strings.TrimSpace(r.FormValue("name")),
		AdminURL: strings.TrimSpace(r.FormValue("admin_url")),
		Type:     r.FormValue("type"),
		Tags:     strings.TrimSpace(r.FormValue("tags")),
		Version:  strings.TrimSpace(r.FormValue("version")),
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
		renderErr("Admin URL is required (e.g. http://10.0.0.2:2019)")
		return
	}
	if !strings.HasPrefix(c.AdminURL, "http://") && !strings.HasPrefix(c.AdminURL, "https://") {
		renderErr("Admin URL must start with http:// or https://")
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
	if existing.AdminURL == "" || (!strings.HasPrefix(existing.AdminURL, "http://") && !strings.HasPrefix(existing.AdminURL, "https://")) {
		renderErr("Admin URL must start with http:// or https://")
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
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, c.AdminURL+"/config/", nil)
	resp, err := client.Do(req)
	if err != nil {
		s.render(w, r, "server_config.html", map[string]any{
			"User":    s.currentUser(r),
			"Target":  c,
			"Error":   err.Error(),
			"Section": "servers",
		})
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	pretty := string(raw)
	var v any
	if err := json.Unmarshal(raw, &v); err == nil {
		if b, err := json.MarshalIndent(v, "", "  "); err == nil {
			pretty = string(b)
		}
	}
	s.render(w, r, "server_config.html", map[string]any{
		"User":    s.currentUser(r),
		"Target":  c,
		"Config":  pretty,
		"Status":  resp.StatusCode,
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
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.AdminURL+"/config/", nil)
	if err != nil {
		_ = models.SetCaddyServerStatus(s.DB, srv.ID, models.CaddyServerStatusOffline, nil)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		_ = models.SetCaddyServerStatus(s.DB, srv.ID, models.CaddyServerStatusOffline, nil)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	status := models.CaddyServerStatusOnline
	if resp.StatusCode >= 500 {
		status = models.CaddyServerStatusOffline
	}
	now := time.Now()
	_ = models.SetCaddyServerStatus(s.DB, srv.ID, status, &now)

}
