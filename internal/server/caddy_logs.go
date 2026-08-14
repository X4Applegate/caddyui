package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/caddylogs"
	"github.com/X4Applegate/caddyui/internal/models"
)

const (
	runtimeLogCaptureTTL   = 15 * time.Minute
	runtimeLogCleanupRetry = 30 * time.Second
)

func caddyLogOptions(server models.CaddyServer, cfg analyticsConfig) caddy.AccessLogOptions {
	return caddy.AccessLogOptions{
		SoftStart: cfg.SoftStart, DialTimeout: cfg.DialTimeout,
		ServerID: server.ID, ServerName: server.Name,
	}
}

// ReconcileCertificateLogs installs the low-volume TLS lifecycle stream on
// every managed Caddy. It is safe to call at startup, after Settings changes,
// and after a server is registered; unrelated/default loggers are preserved.
func (s *Server) ReconcileCertificateLogs() error {
	if s.caddyLogHub == nil {
		return nil
	}
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		return err
	}
	cfg := loadAnalyticsConfig(s.DB)
	var failures []string
	for _, server := range servers {
		if server.Type != models.CaddyServerTypeManaged {
			continue
		}
		client := newCaddyClient(server.AdminURL, server.AdminUsername, server.AdminPassword)
		if err := client.EnableCertificateLogs(cfg.Target, caddyLogOptions(server, cfg)); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", server.Name, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("certificate log monitoring: %s", strings.Join(failures, "; "))
	}
	return nil
}

// ResetRuntimeLogs removes streams left in Caddy's persisted config by a
// prior process/browser session. Full runtime capture is deliberately
// ephemeral; certificate monitoring remains enabled independently.
func (s *Server) ResetRuntimeLogs() error {
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		return err
	}
	var failures []string
	for _, server := range servers {
		if server.Type != models.CaddyServerTypeManaged {
			continue
		}
		if err := s.disableRuntimeLogCapture(server); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", server.Name, err))
			s.runtimeLogMu.Lock()
			if s.runtimeLogTimers[server.ID] == nil {
				s.scheduleRuntimeLogDisableLocked(server.ID, runtimeLogCleanupRetry)
			}
			s.runtimeLogMu.Unlock()
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("reset runtime log capture: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (s *Server) getServerLogs(w http.ResponseWriter, r *http.Request) {
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	managed := servers[:0]
	for _, server := range servers {
		if server.Type == models.CaddyServerTypeManaged {
			managed = append(managed, server)
		}
	}
	selected := s.currentServerID(r)
	if len(managed) > 0 {
		found := false
		for _, server := range managed {
			if server.ID == selected {
				found = true
				break
			}
		}
		if !found {
			selected = managed[0].ID
		}
	}
	s.render(w, r, "server_logs.html", map[string]any{
		"User": s.currentUser(r), "Servers": managed,
		"SelectedServerID": selected, "HubAvailable": s.caddyLogHub != nil,
		"CaptureTTLMinutes": int(runtimeLogCaptureTTL / time.Minute),
		"Section":           "server_logs",
	})
}

func (s *Server) serverLogStatus(w http.ResponseWriter, _ *http.Request) {
	if s.caddyLogHub == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"available": false, "captures": []caddylogs.CaptureState{},
		})
		return
	}
	captures := s.caddyLogHub.Captures()
	sort.Slice(captures, func(i, j int) bool { return captures[i].ServerID < captures[j].ServerID })
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "captures": captures})
}

func (s *Server) enableServerLogs(w http.ResponseWriter, r *http.Request) {
	if s.caddyLogHub == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Caddy log ingest is unavailable")
		return
	}
	server, ok := s.runtimeLogServerFromRequest(w, r)
	if !ok {
		return
	}
	level := strings.ToUpper(strings.TrimSpace(r.FormValue("level")))
	switch level {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		level = "INFO"
	}
	cfg := loadAnalyticsConfig(s.DB)
	expires := time.Now().UTC().Add(runtimeLogCaptureTTL)
	if err := s.enableRuntimeLogCapture(*server, cfg, level, expires); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "expires_at": expires})
}

func (s *Server) disableServerLogs(w http.ResponseWriter, r *http.Request) {
	server, ok := s.runtimeLogServerFromRequest(w, r)
	if !ok {
		return
	}
	if err := s.disableRuntimeLogCapture(*server); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
}

func (s *Server) runtimeLogServerFromRequest(w http.ResponseWriter, r *http.Request) (*models.CaddyServer, bool) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid form")
		return nil, false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("server_id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "select a Caddy server")
		return nil, false
	}
	server, err := models.GetCaddyServer(s.DB, id)
	if err != nil || server == nil {
		writeJSONError(w, http.StatusNotFound, "Caddy server not found")
		return nil, false
	}
	if server.Type != models.CaddyServerTypeManaged {
		writeJSONError(w, http.StatusBadRequest, "external servers cannot be reconfigured")
		return nil, false
	}
	return server, true
}

// enableRuntimeLogCapture serializes Caddy config updates with timer expiry so
// an older capture's timer can never disable a newer capture on the same node.
func (s *Server) enableRuntimeLogCapture(server models.CaddyServer, cfg analyticsConfig, level string, expires time.Time) error {
	s.runtimeLogMu.Lock()
	defer s.runtimeLogMu.Unlock()

	client := newCaddyClient(server.AdminURL, server.AdminUsername, server.AdminPassword)
	if err := client.EnableRuntimeLogs(cfg.Target, level, caddyLogOptions(server, cfg)); err != nil {
		return err
	}

	serverID := server.ID
	if timer := s.runtimeLogTimers[serverID]; timer != nil {
		timer.Stop()
	}
	if s.caddyLogHub != nil {
		s.caddyLogHub.SetCapture(caddylogs.CaptureState{
			ServerID: serverID, ServerName: server.Name, Level: level, ExpiresAt: expires,
		})
	}
	s.scheduleRuntimeLogDisableLocked(serverID, time.Until(expires))
	return nil
}

// scheduleRuntimeLogDisableLocked installs one cleanup attempt for a node.
// The caller holds runtimeLogMu. A failed remote DELETE is retried rather than
// dropping local state and leaving Caddy's temporary network logger behind.
func (s *Server) scheduleRuntimeLogDisableLocked(serverID int64, delay time.Duration) {
	if s.runtimeLogTimers == nil {
		s.runtimeLogTimers = map[int64]*time.Timer{}
	}
	if timer := s.runtimeLogTimers[serverID]; timer != nil {
		timer.Stop()
	}
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		s.runtimeLogMu.Lock()
		defer s.runtimeLogMu.Unlock()
		if s.runtimeLogTimers[serverID] != timer {
			return
		}
		server, err := models.GetCaddyServer(s.DB, serverID)
		if err == nil && server != nil {
			if err := s.disableRuntimeLogCaptureLocked(*server); err != nil {
				log.Printf("server logs: automatic disable for %s failed: %v", server.Name, err)
				s.scheduleRuntimeLogDisableLocked(serverID, runtimeLogCleanupRetry)
			}
		} else {
			s.clearRuntimeLogCaptureLocked(serverID)
		}
	})
	s.runtimeLogTimers[serverID] = timer
}

func (s *Server) disableRuntimeLogCapture(server models.CaddyServer) error {
	s.runtimeLogMu.Lock()
	defer s.runtimeLogMu.Unlock()
	return s.disableRuntimeLogCaptureLocked(server)
}

func (s *Server) disableRuntimeLogCaptureLocked(server models.CaddyServer) error {
	client := newCaddyClient(server.AdminURL, server.AdminUsername, server.AdminPassword)
	if err := client.DisableRuntimeLogs(); err != nil {
		return err
	}
	s.clearRuntimeLogCaptureLocked(server.ID)
	return nil
}

func (s *Server) clearRuntimeLogCaptureLocked(serverID int64) {
	if timer := s.runtimeLogTimers[serverID]; timer != nil {
		timer.Stop()
	}
	delete(s.runtimeLogTimers, serverID)
	if s.caddyLogHub != nil {
		s.caddyLogHub.ClearCapture(serverID)
	}
}

func (s *Server) serverLogStream(w http.ResponseWriter, r *http.Request) {
	if s.caddyLogHub == nil {
		http.Error(w, "Caddy log ingest is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	cursor, _ := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("since")), 10, 64)
	serverID, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("server")), 10, 64)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			entries := s.caddyLogHub.Since(cursor, serverID, 200)
			for _, entry := range entries {
				if entry.ID > cursor {
					cursor = entry.ID
				}
			}
			if len(entries) == 0 {
				_, _ = fmt.Fprint(w, ": ping\n\n")
			} else {
				data, _ := json.Marshal(entries)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			}
			flusher.Flush()
		}
	}
}
