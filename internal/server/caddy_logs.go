package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/caddylogs"
	"github.com/X4Applegate/caddyui/internal/models"
)

const (
	runtimeLogCaptureTTL   = 15 * time.Minute
	runtimeLogCleanupRetry = 30 * time.Second
	certificateProbeEvery  = time.Hour
	staleCertificatePhase  = 15 * time.Minute
)

type certificateProbeTarget struct {
	Certificate models.Certificate
	Identifier  string
}

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

// StartCertificateLifecycleReconciler bootstraps lifecycle state for
// certificates issued before log monitoring existed, then periodically heals
// missed/stale obtaining states. A successful live TLS probe is stronger
// evidence than the "automatic management enabled" log line: it proves the
// selected Caddy node is actually serving a valid matching certificate.
func (s *Server) StartCertificateLifecycleReconciler(ctx context.Context) {
	go func() {
		run := func() {
			updated, err := s.reconcileCertificateLifecycle()
			if err != nil {
				log.Printf("certificate lifecycle: live reconciliation: %v", err)
			} else if updated > 0 {
				log.Printf("certificate lifecycle: confirmed %d previously unknown/stale subject(s)", updated)
			}
		}
		run()
		ticker := time.NewTicker(certificateProbeEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}

func (s *Server) reconcileCertificateLifecycle() (int, error) {
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		return 0, err
	}
	states, err := models.ListCertificateLifecycle(s.DB, 0)
	if err != nil {
		return 0, err
	}
	stateByServerIdentifier := make(map[string]models.CertificateLifecycleStatus, len(states))
	for _, state := range states {
		key := fmt.Sprintf("%d:%s", state.ServerID, models.NormalizeHostname(state.Identifier))
		stateByServerIdentifier[key] = state
	}

	type probeJob struct {
		server models.CaddyServer
		target certificateProbeTarget
	}
	var jobs []probeJob
	now := time.Now().UTC()
	for _, server := range servers {
		if server.Type != models.CaddyServerTypeManaged {
			continue
		}
		targets, targetErr := s.certificateProbeTargets(server.ID)
		if targetErr != nil {
			return 0, fmt.Errorf("%s: collect certificate probes: %w", server.Name, targetErr)
		}
		for _, target := range targets {
			key := fmt.Sprintf("%d:%s", server.ID, models.NormalizeHostname(target.Identifier))
			state, found := stateByServerIdentifier[key]
			if !found || ((state.Phase == "obtaining" || state.Phase == "renewing") && now.Sub(state.UpdatedAt) >= staleCertificatePhase) {
				jobs = append(jobs, probeJob{server: server, target: target})
			}
		}
	}

	probe := s.certificateProbeFn
	if probe == nil {
		probe = s.probeManagedCertificate
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	updated := 0
	var failures []string
	for _, job := range jobs {
		job := job
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			result := probe(job.server, job.target.Certificate)
			<-sem
			if result.Status != "healthy" && result.Status != "expiring" {
				return
			}
			message := "certificate confirmed by live TLS probe"
			if strings.TrimSpace(result.Issuer) != "" {
				message += " (issuer: " + strings.TrimSpace(result.Issuer) + ")"
			}
			identifier := job.target.Identifier
			state := models.CertificateLifecycleStatus{
				ServerID: job.server.ID, ServerName: job.server.Name,
				Identifier: identifier, Phase: "active", Level: "INFO",
				Message: message, UpdatedAt: now,
			}
			if err := models.UpsertCertificateLifecycle(s.DB, state); err != nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("%s/%s: %v", job.server.Name, identifier, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			updated++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(failures) > 0 {
		return updated, fmt.Errorf("store probe results: %s", strings.Join(failures, "; "))
	}
	return updated, nil
}

func (s *Server) certificateProbeTargets(serverID int64) ([]certificateProbeTarget, error) {
	byIdentifier := map[string]certificateProbeTarget{}
	add := func(cert models.Certificate, identifiers []string) {
		for _, identifier := range identifiers {
			identifier = models.NormalizeHostname(identifier)
			if identifier == "" {
				continue
			}
			if _, found := byIdentifier[identifier]; found {
				continue
			}
			probeCert := cert
			probeCert.Domains = identifier
			if managedCertificateProbeName(probeCert) == "" {
				continue
			}
			byIdentifier[identifier] = certificateProbeTarget{Certificate: probeCert, Identifier: identifier}
		}
	}

	certificates, err := models.ListCertificates(s.DB, serverID)
	if err != nil {
		return nil, err
	}
	for _, cert := range certificates {
		if cert.Source == models.CertSourceManaged {
			add(cert, cert.DomainList())
		}
	}
	proxyHosts, err := models.ListProxyHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return nil, err
	}
	for _, host := range proxyHosts {
		if host.Enabled && host.SSLEnabled && host.CertificateID == 0 {
			for _, domain := range host.DomainList() {
				add(models.Certificate{Name: "Auto TLS", Source: models.CertSourceManaged}, []string{domain})
			}
		}
	}
	redirects, err := models.ListRedirectionHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return nil, err
	}
	for _, redirect := range redirects {
		if redirect.Enabled && redirect.SSLEnabled && redirect.CertificateID == 0 {
			for _, domain := range redirect.DomainList() {
				add(models.Certificate{Name: "Auto TLS", Source: models.CertSourceManaged}, []string{domain})
			}
		}
	}
	rawRoutes, err := models.ListRawRoutes(s.DB, serverID, 0, true, nil)
	if err != nil {
		return nil, err
	}
	for _, route := range rawRoutes {
		if route.Enabled && route.CertificateID == 0 {
			for _, domain := range rawRouteHosts(route) {
				add(models.Certificate{Name: "Auto TLS", Source: models.CertSourceManaged}, []string{domain})
			}
		}
	}

	identifiers := make([]string, 0, len(byIdentifier))
	for identifier := range byIdentifier {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)
	out := make([]certificateProbeTarget, 0, len(identifiers))
	for _, identifier := range identifiers {
		out = append(out, byIdentifier[identifier])
	}
	return out, nil
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

// clearServerLogs (v2.35.5, issue #60) discards CaddyUI's in-memory runtime
// log buffer for one Caddy server. The buffer keeps up to 1000 entries for the
// life of the process, so on a quiet node it spans days; the page's "Clear
// screen" used to empty only the table and every entry returned on the next
// load. Nothing on disk is involved — runtime logs are never persisted — so
// this needs no confirmation, but it is recorded in the Activity log.
//
// Unlike enable/disable this doesn't go through runtimeLogServerFromRequest:
// that helper rejects external servers as "cannot be reconfigured", which is
// beside the point for emptying a buffer.
func (s *Server) clearServerLogs(w http.ResponseWriter, r *http.Request) {
	if s.caddyLogHub == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Caddy log ingest is unavailable")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid form")
		return
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("server_id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "select a Caddy server")
		return
	}
	cleared := s.caddyLogHub.Clear(id)
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "server_logs_clear",
		"server:"+strconv.FormatInt(id, 10), strconv.Itoa(cleared)+" buffered runtime log entries discarded", true)
	writeJSON(w, http.StatusOK, map[string]any{"cleared": cleared})
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
