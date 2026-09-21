// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/X4Applegate/caddyui/internal/porkbun"
	"github.com/go-chi/chi/v5"
)

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
	hosts, err := models.ListProxyHostSummaries(s.DB, s.currentServerID(r), viewerID, isAdmin, peers)
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
	certs, _ := s.certOptionListForRequest(r)

	// Per-host today request counts (best-effort — zero if analytics disabled).
	hostRequestsToday := make(map[int64]int)
	visibleDomains := make([]string, 0, len(hosts))
	for _, h := range hosts {
		visibleDomains = append(visibleDomains, h.DomainList()...)
	}
	if domainCounts, err := models.DomainRequestsTodayForDomains(s.DB, visibleDomains); err == nil {
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
		"Certificates":      certs,
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
		"User":               s.currentUser(r),
		"Host":               host,
		"Checks":             checks,
		"Uptime":             uptime,
		"CadenceLabel":       publicHealthCadenceLabel(*host),
		"Expectations":       host.ExpectationList(),      // v2.38.0
		"ExpectationResults": s.expectationResultsFor(id), // v2.38.0
		"Total":              total,
		"Section":            "proxy",
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
	// v2.12.29: capture + log the sync error instead of swallowing it. If
	// Caddy rejects the new config (e.g. an unknown-field validation
	// error like the v2.12.20 `network` bug) the toggle still flips in
	// the DB but Caddy never sees the change — and the user previously
	// got zero feedback that anything went wrong. Logging it at least
	// surfaces the failure in the container logs.
	if err := s.syncCaddy(s.currentServerID(r), false); err != nil {
		log.Printf("toggleProxyHost: auto-sync failed (toggle persisted but Caddy not updated): %v", err)
	}
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
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
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
		// Ownership check: admin can toggle any, others only their own.
		if !isAdmin && (!ph.OwnerID.Valid || ph.OwnerID.Int64 != cu.ID) {
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
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
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
		// Ownership check: admin can change any, others only their own.
		if !isAdmin && (!ph.OwnerID.Valid || ph.OwnerID.Int64 != cu.ID) {
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

// bulkCertificateProxyHosts applies one certificate selection to many proxy
// hosts. certificate_id=0 clears custom certs back to Auto/ACME.
func (s *Server) bulkCertificateProxyHosts(w http.ResponseWriter, r *http.Request) {
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
	certID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("certificate_id")), 10, 64)
	if err != nil || certID < 0 {
		http.Error(w, "invalid certificate", http.StatusBadRequest)
		return
	}
	sid := s.currentServerID(r)
	if certID > 0 {
		allowed := false
		certs, err := s.certOptionListForRequest(r)
		if err != nil {
			http.Error(w, "load certificates: "+err.Error(), http.StatusInternalServerError)
			return
		}
		for _, c := range certs {
			if c.ID == certID {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "certificate not found or not allowed", http.StatusForbidden)
			return
		}
	}

	rawIDs := r.Form["ids[]"]
	if len(rawIDs) == 0 {
		http.Redirect(w, r, "/proxy-hosts", http.StatusSeeOther)
		return
	}
	updated := 0
	for _, raw := range rawIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			continue
		}
		ph, err := models.GetProxyHost(s.DB, id)
		if err != nil || ph == nil || ph.ServerID != sid {
			continue
		}
		if !isAdmin && (!ph.OwnerID.Valid || ph.OwnerID.Int64 != cu.ID) {
			continue
		}
		if ph.CertificateID == certID {
			continue
		}
		ph.CertificateID = certID
		if err := models.UpdateProxyHost(s.DB, ph); err != nil {
			log.Printf("bulkCertificate: update proxy %d: %v", id, err)
			continue
		}
		updated++
	}
	if updated > 0 {
		_ = models.LogActivity(s.DB, sid, cu.Email, "proxy_bulk_certificate", fmt.Sprintf("cert:%d", certID), fmt.Sprintf("%d proxy host(s)", updated), true)
		if err := s.syncCaddy(sid, true); err != nil {
			log.Printf("bulkCertificate: syncCaddy(%d): %v", sid, err)
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
		s.deleteCertificateProbe(id)
		s.deleteCertificateExportStatus(id)
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

// importPorkbunCertificatePage — v2.14.0: renders the Porkbun certificate
// import page. Lists all domains on the Porkbun account so the user can
// pick one and pull its SSL bundle directly into CaddyUI.
func (s *Server) importPorkbunCertificatePage(w http.ResponseWriter, r *http.Request) {
	apiKey, _ := models.GetSetting(s.DB, settingPBAPIKey)
	secretKey, _ := models.GetSetting(s.DB, settingPBSecretKey)
	if apiKey == "" || secretKey == "" {
		s.render(w, r, "certificate_import_porkbun.html", map[string]any{
			"User":    s.currentUser(r),
			"Section": "certs",
			"Error":   "Porkbun API credentials are not configured. Go to Settings → DNS Providers to add them.",
		})
		return
	}
	pb := porkbun.New(apiKey, secretKey)
	domains, err := pb.ListDomains()
	if err != nil {
		s.render(w, r, "certificate_import_porkbun.html", map[string]any{
			"User":    s.currentUser(r),
			"Section": "certs",
			"Error":   "Failed to list Porkbun domains: " + err.Error(),
		})
		return
	}
	s.render(w, r, "certificate_import_porkbun.html", map[string]any{
		"User":    s.currentUser(r),
		"Section": "certs",
		"Domains": domains,
	})
}

// importPorkbunCertificate — v2.14.0: fetches the SSL bundle for the
// selected domain from Porkbun and creates a Certificate record in CaddyUI.
func (s *Server) importPorkbunCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	apiKey, _ := models.GetSetting(s.DB, settingPBAPIKey)
	secretKey, _ := models.GetSetting(s.DB, settingPBSecretKey)
	if apiKey == "" || secretKey == "" {
		http.Error(w, "Porkbun credentials not configured", http.StatusBadRequest)
		return
	}
	pb := porkbun.New(apiKey, secretKey)
	bundle, err := pb.RetrieveSSL(domain)
	if err != nil {
		s.render(w, r, "certificate_import_porkbun.html", map[string]any{
			"User":     s.currentUser(r),
			"Section":  "certs",
			"Error":    "Failed to retrieve certificate from Porkbun: " + err.Error(),
			"Selected": domain,
		})
		return
	}
	cu := s.currentUser(r)
	var ownerID int64
	if cu != nil && cu.Role != models.RoleAdmin {
		ownerID = cu.ID
	}
	cert := &models.Certificate{
		Name:    domain,
		Domains: domain,
		Source:  models.CertSourcePEM,
		CertPEM: bundle.CertificateChain,
		KeyPEM:  bundle.PrivateKey,
	}
	sid := s.currentServerID(r)
	id, err := models.CreateCertificate(s.DB, sid, ownerID, cert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, sid, s.currentUserEmail(r), "cert_create", fmt.Sprintf("cert:%d", id), domain+" (Porkbun import)", true)
	s.trySyncCaddy(sid, true)
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
	s.trySyncCaddy(s.currentServerID(r), false)
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

// previewBasicAuthUsers returns the complete Basic Auth rows represented by
// the unsaved form without hashing or exposing either new passwords or saved
// bcrypt hashes in the preview response.
func previewBasicAuthUsers(r *http.Request) []models.BasicAuthUser {
	usernames := r.Form["basicauth_user"]
	passwords := r.Form["basicauth_pass"]
	hashes := r.Form["basicauth_hash"]
	users := make([]models.BasicAuthUser, 0, len(usernames))
	for i, rawUsername := range usernames {
		username := strings.TrimSpace(rawUsername)
		if username == "" {
			continue
		}
		passwordPresent := i < len(passwords) && strings.TrimSpace(passwords[i]) != ""
		hashPresent := i < len(hashes) && strings.TrimSpace(hashes[i]) != ""
		if !passwordPresent && !hashPresent {
			continue
		}
		users = append(users, models.BasicAuthUser{Username: username, BcryptHash: "<redacted>"})
	}
	return users
}

// buildBasicAuthPreviewHandler mirrors the authentication handler returned by
// Caddy's adapter while keeping credential material redacted. It avoids a
// remote /adapt call on every editor keystroke.
func buildBasicAuthPreviewHandler(users []models.BasicAuthUser, realm string) map[string]any {
	if len(users) == 0 {
		return nil
	}
	accounts := make([]any, 0, len(users))
	for _, user := range users {
		accounts = append(accounts, map[string]any{
			"username": user.Username,
			"password": user.BcryptHash,
		})
	}
	httpBasic := map[string]any{
		"accounts":   accounts,
		"hash":       map[string]any{"algorithm": "bcrypt"},
		"hash_cache": map[string]any{},
	}
	if realm != "" && realm != "Restricted" {
		httpBasic["realm"] = realm
	}
	return map[string]any{
		"handler": "authentication",
		"providers": map[string]any{
			"http_basic": httpBasic,
		},
	}
}

const previewRedacted = "<redacted>"

func redactPreviewRawQuery(raw string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	var redacted strings.Builder
	redacted.Grow(len(raw))
	changed := false
	segmentStart := 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != '&' && raw[i] != ';' {
			continue
		}
		segment := raw[segmentStart:i]
		key := segment
		if equals := strings.IndexByte(segment, '='); equals >= 0 {
			key = segment[:equals]
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			// A malformed key cannot be classified safely. Preserve its name but
			// fail closed on its value so a credential cannot slip into Copy JSON.
			if equals := strings.IndexByte(segment, '='); equals >= 0 {
				segment = segment[:equals+1] + url.QueryEscape(previewRedacted)
				changed = true
			}
		} else if previewSensitiveKey(decodedKey) {
			segment = key + "=" + url.QueryEscape(previewRedacted)
			changed = true
		}
		redacted.WriteString(segment)
		if i < len(raw) {
			redacted.WriteByte(raw[i])
		}
		segmentStart = i + 1
	}
	return redacted.String(), changed
}

func redactPreviewRawUserinfo(raw string) (string, bool) {
	authorityStart := -1
	if schemeSeparator := strings.Index(raw, "://"); schemeSeparator >= 0 {
		authorityStart = schemeSeparator + 3
	} else if strings.HasPrefix(raw, "//") {
		authorityStart = 2
	}
	if authorityStart < 0 {
		return raw, false
	}
	authorityEnd := len(raw)
	if separator := strings.IndexAny(raw[authorityStart:], "/?#"); separator >= 0 {
		authorityEnd = authorityStart + separator
	}
	authority := raw[authorityStart:authorityEnd]
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return raw, false
	}
	userinfo := "redacted"
	if strings.Contains(authority[:at], ":") {
		userinfo = "redacted:redacted"
	}
	redactedAuthority := userinfo + authority[at:]
	return raw[:authorityStart] + redactedAuthority + raw[authorityEnd:], true
}

func redactPreviewURL(raw string) string {
	var userinfoChanged bool
	raw, userinfoChanged = redactPreviewRawUserinfo(raw)
	queryChanged := false
	if queryStart := strings.IndexByte(raw, '?'); queryStart >= 0 {
		queryEnd := len(raw)
		if fragmentStart := strings.IndexByte(raw[queryStart+1:], '#'); fragmentStart >= 0 {
			queryEnd = queryStart + 1 + fragmentStart
		}
		redactedQuery, changed := redactPreviewRawQuery(raw[queryStart+1 : queryEnd])
		if changed {
			raw = raw[:queryStart+1] + redactedQuery + raw[queryEnd:]
			queryChanged = true
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		// The raw-query pass above still removes sensitive values when the URL
		// itself is malformed and cannot be parsed safely.
		return raw
	}
	changed := userinfoChanged || queryChanged
	if parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			parsed.User = url.UserPassword("redacted", "redacted")
		} else {
			parsed.User = url.User("redacted")
		}
		changed = true
	}
	if !changed {
		return raw
	}
	return parsed.String()
}

func previewSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	if normalized == "authorization" || normalized == "proxy-authorization" || normalized == "cookie" || normalized == "set-cookie" {
		return true
	}
	return strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "credential") ||
		strings.Contains(normalized, "api-key") ||
		strings.Contains(normalized, "apikey")
}

func redactPreviewShape(value any) any {
	switch typed := value.(type) {
	case []any:
		redacted := make([]any, len(typed))
		for i := range redacted {
			redacted[i] = previewRedacted
		}
		return redacted
	case []string:
		redacted := make([]string, len(typed))
		for i := range redacted {
			redacted[i] = previewRedacted
		}
		return redacted
	default:
		return previewRedacted
	}
}

// redactProxyRoutePreview scrubs known credential-bearing keys and headers
// while preserving the route's structure. It also removes URL userinfo and
// sensitive query parameters from arbitrary strings, including adapted
// advanced handlers.
func redactProxyRoutePreview(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if previewSensitiveKey(key) {
				typed[key] = redactPreviewShape(child)
			} else {
				typed[key] = redactProxyRoutePreview(child)
			}
		}
		return typed
	case map[string][]string:
		for key, child := range typed {
			if previewSensitiveKey(key) {
				typed[key] = redactPreviewShape(child).([]string)
			}
		}
		return typed
	case map[string][]any:
		for key, child := range typed {
			if previewSensitiveKey(key) {
				typed[key] = redactPreviewShape(child).([]any)
			} else {
				for i := range child {
					child[i] = redactProxyRoutePreview(child[i])
				}
			}
		}
		return typed
	case []any:
		for i := range typed {
			typed[i] = redactProxyRoutePreview(typed[i])
		}
		return typed
	case string:
		return redactPreviewURL(typed)
	default:
		return typed
	}
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

// crossDeployProxyHost creates or updates the source host's paired row on each
// target server and triggers one Caddy sync per target. The durable deployment
// mapping keeps later edits attached even when the hostname changes. Target
// DNS records and custom certificate selections remain server-specific.
// Cross-deployed records are always global/admin-owned (ownerID=0).
func (s *Server) crossDeployProxyHost(actor string, sourceServerID int64, p *models.ProxyHost, serverIDs []int64) {
	s.fleetDeployMu.Lock()
	defer s.fleetDeployMu.Unlock()

	// v2.33.0: a node-local host is pinned to the node it was created on — its
	// upstream only resolves there. Refuse to cross-deploy rather than create a
	// route on the target that points at nothing. Logged so the operator can
	// see why nothing happened; the form also hides the picker for these.
	if p.NodeLocal {
		_ = models.LogActivity(s.DB, sourceServerID, actor, "proxy_cross_deploy", fmt.Sprintf("proxy:%d", p.ID),
			"skipped: host is marked node-local", false)
		return
	}

	sourceCerts, _ := models.ListCertificates(s.DB, sourceServerID)
	for _, sid := range serverIDs {
		if _, _, err := s.validateFleetPair(sourceServerID, sid); err != nil {
			log.Printf("cross-deploy proxy target %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sourceServerID, actor, "proxy_cross_deploy", fmt.Sprintf("server:%d", sid), err.Error(), false)
			continue
		}
		// Managed wildcard certificates are not attached by certificate_id;
		// Caddy selects them automatically by SNI. Copy every source-server
		// managed certificate that covers this host so the target behaves the
		// same instead of obtaining an unrelated per-host certificate.
		for _, cert := range sourceCerts {
			if cert.Source == models.CertSourceManaged && certificateCoversAnyDomain(cert, p.DomainList()) {
				if _, err := s.ensureCertificateOnServer(actor, sourceServerID, sid, cert, 0); err != nil {
					log.Printf("cross-deploy managed certificate to server %d: %v", sid, err)
				}
			}
		}
		s.ensureReferencedCertificate(actor, sourceServerID, sid, p.CertificateID)
		result, err := s.upsertFleetProxyHost(sourceServerID, sid, *p, 0)
		if err != nil {
			log.Printf("cross-deploy proxy to server %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sid, actor, "proxy_cross_deploy", "proxy:new", p.Domains, false)
			continue
		}
		detail := "already current " + p.Domains
		if result.Created {
			detail = "created " + p.Domains
		} else if result.Changed {
			detail = "updated " + p.Domains
		}
		_ = models.LogActivity(s.DB, sid, actor, "proxy_cross_deploy", fmt.Sprintf("proxy:%d", result.ID), detail, true)
		if result.Changed {
			if err := s.syncCaddy(sid, false); err != nil {
				log.Printf("cross-deploy proxy sync server %d: %v", sid, err)
			}
		}
	}
}

func normalizedDomainSet(domains []string) map[string]struct{} {
	out := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		domain = models.NormalizeHostname(domain)
		if domain != "" {
			out[domain] = struct{}{}
		}
	}
	return out
}

func sameDomainSet(a, b []string) bool {
	as, bs := normalizedDomainSet(a), normalizedDomainSet(b)
	if len(as) != len(bs) {
		return false
	}
	for domain := range as {
		if _, ok := bs[domain]; !ok {
			return false
		}
	}
	return true
}

func managedCertificateCovers(certDomain, host string) bool {
	certDomain = models.NormalizeHostname(certDomain)
	host = models.NormalizeHostname(host)
	if certDomain == "" || host == "" {
		return false
	}
	if certDomain == host {
		return true
	}
	if !strings.HasPrefix(certDomain, "*.") || strings.HasPrefix(host, "*.") {
		return false
	}
	suffix := certDomain[1:] // includes the leading dot
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func certificateCoversAnyDomain(cert models.Certificate, hosts []string) bool {
	for _, certDomain := range cert.DomainList() {
		for _, host := range hosts {
			if managedCertificateCovers(certDomain, host) {
				return true
			}
		}
	}
	return false
}

// managedWildcardForHost returns the managed wildcard definition that Auto TLS
// will reuse for host. Exact managed subjects are intentionally excluded: the
// skip_certificates behavior only suppresses exact-host issuance when a
// wildcard already covers that host.
func managedWildcardForHost(certs []models.Certificate, host string) *models.Certificate {
	for i := range certs {
		if certs[i].Source != models.CertSourceManaged {
			continue
		}
		for _, certDomain := range certs[i].DomainList() {
			if strings.HasPrefix(models.NormalizeHostname(certDomain), "*.") &&
				managedCertificateCovers(certDomain, host) {
				return &certs[i]
			}
		}
	}
	return nil
}

// ensureCertificateOnServer creates or updates the target's copy of a
// certificate (see fleetCertificateCopy). Managed definitions copy their
// DNS-01 settings only — each Caddy still orders its own certificate; stored
// PEMs copy their content; file-path certificates are copied as PEM when
// readable, by path reference otherwise (v2.41.0).
func (s *Server) ensureCertificateOnServer(actor string, sourceServerID, targetServerID int64, source models.Certificate, ownerID int64) (bool, error) {
	result, byPath, err := s.upsertFleetCertificate(sourceServerID, targetServerID, source, ownerID)
	if err != nil {
		return false, err
	}
	detail := "already current " + source.Domains
	if result.Created {
		detail = "created " + source.Domains
	} else if result.Changed {
		detail = "updated " + source.Domains
	}
	if byPath {
		detail += " (by file path — the files must exist on the target)"
	}
	_ = models.LogActivity(s.DB, targetServerID, actor, "cert_cross_deploy", fmt.Sprintf("cert:%d", result.ID), detail, true)
	return result.Changed, nil
}

// ensureReferencedCertificate copies the custom certificate a host refers to
// onto the target before the host itself is copied, so the created host can
// resolve the reference (mappedCertificateID). v2.41.0.
func (s *Server) ensureReferencedCertificate(actor string, sourceServerID, targetServerID, certificateID int64) {
	if certificateID == 0 {
		return
	}
	cert, err := models.GetCertificate(s.DB, certificateID)
	if err != nil || cert == nil {
		return
	}
	if _, err := s.ensureCertificateOnServer(actor, sourceServerID, targetServerID, *cert, 0); err != nil {
		log.Printf("cross-deploy referenced certificate %d to server %d: %v", certificateID, targetServerID, err)
	}
}

func (s *Server) crossDeployCertificate(actor string, sourceServerID int64, cert models.Certificate, serverIDs []int64) {
	s.fleetDeployMu.Lock()
	defer s.fleetDeployMu.Unlock()

	for _, targetServerID := range serverIDs {
		if _, _, err := s.validateFleetPair(sourceServerID, targetServerID); err != nil {
			log.Printf("cross-deploy certificate target %d: %v", targetServerID, err)
			continue
		}
		changed, err := s.ensureCertificateOnServer(actor, sourceServerID, targetServerID, cert, 0)
		if err != nil {
			log.Printf("cross-deploy certificate to server %d: %v", targetServerID, err)
			_ = models.LogActivity(s.DB, targetServerID, actor, "cert_cross_deploy", "cert:new", cert.Domains, false)
			continue
		}
		if changed {
			s.trySyncCaddy(targetServerID, true)
		}
	}
}

// crossDeployRedirectionHost creates or updates the paired redirect on each
// target server and triggers a Caddy sync on each.
// Cross-deployed records are always global/admin-owned (ownerID=0).
func (s *Server) crossDeployRedirectionHost(actor string, sourceServerID int64, rh *models.RedirectionHost, serverIDs []int64) {
	s.fleetDeployMu.Lock()
	defer s.fleetDeployMu.Unlock()

	for _, sid := range serverIDs {
		if _, _, err := s.validateFleetPair(sourceServerID, sid); err != nil {
			log.Printf("cross-deploy redirect target %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sourceServerID, actor, "redirect_cross_deploy", fmt.Sprintf("server:%d", sid), err.Error(), false)
			continue
		}
		s.ensureReferencedCertificate(actor, sourceServerID, sid, rh.CertificateID)
		result, err := s.upsertFleetRedirectionHost(sourceServerID, sid, *rh, 0)
		if err != nil {
			log.Printf("cross-deploy redirect to server %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sid, actor, "redirect_cross_deploy", "redirect:new", rh.Domains, false)
			continue
		}
		detail := "already current " + rh.Domains
		if result.Created {
			detail = "created " + rh.Domains
		} else if result.Changed {
			detail = "updated " + rh.Domains
		}
		_ = models.LogActivity(s.DB, sid, actor, "redirect_cross_deploy", fmt.Sprintf("redirect:%d", result.ID), detail, true)
		if result.Changed {
			if err := s.syncCaddy(sid, false); err != nil {
				log.Printf("cross-deploy redirect sync server %d: %v", sid, err)
			}
		}
	}
}

// crossDeployRawRoute mirrors an advanced (raw) route onto the given fleet
// targets, exactly as crossDeployProxyHost/crossDeployRedirectionHost do for
// their resource types.
//
// v2.27.0 (issue #38): advanced routes were the only resource with no "Also
// deploy to" option. The only way to get one onto a second node was a full
// fleet sync of the destination, which overwrites everything else configured
// there — a destructive workaround for a routine task. The fleet upsert
// primitive (upsertFleetRawRoute) already existed for the whole-fleet sync
// path; this just wires it to the per-route form like the other two types.
func (s *Server) crossDeployRawRoute(actor string, sourceServerID int64, rr *models.RawRoute, serverIDs []int64) {
	s.fleetDeployMu.Lock()
	defer s.fleetDeployMu.Unlock()

	// v2.33.0 — see crossDeployProxyHost.
	if rr.NodeLocal {
		_ = models.LogActivity(s.DB, sourceServerID, actor, "raw_cross_deploy", fmt.Sprintf("raw:%d", rr.ID),
			"skipped: route is marked node-local", false)
		return
	}

	for _, sid := range serverIDs {
		if _, _, err := s.validateFleetPair(sourceServerID, sid); err != nil {
			log.Printf("cross-deploy raw route target %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sourceServerID, actor, "raw_cross_deploy", fmt.Sprintf("server:%d", sid), err.Error(), false)
			continue
		}
		s.ensureReferencedCertificate(actor, sourceServerID, sid, rr.CertificateID)
		result, err := s.upsertFleetRawRoute(sourceServerID, sid, *rr, 0)
		if err != nil {
			log.Printf("cross-deploy raw route to server %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sid, actor, "raw_cross_deploy", "raw:new", rr.Label, false)
			continue
		}
		detail := "already current " + rr.Label
		if result.Created {
			detail = "created " + rr.Label
		} else if result.Changed {
			detail = "updated " + rr.Label
		}
		_ = models.LogActivity(s.DB, sid, actor, "raw_cross_deploy", fmt.Sprintf("raw:%d", result.ID), detail, true)
		if result.Changed {
			if err := s.syncCaddy(sid, false); err != nil {
				log.Printf("cross-deploy raw route sync server %d: %v", sid, err)
			}
		}
	}
}

// parsePEMExpiry decodes the first PEM certificate block in pemData and
// returns its NotAfter expiry time, or nil if it cannot be parsed.
func parsePEMExpiry(pemData string) *time.Time {
	cert := parsePEMLeaf(pemData)
	if cert == nil {
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
	IsUnused  bool // custom PEM/path certificate with no resource reference
	Lifecycle *models.CertificateLifecycleStatus
	// v2.39.0: where ExpiresAt came from — "stored" (PEM in the DB), "file"
	// (CertPath readable from this container) or "probe" (the last live TLS
	// handshake with the node, see certificate_probe.go). Probe is the last
	// probe result for any custom certificate; ServedDiffers flags a file or
	// stored PEM whose serial is not what Caddy is serving — typically a
	// renewed file Caddy has not reloaded yet.
	ExpirySource  string
	Probe         *liveCertificateInfo
	ServedDiffers bool
}

type autoDomainView struct {
	Domain          string
	CertificateName string
	UsesWildcard    bool
	Lifecycle       *models.CertificateLifecycleStatus
}

func certificateLifecycleForDomains(states []models.CertificateLifecycleStatus, domains []string) *models.CertificateLifecycleStatus {
	priority := map[string]int{"active": 1, "obtaining": 2, "renewing": 3, "retrying": 4, "error": 5, "revoked": 6}
	var best *models.CertificateLifecycleStatus
	for i := range states {
		identifier := models.NormalizeHostname(states[i].Identifier)
		matched := false
		for _, domain := range domains {
			domain = models.NormalizeHostname(domain)
			if identifier == domain || managedCertificateCovers(identifier, domain) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if best == nil || priority[states[i].Phase] > priority[best.Phase] ||
			(priority[states[i].Phase] == priority[best.Phase] && states[i].UpdatedAt.After(best.UpdatedAt)) {
			candidate := states[i]
			best = &candidate
		}
	}
	return best
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
	type profileEntry struct {
		ID          string
		ProviderID  string
		DisplayName string
		Legacy      bool
	}
	enabled := []providerEntry{}
	profiles := []profileEntry{}
	for _, d := range dns.Descriptors() {
		if dns.CredsComplete(d.ID, s.dnsCreds(d.ID)) {
			enabled = append(enabled, providerEntry{ID: d.ID, DisplayName: d.DisplayName})
			profiles = append(profiles, profileEntry{
				ID:          "legacy:" + d.ID,
				ProviderID:  d.ID,
				DisplayName: d.DisplayName + " (default settings)",
				Legacy:      true,
			})
		}
	}
	for _, p := range s.loadDNSProfiles() {
		if !dns.CredsComplete(p.ProviderID, p.Credentials) {
			continue
		}
		providerName := p.ProviderID
		if d, ok := dns.Lookup(p.ProviderID); ok {
			providerName = d.DisplayName
		}
		profiles = append(profiles, profileEntry{
			ID:          p.ID,
			ProviderID:  p.ProviderID,
			DisplayName: p.Name + " (" + providerName + ")",
		})
		enabled = append(enabled, providerEntry{ID: p.ProviderID, DisplayName: providerName})
	}
	return map[string]any{
		"DNSProviders":    enabled,
		"DNSProfiles":     profiles,
		"AnyDNSEnabled":   len(profiles) > 0,
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
	// New hosts open in the guided publish workflow by default. Experienced
	// operators can opt into the full several-hundred-field editor explicitly;
	// edit routes remain advanced so existing configuration is never hidden.
	guided := r.URL.Query().Get("mode") != "advanced"
	s.render(w, r, "proxy_host_form.html", s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         &models.ProxyHost{Enabled: true, SSLEnabled: true, SSLForced: true, HTTP2Support: true, ForwardScheme: "http"},
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Guided":       guided,
		"Section":      "proxy",
	}))
}

func (s *Server) createProxyHost(w http.ResponseWriter, r *http.Request) {
	p, err := parseProxyHostForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyDNSFormSelection(p)
	if errMsg := validateSSLFlags(p.SSLEnabled, p.SSLForced, p.CertificateID); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	if errMsg := s.validateProxyAdvanced(s.caddyForRequest(r), p); errMsg != "" {
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
	if errMsg := s.validateManagedDNSRecordTarget(s.currentServerID(r), p.DNSProvider, p.DNSZoneID, p.DNSSkipRecord); errMsg != "" {
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
	// SSRF guard (GHSA-r4wm-rgc5-q834): block non-admins from pointing the
	// upstream (host, extra upstreams, or Host override) at loopback/link-local/
	// internal management addresses such as the Caddy admin API.
	if msg := s.validateProxyUpstreamsForUser(cu, p); msg != "" {
		s.renderProxyHostFormError(w, r, p, msg)
		return
	}
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
	// v2.42.1 (issue #74): refuse a host Caddy would not load instead of
	// saving it and failing every later sync.
	if errMsg := s.previewProxyHostValidate(s.currentServerID(r), p); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	id, err := models.CreateProxyHost(s.DB, s.currentServerID(r), ownerID, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.ID = id
	p.ServerID = s.currentServerID(r)
	if err := models.UpdateProxyHostDNSProfile(s.DB, id, p.DNSProfileID); err != nil {
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
	dnsWorkflow := p.DNSProvider != "" && p.DNSZoneID != ""
	if dnsWorkflow && !p.DNSSkipRecord {
		s.dnsCreateRecord(s.currentServerID(r), id, p)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "proxy_create", fmt.Sprintf("proxy:%d", id), p.Domains, true)
	s.trySyncCaddy(s.currentServerID(r), p.CertificateID != 0)
	{
		// v2.12.51: sendNotification fans out to every configured channel
		// (generic webhook + ntfy + future Telegram/Discord/Gotify) and
		// runs each in its own goroutine, replacing the per-channel
		// `if URL { go func() }` pattern that used to live here.
		payload, _ := json.Marshal(map[string]any{
			"event":   "proxy_host_created",
			"message": "Proxy host created: " + p.Domains,
			"domains": p.Domains,
		})
		sendNotification(s.DB, payload)
	}
	if len(deployTo) > 0 {
		s.crossDeployProxyHost(s.currentUserEmail(r), s.currentServerID(r), p, deployTo)
	}
	// v2.5.2: when a managed DNS record was created, park the user on the
	// deploying page so they can watch DNS propagate + cert issue instead
	// of landing on an "active" row that can't actually be opened yet.
	if dnsWorkflow {
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
	s.applyDNSFormSelection(p)
	if errMsg := validateSSLFlags(p.SSLEnabled, p.SSLForced, p.CertificateID); errMsg != "" {
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	if errMsg := s.validateProxyAdvanced(s.caddyForRequest(r), p); errMsg != "" {
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
	if errMsg := s.validateManagedDNSRecordTarget(s.currentServerID(r), p.DNSProvider, p.DNSZoneID, p.DNSSkipRecord); errMsg != "" {
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
	// SSRF guard (GHSA-r4wm-rgc5-q834): re-validate on edit so a non-admin can't
	// switch an existing host's upstream to an internal management address.
	if msg := s.validateProxyUpstreamsForUser(cu, p); msg != "" {
		s.renderProxyHostFormError(w, r, p, msg)
		return
	}
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
	profileChanged := old != nil && old.DNSProfileID != p.DNSProfileID
	zoneChanged := old != nil && old.DNSZoneID != p.DNSZoneID
	recordModeChanged := old != nil && old.DNSSkipRecord != p.DNSSkipRecord
	needDelete := old != nil && old.DNSRecordID != "" &&
		(p.DNSProvider == "" || p.DNSSkipRecord || providerChanged || profileChanged || zoneChanged || domainChanged || recordModeChanged)
	if needDelete {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
		p.DNSRecordID = ""
	} else if old != nil {
		// Preserve existing record + zone metadata when nothing routing-
		// relevant changed. The form doesn't resubmit record IDs, so
		// without this the DB save would clear it.
		p.DNSRecordID = old.DNSRecordID
	}
	needCreate := p.DNSProvider != "" && p.DNSZoneID != "" && !p.DNSSkipRecord &&
		(p.DNSRecordID == "" || providerChanged || profileChanged || zoneChanged || domainChanged || recordModeChanged)

	if errMsg := s.previewProxyHostValidate(s.currentServerID(r), p); errMsg != "" { // v2.42.1 (issue #74)
		s.renderProxyHostFormError(w, r, p, errMsg)
		return
	}
	if err := models.UpdateProxyHost(s.DB, p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := models.UpdateProxyHostDNSProfile(s.DB, p.ID, p.DNSProfileID); err != nil {
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
	s.trySyncCaddy(s.currentServerID(r), forceTLS)
	{
		payload, _ := json.Marshal(map[string]any{
			"event":   "proxy_host_updated",
			"message": "Proxy host updated: " + p.Domains,
			"domains": p.Domains,
		})
		sendNotification(s.DB, payload)
	}
	if len(deployTo) > 0 {
		s.crossDeployProxyHost(s.currentUserEmail(r), s.currentServerID(r), p, deployTo)
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
		s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
	}
	if err := models.DeleteProxyHost(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "proxy_delete", fmt.Sprintf("proxy:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.trySyncCaddy(s.currentServerID(r), forceTLS)
	if old != nil {
		payload, _ := json.Marshal(map[string]any{
			"event":   "proxy_host_deleted",
			"message": "Proxy host deleted: " + old.Domains,
			"domains": old.Domains,
		})
		sendNotification(s.DB, payload)
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
	_ = models.UpdateProxyHostDNSProfile(s.DB, newID, clone.DNSProfileID)
	http.Redirect(w, r, fmt.Sprintf("/proxy-hosts/%d/edit", newID), http.StatusSeeOther)
}
