// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// ─── REST JSON API v1 ─────────────────────────────────────────────────────────
//
// All endpoints are under /api/v1/ and live inside the requireAuth middleware
// group, so both session cookies and Bearer API tokens are accepted.
// Write endpoints (POST/PUT/DELETE) additionally require a write-scoped token
// or an admin/write role — the requireWrite middleware enforces that at the
// chi group level.

// GET /api/v1/servers
func (s *Server) apiV1ListServers(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(servers))
	for _, srv := range servers {
		var lastContactAt any
		if srv.LastContactAt.Valid {
			lastContactAt = srv.LastContactAt.Time.UTC()
		}
		out = append(out, map[string]any{
			"id":              srv.ID,
			"name":            srv.Name,
			"admin_url":       srv.AdminURL,
			"type":            srv.Type,
			"status":          srv.Status,
			"version":         srv.Version,
			"tags":            srv.TagList(),
			"last_contact_at": lastContactAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

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
		"id":                        p.ID,
		"server_id":                 p.ServerID,
		"domains":                   p.Domains,
		"forward_scheme":            p.ForwardScheme,
		"forward_host":              p.ForwardHost,
		"forward_port":              p.ForwardPort,
		"websocket_support":         p.WebsocketSupport,
		"block_common_exploits":     p.BlockCommonExploits,
		"ssl_enabled":               p.SSLEnabled,
		"ssl_forced":                p.SSLForced,
		"http2_support":             p.HTTP2Support,
		"enabled":                   p.Enabled,
		"certificate_id":            p.CertificateID,
		"basicauth_enabled":         p.BasicAuthEnabled,
		"access_list":               p.AccessList,
		"ip_blocklist":              p.IPBlocklist,
		"extra_upstreams":           p.ExtraUpstreams,
		"compression_enabled":       p.CompressionEnabled,
		"security_headers_enabled":  p.SecurityHeadersEnabled,
		"tls_min_version":           p.TLSMinVersion,
		"maintenance_mode":          p.MaintenanceMode,
		"maintenance_msg":           p.MaintenanceMsg,
		"max_request_body_mb":       p.MaxRequestBodyMB,
		"sticky_sessions":           p.StickySessions,
		"lb_policy":                 p.LBPolicy,
		"upstream_timeout_sec":      p.UpstreamTimeoutSec,
		"cors_enabled":              p.CORSEnabled,
		"cors_origins":              p.CORSOrigins,
		"health_check_uri":          p.HealthCheckURI,
		"health_check_interval_sec": p.HealthCheckIntervalSec,
		"health_check_method":       p.HealthCheckMethod,
		"keepalive_conns":           p.KeepaliveConns,
		"tags":                      p.Tags,
		"notes":                     p.Notes,
		"disable_access_log":        p.DisableAccessLog,
		"add_request_id":            p.AddRequestID,
		"strip_resp_headers":        p.StripRespHeaders,
		"blocked_agents":            p.BlockedAgents,
		"upstream_sni":              p.UpstreamSNI,
		"hsts_preload":              p.HSTSPreload,
		"max_conns_per_host":        p.MaxConnsPerHost,
		"upstream_retries":          p.UpstreamRetries,
		"force_http1":               p.ForceHTTP1,
		"proxy_protocol":            p.ProxyProtocol,
		"owner_email":               p.OwnerEmail,
		"created_at":                p.CreatedAt,
		"updated_at":                p.UpdatedAt,
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
// apiV1OwnerOK reports whether cu may read or modify a row owned by ownerID.
// Admins may access every row; any other authenticated account (role "user"
// or "view") may access only rows it validly owns. A nil user or an unowned
// (NULL owner) row is denied for non-admins — deny by default. This is the
// single per-row authorization gate shared by every /api/v1/... handler,
// mirroring the ownership check the HTML-form handlers already enforce, so a
// future REST endpoint cannot silently omit it. Fixes GHSA-r4wm-rgc5-q834.
func apiV1OwnerOK(cu *models.User, ownerID sql.NullInt64) bool {
	if cu == nil {
		return false
	}
	if cu.IsAdmin {
		return true
	}
	return ownerID.Valid && ownerID.Int64 == cu.ID
}

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
	if !apiV1OwnerOK(cu, ph.OwnerID) {
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
		TLSMinVersion:   inp.TLSMinVersion,
		MaintenanceMode: inp.MaintenanceMode, MaintenanceMsg: inp.MaintenanceMsg,
		MaxRequestBodyMB: inp.MaxRequestBodyMB, StickySessions: inp.StickySessions,
		LBPolicy: inp.LBPolicy, UpstreamTimeoutSec: inp.UpstreamTimeoutSec,
		CORSEnabled: inp.CORSEnabled, CORSOrigins: func() string {
			if inp.CORSOrigins == "" {
				return "*"
			}
			return inp.CORSOrigins
		}(),
		HealthCheckURI: inp.HealthCheckURI, HealthCheckIntervalSec: func() int {
			if inp.HealthCheckIntervalSec <= 0 {
				return 30
			}
			return inp.HealthCheckIntervalSec
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
	// SSRF guard (GHSA-r4wm-rgc5-q834): non-admins may not point an upstream at
	// loopback/link-local/internal management addresses (e.g. the Caddy admin API).
	if msg := s.validateProxyUpstreamsForUser(cu, ph); msg != "" {
		writeJSONError(w, http.StatusForbidden, msg)
		return
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
	s.trySyncCaddy(serverID, false)
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
	if !apiV1OwnerOK(cu, existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp apiProxyHostInput
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	// Merge: any field not supplied keeps the existing value.
	if inp.Domains != "" {
		existing.Domains = inp.Domains
	}
	if inp.ForwardScheme != "" {
		existing.ForwardScheme = inp.ForwardScheme
	}
	if inp.ForwardHost != "" {
		existing.ForwardHost = inp.ForwardHost
	}
	if inp.ForwardPort != 0 {
		existing.ForwardPort = inp.ForwardPort
	}
	if inp.CertificateID != 0 {
		existing.CertificateID = inp.CertificateID
	}
	if inp.TLSMinVersion != "" {
		existing.TLSMinVersion = inp.TLSMinVersion
	}
	if inp.MaintenanceMsg != "" {
		existing.MaintenanceMsg = inp.MaintenanceMsg
	}
	if inp.MaxRequestBodyMB != 0 {
		existing.MaxRequestBodyMB = inp.MaxRequestBodyMB
	}
	if inp.UpstreamTimeoutSec != 0 {
		existing.UpstreamTimeoutSec = inp.UpstreamTimeoutSec
	}
	if inp.CORSOrigins != "" {
		existing.CORSOrigins = inp.CORSOrigins
	}
	if inp.HealthCheckURI != "" {
		existing.HealthCheckURI = inp.HealthCheckURI
	}
	if inp.HealthCheckIntervalSec != 0 {
		existing.HealthCheckIntervalSec = inp.HealthCheckIntervalSec
	}
	if inp.HealthCheckMethod != "" {
		existing.HealthCheckMethod = inp.HealthCheckMethod
	}
	if inp.KeepaliveConns != 0 {
		existing.KeepaliveConns = inp.KeepaliveConns
	}
	if inp.StripRespHeaders != "" {
		existing.StripRespHeaders = inp.StripRespHeaders
	}
	if inp.BlockedAgents != "" {
		existing.BlockedAgents = inp.BlockedAgents
	}
	if inp.UpstreamSNI != "" {
		existing.UpstreamSNI = inp.UpstreamSNI
	}
	if inp.MaxConnsPerHost != 0 {
		existing.MaxConnsPerHost = inp.MaxConnsPerHost
	}
	if inp.UpstreamRetries != 0 {
		existing.UpstreamRetries = inp.UpstreamRetries
	}
	if inp.ProxyProtocol != "" {
		existing.ProxyProtocol = inp.ProxyProtocol
	}
	if inp.ExtraUpstreams != "" {
		existing.ExtraUpstreams = inp.ExtraUpstreams
	}
	existing.WebsocketSupport = inp.WebsocketSupport
	existing.BlockCommonExploits = inp.BlockCommonExploits
	existing.SSLEnabled = inp.SSLEnabled
	existing.SSLForced = inp.SSLForced
	existing.HTTP2Support = inp.HTTP2Support
	existing.Enabled = inp.Enabled
	existing.BasicAuthEnabled = inp.BasicAuthEnabled
	existing.CompressionEnabled = inp.CompressionEnabled
	existing.SecurityHeadersEnabled = inp.SecurityHeadersEnabled
	existing.MaintenanceMode = inp.MaintenanceMode
	existing.StickySessions = inp.StickySessions
	existing.CORSEnabled = inp.CORSEnabled
	existing.DisableAccessLog = inp.DisableAccessLog
	existing.AddRequestID = inp.AddRequestID
	existing.HSTSPreload = inp.HSTSPreload
	existing.ForceHTTP1 = inp.ForceHTTP1
	if inp.Tags != "" {
		existing.Tags = inp.Tags
	}
	if inp.Notes != "" {
		existing.Notes = inp.Notes
	}
	if inp.AccessList != "" {
		existing.AccessList = inp.AccessList
	}
	if inp.IPBlocklist != "" {
		existing.IPBlocklist = inp.IPBlocklist
	}
	if inp.LBPolicy != "" {
		existing.LBPolicy = inp.LBPolicy
	}
	// SSRF guard (GHSA-r4wm-rgc5-q834): re-validate the merged upstreams so a
	// non-admin can't edit an existing host to target an internal address.
	if msg := s.validateProxyUpstreamsForUser(cu, existing); msg != "" {
		writeJSONError(w, http.StatusForbidden, msg)
		return
	}
	if err := models.UpdateProxyHost(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, existing.ServerID, s.currentUserEmail(r), "proxy_update", fmt.Sprintf("proxy:%d", id), existing.Domains, true)
	s.trySyncCaddy(existing.ServerID, existing.CertificateID != 0)
	updated, _ := models.GetProxyHost(s.DB, id)
	if updated == nil {
		updated = existing
	}
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
	if !apiV1OwnerOK(cu, ph.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if ph.DNSRecordID != "" {
		s.dnsDeleteRecord(ph.DNSProvider, ph.DNSProfileID, ph.DNSZoneID, ph.DNSZoneName, ph.DNSRecordID)
	}
	if err := models.DeleteProxyHost(s.DB, id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, ph.ServerID, s.currentUserEmail(r), "proxy_delete", fmt.Sprintf("proxy:%d", id), ph.Domains, true)
	s.trySyncCaddy(ph.ServerID, false)
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
	if !apiV1OwnerOK(s.currentUser(r), ph.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	ph.Enabled = !ph.Enabled
	if err := models.UpdateProxyHost(s.DB, ph); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.trySyncCaddy(ph.ServerID, false)
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
	if !apiV1OwnerOK(s.currentUser(r), ph.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
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
	s.trySyncCaddy(ph.ServerID, false)
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
	if !apiV1OwnerOK(s.currentUser(r), rh.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
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
	if inp.ForwardScheme == "" {
		inp.ForwardScheme = "auto"
	}
	if inp.ForwardHTTPCode == 0 {
		inp.ForwardHTTPCode = 301
	}
	rh := &models.RedirectionHost{
		Domains: inp.Domains, ForwardScheme: inp.ForwardScheme,
		ForwardDomain: inp.ForwardDomain, ForwardHTTPCode: inp.ForwardHTTPCode,
		PreservePath: inp.PreservePath, SSLEnabled: inp.SSLEnabled, SSLForced: inp.SSLForced,
		Enabled: inp.Enabled, CertificateID: inp.CertificateID,
		Tags: inp.Tags, Notes: inp.Notes,
	}
	serverID := s.currentServerID(r)
	ownerID := int64(0)
	if !cu.IsAdmin {
		ownerID = cu.ID
	}
	newID, err := models.CreateRedirectionHost(s.DB, serverID, ownerID, rh)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "redirect_create", fmt.Sprintf("redir:%d", newID), rh.Domains, true)
	s.trySyncCaddy(serverID, false)
	created, _ := models.GetRedirectionHost(s.DB, newID)
	if created == nil {
		created = rh
		created.ID = newID
	}
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
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
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
	if inp.Domains != "" {
		existing.Domains = inp.Domains
	}
	if inp.ForwardScheme != "" {
		existing.ForwardScheme = inp.ForwardScheme
	}
	if inp.ForwardDomain != "" {
		existing.ForwardDomain = inp.ForwardDomain
	}
	if inp.ForwardHTTPCode != 0 {
		existing.ForwardHTTPCode = inp.ForwardHTTPCode
	}
	existing.PreservePath = inp.PreservePath
	existing.SSLEnabled = inp.SSLEnabled
	existing.SSLForced = inp.SSLForced
	existing.Enabled = inp.Enabled
	if inp.Tags != "" {
		existing.Tags = inp.Tags
	}
	if inp.Notes != "" {
		existing.Notes = inp.Notes
	}
	if err := models.UpdateRedirectionHost(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_update", fmt.Sprintf("redir:%d", id), existing.Domains, true)
	s.trySyncCaddy(s.currentServerID(r), false)
	updated, _ := models.GetRedirectionHost(s.DB, id)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, redirectionHostToAPIMap(updated))
}

// DELETE /api/v1/redirection-hosts/{id}
func (s *Server) apiV1DeleteRedirectionHost(w http.ResponseWriter, r *http.Request) {
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
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := models.DeleteRedirectionHost(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "redirect_delete", fmt.Sprintf("redir:%d", id), "", true)
	s.trySyncCaddy(s.currentServerID(r), false)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// POST /api/v1/redirection-hosts/{id}/toggle
func (s *Server) apiV1ToggleRedirectionHost(w http.ResponseWriter, r *http.Request) {
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
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	enabled, err := models.ToggleRedirectionHost(s.DB, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found or error: "+err.Error())
		return
	}
	rh, _ := models.GetRedirectionHost(s.DB, id)
	if rh != nil {
		s.syncCaddy(s.currentServerID(r), false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": enabled})
}

// --- REST JSON API v1: Raw Routes ---

func rawRouteToAPIMap(r *models.RawRoute) map[string]any {
	return map[string]any{
		"id":                    r.ID,
		"label":                 r.Label,
		"listen":                r.ListenDisplay(), // v2.36.1 (issue #64)
		"json_data":             r.JSONData,
		"caddyfile_src":         r.CaddyfileSrc,
		"enabled":               r.Enabled,
		"certificate_id":        r.CertificateID,
		"force_ssl":             r.ForceSSL,
		"block_common_exploits": r.BlockCommonExploits,
		"owner_email":           r.OwnerEmail,
		"created_at":            r.CreatedAt,
		"updated_at":            r.UpdatedAt,
	}
}

// GET /api/v1/raw-routes
func (s *Server) apiV1ListRawRoutes(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	routes, err := models.ListRawRoutes(s.DB, s.currentServerID(r), cu.ID, cu.IsAdmin, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(routes))
	for i := range routes {
		out = append(out, rawRouteToAPIMap(&routes[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/raw-routes/{id}
func (s *Server) apiV1GetRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rr, err := models.GetRawRoute(s.DB, id)
	if err != nil || rr == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !apiV1OwnerOK(s.currentUser(r), rr.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, rawRouteToAPIMap(rr))
}

// POST /api/v1/raw-routes
func (s *Server) apiV1CreateRawRoute(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp struct {
		Label               string `json:"label"`
		JSONData            string `json:"json_data"`
		CaddyfileSrc        string `json:"caddyfile_src"`
		Enabled             bool   `json:"enabled"`
		CertificateID       int64  `json:"certificate_id"`
		ForceSSL            bool   `json:"force_ssl"`
		BlockCommonExploits bool   `json:"block_common_exploits"`
		Listen              string `json:"listen"` // v2.36.1 (issue #64): e.g. ":7070" or ":7070, :7071"
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.JSONData == "" {
		writeJSONError(w, http.StatusBadRequest, "json_data is required")
		return
	}
	rr := &models.RawRoute{
		Label: inp.Label, JSONData: inp.JSONData, CaddyfileSrc: inp.CaddyfileSrc,
		Enabled: inp.Enabled, CertificateID: inp.CertificateID,
		ForceSSL: inp.ForceSSL, BlockCommonExploits: inp.BlockCommonExploits,
		Listen: models.NormalizeRawRouteListen(models.ParseRawRouteListenInput(inp.Listen)), // v2.36.1 (issue #64)
	}
	serverID := s.currentServerID(r)
	ownerID := int64(0)
	if !cu.IsAdmin {
		ownerID = cu.ID
	}
	newID, err := models.CreateRawRoute(s.DB, serverID, ownerID, rr)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "rawroute_create", fmt.Sprintf("rr:%d", newID), inp.Label, true)
	s.trySyncCaddy(serverID, false)
	created, _ := models.GetRawRoute(s.DB, newID)
	if created == nil {
		created = rr
		created.ID = newID
	}
	writeJSON(w, http.StatusCreated, rawRouteToAPIMap(created))
}

// PUT /api/v1/raw-routes/{id}
func (s *Server) apiV1UpdateRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRawRoute(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp struct {
		Label               string `json:"label"`
		JSONData            string `json:"json_data"`
		CaddyfileSrc        string `json:"caddyfile_src"`
		Enabled             bool   `json:"enabled"`
		CertificateID       int64  `json:"certificate_id"`
		ForceSSL            bool   `json:"force_ssl"`
		BlockCommonExploits bool   `json:"block_common_exploits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Label != "" {
		existing.Label = inp.Label
	}
	if inp.JSONData != "" {
		existing.JSONData = inp.JSONData
	}
	if inp.CaddyfileSrc != "" {
		existing.CaddyfileSrc = inp.CaddyfileSrc
	}
	existing.Enabled = inp.Enabled
	existing.ForceSSL = inp.ForceSSL
	existing.BlockCommonExploits = inp.BlockCommonExploits
	if inp.CertificateID != 0 {
		existing.CertificateID = inp.CertificateID
	}
	if err := models.UpdateRawRoute(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "rawroute_update", fmt.Sprintf("rr:%d", id), existing.Label, true)
	s.trySyncCaddy(s.currentServerID(r), false)
	updated, _ := models.GetRawRoute(s.DB, id)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, rawRouteToAPIMap(updated))
}

// DELETE /api/v1/raw-routes/{id}
func (s *Server) apiV1DeleteRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRawRoute(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if err := models.DeleteRawRoute(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "rawroute_delete", fmt.Sprintf("rr:%d", id), "", true)
	s.trySyncCaddy(s.currentServerID(r), false)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}

// POST /api/v1/raw-routes/{id}/toggle
func (s *Server) apiV1ToggleRawRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetRawRoute(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	enabled, err := models.ToggleRawRoute(s.DB, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not found or error: "+err.Error())
		return
	}
	rr, _ := models.GetRawRoute(s.DB, id)
	if rr != nil {
		s.syncCaddy(s.currentServerID(r), false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": enabled})
}

// --- REST JSON API v1: Certificates ---

func certificateToAPIMap(c *models.Certificate) map[string]any {
	ownerID := int64(0)
	if c.OwnerID.Valid {
		ownerID = c.OwnerID.Int64
	}
	return map[string]any{
		"id":             c.ID,
		"name":           c.Name,
		"domains":        c.Domains,
		"source":         c.Source,
		"cert_pem":       c.CertPEM,
		"key_pem":        c.KeyPEM,
		"cert_path":      c.CertPath,
		"key_path":       c.KeyPath,
		"dns_provider":   c.DNSProvider,
		"dns_profile_id": c.DNSProfileID,
		"owner_id":       ownerID,
		"owner_email":    c.OwnerEmail,
		"created_at":     c.CreatedAt,
		"updated_at":     c.UpdatedAt,
	}
}

// GET /api/v1/certificates
func (s *Server) apiV1ListCertificates(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	certs, err := models.ListCertificatesForUser(s.DB, s.currentServerID(r), cu.ID, cu.IsAdmin, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(certs))
	for i := range certs {
		out = append(out, certificateToAPIMap(&certs[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/v1/certificates/{id}
func (s *Server) apiV1GetCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := models.GetCertificate(s.DB, id)
	if err != nil || c == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !apiV1OwnerOK(s.currentUser(r), c.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, certificateToAPIMap(c))
}

// POST /api/v1/certificates
func (s *Server) apiV1CreateCertificate(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var inp struct {
		Name         string `json:"name"`
		Domains      string `json:"domains"`
		Source       string `json:"source"`
		CertPEM      string `json:"cert_pem"`
		KeyPEM       string `json:"key_pem"`
		CertPath     string `json:"cert_path"`
		KeyPath      string `json:"key_path"`
		DNSProvider  string `json:"dns_provider"`
		DNSProfileID string `json:"dns_profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Name == "" {
		writeJSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if inp.Source == "" {
		inp.Source = "pem"
	}
	c := &models.Certificate{
		Name: inp.Name, Domains: inp.Domains, Source: inp.Source,
		CertPEM: inp.CertPEM, KeyPEM: inp.KeyPEM,
		CertPath: inp.CertPath, KeyPath: inp.KeyPath,
		DNSProvider: inp.DNSProvider, DNSProfileID: inp.DNSProfileID,
	}
	serverID := s.currentServerID(r)
	ownerID := int64(0)
	if !cu.IsAdmin {
		ownerID = cu.ID
	}
	newID, err := models.CreateCertificate(s.DB, serverID, ownerID, c)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, serverID, cu.Email, "cert_create", fmt.Sprintf("cert:%d", newID), inp.Name, true)
	created, _ := models.GetCertificate(s.DB, newID)
	if created == nil {
		created = c
		created.ID = newID
	}
	writeJSON(w, http.StatusCreated, certificateToAPIMap(created))
}

// PUT /api/v1/certificates/{id}
func (s *Server) apiV1UpdateCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetCertificate(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	var inp struct {
		Name         string `json:"name"`
		Domains      string `json:"domains"`
		Source       string `json:"source"`
		CertPEM      string `json:"cert_pem"`
		KeyPEM       string `json:"key_pem"`
		CertPath     string `json:"cert_path"`
		KeyPath      string `json:"key_path"`
		DNSProvider  string `json:"dns_provider"`
		DNSProfileID string `json:"dns_profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&inp); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if inp.Name != "" {
		existing.Name = inp.Name
	}
	if inp.Domains != "" {
		existing.Domains = inp.Domains
	}
	if inp.Source != "" {
		existing.Source = inp.Source
	}
	if inp.CertPEM != "" {
		existing.CertPEM = inp.CertPEM
	}
	if inp.KeyPEM != "" {
		existing.KeyPEM = inp.KeyPEM
	}
	if inp.CertPath != "" {
		existing.CertPath = inp.CertPath
	}
	if inp.KeyPath != "" {
		existing.KeyPath = inp.KeyPath
	}
	if inp.DNSProvider != "" {
		existing.DNSProvider = inp.DNSProvider
	}
	if inp.DNSProfileID != "" {
		existing.DNSProfileID = inp.DNSProfileID
	}
	if err := models.UpdateCertificate(s.DB, existing); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_update", fmt.Sprintf("cert:%d", id), existing.Name, true)
	updated, _ := models.GetCertificate(s.DB, id)
	if updated == nil {
		updated = existing
	}
	writeJSON(w, http.StatusOK, certificateToAPIMap(updated))
}

// DELETE /api/v1/certificates/{id}
func (s *Server) apiV1DeleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid id")
		return
	}
	existing, err := models.GetCertificate(s.DB, id)
	if err != nil || existing == nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	if !apiV1OwnerOK(s.currentUser(r), existing.OwnerID) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	if inUse, _ := models.CertificateInUse(s.DB, id); inUse > 0 {
		writeJSONError(w, http.StatusConflict, "certificate is in use by one or more hosts; remove references first")
		return
	}
	if err := models.DeleteCertificate(s.DB, id); err != nil {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_delete", fmt.Sprintf("cert:%d", id), "", true)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": id})
}
