// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

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
		"OtherServers": s.otherManagedServers(r),
		"Section":      "raw",
	}))
}

func (s *Server) parseRawRouteForm(r *http.Request) (*models.RawRoute, string) {
	_ = r.ParseForm()
	label := strings.TrimSpace(r.FormValue("label"))
	body := strings.TrimSpace(r.FormValue("json_data"))
	cfSrc := strings.TrimSpace(r.FormValue("caddyfile_src"))
	// v2.36.1 (issue #64): optional own listener(s) for this route, e.g. ":7070".
	// Typed in the form for JSON-only routes; when a Caddyfile block declares a
	// site address with a custom port, the adapted value below wins.
	listen := models.NormalizeRawRouteListen(models.ParseRawRouteListenInput(r.FormValue("listen")))
	if label == "" {
		return nil, "Label is required"
	}
	// If the Caddyfile source field is non-empty, it's authoritative — re-adapt
	// through Caddy and let the resulting JSON replace json_data. This is what
	// makes the Caddyfile block editable after import.
	if cfSrc != "" {
		jsonData, adaptedListen, err := s.adaptRawRouteCaddyfile(s.caddyForRequest(r), cfSrc)
		if err != nil {
			return nil, "Caddyfile rejected by Caddy: " + err.Error()
		}
		body = jsonData
		if adaptedListen != "" {
			listen = adaptedListen
		}
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
	return &models.RawRoute{
		Label:               label,
		JSONData:            body,
		CaddyfileSrc:        cfSrc,
		Enabled:             r.FormValue("enabled") == "on",
		CertificateID:       certID,
		ForceSSL:            r.FormValue("ssl_forced") == "on",
		BlockCommonExploits: r.FormValue("block_common_exploits") == "on",
		NodeLocal:           r.FormValue("node_local") == "on", // v2.33.0
		Listen:              listen,                            // v2.36.1 (issue #64)
		DNSProvider:         provider,
		DNSZoneID:           zoneID,
		DNSZoneName:         zoneName,
		DNSProfileID:        profileID,
		DNSSkipRecord:       provider != "" && r.FormValue("dns_create_record") != "on",
	}, ""
}

// adaptRawRouteCaddyfile sends a Caddyfile block (the `caddyfile_src` field of a
// raw_route) through Caddy's /adapt, prepending auto-loaded snippets from the
// mounted Caddyfile so `import <name>` references resolve. Returns the JSON to
// store in raw_routes.json_data — a single route object if the block produced
// exactly one route, or a JSON array otherwise (buildMergedRoutes handles both) —
// and, v2.36.1 (issue #64), the normalised listen set of the block's server(s)
// ("" when it uses the standard ports). One Advanced route is one listen set:
// if a paste holds several site blocks on different custom ports, their routes
// all serve on the union of those ports — split them into separate Advanced
// routes to keep them apart.
func (s *Server) adaptRawRouteCaddyfile(caddyCl *caddy.Client, src string) (string, string, error) {
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
		return "", "", err
	}
	adaptedRoutes := extractAdaptedServerRoutes(adapted.Result)
	if len(adaptedRoutes) == 0 {
		return "", "", fmt.Errorf("the Caddyfile adapted successfully but produced no HTTP routes — include at least one site block")
	}
	var addrs []string
	routes := make([]map[string]any, 0, len(adaptedRoutes))
	for _, ar := range adaptedRoutes {
		routes = append(routes, ar.Route)
		addrs = append(addrs, ar.Listen...)
	}
	listen := models.NormalizeRawRouteListen(addrs)
	if len(routes) == 1 {
		blob, err := json.Marshal(routes[0])
		if err != nil {
			return "", "", fmt.Errorf("serialize route: %w", err)
		}
		return string(blob), listen, nil
	}
	blob, err := json.Marshal(routes)
	if err != nil {
		return "", "", fmt.Errorf("serialize routes: %w", err)
	}
	return string(blob), listen, nil
}

// previewRawRouteValidate simulates syncCaddy with rr swapped into the raw_routes
// list (replacing the entry with the same ID, or appended if new) and calls
// Caddy's /load?validate_only=true. Returns a non-empty message only when Caddy
// would reject the resulting config — so callers can refuse to save instead of
// committing a change that breaks the live config on next sync.
func (s *Server) previewRawRouteValidate(serverID int64, rr *models.RawRoute) string {
	proxies, redirs, raws, certs, ok := s.serverResources(serverID)
	if !ok {
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
	return s.validateProposedConfig(serverID, proxies, redirs, raws, certs)
}

// validateProposedConfig builds the config a sync would push for these
// resources and asks Caddy to validate it. Returns "" when Caddy accepts it
// or cannot be reached — a save must not be blocked by an unrelated outage.
// v2.42.1 (issue #74): shared by the proxy host, redirection and certificate
// forms as well as Advanced routes.
func (s *Server) validateProposedConfig(serverID int64, proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute, certs []models.Certificate) string {
	caddyCl := s.caddyForServer(serverID)
	current, _, err := caddyCl.FetchConfig()
	if err != nil {
		return ""
	}
	proposed, err := deepCopyMap(current)
	if err != nil {
		return ""
	}
	previewRoutes := append(s.buildMergedRoutes(proxies, redirs, raws), buildManagedCertificateRoutes(certs)...)
	httpRoutes := s.buildHTTPRoutes(proxies, redirs, raws)
	// issue #100: mirror the global blocklist prepend so preview validation
	// matches what sync would push.
	if gb := caddy.BuildGlobalBlocklistRoute(mustGetSetting(s.DB, settingGlobalIPBlocklist)); gb != nil {
		previewRoutes = append([]any{gb}, previewRoutes...)
		if len(httpRoutes) > 0 {
			httpRoutes = append([]any{gb}, httpRoutes...)
		}
	}
	applyRoutes(proposed, previewRoutes)
	applyPlainHTTPServer(proposed, httpRoutes)
	applyRawListenServers(proposed, s.buildRawListenServers(raws)) // v2.36.1 (issue #64)
	loadPEM, loadFiles := buildCertLoaders(certs)
	applyCertLoaders(proposed, loadPEM, loadFiles)
	applySkipCertificates(proposed, buildSkipCertificates(proxies, redirs, raws, certs))
	removeUnsupportedSkipRedirects(proposed)
	applyDisableAutomaticHTTPSRedirects(proposed, len(httpRoutes) > 0)
	applySkipAccessLogs(proposed, buildSkipAccessLogs(proxies))
	previewPolicies := s.buildDNSAutomationPolicies(proxies, redirs, raws, certs)
	previewPolicies = append(previewPolicies, buildInternalTLSAutomationPolicies(proxies)...) // v2.46.0
	applyAutomationPolicies(proposed, previewPolicies)
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
	s.applyRawDNSFormSelection(rr)
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
	if errMsg := s.validateManagedDNSRecordTarget(s.currentServerID(r), rr.DNSProvider, rr.DNSZoneID, rr.DNSSkipRecord); errMsg != "" && len(rawRouteHosts(*rr)) > 0 {
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
	if rr.DNSProvider != "" && rr.DNSZoneID != "" && !rr.DNSSkipRecord && firstRawRouteHost(rr.JSONData) != "" {
		s.dnsCreateRecordForRaw(s.currentServerID(r), id, rr)
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "raw_create", fmt.Sprintf("raw:%d", id), rr.Label, true)
	s.trySyncCaddy(s.currentServerID(r), rr.CertificateID != 0)
	// v2.27.0 (issue #38): "Also deploy to" parity with proxy/redirect hosts.
	// rr.ID must be set so upsertFleetRawRoute can key the fleet mapping off
	// the source row. RawRoute carries no ServerID field — the source server
	// is passed separately, as in the proxy/redirect cross-deploy paths.
	if deployTo := parseDeployTo(r); len(deployTo) > 0 {
		rr.ID = id
		s.crossDeployRawRoute(s.currentUserEmail(r), s.currentServerID(r), rr, deployTo)
	}
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
			Listen:              models.NormalizeRawRouteListen(models.ParseRawRouteListenInput(r.FormValue("listen"))), // v2.36.1
			Enabled:             r.FormValue("enabled") == "on",
			CertificateID:       certID,
			ForceSSL:            r.FormValue("ssl_forced") == "on",
			BlockCommonExploits: r.FormValue("block_common_exploits") == "on",
			DNSProvider:         provider,
			DNSZoneID:           zoneID,
			DNSZoneName:         zoneName,
			DNSProfileID:        strings.TrimSpace(r.FormValue("dns_profile_id")),
			DNSSkipRecord:       provider != "" && r.FormValue("dns_create_record") != "on",
		}
		s.applyRawDNSFormSelection(rr)
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
		"OtherServers": s.otherManagedServers(r),
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
		if !s.canManageOwned(cu, rr.OwnerID) {
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
		"OtherServers": s.otherManagedServers(r),
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
		if err != nil || existing == nil || !s.canManageOwned(cu, existing.OwnerID) {
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
	s.applyRawDNSFormSelection(rr)
	// v2.7.8: zone/hostname match — same as create path. Routes with no host
	// matcher skip the check (rawRouteHosts returns nil → validator returns "").
	if errMsg := validateZoneMatchesHostname(rr.DNSProvider, rr.DNSZoneID, rr.DNSZoneName, rawRouteHosts(*rr)); errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	if errMsg := s.validateManagedDNSRecordTarget(s.currentServerID(r), rr.DNSProvider, rr.DNSZoneID, rr.DNSSkipRecord); errMsg != "" && len(rawRouteHosts(*rr)) > 0 {
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
	profileChanged := old != nil && old.DNSProfileID != rr.DNSProfileID
	zoneChanged := old != nil && old.DNSZoneID != rr.DNSZoneID
	recordModeChanged := old != nil && old.DNSSkipRecord != rr.DNSSkipRecord
	needDelete := old != nil && old.DNSRecordID != "" &&
		(rr.DNSProvider == "" || rr.DNSSkipRecord || providerChanged || profileChanged || zoneChanged || fqdnChanged || recordModeChanged)
	if needDelete {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
		rr.DNSRecordID = ""
	} else if old != nil {
		// Preserve existing record ID when nothing routing-relevant
		// changed. The form doesn't resubmit record IDs, so without this
		// the DB save would clear it.
		rr.DNSRecordID = old.DNSRecordID
	}
	needCreate := rr.DNSProvider != "" && rr.DNSZoneID != "" && !rr.DNSSkipRecord && len(newHosts) > 0 &&
		(rr.DNSRecordID == "" || providerChanged || profileChanged || zoneChanged || fqdnChanged || recordModeChanged)

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
	s.trySyncCaddy(s.currentServerID(r), forceTLS)
	// v2.27.0 (issue #38): re-deploy the edited route to any selected targets.
	if deployTo := parseDeployTo(r); len(deployTo) > 0 {
		s.crossDeployRawRoute(s.currentUserEmail(r), s.currentServerID(r), rr, deployTo)
	}
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
		if old == nil || !s.canManageOwned(cu, old.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	// v2.5.6: remove the managed DNS record before deleting the row so we
	// don't orphan it at the provider. No-op when the route has none.
	if old != nil && old.DNSRecordID != "" {
		s.dnsDeleteRecord(old.DNSProvider, old.DNSProfileID, old.DNSZoneID, old.DNSZoneName, old.DNSRecordID)
	}
	if err := models.DeleteRawRoute(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "raw_delete", fmt.Sprintf("raw:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.trySyncCaddy(s.currentServerID(r), forceTLS)
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
			if !s.canManageOwned(cu, row.OwnerID) {
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
		`DELETE FROM activity_log WHERE created_at < ?`,
		time.Now().UTC().AddDate(0, 0, -days),
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
//
// syncCaddy pushes the current DB state to Caddy. If forceTLS is true, the tls
// and automatic_https subtrees are written unconditionally — used when a cert
// assignment changed, since the skip-when-unchanged optimization would otherwise
// mask the change from Caddy. Otherwise we skip tls/auto_https writes when
// effectively unchanged (avoids cancelling in-flight ACME challenges).
//
// trySyncCaddy is the fire-and-forget variant: calls syncCaddy and logs on
// error instead of returning it. v2.12.35: previously, ~18 handlers (proxy/
// redirect/cert/raw-route create/update/delete + AI tool calls + bulk
// actions) silently dropped the sync error. If Caddy rejected the new
// config (e.g. an unknown-field bug like the v2.12.20 `network` issue),
// the DB write succeeded but the live config never updated AND nothing
// was logged. Now every silent caller funnels through this helper so the
// failure at least lands in `docker logs caddyui`.
func (s *Server) trySyncCaddy(serverID int64, forceTLS bool) {
	if err := s.syncCaddy(serverID, forceTLS); err != nil {
		log.Printf("trySyncCaddy(server=%d, forceTLS=%v): %v", serverID, forceTLS, err)
	}
}

// syncPrometheusMetricsOnly handles selected fleet members that do not yet
// have any CaddyUI-managed routes or certificates. The normal empty-database
// guard must still protect user routes, but metrics management should work on
// a fresh server without forcing the administrator to create a dummy host.
func (s *Server) syncPrometheusMetricsOnly(serverID int64, metricsCfg prometheusMetricsConfig) error {
	current, currentJSON, err := s.Caddy.FetchConfig()
	if err != nil {
		return fmt.Errorf("fetch current config for metrics: %w", err)
	}
	proposed, err := deepCopyMap(current)
	if err != nil {
		return fmt.Errorf("clone config for metrics: %w", err)
	}
	applyPrometheusMetrics(proposed, metricsCfg, serverID)
	if err := s.Caddy.Validate(proposed); err != nil {
		return fmt.Errorf("caddy rejected Prometheus metrics config: %w", err)
	}
	if s.autoSnapshotsEnabled() && currentJSON != "" && currentJSON != "null" {
		if _, err := models.CreateSnapshot(s.DB, serverID, models.SnapshotSourceAuto, "auto: before Prometheus metrics sync", currentJSON); err != nil {
			log.Printf("metrics snapshot failed (non-fatal): %v", err)
		}
	}
	if err := s.writePrometheusMetricsConfig(proposed, metricsCfg, serverID); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_metrics_failed", "", err.Error(), false)
		return fmt.Errorf("apply Prometheus metrics: %w", err)
	}
	_ = models.LogActivity(s.DB, serverID, "system", "sync_metrics_applied", "", "metrics-only sync", true)
	return nil
}

// syncCaddy pushes the DB state for serverID to its Caddy and records the
// outcome per server (v2.42.1, issue #74): a failure shows on every page
// until the next successful sync, so a rejected change can no longer fail
// silently in the log while the form says "saved".
func (s *Server) syncCaddy(serverID int64, forceTLS bool) error {
	err := s.syncCaddyInner(serverID, forceTLS)
	if err == nil {
		s.clearSyncError(serverID)
		return nil
	}
	if s.syncHoldFor(serverID) == nil { // a post-apply hold has its own banner
		name := ""
		if srv, lookupErr := models.GetCaddyServer(s.DB, serverID); lookupErr == nil && srv != nil {
			name = srv.Name
		}
		s.setSyncError(serverID, name, err)
	}
	return err
}

func (s *Server) syncCaddyInner(serverID int64, forceTLS bool) error {
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
	// v2.38.0: while a post-apply check hold is set, automatic syncs are
	// skipped so the failing state isn't pushed again. "Re-apply now" on the
	// banner clears the hold first, then syncs.
	if h := s.syncHoldFor(serverID); h != nil {
		log.Printf("caddy sync skipped: server %d (%s) is held after failed post-apply checks — re-apply from the banner", serverID, srv.Name)
		return fmt.Errorf("sync held for %s: post-apply checks failed at %s; re-apply or accept the rolled-back config from the banner", srv.Name, h.At.Format(time.RFC3339))
	}

	// Build a per-server caddy client and swap it in for the duration of this call.
	// syncCaddy is called from HTTP handlers (single goroutine per request) so this
	// temporary swap is safe as long as we don't sync the same server concurrently.
	origClient := s.Caddy
	s.Caddy = newCaddyClient(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	defer func() { s.Caddy = origClient }()
	metricsCfg := loadPrometheusMetricsConfig(s.DB)

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
		if metricsCfg.manages(serverID) {
			return s.syncPrometheusMetricsOnly(serverID, metricsCfg)
		}
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

	accessLogCfg := loadFleetAccessLogConfig(s.DB)
	crowdSecCfg := loadCrowdSecConfig(s.DB)
	routes := append(s.buildMergedRoutes(proxies, redirs, raws), buildManagedCertificateRoutes(certs)...)
	httpRoutes := s.buildHTTPRoutes(proxies, redirs, raws)
	routes = protectRoutesWithCrowdSec(routes, crowdSecCfg, serverID)
	httpRoutes = protectRoutesWithCrowdSec(httpRoutes, crowdSecCfg, serverID)
	// issue #100: fleet-wide IP blocklist — a top-level 403 route ahead of all
	// host routing, on both the HTTPS and (when present) the plain :80 server.
	if gb := caddy.BuildGlobalBlocklistRoute(mustGetSetting(s.DB, settingGlobalIPBlocklist)); gb != nil {
		routes = append([]any{gb}, routes...)
		if len(httpRoutes) > 0 {
			httpRoutes = append([]any{gb}, httpRoutes...)
		}
	}
	// v2.36.1 (issue #64): Advanced routes bound to their own port(s) become
	// separate servers; give them the same CrowdSec protection as the rest.
	rawListenServers := s.buildRawListenServers(raws)
	for name, srv := range rawListenServers {
		if routes, ok := srv["routes"].([]any); ok {
			srv["routes"] = protectRoutesWithCrowdSec(routes, crowdSecCfg, serverID)
		}
		rawListenServers[name] = srv
	}
	loadPEM, loadFiles := buildCertLoaders(certs)
	skipList := buildSkipCertificates(proxies, redirs, raws, certs)
	skipAccessLogs := buildSkipAccessLogs(proxies)
	// v2.9.0: per-SNI TLS minimum-version connection policies. nil when no
	// host has a min version configured — writeTLSConnectionPoliciesSubtree
	// handles the nil case by clearing stale policies that may exist.
	tlsConnPolicies := caddy.BuildTLSConnectionPolicies(proxies)
	// DNS-01 issuance policies plus (v2.46.0) internal-CA issuance policies,
	// pushed together into apps.tls.automation.
	tlsAutomationPolicies := s.buildDNSAutomationPolicies(proxies, redirs, raws, certs)
	tlsAutomationPolicies = append(tlsAutomationPolicies, buildInternalTLSAutomationPolicies(proxies)...)

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
	applyPlainHTTPServer(proposed, httpRoutes)
	applyRawListenServers(proposed, rawListenServers)
	applyListen(proposed)
	applyProtocols(proposed, s.DB)
	applyCertLoaders(proposed, loadPEM, loadFiles)
	applySkipCertificates(proposed, skipList)
	removeUnsupportedSkipRedirects(proposed)
	applyDisableAutomaticHTTPSRedirects(proposed, len(httpRoutes) > 0)
	applySkipAccessLogs(proposed, skipAccessLogs)
	applyTLSConnectionPolicies(proposed, tlsConnPolicies)
	applyAutomationPolicies(proposed, tlsAutomationPolicies)
	applyClientIPSettings(proposed, s.DB)
	applyFleetAccessLog(proposed, accessLogCfg, loadAnalyticsConfig(s.DB).Enabled, serverID)
	applyPrometheusMetrics(proposed, metricsCfg, serverID)
	applyCrowdSecApp(proposed, crowdSecCfg, serverID)
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

	// Apply. Each subtree write is atomic in Caddy. CrowdSec's app must be
	// provisioned before routes that reference its HTTP handler. When disabling,
	// the inverse happens below: routes are cleared first, then the app.
	crowdSecEnabled := crowdSecCfg.enabledFor(serverID)
	if crowdSecEnabled {
		if err := s.writeCrowdSecApp(proposed, true); err != nil {
			_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_crowdsec_failed", "", err.Error(), false)
			return fmt.Errorf("apply CrowdSec app: %w", err)
		}
	}
	if err := s.writeLoggingConfig(proposed); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_access_logger_failed", "", err.Error(), false)
		return fmt.Errorf("apply access logger: %w", err)
	}
	if err := s.writePrometheusMetricsConfig(proposed, metricsCfg, serverID); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_metrics_failed", "", err.Error(), false)
		return fmt.Errorf("apply Prometheus metrics: %w", err)
	}
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
	// Transition port 80 without ever provisioning two listeners at once.
	// When enabling CaddyUI's HTTP server, suppress Caddy's generated redirect
	// listener first. When removing it, delete ours before restoring automatic
	// redirects.
	if len(httpRoutes) > 0 {
		if err := s.writeAutomaticHTTPSSubtree(skipList, true, forceTLS); err != nil {
			_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_autohttps_failed", "", err.Error(), false)
			return err
		}
		if err := s.writePlainHTTPServerSubtree(httpRoutes); err != nil {
			_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_http_routes_failed", "", err.Error(), false)
			return err
		}
	} else {
		if err := s.writePlainHTTPServerSubtree(nil); err != nil {
			_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_http_routes_failed", "", err.Error(), false)
			return err
		}
		if err := s.writeAutomaticHTTPSSubtree(skipList, false, forceTLS); err != nil {
			_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_autohttps_failed", "", err.Error(), false)
			return err
		}
	}
	if err := s.writeRawListenServersSubtree(rawListenServers); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_listen_servers_failed", "", err.Error(), false)
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
	if err := s.writeProtocolsSubtree(s.DB); err != nil {
		// Non-fatal: protocol restriction is a UX feature; failure here
		// shouldn't roll back the primary sync.
		log.Printf("caddy sync: protocols write failed (non-fatal): %v", err)
	}
	if err := s.writeFleetServerOptions(proposed); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_fleet_options_failed", "", err.Error(), false)
		return fmt.Errorf("apply fleet server options: %w", err)
	}
	if !crowdSecEnabled {
		if err := s.writeCrowdSecApp(proposed, false); err != nil {
			_ = models.LogActivity(s.DB, serverID, "system", "sync_remove_crowdsec_failed", "", err.Error(), false)
			return fmt.Errorf("remove CrowdSec app: %w", err)
		}
	}

	// Hosts with Managed DNS selected use that provider for ACME DNS-01. The
	// same policies were included in validation above, so a missing Caddy DNS
	// module is reported before any subtrees are modified.
	if len(tlsAutomationPolicies) > 0 {
		if err := pushAutomationPoliciesVia(s.Caddy, tlsAutomationPolicies); err != nil {
			_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_automation_failed", "", err.Error(), false)
			return fmt.Errorf("apply TLS automation policies: %w", err)
		}
		log.Printf("caddy sync: pushed %d TLS automation polic(ies)", len(tlsAutomationPolicies))
	}

	detail := fmt.Sprintf("proxies=%d redirects=%d passthrough=%d certs=%d",
		len(proxies), len(redirs), len(raws), len(certs))
	_ = models.LogActivity(s.DB, serverID, "system", "sync_applied", "", detail, true)
	log.Printf("caddy synced server %d (%s): %s", serverID, srv.Name, detail)
	// v2.38.0: post-apply expectations. `current` is the live config fetched
	// before the apply; on failure it is loaded straight back.
	if err := s.verifyAppliedConfig(serverID, srv.Name, s.Caddy, current); err != nil {
		return err
	}
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

func (s *Server) validateProxyAdvanced(caddyCl *caddy.Client, p *models.ProxyHost) string {
	if strings.TrimSpace(p.AdvancedConfig) == "" {
		return ""
	}
	// v2.42.2: judge the repaired config, exactly what the adapter sees.
	if errMsg := validateProxyAdvancedDirectives(normalizeProxyAdvancedConfig(p.AdvancedConfig)); errMsg != "" {
		return errMsg
	}
	if _, _, err := s.adaptProxyAdvancedWithClient(caddyCl, *p); err != nil {
		return friendlyAdvancedRejection(err) // v2.42.2
	}
	return ""
}

func validateProxyAdvancedDirectives(src string) string {
	// Directives that terminate a route — reverse_proxy ships the request, redir
	// writes a 3xx, respond writes a fixed body, file_server serves from disk.
	// The proxy host route ALWAYS ends with its own reverse_proxy, so allowing
	// any of these as top-level directives here would splice a second terminal
	// handler before it, silently breaking routing. Reject at save time rather
	// than waiting for the sync to succeed with a broken result.
	// v2.40.0: reverse_proxy is no longer banned — a `reverse_proxy { … }`
	// block with no upstream is merged into the host's own handler (see
	// proxy_advanced_overrides.go); one that names an upstream or sits
	// behind a matcher is rejected after adapting.
	banned := []string{"redir", "respond", "file_server"}
	if bad := scanTopLevelDirective(src, banned); bad != "" {
		return fmt.Sprintf("Advanced config can't contain `%s` — this field runs BEFORE the proxy's own reverse_proxy handler. Put request-side directives here (header, encode, request_body, rewrite, etc.) and let the Forward host/port handle the upstream.", bad)
	}
	return reverseProxySubdirectiveError(src)
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
		"Guided":       r.FormValue("guided") == "1",
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
func (s *Server) adaptProxyAdvanced(p models.ProxyHost) ([]any, map[string]any, error) {
	return s.adaptProxyAdvancedWithClient(s.Caddy, p)
}

// adaptProxyAdvancedWithClient adapts the Advanced config through Caddy and
// returns the handlers that run before the host's reverse_proxy plus, since
// v2.40.0, the fields of a `reverse_proxy { … }` block to merge into it.
func (s *Server) adaptProxyAdvancedWithClient(caddyCl *caddy.Client, p models.ProxyHost) ([]any, map[string]any, error) {
	// v2.42.2: repairs applied here too, so configs saved before the
	// repairs existed adapt on the next sync without being re-saved.
	src := fmt.Sprintf("localhost {\n%s\n}\n", normalizeProxyAdvancedConfig(p.AdvancedConfig))
	adapted, err := caddyCl.Adapt(src)
	if err != nil {
		return nil, nil, err
	}
	routes := extractAdaptedRoutes(adapted.Result)
	if len(routes) == 0 {
		return nil, nil, nil
	}
	handle, _ := routes[0]["handle"].([]any)
	return extractReverseProxyOverrides(handle)
}
