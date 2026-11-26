// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
		// Issue #184 round 8: a non-admin's text is checked before Caddy
		// sees it, size first.
		if !isAdminUser(s.currentUser(r)) {
			if why := s.tenantRawRouteTextProblem(cfSrc); why != "" {
				return nil, why
			}
		}
		jsonData, adaptedListen, result, err := s.adaptRawRouteCaddyfileResult(s.caddyForRequest(r), cfSrc)
		if err != nil {
			return nil, "Caddyfile rejected by Caddy: " + err.Error()
		}
		// Issue #184 review: a non-admin's text may adapt to routes only.
		if !isAdminUser(s.currentUser(r)) {
			if why := s.tenantRawRouteAdaptedProblem(jsonData, adaptedListen, result); why != "" {
				return nil, why
			}
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
	forceSSL := r.FormValue("ssl_forced") == "on"
	// Issue #121: an Advanced route written with explicit http:// site
	// addresses is a deliberate plain-HTTP route. A certificate has nothing to
	// bind to and a forced HTTPS redirect would contradict the address, so
	// neither is kept — the form disables both controls for it.
	if cfSrc != "" && caddy.CaddyfileHTTPOnly(cfSrc) {
		certID = 0
		forceSSL = false
	}
	return &models.RawRoute{
		Label:               label,
		JSONData:            body,
		CaddyfileSrc:        cfSrc,
		Enabled:             r.FormValue("enabled") == "on",
		CertificateID:       certID,
		ForceSSL:            forceSSL,
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

// rawRouteHTTPOnly reports whether rr was written with explicit http:// site
// addresses (issue #121). Such a route is served as plain HTTP: it needs no
// certificate, so there is nothing for the "deploying" page to wait on.
func rawRouteHTTPOnly(rr *models.RawRoute) bool {
	return rr != nil && rr.CaddyfileSrc != "" && caddy.CaddyfileHTTPOnly(rr.CaddyfileSrc)
}

// httpsRawRoutes returns the Advanced routes that belong on the HTTPS listener
// (srv0, :443) — every enabled route except those written with explicit
// http:// site addresses (v2.59.3, issue #121). The #121 fix only dropped the
// certificate and Force SSL for such a route on save; the route itself was
// still generated on :443, where Caddy served it over HTTPS and issued an
// internal certificate for its host. Routes with their own listener are
// unaffected (they never share srv0), and the list for the plain :80 server is
// built from the full set, so an http:// route still reaches :80.
func httpsRawRoutes(raws []models.RawRoute) []models.RawRoute {
	out := make([]models.RawRoute, 0, len(raws))
	for i := range raws {
		if raws[i].Listen == "" && rawRouteHTTPOnly(&raws[i]) {
			continue
		}
		out = append(out, raws[i])
	}
	return out
}

// withAutoLoadedSnippets prepends the snippet definitions — "(name) { ... }" —
// found in the mounted Caddyfile (CADDYFILE_PATH) to src, so `import <name>`
// resolves without the user pasting the definition. Only the snippet blocks
// themselves are added — never site blocks or the global options block, which
// would duplicate existing routes or clash with Caddy's single global-options
// restriction. A snippet src already defines is skipped, to avoid Caddy's
// duplicate-definition error. If CADDYFILE_PATH is unset or unreadable, or
// holds no snippets, src is returned unchanged.
//
// This is for an administrator's text. A non-admin's goes through
// withTenantSnippets, which never skips a snippet (issue #184 round 10).
// Both files are read the way Caddy's lexer reads them, so a quoted,
// backtick or heredoc value that looks like `(name) {` defines nothing,
// for Caddy or here.
//
// Every path that hands user-written Caddyfile text to /adapt must go through
// this or withTenantSnippets: Advanced routes, the Caddyfile paste importer,
// and a proxy host's Advanced config (issue #119 — that last one was missed
// and rejected any `import <snippet>` with "File to import not found").
func (s *Server) withAutoLoadedSnippets(src string) string {
	if s.CaddyfilePath == "" {
		return src
	}
	b, err := os.ReadFile(s.CaddyfilePath)
	if err != nil {
		return src
	}
	already := map[string]bool{}
	for _, snip := range caddy.CaddyfileSnippets(src) {
		already[snip.Name] = true
	}
	var loaded []string
	for _, snip := range caddy.CaddyfileSnippets(string(b)) {
		if !already[snip.Name] {
			loaded = append(loaded, snip.Text)
		}
	}
	if len(loaded) == 0 {
		return src
	}
	return snippetPrefix(loaded) + src
}

// withTenantSnippets puts the administrator's snippets (adminSnippetSet)
// ahead of a non-admin's text, all of them, always (issue #184 round 10).
// A non-admin may not define snippets (tenantTextRules), so nothing in the
// text can stand in for one: were a definition skipped because the text
// seemed to hold it, an `import` of that name would read a file of that
// name instead. tenantAdaptTextViolation recognises exactly this prefix.
func (s *Server) withTenantSnippets(src string) string {
	return s.autoLoadedSnippetPrefix() + src
}

// snippetsFor is withTenantSnippets for a non-admin's text and
// withAutoLoadedSnippets for an administrator's.
func (s *Server) snippetsFor(src string, tenant bool) string {
	if tenant {
		return s.withTenantSnippets(src)
	}
	return s.withAutoLoadedSnippets(src)
}

// tenantClient reports whether caddyCl adapts on a non-admin's behalf:
// such a client carries the tenant text check (caddyForRequest,
// tenantAdaptClient).
func tenantClient(caddyCl *caddy.Client) bool {
	return caddyCl != nil && caddyCl.AdaptTextCheck != nil
}

// tenantAdaptClient returns a copy of cl that holds every Caddyfile it
// adapts to the tenant text rules first (tenantAdaptTextViolation), as
// caddyForRequest does for a non-admin's request. The live sync uses it
// for rows a non-admin owns (issue #184 round 10).
func (s *Server) tenantAdaptClient(cl *caddy.Client) *caddy.Client {
	if cl == nil {
		return nil
	}
	cp := *cl
	cp.AdaptTextCheck = func(text string) string {
		if why := s.tenantAdaptTextViolation(text); why != "" {
			return "Not allowed for a non-admin account: " + why + ". Ask an administrator."
		}
		return ""
	}
	return &cp
}

// errClientAuthInRawRoute marks the one rejection adaptRawRouteCaddyfile makes
// on its own account rather than relaying from Caddy, so callers can avoid
// blaming Caddy for a block it adapted perfectly well. v2.64.0 (discussion
// #137).
var errClientAuthInRawRoute = errors.New("this block configures client certificate authentication (mTLS), which an Advanced route cannot carry")

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
	jsonData, listen, _, err := s.adaptRawRouteCaddyfileResult(caddyCl, src)
	return jsonData, listen, err
}

// adaptRawRouteCaddyfileResult is adaptRawRouteCaddyfile that also returns
// the whole config Caddy adapted the text to, for the tenant checks of what
// the text produces beyond its routes (tenantAdaptedConfigProblem).
func (s *Server) adaptRawRouteCaddyfileResult(caddyCl *caddy.Client, src string) (string, string, map[string]any, error) {
	if caddyCl == nil {
		return "", "", nil, fmt.Errorf("the Caddy adapter is unavailable")
	}
	adapted, err := caddyCl.Adapt(s.snippetsFor(src, tenantClient(caddyCl)))
	if err != nil {
		return "", "", nil, err
	}
	jsonData, listen, err := rawRouteFromAdapted(adapted.Result)
	return jsonData, listen, adapted.Result, err
}

// rawRouteFromAdapted turns an adapted config into the json_data and listen
// set an Advanced route stores; see adaptRawRouteCaddyfile.
func rawRouteFromAdapted(result map[string]any) (string, string, error) {
	adaptedRoutes := extractAdaptedServerRoutes(result)
	if len(adaptedRoutes) == 0 {
		return "", "", fmt.Errorf("the Caddyfile adapted successfully but produced no HTTP routes — include at least one site block")
	}
	// v2.64.0 (discussion #137): an Advanced route stores routes only, so a
	// `tls { client_auth ... }` block here would be dropped on the floor and
	// the site would serve happily without ever asking for a certificate.
	// Refuse the save and name the setting that works instead.
	if snis := adaptedClientAuthSNIs(result); len(snis) > 0 {
		return "", "", fmt.Errorf("%w (affects %s). Caddy keeps client_auth in the server's TLS connection policies, not in the route, and an Advanced route stores routes only — so it would be discarded here and the site would accept any visitor. Configure it on the proxy host instead — Proxy Hosts → edit → Security → Client certificate authentication — and keep the rest of this block for the routing", errClientAuthInRawRoute, strings.Join(snis, ", "))
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

// buildLayer4App adapts a server's pasted layer4 Caddyfile block (the
// CaddyServer.Layer4Caddyfile field, issue #113) through that server's own
// admin API and returns only the resulting apps.layer4 subtree — never any
// other key the adapt response might contain, even if the pasted block
// happens to produce one (see extractAdaptedLayer4App). caddyCl must already
// be the client for the server whose text is being adapted: sync callers
// pass the per-server-swapped s.Caddy, the save-time validator and
// cross-deploy both build a fresh client from the target server's own
// AdminURL/credentials.
//
// An empty caddyfileSrc (the default, and today's behavior for every
// existing server) returns (nil, nil) without making an admin-API call at
// all — no block configured, nothing to adapt. A non-2xx response from
// Caddy (unknown "layer4" directive because caddy-l4 isn't compiled in,
// Caddyfile syntax error, etc.) is returned as-is from caddy.Client.Adapt,
// which already includes Caddy's diagnostic text — callers surface this as a
// clear, actionable error rather than silently dropping the block.
func buildLayer4App(caddyCl *caddy.Client, caddyfileSrc string) (map[string]any, error) {
	src := strings.TrimSpace(caddyfileSrc)
	if src == "" {
		return nil, nil
	}
	adapted, err := caddyCl.Adapt(src)
	if err != nil {
		return nil, err
	}
	return extractAdaptedLayer4App(adapted.Result), nil
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
	proxies = s.applyMiddlewareProfiles(proxies) // v2.60.0 (issue #124)
	current, _, err := caddyCl.FetchConfig()
	if err != nil {
		return ""
	}
	proposed, err := deepCopyMap(current)
	if err != nil {
		return ""
	}
	previewRoutes := append(s.buildMergedRoutes(proxies, redirs, httpsRawRoutes(raws)), buildManagedCertificateRoutes(certs, s.fallbackRoute()["handle"].([]any))...)
	previewRoutes = sortRoutesBySpecificity(previewRoutes) // v2.61.3 (issue #129): wildcard certificate routes after exact hosts
	previewRoutes = s.withFallbackRoute(previewRoutes)     // v2.59.4 (issue #123)
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
	applySkipCertificates(proposed, buildSkipCertificates(proxies, redirs, httpsRawRoutes(raws), certs))
	removeUnsupportedSkipRedirects(proposed)
	applyDisableAutomaticHTTPSRedirects(proposed, len(httpRoutes) > 0)
	applySkipAccessLogs(proposed, buildSkipAccessLogs(proxies))
	previewPolicies := s.buildDNSAutomationPolicies(proxies, redirs, httpsRawRoutes(raws), certs)
	previewPolicies = append(previewPolicies, buildInternalTLSAutomationPolicies(proxies)...) // v2.46.0
	applyAutomationPolicies(proposed, previewPolicies)
	// Mirror syncCaddy: preview-validation must match the config we'd push
	// for real, otherwise a raw_route edit could validate clean here but
	// fail with errors.routes rejection at sync time.
	applyErrorPages(proposed)
	if err := caddyCl.Validate(proposed); err != nil {
		return "Caddy rejected the proposed config: " + friendlyCaddyError(err.Error())
	}
	return ""
}

func (s *Server) createRawRoute(w http.ResponseWriter, r *http.Request) {
	rr, errMsg := s.parseRawRouteForm(r)
	if errMsg != "" {
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
	if errMsg := s.validateRawRouteForUser(s.currentUser(r), rr); errMsg != "" { // v2.57.1 — see tenant_guard.go
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
	var deployProblems []string
	if deployTo := s.effectiveDeployTargets(s.currentServerID(r), parseDeployTo(r)); len(deployTo) > 0 {
		rr.ID = id
		deployProblems = s.crossDeployRawRoute(s.currentUserEmail(r), s.currentServerID(r), rr, deployTo)
	}
	// v2.5.5: park the user on the deploying checklist when the route has
	// a host matcher we can probe. Path-only / port-only routes have no
	// fqdn to verify, so we skip the page and bounce to the list like before.
	if firstRawRouteHost(rr.JSONData) != "" && !rawRouteHTTPOnly(rr) {
		http.Redirect(w, r, withDeployProblems(fmt.Sprintf("/raw-routes/%d/deploying", id), deployProblems), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, withDeployProblems("/raw-routes", deployProblems), http.StatusSeeOther)
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
	if errMsg := s.validateRawRouteForUser(s.currentUser(r), rr); errMsg != "" { // v2.57.1 — see tenant_guard.go
		s.renderRawRouteFormError(w, r, rr, errMsg)
		return
	}
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
	var deployProblems []string
	if deployTo := s.effectiveDeployTargets(s.currentServerID(r), parseDeployTo(r)); len(deployTo) > 0 {
		deployProblems = s.crossDeployRawRoute(s.currentUserEmail(r), s.currentServerID(r), rr, deployTo)
	}
	// v2.5.5: show the deploying checklist on edits too — changing the
	// host matcher or the backing service is the same "did it come back
	// up on HTTPS?" question the create flow asks. Routes without a host
	// matcher skip the page as in create.
	if newFQDN != "" && !rawRouteHTTPOnly(rr) { // issue #121: an http:// route has no certificate to wait for
		http.Redirect(w, r, withDeployProblems(fmt.Sprintf("/raw-routes/%d/deploying", id), deployProblems), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, withDeployProblems("/raw-routes", deployProblems), http.StatusSeeOther)
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
	note := s.noteFleetDeletion(models.FleetResourceRawRoute, id, "")
	if old != nil {
		note.label = old.Label
	}
	if err := models.DeleteRawRoute(s.DB, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "raw_delete", fmt.Sprintf("raw:%d", id), "", true)
	forceTLS := old != nil && old.CertificateID != 0
	s.trySyncCaddyAfterDelete(s.currentServerID(r), forceTLS)
	s.propagateNotedDeletion(s.currentUserEmail(r), note) // v2.59.0 (issue #120)
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
			// GHSA-r4wm-rgc5-q834 (3rd finding) follow-up: ph.ForwardHost
			// comes from the existing raw route's own JSON, which a non-admin
			// could have pasted in before ever being classified as a proxy
			// host — needs the same non-admin upstream guard as every other
			// proxy-host creation path.
			if msg := s.validateProxyUpstreamsForUser(cu, &ph); msg != "" {
				nKept++
				continue
			}
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
// trySyncCaddyAfterDelete is trySyncCaddy for the delete handlers: removing the
// last resource must clear it from the live Caddy too (v2.59.1, issue #120).
func (s *Server) trySyncCaddyAfterDelete(serverID int64, forceTLS bool) {
	if err := s.syncCaddyOpts(serverID, forceTLS, true); err != nil {
		log.Printf("trySyncCaddyAfterDelete(server=%d, forceTLS=%v): %v", serverID, forceTLS, err)
	}
}

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

// syncLayer4Only handles fleet members with a layer4 Caddyfile block
// configured (issue #113) but no CaddyUI-managed routes or certificates yet.
// apps.layer4 is a standalone top-level app independent of apps.http.servers
// — like Prometheus metrics above — so it should work on a route-less server
// without forcing the administrator to create a dummy host first.
func (s *Server) syncLayer4Only(serverID int64, srv *models.CaddyServer, proxies []models.Layer4Proxy) error {
	// v2.58.0 (issue #122): the raw Caddyfile block plus the managed Layer4
	// proxy rows.
	layer4App, err := layer4AppFor(s.Caddy, srv, proxies)
	if err != nil {
		return fmt.Errorf("layer4 Caddyfile: %w", err)
	}
	current, currentJSON, err := s.Caddy.FetchConfig()
	if err != nil {
		return fmt.Errorf("fetch current config for layer4: %w", err)
	}
	proposed, err := deepCopyMap(current)
	if err != nil {
		return fmt.Errorf("clone config for layer4: %w", err)
	}
	applyLayer4App(proposed, layer4App)
	s.applyLayer4ListenerWrappers(proposed, serverID, proxies) // v2.61.0 (issue #126)
	if err := s.Caddy.Validate(proposed); err != nil {
		return fmt.Errorf("caddy rejected layer4 config: %w", err)
	}
	if s.autoSnapshotsEnabled() && currentJSON != "" && currentJSON != "null" {
		if _, err := models.CreateSnapshot(s.DB, serverID, models.SnapshotSourceAuto, "auto: before layer4 sync", currentJSON); err != nil {
			log.Printf("layer4 snapshot failed (non-fatal): %v", err)
		}
	}
	if err := s.writeLayer4App(proposed); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_layer4_failed", "", err.Error(), false)
		return fmt.Errorf("apply layer4 app: %w", err)
	}
	if err := s.writeLayer4ListenerWrappers(serverID, proxies); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_layer4_wrappers_failed", "", err.Error(), false)
		return fmt.Errorf("apply layer4 listener wrappers: %w", err)
	}
	_ = models.LogActivity(s.DB, serverID, "system", "sync_layer4_applied", "", "layer4-only sync", true)
	return nil
}

// syncCaddy pushes the DB state for serverID to its Caddy and records the
// outcome per server (v2.42.1, issue #74): a failure shows on every page
// until the next successful sync, so a rejected change can no longer fail
// silently in the log while the form says "saved".
func (s *Server) syncCaddy(serverID int64, forceTLS bool) error {
	return s.syncCaddyOpts(serverID, forceTLS, false)
}

// syncCaddyOpts is syncCaddy with one extra switch. allowEmpty (v2.59.1, issue
// #120) lets a sync run when CaddyUI holds NO entries for the server: the
// normal "refusing to push empty routes" guard exists so a fresh or wiped
// database can never blank a live Caddy, but after an explicit deletion of the
// last resource the empty state is the intended one and must reach Caddy, or
// the deleted route would keep serving. Only deletion paths pass true.
func (s *Server) syncCaddyOpts(serverID int64, forceTLS, allowEmpty bool) error {
	// Security/stability (v2.57.1): syncCaddyInner points the shared s.Caddy
	// field at ONE server's admin API for its whole duration. Two syncs for
	// different servers running at once overwrote each other's client, and a
	// reproduction pushed server B's routes — with their certificate keys and
	// basic-auth hashes — to server A (91 of 120 syncs in a stress run). Syncs
	// are therefore serialized. Nothing reachable from a sync calls syncCaddy
	// again, so this cannot deadlock.
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	err := s.syncCaddyInner(serverID, forceTLS, allowEmpty)
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

func (s *Server) syncCaddyInner(serverID int64, forceTLS, allowEmpty bool) error {
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
	// Issue #184 round 11: rows stored before the upgrade are adapted
	// again, with this server's Caddy, before they can be deployed.
	s.migrateTenantRawRoutes(serverID, s.Caddy)

	// Use admin view for sync — all routes must be pushed to Caddy regardless of owner.
	proxies, err := models.ListProxyHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		return err
	}
	proxies = s.applyMiddlewareProfiles(proxies) // v2.60.0 (issue #124)
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
	layer4Proxies, err := models.ListLayer4Proxies(s.DB, serverID)
	if err != nil {
		return err
	}
	if !allowEmpty && len(proxies) == 0 && len(redirs) == 0 && len(raws) == 0 && len(certs) == 0 {
		if metricsCfg.manages(serverID) {
			return s.syncPrometheusMetricsOnly(serverID, metricsCfg)
		}
		// v2.56.0 (issue #113): apps.layer4 is independent of apps.http.servers,
		// so a server dedicated to layer4 TCP/UDP routing with no CaddyUI-managed
		// routes yet should still sync instead of being refused by the empty-
		// routes guard below. (If a route-less server somehow has BOTH metrics
		// and layer4 configured, the metrics-only branch above takes priority and
		// layer4 is skipped this sync — an edge case of an edge case; it starts
		// applying as soon as any proxy/redirect/raw-route/certificate exists.)
		// v2.58.0 (issue #122): Layer4 proxy rows count too, and so does having
		// had managed layer4 servers before — removing the LAST proxy on an
		// otherwise empty server must still clear them from Caddy.
		if strings.TrimSpace(srv.Layer4Caddyfile) != "" || len(layer4Proxies) > 0 || hasManagedLayer4Live(s.Caddy) {
			return s.syncLayer4Only(serverID, srv, layer4Proxies)
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
			// The global list is applied ahead of the per-host one and
			// deduplicated: a header named in both used to be emitted twice.
			// Reads strip_resp_headers (canonical) rather than the retired
			// strip_response_headers column — see MergeStripResponseHeaders.
			proxies[i].StripRespHeaders = models.MergeHeaderNameLists(globalStrip, proxies[i].StripRespHeaders)
			proxies[i].GlobalStripHeaders = stripList
		}
	}

	accessLogCfg := loadFleetAccessLogConfig(s.DB)
	crowdSecCfg := loadCrowdSecConfig(s.DB)
	routes := append(s.buildMergedRoutes(proxies, redirs, httpsRawRoutes(raws)), buildManagedCertificateRoutes(certs, s.fallbackRoute()["handle"].([]any))...)
	routes = sortRoutesBySpecificity(routes) // v2.61.3 (issue #129): wildcard certificate routes after exact hosts
	routes = s.withFallbackRoute(routes)     // v2.59.4 (issue #123)
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
	skipList := buildSkipCertificates(proxies, redirs, httpsRawRoutes(raws), certs)
	skipAccessLogs := buildSkipAccessLogs(proxies)
	// v2.9.0: per-SNI TLS connection policies — minimum version, and since
	// v2.64.0 client certificate authentication. nil when no host needs
	// either; writeTLSConnectionPoliciesSubtree handles the nil case by
	// clearing stale policies that may exist.
	tlsConnPolicies := caddy.BuildTLSConnectionPolicies(proxies)
	// DNS-01 issuance policies plus (v2.46.0) internal-CA issuance policies,
	// pushed together into apps.tls.automation.
	tlsAutomationPolicies := s.buildDNSAutomationPolicies(proxies, redirs, httpsRawRoutes(raws), certs)
	tlsAutomationPolicies = append(tlsAutomationPolicies, buildInternalTLSAutomationPolicies(proxies)...)

	// v2.56.0 (issue #113): adapt the optional layer4 Caddyfile block through
	// this server's own admin API before fetching/mutating its config, so a
	// typo'd block (or a build missing caddy-l4) fails the sync up front with
	// a clear error instead of after other subtrees have already been written.
	layer4App, err := layer4AppFor(s.Caddy, srv, layer4Proxies)
	if err != nil {
		return fmt.Errorf("layer4 Caddyfile for %s: %w", srv.Name, err)
	}

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
	applyLayer4App(proposed, layer4App)
	s.applyLayer4ListenerWrappers(proposed, serverID, layer4Proxies) // v2.61.0 (issue #126)
	// v2.4.12: branded 404/502/503/504 pages with error ID + timestamp so
	// users hitting a restart window see something nicer than Caddy's
	// plaintext fallback and ops can correlate to access logs via {err.id}.
	applyErrorPages(proposed)

	// Validate before touching anything. Caddy runs full provisioning.
	if err := s.Caddy.Validate(proposed); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_validation_failed", "", err.Error(), false)
		return fmt.Errorf("caddy rejected proposed config: %s", friendlyCaddyError(err.Error()))
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
	if err := s.writeLayer4App(proposed); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_layer4_failed", "", err.Error(), false)
		return fmt.Errorf("apply layer4 app: %w", err)
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
	// v2.61.0 (issue #126): layer4 listener wrappers go on the HTTP servers, so
	// they are written once those servers exist.
	if err := s.writeLayer4ListenerWrappers(serverID, layer4Proxies); err != nil {
		_ = models.LogActivity(s.DB, serverID, "system", "sync_apply_layer4_wrappers_failed", "", err.Error(), false)
		return fmt.Errorf("apply layer4 listener wrappers: %w", err)
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

// validateForwardAuthURL rejects a forward auth URL CaddyUI cannot turn into an
// auth subrequest (v2.59.5): it must be http:// or https:// with a host, e.g.
// http://authentik:9000/outpost.goauthentik.io/auth/caddy. Blank = forward auth off.
func validateForwardAuthURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "Forward auth URL must be http:// or https:// followed by the auth service host, e.g. http://authentik:9000/outpost.goauthentik.io/auth/caddy"
	}
	return ""
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
	// Issue #184 round 8: a non-admin's text (the client carries
	// AdaptTextCheck) is held to the tenant text rules before anything else
	// is done with it.
	if caddyCl != nil && caddyCl.AdaptTextCheck != nil {
		if why := s.tenantOwnTextViolation(p.AdvancedConfig); why != "" {
			return "Not allowed for a non-admin account: " + why + ". Ask an administrator."
		}
	}
	// v2.42.2: judge the repaired config, exactly what the adapter sees.
	if errMsg := validateProxyAdvancedDirectives(normalizeProxyAdvancedConfig(p.AdvancedConfig)); errMsg != "" {
		return errMsg
	}
	result, err := s.adaptProxyAdvancedResult(caddyCl, *p)
	if err != nil {
		return friendlyAdvancedRejection(err) // v2.42.2
	}
	handlers, _, err := proxyAdvancedHandlers(result)
	if err != nil {
		return friendlyAdvancedRejection(err)
	}
	// v2.57.1: for a non-admin's request (the client carries AdaptTextCheck),
	// inspect what the text adapted to as well — a handler nested inside a block
	// (file_server, an upstream aimed at the admin API, ...) is invisible to the
	// top-level directive scan above. The sync-time guard would skip such a
	// route silently; this gives the user the reason instead.
	if caddyCl != nil && caddyCl.AdaptTextCheck != nil {
		if msg := s.validateTenantRoute(map[string]any{"handle": handlers}); msg != "" {
			return msg
		}
		// Issue #184 review: and nothing beyond those handlers — the live
		// route drops site-level directives (log, bind, tls, ...), but the
		// Caddyfile export would write them.
		if why := s.proxyAdvancedAdaptedProblem(result); why != "" {
			return "Not allowed for a non-admin account: this Advanced config " + why + ". Ask an administrator."
		}
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
// Issue #184 round 10: lines are read on Caddy's tokens, so a brace or a
// line inside a quoted, backtick or heredoc value is never taken for
// structure. Text Caddy's lexer refuses falls back to the plain line scan
// (Caddy then refuses it anyway).
func scanTopLevelDirective(src string, banned []string) string {
	if heads, ok := caddy.CaddyfileLineHeads(src); ok {
		for _, h := range heads {
			for _, b := range banned {
				if h == b {
					return b
				}
			}
		}
		return ""
	}
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
	selectedProfile, _ := strconv.ParseInt(strings.TrimSpace(r.FormValue("middleware_profile_id")), 10, 64)
	if r.Method != http.MethodPost && p != nil {
		selectedProfile = models.ProxyHostProfileID(s.DB, p.ID)
	}
	s.render(w, r, "proxy_host_form.html", s.withProfileViewData(s.applyDNSViewData(s.currentServerID(r), map[string]any{
		"User":         s.currentUser(r),
		"Host":         p,
		"Certificates": certs,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Error":        errMsg,
		"Guided":       r.FormValue("guided") == "1",
		"Section":      "proxy",
	}), selectedProfile))
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
	result, err := s.adaptProxyAdvancedResult(caddyCl, p)
	if err != nil {
		return nil, nil, err
	}
	return proxyAdvancedHandlers(result)
}

// proxyAdvancedSite is the synthetic site an Advanced config is adapted in.
const proxyAdvancedSite = "localhost"

// adaptProxyAdvancedResult returns the whole config Caddy adapts a proxy
// host's Advanced config to, wrapped in the synthetic site.
func (s *Server) adaptProxyAdvancedResult(caddyCl *caddy.Client, p models.ProxyHost) (map[string]any, error) {
	if caddyCl == nil {
		return nil, fmt.Errorf("the Caddy adapter is unavailable")
	}
	// v2.42.2: repairs applied here too, so configs saved before the
	// repairs existed adapt on the next sync without being re-saved.
	src := fmt.Sprintf("%s {\n%s\n}\n", proxyAdvancedSite, normalizeProxyAdvancedConfig(p.AdvancedConfig))
	// Issue #119: `import <snippet>` must see the snippets from CADDYFILE_PATH,
	// exactly as it does in Advanced routes.
	adapted, err := caddyCl.Adapt(s.snippetsFor(src, tenantClient(caddyCl) || s.isTenantOwner(p.OwnerID)))
	if err != nil {
		return nil, err
	}
	return adapted.Result, nil
}

// proxyAdvancedHandlers picks the handlers of the synthetic site out of an
// adapted Advanced config; see adaptProxyAdvancedWithClient.
func proxyAdvancedHandlers(result map[string]any) ([]any, map[string]any, error) {
	routes := extractAdaptedRoutes(result)
	if len(routes) == 0 {
		return nil, nil, nil
	}
	handle, _ := routes[0]["handle"].([]any)
	return extractReverseProxyOverrides(handle)
}

// caddyfileExportOptions is the server context the Caddyfile export needs
// (issue #184 review): the snippets from CADDYFILE_PATH that admin-owned
// content may import — written into the export only for an administrator
// (forAdmin), and then only those the export imports — which owners are
// tenants, and a re-check through Caddy of exactly the text the export
// writes for a tenant's raw route or proxy host with an Advanced config,
// because rows written by older versions may hold text that never matched
// what the live config carries.
func (s *Server) caddyfileExportOptions(serverID int64, forAdmin bool) caddy.ExportOptions {
	opts := caddy.ExportOptions{TenantOwned: s.isTenantOwner, IncludeSnippets: forAdmin}
	if s.CaddyfilePath != "" {
		if b, err := os.ReadFile(s.CaddyfilePath); err == nil {
			opts.Snippets = caddy.ExtractSnippets(string(b))
		}
	}
	// The exporter consults the vetoes only for tenant-owned content. They
	// share one client, which stops calling Caddy once a call to it has
	// failed: every later check then fails closed at once, instead of each
	// waiting out the client timeout against an adapter that is down.
	adaptClient := s.exportAdaptClient(serverID)
	opts.RawRouteVeto = func(rr models.RawRoute, text string) string {
		return s.rawRouteTextVeto(adaptClient(), rr, text)
	}
	opts.ProxyHostVeto = func(p models.ProxyHost, site string) string {
		return s.proxyAdvancedExportVeto(adaptClient(), p, site)
	}
	opts.RedirectVeto = s.redirectExportVeto
	return opts
}

// redirectExportVeto returns why a tenant's redirection host, written as
// text, must not be exported, or "": the block must pass the tenant text
// rules and the route the live sync builds from the row must pass the
// tenant route rules (issue #184 round 7 — a row stored before those rules,
// or by a path that skipped them, could otherwise export a destination the
// live sync neutralises). The reason is generic: it is written into the
// export, and the row's values are not.
func (s *Server) redirectExportVeto(rh models.RedirectionHost, text string) string {
	if s.tenantBlockTextViolation(text) != "" || s.tenantRouteViolation(caddy.BuildRedirectRoute(rh)) != "" {
		return "its settings are not allowed for a non-admin owner"
	}
	return ""
}

// exportCaddyClient is the client the export re-checks text with: the
// server's own, or s.Caddy when there is no database to look it up in.
func (s *Server) exportCaddyClient(serverID int64) *caddy.Client {
	if s.DB == nil {
		return s.Caddy
	}
	return s.caddyForServer(serverID)
}

// exportAdaptClient returns a function that yields one Caddy client for a
// whole export (created on first use), whose transport refuses every
// request after one has failed to get a response (errExportAdapterDown).
// A refused request is an adapt error, which every veto treats as "could
// not be re-checked", so the export still fails closed.
func (s *Server) exportAdaptClient(serverID int64) func() *caddy.Client {
	var once sync.Once
	var cl *caddy.Client
	return func() *caddy.Client {
		once.Do(func() {
			base := s.exportCaddyClient(serverID)
			if base == nil {
				return
			}
			cp := *base
			hc := http.Client{}
			if base.HTTP != nil {
				hc = *base.HTTP
			}
			inner := hc.Transport
			if inner == nil {
				inner = http.DefaultTransport
			}
			hc.Transport = &stickyFailTransport{inner: inner}
			cp.HTTP = &hc
			cl = &cp
		})
		return cl
	}
}

// errExportAdapterDown is stickyFailTransport's error once it has tripped.
var errExportAdapterDown = errors.New("the Caddy adapter did not answer earlier in this export")

// stickyFailTransport passes requests to inner until one fails to get a
// response (a dial error, a timeout), and refuses every request after that.
type stickyFailTransport struct {
	inner http.RoundTripper
	down  atomic.Bool
}

func (t *stickyFailTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.down.Load() {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, errExportAdapterDown
	}
	resp, err := t.inner.RoundTrip(r)
	if err != nil {
		t.down.Store(true)
	}
	return resp, err
}

// adaptExportText adapts text exactly as the export writes it — no
// snippets are added: tenant text may not import any, so an `import` fails
// here and the text is left out.
func adaptExportText(caddyCl *caddy.Client, text string) (map[string]any, error) {
	if caddyCl == nil {
		return nil, fmt.Errorf("the Caddy adapter is unavailable")
	}
	adapted, err := caddyCl.Adapt(text)
	if err != nil {
		return nil, err
	}
	return adapted.Result, nil
}

// rawRouteTextVeto returns why a tenant's raw-route Caddyfile, as the
// export would write it (text), must not be exported: it fails the tenant
// text rules, does not adapt (or Caddy cannot be reached to check), adapts
// to anything beyond what its stored route carries
// (tenantAdaptedConfigProblem), or serves hosts its stored routes do not.
// "" means the text may be written.
func (s *Server) rawRouteTextVeto(caddyCl *caddy.Client, rr models.RawRoute, text string) string {
	if s.tenantOwnTextViolation(rr.CaddyfileSrc) != "" || s.tenantBlockTextViolation(text) != "" {
		return "its Caddyfile is not allowed for a non-admin owner"
	}
	result, err := adaptExportText(caddyCl, text)
	if err != nil {
		return "its Caddyfile could not be re-checked with Caddy"
	}
	jsonData, _, err := rawRouteFromAdapted(result)
	if err != nil {
		return "its Caddyfile could not be re-checked with Caddy"
	}
	if why := s.tenantAdaptedConfigProblem(result, rawRouteHostSet(rr), rr.ListenAddrs()); why != "" {
		return "its Caddyfile " + why
	}
	stored := rawRouteHostSet(rr)
	for _, h := range rawRouteHosts(models.RawRoute{JSONData: jsonData}) {
		if !stored[strings.ToLower(h)] {
			return "its Caddyfile serves hosts its stored routes do not"
		}
	}
	return ""
}

// proxyAdvancedExportVeto is rawRouteTextVeto for a tenant's proxy host,
// with or without an Advanced config: the block (site) must pass the
// tenant text rules and the host's generated route the tenant route rules,
// and an Advanced config is then re-checked through Caddy. site is the
// whole block the export would write
// for the host — the generated directives with the Advanced text placed
// among them — and that block is what Caddy adapts here, so the verdict is
// about the exact bytes in the file, whatever the exporter did to place
// the text. It may adapt to nothing a tenant's live route could not carry
// (tenantAdaptedConfigProblem, whose route check is tenantRouteViolation),
// and serve only the host's own domains. Any objection, adapt error or
// unreachable Caddy means the host fails closed.
func (s *Server) proxyAdvancedExportVeto(caddyCl *caddy.Client, p models.ProxyHost, site string) string {
	if s.tenantOwnTextViolation(p.AdvancedConfig) != "" || s.tenantBlockTextViolation(site) != "" {
		return "it is not allowed for a non-admin owner"
	}
	// Issue #184 round 7: the host's own fields, judged the way the live
	// sync judges them (sanitizeTenantRoute) — a stored row may hold a
	// header with an {env.…} placeholder or an upstream on the admin API,
	// which the live route neutralises or skips. The export must be no
	// weaker, so such a host fails closed. The reason stays generic: it is
	// written into the export, and the route carries header values.
	if s.tenantRouteViolation(caddy.BuildProxyRoute(p, nil)) != "" {
		return "its settings are not allowed for a non-admin owner"
	}
	if strings.TrimSpace(p.AdvancedConfig) == "" {
		return ""
	}
	result, err := adaptExportText(caddyCl, site)
	if err != nil {
		return "the exported block could not be re-checked with Caddy"
	}
	why := s.proxyHostSiteAdaptedProblem(result, p)
	if why != "" && (p.ClientAuthEnabled() || p.CertificateID > 0) {
		// The host's own client-certificate or certificate-file settings
		// put TLS configuration in the block, which the tenant allowlist
		// refuses as such. Set aside exactly what the same host without
		// an Advanced config adapts to, and judge the rest.
		base := p
		base.AdvancedConfig = ""
		baseline, err := adaptExportText(caddyCl, caddy.RenderProxyHostCaddyfileWithCertificate(base, s.certificateForCaddyfile(p.CertificateID)))
		if err != nil {
			return "the exported block could not be re-checked with Caddy"
		}
		removeBaselineTLS(result, baseline)
		why = s.proxyHostSiteAdaptedProblem(result, p)
	}
	if why != "" {
		return "the exported block " + why
	}
	return ""
}

// proxyHostSiteAdaptedProblem judges the adapted form of a tenant proxy
// host's exported site block: nothing beyond what a tenant's live config
// may carry, and every route matching only the host's own domains.
func (s *Server) proxyHostSiteAdaptedProblem(result map[string]any, p models.ProxyHost) string {
	domains := map[string]bool{}
	for _, d := range p.DomainList() {
		domains[strings.ToLower(d)] = true
	}
	if why := s.tenantAdaptedConfigProblem(result, domains, nil); why != "" {
		return why
	}
	for _, route := range extractAdaptedRoutes(result) {
		hosts := hostsFromRoute(route)
		if len(hosts) == 0 {
			return "serves hosts that are not the proxy host's own"
		}
		for _, h := range hosts {
			if !domains[strings.ToLower(h)] {
				return "serves hosts that are not the proxy host's own"
			}
		}
	}
	return ""
}

// removeBaselineTLS deletes from result each server's TLS connection
// policies, and the TLS app, where they are identical to baseline's.
func removeBaselineTLS(result, baseline map[string]any) {
	appsOf := func(cfg map[string]any) map[string]any {
		apps, _ := cfg["apps"].(map[string]any)
		return apps
	}
	serversOf := func(cfg map[string]any) map[string]any {
		httpApp, _ := appsOf(cfg)["http"].(map[string]any)
		servers, _ := httpApp["servers"].(map[string]any)
		return servers
	}
	baseServers := serversOf(baseline)
	for name, v := range serversOf(result) {
		srv, _ := v.(map[string]any)
		baseSrv, _ := baseServers[name].(map[string]any)
		if srv != nil && baseSrv != nil && srv["tls_connection_policies"] != nil &&
			reflect.DeepEqual(srv["tls_connection_policies"], baseSrv["tls_connection_policies"]) {
			delete(srv, "tls_connection_policies")
		}
	}
	if apps := appsOf(result); apps != nil && apps["tls"] != nil && reflect.DeepEqual(apps["tls"], appsOf(baseline)["tls"]) {
		delete(apps, "tls")
	}
}

// proxyAdvancedAdaptedProblem applies tenantAdaptedConfigProblem to an
// Advanced config adapted in its synthetic site, which must yield at most
// the one route of that site — the live route takes its handlers from the
// first route alone, so any other is text the export would add.
func (s *Server) proxyAdvancedAdaptedProblem(result map[string]any) string {
	site := map[string]bool{proxyAdvancedSite: true}
	if why := s.tenantAdaptedConfigProblem(result, site, nil); why != "" {
		return why
	}
	routes := extractAdaptedRoutes(result)
	if len(routes) > 1 {
		return "adds routes beyond the host's own"
	}
	for _, route := range routes {
		blob, _ := json.Marshal(route)
		for _, h := range rawRouteHosts(models.RawRoute{JSONData: string(blob)}) {
			if !site[strings.ToLower(h)] {
				return "adds routes beyond the host's own"
			}
		}
	}
	return ""
}

// tenantRawRouteAdaptedProblem is the save-time form of the export's
// allowlist for a non-admin's Advanced route Caddyfile: what it adapted to
// (result) may hold nothing beyond the routes and listen set derived from
// it. Returns a form error message, or "".
func (s *Server) tenantRawRouteAdaptedProblem(jsonData, listen string, result map[string]any) string {
	derived := models.RawRoute{JSONData: jsonData, Listen: listen}
	if why := s.tenantAdaptedConfigProblem(result, rawRouteHostSet(derived), derived.ListenAddrs()); why != "" {
		return "Not allowed for a non-admin account: this Caddyfile " + why + ". Ask an administrator."
	}
	return ""
}

// rawRouteHostSet is rawRouteHosts lower-cased into a set.
func rawRouteHostSet(rr models.RawRoute) map[string]bool {
	out := map[string]bool{}
	for _, h := range rawRouteHosts(rr) {
		out[strings.ToLower(h)] = true
	}
	return out
}
