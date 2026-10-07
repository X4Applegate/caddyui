// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.60.0 (issue #124): reusable middleware profiles.
//
// A profile bundles HTTP policy that many hosts share — security headers,
// forward auth, IP restrictions, extra headers — so it is configured once and a
// proxy host only picks it. The profile is applied when the config is built:
// the host row is never rewritten, so detaching a profile restores exactly what
// the host had. A value set on the host itself wins; empty host fields inherit
// the profile; the two header maps merge by header name.

// applyProfileToHost overlays prof onto p (a copy owned by the caller).
func applyProfileToHost(p *models.ProxyHost, prof *models.MiddlewareProfile) {
	if prof == nil {
		return
	}
	if prof.SecurityHeaders {
		p.SecurityHeadersEnabled = true
	}
	inherit := func(host *string, profile string) {
		if strings.TrimSpace(*host) == "" {
			*host = profile
		}
	}
	inherit(&p.XFrameOptions, prof.XFrameOptions)
	inherit(&p.ReferrerPolicy, prof.ReferrerPolicy)
	inherit(&p.PermissionsPolicy, prof.PermissionsPolicy)
	inherit(&p.CSPHeader, prof.CSPHeader)
	inherit(&p.AccessList, prof.AccessList)
	inherit(&p.IPBlocklist, prof.IPBlocklist)

	// Forward auth is one unit: a host with its own auth URL keeps its own
	// method/headers/skip paths entirely; otherwise the profile supplies them all.
	if strings.TrimSpace(p.ForwardAuthURL) == "" && strings.TrimSpace(prof.ForwardAuthURL) != "" {
		p.ForwardAuthURL = prof.ForwardAuthURL
		p.ForwardAuthMethod = prof.ForwardAuthMethod
		p.ForwardAuthCopyHeaders = prof.ForwardAuthCopyHeaders
		p.ForwardAuthHeadersPrefix = prof.ForwardAuthHeadersPrefix
		p.ForwardAuthSkipPaths = prof.ForwardAuthSkipPaths
	}
	if prof.WAFMode == models.WAFModeDetect || prof.WAFMode == models.WAFModeBlock {
		paranoia := prof.WAFParanoia
		if paranoia < 1 {
			paranoia = 1
		}
		p.WAF = &models.WAFSettings{Mode: prof.WAFMode, CRS: prof.WAFCRS, Paranoia: paranoia, Directives: prof.WAFDirectives}
	}
	p.CustomReqHeaders = mergeHeaderJSON(prof.CustomReqHeaders, p.CustomReqHeaders)
	p.CustomRespHeaders = mergeHeaderJSON(prof.CustomRespHeaders, p.CustomRespHeaders)
}

// mergeHeaderJSON merges two {"Name":"value"} documents; entries in host win.
func mergeHeaderJSON(profile, host string) string {
	pm, hm := map[string]string{}, map[string]string{}
	if strings.TrimSpace(profile) != "" {
		_ = json.Unmarshal([]byte(profile), &pm)
	}
	if strings.TrimSpace(host) != "" {
		_ = json.Unmarshal([]byte(host), &hm)
	}
	if len(pm) == 0 {
		return host
	}
	for k, v := range hm {
		pm[k] = v
	}
	b, err := json.Marshal(pm)
	if err != nil {
		return host
	}
	return string(b)
}

// applyMiddlewareProfiles returns proxies with each host's profile applied. The
// input slice is not modified. With no attachments it returns the slice as is.
func (s *Server) applyMiddlewareProfiles(proxies []models.ProxyHost) []models.ProxyHost {
	assoc, err := models.ProxyHostProfileMap(s.DB)
	if err != nil || len(assoc) == 0 {
		if err != nil {
			log.Printf("middleware profiles: load attachments: %v", err)
		}
		return proxies
	}
	profiles, err := models.ListMiddlewareProfiles(s.DB)
	if err != nil {
		log.Printf("middleware profiles: load profiles: %v", err)
		return proxies
	}
	byID := make(map[int64]*models.MiddlewareProfile, len(profiles))
	for i := range profiles {
		byID[profiles[i].ID] = &profiles[i]
	}
	out := make([]models.ProxyHost, len(proxies))
	copy(out, proxies)
	for i := range out {
		if prof := byID[assoc[out[i].ID]]; prof != nil {
			applyProfileToHost(&out[i], prof)
		}
	}
	return out
}

var headerNameRe = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)

// validCIDRList accepts comma/newline/space separated CIDRs or single IPs.
func validCIDRList(raw string) (bad string) {
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' || r == '\r' }) {
		if _, _, err := net.ParseCIDR(f); err == nil {
			continue
		}
		if net.ParseIP(f) != nil {
			continue
		}
		return f
	}
	return ""
}

func hasControlChars(v string) bool { return strings.ContainsAny(v, "\r\n\x00") }

// validateMiddlewareProfile returns a user-facing message, or "" when p is fine.
func validateMiddlewareProfile(p *models.MiddlewareProfile) string {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 80 {
		return "Name is required (up to 80 characters)."
	}
	for label, v := range map[string]string{
		"X-Frame-Options": p.XFrameOptions, "Referrer-Policy": p.ReferrerPolicy,
		"Permissions-Policy": p.PermissionsPolicy, "Content-Security-Policy": p.CSPHeader,
		"Forward auth copy headers": p.ForwardAuthCopyHeaders, "Forward auth headers prefix": p.ForwardAuthHeadersPrefix,
		"Forward auth skip paths": p.ForwardAuthSkipPaths,
	} {
		if hasControlChars(v) {
			return label + " must be a single line."
		}
	}
	if msg := validateForwardAuthURL(p.ForwardAuthURL); msg != "" {
		return msg
	}
	switch strings.ToUpper(strings.TrimSpace(p.ForwardAuthMethod)) {
	case "", "GET", "POST", "HEAD":
	default:
		return "Forward auth method must be GET, POST or HEAD."
	}
	if bad := validCIDRList(p.AccessList); bad != "" {
		return fmt.Sprintf("Allowlist entry %q is not an IP address or CIDR range.", bad)
	}
	if bad := validCIDRList(p.IPBlocklist); bad != "" {
		return fmt.Sprintf("Blocklist entry %q is not an IP address or CIDR range.", bad)
	}
	switch p.WAFMode {
	case models.WAFModeOff, models.WAFModeDetect, models.WAFModeBlock:
	default:
		return "WAF mode must be Off, Detection only or Block."
	}
	if p.WAFMode != models.WAFModeOff {
		if p.WAFParanoia < 1 || p.WAFParanoia > 4 {
			return "WAF paranoia level must be between 1 and 4."
		}
	}
	if len(p.WAFDirectives) > 8192 || strings.ContainsRune(p.WAFDirectives, 0) {
		return "Custom WAF directives must be plain text up to 8 KB."
	}
	for label, raw := range map[string]string{"Request headers": p.CustomReqHeaders, "Response headers": p.CustomRespHeaders} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var m map[string]string
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return label + ` must be a JSON object of header names to values, e.g. {"X-Env": "prod"}.`
		}
		for k, v := range m {
			if !headerNameRe.MatchString(k) {
				return fmt.Sprintf("%s: %q is not a valid header name.", label, k)
			}
			if hasControlChars(v) {
				return fmt.Sprintf("%s: the value of %q must be a single line.", label, k)
			}
		}
	}
	return ""
}

func parseMiddlewareProfileForm(r *http.Request) *models.MiddlewareProfile {
	_ = r.ParseForm()
	t := func(k string) string { return strings.TrimSpace(r.FormValue(k)) }
	p := &models.MiddlewareProfile{
		Name: t("name"), Description: t("description"),
		SecurityHeaders: r.FormValue("security_headers") == "on",
		XFrameOptions:   t("x_frame_options"), ReferrerPolicy: t("referrer_policy"),
		PermissionsPolicy: t("permissions_policy"), CSPHeader: t("csp_header"),
		ForwardAuthURL: t("forward_auth_url"), ForwardAuthMethod: strings.ToUpper(t("forward_auth_method")),
		ForwardAuthCopyHeaders: t("forward_auth_copy_headers"), ForwardAuthHeadersPrefix: t("forward_auth_headers_prefix"),
		ForwardAuthSkipPaths: t("forward_auth_skip_paths"),
		AccessList:           t("access_list"), IPBlocklist: t("ip_blocklist"),
		CustomReqHeaders: t("custom_req_headers"), CustomRespHeaders: t("custom_resp_headers"),
		WAFMode: t("waf_mode"), WAFCRS: r.FormValue("waf_crs") == "on", WAFDirectives: strings.TrimSpace(r.FormValue("waf_directives")),
	}
	p.WAFParanoia, _ = strconv.Atoi(t("waf_paranoia"))
	if p.WAFMode == models.WAFModeOff {
		p.WAFCRS, p.WAFParanoia, p.WAFDirectives = false, 0, ""
	}
	if p.ForwardAuthMethod == "GET" {
		p.ForwardAuthMethod = ""
	}
	return p
}

// --- handlers (admin-only) ---

func (s *Server) listMiddlewareProfiles(w http.ResponseWriter, r *http.Request) {
	rows, err := models.ListMiddlewareProfiles(s.DB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "middleware_profiles.html", map[string]any{
		"User": s.currentUser(r), "Rows": rows, "Section": "middleware",
		"Flash": r.URL.Query().Get("flash"), "FlashError": r.URL.Query().Get("error"),
	})
}

func (s *Server) renderMiddlewareProfileForm(w http.ResponseWriter, r *http.Request, p *models.MiddlewareProfile, errMsg string) {
	s.render(w, r, "middleware_profile_form.html", map[string]any{
		"User": s.currentUser(r), "Row": p, "Error": errMsg, "Section": "middleware",
	})
}

func (s *Server) newMiddlewareProfile(w http.ResponseWriter, r *http.Request) {
	s.renderMiddlewareProfileForm(w, r, &models.MiddlewareProfile{SecurityHeaders: true, WAFCRS: true, WAFParanoia: 1}, "")
}

func (s *Server) middlewareProfileFromURL(w http.ResponseWriter, r *http.Request) *models.MiddlewareProfile {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := models.GetMiddlewareProfile(s.DB, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	if p == nil {
		http.NotFound(w, r)
		return nil
	}
	return p
}

func (s *Server) editMiddlewareProfile(w http.ResponseWriter, r *http.Request) {
	if p := s.middlewareProfileFromURL(w, r); p != nil {
		s.renderMiddlewareProfileForm(w, r, p, "")
	}
}

func (s *Server) createMiddlewareProfile(w http.ResponseWriter, r *http.Request) {
	p := parseMiddlewareProfileForm(r)
	if msg := validateMiddlewareProfile(p); msg != "" {
		s.renderMiddlewareProfileForm(w, r, p, msg)
		return
	}
	if taken, err := models.MiddlewareProfileNameTaken(s.DB, p.Name, 0); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if taken {
		s.renderMiddlewareProfileForm(w, r, p, fmt.Sprintf("A profile named %q already exists.", p.Name))
		return
	}
	if p.WAFMode != models.WAFModeOff {
		if msg := s.wafPreflight([]int64{s.currentServerID(r)}); msg != "" {
			s.renderMiddlewareProfileForm(w, r, p, msg)
			return
		}
	}
	id, err := models.CreateMiddlewareProfile(s.DB, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "profile_create", fmt.Sprintf("profile:%d", id), p.Name, true)
	http.Redirect(w, r, "/middleware-profiles?flash="+urlQueryEscape("Created profile "+p.Name+"."), http.StatusSeeOther)
}

func (s *Server) updateMiddlewareProfile(w http.ResponseWriter, r *http.Request) {
	cur := s.middlewareProfileFromURL(w, r)
	if cur == nil {
		return
	}
	p := parseMiddlewareProfileForm(r)
	p.ID = cur.ID
	if msg := validateMiddlewareProfile(p); msg != "" {
		s.renderMiddlewareProfileForm(w, r, p, msg)
		return
	}
	if taken, err := models.MiddlewareProfileNameTaken(s.DB, p.Name, p.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if taken {
		s.renderMiddlewareProfileForm(w, r, p, fmt.Sprintf("Another profile is already named %q.", p.Name))
		return
	}
	if p.WAFMode != models.WAFModeOff {
		servers, _ := models.ServersUsingProfile(s.DB, p.ID)
		if msg := s.wafPreflight(append(servers, s.currentServerID(r))); msg != "" {
			s.renderMiddlewareProfileForm(w, r, p, msg)
			return
		}
	}
	if err := models.UpdateMiddlewareProfile(s.DB, p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "profile_update", fmt.Sprintf("profile:%d", p.ID), p.Name, true)
	n := s.resyncProfileServers(p.ID)
	msg := "Saved profile " + p.Name + "."
	if n > 0 {
		msg += fmt.Sprintf(" Re-synced %d server(s) that use it.", n)
	}
	http.Redirect(w, r, "/middleware-profiles?flash="+urlQueryEscape(msg), http.StatusSeeOther)
}

func (s *Server) deleteMiddlewareProfile(w http.ResponseWriter, r *http.Request) {
	p := s.middlewareProfileFromURL(w, r)
	if p == nil {
		return
	}
	if err := models.DeleteMiddlewareProfile(s.DB, p.ID); err != nil {
		if errors.Is(err, models.ErrProfileInUse) {
			http.Redirect(w, r, "/middleware-profiles?error="+urlQueryEscape("Profile "+p.Name+" cannot be deleted: "+err.Error()+". Detach it from those hosts first."), http.StatusSeeOther)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "profile_delete", fmt.Sprintf("profile:%d", p.ID), p.Name, true)
	http.Redirect(w, r, "/middleware-profiles?flash="+urlQueryEscape("Deleted profile "+p.Name+"."), http.StatusSeeOther)
}

// resyncProfileServers pushes every server that has a host on the profile, so
// an edit reaches Caddy without anyone re-saving each host. Returns how many.
func (s *Server) resyncProfileServers(profileID int64) int {
	servers, err := models.ServersUsingProfile(s.DB, profileID)
	if err != nil {
		log.Printf("middleware profile %d: list servers: %v", profileID, err)
		return 0
	}
	for _, sid := range servers {
		s.trySyncCaddy(sid, false)
	}
	return len(servers)
}

// --- proxy host form integration ---

// hostProfileFromForm returns the profile picked on a host form, 0 for none or
// for an ID that does not exist.
func (s *Server) hostProfileFromForm(r *http.Request) int64 {
	id, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("middleware_profile_id")), 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	if p, _ := models.GetMiddlewareProfile(s.DB, id); p == nil {
		return 0
	}
	return id
}

// withProfileViewData adds the profile picker's data to a host form render.
func (s *Server) withProfileViewData(data map[string]any, selected int64) map[string]any {
	profiles, _ := models.ListMiddlewareProfiles(s.DB)
	data["Profiles"] = profiles
	data["SelectedProfileID"] = selected
	return data
}

// wafPreflight refuses a WAF that a Caddy cannot run. Without it the whole
// config for that server would be rejected ("unknown module: http.handlers.waf")
// and no host on it could be synced until the image is updated. servers whose
// Caddy cannot be asked are not blocked on.
func (s *Server) wafPreflight(serverIDs []int64) string {
	var missing []string
	seen := map[int64]bool{}
	for _, id := range serverIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		srv, err := models.GetCaddyServer(s.DB, id)
		if err != nil || srv == nil || srv.Type == models.CaddyServerTypeExternal {
			continue
		}
		if present, known := s.caddyForServer(id).HasWAFModule(); known && !present {
			missing = append(missing, srv.Name)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	return "The Caddy on " + strings.Join(missing, ", ") + " has no Coraza WAF module (http.handlers.waf). Update it to an image that includes it — applegater/caddyui-caddy v2.61.0 or newer — before turning the WAF on."
}

// profileWAFOn reports whether the profile with this ID has a WAF enabled.
func (s *Server) profileWAFOn(profileID int64) bool {
	prof, _ := models.GetMiddlewareProfile(s.DB, profileID)
	return prof != nil && (prof.WAFMode == models.WAFModeDetect || prof.WAFMode == models.WAFModeBlock)
}

// friendlyCaddyError adds the fix to the one Caddy rejection people will meet.
func friendlyCaddyError(msg string) string {
	if strings.Contains(msg, "unknown module: http.handlers.waf") {
		return msg + " — this Caddy has no Coraza WAF module; update to applegater/caddyui-caddy v2.61.0 or newer, or detach the WAF middleware profile from the hosts on this server."
	}
	return msg
}
