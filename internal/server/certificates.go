// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// --- Certificates ---

// adminUserList returns the full user list for admins (used by the admin-only
// Owner pickers on new/edit forms so an admin can provision a resource for a
// specific customer). Returns an empty slice for non-admin viewers so we
// don't waste a DB round-trip and so a template leak can't surface email
// addresses to non-admins. v2.7.3.
// groupPeerIDs returns the other user IDs that share at least one group with
// the viewer. Used to expand a non-admin viewer's visibility scope in every
// List* call: viewer sees their own rows + globals + any row owned by a peer.
// Admins skip this path entirely — their List* branch is unfiltered — so we
// return nil immediately for admin/view and for signed-out requests. DB
// errors are swallowed to nil so a transient groups-table hiccup degrades to
// "no group visibility" rather than breaking the whole list page.
func (s *Server) groupPeerIDs(r *http.Request) []int64 {
	cu := s.currentUser(r)
	if cu == nil || cu.Role != models.RoleUser {
		return nil
	}
	ids, err := models.GroupPeerIDs(s.DB, cu.ID)
	if err != nil {
		return nil
	}
	return ids
}

// adminUserList returns the user-role accounts an admin can assign resources
// to. Only admins see anything — nil for non-admin viewers so their templates
// can't accidentally leak the user roster via the Owner <select>. View-role
// and admin accounts are filtered out because neither can "own" a resource in
// the data model (admin ownership is represented as NULL / global; view can't
// manage anything at all), so they'd be dead options in the picker.
func (s *Server) adminUserList(r *http.Request) []models.User {
	cu := s.currentUser(r)
	if cu == nil || cu.Role != models.RoleAdmin {
		return nil
	}
	users, err := models.ListUsers(s.DB)
	if err != nil {
		return nil
	}
	out := users[:0]
	for _, u := range users {
		if u.Role == models.RoleUser {
			out = append(out, u)
		}
	}
	return out
}

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
	return models.ListCertificatesForUser(s.DB, s.currentServerID(r), viewerID, isAdmin, s.groupPeerIDs(r))
}

func (s *Server) certOptionListForRequest(r *http.Request) ([]models.Certificate, error) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	return models.ListCertificateOptionsForUser(s.DB, s.currentServerID(r), viewerID, isAdmin, s.groupPeerIDs(r))
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
	// v2.7.4: ...plus any certs owned by a teammate (shared group member).
	certs, err := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lifecycleStates, _ := models.ListCertificateLifecycle(s.DB, sid)
	// Usage must be calculated against the complete environment, not only
	// resources visible to the current user. Otherwise a global certificate
	// used by another tenant could be incorrectly labeled as unused.
	allHosts, _ := models.ListProxyHosts(s.DB, sid, 0, true, nil)
	allRedirs, _ := models.ListRedirectionHosts(s.DB, sid, 0, true, nil)
	allRoutes, _ := models.ListRawRoutes(s.DB, sid, 0, true, nil)
	referencedCerts := referencedCertificateIDs(allHosts, allRedirs, allRoutes)
	usageFilter := ""
	if r.URL.Query().Get("usage") == "unused" {
		usageFilter = "unused"
	}

	// Precompute the group-peer set once so the per-row edit predicate does
	// not issue a DB query per certificate.
	peerSet := map[int64]bool{}
	for _, id := range s.groupPeerIDs(r) {
		peerSet[id] = true
	}
	views := make([]certView, 0, len(certs))
	unusedCount := 0
	// Resolved once for the whole page rather than per row (v2.53.0).
	readRoots := s.certificateReadRoots()
	for _, c := range certs {
		// Edit/delete predicate: admin → always; user-role → their own rows
		// and rows owned by a group peer (access-groups grant collaborative
		// management, v2.52.5). Global admin-owned (NULL owner) rows stay
		// admin-only even though they're visible for the dropdown-reference case.
		canEdit := isAdmin || (c.OwnerID.Valid && viewerID != 0 && (c.OwnerID.Int64 == viewerID || peerSet[c.OwnerID.Int64]))
		view := certView{
			Certificate: c,
			CanEdit:     canEdit,
			IsUnused:    isUnusedCustomCertificate(c, referencedCerts),
		}
		if c.Source == models.CertSourceManaged {
			view.Lifecycle = certificateLifecycleForDomains(lifecycleStates, c.DomainList())
		}
		if view.IsUnused {
			unusedCount++
		}
		var exp *time.Time
		if isCustomCertificate(c) {
			var leaf *x509.Certificate
			if pemData, readErr := customCertificatePEM(c, readRoots); readErr == nil {
				leaf = parsePEMLeaf(pemData)
			}
			if leaf != nil {
				t := leaf.NotAfter
				exp = &t
				view.ExpirySource = "file"
				if c.Source == models.CertSourcePEM {
					view.ExpirySource = "stored"
				}
			}
			// v2.39.0: a file-path certificate CaddyUI cannot read falls back
			// to what the node actually serves for its domain.
			view.Probe = s.certificateProbeFor(c.ID)
			if view.Probe.HasCertificate() {
				if exp == nil {
					exp = view.Probe.NotAfter
					view.ExpirySource = "probe"
				} else if leaf != nil && leaf.SerialNumber.Text(16) != view.Probe.SerialNumber {
					view.ServedDiffers = true
				}
			}
		}
		if exp != nil {
			view.ExpiresAt = exp
			view.DaysLeft = int(time.Until(*exp).Hours() / 24)
		}
		if usageFilter == "" || view.IsUnused {
			views = append(views, view)
		}
	}
	unusedDismissed := unusedCount > 0 &&
		mustGetSetting(s.DB, unusedCertificateDismissalKey(sid)) == unusedCertificateFingerprint(certs, referencedCerts)

	// Collect domains auto-managed by Caddy (ssl_enabled, no custom cert).
	// Use admin view to see all hosts regardless of owner. v2.36.2 (issue
	// #65): Advanced routes are included — see collectAutoManagedDomains.
	autoDomains := collectAutoManagedDomains(certs, lifecycleStates, allHosts, allRedirs, allRoutes)

	pbAPIKey, _ := models.GetSetting(s.DB, settingPBAPIKey)
	pbSecretKey, _ := models.GetSetting(s.DB, settingPBSecretKey)
	s.render(w, r, "certificates.html", map[string]any{
		"User":              s.currentUser(r),
		"Certs":             views,
		"UnusedCount":       unusedCount,
		"UsageFilter":       usageFilter,
		"UnusedDismissed":   unusedDismissed,
		"AutoDomains":       autoDomains,
		"PorkbunConfigured": pbAPIKey != "" && pbSecretKey != "",
		"Section":           "certs",
	})
}

func (s *Server) dismissUnusedCertificateRecommendation(w http.ResponseWriter, r *http.Request) {
	sid := s.currentServerID(r)
	certs, err := models.ListCertificates(s.DB, sid)
	if err != nil {
		http.Error(w, "load certificates: "+err.Error(), http.StatusInternalServerError)
		return
	}
	hosts, _ := models.ListProxyHosts(s.DB, sid, 0, true, nil)
	redirs, _ := models.ListRedirectionHosts(s.DB, sid, 0, true, nil)
	routes, _ := models.ListRawRoutes(s.DB, sid, 0, true, nil)
	fingerprint := unusedCertificateFingerprint(certs, referencedCertificateIDs(hosts, redirs, routes))
	if err := models.SetSetting(s.DB, unusedCertificateDismissalKey(sid), fingerprint); err != nil {
		http.Error(w, "save dismissal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	actor := ""
	if user := s.currentUser(r); user != nil {
		actor = user.Email
	}
	_ = models.LogActivity(s.DB, sid, actor, "recommendation_dismiss", "unused_custom_certificates", fingerprint, true)
	http.Redirect(w, r, "/certificates?usage=unused", http.StatusSeeOther)
}

// getCertificateInspect parses the stored PEM and renders detailed certificate
// information (subject, issuer, SANs, validity window, key type, serial,
// SHA-256 fingerprint). Accessible to all authenticated users, not just admins,
// so each user can inspect certs they uploaded.
func (s *Server) getCertificateInspect(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	cert, err := models.GetCertificate(s.DB, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data := map[string]any{
		"User":    s.currentUser(r),
		"Cert":    cert,
		"Section": "certs",
	}

	s.fillCertificateInspectData(data, id, *cert)
	s.render(w, r, "certificate_inspect.html", data)
}

// fillCertificateInspectData adds the parsed certificate details to data:
// from the stored PEM or the readable file when there is one, else (v2.39.0)
// from a live TLS probe of the node — refreshed here when the stored result
// is stale, so Inspect always shows something recent. Keys are the ones
// certificate_inspect.html reads; FromProbe marks the fallback.
func (s *Server) fillCertificateInspectData(data map[string]any, id int64, cert models.Certificate) {
	if cert.ID == 0 {
		cert.ID = id // probe results are keyed by certificate ID
	}
	pemData, readErr := customCertificatePEM(cert, s.certificateReadRoots())
	if readErr != nil {
		data["ReadError"] = readErr.Error()
	}
	var probe *liveCertificateInfo
	if isCustomCertificate(cert) {
		probe = s.certificateProbeFor(id)
		if probe.Stale() {
			serverID, _ := models.CertificateServerID(s.DB, id)
			fresh := s.probeCustomCertificate(serverID, cert)
			_ = s.storeCertificateProbe(fresh)
			probe = &fresh
		}
		data["Probe"] = probe
	}

	fill := func(sum x509Summary) {
		data["Subject"] = sum.Subject
		data["Issuer"] = sum.Issuer
		data["SANs"] = sum.SANs
		data["NotBefore"] = sum.NotBefore
		data["NotAfter"] = sum.NotAfter
		data["DaysLeft"] = int(time.Until(sum.NotAfter).Hours() / 24)
		data["KeyType"] = sum.KeyType
		data["KeyBits"] = sum.KeyBits
		data["SerialNumber"] = sum.SerialNumber
		data["Fingerprint"] = sum.Fingerprint
	}

	leaf := parsePEMLeaf(pemData)
	if leaf == nil {
		// Nothing readable locally: show what the node serves for the
		// certificate's domain instead, and say so.
		if probe.HasCertificate() {
			data["FromProbe"] = true
			fill(x509Summary{
				Subject: probe.Subject, Issuer: probe.Issuer, SANs: probe.SANs,
				NotBefore: *probe.NotBefore, NotAfter: *probe.NotAfter,
				KeyType: probe.KeyType, KeyBits: probe.KeyBits,
				SerialNumber: probe.SerialNumber, Fingerprint: probe.Fingerprint,
			})
		}
		return
	}
	sum := summarizeX509(leaf)
	fill(sum)
	if probe.HasCertificate() {
		data["ServedKnown"] = true
		data["ServedMatches"] = probe.Fingerprint == sum.Fingerprint
	}
}

type managedCertificateServerStatus struct {
	ServerID         int64      `json:"server_id"`
	ServerName       string     `json:"server_name"`
	Deployed         bool       `json:"deployed"`
	Status           string     `json:"status"`
	ProbeName        string     `json:"probe_name,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	DaysLeft         int        `json:"days_left,omitempty"`
	Issuer           string     `json:"issuer,omitempty"`
	Error            string     `json:"error,omitempty"`
	LifecyclePhase   string     `json:"lifecycle_phase,omitempty"`
	LifecycleMessage string     `json:"lifecycle_message,omitempty"`
	LifecycleAt      *time.Time `json:"lifecycle_at,omitempty"`
}

func managedCertificateProbeName(cert models.Certificate) string {
	for _, domain := range cert.DomainList() {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if strings.HasPrefix(domain, "*.") {
			return "caddyui-probe." + strings.TrimPrefix(domain, "*.")
		}
	}
	for _, domain := range cert.DomainList() {
		if domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), "."); domain != "" {
			return domain
		}
	}
	return ""
}

func (s *Server) probeManagedCertificate(server models.CaddyServer, cert models.Certificate) managedCertificateServerStatus {
	result := managedCertificateServerStatus{
		ServerID: server.ID, ServerName: server.Name, Deployed: true, Status: "unavailable",
		ProbeName: managedCertificateProbeName(cert),
	}
	if result.ProbeName == "" {
		result.Error = "no certificate subject configured"
		return result
	}
	host := s.caddyDialHost(server.ID)
	if host == "" {
		host = result.ProbeName
	}
	target := net.JoinHostPort(strings.Trim(host, "[]"), "443")
	leaf, err := dialLeafCertificate(target, result.ProbeName, customCertificateProbeTimeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if err := leaf.VerifyHostname(result.ProbeName); err != nil {
		result.Status = "mismatch"
		result.Error = err.Error()
		return result
	}
	expires := leaf.NotAfter.UTC()
	result.ExpiresAt = &expires
	result.DaysLeft = int(time.Until(expires).Hours() / 24)
	result.Issuer = leaf.Issuer.CommonName
	switch {
	case result.DaysLeft < 0:
		result.Status = "expired"
	case result.DaysLeft < 30:
		result.Status = "expiring"
	default:
		result.Status = "healthy"
	}
	return result
}

// getManagedCertificateStatus reports the live certificate served by every
// managed Caddy instance for an SNI name covered by this managed definition.
// A synthetic child name lets wildcard-only certificates be inspected without
// requiring public DNS for a real proxy hostname.
func (s *Server) getManagedCertificateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid certificate id")
		return
	}
	visible, err := s.certListForRequest(r)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var cert *models.Certificate
	for i := range visible {
		if visible[i].ID == id {
			cert = &visible[i]
			break
		}
	}
	if cert == nil {
		writeJSONError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if cert.Source != models.CertSourceManaged {
		writeJSONError(w, http.StatusBadRequest, "certificate is not managed by ACME")
		return
	}
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	results := make([]managedCertificateServerStatus, len(servers))
	var wg sync.WaitGroup
	for i, server := range servers {
		if server.Type != models.CaddyServerTypeManaged {
			results[i] = managedCertificateServerStatus{
				ServerID: server.ID, ServerName: server.Name, Status: "external",
			}
			continue
		}
		deployed := false
		if serverCerts, listErr := models.ListCertificates(s.DB, server.ID); listErr == nil {
			for _, serverCert := range serverCerts {
				if serverCert.Source == models.CertSourceManaged && sameDomainSet(serverCert.DomainList(), cert.DomainList()) {
					deployed = true
					break
				}
			}
		}
		if !deployed {
			results[i] = managedCertificateServerStatus{
				ServerID: server.ID, ServerName: server.Name, Status: "not_configured",
			}
			continue
		}
		wg.Add(1)
		go func(index int, srv models.CaddyServer) {
			defer wg.Done()
			results[index] = s.probeManagedCertificate(srv, *cert)
		}(i, server)
	}
	wg.Wait()
	states, _ := models.ListCertificateLifecycle(s.DB, 0)
	for i := range results {
		serverStates := make([]models.CertificateLifecycleStatus, 0)
		for _, state := range states {
			if state.ServerID == results[i].ServerID {
				serverStates = append(serverStates, state)
			}
		}
		state := certificateLifecycleForDomains(serverStates, cert.DomainList())
		if state == nil {
			continue
		}
		results[i].LifecyclePhase = state.Phase
		results[i].LifecycleMessage = state.Message
		updated := state.UpdatedAt
		results[i].LifecycleAt = &updated
		switch state.Phase {
		case "obtaining", "renewing", "retrying", "error", "revoked":
			results[i].Status = state.Phase
			if state.Error != "" {
				results[i].Error = state.Error
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": results})
}

func (s *Server) newCertificate(w http.ResponseWriter, r *http.Request) {
	// v2.7.3: Users list fuels the admin-only Owner picker on the form.
	// Non-admins get nil — the template skips rendering the picker.
	data := map[string]any{
		"ExportDataDir": s.serverDataDir(s.currentServerID(r)), // v2.42.0
		"Export":        models.CertificateExport{},
		"User":          s.currentUser(r),
		"Cert":          &models.Certificate{Source: models.CertSourcePEM},
		"Users":         s.adminUserList(r),
		"OtherServers":  s.otherManagedServers(r),
		"Section":       "certs",
	}
	s.render(w, r, "certificate_form.html", s.applyDNSViewData(s.currentServerID(r), data))
}

func (s *Server) parseCertificateForm(r *http.Request) (*models.Certificate, string) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	domains := strings.TrimSpace(r.FormValue("domains"))
	source := r.FormValue("source")
	if source != models.CertSourcePEM && source != models.CertSourcePath && source != models.CertSourceManaged {
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
	} else if source == models.CertSourcePath {
		c.CertPath = strings.TrimSpace(r.FormValue("cert_path"))
		c.KeyPath = strings.TrimSpace(r.FormValue("key_path"))
		if c.CertPath == "" || c.KeyPath == "" {
			return nil, "Certificate path and Key path are required when source is 'path'"
		}
	} else {
		c.DNSProvider, c.DNSProfileID = s.normalizeDNSFormSelection(
			r.FormValue("dns_provider"), r.FormValue("dns_profile_id"))
		if c.DNSProvider == "" {
			return nil, "Choose DNS credentials for a managed ACME certificate"
		}
		if caddyDNSProviderConfig(c.DNSProvider, s.dnsCredsFor(c.DNSProvider, c.DNSProfileID), "") == nil {
			return nil, "The selected DNS credential profile is missing required credentials"
		}
		// v2.42.0: export to a directory after every issuance/renewal.
		exportJSON, err := models.NormalizeCertificateExportJSON(models.CertificateExport{
			Dir:      r.FormValue("export_dir"),
			CertFile: r.FormValue("export_cert_file"),
			KeyFile:  r.FormValue("export_key_file"),
		})
		if err != nil {
			return nil, err.Error()
		}
		if exportJSON != "" {
			if _, err := safeAbsolutePath(r.FormValue("export_dir")); err != nil {
				return nil, "Export directory: " + err.Error()
			}
		}
		c.Export = exportJSON
	}
	return c, ""
}

func (s *Server) createCertificate(w http.ResponseWriter, r *http.Request) {
	c, errMsg := s.parseCertificateForm(r)
	if errMsg != "" {
		// Re-render with whatever the user typed
		fallback := &models.Certificate{
			Name:         r.FormValue("name"),
			Domains:      r.FormValue("domains"),
			Source:       r.FormValue("source"),
			CertPEM:      r.FormValue("cert_pem"),
			KeyPEM:       r.FormValue("key_pem"),
			CertPath:     r.FormValue("cert_path"),
			KeyPath:      r.FormValue("key_path"),
			DNSProvider:  r.FormValue("dns_provider"),
			DNSProfileID: r.FormValue("dns_profile_id"),
		}
		data := map[string]any{
			"User":         s.currentUser(r),
			"Cert":         fallback,
			"Users":        s.adminUserList(r),
			"OtherServers": s.otherManagedServers(r),
			"Error":        errMsg,
			"Section":      "certs",
		}
		s.render(w, r, "certificate_form.html", s.applyDNSViewData(s.currentServerID(r), data))
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
	} else if cu != nil && cu.Role == models.RoleAdmin {
		// v2.7.3: admin can upload-and-assign a cert directly to a specific
		// user from the new-cert form.
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				ownerID = parsed
			}
		}
	}
	// v2.42.1 (issue #74): a file-path certificate Caddy cannot open is
	// refused here, with the container-path explanation, instead of being
	// saved and breaking every later sync of this server.
	if errMsg := s.previewCertificateValidate(s.currentServerID(r), c); errMsg != "" {
		s.renderCertificateFormError(w, r, c, errMsg)
		return
	}
	id, err := models.CreateCertificate(s.DB, s.currentServerID(r), ownerID, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.ID = id
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_create", fmt.Sprintf("cert:%d", id), c.Name, true)
	s.trySyncCaddy(s.currentServerID(r), true)
	s.probeCertificateSoon(s.currentServerID(r), *c)
	s.exportCertificateSoon(s.currentServerID(r), *c)
	s.crossDeployCertificate(s.currentUserEmail(r), s.currentServerID(r), *c, parseDeployTo(r))
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
		if !s.canManageOwned(cu, c.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	data := map[string]any{
		"User":         s.currentUser(r),
		"Cert":         c,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Section":      "certs",
	}
	s.addCertificateExportViewData(data, id, *c)
	s.render(w, r, "certificate_form.html", s.applyDNSViewData(s.currentServerID(r), data))
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
		if !s.canManageOwned(cu, existing.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	c, errMsg := s.parseCertificateForm(r)
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
		existing.DNSProvider = r.FormValue("dns_provider")
		existing.DNSProfileID = r.FormValue("dns_profile_id")
		data := map[string]any{
			"User":         s.currentUser(r),
			"Cert":         existing,
			"Users":        s.adminUserList(r),
			"OtherServers": s.otherManagedServers(r),
			"Error":        errMsg,
			"Section":      "certs",
		}
		s.render(w, r, "certificate_form.html", s.applyDNSViewData(s.currentServerID(r), data))
		return
	}
	c.ID = id
	if errMsg := s.previewCertificateValidate(s.currentServerID(r), c); errMsg != "" { // v2.42.1 (issue #74)
		s.renderCertificateFormError(w, r, c, errMsg)
		return
	}
	if err := models.UpdateCertificate(s.DB, c); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// v2.7.3: admin-only owner reassignment. Note: when admin moves a cert
	// from "global" to a specific user, any existing proxy/redirect/raw rows
	// referencing this cert continue to work — the syncCaddy call below
	// rewrites the running Caddy config from the DB, and cert references are
	// resolved by ID not ownership. This is by design: handing a cert off
	// should not break whatever's already using it.
	if isAdmin {
		if v := strings.TrimSpace(r.FormValue("owner_id")); v != "" {
			if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed >= 0 {
				_ = models.SetCertificateOwner(s.DB, c.ID, parsed)
			}
		}
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_update", fmt.Sprintf("cert:%d", id), c.Name, true)
	s.trySyncCaddy(s.currentServerID(r), true)
	s.probeCertificateSoon(s.currentServerID(r), *c)
	s.exportCertificateSoon(s.currentServerID(r), *c)
	s.crossDeployCertificate(s.currentUserEmail(r), s.currentServerID(r), *c, parseDeployTo(r))
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
		if !s.canManageOwned(cu, cert.OwnerID) {
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
	s.deleteCertificateProbe(id)
	s.deleteCertificateExportStatus(id)
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "cert_delete", fmt.Sprintf("cert:%d", id), "", true)
	s.trySyncCaddy(s.currentServerID(r), true)
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}
