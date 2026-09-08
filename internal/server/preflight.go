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

	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// v2.42.1 (issue #74): a change that Caddy will not load used to be saved
// anyway. The form said "saved", the sync failed in the log, the live config
// stayed as it was — and every later sync for that server failed the same
// way until someone noticed. The reported case was a file-path certificate
// whose files exist on the host but not inside the Caddy container.
//
// Two layers now: proxy hosts, redirections and certificates are validated
// against Caddy before they are saved, the way Advanced routes already were;
// and when a sync fails for any reason after a save, the failure is kept per
// server and shown on every page until the next successful sync.

// serverResources loads every resource of a server for a preview build.
// ok is false when a query failed — callers then skip validation rather than
// block a save on an unrelated error.
func (s *Server) serverResources(serverID int64) (proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute, certs []models.Certificate, ok bool) {
	var err error
	if proxies, err = models.ListProxyHosts(s.DB, serverID, 0, true, nil); err != nil {
		return nil, nil, nil, nil, false
	}
	if redirs, err = models.ListRedirectionHosts(s.DB, serverID, 0, true, nil); err != nil {
		return nil, nil, nil, nil, false
	}
	if raws, err = models.ListRawRoutes(s.DB, serverID, 0, true, nil); err != nil {
		return nil, nil, nil, nil, false
	}
	if certs, err = models.ListCertificates(s.DB, serverID); err != nil {
		return nil, nil, nil, nil, false
	}
	return proxies, redirs, raws, certs, true
}

// previewProxyHostValidate simulates the sync with p saved (replacing the
// row with the same ID, or added) and asks Caddy to validate the result.
// Returns a message only when Caddy would reject it.
func (s *Server) previewProxyHostValidate(serverID int64, p *models.ProxyHost) string {
	proxies, redirs, raws, certs, ok := s.serverResources(serverID)
	if !ok {
		return ""
	}
	replaced := false
	for i := range proxies {
		if p.ID != 0 && proxies[i].ID == p.ID {
			proxies[i] = *p
			replaced = true
			break
		}
	}
	if !replaced {
		proxies = append(proxies, *p)
	}
	return friendlyCaddyRejection(s.validateProposedConfig(serverID, proxies, redirs, raws, certs), certs)
}

// previewRedirectValidate is previewProxyHostValidate for a redirection.
func (s *Server) previewRedirectValidate(serverID int64, rh *models.RedirectionHost) string {
	proxies, redirs, raws, certs, ok := s.serverResources(serverID)
	if !ok {
		return ""
	}
	replaced := false
	for i := range redirs {
		if rh.ID != 0 && redirs[i].ID == rh.ID {
			redirs[i] = *rh
			replaced = true
			break
		}
	}
	if !replaced {
		redirs = append(redirs, *rh)
	}
	return friendlyCaddyRejection(s.validateProposedConfig(serverID, proxies, redirs, raws, certs), certs)
}

// previewCertificateValidate is the same for a certificate: a file-path
// certificate whose files Caddy cannot open fails right here, before the
// row exists, instead of breaking every later sync.
func (s *Server) previewCertificateValidate(serverID int64, c *models.Certificate) string {
	proxies, redirs, raws, certs, ok := s.serverResources(serverID)
	if !ok {
		return ""
	}
	replaced := false
	for i := range certs {
		if c.ID != 0 && certs[i].ID == c.ID {
			certs[i] = *c
			replaced = true
			break
		}
	}
	if !replaced {
		certs = append(certs, *c)
	}
	return friendlyCaddyRejection(s.validateProposedConfig(serverID, proxies, redirs, raws, certs), certs)
}

// friendlyCaddyRejection turns Caddy's validation error into something a
// person can act on. The message from validateProposedConfig starts with
// "Caddy rejected the proposed config: "; the common case — a certificate
// file that exists on the host but not inside the Caddy container — gets a
// specific explanation.
func friendlyCaddyRejection(msg string, certs []models.Certificate) string {
	if msg == "" {
		return ""
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "no such file or directory") || strings.Contains(lower, "loading certificates") {
		for _, c := range certs {
			if c.Source != models.CertSourcePath {
				continue
			}
			for _, p := range []string{c.CertPath, c.KeyPath} {
				if p != "" && strings.Contains(msg, p) {
					return fmt.Sprintf("Caddy cannot open %s for certificate %q. File paths are read by Caddy inside the Caddy container, so the file must exist there — mount the directory into the Caddy container (for example `-v /etc/letsencrypt:/etc/letsencrypt:ro`) and use that path, or paste the PEM instead. Caddy said: %s", p, c.Name, strings.TrimPrefix(msg, "Caddy rejected the proposed config: "))
				}
			}
		}
	}
	return strings.Replace(msg, "Caddy rejected the proposed config: ", "Caddy rejected this change, so it was not saved: ", 1)
}

// --- failed-sync banner --------------------------------------------------

const syncErrorKeyPrefix = "sync_error_server_"

type syncError struct {
	ServerID   int64     `json:"server_id"`
	ServerName string    `json:"server_name"`
	Error      string    `json:"error"`
	At         time.Time `json:"at"`
}

func syncErrorKey(serverID int64) string {
	return syncErrorKeyPrefix + strconv.FormatInt(serverID, 10)
}

func (s *Server) setSyncError(serverID int64, serverName string, err error) {
	raw, marshalErr := json.Marshal(syncError{ServerID: serverID, ServerName: serverName, Error: err.Error(), At: time.Now().UTC()})
	if marshalErr != nil {
		return
	}
	if setErr := models.SetSetting(s.DB, syncErrorKey(serverID), string(raw)); setErr != nil {
		log.Printf("record sync error for server %d: %v", serverID, setErr)
	}
}

func (s *Server) clearSyncError(serverID int64) {
	_ = models.DeleteSetting(s.DB, syncErrorKey(serverID))
}

func (s *Server) syncErrorFor(serverID int64) *syncError {
	raw, err := models.GetSetting(s.DB, syncErrorKey(serverID))
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var e syncError
	if json.Unmarshal([]byte(raw), &e) != nil {
		return nil
	}
	return &e
}

// activeSyncErrors lists servers whose last sync failed, for the layout
// banner. Servers under a post-apply hold are left out — the hold banner
// already covers them.
func (s *Server) activeSyncErrors(servers []models.CaddyServer) []syncError {
	var out []syncError
	for _, sr := range servers {
		if s.syncHoldFor(sr.ID) != nil {
			continue
		}
		if e := s.syncErrorFor(sr.ID); e != nil {
			if e.ServerName == "" {
				e.ServerName = sr.Name
			}
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerID < out[j].ServerID })
	return out
}

// clearSyncErrorHandler: POST /servers/{id}/sync-error/clear — Dismiss on
// the banner. The next sync records a fresh result either way.
func (s *Server) clearSyncErrorHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	s.clearSyncError(id)
	redirectBack(w, r)
}

// renderCertificateFormError re-renders the certificate form with what the
// user typed and an error, for both the create and the edit flow.
func (s *Server) renderCertificateFormError(w http.ResponseWriter, r *http.Request, c *models.Certificate, errMsg string) {
	data := map[string]any{
		"User":         s.currentUser(r),
		"Cert":         c,
		"Users":        s.adminUserList(r),
		"OtherServers": s.otherManagedServers(r),
		"Error":        errMsg,
		"Section":      "certs",
	}
	s.addCertificateExportViewData(data, c.ID, *c)
	s.render(w, r, "certificate_form.html", s.applyDNSViewData(s.currentServerID(r), data))
}

// certificateForCaddyfile loads the certificate a host references so the
// Caddyfile view can show a real `tls` line for file-path certificates
// (v2.42.1, issue #74 mentioned the view being "almost empty"). nil when
// there is none or it cannot be loaded.
func (s *Server) certificateForCaddyfile(certificateID int64) *models.Certificate {
	if certificateID == 0 {
		return nil
	}
	c, err := models.GetCertificate(s.DB, certificateID)
	if err != nil {
		return nil
	}
	return c
}
