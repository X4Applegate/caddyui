package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// v2.42.0: export a managed certificate to a directory.
//
// Caddy keeps the certificates it obtains in its data directory
// (<data>/caddy/certificates/<issuer>/<name>/<name>.crt and .key). Other
// services on the same host — a mail server is the usual case — need those
// files, and they need them again after every renewal. When a node's data
// volume is mounted into the CaddyUI container (Caddy Fleet → edit server →
// Data directory), CaddyUI can read the files and copy them wherever the
// certificate's export settings point, atomically, with the private key
// readable by owner only. Exports run when the node reports an issuance or
// renewal, on a timer as a safety net, after the certificate is saved, and
// on Export now. The last result is kept in settings as
// certificate_export_<id> and shown on the certificate form.

const (
	certificateExportEvery         = 10 * time.Minute
	certificateExportSettingPrefix = "certificate_export_"
	// Caddy logs cert_obtained after writing storage, but give the write a
	// moment on slow disks before reading it back.
	certificateExportEventDelay = 5 * time.Second
)

type certificateExportStatus struct {
	CertificateID int64      `json:"certificate_id"`
	ServerID      int64      `json:"server_id"`
	Source        string     `json:"source,omitempty"` // storage .crt the export came from
	Files         []string   `json:"files,omitempty"`
	SerialNumber  string     `json:"serial,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	ExportedAt    *time.Time `json:"exported_at,omitempty"`
	CheckedAt     time.Time  `json:"checked_at"`
	Error         string     `json:"error,omitempty"`
}

func (st *certificateExportStatus) DaysLeft() int {
	if st == nil || st.NotAfter == nil {
		return 0
	}
	return int(time.Until(*st.NotAfter).Hours() / 24)
}

// storageSafeName is certmagic's file-name form of a certificate subject:
// "*" becomes "wildcard_", everything else is kept lower-case.
func storageSafeName(domain string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(domain)), "*", "wildcard_")
}

// caddyStorageCertificateRoots lists where the certificates tree may sit
// under a mounted data directory: the official image keeps storage in
// <volume>/caddy, a host install may mount .../caddy itself, and an
// operator may point straight at the certificates directory.
func caddyStorageCertificateRoots(dataDir string) []string {
	dataDir = strings.TrimRight(strings.TrimSpace(dataDir), "/")
	if dataDir == "" {
		return nil
	}
	return []string{
		filepath.Join(dataDir, "caddy", "certificates"),
		filepath.Join(dataDir, "certificates"),
		dataDir,
	}
}

type storageCertificate struct {
	CertPath string
	KeyPath  string
	Leaf     *x509.Certificate
}

// findStorageCertificate locates the newest certificate Caddy stored for any
// of domains (first match by domain order, latest NotAfter across issuers).
func findStorageCertificate(dataDir string, domains []string) (*storageCertificate, error) {
	var best *storageCertificate
	var looked []string
	for _, root := range caddyStorageCertificateRoots(dataDir) {
		root, err := safeAbsolutePath(root)
		if err != nil {
			continue
		}
		issuers, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		looked = append(looked, root)
		for _, issuer := range issuers {
			if !issuer.IsDir() {
				continue
			}
			for _, domain := range domains {
				name := storageSafeName(domain)
				if name == "" {
					continue
				}
				if strings.Contains(issuer.Name(), "..") || strings.Contains(name, "..") {
					continue
				}
				crt := filepath.Join(root, issuer.Name(), name, name+".crt")
				key := filepath.Join(root, issuer.Name(), name, name+".key")
				raw, err := readCertificateFile(crt)
				if err != nil {
					continue
				}
				leaf := parsePEMLeaf(string(raw))
				if leaf == nil {
					continue
				}
				if _, err := os.Stat(key); err != nil {
					continue
				}
				if best == nil || leaf.NotAfter.After(best.Leaf.NotAfter) {
					best = &storageCertificate{CertPath: crt, KeyPath: key, Leaf: leaf}
				}
			}
		}
	}
	if best != nil {
		return best, nil
	}
	if len(looked) == 0 {
		return nil, fmt.Errorf("no Caddy certificate storage found under %s — is the node's data volume mounted into the CaddyUI container at that path?", dataDir)
	}
	return nil, fmt.Errorf("Caddy has not stored a certificate for %s yet (looked in %s)", strings.Join(domains, ", "), strings.Join(looked, ", "))
}

// writeFileAtomic writes data next to path and renames it into place, so a
// reader never sees a half-written certificate.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func certificateExportKey(certID int64) string {
	return certificateExportSettingPrefix + strconv.FormatInt(certID, 10)
}

func (s *Server) storeCertificateExportStatus(st certificateExportStatus) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return models.SetSetting(s.DB, certificateExportKey(st.CertificateID), string(raw))
}

func (s *Server) certificateExportStatusFor(certID int64) *certificateExportStatus {
	raw, err := models.GetSetting(s.DB, certificateExportKey(certID))
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var st certificateExportStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil
	}
	return &st
}

func (s *Server) deleteCertificateExportStatus(certID int64) {
	_ = models.DeleteSetting(s.DB, certificateExportKey(certID))
}

// exportCertificate copies the certificate Caddy stored for cert to the
// configured directory. Unless force is set, nothing is written when the
// exported files already hold the stored serial. The returned status is
// also persisted; err mirrors status.Error.
func (s *Server) exportCertificate(serverID int64, cert models.Certificate, force bool) (certificateExportStatus, error) {
	st := certificateExportStatus{CertificateID: cert.ID, ServerID: serverID, CheckedAt: time.Now().UTC()}
	if prev := s.certificateExportStatusFor(cert.ID); prev != nil {
		st.Source, st.Files, st.SerialNumber, st.NotAfter, st.ExportedAt = prev.Source, prev.Files, prev.SerialNumber, prev.NotAfter, prev.ExportedAt
	}
	fail := func(err error) (certificateExportStatus, error) {
		st.Error = err.Error()
		_ = s.storeCertificateExportStatus(st)
		return st, err
	}
	cfg := cert.ExportConfig()
	if cert.Source != models.CertSourceManaged || !cfg.Enabled() {
		return fail(fmt.Errorf("export is not configured for this certificate"))
	}
	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err != nil || srv == nil {
		return fail(fmt.Errorf("load server %d: %v", serverID, err))
	}
	if strings.TrimSpace(srv.DataDir) == "" {
		return fail(fmt.Errorf("no Data directory is set for %s — mount the node's Caddy data volume into the CaddyUI container and enter its path under Caddy Fleet → edit server", srv.Name))
	}
	// Both directories are operator input (server form, certificate form):
	// vet them here, right before any file access, like certificate paths.
	dataDir, err := safeAbsolutePath(srv.DataDir)
	if err != nil {
		return fail(fmt.Errorf("Data directory: %w", err))
	}
	exportDir, err := safeAbsolutePath(cfg.Dir)
	if err != nil {
		return fail(fmt.Errorf("export directory: %w", err))
	}
	stored, err := findStorageCertificate(dataDir, cert.DomainList())
	if err != nil {
		return fail(err)
	}
	serial := stored.Leaf.SerialNumber.Text(16)
	certOut := filepath.Join(exportDir, filepath.Base(cfg.CertFile))
	keyOut := filepath.Join(exportDir, filepath.Base(cfg.KeyFile))
	if !force && st.SerialNumber == serial {
		if _, certErr := os.Stat(certOut); certErr == nil {
			if _, keyErr := os.Stat(keyOut); keyErr == nil {
				st.Error = ""
				_ = s.storeCertificateExportStatus(st)
				return st, nil
			}
		}
	}
	certPEM, err := readCertificateFile(stored.CertPath)
	if err != nil {
		return fail(fmt.Errorf("read %s: %w", stored.CertPath, err))
	}
	keyPEM, err := readCertificateFile(stored.KeyPath)
	if err != nil {
		return fail(fmt.Errorf("read %s: %w", stored.KeyPath, err))
	}
	if err := os.MkdirAll(exportDir, 0o755); err != nil {
		return fail(fmt.Errorf("create %s: %w", exportDir, err))
	}
	if err := writeFileAtomic(certOut, certPEM, 0o644); err != nil {
		return fail(fmt.Errorf("write %s: %w", certOut, err))
	}
	if err := writeFileAtomic(keyOut, keyPEM, 0o600); err != nil {
		return fail(fmt.Errorf("write %s: %w", keyOut, err))
	}
	now := time.Now().UTC()
	notAfter := stored.Leaf.NotAfter.UTC()
	st.Source, st.Files, st.SerialNumber, st.NotAfter, st.ExportedAt, st.Error = stored.CertPath, []string{certOut, keyOut}, serial, &notAfter, &now, ""
	_ = s.storeCertificateExportStatus(st)
	_ = models.LogActivity(s.DB, serverID, "system", "cert_export", fmt.Sprintf("cert:%d", cert.ID),
		fmt.Sprintf("exported %s (serial %s, expires %s) to %s", cert.Domains, serial, notAfter.Format("2006-01-02"), exportDir), true)
	return st, nil
}

// runCertificateExports exports every managed certificate with export
// settings on serverID (0 = every managed server with a data directory).
// Returns how many certificates were checked.
func (s *Server) runCertificateExports(serverID int64, force bool) (int, error) {
	s.certExportRunMu.Lock()
	defer s.certExportRunMu.Unlock()
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		return 0, err
	}
	checked := 0
	var failures []string
	for _, srv := range servers {
		if srv.Type != models.CaddyServerTypeManaged || (serverID != 0 && srv.ID != serverID) || strings.TrimSpace(srv.DataDir) == "" {
			continue
		}
		certs, err := models.ListCertificates(s.DB, srv.ID)
		if err != nil {
			return checked, fmt.Errorf("%s: list certificates: %w", srv.Name, err)
		}
		for _, c := range certs {
			if c.Source != models.CertSourceManaged || !c.ExportConfig().Enabled() {
				continue
			}
			checked++
			if _, err := s.exportCertificate(srv.ID, c, force); err != nil {
				failures = append(failures, fmt.Sprintf("%s/%s: %v", srv.Name, c.Name, err))
			}
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return checked, fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return checked, nil
}

// exportCertificatesForIdentifier exports every exporting certificate on
// serverID that covers identifier — the hook behind Caddy's cert_obtained /
// renewal events. Returns how many were exported or re-checked.
func (s *Server) exportCertificatesForIdentifier(serverID int64, identifier string) int {
	certs, err := models.ListCertificates(s.DB, serverID)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range certs {
		if c.Source != models.CertSourceManaged || !c.ExportConfig().Enabled() || !certificateCoversAnyDomain(c, []string{identifier}) {
			continue
		}
		n++
		if _, err := s.exportCertificate(serverID, c, false); err != nil {
			log.Printf("certificate export: %s on server %d after %s became active: %v", c.Name, serverID, identifier, err)
		}
	}
	return n
}

// handleCertificateActive is wired into the log hub (SetCaddyLogHub): a
// node reported a certificate as obtained/renewed/loaded.
func (s *Server) handleCertificateActive(serverID int64, identifier string) {
	if s.DB == nil || serverID <= 0 {
		return
	}
	go func() {
		time.Sleep(certificateExportEventDelay)
		s.exportCertificatesForIdentifier(serverID, identifier)
	}()
}

// exportCertificateSoon runs an export shortly after the certificate was
// saved, so a freshly configured export does not wait for the next pass.
func (s *Server) exportCertificateSoon(serverID int64, cert models.Certificate) {
	if cert.Source != models.CertSourceManaged || !cert.ExportConfig().Enabled() || cert.ID == 0 {
		return
	}
	go func() {
		time.Sleep(2 * time.Second)
		if _, err := s.exportCertificate(serverID, cert, false); err != nil {
			log.Printf("certificate export: %s after save: %v", cert.Name, err)
		}
	}()
}

// StartCertificateExports runs the safety-net pass on a timer until ctx ends.
func (s *Server) StartCertificateExports(ctx context.Context) {
	go func() {
		run := func() {
			n, err := s.runCertificateExports(0, false)
			if err != nil {
				log.Printf("certificate export: %v", err)
			} else if n > 0 {
				log.Printf("certificate export: checked %d certificate(s)", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
		run()
		ticker := time.NewTicker(certificateExportEvery)
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

// exportCertificateHandler: POST /certificates/{id}/export — Export now on
// the certificate form. Uses the saved export settings and always rewrites.
func (s *Server) exportCertificateHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	cert, err := models.GetCertificate(s.DB, id)
	if err != nil || cert == nil {
		http.NotFound(w, r)
		return
	}
	cu := s.currentUser(r)
	if cu == nil || (cu.Role != models.RoleAdmin && (!cert.OwnerID.Valid || cert.OwnerID.Int64 != cu.ID)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serverID, _ := models.CertificateServerID(s.DB, id)
	if _, err := s.exportCertificate(serverID, *cert, true); err != nil {
		_ = models.LogActivity(s.DB, serverID, s.currentUserEmail(r), "cert_export", fmt.Sprintf("cert:%d", id), err.Error(), false)
	}
	http.Redirect(w, r, fmt.Sprintf("/certificates/%d/edit#export", id), http.StatusSeeOther)
}

// serverDataDir is the node's configured data directory, "" when unset.
func (s *Server) serverDataDir(serverID int64) string {
	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err != nil || srv == nil {
		return ""
	}
	return strings.TrimSpace(srv.DataDir)
}

// addCertificateExportViewData adds the export settings, last status and the
// node's data directory to a certificate form's template data.
func (s *Server) addCertificateExportViewData(data map[string]any, id int64, cert models.Certificate) {
	data["Export"] = cert.ExportConfig()
	if id > 0 {
		data["ExportStatus"] = s.certificateExportStatusFor(id)
		serverID, _ := models.CertificateServerID(s.DB, id)
		data["ExportDataDir"] = s.serverDataDir(serverID)
	}
}
