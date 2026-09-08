package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// v2.39.0: live TLS probes for custom (PEM and file-path) certificates.
//
// A file-path certificate names files inside the Caddy container. CaddyUI
// usually cannot read those files from its own container, so the
// Certificates page showed no expiry at all for them and the inspect page
// gave up with "CaddyUI does not read the file contents directly". The
// managed-certificate code already proves what a node serves by opening a
// TLS connection to it and reading the leaf certificate; the same handshake
// works for any certificate Caddy has loaded, however it was loaded.
//
// Results are persisted in the settings table, one JSON document per
// certificate, so they survive a restart and cost nothing to render. They
// are refreshed on a timer, after a certificate is saved, by the Refresh
// status button, and before the inspect page renders when stale.

const (
	customCertificateProbeEvery   = 30 * time.Minute
	customCertificateProbeTimeout = 5 * time.Second
	customCertificateProbeWorkers = 4
	certificateProbeSettingPrefix = "certificate_probe_"
	// A stored result older than this is refreshed before the inspect page
	// renders, so Inspect always shows something recent.
	certificateProbeStaleAfter = 5 * time.Minute
)

// liveCertificateInfo is what one TLS handshake with a Caddy node revealed
// about the certificate it serves for a custom certificate's domain.
type liveCertificateInfo struct {
	CertificateID int64      `json:"certificate_id"`
	ServerID      int64      `json:"server_id"`
	ServerName    string     `json:"server_name,omitempty"`
	ProbeName     string     `json:"probe_name"`       // SNI sent
	Target        string     `json:"target,omitempty"` // host:port dialled
	Status        string     `json:"status"`           // healthy, expiring, expired, mismatch, unavailable
	Subject       string     `json:"subject,omitempty"`
	Issuer        string     `json:"issuer,omitempty"`
	IssuerCN      string     `json:"issuer_cn,omitempty"`
	SANs          []string   `json:"sans,omitempty"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	SerialNumber  string     `json:"serial,omitempty"`
	Fingerprint   string     `json:"fingerprint,omitempty"`
	KeyType       string     `json:"key_type,omitempty"`
	KeyBits       int        `json:"key_bits,omitempty"`
	Error         string     `json:"error,omitempty"`
	CheckedAt     time.Time  `json:"checked_at"`
}

// DaysLeft is days until the served certificate expires; negative once it
// has. Zero when nothing was served.
func (i *liveCertificateInfo) DaysLeft() int {
	if i == nil || i.NotAfter == nil {
		return 0
	}
	return int(time.Until(*i.NotAfter).Hours() / 24)
}

// HasCertificate reports whether the probe saw a certificate that covers the
// probed name — whatever its dates. A mismatch means Caddy answered with a
// certificate for some other name, so its details are not this certificate's.
func (i *liveCertificateInfo) HasCertificate() bool {
	if i == nil || i.NotAfter == nil {
		return false
	}
	return i.Status == "healthy" || i.Status == "expiring" || i.Status == "expired"
}

// Stale is true for a nil or old result; nil-safe so callers can test a
// lookup miss and an aged entry with one condition.
func (i *liveCertificateInfo) Stale() bool {
	return i == nil || time.Since(i.CheckedAt) > certificateProbeStaleAfter
}

// x509Summary carries the fields the inspect page and the probe both show.
type x509Summary struct {
	Subject      string
	Issuer       string
	IssuerCN     string
	SANs         []string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyType      string
	KeyBits      int
	SerialNumber string
	Fingerprint  string // SHA-256 over the DER bytes, colon-separated hex
}

func summarizeX509(c *x509.Certificate) x509Summary {
	out := x509Summary{
		Subject:      c.Subject.String(),
		Issuer:       c.Issuer.String(),
		IssuerCN:     c.Issuer.CommonName,
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		SerialNumber: c.SerialNumber.Text(16),
		KeyType:      "Unknown",
	}
	out.SANs = append(out.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out.SANs = append(out.SANs, ip.String())
	}
	for _, uri := range c.URIs {
		out.SANs = append(out.SANs, uri.String())
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		out.KeyType, out.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		out.KeyType, out.KeyBits = "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		out.KeyType = "Ed25519"
	}
	fp := sha256.Sum256(c.Raw)
	parts := make([]string, len(fp))
	for i, b := range fp {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	out.Fingerprint = strings.Join(parts, ":")
	return out
}

// parsePEMLeaf decodes the first CERTIFICATE block in pemData, or nil.
func parsePEMLeaf(pemData string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

func isCustomCertificate(c models.Certificate) bool {
	return c.Source == models.CertSourcePEM || c.Source == models.CertSourcePath
}

// customCertificatePEM returns the certificate PEM CaddyUI can read locally:
// the stored PEM, or the file at CertPath when that path is readable from
// this container. The error says why a path could not be read; managed
// certificates have nothing to read and return "", nil.
func customCertificatePEM(cert models.Certificate) (string, error) {
	switch cert.Source {
	case models.CertSourcePEM:
		return cert.CertPEM, nil
	case models.CertSourcePath:
		if strings.TrimSpace(cert.CertPath) == "" {
			return "", fmt.Errorf("no certificate path configured")
		}
		raw, err := os.ReadFile(cert.CertPath)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	return "", nil
}

// dialLeafCertificate opens a TLS connection to target with serverName as
// SNI and returns the leaf certificate presented. Nothing is verified here:
// callers judge the name and the dates themselves, so an expired or
// mismatched certificate is reported rather than hidden behind a handshake
// error. The timeout covers the TCP connect and the handshake together.
func dialLeafCertificate(target, serverName string, timeout time.Duration) (*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // nolint:gosec // diagnostic probe; name and expiry are judged by the caller
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, fmt.Errorf("server returned no peer certificate")
	}
	return peers[0], nil
}

// certificateProbeTarget is the host:port a probe for serverID dials: the
// node's admin host on 443, or the probed name itself when the admin URL
// gives no usable host. Tests override it through certProbeTargetFn.
func (s *Server) certificateProbeTarget(serverID int64, probeName string) string {
	if s.certProbeTargetFn != nil {
		return s.certProbeTargetFn(serverID, probeName)
	}
	host := s.caddyDialHost(serverID)
	if host == "" {
		host = probeName
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), "443")
}

// probeCustomCertificate asks the node that owns cert what it serves for the
// certificate's first domain (a synthetic child name for wildcard-only
// definitions, as managedCertificateProbeName does) and classifies it.
func (s *Server) probeCustomCertificate(serverID int64, cert models.Certificate) liveCertificateInfo {
	info := liveCertificateInfo{
		CertificateID: cert.ID,
		ServerID:      serverID,
		ProbeName:     managedCertificateProbeName(cert),
		Status:        "unavailable",
		CheckedAt:     time.Now().UTC(),
	}
	if srv, err := models.GetCaddyServer(s.DB, serverID); err == nil && srv != nil {
		info.ServerName = srv.Name
	}
	if info.ProbeName == "" {
		info.Error = "no domain configured to probe"
		return info
	}
	info.Target = s.certificateProbeTarget(serverID, info.ProbeName)
	leaf, err := dialLeafCertificate(info.Target, info.ProbeName, customCertificateProbeTimeout)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	sum := summarizeX509(leaf)
	notBefore, notAfter := sum.NotBefore.UTC(), sum.NotAfter.UTC()
	info.Subject, info.Issuer, info.IssuerCN, info.SANs = sum.Subject, sum.Issuer, sum.IssuerCN, sum.SANs
	info.NotBefore, info.NotAfter = &notBefore, &notAfter
	info.SerialNumber, info.Fingerprint = sum.SerialNumber, sum.Fingerprint
	info.KeyType, info.KeyBits = sum.KeyType, sum.KeyBits
	if err := leaf.VerifyHostname(info.ProbeName); err != nil {
		info.Status = "mismatch"
		served := strings.Join(sum.SANs, ", ")
		if served == "" {
			served = sum.Subject
		}
		info.Error = fmt.Sprintf("Caddy served a certificate for %s, not for %s", served, info.ProbeName)
		return info
	}
	switch d := info.DaysLeft(); {
	case d < 0:
		info.Status = "expired"
	case d < 30:
		info.Status = "expiring"
	default:
		info.Status = "healthy"
	}
	return info
}

func certificateProbeKey(certID int64) string {
	return certificateProbeSettingPrefix + strconv.FormatInt(certID, 10)
}

func (s *Server) storeCertificateProbe(info liveCertificateInfo) error {
	raw, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return models.SetSetting(s.DB, certificateProbeKey(info.CertificateID), string(raw))
}

// certificateProbeFor returns the stored result for a certificate, or nil.
func (s *Server) certificateProbeFor(certID int64) *liveCertificateInfo {
	raw, err := models.GetSetting(s.DB, certificateProbeKey(certID))
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var info liveCertificateInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return nil
	}
	return &info
}

func (s *Server) deleteCertificateProbe(certID int64) {
	_ = models.DeleteSetting(s.DB, certificateProbeKey(certID))
}

// refreshCertificateProbes probes every custom certificate on serverID
// (0 = every managed server) and stores the results. Runs are serialized so
// a manual refresh during the scheduled pass does not double the dials.
// Returns how many certificates were probed.
func (s *Server) refreshCertificateProbes(serverID int64) (int, error) {
	s.certProbeRunMu.Lock()
	defer s.certProbeRunMu.Unlock()

	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		return 0, err
	}
	type job struct {
		serverID int64
		cert     models.Certificate
	}
	var jobs []job
	for _, srv := range servers {
		if srv.Type != models.CaddyServerTypeManaged || (serverID != 0 && srv.ID != serverID) {
			continue
		}
		certs, err := models.ListCertificates(s.DB, srv.ID)
		if err != nil {
			return 0, fmt.Errorf("%s: list certificates: %w", srv.Name, err)
		}
		for _, c := range certs {
			if isCustomCertificate(c) {
				jobs = append(jobs, job{serverID: srv.ID, cert: c})
			}
		}
	}
	if len(jobs) == 0 {
		return 0, nil
	}
	sem := make(chan struct{}, customCertificateProbeWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := s.storeCertificateProbe(s.probeCustomCertificate(j.serverID, j.cert)); err != nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("%s: %v", j.cert.Name, err))
				mu.Unlock()
			}
		}(j)
	}
	wg.Wait()
	if len(failures) > 0 {
		return len(jobs), fmt.Errorf("store probe results: %s", strings.Join(failures, "; "))
	}
	return len(jobs), nil
}

// probeCertificateSoon re-probes one custom certificate shortly after it was
// saved and synced, so the new row shows live data without waiting for the
// next scheduled pass. Managed certificates are covered by the lifecycle
// reconciler instead.
func (s *Server) probeCertificateSoon(serverID int64, cert models.Certificate) {
	if !isCustomCertificate(cert) || cert.ID == 0 {
		return
	}
	go func() {
		time.Sleep(3 * time.Second)
		_ = s.storeCertificateProbe(s.probeCustomCertificate(serverID, cert))
	}()
}

// StartCustomCertificateProbes runs the first pass shortly after start-up
// (Caddy is usually starting at the same moment) and then every
// customCertificateProbeEvery, until ctx is cancelled.
func (s *Server) StartCustomCertificateProbes(ctx context.Context) {
	go func() {
		run := func() {
			n, err := s.refreshCertificateProbes(0)
			if err != nil {
				log.Printf("certificate probes: %v", err)
			} else if n > 0 {
				log.Printf("certificate probes: checked %d custom certificate(s) over TLS", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
		run()
		ticker := time.NewTicker(customCertificateProbeEvery)
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

// probeCertificatesHandler: POST /certificates/probe — the Refresh status
// button. Re-probes every custom certificate on the selected server, then
// returns to the list. Read-only towards Caddy, so every role may use it.
func (s *Server) probeCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := s.refreshCertificateProbes(s.currentServerID(r)); err != nil {
		log.Printf("certificate probes: manual refresh: %v", err)
	}
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

// probeCertificateHandler: POST /certificates/{id}/probe — the Probe now
// button on the inspect page.
func (s *Server) probeCertificateHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	cert, err := s.visibleCertificate(r, id)
	if err != nil || cert == nil {
		http.NotFound(w, r)
		return
	}
	if isCustomCertificate(*cert) {
		serverID, _ := models.CertificateServerID(s.DB, id)
		_ = s.storeCertificateProbe(s.probeCustomCertificate(serverID, *cert))
	}
	http.Redirect(w, r, fmt.Sprintf("/certificates/%d/inspect", id), http.StatusSeeOther)
}

// visibleCertificate returns the certificate when the current user may see
// it (the same scope the list page uses), or nil.
func (s *Server) visibleCertificate(r *http.Request, id int64) (*models.Certificate, error) {
	visible, err := s.certListForRequest(r)
	if err != nil {
		return nil, err
	}
	for i := range visible {
		if visible[i].ID == id {
			return &visible[i], nil
		}
	}
	return nil, nil
}

// customCertificateExpiries returns the best-known expiry of each custom
// certificate: from the stored PEM or the readable file, else from the last
// live probe. Feeds the dashboard's expiry recommendations, which used to
// see only stored PEMs.
func (s *Server) customCertificateExpiries(certs []models.Certificate) map[int64]time.Time {
	out := map[int64]time.Time{}
	for _, c := range certs {
		if !isCustomCertificate(c) {
			continue
		}
		if pemData, err := customCertificatePEM(c); err == nil {
			if leaf := parsePEMLeaf(pemData); leaf != nil {
				out[c.ID] = leaf.NotAfter
				continue
			}
		}
		if p := s.certificateProbeFor(c.ID); p.HasCertificate() {
			out[c.ID] = *p.NotAfter
		}
	}
	return out
}
