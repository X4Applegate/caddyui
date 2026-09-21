// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// --- Upstream health notifier ---

// upstreamAlertEntry records a single upstream state-change notification.
type upstreamAlertEntry struct {
	ServerName string    `json:"server"`
	Upstream   string    `json:"upstream"`
	Event      string    `json:"event"` // "down" or "recovered"
	AlertedAt  time.Time `json:"alerted_at"`
}

// upstreamNotifyState tracks upstream health across check intervals so we can
// detect transitions (healthy→down and down→recovered) and avoid duplicate alerts.
var upstreamNotifyState struct {
	mu        sync.Mutex
	prevFails map[string]bool // key "serverID:address" → was failing on last check?
	lastCheck time.Time
	recent    []upstreamAlertEntry
}

// runHealthChecker polls each enabled proxy host every 5 minutes and records
// the result in proxy_health — the persisted "Public" health history behind
// /proxy-hosts/{id}/health and the left-most dot on the proxy hosts list. It
// checks the first domain of each host via HTTPS (falling back to HTTP if
// ssl_enabled is false). Runs until the process exits.
//
// v2.35.0 (issue #39 follow-up): this is a *third* probe CaddyUI runs on a
// host's behalf, alongside the App and Port dots that v2.28.0 made
// configurable. It was never wired to MonitorMode, so a host set to "Off" —
// explicitly promised to stop "all outbound probes for this host" — kept
// getting hit here every 5 minutes regardless, and a host in "Custom" mode
// with a non-default path or expected status still showed this dot red
// because the check always requested "/" and only accepted <400/401/403.
// That's the exact failure mode the issue described. Now it honors the same
// MonitorSettings as the other two probes.
//
// NodeLocal is deliberately NOT consulted here. It says the *upstream*
// (forward_host/port) only resolves on this node — it says nothing about
// whether the host's public domain should be checked from the internet-facing
// side, which is what this probe does. Only an explicit MonitorMode of "off"
// suppresses it.
func (s *Server) runHealthChecker() {
	// Stagger the first check by 30 seconds so startup load doesn't spike.
	time.Sleep(30 * time.Second)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	s.checkAllProxyHosts()
	for range ticker.C {
		s.checkAllProxyHosts()
	}
}

// publicHealthCheckerInterval is this poller's native cadence, and therefore
// the "Automatic" default fed to MonitorSettings — distinct from the App
// dot's 60s default, since this checker has always run every 5 minutes.
//
// publicHealthCheckerTimeout matches the client this poller has always used
// (short timeout, no redirect following) — the historical "Automatic"
// default for MonitorSettings, same as the interval above.
const (
	publicHealthCheckerInterval = 5 * time.Minute
	publicHealthCheckerTimeout  = 10 * time.Second
)

func (s *Server) checkAllProxyHosts() {
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		log.Printf("health checker: list servers: %v", err)
		return
	}
	for _, srv := range servers {
		hosts, err := models.ListProxyHosts(s.DB, srv.ID, 0, true, nil)
		if err != nil {
			log.Printf("health checker: list hosts for server %d: %v", srv.ID, err)
			continue
		}
		for _, h := range hosts {
			if !h.Enabled {
				continue
			}
			// v2.35.0: "Off" means no outbound probe of any kind — see the
			// package comment on runHealthChecker.
			if h.MonitoringDisabled() {
				continue
			}
			domains := h.DomainList()
			if len(domains) == 0 {
				continue
			}
			domain := domains[0]
			scheme := "https"
			if !h.SSLEnabled {
				scheme = "http"
			}
			path, method, expectStatus, interval, timeout := h.MonitorSettings(publicHealthCheckerInterval, publicHealthCheckerTimeout)
			if !s.publicHealthDue(h.ID, interval) {
				continue
			}
			targetURL := scheme + "://" + domain + path
			s.checkProxyHost(h.ID, targetURL, method, expectStatus, timeout)
		}
	}
}

// publicHealthCadenceLabel describes the effective cadence of the Public
// health checker for the /proxy-hosts/{id}/health page, since it's no longer
// unconditionally "every 5 min" once Custom mode can set a longer interval.
func publicHealthCadenceLabel(h models.ProxyHost) string {
	if !strings.EqualFold(strings.TrimSpace(h.MonitorMode), "custom") || h.MonitorIntervalSec <= 0 {
		return "every 5 min"
	}
	interval := time.Duration(h.MonitorIntervalSec) * time.Second
	if interval <= publicHealthCheckerInterval {
		return "every 5 min" // custom value floors to the native tick anyway
	}
	minutes := int(interval / time.Minute)
	return fmt.Sprintf("roughly every %d min (custom)", minutes)
}

// publicHealthDue reports whether hostID's persisted public health check is
// due for a new probe, honoring a custom interval longer than the poller's
// native 5-minute tick (a shorter one can't be honoured — the ticker itself
// only fires every 5 minutes). Paced off the most recently persisted check
// rather than separate in-memory state, so — unlike the App dot's pacing —
// this survives a process restart instead of probing immediately on boot
// regardless of how recently it last ran.
func (s *Server) publicHealthDue(hostID int64, interval time.Duration) bool {
	if interval <= publicHealthCheckerInterval {
		return true
	}
	history, err := models.GetProxyHealthHistory(s.DB, hostID, 1)
	if err != nil || len(history) == 0 {
		return true
	}
	// Subtract half a tick so a host configured at exactly 2x the interval
	// isn't pushed out to 3x by scheduling jitter, matching appProbeDue.
	return time.Since(history[0].CheckedAt) >= interval-(publicHealthCheckerInterval/2)
}

func (s *Server) checkProxyHost(hostID int64, targetURL, method string, expectStatus int, timeout time.Duration) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // check reachability, not cert validity
		},
	}
	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		_ = models.InsertProxyHealth(s.DB, hostID, false, 0, 0, err.Error())
		return
	}
	start := time.Now()
	resp, err := client.Do(req)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		errMsg := err.Error()
		if len(errMsg) > 200 {
			errMsg = errMsg[:200]
		}
		_ = models.InsertProxyHealth(s.DB, hostID, false, 0, latencyMs, errMsg)
		return
	}
	defer resp.Body.Close()
	// Drain body to free connection.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	// v2.35.0: an explicit expected status replaces the heuristic entirely —
	// same rule as the App dot probe, and for the same reason: a host whose
	// health path deliberately answers something other than 2xx/401/403 is
	// "up" only if the operator said so.
	var ok bool
	if expectStatus > 0 {
		ok = resp.StatusCode == expectStatus
	} else {
		ok = resp.StatusCode < 400 || resp.StatusCode == 401 || resp.StatusCode == 403
	}
	_ = models.InsertProxyHealth(s.DB, hostID, ok, resp.StatusCode, latencyMs, "")
}

// StartUpstreamNotifier launches a goroutine that checks upstream health every 5 minutes.
func StartUpstreamNotifier(db *sql.DB) {
	upstreamNotifyState.prevFails = map[string]bool{}
	go func() {
		time.Sleep(20 * time.Second) // let the DB settle first
		for {
			runUpstreamCheck(db)
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runUpstreamCheck(db *sql.DB) {
	// Skip entirely if neither SMTP nor webhook is configured.
	webhookURL, _ := models.GetSetting(db, settingNotifyWebhookURL)
	smtpHost, _ := models.GetSetting(db, settingSMTPHost)
	smtpTo, _ := models.GetSetting(db, settingSMTPTo)
	emailOK := smtpHost != "" && smtpTo != ""
	if webhookURL == "" && !emailOK {
		return
	}

	servers, err := models.ListCaddyServers(db)
	if err != nil {
		log.Printf("upstream-notifier: list servers: %v", err)
		return
	}

	upstreamNotifyState.mu.Lock()
	upstreamNotifyState.lastCheck = time.Now()
	// Prune recent alerts older than 7 days.
	fresh := upstreamNotifyState.recent[:0]
	for _, e := range upstreamNotifyState.recent {
		if time.Since(e.AlertedAt) < 7*24*time.Hour {
			fresh = append(fresh, e)
		}
	}
	upstreamNotifyState.recent = fresh
	upstreamNotifyState.mu.Unlock()

	for _, srv := range servers {
		upstreams := fetchCaddyUpstreams(srv.AdminURL)
		for addr, info := range upstreams {
			key := fmt.Sprintf("%d:%s", srv.ID, addr)
			nowFailing := info.Fails > 0

			upstreamNotifyState.mu.Lock()
			wasFailing := upstreamNotifyState.prevFails[key]
			upstreamNotifyState.prevFails[key] = nowFailing
			upstreamNotifyState.mu.Unlock()

			if nowFailing == wasFailing {
				continue // no state change
			}

			event := "recovered"
			if nowFailing {
				event = "down"
			}

			subject := fmt.Sprintf("[CaddyUI] Upstream %s %s on %s", addr, event, srv.Name)
			body := fmt.Sprintf(
				"CaddyUI upstream health alert\n\nServer : %s (%s)\nUpstream: %s\nEvent   : %s\nTime    : %s\n",
				srv.Name, srv.AdminURL, addr, event, time.Now().UTC().Format(time.RFC3339),
			)

			// v2.12.51: sendNotification fans out to webhook + ntfy + future
			// channels. Includes a "message" field so ntfy gets readable text.
			payload, _ := json.Marshal(map[string]any{
				"event":    "upstream_" + event,
				"message":  fmt.Sprintf("%s upstream %s on server %s", event, addr, srv.Name),
				"server":   srv.Name,
				"upstream": addr,
			})
			sendNotification(db, payload)
			// Send email.
			if emailOK {
				if err := sendEmail(db, subject, body); err != nil {
					log.Printf("upstream-notifier: send email: %v", err)
				}
			}

			upstreamNotifyState.mu.Lock()
			upstreamNotifyState.recent = append(upstreamNotifyState.recent, upstreamAlertEntry{
				ServerName: srv.Name,
				Upstream:   addr,
				Event:      event,
				AlertedAt:  time.Now(),
			})
			upstreamNotifyState.mu.Unlock()
			log.Printf("upstream-notifier: %s upstream %q on %q", event, addr, srv.Name)
		}
	}
}

// notifierState holds in-memory tracking for the cert-expiry notifier goroutine.
var notifierState struct {
	mu           sync.Mutex
	lastCheck    time.Time
	lastNotified []notifiedEntry
}

type notifiedEntry struct {
	Domain     string    `json:"domain"`
	DaysLeft   int       `json:"days_left"`
	NotifiedAt time.Time `json:"notified_at"`
}

// StartNotifier launches background goroutines:
//   - cert-expiry check every 24 h (webhook + email)
//   - upstream health check every 5 min (webhook + email)
func StartNotifier(db *sql.DB, _ *caddy.Client) {
	go func() {
		time.Sleep(10 * time.Second) // wait for DB to be ready
		for {
			runNotifierCheck(db)
			time.Sleep(24 * time.Hour)
		}
	}()
	StartUpstreamNotifier(db)
}

func runNotifierCheck(db *sql.DB) {
	notifierState.mu.Lock()
	notifierState.lastCheck = time.Now()
	notifierState.mu.Unlock()

	webhookURL, _ := models.GetSetting(db, settingNotifyWebhookURL)
	smtpHost, _ := models.GetSetting(db, settingSMTPHost)
	smtpTo, _ := models.GetSetting(db, settingSMTPTo)
	emailOK := smtpHost != "" && smtpTo != ""

	if webhookURL == "" && !emailOK {
		return // nothing configured
	}

	daysBeforeStr, _ := models.GetSetting(db, settingNotifyDaysBefore)
	daysBefore := defaultNotifyDaysBefore
	if d, err := strconv.Atoi(daysBeforeStr); err == nil && d > 0 {
		daysBefore = d
	}

	// Collect custom certs from all servers.
	servers, _ := models.ListCaddyServers(db)
	var certs []models.Certificate
	for _, srv := range servers {
		sc, err := models.ListCertificates(db, srv.ID)
		if err == nil {
			certs = append(certs, sc...)
		}
	}
	if len(servers) == 0 {
		// Fallback: server_id=1 if no servers table yet.
		certs, _ = models.ListCertificates(db, 1)
	}

	notifierState.mu.Lock()
	defer notifierState.mu.Unlock()

	// Prune stale notified entries (older than 24h) so we re-notify if still expiring.
	fresh := notifierState.lastNotified[:0]
	for _, e := range notifierState.lastNotified {
		if time.Since(e.NotifiedAt) < 24*time.Hour {
			fresh = append(fresh, e)
		}
	}
	notifierState.lastNotified = fresh

	alreadyNotified := map[string]struct{}{}
	for _, e := range notifierState.lastNotified {
		alreadyNotified[e.Domain] = struct{}{}
	}

	now := time.Now()
	threshold := time.Duration(daysBefore) * 24 * time.Hour

	for _, c := range certs {
		t := parsePEMExpiry(c.CertPEM)
		if t == nil || !t.After(now) {
			continue
		}
		remaining := t.Sub(now)
		if remaining > threshold {
			continue
		}
		domain := c.Name
		if _, seen := alreadyNotified[domain]; seen {
			continue
		}
		daysLeft := int(remaining.Hours() / 24)

		sent := false

		// v2.12.51: webhook + ntfy + future channels via sendNotification.
		// `sent` is still set so the email branch knows whether anything
		// went out (it tracks whether a dedup entry should be written).
		hasChannel := webhookURL != ""
		if u, _ := models.GetSetting(db, settingNotifyNtfyURL); u != "" {
			hasChannel = true
		}
		if hasChannel {
			payload, _ := json.Marshal(map[string]any{
				"event":     "cert_expiring",
				"message":   fmt.Sprintf("Certificate %s expires in %d days", domain, daysLeft),
				"domain":    domain,
				"days_left": daysLeft,
			})
			sendNotification(db, payload)
			sent = true
		}

		// Email notification.
		if emailOK {
			subject := fmt.Sprintf("[CaddyUI] Certificate expiring: %s (%d days left)", domain, daysLeft)
			body := fmt.Sprintf(
				"CaddyUI certificate expiry alert\n\nDomain  : %s\nDays left: %d\nExpires  : %s\n\nGo to /certificates to renew or replace it.\n",
				domain, daysLeft, t.UTC().Format("2006-01-02"),
			)
			if err := sendEmail(db, subject, body); err != nil {
				log.Printf("notifier: send email for %q: %v", domain, err)
			} else {
				sent = true
			}
		}

		if sent {
			notifierState.lastNotified = append(notifierState.lastNotified, notifiedEntry{
				Domain:     domain,
				DaysLeft:   daysLeft,
				NotifiedAt: now,
			})
			log.Printf("notifier: sent cert-expiry notification for %q (%d days left)", domain, daysLeft)
		}
	}

	// v2.11.14: also alert on Let's Encrypt / ACME-managed certs by doing a
	// live TLS dial against each enabled, SSL-enabled proxy host's first
	// domain. Caddy stores ACME-issued certs in its own data dir (which
	// CaddyUI can't read without sharing the volume), so dialing the
	// public endpoint and reading the peer certificate is the most
	// reliable way to surface expiry across LE / ZeroSSL / custom alike.
	runProxyHostCertExpiryCheck(db, webhookURL, emailOK, daysBefore, alreadyNotified, now)
}

// runProxyHostCertExpiryCheck — v2.11.14: extension of runNotifierCheck that
// covers Caddy-managed (ACME / LE) certificates. For each enabled proxy host
// with SSLEnabled=true, dials the first domain at :443, reads the leaf cert,
// and fires the same webhook + email channels when expiry is within
// daysBefore. Dedup keys are prefixed "proxy:" so they don't collide with
// the custom-cert dedup keys used above.
func runProxyHostCertExpiryCheck(db *sql.DB, webhookURL string, emailOK bool, daysBefore int, alreadyNotified map[string]struct{}, now time.Time) {
	threshold := time.Duration(daysBefore) * 24 * time.Hour
	servers, _ := models.ListCaddyServers(db)
	if len(servers) == 0 {
		// Fallback for fresh installs that haven't seeded servers yet.
		servers = []models.CaddyServer{{ID: 1}}
	}
	for _, srv := range servers {
		hosts, err := models.ListProxyHosts(db, srv.ID, 0, true, nil)
		if err != nil {
			continue
		}
		for _, h := range hosts {
			if !h.Enabled || !h.SSLEnabled {
				continue
			}
			first := strings.TrimSpace(strings.SplitN(h.Domains, ",", 2)[0])
			if first == "" || strings.HasPrefix(first, "*.") {
				// Skip wildcards — can't dial a wildcard hostname directly.
				continue
			}
			key := "proxy:" + first
			if _, seen := alreadyNotified[key]; seen {
				continue
			}
			d := &net.Dialer{Timeout: 8 * time.Second}
			conn, err := tls.DialWithDialer(d, "tcp", first+":443", &tls.Config{
				ServerName: first,
				// We need the peer cert chain, not auth — system roots are
				// fine. If verification fails we still get the chain back
				// via PeerCertificates so we can read expiry; but we keep
				// strict verify on first to surface expired/invalid certs.
			})
			if err != nil {
				continue
			}
			peers := conn.ConnectionState().PeerCertificates
			conn.Close()
			if len(peers) == 0 {
				continue
			}
			leaf := peers[0]
			if !leaf.NotAfter.After(now) {
				continue
			}
			remaining := leaf.NotAfter.Sub(now)
			if remaining > threshold {
				continue
			}
			daysLeft := int(remaining.Hours() / 24)

			sent := false
			hasChannel := webhookURL != ""
			if u, _ := models.GetSetting(db, settingNotifyNtfyURL); u != "" {
				hasChannel = true
			}
			if hasChannel {
				payload, _ := json.Marshal(map[string]any{
					"event":     "proxy_cert_expiring",
					"message":   fmt.Sprintf("Live cert for %s expires in %d days (issuer: %s)", first, daysLeft, leaf.Issuer.CommonName),
					"domain":    first,
					"days_left": daysLeft,
					"issuer":    leaf.Issuer.CommonName,
				})
				sendNotification(db, payload)
				sent = true
			}
			if emailOK {
				subject := fmt.Sprintf("[CaddyUI] Live cert expiring: %s (%d days left)", first, daysLeft)
				body := fmt.Sprintf(
					"CaddyUI live-cert expiry alert\n\nDomain  : %s\nDays left: %d\nExpires  : %s\nIssuer  : %s\n\nThis is the certificate Caddy is currently serving for the host. Check /certificates and the host's TLS settings if a renewal hasn't fired.\n",
					first, daysLeft, leaf.NotAfter.UTC().Format("2006-01-02"), leaf.Issuer.CommonName,
				)
				if err := sendEmail(db, subject, body); err != nil {
					log.Printf("notifier: send email for live cert %q: %v", first, err)
				} else {
					sent = true
				}
			}
			if sent {
				notifierState.lastNotified = append(notifierState.lastNotified, notifiedEntry{
					Domain:     key,
					DaysLeft:   daysLeft,
					NotifiedAt: now,
				})
				log.Printf("notifier: sent live-cert-expiry notification for %q (%d days left, issuer %q)", first, daysLeft, leaf.Issuer.CommonName)
			}
		}
	}
}

// sendNotification — v2.12.51: fan-out wrapper that dispatches a single
// notification event to every channel the user has configured. Replaces
// the bare `if whURL := models.GetSetting...; sendWebhookPayload(...)`
// pattern that was duplicated at every call site, and adds ntfy.sh
// alongside the existing generic-webhook path.
//
// The payload is the same canonical JSON every call site already builds:
//
//	{"event": "...", "message": "...", ...event-specific fields}
//
// For ntfy, "event" becomes the title and "message" becomes the body.
// For the generic webhook, the full JSON is POSTed verbatim (back-compat
// with anything users have wired up to it). Future channels (Telegram,
// Discord, Gotify) get added here.
//
// Each channel runs in its own goroutine so a slow / hung remote can't
// block the request handler — same fire-and-forget shape the old
// per-site `go func() { sendWebhookPayload(...) }()` pattern used.
func sendNotification(db *sql.DB, payload []byte) {
	// Extract title + body from the canonical payload shape for the
	// channels that need plain text (ntfy / future Telegram / Discord).
	var meta struct {
		Event   string `json:"event"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(payload, &meta)
	title := meta.Event
	if title == "" {
		title = "CaddyUI alert"
	}
	body := meta.Message
	if body == "" {
		// Fall back to the raw JSON if no message field — better than empty.
		body = string(payload)
	}

	if whURL, _ := models.GetSetting(db, settingNotifyWebhookURL); whURL != "" {
		go sendWebhookPayload(db, whURL, payload)
	}
	if ntfyURL, _ := models.GetSetting(db, settingNotifyNtfyURL); ntfyURL != "" {
		go sendNtfyMessage(db, ntfyURL, title, body)
	}
}

// sendNtfyMessage POSTs a notification to an ntfy.sh-compatible endpoint.
// Body goes as plain text; X-Title carries the event name. If a bearer
// token is configured (for self-hosted ntfy with auth, or ntfy.sh paid
// reserved topics), it's sent as Authorization: Bearer.
//
// ntfy.sh API: https://docs.ntfy.sh/publish/
func sendNtfyMessage(db *sql.DB, ntfyURL, title, body string) {
	req, err := http.NewRequest(http.MethodPost, ntfyURL, strings.NewReader(body))
	if err != nil {
		log.Printf("sendNtfy: create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if title != "" {
		req.Header.Set("X-Title", title)
	}
	// Tag CaddyUI events with a recognisable icon — ntfy renders X-Tags as
	// emoji shortcodes (https://docs.ntfy.sh/publish/#tags-emojis).
	req.Header.Set("X-Tags", "shield")
	if token, _ := models.GetSetting(db, settingNotifyNtfyToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("sendNtfy: POST %s: %v", ntfyURL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("sendNtfy: %s returned %d: %s", ntfyURL, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
}

// sendWebhookPayload POSTs a JSON payload to webhookURL. If a secret is configured
// in the DB (settingNotifyWebhookSecret), it adds an X-Signature-256 header
// containing the HMAC-SHA256 of the payload body in hex, prefixed "sha256=".
// The format is compatible with GitHub's webhook delivery signature.
func sendWebhookPayload(db *sql.DB, webhookURL string, payload []byte) {
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("sendWebhook: create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret, _ := models.GetSetting(db, settingNotifyWebhookSecret); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		req.Header.Set("X-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("sendWebhook: POST %s: %v", webhookURL, err)
		return
	}
	_ = resp.Body.Close()
}

func (s *Server) apiNotifierStatus(w http.ResponseWriter, r *http.Request) {
	webhookURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL)
	notifierState.mu.Lock()
	certLastCheck := notifierState.lastCheck
	certNotified := notifierState.lastNotified
	notifierState.mu.Unlock()

	upstreamNotifyState.mu.Lock()
	upLastCheck := upstreamNotifyState.lastCheck
	upRecent := upstreamNotifyState.recent
	upstreamNotifyState.mu.Unlock()

	status := map[string]any{
		"webhook_url":     webhookURL,
		"last_check":      certLastCheck,
		"last_notified":   certNotified,
		"upstream_check":  upLastCheck,
		"upstream_alerts": upRecent,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) apiSystemStats(w http.ResponseWriter, r *http.Request) {
	// Admin-only. The dashboard template hides these cards for user/viewer
	// roles (see dashboard.html "System stats" block), but the endpoint is
	// still reachable via direct URL — so gate it here too. Host-level data
	// (uptime, RAM, load avg, Caddy-wide upstream totals) reflects the box
	// and Caddy as a whole, not anything a regular user owns, so exposing
	// it to non-admin roles leaks infrastructure details unnecessarily.
	cu := s.currentUser(r)
	if cu == nil || cu.Role != models.RoleAdmin {
		http.Error(w, "admin access required", http.StatusForbidden)
		return
	}

	stats := map[string]any{}

	// The first four values intentionally describe the machine/container that
	// runs CaddyUI. A remote Caddy admin API does not expose host load, total
	// memory, or host uptime. The response names both scopes so the Operations
	// page can distinguish these values from the selected-node Caddy telemetry.
	stats["host_scope"] = "caddyui"

	// Uptime from /proc/uptime (always the CaddyUI host machine).
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				d := time.Duration(secs) * time.Second
				days := int(d.Hours()) / 24
				hours := int(d.Hours()) % 24
				mins := int(d.Minutes()) % 60
				stats["uptime"] = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
			}
		}
	}

	// CPU load from /proc/loadavg.
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			stats["load1"] = fields[0]
			stats["load5"] = fields[1]
			stats["load15"] = fields[2]
		}
	}

	// Memory from /proc/meminfo.
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		memInfo := map[string]uint64{}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
					memInfo[key] = val
				}
			}
		}
		total := memInfo["MemTotal"]
		avail := memInfo["MemAvailable"]
		if total > 0 {
			used := total - avail
			stats["mem_total_mb"] = total / 1024
			stats["mem_used_mb"] = used / 1024
			stats["mem_pct"] = int(float64(used) / float64(total) * 100)
		}
	}

	// Per-server Caddy stats: active upstream requests + healthy upstream count.
	// The active-server cookie is authoritative, matching every other dashboard
	// value and preventing a stale or hand-edited query parameter from mixing
	// scopes inside one Operations page.
	sid := s.currentServerID(r)
	if srv, err := models.GetCaddyServer(s.DB, sid); err == nil {
		stats["selected_server_id"] = srv.ID
		stats["selected_server_name"] = srv.Name
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		upstreams, upstreamErr := caddy.New(srv.AdminURL, srv.AdminUsername, srv.AdminPassword).GetUpstreamHealth(ctx)
		cancel()
		if upstreamErr != nil {
			stats["caddy_error"] = upstreamErr.Error()
		}
		activeReqs := 0
		healthy := 0
		for _, u := range upstreams {
			activeReqs += u.NumRequests
			if u.Healthy {
				healthy++
			}
		}
		if upstreamErr == nil {
			stats["active_requests"] = activeReqs
			stats["healthy_upstreams"] = healthy
			stats["total_upstreams"] = len(upstreams)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// apiDashboardSparklines returns 7 days of daily totals for the dashboard
// stat card sparklines: views, visitors, bandwidth per day. Scoped to the
// active server's hostnames (same logic as dashboard handler). Returns JSON:
//
//	{ "days": [ { "date": "2026-05-25", "views": N, "visitors": N, "bandwidth": N }, … ] }
//
// v2.15.0
func (s *Server) apiDashboardSparklines(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sid := s.currentServerID(r)
	isAdmin := cu.Role == models.RoleAdmin
	peers := s.groupPeerIDs(r)

	hosts, _ := models.ListProxyHosts(s.DB, sid, cu.ID, isAdmin, peers)
	redirs, _ := models.ListRedirectionHosts(s.DB, sid, cu.ID, isAdmin, peers)
	raws, _ := models.ListRawRoutes(s.DB, sid, cu.ID, isAdmin, peers)

	var hostsForActive []string
	for _, h := range hosts {
		hostsForActive = append(hostsForActive, h.DomainList()...)
	}
	for _, rh := range redirs {
		hostsForActive = append(hostsForActive, rh.DomainList()...)
	}
	for _, rr := range raws {
		hostsForActive = append(hostsForActive, rawRouteHosts(rr)...)
	}

	type DayPoint struct {
		Date      string `json:"date"`
		Views     int    `json:"views"`
		Visitors  int    `json:"visitors"`
		Bandwidth int64  `json:"bandwidth"`
	}

	now := time.Now().UTC()
	days := make([]DayPoint, 7)
	seenTrafficHosts := map[string]struct{}{}
	uniqueTrafficHosts := make([]string, 0, len(hostsForActive))
	for _, host := range hostsForActive {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		hostKey := strings.ToLower(host)
		if _, seen := seenTrafficHosts[hostKey]; seen {
			continue
		}
		seenTrafficHosts[hostKey] = struct{}{}
		uniqueTrafficHosts = append(uniqueTrafficHosts, host)
	}

	for i := 6; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Truncate(24 * time.Hour)
		dayEnd := day.Add(24 * time.Hour)
		pt := DayPoint{Date: day.Format("2006-01-02")}
		for _, host := range uniqueTrafficHosts {
			if t, err := models.AccessTotalsBetween(s.DB, day, dayEnd, host, sid); err == nil {
				pt.Views += t.Views
				pt.Visitors += t.Visitors
			}
			if buckets, err := models.BandwidthBuckets(s.DB, day, dayEnd, 24*60*60, host, sid); err == nil {
				for _, bucket := range buckets {
					pt.Bandwidth += bucket.BytesOut
				}
			}
		}
		days[6-i] = pt
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"days": days})
}

// apiCaddyVersion returns the running Caddy version from the selected fleet
// node's admin API. The former bootstrap-client lookup made every environment
// show the primary node's version.
func (s *Server) apiCaddyVersion(w http.ResponseWriter, r *http.Request) {
	sid := s.currentServerID(r)
	srv, serverErr := models.GetCaddyServer(s.DB, sid)
	w.Header().Set("Content-Type", "application/json")
	if serverErr != nil {
		json.NewEncoder(w).Encode(map[string]any{"version": "unknown", "error": serverErr.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	version, err := caddy.New(srv.AdminURL, srv.AdminUsername, srv.AdminPassword).GetVersionFromAdmin(ctx)
	if err != nil {
		if strings.TrimSpace(srv.Version) != "" {
			json.NewEncoder(w).Encode(map[string]any{
				"version": srv.Version, "server_id": srv.ID, "server_name": srv.Name, "source": "saved",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"version": "unknown", "server_id": srv.ID, "server_name": srv.Name, "error": err.Error(),
		})
		return
	}
	_ = models.SetCaddyServerVersion(s.DB, sid, version)
	json.NewEncoder(w).Encode(map[string]any{
		"version": version, "server_id": srv.ID, "server_name": srv.Name,
	})
}

// apiVersionCheck returns the running version and the latest Docker Hub tag,
// so the UI can show an "update available" notice. Result is cached for 1 hour.
func (s *Server) apiVersionCheck(w http.ResponseWriter, r *http.Request) {
	s.versionMu.Lock()
	cached := s.latestVersion
	checkedAt := s.versionCheckedAt
	s.versionMu.Unlock()

	latest := cached
	if latest == "" || time.Since(checkedAt) > time.Hour {
		if v, err := fetchLatestDockerTag("applegater", "caddyui"); err == nil {
			latest = v
			s.versionMu.Lock()
			s.latestVersion = v
			s.versionCheckedAt = time.Now()
			s.versionMu.Unlock()
		}
	}

	current := s.Version
	hasUpdate := latest != "" && current != "" && current != "dev" && semverGT(latest, current)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"current":    current,
		"latest":     latest,
		"has_update": hasUpdate,
	})
}

// fetchLatestDockerTag queries Docker Hub for the highest vX.Y.Z tag of image.
func fetchLatestDockerTag(namespace, image string) (string, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	initialURL := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/%s/tags/?page_size=100", namespace, image)
	return fetchLatestDockerTagFrom(context.Background(), client, initialURL)
}

// fetchLatestDockerTagFrom follows Docker Hub's paginated tag response instead
// of assuming the newest semantic version is present on the first page.
func fetchLatestDockerTagFrom(ctx context.Context, client *http.Client, initialURL string) (string, error) {
	const maxPages = 100
	type tagPage struct {
		Next    string `json:"next"`
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}

	best := ""
	pageURL := initialURL
	for page := 0; pageURL != ""; page++ {
		if page >= maxPages {
			return "", fmt.Errorf("Docker Hub tag pagination exceeded %d pages", maxPages)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		if resp.StatusCode != http.StatusOK {
			msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
			return "", fmt.Errorf("Docker Hub tags returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		var result tagPage
		err = json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		for _, tag := range result.Results {
			if semverValid(tag.Name) && (best == "" || semverGT(tag.Name, best)) {
				best = tag.Name
			}
		}
		pageURL = result.Next
	}
	if best == "" {
		return "", fmt.Errorf("no semver tags found")
	}
	return best, nil
}
