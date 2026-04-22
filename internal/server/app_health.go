package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// appHealthEntry is the cached result of a single HTTPS GET against a proxy
// host's public domain. Unlike the TCP/port health (which asks Caddy whether
// it can open a socket to the upstream), this probe goes all the way through
// — DNS → Caddy → upstream — so it catches "port open but app wedged" cases
// that the TCP probe can't see.
type appHealthEntry struct {
	Status    string    // "ok" / "degraded" / "down" / "unknown" / "disabled"
	Code      int       // HTTP status code, 0 if no response received
	Error     string    // short error detail
	LatencyMS int64     // wall-clock round trip
	CheckedAt time.Time // when the cache entry was written
}

// App-poller tunables. Kept conservative so a dashboard full of hosts doesn't
// hammer the public edge: 60s between cycles, 5s per probe, max 3 redirects,
// at most 8 probes in flight concurrently.
const (
	appHealthInterval    = 60 * time.Second
	appHealthProbeTO     = 5 * time.Second
	appHealthMaxRedirect = 3
	appHealthMaxParallel = 8
)

// StartAppHealthPoller launches a background goroutine that periodically
// probes every enabled proxy host's public URL and caches the result. The
// cached result is read by /api/upstream-health and rendered as the "App"
// dot next to the existing "Port" dot on the dashboard + proxy hosts pages.
//
// The poller shares cadence with (but runs independently of) the server
// health poller — a stuck HTTP probe shouldn't delay the Caddy admin pings.
func (s *Server) StartAppHealthPoller(ctx context.Context) {
	go func() {
		// Fire once right away so the UI is populated on first load after boot
		// without waiting a full interval.
		s.pollAllApps(ctx)
		ticker := time.NewTicker(appHealthInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.pollAllApps(ctx)
			}
		}
	}()
}

// pollAllApps iterates every proxy host across every server and probes each
// in a bounded worker pool. We don't scope to a single server here because
// the dashboard can show hosts from the active server but the user may
// switch servers — keeping all hosts warm means the "App" dot is instantly
// correct after a server switch.
func (s *Server) pollAllApps(ctx context.Context) {
	caddyServers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		log.Printf("app-health poller: list servers: %v", err)
		return
	}
	// Collect every proxy host across every server. We deliberately ignore
	// ownership here (isAdmin=true, viewer=0) because the poller is a
	// system-level background job, not user-facing.
	var allHosts []models.ProxyHost
	for _, cs := range caddyServers {
		hosts, err := models.ListProxyHosts(s.DB, cs.ID, 0, true)
		if err != nil {
			log.Printf("app-health poller: list hosts (server %d): %v", cs.ID, err)
			continue
		}
		allHosts = append(allHosts, hosts...)
	}

	// Worker pool to cap concurrent outbound probes.
	sem := make(chan struct{}, appHealthMaxParallel)
	var wg sync.WaitGroup
	for _, h := range allHosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h models.ProxyHost) {
			defer wg.Done()
			defer func() { <-sem }()
			entry := s.probeApp(ctx, h)
			s.appHealthMu.Lock()
			s.appHealth[h.ID] = entry
			s.appHealthMu.Unlock()
		}(h)
	}
	wg.Wait()

	// Garbage-collect cache entries for hosts that no longer exist, so the
	// map doesn't grow forever as hosts are created and deleted.
	live := make(map[int64]struct{}, len(allHosts))
	for _, h := range allHosts {
		live[h.ID] = struct{}{}
	}
	s.appHealthMu.Lock()
	for id := range s.appHealth {
		if _, ok := live[id]; !ok {
			delete(s.appHealth, id)
		}
	}
	s.appHealthMu.Unlock()
}

// probeApp performs one HTTPS GET against the host's primary domain and
// classifies the result. Classification rules (designed to match what a
// human reading the dashboard would actually call "up" or "down"):
//
//	ok       — 2xx / 3xx / 401 / 403 (app responded with something sensible)
//	degraded — 5xx or slow (>appHealthProbeTO)
//	down     — connection refused / TLS error / timeout
//	unknown  — domain doesn't resolve publicly (WG/Tailscale-only edge)
//
// Redirects are followed up to appHealthMaxRedirect hops so "/ → /login"
// ends up as ok (200) rather than showing the 302. Cert validation is
// skipped — an expired or self-signed cert shouldn't mask the fact that the
// upstream *is* responding; the cert-expiry notifier handles that concern.
func (s *Server) probeApp(ctx context.Context, h models.ProxyHost) appHealthEntry {
	now := time.Now()
	if !h.Enabled {
		return appHealthEntry{Status: "disabled", CheckedAt: now}
	}

	domains := h.DomainList()
	if len(domains) == 0 {
		return appHealthEntry{Status: "unknown", Error: "no domain configured", CheckedAt: now}
	}
	primary := domains[0]

	// Wildcard domains (e.g. "*.example.com") can't be probed directly —
	// there's no specific host to GET. Skip with "unknown" rather than
	// flagging as down.
	if strings.Contains(primary, "*") {
		return appHealthEntry{Status: "unknown", Error: "wildcard domain — no specific host to probe", CheckedAt: now}
	}

	// Decide scheme: we always use https because Caddy auto-upgrades, but
	// fall back to http if the host explicitly disables SSL (SSLEnabled=false
	// + no custom cert). Most installs will be https.
	scheme := "https"
	if !h.SSLEnabled && h.CertificateID == 0 {
		scheme = "http"
	}
	probeURL := (&url.URL{Scheme: scheme, Host: primary, Path: "/"}).String()

	client := &http.Client{
		Timeout: appHealthProbeTO,
		Transport: &http.Transport{
			// Skip TLS verification: we care whether the app responds, not
			// about cert validity (that's tracked separately by the cert
			// notifier). Self-signed / expired certs shouldn't mask app
			// status.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint:gosec // probe-only
			// Be polite: reuse one connection per host, don't hold it open.
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= appHealthMaxRedirect {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	probeCtx, cancel := context.WithTimeout(ctx, appHealthProbeTO)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		return appHealthEntry{Status: "down", Error: err.Error(), CheckedAt: now}
	}
	req.Header.Set("User-Agent", "caddyui-app-health/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		// DNS resolution failure → unknown, not down: the caddyui container
		// may legitimately not resolve an edge-only domain even though the
		// wider internet does.
		if isDNSError(err) || isNetDNSError(err) {
			return appHealthEntry{Status: "unknown", Error: err.Error(), LatencyMS: latency, CheckedAt: now}
		}
		return appHealthEntry{Status: "down", Error: err.Error(), LatencyMS: latency, CheckedAt: now}
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	entry := appHealthEntry{Code: code, LatencyMS: latency, CheckedAt: now}
	switch {
	case code >= 500:
		entry.Status = "degraded"
		entry.Error = fmt.Sprintf("HTTP %d", code)
	case code >= 200 && code < 400, code == http.StatusUnauthorized, code == http.StatusForbidden:
		entry.Status = "ok"
	default:
		// 4xx other than 401/403 — treat as degraded so the user notices;
		// 404 on "/" often means the app is misconfigured.
		entry.Status = "degraded"
		entry.Error = fmt.Sprintf("HTTP %d", code)
	}
	return entry
}

// isNetDNSError catches net.DNSError values that the simpler string-match
// isDNSError() might miss (e.g. wrapped errors). Shared with the existing
// isDNSError helper so callers get the same "unknown not down" semantics
// whichever error shape bubbles up.
func isNetDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
