// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// --- Unified DNS helpers ---
//
// Replaces the v2.2.x per-provider helpers (cfClient/cfCreateDNSRecord/...,
// pbClient/pbCreateDNSRecord/...) with a single code path driven by the
// dns.Provider registry. A proxy_hosts row carries four DNS columns:
//   dns_provider  — the provider ID ("cloudflare", "porkbun", ...)
//   dns_zone_id   — the provider-native zone ID (opaque for CF/Hetzner/Route53;
//                   domain name for PB/DO/GD/NC)
//   dns_zone_name — the base domain in human-readable form ("example.com")
//   dns_record_id — the record identifier returned by the provider
// All mutations happen through dnsCreateRecord / dnsDeleteRecord /
// dnsUpdateAllRecords — no provider-specific branch lives above this line.

// dnsCreateRecordForFQDN creates an A record at fqdn pointing at the
// per-server public IP and returns (recordID, resolvedZoneName). Returns
// ("","") on any precondition failure or provider error; all failures are
// logged but not returned — DNS is non-fatal to the caller's main save
// path. Shared by the proxy-host and raw-route create paths; the caller
// persists the returned record ID via its own Update*DNSRecord helper.
//
// serverID is the Caddy server the caller lives on — v2.4.0 reads the
// per-server public_ip first and falls back to the global setting so
// multi-server setups get the right A-record content instead of always
// pointing at server #1's IP.
func (s *Server) dnsCreateRecordForFQDN(serverID int64, provider, profileID, zoneID, zoneName, fqdn string) (string, string) {
	if provider == "" || zoneID == "" || fqdn == "" {
		return "", ""
	}
	client := s.dnsClientFor(provider, profileID)
	if client == nil {
		return "", ""
	}
	ip := s.serverIPFor(serverID)
	if ip == "" {
		log.Printf("DNS: server IP not configured for server %d — skipping record creation for %s", serverID, fqdn)
		return "", ""
	}
	zone := dns.Zone{ID: zoneID, Name: zoneName}
	if zone.Name == "" {
		// Older rows (pre-migration) may not have zone_name populated —
		// it's optional metadata for most providers. Fall back to the
		// zone ID which doubles as the domain for PB/DO/GD/NC.
		zone.Name = zoneID
	}
	// v2.4.7: honour the per-provider zone allow-list as a last-line guard.
	// The dropdown is already filtered, but the zone name on the row could
	// have come from an older config / direct DB edit / a user who
	// tightened the allow-list after the host was created. Refusing here
	// makes the allow-list a hard safety rail, not just a UI filter.
	if !s.zoneAllowedFor(provider, profileID, zone.Name) {
		log.Printf("DNS %s: zone %q not in allow-list — skipping record creation for %s", provider, zone.Name, fqdn)
		return "", ""
	}
	rec, err := client.CreateRecord(zone, fqdn, ip, "A", 0)
	if err != nil {
		log.Printf("DNS %s: create record for %s: %v", provider, fqdn, err)
		return "", ""
	}
	return rec.ID, zone.Name
}

// splitDNSRecordIDs splits the comma-separated DNSRecordID column value into
// individual provider record IDs. v2.5.9 introduced the comma-separated
// encoding so routes with multiple hostnames (e.g. `example.com, *.example.com`)
// can track one provider record per hostname. Empty / single-ID values still
// parse cleanly — a pre-v2.5.9 row with "abc123" returns []string{"abc123"}.
func splitDNSRecordIDs(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dnsCreateRecord creates an A record for every domain on the proxy host.
// p.DNSProvider / p.DNSZoneID must be set before calling. The set of
// provider-returned record IDs is persisted to the proxy_hosts row as a
// comma-separated string via models.UpdateProxyHostDNSRecord.
// v2.5.9: previously only the first domain got a record — multi-domain hosts
// (aliases + primary, or wildcard + apex) now get one record per hostname so
// clients resolving any alias actually reach the origin.
func (s *Server) dnsCreateRecord(serverID, hostID int64, p *models.ProxyHost) {
	domains := p.DomainList()
	if len(domains) == 0 {
		return
	}
	var ids []string
	var zname string
	for _, fqdn := range domains {
		recID, zn := s.dnsCreateRecordForFQDN(serverID, p.DNSProvider, p.DNSProfileID, p.DNSZoneID, p.DNSZoneName, fqdn)
		if recID == "" {
			continue
		}
		ids = append(ids, recID)
		if zname == "" {
			zname = zn
		}
	}
	if len(ids) == 0 {
		return
	}
	if err := models.UpdateProxyHostDNSRecord(s.DB, hostID, p.DNSProvider, p.DNSZoneID, zname, strings.Join(ids, ",")); err != nil {
		log.Printf("DNS %s: store record IDs for host %d: %v", p.DNSProvider, hostID, err)
	}
}

// dnsCreateRecordForRedirection — v2.12.2: creates an A record per hostname
// in the redirection host's Domains CSV, mirroring dnsCreateRecord on the
// proxy-host side. Persists the comma-separated provider IDs to the
// redirection_hosts row via UpdateRedirectionHostDNSRecord.
func (s *Server) dnsCreateRecordForRedirection(serverID, hostID int64, rh *models.RedirectionHost) {
	domains := rh.DomainList()
	if len(domains) == 0 {
		return
	}
	var ids []string
	var zname string
	for _, fqdn := range domains {
		recID, zn := s.dnsCreateRecordForFQDN(serverID, rh.DNSProvider, rh.DNSProfileID, rh.DNSZoneID, rh.DNSZoneName, fqdn)
		if recID == "" {
			continue
		}
		ids = append(ids, recID)
		if zname == "" {
			zname = zn
		}
	}
	if len(ids) == 0 {
		return
	}
	if err := models.UpdateRedirectionHostDNSRecord(s.DB, hostID, rh.DNSProvider, rh.DNSZoneID, zname, strings.Join(ids, ",")); err != nil {
		log.Printf("DNS %s: store record IDs for redirection %d: %v", rh.DNSProvider, hostID, err)
	}
}

// dnsCreateRecordForRaw is the raw-route twin of dnsCreateRecord.
// v2.5.6: raw routes don't carry a Domains CSV, so hostnames are pulled
// from the JSON blob's match.host[] via rawRouteHosts.
// v2.5.9: creates a record for EVERY hostname in match[].host[] rather than
// only the first — so an advanced route covering `example.com, *.example.com`
// gets both A records provisioned. Record IDs are persisted to the raw_routes
// row as a comma-separated string via models.UpdateRawRouteDNSRecord. No-op
// when DNS fields are unset or the JSON has no host matcher.
func (s *Server) dnsCreateRecordForRaw(serverID, routeID int64, rr *models.RawRoute) {
	hosts := rawRouteHosts(*rr)
	if len(hosts) == 0 {
		return
	}
	var ids []string
	var zname string
	for _, fqdn := range hosts {
		recID, zn := s.dnsCreateRecordForFQDN(serverID, rr.DNSProvider, rr.DNSProfileID, rr.DNSZoneID, rr.DNSZoneName, fqdn)
		if recID == "" {
			continue
		}
		ids = append(ids, recID)
		if zname == "" {
			zname = zn
		}
	}
	if len(ids) == 0 {
		return
	}
	if err := models.UpdateRawRouteDNSRecord(s.DB, routeID, rr.DNSProvider, rr.DNSZoneID, zname, strings.Join(ids, ",")); err != nil {
		log.Printf("DNS %s: store record IDs for raw route %d: %v", rr.DNSProvider, routeID, err)
	}
}

// dnsDeleteRecord removes previously-created records for the given row.
// v2.5.9: recordIDs may be a single ID ("abc123") or a comma-separated list
// ("abc123,def456") — loops internally so callers can keep passing the raw
// DNSRecordID column value regardless of how many records are behind it.
// Best-effort: errors are logged, not returned (the row is being deleted
// anyway; a leftover record is a minor annoyance, not a correctness issue).
func (s *Server) dnsDeleteRecord(providerID, profileID, zoneID, zoneName, recordIDs string) {
	if providerID == "" || recordIDs == "" {
		return
	}
	client := s.dnsClientFor(providerID, profileID)
	if client == nil {
		return
	}
	zone := dns.Zone{ID: zoneID, Name: zoneName}
	if zone.Name == "" {
		zone.Name = zoneID
	}
	// v2.4.7: refuse to delete records in zones the allow-list excludes.
	// Intentionally symmetric with dnsCreateRecord — "touching a record"
	// in an excluded zone is exactly what the allow-list is meant to
	// prevent, even when the touch is a cleanup. Leaves the record in
	// place; the user can remove it by hand via the provider's console.
	if !s.zoneAllowedFor(providerID, profileID, zone.Name) {
		log.Printf("DNS %s: zone %q not in allow-list — leaving records %s in place", providerID, zone.Name, recordIDs)
		return
	}
	for _, recordID := range splitDNSRecordIDs(recordIDs) {
		if err := client.DeleteRecord(zone, recordID); err != nil {
			log.Printf("DNS %s: delete record %s: %v", providerID, recordID, err)
		}
	}
}

// dnsUpdateAllRecords retargets managed DNS records at newIP. Pass
// serverID > 0 to scope the retarget to content rows that live on that
// Caddy server (v2.4.0 per-server public-IP flow); 0 retargets every
// managed record regardless of server (used by the legacy global-IP
// fallback path so pre-v2.4.0 databases still work).
//
// We cache provider clients by ID so we build each at most once per call.
// Records for providers with missing credentials are skipped rather than
// cleared, so partial credential removal doesn't destroy working records.
//
// v2.5.6: also retargets raw-route records alongside proxy-host records.
func (s *Server) dnsUpdateAllRecords(serverID int64, newIP string) {
	hosts, err := models.ListProxyHostsWithDNSRecords(s.DB, serverID)
	if err != nil {
		log.Printf("DNS: list managed hosts for IP update: %v", err)
	}
	rawRoutes, err := models.ListRawRoutesWithDNSRecords(s.DB, serverID)
	if err != nil {
		log.Printf("DNS: list managed raw routes for IP update: %v", err)
	}
	if len(hosts) == 0 && len(rawRoutes) == 0 {
		return
	}
	clients := map[string]dns.Provider{}
	getClient := func(id, profileID string) dns.Provider {
		key := id + "|" + profileID
		if c, ok := clients[key]; ok {
			return c
		}
		c := s.dnsClientFor(id, profileID)
		clients[key] = c
		return c
	}
	log.Printf("DNS: retargeting %d proxy-host record(s) + %d raw-route record(s) to %s", len(hosts), len(rawRoutes), newIP)

	// retarget is the shared delete-then-create worker. kind is a tag for
	// the log line ("proxy"/"raw"); persist is the row-specific updater
	// that writes the fresh record ID(s) (or clears on failure). fqdns are
	// pulled differently per row type (Domains CSV vs match[].host[]), so
	// the caller hands them in.
	// v2.5.9: accepts multiple fqdns + multiple old record IDs to match
	// the multi-hostname create path. Deletes every old record, creates
	// one new record per current hostname, persists the joined ID list.
	// Rows created pre-v2.5.9 (one ID, multiple hostnames) self-heal on
	// the first retarget — the missing-alias records get created fresh.
	retarget := func(kind string, rowID int64, provider, profileID, zoneID, zoneName, recordIDs string, fqdns []string, persist func(zoneID, zoneName, recordID string)) {
		client := getClient(provider, profileID)
		if client == nil {
			log.Printf("DNS %s: credentials missing — skipping %s %d retarget", provider, kind, rowID)
			return
		}
		if len(fqdns) == 0 {
			return
		}
		zone := dns.Zone{ID: zoneID, Name: zoneName}
		if zone.Name == "" {
			zone.Name = zoneID
		}
		// v2.4.7: guard IP retargets against the allow-list too. If a zone
		// was valid when the record was created but the user has since
		// tightened the list, the retarget job leaves that record alone —
		// same policy as dnsCreateRecord / dnsDeleteRecord.
		if !s.zoneAllowedFor(provider, profileID, zone.Name) {
			log.Printf("DNS %s: zone %q not in allow-list — skipping retarget for %v", provider, zone.Name, fqdns)
			return
		}
		// Delete-then-create semantic. Every provider implementation is
		// idempotent on delete (silently succeeds if the record is gone),
		// and recreate gives us a fresh record ID — cleanest across the
		// whole provider set, even if a tiny window exists where the
		// record is absent. Users are already dealing with a live IP
		// change when this runs; a few seconds of DNS flutter is noise.
		for _, recordID := range splitDNSRecordIDs(recordIDs) {
			if err := client.DeleteRecord(zone, recordID); err != nil {
				log.Printf("DNS %s: delete old record %s: %v", provider, recordID, err)
			}
		}
		var newIDs []string
		for _, fqdn := range fqdns {
			rec, err := client.CreateRecord(zone, fqdn, newIP, "A", 0)
			if err != nil {
				log.Printf("DNS %s: create new record for %s: %v", provider, fqdn, err)
				continue
			}
			newIDs = append(newIDs, rec.ID)
			log.Printf("DNS %s: updated %s → %s (record %s)", provider, fqdn, newIP, rec.ID)
		}
		if len(newIDs) == 0 {
			persist("", "", "")
			return
		}
		persist(zone.ID, zone.Name, strings.Join(newIDs, ","))
	}

	for _, h := range hosts {
		h := h
		retarget("proxy", h.ID, h.DNSProvider, h.DNSProfileID, h.DNSZoneID, h.DNSZoneName, h.DNSRecordID,
			h.DomainList(),
			func(zoneID, zoneName, recordID string) {
				provider := h.DNSProvider
				if recordID == "" {
					provider = ""
				}
				_ = models.UpdateProxyHostDNSRecord(s.DB, h.ID, provider, zoneID, zoneName, recordID)
			})
	}
	for _, rr := range rawRoutes {
		rr := rr
		retarget("raw", rr.ID, rr.DNSProvider, rr.DNSProfileID, rr.DNSZoneID, rr.DNSZoneName, rr.DNSRecordID,
			rawRouteHosts(rr),
			func(zoneID, zoneName, recordID string) {
				provider := rr.DNSProvider
				if recordID == "" {
					provider = ""
				}
				_ = models.UpdateRawRouteDNSRecord(s.DB, rr.ID, provider, zoneID, zoneName, recordID)
			})
	}
}

// apiDNSZones returns the list of zones for the provider specified in the
// ?provider= query string. Replaces the per-provider apiCFZones /
// apiPBDomains endpoints with a single handler.
//
// Response shape is always [{id, name}] so the form's zone-picker JS
// renders every provider with the same code path. Cloudflare, Hetzner, and Route 53
// return real opaque zone IDs; for Porkbun/DO/GoDaddy/Namecheap the ID
// and name are the same string (the bare domain).
func (s *Server) apiDNSZones(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	provider := strings.ToLower(strings.TrimSpace(q.Get("provider")))
	profileID := strings.TrimSpace(q.Get("profile"))
	if profileID == "" {
		profileID = strings.TrimSpace(q.Get("dns_profile_id"))
	}
	provider, profileID = s.normalizeDNSFormSelection(provider, profileID)
	w.Header().Set("Content-Type", "application/json")
	if provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing provider parameter"})
		return
	}
	client := s.dnsClientFor(provider, profileID)
	if client == nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "credentials for provider \"" + provider + "\" not configured in Settings"})
		return
	}
	zones, err := client.ListZones()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	// v2.4.7: apply the per-provider zone allow-list. If it's set, only
	// zones whose name is on the list are returned — the proxy-host form's
	// zone dropdown then literally cannot offer domains the user has
	// excluded. Empty allow-list = unrestricted (every zone the credentials
	// can see), which preserves the original behaviour.
	if allow := s.zoneAllowlistFor(provider, profileID); len(allow) > 0 {
		allowSet := make(map[string]struct{}, len(allow))
		for _, a := range allow {
			allowSet[a] = struct{}{}
		}
		filtered := zones[:0]
		for _, z := range zones {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z.Name)), ".")
			if _, ok := allowSet[name]; ok {
				filtered = append(filtered, z)
			}
		}
		zones = filtered
	}
	_ = json.NewEncoder(w).Encode(zones)
}

// apiDNSCheckRecord looks up existing records for an (provider, zone, fqdn)
// triple so the proxy-host form can warn when saving would collide with
// something already in DNS. Called by the form JS after the user has picked
// provider + zone and typed a first domain.
//
// Query string: provider=<id>&zone=<zoneID>&zone_name=<zoneName>&fqdn=<host>
//
// Response shape (always 200 when inputs are valid — errors go in the body):
//
//	{"ok":true, "exists":true, "records":[{id,type,name,content,ttl},...]}
//	{"ok":true, "exists":false}
//	{"ok":false, "error":"..."}
//
// The `exists` flag is the only thing the UI needs to branch on; the full
// record list is included so the warning dialog can show the user what
// they're about to clobber. 200-with-body-error (rather than 4xx/5xx) keeps
// the form JS simple — one JSON parse, branch on `ok`.
func (s *Server) apiDNSCheckRecord(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query()
	provider := strings.ToLower(strings.TrimSpace(q.Get("provider")))
	profileID := strings.TrimSpace(q.Get("profile"))
	if profileID == "" {
		profileID = strings.TrimSpace(q.Get("dns_profile_id"))
	}
	provider, profileID = s.normalizeDNSFormSelection(provider, profileID)
	zoneID := strings.TrimSpace(q.Get("zone"))
	zoneName := strings.TrimSpace(q.Get("zone_name"))
	fqdn := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(q.Get("fqdn"))), ".")
	if provider == "" || zoneID == "" || fqdn == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "missing provider/zone/fqdn"})
		return
	}
	// Zone name is optional on the wire — most providers use ID==Name so
	// we can recover it. Cloudflare, Hetzner, and Route 53 have opaque IDs, so when
	// the client omits zone_name we fall back to zoneID (which will fail
	// SubdomainOf but still works for Cloudflare's server-side filter).
	if zoneName == "" {
		zoneName = zoneID
	}
	client := s.dnsClientFor(provider, profileID)
	if client == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "credentials for provider \"" + provider + "\" not configured"})
		return
	}
	// Allow-list guard: don't leak record listings for zones the user has
	// excluded from management. Symmetrical with apiDNSZones' filter.
	if !s.zoneAllowedFor(provider, profileID, zoneName) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "zone not in allow-list"})
		return
	}
	zone := dns.Zone{ID: zoneID, Name: zoneName}
	records, err := client.FindRecord(zone, fqdn)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// Scope the warning to record types that actually conflict with the
	// A/AAAA/CNAME we're about to write. MX / TXT / SRV / CAA routinely
	// cohabit with the web endpoint (email, SPF, cert issuance) and
	// alarming on them would scare users into clicking Override — which
	// used to wipe their mail records. See IsProxyConflictingType.
	filtered := records[:0]
	for _, rec := range records {
		if dns.IsProxyConflictingType(rec.Type) {
			filtered = append(filtered, rec)
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"exists":  len(filtered) > 0,
		"records": filtered,
	})
}

// ─────────────────────────────────────────────────────────────────────
// v2.5.2: post-save "deploying" flow.
// ─────────────────────────────────────────────────────────────────────
//
// When a proxy-host save creates or changes a managed-DNS A record, we
// redirect to /proxy-hosts/{id}/deploying instead of bouncing straight
// back to the list. That page polls apiProxyHostDeployStatus every few
// seconds and draws a live checklist — DNS propagated, TLS handshake
// succeeded — so the user actually knows when their site is enterable.
// ─────────────────────────────────────────────────────────────────────

// apiProxyHostDeployStatus returns the real-time deployment status for a
// freshly-saved proxy host. Response:
//
//	{
//	  "fqdn":         "test.example.com",
//	  "expected_ip":  "203.0.113.10",
//	  "resolved_ips": ["203.0.113.10"],
//	  "ssl_enabled":  true,
//	  "proxied":      false,
//	  "dns_ready":    true,
//	  "cert_ready":   false,
//	  "error":        ""
//	}
//
// For non-proxied records dns_ready is true only when a public resolver
// returns an A record matching the server's configured public IP. For
// Cloudflare-proxied records (orange cloud) the record points at CF's
// edge IPs, so we relax to "any A record" — the record is live in DNS
// and CF is handling the rest. Cert check is a plain TLS handshake via
// tls.Dial against fqdn:443 with system-trust verification enabled, so
// a Caddy-internal self-signed fallback correctly reports not-ready.
func (s *Server) apiProxyHostDeployStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad id"})
		return
	}
	host, err := models.GetProxyHost(s.DB, id)
	if err != nil || host == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "not found"})
		return
	}
	// Ownership: non-admins can only poll their own hosts.
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !s.canManageOwned(cu, host.OwnerID) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden"})
			return
		}
	}
	fqdn := dns.FirstDomain(host.Domains)
	expectedIP := s.serverIPFor(host.ServerID)
	resp := map[string]any{
		"fqdn":         fqdn,
		"expected_ip":  expectedIP,
		"ssl_enabled":  host.SSLEnabled,
		"proxied":      false,
		"dns_ready":    false,
		"cert_ready":   false,
		"resolved_ips": []string{},
		"dns_skipped":  host.DNSProvider != "" && host.DNSSkipRecord,
	}
	if host.DNSProvider != "" && host.DNSSkipRecord {
		resp["dns_ready"] = true
	}
	if fqdn == "" {
		resp["error"] = "host has no domain"
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	// Proxied flag applies to Cloudflare only; other providers always
	// resolve to the configured server IP.
	if host.DNSProvider == dns.Cloudflare {
		if v, _ := models.GetSetting(s.DB, settingCFProxied); v == "1" {
			resp["proxied"] = true
		}
	}
	// DNS check via Cloudflare DNS-over-HTTPS. Silent on error — the
	// client keeps polling, and a transient DoH failure should just
	// look like "not ready yet".
	if !host.DNSSkipRecord {
		if ips, dnsErr := s.resolveVerifyA(fqdn); dnsErr == nil {
			resp["resolved_ips"] = ips
			if resp["proxied"] == true {
				resp["dns_ready"] = len(ips) > 0
			} else if expectedIP != "" {
				for _, ip := range ips {
					if ip == expectedIP {
						resp["dns_ready"] = true
						break
					}
				}
			} else {
				// No expected IP configured — fall back to "any A record".
				// Otherwise we'd always report not-ready.
				resp["dns_ready"] = len(ips) > 0
			}
		}
	}
	// Cert check: skipped when SSL is off on the host, and deferred
	// until DNS is ready (otherwise the dial is guaranteed to fail on
	// hostname resolution).
	resolvedIPs, _ := resp["resolved_ips"].([]string)
	proxied, _ := resp["proxied"].(bool)
	if !host.SSLEnabled {
		resp["cert_ready"] = true
	} else if resp["dns_ready"] == true {
		resp["cert_ready"] = s.tlsHandshakeOK(host.ServerID, fqdn, proxied, resolvedIPs)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// verifyResolverMode classifies the admin-configured verification resolver.
type verifyResolverMode int

const (
	verifyResolverDefault  verifyResolverMode = iota // Cloudflare DoH
	verifyResolverDoHURL                             // custom DoH JSON endpoint
	verifyResolverPlainDNS                           // one or more host:port DNS servers
)

// classifyVerifyResolver interprets the dns_verify_resolver setting (issue #98).
// Blank -> default (Cloudflare DoH). A value starting with http(s):// is a
// custom DoH endpoint. Otherwise it is a comma/space/newline-separated list of
// plain DNS servers; a bare host gets the default :53 port.
func classifyVerifyResolver(raw string) (verifyResolverMode, []string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return verifyResolverDefault, nil
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return verifyResolverDoHURL, []string{raw}
	}
	var servers []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	}) {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, ":") {
			f += ":53"
		}
		servers = append(servers, f)
	}
	if len(servers) == 0 {
		return verifyResolverDefault, nil
	}
	return verifyResolverPlainDNS, servers
}

// resolveVerifyA resolves A records for fqdn using the admin-configured
// verification resolver (issue #98), falling back to Cloudflare DoH. Used by
// the deploy/readiness checks so filtered or split-horizon networks can point
// verification at a reachable resolver instead of hanging on Cloudflare.
func (s *Server) resolveVerifyA(fqdn string) ([]string, error) {
	raw, _ := models.GetSetting(s.DB, settingDNSVerifyResolver)
	switch mode, detail := classifyVerifyResolver(raw); mode {
	case verifyResolverDoHURL:
		return resolveViaDoHURL(detail[0], fqdn)
	case verifyResolverPlainDNS:
		return resolveViaPlainDNS(detail, fqdn)
	default:
		return resolveViaDoH(fqdn)
	}
}

// resolveViaDoH queries Cloudflare DNS-over-HTTPS for A records for fqdn.
func resolveViaDoH(fqdn string) ([]string, error) {
	return resolveViaDoHURL("https://cloudflare-dns.com/dns-query", fqdn)
}

// resolveViaDoHURL queries any DoH JSON-API endpoint for A records for fqdn.
// Returns the list of IPs, or an empty slice if the record doesn't exist yet.
// 6-second timeout so a slow resolver doesn't stall the poll.
func resolveViaDoHURL(base, fqdn string) ([]string, error) {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	req, err := http.NewRequest("GET", base+sep+"name="+url.QueryEscape(fqdn)+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(data.Answer))
	for _, a := range data.Answer {
		if a.Type == 1 { // A record
			ips = append(ips, strings.TrimSpace(a.Data))
		}
	}
	return ips, nil
}

// plainDNSLookup is the per-server A lookup, indirected so failover ordering
// can be tested without real network I/O.
var plainDNSLookup = lookupAFromServer

// resolveViaPlainDNS resolves A records for fqdn by querying the given DNS
// servers directly, trying each in order until one actually answers. Failover
// is decided by the DNS exchange itself, not by whether a socket could be
// opened: a UDP "dial" to an unreachable server succeeds immediately without
// touching the network, so relying on dial errors would pin every query to a
// dead first server (issue #98). A server that authoritatively reports "no such
// host" ends the search and returns an empty slice — the same "record not live
// yet" signal the DoH path gives — so the poll keeps going.
func resolveViaPlainDNS(servers []string, fqdn string) ([]string, error) {
	var lastErr error
	for _, srv := range servers {
		ips, notFound, err := plainDNSLookup(srv, fqdn)
		if notFound {
			return []string{}, nil
		}
		if err == nil {
			return ips, nil
		}
		lastErr = err // unreachable / timeout — try the next server
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS servers configured")
	}
	return nil, lastErr
}

// lookupAFromServer queries a single DNS server for A records for fqdn. It
// returns notFound=true when the server answered but has no such record (a
// definitive answer, not a reason to fail over), or a non-nil err when the
// server did not answer in time (unreachable/filtered — try the next one).
func lookupAFromServer(server, fqdn string) (ips []string, notFound bool, err error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, lerr := r.LookupIP(ctx, "ip4", fqdn)
	if lerr != nil {
		if dnsErr, ok := lerr.(*net.DNSError); ok && dnsErr.IsNotFound {
			return []string{}, true, nil
		}
		return nil, false, lerr
	}
	out := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		out = append(out, ip.String())
	}
	return out, false, nil
}

// tlsHandshakeOK performs a full TLS handshake with SNI set to fqdn and
// validates the returned chain against the system trust store. Returns
// true only when the cert chain verifies — which is what users actually
// care about ("can I open the site in a browser"). A Caddy-internal
// self-signed fallback cert, an ACME-staging cert, or an expired cert
// all correctly report false.
//
// Dial target depends on how the record is served, to avoid the WAN
// hairpin NAT problem most consumer routers have (resolving fqdn to the
// public IP and dialing it from inside the LAN fails even when the site
// is live for real users). We pick the dial target in priority order:
//
//  1. **Cloudflare-proxied** (orange cloud): dial the CF edge IP we just
//     resolved via DoH. CF edge IPs are always public + outside the LAN,
//     so hairpin never applies; SNI = fqdn makes CF serve the right
//     customer cert from its Universal SSL / Advanced Certs pool. This
//     is v2.5.5 — previously we tried to dial Caddy internally, which
//     is wrong for proxied hosts because the user's browser sees CF's
//     cert, not Caddy's origin cert.
//  2. **Direct**: dial the Caddy server by its admin-URL hostname
//     (docker service name `caddy` for single-host, admin host for
//     remote servers). Bypasses public DNS + WAN hairpin; SNI = fqdn
//     makes Caddy serve the right cert. This is the v2.5.4 path and
//     remains the default for non-proxied providers.
//  3. **Fallback**: dial the public fqdn directly. Used when we can't
//     figure out an internal dial target (e.g. admin URL is a unix
//     socket, or the server row is unreadable).
func (s *Server) tlsHandshakeOK(serverID int64, fqdn string, proxied bool, resolvedIPs []string) bool {
	target := fqdn + ":443"
	switch {
	case proxied && len(resolvedIPs) > 0:
		target = resolvedIPs[0] + ":443"
	default:
		if host := s.caddyDialHost(serverID); host != "" {
			target = host + ":443"
		}
	}
	d := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", target, &tls.Config{
		ServerName: fqdn,
	})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// caddyDialHost returns the hostname (no port) to use when dialing the
// Caddy server for serverID. Pulled from the admin URL so single-host
// setups resolve to "caddy" (the docker service name) and remote-server
// setups resolve to whatever address admin is configured on. Falls back
// to the primary client's admin URL when serverID isn't usable. Returns
// "" when nothing sensible can be extracted — callers then dial the
// public fqdn directly as a last resort.
func (s *Server) caddyDialHost(serverID int64) string {
	adminURL := ""
	if serverID > 0 {
		if srv, err := models.GetCaddyServer(s.DB, serverID); err == nil {
			adminURL = srv.AdminURL
		}
	}
	if adminURL == "" && s.Caddy != nil {
		adminURL = s.Caddy.AdminURL
	}
	if adminURL == "" {
		return ""
	}
	u, err := url.Parse(adminURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	// Unix-socket admins ("http://unix") give an empty hostname above;
	// belt-and-braces skip them too since we can't dial :443 via a
	// socket path.
	if strings.EqualFold(u.Scheme, "unix") || strings.EqualFold(u.Host, "unix") {
		return ""
	}
	return u.Hostname()
}

// proxyHostDeploying renders the post-save "deploying" checklist page.
// Shown after a create/update that created or changed a managed-DNS
// record. The page JS polls /api/proxy-hosts/{id}/deploy-status every
// few seconds and auto-redirects to /proxy-hosts once both DNS and
// cert checks pass — or after the hard 120s timeout.
func (s *Server) proxyHostDeploying(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	host, err := models.GetProxyHost(s.DB, id)
	if err != nil || host == nil {
		http.NotFound(w, r)
		return
	}
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !s.canManageOwned(cu, host.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	providerName := host.DNSProvider
	if d, ok := dns.Lookup(host.DNSProvider); ok {
		providerName = d.DisplayName
	}
	s.render(w, r, "proxy_host_deploying.html", map[string]any{
		"User":         cu,
		"Host":         host,
		"FirstDomain":  dns.FirstDomain(host.Domains),
		"ProviderName": providerName,
		"ExpectedIP":   s.serverIPFor(host.ServerID),
		"Section":      "proxy",
	})
}

// firstRawRouteHost pulls the first hostname out of a raw-route JSON
// blob's match.host[] array. v2.5.5 uses this to drive the post-save
// deploying page for advanced routes — if the route has no host matcher
// (path-only, port-only, etc.) we return "" and the caller skips the
// deploying page entirely since there's nothing DNS- or TLS-shaped to
// probe.
//
// Parsing is defensive: any shape mismatch in the JSON returns empty
// rather than panicking, because raw routes intentionally accept arbitrary
// Caddy JSON and we don't want a malformed blob to break the post-save
// redirect. The save path already runs the config through Caddy's adapter
// before we get here, so well-formed routes reach this function with the
// canonical match[].host[] shape.
func firstRawRouteHost(jsonData string) string {
	if strings.TrimSpace(jsonData) == "" {
		return ""
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(jsonData), &cfg); err != nil {
		return ""
	}
	matches, _ := cfg["match"].([]any)
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		hosts, _ := mm["host"].([]any)
		for _, h := range hosts {
			if s, ok := h.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// apiRawRouteDeployStatus mirrors apiProxyHostDeployStatus for advanced
// routes. Raw routes don't manage their own DNS records (the user wires
// A records manually), so the "record created in <provider>" step is
// absent — but DNS propagation + TLS handshake still apply and are
// exactly the signal the user wants after saving.
func (s *Server) apiRawRouteDeployStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad id"})
		return
	}
	rr, err := models.GetRawRoute(s.DB, id)
	if err != nil || rr == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "not found"})
		return
	}
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !s.canManageOwned(cu, rr.OwnerID) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden"})
			return
		}
	}
	fqdn := firstRawRouteHost(rr.JSONData)
	serverID := s.currentServerID(r)
	expectedIP := s.serverIPFor(serverID)
	// Raw routes are always HTTPS-capable in Caddy (automatic_https is
	// on by default) unless the user manually carved it out — we treat
	// SSL as always-on for the cert check. A custom cert (CertificateID > 0)
	// skips ACME but still terminates TLS, so the probe applies either way.
	resp := map[string]any{
		"fqdn":         fqdn,
		"expected_ip":  expectedIP,
		"ssl_enabled":  true,
		"proxied":      false,
		"dns_ready":    false,
		"cert_ready":   false,
		"resolved_ips": []string{},
		"dns_skipped":  rr.DNSProvider != "" && rr.DNSSkipRecord,
	}
	if rr.DNSProvider != "" && rr.DNSSkipRecord {
		resp["dns_ready"] = true
	}
	if fqdn == "" {
		resp["error"] = "route has no host matcher"
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	// Raw routes don't carry a DNS provider, but the Cloudflare-proxied
	// toggle is a server-wide setting — if the user has CF proxy on and
	// the domain happens to sit in a CF zone, their A record resolves to
	// CF edge IPs even though the raw route doesn't know about it. Trust
	// the resolved IP shape rather than the setting: if DoH returns a CF
	// edge IP (known-proxied ranges), treat it as proxied.
	var ips []string
	if !rr.DNSSkipRecord {
		if got, dnsErr := s.resolveVerifyA(fqdn); dnsErr == nil {
			ips = got
			resp["resolved_ips"] = got
			if looksLikeCloudflareEdge(got) {
				resp["proxied"] = true
				resp["dns_ready"] = len(got) > 0
			} else if expectedIP != "" {
				for _, ip := range got {
					if ip == expectedIP {
						resp["dns_ready"] = true
						break
					}
				}
			} else {
				resp["dns_ready"] = len(got) > 0
			}
		}
	}
	if resp["dns_ready"] == true {
		proxied, _ := resp["proxied"].(bool)
		resp["cert_ready"] = s.tlsHandshakeOK(serverID, fqdn, proxied, ips)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// rawRouteDeploying renders the deploying-checklist page for advanced
// routes. If the route has no host matcher we fall through to the list —
// there's nothing meaningful to poll on a port-only / path-only route.
func (s *Server) rawRouteDeploying(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	rr, err := models.GetRawRoute(s.DB, id)
	if err != nil || rr == nil {
		http.NotFound(w, r)
		return
	}
	cu := s.currentUser(r)
	if cu != nil && cu.Role != models.RoleAdmin {
		if !s.canManageOwned(cu, rr.OwnerID) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	fqdn := firstRawRouteHost(rr.JSONData)
	if fqdn == "" {
		http.Redirect(w, r, "/raw-routes", http.StatusSeeOther)
		return
	}
	// v2.5.6: if Managed DNS is active on this route, render the "DNS
	// record created in <provider>" step by passing the display name.
	providerName := rr.DNSProvider
	if d, ok := dns.Lookup(rr.DNSProvider); ok {
		providerName = d.DisplayName
	}
	serverID := s.currentServerID(r)
	s.render(w, r, "raw_route_deploying.html", map[string]any{
		"User":         cu,
		"Route":        rr,
		"FirstDomain":  fqdn,
		"ProviderName": providerName,
		"ExpectedIP":   s.serverIPFor(serverID),
		"Section":      "raw",
	})
}

// looksLikeCloudflareEdge is a coarse heuristic to spot CF-proxied A
// records from their resolved IP. We use it on raw routes where the
// explicit "proxied" setting is on proxy hosts only. The ranges below
// are Cloudflare's published IPv4 edge set as of 2024 — keeping this
// small + local (vs. fetching cloudflare.com/ips-v4) avoids a network
// dependency on the deploy-status poll. False positives here just mean
// we dial CF edge with SNI=fqdn instead of Caddy internally, which is
// harmless when the domain really is on CF and correctly fails to
// verify when it isn't.
func looksLikeCloudflareEdge(ips []string) bool {
	// Canonical CF v4 edge CIDRs (from https://www.cloudflare.com/ips-v4).
	cfRanges := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		for _, cidr := range cfRanges {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if n.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

// semverValid returns true for tags like v1.2.3.
func semverValid(v string) bool {
	if len(v) < 6 || v[0] != 'v' {
		return false
	}
	parts := strings.SplitN(v[1:], ".", 3)
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// semverGT returns true when a > b (both must be valid semver like v1.2.3).
func semverGT(a, b string) bool {
	pa := semverParts(a)
	pb := semverParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] > pb[i] {
			return true
		}
		if pa[i] < pb[i] {
			return false
		}
	}
	return false
}

func semverParts(v string) [3]int {
	var out [3]int
	if len(v) > 0 && v[0] == 'v' {
		v = v[1:]
	}
	parts := strings.SplitN(v, ".", 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		out[i], _ = strconv.Atoi(parts[i])
	}
	return out
}

func (s *Server) getBackup(w http.ResponseWriter, r *http.Request) {
	if appdb.BackendOf(s.DB) == appdb.BackendMariaDB {
		http.Error(w, "MariaDB backups are managed by your database server. Use mariadb-dump or your platform's scheduled backup tooling.", http.StatusNotImplemented)
		return
	}
	// Write the VACUUM INTO temp file next to the live DB rather than /tmp.
	// Rationale: the scratch-based final image has no /tmp directory and the
	// process runs as a non-root UID, so `os.TempDir()` returns "/tmp" but
	// SQLite's sqlite3_open_v2 gets CANTOPEN (errcode 14). The directory
	// containing the DB is guaranteed to exist (we just opened the DB from
	// there) and is writable by our UID (we write WAL + SHM there every
	// transaction). Falls back to os.TempDir() only if DBPath wasn't plumbed
	// through — every call site in main.go does plumb it, so the fallback is
	// defence-in-depth against a future constructor regression. v2.7.5.
	ts := time.Now().Format("20060102-150405")
	backupDir := os.TempDir()
	if s.DBPath != "" {
		backupDir = filepath.Dir(s.DBPath)
	}
	tmpPath := filepath.Join(backupDir, fmt.Sprintf("caddyui-backup-%s.db", ts))
	defer os.Remove(tmpPath)

	if _, err := s.DB.Exec("VACUUM INTO ?", tmpPath); err != nil {
		http.Error(w, "backup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	f, err := os.Open(tmpPath)
	if err != nil {
		http.Error(w, "open backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="caddyui-backup-`+ts+`.db"`)
	io.Copy(w, f)
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	// v2.44.0: one page per area; /settings is the first page.
	settingsPage := defaultSettingsSection
	if raw := chi.URLParam(r, "section"); raw != "" {
		if settingsPage = settingsSectionSlug(raw); settingsPage == "" {
			http.NotFound(w, r)
			return
		}
	}
	webhookURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL)
	// v2.12.51: ntfy.sh push channel — load alongside the existing webhook.
	ntfyURL, _ := models.GetSetting(s.DB, settingNotifyNtfyURL)
	ntfyToken, _ := models.GetSetting(s.DB, settingNotifyNtfyToken)
	daysBeforeStr, _ := models.GetSetting(s.DB, settingNotifyDaysBefore)
	daysBefore := defaultNotifyDaysBefore
	if d, err := strconv.Atoi(daysBeforeStr); err == nil && d > 0 {
		daysBefore = d
	}

	// v2.11.15: AI assistant settings. v2.12.36: multi-provider — load
	// every provider's credentials so the form can swap visible fields
	// without losing the inactive providers' values on save.
	aiEnabledStr, _ := models.GetSetting(s.DB, settingAIEnabled)
	aiProvider, _ := models.GetSetting(s.DB, settingAIProvider)
	if aiProvider == "" {
		aiProvider = "ollama"
	}
	aiOllamaURL, _ := models.GetSetting(s.DB, settingAIOllamaURL)
	if aiOllamaURL == "" {
		aiOllamaURL = "http://ollama:11434"
	}
	aiOllamaModel, _ := models.GetSetting(s.DB, settingAIOllamaModel)
	if aiOllamaModel == "" {
		aiOllamaModel = "llama3.2:latest"
	}
	aiOllamaCloudKey, _ := models.GetSetting(s.DB, settingAIOllamaCloudAPIKey)
	aiOllamaCloudModel, _ := models.GetSetting(s.DB, settingAIOllamaCloudModel)
	if aiOllamaCloudModel == "" {
		aiOllamaCloudModel = "qwen3-coder:480b-cloud"
	}
	aiAnthropicKey, _ := models.GetSetting(s.DB, settingAIAnthropicAPIKey)
	aiAnthropicModel, _ := models.GetSetting(s.DB, settingAIAnthropicModel)
	if aiAnthropicModel == "" {
		aiAnthropicModel = "claude-haiku-4-5-20251001"
	}
	aiOpenAIBase, _ := models.GetSetting(s.DB, settingAIOpenAIBaseURL)
	if aiOpenAIBase == "" {
		aiOpenAIBase = "https://api.openai.com/v1"
	}
	aiOpenAIKey, _ := models.GetSetting(s.DB, settingAIOpenAIAPIKey)
	aiOpenAIModel, _ := models.GetSetting(s.DB, settingAIOpenAIModel)
	if aiOpenAIModel == "" {
		aiOpenAIModel = "gpt-4o-mini"
	}
	aiSystemPrompt, _ := models.GetSetting(s.DB, settingAISystemPrompt)
	globalStripHdrs, _ := models.GetSetting(s.DB, settingGlobalStripResponseHeaders)

	smtpHost, _ := models.GetSetting(s.DB, settingSMTPHost)
	smtpPort, _ := models.GetSetting(s.DB, settingSMTPPort)
	smtpUsername, _ := models.GetSetting(s.DB, settingSMTPUsername)
	smtpFrom, _ := models.GetSetting(s.DB, settingSMTPFrom)
	smtpTo, _ := models.GetSetting(s.DB, settingSMTPTo)
	smtpSecurity, _ := models.GetSetting(s.DB, settingSMTPSecurity)
	smtpSkipVerify, _ := models.GetSetting(s.DB, settingSMTPSkipVerify)
	if smtpPort == "" {
		smtpPort = "587"
	}
	if smtpSecurity == "" {
		smtpSecurity = "starttls"
	}
	smtpConfigured := smtpHost != "" && smtpTo != ""

	turnstileSiteKey, _ := models.GetSetting(s.DB, settingTurnstileSiteKey)
	turnstileSecretKey, _ := models.GetSetting(s.DB, settingTurnstileSecretKey)

	// v2.5.0: captcha provider selector + reCAPTCHA keys alongside the
	// existing Turnstile keys. The UI renders a radio (Off / Turnstile /
	// reCAPTCHA); only the active provider's key fields are interactable.
	captchaProvider := normalizeCaptchaProvider(mustGetSetting(s.DB, settingCaptchaProvider))
	recaptchaSiteKey := mustGetSetting(s.DB, settingRecaptchaSiteKey)
	recaptchaSecretKey := mustGetSetting(s.DB, settingRecaptchaSecretKey)
	recaptchaMinScoreRaw := mustGetSetting(s.DB, settingRecaptchaMinScore)
	if strings.TrimSpace(recaptchaMinScoreRaw) == "" {
		recaptchaMinScoreRaw = fmt.Sprintf("%.1f", captchaDefaultMinScore)
	}

	// Timezone — admin-picked IANA zone for rendering timestamps. Empty =
	// fall back to TZ env var then UTC. See timezone.go for the priority
	// order and the dropdown options (commonTimezones).
	timezoneSaved, _ := models.GetSetting(s.DB, settingTimezone)

	serverIP := s.serverIP()
	cfProxiedStr, _ := models.GetSetting(s.DB, settingCFProxied)

	// v2.4.0: per-server public IPs. Load every Caddy server so the DNS
	// card can render one IP input per server. At least one IP is required
	// for managed DNS to work — either a server row has public_ip set or
	// the legacy global fallback is populated.
	caddyServers, _ := models.ListCaddyServers(s.DB)
	accessLogCfg := loadFleetAccessLogConfig(s.DB)
	crowdSecCfg := loadCrowdSecConfig(s.DB)
	metricsCfg := loadPrometheusMetricsConfig(s.DB)
	metricsScrapeTargets := make(map[int64]string, len(caddyServers))
	for _, sr := range caddyServers {
		metricsScrapeTargets[sr.ID] = prometheusScrapeTarget(sr.AdminURL)
	}
	hasAnyServerIP := strings.TrimSpace(serverIP) != ""
	for _, sr := range caddyServers {
		if strings.TrimSpace(sr.PublicIP) != "" {
			hasAnyServerIP = true
			break
		}
	}

	// Build a view-model row per registered DNS provider so the template
	// can render the cards in a simple range loop. Each card gets:
	//   ID, DisplayName, DocsAnchor, Credentials (with "Configured" bool),
	//   Configured (bool summing all credential fields).
	type credView struct {
		dns.CredentialField
		Configured bool
		// Value is the stored plaintext. Only rendered for non-secret fields
		// (Namecheap's API user + whitelisted IP) — secret fields are never
		// echoed back to the page.
		Value string
	}
	type providerView struct {
		ID          string
		DisplayName string
		DocsAnchor  string
		Credentials []credView
		Configured  bool           // every field non-empty
		Enabled     bool           // Configured AND serverIP set
		ExtraFlags  map[string]any // per-provider extras (e.g. Cloudflare proxied toggle)
		// v2.4.7: zone allow-list. ZoneAllowlistRaw is the textarea value
		// (one domain per line for readability); ZoneAllowlist is the parsed
		// slice used to render the "N of M zones visible" hint.
		ZoneAllowlistRaw string
		ZoneAllowlist    []string
	}
	var providers []providerView
	for _, d := range dns.Descriptors() {
		pv := providerView{
			ID:          d.ID,
			DisplayName: d.DisplayName,
			DocsAnchor:  d.DocsAnchor,
			ExtraFlags:  map[string]any{},
		}
		allFilled := true
		for _, c := range d.Credentials {
			v, _ := models.GetSetting(s.DB, c.Key)
			set := v != ""
			if !set && !c.Optional {
				allFilled = false
			}
			cv := credView{CredentialField: c, Configured: set}
			// Only expose stored value back to the page for non-secret fields.
			// Secrets stay keep-blank-to-preserve so they're never rendered
			// even in a password input's value attribute.
			if !c.Secret {
				cv.Value = v
			}
			pv.Credentials = append(pv.Credentials, cv)
		}
		pv.Configured = allFilled
		pv.Enabled = allFilled && hasAnyServerIP
		if d.ID == dns.Cloudflare {
			pv.ExtraFlags["Proxied"] = cfProxiedStr == "1"
		}
		// v2.4.7: load the zone allow-list for this provider so the
		// textarea renders with the current value. Render one domain per
		// line (nicer than CSV for hand-editing).
		pv.ZoneAllowlist = s.zoneAllowlist(d.ID)
		if len(pv.ZoneAllowlist) > 0 {
			pv.ZoneAllowlistRaw = strings.Join(pv.ZoneAllowlist, "\n")
		}
		providers = append(providers, pv)
	}

	// v2.7.0: visitor analytics toggle + IP-exclusion list. Loaded via a
	// helper in analytics.go so both the settings page and the POST handler
	// see the same field names.
	analyticsCfg := loadAnalyticsConfig(s.DB)
	var analyticsIngestSnap map[string]any
	if s.analyticsIngest != nil {
		snap := s.analyticsIngest.Stats()
		analyticsIngestSnap = map[string]any{
			"Connections": snap.Connections,
			"Events":      snap.Events,
			"Excluded":    snap.Excluded,
			"Errors":      snap.Errors,
			"LastEvent":   snap.LastEventAt,
			"Healthy":     snap.Events > 0 && time.Since(snap.LastEventAt) < 10*time.Minute,
		}
	}

	success := r.URL.Query().Get("saved") == "1"
	// "cleared=<provider-id>" is set by postClearDNSProvider's redirect.
	// Resolve it back to the pretty display name so the banner can say
	// "Cloudflare credentials cleared" instead of "cloudflare credentials
	// cleared". Unknown IDs are ignored silently.
	var clearedName string
	if cid := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("cleared"))); cid != "" {
		for _, pv := range providers {
			if pv.ID == cid {
				clearedName = pv.DisplayName
				break
			}
		}
	}
	s.render(w, r, "settings.html", map[string]any{
		"User":          s.currentUser(r),
		"WebhookURL":    webhookURL,
		"WebhookSecret": mustGetSetting(s.DB, settingNotifyWebhookSecret),
		// v2.12.51: ntfy.sh — token uses *Set boolean (not the value) so
		// it never re-renders into the form, same pattern as the v2.12.37
		// API-key fields. URL is fine to render — it's not secret.
		"NtfyURL":             ntfyURL,
		"NtfyTokenSet":        strings.TrimSpace(ntfyToken) != "",
		"DaysBefore":          daysBefore,
		"AIEnabled":           aiEnabledStr == "1",
		"AIProvider":          aiProvider,
		"AIOllamaURL":         aiOllamaURL,
		"AIOllamaModel":       aiOllamaModel,
		"AIOllamaCloudKeySet": strings.TrimSpace(aiOllamaCloudKey) != "",
		"AIOllamaCloudModel":  aiOllamaCloudModel,
		"AIAnthropicKeySet":   strings.TrimSpace(aiAnthropicKey) != "",
		"AIAnthropicModel":    aiAnthropicModel,
		"AIOpenAIBaseURL":     aiOpenAIBase,
		"AIOpenAIKeySet":      strings.TrimSpace(aiOpenAIKey) != "",
		"AIOpenAIModel":       aiOpenAIModel,
		"AISystemPrompt":      aiSystemPrompt,
		"GlobalStripHeaders":  globalStripHdrs,
		"SMTPHost":            smtpHost,
		"SMTPPort":            smtpPort,
		"SMTPUsername":        smtpUsername,
		"SMTPFrom":            smtpFrom,
		"SMTPTo":              smtpTo,
		"SMTPSecurity":        smtpSecurity,
		"SMTPSkipVerify":      smtpSkipVerify == "1",
		"SMTPConfigured":      smtpConfigured,
		"TurnstileSiteKey":    turnstileSiteKey,
		// v2.27.0: secret keys pass as *Set booleans, never as values. Rendering
		// them into <input value="..."> leaked the plaintext through F12 →
		// Elements despite type="password" — same bug fixed for the AI provider
		// keys in v2.12.37 and flagged as outstanding for captcha back then.
		"TurnstileSecretKeySet": strings.TrimSpace(turnstileSecretKey) != "",
		"TurnstileEnabled":      turnstileSiteKey != "" && turnstileSecretKey != "",
		// v2.5.0: captcha provider + reCAPTCHA keys
		"CaptchaProvider":       captchaProvider,
		"CaptchaDisabledByEnv":  captchaDisabledByEnv(),
		"RecaptchaSiteKey":      recaptchaSiteKey,
		"RecaptchaSecretKeySet": strings.TrimSpace(recaptchaSecretKey) != "",
		"RecaptchaMinScore":     recaptchaMinScoreRaw,
		"RecaptchaEnabled":      recaptchaSiteKey != "" && recaptchaSecretKey != "",
		// Timezone: Timezone is the saved DB value (may be ""). TimezoneActive
		// is what the server is *actually* rendering in right now — useful as
		// a "(currently: UTC)" hint when the DB value is empty.
		"Timezone":              timezoneSaved,
		"TimezoneActive":        activeLocation().String(),
		"TimezoneOptions":       commonTimezones,
		"ServerIP":              serverIP,
		"Servers":               caddyServers,
		"DNSProviders":          providers,
		"DNSCredentialProfiles": s.dnsProfileViews(),
		// Back-compat aliases for any embed that still references the old
		// CF-centric keys. The template itself now uses DNSProviders +
		// ServerIP; these stay so custom layouts built against v2.2.x
		// don't crash during the upgrade cycle.
		"CFServerIP": serverIP,
		"CFProxied":  cfProxiedStr == "1",
		// issue #98: verification resolver override for deploy/readiness checks.
		"DNSVerifyResolver": mustGetSetting(s.DB, settingDNSVerifyResolver),
		// issue #100: fleet-wide IP blocklist.
		"GlobalIPBlocklist": mustGetSetting(s.DB, settingGlobalIPBlocklist),
		// issue #104: scheduled backups.
		"BackupScheduleEnabled":  mustGetSetting(s.DB, settingBackupScheduleEnabled) == "1",
		"BackupScheduleDir":      mustGetSetting(s.DB, settingBackupScheduleDir),
		"BackupScheduleInterval": mustGetSetting(s.DB, settingBackupScheduleInterval),
		"BackupScheduleKeep":     mustGetSetting(s.DB, settingBackupScheduleKeep),
		"BackupOK":               r.URL.Query().Get("backupok"),
		"BackupErr":              r.URL.Query().Get("backuperr"),
		// issue #106: OIDC / SSO. The client secret is never rendered back — a
		// bool tells the template whether one is already stored.
		"OIDCEnabled":         mustGetSetting(s.DB, settingOIDCEnabled) == "1",
		"OIDCIssuer":          mustGetSetting(s.DB, settingOIDCIssuer),
		"OIDCClientID":        mustGetSetting(s.DB, settingOIDCClientID),
		"OIDCClientSecretSet": strings.TrimSpace(mustGetSetting(s.DB, settingOIDCClientSecret)) != "",
		"OIDCRedirectURL":     mustGetSetting(s.DB, settingOIDCRedirectURL),
		"OIDCAutoCreate":      mustGetSetting(s.DB, settingOIDCAutoCreate) == "1",
		"OIDCButtonLabel":     mustGetSetting(s.DB, settingOIDCButtonLabel),
		"Success":             success,
		"ClearedName":         clearedName,
		// v2.7.0: analytics card
		"AnalyticsEnabled":           analyticsCfg.Enabled,
		"ExpectationsAutoRollback":   expectationsAutoRollbackEnabled(s), // v2.38.0
		"AnalyticsTarget":            analyticsCfg.TargetRaw,
		"AnalyticsTargetPlaceholder": defaultAnalyticsIngestTarget,
		"AnalyticsExcludeRaw":        analyticsCfg.ExcludeRaw,
		"AnalyticsSoftStart":         analyticsCfg.SoftStart,
		"AnalyticsDialTimeoutSec":    int(analyticsCfg.DialTimeout / time.Second),
		"AnalyticsIngestStats":       analyticsIngestSnap,
		"AnalyticsRetentionDays":     analyticsRetentionDays(s), // v2.43.0
		"AnalyticsStorage":           s.analyticsStorageView(),  // v2.43.0
		// Fleet access logging and CrowdSec integrations (v2.21.0).
		"AccessLogEnabled":        accessLogCfg.Enabled,
		"AccessLogPath":           accessLogCfg.Path,
		"AccessLogFormat":         accessLogCfg.Format,
		"AccessLogScope":          accessLogCfg.Scope,
		"AccessLogRollSize":       accessLogCfg.RollSizeMB,
		"AccessLogRollKeep":       accessLogCfg.RollKeep,
		"AccessLogRollDays":       accessLogCfg.RollKeepDays,
		"AccessLogServerSelected": integrationServerSelection(caddyServers, accessLogCfg.ServerIDs),
		"ClientIPHeaders":         mustGetSetting(s.DB, settingClientIPHeaders),
		"CrowdSecEnabled":         crowdSecCfg.Enabled,
		"CrowdSecAPIURL":          crowdSecCfg.APIURL,
		"CrowdSecAPIKeySet":       strings.TrimSpace(crowdSecCfg.APIKey) != "",
		"CrowdSecStreaming":       crowdSecCfg.Streaming,
		"CrowdSecTicker":          crowdSecCfg.Ticker,
		"CrowdSecHardFails":       crowdSecCfg.HardFails,
		"CrowdSecServerSelected":  integrationServerSelection(caddyServers, crowdSecCfg.ServerIDs),
		"CrowdSecExcludedHosts":   mustGetSetting(s.DB, settingCrowdSecExcludeHost),
		"CrowdSecExcludedPaths":   mustGetSetting(s.DB, settingCrowdSecExcludePath),
		"MetricsEnabled":          metricsCfg.Enabled,
		"MetricsPerHost":          metricsCfg.PerHost,
		"MetricsObserveCatchAll":  metricsCfg.ObserveCatchAllHost,
		"MetricsServerSelected":   integrationServerSelection(caddyServers, metricsCfg.ServerIDs),
		"MetricsScrapeTargets":    metricsScrapeTargets,
		// v2.9.5: 2FA enforcement policy
		"Require2FA":  mustGetSetting(s.DB, settingRequire2FA),
		"RequireTOTP": mustGetSetting(s.DB, settingRequireTOTP),
		// v2.10.0: trusted proxies + custom site title
		"TrustedProxies": mustGetSetting(s.DB, settingTrustedProxies),
		"SiteTitle":      mustGetSetting(s.DB, settingSiteTitle),
		// v2.11.0: custom favicon + admin IP allowlist
		"FaviconURL":     mustGetSetting(s.DB, settingFaviconURL),
		"AdminAllowlist": mustGetSetting(s.DB, settingAdminAllowlist),
		// v2.12.0: configurable session duration + global catch-all 404
		"SessionDays":          mustGetSetting(s.DB, settingSessionDays),
		"CatchAll404HTML":      mustGetSetting(s.DB, settingCatchAll404HTML),
		"GlobalMaintenance":    mustGetSetting(s.DB, settingGlobalMaintenance),
		"AutoSyncHours":        mustGetSetting(s.DB, settingAutoSyncHours),
		"ActivityLogDays":      mustGetSetting(s.DB, settingActivityLogDays),
		"MaxLoginAttempts":     mustGetSetting(s.DB, settingMaxLoginAttempts),
		"DisableHTTP3":         mustGetSetting(s.DB, settingDisableHTTP3),
		"DatabaseBackend":      string(appdb.BackendOf(s.DB)),
		"Section":              "settings",
		"SettingsSection":      settingsPage,                       // v2.44.0
		"SettingsSectionLabel": settingsSectionLabel(settingsPage), // v2.44.0
		"SettingsNav":          settingsSections,                   // v2.44.0
		"SettingsAnchorsJSON":  settingsAnchorsJSON(),              // v2.44.0
	})
}

func (s *Server) postSettings(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	// v2.44.0: the posted page owns a subset of keys; "" is the legacy
	// whole-form post (API clients, old bookmarks) and saves everything.
	settingsPage := settingsSectionSlug(r.FormValue("settings_section"))
	integrationSettingsPresent := r.FormValue("fleet_integrations_present") == "1"
	accessLogFormCfg := loadFleetAccessLogConfig(s.DB)
	crowdSecFormCfg := loadCrowdSecConfig(s.DB)
	metricsFormCfg := loadPrometheusMetricsConfig(s.DB)
	if integrationSettingsPresent {
		var err error
		accessLogFormCfg, err = fleetAccessLogConfigFromForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		previousCrowdSec := crowdSecFormCfg
		crowdSecFormCfg, err = crowdSecConfigFromForm(r, s.DB)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if crowdSecFormCfg.Enabled && (crowdSecConfigFingerprint(previousCrowdSec) != crowdSecConfigFingerprint(crowdSecFormCfg) || strings.TrimSpace(r.FormValue("crowdsec_api_key")) != "") {
			if err := s.validateCrowdSecServers(crowdSecFormCfg); err != nil {
				http.Error(w, "CrowdSec validation failed: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		previousMetrics := metricsFormCfg
		metricsFormCfg, err = prometheusMetricsConfigFromForm(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if metricsFormCfg.Enabled && prometheusMetricsConfigFingerprint(previousMetrics) != prometheusMetricsConfigFingerprint(metricsFormCfg) {
			if err := s.validatePrometheusMetricsServers(metricsFormCfg); err != nil {
				http.Error(w, "Prometheus metrics validation failed: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
	}
	webhookURL := strings.TrimSpace(r.FormValue("webhook_url"))
	webhookSecret := strings.TrimSpace(r.FormValue("webhook_secret"))
	// v2.12.51: ntfy.sh URL stored verbatim; token uses keep-blank-to-preserve
	// (handled below alongside SMTP password to avoid the F12 leak fix from v2.12.37).
	ntfyURL := strings.TrimSpace(r.FormValue("notify_ntfy_url"))
	daysBeforeStr := strings.TrimSpace(r.FormValue("days_before"))
	daysBefore := defaultNotifyDaysBefore
	if d, err := strconv.Atoi(daysBeforeStr); err == nil && d > 0 {
		daysBefore = d
	}

	smtpHost := strings.TrimSpace(r.FormValue("smtp_host"))
	smtpPort := strings.TrimSpace(r.FormValue("smtp_port"))
	smtpUsername := strings.TrimSpace(r.FormValue("smtp_username"))
	smtpPassword := r.FormValue("smtp_password") // keep as-is (may contain spaces)
	smtpFrom := strings.TrimSpace(r.FormValue("smtp_from"))
	smtpTo := strings.TrimSpace(r.FormValue("smtp_to"))
	smtpSecurity := strings.TrimSpace(r.FormValue("smtp_security"))
	// Same hidden+checkbox pattern as analytics_enabled below — scan the
	// full PostForm slice for "1" because FormValue always returns the
	// hidden input's "0" when both are submitted. See note on
	// analytics_enabled for the full story. This toggle had the bug from
	// day one; v2.7.1 fixes it here too so anyone who actually needs to
	// disable TLS cert verification (self-signed SMTP host) can finally
	// persist the setting.
	smtpSkipVerify := "0"
	for _, v := range r.PostForm["smtp_skip_verify"] {
		if v == "1" {
			smtpSkipVerify = "1"
			break
		}
	}
	if smtpPort == "" {
		smtpPort = "587"
	}
	if smtpSecurity == "" {
		smtpSecurity = "starttls"
	}

	turnstileSiteKey := strings.TrimSpace(r.FormValue("turnstile_site_key"))
	// turnstile_secret_key / recaptcha_secret_key are read further down, where
	// they are only persisted when non-empty (v2.27.0 keep-blank-to-preserve).

	// v2.5.0: captcha provider + reCAPTCHA keys. The provider radio
	// submits "off" / "turnstile" / "recaptcha"; normalizeCaptchaProvider
	// coerces anything else to "off" so a tampered POST can't set an
	// unknown mode that would 500 loadCaptchaConfig.
	captchaProvider := normalizeCaptchaProvider(r.FormValue("captcha_provider"))
	recaptchaSiteKey := strings.TrimSpace(r.FormValue("recaptcha_site_key"))
	// reCAPTCHA v3 threshold. Accept any 0.0–1.0 float; out-of-range or
	// unparseable values fall back to the default at load time. We still
	// store what the admin typed (after trim) so the next render of the
	// settings page shows their input, not the silent coercion.
	recaptchaMinScore := strings.TrimSpace(r.FormValue("recaptcha_min_score"))
	if recaptchaMinScore != "" {
		if _, err := strconv.ParseFloat(recaptchaMinScore, 64); err != nil {
			http.Error(w, "invalid recaptcha_min_score: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Timezone — the dropdown submits an IANA zone name (or empty string
	// for "use TZ env / UTC"). The "Other…" option in the UI falls back to
	// a free-text input that submits the same field. Validate via
	// time.LoadLocation; if bad, bail with 400 so we don't silently save
	// garbage the next boot can't decode.
	timezone := strings.TrimSpace(r.FormValue("timezone"))
	if timezone != "" {
		if _, err := time.LoadLocation(timezone); err != nil {
			http.Error(w, "invalid timezone: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	// v2.7.0: analytics toggle + ingest target + exclude-IPs. The target
	// may be blank — loadAnalyticsConfig substitutes the default at read
	// time, so we store the admin's literal input (possibly "").
	//
	// The hidden+checkbox pattern in the template submits
	// "analytics_enabled=0&analytics_enabled=1" when checked (hidden wins
	// submission order per HTML5 tree-order, checkbox is appended after).
	// r.FormValue returns the FIRST value, which is always the hidden "0",
	// so we have to scan the full r.PostForm slice to find the checkbox's
	// "1" when present. Matches the browser's "checked box overrides its
	// hidden sibling" intent. v2.7.1 fix — v2.7.0 used FormValue and the
	// toggle silently always stayed off.
	analyticsEnabled := "0"
	for _, v := range r.PostForm["analytics_enabled"] {
		if v == "1" {
			analyticsEnabled = "1"
			break
		}
	}
	analyticsTarget := strings.TrimSpace(r.FormValue("analytics_ingest_target"))
	// v2.38.0: post-apply checks — same hidden+checkbox pattern as above.
	expectationsAutoRollback := "0"
	for _, v := range r.PostForm["expectations_auto_rollback"] {
		if v == "1" {
			expectationsAutoRollback = "1"
			break
		}
	}
	analyticsExclude := r.FormValue("analytics_exclude_ips") // preserve whitespace for textarea re-render
	currentAnalyticsCfg := loadAnalyticsConfig(s.DB)
	analyticsSoftStart := "0"
	if currentAnalyticsCfg.SoftStart {
		analyticsSoftStart = "1"
	}
	if values, present := r.PostForm["analytics_soft_start"]; present {
		analyticsSoftStart = "0"
		for _, v := range values {
			if v == "1" {
				analyticsSoftStart = "1"
				break
			}
		}
	}
	// v2.43.0: retention days (0 = keep forever).
	analyticsRetention, err := parseAnalyticsRetentionDays(r.FormValue("analytics_retention_days"), analyticsRetentionDays(s))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	analyticsDialTimeoutSec := int(currentAnalyticsCfg.DialTimeout / time.Second)
	if raw, present := r.PostForm["analytics_dial_timeout_sec"]; present && len(raw) > 0 && strings.TrimSpace(raw[0]) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(raw[0]))
		if err != nil || n < 1 || n > 60 {
			http.Error(w, "analytics connection timeout must be between 1 and 60 seconds", http.StatusBadRequest)
			return
		}
		analyticsDialTimeoutSec = n
	}

	// Shared server IP — the public IP every DNS provider writes as its
	// record content. Form field name stays as "cf_server_ip" for
	// backwards compatibility with bookmarked form submissions; the
	// template can submit it under either name.
	newServerIP := strings.TrimSpace(r.FormValue("server_ip"))
	if newServerIP == "" {
		newServerIP = strings.TrimSpace(r.FormValue("cf_server_ip"))
	}
	// Same FormValue/hidden-checkbox bug fix as the other two toggles above.
	// v2.7.1 — previously admins could tick the Cloudflare orange-cloud box
	// and hit Save, and the setting would silently remain off.
	cfProxied := "0"
	for _, v := range r.PostForm["cf_proxied"] {
		if v == "1" {
			cfProxied = "1"
			break
		}
	}
	// Snapshot the current server IP before overwriting — used below to
	// detect whether we need to retarget every managed DNS record.
	oldServerIP := s.serverIP()

	backupSchedEnabled := "0"
	if r.FormValue("backup_schedule_enabled") == "on" {
		backupSchedEnabled = "1"
	}
	oidcEnabled := "0"
	if r.FormValue("oidc_enabled") == "on" {
		oidcEnabled = "1"
	}
	oidcAutoCreate := "0"
	if r.FormValue("oidc_auto_create") == "on" {
		oidcAutoCreate = "1"
	}
	kv := map[string]string{
		settingDNSVerifyResolver: strings.TrimSpace(r.FormValue("dns_verify_resolver")), // issue #98
		settingGlobalIPBlocklist: strings.TrimSpace(r.FormValue("global_ip_blocklist")), // issue #100
		// issue #104: scheduled off-host backups.
		settingBackupScheduleEnabled:  backupSchedEnabled,
		settingBackupScheduleDir:      strings.TrimSpace(r.FormValue("backup_schedule_dir")),
		settingBackupScheduleInterval: strings.TrimSpace(r.FormValue("backup_schedule_interval_hours")),
		settingBackupScheduleKeep:     strings.TrimSpace(r.FormValue("backup_schedule_keep")),
		// issue #106: OIDC / SSO login (client secret handled below, keep-blank).
		settingOIDCEnabled:         oidcEnabled,
		settingOIDCIssuer:          strings.TrimSpace(r.FormValue("oidc_issuer")),
		settingOIDCClientID:        strings.TrimSpace(r.FormValue("oidc_client_id")),
		settingOIDCRedirectURL:     strings.TrimSpace(r.FormValue("oidc_redirect_url")),
		settingOIDCAutoCreate:      oidcAutoCreate,
		settingOIDCButtonLabel:     strings.TrimSpace(r.FormValue("oidc_button_label")),
		settingNotifyWebhookURL:    webhookURL,
		settingNotifyWebhookSecret: webhookSecret,
		settingNotifyNtfyURL:       ntfyURL, // v2.12.51
		settingNotifyDaysBefore:    strconv.Itoa(daysBefore),
		settingSMTPHost:            smtpHost,
		// v2.11.15: AI assistant settings.
		settingAIEnabled: func() string {
			for _, v := range r.PostForm["ai_enabled"] {
				if v == "1" {
					return "1"
				}
			}
			return "0"
		}(),
		settingAIProvider: func() string {
			// v2.12.36: clamp to known provider names so a hand-crafted POST
			// can't poison the dispatch with an unknown value.
			switch strings.TrimSpace(r.FormValue("ai_provider")) {
			case "ollama_cloud":
				return "ollama_cloud"
			case "anthropic":
				return "anthropic"
			case "openai":
				return "openai"
			default:
				return "ollama"
			}
		}(),
		settingAIOllamaURL:        strings.TrimSpace(r.FormValue("ai_ollama_url")),
		settingAIOllamaModel:      strings.TrimSpace(r.FormValue("ai_ollama_model")),
		settingAIOllamaCloudModel: strings.TrimSpace(r.FormValue("ai_ollama_cloud_model")),
		settingAIAnthropicModel:   strings.TrimSpace(r.FormValue("ai_anthropic_model")),
		settingAIOpenAIBaseURL:    strings.TrimSpace(r.FormValue("ai_openai_base_url")),
		settingAIOpenAIModel:      strings.TrimSpace(r.FormValue("ai_openai_model")),
		// v2.12.37: API keys deliberately handled below (not in this map) so an
		// empty submission leaves the existing key intact — same pattern as
		// settingSMTPPassword. Rendering the actual key into the form (as
		// v2.12.36 did) leaked it via F12 → Elements even with type="password".
		settingAISystemPrompt:             r.FormValue("ai_system_prompt"), // preserve whitespace + newlines
		settingGlobalStripResponseHeaders: strings.TrimSpace(r.FormValue("global_strip_response_headers")),
		// v2.14.4: disable HTTP/3 / QUIC for compatibility with older Android clients.
		settingDisableHTTP3: func() string {
			if r.FormValue("disable_http3") == "on" {
				return "1"
			}
			return "0"
		}(),
		// v2.9.5: 2FA enforcement policy (checkbox → "on" when checked).
		settingRequire2FA: func() string {
			if r.FormValue("require_2fa") == "on" {
				return "1"
			}
			return "0"
		}(),
		// require_totp toggle uses value="1" checkbox pattern.
		settingRequireTOTP: func() string {
			if r.FormValue("require_totp") == "1" {
				return "1"
			}
			return "0"
		}(),
		settingSMTPPort:         smtpPort,
		settingSMTPUsername:     smtpUsername,
		settingSMTPFrom:         smtpFrom,
		settingSMTPTo:           smtpTo,
		settingSMTPSecurity:     smtpSecurity,
		settingSMTPSkipVerify:   smtpSkipVerify,
		settingTurnstileSiteKey: turnstileSiteKey,
		settingCaptchaProvider:  captchaProvider,
		settingRecaptchaSiteKey: recaptchaSiteKey,
		// v2.27.0: turnstile/recaptcha secret keys deliberately handled below
		// (not in this map) so an empty submission preserves the stored key —
		// same keep-blank-to-preserve pattern as settingSMTPPassword and the AI
		// provider keys. Site keys stay here: they are public by design.
		settingRecaptchaMinScore: recaptchaMinScore,
		settingTimezone:          timezone,
		settingServerIP:          newServerIP,
		settingCFProxied:         cfProxied,
		// v2.7.0: visitor analytics
		settingAnalyticsEnabled:         analyticsEnabled,
		settingExpectationsAutoRollback: expectationsAutoRollback, // v2.38.0
		settingAnalyticsIngestTarget:    analyticsTarget,
		settingAnalyticsExcludeIPs:      analyticsExclude,
		settingAnalyticsSoftStart:       analyticsSoftStart,
		settingAnalyticsDialTimeoutSec:  strconv.Itoa(analyticsDialTimeoutSec),
		settingAnalyticsRetentionDays:   strconv.Itoa(analyticsRetention), // v2.43.0
		// v2.10.0: trusted proxies + custom site title
		settingTrustedProxies: strings.TrimSpace(r.FormValue("trusted_proxies")),
		settingSiteTitle:      strings.TrimSpace(r.FormValue("site_title")),
		// v2.11.0: custom favicon + admin IP allowlist
		settingFaviconURL:     strings.TrimSpace(r.FormValue("favicon_url")),
		settingAdminAllowlist: strings.TrimSpace(r.FormValue("admin_allowlist")),
		// v2.12.0: configurable session duration + global catch-all 404
		settingCatchAll404HTML: strings.TrimSpace(r.FormValue("catch_all_404_html")),
		// Global maintenance mode: checkbox → "1"/"0"
		settingGlobalMaintenance: func() string {
			if r.FormValue("global_maintenance") == "1" {
				return "1"
			}
			return "0"
		}(),
	}
	if integrationSettingsPresent {
		for key, value := range fleetIntegrationSettings(accessLogFormCfg, crowdSecFormCfg, metricsFormCfg, r.FormValue("client_ip_headers")) {
			kv[key] = value
		}
		if key := strings.TrimSpace(r.FormValue("crowdsec_api_key")); key != "" {
			kv[settingCrowdSecAPIKey] = key
		}
	}
	if sessionDays := strings.TrimSpace(r.FormValue("session_duration_days")); sessionDays != "" {
		kv[settingSessionDays] = sessionDays
	}
	// Auto-sync hours: "0" or empty = disabled.
	if autoSyncHours := strings.TrimSpace(r.FormValue("auto_sync_hours")); autoSyncHours != "" {
		if h, err := strconv.Atoi(autoSyncHours); err == nil && h >= 0 {
			kv[settingAutoSyncHours] = strconv.Itoa(h)
		}
	} else {
		kv[settingAutoSyncHours] = "0"
	}
	// Activity log retention days: 0 = keep forever.
	if aldStr := strings.TrimSpace(r.FormValue("activity_log_days")); aldStr != "" {
		if d, err := strconv.Atoi(aldStr); err == nil && d >= 0 {
			kv[settingActivityLogDays] = strconv.Itoa(d)
		}
	} else {
		kv[settingActivityLogDays] = "0"
	}
	// Max login attempts per IP: 0 = no limit.
	if mlaStr := strings.TrimSpace(r.FormValue("max_login_attempts")); mlaStr != "" {
		if n, err := strconv.Atoi(mlaStr); err == nil && n >= 0 {
			kv[settingMaxLoginAttempts] = strconv.Itoa(n)
		}
	} else {
		kv[settingMaxLoginAttempts] = "0"
	}

	// Walk every registered DNS provider and pick up credential fields
	// from the form. Same keep-blank-to-preserve UX as SMTP password:
	// leaving a field empty keeps the stored value, so users don't have
	// to re-enter secrets just to toggle a checkbox. Non-secret fields
	// (for example Namecheap's API user/client IP and Route 53's region/
	// access-key ID) are always overwritten so users can edit or clear them.
	// v2.44.0: provider credentials and allow-lists only exist on the DNS
	// page; collecting them from any other page would clear them.
	if settingsPage == "" || settingsPage == "dns" {
		for _, d := range dns.Descriptors() {
			for _, c := range d.Credentials {
				v := strings.TrimSpace(r.FormValue(c.Key))
				if v == "" && c.Secret {
					// Empty + secret field → preserve existing value.
					continue
				}
				kv[c.Key] = v
			}
			// v2.4.7: per-provider zone allow-list. Always overwrite — an
			// empty textarea means "remove the allow-list, accept every zone
			// again". Normalised form (lowercase, deduped, comma-separated)
			// is what we persist, even though the textarea offers lines for
			// readability.
			allowRaw := r.FormValue(d.ID + "_zone_allowlist")
			kv[zoneAllowlistKey(d.ID)] = strings.Join(parseZoneAllowlist(allowRaw), ",")
		}
	}
	// v2.44.0: client_ip_headers lives on the Security page but is saved by
	// the integrations bundle above; save it directly when its field posted.
	if _, present := r.PostForm["client_ip_headers"]; present && !integrationSettingsPresent {
		kv[settingClientIPHeaders] = strings.TrimSpace(r.FormValue("client_ip_headers"))
	}
	if _, ok := r.PostForm["dns_profile_name"]; ok {
		if err := s.saveDNSProfiles(s.parseDNSProfilesForm(r)); err != nil {
			http.Error(w, "failed to save DNS profiles: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// SMTP password stays keep-blank-to-preserve.
	if smtpPassword != "" {
		kv[settingSMTPPassword] = smtpPassword
	}
	// issue #106: OIDC client secret — keep-blank-to-preserve, like other secrets.
	if v := r.FormValue("oidc_client_secret"); strings.TrimSpace(v) != "" {
		kv[settingOIDCClientSecret] = strings.TrimSpace(v)
	}
	// v2.27.0: captcha secret keys — same keep-blank-to-preserve pattern. The
	// Settings template no longer renders them into the form, so a blank field
	// means "keep the stored value", not "clear it". To actually clear a key,
	// switch the captcha provider off.
	if k := strings.TrimSpace(r.FormValue("turnstile_secret_key")); k != "" {
		kv[settingTurnstileSecretKey] = k
	}
	if k := strings.TrimSpace(r.FormValue("recaptcha_secret_key")); k != "" {
		kv[settingRecaptchaSecretKey] = k
	}
	// v2.12.37: AI provider API keys — same keep-blank-to-preserve pattern.
	// Only persist when the user typed a fresh value; an empty submission
	// means "keep what's already stored." The Settings template never
	// renders the saved key into the form (F12 leak fix from v2.12.36).
	if k := strings.TrimSpace(r.FormValue("ai_ollama_cloud_api_key")); k != "" {
		kv[settingAIOllamaCloudAPIKey] = k
	}
	if k := strings.TrimSpace(r.FormValue("ai_anthropic_api_key")); k != "" {
		kv[settingAIAnthropicAPIKey] = k
	}
	if k := strings.TrimSpace(r.FormValue("ai_openai_api_key")); k != "" {
		kv[settingAIOpenAIAPIKey] = k
	}
	// v2.12.51: ntfy bearer token — same keep-blank-to-preserve pattern
	// so the value never re-renders into the form.
	if t := strings.TrimSpace(r.FormValue("notify_ntfy_token")); t != "" {
		kv[settingNotifyNtfyToken] = t
	}
	// v2.44.0: keep only the keys the posted page owns.
	if settingsPage != "" {
		for k := range kv {
			if owner, known := settingsKeySection[k]; known && owner != settingsPage {
				delete(kv, k)
			}
		}
	}
	for k, v := range kv {
		if err := models.SetSetting(s.DB, k, v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Hot-apply the timezone: updates the atomic pointer every template
	// fmtDate call reads from, so the redirect back to /settings below
	// already renders in the new zone without waiting for a restart. Error
	// is ignored — we already validated above, so LoadLocation can't fail
	// here barring a race with tzdata being unloaded (won't happen in a
	// container with /usr/share/zoneinfo baked in).
	if settingsPage == "" || settingsPage == "general" {
		_ = setActiveLocation(timezone)
	}
	activityDetail := "notify+smtp"
	if settingsPage != "" {
		activityDetail = "page:" + settingsPage
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "settings_update", activityDetail, smtpHost, true)

	// v2.7.0: push the analytics toggle through to the live ingest +
	// Caddy admin API after saving to the settings table. Errors are
	// logged but not surfaced as a page error — the saved row stays, and
	// the Settings page's "Analytics" card reflects the current wiring
	// state so the admin can retry. This avoids a half-saved "settings
	// didn't persist, Caddy pivoted anyway" that would be very confusing.
	if settingsPage == "" || settingsPage == "analytics" {
		if err := s.applyAnalyticsToggle(loadAnalyticsConfig(s.DB)); err != nil {
			log.Printf("settings: analytics toggle: %v", err)
		}
		// The certificate monitor shares the analytics ingest target even when
		// visitor analytics itself is disabled. Refresh it after target/timeout
		// changes so lifecycle events keep flowing to the right listener.
		if err := s.ReconcileCertificateLogs(); err != nil {
			log.Printf("settings: certificate log monitoring: %v", err)
		}
	}

	// v2.4.0: per-server public IP update. The settings form submits one
	// server_ip_<id> field per Caddy server. For each one that changed,
	// retarget only that server's managed DNS records in the background.
	//
	// We collect both the IDs whose IP changed and the new IP each maps to,
	// then fan out one goroutine per server. No fan-out if nothing changed.
	if servers, err := models.ListCaddyServers(s.DB); err == nil {
		type retarget struct {
			serverID int64
			newIP    string
		}
		var pending []retarget
		for _, sr := range servers {
			field := fmt.Sprintf("server_ip_%d", sr.ID)
			// Only act if the form actually submitted this field — guards
			// against accidental wipes from partial form POSTs.
			if _, ok := r.Form[field]; !ok {
				continue
			}
			newIP := strings.TrimSpace(r.FormValue(field))
			old, err := models.SetCaddyServerPublicIP(s.DB, sr.ID, newIP)
			if err != nil {
				log.Printf("settings: save public_ip for server %d: %v", sr.ID, err)
				continue
			}
			if newIP != "" && newIP != strings.TrimSpace(old) {
				pending = append(pending, retarget{serverID: sr.ID, newIP: newIP})
			}
		}
		for _, t := range pending {
			sid, ip := t.serverID, t.newIP
			go s.dnsUpdateAllRecords(sid, ip)
		}
	}

	// Legacy global-IP fallback retarget: only fires when the per-server
	// table is empty (brand-new databases or users who haven't filled in
	// the new per-server column). Passing serverID=0 walks every managed
	// host so pre-v2.4.0 behaviour still works.
	if newServerIP != "" && newServerIP != oldServerIP {
		go s.dnsUpdateAllRecords(0, newServerIP)
	}

	// v2.12.18: auto-sync Caddy after a settings save so changes that
	// affect the live config (global strip-headers, catch-all 404 HTML,
	// global maintenance toggle, etc.) take effect immediately. Without
	// this, users had to manually click Sync Caddy after Save and
	// wondered why their setting "didn't work." Best-effort — failures
	// are logged but don't block the redirect.
	serverIDsToSync := []int64{s.currentServerID(r)}
	if integrationSettingsPresent {
		serverIDsToSync = serverIDsToSync[:0]
		if servers, err := models.ListCaddyServers(s.DB); err == nil {
			for _, srv := range servers {
				if srv.Type != models.CaddyServerTypeExternal {
					serverIDsToSync = append(serverIDsToSync, srv.ID)
				}
			}
		}
	}
	if settingsSectionSyncsCaddy(settingsPage) { // v2.44.0
		go func(serverIDs []int64) {
			// syncCaddy temporarily swaps s.Caddy, so fleet syncs stay sequential.
			for _, serverID := range serverIDs {
				if err := s.syncCaddy(serverID, false); err != nil {
					log.Printf("settings: auto-sync server %d after save failed (non-fatal): %v", serverID, err)
				}
			}
		}(serverIDsToSync)
	}

	if settingsPage != "" {
		http.Redirect(w, r, "/settings/"+settingsPage+"?saved=1", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// postClearDNSProvider wipes every stored credential for a single DNS
// provider (and its provider-specific flags, e.g. Cloudflare's cf_proxied
// toggle). The provider ID comes from the URL path. Storing an empty string
// via SetSetting is how we "delete" — GetSetting returns "" for both
// "never written" and "written as empty", and every dns.Build call treats
// empty strings as "provider not configured".
//
// Admin-gated at the router level; also logs an audit entry so a
// credential wipe is traceable the same way a save is.
func (s *Server) postClearDNSProvider(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "id")))
	keys, ok := dnsProviderCredKeys[id]
	if !ok {
		http.Error(w, "unknown DNS provider", http.StatusBadRequest)
		return
	}

	for _, k := range keys {
		if err := models.SetSetting(s.DB, k, ""); err != nil {
			http.Error(w, "failed to clear credentials: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Cloudflare also stores a per-provider flag (orange-cloud proxied) that
	// should be reset alongside the API token — otherwise re-entering a
	// token later would silently inherit the previous proxied state.
	if id == dns.Cloudflare {
		_ = models.SetSetting(s.DB, settingCFProxied, "")
	}
	// v2.4.7: also clear the zone allow-list. A user wiping the credentials
	// usually wants a clean slate — a stale allow-list sitting around means
	// the next set of keys they enter would silently be restricted by rules
	// they've forgotten about.
	_ = models.SetSetting(s.DB, zoneAllowlistKey(id), "")

	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r),
		"dns_provider_clear", "dns:"+id, "", true)

	http.Redirect(w, r, "/settings/dns?cleared="+url.QueryEscape(id), http.StatusSeeOther)
}

func (s *Server) postTestWebhook(w http.ResponseWriter, r *http.Request) {
	// Always read the webhook URL from the trusted database — never from the
	// request body — to prevent server-side request forgery (SSRF).
	webhookURL, _ := models.GetSetting(s.DB, settingNotifyWebhookURL)
	if webhookURL == "" {
		http.Error(w, "No webhook URL configured. Save your settings first.", http.StatusBadRequest)
		return
	}
	// Validate that the stored URL is a safe http/https endpoint.
	parsedWebhook, parseErr := url.Parse(webhookURL)
	if parseErr != nil || (parsedWebhook.Scheme != "http" && parsedWebhook.Scheme != "https") || parsedWebhook.Host == "" {
		http.Error(w, "Invalid webhook URL in settings — must begin with http:// or https://", http.StatusBadRequest)
		return
	}
	payload := map[string]any{
		"event":     "test",
		"message":   "CaddyUI webhook test",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(parsedWebhook.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Webhook POST failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	_ = resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"status_code": resp.StatusCode,
	})
}

func (s *Server) postTestEmail(w http.ResponseWriter, r *http.Request) {
	subject := "[CaddyUI] Test email"
	body := fmt.Sprintf(
		"This is a test notification from CaddyUI.\n\nIf you received this, your SMTP configuration is working correctly.\n\nSent at: %s\n",
		time.Now().UTC().Format(time.RFC3339),
	)
	if err := sendEmail(s.DB, subject, body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
