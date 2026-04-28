package server

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Settings-table keys for the v2.7.0 visitor-analytics feature. All three
// are stored as plain strings via models.GetSetting/SetSetting.
const (
	// settingAnalyticsEnabled is "1" when the admin has turned on access-log
	// ingestion. Controls whether postSettings calls the Caddy admin API to
	// install the net-writer logger — the ingest listener itself runs all
	// the time (see main.go), this just controls whether Caddy feeds it.
	settingAnalyticsEnabled = "analytics_enabled"

	// settingAnalyticsIngestTarget is the host:port Caddy connects to to
	// ship logs. Defaults to "caddyui:9019" which is the container-hostname
	// the docker-compose file in the README uses. On host-network
	// deployments an admin can override to "host.docker.internal:9019" or
	// similar. We store what the admin typed (after trim) rather than the
	// effective value — the handler substitutes the default only when the
	// field is blank.
	settingAnalyticsIngestTarget = "analytics_ingest_target"

	// settingAnalyticsExcludeIPs is a newline-or-comma separated list of
	// plain IPs and CIDR blocks whose events should be dropped before the
	// DB insert. Typical entries: your home LAN ("10.0.0.0/8"), a VPN
	// subnet, the office public IP, an uptime-monitor provider's /24.
	settingAnalyticsExcludeIPs = "analytics_exclude_ips"

	// defaultAnalyticsIngestTarget is what the ingest configuration card
	// pre-fills when no value has been saved yet. Chosen to match the
	// docker-compose example in the README — a copy-paste config that
	// works out of the box for users who didn't customise their stack.
	defaultAnalyticsIngestTarget = "caddyui:9019"
)

// loadAnalyticsConfig reads the three analytics settings into a tidy struct.
// Called both by the /settings handler (to render the form) and by the
// save-then-enable path below (to know what target to pass to EnableAccessLogs).
type analyticsConfig struct {
	Enabled      bool
	Target       string   // host:port, resolved (default applied if blank)
	TargetRaw    string   // the admin's literal input, possibly ""
	ExcludeIPs   []string // one entry per line of the admin's list
	ExcludeRaw   string   // the admin's literal textarea value, for re-render
}

func loadAnalyticsConfig(db *sql.DB) analyticsConfig {
	cfg := analyticsConfig{
		Enabled:    mustGetSetting(db, settingAnalyticsEnabled) == "1",
		TargetRaw:  strings.TrimSpace(mustGetSetting(db, settingAnalyticsIngestTarget)),
		ExcludeRaw: mustGetSetting(db, settingAnalyticsExcludeIPs),
	}
	cfg.Target = cfg.TargetRaw
	if cfg.Target == "" {
		cfg.Target = defaultAnalyticsIngestTarget
	}
	cfg.ExcludeIPs = parseExcludeIPs(cfg.ExcludeRaw)
	return cfg
}

// parseExcludeIPs splits a raw textarea value into entries. Accepts commas
// and/or newlines as separators so admins can paste either format. Blank
// entries are dropped; order is preserved; no dedup (the ingest checks
// nets in O(n), so preserving admin intent is more valuable than a tiny
// speedup from dedup on what's typically <10 entries).
func parseExcludeIPs(raw string) []string {
	if raw == "" {
		return nil
	}
	// Unify separators: replace commas with newlines, then Fields-on-newline.
	raw = strings.ReplaceAll(raw, ",", "\n")
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// applyAnalyticsToggle is called from postSettings after the three settings
// keys have been saved. It does two things:
//
//  1. Pushes the new exclude-IP list to the live ingest listener so the
//     change is visible immediately without a restart.
//  2. Enables or disables Caddy's access-log forwarding via the admin API
//     depending on the toggle state. Enable+already-enabled re-pushes the
//     target so a changed target takes effect on save.
//
// v2.7.6: applies the toggle to *every* registered Caddy server, not just
// the primary. Before this, only s.Caddy (the CADDY_ADMIN_URL primary) got
// reconfigured — secondary servers added via /servers kept their default
// "no access logs" state, so events from those servers never reached the
// ingest. An admin picking a secondary in the /analytics server filter saw
// "no data" even when the server was live and serving real traffic.
// External-type servers are skipped (read-only from CaddyUI's point of view
// — we can't push config changes to them).
//
// Errors from individual servers are collected into a single aggregated
// error rather than short-circuiting on the first failure — one unreachable
// Caddy shouldn't stop us configuring the other three.
func (s *Server) applyAnalyticsToggle(cfg analyticsConfig) error {
	// Push exclude list to the ingest regardless of enable state — even
	// when disabled, keeping the filter in sync means a later re-enable
	// picks up whatever the admin configured in the meantime.
	if s.analyticsIngest != nil {
		s.analyticsIngest.SetExcludeIPs(cfg.ExcludeIPs)
	}

	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		return fmt.Errorf("list caddy servers: %w", err)
	}

	// Fallback: on a fresh install that hasn't seeded any server rows yet
	// (the SeedBootstrapServer step in main.go hasn't run, or the DB lost
	// its servers row), fall back to the pre-2.7.6 behaviour and toggle
	// via s.Caddy directly so the first-boot analytics enable still works.
	if len(servers) == 0 {
		if cfg.Enabled {
			if err := s.Caddy.EnableAccessLogs(cfg.Target); err != nil {
				return fmt.Errorf("enable access logs: %w", err)
			}
			return nil
		}
		if err := s.Caddy.DisableAccessLogs(); err != nil {
			return fmt.Errorf("disable access logs: %w", err)
		}
		return nil
	}

	var errMsgs []string
	for _, sr := range servers {
		// External servers are read-only — we can't reconfigure them via
		// the admin API, so skip silently. The typical case is a Caddy
		// managed by a different tool that CaddyUI is observing but not
		// authoritative over.
		if sr.Type == models.CaddyServerTypeExternal {
			continue
		}
		cli := newCaddyClient(sr.AdminURL, sr.AdminUsername, sr.AdminPassword)
		if cfg.Enabled {
			if err := cli.EnableAccessLogs(cfg.Target); err != nil {
				errMsgs = append(errMsgs, fmt.Sprintf("server %q (%s): enable: %v", sr.Name, sr.AdminURL, err))
				continue
			}
		} else {
			if err := cli.DisableAccessLogs(); err != nil {
				errMsgs = append(errMsgs, fmt.Sprintf("server %q (%s): disable: %v", sr.Name, sr.AdminURL, err))
				continue
			}
		}
	}
	if len(errMsgs) > 0 {
		return fmt.Errorf("analytics toggle: %s", strings.Join(errMsgs, "; "))
	}
	return nil
}

// userAllowedHosts returns the list of host strings (as Caddy would see them
// in http.log.access.request.host) that the given user is allowed to see
// analytics for. Admins get nil, which callers interpret as "no filter".
// Non-admins get the union of their owned proxy-host domains and raw-route
// names across every Caddy server in the DB — analytics is cross-server by
// default (one dashboard for the whole fleet).
//
// Thin wrapper over scopedHostsForAnalytics — preserved as a separate name
// for callers that don't yet pass a server scope.
func (s *Server) userAllowedHosts(u *models.User) ([]string, error) {
	return s.scopedHostsForAnalytics(u, 0)
}

// scopedHostsForAnalytics returns the set of hosts a user is allowed to see
// analytics for, optionally narrowed to a single Caddy server. v2.7.1
// added the `serverID` parameter to power the inline server-filter UI on
// /analytics — admins with 5+ servers were swamped by a fleet-wide dashboard
// and wanted to focus on one at a time.
//
//	serverID == 0 → cross-fleet scope (legacy behaviour).
//	  - admin    → nil (means "no host filter", single-query hot path).
//	  - non-admin → union of owned hosts across every server.
//
//	serverID > 0 → scoped to that one server.
//	  - admin    → every host routed by that server (a *concrete* list so
//	              the existing per-host-list query paths apply).
//	  - non-admin → intersection of "owned" with "routed by this server"
//	              (i.e. the same ListProxyHosts/ListRawRoutes call with
//	              viewerID + isAdmin=false).
//
// The host list is lowercased + deduped so downstream SQL IN-clauses don't
// have to worry about case or repeats.
func (s *Server) scopedHostsForAnalytics(u *models.User, serverID int64) ([]string, error) {
	if u == nil {
		return []string{}, nil
	}
	isAdmin := u.Role == models.RoleAdmin
	// Cross-fleet + admin → no filter. Single-query hot path through
	// AccessTotalsSince("") / TopHostsSince(...).
	if isAdmin && serverID == 0 {
		return nil, nil
	}

	var servers []models.CaddyServer
	if serverID > 0 {
		// Single-server scope — fetch just that one and proceed with a
		// one-element loop. Missing/unknown server_id returns empty hosts
		// rather than an error so a stale query-string doesn't 500 the
		// page; the UI picker will re-render with "All servers" selected.
		sr, err := models.GetCaddyServer(s.DB, serverID)
		if err != nil || sr == nil {
			return []string{}, nil
		}
		servers = []models.CaddyServer{*sr}
	} else {
		// Cross-fleet non-admin: every server.
		var err error
		servers, err = models.ListCaddyServers(s.DB)
		if err != nil {
			return nil, err
		}
	}

	// viewerID is only consulted when isAdmin=false. For admin + specific
	// server we pass ID=0 + isAdmin=true so the ListProxyHosts path returns
	// every row; non-admin passes the user's ID + isAdmin=false so only
	// owned rows come back.
	viewerID := int64(0)
	queryAsAdmin := true
	var peers []int64
	if !isAdmin {
		viewerID = u.ID
		queryAsAdmin = false
		// v2.7.4: analytics visibility follows list visibility — if a user can
		// see a teammate's proxy host on the hosts page, they should also see
		// its traffic in the analytics picker.
		peers, _ = models.GroupPeerIDs(s.DB, u.ID)
	}

	var hosts []string
	seen := make(map[string]bool)
	add := func(raw string) {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		hosts = append(hosts, d)
	}
	for _, sr := range servers {
		proxies, err := models.ListProxyHosts(s.DB, sr.ID, viewerID, queryAsAdmin, peers)
		if err != nil {
			return nil, err
		}
		for _, p := range proxies {
			for _, d := range p.DomainList() {
				add(d)
			}
		}
		// v2.12.17: include redirection hosts in analytics scope. The
		// access-log ingest tags every request by hostname regardless of
		// what handler served it (proxy / redirect / raw), so leaving
		// redirections out meant the dashboard cards undercounted users
		// who land on a redirect, follow it, and produce two access_events
		// — one for the source hostname (redirect) and one for the target
		// (proxy). Only the target was being counted.
		redirs, err := models.ListRedirectionHosts(s.DB, sr.ID, viewerID, queryAsAdmin, peers)
		if err != nil {
			return nil, err
		}
		for _, rh := range redirs {
			for _, d := range rh.DomainList() {
				add(d)
			}
		}
		raws, err := models.ListRawRoutes(s.DB, sr.ID, viewerID, queryAsAdmin, peers)
		if err != nil {
			return nil, err
		}
		for _, r := range raws {
			// RawRoute doesn't have a DomainList() like ProxyHost —
			// hostnames live inside the JSONData blob's match[].host[]
			// array. rawRouteHosts (server.go) is the canonical extractor.
			for _, d := range rawRouteHosts(r) {
				add(d)
			}
		}
	}
	return hosts, nil
}

// getAnalytics renders the /analytics overview page. Shows totals (today +
// last 7d), the "live now" visitor count, a per-host table, a 24-hour
// hourly sparkline, and a status-code breakdown. Scope is admin-see-all
// vs non-admin-see-only-my-hosts, driven by scopedHostsForAnalytics above.
//
// v2.7.1 added the `?server=<id>` query-param for the inline server filter
// — an admin with 5+ Caddy servers can now narrow the dashboard to one
// server without changing their global CurrentServer selection.
func (s *Server) getAnalytics(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)

	// v2.12.13: bare /analytics now defaults to the picker-active server
	// (s.currentServerID), not the cross-fleet view. The all-fleet rollup
	// is the slow path on multi-server installs; users almost always want
	// "show me what's happening on the server I picked." Explicit
	// ?server=all (or ?server=0 for back-compat with old bookmarks)
	// still gets you the cross-fleet view.
	var serverScopeID int64
	q := r.URL.Query()
	if q.Has("server") {
		raw := strings.TrimSpace(q.Get("server"))
		switch raw {
		case "", "0", "all":
			serverScopeID = 0
		default:
			if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
				serverScopeID = n
			}
		}
	} else {
		serverScopeID = s.currentServerID(r)
	}

	allowedHosts, err := s.scopedHostsForAnalytics(u, serverScopeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	isAdmin := u != nil && u.Role == models.RoleAdmin
	// If we have a concrete scope — either non-admin anywhere or admin
	// picking a specific server — treat it as per-host filter mode. The
	// hot "nil allowedHosts = no filter" path only kicks in for admin
	// viewing the full fleet.
	//
	// When an admin picks a server that has no routes at all, allowedHosts
	// comes back as an empty non-nil slice. We still want the totals to
	// show 0 rather than all-fleet, so "scoped" stays true and the per-host
	// loops below execute with an empty list (zero iterations, zero sums).
	scoped := allowedHosts != nil
	allServers, _ := models.ListCaddyServers(s.DB)

	now := time.Now()
	// UTC midnight boundaries — access_events stores unix seconds, so all
	// windows compute against time.Unix. "Today" here means "since local
	// midnight in the active timezone" so the card matches what admins
	// read on the clock, not an arbitrary UTC cutoff.
	loc := activeLocation()
	todayStart := time.Date(now.In(loc).Year(), now.In(loc).Month(), now.In(loc).Day(), 0, 0, 0, 0, loc)
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)
	twentyFourHoursAgo := now.Add(-24 * time.Hour)

	// Filter helper: unscoped (admin + no server filter) sees everything via
	// a single-query hot path. Scoped (non-admin anywhere, or admin with
	// ?server=<id>) loops per-host and sums, because a 20-way IN clause on
	// every aggregate query is slower than 20 indexed single-host lookups
	// — and keeps AccessTotalsSince's public signature uncluttered.
	var (
		todayTotals  models.AccessTotals
		sevenTotals  models.AccessTotals
		liveVisitors int
	)
	if !scoped {
		var err2 error
		todayTotals, err2 = models.AccessTotalsSince(s.DB, todayStart, "")
		if err2 != nil {
			log.Printf("analytics: AccessTotalsSince(today): %v", err2)
		}
		sevenTotals, err2 = models.AccessTotalsSince(s.DB, sevenDaysAgo, "")
		if err2 != nil {
			log.Printf("analytics: AccessTotalsSince(7d): %v", err2)
		}
		liveVisitors, err2 = models.AccessLiveVisitors(s.DB, 5*time.Minute)
		if err2 != nil {
			log.Printf("analytics: AccessLiveVisitors: %v", err2)
		}
	} else {
		for _, h := range allowedHosts {
			t1, _ := models.AccessTotalsSince(s.DB, todayStart, h)
			todayTotals.Views += t1.Views
			todayTotals.Visitors += t1.Visitors
			t7, _ := models.AccessTotalsSince(s.DB, sevenDaysAgo, h)
			sevenTotals.Views += t7.Views
			sevenTotals.Visitors += t7.Visitors
		}
		// Live: distinct IPs across owned hosts. Per-host counts aren't
		// additive (an IP visiting two hosts would double-count), so we
		// union in code rather than sum.
		liveVisitors = s.liveVisitorsAcrossHosts(allowedHosts, 5*time.Minute)
	}

	// Per-host table: top 50 by views in last 7 days.
	var hostRows []models.HostStats
	if !scoped {
		var err2 error
		hostRows, err2 = models.TopHostsSince(s.DB, sevenDaysAgo, 50)
		if err2 != nil {
			log.Printf("analytics: TopHostsSince: %v", err2)
		}
	} else {
		var err2 error
		hostRows, err2 = models.HostStatsForHosts(s.DB, sevenDaysAgo, allowedHosts)
		if err2 != nil {
			log.Printf("analytics: HostStatsForHosts: %v", err2)
		}
	}

	// 24h hourly sparkline: fill zero-buckets so the chart doesn't jump.
	bucketSec := int64(3600) // 1h buckets
	var rawBuckets []models.HourlyBucket
	if !scoped {
		var err2 error
		rawBuckets, err2 = models.AccessBuckets(s.DB, twentyFourHoursAgo, now, bucketSec, "")
		if err2 != nil {
			log.Printf("analytics: AccessBuckets(unscoped): %v", err2)
		}
	} else {
		// Scoped path needs per-host buckets summed. AccessBuckets takes a
		// single host string, so loop and merge by hour.
		merged := make(map[int64]models.HourlyBucket)
		for _, h := range allowedHosts {
			bs, _ := models.AccessBuckets(s.DB, twentyFourHoursAgo, now, bucketSec, h)
			for _, b := range bs {
				key := b.Hour.Unix()
				m := merged[key]
				m.Hour = b.Hour
				m.Views += b.Views
				m.Visitors += b.Visitors
				merged[key] = m
			}
		}
		for _, b := range merged {
			rawBuckets = append(rawBuckets, b)
		}
	}
	sparkline := fillBuckets(rawBuckets, twentyFourHoursAgo, now, bucketSec)

	// Bandwidth (bytes_out) sparkline — same window and bucket as request sparkline.
	var bwBuckets []models.BandwidthBucket
	if !scoped {
		bwBuckets, _ = models.BandwidthBuckets(s.DB, twentyFourHoursAgo, now, bucketSec, "")
	} else {
		bwMap := make(map[int64]models.BandwidthBucket)
		for _, h := range allowedHosts {
			bs, _ := models.BandwidthBuckets(s.DB, twentyFourHoursAgo, now, bucketSec, h)
			for _, b := range bs {
				key := b.Hour.Unix()
				m := bwMap[key]
				m.Hour = b.Hour
				m.BytesOut += b.BytesOut
				bwMap[key] = m
			}
		}
		for _, b := range bwMap {
			bwBuckets = append(bwBuckets, b)
		}
	}
	// Fill zero-gaps.
	bwSparkline := fillBandwidthBuckets(bwBuckets, twentyFourHoursAgo, now, bucketSec)
	// Compute total and max bandwidth for the template.
	var bwTotal, bwMax int64
	for _, b := range bwSparkline {
		bwTotal += b.BytesOut
		if b.BytesOut > bwMax {
			bwMax = b.BytesOut
		}
	}
	if bwMax == 0 {
		bwMax = 1
	}

	// Status-class pie.
	var statusBuckets models.StatusBuckets
	if !scoped {
		var err2 error
		statusBuckets, err2 = models.StatusBucketsSince(s.DB, sevenDaysAgo, "")
		if err2 != nil {
			log.Printf("analytics: StatusBucketsSince(unscoped): %v", err2)
		}
	} else {
		for _, h := range allowedHosts {
			b, err2 := models.StatusBucketsSince(s.DB, sevenDaysAgo, h)
			if err2 != nil {
				log.Printf("analytics: StatusBucketsSince(%s): %v", h, err2)
				continue
			}
			statusBuckets.S2xx += b.S2xx
			statusBuckets.S3xx += b.S3xx
			statusBuckets.S4xx += b.S4xx
			statusBuckets.S5xx += b.S5xx
			statusBuckets.SOther += b.SOther
		}
	}

	// Ingest health card — values only meaningful on admin view, so render
	// conditionally in the template.
	var ingestStats map[string]any
	if s.analyticsIngest != nil {
		snap := s.analyticsIngest.Stats()
		ingestStats = map[string]any{
			"Connections": snap.Connections,
			"Events":      snap.Events,
			"Excluded":    snap.Excluded,
			"Errors":      snap.Errors,
			"LastEvent":   snap.LastEventAt,
			"Healthy":     snap.Events > 0 && time.Since(snap.LastEventAt) < 10*time.Minute,
		}
	}

	cfg := loadAnalyticsConfig(s.DB)
	s.render(w, r, "analytics.html", map[string]any{
		"User":             u,
		"IsAdmin":          isAdmin,
		"Today":            todayTotals,
		"SevenDay":         sevenTotals,
		"LiveVisitors":     liveVisitors,
		"Hosts":            hostRows,
		"Sparkline":           sparkline,
		"BandwidthSparkline": bwSparkline,
		"BandwidthTotal":     bwTotal,
		"BandwidthMax":       bwMax,
		"Status":              statusBuckets,
		"IngestStats":      ingestStats,
		"AnalyticsEnabled": cfg.Enabled,
		// Server-switcher data. AllServers feeds the <select>; the template
		// only renders the picker when len > 1 so a one-server deployment
		// doesn't get a useless dropdown. SelectedServerID is 0 for "all
		// servers" so the picker's first <option value="0"> is marked
		// selected when nothing's been picked.
		"AllServers":       allServers,
		"SelectedServerID": serverScopeID,
		"Section":          "analytics",
	})
}

// getAnalyticsHost is the per-host drill-down. Shows path leaderboard,
// client-IP leaderboard, hourly chart for the selected window, and status
// breakdown — all scoped to one host. Non-admins only see hosts they own.
func (s *Server) getAnalyticsHost(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "host")))
	if host == "" {
		http.Redirect(w, r, "/analytics", http.StatusSeeOther)
		return
	}
	u := s.currentUser(r)
	isAdmin := u != nil && u.Role == models.RoleAdmin
	if !isAdmin {
		allowed, err := s.userAllowedHosts(u)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ok := false
		for _, h := range allowed {
			if h == host {
				ok = true
				break
			}
		}
		if !ok {
			// 404 rather than 403 — leaking "this host exists but you
			// can't see it" would help attackers enumerate other users'
			// sites. The standard "not found" matches what they'd get
			// for a host that genuinely has no events either.
			http.NotFound(w, r)
			return
		}
	}

	// Window: default 7d, let ?window= override with 1d/30d. Kept in a
	// small set of approved values so a tampered query-string can't make
	// us scan a trillion-row range.
	window := 7 * 24 * time.Hour
	switch strings.ToLower(r.URL.Query().Get("window")) {
	case "1d", "24h", "day":
		window = 24 * time.Hour
	case "30d":
		window = 30 * 24 * time.Hour
	}
	now := time.Now()
	since := now.Add(-window)
	prevSince := since.Add(-window) // start of previous period
	prevTo := since                 // = start of current period

	totals, _ := models.AccessTotalsBetween(s.DB, since, now, host)
	prevTotals, _ := models.AccessTotalsBetween(s.DB, prevSince, prevTo, host)

	var viewsChange, visitorsChange int
	var viewsUp, visitorsUp bool
	if prevTotals.Views > 0 {
		viewsChange = (totals.Views - prevTotals.Views) * 100 / prevTotals.Views
		viewsUp = totals.Views >= prevTotals.Views
	} else if totals.Views > 0 {
		viewsChange = 100
		viewsUp = true
	}
	if prevTotals.Visitors > 0 {
		visitorsChange = (totals.Visitors - prevTotals.Visitors) * 100 / prevTotals.Visitors
		visitorsUp = totals.Visitors >= prevTotals.Visitors
	} else if totals.Visitors > 0 {
		visitorsChange = 100
		visitorsUp = true
	}
	viewsChangeAbs := viewsChange
	if viewsChangeAbs < 0 {
		viewsChangeAbs = -viewsChangeAbs
	}
	visitorsChangeAbs := visitorsChange
	if visitorsChangeAbs < 0 {
		visitorsChangeAbs = -visitorsChangeAbs
	}
	paths, _ := models.TopPaths(s.DB, since, host, 20)
	clients, _ := models.TopClientIPs(s.DB, since, host, 20)
	status, _ := models.StatusBucketsSince(s.DB, since, host)
	rtStats, err2 := models.ResponseTimeSince(s.DB, since, host)
	if err2 != nil {
		log.Printf("analytics: ResponseTimeSince(%s): %v", host, err2)
	}
	bandwidth, err3 := models.BandwidthSince(s.DB, since, host)
	if err3 != nil {
		log.Printf("analytics: BandwidthSince(%s): %v", host, err3)
	}
	errorPaths, err4 := models.TopErrorPaths(s.DB, since, host, 15)
	if err4 != nil {
		log.Printf("analytics: TopErrorPaths(%s): %v", host, err4)
	}
	browsers, _ := models.TopBrowsers(s.DB, since, host, 8)

	bucketSec := int64(3600) // 1h buckets regardless of window — keeps the
	if window >= 30*24*time.Hour {
		bucketSec = 86400 // ...except 30d+ views where hourly would be 720 bars.
	}
	rawBuckets, _ := models.AccessBuckets(s.DB, since, now, bucketSec, host)
	buckets := fillBuckets(rawBuckets, since, now, bucketSec)

	s.render(w, r, "analytics_host.html", map[string]any{
		"User":               u,
		"IsAdmin":            isAdmin,
		"Host":               host,
		"Window":             window,
		"WindowLabel":        formatWindow(window),
		"Totals":             totals,
		"Paths":              paths,
		"Clients":            clients,
		"Status":             status,
		"Buckets":            buckets,
		"BucketSeconds":      bucketSec,
		"ResponseTime":       rtStats,
		"Bandwidth":          bandwidth,
		"ErrorPaths":         errorPaths,
		"Browsers":           browsers,
		"Section":            "analytics",
		"ViewsChange":        viewsChange,
		"ViewsUp":            viewsUp,
		"ViewsChangeAbs":     viewsChangeAbs,
		"VisitorsChange":     visitorsChange,
		"VisitorsUp":         visitorsUp,
		"VisitorsChangeAbs":  visitorsChangeAbs,
		"PrevPeriod":         fmt.Sprintf("prev %s", formatWindow(window)),
	})
}

// liveVisitorsAcrossHosts counts distinct client IPs on the given host
// list over the last `window`. Used by the non-admin path of getAnalytics
// so an IP visiting two owned hosts is counted once, not twice.
func (s *Server) liveVisitorsAcrossHosts(hosts []string, window time.Duration) int {
	if len(hosts) == 0 {
		return 0
	}
	// One-shot query with IN(...) — same pattern as HostStatsForHosts.
	placeholders := make([]byte, 0, len(hosts)*2)
	args := []any{time.Now().Add(-window).Unix()}
	for i, h := range hosts {
		if i > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		args = append(args, h)
	}
	q := `SELECT COUNT(DISTINCT client_ip) FROM access_events WHERE ts >= ? AND host IN (` + string(placeholders) + `)`
	var n int
	if err := s.DB.QueryRow(q, args...).Scan(&n); err != nil {
		return 0
	}
	return n
}

// fillBuckets takes the sparse bucket slice from models.AccessBuckets and
// returns a dense slice covering every bucketSec window between from and
// to — gaps get zero-valued entries so the chart reads like a continuous
// series. Sorted ascending by bucket start.
func fillBuckets(sparse []models.HourlyBucket, from, to time.Time, bucketSec int64) []models.HourlyBucket {
	if bucketSec <= 0 {
		bucketSec = 3600
	}
	// Snap from/to to bucket boundaries so the first and last entries
	// align with what the SQL groups on.
	start := (from.Unix() / bucketSec) * bucketSec
	end := (to.Unix() / bucketSec) * bucketSec
	byKey := make(map[int64]models.HourlyBucket, len(sparse))
	for _, b := range sparse {
		byKey[(b.Hour.Unix()/bucketSec)*bucketSec] = b
	}
	var out []models.HourlyBucket
	for t := start; t <= end; t += bucketSec {
		if b, ok := byKey[t]; ok {
			out = append(out, b)
			continue
		}
		out = append(out, models.HourlyBucket{Hour: time.Unix(t, 0)})
	}
	// Defensive sort in case models returned out-of-order rows (SQLite
	// GROUP BY without ORDER BY is stable in practice, but be explicit).
	sort.Slice(out, func(i, j int) bool { return out[i].Hour.Before(out[j].Hour) })
	return out
}

// fillBandwidthBuckets is the bandwidth analogue of fillBuckets — fills in
// zero-BytesOut buckets for each expected slot between from and to.
func fillBandwidthBuckets(raw []models.BandwidthBucket, from, to time.Time, bucketSeconds int64) []models.BandwidthBucket {
	if bucketSeconds <= 0 {
		bucketSeconds = 3600
	}
	start := (from.Unix() / bucketSeconds) * bucketSeconds
	end := (to.Unix() / bucketSeconds) * bucketSeconds
	byKey := make(map[int64]int64, len(raw))
	for _, b := range raw {
		byKey[(b.Hour.Unix()/bucketSeconds)*bucketSeconds] = b.BytesOut
	}
	var out []models.BandwidthBucket
	for t := start; t <= end; t += bucketSeconds {
		out = append(out, models.BandwidthBucket{Hour: time.Unix(t, 0), BytesOut: byKey[t]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hour.Before(out[j].Hour) })
	return out
}

// formatWindow turns a duration into a label for the page headline. Used
// by both the overview page (7d default, no override) and the per-host
// page (1d / 7d / 30d selectable).
func formatWindow(d time.Duration) string {
	h := int(d.Hours())
	switch {
	case h <= 1:
		return "last hour"
	case h <= 24:
		return "last 24 hours"
	case h < 24*7:
		return fmt.Sprintf("last %d days", h/24)
	case h < 24*14:
		return "last 7 days"
	case h < 24*60:
		return fmt.Sprintf("last %d days", h/24)
	case h < 24*180:
		return "last 30 days"
	default:
		return fmt.Sprintf("last %d days", h/24)
	}
}

// pruneAccessLoop runs forever, deleting access_events older than the
// configured retention (default 30d) once per day. Started by main.go
// alongside the ingest listener. Cheap — one DELETE with an indexed
// WHERE clause; SQLite can knock out 100k rows in a fraction of a second.
func (s *Server) pruneAccessLoop() {
	// First prune after 60s so a crashing container that wrote bad events
	// gets cleaned promptly on next restart, rather than waiting 24h.
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	for {
		<-timer.C
		cutoff := time.Now().Add(-30 * 24 * time.Hour)
		if n, err := models.PruneAccessEvents(s.DB, cutoff); err != nil {
			log.Printf("analytics: prune error: %v", err)
		} else if n > 0 {
			log.Printf("analytics: pruned %d events older than %s", n, cutoff.Format(time.RFC3339))
		}
		timer.Reset(24 * time.Hour)
	}
}

// --- Global search ---

// getSearch handles GET /search — full-text search across proxy hosts,
// redirection hosts, raw routes, and certificates.
func (s *Server) getSearch(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	isAdmin := u != nil && u.Role == models.RoleAdmin

	var proxyHosts []models.ProxyHost
	var redirects []models.RedirectionHost
	var rawRoutes []models.RawRoute
	var certs []models.Certificate

	if q != "" {
		sid := s.currentServerID(r)
		viewerID := int64(0)
		if u != nil && !isAdmin {
			viewerID = u.ID
		}
		var peers []int64
		if u != nil && !isAdmin {
			peers, _ = models.GroupPeerIDs(s.DB, u.ID)
		}
		qLower := strings.ToLower(q)

		// Search proxy hosts by domain or forward host.
		all, _ := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin, peers)
		for _, p := range all {
			if strings.Contains(strings.ToLower(p.Domains), qLower) ||
				strings.Contains(strings.ToLower(p.ForwardHost), qLower) {
				proxyHosts = append(proxyHosts, p)
			}
		}

		// Search redirection hosts.
		allR, _ := models.ListRedirectionHosts(s.DB, sid, viewerID, isAdmin, peers)
		for _, rh := range allR {
			if strings.Contains(strings.ToLower(rh.Domains), qLower) ||
				strings.Contains(strings.ToLower(rh.ForwardDomain), qLower) {
				redirects = append(redirects, rh)
			}
		}

		// Search raw routes by label.
		allRaw, _ := models.ListRawRoutes(s.DB, sid, viewerID, isAdmin, peers)
		for _, rr := range allRaw {
			if strings.Contains(strings.ToLower(rr.Label), qLower) {
				rawRoutes = append(rawRoutes, rr)
			}
		}

		// Search certificates by name or domains.
		allCerts, _ := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin, peers)
		for _, c := range allCerts {
			if strings.Contains(strings.ToLower(c.Name), qLower) ||
				strings.Contains(strings.ToLower(c.Domains), qLower) {
				certs = append(certs, c)
			}
		}
	}

	s.render(w, r, "search.html", map[string]any{
		"User":       u,
		"IsAdmin":    isAdmin,
		"Query":      q,
		"ProxyHosts": proxyHosts,
		"Redirects":  redirects,
		"RawRoutes":  rawRoutes,
		"Certs":      certs,
		"Section":    "",
	})
}

// --- Session manager ---

// SessionRow is one row in the sessions table view.
type SessionRow struct {
	Token     string
	UserEmail string
	ExpiresAt time.Time
	IsCurrent bool
}

// getSessions handles GET /sessions.
func (s *Server) getSessions(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	isAdmin := u.Role == models.RoleAdmin

	// Get current token to mark it.
	currentToken := ""
	if c, err := r.Cookie("caddyui_session"); err == nil {
		currentToken = c.Value
	}

	var rows []SessionRow
	var dbRows *sql.Rows
	var err error
	if isAdmin {
		dbRows, err = s.DB.Query(
			`SELECT s.token, u.email, s.expires_at FROM sessions s
			   JOIN users u ON u.id = s.user_id
			  WHERE s.expires_at > datetime('now')
			  ORDER BY s.expires_at DESC`)
	} else {
		dbRows, err = s.DB.Query(
			`SELECT token, ?, expires_at FROM sessions
			  WHERE user_id = ? AND expires_at > datetime('now')
			  ORDER BY expires_at DESC`, u.Email, u.ID)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer dbRows.Close()
	for dbRows.Next() {
		var row SessionRow
		var expStr string
		if err := dbRows.Scan(&row.Token, &row.UserEmail, &expStr); err != nil {
			continue
		}
		row.ExpiresAt, _ = time.Parse("2006-01-02 15:04:05", expStr)
		row.IsCurrent = row.Token == currentToken
		rows = append(rows, row)
	}

	s.render(w, r, "sessions.html", map[string]any{
		"User":     u,
		"IsAdmin":  isAdmin,
		"Sessions": rows,
		"Section":  "",
	})
}

// revokeSession handles POST /sessions/{token}/revoke.
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	token := chi.URLParam(r, "token")
	isAdmin := u.Role == models.RoleAdmin

	if isAdmin {
		s.DB.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	} else {
		// Non-admin can only revoke their own sessions.
		s.DB.Exec(`DELETE FROM sessions WHERE token = ? AND user_id = ?`, token, u.ID)
	}
	http.Redirect(w, r, "/sessions", http.StatusSeeOther)
}

// exportAnalyticsCSV exports access_events as a downloadable CSV file.
// Query params: ?host= (filter to one host), ?days=7 (lookback window, max 90).
func (s *Server) exportAnalyticsCSV(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	isAdmin := u != nil && u.Role == models.RoleAdmin

	host := strings.TrimSpace(r.URL.Query().Get("host"))
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 90 {
			days = n
		}
	}

	// Non-admins: verify they own the requested host.
	if !isAdmin && host != "" {
		allowed, err := s.userAllowedHosts(u)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ok := false
		for _, h := range allowed {
			if h == host {
				ok = true
				break
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
	} else if !isAdmin && host == "" {
		// Non-admin without host filter: require a host param for non-admins.
		http.Error(w, "specify ?host= for non-admin export", http.StatusForbidden)
		return
	}

	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	rows, err := models.ExportAccessEvents(s.DB, since, host, 50000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	fname := "analytics"
	if host != "" {
		fname = strings.ReplaceAll(host, ".", "_")
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_%dd.csv"`, fname, days))

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "host", "path", "method", "status", "client_ip", "user_agent", "duration_ms", "bytes_out"})
	for _, e := range rows {
		_ = cw.Write([]string{
			e.TS.UTC().Format(time.RFC3339),
			e.Host, e.Path, e.Method,
			strconv.Itoa(e.Status),
			e.ClientIP, e.UserAgent,
			strconv.FormatInt(e.DurationMs, 10),
			strconv.FormatInt(e.BytesOut, 10),
		})
	}
	cw.Flush()
}
