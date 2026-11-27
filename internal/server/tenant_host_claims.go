// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Host claims of a non-admin's Advanced routes.
//
// A proxy host or redirect names its hosts in a Domains field, and a name
// may be used by only one of them per server (models.DomainsConflict). An
// Advanced route names its hosts inside its route JSON instead, and nothing
// checked them: a non-admin could save a route matching a host another
// account serves — an administrator's included — and Caddy would run
// whichever route came first. A route with no host matcher at all answers
// for every host on the listener it is placed on.
//
// The rule for a route owned by a non-admin:
//
//   - every top-level route must match on host names, and each name must be
//     a plain host name (an optional leading "*." aside) — no placeholder,
//     no "*" or "*.*" that matches every name of a shape;
//   - no host it names may be named by a row (proxy host, redirect or
//     Advanced route) on the same server that the owner cannot manage;
//   - a route without host matchers is allowed only on a listener of its
//     own: one no Advanced route of another owner listens on.
//
// It is checked when a non-admin saves a route (form and REST API, create
// and update: tenantRawRouteClaimProblem) and again on every sync
// (withoutForeignHostClaims), which covers rows stored before the rule and
// rows written by any other path. A stored row that breaks it is not
// deployed and stays in the database unchanged, so its owner or an
// administrator can see and fix it.

// claimHost is a host name as the claim rules compare it: lower-cased,
// trimmed, without a trailing dot (Caddy matches host names without regard
// to case).
func claimHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// rawRouteMatchShape reads what an Advanced route's top-level routes match
// on: the host names (claimHost form), whether some route or matcher set
// matches without a host name (hostless), and the first host matcher value
// that is not a plain host name (bad).
func rawRouteMatchShape(jsonData string) (hosts []string, hostless bool, bad string) {
	var decoded any
	if err := json.Unmarshal([]byte(jsonData), &decoded); err != nil {
		return nil, false, "" // not deployed at all (rawRouteEntries)
	}
	var routes []any
	switch t := decoded.(type) {
	case []any:
		routes = t
	case map[string]any:
		routes = []any{t}
	default:
		return nil, false, ""
	}
	for _, r := range routes {
		route, ok := r.(map[string]any)
		if !ok {
			hostless = true
			continue
		}
		sets, ok := route["match"].([]any)
		if !ok || len(sets) == 0 {
			hostless = true
			continue
		}
		for _, s := range sets {
			set, ok := s.(map[string]any)
			if !ok {
				hostless = true
				continue
			}
			names, ok := set["host"].([]any)
			if !ok || len(names) == 0 {
				hostless = true
				continue
			}
			for _, n := range names {
				str, ok := n.(string)
				h := claimHost(str)
				if !ok || !tenantHostnameRe.MatchString(h) {
					if bad == "" {
						bad = fmt.Sprint(n)
					}
					continue
				}
				hosts = append(hosts, h)
			}
		}
	}
	return hosts, hostless, bad
}

// hostClaim is one row's claim on the hosts and listeners of a server.
type hostClaim struct {
	kind    string // "proxy host", "redirect", "Advanced route"
	id      int64
	owner   sql.NullInt64
	enabled bool
	hosts   []string
	listen  []string // Advanced routes only
}

// serverHostClaims lists every row's claims, from the server's rows as
// given.
func serverHostClaims(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute) []hostClaim {
	var out []hostClaim
	for _, p := range proxies {
		c := hostClaim{kind: "proxy host", id: p.ID, owner: p.OwnerID, enabled: p.Enabled}
		for _, d := range p.DomainList() {
			if h := claimHost(d); h != "" {
				c.hosts = append(c.hosts, h)
			}
		}
		out = append(out, c)
	}
	for _, rd := range redirs {
		c := hostClaim{kind: "redirect", id: rd.ID, owner: rd.OwnerID, enabled: rd.Enabled}
		for _, d := range rd.DomainList() {
			if h := claimHost(d); h != "" {
				c.hosts = append(c.hosts, h)
			}
		}
		out = append(out, c)
	}
	for _, rr := range raws {
		c := hostClaim{kind: "Advanced route", id: rr.ID, owner: rr.OwnerID, enabled: rr.Enabled, listen: rr.ListenAddrs()}
		for _, h := range rawRouteHosts(rr) {
			if h = claimHost(h); h != "" {
				c.hosts = append(c.hosts, h)
			}
		}
		out = append(out, c)
	}
	return out
}

// listenPortRange reads the port, or port range, of a Caddy listen
// address (":7070", "127.0.0.1:7070", "tcp/:7070-7080"). ok is false when
// it cannot be read.
func listenPortRange(addr string) (lo, hi int, ok bool) {
	a := strings.TrimSpace(addr)
	if i := strings.Index(a, "/"); i >= 0 {
		a = a[i+1:]
	}
	i := strings.LastIndex(a, ":")
	if i < 0 {
		return 0, 0, false
	}
	p := a[i+1:]
	from, to, isRange := strings.Cut(p, "-")
	var err error
	if lo, err = strconv.Atoi(from); err != nil {
		return 0, 0, false
	}
	hi = lo
	if isRange {
		if hi, err = strconv.Atoi(to); err != nil || hi < lo {
			return 0, 0, false
		}
	}
	return lo, hi, true
}

// listenSetsOverlap reports whether two listen sets may share a port; an
// address that cannot be read is taken to overlap.
func listenSetsOverlap(a, b []string) bool {
	for _, x := range a {
		xl, xh, xok := listenPortRange(x)
		for _, y := range b {
			yl, yh, yok := listenPortRange(y)
			if !xok || !yok || (xl <= yh && yl <= xh) {
				return true
			}
		}
	}
	return false
}

// rawRouteClaimRules checks one non-admin Advanced route (rr) against the
// other rows' claims. foreign reports whether a row's owner is one the
// route's owner cannot manage; outranks whether a foreign row that names
// the same host keeps it (at save time every foreign row does; at sync time
// see withoutForeignHostClaims). Returns a message, or "".
func rawRouteClaimRules(rr models.RawRoute, claims []hostClaim, foreign func(sql.NullInt64) bool, outranks func(hostClaim) bool) string {
	hosts, hostless, bad := rawRouteMatchShape(rr.JSONData)
	if bad != "" {
		return fmt.Sprintf("the host matcher %q is not a plain host name — placeholders and wildcards other than a leading \"*.\" are not allowed for non-admin accounts", bad)
	}
	listen := rr.ListenAddrs()
	if hostless {
		if len(listen) == 0 {
			return "every route must match on host names (a route without a host matcher would answer for every site on this server); add the site's host name, or give the route a listen port of its own"
		}
		for _, c := range claims {
			if c.kind == "Advanced route" && c.id != rr.ID && len(c.listen) > 0 && foreign(c.owner) && outranks(c) && listenSetsOverlap(listen, c.listen) {
				return "a route without a host matcher needs a listen port of its own, and another account's Advanced route listens on the same port"
			}
		}
	}
	want := map[string]bool{}
	for _, h := range hosts {
		want[h] = true
	}
	for _, c := range claims {
		if c.kind == "Advanced route" && c.id == rr.ID {
			continue
		}
		if !foreign(c.owner) || !outranks(c) {
			continue
		}
		for _, h := range c.hosts {
			if want[h] {
				return fmt.Sprintf("the host %q is used by another account's %s on this server", h, c.kind)
			}
		}
	}
	return ""
}

// tenantRawRouteClaimProblem is the save-time check: for a non-admin (cu)
// saving rr on serverID, why its host matchers may not be saved, or "".
// rr.ID is the row being updated (0 on create). Every other row counts,
// enabled or not: a name is claimed by the row that holds it.
func (s *Server) tenantRawRouteClaimProblem(cu *models.User, serverID int64, rr *models.RawRoute) string {
	if isAdminUser(cu) || rr == nil {
		return ""
	}
	if rr.ID != 0 {
		// An update is judged on the server the row is on, whichever
		// server the request has selected.
		sid, err := models.RawRouteServerID(s.DB, rr.ID)
		if err != nil {
			return "Could not check which hosts are in use on this server; try again."
		}
		serverID = sid
	}
	proxies, redirs, raws, _, ok := s.serverResources(serverID)
	if !ok {
		return "Could not check which hosts are in use on this server; try again."
	}
	foreign := func(owner sql.NullInt64) bool { return !s.canManageOwned(cu, owner) }
	always := func(hostClaim) bool { return true }
	if why := rawRouteClaimRules(*rr, serverHostClaims(proxies, redirs, raws), foreign, always); why != "" {
		return "Not allowed for a non-admin account: " + why + "."
	}
	return ""
}

// ownerPeers answers "may this owner manage that owner's rows?" for owners
// of stored rows, remembering answers for one sync.
type ownerPeers struct {
	s    *Server
	memo map[[2]int64]bool
}

func (p *ownerPeers) foreignTo(owner sql.NullInt64) func(sql.NullInt64) bool {
	return func(other sql.NullInt64) bool {
		if !other.Valid || !p.s.isTenantOwner(other) {
			return true // admin-owned
		}
		if other.Int64 == owner.Int64 {
			return false
		}
		key := [2]int64{min(owner.Int64, other.Int64), max(owner.Int64, other.Int64)}
		shared, ok := p.memo[key]
		if !ok {
			shared, _ = models.UsersShareGroup(p.s.DB, owner.Int64, other.Int64)
			p.memo[key] = shared
		}
		return !shared
	}
}

// withoutForeignHostClaims is the sync-time enforcement: raws without the
// enabled non-admin Advanced routes that break the claim rules, judged
// against the enabled rows of the server. Between two non-admin owners'
// Advanced routes naming one host, or listening on one port, the older
// (lower id) keeps it; a proxy host or redirect, and any row of an
// administrator, always does. Rows that are left out are logged, once per
// change.
func (s *Server) withoutForeignHostClaims(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute) []models.RawRoute {
	if s == nil || s.DB == nil {
		return raws
	}
	var claims []hostClaim
	for _, c := range serverHostClaims(proxies, redirs, raws) {
		if c.enabled {
			claims = append(claims, c)
		}
	}
	peers := &ownerPeers{s: s, memo: map[[2]int64]bool{}}
	out := make([]models.RawRoute, 0, len(raws))
	held := map[int64]string{}
	for _, rr := range raws {
		if rr.Enabled && s.isTenantOwner(rr.OwnerID) {
			outranks := func(c hostClaim) bool {
				return c.kind != "Advanced route" || !s.isTenantOwner(c.owner) || c.id < rr.ID
			}
			if why := rawRouteClaimRules(rr, claims, peers.foreignTo(rr.OwnerID), outranks); why != "" {
				held[rr.ID] = why
				continue
			}
		}
		out = append(out, rr)
	}
	s.logHeldHostClaims(raws, held)
	return out
}

// logHeldHostClaims logs each of raws left out for its host claims (held),
// and each that no longer is, when that changes.
func (s *Server) logHeldHostClaims(raws []models.RawRoute, held map[int64]string) {
	s.withheldMu.Lock()
	defer s.withheldMu.Unlock()
	if s.heldClaims == nil {
		s.heldClaims = map[int64]string{}
	}
	for _, rr := range raws {
		why, was := held[rr.ID], s.heldClaims[rr.ID]
		switch {
		case why != "" && why != was:
			log.Printf("caddy sync: advanced route id=%d not deployed: %s", rr.ID, why)
			s.heldClaims[rr.ID] = why
		case why == "" && was != "":
			log.Printf("caddy sync: advanced route id=%d is deployed again (its host claims are allowed now)", rr.ID)
			delete(s.heldClaims, rr.ID)
		}
	}
}
