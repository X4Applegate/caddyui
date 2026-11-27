// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Host claims of non-admin accounts.
//
// A proxy host or redirect names its hosts in a Domains field, and a name
// may be used by only one of them per server (models.DomainsConflict). An
// Advanced route names its hosts inside its route JSON instead, and nothing
// compared them with the other rows: a non-admin could save a route matching
// a host another account serves — an administrator's included — and Caddy
// would run whichever route came first. A route with no host matcher answers
// for every host on its listener.
//
// The rules for a row owned by a non-admin:
//
//   - every top-level route of an Advanced route must match on host names,
//     each a plain host name, optionally with a leading "*." over at least
//     two labels (no placeholder, no "*", "*.*" or "*.com");
//   - no host it names may be one a row of an account it cannot manage
//     names on the same server, and — since Caddy matches "*.example.com"
//     for every one-label name under example.com — a wildcard may not cover
//     such a name, nor such a wildcard cover its name;
//   - an Advanced route's own listener (tenantListenProblem) is a plain
//     port of 1024 or above that no other server uses, and a route without
//     host matchers may not share it with another account's Advanced route
//     (in either direction); no Advanced route may listen on part of another
//     route's port set, which Caddy refuses for the whole server.
//
// They are checked when a non-admin saves a row (every path: forms, REST
// API, paste import, reclassify, the AI tool, fleet copies) and on every
// sync and preview (withoutForeignHostClaims), which covers rows stored
// before the rules and rows written by any other path. A stored row that
// breaks them is not deployed and stays in the database unchanged.
//
// At save time, a row an account cannot manage is foreign, and so is an
// administrator's row (also when the administrator shares a group with the
// account), so a save is accepted only when the sync would deploy it. At
// sync time, ties are broken so that some row keeps every name: an
// administrator's row always does; a proxy host or redirect keeps its names
// against a non-admin's Advanced route; between two non-admins' Advanced
// routes the older one keeps it. Wildcard coverage is enforced at sync time
// only between non-admin accounts' rows; an administrator's wildcard keeps
// its exact names, but existing names of non-admins under it stay served.

const (
	claimProxy    = "proxy host"
	claimRedirect = "redirect"
	claimRaw      = "Advanced route"
)

// claimHost is a host name as the claim rules compare it: lower-cased,
// trimmed, without a trailing dot (Caddy matches host names without regard
// to case or a trailing dot).
func claimHost(h string) string {
	return models.NormalizeHostname(h) // also drops a port, as the route builders do
}

// tenantClaimHostProblem returns why h (claimHost form) may not be a
// non-admin's host name, or "".
func tenantClaimHostProblem(h string) string {
	if !tenantHostnameRe.MatchString(h) {
		return "is not a plain host name"
	}
	if rest, ok := strings.CutPrefix(h, "*."); ok && !strings.Contains(rest, ".") {
		return "is a wildcard over a whole top-level domain"
	}
	return ""
}

// rawRouteMatchShape reads what an Advanced route's top-level routes match
// on: the host names (claimHost form), whether some route or matcher set
// matches without a host name (hostless), and the first host matcher value
// a non-admin may not use (bad).
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
				if !ok || tenantClaimHostProblem(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(str)), ".")) != "" {
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
	kind     string // claimProxy, claimRedirect, claimRaw
	id       int64
	owner    sql.NullInt64
	enabled  bool
	hosts    []string
	listen   []string // Advanced routes only
	hostless bool     // Advanced routes only
}

func (c hostClaim) is(kind string, id int64) bool { return id != 0 && c.kind == kind && c.id == id }

// serverHostClaims lists every row's claims, from the server's rows as
// given.
func serverHostClaims(proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute) []hostClaim {
	out := make([]hostClaim, 0, len(proxies)+len(redirs)+len(raws))
	domains := func(list []string) []string {
		var hs []string
		for _, d := range list {
			if h := claimHost(d); h != "" {
				hs = append(hs, h)
			}
		}
		return hs
	}
	for _, p := range proxies {
		out = append(out, hostClaim{kind: claimProxy, id: p.ID, owner: p.OwnerID, enabled: p.Enabled, hosts: domains(p.DomainList())})
	}
	for _, rd := range redirs {
		out = append(out, hostClaim{kind: claimRedirect, id: rd.ID, owner: rd.OwnerID, enabled: rd.Enabled, hosts: domains(rd.DomainList())})
	}
	for _, rr := range raws {
		c := hostClaim{kind: claimRaw, id: rr.ID, owner: rr.OwnerID, enabled: rr.Enabled, listen: rr.ListenAddrs()}
		for _, h := range rawRouteHosts(rr) {
			if h = claimHost(h); h != "" {
				c.hosts = append(c.hosts, h)
			}
		}
		_, c.hostless, _ = rawRouteMatchShape(rr.JSONData)
		out = append(out, c)
	}
	return out
}

// claimIndex finds the claims that may conflict with a name without
// looking at every claim (a server may hold thousands of rows).
type claimIndex struct {
	claims   []hostClaim
	exact    map[string][]int // host -> claims naming it
	children map[string][]int // "example.com" -> claims naming "x.example.com" (not a wildcard)
	listens  []int            // claims with a listen set
}

func newClaimIndex(claims []hostClaim) *claimIndex {
	ix := &claimIndex{claims: claims, exact: map[string][]int{}, children: map[string][]int{}}
	for i, c := range claims {
		for _, h := range c.hosts {
			ix.exact[h] = append(ix.exact[h], i)
			if !strings.HasPrefix(h, "*.") {
				if _, parent, ok := strings.Cut(h, "."); ok {
					ix.children[parent] = append(ix.children[parent], i)
				}
			}
		}
		if len(c.listen) > 0 {
			ix.listens = append(ix.listens, i)
		}
	}
	return ix
}

// candidate is a claim that may conflict with a name; wildcard says the
// conflict is one of wildcard coverage rather than the same name.
type candidate struct {
	i        int
	wildcard bool
}

// candidates returns the claims naming h, the wildcard that covers h, or —
// for a wildcard h — the names it covers.
func (ix *claimIndex) candidates(h string) []candidate {
	var out []candidate
	for _, i := range ix.exact[h] {
		out = append(out, candidate{i, false})
	}
	if rest, ok := strings.CutPrefix(h, "*."); ok {
		for _, i := range ix.children[rest] {
			out = append(out, candidate{i, true})
		}
	} else if _, parent, ok := strings.Cut(h, "."); ok {
		for _, i := range ix.exact["*."+parent] {
			out = append(out, candidate{i, true})
		}
	}
	return out
}

// claimPolicy says how a row's claims are weighed against another row's.
type claimPolicy struct {
	// foreign reports whether a row's owner is one the row's owner may not
	// share names with.
	foreign func(sql.NullInt64) bool
	// keeps reports whether the other row keeps a contested name (or port).
	keeps func(hostClaim) bool
	// wildcards reports whether wildcard coverage of the row's name h by
	// (or of) the other row counts against the row.
	wildcards func(h string, c hostClaim) bool
}

// hostConflict returns a message for the first of hosts another row keeps,
// or "". self is the row being judged.
func (ix *claimIndex) hostConflict(self hostClaim, hosts []string, pol claimPolicy) string {
	for _, h := range hosts {
		for _, cd := range ix.candidates(h) {
			c := ix.claims[cd.i]
			if c.is(self.kind, self.id) || !pol.foreign(c.owner) || !pol.keeps(c) {
				continue
			}
			if cd.wildcard {
				if !pol.wildcards(h, c) {
					continue
				}
				return fmt.Sprintf("the host %q overlaps a wildcard name of another account's %s on this server", h, c.kind)
			}
			return fmt.Sprintf("the host %q is used by another account's %s on this server", h, c.kind)
		}
	}
	return ""
}

// rawRouteClaimRules checks one non-admin Advanced route against the
// other rows' claims. Returns a message, or "".
func rawRouteClaimRules(rr models.RawRoute, ix *claimIndex, pol claimPolicy) string {
	hosts, hostless, bad := rawRouteMatchShape(rr.JSONData)
	if bad != "" {
		return fmt.Sprintf("the host matcher %q is not allowed — non-admin accounts may only match plain host names, with an optional leading \"*.\" over a domain of at least two labels", bad)
	}
	self := hostClaim{kind: claimRaw, id: rr.ID, owner: rr.OwnerID}
	listen := rr.ListenAddrs()
	if hostless && len(listen) == 0 {
		return "every route must match on host names (a route without a host matcher would answer for every site on this server); add the site's host name, or give the route a listen port of its own"
	}
	for _, i := range ix.listens {
		c := ix.claims[i]
		if c.is(self.kind, self.id) || len(listen) == 0 || !listenSetsOverlap(listen, c.listen) || !pol.keeps(c) {
			continue
		}
		// Caddy refuses two servers that share part of a port set, for the
		// whole server; routes on the same set share one server.
		if !sameListenSet(listen, c.listen) {
			return "its listen ports overlap part of another Advanced route's ports on this server; use exactly the same ports, or other ports"
		}
		if pol.foreign(c.owner) && (hostless || c.hostless) {
			return "a route without a host matcher needs a listen port of its own, and another account's Advanced route listens on the same port"
		}
	}
	return ix.hostConflict(self, hosts, pol)
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
		if socketListen(x) {
			continue
		}
		xl, xh, xok := listenPortRange(x)
		for _, y := range b {
			if socketListen(y) {
				continue
			}
			yl, yh, yok := listenPortRange(y)
			if !xok || !yok || (xl <= yh && yl <= xh) {
				return true
			}
		}
	}
	return false
}

func sameListenSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// layer4PortRe finds ports in a Layer4 Caddyfile.
var layer4PortRe = regexp.MustCompile(`:(\d{1,5})(?:-(\d{1,5}))?`)

// maxTenantListenRange is the widest port range a non-admin's listen
// address may name.
const maxTenantListenRange = 16

// tenantListenProblem returns why a non-admin's Advanced route may not
// listen on addrs, or "". Only ":PORT" or ":LO-HI" (optionally "tcp/") is
// allowed: an address with a host part is bound next to — and can take
// connections from — a listener on the same port (Caddy binds with
// SO_REUSEPORT), and other networks reach sockets. Ports below 1024, the
// standard ports, Caddy admin ports and Layer4 ports (reserved) are refused.
func tenantListenProblem(addrs []string, reserved map[int]bool) string {
	for _, a := range addrs {
		rest := strings.TrimPrefix(strings.TrimSpace(a), "tcp/")
		port, ok := strings.CutPrefix(rest, ":")
		if !ok || port == "" || strings.ContainsAny(port, ":/[]") {
			return fmt.Sprintf("the listen address %q is not allowed: non-admin accounts may only listen on a port (\":8080\"), without a host or network", a)
		}
		from, to, isRange := strings.Cut(port, "-")
		if !isRange {
			to = from
		}
		for _, p := range []string{from, to} {
			if p == "" || (len(p) > 1 && p[0] == '0') || strings.Trim(p, "0123456789") != "" {
				return fmt.Sprintf("the listen address %q is not allowed: its port is not a plain number", a)
			}
		}
		lo, _ := strconv.Atoi(from)
		hi, _ := strconv.Atoi(to)
		if lo < 1024 || hi > 65535 || hi < lo {
			return fmt.Sprintf("the listen address %q is not allowed: non-admin accounts may listen on ports 1024 to 65535", a)
		}
		if hi-lo+1 > maxTenantListenRange {
			return fmt.Sprintf("the listen address %q is not allowed: a port range may span at most %d ports", a, maxTenantListenRange)
		}
		for p := lo; p <= hi; p++ {
			if reserved[p] {
				return fmt.Sprintf("the listen address %q is not allowed: port %d is used by the server itself", a, p)
			}
		}
	}
	if n := listenPortCount(addrs); n > maxTenantListenRange {
		return fmt.Sprintf("the route would listen on %d ports; non-admin accounts may use at most %d per route", n, maxTenantListenRange)
	}
	return ""
}

// maxTenantOwnerListenPorts is how many ports one non-admin account's
// Advanced routes may listen on, per server, together.
const maxTenantOwnerListenPorts = 64

// listenPortCount is how many ports addrs name; an address that cannot be
// read counts as one.
func listenPortCount(addrs []string) int {
	n := 0
	for _, a := range addrs {
		if lo, hi, ok := listenPortRange(a); ok {
			n += hi - lo + 1
		} else {
			n++
		}
	}
	return n
}

// ownerListenBudget returns why rr would take its owner's Advanced routes
// on the server (raws, the stored rows; rr replaces the one with its ID)
// over maxTenantOwnerListenPorts, or "".
func ownerListenBudget(rr models.RawRoute, raws []models.RawRoute) string {
	n := listenPortCount(rr.ListenAddrs())
	if n == 0 {
		return ""
	}
	for _, other := range raws {
		if other.ID != rr.ID && other.OwnerID == rr.OwnerID && rr.OwnerID.Valid {
			n += listenPortCount(other.ListenAddrs())
		}
	}
	if n > maxTenantOwnerListenPorts {
		return fmt.Sprintf("the account's Advanced routes would listen on %d ports on this server; the limit is %d", n, maxTenantOwnerListenPorts)
	}
	return ""
}

// wildcardOverTLD returns why one of hosts is a wildcard over a whole
// top-level domain, or "".
func wildcardOverTLD(hosts []string) string {
	for _, h := range hosts {
		if rest, ok := strings.CutPrefix(h, "*."); ok && !strings.Contains(rest, ".") {
			return fmt.Sprintf("the domain %q is a wildcard over a whole top-level domain", h)
		}
	}
	return ""
}

// reservedListenPorts are the ports a non-admin's Advanced route may never
// listen on: the standard ports, every Caddy server's admin port, and every
// Layer4 proxy's port.
func (s *Server) reservedListenPorts() map[int]bool {
	out := map[int]bool{80: true, 443: true, 2019: true}
	if s == nil || s.DB == nil {
		return out
	}
	if servers, err := models.ListCaddyServers(s.DB); err == nil {
		for _, srv := range servers {
			if u, err := url.Parse(srv.AdminURL); err == nil {
				if p, err := strconv.Atoi(u.Port()); err == nil {
					out[p] = true
				}
			}
		}
	}
	// Ports named in a server's free-form Layer4 Caddyfile, read
	// generously: any ":PORT" or ":LO-HI" in the text.
	if servers, err := models.ListCaddyServers(s.DB); err == nil {
		for _, srv := range servers {
			for _, m := range layer4PortRe.FindAllStringSubmatch(srv.Layer4Caddyfile, -1) {
				lo, _ := strconv.Atoi(m[1])
				hi := lo
				if m[2] != "" {
					hi, _ = strconv.Atoi(m[2])
				}
				for p := lo; p <= hi && p <= 65535 && p-lo < 65536; p++ {
					out[p] = true
				}
			}
		}
	}
	if rows, err := s.DB.Query(`SELECT listen_port FROM layer4_proxies`); err == nil {
		for rows.Next() {
			var p int
			if rows.Scan(&p) == nil {
				out[p] = true
			}
		}
		_ = rows.Close()
	}
	return out
}

// ownerTenancy answers isTenantOwner for many rows with one query.
type ownerTenancy struct {
	s      *Server
	loaded bool
	admins map[int64]bool
	known  map[int64]bool
	shares map[[2]int64]bool
}

func (s *Server) newOwnerTenancy() *ownerTenancy {
	return &ownerTenancy{s: s, shares: map[[2]int64]bool{}}
}

// tenant is isTenantOwner, answered from one read of the users table.
func (o *ownerTenancy) tenant(owner sql.NullInt64) bool {
	if !owner.Valid {
		return false
	}
	if !o.loaded {
		o.loaded = true
		o.admins, o.known = map[int64]bool{}, map[int64]bool{}
		rows, err := o.s.DB.Query(`SELECT id, COALESCE(is_admin, 0), COALESCE(role, CASE WHEN is_admin=1 THEN 'admin' ELSE 'view' END) FROM users`)
		if err != nil {
			o.known = nil
		} else {
			for rows.Next() {
				var id int64
				var isAdmin bool
				var role string
				if rows.Scan(&id, &isAdmin, &role) != nil {
					o.known = nil // fall back to one lookup per owner
					break
				}
				o.known[id] = true
				o.admins[id] = isAdmin || role == models.RoleAdmin
			}
			if rows.Close() != nil || rows.Err() != nil {
				o.known = nil
			}
		}
	}
	if o.known == nil {
		return o.s.isTenantOwner(owner)
	}
	// A user that no longer exists is a tenant (isTenantOwner).
	return !o.admins[owner.Int64]
}

// foreignTo is the sync-time foreign rule for rows of owner (a non-admin).
func (o *ownerTenancy) foreignTo(owner sql.NullInt64) func(sql.NullInt64) bool {
	return func(other sql.NullInt64) bool {
		if !o.tenant(other) {
			return true // admin-owned
		}
		if other.Int64 == owner.Int64 {
			return false
		}
		key := [2]int64{min(owner.Int64, other.Int64), max(owner.Int64, other.Int64)}
		shared, ok := o.shares[key]
		if !ok {
			shared, _ = models.UsersShareGroup(o.s.DB, owner.Int64, other.Int64)
			o.shares[key] = shared
		}
		return !shared
	}
}

// savePolicy is the save-time policy for a non-admin (cu): every row it
// cannot manage, and every administrator's row, is foreign and keeps its
// names; wildcard coverage counts — except, for a name the row being
// updated already holds (held), coverage by an administrator's row, which
// the sync does not enforce either: an existing row stays editable.
func (s *Server) savePolicy(cu *models.User, o *ownerTenancy, held map[string]bool) claimPolicy {
	return claimPolicy{
		foreign: func(owner sql.NullInt64) bool { return !o.tenant(owner) || !s.canManageOwned(cu, owner) },
		keeps:   func(hostClaim) bool { return true },
		wildcards: func(h string, c hostClaim) bool {
			return !held[h] || o.tenant(c.owner)
		},
	}
}

// heldNames is the names the stored row (kind, id) holds now, or nil.
func (s *Server) heldNames(kind string, id int64) map[string]bool {
	if id == 0 {
		return nil
	}
	var names []string
	switch kind {
	case claimProxy:
		if p, err := models.GetProxyHost(s.DB, id); err == nil && p != nil {
			names = p.DomainList()
		}
	case claimRedirect:
		if rd, err := models.GetRedirectionHost(s.DB, id); err == nil && rd != nil {
			names = rd.DomainList()
		}
	case claimRaw:
		if rr, err := models.GetRawRoute(s.DB, id); err == nil && rr != nil {
			names = rawRouteHosts(*rr)
		}
	}
	out := map[string]bool{}
	for _, n := range names {
		out[claimHost(n)] = true
	}
	return out
}

// claimServerID is the server a stored row is on, or fallback for a new
// row (id 0).
func (s *Server) claimServerID(kind string, id, fallback int64) (int64, error) {
	if id == 0 {
		return fallback, nil
	}
	table := map[string]string{claimProxy: "proxy_hosts", claimRedirect: "redirection_hosts", claimRaw: "raw_routes"}[kind]
	var sid int64
	err := s.DB.QueryRow(`SELECT server_id FROM `+table+` WHERE id = ?`, id).Scan(&sid)
	return sid, err
}

const claimCheckFailed = "Could not check which hosts are in use on this server; try again."

// tenantRawRouteClaimProblem is the save-time check: for a non-admin (cu)
// saving rr on serverID, why its host matchers or listener may not be
// saved, or "". rr.ID is the row being updated (0 on create), judged on
// the server it is on. Every other row counts, enabled or not: a name is
// claimed by the row that holds it.
func (s *Server) tenantRawRouteClaimProblem(cu *models.User, serverID int64, rr *models.RawRoute) string {
	if isAdminUser(cu) || rr == nil {
		return ""
	}
	sid, err := s.claimServerID(claimRaw, rr.ID, serverID)
	if err != nil {
		return claimCheckFailed
	}
	proxies, redirs, raws, _, ok := s.serverResources(sid)
	if !ok {
		return claimCheckFailed
	}
	o := s.newOwnerTenancy()
	if why := rawRouteClaimRules(*rr, newClaimIndex(serverHostClaims(proxies, redirs, raws)), s.savePolicy(cu, o, s.heldNames(claimRaw, rr.ID))); why != "" {
		return "Not allowed for a non-admin account: " + why + "."
	}
	// The budget is the row owner's: the requester on create, the stored
	// row's owner (perhaps a group peer) on update.
	budget := *rr
	budget.OwnerID = sql.NullInt64{Int64: cu.ID, Valid: cu != nil}
	if rr.ID != 0 {
		if stored, err := models.GetRawRoute(s.DB, rr.ID); err == nil && stored != nil {
			budget.OwnerID = stored.OwnerID
		}
	}
	if why := ownerListenBudget(budget, raws); why != "" {
		return "Not allowed for a non-admin account: " + why + "."
	}
	return ""
}

// tenantDomainClaimProblem is the save-time check for a non-admin's proxy
// host or redirect (kind, id: 0 on create) with these domains on
// serverID: models.DomainsConflict already refuses a name any proxy host
// or redirect uses; this adds Advanced routes and wildcard coverage, of
// rows the account may not share names with.
func (s *Server) tenantDomainClaimProblem(cu *models.User, serverID int64, kind string, id int64, domains []string) string {
	if isAdminUser(cu) {
		return ""
	}
	sid, err := s.claimServerID(kind, id, serverID)
	if err != nil {
		return claimCheckFailed
	}
	proxies, redirs, raws, _, ok := s.serverResources(sid)
	if !ok {
		return claimCheckFailed
	}
	var hosts []string
	for _, d := range domains {
		h := claimHost(d)
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "*.") && !strings.Contains(strings.TrimPrefix(h, "*."), ".") {
			return fmt.Sprintf("Not allowed for a non-admin account: the domain %q is a wildcard over a whole top-level domain.", d)
		}
		hosts = append(hosts, h)
	}
	self := hostClaim{kind: kind, id: id}
	if why := newClaimIndex(serverHostClaims(proxies, redirs, raws)).hostConflict(self, hosts, s.savePolicy(cu, s.newOwnerTenancy(), s.heldNames(kind, id))); why != "" {
		return "Not allowed for a non-admin account: " + why + "."
	}
	return ""
}

// fleetRawRouteClaimProblem is the claim check for a copy of a
// non-admin's Advanced route (owned by owner) about to be written to
// targetServerID; copy.ID is the target row it replaces, or 0.
func (s *Server) fleetRawRouteClaimProblem(targetServerID int64, copy models.RawRoute, owner sql.NullInt64) string {
	if why := tenantListenProblem(copy.ListenAddrs(), s.reservedListenPorts()); why != "" {
		return "not allowed for a non-admin account on the target: " + why
	}
	proxies, redirs, raws, _, ok := s.serverResources(targetServerID)
	if !ok {
		return "could not check which hosts are in use on the target"
	}
	o := s.newOwnerTenancy()
	pol := claimPolicy{foreign: o.foreignTo(owner), keeps: func(hostClaim) bool { return true }, wildcards: func(_ string, c hostClaim) bool { return o.tenant(c.owner) }}
	if why := rawRouteClaimRules(copy, newClaimIndex(serverHostClaims(proxies, redirs, raws)), pol); why != "" {
		return "not allowed for a non-admin account on the target: " + why
	}
	copy.OwnerID = owner
	if why := ownerListenBudget(copy, raws); why != "" {
		return "not allowed for a non-admin account on the target: " + why
	}
	return ""
}

// fleetDomainClaimProblem is tenantDomainClaimProblem for a copy of a
// non-admin's proxy host or redirect (kind; id is the target row it
// replaces, or 0) on targetServerID.
func (s *Server) fleetDomainClaimProblem(targetServerID int64, kind string, id int64, domains []string, owner sql.NullInt64) string {
	proxies, redirs, raws, _, ok := s.serverResources(targetServerID)
	if !ok {
		return "could not check which hosts are in use on the target"
	}
	var hosts []string
	for _, d := range domains {
		if h := claimHost(d); h != "" {
			hosts = append(hosts, h)
		}
	}
	o := s.newOwnerTenancy()
	pol := claimPolicy{foreign: o.foreignTo(owner), keeps: func(hostClaim) bool { return true }, wildcards: func(_ string, c hostClaim) bool { return o.tenant(c.owner) }}
	if why := newClaimIndex(serverHostClaims(proxies, redirs, raws)).hostConflict(hostClaim{kind: kind, id: id}, hosts, pol); why != "" {
		return "not allowed for a non-admin account on the target: " + why
	}
	return ""
}

// withoutForeignHostClaims is the sync-time enforcement: the rows without
// the enabled non-admin rows that break the claim rules, judged against
// the server's enabled rows (see the top of this file for who keeps a
// contested name). serverID is the server being synced, whose held rows
// are logged and recorded in the activity log when that changes; a preview
// passes 0 and records nothing.
func (s *Server) withoutForeignHostClaims(serverID int64, proxies []models.ProxyHost, redirs []models.RedirectionHost, raws []models.RawRoute) ([]models.ProxyHost, []models.RedirectionHost, []models.RawRoute) {
	if s == nil || s.DB == nil {
		return proxies, redirs, raws
	}
	var claims []hostClaim
	for _, c := range serverHostClaims(proxies, redirs, raws) {
		if c.enabled {
			claims = append(claims, c)
		}
	}
	ix := newClaimIndex(claims)
	o := s.newOwnerTenancy()
	held := map[string]string{}
	var reserved map[int]bool

	// A non-admin's proxy host or redirect keeps its names against other
	// non-admins' rows; it gives way to an administrator's Advanced route
	// (proxy hosts and redirects of different owners never share a name,
	// models.DomainsConflict).
	adminRaw := claimPolicy{
		keeps:     func(c hostClaim) bool { return c.kind == claimRaw && !o.tenant(c.owner) },
		wildcards: func(string, hostClaim) bool { return false },
	}
	keptProxies := make([]models.ProxyHost, 0, len(proxies))
	for _, p := range proxies {
		if p.Enabled && o.tenant(p.OwnerID) {
			adminRaw.foreign = o.foreignTo(p.OwnerID)
			self := hostClaim{kind: claimProxy, id: p.ID}
			var hosts []string
			for _, d := range p.DomainList() {
				hosts = append(hosts, claimHost(d))
			}
			why := wildcardOverTLD(hosts)
			if why == "" {
				why = ix.hostConflict(self, hosts, adminRaw)
			}
			if why != "" {
				held[fmt.Sprintf("proxy:%d", p.ID)] = why
				continue
			}
		}
		keptProxies = append(keptProxies, p)
	}
	keptRedirs := make([]models.RedirectionHost, 0, len(redirs))
	for _, rd := range redirs {
		if rd.Enabled && o.tenant(rd.OwnerID) {
			adminRaw.foreign = o.foreignTo(rd.OwnerID)
			self := hostClaim{kind: claimRedirect, id: rd.ID}
			var hosts []string
			for _, d := range rd.DomainList() {
				hosts = append(hosts, claimHost(d))
			}
			why := wildcardOverTLD(hosts)
			if why == "" {
				why = ix.hostConflict(self, hosts, adminRaw)
			}
			if why != "" {
				held[fmt.Sprintf("redirect:%d", rd.ID)] = why
				continue
			}
		}
		keptRedirs = append(keptRedirs, rd)
	}
	keptRaws := make([]models.RawRoute, 0, len(raws))
	ownerPorts := map[int64]int{}
	for _, rr := range raws {
		if rr.Enabled && o.tenant(rr.OwnerID) {
			if reserved == nil {
				reserved = s.reservedListenPorts()
			}
			why := tenantListenProblem(rr.ListenAddrs(), reserved)
			if why == "" {
				n := listenPortCount(rr.ListenAddrs())
				if ownerPorts[rr.OwnerID.Int64]+n > maxTenantOwnerListenPorts {
					why = fmt.Sprintf("its account's Advanced routes would listen on more than %d ports on this server", maxTenantOwnerListenPorts)
				} else {
					ownerPorts[rr.OwnerID.Int64] += n
				}
			}
			if why == "" {
				id := rr.ID
				pol := claimPolicy{
					foreign:   o.foreignTo(rr.OwnerID),
					keeps:     func(c hostClaim) bool { return c.kind != claimRaw || !o.tenant(c.owner) || c.id < id },
					wildcards: func(_ string, c hostClaim) bool { return o.tenant(c.owner) },
				}
				why = rawRouteClaimRules(rr, ix, pol)
			}
			if why != "" {
				held[fmt.Sprintf("raw:%d", rr.ID)] = why
				continue
			}
		}
		keptRaws = append(keptRaws, rr)
	}
	if serverID > 0 {
		s.recordHeldHostClaims(serverID, held)
	}
	return keptProxies, keptRedirs, keptRaws
}

// recordHeldHostClaims logs each row of serverID left out for its host
// claims (held, keyed "raw:ID", "proxy:ID", "redirect:ID") and each that
// no longer is, when that changes, and records new holds in the activity
// log, where the administrator and the owner see them.
func (s *Server) recordHeldHostClaims(serverID int64, held map[string]string) {
	s.withheldMu.Lock()
	if s.heldClaims == nil {
		s.heldClaims = map[int64]map[string]string{}
	}
	before := s.heldClaims[serverID]
	s.heldClaims[serverID] = held
	s.withheldMu.Unlock()
	for key, why := range held {
		if before[key] != why {
			log.Printf("caddy sync: server %d: %s not deployed: %s", serverID, key, why)
			_ = models.LogActivity(s.DB, serverID, "system", "host_claim_held", key, why, false)
		}
	}
	for key := range before {
		if _, ok := held[key]; !ok {
			log.Printf("caddy sync: server %d: %s is deployed again (its host claims are allowed now)", serverID, key)
		}
	}
}

// reclassifyClaimProblem is the save-time claim check for the proxy host or
// redirect a non-admin's Advanced route (row) is turned into. A row still
// waiting for the #184 upgrade check is not turned into anything.
func (s *Server) reclassifyClaimProblem(cu *models.User, serverID int64, kind string, row models.RawRoute, domains []string) string {
	if isAdminUser(cu) {
		return ""
	}
	if s.rawRouteMigrationBlocks(row) {
		return "the Advanced route is waiting for the upgrade check"
	}
	if conflict, err := models.DomainsConflict(s.DB, serverID, domains, 0, 0); err != nil || conflict != "" {
		return "the domain is in use"
	}
	return s.tenantDomainClaimProblem(cu, serverID, kind, 0, domains)
}

// socketListen reports whether a listen address is a socket or file
// descriptor rather than a TCP/UDP port (an administrator's; a non-admin
// may not use one), which shares no port with anything.
func socketListen(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	return strings.HasPrefix(a, "unix") || strings.HasPrefix(a, "fd/") || strings.HasPrefix(a, "fdgram/")
}
