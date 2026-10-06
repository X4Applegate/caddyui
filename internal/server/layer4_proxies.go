// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

// Layer4 proxies (v2.58.0, issue #122): TCP/UDP forwards managed as individual
// resources. CaddyUI generates a caddy-l4 server per enabled row and merges
// them into apps.layer4 together with the optional raw per-server Layer4
// Caddyfile block. Admin-only: a layer4 listener opens a port on the host and a
// forward reaches whatever the host can reach.

// layer4ServerPrefix names the generated caddy-l4 servers. Everything under
// this prefix is owned by CaddyUI and rewritten on every sync.
const layer4ServerPrefix = "caddyui_l4_"

// buildManagedLayer4Servers turns the enabled rows into caddy-l4 servers.
func buildManagedLayer4Servers(proxies []models.Layer4Proxy) map[string]any {
	out := map[string]any{}
	for _, p := range proxies {
		if !p.Enabled {
			continue
		}
		listen := p.Protocol + "/" + p.ListenDisplay()
		dial := p.Protocol + "/" + p.UpstreamDisplay()
		out[fmt.Sprintf("%s%d", layer4ServerPrefix, p.ID)] = map[string]any{
			"listen": []any{listen},
			"routes": []any{map[string]any{
				"handle": []any{map[string]any{
					"handler":   "proxy",
					"upstreams": []any{map[string]any{"dial": []any{dial}}},
				}},
			}},
		}
	}
	return out
}

// mergeLayer4App adds the managed servers to the raw (Caddyfile-derived)
// layer4 app. The raw app is returned unchanged when there is nothing to add.
func mergeLayer4App(raw map[string]any, managed map[string]any) map[string]any {
	if len(managed) == 0 {
		return raw
	}
	app := map[string]any{}
	for k, v := range raw {
		app[k] = v
	}
	servers := map[string]any{}
	if existing, ok := raw["servers"].(map[string]any); ok {
		for k, v := range existing {
			servers[k] = v
		}
	}
	for k, v := range managed {
		servers[k] = v
	}
	app["servers"] = servers
	return app
}

// layer4AppFor builds the complete apps.layer4 for a server: the raw
// Caddyfile block (adapted through the given client) plus the managed rows.
func layer4AppFor(cl *caddy.Client, srv *models.CaddyServer, proxies []models.Layer4Proxy) (map[string]any, error) {
	raw, err := buildLayer4App(cl, srv.Layer4Caddyfile)
	if err != nil {
		return nil, err
	}
	return mergeLayer4App(raw, buildManagedLayer4Servers(proxies)), nil
}

// hasManagedLayer4Live reports whether the live config still carries servers
// CaddyUI generated earlier — so removing the last proxy on an otherwise empty
// server still clears them instead of being skipped by the empty-config guard.
func hasManagedLayer4Live(cl *caddy.Client) bool {
	live, err := cl.FetchPath("/config/apps/layer4")
	if err != nil || live == nil {
		return false
	}
	app, _ := live.(map[string]any)
	servers, _ := app["servers"].(map[string]any)
	for name := range servers {
		if strings.HasPrefix(name, layer4ServerPrefix) {
			return true
		}
	}
	return false
}

var layer4HostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)

// reservedLayer4Ports are ports a layer4 listener must not take: HTTP/HTTPS
// (Caddy's own servers, including HTTP/3 on UDP 443) and the admin API.
var reservedLayer4Ports = map[int]string{80: "HTTP", 443: "HTTPS", 2019: "the Caddy admin API"}

// validateLayer4Proxy checks a proxy's fields, returning a user-facing message.
func validateLayer4Proxy(p *models.Layer4Proxy) string {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 100 || strings.ContainsAny(p.Name, "\r\n\x00") {
		return "Name is required (up to 100 characters)."
	}
	p.Protocol = models.NormalizeLayer4Protocol(p.Protocol)
	p.ListenAddr = strings.Trim(strings.TrimSpace(p.ListenAddr), "[]")
	p.UpstreamHost = strings.Trim(strings.TrimSpace(p.UpstreamHost), "[]")
	if p.ListenAddr != "" && net.ParseIP(p.ListenAddr) == nil {
		return "Listen address must be empty (all interfaces) or an IP address."
	}
	if p.ListenPort < 1 || p.ListenPort > 65535 {
		return "Listen port must be between 1 and 65535."
	}
	if why, bad := reservedLayer4Ports[p.ListenPort]; bad {
		return fmt.Sprintf("Port %d is used by %s — pick another listen port.", p.ListenPort, why)
	}
	if p.UpstreamHost == "" {
		return "Upstream host is required."
	}
	if net.ParseIP(p.UpstreamHost) == nil && !layer4HostnameRe.MatchString(p.UpstreamHost) {
		return "Upstream host must be a hostname or an IP address (no ports, paths or spaces)."
	}
	if p.UpstreamPort < 1 || p.UpstreamPort > 65535 {
		return "Upstream port must be between 1 and 65535."
	}
	return ""
}

func parseLayer4Form(r *http.Request) *models.Layer4Proxy {
	_ = r.ParseForm()
	port := func(name string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(name)))
		return n
	}
	return &models.Layer4Proxy{
		Name:         r.FormValue("name"),
		Protocol:     r.FormValue("protocol"),
		ListenAddr:   r.FormValue("listen_addr"),
		ListenPort:   port("listen_port"),
		UpstreamHost: r.FormValue("upstream_host"),
		UpstreamPort: port("upstream_port"),
		Enabled:      r.FormValue("enabled") == "on",
		NodeLocal:    r.FormValue("node_local") == "on",
		Notes:        strings.TrimSpace(r.FormValue("notes")),
	}
}

// previewLayer4Validate asks Caddy to validate the config a sync would push
// with p added or replaced, so a rejected proxy (for example a Caddy without
// the caddy-l4 module) is refused at save time with Caddy's own message.
// Returns "" when Caddy accepts it or cannot be reached.
func (s *Server) previewLayer4Validate(serverID int64, p *models.Layer4Proxy) string {
	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err != nil {
		return ""
	}
	proxies, _ := models.ListLayer4Proxies(s.DB, serverID)
	replaced := false
	for i := range proxies {
		if proxies[i].ID == p.ID && p.ID != 0 {
			proxies[i] = *p
			replaced = true
		}
	}
	if !replaced {
		proxies = append(proxies, *p)
	}
	cl := s.caddyForServer(serverID)
	app, err := layer4AppFor(cl, srv, proxies)
	if err != nil {
		return "Caddy rejected the layer4 configuration: " + err.Error()
	}
	current, _, err := cl.FetchConfig()
	if err != nil {
		return ""
	}
	proposed, err := deepCopyMap(current)
	if err != nil {
		return ""
	}
	applyLayer4App(proposed, app)
	if err := cl.Validate(proposed); err != nil {
		return "Caddy rejected this layer4 proxy: " + err.Error() + " (Layer4 needs a Caddy build with the caddy-l4 module, such as applegater/caddyui-caddy.)"
	}
	return ""
}

// --- pages ---

func (s *Server) listLayer4Proxies(w http.ResponseWriter, r *http.Request) {
	sid := s.currentServerID(r)
	rows, err := models.ListLayer4Proxies(s.DB, sid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	srv, _ := models.GetCaddyServer(s.DB, sid)
	raw := ""
	if srv != nil {
		raw = strings.TrimSpace(srv.Layer4Caddyfile)
	}
	s.render(w, r, "layer4_proxies.html", map[string]any{
		"User": s.currentUser(r), "Rows": rows, "Section": "layer4",
		"ServerID": sid, "HasRaw": raw != "", "Flash": r.URL.Query().Get("flash"),
	})
}

func (s *Server) renderLayer4Form(w http.ResponseWriter, r *http.Request, p *models.Layer4Proxy, errMsg string) {
	s.render(w, r, "layer4_proxy_form.html", map[string]any{
		"User": s.currentUser(r), "Row": p, "Error": errMsg, "Section": "layer4",
		"ServerID": s.currentServerID(r), "OtherServers": s.otherManagedServers(r),
	})
}

func (s *Server) newLayer4Proxy(w http.ResponseWriter, r *http.Request) {
	s.renderLayer4Form(w, r, &models.Layer4Proxy{Protocol: models.Layer4ProtocolTCP, Enabled: true}, "")
}

func (s *Server) editLayer4Proxy(w http.ResponseWriter, r *http.Request) {
	p := s.layer4FromURL(w, r)
	if p == nil {
		return
	}
	s.renderLayer4Form(w, r, p, "")
}

// layer4FromURL loads the proxy for {id} and checks it belongs to the selected
// server; it writes the error response and returns nil otherwise.
func (s *Server) layer4FromURL(w http.ResponseWriter, r *http.Request) *models.Layer4Proxy {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := models.GetLayer4Proxy(s.DB, id)
	if err != nil || p == nil || p.ServerID != s.currentServerID(r) {
		http.NotFound(w, r)
		return nil
	}
	return p
}

func (s *Server) saveLayer4Checks(w http.ResponseWriter, r *http.Request, p *models.Layer4Proxy) bool {
	if msg := validateLayer4Proxy(p); msg != "" {
		s.renderLayer4Form(w, r, p, msg)
		return false
	}
	sid := s.currentServerID(r)
	if other, err := models.Layer4ListenConflict(s.DB, sid, *p); err != nil {
		s.renderLayer4Form(w, r, p, "Could not check for conflicts: "+err.Error())
		return false
	} else if other != nil {
		s.renderLayer4Form(w, r, p, fmt.Sprintf("%s %s is already used by %q on this server.", strings.ToUpper(p.Protocol), p.ListenDisplay(), other.Name))
		return false
	}
	if p.Enabled {
		if msg := s.previewLayer4Validate(sid, p); msg != "" {
			s.renderLayer4Form(w, r, p, msg)
			return false
		}
	}
	return true
}

func (s *Server) createLayer4Proxy(w http.ResponseWriter, r *http.Request) {
	p := parseLayer4Form(r)
	deployTo := s.effectiveDeployTargets(s.currentServerID(r), parseDeployTo(r))
	if !s.saveLayer4Checks(w, r, p) {
		return
	}
	sid := s.currentServerID(r)
	id, err := models.CreateLayer4Proxy(s.DB, sid, p)
	if err != nil {
		s.renderLayer4Form(w, r, p, err.Error())
		return
	}
	p.ID, p.ServerID = id, sid
	_ = models.LogActivity(s.DB, sid, s.currentUserEmail(r), "layer4_create", fmt.Sprintf("layer4:%d", id), p.Name+" "+p.ListenKey(), true)
	s.trySyncCaddy(sid, false)
	if len(deployTo) > 0 {
		s.crossDeployLayer4Proxy(s.currentUserEmail(r), sid, p, deployTo)
	}
	http.Redirect(w, r, "/layer4-proxies", http.StatusSeeOther)
}

func (s *Server) updateLayer4Proxy(w http.ResponseWriter, r *http.Request) {
	existing := s.layer4FromURL(w, r)
	if existing == nil {
		return
	}
	p := parseLayer4Form(r)
	p.ID, p.ServerID = existing.ID, existing.ServerID
	deployTo := s.effectiveDeployTargets(s.currentServerID(r), parseDeployTo(r))
	if !s.saveLayer4Checks(w, r, p) {
		return
	}
	if err := models.UpdateLayer4Proxy(s.DB, p); err != nil {
		s.renderLayer4Form(w, r, p, err.Error())
		return
	}
	_ = models.LogActivity(s.DB, p.ServerID, s.currentUserEmail(r), "layer4_update", fmt.Sprintf("layer4:%d", p.ID), p.Name+" "+p.ListenKey(), true)
	s.trySyncCaddy(p.ServerID, false)
	if len(deployTo) > 0 {
		s.crossDeployLayer4Proxy(s.currentUserEmail(r), p.ServerID, p, deployTo)
	}
	http.Redirect(w, r, "/layer4-proxies", http.StatusSeeOther)
}

func (s *Server) toggleLayer4Proxy(w http.ResponseWriter, r *http.Request) {
	p := s.layer4FromURL(w, r)
	if p == nil {
		return
	}
	enabled, err := models.ToggleLayer4Proxy(s.DB, p.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.Enabled = enabled
	action := "layer4_disable"
	if enabled {
		action = "layer4_enable"
	}
	_ = models.LogActivity(s.DB, p.ServerID, s.currentUserEmail(r), action, fmt.Sprintf("layer4:%d", p.ID), p.Name, true)
	s.trySyncCaddy(p.ServerID, false)
	// A toggle is a change to the resource, so it follows the automatic
	// deployment targets like a save does.
	if targets := s.effectiveDeployTargets(p.ServerID, nil); len(targets) > 0 {
		s.crossDeployLayer4Proxy(s.currentUserEmail(r), p.ServerID, p, targets)
	}
	http.Redirect(w, r, "/layer4-proxies", http.StatusSeeOther)
}

func (s *Server) deleteLayer4Proxy(w http.ResponseWriter, r *http.Request) {
	p := s.layer4FromURL(w, r)
	if p == nil {
		return
	}
	note := s.noteFleetDeletion(models.FleetResourceLayer4, p.ID, p.Name)
	if err := models.DeleteLayer4Proxy(s.DB, p.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = models.LogActivity(s.DB, p.ServerID, s.currentUserEmail(r), "layer4_delete", fmt.Sprintf("layer4:%d", p.ID), p.Name+" "+p.ListenKey(), true)
	s.trySyncCaddy(p.ServerID, false)
	// Copies on other servers are removed only when the source server has
	// "Propagate deletions" enabled (v2.59.0, issue #120).
	s.propagateNotedDeletion(s.currentUserEmail(r), note)
	msg := "Deleted " + p.Name + "."
	if src, _ := models.GetCaddyServer(s.DB, p.ServerID); src == nil || !src.PropagateDeletions {
		msg += " Copies on other servers were not removed."
	}
	http.Redirect(w, r, "/layer4-proxies?flash="+urlQueryEscape(msg), http.StatusSeeOther)
}

func urlQueryEscape(v string) string {
	return strings.NewReplacer(" ", "+", "&", "%26", "?", "%3F", "#", "%23").Replace(v)
}

// --- fleet deployment ---

// upsertFleetLayer4Proxy creates or updates the target server's copy of a
// proxy, keyed through the durable source→target mapping and, failing that,
// the same protocol + listen socket.
func (s *Server) upsertFleetLayer4Proxy(sourceServerID, targetServerID int64, source models.Layer4Proxy) (fleetUpsertResult, error) {
	targetID, err := s.mappedFleetTarget(sourceServerID, models.FleetResourceLayer4, source.ID, targetServerID)
	if err != nil {
		return fleetUpsertResult{}, err
	}
	var existing *models.Layer4Proxy
	if targetID > 0 {
		existing, err = models.GetLayer4Proxy(s.DB, targetID)
		if err != nil {
			return fleetUpsertResult{}, err
		}
	} else {
		targets, err := models.ListLayer4Proxies(s.DB, targetServerID)
		if err != nil {
			return fleetUpsertResult{}, err
		}
		for i := range targets {
			if targets[i].ListenKey() == source.ListenKey() {
				existing = &targets[i]
				targetID = targets[i].ID
				break
			}
		}
	}
	copy := source
	copy.ID, copy.ServerID, copy.NodeLocal = 0, targetServerID, false
	created := existing == nil
	changed := true
	if existing != nil {
		copy.ID = existing.ID
		current := *existing
		current.CreatedAt, current.UpdatedAt = copy.CreatedAt, copy.UpdatedAt
		changed = current != copy
	} else if other, err := models.Layer4ListenConflict(s.DB, targetServerID, copy); err != nil {
		return fleetUpsertResult{}, err
	} else if other != nil {
		return fleetUpsertResult{}, fmt.Errorf("%s %s is already used on the target server", strings.ToUpper(copy.Protocol), copy.ListenDisplay())
	}
	if created {
		targetID, err = models.CreateLayer4Proxy(s.DB, targetServerID, &copy)
	} else if changed {
		err = models.UpdateLayer4Proxy(s.DB, &copy)
	}
	if err != nil {
		return fleetUpsertResult{}, err
	}
	if err := models.SaveFleetDeployment(s.DB, sourceServerID, models.FleetResourceLayer4, source.ID, targetServerID, targetID); err != nil {
		return fleetUpsertResult{}, err
	}
	return fleetUpsertResult{ID: targetID, Created: created, Changed: changed}, nil
}

// crossDeployLayer4Proxy mirrors a proxy onto the given fleet targets, exactly
// as crossDeployProxyHost does for hosts. A node-local proxy is never deployed.
func (s *Server) crossDeployLayer4Proxy(actor string, sourceServerID int64, p *models.Layer4Proxy, serverIDs []int64) {
	s.fleetDeployMu.Lock()
	defer s.fleetDeployMu.Unlock()
	if p.NodeLocal {
		_ = models.LogActivity(s.DB, sourceServerID, actor, "layer4_cross_deploy", fmt.Sprintf("layer4:%d", p.ID), "skipped: proxy is marked node-local", false)
		return
	}
	for _, sid := range serverIDs {
		if _, _, err := s.validateFleetPair(sourceServerID, sid); err != nil {
			log.Printf("cross-deploy layer4 target %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sourceServerID, actor, "layer4_cross_deploy", fmt.Sprintf("server:%d", sid), err.Error(), false)
			continue
		}
		result, err := s.upsertFleetLayer4Proxy(sourceServerID, sid, *p)
		if err != nil {
			log.Printf("cross-deploy layer4 to server %d: %v", sid, err)
			_ = models.LogActivity(s.DB, sid, actor, "layer4_cross_deploy", "layer4:new", p.Name+": "+err.Error(), false)
			continue
		}
		detail := "already current " + p.Name
		if result.Created {
			detail = "created " + p.Name
		} else if result.Changed {
			detail = "updated " + p.Name
		}
		_ = models.LogActivity(s.DB, sid, actor, "layer4_cross_deploy", fmt.Sprintf("layer4:%d", result.ID), detail, true)
		if result.Changed {
			if err := s.syncCaddy(sid, false); err != nil {
				log.Printf("cross-deploy layer4 sync server %d: %v", sid, err)
			}
		}
	}
}
