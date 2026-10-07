// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.61.0 (issue #126): Layer4 proxies that SHARE a port through a caddy-l4
// listener wrapper.
//
// A dedicated Layer4 server cannot take a port Caddy's HTTP servers already use
// (":443 is already bound"). A listener wrapper sits in front of an existing
// server's listener: it reads the first bytes of each connection, hands the ones
// that match a layer4 route (an SNI name, an SSH banner, RDP, PostgreSQL) to
// that route's handlers, and passes everything else on untouched — to Caddy's
// own TLS and HTTP handling. That is what lets SSH for ssh.example.com travel
// over :443 next to normal HTTPS. TCP only: wrapping a UDP packet connection is
// not offered.

// layer4WrapTargets maps the form's choice to the generated HTTP server.
var layer4WrapTargets = map[string]string{
	models.Layer4WrapHTTPS: "srv0",         // :443
	models.Layer4WrapHTTP:  "caddyui_http", // :80
}

var layer4SNIRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$`)

// validateLayer4Shared checks the shared-port fields and normalises them.
func validateLayer4Shared(p *models.Layer4Proxy) string {
	if models.NormalizeLayer4Protocol(p.Protocol) != models.Layer4ProtocolTCP {
		return "Sharing a port works for TCP only — use a dedicated listener for UDP."
	}
	p.Protocol = models.Layer4ProtocolTCP
	p.ListenAddr = ""
	if _, ok := layer4WrapTargets[p.WrapServer]; !ok {
		return "Choose which port to share: HTTPS (443) or HTTP (80)."
	}
	p.ListenPort = p.WrapPort()
	allowed := map[string]bool{models.Layer4MatchSSH: true, models.Layer4MatchRDP: true, models.Layer4MatchPostgres: true}
	if p.WrapServer == models.Layer4WrapHTTPS {
		allowed[models.Layer4MatchTLSSNI] = true
	} else {
		allowed[models.Layer4MatchHTTPHost] = true
	}
	if !allowed[p.MatchKind] {
		if p.WrapServer == models.Layer4WrapHTTPS {
			return "On the HTTPS port, match TLS SNI hostnames, or an SSH, RDP or PostgreSQL connection."
		}
		return "On the HTTP port, match HTTP hostnames, or an SSH, RDP or PostgreSQL connection."
	}
	if p.MatchKind == models.Layer4MatchTLSSNI || p.MatchKind == models.Layer4MatchHTTPHost {
		hosts := p.MatchHostList()
		if len(hosts) == 0 {
			return "Enter at least one hostname to match."
		}
		for _, h := range hosts {
			if !layer4SNIRe.MatchString(h) {
				return fmt.Sprintf("%q is not a valid hostname (a leading *. wildcard is allowed).", h)
			}
		}
		p.MatchHosts = strings.Join(hosts, ", ")
	} else {
		p.MatchHosts = ""
	}
	if p.TerminateTLS && p.MatchKind != models.Layer4MatchTLSSNI {
		p.TerminateTLS = false
	}
	return ""
}

// layer4MatcherFor returns the caddy-l4 matcher object for a shared proxy.
func layer4MatcherFor(p models.Layer4Proxy) map[string]any {
	hosts := make([]any, 0)
	for _, h := range p.MatchHostList() {
		hosts = append(hosts, h)
	}
	switch p.MatchKind {
	case models.Layer4MatchTLSSNI:
		return map[string]any{"tls": map[string]any{"sni": hosts}}
	case models.Layer4MatchHTTPHost:
		return map[string]any{"http": []any{map[string]any{"host": hosts}}}
	case models.Layer4MatchSSH:
		return map[string]any{"ssh": map[string]any{}}
	case models.Layer4MatchRDP:
		return map[string]any{"rdp": map[string]any{}}
	case models.Layer4MatchPostgres:
		return map[string]any{"postgres": map[string]any{}}
	}
	return nil
}

// buildLayer4ListenerWrappers returns, per generated HTTP server, the layer4
// listener wrapper holding one route per enabled shared proxy.
func buildLayer4ListenerWrappers(proxies []models.Layer4Proxy) map[string]map[string]any {
	routes := map[string][]any{}
	for _, p := range proxies {
		if !p.Enabled || !p.IsShared() {
			continue
		}
		server := layer4WrapTargets[p.WrapServer]
		matcher := layer4MatcherFor(p)
		if server == "" || matcher == nil {
			continue
		}
		var handle []any
		if p.TerminateTLS {
			handle = append(handle, map[string]any{"handler": "tls"})
		}
		handle = append(handle, map[string]any{
			"handler":   "proxy",
			"upstreams": []any{map[string]any{"dial": []any{"tcp/" + p.UpstreamDisplay()}}},
		})
		routes[server] = append(routes[server], map[string]any{
			"match":  []any{matcher},
			"handle": handle,
		})
	}
	out := map[string]map[string]any{}
	for server, r := range routes {
		out[server] = map[string]any{"wrapper": "layer4", "routes": r}
	}
	return out
}

// isLayer4Wrapper reports whether a live listener_wrappers entry is a layer4 one.
func isLayer4Wrapper(w any) bool {
	m, _ := w.(map[string]any)
	return m != nil && m["wrapper"] == "layer4"
}

func isTLSWrapper(w any) bool {
	m, _ := w.(map[string]any)
	return m != nil && m["wrapper"] == "tls"
}

// mergeListenerWrappers builds the listener_wrappers list for one HTTP server.
//
// Order matters: the first wrapper listed sees a new connection first. The
// layer4 wrapper has to read the RAW bytes, so it must come BEFORE the tls
// wrapper — and when no tls wrapper is listed Caddy applies TLS first, which
// leaves the layer4 matchers looking at decrypted nonsense (found on a real
// Caddy: "tls: first record does not look like a TLS handshake"). So on a TLS
// server (needsTLS) we list tls explicitly, right after ours. Other wrappers the
// operator configured (PROXY protocol, for example) keep their place ahead of
// ours: they must strip their header before layer4 reads the stream.
//
// dropOurs removes a layer4 wrapper CaddyUI wrote earlier (we own it); without
// it a live layer4 wrapper is left alone unless we are replacing it.
func mergeListenerWrappers(live []any, ours map[string]any, dropOurs, needsTLS bool) []any {
	var others []any
	var tls any
	for _, w := range live {
		switch {
		case isLayer4Wrapper(w) && (ours != nil || dropOurs):
			continue
		case isTLSWrapper(w):
			tls = w
		default:
			others = append(others, w)
		}
	}
	out := append([]any{}, others...)
	if ours != nil {
		out = append(out, ours)
		if tls == nil && needsTLS {
			tls = map[string]any{"wrapper": "tls"}
		}
	}
	if tls != nil {
		// Dropping ours must not leave behind the tls wrapper we added: a lone
		// tls entry is what Caddy does implicitly anyway.
		if ours != nil || len(others) > 0 || !dropOurs {
			out = append(out, tls)
		}
	}
	return out
}

func layer4WrapperSettingKey(serverID int64) string {
	return fmt.Sprintf("layer4_wrappers_managed_%d", serverID)
}

// managedWrapperServers lists the HTTP servers CaddyUI wrote a layer4 wrapper to
// on a previous sync — the only ones it may later clear.
func (s *Server) managedWrapperServers(serverID int64) map[string]bool {
	out := map[string]bool{}
	for _, name := range strings.Split(mustGetSetting(s.DB, layer4WrapperSettingKey(serverID)), ",") {
		if name = strings.TrimSpace(name); name != "" {
			out[name] = true
		}
	}
	return out
}

func (s *Server) saveManagedWrapperServers(serverID int64, set map[string]bool) {
	var names []string
	for _, n := range []string{"srv0", "caddyui_http"} {
		if set[n] {
			names = append(names, n)
		}
	}
	_ = models.SetSetting(s.DB, layer4WrapperSettingKey(serverID), strings.Join(names, ","))
}

// applyLayer4ListenerWrappers sets the wrappers on the proposed (pre-validation)
// config, mirroring what writeLayer4ListenerWrappers pushes.
func (s *Server) applyLayer4ListenerWrappers(cfg map[string]any, serverID int64, proxies []models.Layer4Proxy) {
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	wrappers := buildLayer4ListenerWrappers(proxies)
	managed := s.managedWrapperServers(serverID)
	for _, name := range []string{"srv0", "caddyui_http"} {
		srv, ok := servers[name].(map[string]any)
		if !ok {
			continue
		}
		ours := wrappers[name]
		if ours == nil && !managed[name] {
			continue
		}
		live, _ := srv["listener_wrappers"].([]any)
		merged := mergeListenerWrappers(live, ours, managed[name], name == "srv0")
		if len(merged) == 0 {
			delete(srv, "listener_wrappers")
		} else {
			srv["listener_wrappers"] = merged
		}
	}
}

// writeLayer4ListenerWrappers pushes the wrappers to the live Caddy. Only
// listener_wrappers entries of kind layer4 that CaddyUI wrote itself are ever
// replaced or removed; wrappers set any other way are left exactly as they are.
func (s *Server) writeLayer4ListenerWrappers(serverID int64, proxies []models.Layer4Proxy) error {
	wrappers := buildLayer4ListenerWrappers(proxies)
	managed := s.managedWrapperServers(serverID)
	changed := false
	for _, name := range []string{"srv0", "caddyui_http"} {
		ours := wrappers[name]
		if ours == nil && !managed[name] {
			continue
		}
		serverPath := "/config/apps/http/servers/" + name
		srvLive, err := s.Caddy.FetchPath(serverPath)
		if err != nil {
			return err
		}
		if srvLive == nil { // that HTTP server does not exist (yet); nothing to wrap
			if ours != nil {
				log.Printf("layer4 shared proxy: server %s has no %s server yet — the wrapper is applied once it exists", fmt.Sprint(serverID), name)
			}
			continue
		}
		path := serverPath + "/listener_wrappers"
		liveRaw, err := s.Caddy.FetchPath(path)
		if err != nil {
			return err
		}
		live, _ := liveRaw.([]any)
		merged := mergeListenerWrappers(live, ours, managed[name], name == "srv0")
		switch {
		case len(merged) == 0 && liveRaw != nil:
			if err := s.Caddy.DeletePath(path); err != nil {
				return err
			}
		case len(merged) > 0 && !configValuesEqual(liveRaw, merged):
			if liveRaw == nil {
				if err := s.Caddy.PutPath(path, merged); err != nil {
					return err
				}
			} else if err := s.Caddy.PatchPath(path, merged); err != nil {
				return err
			}
		}
		if ours != nil {
			if !managed[name] {
				managed[name] = true
				changed = true
			}
		} else if managed[name] {
			delete(managed, name)
			changed = true
		}
	}
	if changed {
		s.saveManagedWrapperServers(serverID, managed)
	}
	return nil
}

// layer4WrappersJSON is a small helper for tests and logs.
func layer4WrappersJSON(w map[string]map[string]any) string {
	b, _ := json.Marshal(w)
	return string(b)
}
