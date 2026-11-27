// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"sort"
	"strings"
)

// Tenant Caddyfile allowlist (issue #184 review).
//
// A non-admin's Caddyfile text — an Advanced route's source or a proxy
// host's Advanced config — reaches the live config only as routes (and, for
// a proxy host, the handlers of one route): everything else Caddy adapts the
// text to is dropped. The Caddyfile export, though, writes the text itself,
// so a site-level directive the live config never carried — `log` writing
// to any file, `bind` to a unix socket, `tls` with a custom ACME directory
// or certificate files, `handle_errors` — would come back to life when the
// export is loaded. Rather than list such directives, the adapted config is
// held to what the live config can carry, and anything else is refused.

// tenantAdaptedConfigProblem returns why the config Caddy adapted a
// non-admin's Caddyfile text to holds more than the live config keeps, or
// "". Allowed: the http app's servers with only `listen` and `routes`,
// listening on the standard ports or the route's stored listen set (never a
// socket), every route passing tenantRouteViolation; and TLS automation
// policies naming only hosts in subjects, with nothing but those subjects.
// No other app, no logging, no server option.
func (s *Server) tenantAdaptedConfigProblem(cfg map[string]any, subjects map[string]bool, listen []string) string {
	allowedListen := map[string]bool{":80": true, ":443": true}
	for _, a := range listen {
		allowedListen[a] = true
	}
	for _, key := range sortedKeys(cfg) {
		switch key {
		case "apps":
		case "logging":
			return "configures logging (a `log` directive), which the live route does not carry"
		default:
			return fmt.Sprintf("sets the global %q option, which the live route does not carry", key)
		}
	}
	apps, _ := cfg["apps"].(map[string]any)
	for _, name := range sortedKeys(apps) {
		switch name {
		case "http":
			if why := s.tenantAdaptedHTTPProblem(apps[name], allowedListen); why != "" {
				return why
			}
		case "tls":
			if why := tenantAdaptedTLSProblem(apps[name], subjects); why != "" {
				return why
			}
		default:
			return fmt.Sprintf("configures the Caddy %q app, which the live route does not carry", name)
		}
	}
	return ""
}

func (s *Server) tenantAdaptedHTTPProblem(app any, allowedListen map[string]bool) string {
	httpApp, ok := app.(map[string]any)
	if !ok {
		return "adapts to an HTTP app CaddyUI cannot read"
	}
	for _, key := range sortedKeys(httpApp) {
		if key != "servers" {
			return fmt.Sprintf("sets the HTTP app's %q option, which the live route does not carry", key)
		}
	}
	servers, _ := httpApp["servers"].(map[string]any)
	for _, name := range sortedKeys(servers) {
		srv, ok := servers[name].(map[string]any)
		if !ok {
			return "adapts to a server CaddyUI cannot read"
		}
		for _, key := range sortedKeys(srv) {
			switch key {
			case "listen", "routes":
			case "logs":
				return "configures logging (a `log` directive), which the live route does not carry"
			case "errors":
				return "handles errors (`handle_errors`), which the live route does not carry"
			case "tls_connection_policies":
				return "configures TLS for its site (`tls`), which the live route does not carry"
			default:
				return fmt.Sprintf("sets the server option %q, which the live route does not carry", key)
			}
		}
		for _, a := range asAnySlice(srv["listen"]) {
			addr, _ := a.(string)
			if strings.Contains(addr, "/") || !allowedListen[addr] {
				return "listens on an address its route does not (`bind` or a socket address)"
			}
		}
		for _, route := range asAnySlice(srv["routes"]) {
			if s.tenantRouteViolation(route) != "" {
				return "adapts to routes a non-admin may not have"
			}
		}
	}
	return ""
}

func tenantAdaptedTLSProblem(app any, subjects map[string]bool) string {
	const why = "configures TLS certificates or issuers (`tls`), which the live route does not carry"
	tlsApp, ok := app.(map[string]any)
	if !ok {
		return why
	}
	for _, key := range sortedKeys(tlsApp) {
		if key != "automation" {
			return why
		}
	}
	automation, ok := tlsApp["automation"].(map[string]any)
	if !ok {
		return why
	}
	for _, key := range sortedKeys(automation) {
		if key != "policies" {
			return why
		}
	}
	for _, p := range asAnySlice(automation["policies"]) {
		policy, ok := p.(map[string]any)
		if !ok {
			return why
		}
		for _, key := range sortedKeys(policy) {
			if key != "subjects" {
				return why
			}
		}
		for _, sub := range asAnySlice(policy["subjects"]) {
			name, _ := sub.(string)
			if !subjects[strings.ToLower(name)] {
				return why
			}
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
