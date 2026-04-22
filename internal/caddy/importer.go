package caddy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

type ImportResult struct {
	Proxies     []models.ProxyHost
	Redirect    []models.RedirectionHost
	Passthrough []models.RawRoute
	Skipped     []string
	RawJSON     string
}

func (c *Client) FetchConfig() (map[string]any, string, error) {
	req, err := http.NewRequest(http.MethodGet, c.AdminURL+"/config/", nil)
	if err != nil {
		return nil, "", err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode >= 300 {
		return nil, string(body), fmt.Errorf("caddy admin status %d", resp.StatusCode)
	}
	var cfg map[string]any
	if len(body) == 0 || string(body) == "null" {
		return map[string]any{}, string(body), nil
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, string(body), fmt.Errorf("parse caddy config: %w", err)
	}
	return cfg, string(body), nil
}

// FetchPath GETs /config/{path}. Returns (nil, nil) when Caddy returns `null`
// (i.e. that config branch is unset). Errors on network failure or non-2xx.
func (c *Client) FetchPath(path string) (any, error) {
	req, err := http.NewRequest(http.MethodGet, c.AdminURL+path, nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("caddy GET %s status %d: %s", path, resp.StatusCode, string(body))
	}
	if len(body) == 0 || string(body) == "null" {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return out, nil
}

func (c *Client) Import() (*ImportResult, error) {
	cfg, raw, err := c.FetchConfig()
	if err != nil {
		return nil, err
	}
	r := parseConfig(cfg)
	r.RawJSON = raw
	return r, nil
}

func parseConfig(cfg map[string]any) *ImportResult {
	r := &ImportResult{}
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)

	for srvName, s := range servers {
		srv, _ := s.(map[string]any)
		// Skip the auto-HTTPS redirect helper server — it's regenerated automatically
		if srvName == "remaining_auto_https_redirects" {
			continue
		}
		routes, _ := srv["routes"].([]any)
		for i, rv := range routes {
			route, _ := rv.(map[string]any)
			hosts := extractHosts(route)
			label := strings.Join(hosts, ",")
			if label == "" {
				label = fmt.Sprintf("%s route[%d] (no host match)", srvName, i)
			}

			kind, proxy, redir := classifyRoute(route, hosts)
			switch kind {
			case kindProxy:
				r.Proxies = append(r.Proxies, proxy)
			case kindRedirect:
				r.Redirect = append(r.Redirect, redir)
			case kindRaw:
				blob, err := json.Marshal(route)
				if err != nil {
					r.Skipped = append(r.Skipped, fmt.Sprintf("%s: can't serialize (%v)", label, err))
					continue
				}
				r.Passthrough = append(r.Passthrough, models.RawRoute{
					Label:    label,
					JSONData: string(blob),
					Enabled:  true,
				})
			}
		}
	}
	return r
}

type routeKind int

const (
	kindRaw routeKind = iota
	kindProxy
	kindRedirect
)

// classifyRoute decides how to import a single route.
// Rules:
//  1. If the route contains ANY inner path matcher (per-path routing via handle/handle_path/redir),
//     we can't faithfully represent it — passthrough. CaddyUI's own exploit-blocker subroute is
//     stripped first so a proxy host with "Block common exploits" enabled still classifies as proxy.
//  2. If the route has exactly one reverse_proxy handler → proxy host.
//  3. If the route has zero reverse_proxy handlers but at least one 3xx static_response with Location → redirect.
//  4. Otherwise → passthrough (raw JSON preserved on sync).
func classifyRoute(route map[string]any, hosts []string) (routeKind, models.ProxyHost, models.RedirectionHost) {
	if len(hosts) == 0 {
		return kindRaw, models.ProxyHost{}, models.RedirectionHost{}
	}
	handle, hadExploitBlocker := stripExploitBlocker(route["handle"])
	if hasInnerPathMatcher(handle) {
		return kindRaw, models.ProxyHost{}, models.RedirectionHost{}
	}

	handlers := flattenHandlers(handle)
	var rpHandlers, srHandlers []map[string]any
	for _, h := range handlers {
		switch h["handler"] {
		case "reverse_proxy":
			rpHandlers = append(rpHandlers, h)
		case "static_response":
			srHandlers = append(srHandlers, h)
		}
	}

	if len(rpHandlers) == 1 {
		if p, ok := proxyFromHandler(rpHandlers[0], hosts); ok {
			p.BlockCommonExploits = hadExploitBlocker
			return kindProxy, p, models.RedirectionHost{}
		}
	}
	if len(rpHandlers) == 0 && len(srHandlers) > 0 {
		for _, h := range srHandlers {
			if rd, ok := redirectFromHandler(h, hosts); ok {
				return kindRedirect, models.ProxyHost{}, rd
			}
		}
	}
	return kindRaw, models.ProxyHost{}, models.RedirectionHost{}
}

// stripExploitBlocker returns handle[] with any CaddyUI-emitted exploit-blocker
// subroute removed, plus a flag indicating whether one was found. The blocker's
// path matchers (/.env*, /wp-admin*, etc.) would otherwise flip the route into
// the "complex / per-path" bucket, sending every proxy host with the flag on
// into Advanced routes at import time.
func stripExploitBlocker(handle any) (any, bool) {
	list, ok := handle.([]any)
	if !ok {
		return handle, false
	}
	out := make([]any, 0, len(list))
	stripped := false
	for _, item := range list {
		if isExploitBlockerSubroute(item) {
			stripped = true
			continue
		}
		out = append(out, item)
	}
	return out, stripped
}

// isExploitBlockerSubroute recognizes the shape produced by caddy.ExploitBlockerSubroute:
// a subroute handler whose inner routes all terminate with static_response 403 on a set
// of exploit-probing paths. Matching on shape (not exact paths) so minor list changes
// don't silently break import.
func isExploitBlockerSubroute(item any) bool {
	h, ok := item.(map[string]any)
	if !ok || h["handler"] != "subroute" {
		return false
	}
	routes, _ := h["routes"].([]any)
	if len(routes) == 0 {
		return false
	}
	for _, r := range routes {
		rm, _ := r.(map[string]any)
		matches, _ := rm["match"].([]any)
		hasExploitPath := false
		for _, m := range matches {
			mm, _ := m.(map[string]any)
			paths, _ := mm["path"].([]any)
			for _, p := range paths {
				if s, ok := p.(string); ok && looksLikeExploitPath(s) {
					hasExploitPath = true
					break
				}
			}
		}
		if !hasExploitPath {
			return false
		}
		handlers, _ := rm["handle"].([]any)
		if len(handlers) == 0 {
			return false
		}
		for _, hh := range handlers {
			hm, _ := hh.(map[string]any)
			if hm["handler"] != "static_response" {
				return false
			}
			code := 0
			switch v := hm["status_code"].(type) {
			case float64:
				code = int(v)
			case int:
				code = v
			}
			if code != 403 {
				return false
			}
		}
	}
	return true
}

func looksLikeExploitPath(p string) bool {
	markers := []string{".env", "wp-admin", "wp-login", "phpmyadmin", ".git", "xmlrpc"}
	for _, m := range markers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

// hasInnerPathMatcher returns true if any nested subroute has a path matcher.
// The outer route's own match (host) is NOT inspected — only nested routes.
func hasInnerPathMatcher(handle any) bool {
	list, _ := handle.([]any)
	for _, item := range list {
		h, _ := item.(map[string]any)
		if h == nil {
			continue
		}
		if h["handler"] == "subroute" {
			subroutes, _ := h["routes"].([]any)
			for _, sr := range subroutes {
				srm, _ := sr.(map[string]any)
				matches, _ := srm["match"].([]any)
				for _, m := range matches {
					mm, _ := m.(map[string]any)
					if _, hasPath := mm["path"]; hasPath {
						return true
					}
					if _, hasMethod := mm["method"]; hasMethod {
						return true
					}
				}
				if hasInnerPathMatcher(srm["handle"]) {
					return true
				}
			}
		}
	}
	return false
}

func extractHosts(route map[string]any) []string {
	matches, _ := route["match"].([]any)
	var out []string
	for _, m := range matches {
		mm, _ := m.(map[string]any)
		hs, _ := mm["host"].([]any)
		for _, h := range hs {
			if s, ok := h.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// flattenHandlers walks a handle[] list, descending into subroute handlers to produce a flat list.
func flattenHandlers(in any) []map[string]any {
	list, _ := in.([]any)
	var out []map[string]any
	for _, item := range list {
		h, _ := item.(map[string]any)
		if h == nil {
			continue
		}
		if h["handler"] == "subroute" {
			sroutes, _ := h["routes"].([]any)
			for _, sr := range sroutes {
				srm, _ := sr.(map[string]any)
				out = append(out, flattenHandlers(srm["handle"])...)
			}
			continue
		}
		out = append(out, h)
	}
	return out
}

func proxyFromHandler(h map[string]any, hosts []string) (models.ProxyHost, bool) {
	ups, _ := h["upstreams"].([]any)
	if len(ups) == 0 {
		return models.ProxyHost{}, false
	}
	first, _ := ups[0].(map[string]any)
	dial, _ := first["dial"].(string)
	fh, fp := splitHostPort(dial)
	if fh == "" || fp == 0 {
		return models.ProxyHost{}, false
	}
	scheme := "http"
	if transport, ok := h["transport"].(map[string]any); ok {
		if _, hasTLS := transport["tls"]; hasTLS {
			scheme = "https"
		}
	}
	return models.ProxyHost{
		Domains:       strings.Join(hosts, ","),
		ForwardScheme: scheme,
		ForwardHost:   fh,
		ForwardPort:   fp,
		Enabled:       true,
		SSLEnabled:    true,
		SSLForced:     true,
		HTTP2Support:  true,
	}, true
}

func redirectFromHandler(h map[string]any, hosts []string) (models.RedirectionHost, bool) {
	codeAny := h["status_code"]
	code := 0
	switch v := codeAny.(type) {
	case float64:
		code = int(v)
	case string:
		code, _ = strconv.Atoi(v)
	case int:
		code = v
	}
	if code < 300 || code >= 400 {
		return models.RedirectionHost{}, false
	}
	hdrs, _ := h["headers"].(map[string]any)
	locs, _ := hdrs["Location"].([]any)
	if len(locs) == 0 {
		return models.RedirectionHost{}, false
	}
	loc, _ := locs[0].(string)
	if loc == "" {
		return models.RedirectionHost{}, false
	}
	scheme, domain, path := splitRedirect(loc)
	return models.RedirectionHost{
		Domains:         strings.Join(hosts, ","),
		ForwardScheme:   scheme,
		ForwardDomain:   domain,
		ForwardHTTPCode: code,
		PreservePath:    strings.Contains(path, "{http.request.uri}") || path != "",
		Enabled:         true,
		SSLEnabled:      true,
		SSLForced:       true,
	}, true
}

func splitHostPort(dial string) (string, int) {
	d := dial
	if i := strings.Index(d, "/"); i != -1 {
		d = d[i+1:]
	}
	i := strings.LastIndex(d, ":")
	if i == -1 {
		return d, 80
	}
	host := d[:i]
	port, err := strconv.Atoi(d[i+1:])
	if err != nil {
		return host, 0
	}
	return host, port
}

func splitRedirect(loc string) (scheme, domain, path string) {
	if strings.HasPrefix(loc, "{http.request.scheme}://") {
		scheme = "auto"
		rest := strings.TrimPrefix(loc, "{http.request.scheme}://")
		domain, path = splitDomainPath(rest)
		return
	}
	u, err := url.Parse(loc)
	if err != nil || u.Scheme == "" || u.Host == "" {
		scheme = "auto"
		if strings.HasPrefix(loc, "//") {
			domain, path = splitDomainPath(strings.TrimPrefix(loc, "//"))
			return
		}
		domain = loc
		return
	}
	scheme = u.Scheme
	domain = u.Host
	path = u.Path
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return
}

func splitDomainPath(s string) (domain, path string) {
	i := strings.Index(s, "/")
	if i == -1 {
		return s, ""
	}
	return s[:i], s[i:]
}
