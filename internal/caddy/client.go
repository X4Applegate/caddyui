package caddy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

type Client struct {
	AdminURL string
	HTTP     *http.Client
}

func New(adminURL string) *Client {
	return &Client{
		AdminURL: strings.TrimRight(adminURL, "/"),
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

type LoadedConfig struct {
	Apps map[string]any `json:"apps"`
}

func (c *Client) Load(cfg map[string]any) error {
	return c.send(http.MethodPost, "/load", cfg)
}

// Validate POSTs the given config to /load?validate_only=true. Caddy runs the full
// provisioning pipeline but does NOT apply the config. Returns nil if valid,
// or an error with Caddy's diagnostic message if not.
func (c *Client) Validate(cfg map[string]any) error {
	return c.send(http.MethodPost, "/load?validate_only=true", cfg)
}

// PutPath upserts the config value at the given path (e.g. "/config/apps/http/servers/srv0/routes").
// Uses POST which is Caddy's "set or replace" semantic for OBJECTS (PUT is strict insert and
// 409s if the key exists). NOTE: for arrays, POST appends the body as a single element, which
// would nest an array inside the array. Use PatchPath to replace an array wholesale.
func (c *Client) PutPath(path string, val any) error {
	return c.send(http.MethodPost, path, val)
}

// PatchPath replaces the existing config value at the given path. Required for
// array paths like .../routes where POST would append-and-nest rather than replace.
// Fails with 404 if the path doesn't exist — callers should use PutPath for first writes.
func (c *Client) PatchPath(path string, val any) error {
	return c.send(http.MethodPatch, path, val)
}

// AdaptResult is what /adapt returns: the fully-resolved Caddy JSON config under
// "result", plus any warnings the adapter emitted (unknown directives, deprecations).
type AdaptResult struct {
	Result   map[string]any   `json:"result"`
	Warnings []map[string]any `json:"warnings"`
}

// Adapt sends Caddyfile source to Caddy's /adapt endpoint and returns the JSON config
// Caddy would run if that Caddyfile were loaded. Does NOT modify the live config.
func (c *Client) Adapt(caddyfile string) (*AdaptResult, error) {
	req, err := http.NewRequest(http.MethodPost, c.AdminURL+"/adapt", strings.NewReader(caddyfile))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/caddyfile")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy adapt: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("caddy rejected Caddyfile: %s", strings.TrimSpace(string(body)))
	}
	var out AdaptResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse adapt response: %w", err)
	}
	return &out, nil
}

func (c *Client) send(method, path string, val any) error {
	body, err := json.Marshal(val)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.AdminURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("caddy %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy %s %s status %d: %s", method, path, resp.StatusCode, string(msg))
	}
	return nil
}

// BuildProxyRoute constructs a single route for a proxy host. If advancedHandlers
// is non-nil, those handlers are inserted before the reverse_proxy handler so
// directives like `header`, `encode`, `request_body` run on the incoming request
// before it's proxied.
func BuildProxyRoute(p models.ProxyHost, advancedHandlers []any) map[string]any {
	domains := p.DomainList()

	// Build upstreams list: primary + any extra (Feature D).
	upstreams := []any{map[string]any{"dial": fmt.Sprintf("%s:%d", p.ForwardHost, p.ForwardPort)}}
	for _, u := range p.ExtraUpstreamList() {
		u = strings.TrimSpace(u)
		if u != "" {
			upstreams = append(upstreams, map[string]any{"dial": u})
		}
	}

	reverseProxy := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": upstreams,
	}
	// Enable round-robin load balancing when there are multiple upstreams.
	if len(upstreams) > 1 {
		reverseProxy["load_balancing"] = map[string]any{
			"selection_policy": map[string]any{"policy": "round_robin"},
		}
	}
	if p.ForwardScheme == "https" {
		reverseProxy["transport"] = map[string]any{
			"protocol": "http",
			"tls":      map[string]any{"insecure_skip_verify": true},
		}
	}
	if p.WebsocketSupport {
		reverseProxy["headers"] = map[string]any{
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Host":  []any{"{http.request.host}"},
					"X-Forwarded-Proto": []any{"{http.request.scheme}"},
				},
			},
		}
	}

	handlers := []any{}
	if p.BlockCommonExploits {
		handlers = append(handlers, ExploitBlockerSubroute())
	}
	// Feature C: prepend IP allowlist subroute if access_list is set.
	if p.AccessList != "" {
		cidrList := parseCIDRList(p.AccessList)
		if len(cidrList) > 0 {
			handlers = append(handlers, ipAllowlistSubroute(cidrList))
		}
	}
	handlers = append(handlers, advancedHandlers...)
	handlers = append(handlers, reverseProxy)

	return map[string]any{
		"match":    []any{map[string]any{"host": asIfaceStrings(domains)}},
		"handle":   handlers,
		"terminal": true,
	}
}

// parseCIDRList splits a comma-separated CIDR string and trims whitespace.
func parseCIDRList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ipAllowlistSubroute returns a Caddy subroute handler that responds 403 to
// any request whose remote IP is not in the given CIDR allowlist.
func ipAllowlistSubroute(cidrList []string) map[string]any {
	ranges := make([]any, len(cidrList))
	for i, c := range cidrList {
		ranges[i] = c
	}
	return map[string]any{
		"handler": "subroute",
		"routes": []any{
			map[string]any{
				"match": []any{map[string]any{
					"not": []any{map[string]any{
						"remote_ip": map[string]any{"ranges": ranges},
					}},
				}},
				"handle":   []any{map[string]any{"handler": "static_response", "status_code": 403}},
				"terminal": true,
			},
		},
	}
}

// BuildRedirectRoute constructs a single route for a redirection host.
func BuildRedirectRoute(r models.RedirectionHost) map[string]any {
	domains := r.DomainList()
	scheme := r.ForwardScheme
	if scheme == "auto" || scheme == "" {
		scheme = "{http.request.scheme}"
	}
	path := ""
	if r.PreservePath {
		path = "{http.request.uri}"
	}
	location := fmt.Sprintf("%s://%s%s", scheme, r.ForwardDomain, path)
	if scheme == "{http.request.scheme}" {
		location = fmt.Sprintf("{http.request.scheme}://%s%s", r.ForwardDomain, path)
	}
	statusCode := r.ForwardHTTPCode
	if statusCode == 0 {
		statusCode = 301
	}
	return map[string]any{
		"match": []any{map[string]any{"host": asIfaceStrings(domains)}},
		"handle": []any{
			map[string]any{
				"handler": "static_response",
				"headers": map[string]any{
					"Location": []any{location},
				},
				"status_code": statusCode,
			},
		},
		"terminal": true,
	}
}

// BuildRoutes is kept as a convenience for callers that don't need per-host
// advanced handlers (e.g. importer/tests). syncCaddy uses the per-route helpers
// directly so it can splice in adapted AdvancedConfig.
func BuildRoutes(proxies []models.ProxyHost, redirects []models.RedirectionHost) []any {
	routes := []any{}
	for _, p := range proxies {
		if !p.Enabled || len(p.DomainList()) == 0 {
			continue
		}
		routes = append(routes, BuildProxyRoute(p, nil))
	}
	for _, r := range redirects {
		if !r.Enabled || len(r.DomainList()) == 0 {
			continue
		}
		routes = append(routes, BuildRedirectRoute(r))
	}
	return routes
}

// ExploitBlockerSubroute returns a subroute handler that returns 403 for common
// exploit-probing paths. Used by proxy hosts and optionally by raw routes that
// opt in via the BlockCommonExploits flag.
func ExploitBlockerSubroute() map[string]any {
	return map[string]any{
		"handler": "subroute",
		"routes": []any{
			map[string]any{
				"match": []any{
					map[string]any{
						"path": []any{
							"/.env*", "/wp-admin*", "/wp-login*",
							"/phpmyadmin*", "/.git/*", "/xmlrpc.php",
						},
					},
				},
				"handle": []any{
					map[string]any{
						"handler":     "static_response",
						"status_code": 403,
					},
				},
				"terminal": true,
			},
		},
	}
}

func asIfaceStrings(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
