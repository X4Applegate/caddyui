package caddy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Client talks to a single Caddy instance's admin API.
//
// The AdminURL can be:
//   - http://host:port  — plain TCP (default Caddy: http://localhost:2019)
//   - https://host:port — if you've wrapped the admin API behind a TLS proxy
//   - unix:///path/to/caddy-admin.sock — dials a Unix domain socket instead
//     of TCP. The path is taken verbatim after "unix://". All HTTP requests
//     then use a dummy "http://unix/..." scheme; the transport rewrites the
//     dial target to the socket file.
//
// If Username/Password are set, every request includes an
// `Authorization: Basic <base64(user:pass)>` header so the call can traverse
// a reverse proxy that enforces HTTP Basic Auth in front of port 2019.
type Client struct {
	AdminURL string
	Username string
	Password string
	// socketPath is populated when AdminURL has the unix:// scheme; the
	// effective URL sent to the HTTP transport is rewritten to http://unix.
	socketPath string
	HTTP       *http.Client
}

// New returns a Client configured to talk to adminURL. Pass empty strings for
// username/password to skip the Authorization header.
func New(adminURL, username, password string) *Client {
	adminURL = strings.TrimRight(adminURL, "/")
	c := &Client{
		AdminURL: adminURL,
		Username: username,
		Password: password,
	}
	// Detect unix:// scheme and wire a custom transport that dials the socket.
	// The caller-facing AdminURL is replaced with http://unix so net/http will
	// build a valid request; the transport's DialContext ignores the host.
	if strings.HasPrefix(adminURL, "unix://") {
		c.socketPath = strings.TrimPrefix(adminURL, "unix://")
		c.AdminURL = "http://unix"
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", c.socketPath)
			},
		}
		c.HTTP = &http.Client{Timeout: 10 * time.Second, Transport: tr}
		return c
	}
	c.HTTP = &http.Client{Timeout: 10 * time.Second}
	return c
}

// applyAuth attaches HTTP Basic Auth to req when credentials are configured.
func (c *Client) applyAuth(req *http.Request) {
	if c.Username != "" || c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
}

// Ping does a cheap GET /config/ against the admin API and returns (status, err).
// Used by the health poller so it goes through the same transport + auth as
// the rest of the client (works for unix sockets and basic-auth-wrapped endpoints).
func (c *Client) Ping(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.AdminURL+"/config/", nil)
	if err != nil {
		return 0, err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}

type LoadedConfig struct {
	Apps map[string]any `json:"apps"`
}

func (c *Client) Load(cfg map[string]any) error {
	return c.send(http.MethodPost, "/load", cfg)
}

// UpstreamStatus is one entry from Caddy's /reverse_proxy/upstreams response.
type UpstreamStatus struct {
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
	// v2.9.216: needs `json:"healthy"` so the field is serialised lowercase
	// to match the proxy_hosts.html JS that reads `u.healthy`. Without the
	// tag Go marshalled this as "Healthy" (capital H) and the JS read
	// undefined → falsy → painted every Live-upstream pill red regardless
	// of Caddy's real verdict.
	Healthy bool `json:"healthy"`
}

// CaddyVersion holds the version information returned by Caddy's root endpoint.
type CaddyVersion struct {
	Version string `json:"version"`
}

// GetVersion fetches Caddy's version from the admin API root endpoint.
// Returns empty string on error — callers should treat "" as "unknown".
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.AdminURL+"/", nil)
	if err != nil {
		return "", err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("caddy version: status %d", resp.StatusCode)
	}
	var v CaddyVersion
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	return v.Version, nil
}

// GetUpstreamHealth fetches the live upstream health from Caddy's admin API.
// Returns nil without error when the endpoint isn't available (older Caddy).
func (c *Client) GetUpstreamHealth(ctx context.Context) ([]UpstreamStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.AdminURL+"/reverse_proxy/upstreams", nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // endpoint not available
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy upstreams: status %d", resp.StatusCode)
	}
	var result []UpstreamStatus
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	for i := range result {
		result[i].Healthy = result[i].Fails == 0
	}
	return result, nil
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
	c.applyAuth(req)
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
	c.applyAuth(req)
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
	// Load balancing: StickySessions overrides all; otherwise respect LBPolicy;
	// default to round_robin for multi-upstream hosts.
	if len(upstreams) > 1 {
		policyMap := map[string]any{"policy": "round_robin"}
		if p.StickySessions {
			cookieName := p.StickyCookieName
			if cookieName == "" {
				cookieName = "lb_backend"
			}
			cookiePolicy := map[string]any{"policy": "cookie", "name": cookieName}
			// v2.9.45: lb_cookie_path — scope the sticky-session cookie to a sub-path.
			if p.LBCookiePath != "" {
				cookiePolicy["path"] = p.LBCookiePath
			}
			// v2.9.83: lb_cookie_secret — HMAC secret to sign/verify cookie values.
			if p.LBCookieSecret != "" {
				cookiePolicy["secret"] = p.LBCookieSecret
			}
			// v2.9.122: lb_cookie_httponly — HttpOnly flag on the sticky cookie.
			if p.LBCookieHTTPOnly {
				cookiePolicy["http_only"] = true
			}
			// v2.9.123: lb_cookie_secure — Secure flag on the sticky cookie.
			if p.LBCookieSecure {
				cookiePolicy["secure"] = true
			}
			// v2.9.124: lb_cookie_same_site — SameSite attribute on the sticky cookie.
			if p.LBCookieSameSite != "" {
				cookiePolicy["same_site"] = p.LBCookieSameSite
			}
			// v2.9.133: lb_cookie_max_age_sec — max-age of the sticky cookie in seconds (0 = session).
			if p.LBCookieMaxAgeSec > 0 {
				cookiePolicy["max_age"] = p.LBCookieMaxAgeSec
			}
			policyMap = cookiePolicy
		} else if p.LBPolicy != "" {
			policyMap = map[string]any{"policy": p.LBPolicy}
			// v2.9.99: lb_header_field — header name for the 'header' sticky selection policy.
			if p.LBHeaderField != "" {
				policyMap["field"] = p.LBHeaderField
			}
			// v2.9.142: lb_random_choose_count — "choose" count for the random_choice policy.
			if p.LBRandomChooseCount > 0 && p.LBPolicy == "random_choice" {
				policyMap["choose"] = p.LBRandomChooseCount
			}
		}
		lbCfg := map[string]any{"selection_policy": policyMap}
		// v2.9.17: try_duration / try_interval for upstream retry timing.
		if p.LBTryDurationSec > 0 {
			lbCfg["try_duration"] = fmt.Sprintf("%ds", p.LBTryDurationSec)
		}
		if p.LBTryIntervalMS > 0 {
			lbCfg["try_interval"] = fmt.Sprintf("%dms", p.LBTryIntervalMS)
		}
		reverseProxy["load_balancing"] = lbCfg
	}
	needsTransport := p.ForwardScheme == "https" ||
		p.UpstreamTimeoutSec > 0 || p.ReadTimeoutSec > 0 || p.DialTimeoutSec > 0 || p.WriteTimeoutSec > 0 ||
		p.ResponseHeaderTimeoutSec > 0 || p.MaxConnDurationSec > 0 || p.UpstreamMaxRespHeaderKB > 0 ||
		p.TLSHandshakeTimeoutSec > 0 || p.ExpectContinueTimeoutSec > 0 || p.UpstreamTLSCAPEMFile != "" ||
		p.KeepaliveDisabled || p.DialFallbackDelayMS > 0 || p.UpstreamNetwork != "" || p.DNSResolver != "" ||
		p.UpstreamTLSMinVersion != "" || p.ForwardProxyURL != "" || p.UpstreamResolveTimeoutSec > 0 ||
		p.UpstreamReadBufferSizeKB > 0 || p.UpstreamWriteBufferSizeKB > 0 ||
		p.UpstreamTLSClientCertFile != "" || p.UpstreamLocalAddr != "" ||
		p.UpstreamTLSRenegotiation != "" || p.UpstreamTLSCurves != "" || p.UpstreamTLSMaxVersion != "" ||
		p.UpstreamTLSPins != "" || p.UpstreamTLSCipherSuites != "" || p.UpstreamTLSEarlyData ||
		p.UpstreamTLSALPN != "" || p.UpstreamTLSCAPEMInline != "" ||
		p.UpstreamTLSServerNameFromHost
	if needsTransport {
		transport := map[string]any{"protocol": "http"}
		if p.ForwardScheme == "https" {
			// v2.9.9: ssl_verify_upstream — when false (the default), skip TLS
			// verification so self-signed or internal CA certs are accepted.
			// When true, use the system trust store for proper verification.
			tlsCfg := map[string]any{}
			if !p.SSLVerifyUpstream {
				tlsCfg["insecure_skip_verify"] = true
			}
			if p.UpstreamSNI != "" {
				tlsCfg["server_name"] = p.UpstreamSNI
			}
			transport["tls"] = tlsCfg
		}
		// Timeout hierarchy: per-field overrides > combined upstream_timeout_sec.
		dialDur := p.UpstreamTimeoutSec
		if p.DialTimeoutSec > 0 {
			dialDur = p.DialTimeoutSec
		}
		if dialDur > 0 {
			transport["dial_timeout"] = fmt.Sprintf("%ds", dialDur)
		}
		// v2.9.29: ResponseHeaderTimeoutSec overrides UpstreamTimeoutSec for response_header_timeout.
		respHdrDur := p.UpstreamTimeoutSec
		if p.ResponseHeaderTimeoutSec > 0 {
			respHdrDur = p.ResponseHeaderTimeoutSec
		}
		if respHdrDur > 0 {
			transport["response_header_timeout"] = fmt.Sprintf("%ds", respHdrDur)
		}
		if p.ReadTimeoutSec > 0 {
			transport["read_timeout"] = fmt.Sprintf("%ds", p.ReadTimeoutSec)
		}
		// v2.9.22: write_timeout — time allowed to write the request body to upstream.
		if p.WriteTimeoutSec > 0 {
			transport["write_timeout"] = fmt.Sprintf("%ds", p.WriteTimeoutSec)
		}
		// v2.9.23: upstream TLS minimum version — merges into the tls sub-object.
		if p.UpstreamTLSMinVersion != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["min_version"] = "tls" + p.UpstreamTLSMinVersion
			transport["tls"] = tlsCfg
		}
		// v2.9.59: upstream_tls_ca_pem_file — custom CA bundle for upstream TLS verification.
		if p.UpstreamTLSCAPEMFile != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["root_ca_pem_files"] = []any{p.UpstreamTLSCAPEMFile}
			transport["tls"] = tlsCfg
		}
		// v2.9.86/87: mutual TLS client certificate for upstream connections.
		if p.UpstreamTLSClientCertFile != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["client_certificate_file"] = p.UpstreamTLSClientCertFile
			if p.UpstreamTLSClientKeyFile != "" {
				tlsCfg["client_certificate_key_file"] = p.UpstreamTLSClientKeyFile
			}
			transport["tls"] = tlsCfg
		}
		// v2.9.95: upstream_tls_renegotiation — TLS renegotiation policy for upstream connections.
		if p.UpstreamTLSRenegotiation != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["renegotiation"] = p.UpstreamTLSRenegotiation
			transport["tls"] = tlsCfg
		}
		// v2.9.96: upstream_tls_curves — comma-separated TLS curve preferences for upstream connections.
		if p.UpstreamTLSCurves != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			curves := []any{}
			for _, c := range strings.Split(p.UpstreamTLSCurves, ",") {
				c = strings.TrimSpace(c)
				if c != "" {
					curves = append(curves, c)
				}
			}
			if len(curves) > 0 {
				tlsCfg["curves"] = curves
			}
			transport["tls"] = tlsCfg
		}
		// v2.9.97: upstream_tls_max_version — maximum TLS version for upstream connections.
		if p.UpstreamTLSMaxVersion != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["max_version"] = "tls" + p.UpstreamTLSMaxVersion
			transport["tls"] = tlsCfg
		}
		// v2.9.98: upstream_tls_pins — pin the upstream certificate by SPKI SHA-256 fingerprint(s).
		if p.UpstreamTLSPins != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			pins := []any{}
			for _, pin := range strings.Split(p.UpstreamTLSPins, "\n") {
				pin = strings.TrimSpace(pin)
				if pin != "" && !strings.HasPrefix(pin, "#") {
					pins = append(pins, pin)
				}
			}
			if len(pins) > 0 {
				tlsCfg["pins"] = pins
			}
			transport["tls"] = tlsCfg
		}
		// v2.9.119: upstream_tls_cipher_suites — restrict cipher suites for upstream TLS connections.
		if p.UpstreamTLSCipherSuites != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			var suites []any
			for _, s := range strings.Split(p.UpstreamTLSCipherSuites, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					suites = append(suites, s)
				}
			}
			if len(suites) > 0 {
				tlsCfg["cipher_suites"] = suites
			}
			transport["tls"] = tlsCfg
		}
		// v2.9.125: upstream_tls_early_data — allow TLS 1.3 early data (0-RTT) for upstream connections.
		if p.UpstreamTLSEarlyData {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["early_data"] = true
			transport["tls"] = tlsCfg
		}
		// v2.9.160: upstream_tls_ca_pem_inline — inline PEM CA certificate for upstream TLS verification.
		if p.UpstreamTLSCAPEMInline != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["root_ca_pem"] = p.UpstreamTLSCAPEMInline
			transport["tls"] = tlsCfg
		}
		// v2.9.153: upstream_tls_alpn — ALPN protocol list for upstream TLS connections.
		if p.UpstreamTLSALPN != "" {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			alpnList := []any{}
			for _, proto := range strings.Split(p.UpstreamTLSALPN, ",") {
				proto = strings.TrimSpace(proto)
				if proto != "" {
					alpnList = append(alpnList, proto)
				}
			}
			if len(alpnList) > 0 {
				tlsCfg["alpn"] = alpnList
			}
			transport["tls"] = tlsCfg
		}
		// v2.9.166: upstream_tls_server_name_from_host — derive upstream TLS SNI from the Host header.
		if p.UpstreamTLSServerNameFromHost {
			tlsCfg, _ := transport["tls"].(map[string]any)
			if tlsCfg == nil {
				tlsCfg = map[string]any{}
			}
			tlsCfg["server_name"] = "{http.request.host}"
			transport["tls"] = tlsCfg
		}
		// v2.9.23: forward_proxy_url — chain outbound requests through an HTTP proxy.
		if p.ForwardProxyURL != "" {
			transport["forward_proxy_url"] = p.ForwardProxyURL
		}
		// v2.9.31: max_conn_duration — maximum lifetime of an upstream TCP connection.
		if p.MaxConnDurationSec > 0 {
			transport["max_conn_duration"] = fmt.Sprintf("%ds", p.MaxConnDurationSec)
		}
		// v2.9.42: upstream_max_resp_header_kb — limit response header bytes from upstream.
		if p.UpstreamMaxRespHeaderKB > 0 {
			transport["max_response_header_size"] = p.UpstreamMaxRespHeaderKB * 1024
		}
		// v2.9.60: keepalive_disabled — force every upstream request to use a new connection.
		if p.KeepaliveDisabled {
			transport["keep_alive"] = map[string]any{"enabled": false}
		}
		// v2.9.47: tls_handshake_timeout_sec — timeout for TLS handshake with upstream.
		if p.TLSHandshakeTimeoutSec > 0 {
			transport["tls_handshake_timeout"] = fmt.Sprintf("%ds", p.TLSHandshakeTimeoutSec)
		}
		// v2.9.48: expect_continue_timeout_sec — wait for upstream 100-Continue response.
		if p.ExpectContinueTimeoutSec > 0 {
			transport["expect_continue_timeout"] = fmt.Sprintf("%ds", p.ExpectContinueTimeoutSec)
		}
		// v2.9.62: dial_fallback_delay_ms — time to wait before trying next upstream on dial failure.
		if p.DialFallbackDelayMS > 0 {
			transport["dial_fallback_delay"] = fmt.Sprintf("%dms", p.DialFallbackDelayMS)
		}
		// v2.9.63: upstream_network — force IPv4 or IPv6 for upstream TCP connections.
		if p.UpstreamNetwork != "" {
			transport["network"] = p.UpstreamNetwork
		}
		// v2.9.64: dns_resolver — custom DNS server for upstream hostname resolution.
		// v2.9.69: upstream_resolve_timeout_sec — timeout added to the resolver map.
		if p.DNSResolver != "" || p.UpstreamResolveTimeoutSec > 0 {
			resolver, _ := transport["resolver"].(map[string]any)
			if resolver == nil {
				resolver = map[string]any{}
			}
			if p.DNSResolver != "" {
				resolver["addresses"] = []any{p.DNSResolver}
			}
			if p.UpstreamResolveTimeoutSec > 0 {
				resolver["timeout"] = fmt.Sprintf("%ds", p.UpstreamResolveTimeoutSec)
			}
			transport["resolver"] = resolver
		}
		// v2.9.70: upstream_read_buffer_size_kb — transport read buffer size.
		if p.UpstreamReadBufferSizeKB > 0 {
			transport["read_buffer_size"] = p.UpstreamReadBufferSizeKB * 1024
		}
		// v2.9.71: upstream_write_buffer_size_kb — transport write buffer size.
		if p.UpstreamWriteBufferSizeKB > 0 {
			transport["write_buffer_size"] = p.UpstreamWriteBufferSizeKB * 1024
		}
		// v2.9.94: upstream_local_addr — bind this local IP for upstream connections.
		if p.UpstreamLocalAddr != "" {
			transport["local_address"] = p.UpstreamLocalAddr
		}
		reverseProxy["transport"] = transport
	}
	// v2.9.32: decompress_response — decompress gzip/br upstream responses before
	// forwarding to the client (enables response-body transforms downstream).
	if p.DecompressResponse {
		reverseProxy["decompress_response"] = true
	}
	// v2.9.4: active upstream health check.
	if p.HealthCheckURI != "" {
		interval := p.HealthCheckIntervalSec
		if interval <= 0 {
			interval = 30
		}
		timeoutSec := p.HealthCheckTimeoutSec
		if timeoutSec <= 0 {
			timeoutSec = 5
		}
		// v2.9.219: health_check_query_params — append query string to the
		// probe URL. Lets you ping endpoints that expect e.g. ?token=xyz or
		// ?check=deep without baking it into HealthCheckURI itself (which
		// would conflate path with parameters).
		probeURI := p.HealthCheckURI
		if p.HealthCheckQueryParams != "" {
			sep := "?"
			if strings.Contains(probeURI, "?") {
				sep = "&"
			}
			probeURI = probeURI + sep + strings.TrimPrefix(p.HealthCheckQueryParams, "?")
		}
		activeCheck := map[string]any{
			"uri":      probeURI,
			"interval": fmt.Sprintf("%ds", interval),
			"timeout":  fmt.Sprintf("%ds", timeoutSec),
		}
		if p.HealthCheckMethod != "" && p.HealthCheckMethod != "GET" {
			activeCheck["method"] = p.HealthCheckMethod
		}
		// v2.9.5: custom headers sent with each active health-check probe.
		if p.HealthCheckHeaders != "" && p.HealthCheckHeaders != "{}" {
			var hdrMap map[string]string
			if json.Unmarshal([]byte(p.HealthCheckHeaders), &hdrMap) == nil && len(hdrMap) > 0 {
				hdrs := map[string][]string{}
				for k, v := range hdrMap {
					hdrs[k] = []string{v}
				}
				activeCheck["headers"] = hdrs
			}
		}
		// v2.9.15: expected status code and response body regexp.
		if p.HealthCheckExpectStatus > 0 {
			activeCheck["expect_status"] = p.HealthCheckExpectStatus
		}
		if p.HealthCheckExpectBody != "" {
			activeCheck["expect_body"] = p.HealthCheckExpectBody
		}
		if p.HealthCheckFollowRedirects {
			activeCheck["follow_redirects"] = true
		}
		// v2.9.43: health_check_port — probe on a different port than the traffic upstreams.
		if p.HealthCheckPort > 0 {
			activeCheck["port"] = p.HealthCheckPort
		}
		// v2.9.55: health_check_max_size_kb — cap response body bytes read during health probes.
		if p.HealthCheckMaxSizeKB > 0 {
			activeCheck["max_size"] = p.HealthCheckMaxSizeKB * 1024
		}
		// v2.9.75: health_check_body — request body sent with each probe request.
		if p.HealthCheckBody != "" {
			activeCheck["body"] = p.HealthCheckBody
		}
		// v2.9.85: health_check_content_type — Content-Type for health check probe requests.
		if p.HealthCheckContentType != "" {
			existing, _ := activeCheck["headers"].(map[string][]string)
			if existing == nil {
				existing = map[string][]string{}
			}
			existing["Content-Type"] = []string{p.HealthCheckContentType}
			activeCheck["headers"] = existing
		}
		// v2.9.111: health_check_host_override — Host header override for health check probes.
		if p.HealthCheckHostOverride != "" {
			existing, _ := activeCheck["headers"].(map[string][]string)
			if existing == nil {
				existing = map[string][]string{}
			}
			existing["Host"] = []string{p.HealthCheckHostOverride}
			activeCheck["headers"] = existing
		}
		// v2.9.180: health_check_user_agent — custom User-Agent for active health check probes.
		if p.HealthCheckUserAgent != "" {
			existing, _ := activeCheck["headers"].(map[string][]string)
			if existing == nil {
				existing = map[string][]string{}
			}
			existing["User-Agent"] = []string{p.HealthCheckUserAgent}
			activeCheck["headers"] = existing
		}
		// v2.9.241: health_check_basic_auth — "user:pass" credentials sent as
		// Basic Auth on every probe so endpoints behind auth (e.g. an admin
		// /healthz that requires login) can still be checked. Encoded once
		// here at config-build time; Caddy doesn't re-encode per probe.
		if p.HealthCheckBasicAuth != "" {
			existing, _ := activeCheck["headers"].(map[string][]string)
			if existing == nil {
				existing = map[string][]string{}
			}
			encoded := base64.StdEncoding.EncodeToString([]byte(p.HealthCheckBasicAuth))
			existing["Authorization"] = []string{"Basic " + encoded}
			activeCheck["headers"] = existing
		}
		// v2.9.148: health_check_tls_server_name — TLS SNI override for health check connections.
		if p.HealthCheckTLSServerName != "" {
			activeCheck["tls_server_name"] = p.HealthCheckTLSServerName
		}
		// v2.9.151: health_check_tls_insecure_skip_verify — skip TLS cert verification for health check probes.
		if p.HealthCheckTLSInsecureSkipVerify {
			activeCheck["tls_insecure_skip_verify"] = true
		}
		reverseProxy["health_checks"] = map[string]any{
			"active": activeCheck,
		}
	}

	// v2.9.5: passive health check — detect failures in live traffic without
	// sending dedicated probe requests.
	if p.PassiveFailDurationSec > 0 || p.PassiveMaxFails > 0 || p.PassiveUnhealthyLatencyMS > 0 || p.PassiveUnhealthyStatusCodes != "" || p.PassiveUnhealthyCount > 0 {
		passive := map[string]any{}
		if p.PassiveFailDurationSec > 0 {
			passive["fail_duration"] = fmt.Sprintf("%ds", p.PassiveFailDurationSec)
		}
		if p.PassiveMaxFails > 0 {
			passive["max_fails"] = p.PassiveMaxFails
		}
		// v2.9.46: passive_unhealthy_latency_ms — flag upstream unhealthy above this latency.
		if p.PassiveUnhealthyLatencyMS > 0 {
			passive["unhealthy_latency"] = fmt.Sprintf("%dms", p.PassiveUnhealthyLatencyMS)
		}
		// v2.9.84: passive_unhealthy_status_codes — specific HTTP codes that trigger passive unhealthy.
		if p.PassiveUnhealthyStatusCodes != "" {
			var codes []any
			for _, s := range strings.Split(p.PassiveUnhealthyStatusCodes, ",") {
				s = strings.TrimSpace(s)
				if code, err := strconv.Atoi(s); err == nil && code >= 100 && code <= 599 {
					codes = append(codes, code)
				}
			}
			if len(codes) > 0 {
				passive["unhealthy_status"] = codes
			}
		}
		// v2.9.130: passive_unhealthy_count — flag upstream overloaded above this many concurrent requests.
		if p.PassiveUnhealthyCount > 0 {
			passive["unhealthy_request_count"] = p.PassiveUnhealthyCount
		}
		if hc, ok := reverseProxy["health_checks"].(map[string]any); ok {
			hc["passive"] = passive
		} else {
			reverseProxy["health_checks"] = map[string]any{"passive": passive}
		}
	}

	// Configure upstream retry on failure.
	if p.UpstreamRetries > 0 || p.RetryStatusCodes != "" || p.LBRetryOn != "" {
		lb, _ := reverseProxy["load_balancing"].(map[string]any)
		if lb == nil {
			lb = map[string]any{}
		}
		if p.UpstreamRetries > 0 {
			lb["retries"] = p.UpstreamRetries
		}
		// v2.9.22: retry_status_codes — retry on specific upstream HTTP response codes.
		if p.RetryStatusCodes != "" {
			var codes []any
			for _, s := range strings.Split(p.RetryStatusCodes, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				var code int
				if _, err := fmt.Sscanf(s, "%d", &code); err == nil && code > 0 {
					codes = append(codes, code)
				}
			}
			if len(codes) > 0 {
				lb["retry_status_codes"] = codes
			}
		}
		// v2.9.113: lb_retry_on — retry trigger conditions ("error","5xx","4xx","connect_error","timeout","reset").
		if p.LBRetryOn != "" {
			var triggers []any
			for _, t := range strings.Split(p.LBRetryOn, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					triggers = append(triggers, t)
				}
			}
			if len(triggers) > 0 {
				lb["retry_on"] = triggers
			}
		}
		reverseProxy["load_balancing"] = lb
	}

	// v2.9.4: keepalive connection pooling.
	// v2.9.14: also triggered when only idle timeout is set (KeepaliveConns may be 0).
	// Merge into transport if it already exists (set by ForwardScheme==https or UpstreamTimeoutSec>0).
	if p.KeepaliveConns > 0 || p.KeepaliveIdleTimeoutSec > 0 {
		transport, _ := reverseProxy["transport"].(map[string]any)
		if transport == nil {
			transport = map[string]any{"protocol": "http"}
		}
		idleTimeout := "90s"
		if p.KeepaliveIdleTimeoutSec > 0 {
			idleTimeout = fmt.Sprintf("%ds", p.KeepaliveIdleTimeoutSec)
		}
		ka := map[string]any{
			"enabled":      true,
			"idle_timeout": idleTimeout,
		}
		if p.KeepaliveConns > 0 {
			ka["max_idle_conns_per_host"] = p.KeepaliveConns
		}
		transport["keep_alive"] = ka
		reverseProxy["transport"] = transport
	}

	if p.MaxConnsPerHost > 0 {
		transport, _ := reverseProxy["transport"].(map[string]any)
		if transport == nil {
			transport = map[string]any{"protocol": "http"}
		}
		keepAlive, _ := transport["keep_alive"].(map[string]any)
		if keepAlive == nil {
			keepAlive = map[string]any{"enabled": true}
		}
		keepAlive["max_conns_per_host"] = p.MaxConnsPerHost
		transport["keep_alive"] = keepAlive
		reverseProxy["transport"] = transport
	}

	// v2.9.50/51: upstream keepalive pool — max total idle conns and probe interval.
	// v2.9.115: upstream_keepalive_probes — TCP keepalive probe count.
	if p.UpstreamMaxIdleConns > 0 || p.UpstreamKeepAliveProbeIntervalSec > 0 || p.UpstreamKeepaliveProbes > 0 || p.UpstreamKeepaliveMaxLifetimeSec > 0 {
		transport, _ := reverseProxy["transport"].(map[string]any)
		if transport == nil {
			transport = map[string]any{"protocol": "http"}
		}
		keepAlive, _ := transport["keep_alive"].(map[string]any)
		if keepAlive == nil {
			keepAlive = map[string]any{"enabled": true}
		}
		if p.UpstreamMaxIdleConns > 0 {
			keepAlive["max_idle_conns"] = p.UpstreamMaxIdleConns
		}
		if p.UpstreamKeepAliveProbeIntervalSec > 0 {
			keepAlive["probe_interval"] = fmt.Sprintf("%ds", p.UpstreamKeepAliveProbeIntervalSec)
		}
		if p.UpstreamKeepaliveProbes > 0 {
			keepAlive["probes"] = p.UpstreamKeepaliveProbes
		}
		// v2.9.158: upstream_keepalive_max_lifetime_sec — max duration before a keepalive connection is recycled.
		if p.UpstreamKeepaliveMaxLifetimeSec > 0 {
			keepAlive["maximum_connection_lifetime"] = fmt.Sprintf("%ds", p.UpstreamKeepaliveMaxLifetimeSec)
		}
		transport["keep_alive"] = keepAlive
		reverseProxy["transport"] = transport
	}

	if p.ForceHTTP1 {
		transport, _ := reverseProxy["transport"].(map[string]any)
		if transport == nil {
			transport = map[string]any{"protocol": "http"}
		}
		transport["versions"] = []any{"1.1"}
		reverseProxy["transport"] = transport
	}

	// v2.9.5: H2C (HTTP/2 cleartext) transport — useful for gRPC backends that
	// don't use TLS. Sets the allowed versions to "h2c" and "2" so Caddy
	// upgrades the upstream connection without requiring SSL.
	if p.H2CEnabled {
		transport, _ := reverseProxy["transport"].(map[string]any)
		if transport == nil {
			transport = map[string]any{"protocol": "http"}
		}
		transport["versions"] = []any{"h2c", "2"}
		reverseProxy["transport"] = transport
	}

	// v2.9.74: upstream_http_versions — explicit HTTP version list for upstream transport.
	// Only applied when ForceHTTP1 and H2CEnabled are both false; those two flags
	// take priority if set alongside this field.
	if p.UpstreamHTTPVersions != "" && !p.ForceHTTP1 && !p.H2CEnabled {
		transport, _ := reverseProxy["transport"].(map[string]any)
		if transport == nil {
			transport = map[string]any{"protocol": "http"}
		}
		var versions []any
		for _, v := range strings.Split(p.UpstreamHTTPVersions, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				versions = append(versions, v)
			}
		}
		if len(versions) > 0 {
			transport["versions"] = versions
		}
		reverseProxy["transport"] = transport
	}
	// v2.9.5: PROXY protocol — tell Caddy to prepend a PROXY protocol header
	// on the upstream TCP connection so the backend sees the real client IP.
	if p.ProxyProtocol == "v1" || p.ProxyProtocol == "v2" {
		transport, _ := reverseProxy["transport"].(map[string]any)
		if transport == nil {
			transport = map[string]any{"protocol": "http"}
		}
		transport["proxy_protocol"] = p.ProxyProtocol
		reverseProxy["transport"] = transport
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

	// v2.9.7: upstream Host header override — lets the operator send a different
	// Host to the backend than the one the client used (e.g. for SaaS/CDN SNI routing).
	if p.UpstreamHostOverride != "" {
		hdrCfg, _ := reverseProxy["headers"].(map[string]any)
		if hdrCfg == nil {
			hdrCfg = map[string]any{}
		}
		reqHdr, _ := hdrCfg["request"].(map[string]any)
		if reqHdr == nil {
			reqHdr = map[string]any{}
		}
		setHdr, _ := reqHdr["set"].(map[string]any)
		if setHdr == nil {
			setHdr = map[string]any{}
		}
		setHdr["Host"] = []any{p.UpstreamHostOverride}
		reqHdr["set"] = setHdr
		hdrCfg["request"] = reqHdr
		reverseProxy["headers"] = hdrCfg
	}

	// v2.9.18: forward real client IP as X-Real-IP header to the upstream.
	// Uses {http.request.remote.host} so it's the actual TCP connection IP,
	// not what's in X-Forwarded-For (which can be spoofed by untrusted clients).
	if p.ForwardClientIP {
		hdrCfg, _ := reverseProxy["headers"].(map[string]any)
		if hdrCfg == nil {
			hdrCfg = map[string]any{}
		}
		reqHdr, _ := hdrCfg["request"].(map[string]any)
		if reqHdr == nil {
			reqHdr = map[string]any{}
		}
		setHdr, _ := reqHdr["set"].(map[string]any)
		if setHdr == nil {
			setHdr = map[string]any{}
		}
		setHdr["X-Real-IP"] = []any{"{http.request.remote.host}"}
		reqHdr["set"] = setHdr
		hdrCfg["request"] = reqHdr
		reverseProxy["headers"] = hdrCfg
	}

	// v2.9.8: request body buffering — buffer the upstream request body before
	// forwarding. Useful for backends that require Content-Length or don't
	// support chunked transfer. Value is in KB; Caddy uses bytes.
	if p.RequestBuffersKB > 0 {
		reverseProxy["request_buffers"] = p.RequestBuffersKB * 1024
	}

	// v2.9.6: flush_immediate — set flush_interval to -1 so that streaming
	// responses (SSE, chunked transfer) are forwarded immediately to the client
	// rather than being buffered by Caddy.
	if p.FlushImmediate {
		reverseProxy["flush_interval"] = -1
	}
	// v2.9.116: upstream_flush_interval_ms — explicit flush_interval override in ms.
	// Takes precedence over FlushImmediate when non-zero. Negative values are allowed (-1 = immediate).
	if p.UpstreamFlushIntervalMS != 0 {
		reverseProxy["flush_interval"] = p.UpstreamFlushIntervalMS * int(time.Millisecond)
	}

	// v2.9.6: buffer_responses — buffer the full upstream response body before
	// forwarding it to the client. Useful when the upstream is slow and you want
	// to free the upstream connection quickly.
	if p.BufferResponses {
		reverseProxy["buffer_responses"] = true
	}
	// v2.9.114: max_buffer_size_kb — cap the amount of data Caddy will buffer when
	// buffer_responses is enabled. 0 means unlimited (Caddy default).
	if p.MaxBufferSizeKB > 0 {
		reverseProxy["max_buffer_size"] = p.MaxBufferSizeKB * 1024
	}
	// v2.9.49: response_buffers_kb — granular per-connection response streaming buffer.
	// Distinct from buffer_responses: this controls streaming chunk size, not full buffering.
	if p.ResponseBuffersKB > 0 {
		reverseProxy["response_buffers"] = p.ResponseBuffersKB * 1024
	}

	// v2.9.6: per-host trusted proxies — override which upstream IP ranges are
	// trusted to supply X-Forwarded-For / X-Real-IP headers.
	if p.TrustedProxies != "" {
		if tpRanges := parseCIDRList(p.TrustedProxies); len(tpRanges) > 0 {
			reverseProxy["trusted_proxies"] = map[string]any{
				"source": "static",
				"ranges": tpRanges,
			}
		}
	}

	handlers := []any{}
	// v2.9.34: www redirect — inject a subroute that redirects between the
	// www and bare forms of each domain before any other handler fires.
	if p.WWWRedirect != "" {
		var redirectRoutes []any
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			var fromDomain, toDomain string
			switch p.WWWRedirect {
			case "to_www":
				if !strings.HasPrefix(d, "www.") {
					fromDomain = d
					toDomain = "www." + d
				}
			case "to_bare":
				if strings.HasPrefix(d, "www.") {
					fromDomain = d
					toDomain = strings.TrimPrefix(d, "www.")
				}
			}
			if fromDomain != "" {
				redirectRoutes = append(redirectRoutes, map[string]any{
					"match": []any{map[string]any{"host": []any{fromDomain}}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 301,
						"headers": map[string]any{
							"Location": []any{"{http.request.scheme}://" + toDomain + "{http.request.uri}"},
						},
					}},
					"terminal": true,
				})
			}
		}
		if len(redirectRoutes) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes":  redirectRoutes,
			})
		}
	}
	// v2.9.61: trailing_slash_redirect — auto-redirect for trailing slash normalisation.
	if p.TrailingSlashRedirect == "add" {
		// Redirect /path → /path/ when path has no extension and no trailing slash.
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"path_regexp": map[string]any{
							"pattern": `^(/[^.]*[^/])$`,
						},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 301,
						"headers": map[string]any{
							"Location": []any{"{http.request.uri.path}/{http.request.uri.query}"},
						},
					}},
					"terminal": true,
				},
			},
		})
	} else if p.TrailingSlashRedirect == "remove" {
		// Redirect /path/ → /path when path ends with / but is not the root.
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"path_regexp": map[string]any{
							"pattern": `^(/.+)/$`,
						},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 301,
						"headers": map[string]any{
							"Location": []any{"{http.regexp.capture.1}"},
						},
					}},
					"terminal": true,
				},
			},
		})
	}
	if p.BlockCommonExploits {
		handlers = append(handlers, ExploitBlockerSubroute())
	}
	// v2.9.7: dotfile blocking — return 403 for any request whose path contains
	// a segment beginning with "." (e.g. /.env, /.git/config, /.htaccess).
	if p.DenyDotfiles {
		handlers = append(handlers, denyDotfilesSubroute())
	}
	// v2.9.10: block requests with no User-Agent header.
	if p.BlockEmptyUserAgent {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"not": []any{map[string]any{
							"header_regexp": map[string]any{
								"User-Agent": map[string]any{"pattern": "."},
							},
						}},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 403,
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.10: API key header authentication — reject requests that don't carry
	// the expected header value. The key is stored in plaintext in the DB.
	if p.APIKeyHeader != "" && p.APIKeyValue != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"not": []any{map[string]any{
							"header": map[string]any{
								p.APIKeyHeader: []any{p.APIKeyValue},
							},
						}},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 401,
						"body":        "Unauthorized",
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.25: blocked_methods — reject specific HTTP methods with 405 before anything else.
	if p.BlockedMethods != "" {
		var methods []any
		for _, m := range strings.Split(p.BlockedMethods, ",") {
			m = strings.TrimSpace(strings.ToUpper(m))
			if m != "" {
				methods = append(methods, m)
			}
		}
		if len(methods) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match":    []any{map[string]any{"method": methods}},
						"handle":   []any{map[string]any{"handler": "static_response", "status_code": 405}},
						"terminal": true,
					},
				},
			})
		}
	}
	// v2.9.41: allowed_methods — reject methods NOT in the allowlist with 405.
	// Runs after blocked_methods so an explicit deny always wins.
	if p.AllowedMethods != "" {
		var allowed []any
		for _, m := range strings.Split(p.AllowedMethods, ",") {
			m = strings.TrimSpace(strings.ToUpper(m))
			if m != "" {
				allowed = append(allowed, m)
			}
		}
		if len(allowed) > 0 {
			// Build a "not" matcher: match any method NOT in the allowed list → 405.
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match": []any{map[string]any{"not": []any{map[string]any{"method": allowed}}}},
						"handle": []any{map[string]any{
							"handler":     "static_response",
							"status_code": 405,
							"headers":     map[string]any{"Allow": []any{strings.Join(methodStrings(allowed), ", ")}},
						}},
						"terminal": true,
					},
				},
			})
		}
	}
	// v2.9.5: IP blocklist — deny requests from specific CIDR ranges before
	// the allowlist check so blocklisted IPs are always rejected.
	if p.IPBlocklist != "" {
		if blockRanges := parseCIDRList(p.IPBlocklist); len(blockRanges) > 0 {
			handlers = append(handlers, ipBlocklistSubroute(blockRanges))
		}
	}
	// v2.9.88: block_private_ips — reject requests from RFC 1918 / loopback ranges.
	if p.BlockPrivateIPs {
		privateRanges := []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
			"::1/128", "fc00::/7", "fe80::/10",
		}
		handlers = append(handlers, ipBlocklistSubroute(privateRanges))
	}
	// Feature C: prepend IP allowlist subroute if access_list is set.
	if p.AccessList != "" {
		cidrList := parseCIDRList(p.AccessList)
		if len(cidrList) > 0 {
			handlers = append(handlers, ipAllowlistSubroute(cidrList))
		}
	}
	// v2.9.155: block_query_params — deny requests containing any of the listed query parameter names (403).
	if p.BlockQueryParams != "" {
		for _, param := range strings.Split(p.BlockQueryParams, ",") {
			param = strings.TrimSpace(param)
			if param == "" {
				continue
			}
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{map[string]any{
					"match": []any{map[string]any{
						"query": map[string]any{param: []any{"*"}},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 403,
						"body":        "Forbidden\n",
					}},
					"terminal": true,
				}},
			})
		}
	}
	// v2.9.146: deny_path_regexp — reject requests whose full path matches a custom regex (403).
	if p.DenyPathRegexp != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{map[string]any{
				"match": []any{map[string]any{
					"path_regexp": map[string]any{"pattern": p.DenyPathRegexp},
				}},
				"handle": []any{map[string]any{
					"handler":     "static_response",
					"status_code": 403,
					"body":        "Forbidden\n",
				}},
				"terminal": true,
			}},
		})
	}
	// v2.9.101: deny_extensions — block requests whose path ends with any listed extension (403).
	if p.DenyExtensions != "" {
		var exts []string
		for _, ext := range strings.Split(p.DenyExtensions, ",") {
			ext = strings.TrimSpace(ext)
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			exts = append(exts, regexp.QuoteMeta(ext))
		}
		if len(exts) > 0 {
			pattern := "(?i)(" + strings.Join(exts, "|") + ")$"
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{map[string]any{
					"match": []any{map[string]any{
						"path_regexp": map[string]any{"pattern": pattern},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 403,
						"body":        "Forbidden\n",
					}},
					"terminal": true,
				}},
			})
		}
	}
	// v2.9.0: response compression — gzip/zstd encode handler. Must precede
	// the reverse_proxy handler so it can wrap the ResponseWriter.
	// v2.9.18: minimum_length skips compression for small responses.
	if p.CompressionEnabled {
		// v2.9.37: per-algorithm config objects allow setting compression level.
		gzipCfg := map[string]any{}
		zstdCfg := map[string]any{}
		if p.CompressionLevel > 0 {
			gzipCfg["level"] = p.CompressionLevel
			// zstd levels are different from gzip (1-22); map gzip 1-9 proportionally.
			zstdCfg["level"] = p.CompressionLevel
		}
		encodings := map[string]any{"gzip": gzipCfg, "zstd": zstdCfg}
		// v2.9.89: enable_brotli — add brotli (br) encoding to the handler.
		if p.EnableBrotli {
			encodings["br"] = map[string]any{}
		}
		preferOrder := []any{"zstd", "gzip"}
		if p.CompressionPreferGzip {
			preferOrder = []any{"gzip", "zstd"}
		}
		if p.EnableBrotli {
			preferOrder = append([]any{"br"}, preferOrder...)
		}
		encHandler := map[string]any{
			"handler":   "encode",
			"encodings": encodings,
			"prefer":    preferOrder,
		}
		if p.CompressionMinSizeKB > 0 {
			encHandler["minimum_length"] = p.CompressionMinSizeKB * 1024
		}
		// v2.9.138: compression_exclude_regexp — skip compression for paths matching this regexp.
		// Wrap the encode handler in a subroute that fires only for non-matching paths.
		if p.CompressionExcludeRegexp != "" {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{map[string]any{
					"match": []any{map[string]any{
						"not": []any{map[string]any{
							"path_regexp": map[string]any{"pattern": p.CompressionExcludeRegexp},
						}},
					}},
					"handle": []any{encHandler},
				}},
			})
		} else {
			handlers = append(handlers, encHandler)
		}
	}
	// v2.9.0: security response headers bundle. Added as a headers handler
	// before reverse_proxy so the headers appear on every upstream response.
	if p.SecurityHeadersEnabled {
		hstsDur := 31536000 // default: 1 year
		if p.HSTSMaxAgeSec > 0 {
			hstsDur = p.HSTSMaxAgeSec
		}
		hsts := fmt.Sprintf("max-age=%d", hstsDur)
		if p.HSTSIncludeSubdomains {
			hsts += "; includeSubDomains"
		}
		if p.HSTSPreload {
			hsts += "; preload"
		}
		xfo := "SAMEORIGIN"
		if p.XFrameOptions != "" {
			xfo = p.XFrameOptions
		}
		rp := "strict-origin-when-cross-origin"
		if p.ReferrerPolicy != "" {
			rp = p.ReferrerPolicy
		}
		secHdrs := map[string]any{
			"Strict-Transport-Security": []any{hsts},
			"X-Frame-Options":           []any{xfo},
			"X-Content-Type-Options":    []any{"nosniff"},
			"Referrer-Policy":           []any{rp},
			"X-XSS-Protection":          []any{"1; mode=block"},
		}
		// v2.9.11: Permissions-Policy — modern replacement for Feature-Policy.
		if p.PermissionsPolicy != "" {
			secHdrs["Permissions-Policy"] = []any{p.PermissionsPolicy}
		}
		handlers = append(handlers, map[string]any{
			"handler":  "headers",
			"response": map[string]any{"set": secHdrs},
		})
	} else if p.PermissionsPolicy != "" {
		// Even without the full security bundle, still inject Permissions-Policy alone.
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{"Permissions-Policy": []any{p.PermissionsPolicy}},
			},
		})
	}
	// v2.9.5: Content-Security-Policy header — injected independently of
	// SecurityHeadersEnabled so it can be set without enabling the full bundle.
	if p.CSPHeader != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Content-Security-Policy": []any{p.CSPHeader},
				},
			},
		})
	}
	// v2.9.14: Content-Security-Policy-Report-Only — report violations without
	// blocking, useful for testing a new policy before enforcing it.
	if p.CSPReportOnly != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Content-Security-Policy-Report-Only": []any{p.CSPReportOnly},
				},
			},
		})
	}
	// v2.9.1: custom request headers — added to/deleted from the upstream request.
	// v2.9.35: strip_req_headers merged in as additional deletes.
	if reqHeaders := p.CustomReqHeaderMap(); len(reqHeaders) > 0 || p.StripReqHeaders != "" {
		setReq := map[string]any{}
		deleteReq := []any{}
		for k, v := range reqHeaders {
			if v == "" {
				deleteReq = append(deleteReq, k)
			} else {
				setReq[k] = []any{v}
			}
		}
		for _, h := range p.StripReqHeaderList() {
			deleteReq = append(deleteReq, h)
		}
		reqOp := map[string]any{}
		if len(setReq) > 0 {
			reqOp["set"] = setReq
		}
		if len(deleteReq) > 0 {
			reqOp["delete"] = deleteReq
		}
		if len(reqOp) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "headers",
				"request": reqOp,
			})
		}
	}
	// v2.9.1: custom response headers — added to/deleted from the response.
	if respHeaders := p.CustomRespHeaderMap(); len(respHeaders) > 0 {
		setResp := map[string]any{}
		deleteResp := []any{}
		for k, v := range respHeaders {
			if v == "" {
				deleteResp = append(deleteResp, k)
			} else {
				setResp[k] = []any{v}
			}
		}
		respOp := map[string]any{}
		if len(setResp) > 0 {
			respOp["set"] = setResp
		}
		if len(deleteResp) > 0 {
			respOp["delete"] = deleteResp
		}
		if len(respOp) > 0 {
			handlers = append(handlers, map[string]any{
				"handler":  "headers",
				"response": respOp,
			})
		}
	}
	// v2.9.127: req_header_rename — rename request headers before forwarding ("OldName: NewName" per line).
	// Implemented as: delete old name, set new name = {http.request.header.OldName}.
	if p.ReqHeaderRename != "" {
		type renameRule struct{ from, to string }
		var rules []renameRule
		for _, line := range strings.Split(p.ReqHeaderRename, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if idx := strings.IndexByte(line, ':'); idx > 0 {
				from := strings.TrimSpace(line[:idx])
				to := strings.TrimSpace(line[idx+1:])
				if from != "" && to != "" {
					rules = append(rules, renameRule{from: from, to: to})
				}
			}
		}
		if len(rules) > 0 {
			setMap := map[string]any{}
			deleteList := []any{}
			for _, r := range rules {
				setMap[r.to] = []any{"{http.request.header." + r.from + "}"}
				deleteList = append(deleteList, r.from)
			}
			handlers = append(handlers, map[string]any{
				"handler": "headers",
				"request": map[string]any{
					"set":    setMap,
					"delete": deleteList,
				},
			})
		}
	}
	// v2.9.77: http_basic_auth_upstream — inject Authorization: Basic header for upstream auth.
	if p.HTTPBasicAuthUpstream != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(p.HTTPBasicAuthUpstream))
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"Authorization": []any{"Basic " + encoded},
				},
			},
		})
	}
	// v2.9.72: req_header_replace — regex-based value replacement on request headers.
	if p.ReqHeaderReplace != "" {
		if rules := parseHeaderReplaceRules(p.ReqHeaderReplace); len(rules) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "headers",
				"request": map[string]any{"replace": rules},
			})
		}
	}
	// v2.9.73: resp_header_replace — regex-based value replacement on response headers.
	if p.RespHeaderReplace != "" {
		if rules := parseHeaderReplaceRules(p.RespHeaderReplace); len(rules) > 0 {
			handlers = append(handlers, map[string]any{
				"handler":  "headers",
				"response": map[string]any{"replace": rules},
			})
		}
	}
	// v2.9.90: vary_header — set Vary response header for CDN/caching control.
	if p.VaryHeader != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Vary": []any{p.VaryHeader},
				},
			},
		})
	}
	// v2.9.91: strip_etag — delete ETag response header from upstream responses.
	if p.StripETag {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"delete": []any{"ETag"},
			},
		})
	}
	// v2.9.161: add_server_timing_header — inject standard Server-Timing response header with upstream duration.
	if p.AddServerTimingHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Server-Timing": []any{"upstream;dur={http.reverse_proxy.upstream.duration}"},
				},
			},
		})
	}
	// v2.9.105: add_upstream_timing_header — inject X-Upstream-Time response header with upstream latency.
	if p.AddUpstreamTimingHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Upstream-Time": []any{"{http.reverse_proxy.upstream.duration}"},
				},
			},
		})
	}
	// v2.9.126: add_via_header — add Via response header identifying this proxy (1.1 caddy).
	if p.AddViaHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"add": map[string]any{
					"Via": []any{"1.1 caddy"},
				},
			},
		})
	}
	// v2.9.132: add_timing_allow_origin — set Timing-Allow-Origin header to enable Resource Timing API.
	if p.AddTimingAllowOrigin != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Timing-Allow-Origin": []any{p.AddTimingAllowOrigin},
				},
			},
		})
	}
	// v2.9.134: cross_origin_opener_policy — isolate browsing context from cross-origin documents.
	if p.CrossOriginOpenerPolicy != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cross-Origin-Opener-Policy": []any{p.CrossOriginOpenerPolicy},
				},
			},
		})
	}
	// v2.9.135: cross_origin_resource_policy — control which origins can include this resource.
	if p.CrossOriginResourcePolicy != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cross-Origin-Resource-Policy": []any{p.CrossOriginResourcePolicy},
				},
			},
		})
	}
	// v2.9.136: cross_origin_embedder_policy — require CORP for embedded sub-resources.
	if p.CrossOriginEmbedderPolicy != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cross-Origin-Embedder-Policy": []any{p.CrossOriginEmbedderPolicy},
				},
			},
		})
	}
	// v2.9.106: strip_server_header — delete Server response header from upstream replies.
	if p.StripServerHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"delete": []any{"Server"},
			},
		})
	}
	// v2.9.162: add_clear_site_data — set Clear-Site-Data response header (e.g. "cache","cookies","storage").
	if p.AddClearSiteData != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Clear-Site-Data": []any{p.AddClearSiteData},
				},
			},
		})
	}
	// v2.9.163: add_x_dns_prefetch_control — set X-DNS-Prefetch-Control: off to prevent DNS prefetching.
	if p.AddXDNSPrefetchControl {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-DNS-Prefetch-Control": []any{"off"},
				},
			},
		})
	}
	// v2.9.164: add_accept_ranges — set Accept-Ranges: bytes to signal byte-range support.
	if p.AddAcceptRanges {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Accept-Ranges": []any{"bytes"},
				},
			},
		})
	}
	// v2.9.165: add_content_disposition — set Content-Disposition response header.
	if p.AddContentDisposition != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Content-Disposition": []any{p.AddContentDisposition},
				},
			},
		})
	}
	// v2.9.167: add_x_permitted_cross_domain_policies — set X-Permitted-Cross-Domain-Policies response header.
	if p.AddXPermittedCrossDomainPolicies != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Permitted-Cross-Domain-Policies": []any{p.AddXPermittedCrossDomainPolicies},
				},
			},
		})
	}
	// v2.9.168: strip_response_headers — delete comma-separated list of response headers from upstream replies.
	if p.StripResponseHeaders != "" {
		delList := []any{}
		for _, h := range strings.Split(p.StripResponseHeaders, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				delList = append(delList, h)
			}
		}
		if len(delList) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "headers",
				"response": map[string]any{
					"delete": delList,
				},
			})
		}
	}
	// v2.9.169: add_report_to — set Report-To response header (JSON endpoint group for CSP/NEL reporting).
	if p.AddReportTo != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Report-To": []any{p.AddReportTo},
				},
			},
		})
	}
	// v2.9.170: add_nel_header — set NEL (Network Error Logging) response header.
	if p.AddNELHeader != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Nel": []any{p.AddNELHeader},
				},
			},
		})
	}
	// v2.9.171: block_http_methods — reject listed HTTP methods with 405 Method Not Allowed.
	if p.BlockHTTPMethods != "" {
		for _, method := range strings.Split(p.BlockHTTPMethods, ",") {
			method = strings.TrimSpace(strings.ToUpper(method))
			if method == "" {
				continue
			}
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match": []any{
							map[string]any{"method": []any{method}},
						},
						"handle": []any{
							map[string]any{
								"handler":     "static_response",
								"status_code": 405,
								"headers": map[string]any{
									"Allow": []any{"GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"},
								},
							},
						},
					},
				},
			})
		}
	}
	// v2.9.172: add_service_worker_allowed — set Service-Worker-Allowed response header to expand SW scope.
	if p.AddServiceWorkerAllowed != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Service-Worker-Allowed": []any{p.AddServiceWorkerAllowed},
				},
			},
		})
	}
	// v2.9.173: add_accept_ch — set Accept-CH response header to declare supported client hints.
	if p.AddAcceptCH != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Accept-Ch": []any{p.AddAcceptCH},
				},
			},
		})
	}
	// v2.9.174: add_alt_svc — set Alt-Svc response header to advertise alternative services.
	if p.AddAltSvc != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Alt-Svc": []any{p.AddAltSvc},
				},
			},
		})
	}
	// v2.9.175: add_content_language — set Content-Language response header.
	if p.AddContentLanguage != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Content-Language": []any{p.AddContentLanguage},
				},
			},
		})
	}
	// v2.9.176: add_critical_ch — set Critical-CH response header (marks required client hints).
	if p.AddCriticalCH != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Critical-Ch": []any{p.AddCriticalCH},
				},
			},
		})
	}
	// v2.9.177: add_x_download_options — set X-Download-Options: noopen to prevent IE auto-open.
	if p.AddXDownloadOptions {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Download-Options": []any{"noopen"},
				},
			},
		})
	}
	// v2.9.178: deny_user_agent_regexp — block requests whose User-Agent matches the regexp with 403.
	if p.DenyUserAgentRegexp != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{
						map[string]any{
							"header_regexp": map[string]any{
								"User-Agent": map[string]any{
									"pattern": p.DenyUserAgentRegexp,
								},
							},
						},
					},
					"handle": []any{
						map[string]any{
							"handler":     "static_response",
							"status_code": 403,
						},
					},
				},
			},
		})
	}
	// v2.9.217: add_x_environment — set static X-Environment request header on upstream calls.
	if p.AddXEnvironment != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Environment": []any{p.AddXEnvironment},
				},
			},
		})
	}
	// v2.9.218: add_x_trace_id — forward X-Trace-ID request header (Caddy UUID per request) to upstream.
	if p.AddXTraceID {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Trace-Id": []any{"{http.request.uuid}"},
				},
			},
		})
	}
	// v2.9.220: add_x_session_id — forward X-Session-ID request header (Caddy UUID per request) to upstream.
	if p.AddXSessionID {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Session-Id": []any{"{http.request.uuid}"},
				},
			},
		})
	}
	// v2.9.221: add_x_response_trace_id — set X-Response-Trace-ID response header (echoes the trace UUID).
	if p.AddXResponseTraceID {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Response-Trace-Id": []any{"{http.request.uuid}"},
				},
			},
		})
	}
	// v2.9.222: add_x_request_local_addr — forward X-Local-Addr request header (Caddy listen IP) to upstream.
	if p.AddXRequestLocalAddr {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Local-Addr": []any{"{http.request.local.host}"},
				},
			},
		})
	}
	// v2.9.223: add_x_request_local_port — forward X-Local-Port request header (Caddy listen port) to upstream.
	if p.AddXRequestLocalPort {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Local-Port": []any{"{http.request.local.port}"},
				},
			},
		})
	}
	// v2.9.224: add_x_request_path_info — forward X-PathInfo header (CGI-style PATH_INFO) to upstream.
	if p.AddXRequestPathInfo {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Pathinfo": []any{"{http.request.uri.path}"},
				},
			},
		})
	}
	// v2.9.258: force_canonical_host — when set, any request whose Host
	// header doesn't equal the canonical value gets a 301 to the canonical
	// equivalent (path + query preserved). Common SEO pattern: redirect
	// www.example.com → example.com (or vice versa) to avoid duplicate
	// content penalties.
	if p.ForceCanonicalHost != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{
						map[string]any{
							"not": []any{
								map[string]any{"host": []any{p.ForceCanonicalHost}},
							},
						},
					},
					"handle": []any{map[string]any{
						"handler": "static_response",
						"headers": map[string]any{
							"Location": []any{"https://" + p.ForceCanonicalHost + "{http.request.uri}"},
						},
						"status_code": 301,
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.259: add_x_robots_noindex_quick — quick X-Robots-Tag noindex toggle.
	if p.AddXRobotsNoindexQuick {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Robots-Tag": []any{"noindex, nofollow"},
				},
			},
		})
	}
	// v2.9.260: block_bot_user_agents — built-in regexp matching common
	// scrapers (AhrefsBot, SemrushBot, Bytespider, MJ12bot, DotBot, etc.).
	// 403 on match. Maintained as a single regex string here so users get
	// a baseline blocklist with one click without needing to write their own.
	if p.BlockBotUserAgents {
		const botRegex = `(?i)(AhrefsBot|SemrushBot|Bytespider|MJ12bot|DotBot|PetalBot|DataForSeoBot|YandexBot|BLEXBot|SerpstatBot)`
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"header_regexp": map[string]any{
							"User-Agent": map[string]any{"pattern": botRegex},
						},
					}},
					"handle": []any{map[string]any{"handler": "static_response", "status_code": 403}},
				},
			},
		})
	}
	// v2.9.261: block_admin_paths — 404 common admin / config paths so
	// scanners that probe /wp-admin, /.git, /.env, /phpmyadmin etc. on
	// non-applicable upstreams don't waste upstream cycles. 404 (rather
	// than 403) so the scanner doesn't learn the path exists at all.
	if p.BlockAdminPaths {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{"path": []any{
						"/wp-admin*", "/wp-login*", "/.git*", "/.env*",
						"/phpmyadmin*", "/myadmin*", "/.svn*", "/.hg*",
						"/.aws*", "/.ssh*", "/admin/config.php*",
					}}},
					"handle": []any{map[string]any{"handler": "static_response", "status_code": 404}},
				},
			},
		})
	}
	// v2.9.262: add_link_dns_prefetch — Link: <…>; rel=dns-prefetch response header.
	if p.AddLinkDNSPrefetch != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"add": map[string]any{
					"Link": []any{p.AddLinkDNSPrefetch + "; rel=dns-prefetch"},
				},
			},
		})
	}
	// v2.9.263: add_link_preconnect — Link: <…>; rel=preconnect response header.
	if p.AddLinkPreconnect != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"add": map[string]any{
					"Link": []any{p.AddLinkPreconnect + "; rel=preconnect"},
				},
			},
		})
	}
	// v2.9.264: add_x_csp_disabled — explicitly clear Content-Security-Policy.
	// Different from "no CSP set" because some upstreams set their own CSP
	// header that you may want to suppress at the edge. Sets the header to
	// empty so it overrides any upstream value.
	if p.AddXCSPDisabled {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"delete": []any{"Content-Security-Policy"},
			},
		})
	}
	// v2.9.265: add_x_request_method_override — honor X-HTTP-Method-Override.
	// When the client sends `X-HTTP-Method-Override: PUT`, Caddy rewrites
	// the request method to PUT before forwarding. Common for clients
	// behind firewalls that only allow GET/POST.
	if p.AddXRequestMethodOverride {
		handlers = append(handlers, map[string]any{
			"handler": "rewrite",
			"method":  "{http.request.header.X-Http-Method-Override}",
		})
	}
	// v2.9.250: strip_request_headers — delete listed request headers before forwarding.
	if p.StripRequestHeaders != "" {
		delList := []any{}
		for _, h := range strings.Split(p.StripRequestHeaders, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				delList = append(delList, h)
			}
		}
		if len(delList) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "headers",
				"request": map[string]any{
					"delete": delList,
				},
			})
		}
	}
	// v2.9.251: add_x_forwarded_method — forward HTTP method as X-Forwarded-Method.
	if p.AddXForwardedMethod {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Method": []any{"{http.request.method}"},
				},
			},
		})
	}
	// v2.9.252: add_x_request_original_host — preserve original Host header (pre-rewrite).
	if p.AddXRequestOriginalHost {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Original-Host": []any{"{http.request.host}"},
				},
			},
		})
	}
	// v2.9.253: add_x_request_dnt — forward DNT (Do Not Track) header to upstream.
	if p.AddXRequestDNT {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Dnt": []any{"{http.request.header.DNT}"},
				},
			},
		})
	}
	// v2.9.254: add_x_geo_region — set static X-Geo-Region request header.
	if p.AddXGeoRegion != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Geo-Region": []any{p.AddXGeoRegion},
				},
			},
		})
	}
	// v2.9.255: add_x_request_secure — X-Request-Secure: on/off based on TLS state.
	if p.AddXRequestSecure {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					// Caddy expression: TLS handshake completed → "on", else "off".
					"X-Request-Secure": []any{"{http.request.tls.version}"},
				},
			},
		})
	}
	// v2.9.256: add_x_request_query_count — debug header (presence of query string).
	if p.AddXRequestQueryCount {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Query-Count": []any{"{http.request.uri.query}"},
				},
			},
		})
	}
	// v2.9.257: add_x_request_id_header_response — echo trace UUID to response header.
	if p.AddXRequestIDHeaderResponse {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Request-Id": []any{"{http.request.uuid}"},
				},
			},
		})
	}
	// v2.9.242: add_x_real_ssl_protocol — forward TLS version as X-Real-SSL-Protocol to upstream.
	if p.AddXRealSSLProtocol {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Real-SSL-Protocol": []any{"{http.request.tls.version}"},
				},
			},
		})
	}
	// v2.9.243: add_x_real_ssl_cipher — forward negotiated cipher as X-Real-SSL-Cipher to upstream.
	if p.AddXRealSSLCipher {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Real-SSL-Cipher": []any{"{http.request.tls.cipher_suite}"},
				},
			},
		})
	}
	// v2.9.244: add_x_cache_status — set static X-Cache-Status response header.
	if p.AddXCacheStatus != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Cache-Status": []any{p.AddXCacheStatus},
				},
			},
		})
	}
	// v2.9.245: deny_referer_regexp — return 403 when Referer header matches the regexp.
	if p.DenyRefererRegexp != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{
						map[string]any{
							"header_regexp": map[string]any{
								"Referer": map[string]any{"pattern": p.DenyRefererRegexp},
							},
						},
					},
					"handle": []any{map[string]any{"handler": "static_response", "status_code": 403}},
				},
			},
		})
	}
	// v2.9.246: add_x_request_user_agent — forward UA as X-Request-User-Agent to upstream (debug).
	if p.AddXRequestUserAgent {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-User-Agent": []any{"{http.request.header.User-Agent}"},
				},
			},
		})
	}
	// v2.9.247: add_reporting_endpoints — Reporting-Endpoints response header (RFC 8942).
	if p.AddReportingEndpoints != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Reporting-Endpoints": []any{p.AddReportingEndpoints},
				},
			},
		})
	}
	// v2.9.248: add_x_request_byte_count — forward Content-Length as X-Request-Byte-Count.
	if p.AddXRequestByteCount {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Byte-Count": []any{"{http.request.header.Content-Length}"},
				},
			},
		})
	}
	// v2.9.249: add_x_request_received_at — forward server-side timestamp as X-Request-Received-At.
	if p.AddXRequestReceivedAt {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Received-At": []any{"{time.now}"},
				},
			},
		})
	}
	// v2.9.234: add_x_authenticated_user — set static X-Authenticated-User request header.
	if p.AddXAuthenticatedUser != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Authenticated-User": []any{p.AddXAuthenticatedUser},
				},
			},
		})
	}
	// v2.9.235: block_path_extensions — return 403 for paths ending in any
	// of the listed extensions (e.g. ".php,.git,.cgi"). Each extension is
	// matched as a glob `*<ext>` so the matcher catches every path level.
	if p.BlockPathExtensions != "" {
		var globs []any
		for _, ext := range strings.Split(p.BlockPathExtensions, ",") {
			ext = strings.TrimSpace(ext)
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			globs = append(globs, "*"+ext)
		}
		if len(globs) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match":  []any{map[string]any{"path": globs}},
						"handle": []any{map[string]any{"handler": "static_response", "status_code": 403}},
					},
				},
			})
		}
	}
	// v2.9.236: add_link_modulepreload — Link: <…>; rel=modulepreload response header.
	if p.AddLinkModulePreload != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"add": map[string]any{
					"Link": []any{p.AddLinkModulePreload + "; rel=modulepreload"},
				},
			},
		})
	}
	// v2.9.237: add_x_remote_user — set static X-Remote-User request header (Nginx-style).
	if p.AddXRemoteUser != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Remote-User": []any{p.AddXRemoteUser},
				},
			},
		})
	}
	// v2.9.238: add_x_forwarded_path — forward X-Forwarded-Path request header (URI path) to upstream.
	if p.AddXForwardedPath {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Path": []any{"{http.request.uri.path}"},
				},
			},
		})
	}
	// v2.9.239: add_x_geo_country_code — set static X-Geo-Country header (CDN convention).
	if p.AddXGeoCountryCode != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Geo-Country": []any{p.AddXGeoCountryCode},
				},
			},
		})
	}
	// v2.9.240: add_x_request_priority — RFC 9218 Priority hints in X-Request-Priority response header.
	if p.AddXRequestPriority != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Request-Priority": []any{p.AddXRequestPriority},
				},
			},
		})
	}
	// v2.9.212: add_x_request_remote_port — forward client TCP port as X-Request-Remote-Port to upstream.
	if p.AddXRequestRemotePort {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Remote-Port": []any{"{http.request.remote.port}"},
				},
			},
		})
	}
	// v2.9.213: add_x_request_protocol — forward HTTP version (HTTP/1.1, HTTP/2) as X-Request-Protocol to upstream.
	if p.AddXRequestProtocol {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Protocol": []any{"{http.request.proto}"},
				},
			},
		})
	}
	// v2.9.214: add_save_data_vary — append Save-Data to the Vary response header for client-hint aware caching.
	if p.AddSaveDataVary {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"add": map[string]any{
					"Vary": []any{"Save-Data"},
				},
			},
		})
	}
	// v2.9.200: add_x_no_archive — set X-No-Archive: yes response header to block archive caching.
	if p.AddXNoArchive {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-No-Archive": []any{"yes"},
				},
			},
		})
	}
	// v2.9.201: add_x_request_hostname — forward X-Request-Hostname request header to upstream.
	if p.AddXRequestHostname {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Hostname": []any{"{http.request.hostname}"},
				},
			},
		})
	}
	// v2.9.202: add_x_xss_protection_disabled — set X-XSS-Protection: 0 response header (disable legacy XSS filter).
	if p.AddXXSSProtectionDisabled {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Xss-Protection": []any{"0"},
				},
			},
		})
	}
	// v2.9.197: add_x_request_referer — forward X-Request-Referer request header (echoes Referer) to upstream.
	if p.AddXRequestReferer {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Referer": []any{"{http.request.header.Referer}"},
				},
			},
		})
	}
	// v2.9.198: add_x_request_origin — forward X-Request-Origin request header (echoes Origin) to upstream.
	if p.AddXRequestOrigin {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Origin": []any{"{http.request.header.Origin}"},
				},
			},
		})
	}
	// v2.9.199: add_x_forwarded_uri — forward X-Forwarded-URI request header (full request URI) to upstream.
	if p.AddXForwardedURI {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Uri": []any{"{http.request.uri}"},
				},
			},
		})
	}
	// v2.9.194: add_x_forwarded_email — set static X-Forwarded-Email request header on upstream calls.
	if p.AddXForwardedEmail != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Email": []any{p.AddXForwardedEmail},
				},
			},
		})
	}
	// v2.9.195: add_x_forwarded_roles — set static X-Forwarded-Roles request header on upstream calls.
	if p.AddXForwardedRoles != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Roles": []any{p.AddXForwardedRoles},
				},
			},
		})
	}
	// v2.9.196: block_query_param_regexp — return 403 when the request's raw query string matches the regexp.
	if p.BlockQueryParamRegexp != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{
						map[string]any{
							"expression": fmt.Sprintf("{http.request.uri.query} matches '%s'", strings.ReplaceAll(p.BlockQueryParamRegexp, "'", "\\'")),
						},
					},
					"handle": []any{
						map[string]any{
							"handler":     "static_response",
							"status_code": 403,
						},
					},
				},
			},
		})
	}
	// v2.9.191: add_x_real_scheme — forward X-Real-Scheme request header (http or https) to upstream.
	if p.AddXRealScheme {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Real-Scheme": []any{"{http.request.scheme}"},
				},
			},
		})
	}
	// v2.9.192: add_origin_agent_cluster — set Origin-Agent-Cluster: ?1 response header.
	if p.AddOriginAgentCluster {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Origin-Agent-Cluster": []any{"?1"},
				},
			},
		})
	}
	// v2.9.193: add_x_forwarded_groups — set static X-Forwarded-Groups request header on upstream calls.
	if p.AddXForwardedGroups != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Groups": []any{p.AddXForwardedGroups},
				},
			},
		})
	}
	// v2.9.188: add_x_request_method — forward X-Request-Method request header (echoes HTTP method) to upstream.
	if p.AddXRequestMethod {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Method": []any{"{http.request.method}"},
				},
			},
		})
	}
	// v2.9.189: add_x_request_query — forward X-Request-Query request header (echoes query string) to upstream.
	if p.AddXRequestQuery {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Query": []any{"{http.request.uri.query}"},
				},
			},
		})
	}
	// v2.9.190: add_x_forwarded_user — set static X-Forwarded-User request header on upstream calls.
	if p.AddXForwardedUser != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-User": []any{p.AddXForwardedUser},
				},
			},
		})
	}
	// v2.9.185: add_age_zero — set Age: 0 response header to signal a fresh response (CDN bypass).
	if p.AddAgeZero {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Age": []any{"0"},
				},
			},
		})
	}
	// v2.9.186: add_surrogate_control — set Surrogate-Control response header (CDN-only cache directive).
	if p.AddSurrogateControl != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Surrogate-Control": []any{p.AddSurrogateControl},
				},
			},
		})
	}
	// v2.9.187: add_warning_header — set Warning response header (RFC 7234 warning codes).
	if p.AddWarningHeader != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Warning": []any{p.AddWarningHeader},
				},
			},
		})
	}
	// v2.9.182: add_x_clacks_overhead — set X-Clacks-Overhead response header (custom value).
	if p.AddXClacksOverhead != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Clacks-Overhead": []any{p.AddXClacksOverhead},
				},
			},
		})
	}
	// v2.9.183: add_x_ua_compatible — set X-UA-Compatible response header (legacy IE rendering).
	if p.AddXUACompatible != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Ua-Compatible": []any{p.AddXUACompatible},
				},
			},
		})
	}
	// v2.9.179: add_pragma_no_cache — set Pragma: no-cache response header (HTTP/1.0 cache directive).
	if p.AddPragmaNoCache {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Pragma": []any{"no-cache"},
				},
			},
		})
	}
	// v2.9.181: add_x_request_path — inject X-Request-Path request header on upstream calls.
	if p.AddXRequestPath {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Path": []any{"{http.request.uri.path}"},
				},
			},
		})
	}
	// v2.9.156: add_document_policy — set Document-Policy response header for web platform feature controls.
	if p.AddDocumentPolicy != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Document-Policy": []any{p.AddDocumentPolicy},
				},
			},
		})
	}
	// v2.9.154: add_x_powered_by — set a custom X-Powered-By response header.
	if p.AddXPoweredBy != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Powered-By": []any{p.AddXPoweredBy},
				},
			},
		})
	}
	// v2.9.131: strip_x_powered_by — delete X-Powered-By response header (hides technology stack).
	if p.StripXPoweredBy {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"delete": []any{"X-Powered-By"},
			},
		})
	}
	// v2.9.103: add_resp_cookies — append Set-Cookie headers to every response.
	if p.AddRespCookies != "" {
		cookies := []any{}
		for _, line := range strings.Split(p.AddRespCookies, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				cookies = append(cookies, line)
			}
		}
		if len(cookies) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "headers",
				"response": map[string]any{
					"add": map[string]any{
						"Set-Cookie": cookies,
					},
				},
			})
		}
	}
	// v2.9.80: server_header_value — override (or suppress) the Server response header.
	if p.ServerHeaderValue != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Server": []any{p.ServerHeaderValue},
				},
			},
		})
	}
	// v2.9.81: x_robots_tag — X-Robots-Tag response header for search-engine control.
	if p.XRobotsTag != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Robots-Tag": []any{p.XRobotsTag},
				},
			},
		})
	}
	// v2.9.82: add_forwarded_header — inject RFC 7239 Forwarded header on upstream requests.
	if p.AddForwardedHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"Forwarded": []any{"for={http.request.remote.host};proto={http.request.scheme};host={http.request.host}"},
				},
			},
		})
	}
	// v2.9.76: add_canonical_link_header — inject Link: <https://primary/>; rel="canonical".
	if p.AddCanonicalLinkHeader && len(domains) > 0 {
		canonical := fmt.Sprintf("<https://%s/>; rel=\"canonical\"", domains[0])
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Link": []any{canonical},
				},
			},
		})
	}
	// v2.9.3: CORS headers — preflight (OPTIONS) handling + response headers.
	// v2.9.8: extended with cors_allow_credentials and cors_expose_headers.
	// v2.9.19: cors_max_age_sec, cors_allow_methods, cors_allow_headers overrides.
	if p.CORSEnabled {
		origins := strings.TrimSpace(p.CORSOrigins)
		if origins == "" {
			origins = "*"
		}
		corsAllowMethods := "GET, POST, PUT, DELETE, PATCH, OPTIONS"
		if p.CORSAllowMethods != "" {
			corsAllowMethods = p.CORSAllowMethods
		}
		corsAllowHeaders := "Content-Type, Authorization, X-Requested-With"
		if p.CORSAllowHeaders != "" {
			corsAllowHeaders = p.CORSAllowHeaders
		}
		corsMaxAge := "86400"
		if p.CORSMaxAgeSec > 0 {
			corsMaxAge = fmt.Sprintf("%d", p.CORSMaxAgeSec)
		}
		preflightHdrs := map[string]any{
			"Access-Control-Allow-Origin":  []any{origins},
			"Access-Control-Allow-Methods": []any{corsAllowMethods},
			"Access-Control-Allow-Headers": []any{corsAllowHeaders},
			"Access-Control-Max-Age":       []any{corsMaxAge},
		}
		respHdrs := map[string]any{
			"Access-Control-Allow-Origin":  []any{origins},
			"Access-Control-Allow-Methods": []any{corsAllowMethods},
			"Access-Control-Allow-Headers": []any{corsAllowHeaders},
		}
		if p.CORSAllowCredentials {
			preflightHdrs["Access-Control-Allow-Credentials"] = []any{"true"}
			respHdrs["Access-Control-Allow-Credentials"] = []any{"true"}
		}
		if p.CORSExposeHeaders != "" {
			respHdrs["Access-Control-Expose-Headers"] = []any{p.CORSExposeHeaders}
		}
		// v2.9.66: cors_allow_private_network — Chrome Private Network Access CORS extension.
		if p.CORSAllowPrivateNetwork {
			preflightHdrs["Access-Control-Allow-Private-Network"] = []any{"true"}
		}
		// Handle OPTIONS preflight: respond immediately with 204.
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{"method": []any{"OPTIONS"}}},
					"handle": []any{
						map[string]any{
							"handler":  "headers",
							"response": map[string]any{"set": preflightHdrs},
						},
						map[string]any{"handler": "static_response", "status_code": 204},
					},
					"terminal": true,
				},
			},
		})
		// For non-OPTIONS requests: add CORS headers to the response.
		handlers = append(handlers, map[string]any{
			"handler":  "headers",
			"response": map[string]any{"set": respHdrs},
		})
	}
	// v2.9.152: add_cors_vary_header — add Vary: Origin for correct CDN caching of CORS responses.
	if p.AddCORSVaryHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"add": map[string]any{
					"Vary": []any{"Origin"},
				},
			},
		})
	}
	// v2.9.2: URL rewrite rules — each rule becomes a Caddy `rewrite` handler.
	// strip_prefix: chop a leading path segment via regexp.
	// add_prefix: prepend a path prefix via static_response placeholder.
	// regex: apply a regexp substitution to the path.
	for _, rule := range p.URLRewriteList() {
		from := strings.TrimSpace(rule.From)
		to := strings.TrimSpace(rule.To)
		if from == "" {
			continue
		}
		switch rule.Type {
		case "strip_prefix":
			// Rewrite /prefix/rest → /rest
			handlers = append(handlers, map[string]any{
				"handler":            "rewrite",
				"strip_path_prefix": from,
			})
		case "add_prefix":
			// Rewrite /path → /prefix/path
			handlers = append(handlers, map[string]any{
				"handler": "rewrite",
				"uri":     from + "{http.request.uri}",
			})
		case "regex":
			if to == "" {
				to = "/"
			}
			handlers = append(handlers, map[string]any{
				"handler": "rewrite",
				"uri": map[string]any{
					"path": map[string]any{
						"find":    from,
						"replace": to,
					},
				},
			})
		}
	}
	// v2.9.67: robots_txt_disallow_all — serve "User-agent: *\nDisallow: /" for all bots.
	if p.RobotsTxtDisallowAll {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"path":   []any{"/robots.txt"},
						"method": []any{"GET", "HEAD"},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 200,
						"headers":     map[string]any{"Content-Type": []any{"text/plain; charset=utf-8"}},
						"body":        "User-agent: *\nDisallow: /",
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.5: custom robots.txt — intercept GET/HEAD /robots.txt and serve
	// the configured body before the request reaches the upstream.
	if p.RobotsTxt != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"path":   []any{"/robots.txt"},
						"method": []any{"GET", "HEAD"},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 200,
						"headers":     map[string]any{"Content-Type": []any{"text/plain; charset=utf-8"}},
						"body":        p.RobotsTxt,
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.79: security_txt_body — serve custom security.txt at /.well-known/security.txt.
	if p.SecurityTxtBody != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"path":   []any{"/.well-known/security.txt"},
						"method": []any{"GET", "HEAD"},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 200,
						"headers":     map[string]any{"Content-Type": []any{"text/plain; charset=utf-8"}},
						"body":        p.SecurityTxtBody,
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.92: http2_push_paths — push static resources via HTTP/2 server push.
	if p.HTTP2PushPaths != "" {
		var resources []any
		for _, path := range strings.Split(p.HTTP2PushPaths, "\n") {
			path = strings.TrimSpace(path)
			if path != "" && !strings.HasPrefix(path, "#") {
				resources = append(resources, map[string]any{"path": path})
			}
		}
		if len(resources) > 0 {
			handlers = append(handlers, map[string]any{
				"handler":   "push",
				"resources": resources,
			})
		}
	}
	// v2.9.93: deny_content_types — reject requests whose Content-Type matches a blocked prefix (415).
	if p.DenyContentTypes != "" {
		var typePatterns []any
		for _, ct := range strings.Split(p.DenyContentTypes, ",") {
			ct = strings.TrimSpace(ct)
			if ct != "" {
				typePatterns = append(typePatterns, ct+"*")
			}
		}
		if len(typePatterns) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match": []any{map[string]any{
							"header": map[string]any{
								"Content-Type": typePatterns,
							},
						}},
						"handle": []any{map[string]any{
							"handler":     "static_response",
							"status_code": 415,
							"body":        "Unsupported Media Type.\n",
						}},
						"terminal": true,
					},
				},
			})
		}
	}
	// v2.9.3: request body size limit (Caddy request_body handler).
	// v2.9.29: also sets read_timeout when RequestBodyReadTimeoutSec > 0.
	if p.MaxRequestBodyMB > 0 || p.RequestBodyReadTimeoutSec > 0 {
		rbHandler := map[string]any{"handler": "request_body"}
		if p.MaxRequestBodyMB > 0 {
			rbHandler["max_size"] = int64(p.MaxRequestBodyMB) * 1024 * 1024
		}
		if p.RequestBodyReadTimeoutSec > 0 {
			rbHandler["read_timeout"] = fmt.Sprintf("%ds", p.RequestBodyReadTimeoutSec)
		}
		handlers = append(handlers, rbHandler)
	}
	// v2.9.3: maintenance mode — serve 503 with a simple HTML body instead
	// of forwarding to the upstream. Also honoured during a scheduled window.
	if p.MaintenanceMode || p.InScheduledMaintenanceWindow() {
		maintenanceBody := `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Maintenance</title><style>*{box-sizing:border-box}body{font-family:system-ui,sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.card{background:#fff;border-radius:16px;padding:40px 48px;text-align:center;box-shadow:0 4px 32px rgba(0,0,0,.08);max-width:480px}h1{font-size:1.5rem;color:#1e293b;margin:16px 0 8px}p{color:#64748b;font-size:.95rem;line-height:1.6;margin:0}</style></head><body><div class="card"><svg width="48" height="48" fill="none" stroke="#f59e0b" stroke-width="1.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M10.34 15.84c-.688-.06-1.386-.09-2.09-.09H7.5a4.5 4.5 0 010-9h.75c.704 0 1.402-.03 2.09-.09m0 9.18c.253.962.584 1.892.985 2.783.247.55.06 1.21-.463 1.511l-.657.38c-.551.318-1.26.117-1.527-.461a20.845 20.845 0 01-1.44-4.282m3.102.069a18.03 18.03 0 01-.59-4.59c0-1.586.205-3.124.59-4.59m0 9.18a23.848 23.848 0 018.835 2.535M10.34 6.66a23.847 23.847 0 008.835-2.535m0 0A23.74 23.74 0 0018.795 3m.38 1.125a23.91 23.91 0 011.014 5.395m-1.014 8.855c-.118.38-.245.754-.38 1.125m.38-1.125a23.91 23.91 0 001.014-5.395m0-3.46c.495.413.811 1.035.811 1.73 0 .695-.316 1.317-.811 1.73m0-3.46a24.347 24.347 0 010 3.46"/></svg><h1>Down for Maintenance</h1><p>` + htmlEscape(msgOrDefault(p.MaintenanceMsg, "We're making improvements and will be back shortly. Thank you for your patience.")) + `</p></div></body></html>`
		maintHeaders := map[string]any{
			"Content-Type": []any{"text/html; charset=utf-8"},
			"Retry-After":  []any{func() string { if p.MaintenanceRetryAfterSec > 0 { return strconv.Itoa(p.MaintenanceRetryAfterSec) }; return "3600" }()},
		}
		// v2.9.100: maintenance_custom_headers — extra "Name: Value" headers on the 503 response.
		if p.MaintenanceCustomHeaders != "" {
			for _, line := range strings.Split(p.MaintenanceCustomHeaders, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if idx := strings.IndexByte(line, ':'); idx > 0 {
					name := strings.TrimSpace(line[:idx])
					val := strings.TrimSpace(line[idx+1:])
					if name != "" {
						maintHeaders[name] = []any{val}
					}
				}
			}
		}
		var maintHandler map[string]any
		// v2.9.157: maintenance_redirect_url — redirect to external page instead of inline 503.
		if p.MaintenanceRedirectURL != "" {
			maintHandler = map[string]any{
				"handler":     "static_response",
				"status_code": 302,
				"headers": map[string]any{
					"Location": []any{p.MaintenanceRedirectURL},
				},
			}
		} else {
			maintHandler = map[string]any{
				"handler":     "static_response",
				"status_code": maintenanceStatusCode(p.MaintenanceStatusCode),
				"headers":     maintHeaders,
				"body":        maintenanceBody,
			}
		}
		// v2.9.118: maintenance_allowed_ips — IPs/CIDRs that bypass maintenance and reach the upstream.
		if p.MaintenanceAllowedIPs != "" {
			var allowedRanges []any
			for _, cidr := range strings.Split(p.MaintenanceAllowedIPs, ",") {
				cidr = strings.TrimSpace(cidr)
				if cidr != "" {
					allowedRanges = append(allowedRanges, cidr)
				}
			}
			if len(allowedRanges) > 0 {
				handlers = append(handlers, map[string]any{
					"handler": "subroute",
					"routes": []any{map[string]any{
						"match": []any{map[string]any{
							"not": []any{map[string]any{
								"remote_ip": map[string]any{"ranges": allowedRanges},
							}},
						}},
						"handle":   []any{maintHandler},
						"terminal": true,
					}},
				})
			} else {
				handlers = append(handlers, maintHandler)
			}
		} else {
			handlers = append(handlers, maintHandler)
		}
		// Still append advancedHandlers so custom error_pages/rate_limit work,
		// but skip the reverse_proxy by returning early from handler chain.
		// (Caddy will short-circuit after static_response.)
	}
	// Feature A: Inject X-Request-Id (or custom header) for distributed tracing.
	if p.AddRequestID {
		ridHeader := p.RequestIDHeaderName
		if ridHeader == "" {
			ridHeader = "X-Request-Id"
		}
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					ridHeader: []any{"{http.request.uuid}"},
				},
			},
		})
		// v2.9.147: add_request_id_to_response — echo the request trace ID in the response header.
		if p.AddRequestIDToResponse {
			handlers = append(handlers, map[string]any{
				"handler": "headers",
				"response": map[string]any{
					"set": map[string]any{
						ridHeader: []any{"{http.request.header." + ridHeader + "}"},
					},
				},
			})
		}
	}
	// v2.9.102: inject_request_timestamp — add X-Request-Timestamp header with the UNIX epoch.
	if p.InjectRequestTimestamp {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Timestamp": []any{"{time.now.unix}"},
				},
			},
		})
	}
	// v2.9.140: add_x_request_start — inject X-Request-Start with millisecond epoch for APM tools.
	if p.AddXRequestStart {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Request-Start": []any{"t={time.now.unix_ms}"},
				},
			},
		})
	}
	// v2.9.104: strip_accept_encoding — delete Accept-Encoding before forwarding to prevent upstream compression.
	if p.StripAcceptEncoding {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"delete": []any{"Accept-Encoding"},
			},
		})
	}
	// v2.9.129: force_upstream_encoding — override Accept-Encoding sent to upstream (e.g. "gzip","identity","br").
	if p.ForceUpstreamEncoding != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"Accept-Encoding": []any{p.ForceUpstreamEncoding},
				},
			},
		})
	}
	// v2.9.109: strip_authorization_header — delete Authorization before forwarding (for proxy-level auth replacement).
	if p.StripAuthorizationHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"delete": []any{"Authorization"},
			},
		})
	}
	// v2.9.110: real_ip_from_header — copy real client IP from a custom header into X-Real-IP.
	if p.RealIPFromHeader != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Real-IP": []any{"{http.request.header." + p.RealIPFromHeader + "}"},
				},
			},
		})
	}
	// v2.9.112: add_x_forwarded_port — add X-Forwarded-Port with the incoming request port.
	if p.AddXForwardedPort {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Port": []any{"{http.request.port}"},
				},
			},
		})
	}
	// v2.9.117: add_x_forwarded_host — inject X-Forwarded-Host with the original Host value.
	if p.AddXForwardedHost {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Host": []any{"{http.request.host}"},
				},
			},
		})
	}
	// v2.9.143: add_x_forwarded_scheme — inject X-Forwarded-Scheme with the client-facing scheme.
	if p.AddXForwardedScheme {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Forwarded-Scheme": []any{"{http.request.scheme}"},
				},
			},
		})
	}
	// v2.9.159: add_origin_header — inject Origin request header for upstream APIs that require it.
	if p.AddOriginHeader != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"Origin": []any{p.AddOriginHeader},
				},
			},
		})
	}
	// v2.9.149: add_x_real_ip — inject X-Real-IP with the direct client IP.
	if p.AddXRealIP {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"set": map[string]any{
					"X-Real-IP": []any{"{http.request.remote.host}"},
				},
			},
		})
	}
	// v2.9.150: strip_incoming_x_forwarded_for — delete X-Forwarded-For to prevent IP spoofing.
	if p.StripIncomingXForwardedFor {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"request": map[string]any{
				"delete": []any{"X-Forwarded-For"},
			},
		})
	}
	// Feature B: Strip configured response headers from upstream replies.
	if toStrip := p.StripRespHeaderList(); len(toStrip) > 0 {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"delete": toStrip,
			},
		})
	}
	// Feature C: Block requests from listed user-agent patterns (case-insensitive regex OR).
	if p.BlockedAgents != "" {
		var patterns []string
		for _, a := range strings.Split(p.BlockedAgents, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				patterns = append(patterns, regexp.QuoteMeta(a))
			}
		}
		if len(patterns) > 0 {
			combined := strings.Join(patterns, "|")
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match": []any{map[string]any{
							"header_regexp": map[string]any{
								"User-Agent": "(?i)(" + combined + ")",
							},
						}},
						"handle": []any{map[string]any{
							"handler":     "static_response",
							"status_code": 403,
							"body":        "Access denied.\n",
						}},
						"terminal": true,
					},
				},
			})
		}
	}
	// v2.9.78: block_ua_regexp — block requests whose User-Agent matches the Go regexp (403).
	if p.BlockUARegexp != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"header_regexp": map[string]any{
							"User-Agent": p.BlockUARegexp,
						},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 403,
						"body":        "Access denied.\n",
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.107: block_referer_regexp — block requests whose Referer header matches the Go regexp (hotlink protection).
	if p.BlockRefererRegexp != "" {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{
				map[string]any{
					"match": []any{map[string]any{
						"header_regexp": map[string]any{
							"Referer": p.BlockRefererRegexp,
						},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 403,
						"body":        "Access denied.\n",
					}},
					"terminal": true,
				},
			},
		})
	}
	// v2.9.137: deny_request_content_type — block requests whose Content-Type matches a configured MIME type.
	if p.DenyRequestContentType != "" {
		var typePatterns []string
		for _, ct := range strings.Split(p.DenyRequestContentType, ",") {
			ct = strings.TrimSpace(ct)
			if ct != "" {
				typePatterns = append(typePatterns, regexp.QuoteMeta(ct))
			}
		}
		if len(typePatterns) > 0 {
			combined := "(?i)(" + strings.Join(typePatterns, "|") + ")"
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{map[string]any{
					"match": []any{map[string]any{
						"header_regexp": map[string]any{"Content-Type": combined},
					}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 415,
						"body":        "Unsupported Media Type\n",
					}},
					"terminal": true,
				}},
			})
		}
	}
	// v2.9.121: deny_referer_empty — block requests that carry no Referer header (prevents direct hotlinking).
	if p.DenyRefererEmpty {
		handlers = append(handlers, map[string]any{
			"handler": "subroute",
			"routes": []any{map[string]any{
				"match": []any{map[string]any{
					"not": []any{map[string]any{
						"header": map[string]any{"Referer": []any{"*"}},
					}},
				}},
				"handle": []any{map[string]any{
					"handler":     "static_response",
					"status_code": 403,
					"body":        "Access denied.\n",
				}},
				"terminal": true,
			}},
		})
	}
	// v2.9.108: add_content_type_nosniff — add X-Content-Type-Options: nosniff response header.
	if p.AddContentTypeNosniff {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"X-Content-Type-Options": []any{"nosniff"},
				},
			},
		})
	}
	// Inject or override Cache-Control response header.
	if p.ResponseCacheControl != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cache-Control": []any{p.ResponseCacheControl},
				},
			},
		})
	}
	// v2.9.128: add_expect_ct_header — add Expect-CT: enforce response header for certificate transparency.
	if p.AddExpectCTHeader {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Expect-CT": []any{"enforce"},
				},
			},
		})
	}
	// v2.9.139: add_cache_control_public — add Cache-Control: public response header for CDN caching.
	if p.AddCacheControlPublic {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cache-Control": []any{"public"},
				},
			},
		})
	}
	// v2.9.120: add_cache_control_no_store — force Cache-Control: no-store on all responses.
	if p.AddCacheControlNoStore {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cache-Control": []any{"no-store"},
				},
			},
		})
	}
	// v2.9.144: response_cache_ttl_sec — set Cache-Control: max-age=N on responses.
	if p.ResponseCacheTTLSec > 0 {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Cache-Control": []any{fmt.Sprintf("max-age=%d", p.ResponseCacheTTLSec)},
				},
			},
		})
	}
	// v2.9.145: add_link_preload — set Link response header for HTTP/2 preload hints.
	if p.AddLinkPreload != "" {
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Link": []any{p.AddLinkPreload},
				},
			},
		})
	}
	// v2.9.11: error_redirect_url takes priority over error_page_html — redirect
	// the client to a custom URL instead of serving the error inline.
	if p.ErrorRedirectURL != "" {
		reverseProxy["handle_response"] = []any{
			map[string]any{
				"match": map[string]any{"status_code": []any{4, 5}},
				"handle": []any{
					map[string]any{
						"handler":     "static_response",
						"status_code": 302,
						"headers":     map[string]any{"Location": []any{p.ErrorRedirectURL}},
					},
				},
			},
		}
	} else if p.ErrorPageHTML != "" {
		// v2.9.58: error_page_codes — if set, only intercept these specific codes.
		var epMatch map[string]any
		if p.ErrorPageCodes != "" {
			var codes []any
			for _, cs := range strings.Split(p.ErrorPageCodes, ",") {
				cs = strings.TrimSpace(cs)
				if code, err := strconv.Atoi(cs); err == nil && code >= 100 && code <= 599 {
					codes = append(codes, code)
				}
			}
			if len(codes) > 0 {
				epMatch = map[string]any{"status_code": codes}
			}
		}
		if epMatch == nil {
			epMatch = map[string]any{"status_code": []any{4, 5}}
		}
		reverseProxy["handle_response"] = []any{
			map[string]any{
				"match": epMatch,
				"handle": []any{
					map[string]any{
						"handler":     "static_response",
						"status_code": "{http.reverse_proxy.status_code}",
						"headers":     map[string]any{"Content-Type": []any{"text/html; charset=utf-8"}},
						"body":        p.ErrorPageHTML,
					},
				},
			},
		}
	}
	handlers = append(handlers, advancedHandlers...)

	// v2.9.28: query string control — strip or selectively delete query params before forwarding.
	if p.StripQueryString {
		// Drop the entire query string by rewriting the URI to the path only.
		handlers = append(handlers, map[string]any{
			"handler": "rewrite",
			"uri":     "{http.request.uri.path}",
		})
	} else if p.DeleteQueryParams != "" {
		// Delete specific query parameters (e.g. tracking IDs) while keeping the rest.
		var delParams []any
		for _, q := range strings.Split(p.DeleteQueryParams, ",") {
			q = strings.TrimSpace(q)
			if q != "" {
				delParams = append(delParams, q)
			}
		}
		if len(delParams) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "rewrite",
				"query": map[string]any{
					"delete": delParams,
				},
			})
		}
	}

	// v2.9.27: forward_auth — delegate authentication to an external service.
	// If the auth service returns non-2xx the response is sent to the client
	// directly (typically 401/403). On 2xx, configured headers are copied to
	// the upstream request and the proxy continues normally.
	if p.ForwardAuthURL != "" {
		faHandler := map[string]any{
			"handler": "forward_auth",
			"uri":     p.ForwardAuthURL,
		}
		// v2.9.52: forward_auth_method — HTTP method for the auth subrequest (default GET).
		if p.ForwardAuthMethod != "" && p.ForwardAuthMethod != "GET" {
			faHandler["method"] = strings.ToUpper(p.ForwardAuthMethod)
		}
		// v2.9.54: forward_auth_headers_prefix — prefix applied to all copied headers.
		if p.ForwardAuthHeadersPrefix != "" {
			faHandler["headers_prefix"] = p.ForwardAuthHeadersPrefix
		}
		if p.ForwardAuthCopyHeaders != "" {
			var hdrs []any
			for _, h := range strings.Split(p.ForwardAuthCopyHeaders, ",") {
				h = strings.TrimSpace(h)
				if h != "" {
					hdrs = append(hdrs, h)
				}
			}
			if len(hdrs) > 0 {
				faHandler["copy_headers"] = hdrs
			}
		}
		// v2.9.184: forward_auth_skip_paths — wrap forward_auth in a subroute that skips
		// listed path prefixes, so health/metrics/etc. bypass the auth subrequest.
		if p.ForwardAuthSkipPaths != "" {
			var skipPaths []any
			for _, sp := range strings.Split(p.ForwardAuthSkipPaths, ",") {
				sp = strings.TrimSpace(sp)
				if sp == "" {
					continue
				}
				if !strings.HasSuffix(sp, "*") {
					sp = sp + "*"
				}
				skipPaths = append(skipPaths, sp)
			}
			if len(skipPaths) > 0 {
				handlers = append(handlers, map[string]any{
					"handler": "subroute",
					"routes": []any{
						map[string]any{
							"match": []any{
								map[string]any{
									"not": []any{
										map[string]any{"path": skipPaths},
									},
								},
							},
							"handle": []any{faHandler},
						},
					},
				})
			} else {
				handlers = append(handlers, faHandler)
			}
		} else {
			handlers = append(handlers, faHandler)
		}
	}

	// v2.9.53: grpc_web_enabled — transcode gRPC-Web requests to standard gRPC for the upstream.
	// Must be placed immediately before the reverse_proxy handler so it intercepts gRPC-Web
	// Content-Type frames before the proxy forwards them.
	if p.GRPCWebEnabled {
		handlers = append(handlers, map[string]any{"handler": "grpc_web"})
	}

	// v2.9.16: strip path prefix before forwarding to upstream.
	if p.StripPathPrefix && p.PathMatcher != "" {
		prefix := strings.TrimRight(p.PathMatcher, "/*")
		if prefix != "" {
			handlers = append(handlers, map[string]any{
				"handler":           "rewrite",
				"strip_path_prefix": prefix,
			})
		}
	}
	// v2.9.36: upstream_path_prefix — prepend a static prefix to every upstream
	// request URI (e.g. public / → upstream /v2/). Applied after path-prefix
	// stripping so both options can be combined.
	if p.UpstreamPathPrefix != "" {
		pfx := "/" + strings.TrimLeft(p.UpstreamPathPrefix, "/")
		handlers = append(handlers, map[string]any{
			"handler": "rewrite",
			"uri":     pfx + "{http.request.uri}",
		})
	}
	// v2.9.56: strip_path_suffix — remove a static suffix from the request path before proxying.
	if p.StripPathSuffix != "" {
		handlers = append(handlers, map[string]any{
			"handler":           "rewrite",
			"strip_path_suffix": p.StripPathSuffix,
		})
	}
	// v2.9.57: add_req_query_params — append key=value pairs to the upstream query string.
	if p.AddReqQueryParams != "" {
		addQuery := map[string][]string{}
		for _, pair := range strings.FieldsFunc(p.AddReqQueryParams, func(r rune) bool {
			return r == ',' || r == '\n'
		}) {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := ""
			if len(parts) == 2 {
				val = strings.TrimSpace(parts[1])
			}
			if key != "" {
				addQuery[key] = append(addQuery[key], val)
			}
		}
		if len(addQuery) > 0 {
			qAny := map[string]any{}
			for k, vs := range addQuery {
				qAny[k] = vs
			}
			handlers = append(handlers, map[string]any{
				"handler": "rewrite",
				"query":   map[string]any{"add": qAny},
			})
		}
	}
	// v2.9.266: proxy_redirect_rules — when present, emit a subroute BEFORE
	// the reverse_proxy that catches matching paths and redirects. The
	// reverse_proxy still handles every path that doesn't match any rule
	// (Caddy falls through after the subroute completes for unmatched
	// paths). Each rule: {path, code, destination}. Empty destination +
	// non-2xx code = static response with no Location header (e.g. 410
	// Gone for retired endpoints).
	if rules := p.ProxyRedirectRuleList(); len(rules) > 0 {
		ruleRoutes := []any{}
		for _, rule := range rules {
			if rule.Path == "" {
				continue
			}
			code := rule.Code
			if code == 0 {
				code = 301
			}
			var ruleHandle map[string]any
			if rule.Destination == "" {
				ruleHandle = map[string]any{
					"handler":     "static_response",
					"status_code": code,
				}
			} else {
				ruleHandle = map[string]any{
					"handler": "static_response",
					"headers": map[string]any{
						"Location": []any{rule.Destination},
					},
					"status_code": code,
				}
			}
			ruleRoutes = append(ruleRoutes, map[string]any{
				"match":    []any{map[string]any{"path": []any{rule.Path}}},
				"handle":   []any{ruleHandle},
				"terminal": true,
			})
		}
		if len(ruleRoutes) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes":  ruleRoutes,
			})
		}
	}
	handlers = append(handlers, reverseProxy)

	// v2.9.16: path-based routing — narrow the match to a specific path prefix.
	// v2.9.65: path_matcher_type controls how PathMatcher is applied.
	matchObj := map[string]any{"host": asIfaceStrings(domains)}
	if p.PathMatcher != "" {
		switch p.PathMatcherType {
		case "exact":
			// Exact path match — only match this literal path (no wildcard).
			matchObj["path"] = []any{p.PathMatcher}
		case "regexp":
			// Regular expression match against the path.
			matchObj["path_regexp"] = map[string]any{"pattern": p.PathMatcher}
		default:
			// '' or "prefix" — legacy prefix matching behaviour.
			prefix := strings.TrimRight(p.PathMatcher, "/*")
			if prefix != "" {
				matchObj["path"] = []any{prefix, prefix + "/*"}
			}
		}
	}
	return map[string]any{
		"match":    []any{matchObj},
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

// ipBlocklistSubroute returns a Caddy subroute handler that responds 403 to
// any request whose remote IP matches one of the listed CIDR ranges.
func ipBlocklistSubroute(cidrList []string) map[string]any {
	ranges := make([]any, len(cidrList))
	for i, c := range cidrList {
		ranges[i] = c
	}
	return map[string]any{
		"handler": "subroute",
		"routes": []any{
			map[string]any{
				"match": []any{map[string]any{
					"remote_ip": map[string]any{"ranges": ranges},
				}},
				"handle":   []any{map[string]any{"handler": "static_response", "status_code": 403}},
				"terminal": true,
			},
		},
	}
}

// BuildRedirectRoute constructs a single route for a redirection host.
// v2.9.13: prepends IP allowlist subroute and/or maintenance-mode handler
// before the redirect static_response when those features are enabled.
func BuildRedirectRoute(r models.RedirectionHost) map[string]any {
	domains := r.DomainList()
	scheme := r.ForwardScheme
	if scheme == "auto" || scheme == "" {
		scheme = "{http.request.scheme}"
	}
	path := ""
	if r.PreservePath {
		// v2.9.230: redirect_strip_path_prefix — if set, drop the prefix
		// from the captured path before composing Location. We use Caddy's
		// re_replace placeholder via a regex that anchors at start. Falls
		// back to plain {http.request.uri} when no prefix is configured.
		if pfx := strings.TrimSpace(r.RedirectStripPathPrefix); pfx != "" {
			// Caddy supports re.<name> placeholder if the URL has a regex
			// matcher capturing it; without that we fall back to the
			// path_regexp matcher in a wrapping subroute. Simpler: use
			// {http.request.uri.path.replace} via path manipulation.
			// Caddy's `path_regexp` matcher captures into {re.NAME.N}. To
			// keep this simple and not require a matcher rewrite, we
			// build the destination using a Caddy expression placeholder
			// with the prefix stripped at runtime.
			path = "{http.request.uri.path.suffix-after." + pfx + "}{http.request.uri.search}"
		} else {
			path = "{http.request.uri}"
		}
	}
	// v2.9.231: redirect_wildcard_subdomain — substitute first hostname
	// label (the `*` part of *.old.com) into the destination if requested.
	// User puts `{labels.0}.new.example.com` in the destination and Caddy
	// expands it at request time.
	destDomain := r.ForwardDomain
	if r.RedirectWildcardSubdomain {
		// Replace literal '*.' if user put one in the destination,
		// otherwise leave it — they may already have written
		// {http.request.host.labels.0} themselves.
		destDomain = strings.Replace(destDomain, "*", "{http.request.host.labels.0}", 1)
	}
	location := fmt.Sprintf("%s://%s%s", scheme, destDomain, path)
	if scheme == "{http.request.scheme}" {
		location = fmt.Sprintf("{http.request.scheme}://%s%s", destDomain, path)
	}
	statusCode := r.ForwardHTTPCode
	if statusCode == 0 {
		statusCode = 301
	}
	// v2.9.232: sunset_at — after the configured ISO date, every request
	// to this redirect returns 410 Gone instead of redirecting. Comparison
	// is purely date-vs-date in UTC; if today >= sunset, we early-return a
	// 410 handler before any redirect plumbing runs.
	if sunset := strings.TrimSpace(r.SunsetAt); sunset != "" {
		if t, err := time.Parse("2006-01-02", sunset); err == nil {
			today := time.Now().UTC().Truncate(24 * time.Hour)
			if !today.Before(t) {
				return map[string]any{
					"match": []any{map[string]any{"host": asIfaceStrings(domains)}},
					"handle": []any{map[string]any{
						"handler":     "static_response",
						"status_code": 410,
						"body":        "This URL has been retired.",
					}},
					"terminal": true,
				}
			}
		}
	}

	var handlers []any

	// v2.9.26: advanced_config — raw JSON array of handlers injected before security checks.
	if strings.TrimSpace(r.AdvancedConfig) != "" {
		var adv []any
		if err := json.Unmarshal([]byte(r.AdvancedConfig), &adv); err == nil {
			handlers = append(handlers, adv...)
		}
	}

	// v2.9.21: IP blocklist — deny matching IPs with 403 before the redirect fires.
	if r.IPBlocklist != "" {
		if blockRanges := parseCIDRList(r.IPBlocklist); len(blockRanges) > 0 {
			handlers = append(handlers, ipBlocklistSubroute(blockRanges))
		}
	}

	// IP allowlist: deny non-matching IPs before the redirect fires.
	if r.AccessList != "" {
		if allowed := parseCIDRList(r.AccessList); len(allowed) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{
						"match": []any{map[string]any{
							"not": []any{map[string]any{
								"remote_ip": map[string]any{"ranges": allowed},
							}},
						}},
						"handle":   []any{map[string]any{"handler": "static_response", "status_code": 403}},
						"terminal": true,
					},
				},
			})
		}
	}

	// Maintenance mode: respond with configured status code and skip the redirect.
	if r.MaintenanceMode {
		msg := r.MaintenanceMsg
		if msg == "" {
			msg = "Service temporarily unavailable for maintenance."
		}
		statusCode := r.MaintenanceStatusCode
		if statusCode == 0 {
			statusCode = 503
		}
		handlers = append(handlers, map[string]any{
			"handler":     "static_response",
			"status_code": statusCode,
			"body":        msg,
		})
		// Return early — don't add redirect handler below.
		return map[string]any{
			"match":    []any{map[string]any{"host": asIfaceStrings(domains)}},
			"handle":   handlers,
			"terminal": true,
		}
	}

	// v2.9.24: HSTS — inject Strict-Transport-Security on redirect responses.
	if r.HSTSMaxAgeSec > 0 {
		hsts := fmt.Sprintf("max-age=%d", r.HSTSMaxAgeSec)
		if r.HSTSIncludeSubdomains {
			hsts += "; includeSubDomains"
		}
		if r.HSTSPreload {
			hsts += "; preload"
		}
		handlers = append(handlers, map[string]any{
			"handler": "headers",
			"response": map[string]any{
				"set": map[string]any{
					"Strict-Transport-Security": []any{hsts},
				},
			},
		})
	}

	// v2.9.20: custom response headers injected before the redirect fires.
	if respHdrs := r.CustomRespHeaderMap(); len(respHdrs) > 0 {
		setHdrs := map[string]any{}
		delHdrs := []any{}
		for k, v := range respHdrs {
			if v == "" {
				delHdrs = append(delHdrs, k)
			} else {
				setHdrs[k] = []any{v}
			}
		}
		respOp := map[string]any{}
		if len(setHdrs) > 0 {
			respOp["set"] = setHdrs
		}
		if len(delHdrs) > 0 {
			respOp["delete"] = delHdrs
		}
		handlers = append(handlers, map[string]any{"handler": "headers", "response": respOp})
	}

	// v2.9.229: path-based redirect rules. When the row has any rules in
	// redirect_rules, each rule is materialised as an inner subroute with
	// its own path matcher; the host-wide redirect below acts as the
	// catch-all fallback. Rule entries shape:
	//   {path: "/old/*", code: 301, destination: "https://new.example.com{uri}"}
	// Caddy's {uri}, {http.request.uri}, etc. placeholders work in the
	// destination string. Rules without a destination produce a static
	// status response instead (so 410 Gone for deleted resources is
	// expressible as `code: 410, destination: ""`).
	if rules := r.RedirectRuleList(); len(rules) > 0 {
		ruleRoutes := []any{}
		for _, rule := range rules {
			if rule.Path == "" {
				continue
			}
			code := rule.Code
			if code == 0 {
				code = 301
			}
			var ruleHandle map[string]any
			if rule.Destination == "" {
				// No destination → static response with the configured
				// status code (handy for 404/410 on retired endpoints).
				ruleHandle = map[string]any{
					"handler":     "static_response",
					"status_code": code,
				}
			} else {
				ruleHandle = map[string]any{
					"handler": "static_response",
					"headers": map[string]any{
						"Location": []any{rule.Destination},
					},
					"status_code": code,
				}
			}
			ruleRoutes = append(ruleRoutes, map[string]any{
				"match":    []any{map[string]any{"path": []any{rule.Path}}},
				"handle":   []any{ruleHandle},
				"terminal": true,
			})
		}
		if len(ruleRoutes) > 0 {
			handlers = append(handlers, map[string]any{
				"handler": "subroute",
				"routes":  ruleRoutes,
			})
		}
	}

	// The host-wide default redirect — runs after any per-path rules above
	// fall through (or as the only handler when redirect_rules is empty).
	handlers = append(handlers, map[string]any{
		"handler": "static_response",
		"headers": map[string]any{
			"Location": []any{location},
		},
		"status_code": statusCode,
	})

	return map[string]any{
		"match":    []any{map[string]any{"host": asIfaceStrings(domains)}},
		"handle":   handlers,
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

// denyDotfilesSubroute returns a subroute that blocks any request whose URI
// path contains a segment starting with "." (hidden files and directories,
// e.g. /.env, /.git/config, /foo/.htpasswd). Returns 403 Forbidden.
func denyDotfilesSubroute() map[string]any {
	return map[string]any{
		"handler": "subroute",
		"routes": []any{
			map[string]any{
				"match": []any{
					map[string]any{
						"path_regexp": map[string]any{
							"pattern": `(?i)(?:^|/)\.`,
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

// BuildTLSConnectionPolicies returns per-SNI TLS connection policies for proxy
// hosts that have TLSMinVersion set. Returns nil when no enabled host specifies
// a minimum version (caller skips writing the key to Caddy). When non-empty, the
// last element is always an empty catch-all {} so Caddy applies its default TLS
// settings to every other hostname — without it Caddy would only serve TLS for
// explicitly matched SNIs.
func BuildTLSConnectionPolicies(proxies []models.ProxyHost) []any {
	var policies []any
	for _, p := range proxies {
		if !p.Enabled || p.TLSMinVersion == "" {
			continue
		}
		domains := p.DomainList()
		if len(domains) == 0 {
			continue
		}
		snis := make([]any, len(domains))
		for i, d := range domains {
			snis[i] = d
		}
		policies = append(policies, map[string]any{
			"match":        map[string]any{"sni": snis},
			"protocol_min": "tls" + p.TLSMinVersion, // e.g. "tls1.2"
		})
	}
	if len(policies) == 0 {
		return nil
	}
	// Catch-all: without this Caddy would refuse TLS for unmatched SNIs.
	policies = append(policies, map[string]any{})
	return policies
}

// methodStrings converts a []any of method strings back to []string for the
// Allow header in allowed_methods 405 responses.
func methodStrings(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func asIfaceStrings(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// maintenanceStatusCode returns a valid maintenance HTTP status code.
// Valid values are 429, 502, 503 (default), 520.
func maintenanceStatusCode(code int) int {
	switch code {
	case 429, 502, 520:
		return code
	default:
		return 503
	}
}

// msgOrDefault returns msg if non-empty, otherwise returns def.
func msgOrDefault(msg, def string) string {
	if msg != "" {
		return msg
	}
	return def
}

// htmlEscape escapes special HTML characters to prevent injection.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	return s
}

// parseHeaderReplaceRules parses newline-separated "Name|regexp|replacement"
// lines into a Caddy headers handler replace map. Lines that don't have exactly
// two '|' separators are skipped. Multiple rules for the same header name are
// merged into a single slice.
func parseHeaderReplaceRules(raw string) map[string][]any {
	out := map[string][]any{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		pattern := strings.TrimSpace(parts[1])
		replacement := parts[2] // preserve trailing spaces in replacement
		if name == "" || pattern == "" {
			continue
		}
		out[name] = append(out[name], map[string]any{
			"search_regexp": pattern,
			"replace":       replacement,
		})
	}
	return out
}
