package models

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BasicAuthUser is a single HTTP basic-auth credential stored per proxy host.
// BcryptHash is a standard bcrypt hash string (e.g. $2a$12$...).
type BasicAuthUser struct {
	Username   string `json:"user"`
	BcryptHash string `json:"hash"`
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Name         string
	IsAdmin      bool
	Role         string // "admin", "view", or "user"
	CreatedAt    time.Time
	TOTPSecret   string
	TOTPEnabled  bool
	BackupCodes  string // JSON array of SHA-256 hex hashes; empty means no backup codes set
	ColorTheme   string // v2.12.27: "" = default | "orange" — synced across devices via DB
}

const (
	RoleAdmin = "admin"
	RoleView  = "view"
	RoleUser  = "user"
)

func (u *User) IsViewer() bool { return u != nil && u.Role == RoleView }
func (u *User) CanWrite() bool { return u != nil && u.Role != RoleView }

type ProxyHost struct {
	ID                  int64
	ServerID            int64 // v2.4.0: which caddy_servers row this host belongs to (for per-server public-IP lookup)
	Domains             string
	ForwardScheme       string
	ForwardHost         string
	ForwardPort         int
	WebsocketSupport    bool
	BlockCommonExploits bool
	SSLEnabled          bool
	SSLForced           bool
	HTTP2Support        bool
	AdvancedConfig      string
	Enabled             bool
	CertificateID       int64 // 0 = auto (ACME); >0 = use custom certificate with this ID
	BasicAuthEnabled    bool
	BasicAuthUsers      string // JSON: []BasicAuthUser
	AccessList          string // comma-separated CIDRs; empty = allow all
	ExtraUpstreams      string // JSON: []string of "host:port" entries
	OwnerID             sql.NullInt64
	OwnerEmail          string // populated via JOIN for display
	// v2.3.0 unified DNS columns. One record per proxy host; provider
	// identifies which adapter in internal/dns handles lifecycle calls.
	// Empty DNSProvider means "no managed DNS" — the host's A record is
	// whatever the user set manually.
	DNSProvider  string // "" | cloudflare | porkbun | namecheap | godaddy | digitalocean | hetzner
	DNSZoneID    string // provider-native zone ID (opaque for CF/Hetzner; domain for others)
	DNSZoneName  string // base domain, e.g. "example.com", for display
	DNSRecordID  string // record ID returned by the provider after create
	DNSProfileID string // optional credential profile ID; empty uses legacy provider settings
	// Legacy CF/PB columns. Kept for rollback safety — the v2.3.0 migration
	// copies these into the unified columns above. New writes only touch
	// the unified columns, so these stay frozen at whatever the last v2.2.x
	// release left them as.
	CFDNSRecordID string
	CFZoneID      string
	PBDNSRecordID string
	PBDomain      string
	// v2.9.0: per-host security settings. All default to off/empty so
	// existing hosts are unchanged after upgrade. These three are persisted
	// to the proxy_hosts table and reflected in the Caddy config on each sync.
	CompressionEnabled     bool // prepend gzip/zstd encode handler
	SecurityHeadersEnabled bool // add HSTS, X-Frame-Options, X-Content-Type-Options, etc.
	// v2.12.16: in-memory only (not persisted). syncCaddy populates this
	// from settingGlobalStripResponseHeaders before BuildProxyRoute fires
	// so the per-host SecurityHeaders bundle can skip headers the user
	// listed in the global strip — otherwise the bundle's `set` would
	// override the strip handler.
	GlobalStripHeaders     []string `json:"-"`
	TLSMinVersion          string   // "" | "1.0" | "1.1" | "1.2" | "1.3"
	CustomReqHeaders       string   // JSON: map[string]string of request headers to set/delete
	CustomRespHeaders      string   // JSON: map[string]string of response headers to set/delete
	URLRewrites            string   // JSON: []URLRewriteRule
	MaintenanceMode        bool     // v2.9.3: serve 503 instead of proxying
	MaintenanceMsg         string   // custom message shown on the 503 page
	MaintenanceStatusCode  int      // 503 (default), 429, 502, or 520
	MaxRequestBodyMB       int      // 0 = unlimited; >0 = max body size in MiB
	StickySessions         bool     // cookie-based LB for multi-upstream hosts
	UpstreamTimeoutSec     int      // 0 = Caddy default; >0 = dial/response timeout seconds
	CORSEnabled            bool     // add CORS response headers
	CORSOrigins            string   // comma-separated allowed origins, or "*"
	HealthCheckURI         string   // e.g. "/health"; empty = no active checks
	HealthCheckIntervalSec int      // default 30 when HealthCheckURI is set
	HealthCheckMethod      string   // "GET" (default) or "HEAD"
	KeepaliveConns         int      // max idle conns per host; 0 = Caddy default
	Tags                   string   // comma-separated labels, UI-only
	Notes                  string   // freeform admin notes, UI-only
	DisableAccessLog       bool     // skip analytics ingest for this host
	AddRequestID           bool     // inject X-Request-Id header for distributed tracing
	StripRespHeaders       string   // comma-separated response header names to delete
	BlockedAgents          string   // comma-separated user-agent patterns to block (403)
	ResponseCacheControl   string   // override Cache-Control response header; empty = keep upstream value
	UpstreamSNI            string   // override TLS SNI for HTTPS upstreams with a different hostname
	HSTSPreload            bool     // append "; preload" to the HSTS header when SecurityHeadersEnabled
	MaxConnsPerHost        int      // max concurrent connections per upstream (0 = unlimited)
	HealthCheckTimeoutSec  int      // active health check timeout in seconds (default 5)
	UpstreamRetries        int      // number of retries on upstream failure (0 = no retry)
	ForceHTTP1             bool     // force HTTP/1.1 to upstream (disables H2 upstreams)
	BasicAuthRealm         string   // realm shown in browser basic-auth prompt (default "Restricted")
	ErrorPageHTML          string   // custom HTML served when upstream returns 4xx/5xx; empty = pass through
	// v2.9.5: scheduled maintenance window
	MaintenanceWindowStart string // "HH:MM" (24-hour) when the window begins; "" = disabled
	MaintenanceWindowEnd   string // "HH:MM" (24-hour) when the window ends
	MaintenanceWindowDays  string // "" = every day; "mon,wed,fri" subset (3-letter abbrevs)
	// v2.9.5: per-host security
	IPBlocklist            string // comma-separated CIDR ranges to block (403 response)
	LBPolicy               string // "" | "round_robin" | "random" | "ip_hash" | "least_conn" | "uri_hash" | "cookie"
	ProxyProtocol          string // "" | "v1" | "v2" — PROXY protocol version for upstream transport
	RobotsTxt              string // custom robots.txt body injected before the reverse proxy; empty = passthrough
	PassiveFailDurationSec int    // seconds to hold upstream out-of-rotation after failures; 0 = disabled
	PassiveMaxFails        int    // consecutive failures before marking unhealthy; 0 = Caddy default (1)
	HSTSMaxAgeSec          int    // 0 = use default 31536000; >0 = custom max-age for Strict-Transport-Security
	CSPHeader              string // Content-Security-Policy header value; empty = omit
	H2CEnabled             bool   // use h2c (HTTP/2 cleartext) transport to upstream
	HealthCheckHeaders     string // JSON map of headers to include in active health check requests
	// v2.9.6: streaming, buffering, trusted proxy control
	FlushImmediate  bool   // set flush_interval:-1 for SSE/streaming backends
	BufferResponses bool   // buffer full response body before sending to client
	TrustedProxies  string // comma-separated CIDR ranges trusted for X-Forwarded-For
	// v2.9.7: host override, per-host read timeout, dotfile blocking
	UpstreamHostOverride string // override Host header sent to upstream; "" = forward original
	ReadTimeoutSec       int    // response body read timeout in seconds; 0 = no limit
	DenyDotfiles         bool   // block requests to dotfiles/directories (403)
	// v2.9.8: request buffering; CORS enhancements
	RequestBuffersKB     int    // buffer this many KB of request body before forwarding; 0 = disabled
	CORSAllowCredentials bool   // add Access-Control-Allow-Credentials: true
	CORSExposeHeaders    string // comma-separated list for Access-Control-Expose-Headers
	// v2.9.9: upstream TLS verification; separate dial timeout
	SSLVerifyUpstream bool // verify upstream TLS certificate (default: skip verify)
	DialTimeoutSec    int  // dial/connect timeout in seconds; 0 = use upstream_timeout_sec or Caddy default
	// v2.9.10: header-based API key auth; empty User-Agent blocking
	APIKeyHeader        string // header name for API key authentication (e.g. "X-API-Key"); "" = disabled
	APIKeyValue         string // expected API key value; "" = disabled
	BlockEmptyUserAgent bool   // return 403 if the request has no User-Agent header
	// v2.9.11: error redirect URL; granular security header overrides
	ErrorRedirectURL  string // redirect client here on 4xx/5xx from upstream (overrides error_page_html)
	PermissionsPolicy string // custom Permissions-Policy header value; empty = omit
	XFrameOptions     string // override X-Frame-Options in security bundle; empty = use "SAMEORIGIN"
	ReferrerPolicy    string // override Referrer-Policy in security bundle; empty = use default
	// v2.9.14: HSTS includeSubDomains toggle; CSP report-only; keepalive idle timeout
	HSTSIncludeSubdomains   bool   // add "; includeSubDomains" to HSTS header (DB DEFAULT 1 preserves prior always-on behaviour)
	CSPReportOnly           string // Content-Security-Policy-Report-Only header value
	KeepaliveIdleTimeoutSec int    // upstream keepalive idle timeout in seconds (0 = default 90 s)
	// v2.9.15: active health check expected response controls
	HealthCheckExpectStatus    int    // 0 = any 2xx; >0 = require that exact HTTP status code
	HealthCheckExpectBody      string // regexp that must match somewhere in the response body
	HealthCheckFollowRedirects bool   // follow redirects during active health probes
	// v2.9.16: path-based routing
	PathMatcher     string // if non-empty, route only matches this path prefix (e.g. "/api")
	StripPathPrefix bool   // strip PathMatcher prefix before forwarding to upstream
	// v2.9.17: load-balancer tuning
	StickyCookieName string // custom cookie name for sticky-session LB (default "lb_backend")
	LBTryDurationSec int    // seconds to keep retrying across upstreams (0 = Caddy default)
	LBTryIntervalMS  int    // ms between retry attempts (0 = Caddy default 250ms)
	// v2.9.18: compression min size + client IP forwarding
	CompressionMinSizeKB int  // minimum response size in KB to compress (0 = always compress)
	ForwardClientIP      bool // add X-Real-IP header with the real client IP to upstream requests
	// v2.9.19: CORS fine-tuning
	CORSMaxAgeSec    int    // Access-Control-Max-Age in seconds (0 = default 86400)
	CORSAllowMethods string // override Access-Control-Allow-Methods (empty = use default)
	CORSAllowHeaders string // override Access-Control-Allow-Headers (empty = use default)
	// v2.9.22
	RetryStatusCodes string // comma-separated HTTP status codes to trigger retry (e.g. "502,503,504")
	WriteTimeoutSec  int    // time to write request body to upstream; 0 = no limit
	// v2.9.23
	UpstreamTLSMinVersion string // "" | "1.2" | "1.3" — minimum TLS version for upstream connections
	ForwardProxyURL       string // chain through an upstream HTTP proxy (e.g. "http://squid:3128")
	// v2.9.25
	BlockedMethods string // comma-separated HTTP methods to block with 405 (e.g. "TRACE,CONNECT")
	// v2.9.27: forward auth
	ForwardAuthURL         string // auth service URL; empty = disabled
	ForwardAuthCopyHeaders string // comma-separated response headers to copy from auth service to upstream
	// v2.9.28: query string control
	StripQueryString  bool   // remove the entire query string before forwarding
	DeleteQueryParams string // comma-separated query param names to strip (e.g. "utm_source,fbclid")
	// v2.9.29: request/response timing
	RequestBodyReadTimeoutSec int // client→caddy request body read timeout; 0 = no limit
	ResponseHeaderTimeoutSec  int // caddy→upstream response header wait; 0 = use upstream_timeout_sec
	// v2.9.31: upstream connection lifetime limit
	MaxConnDurationSec int // 0 = unlimited; >0 = max seconds before Caddy replaces the upstream conn
	// v2.9.32: upstream response decompression before client delivery
	DecompressResponse bool // when true, decompress gzip/br upstream responses before forwarding
	// v2.9.33: color label for visual grouping in list views (no Caddy impact)
	Color string // "" | "red" | "orange" | "yellow" | "green" | "teal" | "blue" | "purple" | "pink" | "gray"
	// v2.9.34: automatic www ↔ bare domain redirect injected before the proxy
	WWWRedirect string // "" (off) | "to_www" (bare→www) | "to_bare" (www→bare)
	// v2.9.35: strip request headers — companion to StripRespHeaders for the request side
	StripReqHeaders string // comma-separated request header names to delete before forwarding
	// v2.9.36: upstream path prefix — prepend a static prefix to every upstream request URI
	UpstreamPathPrefix string // e.g. "/v2" → proxy / → upstream /v2/
	// v2.9.37: compression tuning
	CompressionLevel      int  // 0 = default; 1-9 for gzip level (1 fast, 9 best)
	CompressionPreferGzip bool // when true, prefer gzip over zstd in encode handler
	// v2.9.39: sort order — manual ordering weight in the list view (0 = default, lower = first)
	SortOrder int
	// v2.9.41: allowed_methods — HTTP method allowlist; empty = allow all (complement to BlockedMethods denylist)
	AllowedMethods string // comma-separated methods, e.g. "GET,POST,PUT" — requests with other methods get 405
	// v2.9.42: upstream max response header size in KB (0 = Caddy default ~1MB)
	UpstreamMaxRespHeaderKB int // transport.max_response_header_size in bytes = value * 1024
	// v2.9.43: dedicated health check port — run active probes on a different port than traffic (0 = same port)
	HealthCheckPort int // e.g. 8080 when the app serves /health on :8080 but traffic on :80
	// v2.9.44: request_id_header_name — custom header for injected request IDs ('' = X-Request-Id default)
	RequestIDHeaderName string // e.g. "X-Trace-Id"; only used when AddRequestID is true
	// v2.9.45: lb_cookie_path — path scope for the sticky-session LB cookie ('' = / default)
	LBCookiePath string // e.g. "/api" scopes the cookie to /api subtree only
	// v2.9.46: passive_unhealthy_latency_ms — mark upstream passive-unhealthy above this latency (0 = disabled)
	PassiveUnhealthyLatencyMS int // e.g. 5000 → trigger unhealthy if response > 5s
	// v2.9.47: tls_handshake_timeout_sec — TLS handshake timeout for upstream connections (0 = Caddy default)
	TLSHandshakeTimeoutSec int // only applies when ForwardScheme=https or UpstreamTLSMinVersion is set
	// v2.9.48: expect_continue_timeout_sec — wait for upstream 100-Continue (0 = disabled/no wait)
	ExpectContinueTimeoutSec int // useful for large file uploads behind a reverse proxy
	// v2.9.49: response_buffers_kb — per-connection response streaming buffer size (0 = Caddy default)
	ResponseBuffersKB int // sets Caddy reverse_proxy.response_buffers; distinct from BufferResponses bool
	// v2.9.50: upstream_max_idle_conns — total idle connections across all upstream hosts (0 = Caddy default)
	UpstreamMaxIdleConns int // transport.keep_alive.max_idle_conns; complement to per-host KeepaliveConns
	// v2.9.51: upstream_keep_alive_probe_sec — interval for TCP keepalive probes to upstreams (0 = no probing)
	UpstreamKeepAliveProbeIntervalSec int // transport.keep_alive.probe_interval
	// v2.9.52: forward_auth_method — HTTP method for ForwardAuth subrequest ('' = GET default)
	ForwardAuthMethod string // "GET" | "POST" | "HEAD" — method used when calling the auth service
	// v2.9.53: grpc_web_enabled — prepend the grpc_web handler to transcode gRPC-Web to gRPC for the upstream
	GRPCWebEnabled bool // allows browser clients that use gRPC-Web or gRPC-Gateway to reach gRPC upstreams
	// v2.9.54: forward_auth_headers_prefix — prefix applied to all headers copied from the ForwardAuth response
	ForwardAuthHeadersPrefix string // e.g. "X-Auth-" → header Foo from auth becomes X-Auth-Foo upstream
	// v2.9.55: health_check_max_size_kb — max body bytes read from upstream during active health checks (0 = Caddy default)
	HealthCheckMaxSizeKB int // reduces memory use when upstream returns large responses on the health endpoint
	// v2.9.56: strip_path_suffix — strip this static suffix from the request path before proxying (e.g. ".html")
	StripPathSuffix string // Caddy rewrite.strip_path_suffix; complements StripPathPrefix
	// v2.9.57: add_req_query_params — newline or comma-separated key=value pairs appended to upstream query string
	AddReqQueryParams string // e.g. "version=2,debug=false" → upstream gets ?version=2&debug=false appended
	// v2.9.58: error_page_codes — comma-separated HTTP codes that trigger ErrorPageHTML (empty = all 4xx/5xx)
	ErrorPageCodes string // e.g. "404,500,503" — only serve custom error page for these codes
	// v2.9.59: upstream_tls_ca_pem_file — path to CA certificate bundle for upstream TLS verification
	UpstreamTLSCAPEMFile string // only used when SSLVerifyUpstream=true; '' = system default CA
	// v2.9.60: keepalive_disabled — completely disable upstream TCP keepalive (for NTLM/kerberos auth upstreams)
	KeepaliveDisabled bool // when true, every upstream request uses a new connection (no pooling)
	// v2.9.61: trailing_slash_redirect — auto-redirect for trailing slash normalisation ('' = off | "add" = add / | "remove" = strip /)
	TrailingSlashRedirect string // injected as a subroute redirect before the proxy
	// v2.9.62: dial_fallback_delay_ms — ms to wait before falling back to the next upstream on dial failure
	DialFallbackDelayMS int // Caddy transport.dial_fallback_delay; 0 = Caddy default (300ms)
	// v2.9.63: upstream_network — TCP protocol variant for upstream dial ('' = tcp | "tcp4" | "tcp6")
	UpstreamNetwork string // force IPv4 or IPv6 for upstream connections
	// v2.9.64: dns_resolver — custom DNS server for resolving upstream hostnames ('' = system resolver)
	DNSResolver string // e.g. "1.1.1.1:53"; only used when UpstreamNetwork or dial requires DNS
	// v2.9.65: path_matcher_type — how PathMatcher is interpreted ('' = prefix | "exact" | "regexp")
	PathMatcherType string // '' (prefix, default) | "exact" | "regexp"
	// v2.9.66: cors_allow_private_network — add Access-Control-Allow-Private-Network: true for Chrome private network access
	CORSAllowPrivateNetwork bool // RFC-compliant CORS extension for private network requests from browser
	// v2.9.67: robots_txt_disallow_all — serve "User-agent: *\nDisallow: /" robots.txt as a quick bot block
	RobotsTxtDisallowAll bool // overrides RobotsTxt field; prepended before the proxy
	// v2.9.68: maintenance_retry_after_sec — Retry-After header value in maintenance 503 response (0 = default 3600)
	MaintenanceRetryAfterSec int
	// v2.9.69: upstream_resolve_timeout_sec — timeout in seconds for DNS resolution of upstream hostnames (0 = Caddy default)
	UpstreamResolveTimeoutSec int
	// v2.9.70: upstream_read_buffer_size_kb — transport read buffer size in KB (0 = Caddy default 32KB)
	UpstreamReadBufferSizeKB int
	// v2.9.71: upstream_write_buffer_size_kb — transport write buffer size in KB (0 = Caddy default 32KB)
	UpstreamWriteBufferSizeKB int
	// v2.9.72: req_header_replace — newline-separated "Name|regexp|replacement" rules applied to request header values
	ReqHeaderReplace string
	// v2.9.73: resp_header_replace — newline-separated "Name|regexp|replacement" rules applied to response header values
	RespHeaderReplace string
	// v2.9.74: upstream_http_versions — comma-separated HTTP version list for upstream transport ('' = Caddy default)
	UpstreamHTTPVersions string // e.g. "1.1" | "2" | "1.1,2" — overrides ForceHTTP1/H2CEnabled when set
	// v2.9.75: health_check_body — request body sent with active health check probes (e.g. a JSON payload)
	HealthCheckBody string
	// v2.9.76: add_canonical_link_header — inject Link: <https://primarydomain/>; rel="canonical" response header
	AddCanonicalLinkHeader bool
	// v2.9.77: http_basic_auth_upstream — "user:pass" credentials injected as Authorization: Basic to upstream requests
	HTTPBasicAuthUpstream string // stored in plain text; base64-encoded at config-build time
	// v2.9.78: block_ua_regexp — Go regexp pattern; requests whose User-Agent matches receive a 403
	BlockUARegexp string
	// v2.9.79: security_txt_body — serve this text at GET/HEAD /.well-known/security.txt before proxying
	SecurityTxtBody string
	// v2.9.80: server_header_value — override the Server response header ('' = keep upstream value)
	ServerHeaderValue string
	// v2.9.81: x_robots_tag — X-Robots-Tag response header value ('' = omit header)
	XRobotsTag string
	// v2.9.82: add_forwarded_header — inject RFC 7239 Forwarded header on upstream requests
	AddForwardedHeader bool
	// v2.9.83: lb_cookie_secret — HMAC secret for signing sticky-session cookies (prevents client tampering)
	LBCookieSecret string
	// v2.9.84: passive_unhealthy_status_codes — comma-separated HTTP codes that mark upstream passive-unhealthy
	PassiveUnhealthyStatusCodes string
	// v2.9.85: health_check_content_type — Content-Type header value sent with active health check requests
	HealthCheckContentType string
	// v2.9.86: upstream_tls_client_cert_file — path to PEM client certificate for mutual TLS to upstream
	UpstreamTLSClientCertFile string
	// v2.9.87: upstream_tls_client_key_file — path to PEM private key matching UpstreamTLSClientCertFile
	UpstreamTLSClientKeyFile string
	// v2.9.88: block_private_ips — reject incoming connections from RFC 1918 / loopback IP ranges (403)
	BlockPrivateIPs bool
	// v2.9.89: enable_brotli — include brotli (br) in the encode handler when CompressionEnabled is true
	EnableBrotli bool
	// v2.9.90: vary_header — value for the Vary response header ('' = omit)
	VaryHeader string
	// v2.9.91: strip_etag — delete ETag response header from upstream responses
	StripETag bool
	// v2.9.92: http2_push_paths — newline-separated resource paths to push via HTTP/2 server push
	HTTP2PushPaths string
	// v2.9.93: deny_content_types — comma-separated Content-Type prefixes that receive 415
	DenyContentTypes string
	// v2.9.94: upstream_local_addr — local IP address to bind when dialing upstream connections
	UpstreamLocalAddr string
	// v2.9.95: upstream_tls_renegotiation — TLS renegotiation policy for upstream connections: '' (never) | 'once' | 'freely'
	UpstreamTLSRenegotiation string
	// v2.9.96: upstream_tls_curves — comma-separated TLS curve names for upstream connections ('' = Caddy default)
	UpstreamTLSCurves string
	// v2.9.97: upstream_tls_max_version — maximum TLS version for upstream connections: '' | '1.2' | '1.3'
	UpstreamTLSMaxVersion string
	// v2.9.98: upstream_tls_pins — newline-separated SHA-256 SPKI fingerprints for upstream certificate pinning
	UpstreamTLSPins string
	// v2.9.99: lb_header_field — request header name used by the 'header' LB selection policy for sticky routing
	LBHeaderField string
	// v2.9.100: maintenance_custom_headers — newline-separated "Name: Value" headers added to the 503 maintenance response
	MaintenanceCustomHeaders string
	// v2.9.101: deny_extensions — comma-separated file extensions to block (e.g. ".php,.asp,.aspx") — returns 403
	DenyExtensions string
	// v2.9.102: inject_request_timestamp — add X-Request-Timestamp header with UNIX epoch to upstream requests
	InjectRequestTimestamp bool
	// v2.9.103: add_resp_cookies — newline-separated Set-Cookie header values added to every response
	AddRespCookies string
	// v2.9.104: strip_accept_encoding — delete Accept-Encoding request header before forwarding to upstream
	StripAcceptEncoding bool
	// v2.9.105: add_upstream_timing_header — inject X-Upstream-Time response header with upstream latency
	AddUpstreamTimingHeader bool
	// v2.9.106: strip_server_header — delete Server response header from upstream replies
	StripServerHeader bool
	// v2.9.107: block_referer_regexp — Go regexp; requests whose Referer header matches receive 403 (hotlink protection)
	BlockRefererRegexp string
	// v2.9.108: add_content_type_nosniff — add X-Content-Type-Options: nosniff response header
	AddContentTypeNosniff bool
	// v2.9.109: strip_authorization_header — delete Authorization request header before forwarding to upstream
	StripAuthorizationHeader bool
	// v2.9.110: real_ip_from_header — copy real client IP from this request header name into X-Real-IP (e.g. "CF-Connecting-IP")
	RealIPFromHeader string
	// v2.9.111: health_check_host_override — override Host header sent during active health check probes
	HealthCheckHostOverride string
	// v2.9.112: add_x_forwarded_port — add X-Forwarded-Port request header with the incoming request port
	AddXForwardedPort bool
	// v2.9.113: lb_retry_on — comma-separated retry trigger conditions ("error","5xx","4xx","connect_error","timeout","reset")
	LBRetryOn string
	// v2.9.114: max_buffer_size_kb — maximum bytes to buffer when buffer_responses is enabled (0 = unlimited)
	MaxBufferSizeKB int
	// v2.9.115: upstream_keepalive_probes — TCP keepalive probe count for upstream connections
	UpstreamKeepaliveProbes int
	// v2.9.116: upstream_flush_interval_ms — flush_interval override in ms (0=default, -1=immediate, >0=interval)
	UpstreamFlushIntervalMS int
	// v2.9.117: add_x_forwarded_host — inject X-Forwarded-Host request header with original Host value
	AddXForwardedHost bool
	// v2.9.118: maintenance_allowed_ips — comma-separated CIDRs that bypass maintenance mode
	MaintenanceAllowedIPs string
	// v2.9.119: upstream_tls_cipher_suites — comma-separated TLS cipher suite names for upstream connections
	UpstreamTLSCipherSuites string
	// v2.9.120: add_cache_control_no_store — add Cache-Control: no-store response header
	AddCacheControlNoStore bool
	// v2.9.121: deny_referer_empty — block requests that have no Referer header (anti-hotlinking)
	DenyRefererEmpty bool
	// v2.9.122: lb_cookie_httponly — set HttpOnly flag on the sticky-session cookie
	LBCookieHTTPOnly bool
	// v2.9.123: lb_cookie_secure — set Secure flag on the sticky-session cookie
	LBCookieSecure bool
	// v2.9.124: lb_cookie_same_site — SameSite attribute on the sticky-session cookie ("Strict","Lax","None")
	LBCookieSameSite string
	// v2.9.125: upstream_tls_early_data — enable TLS 1.3 early data (0-RTT) for upstream connections
	UpstreamTLSEarlyData bool
	// v2.9.126: add_via_header — add Via response header identifying this proxy
	AddViaHeader bool
	// v2.9.127: req_header_rename — newline-separated "OldName: NewName" pairs to rename request headers
	ReqHeaderRename string
	// v2.9.128: add_expect_ct_header — add Expect-CT: enforce response header for certificate transparency
	AddExpectCTHeader bool
	// v2.9.129: force_upstream_encoding — override Accept-Encoding sent to upstream (e.g. "gzip","identity","br")
	ForceUpstreamEncoding string
	// v2.9.130: passive_unhealthy_count — max concurrent in-flight requests before flagging upstream overloaded
	PassiveUnhealthyCount int
	// v2.9.131: strip_x_powered_by — delete X-Powered-By response header from upstream replies
	StripXPoweredBy bool
	// v2.9.132: add_timing_allow_origin — value for Timing-Allow-Origin response header (e.g. "*")
	AddTimingAllowOrigin string
	// v2.9.133: lb_cookie_max_age_sec — max-age in seconds for the sticky-session cookie (0 = session)
	LBCookieMaxAgeSec int
	// v2.9.134: cross_origin_opener_policy — Cross-Origin-Opener-Policy response header value
	CrossOriginOpenerPolicy string
	// v2.9.135: cross_origin_resource_policy — Cross-Origin-Resource-Policy response header value
	CrossOriginResourcePolicy string
	// v2.9.136: cross_origin_embedder_policy — Cross-Origin-Embedder-Policy response header value
	CrossOriginEmbedderPolicy string
	// v2.9.137: deny_request_content_type — comma-separated MIME types to block on request Content-Type (returns 415)
	DenyRequestContentType string
	// v2.9.138: compression_exclude_regexp — regexp of paths to exclude from response compression
	CompressionExcludeRegexp string
	// v2.9.139: add_cache_control_public — add Cache-Control: public response header
	AddCacheControlPublic bool
	// v2.9.140: add_x_request_start — inject X-Request-Start header with Unix ms timestamp for APM tools
	AddXRequestStart bool
	// v2.9.141: maintenance_window_timezone — IANA timezone name for the scheduled maintenance window (empty = server local)
	MaintenanceWindowTimezone string
	// v2.9.142: lb_random_choose_count — "choose" count for random_choice lb policy (0 = disabled)
	LBRandomChooseCount int
	// v2.9.143: add_x_forwarded_scheme — inject X-Forwarded-Scheme: {scheme} request header
	AddXForwardedScheme bool
	// v2.9.144: response_cache_ttl_sec — set Cache-Control: max-age=N on responses (0 = disabled)
	ResponseCacheTTLSec int
	// v2.9.145: add_link_preload — Link response header value for HTTP/2 preload hints
	AddLinkPreload string
	// v2.9.146: deny_path_regexp — block requests whose path matches this regex (403)
	DenyPathRegexp string
	// v2.9.147: add_request_id_to_response — echo request trace ID in response header for debugging
	AddRequestIDToResponse bool
	// v2.9.148: health_check_tls_server_name — TLS SNI override for active health check connections
	HealthCheckTLSServerName string
	// v2.9.149: add_x_real_ip — inject X-Real-IP request header with the direct client IP
	AddXRealIP bool
	// v2.9.150: strip_incoming_x_forwarded_for — delete X-Forwarded-For from incoming requests (prevent IP spoofing)
	StripIncomingXForwardedFor bool
	// v2.9.151: health_check_tls_insecure_skip_verify — skip TLS cert verification for health check probes
	HealthCheckTLSInsecureSkipVerify bool
	// v2.9.152: add_cors_vary_header — add Vary: Origin response header for CDN caching of CORS responses
	AddCORSVaryHeader bool
	// v2.9.153: upstream_tls_alpn — comma-separated ALPN protocol list for upstream TLS connections
	UpstreamTLSALPN string
	// v2.9.154: add_x_powered_by — custom X-Powered-By response header value (empty = disabled)
	AddXPoweredBy string
	// v2.9.155: block_query_params — comma-separated query param names to block (403 if any present)
	BlockQueryParams string
	// v2.9.156: add_document_policy — Document-Policy response header value
	AddDocumentPolicy string
	// v2.9.157: maintenance_redirect_url — redirect to this URL during maintenance (overrides inline 503)
	MaintenanceRedirectURL string
	// v2.9.158: upstream_keepalive_max_lifetime_sec — max lifetime for keepalive connections before recycling (0 = no limit)
	UpstreamKeepaliveMaxLifetimeSec int
	// v2.9.159: add_origin_header — inject Origin: <value> request header for upstream APIs that require it
	AddOriginHeader string
	// v2.9.160: upstream_tls_ca_pem_inline — inline PEM CA certificate for upstream TLS verification
	UpstreamTLSCAPEMInline string
	// v2.9.161: add_server_timing_header — inject Server-Timing response header with upstream duration
	AddServerTimingHeader bool
	// v2.9.162: add_clear_site_data — Clear-Site-Data response header value (e.g. "cache","cookies")
	AddClearSiteData string
	// v2.9.163: add_x_dns_prefetch_control — set X-DNS-Prefetch-Control: off response header
	AddXDNSPrefetchControl bool
	// v2.9.164: add_accept_ranges — set Accept-Ranges: bytes response header
	AddAcceptRanges bool
	// v2.9.165: add_content_disposition — Content-Disposition response header value
	AddContentDisposition string
	// v2.9.166: upstream_tls_server_name_from_host — use request Host as upstream TLS SNI (dynamic)
	UpstreamTLSServerNameFromHost bool
	// v2.9.167: add_x_permitted_cross_domain_policies — X-Permitted-Cross-Domain-Policies response header value
	AddXPermittedCrossDomainPolicies string
	// v2.9.168: strip_response_headers — comma-separated list of response header names to delete
	StripResponseHeaders string
	// v2.9.169: add_report_to — Report-To response header value (JSON endpoint group for CSP/NEL reporting)
	AddReportTo string
	// v2.9.170: add_nel_header — NEL response header JSON config (Network Error Logging)
	AddNELHeader string
	// v2.9.171: block_http_methods — comma-separated HTTP methods to reject with 405
	BlockHTTPMethods string
	// v2.9.172: add_service_worker_allowed — Service-Worker-Allowed response header value
	AddServiceWorkerAllowed string
	// v2.9.173: add_accept_ch — Accept-CH response header value (declare accepted client hints)
	AddAcceptCH string
	// v2.9.174: add_alt_svc — Alt-Svc response header value (advertise HTTP/2 or HTTP/3 service endpoint)
	AddAltSvc string
	// v2.9.175: add_content_language — Content-Language response header value
	AddContentLanguage string
	// v2.9.176: add_critical_ch — Critical-CH response header (client hints required before rendering)
	AddCriticalCH string
	// v2.9.177: add_x_download_options — set X-Download-Options: noopen (IE file open prevention)
	AddXDownloadOptions bool
	// v2.9.178: deny_user_agent_regexp — block requests whose User-Agent matches this regexp with 403
	DenyUserAgentRegexp string
	// v2.9.179: add_pragma_no_cache — set Pragma: no-cache response header (HTTP/1.0 cache directive)
	AddPragmaNoCache bool
	// v2.9.180: health_check_user_agent — custom User-Agent for active health check probes
	HealthCheckUserAgent string
	// v2.9.181: add_x_request_path — inject X-Request-Path header (request URI path) on upstream requests
	AddXRequestPath bool
	// v2.9.182: add_x_clacks_overhead — X-Clacks-Overhead response header value
	AddXClacksOverhead string
	// v2.9.183: add_x_ua_compatible — X-UA-Compatible response header value (e.g. 'IE=edge')
	AddXUACompatible string
	// v2.9.184: forward_auth_skip_paths — comma-separated path prefixes that bypass forward_auth
	ForwardAuthSkipPaths string
	// v2.9.185: add_age_zero — set Age: 0 response header (signal fresh response to CDNs)
	AddAgeZero bool
	// v2.9.186: add_surrogate_control — Surrogate-Control response header value (CDN-only cache directive)
	AddSurrogateControl string
	// v2.9.187: add_warning_header — Warning response header value (RFC 7234 warning codes)
	AddWarningHeader string
	// v2.9.188: add_x_request_method — forward X-Request-Method header (echoes HTTP method) to upstream
	AddXRequestMethod bool
	// v2.9.189: add_x_request_query — forward X-Request-Query header (echoes query string) to upstream
	AddXRequestQuery bool
	// v2.9.190: add_x_forwarded_user — static X-Forwarded-User request header value
	AddXForwardedUser string
	// v2.9.191: add_x_real_scheme — forward X-Real-Scheme request header (http or https) to upstream
	AddXRealScheme bool
	// v2.9.192: add_origin_agent_cluster — set Origin-Agent-Cluster: ?1 response header (origin-keyed isolation hint)
	AddOriginAgentCluster bool
	// v2.9.193: add_x_forwarded_groups — static X-Forwarded-Groups request header value
	AddXForwardedGroups string
	// v2.9.194: add_x_forwarded_email — static X-Forwarded-Email request header value
	AddXForwardedEmail string
	// v2.9.195: add_x_forwarded_roles — static X-Forwarded-Roles request header value
	AddXForwardedRoles string
	// v2.9.196: block_query_param_regexp — block requests whose raw query string matches this regexp with 403
	BlockQueryParamRegexp string
	// v2.9.197: add_x_request_referer — forward X-Request-Referer header (echoes original Referer) to upstream
	AddXRequestReferer bool
	// v2.9.198: add_x_request_origin — forward X-Request-Origin header (echoes original Origin) to upstream
	AddXRequestOrigin bool
	// v2.9.199: add_x_forwarded_uri — forward X-Forwarded-URI header (echoes original URI) to upstream
	AddXForwardedURI bool
	// v2.9.200: add_x_no_archive — set X-No-Archive: yes response header to block archive caching
	AddXNoArchive bool
	// v2.9.201: add_x_request_hostname — forward X-Request-Hostname header (echoes hostname) to upstream
	AddXRequestHostname bool
	// v2.9.202: add_x_xss_protection_disabled — set X-XSS-Protection: 0 response header
	AddXXSSProtectionDisabled bool
	// v2.9.212: add_x_request_remote_port — forward X-Request-Remote-Port header to upstream
	AddXRequestRemotePort bool
	// v2.9.213: add_x_request_protocol — forward X-Request-Protocol header (HTTP version) to upstream
	AddXRequestProtocol bool
	// v2.9.214: add_save_data_vary — set Vary: Save-Data response header (client hint aware caching)
	AddSaveDataVary bool
	// v2.9.217: add_x_environment — static X-Environment request header value
	AddXEnvironment string
	// v2.9.218: add_x_trace_id — forward X-Trace-ID header (Caddy UUID per request) to upstream
	AddXTraceID bool
	// v2.9.219: health_check_query_params — query string appended to active health check probe URL
	HealthCheckQueryParams string
	// v2.9.220: add_x_session_id — forward X-Session-ID header (Caddy UUID per request) to upstream
	AddXSessionID bool
	// v2.9.221: add_x_response_trace_id — set X-Response-Trace-ID response header (echoes the trace UUID)
	AddXResponseTraceID bool
	// v2.9.222: add_x_request_local_addr — forward X-Local-Addr header (Caddy's listening IP) to upstream
	AddXRequestLocalAddr bool
	// v2.9.223: add_x_request_local_port — forward X-Local-Port header (Caddy's listening port) to upstream
	AddXRequestLocalPort bool
	// v2.9.224: add_x_request_path_info — forward X-PathInfo header (CGI-style PATH_INFO) to upstream
	AddXRequestPathInfo bool
	// v2.9.234: add_x_authenticated_user — static X-Authenticated-User request header
	AddXAuthenticatedUser string
	// v2.9.235: block_path_extensions — comma-separated file extensions (.php,.git,.cgi) blocked with 403
	BlockPathExtensions string
	// v2.9.236: add_link_modulepreload — Link: <…>; rel=modulepreload response header value
	AddLinkModulePreload string
	// v2.9.237: add_x_remote_user — static X-Remote-User request header (Nginx-style)
	AddXRemoteUser string
	// v2.9.238: add_x_forwarded_path — forward X-Forwarded-Path request header
	AddXForwardedPath bool
	// v2.9.239: add_x_geo_country_code — static X-Geo-Country header (CDN convention)
	AddXGeoCountryCode string
	// v2.9.240: add_x_request_priority — X-Request-Priority response header (RFC 9218)
	AddXRequestPriority string
	// v2.9.241: health_check_basic_auth — "user:pass" basic auth for health check probes
	HealthCheckBasicAuth string
	// v2.9.242: add_x_real_ssl_protocol — forward X-Real-SSL-Protocol header (TLS version)
	AddXRealSSLProtocol bool
	// v2.9.243: add_x_real_ssl_cipher — forward X-Real-SSL-Cipher header (negotiated cipher)
	AddXRealSSLCipher bool
	// v2.9.244: add_x_cache_status — static X-Cache-Status response header value
	AddXCacheStatus string
	// v2.9.245: deny_referer_regexp — block requests by Referer regexp with 403
	DenyRefererRegexp string
	// v2.9.246: add_x_request_user_agent — forward X-Request-User-Agent (echoes UA) header
	AddXRequestUserAgent bool
	// v2.9.247: add_reporting_endpoints — Reporting-Endpoints response header (RFC 8942)
	AddReportingEndpoints string
	// v2.9.248: add_x_request_byte_count — forward X-Request-Byte-Count (Content-Length) header
	AddXRequestByteCount bool
	// v2.9.249: add_x_request_received_at — forward X-Request-Received-At (timestamp) header
	AddXRequestReceivedAt bool
	// v2.9.250: strip_request_headers — comma-separated list of request header names to delete
	StripRequestHeaders string
	// v2.9.251: add_x_forwarded_method — forward X-Forwarded-Method (HTTP method) header
	AddXForwardedMethod bool
	// v2.9.252: add_x_request_original_host — preserve original Host before rewrites
	AddXRequestOriginalHost bool
	// v2.9.253: add_x_request_dnt — forward DNT (Do Not Track) header
	AddXRequestDNT bool
	// v2.9.254: add_x_geo_region — static X-Geo-Region request header
	AddXGeoRegion string
	// v2.9.255: add_x_request_secure — X-Request-Secure: on/off based on TLS state
	AddXRequestSecure bool
	// v2.9.256: add_x_request_query_count — debug header counting query params
	AddXRequestQueryCount bool
	// v2.9.257: add_x_request_id_header_response — echo trace UUID to response header
	AddXRequestIDHeaderResponse bool
	// v2.9.258: force_canonical_host — canonical host; alt hostnames get 301 redirected
	ForceCanonicalHost string
	// v2.9.259: add_x_robots_noindex_quick — quick X-Robots-Tag: noindex, nofollow toggle
	AddXRobotsNoindexQuick bool
	// v2.9.260: block_bot_user_agents — built-in bot blocklist (regexp matches common scrapers)
	BlockBotUserAgents bool
	// v2.9.261: block_admin_paths — 404 common admin paths
	BlockAdminPaths bool
	// v2.9.262: add_link_dns_prefetch — Link: <…>; rel=dns-prefetch response header
	AddLinkDNSPrefetch string
	// v2.9.263: add_link_preconnect — Link: <…>; rel=preconnect response header
	AddLinkPreconnect string
	// v2.9.264: add_x_csp_disabled — set Content-Security-Policy: '' to disable CSP explicitly
	AddXCSPDisabled bool
	// v2.9.265: add_x_request_method_override — honor X-HTTP-Method-Override (rewrites method)
	AddXRequestMethodOverride bool
	// v2.9.266: proxy_redirect_rules — JSON array of path-based redirects
	// that fire BEFORE the reverse_proxy. Same schema as RedirectionHost's
	// RedirectRules. Common use: redirect /  → /webmail (302) while still
	// proxying every other path normally.
	ProxyRedirectRules string
	// v2.9.267: additional_upstream_rules — JSON array of path-based upstream
	// overrides. When set, each rule gets its own subroute with a reverse_proxy
	// to the override upstream BEFORE the host's main reverse_proxy. Use for
	// multi-upstream patterns like Nextcloud + notify_push on /push/* +
	// AppAPI on /exapps/* on a single hostname.
	AdditionalUpstreamRules string
	// v2.12.52: disable upstream compression — emit `transport http { compression off }`
	// in the reverse_proxy block. Useful when the upstream double-compresses
	// already-compressed responses.
	DisableUpstreamCompression bool
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

// InScheduledMaintenanceWindow returns true when the current wall-clock time
// falls inside this host's scheduled maintenance window, respecting the optional
// day-of-week restriction (MaintenanceWindowDays). Returns false when the window
// is not configured or the time strings are malformed.
func (p *ProxyHost) InScheduledMaintenanceWindow() bool {
	if p.MaintenanceWindowStart == "" || p.MaintenanceWindowEnd == "" {
		return false
	}
	now := time.Now()
	// v2.9.141: maintenance_window_timezone — evaluate the window in the configured IANA timezone.
	if p.MaintenanceWindowTimezone != "" {
		if loc, err := time.LoadLocation(p.MaintenanceWindowTimezone); err == nil {
			now = now.In(loc)
		}
	}
	if p.MaintenanceWindowDays != "" {
		abbr := strings.ToLower(now.Weekday().String()[:3])
		matched := false
		for _, d := range strings.Split(strings.ToLower(p.MaintenanceWindowDays), ",") {
			if strings.TrimSpace(d) == abbr {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	parseHHMM := func(s string) (int, bool) {
		parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
		if len(parts) != 2 {
			return 0, false
		}
		h, e1 := strconv.Atoi(parts[0])
		m, e2 := strconv.Atoi(parts[1])
		if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
			return 0, false
		}
		return h*60 + m, true
	}
	startMins, ok1 := parseHHMM(p.MaintenanceWindowStart)
	endMins, ok2 := parseHHMM(p.MaintenanceWindowEnd)
	if !ok1 || !ok2 {
		return false
	}
	nowMins := now.Hour()*60 + now.Minute()
	if startMins < endMins {
		return nowMins >= startMins && nowMins < endMins
	}
	// Overnight window (e.g. 23:00–01:00): active after start OR before end.
	return nowMins >= startMins || nowMins < endMins
}

// BasicAuthUserList parses the JSON-encoded BasicAuthUsers string into a slice.
// Returns nil if empty or unparseable.
func (p *ProxyHost) BasicAuthUserList() []BasicAuthUser {
	if p.BasicAuthUsers == "" || p.BasicAuthUsers == "[]" {
		return nil
	}
	var users []BasicAuthUser
	_ = json.Unmarshal([]byte(p.BasicAuthUsers), &users)
	return users
}

// ExtraUpstreamList parses the JSON-encoded ExtraUpstreams string into a slice.
// Returns nil if empty or unparseable.
func (p *ProxyHost) ExtraUpstreamList() []string {
	if p.ExtraUpstreams == "" || p.ExtraUpstreams == "[]" {
		return nil
	}
	var list []string
	_ = json.Unmarshal([]byte(p.ExtraUpstreams), &list)
	return list
}

// CustomReqHeaderMap parses CustomReqHeaders into a map. Returns nil if empty.
func (p *ProxyHost) CustomReqHeaderMap() map[string]string {
	if p.CustomReqHeaders == "" || p.CustomReqHeaders == "{}" {
		return nil
	}
	var m map[string]string
	_ = json.Unmarshal([]byte(p.CustomReqHeaders), &m)
	return m
}

// CustomRespHeaderMap parses CustomRespHeaders into a map. Returns nil if empty.
func (p *ProxyHost) CustomRespHeaderMap() map[string]string {
	if p.CustomRespHeaders == "" || p.CustomRespHeaders == "{}" {
		return nil
	}
	var m map[string]string
	_ = json.Unmarshal([]byte(p.CustomRespHeaders), &m)
	return m
}

// URLRewriteRule is one rewrite entry on a proxy host.
// Type is "strip_prefix", "add_prefix", or "regex".
// For strip_prefix/add_prefix: From is the prefix string, To is ignored/target prefix.
// For regex: From is the pattern, To is the replacement.
type URLRewriteRule struct {
	Type string `json:"type"` // "strip_prefix" | "add_prefix" | "regex"
	From string `json:"from"`
	To   string `json:"to"`
}

// URLRewriteList parses the JSON-encoded URLRewrites string.
// Returns nil if empty or unparseable.
func (p *ProxyHost) URLRewriteList() []URLRewriteRule {
	if p.URLRewrites == "" || p.URLRewrites == "[]" {
		return nil
	}
	var rules []URLRewriteRule
	_ = json.Unmarshal([]byte(p.URLRewrites), &rules)
	return rules
}

func (p ProxyHost) DomainList() []string {
	parts := strings.Split(p.Domains, ",")
	out := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// TagList returns Tags split into individual trimmed strings, filtering empties.
func (p *ProxyHost) TagList() []string {
	if p.Tags == "" {
		return nil
	}
	parts := strings.Split(p.Tags, ",")
	out := make([]string, 0, len(parts))
	for _, t := range parts {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// StripRespHeaderList parses the comma-separated strip_resp_headers field.
func (p *ProxyHost) StripRespHeaderList() []string {
	if p.StripRespHeaders == "" {
		return nil
	}
	var out []string
	for _, h := range strings.Split(p.StripRespHeaders, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, http.CanonicalHeaderKey(h))
		}
	}
	return out
}

// StripReqHeaderList parses the comma-separated strip_req_headers field.
func (p *ProxyHost) StripReqHeaderList() []string {
	if p.StripReqHeaders == "" {
		return nil
	}
	var out []string
	for _, h := range strings.Split(p.StripReqHeaders, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, http.CanonicalHeaderKey(h))
		}
	}
	return out
}

type RedirectionHost struct {
	ID              int64
	Domains         string
	ForwardScheme   string
	ForwardDomain   string
	ForwardHTTPCode int
	PreservePath    bool
	SSLEnabled      bool
	SSLForced       bool
	Enabled         bool
	CertificateID   int64
	OwnerID         sql.NullInt64
	OwnerEmail      string // populated via JOIN for display
	Tags            string // comma-separated labels (UI-only, same as proxy hosts)
	Notes           string // freeform admin notes (UI-only)
	// v2.12.2: unified Managed DNS — same triple as proxy_hosts and
	// raw_routes. CaddyUI auto-creates an A record per hostname in
	// Domains when DNSProvider is set, deletes them on row removal.
	DNSProvider  string
	DNSZoneID    string
	DNSZoneName  string
	DNSRecordID  string
	DNSProfileID string
	// v2.9.13: access control + maintenance mode (parity with proxy hosts)
	AccessList      string // comma/newline-separated CIDR allowlist (empty = allow all)
	MaintenanceMode bool   // when true, respond 503 before redirecting
	MaintenanceMsg  string // custom maintenance message body
	// v2.9.20: custom response headers injected into every redirect response
	CustomRespHeaders string // JSON: map[string]string — empty value means delete header
	// v2.9.21: IP blocklist — deny specific CIDRs before the redirect fires
	IPBlocklist string // comma-separated CIDR ranges to block with 403
	// v2.9.24: HSTS — inject Strict-Transport-Security on redirect responses
	HSTSMaxAgeSec         int  // 0 = disabled; >0 = seconds for max-age
	HSTSIncludeSubdomains bool // include includeSubDomains directive
	HSTSPreload           bool // include preload directive
	// v2.9.26: advanced config — raw JSON array of Caddy handlers injected before the redirect
	AdvancedConfig string // JSON: []any of handler maps
	// v2.9.33: color label for visual grouping in list views (no Caddy impact)
	Color string // "" | "red" | "orange" | "yellow" | "green" | "teal" | "blue" | "purple" | "pink" | "gray"
	// v2.9.38: maintenance status code — HTTP code used during maintenance mode (default 503)
	MaintenanceStatusCode int // 503 (default), 429, 502, 520
	// v2.9.39: sort order — manual ordering weight in the list view (0 = default, lower = first)
	SortOrder int
	// v2.9.229: redirect_rules — JSON array of path-based redirect rules.
	// When non-empty, takes precedence over ForwardDomain/PreservePath/etc.
	// for matched paths. Each rule entry shape:
	//   {"path":"/old-blog/*", "code":301, "destination":"https://newblog.com{uri}"}
	// Caddy's `{uri}` placeholder in the destination preserves the original
	// path + query; "{path}" preserves only the path. Rules are evaluated
	// in order; the host-wide redirect is the catch-all fallback for
	// requests that don't match any rule.
	RedirectRules string
	// v2.9.230: redirect_strip_path_prefix — drop a leading prefix from
	// the path before composing the Location header on the host-wide
	// redirect. e.g. prefix /old-blog and PreservePath on:
	//   /old-blog/post/123 → ForwardDomain/post/123 instead of /old-blog/post/123
	RedirectStripPathPrefix string
	// v2.9.231: redirect_wildcard_subdomain — substitute the subdomain
	// label into the destination ({labels.0} for first label).
	// Enables `*.old.com → *.new.com` style migrations.
	RedirectWildcardSubdomain bool
	// v2.9.232: sunset_at — ISO-8601 date (YYYY-MM-DD) after which this
	// redirect returns 410 Gone instead of redirecting. Empty = no sunset.
	SunsetAt  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ProxyRedirectRuleList parses the JSON-encoded ProxyRedirectRules column
// into typed rules. Returns nil for empty / malformed values so callers
// can range over it safely. v2.9.266.
func (p *ProxyHost) ProxyRedirectRuleList() []RedirectRule {
	if p.ProxyRedirectRules == "" {
		return nil
	}
	var out []RedirectRule
	if err := json.Unmarshal([]byte(p.ProxyRedirectRules), &out); err != nil {
		return nil
	}
	return out
}

// UpstreamRule is one entry in the JSON stored on
// ProxyHost.AdditionalUpstreamRules. v2.9.267.
//
// Path / Scheme / Host / Port describe an alternative reverse_proxy
// target. StripPrefix mirrors Caddyfile's `handle_path` (strip the
// matched prefix before forwarding) vs `handle` (keep the full path).
// AddXRealIP toggles X-Real-IP injection on the override branch
// independently of the host-wide AddXRealIP — useful when a specific
// upstream needs the real IP and the rest doesn't (or vice versa).
type UpstreamRule struct {
	Path        string `json:"path"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	StripPrefix bool   `json:"strip_prefix"`
	AddXRealIP  bool   `json:"add_x_real_ip"`
}

// UpstreamRuleList parses the JSON-encoded AdditionalUpstreamRules column.
// Returns nil for empty / malformed values. v2.9.267.
func (p *ProxyHost) UpstreamRuleList() []UpstreamRule {
	if p.AdditionalUpstreamRules == "" {
		return nil
	}
	var out []UpstreamRule
	if err := json.Unmarshal([]byte(p.AdditionalUpstreamRules), &out); err != nil {
		return nil
	}
	return out
}

// RedirectRule is one entry in the JSON stored on RedirectionHost.RedirectRules.
type RedirectRule struct {
	Path        string `json:"path"`
	Code        int    `json:"code"`
	Destination string `json:"destination"`
}

// RedirectRuleList parses the JSON-encoded RedirectRules column into typed
// rules. Returns nil for empty / malformed values so callers can range over
// it safely.
func (r *RedirectionHost) RedirectRuleList() []RedirectRule {
	if r.RedirectRules == "" {
		return nil
	}
	var out []RedirectRule
	if err := json.Unmarshal([]byte(r.RedirectRules), &out); err != nil {
		return nil
	}
	return out
}

func (r RedirectionHost) DomainList() []string {
	parts := strings.Split(r.Domains, ",")
	out := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// TagList returns Tags split into individual trimmed strings, filtering empties.
// Mirrors ProxyHost.TagList so redirection_hosts.html can iterate tag pills.
func (r RedirectionHost) TagList() []string {
	if r.Tags == "" {
		return nil
	}
	parts := strings.Split(r.Tags, ",")
	out := make([]string, 0, len(parts))
	for _, t := range parts {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// CustomRespHeaderMap parses CustomRespHeaders into a map. Returns nil if empty.
func (r RedirectionHost) CustomRespHeaderMap() map[string]string {
	if r.CustomRespHeaders == "" || r.CustomRespHeaders == "{}" {
		return nil
	}
	var m map[string]string
	_ = json.Unmarshal([]byte(r.CustomRespHeaders), &m)
	return m
}

const userCols = `id, email, password_hash, COALESCE(name,''), is_admin,
    COALESCE(role, CASE WHEN is_admin=1 THEN 'admin' ELSE 'view' END), created_at,
    COALESCE(totp_secret,''), COALESCE(totp_enabled,0), COALESCE(totp_backup_codes,''),
    COALESCE(color_theme,'')`

func scanUser(s interface {
	Scan(dest ...any) error
}) (*User, error) {
	u := &User{}
	var isAdmin, totpEnabled int
	if err := s.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &isAdmin, &u.Role, &u.CreatedAt, &u.TOTPSecret, &totpEnabled, &u.BackupCodes, &u.ColorTheme); err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin == 1
	u.TOTPEnabled = totpEnabled == 1
	if u.Role == "" {
		if u.IsAdmin {
			u.Role = RoleAdmin
		} else {
			u.Role = RoleView
		}
	}
	return u, nil
}

// UpdateUserColorTheme stores the user's preferred color theme so it
// follows them across devices. Accepts "" (default), "orange", or any
// future palette names — caller should validate before calling. v2.12.27.
func UpdateUserColorTheme(db *sql.DB, userID int64, theme string) error {
	_, err := db.Exec(`UPDATE users SET color_theme = ? WHERE id = ?`, theme, userID)
	return err
}

// GenerateBackupCodes creates n single-use backup codes as uppercase alphanumeric strings.
func GenerateBackupCodes(n int) ([]string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	codes := make([]string, n)
	for i := range codes {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		for j := range b {
			b[j] = chars[int(b[j])%len(chars)]
		}
		codes[i] = string(b)
	}
	return codes, nil
}

// HashBackupCode returns the hex-encoded SHA-256 of an uppercase code.
func HashBackupCode(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return fmt.Sprintf("%x", sum)
}

// SaveBackupCodes stores hashed backup codes for the user.
func SaveBackupCodes(db *sql.DB, userID int64, codes []string) error {
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = HashBackupCode(c)
	}
	data, _ := json.Marshal(hashes)
	_, err := db.Exec(`UPDATE users SET totp_backup_codes = ? WHERE id = ?`, string(data), userID)
	return err
}

// ConsumeBackupCode checks whether the given code matches a stored hash.
// If it matches, the code is removed (single-use) and the DB is updated.
// Returns true if the code was valid and has been consumed.
func ConsumeBackupCode(db *sql.DB, userID int64, codesJSON, rawCode string) (bool, error) {
	var hashes []string
	if codesJSON == "" || json.Unmarshal([]byte(codesJSON), &hashes) != nil {
		return false, nil
	}
	target := HashBackupCode(rawCode)
	for i, h := range hashes {
		if h == target {
			remaining := append(hashes[:i:i], hashes[i+1:]...)
			data, _ := json.Marshal(remaining)
			_, err := db.Exec(`UPDATE users SET totp_backup_codes = ? WHERE id = ?`, string(data), userID)
			return err == nil, err
		}
	}
	return false, nil
}

func SetUserTOTP(db *sql.DB, userID int64, secret string, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := db.Exec(`UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?`, secret, e, userID)
	return err
}

func GetUser(db *sql.DB, userID int64) (*User, error) {
	return GetUserByID(db, userID)
}

func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	return scanUser(db.QueryRow(`SELECT `+userCols+` FROM users WHERE email = ?`, strings.ToLower(email)))
}

func GetUserByID(db *sql.DB, id int64) (*User, error) {
	return scanUser(db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func ListUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// v2.7.4: Group + user_groups data access layer.
//
// A Group bundles `user`-role accounts into a team. Every user in a group
// sees every other member's proxy hosts / redirects / raw routes / certs in
// their list views (read-only — edit/delete stays owner-scoped at the handler
// level). Admin creates, names, and populates groups; users themselves have
// no say in membership.
//
// `MemberCount` is populated via COUNT subquery on list queries so the /groups
// index page doesn't need N+1 fetches to show "3 members".

type Group struct {
	ID          int64
	Name        string
	Description string
	MemberCount int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func ListGroups(db *sql.DB) ([]Group, error) {
	rows, err := db.Query(`
        SELECT g.id, g.name, COALESCE(g.description,''), g.created_at, g.updated_at,
               COALESCE((SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = g.id), 0)
        FROM groups g ORDER BY g.name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func GetGroup(db *sql.DB, id int64) (*Group, error) {
	var g Group
	err := db.QueryRow(`
        SELECT g.id, g.name, COALESCE(g.description,''), g.created_at, g.updated_at,
               COALESCE((SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = g.id), 0)
        FROM groups g WHERE g.id = ?`, id).
		Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func CreateGroup(db *sql.DB, name, description string) (int64, error) {
	res, err := db.Exec(`INSERT INTO groups (name, description) VALUES (?, ?)`,
		strings.TrimSpace(name), strings.TrimSpace(description))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateGroup(db *sql.DB, id int64, name, description string) error {
	_, err := db.Exec(`UPDATE groups SET name=?, description=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		strings.TrimSpace(name), strings.TrimSpace(description), id)
	return err
}

func DeleteGroup(db *sql.DB, id int64) error {
	// ON DELETE CASCADE on user_groups.group_id drops memberships automatically.
	// Resources owned by members are unaffected — ownership lives on the
	// resource row itself, not on the group.
	_, err := db.Exec(`DELETE FROM groups WHERE id=?`, id)
	return err
}

// ListGroupMembers returns the User rows currently in the group, ordered by
// email for a stable display order in the admin UI.
func ListGroupMembers(db *sql.DB, groupID int64) ([]User, error) {
	rows, err := db.Query(`
        SELECT `+userCols+`
        FROM users u
        INNER JOIN user_groups ug ON ug.user_id = u.id
        WHERE ug.group_id = ? ORDER BY u.email ASC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// SetGroupMembers atomically replaces the full member set of a group with
// the given user IDs. Idempotent: re-submitting the same list is a no-op
// from the caller's perspective (DELETE + bulk INSERT inside one transaction).
// Admin uses this on the group-edit form: a checkbox array of user IDs gets
// marshalled straight into userIDs and this wipes-and-rebuilds membership.
func SetGroupMembers(db *sql.DB, groupID int64, userIDs []int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM user_groups WHERE group_id = ?`, groupID); err != nil {
		return err
	}
	if len(userIDs) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, uid := range userIDs {
			if _, err := stmt.Exec(uid, groupID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// GroupPeerIDs returns every OTHER user ID that shares at least one group
// with the viewer. Callers use this to expand a user's visibility scope in
// list queries: the viewer sees rows owned by self + globals + any ID in
// this set. Does NOT include the viewer themselves (they're already covered
// by the owner_id = viewerID clause) and de-dupes users who are in multiple
// shared groups. Admin and view-role accounts aren't filtered out here;
// callers that want user-role-only can layer that filter, but in practice
// the resources we care about (proxy/redirect/raw/cert) are only ever owned
// by user-role accounts anyway.
func GroupPeerIDs(db *sql.DB, viewerID int64) ([]int64, error) {
	rows, err := db.Query(`
        SELECT DISTINCT ug2.user_id
        FROM user_groups ug1
        INNER JOIN user_groups ug2 ON ug2.group_id = ug1.group_id
        WHERE ug1.user_id = ? AND ug2.user_id != ?`, viewerID, viewerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// inClause builds a placeholder string of the form "?,?,?,..." for a SQL
// `IN (...)` clause along with the matching []any slice for db.Query args.
// Returns ("NULL", nil) on empty input so callers can always splice the
// returned fragment directly — `owner_id IN (NULL)` is always false, which
// is the correct behavior when a viewer has no group peers (no additional
// rows should be visible beyond their own + globals).
func inClause(ids []int64) (string, []any) {
	if len(ids) == 0 {
		return "NULL", nil
	}
	parts := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		parts[i] = "?"
		args[i] = id
	}
	return strings.Join(parts, ","), args
}

func normalizeRole(role string) string {
	switch role {
	case RoleView:
		return RoleView
	case RoleUser:
		return RoleUser
	default:
		return RoleAdmin
	}
}

func CreateUser(db *sql.DB, email, passwordHash, name, role string) (int64, error) {
	role = normalizeRole(role)
	admin := 0
	if role == RoleAdmin {
		admin = 1
	}
	// RoleUser and RoleView are both non-admin
	res, err := db.Exec(
		`INSERT INTO users (email, password_hash, name, is_admin, role) VALUES (?, ?, ?, ?, ?)`,
		strings.ToLower(email), passwordHash, name, admin, role,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateUser(db *sql.DB, id int64, name, role string) error {
	role = normalizeRole(role)
	admin := 0
	if role == RoleAdmin {
		admin = 1
	}
	_, err := db.Exec(`UPDATE users SET name=?, role=?, is_admin=? WHERE id=?`, name, role, admin, id)
	return err
}

func UpdateUserPassword(db *sql.DB, id int64, passwordHash string) error {
	_, err := db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, passwordHash, id)
	return err
}

func DeleteUser(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func CountAdmins(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE COALESCE(role, CASE WHEN is_admin=1 THEN 'admin' ELSE 'view' END) = 'admin'`).Scan(&n)
	return n, err
}

func CountUsers(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// Column list shared between ListProxyHosts and GetProxyHost. Every column
// is qualified with the `ph` alias so the same string works inside the
// users-JOIN SELECTs in ListProxyHosts (where bare `id` would collide with
// users.id and raise SQLite "ambiguous column name: id"). Callers must
// alias proxy_hosts AS ph in the FROM clause. The unified dns_* columns
// sit at the end; cf_*/pb_* are not read — their data was copied into
// dns_* by the v2.3.0 migration in internal/db.
const proxyHostBaseCols = `ph.id, ph.server_id, ph.domains, ph.forward_scheme, ph.forward_host, ph.forward_port,
    ph.websocket_support, ph.block_common_exploits, ph.ssl_enabled, ph.ssl_forced,
    ph.http2_support, COALESCE(ph.advanced_config, ''), ph.enabled,
    COALESCE(ph.certificate_id, 0), ph.created_at, ph.updated_at,
    ph.basicauth_enabled, COALESCE(ph.basicauth_users, '[]'),
    COALESCE(ph.access_list, ''), COALESCE(ph.extra_upstreams, '[]'),
    COALESCE(ph.owner_id, 0),
    COALESCE(ph.dns_provider,''), COALESCE(ph.dns_zone_id,''),
    COALESCE(ph.dns_zone_name,''), COALESCE(ph.dns_record_id,''),
    COALESCE(ph.dns_profile_id,''),
    COALESCE(ph.compression_enabled,0), COALESCE(ph.security_headers_enabled,0),
    COALESCE(ph.tls_min_version,''),
    COALESCE(ph.custom_req_headers,'{}'), COALESCE(ph.custom_resp_headers,'{}'),
    COALESCE(ph.url_rewrites,'[]'),
    COALESCE(ph.maintenance_mode,0), COALESCE(ph.maintenance_msg, ''),
    COALESCE(ph.max_request_body_mb,0),
    COALESCE(ph.sticky_sessions,0),
    COALESCE(ph.upstream_timeout_sec,0),
    COALESCE(ph.cors_enabled,0), COALESCE(ph.cors_origins,'*'),
    COALESCE(ph.health_check_uri,''), COALESCE(ph.health_check_interval_sec,30),
    COALESCE(ph.keepalive_conns,0),
    COALESCE(ph.tags,''),
    COALESCE(ph.notes,''),
    COALESCE(ph.disable_access_log,0),
    COALESCE(ph.add_request_id,0),
    COALESCE(ph.strip_resp_headers,''),
    COALESCE(ph.blocked_agents,''),
    COALESCE(ph.health_check_method,'GET'),
    COALESCE(ph.maintenance_status_code,503),
    COALESCE(ph.response_cache_control,''),
    COALESCE(ph.upstream_sni,''),
    COALESCE(ph.hsts_preload,0),
    COALESCE(ph.max_conns_per_host,0),
    COALESCE(ph.health_check_timeout_sec,5),
    COALESCE(ph.upstream_retries,0),
    COALESCE(ph.force_http1,0),
    COALESCE(ph.basicauth_realm,'Restricted'),
    COALESCE(ph.error_page_html,''),
    COALESCE(ph.maintenance_window_start,''), COALESCE(ph.maintenance_window_end,''),
    COALESCE(ph.maintenance_window_days,''),
    COALESCE(ph.ip_blocklist,''),
    COALESCE(ph.lb_policy,''),
    COALESCE(ph.proxy_protocol,''),
    COALESCE(ph.robots_txt,''),
    COALESCE(ph.passive_fail_duration_sec,0),
    COALESCE(ph.passive_max_fails,0),
    COALESCE(ph.hsts_max_age_sec,0),
    COALESCE(ph.csp_header,''),
    COALESCE(ph.h2c_enabled,0),
    COALESCE(ph.health_check_headers,'{}'),
    COALESCE(ph.flush_immediate,0),
    COALESCE(ph.buffer_responses,0),
    COALESCE(ph.trusted_proxies,''),
    COALESCE(ph.upstream_host_override,''),
    COALESCE(ph.read_timeout_sec,0),
    COALESCE(ph.deny_dotfiles,0),
    COALESCE(ph.request_buffers_kb,0),
    COALESCE(ph.cors_allow_credentials,0),
    COALESCE(ph.cors_expose_headers,''),
    COALESCE(ph.ssl_verify_upstream,0),
    COALESCE(ph.dial_timeout_sec,0),
    COALESCE(ph.api_key_header,''),
    COALESCE(ph.api_key_value,''),
    COALESCE(ph.block_empty_user_agent,0),
    COALESCE(ph.error_redirect_url,''),
    COALESCE(ph.permissions_policy,''),
    COALESCE(ph.x_frame_options,''),
    COALESCE(ph.referrer_policy,''),
    COALESCE(ph.hsts_include_subdomains,1),
    COALESCE(ph.csp_report_only,''),
    COALESCE(ph.keepalive_idle_timeout_sec,0),
    COALESCE(ph.health_check_expect_status,0),
    COALESCE(ph.health_check_expect_body,''),
    COALESCE(ph.health_check_follow_redirects,0),
    COALESCE(ph.path_matcher,''),
    COALESCE(ph.strip_path_prefix,0),
    COALESCE(ph.sticky_cookie_name,''),
    COALESCE(ph.lb_try_duration_sec,0),
    COALESCE(ph.lb_try_interval_ms,0),
    COALESCE(ph.compression_min_size_kb,0),
    COALESCE(ph.forward_client_ip,0),
    COALESCE(ph.cors_max_age_sec,0),
    COALESCE(ph.cors_allow_methods,''),
    COALESCE(ph.cors_allow_headers,''),
    COALESCE(ph.retry_status_codes,''),
    COALESCE(ph.write_timeout_sec,0),
    COALESCE(ph.upstream_tls_min_version,''),
    COALESCE(ph.forward_proxy_url,''),
    COALESCE(ph.blocked_methods,''),
    COALESCE(ph.forward_auth_url,''),
    COALESCE(ph.forward_auth_copy_headers,''),
    COALESCE(ph.strip_query_string,0),
    COALESCE(ph.delete_query_params,''),
    COALESCE(ph.request_body_read_timeout_sec,0),
    COALESCE(ph.response_header_timeout_sec,0),
    COALESCE(ph.max_conn_duration_sec,0),
    COALESCE(ph.decompress_response,0),
    COALESCE(ph.color,''),
    COALESCE(ph.www_redirect,''),
    COALESCE(ph.strip_req_headers,''),
    COALESCE(ph.upstream_path_prefix,''),
    COALESCE(ph.compression_level,0),
    COALESCE(ph.compression_prefer_gzip,0),
    COALESCE(ph.sort_order,0),
    COALESCE(ph.allowed_methods,''),
    COALESCE(ph.upstream_max_resp_header_kb,0),
    COALESCE(ph.health_check_port,0),
    COALESCE(ph.request_id_header_name,''),
    COALESCE(ph.lb_cookie_path,''),
    COALESCE(ph.passive_unhealthy_latency_ms,0),
    COALESCE(ph.tls_handshake_timeout_sec,0),
    COALESCE(ph.expect_continue_timeout_sec,0),
    COALESCE(ph.response_buffers_kb,0),
    COALESCE(ph.upstream_max_idle_conns,0),
    COALESCE(ph.upstream_keep_alive_probe_sec,0),
    COALESCE(ph.forward_auth_method,''),
    COALESCE(ph.grpc_web_enabled,0),
    COALESCE(ph.forward_auth_headers_prefix,''),
    COALESCE(ph.health_check_max_size_kb,0),
    COALESCE(ph.strip_path_suffix,''),
    COALESCE(ph.add_req_query_params,''),
    COALESCE(ph.error_page_codes,''),
    COALESCE(ph.upstream_tls_ca_pem_file,''),
    COALESCE(ph.keepalive_disabled,0),
    COALESCE(ph.trailing_slash_redirect,''),
    COALESCE(ph.dial_fallback_delay_ms,0),
    COALESCE(ph.upstream_network,''),
    COALESCE(ph.dns_resolver,''),
    COALESCE(ph.path_matcher_type,''),
    COALESCE(ph.cors_allow_private_network,0),
    COALESCE(ph.robots_txt_disallow_all,0),
    COALESCE(ph.maintenance_retry_after_sec,0),
    COALESCE(ph.upstream_resolve_timeout_sec,0),
    COALESCE(ph.upstream_read_buffer_size_kb,0),
    COALESCE(ph.upstream_write_buffer_size_kb,0),
    COALESCE(ph.req_header_replace,''),
    COALESCE(ph.resp_header_replace,''),
    COALESCE(ph.upstream_http_versions,''),
    COALESCE(ph.health_check_body,''),
    COALESCE(ph.add_canonical_link_header,0),
    COALESCE(ph.http_basic_auth_upstream,''),
    COALESCE(ph.block_ua_regexp,''),
    COALESCE(ph.security_txt_body,''),
    COALESCE(ph.server_header_value,''),
    COALESCE(ph.x_robots_tag,''),
    COALESCE(ph.add_forwarded_header,0),
    COALESCE(ph.lb_cookie_secret,''),
    COALESCE(ph.passive_unhealthy_status_codes,''),
    COALESCE(ph.health_check_content_type,''),
    COALESCE(ph.upstream_tls_client_cert_file,''),
    COALESCE(ph.upstream_tls_client_key_file,''),
    COALESCE(ph.block_private_ips,0),
    COALESCE(ph.enable_brotli,0),
    COALESCE(ph.vary_header,''),
    COALESCE(ph.strip_etag,0),
    COALESCE(ph.http2_push_paths,''),
    COALESCE(ph.deny_content_types,''),
    COALESCE(ph.upstream_local_addr,''),
    COALESCE(ph.upstream_tls_renegotiation,''),
    COALESCE(ph.upstream_tls_curves,''),
    COALESCE(ph.upstream_tls_max_version,''),
    COALESCE(ph.upstream_tls_pins,''),
    COALESCE(ph.lb_header_field,''),
    COALESCE(ph.maintenance_custom_headers,''),
    COALESCE(ph.deny_extensions,''),
    COALESCE(ph.inject_request_timestamp,0),
    COALESCE(ph.add_resp_cookies,''),
    COALESCE(ph.strip_accept_encoding,0),
    COALESCE(ph.add_upstream_timing_header,0),
    COALESCE(ph.strip_server_header,0),
    COALESCE(ph.block_referer_regexp,''),
    COALESCE(ph.add_content_type_nosniff,0),
    COALESCE(ph.strip_authorization_header,0),
    COALESCE(ph.real_ip_from_header,''),
    COALESCE(ph.health_check_host_override,''),
    COALESCE(ph.add_x_forwarded_port,0),
    COALESCE(ph.lb_retry_on,''),
    COALESCE(ph.max_buffer_size_kb,0),
    COALESCE(ph.upstream_keepalive_probes,0),
    COALESCE(ph.upstream_flush_interval_ms,0),
    COALESCE(ph.add_x_forwarded_host,0),
    COALESCE(ph.maintenance_allowed_ips,''),
    COALESCE(ph.upstream_tls_cipher_suites,''),
    COALESCE(ph.add_cache_control_no_store,0),
    COALESCE(ph.deny_referer_empty,0),
    COALESCE(ph.lb_cookie_httponly,0),
    COALESCE(ph.lb_cookie_secure,0),
    COALESCE(ph.lb_cookie_same_site,''),
    COALESCE(ph.upstream_tls_early_data,0),
    COALESCE(ph.add_via_header,0),
    COALESCE(ph.req_header_rename,''),
    COALESCE(ph.add_expect_ct_header,0),
    COALESCE(ph.force_upstream_encoding,''),
    COALESCE(ph.passive_unhealthy_count,0),
    COALESCE(ph.strip_x_powered_by,0),
    COALESCE(ph.add_timing_allow_origin,''),
    COALESCE(ph.lb_cookie_max_age_sec,0),
    COALESCE(ph.cross_origin_opener_policy,''),
    COALESCE(ph.cross_origin_resource_policy,''),
    COALESCE(ph.cross_origin_embedder_policy,''),
    COALESCE(ph.deny_request_content_type,''),
    COALESCE(ph.compression_exclude_regexp,''),
    COALESCE(ph.add_cache_control_public,0),
    COALESCE(ph.add_x_request_start,0),
    COALESCE(ph.maintenance_window_timezone,''),
    COALESCE(ph.lb_random_choose_count,0),
    COALESCE(ph.add_x_forwarded_scheme,0),
    COALESCE(ph.response_cache_ttl_sec,0),
    COALESCE(ph.add_link_preload,''),
    COALESCE(ph.deny_path_regexp,''),
    COALESCE(ph.add_request_id_to_response,0),
    COALESCE(ph.health_check_tls_server_name,''),
    COALESCE(ph.add_x_real_ip,0),
    COALESCE(ph.strip_incoming_x_forwarded_for,0),
    COALESCE(ph.health_check_tls_insecure_skip_verify,0),
    COALESCE(ph.add_cors_vary_header,0),
    COALESCE(ph.upstream_tls_alpn,''),
    COALESCE(ph.add_x_powered_by,''),
    COALESCE(ph.block_query_params,''),
    COALESCE(ph.add_document_policy,''),
    COALESCE(ph.maintenance_redirect_url,''),
    COALESCE(ph.upstream_keepalive_max_lifetime_sec,0),
    COALESCE(ph.add_origin_header,''),
    COALESCE(ph.upstream_tls_ca_pem_inline,''),
    COALESCE(ph.add_server_timing_header,0),
    COALESCE(ph.add_clear_site_data,''),
    COALESCE(ph.add_x_dns_prefetch_control,0),
    COALESCE(ph.add_accept_ranges,0),
    COALESCE(ph.add_content_disposition,''),
    COALESCE(ph.upstream_tls_server_name_from_host,0),
    COALESCE(ph.add_x_permitted_cross_domain_policies,''),
    COALESCE(ph.strip_response_headers,''),
    COALESCE(ph.add_report_to,''),
    COALESCE(ph.add_nel_header,''),
    COALESCE(ph.block_http_methods,''),
    COALESCE(ph.add_service_worker_allowed,''),
    COALESCE(ph.add_accept_ch,''),
    COALESCE(ph.add_alt_svc,''),
    COALESCE(ph.add_content_language,''),
    COALESCE(ph.add_critical_ch,''),
    COALESCE(ph.add_x_download_options,0),
    COALESCE(ph.deny_user_agent_regexp,''),
    COALESCE(ph.add_pragma_no_cache,0),
    COALESCE(ph.health_check_user_agent,''),
    COALESCE(ph.add_x_request_path,0),
    COALESCE(ph.add_x_clacks_overhead,''),
    COALESCE(ph.add_x_ua_compatible,''),
    COALESCE(ph.forward_auth_skip_paths,''),
    COALESCE(ph.add_age_zero,0),
    COALESCE(ph.add_surrogate_control,''),
    COALESCE(ph.add_warning_header,''),
    COALESCE(ph.add_x_request_method,0),
    COALESCE(ph.add_x_request_query,0),
    COALESCE(ph.add_x_forwarded_user,''),
    COALESCE(ph.add_x_real_scheme,0),
    COALESCE(ph.add_origin_agent_cluster,0),
    COALESCE(ph.add_x_forwarded_groups,''),
    COALESCE(ph.add_x_forwarded_email,''),
    COALESCE(ph.add_x_forwarded_roles,''),
    COALESCE(ph.block_query_param_regexp,''),
    COALESCE(ph.add_x_request_referer,0),
    COALESCE(ph.add_x_request_origin,0),
    COALESCE(ph.add_x_forwarded_uri,0),
    COALESCE(ph.add_x_no_archive,0),
    COALESCE(ph.add_x_request_hostname,0),
    COALESCE(ph.add_x_xss_protection_disabled,0),
    COALESCE(ph.add_x_request_remote_port,0),
    COALESCE(ph.add_x_request_protocol,0),
    COALESCE(ph.add_save_data_vary,0),
    COALESCE(ph.add_x_environment,''),
    COALESCE(ph.add_x_trace_id,0),
    COALESCE(ph.health_check_query_params,''),
    COALESCE(ph.add_x_session_id,0),
    COALESCE(ph.add_x_response_trace_id,0),
    COALESCE(ph.add_x_request_local_addr,0),
    COALESCE(ph.add_x_request_local_port,0),
    COALESCE(ph.add_x_request_path_info,0),
    COALESCE(ph.add_x_authenticated_user,''),
    COALESCE(ph.block_path_extensions,''),
    COALESCE(ph.add_link_modulepreload,''),
    COALESCE(ph.add_x_remote_user,''),
    COALESCE(ph.add_x_forwarded_path,0),
    COALESCE(ph.add_x_geo_country_code,''),
    COALESCE(ph.add_x_request_priority,''),
    COALESCE(ph.health_check_basic_auth,''),
    COALESCE(ph.add_x_real_ssl_protocol,0),
    COALESCE(ph.add_x_real_ssl_cipher,0),
    COALESCE(ph.add_x_cache_status,''),
    COALESCE(ph.deny_referer_regexp,''),
    COALESCE(ph.add_x_request_user_agent,0),
    COALESCE(ph.add_reporting_endpoints,''),
    COALESCE(ph.add_x_request_byte_count,0),
    COALESCE(ph.add_x_request_received_at,0),
    COALESCE(ph.strip_request_headers,''),
    COALESCE(ph.add_x_forwarded_method,0),
    COALESCE(ph.add_x_request_original_host,0),
    COALESCE(ph.add_x_request_dnt,0),
    COALESCE(ph.add_x_geo_region,''),
    COALESCE(ph.add_x_request_secure,0),
    COALESCE(ph.add_x_request_query_count,0),
    COALESCE(ph.add_x_request_id_header_response,0),
    COALESCE(ph.force_canonical_host,''),
    COALESCE(ph.add_x_robots_noindex_quick,0),
    COALESCE(ph.block_bot_user_agents,0),
    COALESCE(ph.block_admin_paths,0),
    COALESCE(ph.add_link_dns_prefetch,''),
    COALESCE(ph.add_link_preconnect,''),
    COALESCE(ph.add_x_csp_disabled,0),
    COALESCE(ph.add_x_request_method_override,0),
    COALESCE(ph.proxy_redirect_rules,''),
    COALESCE(ph.additional_upstream_rules,''),
    COALESCE(ph.disable_upstream_compression,0)`

// scanProxyHost pulls a single row into the struct. Centralises the
// bool-int unpack so each query site doesn't repeat it.
func scanProxyHost(s interface {
	Scan(dest ...any) error
}, p *ProxyHost, ownerEmail *string) error {
	var ws, bce, ssl, sslf, h2, en, bae int
	var ownerID int64
	var compr, sechdrs, maint, sticky, cors, disableAccessLog, addReqID, hstsPreload, forceHTTP1, h2c, flushImm, bufResp, denyDot, corsCredentials, sslVerify, blockUA, hstsSubdomains, hcFollowRedirects, stripPfx, fwdClientIP, stripQS, decompResp, comprPrefGzip, grpcWeb, kaDisabled, corsPrivNet, robotsDisallowAll, canonicalLink, fwdHeader, blockPrivIP, brotli, stripEtag, injectReqTimestamp, stripAcceptEnc, addUpstreamTiming, stripSrvHdr, addNosniff, stripAuthHdr, addXFwdPort, addXFwdHost, addCacheCtrlNoStore, denyRefEmpty, lbCookieHTTPOnly, lbCookieSecure, tlsEarlyData, addVia, addExpectCT, stripXPoweredBy, addCacheCtrlPublic, addXReqStart, addXFwdScheme, addReqIDToResp, addXRealIP, stripIncomingXFwdFor, hcTLSSkipVerify, addCORSVary, addSrvTiming, addXDNSPrefetch, addAcceptRanges, tlsSNIFromHost, addXDlOpts, addPragmaNC, addXReqPath, addAgeZero, addXReqMethod, addXReqQuery, addXRealScheme, addOAC, addXReqReferer, addXReqOrigin, addXFwdURI, addXNoArch, addXReqHost, addXXSSDis, addXReqRemotePort, addXReqProto, addSaveDataVary, addXTraceID, addXSessionID, addXRespTraceID, addXReqLocalAddr, addXReqLocalPort, addXReqPathInfo, addXFwdPath, addXRealSSLProto, addXRealSSLCipher, addXReqUA, addXReqByteCount, addXReqReceivedAt, addXFwdMethod, addXReqOrigHost, addXReqDNT, addXReqSecure, addXReqQueryCount, addXReqIDHdrResp, addXRobotsNoindex, blockBotUA, blockAdminPaths, addXCSPDis, addXMethodOverride, disableUpstreamCompression int
	dst := []any{
		&p.ID, &p.ServerID, &p.Domains, &p.ForwardScheme, &p.ForwardHost, &p.ForwardPort,
		&ws, &bce, &ssl, &sslf, &h2, &p.AdvancedConfig, &en, &p.CertificateID,
		&p.CreatedAt, &p.UpdatedAt,
		&bae, &p.BasicAuthUsers,
		&p.AccessList, &p.ExtraUpstreams,
		&ownerID,
		&p.DNSProvider, &p.DNSZoneID, &p.DNSZoneName, &p.DNSRecordID, &p.DNSProfileID,
		&compr, &sechdrs, &p.TLSMinVersion,
		&p.CustomReqHeaders, &p.CustomRespHeaders,
		&p.URLRewrites,
		&maint,
		&p.MaintenanceMsg,
		&p.MaxRequestBodyMB,
		&sticky,
		&p.UpstreamTimeoutSec,
		&cors, &p.CORSOrigins,
		&p.HealthCheckURI, &p.HealthCheckIntervalSec, &p.KeepaliveConns,
		&p.Tags,
		&p.Notes,
		&disableAccessLog,
		&addReqID,
		&p.StripRespHeaders,
		&p.BlockedAgents,
		&p.HealthCheckMethod,
		&p.MaintenanceStatusCode,
		&p.ResponseCacheControl,
		&p.UpstreamSNI,
		&hstsPreload,
		&p.MaxConnsPerHost,
		&p.HealthCheckTimeoutSec,
		&p.UpstreamRetries,
		&forceHTTP1,
		&p.BasicAuthRealm,
		&p.ErrorPageHTML,
		&p.MaintenanceWindowStart, &p.MaintenanceWindowEnd, &p.MaintenanceWindowDays,
		&p.IPBlocklist,
		&p.LBPolicy,
		&p.ProxyProtocol,
		&p.RobotsTxt,
		&p.PassiveFailDurationSec,
		&p.PassiveMaxFails,
		&p.HSTSMaxAgeSec,
		&p.CSPHeader,
		&h2c,
		&p.HealthCheckHeaders,
		&flushImm,
		&bufResp,
		&p.TrustedProxies,
		&p.UpstreamHostOverride,
		&p.ReadTimeoutSec,
		&denyDot,
		&p.RequestBuffersKB,
		&corsCredentials,
		&p.CORSExposeHeaders,
		&sslVerify,
		&p.DialTimeoutSec,
		&p.APIKeyHeader,
		&p.APIKeyValue,
		&blockUA,
		&p.ErrorRedirectURL,
		&p.PermissionsPolicy,
		&p.XFrameOptions,
		&p.ReferrerPolicy,
		&hstsSubdomains,
		&p.CSPReportOnly,
		&p.KeepaliveIdleTimeoutSec,
		&p.HealthCheckExpectStatus,
		&p.HealthCheckExpectBody,
		&hcFollowRedirects,
		&p.PathMatcher,
		&stripPfx,
		&p.StickyCookieName,
		&p.LBTryDurationSec,
		&p.LBTryIntervalMS,
		&p.CompressionMinSizeKB,
		&fwdClientIP,
		&p.CORSMaxAgeSec,
		&p.CORSAllowMethods,
		&p.CORSAllowHeaders,
		&p.RetryStatusCodes,
		&p.WriteTimeoutSec,
		&p.UpstreamTLSMinVersion,
		&p.ForwardProxyURL,
		&p.BlockedMethods,
		&p.ForwardAuthURL,
		&p.ForwardAuthCopyHeaders,
		&stripQS,
		&p.DeleteQueryParams,
		&p.RequestBodyReadTimeoutSec,
		&p.ResponseHeaderTimeoutSec,
		&p.MaxConnDurationSec,
		&decompResp,
		&p.Color,
		&p.WWWRedirect,
		&p.StripReqHeaders,
		&p.UpstreamPathPrefix,
		&p.CompressionLevel,
		&comprPrefGzip,
		&p.SortOrder,
		&p.AllowedMethods,
		&p.UpstreamMaxRespHeaderKB,
		&p.HealthCheckPort,
		&p.RequestIDHeaderName,
		&p.LBCookiePath,
		&p.PassiveUnhealthyLatencyMS,
		&p.TLSHandshakeTimeoutSec,
		&p.ExpectContinueTimeoutSec,
		&p.ResponseBuffersKB,
		&p.UpstreamMaxIdleConns,
		&p.UpstreamKeepAliveProbeIntervalSec,
		&p.ForwardAuthMethod,
		&grpcWeb,
		&p.ForwardAuthHeadersPrefix,
		&p.HealthCheckMaxSizeKB,
		&p.StripPathSuffix,
		&p.AddReqQueryParams,
		&p.ErrorPageCodes,
		&p.UpstreamTLSCAPEMFile,
		&kaDisabled,
		&p.TrailingSlashRedirect,
		&p.DialFallbackDelayMS,
		&p.UpstreamNetwork,
		&p.DNSResolver,
		&p.PathMatcherType,
		&corsPrivNet,
		&robotsDisallowAll,
		&p.MaintenanceRetryAfterSec,
		&p.UpstreamResolveTimeoutSec,
		&p.UpstreamReadBufferSizeKB,
		&p.UpstreamWriteBufferSizeKB,
		&p.ReqHeaderReplace,
		&p.RespHeaderReplace,
		&p.UpstreamHTTPVersions,
		&p.HealthCheckBody,
		&canonicalLink,
		&p.HTTPBasicAuthUpstream,
		&p.BlockUARegexp,
		&p.SecurityTxtBody,
		&p.ServerHeaderValue,
		&p.XRobotsTag,
		&fwdHeader,
		&p.LBCookieSecret,
		&p.PassiveUnhealthyStatusCodes,
		&p.HealthCheckContentType,
		&p.UpstreamTLSClientCertFile,
		&p.UpstreamTLSClientKeyFile,
		&blockPrivIP,
		&brotli,
		&p.VaryHeader,
		&stripEtag,
		&p.HTTP2PushPaths,
		&p.DenyContentTypes,
		&p.UpstreamLocalAddr,
		&p.UpstreamTLSRenegotiation,
		&p.UpstreamTLSCurves,
		&p.UpstreamTLSMaxVersion,
		&p.UpstreamTLSPins,
		&p.LBHeaderField,
		&p.MaintenanceCustomHeaders,
		&p.DenyExtensions,
		&injectReqTimestamp,
		&p.AddRespCookies,
		&stripAcceptEnc,
		&addUpstreamTiming,
		&stripSrvHdr,
		&p.BlockRefererRegexp,
		&addNosniff,
		&stripAuthHdr,
		&p.RealIPFromHeader,
		&p.HealthCheckHostOverride,
		&addXFwdPort,
		&p.LBRetryOn,
		&p.MaxBufferSizeKB,
		&p.UpstreamKeepaliveProbes,
		&p.UpstreamFlushIntervalMS,
		&addXFwdHost,
		&p.MaintenanceAllowedIPs,
		&p.UpstreamTLSCipherSuites,
		&addCacheCtrlNoStore,
		&denyRefEmpty,
		&lbCookieHTTPOnly,
		&lbCookieSecure,
		&p.LBCookieSameSite,
		&tlsEarlyData,
		&addVia,
		&p.ReqHeaderRename,
		&addExpectCT,
		&p.ForceUpstreamEncoding,
		&p.PassiveUnhealthyCount,
		&stripXPoweredBy,
		&p.AddTimingAllowOrigin,
		&p.LBCookieMaxAgeSec,
		&p.CrossOriginOpenerPolicy,
		&p.CrossOriginResourcePolicy,
		&p.CrossOriginEmbedderPolicy,
		&p.DenyRequestContentType,
		&p.CompressionExcludeRegexp,
		&addCacheCtrlPublic,
		&addXReqStart,
		&p.MaintenanceWindowTimezone,
		&p.LBRandomChooseCount,
		&addXFwdScheme,
		&p.ResponseCacheTTLSec,
		&p.AddLinkPreload,
		&p.DenyPathRegexp,
		&addReqIDToResp,
		&p.HealthCheckTLSServerName,
		&addXRealIP,
		&stripIncomingXFwdFor,
		&hcTLSSkipVerify,
		&addCORSVary,
		&p.UpstreamTLSALPN,
		&p.AddXPoweredBy,
		&p.BlockQueryParams,
		&p.AddDocumentPolicy,
		&p.MaintenanceRedirectURL,
		&p.UpstreamKeepaliveMaxLifetimeSec,
		&p.AddOriginHeader,
		&p.UpstreamTLSCAPEMInline,
		&addSrvTiming,
		&p.AddClearSiteData,
		&addXDNSPrefetch,
		&addAcceptRanges,
		&p.AddContentDisposition,
		&tlsSNIFromHost,
		&p.AddXPermittedCrossDomainPolicies,
		&p.StripResponseHeaders,
		&p.AddReportTo,
		&p.AddNELHeader,
		&p.BlockHTTPMethods,
		&p.AddServiceWorkerAllowed,
		&p.AddAcceptCH,
		&p.AddAltSvc,
		&p.AddContentLanguage,
		&p.AddCriticalCH,
		&addXDlOpts,
		&p.DenyUserAgentRegexp,
		&addPragmaNC,
		&p.HealthCheckUserAgent,
		&addXReqPath,
		&p.AddXClacksOverhead,
		&p.AddXUACompatible,
		&p.ForwardAuthSkipPaths,
		&addAgeZero,
		&p.AddSurrogateControl,
		&p.AddWarningHeader,
		&addXReqMethod,
		&addXReqQuery,
		&p.AddXForwardedUser,
		&addXRealScheme,
		&addOAC,
		&p.AddXForwardedGroups,
		&p.AddXForwardedEmail,
		&p.AddXForwardedRoles,
		&p.BlockQueryParamRegexp,
		&addXReqReferer,
		&addXReqOrigin,
		&addXFwdURI,
		&addXNoArch,
		&addXReqHost,
		&addXXSSDis,
		&addXReqRemotePort,
		&addXReqProto,
		&addSaveDataVary,
		&p.AddXEnvironment,
		&addXTraceID,
		&p.HealthCheckQueryParams,
		&addXSessionID,
		&addXRespTraceID,
		&addXReqLocalAddr,
		&addXReqLocalPort,
		&addXReqPathInfo,
		&p.AddXAuthenticatedUser,
		&p.BlockPathExtensions,
		&p.AddLinkModulePreload,
		&p.AddXRemoteUser,
		&addXFwdPath,
		&p.AddXGeoCountryCode,
		&p.AddXRequestPriority,
		&p.HealthCheckBasicAuth,
		&addXRealSSLProto,
		&addXRealSSLCipher,
		&p.AddXCacheStatus,
		&p.DenyRefererRegexp,
		&addXReqUA,
		&p.AddReportingEndpoints,
		&addXReqByteCount,
		&addXReqReceivedAt,
		&p.StripRequestHeaders,
		&addXFwdMethod,
		&addXReqOrigHost,
		&addXReqDNT,
		&p.AddXGeoRegion,
		&addXReqSecure,
		&addXReqQueryCount,
		&addXReqIDHdrResp,
		&p.ForceCanonicalHost,
		&addXRobotsNoindex,
		&blockBotUA,
		&blockAdminPaths,
		&p.AddLinkDNSPrefetch,
		&p.AddLinkPreconnect,
		&addXCSPDis,
		&addXMethodOverride,
		&p.ProxyRedirectRules,
		&p.AdditionalUpstreamRules,
		&disableUpstreamCompression, // v2.12.52
	}
	if ownerEmail != nil {
		dst = append(dst, ownerEmail)
	}
	if err := s.Scan(dst...); err != nil {
		return err
	}
	p.WebsocketSupport = ws == 1
	p.BlockCommonExploits = bce == 1
	p.SSLEnabled = ssl == 1
	p.SSLForced = sslf == 1
	p.HTTP2Support = h2 == 1
	p.Enabled = en == 1
	p.BasicAuthEnabled = bae == 1
	p.CompressionEnabled = compr == 1
	p.SecurityHeadersEnabled = sechdrs == 1
	p.MaintenanceMode = maint == 1
	p.StickySessions = sticky == 1
	p.CORSEnabled = cors == 1
	p.DisableAccessLog = disableAccessLog == 1
	p.AddRequestID = addReqID == 1
	p.HSTSPreload = hstsPreload == 1
	p.ForceHTTP1 = forceHTTP1 == 1
	p.H2CEnabled = h2c == 1
	p.FlushImmediate = flushImm == 1
	p.BufferResponses = bufResp == 1
	p.DenyDotfiles = denyDot == 1
	p.CORSAllowCredentials = corsCredentials == 1
	p.SSLVerifyUpstream = sslVerify == 1
	p.BlockEmptyUserAgent = blockUA == 1
	p.HSTSIncludeSubdomains = hstsSubdomains == 1
	p.HealthCheckFollowRedirects = hcFollowRedirects == 1
	p.StripPathPrefix = stripPfx == 1
	p.ForwardClientIP = fwdClientIP == 1
	p.StripQueryString = stripQS == 1
	p.DecompressResponse = decompResp == 1
	p.CompressionPreferGzip = comprPrefGzip == 1
	p.GRPCWebEnabled = grpcWeb == 1
	p.KeepaliveDisabled = kaDisabled == 1
	p.CORSAllowPrivateNetwork = corsPrivNet == 1
	p.RobotsTxtDisallowAll = robotsDisallowAll == 1
	p.AddCanonicalLinkHeader = canonicalLink == 1
	p.AddForwardedHeader = fwdHeader == 1
	p.BlockPrivateIPs = blockPrivIP == 1
	p.EnableBrotli = brotli == 1
	p.StripETag = stripEtag == 1
	p.InjectRequestTimestamp = injectReqTimestamp == 1
	p.StripAcceptEncoding = stripAcceptEnc == 1
	p.AddUpstreamTimingHeader = addUpstreamTiming == 1
	p.StripServerHeader = stripSrvHdr == 1
	p.AddContentTypeNosniff = addNosniff == 1
	p.StripAuthorizationHeader = stripAuthHdr == 1
	p.AddXForwardedPort = addXFwdPort == 1
	p.AddXForwardedHost = addXFwdHost == 1
	p.AddCacheControlNoStore = addCacheCtrlNoStore == 1
	p.DenyRefererEmpty = denyRefEmpty == 1
	p.LBCookieHTTPOnly = lbCookieHTTPOnly == 1
	p.LBCookieSecure = lbCookieSecure == 1
	p.UpstreamTLSEarlyData = tlsEarlyData == 1
	p.AddViaHeader = addVia == 1
	p.AddExpectCTHeader = addExpectCT == 1
	p.StripXPoweredBy = stripXPoweredBy == 1
	p.AddCacheControlPublic = addCacheCtrlPublic == 1
	p.AddXRequestStart = addXReqStart == 1
	p.AddXForwardedScheme = addXFwdScheme == 1
	p.AddRequestIDToResponse = addReqIDToResp == 1
	p.AddXRealIP = addXRealIP == 1
	p.StripIncomingXForwardedFor = stripIncomingXFwdFor == 1
	p.HealthCheckTLSInsecureSkipVerify = hcTLSSkipVerify == 1
	p.AddCORSVaryHeader = addCORSVary == 1
	p.AddServerTimingHeader = addSrvTiming == 1
	p.AddXDNSPrefetchControl = addXDNSPrefetch == 1
	p.AddAcceptRanges = addAcceptRanges == 1
	p.UpstreamTLSServerNameFromHost = tlsSNIFromHost == 1
	p.AddXDownloadOptions = addXDlOpts == 1
	p.AddPragmaNoCache = addPragmaNC == 1
	p.AddXRequestPath = addXReqPath == 1
	p.AddAgeZero = addAgeZero == 1
	p.AddXRequestMethod = addXReqMethod == 1
	p.AddXRequestQuery = addXReqQuery == 1
	p.AddXRealScheme = addXRealScheme == 1
	p.AddOriginAgentCluster = addOAC == 1
	p.AddXRequestReferer = addXReqReferer == 1
	p.AddXRequestOrigin = addXReqOrigin == 1
	p.AddXForwardedURI = addXFwdURI == 1
	p.AddXNoArchive = addXNoArch == 1
	p.AddXRequestHostname = addXReqHost == 1
	p.AddXXSSProtectionDisabled = addXXSSDis == 1
	p.AddXRequestRemotePort = addXReqRemotePort == 1
	p.AddXRequestProtocol = addXReqProto == 1
	p.AddSaveDataVary = addSaveDataVary == 1
	p.AddXTraceID = addXTraceID == 1
	p.AddXSessionID = addXSessionID == 1
	p.AddXResponseTraceID = addXRespTraceID == 1
	p.AddXRequestLocalAddr = addXReqLocalAddr == 1
	p.AddXRequestLocalPort = addXReqLocalPort == 1
	p.AddXRequestPathInfo = addXReqPathInfo == 1
	p.AddXForwardedPath = addXFwdPath == 1
	p.AddXRealSSLProtocol = addXRealSSLProto == 1
	p.AddXRealSSLCipher = addXRealSSLCipher == 1
	p.AddXRequestUserAgent = addXReqUA == 1
	p.AddXRequestByteCount = addXReqByteCount == 1
	p.AddXRequestReceivedAt = addXReqReceivedAt == 1
	p.AddXForwardedMethod = addXFwdMethod == 1
	p.AddXRequestOriginalHost = addXReqOrigHost == 1
	p.AddXRequestDNT = addXReqDNT == 1
	p.AddXRequestSecure = addXReqSecure == 1
	p.AddXRequestQueryCount = addXReqQueryCount == 1
	p.AddXRequestIDHeaderResponse = addXReqIDHdrResp == 1
	p.AddXRobotsNoindexQuick = addXRobotsNoindex == 1
	p.BlockBotUserAgents = blockBotUA == 1
	p.BlockAdminPaths = blockAdminPaths == 1
	p.AddXCSPDisabled = addXCSPDis == 1
	p.AddXRequestMethodOverride = addXMethodOverride == 1
	p.DisableUpstreamCompression = disableUpstreamCompression == 1 // v2.12.52
	if ownerID != 0 {
		p.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
	}
	return nil
}

// ListProxyHosts returns proxy hosts for the given server.
// If isAdmin is true, all hosts are returned and owner email is populated via JOIN.
// If isAdmin is false, only hosts owned by viewerID OR by anyone whose user ID
// is in peerIDs (group teammates, per v2.7.4) are returned. peerIDs may be
// nil/empty — in that case only the viewer's own hosts come back. The JOIN on
// users still populates OwnerEmail in the non-admin path so the template can
// show a "Team: alice@example.com" chip on teammates' rows.
func ListProxyHosts(db *sql.DB, serverID int64, viewerID int64, isAdmin bool, peerIDs []int64) ([]ProxyHost, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
        SELECT `+proxyHostBaseCols+`, COALESCE(u.email, '')
        FROM proxy_hosts ph
        LEFT JOIN users u ON u.id = ph.owner_id
        WHERE ph.server_id = ? ORDER BY ph.sort_order ASC, ph.id DESC`, serverID)
	} else {
		inStr, inArgs := inClause(peerIDs)
		args := append([]any{serverID, viewerID}, inArgs...)
		rows, err = db.Query(`
        SELECT `+proxyHostBaseCols+`, COALESCE(u.email, '')
        FROM proxy_hosts ph
        LEFT JOIN users u ON u.id = ph.owner_id
        WHERE ph.server_id = ?
          AND (ph.owner_id = ? OR ph.owner_id IN (`+inStr+`))
        ORDER BY ph.sort_order ASC, ph.id DESC`, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ProxyHost
	for rows.Next() {
		var p ProxyHost
		var email string
		if err := scanProxyHost(rows, &p, &email); err != nil {
			return nil, err
		}
		p.OwnerEmail = email
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListProxyHostSummaries returns only the fields used by the proxy-host list
// and its live-health endpoint. ProxyHost has hundreds of optional fields,
// many containing large JSON/HTML blobs; selecting and scanning all of them
// made /proxy-hosts increasingly expensive as the host count grew.
func ListProxyHostSummaries(db *sql.DB, serverID int64, viewerID int64, isAdmin bool, peerIDs []int64) ([]ProxyHost, error) {
	const cols = `ph.id, ph.domains, ph.forward_scheme, ph.forward_host, ph.forward_port,
		ph.ssl_enabled, ph.ssl_forced, ph.enabled, COALESCE(ph.certificate_id, 0),
		ph.basicauth_enabled, COALESCE(ph.owner_id, 0),
		COALESCE(ph.dns_provider, ''), COALESCE(ph.dns_record_id, ''),
		COALESCE(ph.maintenance_mode, 0), COALESCE(ph.tags, ''),
		COALESCE(ph.notes, ''), COALESCE(ph.color, ''), ph.updated_at,
		COALESCE(u.email, '')`

	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
			SELECT `+cols+`
			FROM proxy_hosts ph
			LEFT JOIN users u ON u.id = ph.owner_id
			WHERE ph.server_id = ?
			ORDER BY ph.sort_order ASC, ph.id DESC`, serverID)
	} else {
		inStr, inArgs := inClause(peerIDs)
		args := append([]any{serverID, viewerID}, inArgs...)
		rows, err = db.Query(`
			SELECT `+cols+`
			FROM proxy_hosts ph
			LEFT JOIN users u ON u.id = ph.owner_id
			WHERE ph.server_id = ?
			  AND (ph.owner_id = ? OR ph.owner_id IN (`+inStr+`))
			ORDER BY ph.sort_order ASC, ph.id DESC`, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ProxyHost
	for rows.Next() {
		var p ProxyHost
		var sslEnabled, sslForced, enabled, basicAuth, maintenance int
		var ownerID int64
		if err := rows.Scan(
			&p.ID, &p.Domains, &p.ForwardScheme, &p.ForwardHost, &p.ForwardPort,
			&sslEnabled, &sslForced, &enabled, &p.CertificateID,
			&basicAuth, &ownerID, &p.DNSProvider, &p.DNSRecordID,
			&maintenance, &p.Tags, &p.Notes, &p.Color, &p.UpdatedAt,
			&p.OwnerEmail,
		); err != nil {
			return nil, err
		}
		p.SSLEnabled = sslEnabled == 1
		p.SSLForced = sslForced == 1
		p.Enabled = enabled == 1
		p.BasicAuthEnabled = basicAuth == 1
		p.MaintenanceMode = maintenance == 1
		if ownerID != 0 {
			p.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
		}
		// The list template still uses the legacy Cloudflare-specific display
		// field for its badge. Keep it populated without loading legacy columns.
		if p.DNSProvider == "cloudflare" {
			p.CFDNSRecordID = p.DNSRecordID
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func GetProxyHost(db *sql.DB, id int64) (*ProxyHost, error) {
	var p ProxyHost
	if err := scanProxyHost(
		db.QueryRow(`SELECT `+proxyHostBaseCols+` FROM proxy_hosts ph WHERE ph.id = ?`, id),
		&p, nil,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListProxyHostsWithMaintenanceWindow returns all enabled proxy hosts that have
// a scheduled maintenance window configured (maintenance_window_start is non-empty).
// Used by the background window-boundary loop to know which servers need a sync.
func ListProxyHostsWithMaintenanceWindow(db *sql.DB) ([]ProxyHost, error) {
	rows, err := db.Query(`SELECT ` + proxyHostBaseCols + ` FROM proxy_hosts ph WHERE ph.maintenance_window_start != '' AND ph.enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyHost
	for rows.Next() {
		var p ProxyHost
		if err := scanProxyHost(rows, &p, nil); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// nilIfZero returns nil for 0 so INSERT/UPDATE stores NULL in certificate_id.
func nilIfZero(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateProxyHost inserts a new proxy host. ownerID 0 means global/admin-owned (NULL in DB).
func CreateProxyHost(db *sql.DB, serverID int64, ownerID int64, p *ProxyHost) (int64, error) {
	if p.ForwardScheme == "" {
		p.ForwardScheme = "http"
	}
	if p.BasicAuthUsers == "" {
		p.BasicAuthUsers = "[]"
	}
	if p.ExtraUpstreams == "" {
		p.ExtraUpstreams = "[]"
	}
	if p.CustomReqHeaders == "" {
		p.CustomReqHeaders = "{}"
	}
	if p.CustomRespHeaders == "" {
		p.CustomRespHeaders = "{}"
	}
	if p.URLRewrites == "" {
		p.URLRewrites = "[]"
	}
	res, err := db.Exec(`
        INSERT INTO proxy_hosts (server_id, domains, forward_scheme, forward_host, forward_port,
            websocket_support, block_common_exploits, ssl_enabled, ssl_forced,
            http2_support, advanced_config, enabled, certificate_id,
            basicauth_enabled, basicauth_users, access_list, extra_upstreams, owner_id,
            dns_provider, dns_zone_id, dns_zone_name, dns_record_id,
            compression_enabled, security_headers_enabled, tls_min_version,
            custom_req_headers, custom_resp_headers, url_rewrites, maintenance_mode, maintenance_msg,
            max_request_body_mb, sticky_sessions, upstream_timeout_sec,
            cors_enabled, cors_origins,
            health_check_uri, health_check_interval_sec, keepalive_conns,
            tags, notes, disable_access_log,
            add_request_id, strip_resp_headers, blocked_agents, health_check_method,
            maintenance_status_code, response_cache_control,
            upstream_sni, hsts_preload, max_conns_per_host,
            health_check_timeout_sec, upstream_retries,
            force_http1, basicauth_realm, error_page_html,
            maintenance_window_start, maintenance_window_end, maintenance_window_days,
            ip_blocklist, lb_policy, proxy_protocol, robots_txt,
            passive_fail_duration_sec, passive_max_fails,
            hsts_max_age_sec, csp_header,
            h2c_enabled, health_check_headers,
            flush_immediate, buffer_responses, trusted_proxies,
            upstream_host_override, read_timeout_sec, deny_dotfiles,
            request_buffers_kb, cors_allow_credentials, cors_expose_headers,
            ssl_verify_upstream, dial_timeout_sec,
            api_key_header, api_key_value, block_empty_user_agent,
            error_redirect_url, permissions_policy, x_frame_options, referrer_policy,
            hsts_include_subdomains, csp_report_only, keepalive_idle_timeout_sec,
            health_check_expect_status, health_check_expect_body, health_check_follow_redirects,
            path_matcher, strip_path_prefix,
            sticky_cookie_name, lb_try_duration_sec, lb_try_interval_ms,
            compression_min_size_kb, forward_client_ip,
            cors_max_age_sec, cors_allow_methods, cors_allow_headers,
            retry_status_codes, write_timeout_sec,
            upstream_tls_min_version, forward_proxy_url,
            blocked_methods, forward_auth_url, forward_auth_copy_headers,
            strip_query_string, delete_query_params,
            request_body_read_timeout_sec, response_header_timeout_sec,
            max_conn_duration_sec, decompress_response, color, www_redirect,
            strip_req_headers, upstream_path_prefix,
            compression_level, compression_prefer_gzip, sort_order,
            allowed_methods, upstream_max_resp_header_kb, health_check_port,
            request_id_header_name, lb_cookie_path, passive_unhealthy_latency_ms,
            tls_handshake_timeout_sec, expect_continue_timeout_sec, response_buffers_kb,
            upstream_max_idle_conns, upstream_keep_alive_probe_sec, forward_auth_method,
            grpc_web_enabled, forward_auth_headers_prefix, health_check_max_size_kb,
            strip_path_suffix, add_req_query_params, error_page_codes,
            upstream_tls_ca_pem_file, keepalive_disabled, trailing_slash_redirect,
            dial_fallback_delay_ms, upstream_network, dns_resolver,
            path_matcher_type, cors_allow_private_network, robots_txt_disallow_all,
            maintenance_retry_after_sec, upstream_resolve_timeout_sec, upstream_read_buffer_size_kb,
            upstream_write_buffer_size_kb, req_header_replace, resp_header_replace,
            upstream_http_versions, health_check_body, add_canonical_link_header,
            http_basic_auth_upstream, block_ua_regexp, security_txt_body,
            server_header_value, x_robots_tag, add_forwarded_header,
            lb_cookie_secret, passive_unhealthy_status_codes, health_check_content_type,
            upstream_tls_client_cert_file, upstream_tls_client_key_file, block_private_ips,
            enable_brotli, vary_header, strip_etag,
            http2_push_paths, deny_content_types, upstream_local_addr,
            upstream_tls_renegotiation, upstream_tls_curves, upstream_tls_max_version,
            upstream_tls_pins, lb_header_field, maintenance_custom_headers,
            deny_extensions, inject_request_timestamp, add_resp_cookies,
            strip_accept_encoding, add_upstream_timing_header, strip_server_header,
            block_referer_regexp, add_content_type_nosniff, strip_authorization_header,
            real_ip_from_header, health_check_host_override, add_x_forwarded_port,
            lb_retry_on, max_buffer_size_kb, upstream_keepalive_probes,
            upstream_flush_interval_ms, add_x_forwarded_host, maintenance_allowed_ips,
            upstream_tls_cipher_suites, add_cache_control_no_store, deny_referer_empty,
            lb_cookie_httponly, lb_cookie_secure, lb_cookie_same_site,
            upstream_tls_early_data, add_via_header, req_header_rename,
            add_expect_ct_header, force_upstream_encoding, passive_unhealthy_count,
            strip_x_powered_by, add_timing_allow_origin, lb_cookie_max_age_sec,
            cross_origin_opener_policy, cross_origin_resource_policy, cross_origin_embedder_policy,
            deny_request_content_type, compression_exclude_regexp, add_cache_control_public,
            add_x_request_start, maintenance_window_timezone, lb_random_choose_count,
            add_x_forwarded_scheme, response_cache_ttl_sec, add_link_preload,
            deny_path_regexp, add_request_id_to_response, health_check_tls_server_name,
            add_x_real_ip, strip_incoming_x_forwarded_for, health_check_tls_insecure_skip_verify,
            add_cors_vary_header, upstream_tls_alpn, add_x_powered_by,
            block_query_params, add_document_policy, maintenance_redirect_url,
            upstream_keepalive_max_lifetime_sec, add_origin_header, upstream_tls_ca_pem_inline,
            add_server_timing_header, add_clear_site_data, add_x_dns_prefetch_control,
            add_accept_ranges, add_content_disposition, upstream_tls_server_name_from_host,
            add_x_permitted_cross_domain_policies, strip_response_headers, add_report_to,
            add_nel_header, block_http_methods, add_service_worker_allowed,
            add_accept_ch, add_alt_svc, add_content_language,
            add_critical_ch, add_x_download_options, deny_user_agent_regexp,
            add_pragma_no_cache, health_check_user_agent, add_x_request_path,
            add_x_clacks_overhead, add_x_ua_compatible, forward_auth_skip_paths,
            add_age_zero, add_surrogate_control, add_warning_header,
            add_x_request_method, add_x_request_query, add_x_forwarded_user,
            add_x_real_scheme, add_origin_agent_cluster, add_x_forwarded_groups,
            add_x_forwarded_email, add_x_forwarded_roles, block_query_param_regexp,
            add_x_request_referer, add_x_request_origin, add_x_forwarded_uri,
            add_x_no_archive, add_x_request_hostname, add_x_xss_protection_disabled,
            add_x_request_remote_port, add_x_request_protocol, add_save_data_vary,
            add_x_environment, add_x_trace_id, health_check_query_params,
            add_x_session_id, add_x_response_trace_id, add_x_request_local_addr,
            add_x_request_local_port, add_x_request_path_info,
            add_x_authenticated_user, block_path_extensions, add_link_modulepreload,
            add_x_remote_user, add_x_forwarded_path, add_x_geo_country_code,
            add_x_request_priority, health_check_basic_auth,
            add_x_real_ssl_protocol, add_x_real_ssl_cipher, add_x_cache_status,
            deny_referer_regexp, add_x_request_user_agent, add_reporting_endpoints,
            add_x_request_byte_count, add_x_request_received_at,
            strip_request_headers, add_x_forwarded_method, add_x_request_original_host,
            add_x_request_dnt, add_x_geo_region, add_x_request_secure,
            add_x_request_query_count, add_x_request_id_header_response,
            force_canonical_host, add_x_robots_noindex_quick, block_bot_user_agents,
            block_admin_paths, add_link_dns_prefetch, add_link_preconnect,
            add_x_csp_disabled, add_x_request_method_override, proxy_redirect_rules,
            additional_upstream_rules, disable_upstream_compression)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID,
		p.Domains, p.ForwardScheme, p.ForwardHost, p.ForwardPort,
		boolInt(p.WebsocketSupport), boolInt(p.BlockCommonExploits),
		boolInt(p.SSLEnabled), boolInt(p.SSLForced), boolInt(p.HTTP2Support),
		p.AdvancedConfig, boolInt(p.Enabled), nilIfZero(p.CertificateID),
		boolInt(p.BasicAuthEnabled), p.BasicAuthUsers,
		p.AccessList, p.ExtraUpstreams,
		nilIfZero(ownerID),
		p.DNSProvider, p.DNSZoneID, p.DNSZoneName, p.DNSRecordID,
		boolInt(p.CompressionEnabled), boolInt(p.SecurityHeadersEnabled), p.TLSMinVersion,
		p.CustomReqHeaders, p.CustomRespHeaders, p.URLRewrites, boolInt(p.MaintenanceMode), p.MaintenanceMsg,
		p.MaxRequestBodyMB, boolInt(p.StickySessions), p.UpstreamTimeoutSec,
		boolInt(p.CORSEnabled), p.CORSOrigins,
		p.HealthCheckURI, p.HealthCheckIntervalSec, p.KeepaliveConns,
		p.Tags, p.Notes, boolInt(p.DisableAccessLog),
		boolInt(p.AddRequestID), p.StripRespHeaders, p.BlockedAgents, p.HealthCheckMethod,
		p.MaintenanceStatusCode, p.ResponseCacheControl,
		p.UpstreamSNI, boolInt(p.HSTSPreload), p.MaxConnsPerHost,
		p.HealthCheckTimeoutSec, p.UpstreamRetries,
		boolInt(p.ForceHTTP1), p.BasicAuthRealm, p.ErrorPageHTML,
		p.MaintenanceWindowStart, p.MaintenanceWindowEnd, p.MaintenanceWindowDays,
		p.IPBlocklist, p.LBPolicy, p.ProxyProtocol, p.RobotsTxt,
		p.PassiveFailDurationSec, p.PassiveMaxFails,
		p.HSTSMaxAgeSec, p.CSPHeader,
		boolInt(p.H2CEnabled), p.HealthCheckHeaders,
		boolInt(p.FlushImmediate), boolInt(p.BufferResponses), p.TrustedProxies,
		p.UpstreamHostOverride, p.ReadTimeoutSec, boolInt(p.DenyDotfiles),
		p.RequestBuffersKB, boolInt(p.CORSAllowCredentials), p.CORSExposeHeaders,
		boolInt(p.SSLVerifyUpstream), p.DialTimeoutSec,
		p.APIKeyHeader, p.APIKeyValue, boolInt(p.BlockEmptyUserAgent),
		p.ErrorRedirectURL, p.PermissionsPolicy, p.XFrameOptions, p.ReferrerPolicy,
		boolInt(p.HSTSIncludeSubdomains), p.CSPReportOnly, p.KeepaliveIdleTimeoutSec,
		p.HealthCheckExpectStatus, p.HealthCheckExpectBody, boolInt(p.HealthCheckFollowRedirects),
		p.PathMatcher, boolInt(p.StripPathPrefix),
		p.StickyCookieName, p.LBTryDurationSec, p.LBTryIntervalMS,
		p.CompressionMinSizeKB, boolInt(p.ForwardClientIP),
		p.CORSMaxAgeSec, p.CORSAllowMethods, p.CORSAllowHeaders,
		p.RetryStatusCodes, p.WriteTimeoutSec,
		p.UpstreamTLSMinVersion, p.ForwardProxyURL,
		p.BlockedMethods, p.ForwardAuthURL, p.ForwardAuthCopyHeaders,
		boolInt(p.StripQueryString), p.DeleteQueryParams,
		p.RequestBodyReadTimeoutSec, p.ResponseHeaderTimeoutSec,
		p.MaxConnDurationSec, boolInt(p.DecompressResponse), p.Color, p.WWWRedirect,
		p.StripReqHeaders, p.UpstreamPathPrefix,
		p.CompressionLevel, boolInt(p.CompressionPreferGzip), p.SortOrder,
		p.AllowedMethods, p.UpstreamMaxRespHeaderKB, p.HealthCheckPort,
		p.RequestIDHeaderName, p.LBCookiePath, p.PassiveUnhealthyLatencyMS,
		p.TLSHandshakeTimeoutSec, p.ExpectContinueTimeoutSec, p.ResponseBuffersKB,
		p.UpstreamMaxIdleConns, p.UpstreamKeepAliveProbeIntervalSec, p.ForwardAuthMethod,
		boolInt(p.GRPCWebEnabled), p.ForwardAuthHeadersPrefix, p.HealthCheckMaxSizeKB,
		p.StripPathSuffix, p.AddReqQueryParams, p.ErrorPageCodes,
		p.UpstreamTLSCAPEMFile, boolInt(p.KeepaliveDisabled), p.TrailingSlashRedirect,
		p.DialFallbackDelayMS, p.UpstreamNetwork, p.DNSResolver,
		p.PathMatcherType, boolInt(p.CORSAllowPrivateNetwork), boolInt(p.RobotsTxtDisallowAll),
		p.MaintenanceRetryAfterSec, p.UpstreamResolveTimeoutSec, p.UpstreamReadBufferSizeKB,
		p.UpstreamWriteBufferSizeKB, p.ReqHeaderReplace, p.RespHeaderReplace,
		p.UpstreamHTTPVersions, p.HealthCheckBody, boolInt(p.AddCanonicalLinkHeader),
		p.HTTPBasicAuthUpstream, p.BlockUARegexp, p.SecurityTxtBody,
		p.ServerHeaderValue, p.XRobotsTag, boolInt(p.AddForwardedHeader),
		p.LBCookieSecret, p.PassiveUnhealthyStatusCodes, p.HealthCheckContentType,
		p.UpstreamTLSClientCertFile, p.UpstreamTLSClientKeyFile, boolInt(p.BlockPrivateIPs),
		boolInt(p.EnableBrotli), p.VaryHeader, boolInt(p.StripETag),
		p.HTTP2PushPaths, p.DenyContentTypes, p.UpstreamLocalAddr,
		p.UpstreamTLSRenegotiation, p.UpstreamTLSCurves, p.UpstreamTLSMaxVersion,
		p.UpstreamTLSPins, p.LBHeaderField, p.MaintenanceCustomHeaders,
		p.DenyExtensions, boolInt(p.InjectRequestTimestamp), p.AddRespCookies,
		boolInt(p.StripAcceptEncoding), boolInt(p.AddUpstreamTimingHeader), boolInt(p.StripServerHeader),
		p.BlockRefererRegexp, boolInt(p.AddContentTypeNosniff), boolInt(p.StripAuthorizationHeader),
		p.RealIPFromHeader, p.HealthCheckHostOverride, boolInt(p.AddXForwardedPort),
		p.LBRetryOn, p.MaxBufferSizeKB, p.UpstreamKeepaliveProbes,
		p.UpstreamFlushIntervalMS, boolInt(p.AddXForwardedHost), p.MaintenanceAllowedIPs,
		p.UpstreamTLSCipherSuites, boolInt(p.AddCacheControlNoStore), boolInt(p.DenyRefererEmpty),
		boolInt(p.LBCookieHTTPOnly), boolInt(p.LBCookieSecure), p.LBCookieSameSite,
		boolInt(p.UpstreamTLSEarlyData), boolInt(p.AddViaHeader), p.ReqHeaderRename,
		boolInt(p.AddExpectCTHeader), p.ForceUpstreamEncoding, p.PassiveUnhealthyCount,
		boolInt(p.StripXPoweredBy), p.AddTimingAllowOrigin, p.LBCookieMaxAgeSec,
		p.CrossOriginOpenerPolicy, p.CrossOriginResourcePolicy, p.CrossOriginEmbedderPolicy,
		p.DenyRequestContentType, p.CompressionExcludeRegexp, boolInt(p.AddCacheControlPublic),
		boolInt(p.AddXRequestStart), p.MaintenanceWindowTimezone, p.LBRandomChooseCount,
		boolInt(p.AddXForwardedScheme), p.ResponseCacheTTLSec, p.AddLinkPreload,
		p.DenyPathRegexp, boolInt(p.AddRequestIDToResponse), p.HealthCheckTLSServerName,
		boolInt(p.AddXRealIP), boolInt(p.StripIncomingXForwardedFor), boolInt(p.HealthCheckTLSInsecureSkipVerify),
		boolInt(p.AddCORSVaryHeader), p.UpstreamTLSALPN, p.AddXPoweredBy,
		p.BlockQueryParams, p.AddDocumentPolicy, p.MaintenanceRedirectURL,
		p.UpstreamKeepaliveMaxLifetimeSec, p.AddOriginHeader, p.UpstreamTLSCAPEMInline,
		boolInt(p.AddServerTimingHeader), p.AddClearSiteData, boolInt(p.AddXDNSPrefetchControl),
		boolInt(p.AddAcceptRanges), p.AddContentDisposition, boolInt(p.UpstreamTLSServerNameFromHost),
		p.AddXPermittedCrossDomainPolicies, p.StripResponseHeaders, p.AddReportTo,
		p.AddNELHeader, p.BlockHTTPMethods, p.AddServiceWorkerAllowed,
		p.AddAcceptCH, p.AddAltSvc, p.AddContentLanguage,
		p.AddCriticalCH, boolInt(p.AddXDownloadOptions), p.DenyUserAgentRegexp,
		boolInt(p.AddPragmaNoCache), p.HealthCheckUserAgent, boolInt(p.AddXRequestPath),
		p.AddXClacksOverhead, p.AddXUACompatible, p.ForwardAuthSkipPaths,
		boolInt(p.AddAgeZero), p.AddSurrogateControl, p.AddWarningHeader,
		boolInt(p.AddXRequestMethod), boolInt(p.AddXRequestQuery), p.AddXForwardedUser,
		boolInt(p.AddXRealScheme), boolInt(p.AddOriginAgentCluster), p.AddXForwardedGroups,
		p.AddXForwardedEmail, p.AddXForwardedRoles, p.BlockQueryParamRegexp,
		boolInt(p.AddXRequestReferer), boolInt(p.AddXRequestOrigin), boolInt(p.AddXForwardedURI),
		boolInt(p.AddXNoArchive), boolInt(p.AddXRequestHostname), boolInt(p.AddXXSSProtectionDisabled),
		boolInt(p.AddXRequestRemotePort), boolInt(p.AddXRequestProtocol), boolInt(p.AddSaveDataVary),
		p.AddXEnvironment, boolInt(p.AddXTraceID), p.HealthCheckQueryParams,
		boolInt(p.AddXSessionID), boolInt(p.AddXResponseTraceID), boolInt(p.AddXRequestLocalAddr),
		boolInt(p.AddXRequestLocalPort), boolInt(p.AddXRequestPathInfo),
		p.AddXAuthenticatedUser, p.BlockPathExtensions, p.AddLinkModulePreload,
		p.AddXRemoteUser, boolInt(p.AddXForwardedPath), p.AddXGeoCountryCode,
		p.AddXRequestPriority, p.HealthCheckBasicAuth,
		boolInt(p.AddXRealSSLProtocol), boolInt(p.AddXRealSSLCipher), p.AddXCacheStatus,
		p.DenyRefererRegexp, boolInt(p.AddXRequestUserAgent), p.AddReportingEndpoints,
		boolInt(p.AddXRequestByteCount), boolInt(p.AddXRequestReceivedAt),
		p.StripRequestHeaders, boolInt(p.AddXForwardedMethod), boolInt(p.AddXRequestOriginalHost),
		boolInt(p.AddXRequestDNT), p.AddXGeoRegion, boolInt(p.AddXRequestSecure),
		boolInt(p.AddXRequestQueryCount), boolInt(p.AddXRequestIDHeaderResponse),
		p.ForceCanonicalHost, boolInt(p.AddXRobotsNoindexQuick), boolInt(p.BlockBotUserAgents),
		boolInt(p.BlockAdminPaths), p.AddLinkDNSPrefetch, p.AddLinkPreconnect,
		boolInt(p.AddXCSPDisabled), boolInt(p.AddXRequestMethodOverride),
		p.ProxyRedirectRules,
		p.AdditionalUpstreamRules,
		boolInt(p.DisableUpstreamCompression), // v2.12.52
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateProxyHost(db *sql.DB, p *ProxyHost) error {
	if p.ForwardScheme == "" {
		p.ForwardScheme = "http"
	}
	if p.BasicAuthUsers == "" {
		p.BasicAuthUsers = "[]"
	}
	if p.ExtraUpstreams == "" {
		p.ExtraUpstreams = "[]"
	}
	if p.CustomReqHeaders == "" {
		p.CustomReqHeaders = "{}"
	}
	if p.CustomRespHeaders == "" {
		p.CustomRespHeaders = "{}"
	}
	if p.URLRewrites == "" {
		p.URLRewrites = "[]"
	}
	_, err := db.Exec(`
        UPDATE proxy_hosts SET domains=?, forward_scheme=?, forward_host=?, forward_port=?,
            websocket_support=?, block_common_exploits=?, ssl_enabled=?, ssl_forced=?,
            http2_support=?, advanced_config=?, enabled=?, certificate_id=?,
            basicauth_enabled=?, basicauth_users=?,
            access_list=?, extra_upstreams=?,
            dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
            compression_enabled=?, security_headers_enabled=?, tls_min_version=?,
            custom_req_headers=?, custom_resp_headers=?, url_rewrites=?,
            maintenance_mode=?, maintenance_msg=?, max_request_body_mb=?, sticky_sessions=?,
            upstream_timeout_sec=?, cors_enabled=?, cors_origins=?,
            health_check_uri=?, health_check_interval_sec=?, keepalive_conns=?,
            tags=?, notes=?, disable_access_log=?,
            add_request_id=?, strip_resp_headers=?, blocked_agents=?,
            health_check_method=?,
            maintenance_status_code=?,
            response_cache_control=?,
            upstream_sni=?,
            hsts_preload=?,
            max_conns_per_host=?,
            health_check_timeout_sec=?,
            upstream_retries=?,
            force_http1=?,
            basicauth_realm=?,
            error_page_html=?,
            maintenance_window_start=?, maintenance_window_end=?, maintenance_window_days=?,
            ip_blocklist=?,
            lb_policy=?,
            proxy_protocol=?,
            robots_txt=?,
            passive_fail_duration_sec=?,
            passive_max_fails=?,
            hsts_max_age_sec=?,
            csp_header=?,
            h2c_enabled=?,
            health_check_headers=?,
            flush_immediate=?,
            buffer_responses=?,
            trusted_proxies=?,
            upstream_host_override=?,
            read_timeout_sec=?,
            deny_dotfiles=?,
            request_buffers_kb=?,
            cors_allow_credentials=?,
            cors_expose_headers=?,
            ssl_verify_upstream=?,
            dial_timeout_sec=?,
            api_key_header=?,
            api_key_value=?,
            block_empty_user_agent=?,
            error_redirect_url=?,
            permissions_policy=?,
            x_frame_options=?,
            referrer_policy=?,
            hsts_include_subdomains=?,
            csp_report_only=?,
            keepalive_idle_timeout_sec=?,
            health_check_expect_status=?,
            health_check_expect_body=?,
            health_check_follow_redirects=?,
            path_matcher=?,
            strip_path_prefix=?,
            sticky_cookie_name=?,
            lb_try_duration_sec=?,
            lb_try_interval_ms=?,
            compression_min_size_kb=?,
            forward_client_ip=?,
            cors_max_age_sec=?,
            cors_allow_methods=?,
            cors_allow_headers=?,
            retry_status_codes=?,
            write_timeout_sec=?,
            upstream_tls_min_version=?,
            forward_proxy_url=?,
            blocked_methods=?,
            forward_auth_url=?,
            forward_auth_copy_headers=?,
            strip_query_string=?,
            delete_query_params=?,
            request_body_read_timeout_sec=?,
            response_header_timeout_sec=?,
            max_conn_duration_sec=?,
            decompress_response=?,
            color=?,
            www_redirect=?,
            strip_req_headers=?,
            upstream_path_prefix=?,
            compression_level=?,
            compression_prefer_gzip=?,
            sort_order=?,
            allowed_methods=?,
            upstream_max_resp_header_kb=?,
            health_check_port=?,
            request_id_header_name=?,
            lb_cookie_path=?,
            passive_unhealthy_latency_ms=?,
            tls_handshake_timeout_sec=?,
            expect_continue_timeout_sec=?,
            response_buffers_kb=?,
            upstream_max_idle_conns=?,
            upstream_keep_alive_probe_sec=?,
            forward_auth_method=?,
            grpc_web_enabled=?,
            forward_auth_headers_prefix=?,
            health_check_max_size_kb=?,
            strip_path_suffix=?,
            add_req_query_params=?,
            error_page_codes=?,
            upstream_tls_ca_pem_file=?,
            keepalive_disabled=?,
            trailing_slash_redirect=?,
            dial_fallback_delay_ms=?,
            upstream_network=?,
            dns_resolver=?,
            path_matcher_type=?,
            cors_allow_private_network=?,
            robots_txt_disallow_all=?,
            maintenance_retry_after_sec=?,
            upstream_resolve_timeout_sec=?,
            upstream_read_buffer_size_kb=?,
            upstream_write_buffer_size_kb=?,
            req_header_replace=?,
            resp_header_replace=?,
            upstream_http_versions=?,
            health_check_body=?,
            add_canonical_link_header=?,
            http_basic_auth_upstream=?,
            block_ua_regexp=?,
            security_txt_body=?,
            server_header_value=?,
            x_robots_tag=?,
            add_forwarded_header=?,
            lb_cookie_secret=?,
            passive_unhealthy_status_codes=?,
            health_check_content_type=?,
            upstream_tls_client_cert_file=?,
            upstream_tls_client_key_file=?,
            block_private_ips=?,
            enable_brotli=?,
            vary_header=?,
            strip_etag=?,
            http2_push_paths=?,
            deny_content_types=?,
            upstream_local_addr=?,
            upstream_tls_renegotiation=?,
            upstream_tls_curves=?,
            upstream_tls_max_version=?,
            upstream_tls_pins=?,
            lb_header_field=?,
            maintenance_custom_headers=?,
            deny_extensions=?,
            inject_request_timestamp=?,
            add_resp_cookies=?,
            strip_accept_encoding=?,
            add_upstream_timing_header=?,
            strip_server_header=?,
            block_referer_regexp=?,
            add_content_type_nosniff=?,
            strip_authorization_header=?,
            real_ip_from_header=?,
            health_check_host_override=?,
            add_x_forwarded_port=?,
            lb_retry_on=?,
            max_buffer_size_kb=?,
            upstream_keepalive_probes=?,
            upstream_flush_interval_ms=?,
            add_x_forwarded_host=?,
            maintenance_allowed_ips=?,
            upstream_tls_cipher_suites=?,
            add_cache_control_no_store=?,
            deny_referer_empty=?,
            lb_cookie_httponly=?,
            lb_cookie_secure=?,
            lb_cookie_same_site=?,
            upstream_tls_early_data=?,
            add_via_header=?,
            req_header_rename=?,
            add_expect_ct_header=?,
            force_upstream_encoding=?,
            passive_unhealthy_count=?,
            strip_x_powered_by=?,
            add_timing_allow_origin=?,
            lb_cookie_max_age_sec=?,
            cross_origin_opener_policy=?,
            cross_origin_resource_policy=?,
            cross_origin_embedder_policy=?,
            deny_request_content_type=?,
            compression_exclude_regexp=?,
            add_cache_control_public=?,
            add_x_request_start=?,
            maintenance_window_timezone=?,
            lb_random_choose_count=?,
            add_x_forwarded_scheme=?,
            response_cache_ttl_sec=?,
            add_link_preload=?,
            deny_path_regexp=?,
            add_request_id_to_response=?,
            health_check_tls_server_name=?,
            add_x_real_ip=?,
            strip_incoming_x_forwarded_for=?,
            health_check_tls_insecure_skip_verify=?,
            add_cors_vary_header=?,
            upstream_tls_alpn=?,
            add_x_powered_by=?,
            block_query_params=?,
            add_document_policy=?,
            maintenance_redirect_url=?,
            upstream_keepalive_max_lifetime_sec=?,
            add_origin_header=?,
            upstream_tls_ca_pem_inline=?,
            add_server_timing_header=?,
            add_clear_site_data=?,
            add_x_dns_prefetch_control=?,
            add_accept_ranges=?,
            add_content_disposition=?,
            upstream_tls_server_name_from_host=?,
            add_x_permitted_cross_domain_policies=?,
            strip_response_headers=?,
            add_report_to=?,
            add_nel_header=?,
            block_http_methods=?,
            add_service_worker_allowed=?,
            add_accept_ch=?,
            add_alt_svc=?,
            add_content_language=?,
            add_critical_ch=?,
            add_x_download_options=?,
            deny_user_agent_regexp=?,
            add_pragma_no_cache=?,
            health_check_user_agent=?,
            add_x_request_path=?,
            add_x_clacks_overhead=?,
            add_x_ua_compatible=?,
            forward_auth_skip_paths=?,
            add_age_zero=?,
            add_surrogate_control=?,
            add_warning_header=?,
            add_x_request_method=?,
            add_x_request_query=?,
            add_x_forwarded_user=?,
            add_x_real_scheme=?,
            add_origin_agent_cluster=?,
            add_x_forwarded_groups=?,
            add_x_forwarded_email=?,
            add_x_forwarded_roles=?,
            block_query_param_regexp=?,
            add_x_request_referer=?,
            add_x_request_origin=?,
            add_x_forwarded_uri=?,
            add_x_no_archive=?,
            add_x_request_hostname=?,
            add_x_xss_protection_disabled=?,
            add_x_request_remote_port=?,
            add_x_request_protocol=?,
            add_save_data_vary=?,
            add_x_environment=?,
            add_x_trace_id=?,
            health_check_query_params=?,
            add_x_session_id=?,
            add_x_response_trace_id=?,
            add_x_request_local_addr=?,
            add_x_request_local_port=?,
            add_x_request_path_info=?,
            add_x_authenticated_user=?,
            block_path_extensions=?,
            add_link_modulepreload=?,
            add_x_remote_user=?,
            add_x_forwarded_path=?,
            add_x_geo_country_code=?,
            add_x_request_priority=?,
            health_check_basic_auth=?,
            add_x_real_ssl_protocol=?,
            add_x_real_ssl_cipher=?,
            add_x_cache_status=?,
            deny_referer_regexp=?,
            add_x_request_user_agent=?,
            add_reporting_endpoints=?,
            add_x_request_byte_count=?,
            add_x_request_received_at=?,
            strip_request_headers=?,
            add_x_forwarded_method=?,
            add_x_request_original_host=?,
            add_x_request_dnt=?,
            add_x_geo_region=?,
            add_x_request_secure=?,
            add_x_request_query_count=?,
            add_x_request_id_header_response=?,
            force_canonical_host=?,
            add_x_robots_noindex_quick=?,
            block_bot_user_agents=?,
            block_admin_paths=?,
            add_link_dns_prefetch=?,
            add_link_preconnect=?,
            add_x_csp_disabled=?,
            add_x_request_method_override=?,
            proxy_redirect_rules=?,
            additional_upstream_rules=?,
            disable_upstream_compression=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id = ?`,
		p.Domains, p.ForwardScheme, p.ForwardHost, p.ForwardPort,
		boolInt(p.WebsocketSupport), boolInt(p.BlockCommonExploits),
		boolInt(p.SSLEnabled), boolInt(p.SSLForced), boolInt(p.HTTP2Support),
		p.AdvancedConfig, boolInt(p.Enabled), nilIfZero(p.CertificateID),
		boolInt(p.BasicAuthEnabled), p.BasicAuthUsers,
		p.AccessList, p.ExtraUpstreams,
		p.DNSProvider, p.DNSZoneID, p.DNSZoneName, p.DNSRecordID,
		boolInt(p.CompressionEnabled), boolInt(p.SecurityHeadersEnabled), p.TLSMinVersion,
		p.CustomReqHeaders, p.CustomRespHeaders, p.URLRewrites,
		boolInt(p.MaintenanceMode), p.MaintenanceMsg, p.MaxRequestBodyMB, boolInt(p.StickySessions),
		p.UpstreamTimeoutSec, boolInt(p.CORSEnabled), p.CORSOrigins,
		p.HealthCheckURI, p.HealthCheckIntervalSec, p.KeepaliveConns,
		p.Tags, p.Notes, boolInt(p.DisableAccessLog),
		boolInt(p.AddRequestID), p.StripRespHeaders, p.BlockedAgents,
		p.HealthCheckMethod,
		p.MaintenanceStatusCode,
		p.ResponseCacheControl,
		p.UpstreamSNI,
		boolInt(p.HSTSPreload),
		p.MaxConnsPerHost,
		p.HealthCheckTimeoutSec,
		p.UpstreamRetries,
		boolInt(p.ForceHTTP1),
		p.BasicAuthRealm,
		p.ErrorPageHTML,
		p.MaintenanceWindowStart, p.MaintenanceWindowEnd, p.MaintenanceWindowDays,
		p.IPBlocklist,
		p.LBPolicy,
		p.ProxyProtocol,
		p.RobotsTxt,
		p.PassiveFailDurationSec,
		p.PassiveMaxFails,
		p.HSTSMaxAgeSec,
		p.CSPHeader,
		boolInt(p.H2CEnabled),
		p.HealthCheckHeaders,
		boolInt(p.FlushImmediate),
		boolInt(p.BufferResponses),
		p.TrustedProxies,
		p.UpstreamHostOverride,
		p.ReadTimeoutSec,
		boolInt(p.DenyDotfiles),
		p.RequestBuffersKB,
		boolInt(p.CORSAllowCredentials),
		p.CORSExposeHeaders,
		boolInt(p.SSLVerifyUpstream),
		p.DialTimeoutSec,
		p.APIKeyHeader,
		p.APIKeyValue,
		boolInt(p.BlockEmptyUserAgent),
		p.ErrorRedirectURL,
		p.PermissionsPolicy,
		p.XFrameOptions,
		p.ReferrerPolicy,
		boolInt(p.HSTSIncludeSubdomains),
		p.CSPReportOnly,
		p.KeepaliveIdleTimeoutSec,
		p.HealthCheckExpectStatus,
		p.HealthCheckExpectBody,
		boolInt(p.HealthCheckFollowRedirects),
		p.PathMatcher,
		boolInt(p.StripPathPrefix),
		p.StickyCookieName,
		p.LBTryDurationSec,
		p.LBTryIntervalMS,
		p.CompressionMinSizeKB,
		boolInt(p.ForwardClientIP),
		p.CORSMaxAgeSec,
		p.CORSAllowMethods,
		p.CORSAllowHeaders,
		p.RetryStatusCodes,
		p.WriteTimeoutSec,
		p.UpstreamTLSMinVersion,
		p.ForwardProxyURL,
		p.BlockedMethods,
		p.ForwardAuthURL,
		p.ForwardAuthCopyHeaders,
		boolInt(p.StripQueryString),
		p.DeleteQueryParams,
		p.RequestBodyReadTimeoutSec,
		p.ResponseHeaderTimeoutSec,
		p.MaxConnDurationSec,
		boolInt(p.DecompressResponse),
		p.Color,
		p.WWWRedirect,
		p.StripReqHeaders,
		p.UpstreamPathPrefix,
		p.CompressionLevel,
		boolInt(p.CompressionPreferGzip),
		p.SortOrder,
		p.AllowedMethods,
		p.UpstreamMaxRespHeaderKB,
		p.HealthCheckPort,
		p.RequestIDHeaderName,
		p.LBCookiePath,
		p.PassiveUnhealthyLatencyMS,
		p.TLSHandshakeTimeoutSec,
		p.ExpectContinueTimeoutSec,
		p.ResponseBuffersKB,
		p.UpstreamMaxIdleConns,
		p.UpstreamKeepAliveProbeIntervalSec,
		p.ForwardAuthMethod,
		boolInt(p.GRPCWebEnabled),
		p.ForwardAuthHeadersPrefix,
		p.HealthCheckMaxSizeKB,
		p.StripPathSuffix,
		p.AddReqQueryParams,
		p.ErrorPageCodes,
		p.UpstreamTLSCAPEMFile,
		boolInt(p.KeepaliveDisabled),
		p.TrailingSlashRedirect,
		p.DialFallbackDelayMS,
		p.UpstreamNetwork,
		p.DNSResolver,
		p.PathMatcherType,
		boolInt(p.CORSAllowPrivateNetwork),
		boolInt(p.RobotsTxtDisallowAll),
		p.MaintenanceRetryAfterSec,
		p.UpstreamResolveTimeoutSec,
		p.UpstreamReadBufferSizeKB,
		p.UpstreamWriteBufferSizeKB,
		p.ReqHeaderReplace,
		p.RespHeaderReplace,
		p.UpstreamHTTPVersions,
		p.HealthCheckBody,
		boolInt(p.AddCanonicalLinkHeader),
		p.HTTPBasicAuthUpstream,
		p.BlockUARegexp,
		p.SecurityTxtBody,
		p.ServerHeaderValue,
		p.XRobotsTag,
		boolInt(p.AddForwardedHeader),
		p.LBCookieSecret,
		p.PassiveUnhealthyStatusCodes,
		p.HealthCheckContentType,
		p.UpstreamTLSClientCertFile,
		p.UpstreamTLSClientKeyFile,
		boolInt(p.BlockPrivateIPs),
		boolInt(p.EnableBrotli),
		p.VaryHeader,
		boolInt(p.StripETag),
		p.HTTP2PushPaths,
		p.DenyContentTypes,
		p.UpstreamLocalAddr,
		p.UpstreamTLSRenegotiation,
		p.UpstreamTLSCurves,
		p.UpstreamTLSMaxVersion,
		p.UpstreamTLSPins,
		p.LBHeaderField,
		p.MaintenanceCustomHeaders,
		p.DenyExtensions,
		boolInt(p.InjectRequestTimestamp),
		p.AddRespCookies,
		boolInt(p.StripAcceptEncoding),
		boolInt(p.AddUpstreamTimingHeader),
		boolInt(p.StripServerHeader),
		p.BlockRefererRegexp,
		boolInt(p.AddContentTypeNosniff),
		boolInt(p.StripAuthorizationHeader),
		p.RealIPFromHeader,
		p.HealthCheckHostOverride,
		boolInt(p.AddXForwardedPort),
		p.LBRetryOn,
		p.MaxBufferSizeKB,
		p.UpstreamKeepaliveProbes,
		p.UpstreamFlushIntervalMS,
		boolInt(p.AddXForwardedHost),
		p.MaintenanceAllowedIPs,
		p.UpstreamTLSCipherSuites,
		boolInt(p.AddCacheControlNoStore),
		boolInt(p.DenyRefererEmpty),
		boolInt(p.LBCookieHTTPOnly),
		boolInt(p.LBCookieSecure),
		p.LBCookieSameSite,
		boolInt(p.UpstreamTLSEarlyData),
		boolInt(p.AddViaHeader),
		p.ReqHeaderRename,
		boolInt(p.AddExpectCTHeader),
		p.ForceUpstreamEncoding,
		p.PassiveUnhealthyCount,
		boolInt(p.StripXPoweredBy),
		p.AddTimingAllowOrigin,
		p.LBCookieMaxAgeSec,
		p.CrossOriginOpenerPolicy,
		p.CrossOriginResourcePolicy,
		p.CrossOriginEmbedderPolicy,
		p.DenyRequestContentType,
		p.CompressionExcludeRegexp,
		boolInt(p.AddCacheControlPublic),
		boolInt(p.AddXRequestStart),
		p.MaintenanceWindowTimezone,
		p.LBRandomChooseCount,
		boolInt(p.AddXForwardedScheme),
		p.ResponseCacheTTLSec,
		p.AddLinkPreload,
		p.DenyPathRegexp,
		boolInt(p.AddRequestIDToResponse),
		p.HealthCheckTLSServerName,
		boolInt(p.AddXRealIP),
		boolInt(p.StripIncomingXForwardedFor),
		boolInt(p.HealthCheckTLSInsecureSkipVerify),
		boolInt(p.AddCORSVaryHeader),
		p.UpstreamTLSALPN,
		p.AddXPoweredBy,
		p.BlockQueryParams,
		p.AddDocumentPolicy,
		p.MaintenanceRedirectURL,
		p.UpstreamKeepaliveMaxLifetimeSec,
		p.AddOriginHeader,
		p.UpstreamTLSCAPEMInline,
		boolInt(p.AddServerTimingHeader),
		p.AddClearSiteData,
		boolInt(p.AddXDNSPrefetchControl),
		boolInt(p.AddAcceptRanges),
		p.AddContentDisposition,
		boolInt(p.UpstreamTLSServerNameFromHost),
		p.AddXPermittedCrossDomainPolicies,
		p.StripResponseHeaders,
		p.AddReportTo,
		p.AddNELHeader,
		p.BlockHTTPMethods,
		p.AddServiceWorkerAllowed,
		p.AddAcceptCH,
		p.AddAltSvc,
		p.AddContentLanguage,
		p.AddCriticalCH,
		boolInt(p.AddXDownloadOptions),
		p.DenyUserAgentRegexp,
		boolInt(p.AddPragmaNoCache),
		p.HealthCheckUserAgent,
		boolInt(p.AddXRequestPath),
		p.AddXClacksOverhead,
		p.AddXUACompatible,
		p.ForwardAuthSkipPaths,
		boolInt(p.AddAgeZero),
		p.AddSurrogateControl,
		p.AddWarningHeader,
		boolInt(p.AddXRequestMethod),
		boolInt(p.AddXRequestQuery),
		p.AddXForwardedUser,
		boolInt(p.AddXRealScheme),
		boolInt(p.AddOriginAgentCluster),
		p.AddXForwardedGroups,
		p.AddXForwardedEmail,
		p.AddXForwardedRoles,
		p.BlockQueryParamRegexp,
		boolInt(p.AddXRequestReferer),
		boolInt(p.AddXRequestOrigin),
		boolInt(p.AddXForwardedURI),
		boolInt(p.AddXNoArchive),
		boolInt(p.AddXRequestHostname),
		boolInt(p.AddXXSSProtectionDisabled),
		boolInt(p.AddXRequestRemotePort),
		boolInt(p.AddXRequestProtocol),
		boolInt(p.AddSaveDataVary),
		p.AddXEnvironment,
		boolInt(p.AddXTraceID),
		p.HealthCheckQueryParams,
		boolInt(p.AddXSessionID),
		boolInt(p.AddXResponseTraceID),
		boolInt(p.AddXRequestLocalAddr),
		boolInt(p.AddXRequestLocalPort),
		boolInt(p.AddXRequestPathInfo),
		p.AddXAuthenticatedUser,
		p.BlockPathExtensions,
		p.AddLinkModulePreload,
		p.AddXRemoteUser,
		boolInt(p.AddXForwardedPath),
		p.AddXGeoCountryCode,
		p.AddXRequestPriority,
		p.HealthCheckBasicAuth,
		boolInt(p.AddXRealSSLProtocol),
		boolInt(p.AddXRealSSLCipher),
		p.AddXCacheStatus,
		p.DenyRefererRegexp,
		boolInt(p.AddXRequestUserAgent),
		p.AddReportingEndpoints,
		boolInt(p.AddXRequestByteCount),
		boolInt(p.AddXRequestReceivedAt),
		p.StripRequestHeaders,
		boolInt(p.AddXForwardedMethod),
		boolInt(p.AddXRequestOriginalHost),
		boolInt(p.AddXRequestDNT),
		p.AddXGeoRegion,
		boolInt(p.AddXRequestSecure),
		boolInt(p.AddXRequestQueryCount),
		boolInt(p.AddXRequestIDHeaderResponse),
		p.ForceCanonicalHost,
		boolInt(p.AddXRobotsNoindexQuick),
		boolInt(p.BlockBotUserAgents),
		boolInt(p.BlockAdminPaths),
		p.AddLinkDNSPrefetch,
		p.AddLinkPreconnect,
		boolInt(p.AddXCSPDisabled),
		boolInt(p.AddXRequestMethodOverride),
		p.ProxyRedirectRules,
		p.AdditionalUpstreamRules,
		boolInt(p.DisableUpstreamCompression), // v2.12.52
		p.ID,
	)
	return err
}

// SetProxyHostOwner reassigns a proxy host to a new owner. ownerID == 0
// means global/admin (stored as NULL); >0 means that user's uploads bucket.
// v2.7.3: admin-only feature for handing off a host to a customer after
// initial provisioning. Kept separate from UpdateProxyHost so the regular
// edit path — which is callable by a user-role account — can never alter
// ownership. Handler enforces the role gate before calling this.
func SetProxyHostOwner(db *sql.DB, id int64, ownerID int64) error {
	_, err := db.Exec(`UPDATE proxy_hosts SET owner_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		nilIfZero(ownerID), id)
	return err
}

// UpdateProxyHostDNSRecord persists the record ID + zone identifier after
// a successful provider create/delete. Kept as a minimal UPDATE (instead
// of round-tripping the full proxy host) so the IP-retarget goroutine and
// the post-create hook can both use it without racing the main form save.
//
// Pass empty strings for all four fields to clear DNS management on a host.
func UpdateProxyHostDNSRecord(db *sql.DB, id int64, provider, zoneID, zoneName, recordID string) error {
	_, err := db.Exec(`UPDATE proxy_hosts
		SET dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
		    updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		provider, zoneID, zoneName, recordID, id)
	return err
}

// UpdateProxyHostDNSProfile persists the credential profile selected for
// managed DNS without touching the provider-returned record metadata.
func UpdateProxyHostDNSProfile(db *sql.DB, id int64, profileID string) error {
	_, err := db.Exec(`UPDATE proxy_hosts
		SET dns_profile_id=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		profileID, id)
	return err
}

// ListProxyHostsWithDNSRecords returns a lightweight slice of all proxy
// hosts that have an active managed DNS record. Only the fields needed for
// lifecycle management (IP retarget, bulk delete) are populated — the
// counterpart to the pre-v2.3.0 ListProxyHostsWith{CF,PB}Records helpers.
// Pass serverID > 0 to restrict to that Caddy server (for per-server IP
// retargeting); 0 means "all servers".
func ListProxyHostsWithDNSRecords(db *sql.DB, serverID int64) ([]ProxyHost, error) {
	q := `SELECT id, server_id, domains, dns_provider, dns_zone_id, dns_zone_name, dns_record_id, COALESCE(dns_profile_id,'')
		FROM proxy_hosts
		WHERE dns_provider != '' AND dns_record_id != ''`
	args := []any{}
	if serverID > 0 {
		q += ` AND server_id = ?`
		args = append(args, serverID)
	}
	q += ` ORDER BY id ASC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyHost
	for rows.Next() {
		var p ProxyHost
		if err := rows.Scan(&p.ID, &p.ServerID, &p.Domains, &p.DNSProvider, &p.DNSZoneID, &p.DNSZoneName, &p.DNSRecordID, &p.DNSProfileID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ToggleProxyHost flips the enabled flag on a proxy host and returns the new state.
func ToggleProxyHost(db *sql.DB, id int64) (bool, error) {
	if _, err := db.Exec(`UPDATE proxy_hosts SET enabled = 1 - enabled, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return false, err
	}
	var en int
	if err := db.QueryRow(`SELECT enabled FROM proxy_hosts WHERE id = ?`, id).Scan(&en); err != nil {
		return false, err
	}
	return en == 1, nil
}

// ToggleRedirectionHost flips the enabled flag on a redirection host and returns the new state.
func ToggleRedirectionHost(db *sql.DB, id int64) (bool, error) {
	if _, err := db.Exec(`UPDATE redirection_hosts SET enabled = 1 - enabled, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return false, err
	}
	var en int
	if err := db.QueryRow(`SELECT enabled FROM redirection_hosts WHERE id = ?`, id).Scan(&en); err != nil {
		return false, err
	}
	return en == 1, nil
}

// ToggleRawRoute flips the enabled flag on a raw route and returns the new state.
func ToggleRawRoute(db *sql.DB, id int64) (bool, error) {
	if _, err := db.Exec(`UPDATE raw_routes SET enabled = 1 - enabled, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return false, err
	}
	var en int
	if err := db.QueryRow(`SELECT enabled FROM raw_routes WHERE id = ?`, id).Scan(&en); err != nil {
		return false, err
	}
	return en == 1, nil
}

func DeleteProxyHost(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM proxy_hosts WHERE id = ?`, id)
	return err
}

// ListRedirectionHosts returns redirection hosts for the given server.
// If isAdmin is true, all hosts are returned with owner email via JOIN.
// If isAdmin is false, viewer sees rows they own plus rows owned by any
// peerID (group teammates, v2.7.4). peerIDs may be nil for "only my own".
func ListRedirectionHosts(db *sql.DB, serverID int64, viewerID int64, isAdmin bool, peerIDs []int64) ([]RedirectionHost, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
        SELECT rh.id, rh.domains, rh.forward_scheme, rh.forward_domain, rh.forward_http_code,
               rh.preserve_path, rh.ssl_enabled, rh.ssl_forced, rh.enabled,
               COALESCE(rh.certificate_id, 0), rh.created_at, rh.updated_at,
               COALESCE(rh.owner_id, 0), COALESCE(u.email, ''),
               COALESCE(rh.tags,''), COALESCE(rh.notes,''),
               COALESCE(rh.access_list,''), COALESCE(rh.maintenance_mode,0), COALESCE(rh.maintenance_msg,''),
               COALESCE(rh.custom_resp_headers,'{}'),
               COALESCE(rh.ip_blocklist,''),
               COALESCE(rh.hsts_max_age_sec,0), COALESCE(rh.hsts_include_subdomains,0), COALESCE(rh.hsts_preload,0),
               COALESCE(rh.advanced_config,''),
               COALESCE(rh.color,''),
               COALESCE(rh.maintenance_status_code,503),
               COALESCE(rh.sort_order,0),
               COALESCE(rh.redirect_rules,''),
               COALESCE(rh.redirect_strip_path_prefix,''),
               COALESCE(rh.redirect_wildcard_subdomain,0),
               COALESCE(rh.sunset_at,''),
               COALESCE(rh.dns_provider,''), COALESCE(rh.dns_zone_id,''),
               COALESCE(rh.dns_zone_name,''), COALESCE(rh.dns_record_id,''),
               COALESCE(rh.dns_profile_id,'')
        FROM redirection_hosts rh
        LEFT JOIN users u ON u.id = rh.owner_id
        WHERE rh.server_id = ? ORDER BY rh.sort_order ASC, rh.id DESC`, serverID)
	} else {
		inStr, inArgs := inClause(peerIDs)
		args := append([]any{serverID, viewerID}, inArgs...)
		rows, err = db.Query(`
        SELECT rh.id, rh.domains, rh.forward_scheme, rh.forward_domain, rh.forward_http_code,
               rh.preserve_path, rh.ssl_enabled, rh.ssl_forced, rh.enabled,
               COALESCE(rh.certificate_id, 0), rh.created_at, rh.updated_at,
               COALESCE(rh.owner_id, 0), COALESCE(u.email, ''),
               COALESCE(rh.tags,''), COALESCE(rh.notes,''),
               COALESCE(rh.access_list,''), COALESCE(rh.maintenance_mode,0), COALESCE(rh.maintenance_msg,''),
               COALESCE(rh.custom_resp_headers,'{}'),
               COALESCE(rh.ip_blocklist,''),
               COALESCE(rh.hsts_max_age_sec,0), COALESCE(rh.hsts_include_subdomains,0), COALESCE(rh.hsts_preload,0),
               COALESCE(rh.advanced_config,''),
               COALESCE(rh.color,''),
               COALESCE(rh.maintenance_status_code,503),
               COALESCE(rh.sort_order,0),
               COALESCE(rh.redirect_rules,''),
               COALESCE(rh.redirect_strip_path_prefix,''),
               COALESCE(rh.redirect_wildcard_subdomain,0),
               COALESCE(rh.sunset_at,''),
               COALESCE(rh.dns_provider,''), COALESCE(rh.dns_zone_id,''),
               COALESCE(rh.dns_zone_name,''), COALESCE(rh.dns_record_id,''),
               COALESCE(rh.dns_profile_id,'')
        FROM redirection_hosts rh
        LEFT JOIN users u ON u.id = rh.owner_id
        WHERE rh.server_id = ?
          AND (rh.owner_id = ? OR rh.owner_id IN (`+inStr+`))
        ORDER BY rh.sort_order ASC, rh.id DESC`, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RedirectionHost
	for rows.Next() {
		var r RedirectionHost
		var pp, ssl, sslf, en, maintMode int
		var ownerID int64
		var hstsSubdomains, hstsPreload, wildcardSub int
		if err := rows.Scan(&r.ID, &r.Domains, &r.ForwardScheme, &r.ForwardDomain,
			&r.ForwardHTTPCode, &pp, &ssl, &sslf, &en, &r.CertificateID,
			&r.CreatedAt, &r.UpdatedAt, &ownerID, &r.OwnerEmail,
			&r.Tags, &r.Notes,
			&r.AccessList, &maintMode, &r.MaintenanceMsg,
			&r.CustomRespHeaders, &r.IPBlocklist,
			&r.HSTSMaxAgeSec, &hstsSubdomains, &hstsPreload,
			&r.AdvancedConfig, &r.Color,
			&r.MaintenanceStatusCode, &r.SortOrder, &r.RedirectRules,
			&r.RedirectStripPathPrefix, &wildcardSub, &r.SunsetAt,
			&r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID, &r.DNSProfileID); err != nil {
			return nil, err
		}
		r.PreservePath = pp == 1
		r.SSLEnabled = ssl == 1
		r.SSLForced = sslf == 1
		r.Enabled = en == 1
		r.MaintenanceMode = maintMode == 1
		r.HSTSIncludeSubdomains = hstsSubdomains == 1
		r.HSTSPreload = hstsPreload == 1
		r.RedirectWildcardSubdomain = wildcardSub == 1
		if ownerID != 0 {
			r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func GetRedirectionHost(db *sql.DB, id int64) (*RedirectionHost, error) {
	var r RedirectionHost
	var pp, ssl, sslf, en, maintMode int
	var ownerID int64
	var hstsSubdomains, hstsPreload, wildcardSub int
	err := db.QueryRow(`
        SELECT id, domains, forward_scheme, forward_domain, forward_http_code,
               preserve_path, ssl_enabled, ssl_forced, enabled,
               COALESCE(certificate_id, 0), created_at, updated_at,
               COALESCE(owner_id, 0),
               COALESCE(tags,''), COALESCE(notes,''),
               COALESCE(access_list,''), COALESCE(maintenance_mode,0), COALESCE(maintenance_msg,''),
               COALESCE(custom_resp_headers,'{}'),
               COALESCE(ip_blocklist,''),
               COALESCE(hsts_max_age_sec,0), COALESCE(hsts_include_subdomains,0), COALESCE(hsts_preload,0),
               COALESCE(advanced_config,''),
               COALESCE(color,''),
               COALESCE(maintenance_status_code,503),
               COALESCE(sort_order,0),
               COALESCE(redirect_rules,''),
               COALESCE(redirect_strip_path_prefix,''),
               COALESCE(redirect_wildcard_subdomain,0),
               COALESCE(sunset_at,''),
               COALESCE(dns_provider,''), COALESCE(dns_zone_id,''),
               COALESCE(dns_zone_name,''), COALESCE(dns_record_id,''),
               COALESCE(dns_profile_id,'')
        FROM redirection_hosts WHERE id = ?`, id).Scan(
		&r.ID, &r.Domains, &r.ForwardScheme, &r.ForwardDomain, &r.ForwardHTTPCode,
		&pp, &ssl, &sslf, &en, &r.CertificateID, &r.CreatedAt, &r.UpdatedAt,
		&ownerID, &r.Tags, &r.Notes,
		&r.AccessList, &maintMode, &r.MaintenanceMsg,
		&r.CustomRespHeaders, &r.IPBlocklist,
		&r.HSTSMaxAgeSec, &hstsSubdomains, &hstsPreload,
		&r.AdvancedConfig, &r.Color,
		&r.MaintenanceStatusCode, &r.SortOrder, &r.RedirectRules,
		&r.RedirectStripPathPrefix, &wildcardSub, &r.SunsetAt,
		&r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID, &r.DNSProfileID,
	)
	if err != nil {
		return nil, err
	}
	r.PreservePath = pp == 1
	r.SSLEnabled = ssl == 1
	r.SSLForced = sslf == 1
	r.Enabled = en == 1
	r.MaintenanceMode = maintMode == 1
	r.HSTSIncludeSubdomains = hstsSubdomains == 1
	r.HSTSPreload = hstsPreload == 1
	r.RedirectWildcardSubdomain = wildcardSub == 1
	if ownerID != 0 {
		r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
	}
	return &r, nil
}

// CreateRedirectionHost inserts a new redirection host. ownerID 0 means global/admin-owned (NULL in DB).
func CreateRedirectionHost(db *sql.DB, serverID int64, ownerID int64, r *RedirectionHost) (int64, error) {
	if r.ForwardScheme == "" {
		r.ForwardScheme = "auto"
	}
	if r.ForwardHTTPCode == 0 {
		r.ForwardHTTPCode = 301
	}
	if r.CustomRespHeaders == "" {
		r.CustomRespHeaders = "{}"
	}
	if r.MaintenanceStatusCode == 0 {
		r.MaintenanceStatusCode = 503
	}
	res, err := db.Exec(`
        INSERT INTO redirection_hosts (server_id, domains, forward_scheme, forward_domain,
            forward_http_code, preserve_path, ssl_enabled, ssl_forced, enabled, certificate_id, owner_id,
            tags, notes, access_list, maintenance_mode, maintenance_msg, custom_resp_headers, ip_blocklist,
            hsts_max_age_sec, hsts_include_subdomains, hsts_preload, advanced_config, color,
            maintenance_status_code, sort_order, redirect_rules,
            redirect_strip_path_prefix, redirect_wildcard_subdomain, sunset_at,
            dns_provider, dns_zone_id, dns_zone_name, dns_record_id, dns_profile_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID,
		r.Domains, r.ForwardScheme, r.ForwardDomain, r.ForwardHTTPCode,
		boolInt(r.PreservePath), boolInt(r.SSLEnabled), boolInt(r.SSLForced),
		boolInt(r.Enabled), nilIfZero(r.CertificateID),
		nilIfZero(ownerID),
		r.Tags, r.Notes, r.AccessList, boolInt(r.MaintenanceMode), r.MaintenanceMsg,
		r.CustomRespHeaders, r.IPBlocklist,
		r.HSTSMaxAgeSec, boolInt(r.HSTSIncludeSubdomains), boolInt(r.HSTSPreload),
		r.AdvancedConfig, r.Color,
		r.MaintenanceStatusCode, r.SortOrder, r.RedirectRules,
		r.RedirectStripPathPrefix, boolInt(r.RedirectWildcardSubdomain), r.SunsetAt,
		r.DNSProvider, r.DNSZoneID, r.DNSZoneName, r.DNSRecordID, r.DNSProfileID,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateRedirectionHost(db *sql.DB, r *RedirectionHost) error {
	if r.ForwardScheme == "" {
		r.ForwardScheme = "auto"
	}
	if r.CustomRespHeaders == "" {
		r.CustomRespHeaders = "{}"
	}
	if r.MaintenanceStatusCode == 0 {
		r.MaintenanceStatusCode = 503
	}
	_, err := db.Exec(`
        UPDATE redirection_hosts SET domains=?, forward_scheme=?, forward_domain=?,
            forward_http_code=?, preserve_path=?, ssl_enabled=?, ssl_forced=?, enabled=?,
            certificate_id=?, tags=?, notes=?,
            access_list=?, maintenance_mode=?, maintenance_msg=?,
            custom_resp_headers=?, ip_blocklist=?,
            hsts_max_age_sec=?, hsts_include_subdomains=?, hsts_preload=?,
            advanced_config=?, color=?,
            maintenance_status_code=?, sort_order=?, redirect_rules=?,
            redirect_strip_path_prefix=?, redirect_wildcard_subdomain=?, sunset_at=?,
            dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?, dns_profile_id=?,
            updated_at=CURRENT_TIMESTAMP WHERE id = ?`,
		r.Domains, r.ForwardScheme, r.ForwardDomain, r.ForwardHTTPCode,
		boolInt(r.PreservePath), boolInt(r.SSLEnabled), boolInt(r.SSLForced),
		boolInt(r.Enabled), nilIfZero(r.CertificateID), r.Tags, r.Notes,
		r.AccessList, boolInt(r.MaintenanceMode), r.MaintenanceMsg,
		r.CustomRespHeaders, r.IPBlocklist,
		r.HSTSMaxAgeSec, boolInt(r.HSTSIncludeSubdomains), boolInt(r.HSTSPreload),
		r.AdvancedConfig, r.Color,
		r.MaintenanceStatusCode, r.SortOrder, r.RedirectRules,
		r.RedirectStripPathPrefix, boolInt(r.RedirectWildcardSubdomain), r.SunsetAt,
		r.DNSProvider, r.DNSZoneID, r.DNSZoneName, r.DNSRecordID, r.DNSProfileID,
		r.ID,
	)
	return err
}

// UpdateRedirectionHostDNSRecord — v2.12.2: persists provider-returned record
// IDs after auto-creation. Mirror of UpdateProxyHostDNSRecord /
// UpdateRawRouteDNSRecord. recordIDs may be a single ID or comma-separated.
func UpdateRedirectionHostDNSRecord(db *sql.DB, id int64, provider, zoneID, zoneName, recordIDs string) error {
	_, err := db.Exec(`UPDATE redirection_hosts
        SET dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
            updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		provider, zoneID, zoneName, recordIDs, id)
	return err
}

func UpdateRedirectionHostDNSProfile(db *sql.DB, id int64, profileID string) error {
	_, err := db.Exec(`UPDATE redirection_hosts
        SET dns_profile_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		profileID, id)
	return err
}

func DeleteRedirectionHost(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM redirection_hosts WHERE id = ?`, id)
	return err
}

// SetRedirectionHostOwner reassigns ownership. See SetProxyHostOwner for the
// rationale behind keeping this separate from UpdateRedirectionHost.
func SetRedirectionHostOwner(db *sql.DB, id int64, ownerID int64) error {
	_, err := db.Exec(`UPDATE redirection_hosts SET owner_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		nilIfZero(ownerID), id)
	return err
}

type RawRoute struct {
	ID                  int64
	Label               string
	JSONData            string
	CaddyfileSrc        string // optional: original Caddyfile block the JSON was adapted from
	Enabled             bool
	CertificateID       int64 // 0 = auto (ACME) / none; >0 = use custom certificate with this ID
	ForceSSL            bool  // cosmetic: Caddy's automatic_https handles http→https already
	BlockCommonExploits bool  // wrap route with /.env, /wp-admin, etc. → 403 subroute
	// v2.5.6: unified Managed DNS, mirroring the proxy-host DNS triple.
	// Populated on save when the user picks a provider + zone in the form;
	// empty means "no managed DNS, user wires A records manually." Same
	// semantics as the proxy-host columns — see models.ProxyHost.
	DNSProvider  string
	DNSZoneID    string
	DNSZoneName  string
	DNSRecordID  string
	DNSProfileID string
	OwnerID      sql.NullInt64
	OwnerEmail   string // populated via JOIN for display
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const rawRouteCols = `id, label, json_data, COALESCE(caddyfile_src, ''), enabled,
    COALESCE(certificate_id, 0), COALESCE(force_ssl, 0), COALESCE(block_common_exploits, 0),
    COALESCE(dns_provider,''), COALESCE(dns_zone_id,''),
    COALESCE(dns_zone_name,''), COALESCE(dns_record_id,''),
    COALESCE(dns_profile_id,''),
    created_at, updated_at, COALESCE(owner_id, 0)`

func scanRawRoute(s interface {
	Scan(dest ...any) error
}) (RawRoute, error) {
	var r RawRoute
	var en, force, block int
	var ownerID int64
	err := s.Scan(&r.ID, &r.Label, &r.JSONData, &r.CaddyfileSrc, &en,
		&r.CertificateID, &force, &block,
		&r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID, &r.DNSProfileID,
		&r.CreatedAt, &r.UpdatedAt, &ownerID)
	if err == nil {
		r.Enabled = en == 1
		r.ForceSSL = force == 1
		r.BlockCommonExploits = block == 1
		if ownerID != 0 {
			r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
		}
	}
	return r, err
}

// ListRawRoutes returns raw routes for the given server.
// If isAdmin is true, all routes are returned with owner email via JOIN.
// If isAdmin is false, viewer sees rows they own plus any peerID-owned rows
// (group teammates, v2.7.4). peerIDs may be nil for "only my own".
func ListRawRoutes(db *sql.DB, serverID int64, viewerID int64, isAdmin bool, peerIDs []int64) ([]RawRoute, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
        SELECT rr.id, rr.label, rr.json_data, COALESCE(rr.caddyfile_src, ''), rr.enabled,
               COALESCE(rr.certificate_id, 0), COALESCE(rr.force_ssl, 0), COALESCE(rr.block_common_exploits, 0),
               COALESCE(rr.dns_provider,''), COALESCE(rr.dns_zone_id,''),
               COALESCE(rr.dns_zone_name,''), COALESCE(rr.dns_record_id,''),
               COALESCE(rr.dns_profile_id,''),
               rr.created_at, rr.updated_at, COALESCE(rr.owner_id, 0), COALESCE(u.email, '')
        FROM raw_routes rr
        LEFT JOIN users u ON u.id = rr.owner_id
        WHERE rr.server_id = ? ORDER BY rr.id ASC`, serverID)
	} else {
		inStr, inArgs := inClause(peerIDs)
		args := append([]any{serverID, viewerID}, inArgs...)
		rows, err = db.Query(`
        SELECT rr.id, rr.label, rr.json_data, COALESCE(rr.caddyfile_src, ''), rr.enabled,
               COALESCE(rr.certificate_id, 0), COALESCE(rr.force_ssl, 0), COALESCE(rr.block_common_exploits, 0),
               COALESCE(rr.dns_provider,''), COALESCE(rr.dns_zone_id,''),
               COALESCE(rr.dns_zone_name,''), COALESCE(rr.dns_record_id,''),
               COALESCE(rr.dns_profile_id,''),
               rr.created_at, rr.updated_at, COALESCE(rr.owner_id, 0), COALESCE(u.email, '')
        FROM raw_routes rr
        LEFT JOIN users u ON u.id = rr.owner_id
        WHERE rr.server_id = ?
          AND (rr.owner_id = ? OR rr.owner_id IN (`+inStr+`))
        ORDER BY rr.id ASC`, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RawRoute
	for rows.Next() {
		var r RawRoute
		var en, force, block int
		var ownerID int64
		if err := rows.Scan(&r.ID, &r.Label, &r.JSONData, &r.CaddyfileSrc, &en,
			&r.CertificateID, &force, &block,
			&r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID, &r.DNSProfileID,
			&r.CreatedAt, &r.UpdatedAt, &ownerID, &r.OwnerEmail); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.ForceSSL = force == 1
		r.BlockCommonExploits = block == 1
		if ownerID != 0 {
			r.OwnerID = sql.NullInt64{Int64: ownerID, Valid: true}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateRawRoute inserts a new raw route. ownerID 0 means global/admin-owned (NULL in DB).
func CreateRawRoute(db *sql.DB, serverID int64, ownerID int64, r *RawRoute) (int64, error) {
	res, err := db.Exec(`INSERT INTO raw_routes (server_id, label, json_data, caddyfile_src, enabled,
            certificate_id, force_ssl, block_common_exploits,
            dns_provider, dns_zone_id, dns_zone_name, dns_record_id, dns_profile_id,
            owner_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID, r.Label, r.JSONData, r.CaddyfileSrc, boolInt(r.Enabled),
		nilIfZero(r.CertificateID), boolInt(r.ForceSSL), boolInt(r.BlockCommonExploits),
		r.DNSProvider, r.DNSZoneID, r.DNSZoneName, r.DNSRecordID, r.DNSProfileID,
		nilIfZero(ownerID))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func GetRawRoute(db *sql.DB, id int64) (*RawRoute, error) {
	r, err := scanRawRoute(db.QueryRow(`SELECT `+rawRouteCols+` FROM raw_routes WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func UpdateRawRoute(db *sql.DB, r *RawRoute) error {
	_, err := db.Exec(`UPDATE raw_routes SET label=?, json_data=?, caddyfile_src=?, enabled=?,
            certificate_id=?, force_ssl=?, block_common_exploits=?,
            dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?, dns_profile_id=?,
            updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		r.Label, r.JSONData, r.CaddyfileSrc, boolInt(r.Enabled),
		nilIfZero(r.CertificateID), boolInt(r.ForceSSL), boolInt(r.BlockCommonExploits),
		r.DNSProvider, r.DNSZoneID, r.DNSZoneName, r.DNSRecordID, r.DNSProfileID,
		r.ID)
	return err
}

// SetRawRouteOwner reassigns ownership. See SetProxyHostOwner for the
// rationale behind keeping this separate from UpdateRawRoute.
func SetRawRouteOwner(db *sql.DB, id int64, ownerID int64) error {
	_, err := db.Exec(`UPDATE raw_routes SET owner_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		nilIfZero(ownerID), id)
	return err
}

// UpdateRawRouteDNSRecord persists the record ID + zone identifier after
// a successful provider create/delete. Mirrors UpdateProxyHostDNSRecord
// — kept as a minimal UPDATE so the post-create hook can write back
// without racing the main form save. Pass empty strings for all four
// fields to clear DNS management on a route.
func UpdateRawRouteDNSRecord(db *sql.DB, id int64, provider, zoneID, zoneName, recordID string) error {
	_, err := db.Exec(`UPDATE raw_routes
        SET dns_provider=?, dns_zone_id=?, dns_zone_name=?, dns_record_id=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?`,
		provider, zoneID, zoneName, recordID, id)
	return err
}

func UpdateRawRouteDNSProfile(db *sql.DB, id int64, profileID string) error {
	_, err := db.Exec(`UPDATE raw_routes
        SET dns_profile_id=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=?`,
		profileID, id)
	return err
}

// ListRawRoutesWithDNSRecords returns a lightweight slice of all raw
// routes with an active managed DNS record. Only the fields needed for
// lifecycle management (IP retarget, bulk delete) are populated —
// mirrors ListProxyHostsWithDNSRecords. Pass serverID > 0 to restrict
// to that Caddy server; 0 means "all servers".
func ListRawRoutesWithDNSRecords(db *sql.DB, serverID int64) ([]RawRoute, error) {
	q := `SELECT id, label, json_data, dns_provider, dns_zone_id, dns_zone_name, dns_record_id, COALESCE(dns_profile_id,'')
        FROM raw_routes
        WHERE dns_provider != '' AND dns_record_id != ''`
	args := []any{}
	if serverID > 0 {
		q += ` AND server_id = ?`
		args = append(args, serverID)
	}
	q += ` ORDER BY id ASC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RawRoute
	for rows.Next() {
		var r RawRoute
		if err := rows.Scan(&r.ID, &r.Label, &r.JSONData, &r.DNSProvider, &r.DNSZoneID, &r.DNSZoneName, &r.DNSRecordID, &r.DNSProfileID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func DeleteRawRoute(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM raw_routes WHERE id = ?`, id)
	return err
}

func GetSetting(db *sql.DB, key string) (string, error) {
	var v string
	err := db.QueryRow("SELECT value FROM settings WHERE `key` = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func SetSetting(db *sql.DB, key, value string) error {
	result, err := db.Exec("UPDATE settings SET value = ? WHERE `key` = ?", value, key)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		return nil
	}
	if _, err := db.Exec("INSERT INTO settings (`key`, value) VALUES (?, ?)", key, value); err == nil {
		return nil
	}
	// A concurrent first write may have inserted the row after our UPDATE.
	// Retrying the UPDATE is portable across SQLite and MariaDB.
	_, err = db.Exec("UPDATE settings SET value = ? WHERE `key` = ?", value, key)
	return err
}

// DomainsConflict checks whether any of `domains` is already claimed by another
// proxy host or redirection host on the same server. Returns the first
// conflicting domain (in its original casing) or "" if none.
//
// excludeProxyID / excludeRedirectID let the caller skip the row being edited
// — exactly one is non-zero per call (proxy edit → excludeProxyID, redirect
// edit → excludeRedirectID, create on either form → both 0). Proxies and
// redirects share no ID space (separate tables), so a single excludeID would
// be ambiguous, hence the split.
//
// Matching is case-insensitive and trim-tolerant. Admin view is forced
// (isAdmin=true) so the check is global across all owners — a hostname claimed
// by user A's proxy still conflicts with user B trying to create the same
// proxy, since Caddy resolves routes by hostname not by owner.
//
// Raw routes are intentionally NOT checked here. Their host matchers live
// inside the route's JSON body rather than a flat column, and `postImport`
// already covers that case during the Caddyfile import flow. v2.7.7.
func DomainsConflict(db *sql.DB, serverID int64, domains []string, excludeProxyID, excludeRedirectID int64) (string, error) {
	hosts, err := ListProxyHosts(db, serverID, 0, true, nil)
	if err != nil {
		return "", err
	}
	redirs, err := ListRedirectionHosts(db, serverID, 0, true, nil)
	if err != nil {
		return "", err
	}
	existing := map[string]struct{}{}
	for _, h := range hosts {
		if h.ID == excludeProxyID {
			continue
		}
		for _, d := range h.DomainList() {
			existing[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
		}
	}
	for _, r := range redirs {
		if r.ID == excludeRedirectID {
			continue
		}
		for _, d := range r.DomainList() {
			existing[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
		}
	}
	for _, d := range domains {
		key := strings.ToLower(strings.TrimSpace(d))
		if key == "" {
			continue
		}
		if _, ok := existing[key]; ok {
			return d, nil
		}
	}
	return "", nil
}

func FormatSchemeHost(scheme, host string, port int) string {
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

const (
	CertSourcePEM     = "pem"
	CertSourcePath    = "path"
	CertSourceManaged = "managed"
)

type Certificate struct {
	ID           int64
	Name         string
	Domains      string // comma-separated hostnames the cert covers (for display / skip_certificates)
	Source       string // "pem", "path", or "managed"
	CertPEM      string
	KeyPEM       string
	CertPath     string
	KeyPath      string
	DNSProvider  string
	DNSProfileID string
	CreatedAt    time.Time
	UpdatedAt    time.Time

	// v2.7.2: per-user ownership. OwnerID.Valid == false means admin-owned /
	// global — any user-role account can reference it from the proxy-host
	// dropdown, but only admin can edit or delete it. OwnerID.Int64 == user.ID
	// means a user-role account uploaded it; only the uploader (or admin) can
	// see it in the dropdown, edit, or delete. OwnerEmail is populated by
	// ListCertificates when the caller is admin (for the Owner column); blank
	// otherwise to avoid a JOIN round-trip in the non-admin hot path.
	OwnerID    sql.NullInt64
	OwnerEmail string
}

func (c Certificate) DomainList() []string {
	parts := strings.Split(c.Domains, ",")
	out := make([]string, 0, len(parts))
	for _, d := range parts {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// ListCertificates returns every certificate configured on a server regardless
// of owner. Used by the Caddy sync path (which builds tls.certificates for the
// whole config) and by any other back-end path that needs a complete view.
// For user-facing lists and form dropdowns, use ListCertificatesForUser so
// non-admin accounts don't see another user's private TLS material.
func ListCertificates(db *sql.DB, serverID int64) ([]Certificate, error) {
	rows, err := db.Query(`
        SELECT id, name, domains, source, cert_pem, key_pem, cert_path, key_path,
               COALESCE(dns_provider,''), COALESCE(dns_profile_id,''), owner_id, created_at, updated_at
        FROM certificates WHERE server_id = ? ORDER BY id DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Name, &c.Domains, &c.Source,
			&c.CertPEM, &c.KeyPEM, &c.CertPath, &c.KeyPath,
			&c.DNSProvider, &c.DNSProfileID, &c.OwnerID,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListCertificatesForUser scopes the list to what the viewer is allowed to
// see. Admin gets every row plus the owner's email (for the Owner column on
// /certificates). A non-admin gets their own uploads plus global
// (admin-owned, owner_id IS NULL) certs — the latter so the proxy-host form's
// TLS dropdown still offers the shared wildcard etc. that admins maintain.
//
// OwnerEmail is populated only on the admin path; the non-admin path can't
// surface other users' emails and the column isn't shown to them anyway.
func ListCertificatesForUser(db *sql.DB, serverID int64, viewerID int64, isAdmin bool, peerIDs []int64) ([]Certificate, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
            SELECT c.id, c.name, c.domains, c.source, c.cert_pem, c.key_pem, c.cert_path, c.key_path,
                   COALESCE(c.dns_provider,''), COALESCE(c.dns_profile_id,''),
                   c.owner_id, c.created_at, c.updated_at, COALESCE(u.email, '')
            FROM certificates c
            LEFT JOIN users u ON u.id = c.owner_id
            WHERE c.server_id = ? ORDER BY c.id DESC`, serverID)
	} else {
		// v2.7.4: JOIN in the non-admin path too so teammates' cert rows render
		// with an Owner email. Pre-v2.7.4 we returned '' here as a privacy
		// measure (a user-role account should never see another user's email
		// unless they're both admins), but under groups the whole point is
		// that teammates see each other's resources, owner label included.
		inStr, inArgs := inClause(peerIDs)
		args := append([]any{serverID, viewerID}, inArgs...)
		rows, err = db.Query(`
            SELECT c.id, c.name, c.domains, c.source, c.cert_pem, c.key_pem, c.cert_path, c.key_path,
                   COALESCE(c.dns_provider,''), COALESCE(c.dns_profile_id,''),
                   c.owner_id, c.created_at, c.updated_at, COALESCE(u.email, '')
            FROM certificates c
            LEFT JOIN users u ON u.id = c.owner_id
            WHERE c.server_id = ?
              AND (c.owner_id IS NULL OR c.owner_id = ? OR c.owner_id IN (`+inStr+`))
            ORDER BY c.id DESC`, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Name, &c.Domains, &c.Source,
			&c.CertPEM, &c.KeyPEM, &c.CertPath, &c.KeyPath,
			&c.DNSProvider, &c.DNSProfileID, &c.OwnerID,
			&c.CreatedAt, &c.UpdatedAt, &c.OwnerEmail); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListCertificateOptionsForUser returns the same scoped certificate rows as
// ListCertificatesForUser, but omits PEM/key payload columns. Use this for
// dropdowns on pages that do not inspect or edit certificate material.
func ListCertificateOptionsForUser(db *sql.DB, serverID int64, viewerID int64, isAdmin bool, peerIDs []int64) ([]Certificate, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
            SELECT c.id, c.name, c.domains, c.source, c.owner_id, c.created_at, c.updated_at, COALESCE(u.email, '')
            FROM certificates c
            LEFT JOIN users u ON u.id = c.owner_id
            WHERE c.server_id = ? AND c.source != ? ORDER BY c.id DESC`, serverID, CertSourceManaged)
	} else {
		inStr, inArgs := inClause(peerIDs)
		args := append([]any{serverID, CertSourceManaged, viewerID}, inArgs...)
		rows, err = db.Query(`
            SELECT c.id, c.name, c.domains, c.source, c.owner_id, c.created_at, c.updated_at, COALESCE(u.email, '')
            FROM certificates c
            LEFT JOIN users u ON u.id = c.owner_id
            WHERE c.server_id = ? AND c.source != ?
              AND (c.owner_id IS NULL OR c.owner_id = ? OR c.owner_id IN (`+inStr+`))
            ORDER BY c.id DESC`, args...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Name, &c.Domains, &c.Source, &c.OwnerID,
			&c.CreatedAt, &c.UpdatedAt, &c.OwnerEmail); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func GetCertificate(db *sql.DB, id int64) (*Certificate, error) {
	var c Certificate
	err := db.QueryRow(`
        SELECT id, name, domains, source, cert_pem, key_pem, cert_path, key_path,
               COALESCE(dns_provider,''), COALESCE(dns_profile_id,''), owner_id, created_at, updated_at
        FROM certificates WHERE id = ?`, id).Scan(
		&c.ID, &c.Name, &c.Domains, &c.Source,
		&c.CertPEM, &c.KeyPEM, &c.CertPath, &c.KeyPath,
		&c.DNSProvider, &c.DNSProfileID, &c.OwnerID,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateCertificate inserts a new TLS cert. ownerID == 0 → global / admin
// (owner_id stored as NULL). ownerID > 0 → owned by that user (stored as-is).
// Pairs with nilIfZero so the ownership column is consistent with the other
// three tables that use the same sentinel.
func CreateCertificate(db *sql.DB, serverID int64, ownerID int64, c *Certificate) (int64, error) {
	if c.Source == "" {
		c.Source = CertSourcePEM
	}
	res, err := db.Exec(`
        INSERT INTO certificates (server_id, owner_id, name, domains, source, cert_pem, key_pem, cert_path, key_path, dns_provider, dns_profile_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID, nilIfZero(ownerID), c.Name, c.Domains, c.Source, c.CertPEM, c.KeyPEM,
		c.CertPath, c.KeyPath, c.DNSProvider, c.DNSProfileID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdateCertificate(db *sql.DB, c *Certificate) error {
	if c.Source == "" {
		c.Source = CertSourcePEM
	}
	_, err := db.Exec(`
        UPDATE certificates SET name=?, domains=?, source=?, cert_pem=?, key_pem=?,
            cert_path=?, key_path=?, dns_provider=?, dns_profile_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		c.Name, c.Domains, c.Source, c.CertPEM, c.KeyPEM, c.CertPath, c.KeyPath,
		c.DNSProvider, c.DNSProfileID, c.ID)
	return err
}

// SetCertificateOwner reassigns ownership. See SetProxyHostOwner for the
// rationale behind keeping this separate from UpdateCertificate.
func SetCertificateOwner(db *sql.DB, id int64, ownerID int64) error {
	_, err := db.Exec(`UPDATE certificates SET owner_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		nilIfZero(ownerID), id)
	return err
}

func DeleteCertificate(db *sql.DB, id int64) error {
	// NULL out references so we don't leave dangling FKs. No real FK so we do it manually.
	if _, err := db.Exec(`UPDATE proxy_hosts SET certificate_id=NULL WHERE certificate_id=?`, id); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE redirection_hosts SET certificate_id=NULL WHERE certificate_id=?`, id); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE raw_routes SET certificate_id=NULL WHERE certificate_id=?`, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM certificates WHERE id=?`, id)
	return err
}

// --- Config snapshots ---

const (
	SnapshotSourceAuto   = "auto"
	SnapshotSourceManual = "manual"
)

type ConfigSnapshot struct {
	ID         int64
	Note       string
	Source     string // "auto" (pre-sync) or "manual"
	ConfigJSON string
	CreatedAt  time.Time
}

// SizeKB is a convenience for templates.
func (s ConfigSnapshot) SizeKB() int { return (len(s.ConfigJSON) + 1023) / 1024 }

func ListSnapshots(db *sql.DB, serverID int64, limit int) ([]ConfigSnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.Query(`SELECT id, note, source, config_json, created_at
		FROM config_snapshots WHERE server_id = ? ORDER BY id DESC LIMIT ?`, serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConfigSnapshot
	for rows.Next() {
		var s ConfigSnapshot
		if err := rows.Scan(&s.ID, &s.Note, &s.Source, &s.ConfigJSON, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func GetSnapshot(db *sql.DB, id int64) (*ConfigSnapshot, error) {
	var s ConfigSnapshot
	err := db.QueryRow(`SELECT id, note, source, config_json, created_at
		FROM config_snapshots WHERE id=?`, id).
		Scan(&s.ID, &s.Note, &s.Source, &s.ConfigJSON, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func CreateSnapshot(db *sql.DB, serverID int64, source, note, configJSON string) (int64, error) {
	if source == "" {
		source = SnapshotSourceAuto
	}
	res, err := db.Exec(`INSERT INTO config_snapshots (server_id, note, source, config_json) VALUES (?, ?, ?, ?)`,
		serverID, note, source, configJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func DeleteSnapshot(db *sql.DB, id int64) error {
	_, err := db.Exec(`DELETE FROM config_snapshots WHERE id=?`, id)
	return err
}

// PruneAutoSnapshots keeps the most recent `keep` auto-snapshots per server and deletes older ones.
// Manual snapshots are never pruned.
func PruneAutoSnapshots(db *sql.DB, serverID int64, keep int) error {
	if keep < 1 {
		keep = 20
	}
	_, err := db.Exec(`
        DELETE FROM config_snapshots
        WHERE server_id = ? AND source = 'auto'
          AND id NOT IN (
            SELECT id FROM config_snapshots WHERE server_id = ? AND source='auto' ORDER BY id DESC LIMIT ?
          )`, serverID, serverID, keep)
	return err
}

// --- Activity log ---

type Activity struct {
	ID        int64
	Actor     string
	Action    string
	Target    string
	Detail    string
	Success   bool
	CreatedAt time.Time
}

func LogActivity(db *sql.DB, serverID int64, actor, action, target, detail string, success bool) error {
	if actor == "" {
		actor = "system"
	}
	ok := 1
	if !success {
		ok = 0
	}
	_, err := db.Exec(`INSERT INTO activity_log (server_id, actor, action, target, detail, success)
        VALUES (?, ?, ?, ?, ?, ?)`, serverID, actor, action, target, detail, ok)
	return err
}

func ListActivity(db *sql.DB, serverID int64, limit int) ([]Activity, error) {
	if limit <= 0 {
		limit = 200
	}
	// v2.9.211: also surface server_id=0 rows (auth/login/logout events have
	// no Caddy-server context). Without this, /activity hides login_success,
	// login_fail, login_totp_*, and logout entries when the page is scoped
	// to a specific server — i.e. always.
	rows, err := db.Query(`SELECT id, actor, action, target, detail, success, created_at
        FROM activity_log WHERE server_id = ? OR server_id = 0 ORDER BY id DESC LIMIT ?`, serverID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		var ok int
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &ok, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Success = ok == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListActivitySearch is like ListActivity but filters rows where actor, action,
// target, or detail contain the given search string (case-insensitive LIKE).
// When search is empty it behaves identically to ListActivity.
func ListActivitySearch(db *sql.DB, serverID int64, limit int, search string) ([]Activity, error) {
	if limit <= 0 {
		limit = 200
	}
	if search == "" {
		return ListActivity(db, serverID, limit)
	}
	like := "%" + search + "%"
	// v2.9.211: include server_id=0 (global auth events) — see ListActivity.
	rows, err := db.Query(`SELECT id, actor, action, target, detail, success, created_at
        FROM activity_log
        WHERE (server_id = ? OR server_id = 0)
          AND (actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ?)
        ORDER BY id DESC LIMIT ?`,
		serverID, like, like, like, like, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Activity
	for rows.Next() {
		var a Activity
		var ok int
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &ok, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.Success = ok == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// CertificateInUse returns the number of proxy/redirect/raw routes currently referencing this cert.
func CertificateInUse(db *sql.DB, id int64) (int, error) {
	var n int
	if err := db.QueryRow(`
        SELECT
          (SELECT COUNT(*) FROM proxy_hosts WHERE certificate_id=?) +
          (SELECT COUNT(*) FROM redirection_hosts WHERE certificate_id=?) +
          (SELECT COUNT(*) FROM raw_routes WHERE certificate_id=?)`,
		id, id, id).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CertificateInUseByOthers returns how many proxy/redirect/raw rows reference
// this cert AND are owned by someone other than excludeOwnerID (a NULL owner
// counts as "other" — those are admin/global sites). Used by the user-role
// delete path to block a cert-delete that would strip TLS off another
// tenant's site; the caller's own sites are allowed to fall back to auto-ssl.
func CertificateInUseByOthers(db *sql.DB, id int64, excludeOwnerID int64) (int, error) {
	var n int
	if err := db.QueryRow(`
        SELECT
          (SELECT COUNT(*) FROM proxy_hosts
             WHERE certificate_id=? AND (owner_id IS NULL OR owner_id != ?)) +
          (SELECT COUNT(*) FROM redirection_hosts
             WHERE certificate_id=? AND (owner_id IS NULL OR owner_id != ?)) +
          (SELECT COUNT(*) FROM raw_routes
             WHERE certificate_id=? AND (owner_id IS NULL OR owner_id != ?))`,
		id, excludeOwnerID, id, excludeOwnerID, id, excludeOwnerID).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// --- API Tokens ---

// API token scope values. Stored verbatim in the scopes column.
const (
	TokenScopeFull       = "full"        // full access as the user's role
	TokenScopeReadOnly   = "read_only"   // GET/HEAD requests only
	TokenScopeProxyWrite = "proxy_write" // proxy-host write + everything else read-only
)

// APIToken is a named bearer-token credential for programmatic access.
// The raw token is shown exactly once at creation; only the SHA-256 hash
// is persisted. Expiry == zero means the token never expires.
type APIToken struct {
	ID         int64
	UserID     int64
	UserEmail  string // populated via JOIN on list queries
	Name       string
	TokenHash  string
	Scopes     string
	LastUsedAt sql.NullTime
	ExpiresAt  sql.NullTime
	CreatedAt  time.Time
}

func (t *APIToken) Expired() bool {
	return t.ExpiresAt.Valid && t.ExpiresAt.Time.Before(time.Now())
}

// CreateAPIToken inserts a new API token row and returns the inserted ID.
// tokenHash must be hex(sha256(rawToken)).
func CreateAPIToken(db *sql.DB, userID int64, name, tokenHash, scopes string, expiresAt *time.Time) (int64, error) {
	var exp any
	if expiresAt != nil {
		exp = *expiresAt
	}
	res, err := db.Exec(
		`INSERT INTO api_tokens (user_id, name, token_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?)`,
		userID, strings.TrimSpace(name), tokenHash, scopes, exp,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListAPITokens returns all tokens for the given user.
// If isAdmin is true, all users' tokens are returned with user email.
func ListAPITokens(db *sql.DB, userID int64, isAdmin bool) ([]APIToken, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = db.Query(`
			SELECT t.id, t.user_id, COALESCE(u.email,''), t.name, t.token_hash, t.scopes,
			       t.last_used_at, t.expires_at, t.created_at
			FROM api_tokens t
			LEFT JOIN users u ON u.id = t.user_id
			ORDER BY t.id DESC`)
	} else {
		rows, err = db.Query(`
			SELECT t.id, t.user_id, COALESCE(u.email,''), t.name, t.token_hash, t.scopes,
			       t.last_used_at, t.expires_at, t.created_at
			FROM api_tokens t
			LEFT JOIN users u ON u.id = t.user_id
			WHERE t.user_id = ?
			ORDER BY t.id DESC`, userID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.UserEmail, &t.Name, &t.TokenHash, &t.Scopes,
			&t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetAPITokenByHash looks up a token by its SHA-256 hex hash. Returns nil if not found.
func GetAPITokenByHash(db *sql.DB, tokenHash string) (*APIToken, error) {
	var t APIToken
	err := db.QueryRow(`
		SELECT t.id, t.user_id, COALESCE(u.email,''), t.name, t.token_hash, t.scopes,
		       t.last_used_at, t.expires_at, t.created_at
		FROM api_tokens t
		LEFT JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ?`, tokenHash).
		Scan(&t.ID, &t.UserID, &t.UserEmail, &t.Name, &t.TokenHash, &t.Scopes,
			&t.LastUsedAt, &t.ExpiresAt, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// TouchAPIToken updates last_used_at to now.
func TouchAPIToken(db *sql.DB, id int64) {
	_, _ = db.Exec(`UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
}

// DeleteAPIToken removes a token by ID. ownerID == 0 skips the ownership check (admin path).
func DeleteAPIToken(db *sql.DB, id int64, ownerID int64) error {
	if ownerID == 0 {
		_, err := db.Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
		return err
	}
	_, err := db.Exec(`DELETE FROM api_tokens WHERE id = ? AND user_id = ?`, id, ownerID)
	return err
}

// --- Proxy Health ---

// ProxyHealthCheck is a single health-check result for a proxy host.
type ProxyHealthCheck struct {
	ID          int64
	ProxyHostID int64
	CheckedAt   time.Time
	OK          bool
	StatusCode  int
	LatencyMs   int64
	ErrorMsg    string
}

// LatestProxyHealth returns the most recent health check for each proxy host ID
// in the given list. Returns a map of proxyHostID → ProxyHealthCheck.
// Hosts with no check history are absent from the map.
func LatestProxyHealth(db *sql.DB, hostIDs []int64) (map[int64]ProxyHealthCheck, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(hostIDs))
	args := make([]any, len(hostIDs))
	for i, id := range hostIDs {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := db.Query(`
		SELECT ph.proxy_host_id, ph.checked_at, ph.ok, ph.status_code, ph.latency_ms, ph.error_msg
		FROM proxy_health ph
		INNER JOIN (
			SELECT proxy_host_id, MAX(checked_at) AS max_ts
			FROM proxy_health
			WHERE proxy_host_id IN (`+strings.Join(placeholders, ",")+`)
			GROUP BY proxy_host_id
		) latest ON ph.proxy_host_id = latest.proxy_host_id AND ph.checked_at = latest.max_ts
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64]ProxyHealthCheck)
	for rows.Next() {
		var h ProxyHealthCheck
		var ok int
		var ts int64
		if err := rows.Scan(&h.ProxyHostID, &ts, &ok, &h.StatusCode, &h.LatencyMs, &h.ErrorMsg); err != nil {
			return nil, err
		}
		h.OK = ok == 1
		h.CheckedAt = time.Unix(ts, 0)
		out[h.ProxyHostID] = h
	}
	return out, rows.Err()
}

// InsertProxyHealth stores a health check result and prunes old rows for that host
// to keep at most 288 entries (24 hours at 5-min intervals).
func InsertProxyHealth(db *sql.DB, hostID int64, ok bool, statusCode int, latencyMs int64, errMsg string) error {
	ts := time.Now().Unix()
	okInt := 0
	if ok {
		okInt = 1
	}
	if _, err := db.Exec(`
		INSERT INTO proxy_health (proxy_host_id, checked_at, ok, status_code, latency_ms, error_msg)
		VALUES (?, ?, ?, ?, ?, ?)`,
		hostID, ts, okInt, statusCode, latencyMs, errMsg); err != nil {
		return err
	}
	// Prune: keep only the newest 288 rows per host.
	_, err := db.Exec(`
		DELETE FROM proxy_health
		WHERE proxy_host_id = ? AND id NOT IN (
			SELECT id FROM proxy_health WHERE proxy_host_id = ? ORDER BY checked_at DESC LIMIT 288
		)`, hostID, hostID)
	return err
}

// GetProxyHealthHistory returns the last N health checks for a given proxy host,
// ordered newest first.
func GetProxyHealthHistory(db *sql.DB, hostID int64, limit int) ([]ProxyHealthCheck, error) {
	rows, err := db.Query(`
		SELECT checked_at, ok, status_code, latency_ms, error_msg
		FROM proxy_health WHERE proxy_host_id = ?
		ORDER BY checked_at DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProxyHealthCheck
	for rows.Next() {
		var h ProxyHealthCheck
		var ok int
		var ts int64
		if err := rows.Scan(&ts, &ok, &h.StatusCode, &h.LatencyMs, &h.ErrorMsg); err != nil {
			return nil, err
		}
		h.OK = ok == 1
		h.CheckedAt = time.Unix(ts, 0)
		h.ProxyHostID = hostID
		out = append(out, h)
	}
	return out, rows.Err()
}
