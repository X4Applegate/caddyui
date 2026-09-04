package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Proxy-host form parsing.
//
// v2.30.0: moved verbatim out of server.go. parseProxyHostForm is ~660 lines
// on its own — the single largest function in the codebase — and server.go
// was over 16,600 lines. Nothing here changed except the file it lives in.

// clampAtoi parses a form value as an int and constrains it to [min, max].
// Blank, unparseable, or non-positive input yields zeroValue, which callers
// use as their "unset — fall back to the built-in default" sentinel. A value
// that parses but falls outside the range is pulled to the nearest bound
// rather than rejected, so a typo in one numeric field can't fail the whole
// form save.
//
// v2.28.0 (issue #39).
func clampAtoi(raw string, zeroValue, min, max int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return zeroValue
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func parseProxyHostForm(r *http.Request) (*models.ProxyHost, error) {
	_ = r.ParseForm()
	port, err := strconv.Atoi(r.FormValue("forward_port"))
	if err != nil {
		return nil, err
	}
	certID, _ := strconv.ParseInt(r.FormValue("certificate_id"), 10, 64)
	// DNS picker is now a two-field combo: dns_provider selects which
	// provider (or "" for none) and dns_zone_id is the provider-native
	// zone identifier. For human display the zone_name is also captured —
	// the form stashes it in a hidden input whenever the picker changes.
	provider := strings.ToLower(strings.TrimSpace(r.FormValue("dns_provider")))
	profileID := strings.TrimSpace(r.FormValue("dns_profile_id"))
	zoneID := ""
	zoneName := ""
	if provider != "" {
		if _, ok := dns.Lookup(provider); !ok {
			provider = "" // unknown ID → treat as "no DNS"
		} else {
			zoneID = strings.TrimSpace(r.FormValue("dns_zone_id"))
			zoneName = strings.TrimSpace(r.FormValue("dns_zone_name"))
			if zoneID == "" {
				// Picker never captured a zone; treat the whole thing as
				// unset so we don't try to create a record with no target.
				provider = ""
				zoneName = ""
			}
			if zoneName == "" {
				// PB/DO/GD/NC use ID == Name; fall back transparently.
				zoneName = zoneID
			}
		}
	}
	// v2.9.0: validate TLS min version — only accept known values.
	tlsMinVersion := strings.TrimSpace(r.FormValue("tls_min_version"))
	switch tlsMinVersion {
	case "", "1.0", "1.1", "1.2", "1.3":
		// valid
	default:
		tlsMinVersion = ""
	}
	// Parse custom request headers: parallel arrays header_req_key[] + header_req_val[]
	reqKeys := r.Form["header_req_key"]
	reqVals := r.Form["header_req_val"]
	reqMap := map[string]string{}
	for i, k := range reqKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v := ""
		if i < len(reqVals) {
			v = strings.TrimSpace(reqVals[i])
		}
		reqMap[k] = v
	}
	customReqHeaders := "{}"
	if len(reqMap) > 0 {
		if b, err := json.Marshal(reqMap); err == nil {
			customReqHeaders = string(b)
		}
	}

	// Parse custom response headers: parallel arrays header_resp_key[] + header_resp_val[]
	respKeys := r.Form["header_resp_key"]
	respVals := r.Form["header_resp_val"]
	respMap := map[string]string{}
	for i, k := range respKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v := ""
		if i < len(respVals) {
			v = strings.TrimSpace(respVals[i])
		}
		respMap[k] = v
	}
	customRespHeaders := "{}"
	if len(respMap) > 0 {
		if b, err := json.Marshal(respMap); err == nil {
			customRespHeaders = string(b)
		}
	}
	// v2.9.2: URL rewrite rules — submitted as parallel arrays:
	// rewrite_type[], rewrite_from[], rewrite_to[]
	rewriteTypes := r.Form["rewrite_type[]"]
	rewriteFroms := r.Form["rewrite_from[]"]
	rewriteTos := r.Form["rewrite_to[]"]
	var urlRewrites string
	{
		type rule struct {
			Type string `json:"type"`
			From string `json:"from"`
			To   string `json:"to"`
		}
		var rules []rule
		for i := range rewriteTypes {
			from := ""
			to := ""
			if i < len(rewriteFroms) {
				from = strings.TrimSpace(rewriteFroms[i])
			}
			if i < len(rewriteTos) {
				to = strings.TrimSpace(rewriteTos[i])
			}
			t := strings.TrimSpace(rewriteTypes[i])
			if t == "" || from == "" {
				continue
			}
			rules = append(rules, rule{Type: t, From: from, To: to})
		}
		if len(rules) == 0 {
			urlRewrites = "[]"
		} else {
			b, _ := json.Marshal(rules)
			urlRewrites = string(b)
		}
	}
	var maxBodyMB int
	if v := strings.TrimSpace(r.FormValue("max_request_body_mb")); v != "" && v != "0" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxBodyMB = n
		}
	}
	var upstreamTimeoutSec int
	if v := strings.TrimSpace(r.FormValue("upstream_timeout_sec")); v != "" && v != "0" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			upstreamTimeoutSec = n
		}
	}
	var healthCheckIntervalSec int = 30
	if v := strings.TrimSpace(r.FormValue("health_check_interval_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			healthCheckIntervalSec = n
		}
	}
	var keepaliveConns int
	if v := strings.TrimSpace(r.FormValue("keepalive_conns")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			keepaliveConns = n
		}
	}
	ph := &models.ProxyHost{
		Domains:                strings.TrimSpace(r.FormValue("domains")),
		ForwardScheme:          r.FormValue("forward_scheme"),
		ForwardHost:            strings.TrimSpace(r.FormValue("forward_host")),
		ForwardPort:            port,
		WebsocketSupport:       r.FormValue("websocket_support") == "on",
		BlockCommonExploits:    r.FormValue("block_common_exploits") == "on",
		SSLEnabled:             r.FormValue("ssl_enabled") == "on",
		SSLForced:              r.FormValue("ssl_forced") == "on",
		HTTP2Support:           r.FormValue("http2_support") == "on",
		AdvancedConfig:         r.FormValue("advanced_config"),
		Enabled:                r.FormValue("enabled") == "on",
		CertificateID:          certID,
		AccessList:             strings.TrimSpace(r.FormValue("access_list")),
		DNSProvider:            provider,
		DNSZoneID:              zoneID,
		DNSZoneName:            zoneName,
		DNSProfileID:           profileID,
		DNSSkipRecord:          provider != "" && r.FormValue("dns_create_record") != "on",
		CompressionEnabled:     r.FormValue("compression_enabled") == "on",
		SecurityHeadersEnabled: r.FormValue("security_headers_enabled") == "on",
		MaintenanceMode:        r.FormValue("maintenance_mode") == "on",
		MaintenanceMsg:         strings.TrimSpace(r.FormValue("maintenance_msg")),
		MaintenanceStatusCode: func() int {
			if sc, err := strconv.Atoi(r.FormValue("maintenance_status_code")); err == nil && sc > 0 {
				return sc
			}
			return 503
		}(),
		StickySessions:         r.FormValue("sticky_sessions") == "on",
		TLSMinVersion:          tlsMinVersion,
		CustomReqHeaders:       customReqHeaders,
		CustomRespHeaders:      customRespHeaders,
		URLRewrites:            urlRewrites,
		MaxRequestBodyMB:       maxBodyMB,
		UpstreamTimeoutSec:     upstreamTimeoutSec,
		CORSEnabled:            r.FormValue("cors_enabled") == "on",
		CORSOrigins:            strings.TrimSpace(r.FormValue("cors_origins")),
		HealthCheckURI:         strings.TrimSpace(r.FormValue("health_check_uri")),
		HealthCheckIntervalSec: healthCheckIntervalSec,
		HealthCheckMethod: func() string {
			m := r.FormValue("health_check_method")
			if m == "" {
				return "GET"
			}
			return m
		}(),
		KeepaliveConns:       keepaliveConns,
		Tags:                 strings.TrimSpace(r.FormValue("tags")),
		Notes:                r.FormValue("notes"),
		DisableAccessLog:     r.FormValue("disable_access_log") == "on",
		AddRequestID:         r.FormValue("add_request_id") == "on",
		StripRespHeaders:     strings.TrimSpace(r.FormValue("strip_resp_headers")),
		BlockedAgents:        strings.TrimSpace(r.FormValue("blocked_agents")),
		ResponseCacheControl: strings.TrimSpace(r.FormValue("response_cache_control")),
		UpstreamSNI:          strings.TrimSpace(r.FormValue("upstream_sni")),
		HSTSPreload:          r.FormValue("hsts_preload") == "on",
		MaxConnsPerHost: func() int {
			n, _ := strconv.Atoi(r.FormValue("max_conns_per_host"))
			return n
		}(),
	}
	hcTimeout, _ := strconv.Atoi(r.FormValue("health_check_timeout_sec"))
	ph.HealthCheckTimeoutSec = hcTimeout
	retries, _ := strconv.Atoi(r.FormValue("upstream_retries"))
	ph.UpstreamRetries = retries
	ph.ForceHTTP1 = r.FormValue("force_http1") == "on"
	ph.BasicAuthRealm = strings.TrimSpace(r.FormValue("basicauth_realm"))
	if ph.BasicAuthRealm == "" {
		ph.BasicAuthRealm = "Restricted"
	}
	ph.ErrorPageHTML = r.FormValue("error_page_html")
	ph.MaintenanceWindowStart = strings.TrimSpace(r.FormValue("maintenance_window_start"))
	ph.MaintenanceWindowEnd = strings.TrimSpace(r.FormValue("maintenance_window_end"))
	ph.MaintenanceWindowDays = strings.Join(r.Form["maintenance_window_days"], ",")
	ph.IPBlocklist = strings.TrimSpace(r.FormValue("ip_blocklist"))
	ph.LBPolicy = r.FormValue("lb_policy")
	ph.ProxyProtocol = r.FormValue("proxy_protocol")
	ph.RobotsTxt = r.FormValue("robots_txt")
	ph.PassiveFailDurationSec, _ = strconv.Atoi(r.FormValue("passive_fail_duration_sec"))
	ph.PassiveMaxFails, _ = strconv.Atoi(r.FormValue("passive_max_fails"))
	ph.HSTSMaxAgeSec, _ = strconv.Atoi(r.FormValue("hsts_max_age_sec"))
	ph.CSPHeader = strings.TrimSpace(r.FormValue("csp_header"))
	ph.H2CEnabled = r.FormValue("h2c_enabled") == "on"
	if hch := strings.TrimSpace(r.FormValue("health_check_headers")); hch != "" {
		ph.HealthCheckHeaders = hch
	} else {
		ph.HealthCheckHeaders = "{}"
	}
	ph.FlushImmediate = r.FormValue("flush_immediate") == "on"
	ph.BufferResponses = r.FormValue("buffer_responses") == "on"
	ph.TrustedProxies = strings.TrimSpace(r.FormValue("trusted_proxies"))
	ph.UpstreamHostOverride = strings.TrimSpace(r.FormValue("upstream_host_override"))
	ph.ReadTimeoutSec, _ = strconv.Atoi(r.FormValue("read_timeout_sec"))
	ph.DenyDotfiles = r.FormValue("deny_dotfiles") == "on"
	ph.RequestBuffersKB, _ = strconv.Atoi(r.FormValue("request_buffers_kb"))
	ph.CORSAllowCredentials = r.FormValue("cors_allow_credentials") == "on"
	ph.CORSExposeHeaders = strings.TrimSpace(r.FormValue("cors_expose_headers"))
	ph.SSLVerifyUpstream = r.FormValue("ssl_verify_upstream") == "on"
	ph.DialTimeoutSec, _ = strconv.Atoi(r.FormValue("dial_timeout_sec"))
	ph.APIKeyHeader = strings.TrimSpace(r.FormValue("api_key_header"))
	ph.APIKeyValue = strings.TrimSpace(r.FormValue("api_key_value"))
	ph.BlockEmptyUserAgent = r.FormValue("block_empty_user_agent") == "on"
	ph.ErrorRedirectURL = strings.TrimSpace(r.FormValue("error_redirect_url"))
	ph.PermissionsPolicy = strings.TrimSpace(r.FormValue("permissions_policy"))
	ph.XFrameOptions = strings.TrimSpace(r.FormValue("x_frame_options"))
	ph.ReferrerPolicy = strings.TrimSpace(r.FormValue("referrer_policy"))
	ph.HSTSIncludeSubdomains = r.FormValue("hsts_include_subdomains") == "on"
	ph.CSPReportOnly = strings.TrimSpace(r.FormValue("csp_report_only"))
	ph.KeepaliveIdleTimeoutSec, _ = strconv.Atoi(r.FormValue("keepalive_idle_timeout_sec"))
	ph.HealthCheckExpectStatus, _ = strconv.Atoi(r.FormValue("health_check_expect_status"))
	ph.HealthCheckExpectBody = strings.TrimSpace(r.FormValue("health_check_expect_body"))
	ph.HealthCheckFollowRedirects = r.FormValue("health_check_follow_redirects") == "on"
	ph.PathMatcher = strings.TrimSpace(r.FormValue("path_matcher"))
	ph.StripPathPrefix = r.FormValue("strip_path_prefix") == "on"
	ph.StickyCookieName = strings.TrimSpace(r.FormValue("sticky_cookie_name"))
	ph.LBTryDurationSec, _ = strconv.Atoi(r.FormValue("lb_try_duration_sec"))
	ph.LBTryIntervalMS, _ = strconv.Atoi(r.FormValue("lb_try_interval_ms"))
	ph.CompressionMinSizeKB, _ = strconv.Atoi(r.FormValue("compression_min_size_kb"))
	ph.ForwardClientIP = r.FormValue("forward_client_ip") == "on"
	ph.CORSMaxAgeSec, _ = strconv.Atoi(r.FormValue("cors_max_age_sec"))
	ph.CORSAllowMethods = strings.TrimSpace(r.FormValue("cors_allow_methods"))
	ph.CORSAllowHeaders = strings.TrimSpace(r.FormValue("cors_allow_headers"))
	ph.RetryStatusCodes = strings.TrimSpace(r.FormValue("retry_status_codes"))
	ph.WriteTimeoutSec, _ = strconv.Atoi(r.FormValue("write_timeout_sec"))
	ph.UpstreamTLSMinVersion = r.FormValue("upstream_tls_min_version")
	ph.ForwardProxyURL = strings.TrimSpace(r.FormValue("forward_proxy_url"))
	ph.BlockedMethods = strings.TrimSpace(r.FormValue("blocked_methods"))
	ph.ForwardAuthURL = strings.TrimSpace(r.FormValue("forward_auth_url"))
	ph.ForwardAuthCopyHeaders = strings.TrimSpace(r.FormValue("forward_auth_copy_headers"))
	ph.StripQueryString = r.FormValue("strip_query_string") == "on"
	ph.DeleteQueryParams = strings.TrimSpace(r.FormValue("delete_query_params"))
	ph.RequestBodyReadTimeoutSec, _ = strconv.Atoi(r.FormValue("request_body_read_timeout_sec"))
	ph.ResponseHeaderTimeoutSec, _ = strconv.Atoi(r.FormValue("response_header_timeout_sec"))
	ph.MaxConnDurationSec, _ = strconv.Atoi(r.FormValue("max_conn_duration_sec"))
	ph.DecompressResponse = r.FormValue("decompress_response") == "on"
	ph.Color = strings.TrimSpace(r.FormValue("color"))
	ph.WWWRedirect = r.FormValue("www_redirect") // "" | "to_www" | "to_bare"
	ph.StripReqHeaders = strings.TrimSpace(r.FormValue("strip_req_headers"))
	ph.UpstreamPathPrefix = strings.TrimSpace(r.FormValue("upstream_path_prefix"))
	ph.CompressionLevel, _ = strconv.Atoi(r.FormValue("compression_level"))
	ph.CompressionPreferGzip = r.FormValue("compression_prefer_gzip") == "on"
	ph.SortOrder, _ = strconv.Atoi(r.FormValue("sort_order"))
	ph.AllowedMethods = strings.TrimSpace(r.FormValue("allowed_methods"))
	ph.UpstreamMaxRespHeaderKB, _ = strconv.Atoi(r.FormValue("upstream_max_resp_header_kb"))
	ph.HealthCheckPort, _ = strconv.Atoi(r.FormValue("health_check_port"))
	ph.RequestIDHeaderName = strings.TrimSpace(r.FormValue("request_id_header_name"))
	ph.LBCookiePath = strings.TrimSpace(r.FormValue("lb_cookie_path"))
	ph.PassiveUnhealthyLatencyMS, _ = strconv.Atoi(r.FormValue("passive_unhealthy_latency_ms"))
	ph.TLSHandshakeTimeoutSec, _ = strconv.Atoi(r.FormValue("tls_handshake_timeout_sec"))
	ph.ExpectContinueTimeoutSec, _ = strconv.Atoi(r.FormValue("expect_continue_timeout_sec"))
	ph.ResponseBuffersKB, _ = strconv.Atoi(r.FormValue("response_buffers_kb"))
	ph.UpstreamMaxIdleConns, _ = strconv.Atoi(r.FormValue("upstream_max_idle_conns"))
	ph.UpstreamKeepAliveProbeIntervalSec, _ = strconv.Atoi(r.FormValue("upstream_keep_alive_probe_sec"))
	ph.ForwardAuthMethod = strings.TrimSpace(r.FormValue("forward_auth_method"))
	ph.GRPCWebEnabled = r.FormValue("grpc_web_enabled") == "on"
	ph.ForwardAuthHeadersPrefix = strings.TrimSpace(r.FormValue("forward_auth_headers_prefix"))
	ph.HealthCheckMaxSizeKB, _ = strconv.Atoi(r.FormValue("health_check_max_size_kb"))
	ph.StripPathSuffix = strings.TrimSpace(r.FormValue("strip_path_suffix"))
	ph.AddReqQueryParams = strings.TrimSpace(r.FormValue("add_req_query_params"))
	ph.ErrorPageCodes = strings.TrimSpace(r.FormValue("error_page_codes"))
	ph.UpstreamTLSCAPEMFile = strings.TrimSpace(r.FormValue("upstream_tls_ca_pem_file"))
	ph.KeepaliveDisabled = r.FormValue("keepalive_disabled") == "on"
	ph.TrailingSlashRedirect = r.FormValue("trailing_slash_redirect")
	ph.DialFallbackDelayMS, _ = strconv.Atoi(r.FormValue("dial_fallback_delay_ms"))
	ph.UpstreamNetwork = strings.TrimSpace(r.FormValue("upstream_network"))
	ph.DNSResolver = strings.TrimSpace(r.FormValue("dns_resolver"))
	ph.PathMatcherType = r.FormValue("path_matcher_type")
	ph.CORSAllowPrivateNetwork = r.FormValue("cors_allow_private_network") == "on"
	ph.RobotsTxtDisallowAll = r.FormValue("robots_txt_disallow_all") == "on"
	ph.MaintenanceRetryAfterSec, _ = strconv.Atoi(r.FormValue("maintenance_retry_after_sec"))
	ph.UpstreamResolveTimeoutSec, _ = strconv.Atoi(r.FormValue("upstream_resolve_timeout_sec"))
	ph.UpstreamReadBufferSizeKB, _ = strconv.Atoi(r.FormValue("upstream_read_buffer_size_kb"))
	ph.UpstreamWriteBufferSizeKB, _ = strconv.Atoi(r.FormValue("upstream_write_buffer_size_kb"))
	ph.ReqHeaderReplace = strings.TrimSpace(r.FormValue("req_header_replace"))
	ph.RespHeaderReplace = strings.TrimSpace(r.FormValue("resp_header_replace"))
	ph.UpstreamHTTPVersions = strings.TrimSpace(r.FormValue("upstream_http_versions"))
	ph.HealthCheckBody = strings.TrimSpace(r.FormValue("health_check_body"))
	ph.AddCanonicalLinkHeader = r.FormValue("add_canonical_link_header") == "on"
	ph.HTTPBasicAuthUpstream = strings.TrimSpace(r.FormValue("http_basic_auth_upstream"))
	ph.BlockUARegexp = strings.TrimSpace(r.FormValue("block_ua_regexp"))
	ph.SecurityTxtBody = strings.TrimSpace(r.FormValue("security_txt_body"))
	ph.ServerHeaderValue = strings.TrimSpace(r.FormValue("server_header_value"))
	ph.XRobotsTag = strings.TrimSpace(r.FormValue("x_robots_tag"))
	ph.AddForwardedHeader = r.FormValue("add_forwarded_header") == "on"
	ph.LBCookieSecret = strings.TrimSpace(r.FormValue("lb_cookie_secret"))
	ph.PassiveUnhealthyStatusCodes = strings.TrimSpace(r.FormValue("passive_unhealthy_status_codes"))
	ph.HealthCheckContentType = strings.TrimSpace(r.FormValue("health_check_content_type"))
	ph.UpstreamTLSClientCertFile = strings.TrimSpace(r.FormValue("upstream_tls_client_cert_file"))
	ph.UpstreamTLSClientKeyFile = strings.TrimSpace(r.FormValue("upstream_tls_client_key_file"))
	ph.BlockPrivateIPs = r.FormValue("block_private_ips") == "on"
	ph.EnableBrotli = r.FormValue("enable_brotli") == "on"
	ph.VaryHeader = strings.TrimSpace(r.FormValue("vary_header"))
	ph.StripETag = r.FormValue("strip_etag") == "on"
	ph.HTTP2PushPaths = strings.TrimSpace(r.FormValue("http2_push_paths"))
	ph.DenyContentTypes = strings.TrimSpace(r.FormValue("deny_content_types"))
	ph.UpstreamLocalAddr = strings.TrimSpace(r.FormValue("upstream_local_addr"))
	ph.UpstreamTLSRenegotiation = r.FormValue("upstream_tls_renegotiation")
	ph.UpstreamTLSCurves = strings.TrimSpace(r.FormValue("upstream_tls_curves"))
	ph.UpstreamTLSMaxVersion = r.FormValue("upstream_tls_max_version")
	ph.UpstreamTLSPins = strings.TrimSpace(r.FormValue("upstream_tls_pins"))
	ph.LBHeaderField = strings.TrimSpace(r.FormValue("lb_header_field"))
	ph.MaintenanceCustomHeaders = strings.TrimSpace(r.FormValue("maintenance_custom_headers"))
	ph.DenyExtensions = strings.TrimSpace(r.FormValue("deny_extensions"))
	ph.InjectRequestTimestamp = r.FormValue("inject_request_timestamp") == "on"
	ph.AddRespCookies = strings.TrimSpace(r.FormValue("add_resp_cookies"))
	ph.StripAcceptEncoding = r.FormValue("strip_accept_encoding") == "on"
	ph.AddUpstreamTimingHeader = r.FormValue("add_upstream_timing_header") == "on"
	ph.StripServerHeader = r.FormValue("strip_server_header") == "on"
	ph.BlockRefererRegexp = strings.TrimSpace(r.FormValue("block_referer_regexp"))
	ph.AddContentTypeNosniff = r.FormValue("add_content_type_nosniff") == "on"
	ph.StripAuthorizationHeader = r.FormValue("strip_authorization_header") == "on"
	ph.RealIPFromHeader = strings.TrimSpace(r.FormValue("real_ip_from_header"))
	ph.HealthCheckHostOverride = strings.TrimSpace(r.FormValue("health_check_host_override"))
	ph.AddXForwardedPort = r.FormValue("add_x_forwarded_port") == "on"
	ph.LBRetryOn = strings.TrimSpace(r.FormValue("lb_retry_on"))
	if v := strings.TrimSpace(r.FormValue("max_buffer_size_kb")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.MaxBufferSizeKB = n
		}
	}
	if v := strings.TrimSpace(r.FormValue("upstream_keepalive_probes")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.UpstreamKeepaliveProbes = n
		}
	}
	if v := strings.TrimSpace(r.FormValue("upstream_flush_interval_ms")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ph.UpstreamFlushIntervalMS = n
		}
	}
	ph.AddXForwardedHost = r.FormValue("add_x_forwarded_host") == "on"
	ph.MaintenanceAllowedIPs = strings.TrimSpace(r.FormValue("maintenance_allowed_ips"))
	ph.UpstreamTLSCipherSuites = strings.TrimSpace(r.FormValue("upstream_tls_cipher_suites"))
	ph.AddCacheControlNoStore = r.FormValue("add_cache_control_no_store") == "on"
	ph.DenyRefererEmpty = r.FormValue("deny_referer_empty") == "on"
	ph.LBCookieHTTPOnly = r.FormValue("lb_cookie_httponly") == "on"
	ph.LBCookieSecure = r.FormValue("lb_cookie_secure") == "on"
	ph.LBCookieSameSite = r.FormValue("lb_cookie_same_site")
	ph.UpstreamTLSEarlyData = r.FormValue("upstream_tls_early_data") == "on"
	ph.AddViaHeader = r.FormValue("add_via_header") == "on"
	ph.ReqHeaderRename = strings.TrimSpace(r.FormValue("req_header_rename"))
	ph.AddExpectCTHeader = r.FormValue("add_expect_ct_header") == "on"
	ph.ForceUpstreamEncoding = strings.TrimSpace(r.FormValue("force_upstream_encoding"))
	if v := strings.TrimSpace(r.FormValue("passive_unhealthy_count")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.PassiveUnhealthyCount = n
		}
	}
	ph.StripXPoweredBy = r.FormValue("strip_x_powered_by") == "on"
	ph.AddTimingAllowOrigin = strings.TrimSpace(r.FormValue("add_timing_allow_origin"))
	if v := strings.TrimSpace(r.FormValue("lb_cookie_max_age_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.LBCookieMaxAgeSec = n
		}
	}
	ph.CrossOriginOpenerPolicy = strings.TrimSpace(r.FormValue("cross_origin_opener_policy"))
	ph.CrossOriginResourcePolicy = strings.TrimSpace(r.FormValue("cross_origin_resource_policy"))
	ph.CrossOriginEmbedderPolicy = strings.TrimSpace(r.FormValue("cross_origin_embedder_policy"))
	ph.DenyRequestContentType = strings.TrimSpace(r.FormValue("deny_request_content_type"))
	ph.CompressionExcludeRegexp = strings.TrimSpace(r.FormValue("compression_exclude_regexp"))
	ph.AddCacheControlPublic = r.FormValue("add_cache_control_public") == "on"
	// v2.9.140: add_x_request_start — inject X-Request-Start: t=<epoch_ms> for APM timing.
	ph.AddXRequestStart = r.FormValue("add_x_request_start") == "on"
	// v2.9.141: maintenance_window_timezone — IANA timezone for the scheduled maintenance window.
	ph.MaintenanceWindowTimezone = strings.TrimSpace(r.FormValue("maintenance_window_timezone"))
	// v2.9.142: lb_random_choose_count — "choose" count for the random_choice lb policy.
	if v := strings.TrimSpace(r.FormValue("lb_random_choose_count")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.LBRandomChooseCount = n
		}
	}
	// v2.9.143: add_x_forwarded_scheme — inject X-Forwarded-Scheme with the client-facing scheme.
	ph.AddXForwardedScheme = r.FormValue("add_x_forwarded_scheme") == "on"
	// v2.9.144: response_cache_ttl_sec — set Cache-Control: max-age=N (0 = disabled).
	if v := strings.TrimSpace(r.FormValue("response_cache_ttl_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.ResponseCacheTTLSec = n
		}
	}
	// v2.9.145: add_link_preload — Link response header for HTTP/2 preload hints.
	ph.AddLinkPreload = strings.TrimSpace(r.FormValue("add_link_preload"))
	// v2.9.146: deny_path_regexp — block requests whose path matches this regex (403).
	ph.DenyPathRegexp = strings.TrimSpace(r.FormValue("deny_path_regexp"))
	// v2.9.147: add_request_id_to_response — echo request trace ID in response header.
	ph.AddRequestIDToResponse = r.FormValue("add_request_id_to_response") == "on"
	// v2.9.148: health_check_tls_server_name — TLS SNI override for health check connections.
	ph.HealthCheckTLSServerName = strings.TrimSpace(r.FormValue("health_check_tls_server_name"))
	// v2.9.149: add_x_real_ip — inject X-Real-IP with the direct client IP.
	ph.AddXRealIP = r.FormValue("add_x_real_ip") == "on"
	// v2.9.150: strip_incoming_x_forwarded_for — delete incoming X-Forwarded-For.
	ph.StripIncomingXForwardedFor = r.FormValue("strip_incoming_x_forwarded_for") == "on"
	// v2.9.151: health_check_tls_insecure_skip_verify — skip TLS cert verification for health check probes.
	ph.HealthCheckTLSInsecureSkipVerify = r.FormValue("health_check_tls_insecure_skip_verify") == "on"
	// v2.9.152: add_cors_vary_header — add Vary: Origin response header for CDN caching of CORS responses.
	ph.AddCORSVaryHeader = r.FormValue("add_cors_vary_header") == "on"
	// v2.9.153: upstream_tls_alpn — ALPN protocol list for upstream TLS connections.
	ph.UpstreamTLSALPN = strings.TrimSpace(r.FormValue("upstream_tls_alpn"))
	// v2.9.154: add_x_powered_by — custom X-Powered-By response header value.
	ph.AddXPoweredBy = strings.TrimSpace(r.FormValue("add_x_powered_by"))
	// v2.9.155: block_query_params — comma-separated query param names to block (403).
	ph.BlockQueryParams = strings.TrimSpace(r.FormValue("block_query_params"))
	// v2.9.156: add_document_policy — Document-Policy response header value.
	ph.AddDocumentPolicy = strings.TrimSpace(r.FormValue("add_document_policy"))
	// v2.9.157: maintenance_redirect_url — redirect to this URL during maintenance.
	ph.MaintenanceRedirectURL = strings.TrimSpace(r.FormValue("maintenance_redirect_url"))
	// v2.9.158: upstream_keepalive_max_lifetime_sec — max keepalive connection lifetime.
	if v := strings.TrimSpace(r.FormValue("upstream_keepalive_max_lifetime_sec")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			ph.UpstreamKeepaliveMaxLifetimeSec = n
		}
	}
	// v2.9.159: add_origin_header — inject Origin request header.
	ph.AddOriginHeader = strings.TrimSpace(r.FormValue("add_origin_header"))
	// v2.9.160: upstream_tls_ca_pem_inline — inline PEM CA certificate for upstream TLS.
	ph.UpstreamTLSCAPEMInline = strings.TrimSpace(r.FormValue("upstream_tls_ca_pem_inline"))
	// v2.9.161: add_server_timing_header — inject Server-Timing with upstream duration.
	ph.AddServerTimingHeader = r.FormValue("add_server_timing_header") == "on"
	// v2.9.162: add_clear_site_data — Clear-Site-Data response header value.
	ph.AddClearSiteData = strings.TrimSpace(r.FormValue("add_clear_site_data"))
	// v2.9.163: add_x_dns_prefetch_control — set X-DNS-Prefetch-Control: off.
	ph.AddXDNSPrefetchControl = r.FormValue("add_x_dns_prefetch_control") == "on"
	// v2.9.164: add_accept_ranges — signal byte-range support with Accept-Ranges: bytes.
	ph.AddAcceptRanges = r.FormValue("add_accept_ranges") == "on"
	// v2.9.165: add_content_disposition — set a custom Content-Disposition response header.
	ph.AddContentDisposition = strings.TrimSpace(r.FormValue("add_content_disposition"))
	// v2.9.166: upstream_tls_server_name_from_host — use Host header value as upstream TLS SNI.
	ph.UpstreamTLSServerNameFromHost = r.FormValue("upstream_tls_server_name_from_host") == "on"
	// v2.9.167: add_x_permitted_cross_domain_policies — X-Permitted-Cross-Domain-Policies response header value.
	ph.AddXPermittedCrossDomainPolicies = strings.TrimSpace(r.FormValue("add_x_permitted_cross_domain_policies"))
	// v2.9.168: strip_response_headers — comma-separated list of response headers to delete.
	ph.StripResponseHeaders = strings.TrimSpace(r.FormValue("strip_response_headers"))
	// v2.9.169: add_report_to — Report-To response header value (JSON endpoint group config).
	ph.AddReportTo = strings.TrimSpace(r.FormValue("add_report_to"))
	// v2.9.170: add_nel_header — NEL response header JSON config for Network Error Logging.
	ph.AddNELHeader = strings.TrimSpace(r.FormValue("add_nel_header"))
	// v2.9.171: block_http_methods — comma-separated HTTP methods to reject with 405.
	ph.BlockHTTPMethods = strings.TrimSpace(r.FormValue("block_http_methods"))
	// v2.9.172: add_service_worker_allowed — Service-Worker-Allowed response header value.
	ph.AddServiceWorkerAllowed = strings.TrimSpace(r.FormValue("add_service_worker_allowed"))
	// v2.9.173: add_accept_ch — Accept-CH response header to declare accepted client hints.
	ph.AddAcceptCH = strings.TrimSpace(r.FormValue("add_accept_ch"))
	// v2.9.174: add_alt_svc — Alt-Svc response header for alternate service advertisement.
	ph.AddAltSvc = strings.TrimSpace(r.FormValue("add_alt_svc"))
	// v2.9.175: add_content_language — Content-Language response header value.
	ph.AddContentLanguage = strings.TrimSpace(r.FormValue("add_content_language"))
	// v2.9.176: add_critical_ch — Critical-CH response header (marks client hints required before rendering).
	ph.AddCriticalCH = strings.TrimSpace(r.FormValue("add_critical_ch"))
	// v2.9.177: add_x_download_options — set X-Download-Options: noopen (IE file open prevention).
	ph.AddXDownloadOptions = r.FormValue("add_x_download_options") == "on"
	// v2.9.178: deny_user_agent_regexp — block requests whose User-Agent matches this regexp with 403.
	ph.DenyUserAgentRegexp = strings.TrimSpace(r.FormValue("deny_user_agent_regexp"))
	// v2.9.179: add_pragma_no_cache — set Pragma: no-cache response header.
	ph.AddPragmaNoCache = r.FormValue("add_pragma_no_cache") == "on"
	// v2.9.180: health_check_user_agent — custom User-Agent for active health check probes.
	ph.HealthCheckUserAgent = strings.TrimSpace(r.FormValue("health_check_user_agent"))
	// v2.9.181: add_x_request_path — inject X-Request-Path request header on upstream calls.
	ph.AddXRequestPath = r.FormValue("add_x_request_path") == "on"
	// v2.9.182: add_x_clacks_overhead — X-Clacks-Overhead response header value.
	ph.AddXClacksOverhead = strings.TrimSpace(r.FormValue("add_x_clacks_overhead"))
	// v2.9.183: add_x_ua_compatible — X-UA-Compatible response header value.
	ph.AddXUACompatible = strings.TrimSpace(r.FormValue("add_x_ua_compatible"))
	// v2.9.184: forward_auth_skip_paths — comma-separated path prefixes that bypass forward_auth.
	ph.ForwardAuthSkipPaths = strings.TrimSpace(r.FormValue("forward_auth_skip_paths"))
	// v2.9.185: add_age_zero — set Age: 0 response header to signal a fresh response.
	ph.AddAgeZero = r.FormValue("add_age_zero") == "on"
	// v2.9.186: add_surrogate_control — Surrogate-Control response header value (CDN-only cache directive).
	ph.AddSurrogateControl = strings.TrimSpace(r.FormValue("add_surrogate_control"))
	// v2.9.187: add_warning_header — Warning response header value.
	ph.AddWarningHeader = strings.TrimSpace(r.FormValue("add_warning_header"))
	// v2.9.188: add_x_request_method — forward X-Request-Method header (echoes HTTP method) to upstream.
	ph.AddXRequestMethod = r.FormValue("add_x_request_method") == "on"
	// v2.9.189: add_x_request_query — forward X-Request-Query header (echoes query string) to upstream.
	ph.AddXRequestQuery = r.FormValue("add_x_request_query") == "on"
	// v2.9.190: add_x_forwarded_user — static X-Forwarded-User request header value.
	ph.AddXForwardedUser = strings.TrimSpace(r.FormValue("add_x_forwarded_user"))
	// v2.9.191: add_x_real_scheme — forward X-Real-Scheme request header to upstream.
	ph.AddXRealScheme = r.FormValue("add_x_real_scheme") == "on"
	// v2.9.192: add_origin_agent_cluster — set Origin-Agent-Cluster: ?1 response header.
	ph.AddOriginAgentCluster = r.FormValue("add_origin_agent_cluster") == "on"
	// v2.9.193: add_x_forwarded_groups — static X-Forwarded-Groups request header value.
	ph.AddXForwardedGroups = strings.TrimSpace(r.FormValue("add_x_forwarded_groups"))
	// v2.9.194: add_x_forwarded_email — static X-Forwarded-Email request header value.
	ph.AddXForwardedEmail = strings.TrimSpace(r.FormValue("add_x_forwarded_email"))
	// v2.9.195: add_x_forwarded_roles — static X-Forwarded-Roles request header value.
	ph.AddXForwardedRoles = strings.TrimSpace(r.FormValue("add_x_forwarded_roles"))
	// v2.9.196: block_query_param_regexp — block requests whose query string matches this regexp with 403.
	ph.BlockQueryParamRegexp = strings.TrimSpace(r.FormValue("block_query_param_regexp"))
	// v2.9.197: add_x_request_referer — forward X-Request-Referer header to upstream.
	ph.AddXRequestReferer = r.FormValue("add_x_request_referer") == "on"
	// v2.9.198: add_x_request_origin — forward X-Request-Origin header to upstream.
	ph.AddXRequestOrigin = r.FormValue("add_x_request_origin") == "on"
	// v2.9.199: add_x_forwarded_uri — forward X-Forwarded-URI header to upstream.
	ph.AddXForwardedURI = r.FormValue("add_x_forwarded_uri") == "on"
	// v2.9.200: add_x_no_archive — set X-No-Archive: yes response header.
	ph.AddXNoArchive = r.FormValue("add_x_no_archive") == "on"
	// v2.9.201: add_x_request_hostname — forward X-Request-Hostname header to upstream.
	ph.AddXRequestHostname = r.FormValue("add_x_request_hostname") == "on"
	// v2.9.202: add_x_xss_protection_disabled — set X-XSS-Protection: 0 response header.
	ph.AddXXSSProtectionDisabled = r.FormValue("add_x_xss_protection_disabled") == "on"
	// v2.9.212: add_x_request_remote_port — forward X-Request-Remote-Port header to upstream.
	ph.AddXRequestRemotePort = r.FormValue("add_x_request_remote_port") == "on"
	// v2.9.213: add_x_request_protocol — forward X-Request-Protocol header (HTTP version) to upstream.
	ph.AddXRequestProtocol = r.FormValue("add_x_request_protocol") == "on"
	// v2.9.214: add_save_data_vary — append Save-Data to Vary response header.
	ph.AddSaveDataVary = r.FormValue("add_save_data_vary") == "on"
	// v2.9.217: add_x_environment — static X-Environment request header value.
	ph.AddXEnvironment = strings.TrimSpace(r.FormValue("add_x_environment"))
	// v2.9.218: add_x_trace_id — forward X-Trace-ID header (Caddy UUID per request) to upstream.
	ph.AddXTraceID = r.FormValue("add_x_trace_id") == "on"
	// v2.9.219: health_check_query_params — query string appended to active health check URL.
	ph.HealthCheckQueryParams = strings.TrimSpace(r.FormValue("health_check_query_params"))
	// v2.9.220: add_x_session_id — forward X-Session-ID header to upstream.
	ph.AddXSessionID = r.FormValue("add_x_session_id") == "on"
	// v2.9.221: add_x_response_trace_id — set X-Response-Trace-ID response header.
	ph.AddXResponseTraceID = r.FormValue("add_x_response_trace_id") == "on"
	// v2.9.222: add_x_request_local_addr — forward X-Local-Addr header to upstream.
	ph.AddXRequestLocalAddr = r.FormValue("add_x_request_local_addr") == "on"
	// v2.9.223: add_x_request_local_port — forward X-Local-Port header to upstream.
	ph.AddXRequestLocalPort = r.FormValue("add_x_request_local_port") == "on"
	// v2.9.224: add_x_request_path_info — forward X-PathInfo header to upstream.
	ph.AddXRequestPathInfo = r.FormValue("add_x_request_path_info") == "on"
	// v2.9.234: add_x_authenticated_user — static X-Authenticated-User request header.
	ph.AddXAuthenticatedUser = strings.TrimSpace(r.FormValue("add_x_authenticated_user"))
	// v2.9.235: block_path_extensions — comma-separated extensions to 403.
	ph.BlockPathExtensions = strings.TrimSpace(r.FormValue("block_path_extensions"))
	// v2.9.236: add_link_modulepreload — Link rel=modulepreload value.
	ph.AddLinkModulePreload = strings.TrimSpace(r.FormValue("add_link_modulepreload"))
	// v2.9.237: add_x_remote_user — static X-Remote-User request header.
	ph.AddXRemoteUser = strings.TrimSpace(r.FormValue("add_x_remote_user"))
	// v2.9.238: add_x_forwarded_path — forward X-Forwarded-Path header.
	ph.AddXForwardedPath = r.FormValue("add_x_forwarded_path") == "on"
	// v2.9.239: add_x_geo_country_code — static X-Geo-Country header.
	ph.AddXGeoCountryCode = strings.TrimSpace(r.FormValue("add_x_geo_country_code"))
	// v2.9.240: add_x_request_priority — X-Request-Priority response header (RFC 9218).
	ph.AddXRequestPriority = strings.TrimSpace(r.FormValue("add_x_request_priority"))
	// v2.9.241: health_check_basic_auth — "user:pass" credentials for health check probes.
	ph.HealthCheckBasicAuth = strings.TrimSpace(r.FormValue("health_check_basic_auth"))
	// v2.9.242: add_x_real_ssl_protocol — forward TLS version header.
	ph.AddXRealSSLProtocol = r.FormValue("add_x_real_ssl_protocol") == "on"
	// v2.9.243: add_x_real_ssl_cipher — forward negotiated cipher header.
	ph.AddXRealSSLCipher = r.FormValue("add_x_real_ssl_cipher") == "on"
	// v2.9.244: add_x_cache_status — static X-Cache-Status response header.
	ph.AddXCacheStatus = strings.TrimSpace(r.FormValue("add_x_cache_status"))
	// v2.9.245: deny_referer_regexp — block by Referer regexp with 403.
	ph.DenyRefererRegexp = strings.TrimSpace(r.FormValue("deny_referer_regexp"))
	// v2.9.246: add_x_request_user_agent — echo UA to upstream (debug).
	ph.AddXRequestUserAgent = r.FormValue("add_x_request_user_agent") == "on"
	// v2.9.247: add_reporting_endpoints — Reporting-Endpoints response header (RFC 8942).
	ph.AddReportingEndpoints = strings.TrimSpace(r.FormValue("add_reporting_endpoints"))
	// v2.9.248: add_x_request_byte_count — forward Content-Length as X-Request-Byte-Count.
	ph.AddXRequestByteCount = r.FormValue("add_x_request_byte_count") == "on"
	// v2.9.249: add_x_request_received_at — forward server-side timestamp.
	ph.AddXRequestReceivedAt = r.FormValue("add_x_request_received_at") == "on"
	// v2.9.250: strip_request_headers — comma-separated list of request headers to delete.
	ph.StripRequestHeaders = strings.TrimSpace(r.FormValue("strip_request_headers"))
	// v2.9.251: add_x_forwarded_method — forward HTTP method header.
	ph.AddXForwardedMethod = r.FormValue("add_x_forwarded_method") == "on"
	// v2.9.252: add_x_request_original_host — preserve original Host header.
	ph.AddXRequestOriginalHost = r.FormValue("add_x_request_original_host") == "on"
	// v2.9.253: add_x_request_dnt — forward DNT header.
	ph.AddXRequestDNT = r.FormValue("add_x_request_dnt") == "on"
	// v2.9.254: add_x_geo_region — static X-Geo-Region request header.
	ph.AddXGeoRegion = strings.TrimSpace(r.FormValue("add_x_geo_region"))
	// v2.9.255: add_x_request_secure — X-Request-Secure header based on TLS state.
	ph.AddXRequestSecure = r.FormValue("add_x_request_secure") == "on"
	// v2.9.256: add_x_request_query_count — debug header for query parameters.
	ph.AddXRequestQueryCount = r.FormValue("add_x_request_query_count") == "on"
	// v2.9.257: add_x_request_id_header_response — echo trace UUID to response header.
	ph.AddXRequestIDHeaderResponse = r.FormValue("add_x_request_id_header_response") == "on"
	// v2.9.258: force_canonical_host — canonical host for SEO-style consolidation.
	ph.ForceCanonicalHost = strings.TrimSpace(r.FormValue("force_canonical_host"))
	// v2.9.259: add_x_robots_noindex_quick — X-Robots-Tag: noindex, nofollow.
	ph.AddXRobotsNoindexQuick = r.FormValue("add_x_robots_noindex_quick") == "on"
	// v2.9.260: block_bot_user_agents — built-in bot blocklist.
	ph.BlockBotUserAgents = r.FormValue("block_bot_user_agents") == "on"
	// v2.9.261: block_admin_paths — 404 common admin paths.
	ph.BlockAdminPaths = r.FormValue("block_admin_paths") == "on"
	// v2.9.262: add_link_dns_prefetch — Link rel=dns-prefetch header.
	ph.AddLinkDNSPrefetch = strings.TrimSpace(r.FormValue("add_link_dns_prefetch"))
	// v2.9.263: add_link_preconnect — Link rel=preconnect header.
	ph.AddLinkPreconnect = strings.TrimSpace(r.FormValue("add_link_preconnect"))
	// v2.9.264: add_x_csp_disabled — strip Content-Security-Policy from response.
	ph.AddXCSPDisabled = r.FormValue("add_x_csp_disabled") == "on"
	// v2.9.265: add_x_request_method_override — honor X-HTTP-Method-Override.
	ph.AddXRequestMethodOverride = r.FormValue("add_x_request_method_override") == "on"
	// v2.12.52: disable upstream compression toggle.
	ph.DisableUpstreamCompression = r.FormValue("disable_upstream_compression") == "on"
	// v2.28.0 (issue #39): CaddyUI's own monitoring controls. The override
	// fields are parsed regardless of mode so switching custom → auto → custom
	// doesn't discard what the user typed; the mode alone decides whether they
	// take effect (see models.ProxyHost.MonitorSettings).
	ph.MonitorMode = models.NormalizeMonitorMode(r.FormValue("monitor_mode"))
	ph.MonitorPath = strings.TrimSpace(r.FormValue("monitor_path"))
	// v2.36.0 (issue #59): any method in models.MonitorMethods; blank or
	// unrecognised input is stored as GET so the row is canonical on disk.
	ph.MonitorMethod = models.NormalizeMonitorMethod(r.FormValue("monitor_method"))
	ph.MonitorExpectStatus = clampAtoi(r.FormValue("monitor_expect_status"), 0, 100, 599)
	// Floor the interval at the poller's own tick: a smaller value can't be
	// honoured (the poller only wakes every appHealthInterval) and storing it
	// would promise a cadence the UI can't deliver.
	ph.MonitorIntervalSec = clampAtoi(r.FormValue("monitor_interval_sec"), 0, 60, 86400)
	ph.MonitorTimeoutSec = clampAtoi(r.FormValue("monitor_timeout_sec"), 0, 1, 120)
	// v2.33.0: node-local — never sync this host to another Caddy.
	ph.NodeLocal = r.FormValue("node_local") == "on"
	// v2.9.266: proxy_redirect_rules — JSON array of path-based redirects
	// fired before the reverse_proxy. Same shape as redirection_hosts.
	ph.ProxyRedirectRules = func() string {
		v := strings.TrimSpace(r.FormValue("proxy_redirect_rules"))
		if v == "" || v == "[]" {
			return ""
		}
		var probe []models.RedirectRule
		if err := json.Unmarshal([]byte(v), &probe); err != nil {
			return ""
		}
		return v
	}()
	// v2.9.267: additional_upstream_rules — JSON array of path-based upstream
	// overrides. Probe-parse to drop garbage that UpstreamRuleList would
	// silently ignore on read.
	ph.AdditionalUpstreamRules = func() string {
		v := strings.TrimSpace(r.FormValue("additional_upstream_rules"))
		if v == "" || v == "[]" {
			return ""
		}
		var probe []models.UpstreamRule
		if err := json.Unmarshal([]byte(v), &probe); err != nil {
			return ""
		}
		return v
	}()
	// v2.38.0: expectations_json — post-apply checks; stored canonicalised.
	ph.Expectations = models.NormalizeHostExpectationsJSON(r.FormValue("expectations_json"))
	return ph, nil
}
