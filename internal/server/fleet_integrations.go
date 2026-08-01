package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

const (
	settingAccessLogEnabled    = "fleet_access_log_enabled"
	settingAccessLogPath       = "fleet_access_log_path"
	settingAccessLogFormat     = "fleet_access_log_format"
	settingAccessLogScope      = "fleet_access_log_scope"
	settingAccessLogRollSize   = "fleet_access_log_roll_size_mb"
	settingAccessLogRollKeep   = "fleet_access_log_roll_keep"
	settingAccessLogRollDays   = "fleet_access_log_roll_keep_days"
	settingAccessLogServerIDs  = "fleet_access_log_server_ids"
	settingClientIPHeaders     = "client_ip_headers"
	settingCrowdSecEnabled     = "crowdsec_enabled"
	settingCrowdSecAPIURL      = "crowdsec_api_url"
	settingCrowdSecAPIKey      = "crowdsec_api_key"
	settingCrowdSecStreaming   = "crowdsec_streaming"
	settingCrowdSecTicker      = "crowdsec_ticker_interval"
	settingCrowdSecHardFails   = "crowdsec_hard_fails"
	settingCrowdSecServerIDs   = "crowdsec_server_ids"
	settingCrowdSecExcludeHost = "crowdsec_excluded_hosts"
	settingCrowdSecExcludePath = "crowdsec_excluded_paths"

	fleetAccessLoggerName = "caddyui_file_access"
)

type fleetAccessLogConfig struct {
	Enabled      bool
	Path         string
	Format       string
	Scope        string
	RollSizeMB   int
	RollKeep     int
	RollKeepDays int
	ServerIDs    map[int64]bool
}

func loadFleetAccessLogConfig(db *sql.DB) fleetAccessLogConfig {
	cfg := fleetAccessLogConfig{
		Enabled:      mustGetSetting(db, settingAccessLogEnabled) == "1",
		Path:         strings.TrimSpace(mustGetSetting(db, settingAccessLogPath)),
		Format:       strings.ToLower(strings.TrimSpace(mustGetSetting(db, settingAccessLogFormat))),
		Scope:        strings.ToLower(strings.TrimSpace(mustGetSetting(db, settingAccessLogScope))),
		RollSizeMB:   positiveIntSetting(db, settingAccessLogRollSize, 100),
		RollKeep:     nonNegativeIntSetting(db, settingAccessLogRollKeep, 10),
		RollKeepDays: nonNegativeIntSetting(db, settingAccessLogRollDays, 90),
		ServerIDs:    parseServerIDs(mustGetSetting(db, settingAccessLogServerIDs)),
	}
	if cfg.Path == "" {
		cfg.Path = "/var/log/caddy/access.log"
	}
	if cfg.Format != "console" {
		cfg.Format = "json"
	}
	if cfg.Scope != "http" && cfg.Scope != "https" {
		cfg.Scope = "all"
	}
	return cfg
}

func (c fleetAccessLogConfig) enabledFor(serverID int64) bool {
	return c.Enabled && c.ServerIDs[serverID]
}

func (c fleetAccessLogConfig) logger() map[string]any {
	return map[string]any{
		"writer": map[string]any{
			"output":         "file",
			"filename":       c.Path,
			"roll_size_mb":   c.RollSizeMB,
			"roll_keep":      c.RollKeep,
			"roll_keep_days": c.RollKeepDays,
		},
		"encoder": map[string]any{"format": c.Format},
		"include": []any{"http.log.access"},
	}
}

type crowdSecConfig struct {
	Enabled       bool
	APIURL        string
	APIKey        string
	Streaming     bool
	Ticker        string
	HardFails     bool
	ServerIDs     map[int64]bool
	ExcludedHosts map[string]bool
	ExcludedPaths []string
}

func loadCrowdSecConfig(db *sql.DB) crowdSecConfig {
	cfg := crowdSecConfig{
		Enabled:       mustGetSetting(db, settingCrowdSecEnabled) == "1",
		APIURL:        strings.TrimSpace(mustGetSetting(db, settingCrowdSecAPIURL)),
		APIKey:        strings.TrimSpace(mustGetSetting(db, settingCrowdSecAPIKey)),
		Streaming:     mustGetSetting(db, settingCrowdSecStreaming) != "0",
		Ticker:        strings.TrimSpace(mustGetSetting(db, settingCrowdSecTicker)),
		HardFails:     mustGetSetting(db, settingCrowdSecHardFails) == "1",
		ServerIDs:     parseServerIDs(mustGetSetting(db, settingCrowdSecServerIDs)),
		ExcludedHosts: parseHostSet(mustGetSetting(db, settingCrowdSecExcludeHost)),
		ExcludedPaths: parsePathList(mustGetSetting(db, settingCrowdSecExcludePath)),
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "http://crowdsec:8080/"
	}
	if cfg.Ticker == "" {
		cfg.Ticker = "15s"
	}
	return cfg
}

func fleetAccessLogConfigFromForm(r *http.Request) (fleetAccessLogConfig, error) {
	rollSize, err := strconv.Atoi(strings.TrimSpace(r.FormValue("fleet_access_log_roll_size_mb")))
	if err != nil {
		return fleetAccessLogConfig{}, fmt.Errorf("access log maximum file size must be a number")
	}
	rollKeep, err := strconv.Atoi(strings.TrimSpace(r.FormValue("fleet_access_log_roll_keep")))
	if err != nil {
		return fleetAccessLogConfig{}, fmt.Errorf("access log retained-file count must be a number")
	}
	rollDays, err := strconv.Atoi(strings.TrimSpace(r.FormValue("fleet_access_log_roll_keep_days")))
	if err != nil {
		return fleetAccessLogConfig{}, fmt.Errorf("access log retention period must be a number")
	}
	cfg := fleetAccessLogConfig{
		Enabled:      formHasValue(r, "fleet_access_log_enabled", "1"),
		Path:         strings.TrimSpace(r.FormValue("fleet_access_log_path")),
		Format:       strings.ToLower(strings.TrimSpace(r.FormValue("fleet_access_log_format"))),
		Scope:        strings.ToLower(strings.TrimSpace(r.FormValue("fleet_access_log_scope"))),
		RollSizeMB:   rollSize,
		RollKeep:     rollKeep,
		RollKeepDays: rollDays,
		ServerIDs:    parseServerIDs(strings.Join(r.PostForm["fleet_access_log_server_ids"], ",")),
	}
	if cfg.Format != "console" {
		cfg.Format = "json"
	}
	if cfg.Scope != "http" && cfg.Scope != "https" {
		cfg.Scope = "all"
	}
	return cfg, validateFleetAccessLogConfig(cfg)
}

func crowdSecConfigFromForm(r *http.Request, db *sql.DB) (crowdSecConfig, error) {
	key := strings.TrimSpace(r.FormValue("crowdsec_api_key"))
	if key == "" {
		key = strings.TrimSpace(mustGetSetting(db, settingCrowdSecAPIKey))
	}
	cfg := crowdSecConfig{
		Enabled:       formHasValue(r, "crowdsec_enabled", "1"),
		APIURL:        strings.TrimSpace(r.FormValue("crowdsec_api_url")),
		APIKey:        key,
		Streaming:     formHasValue(r, "crowdsec_streaming", "1"),
		Ticker:        strings.TrimSpace(r.FormValue("crowdsec_ticker_interval")),
		HardFails:     formHasValue(r, "crowdsec_hard_fails", "1"),
		ServerIDs:     parseServerIDs(strings.Join(r.PostForm["crowdsec_server_ids"], ",")),
		ExcludedHosts: parseHostSet(r.FormValue("crowdsec_excluded_hosts")),
		ExcludedPaths: parsePathList(r.FormValue("crowdsec_excluded_paths")),
	}
	return cfg, validateCrowdSecConfig(cfg)
}

func formHasValue(r *http.Request, key, wanted string) bool {
	for _, value := range r.PostForm[key] {
		if value == wanted {
			return true
		}
	}
	return false
}

func fleetIntegrationSettings(access fleetAccessLogConfig, crowd crowdSecConfig, clientIPHeaders string) map[string]string {
	boolString := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	pathList := strings.Join(crowd.ExcludedPaths, "\n")
	hosts := make([]string, 0, len(crowd.ExcludedHosts))
	for host := range crowd.ExcludedHosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return map[string]string{
		settingAccessLogEnabled:    boolString(access.Enabled),
		settingAccessLogPath:       access.Path,
		settingAccessLogFormat:     access.Format,
		settingAccessLogScope:      access.Scope,
		settingAccessLogRollSize:   strconv.Itoa(access.RollSizeMB),
		settingAccessLogRollKeep:   strconv.Itoa(access.RollKeep),
		settingAccessLogRollDays:   strconv.Itoa(access.RollKeepDays),
		settingAccessLogServerIDs:  serverIDsCSV(mapKeys(access.ServerIDs)),
		settingClientIPHeaders:     strings.TrimSpace(clientIPHeaders),
		settingCrowdSecEnabled:     boolString(crowd.Enabled),
		settingCrowdSecAPIURL:      crowd.APIURL,
		settingCrowdSecStreaming:   boolString(crowd.Streaming),
		settingCrowdSecTicker:      crowd.Ticker,
		settingCrowdSecHardFails:   boolString(crowd.HardFails),
		settingCrowdSecServerIDs:   serverIDsCSV(mapKeys(crowd.ServerIDs)),
		settingCrowdSecExcludeHost: strings.Join(hosts, "\n"),
		settingCrowdSecExcludePath: pathList,
	}
}

func mapKeys(values map[int64]bool) []string {
	out := make([]string, 0, len(values))
	for id, enabled := range values {
		if enabled {
			out = append(out, strconv.FormatInt(id, 10))
		}
	}
	return out
}

func crowdSecConfigFingerprint(cfg crowdSecConfig) string {
	servers := serverIDsCSV(mapKeys(cfg.ServerIDs))
	hosts := make([]string, 0, len(cfg.ExcludedHosts))
	for host := range cfg.ExcludedHosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return strings.Join([]string{
		strconv.FormatBool(cfg.Enabled), cfg.APIURL, cfg.APIKey,
		strconv.FormatBool(cfg.Streaming), cfg.Ticker,
		strconv.FormatBool(cfg.HardFails), servers,
		strings.Join(hosts, ","), strings.Join(cfg.ExcludedPaths, ","),
	}, "\x00")
}

func (c crowdSecConfig) enabledFor(serverID int64) bool {
	return c.Enabled && c.ServerIDs[serverID]
}

func (c crowdSecConfig) app() map[string]any {
	return map[string]any{
		"api_url":           c.APIURL,
		"api_key":           c.APIKey,
		"ticker_interval":   c.Ticker,
		"enable_streaming":  c.Streaming,
		"enable_hard_fails": c.HardFails,
	}
}

func positiveIntSetting(db *sql.DB, key string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(mustGetSetting(db, key)))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func nonNegativeIntSetting(db *sql.DB, key string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(mustGetSetting(db, key)))
	if err != nil || v < 0 {
		return fallback
	}
	return v
}

func parseServerIDs(raw string) map[int64]bool {
	out := map[int64]bool{}
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if id, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64); err == nil && id > 0 {
			out[id] = true
		}
	}
	return out
}

func serverIDsCSV(values []string) string {
	set := parseServerIDs(strings.Join(values, ","))
	ids := make([]int64, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

func parseHostSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		host := strings.ToLower(strings.TrimSpace(field))
		if host != "" {
			out[host] = true
		}
	}
	return out
}

func parsePathList(raw string) []string {
	seen := map[string]bool{}
	var out []string
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		path := strings.TrimSpace(field)
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}

func validateFleetAccessLogConfig(cfg fleetAccessLogConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.ServerIDs) == 0 {
		return fmt.Errorf("select at least one Caddy server for file access logging")
	}
	if !filepath.IsAbs(cfg.Path) {
		return fmt.Errorf("access log path must be absolute")
	}
	if cfg.RollSizeMB <= 0 || cfg.RollSizeMB > 1_000_000 {
		return fmt.Errorf("access log maximum size must be between 1 and 1000000 MB")
	}
	if cfg.RollKeep < 0 || cfg.RollKeep > 100_000 || cfg.RollKeepDays < 0 || cfg.RollKeepDays > 36500 {
		return fmt.Errorf("access log retention values are outside the supported range")
	}
	return nil
}

func validateCrowdSecConfig(cfg crowdSecConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.ServerIDs) == 0 {
		return fmt.Errorf("select at least one Caddy server for CrowdSec")
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("CrowdSec bouncer API key is required")
	}
	if !strings.HasPrefix(cfg.APIURL, "http://") && !strings.HasPrefix(cfg.APIURL, "https://") {
		return fmt.Errorf("CrowdSec LAPI URL must begin with http:// or https://")
	}
	if d, err := time.ParseDuration(cfg.Ticker); err != nil || d <= 0 {
		return fmt.Errorf("CrowdSec decision refresh interval must be a positive duration such as 15s")
	}
	return nil
}

func applyClientIPSettings(cfg map[string]any, db *sql.DB) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	rawProxies := strings.TrimSpace(mustGetSetting(db, settingTrustedProxies))
	rawHeaders := strings.TrimSpace(mustGetSetting(db, settingClientIPHeaders))

	var ranges []any
	for _, field := range strings.FieldsFunc(rawProxies, func(r rune) bool { return r == ',' || r == '\n' }) {
		if value := strings.TrimSpace(field); value != "" {
			ranges = append(ranges, value)
		}
	}
	var headers []any
	for _, field := range strings.FieldsFunc(rawHeaders, func(r rune) bool { return r == ',' || r == '\n' }) {
		if value := http.CanonicalHeaderKey(strings.TrimSpace(field)); value != "" {
			headers = append(headers, value)
		}
	}

	for _, name := range []string{"srv0", "caddyui_http"} {
		srv, ok := servers[name].(map[string]any)
		if !ok {
			continue
		}
		if len(ranges) > 0 {
			srv["trusted_proxies"] = map[string]any{"source": "static", "ranges": ranges}
		} else {
			delete(srv, "trusted_proxies")
		}
		if len(headers) > 0 {
			srv["client_ip_headers"] = headers
		} else {
			delete(srv, "client_ip_headers")
		}
	}
}

func applyFleetAccessLog(cfg map[string]any, access fleetAccessLogConfig, analyticsEnabled bool, serverID int64) {
	logging, _ := cfg["logging"].(map[string]any)
	if logging == nil {
		logging = map[string]any{}
		cfg["logging"] = logging
	}
	logs := ensureMap(logging, "logs")
	enabled := access.enabledFor(serverID)
	if enabled {
		logs[fleetAccessLoggerName] = access.logger()
	} else {
		delete(logs, fleetAccessLoggerName)
	}
	if len(logs) == 0 {
		delete(logging, "logs")
	}
	if len(logging) == 0 {
		delete(cfg, "logging")
	}

	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	for _, name := range []string{"srv0", "caddyui_http"} {
		srv, ok := servers[name].(map[string]any)
		if !ok {
			continue
		}
		applies := enabled && (access.Scope == "all" || (access.Scope == "https" && name == "srv0") || (access.Scope == "http" && name == "caddyui_http"))
		logsCfg, _ := srv["logs"].(map[string]any)
		if applies {
			if logsCfg == nil {
				logsCfg = map[string]any{}
				srv["logs"] = logsCfg
			}
			currentLogger, _ := logsCfg["default_logger_name"].(string)
			if !analyticsEnabled && strings.TrimSpace(currentLogger) == "" {
				logsCfg["default_logger_name"] = fleetAccessLoggerName
			}
			continue
		}
		if logsCfg == nil {
			continue
		}
		if logsCfg["default_logger_name"] == fleetAccessLoggerName {
			delete(logsCfg, "default_logger_name")
		}
		if len(logsCfg) == 0 {
			delete(srv, "logs")
		}
	}
}

func applyCrowdSecApp(cfg map[string]any, crowd crowdSecConfig, serverID int64) {
	apps := ensureMap(cfg, "apps")
	if crowd.enabledFor(serverID) {
		apps["crowdsec"] = crowd.app()
	} else {
		delete(apps, "crowdsec")
	}
}

func protectRoutesWithCrowdSec(routes []any, crowd crowdSecConfig, serverID int64) []any {
	if !crowd.enabledFor(serverID) {
		return routes
	}
	out := make([]any, 0, len(routes))
	for _, raw := range routes {
		route, ok := raw.(map[string]any)
		if !ok || crowdSecRouteExcluded(route, crowd.ExcludedHosts) {
			out = append(out, raw)
			continue
		}
		handlers, _ := route["handle"].([]any)
		guard := any(map[string]any{"handler": "crowdsec"})
		if len(crowd.ExcludedPaths) > 0 {
			paths := make([]any, 0, len(crowd.ExcludedPaths))
			for _, path := range crowd.ExcludedPaths {
				paths = append(paths, path)
			}
			guard = map[string]any{
				"handler": "subroute",
				"routes": []any{
					map[string]any{"match": []any{map[string]any{"path": paths}}, "terminal": true},
					map[string]any{"handle": []any{map[string]any{"handler": "crowdsec"}}},
				},
			}
		}
		route["handle"] = append([]any{guard}, handlers...)
		out = append(out, route)
	}
	return out
}

func crowdSecRouteExcluded(route map[string]any, excluded map[string]bool) bool {
	if len(excluded) == 0 {
		return false
	}
	matches, _ := route["match"].([]any)
	for _, rawMatch := range matches {
		match, _ := rawMatch.(map[string]any)
		hosts, _ := match["host"].([]any)
		for _, rawHost := range hosts {
			if host, ok := rawHost.(string); ok && excluded[strings.ToLower(strings.TrimSpace(host))] {
				return true
			}
		}
	}
	return false
}

func (s *Server) writeLoggingConfig(proposed map[string]any) error {
	want, _ := proposed["logging"].(map[string]any)
	existing, err := s.Caddy.FetchPath("/config/logging")
	if err != nil {
		return err
	}
	if len(want) == 0 {
		if existing == nil {
			return nil
		}
		return s.Caddy.DeletePath("/logging")
	}
	if configValuesEqual(existing, want) {
		return nil
	}
	return s.Caddy.PutPath("/config/logging", want)
}

func (s *Server) writeCrowdSecApp(proposed map[string]any, enabled bool) error {
	apps, _ := proposed["apps"].(map[string]any)
	want, _ := apps["crowdsec"].(map[string]any)
	existing, err := s.Caddy.FetchPath("/config/apps/crowdsec")
	if err != nil {
		return err
	}
	if !enabled || len(want) == 0 {
		if existing == nil {
			return nil
		}
		return s.Caddy.DeletePath("/apps/crowdsec")
	}
	if configValuesEqual(existing, want) {
		return nil
	}
	return s.Caddy.PutPath("/config/apps/crowdsec", want)
}

// writeFleetServerOptions applies the small server-level fields managed by the
// fleet integration cards without replacing the complete server object. That
// preserves listeners, TLS policies, routes, and any options owned outside
// CaddyUI while ensuring HTTP/HTTPS log and real-client-IP settings stay in
// sync on both generated servers.
func (s *Server) writeFleetServerOptions(proposed map[string]any) error {
	apps, _ := proposed["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for _, name := range []string{"srv0", "caddyui_http"} {
		srv, exists := servers[name].(map[string]any)
		if !exists {
			continue
		}
		for _, key := range []string{"logs", "trusted_proxies", "client_ip_headers"} {
			path := "/config/apps/http/servers/" + name + "/" + key
			if err := s.writeOptionalConfigValue(path, srv[key]); err != nil {
				return fmt.Errorf("write %s.%s: %w", name, key, err)
			}
		}
	}
	return nil
}

func (s *Server) writeOptionalConfigValue(path string, want any) error {
	existing, err := s.Caddy.FetchPath(path)
	if err != nil {
		return err
	}
	if want == nil {
		if existing == nil {
			return nil
		}
		return s.Caddy.DeletePath(strings.TrimPrefix(path, "/config"))
	}
	if existing == nil {
		return s.Caddy.PutPath(path, want)
	}
	if configValuesEqual(existing, want) {
		return nil
	}
	return s.Caddy.PatchPath(path, want)
}

func configValuesEqual(a, b any) bool {
	aJSON, errA := json.Marshal(a)
	bJSON, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(aJSON) == string(bJSON)
}

func (s *Server) validateCrowdSecServers(crowd crowdSecConfig) error {
	if !crowd.Enabled {
		return nil
	}
	servers, err := models.ListCaddyServers(s.DB)
	if err != nil {
		return fmt.Errorf("list Caddy servers: %w", err)
	}
	seen := map[int64]bool{}
	for _, srv := range servers {
		if !crowd.ServerIDs[srv.ID] {
			continue
		}
		seen[srv.ID] = true
		if srv.Type == models.CaddyServerTypeExternal {
			return fmt.Errorf("CrowdSec cannot be enabled on read-only server %q", srv.Name)
		}
		client := newCaddyClient(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
		current, _, err := client.FetchConfig()
		if err != nil {
			return fmt.Errorf("check CrowdSec modules on %s: %w", srv.Name, err)
		}
		probe, err := deepCopyMap(current)
		if err != nil {
			return fmt.Errorf("build CrowdSec module check for %s: %w", srv.Name, err)
		}
		apps := ensureMap(probe, "apps")
		apps["crowdsec"] = crowd.app()
		httpApp := ensureMap(apps, "http")
		httpServers := ensureMap(httpApp, "servers")
		httpServers["caddyui_crowdsec_probe"] = map[string]any{
			"listen": []any{"127.0.0.1:0"},
			"routes": []any{map[string]any{
				"handle": []any{map[string]any{"handler": "crowdsec"}},
			}},
		}
		if err := client.Validate(probe); err != nil {
			return fmt.Errorf("Caddy server %q does not accept the CrowdSec app and http.handlers.crowdsec modules: %w", srv.Name, err)
		}
	}
	for id := range crowd.ServerIDs {
		if !seen[id] {
			return fmt.Errorf("selected CrowdSec server %d no longer exists", id)
		}
	}
	return nil
}

func (s *Server) postTestCrowdSec(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	serverID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		http.Error(w, "invalid Caddy server", http.StatusBadRequest)
		return
	}
	crowd := loadCrowdSecConfig(s.DB)
	if !crowd.enabledFor(serverID) {
		http.Error(w, "CrowdSec is not enabled for that server", http.StatusBadRequest)
		return
	}
	srv, err := models.GetCaddyServer(s.DB, serverID)
	if err != nil || srv.Type == models.CaddyServerTypeExternal {
		http.Error(w, "Caddy server is unavailable or read-only", http.StatusBadRequest)
		return
	}
	client := newCaddyClient(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	var response struct {
		OK bool `json:"Ok"`
	}
	if err := client.PostAdminJSON("/crowdsec/ping", map[string]any{}, &response); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"ok":false,"error":` + strconv.Quote(err.Error()) + `}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !response.OK {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"ok":false,"error":"CrowdSec LAPI did not respond successfully"}`))
		return
	}
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func integrationServerSelection(servers []models.CaddyServer, selected map[int64]bool) map[int64]bool {
	out := map[int64]bool{}
	for _, srv := range servers {
		out[srv.ID] = selected[srv.ID]
	}
	return out
}
