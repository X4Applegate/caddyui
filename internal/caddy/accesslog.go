package caddy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AccessLogLoggerName is the ID under logging.logs where CaddyUI installs
// its dedicated access-log forwarder. Using a well-known name makes
// enable/disable idempotent — every call lands on the same key so repeated
// toggles don't leak duplicate loggers into the Caddy config.
const AccessLogLoggerName = "caddyui_access"

// CertificateLogLoggerName is the low-volume, always-on stream CaddyUI uses
// to observe certificate issuance and renewal. RuntimeLogLoggerName is the
// temporary, admin-controlled stream used by the Server Logs page.
const (
	CertificateLogLoggerName = "caddyui_certificates"
	RuntimeLogLoggerName     = "caddyui_runtime"
)

// AccessLogDeleteMethod is exposed so callers can tell what HTTP verb the
// cleanup path uses, mostly for tests. Admin API DELETEs are idempotent
// (404 is fine), which is why DisableAccessLogs doesn't treat "not found"
// as an error.
const AccessLogDeleteMethod = http.MethodDelete

// AccessLogOptions controls how Caddy connects to CaddyUI's analytics ingest
// listener. SoftStart prevents an unavailable listener from blocking Caddy's
// config load; DialTimeout limits how long a failed connection may block log
// emission before Caddy falls back to stderr.
type AccessLogOptions struct {
	SoftStart   bool
	DialTimeout time.Duration
	ServerID    int64
	ServerName  string
}

func networkLogWriter(target string, opts AccessLogOptions) map[string]any {
	writer := map[string]any{
		"output":  "net",
		"address": target,
	}
	if opts.SoftStart {
		writer["soft_start"] = true
	}
	if opts.DialTimeout > 0 {
		writer["dial_timeout"] = opts.DialTimeout.String()
	}
	return writer
}

// annotatedJSONEncoder stamps every forwarded entry with the CaddyUI fleet
// server that produced it. The append encoder is part of Caddy core and uses
// a JSON encoder underneath, so the ingest path receives normal structured
// logs plus stable source metadata without changing route handlers.
func annotatedJSONEncoder(opts AccessLogOptions) map[string]any {
	fields := map[string]any{
		"caddyui_server_id":   opts.ServerID,
		"caddyui_server_name": strings.TrimSpace(opts.ServerName),
	}
	return map[string]any{
		"format": "append",
		"fields": fields,
		"wrap":   map[string]any{"format": "json"},
	}
}

// installNamedLog creates or replaces one entry below logging.logs while
// preserving unrelated loggers. Fresh Caddy configs often have no logging
// tree at all, in which case the path API cannot traverse the missing parent;
// bootstrap the parent object and merge any loggers that do exist.
func (c *Client) installNamedLog(name string, logger map[string]any) error {
	if err := c.PutPath("/config/logging/logs/"+name, logger); err == nil {
		return nil
	} else if !isCaddyMissingPathErr(err.Error()) {
		return err
	}

	logs := map[string]any{name: logger}
	if cfg, _, cfgErr := c.FetchConfig(); cfgErr == nil {
		if logging, _ := cfg["logging"].(map[string]any); logging != nil {
			if existing, _ := logging["logs"].(map[string]any); existing != nil {
				for key, value := range existing {
					if key != name {
						logs[key] = value
					}
				}
			}
		}
	}
	return c.PutPath("/config/logging", map[string]any{"logs": logs})
}

// EnableAccessLogs configures the live Caddy instance to stream its access
// logs to target over plain TCP (NDJSON, one request per line). target is a
// host:port string — typically "caddyui:9019" inside a shared docker network
// or "host.docker.internal:9019" when CaddyUI is on the host and Caddy is
// containerised.
//
// Three things change in Caddy's config:
//
//  1. logging.logs.caddyui_access is created (or replaced) with a net-writer
//     that points at target. Only logs tagged http.log.access are routed
//     there, so Caddy's own admin / app logs aren't shipped.
//  2. Every entry under apps.http.servers is patched to have a non-empty
//     logs block — Caddy only emits http.log.access events for servers
//     with logs enabled, so without this step our logger sits unused.
//  3. apps.http.servers.<name>.logs.default_logger_name is set to
//     caddyui_access so requests without an explicit per-host logger go
//     to us. Per-host `log` directives in the Caddyfile will continue to
//     win when present — this just sets the default.
//
// Returns an error if Caddy's admin API rejects any step. Callers should
// fall back to DisableAccessLogs on failure to avoid leaving the config in
// a half-enabled state where the logger exists but no server emits events.
func (c *Client) EnableAccessLogs(target string, opts AccessLogOptions) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("EnableAccessLogs: target is empty")
	}

	// Step 1: install the net-writer logger. Use PUT on the specific key so
	// the call is create-or-replace — PATCH would 404 on first run.
	logger := map[string]any{
		"writer":  networkLogWriter(target, opts),
		"encoder": annotatedJSONEncoder(opts),
		"include": []string{"http.log.access"},
	}
	if err := c.installNamedLog(AccessLogLoggerName, logger); err != nil {
		return fmt.Errorf("install access-log logger: %w", err)
	}

	// Step 2+3: fetch the server names, then patch each one's logs block.
	// We can't patch .../servers/*/logs with a wildcard — Caddy's admin API
	// is path-oriented, not pattern-oriented — so we enumerate servers and
	// issue one PUT per server. Typical caddyui deployments have one
	// server, so this is a one-request loop in practice.
	servers, err := c.listHTTPServerNames()
	if err != nil {
		return fmt.Errorf("list http servers for access-log enable: %w", err)
	}
	if len(servers) == 0 {
		// Logger is installed but nothing will feed it — return a
		// descriptive error so the admin knows to add a site block first.
		return fmt.Errorf("access-log logger installed but no http servers exist in Caddy config")
	}
	for _, srv := range servers {
		logsCfg := map[string]any{
			"default_logger_name": AccessLogLoggerName,
		}
		if err := c.PutPath("/config/apps/http/servers/"+srv+"/logs", logsCfg); err != nil {
			return fmt.Errorf("enable logs on server %q: %w", srv, err)
		}
	}
	return nil
}

// EnableCertificateLogs duplicates Caddy's TLS runtime log namespace to the
// CaddyUI ingest socket. Caddy's default logger remains unchanged, so normal
// container/journal logs continue to receive the same messages. The stream is
// intentionally INFO-level and low-volume; CaddyUI persists only the latest
// lifecycle state per server and certificate identifier.
func (c *Client) EnableCertificateLogs(target string, opts AccessLogOptions) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("EnableCertificateLogs: target is empty")
	}
	logger := map[string]any{
		"writer":  networkLogWriter(target, opts),
		"encoder": annotatedJSONEncoder(opts),
		"include": []string{"tls"},
		"level":   "INFO",
	}
	if err := c.installNamedLog(CertificateLogLoggerName, logger); err != nil {
		return fmt.Errorf("install certificate logger: %w", err)
	}
	return nil
}

// EnableRuntimeLogs installs a temporary duplicate stream for operational
// Caddy logs. Access logs are excluded because they already have a dedicated
// analytics stream; TLS logs are excluded because the certificate monitor
// supplies them continuously. No existing logger is replaced or redirected.
func (c *Client) EnableRuntimeLogs(target, level string, opts AccessLogOptions) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("EnableRuntimeLogs: target is empty")
	}
	level = strings.ToUpper(strings.TrimSpace(level))
	switch level {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		level = "INFO"
	}
	logger := map[string]any{
		"writer":  networkLogWriter(target, opts),
		"encoder": annotatedJSONEncoder(opts),
		"exclude": []string{"http.log.access", "tls"},
		"level":   level,
	}
	if err := c.installNamedLog(RuntimeLogLoggerName, logger); err != nil {
		return fmt.Errorf("install runtime logger: %w", err)
	}
	return nil
}

// DisableRuntimeLogs stops the temporary operational stream. It does not
// touch Caddy's default logger, access analytics, or certificate monitoring.
func (c *Client) DisableRuntimeLogs() error {
	if err := c.deletePathIgnoreMissing("/config/logging/logs/" + RuntimeLogLoggerName); err != nil {
		return fmt.Errorf("remove runtime logger: %w", err)
	}
	return nil
}

// DisableAccessLogs reverses EnableAccessLogs. Removes the caddyui_access
// logger and deletes the logs block on every http server. Missing paths
// are not treated as errors — a DELETE on a path that Caddy doesn't know
// about returns 404 and we swallow it, so repeated disable calls are
// idempotent and safe after a partial-enable rollback.
func (c *Client) DisableAccessLogs() error {
	// Step 1: remove the logger. If the admin toggled off the feature
	// while Caddy was also holding a per-server `logs` block, skipping
	// this leaves the logger attached to servers that no longer have a
	// writer — which Caddy treats as "log nowhere", silently.
	if err := c.deletePathIgnoreMissing("/config/logging/logs/" + AccessLogLoggerName); err != nil {
		return fmt.Errorf("remove access-log logger: %w", err)
	}

	// Step 2: clear the logs block on each http server. Caddyfile sites
	// with their own explicit `log` directive will re-install a logs
	// block on next adapt — that's fine, we only want to undo our own
	// automatic wiring here.
	servers, err := c.listHTTPServerNames()
	if err != nil {
		// If we can't enumerate servers, we can't be sure nothing is
		// still pointing at the logger — but the logger is already
		// gone, so access logs are effectively off. Surface the error
		// but don't fail hard.
		return fmt.Errorf("list http servers for access-log disable: %w", err)
	}
	for _, srv := range servers {
		if err := c.deletePathIgnoreMissing("/config/apps/http/servers/" + srv + "/logs"); err != nil {
			return fmt.Errorf("clear logs on server %q: %w", srv, err)
		}
	}
	return nil
}

// listHTTPServerNames returns the keys under apps.http.servers. Empty slice
// means Caddy has no HTTP app configured (possible on a fresh boot before
// the first sync). The admin API returns null for missing paths, which we
// normalise to an empty slice so callers don't have to special-case it.
func (c *Client) listHTTPServerNames() ([]string, error) {
	cfg, _, err := c.FetchConfig()
	if err != nil {
		return nil, err
	}
	apps, _ := cfg["apps"].(map[string]any)
	if apps == nil {
		return nil, nil
	}
	httpApp, _ := apps["http"].(map[string]any)
	if httpApp == nil {
		return nil, nil
	}
	servers, _ := httpApp["servers"].(map[string]any)
	if servers == nil {
		return nil, nil
	}
	names := make([]string, 0, len(servers))
	for k := range servers {
		names = append(names, k)
	}
	return names, nil
}

// deletePathIgnoreMissing issues a DELETE on a config path and treats 404
// as success. Caddy's admin API is strict about path existence — deleting
// a non-existent key returns "config path not found" — but for our
// toggle-off flow that's the outcome we want anyway.
func (c *Client) deletePathIgnoreMissing(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.AdminURL+path, nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil // idempotent — already gone
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	// Caddy uses a non-standard body with {"error":"..."}; surface it so
	// the admin can see what went wrong without having to tail caddyui
	// logs and the caddy logs side-by-side.
	if body.Error != "" {
		// "target doesn't exist" phrasings across Caddy versions are the
		// expected outcome of disable-when-already-disabled — treat as
		// idempotent success. Details at isCaddyMissingPathErr below.
		if isCaddyMissingPathErr(body.Error) {
			return nil
		}
		return fmt.Errorf("caddy DELETE %s: %s", path, body.Error)
	}
	return fmt.Errorf("caddy DELETE %s: status %d", path, resp.StatusCode)
}

// isCaddyMissingPathErr reports whether a Caddy admin-API error body means
// "this path or one of its parents doesn't exist." Shared by the delete
// flow (treats it as idempotent success — already gone) and the enable
// flow (treats it as a signal to bootstrap the parent tree and retry).
//
// Empirically observed phrasings across Caddy versions:
//   - "config path not found"                  (modern 404)
//   - "unknown key: <name>"                    (older releases, 400)
//   - "invalid traversal path at: <path>"      (parent is null/missing —
//     e.g. a fresh Caddy where `logging` has never been set. Hit by DELETE
//     on first toggle-off before any enable, and by PUT on first enable
//     before any logger has ever been installed.)
func isCaddyMissingPathErr(msg string) bool {
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "unknown") ||
		strings.Contains(msg, "invalid traversal path")
}
