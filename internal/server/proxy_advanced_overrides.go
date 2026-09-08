package server

import (
	"fmt"
	"strings"
)

// v2.40.0: the proxy host's Advanced config box wraps its directives in a
// site block and adapts them through Caddy; the resulting handlers run
// before the host's own reverse_proxy. Anything that belongs *inside*
// reverse_proxy — flush_interval, header_up, transport, lb_policy, health
// checks — therefore had no home: typed bare it came back from Caddy as
// "Caddyfile:2: unrecognized directive: flush_interval", and a reverse_proxy
// block was rejected as a second terminal handler. Now a reverse_proxy block
// with no upstream is accepted and its sub-directives are merged into the
// host's generated handler (see caddy.MergeReverseProxyOverrides), and a
// bare sub-directive gets an error that says where it goes.

// reverseProxySubdirectives is every sub-directive of Caddy's reverse_proxy
// directive. Seen at the top level of an Advanced config they are a sure
// sign the user meant the reverse_proxy block.
var reverseProxySubdirectives = []string{
	"to", "dynamic",
	"lb_policy", "lb_retries", "lb_try_duration", "lb_try_interval", "lb_retry_match",
	"health_uri", "health_upstream", "health_port", "health_interval", "health_timeout",
	"health_status", "health_body", "health_method", "health_request_body",
	"health_follow_redirects", "health_headers", "health_passes", "health_fails",
	"fail_duration", "max_fails", "unhealthy_status", "unhealthy_latency", "unhealthy_request_count",
	"flush_interval", "request_buffers", "response_buffers", "stream_timeout", "stream_close_delay",
	"buffer_requests", "buffer_responses", "max_buffer_size", "verbose_logs",
	"trusted_proxies", "header_up", "header_down", "method", "rewrite",
	"transport", "replace_status", "handle_response", "copy_response", "copy_response_headers",
}

// reverseProxySubdirectiveError explains a bare reverse_proxy sub-directive
// at the top level of an Advanced config, or returns "" when there is none.
func reverseProxySubdirectiveError(src string) string {
	bad := scanTopLevelDirective(src, reverseProxySubdirectives)
	if bad == "" {
		return ""
	}
	hint := ""
	switch bad {
	case "flush_interval":
		hint = " This one also has a dedicated option: Streaming → Flush immediately / Flush interval."
	case "header_up", "header_down":
		hint = " Upstream request/response headers also have dedicated options under Headers."
	case "transport":
		hint = " Timeouts, TLS and HTTP version to the upstream also have dedicated options under Upstream."
	case "lb_policy", "lb_retries", "lb_try_duration", "lb_try_interval":
		hint = " Load balancing also has dedicated options under Upstreams."
	}
	return fmt.Sprintf("`%s` is a reverse_proxy sub-directive, not a site directive, so Caddy rejects it here. Wrap it in a reverse_proxy block and CaddyUI merges it into this host's own reverse_proxy:\n\nreverse_proxy {\n    %s …\n}\n\nLeave the upstream address out — it comes from Forward host / port.%s", bad, bad, hint)
}

// extractReverseProxyOverrides removes the reverse_proxy handler that a
// `reverse_proxy { … }` block in the Advanced config adapted to — walking
// into the subroute Caddy wraps site directives in — and returns the
// remaining handlers (which still run before the proxy) plus that handler's
// fields, ready for caddy.MergeReverseProxyOverrides. It is an error for the
// block to name an upstream or to sit behind a matcher: neither can be
// folded into the host's single generated handler.
func extractReverseProxyOverrides(handlers []any) ([]any, map[string]any, error) {
	var overrides map[string]any
	var walk func(hs []any, matched bool) ([]any, error)
	walk = func(hs []any, matched bool) ([]any, error) {
		out := make([]any, 0, len(hs))
		for _, h := range hs {
			hm, ok := h.(map[string]any)
			if !ok {
				out = append(out, h)
				continue
			}
			switch hm["handler"] {
			case "reverse_proxy":
				if matched {
					return nil, fmt.Errorf("a reverse_proxy block behind a matcher can't be merged into this host's reverse_proxy — create an Advanced route for a matched proxy")
				}
				if overrides != nil {
					return nil, fmt.Errorf("Advanced config may contain only one reverse_proxy block")
				}
				if ups, _ := hm["upstreams"].([]any); len(ups) > 0 {
					return nil, fmt.Errorf("the reverse_proxy block in Advanced config must not name an upstream — the address comes from Forward host / port; keep only sub-directives such as flush_interval, header_up or transport")
				}
				overrides = map[string]any{}
				for k, v := range hm {
					if k != "handler" && k != "upstreams" {
						overrides[k] = v
					}
				}
			case "subroute":
				routes, _ := hm["routes"].([]any)
				kept := make([]any, 0, len(routes))
				for _, r := range routes {
					rm, ok := r.(map[string]any)
					if !ok {
						kept = append(kept, r)
						continue
					}
					_, hasMatch := rm["match"]
					inner, _ := rm["handle"].([]any)
					newInner, err := walk(inner, matched || hasMatch)
					if err != nil {
						return nil, err
					}
					if len(inner) > 0 && len(newInner) == 0 {
						continue // the block was this route's only handler
					}
					copyRoute := make(map[string]any, len(rm))
					for k, v := range rm {
						copyRoute[k] = v
					}
					copyRoute["handle"] = newInner
					kept = append(kept, copyRoute)
				}
				if len(routes) > 0 && len(kept) == 0 {
					continue
				}
				copyHandler := make(map[string]any, len(hm))
				for k, v := range hm {
					copyHandler[k] = v
				}
				copyHandler["routes"] = kept
				out = append(out, copyHandler)
			default:
				out = append(out, hm)
			}
		}
		return out, nil
	}
	rest, err := walk(handlers, false)
	if err != nil {
		return nil, nil, err
	}
	return rest, overrides, nil
}

// describeOverrides lists the merged sub-directive keys for log lines.
func describeOverrides(overrides map[string]any) string {
	if len(overrides) == 0 {
		return ""
	}
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
