package server

import (
	"fmt"
	"regexp"
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

// wrapBareReverseProxySubdirectives (v2.42.1) moves reverse_proxy
// sub-directives typed at the top level of an Advanced config into a
// `reverse_proxy { … }` block — merged into an existing one when there is
// one — so `flush_interval -1` on its own simply works instead of being
// explained back to the user. Multi-line sub-directives (a transport block)
// move with their braces. Sources that need no change come back unchanged.
func wrapBareReverseProxySubdirectives(src string) string {
	out, _ := wrapBareReverseProxySubdirectivesNamed(src)
	return out
}

func wrapBareReverseProxySubdirectivesNamed(src string) (string, []string) {
	isSub := map[string]bool{}
	for _, d := range reverseProxySubdirectives {
		isSub[d] = true
	}
	stripped := func(line string) string {
		t := strings.TrimSpace(line)
		if i := strings.Index(t, "#"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		return t
	}
	braces := func(line string) int {
		d := 0
		for _, ch := range stripped(line) {
			switch ch {
			case '{':
				d++
			case '}':
				d--
			}
		}
		return d
	}
	lines := strings.Split(src, "\n")
	var top, moved, names []string
	depth := 0
	for i := 0; i < len(lines); {
		line := lines[i]
		t := stripped(line)
		first := ""
		if t != "" {
			first = strings.Fields(t)[0]
		}
		if depth == 0 && first != "" && isSub[first] {
			names = append(names, first)
			moved = append(moved, "\t"+strings.TrimSpace(line))
			d := braces(line)
			i++
			for d > 0 && i < len(lines) {
				moved = append(moved, "\t"+strings.TrimSpace(lines[i]))
				d += braces(lines[i])
				i++
			}
			continue
		}
		top = append(top, line)
		depth += braces(line)
		i++
	}
	if len(moved) == 0 {
		return src, nil
	}
	// Merge into an existing top-level reverse_proxy block when there is one.
	depth = 0
	for i, line := range top {
		t := stripped(line)
		if depth == 0 && t != "" && strings.Fields(t)[0] == "reverse_proxy" && strings.HasSuffix(t, "{") {
			d := braces(line)
			for j := i + 1; j < len(top); j++ {
				d += braces(top[j])
				if d == 0 {
					merged := append([]string{}, top[:j]...)
					merged = append(merged, moved...)
					merged = append(merged, top[j:]...)
					return strings.TrimRight(strings.Join(merged, "\n"), "\n") + "\n", names
				}
			}
		}
		depth += braces(line)
	}
	body := strings.TrimRight(strings.Join(top, "\n"), "\n")
	block := "reverse_proxy {\n" + strings.Join(moved, "\n") + "\n}\n"
	if strings.TrimSpace(body) == "" {
		return block, names
	}
	return body + "\n" + block, names
}

// v2.42.2: users copy option names from Caddy's JSON (read_buffer_size) or
// put transport options straight under reverse_proxy; Caddy's adapter
// rejects both with "unrecognized subdirective". Both are unambiguous, so
// they are repaired rather than reported: JSON-style names become their
// Caddyfile spelling, and transport-only options found directly under
// reverse_proxy move into its `transport http { … }` block.

// transportAliases maps JSON field names people type into the Caddyfile
// spelling of the same `transport http` option.
var transportAliases = map[string]string{
	"read_buffer_size":         "read_buffer",
	"write_buffer_size":        "write_buffer",
	"max_response_header_size": "max_response_header",
}

// transportSubdirectives are options that only exist inside `transport http`.
var transportSubdirectives = []string{
	"read_buffer", "write_buffer", "max_response_header", "proxy_protocol",
	"dial_timeout", "dial_fallback_delay", "response_header_timeout", "expect_continue_timeout",
	"resolvers", "tls", "tls_client_auth", "tls_insecure_skip_verify", "tls_timeout", "tls_trusted_ca_certs",
	"tls_trust_pool", "tls_server_name", "tls_renegotiation", "tls_except_ports", "tls_curves",
	"keepalive", "keepalive_interval", "keepalive_idle_conns", "keepalive_idle_conns_per_host",
	"versions", "compression", "max_conns_per_host", "forward_proxy_url", "network_proxy", "local_address",
}

// normalizeProxyAdvancedConfig is every repair applied to an Advanced config
// before it is adapted or saved: bare reverse_proxy sub-directives wrapped
// (v2.42.1), JSON-style transport names respelled, and transport options
// under reverse_proxy moved into its transport block.
func normalizeProxyAdvancedConfig(src string) string {
	return relocateTransportSubdirectives(respellTransportAliases(wrapBareReverseProxySubdirectives(src)))
}

func advancedFirstToken(line string) string {
	t := strings.TrimSpace(line)
	if i := strings.Index(t, "#"); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	if t == "" {
		return ""
	}
	return strings.Fields(t)[0]
}

func advancedBraceDelta(line string) int {
	t := strings.TrimSpace(line)
	if i := strings.Index(t, "#"); i >= 0 {
		t = t[:i]
	}
	d := 0
	for _, ch := range t {
		switch ch {
		case '{':
			d++
		case '}':
			d--
		}
	}
	return d
}

// respellTransportAliases rewrites the first token of any line that uses a
// JSON-style transport option name.
func respellTransportAliases(src string) string {
	lines := strings.Split(src, "\n")
	changed := false
	for i, line := range lines {
		first := advancedFirstToken(line)
		alias, ok := transportAliases[first]
		if !ok {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[i] = indent + alias + strings.TrimPrefix(strings.TrimLeft(line, " \t"), first)
		changed = true
	}
	if !changed {
		return src
	}
	return strings.Join(lines, "\n")
}

// relocateTransportSubdirectives moves transport-only options that sit
// directly inside a top-level reverse_proxy block into that block's
// `transport http { … }` (merged into an existing one). Anything else is
// left exactly as typed.
func relocateTransportSubdirectives(src string) string {
	isTransport := map[string]bool{}
	for _, d := range transportSubdirectives {
		isTransport[d] = true
	}
	lines := strings.Split(src, "\n")
	// Find the top-level reverse_proxy block.
	depth, start, end := 0, -1, -1
	for i, line := range lines {
		first := advancedFirstToken(line)
		if depth == 0 && first == "reverse_proxy" && strings.HasSuffix(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]), "{") {
			start = i
			d := advancedBraceDelta(line)
			for j := i + 1; j < len(lines); j++ {
				d += advancedBraceDelta(lines[j])
				if d == 0 {
					end = j
					break
				}
			}
			break
		}
		depth += advancedBraceDelta(line)
	}
	if start < 0 || end < 0 {
		return src
	}
	// Walk the block body at relative depth 1: pull out transport options,
	// remember an existing transport block.
	var body, moved []string
	transportOpen, transportClose := -1, -1 // indexes into body
	rel := 0
	for i := start + 1; i < end; {
		line := lines[i]
		first := advancedFirstToken(line)
		if rel == 0 && first == "transport" && transportOpen < 0 {
			transportOpen = len(body)
			body = append(body, line)
			d := advancedBraceDelta(line)
			i++
			for d > 0 && i < end {
				body = append(body, lines[i])
				d += advancedBraceDelta(lines[i])
				i++
			}
			transportClose = len(body) - 1
			continue
		}
		if rel == 0 && isTransport[first] {
			moved = append(moved, "\t\t"+strings.TrimSpace(line))
			d := advancedBraceDelta(line)
			i++
			for d > 0 && i < end {
				moved = append(moved, "\t\t"+strings.TrimSpace(lines[i]))
				d += advancedBraceDelta(lines[i])
				i++
			}
			continue
		}
		body = append(body, line)
		rel += advancedBraceDelta(line)
		i++
	}
	if len(moved) == 0 {
		return src
	}
	var newBody []string
	if transportOpen >= 0 && transportClose > transportOpen {
		newBody = append(newBody, body[:transportClose]...)
		newBody = append(newBody, moved...)
		newBody = append(newBody, body[transportClose:]...)
	} else {
		newBody = append(newBody, body...)
		newBody = append(newBody, "\ttransport http {")
		newBody = append(newBody, moved...)
		newBody = append(newBody, "\t}")
	}
	out := append([]string{}, lines[:start+1]...)
	out = append(out, newBody...)
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n")
}

var unrecognizedSubdirective = regexp.MustCompile(`unrecognized subdirective ([A-Za-z0-9_]+)`)

// friendlyAdvancedRejection turns Caddy's adapter error into advice when it
// is about an unknown sub-directive — the one people hit when they mix JSON
// names, Caddyfile names and transport options.
func friendlyAdvancedRejection(err error) string {
	msg := err.Error()
	m := unrecognizedSubdirective.FindStringSubmatch(msg)
	if m == nil {
		return "Advanced config rejected by Caddy: " + msg
	}
	name := m[1]
	hint := fmt.Sprintf("`%s` is not an option Caddy knows there.", name)
	if alias, ok := transportAliases[name]; ok {
		hint += fmt.Sprintf(" In a Caddyfile it is spelled `%s`, inside `transport http { … }`.", alias)
	}
	hint += " Caddyfile names differ from the JSON ones (read_buffer_size → read_buffer, write_buffer_size → write_buffer, max_response_header_size → max_response_header); transport options belong inside `transport http { … }` within the reverse_proxy block; and most have a dedicated option in this form — Upstream → timeouts and buffers, Streaming → Flush immediately — which is the simplest place for them."
	return "Advanced config rejected by Caddy: " + hint + " Caddy said: " + msg
}
