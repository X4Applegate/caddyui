package caddy

// v2.40.0: a proxy host's Advanced config may carry a `reverse_proxy { … }`
// block whose sub-directives (flush_interval, header_up, transport,
// lb_policy, health checks, …) belong inside the host's own reverse_proxy
// handler rather than in front of it. The server adapts that block through
// Caddy and hands the resulting handler fields here to be folded into the
// generated handler.

// MergeReverseProxyOverrides deep-merges overrides into the first
// reverse_proxy handler found in route (descending into subroutes).
// "handler" and "upstreams" are never taken from overrides — the upstream
// comes from Forward host / port. Nested maps merge key by key with the
// override winning on conflicts; any other value replaces the generated one
// outright. Returns false when route has no reverse_proxy handler (for
// example a host in maintenance mode), in which case nothing changes.
func MergeReverseProxyOverrides(route map[string]any, overrides map[string]any) bool {
	if len(overrides) == 0 {
		return false
	}
	rp := findReverseProxyHandler(route)
	if rp == nil {
		return false
	}
	for k, v := range overrides {
		if k == "handler" || k == "upstreams" {
			continue
		}
		rp[k] = mergeValue(rp[k], v)
	}
	return true
}

func findReverseProxyHandler(route map[string]any) map[string]any {
	handlers, _ := route["handle"].([]any)
	for _, h := range handlers {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		switch hm["handler"] {
		case "reverse_proxy":
			return hm
		case "subroute":
			routes, _ := hm["routes"].([]any)
			for _, r := range routes {
				if rm, ok := r.(map[string]any); ok {
					if found := findReverseProxyHandler(rm); found != nil {
						return found
					}
				}
			}
		}
	}
	return nil
}

// mergeValue returns src merged over dst: two maps merge recursively (a
// fresh map, so the generated config is never aliased), anything else is
// replaced by src.
func mergeValue(dst, src any) any {
	dm, dok := dst.(map[string]any)
	sm, sok := src.(map[string]any)
	if !dok || !sok {
		return src
	}
	out := make(map[string]any, len(dm)+len(sm))
	for k, v := range dm {
		out[k] = v
	}
	for k, v := range sm {
		out[k] = mergeValue(out[k], v)
	}
	return out
}
