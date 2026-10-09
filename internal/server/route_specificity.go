// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sort"
	"strings"
)

// v2.61.3 (issue #129): order host routes by specificity.
//
// Caddy runs the FIRST route whose matcher fits a request. CaddyUI emitted host
// routes in list order (manual sort order, then newest first), so a wildcard
// host such as *.example.com created after app.example.com came first — and a
// request for app.example.com was served by the wildcard's route, skipping
// everything on its own route: the IP allowlist, Basic Auth, forward auth, a
// middleware profile, the WAF. Verified on a real Caddy: an allowlisted host
// answered 200 to a client outside its allowlist. Caddy's own Caddyfile adapter
// always puts exact names before wildcards; this does the same.
//
// Only routes that match on hostnames move, and only among the positions such
// routes already occupy, so routes without a host matcher (global maintenance,
// a catch-all Advanced route, the fallback) keep their exact place. The sort is
// stable, so the manual order still decides between routes of equal specificity.

// routeSpecificity is the sort key: lower runs first. ok is false for a route
// that does not match on hostnames.
func routeSpecificity(route any) (key [3]int, ok bool) {
	m, _ := route.(map[string]any)
	if m == nil {
		return key, false
	}
	var hosts []string
	hasPath := false
	collect := func(set map[string]any) {
		switch h := set["host"].(type) {
		case []any:
			for _, v := range h {
				if s, ok := v.(string); ok {
					hosts = append(hosts, s)
				}
			}
		case []string:
			hosts = append(hosts, h...)
		}
		if _, ok := set["path"]; ok {
			hasPath = true
		}
		if _, ok := set["path_regexp"]; ok {
			hasPath = true
		}
	}
	switch match := m["match"].(type) {
	case []any:
		for _, s := range match {
			if set, ok := s.(map[string]any); ok {
				collect(set)
			}
		}
	case []map[string]any:
		for _, set := range match {
			collect(set)
		}
	}
	if len(hosts) == 0 {
		return key, false
	}
	// A route is as general as its least specific hostname: one that also
	// carries *.example.com must not run before an exact name it would cover.
	wildcard, minLabels := 0, 1<<30
	for _, h := range hosts {
		if strings.Contains(h, "*") {
			wildcard = 1
			if n := strings.Count(strings.Trim(h, "."), ".") + 1; n < minLabels {
				minLabels = n
			}
		}
	}
	key[0] = wildcard
	if wildcard == 1 {
		key[1] = -minLabels // more labels (*.a.example.com) before fewer (*.example.com)
	}
	if !hasPath {
		key[2] = 1 // a path-scoped route before the same host's catch-all route
	}
	return key, true
}

// sortRoutesBySpecificity returns routes with the host-matched ones reordered
// most-specific-first, in place of each other.
func sortRoutesBySpecificity(routes []any) []any {
	type item struct {
		route any
		key   [3]int
	}
	var slots []int
	var items []item
	for i, r := range routes {
		if k, ok := routeSpecificity(r); ok {
			slots = append(slots, i)
			items = append(items, item{r, k})
		}
	}
	if len(items) < 2 {
		return routes
	}
	sort.SliceStable(items, func(a, b int) bool {
		ka, kb := items[a].key, items[b].key
		for i := range ka {
			if ka[i] != kb[i] {
				return ka[i] < kb[i]
			}
		}
		return false
	})
	out := make([]any, len(routes))
	copy(out, routes)
	for i, slot := range slots {
		out[slot] = items[i].route
	}
	return out
}
