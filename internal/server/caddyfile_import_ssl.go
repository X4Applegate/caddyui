// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net"
	"strings"
)

// caddyfileImportSSL is how the Caddyfile import reads a host's Force SSL
// setting from where Caddy serves it (finding 12 of the T-0927 review,
// T-0947). The export writes a host with Force SSL off as an http:// and an
// https:// site (or, with certificate files, an HTTPS site and a plain
// http:// twin), which Caddy adapts to the same route on a :80 server and
// on a TLS server. Each route used to become a host with Force SSL on —
// the :80 one then skipped as a duplicate — so a re-import turned the :80
// redirect back on.
type caddyfileImportSSL struct {
	// twinOf maps a :80 route to the TLS-server route it repeats exactly;
	// once the other one has become a proxy host, which then serves :80
	// with Force SSL off.
	twinOf map[int]int
	// forceOff holds both routes of each such pair: whichever becomes the
	// proxy host gets Force SSL off (the other is then skipped).
	forceOff map[int]bool
	// plainOnly holds :80 routes no TLS-server route repeats: a site that
	// is served over plain HTTP only.
	plainOnly map[int]bool
}

func readCaddyfileImportSSL(ars []adaptedServerRoute) caddyfileImportSSL {
	out := caddyfileImportSSL{twinOf: map[int]int{}, forceOff: map[int]bool{}, plainOnly: map[int]bool{}}
	key := func(i int) string {
		b, err := json.Marshal(ars[i].Route) // map keys sorted
		if err != nil {
			return ""
		}
		return string(b)
	}
	tlsByKey := map[string]int{}
	for i, ar := range ars {
		if listensOnlyOn(ar.Listen, "443") {
			if k := key(i); k != "" {
				if _, dup := tlsByKey[k]; !dup {
					tlsByKey[k] = i
				}
			}
		}
	}
	for i, ar := range ars {
		if !listensOnlyOn(ar.Listen, "80") {
			continue
		}
		if j, ok := tlsByKey[key(i)]; ok && key(i) != "" {
			out.twinOf[i] = j
			out.forceOff[i], out.forceOff[j] = true, true
		} else {
			out.plainOnly[i] = true
		}
	}
	return out
}

// listensOnlyOn reports whether every address in listen is on port, and
// there is at least one.
func listensOnlyOn(listen []string, port string) bool {
	if len(listen) == 0 {
		return false
	}
	for _, a := range listen {
		a = strings.TrimSpace(a)
		if i := strings.Index(a, "/"); i >= 0 && !strings.Contains(a[:i], ":") {
			a = a[i+1:] // network prefix such as tcp/
		}
		_, p, err := net.SplitHostPort(a)
		if err != nil || p != port {
			return false
		}
	}
	return true
}
