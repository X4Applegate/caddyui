// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// The Caddyfile paste importer for a non-admin account: held to the same
// rules as an Advanced route's Caddyfile, before and after Caddy adapts it.

func pasteRequests(e *secEnv, needle string) (adapt, other []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rq := range e.reqs {
		if !strings.Contains(rq, needle) {
			continue
		}
		if strings.Contains(rq, " /adapt") {
			adapt = append(adapt, rq)
		} else {
			other = append(other, rq)
		}
	}
	return adapt, other
}

func storedRowCount(t *testing.T, e *secEnv) int {
	t.Helper()
	p, _ := models.ListProxyHosts(e.db, 1, 0, true, nil)
	rd, _ := models.ListRedirectionHosts(e.db, 1, 0, true, nil)
	return len(p) + len(rd) + rawRouteCount(t, e)
}

func TestTenantPasteCannotExpandEnvPlaceholders(t *testing.T) {
	e := newSecEnv(t)
	for _, src := range []string{
		"leak.example.test {\n\trespond \"{$CF_API_TOKEN}\"\n}",
		"leak.example.test {\n\trespond {env.CF_API_TOKEN}\n}",
		"leak.example.test {\n\timport secrets\n}",
	} {
		rec := e.do(t, "alice", http.MethodPost, "/caddyfile-import", url.Values{"caddyfile": {src}})
		if !strings.Contains(rec.Body.String(), "Not allowed for a non-admin account") {
			t.Errorf("%q: no refusal shown: %s", src, excerpt(rec.Body.String(), "rror"))
		}
	}
	if adapt, _ := pasteRequests(e, "leak.example.test"); len(adapt) != 0 {
		t.Errorf("the text was sent to Caddy's /adapt: %v", adapt)
	}
	if n := storedRowCount(t, e); n != 0 {
		t.Errorf("%d row(s) stored", n)
	}
}

// pasteTLSAdapt is what Caddy adapts a site with a custom ACME directory to:
// the site's route and a TLS automation policy carrying the issuer — here
// for another account's host as well.
const pasteTLSAdapt = `{"result":{"apps":{` +
	`"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["paste.example.test"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"203.0.113.5:80"}]}]}]}],"terminal":true}]}}},` +
	`"tls":{"automation":{"policies":[{"subjects":["paste.example.test","admin.example.test"],"issuers":[{"module":"acme","ca":"https://acme.evil.test/directory"}]}]}}}}}`

func TestTenantPasteCannotPushTLSPolicies(t *testing.T) {
	src := "paste.example.test {\n\treverse_proxy 203.0.113.5:80\n\ttls {\n\t\tca https://acme.evil.test/directory\n\t}\n}"

	e := newSecEnv(t)
	e.adaptResponse = pasteTLSAdapt
	rec := e.do(t, "alice", http.MethodPost, "/caddyfile-import", url.Values{"caddyfile": {src}})
	if !strings.Contains(rec.Body.String(), "Not allowed for a non-admin account") {
		t.Errorf("no refusal shown: %s", excerpt(rec.Body.String(), "rror"))
	}
	if _, other := pasteRequests(e, "acme.evil.test"); len(other) != 0 {
		t.Errorf("a TLS policy from a non-admin's paste reached the live config: %v", other)
	}
	if n := storedRowCount(t, e); n != 0 {
		t.Errorf("%d row(s) stored", n)
	}

	// Control: the administrator's paste does push it, so the check above
	// can see a push.
	e = newSecEnv(t)
	e.adaptResponse = pasteTLSAdapt
	rec = e.do(t, "admin", http.MethodPost, "/caddyfile-import", url.Values{"caddyfile": {src}})
	if _, other := pasteRequests(e, "acme.evil.test"); len(other) == 0 {
		t.Errorf("admin: the policy was not pushed (status %d): %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
}

func TestTenantPasteRowsGetTheSaveTimeChecks(t *testing.T) {
	e := newSecEnv(t)
	if _, err := models.CreateProxyHost(e.db, 1, 0, &models.ProxyHost{Domains: "admin.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// A route with no host matcher, stored as an Advanced route, would
	// answer for every site on the server.
	e.adaptResponse = `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"handle":[{"handler":"static_response","body":"mine now"}]}]}}}}}}`
	rec := e.do(t, "alice", http.MethodPost, "/caddyfile-import", url.Values{"caddyfile": {"https:// {\n\trespond \"mine now\"\n}"}})
	if n := rawRouteCount(t, e); n != 0 {
		t.Errorf("a catch-all Advanced route was stored from a non-admin's paste (status %d): %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
}
