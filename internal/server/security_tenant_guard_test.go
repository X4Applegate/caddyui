// SPDX-License-Identifier: Apache-2.0

package server

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Tenant route guard (v2.57.1). Verified against a real Caddy 2.11: a response
// header or body of "{env.SECRET}" / "{file./path}" is expanded at request time
// and served to whoever requests the route, so a non-admin who can set any such
// string can read the Caddy process environment (where the shipped compose puts
// the DNS API token) and any file the Caddy container can read.

func route(handlers ...map[string]any) map[string]any {
	hs := make([]any, len(handlers))
	for i, h := range handlers {
		hs[i] = h
	}
	return map[string]any{"match": []any{map[string]any{"host": []any{"t.example.test"}}}, "handle": hs}
}

func rp(dial string, extra map[string]any) map[string]any {
	h := map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": dial}}}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func hostOverride(host string) map[string]any {
	return map[string]any{"request": map[string]any{"set": map[string]any{"Host": []any{host}}}}
}

func TestTenantRouteViolation(t *testing.T) {
	e := newSecEnv(t)
	// A second registered Caddy node: its admin API must be off limits too, not
	// just the primary's.
	if _, err := models.CreateCaddyServer(e.db, &models.CaddyServer{Name: "edge", AdminURL: "http://10.8.0.2:2019", Type: models.CaddyServerTypeManaged}); err != nil {
		t.Fatal(err)
	}

	bad := map[string]map[string]any{
		"env placeholder in a response header": route(map[string]any{"handler": "static_response", "headers": map[string]any{"X-T": []any{"{env.CF_API_TOKEN}"}}}),
		"file placeholder in a body":           route(map[string]any{"handler": "static_response", "body": "x {file./data/caddy/pki/authorities/local/root.key}"}),
		"spaced env placeholder":               route(map[string]any{"handler": "static_response", "body": "{ env.X }"}),
		"adapt-time $ placeholder":             route(map[string]any{"handler": "static_response", "body": "{$SECRET}"}),
		"upper-case placeholder":               route(map[string]any{"handler": "static_response", "body": "{ENV.X}"}),
		"file_server handler":                  route(map[string]any{"handler": "file_server", "root": "/"}),
		"templates handler":                    route(map[string]any{"handler": "templates"}),
		"acme_server handler":                  route(map[string]any{"handler": "acme_server"}),
		"loopback admin API":                   route(rp("127.0.0.1:2019", nil)),
		"localhost":                            route(rp("localhost:2019", nil)),
		"tcp/ prefixed loopback":               route(rp("tcp/127.0.0.1:2019", nil)),
		"unix socket":                          route(rp("unix//run/caddy/admin.sock", nil)),
		"placeholder dial":                     route(rp("{http.request.header.X-Target}:80", nil)),
		"cloud metadata":                       route(rp("169.254.169.254:80", nil)),
		"alibaba metadata":                     route(rp("100.100.100.200:80", nil)),
		"azure wireserver":                     route(rp("168.63.129.16:80", nil)),
		"ipv6 loopback":                        route(rp("[::1]:80", nil)),
		"ipv4-mapped loopback":                 route(rp("[::ffff:127.0.0.1]:80", nil)),
		"integer ip":                           route(rp("2130706433:80", nil)),
		"hex ip":                               route(rp("0x7f000001:80", nil)),
		"another fleet node's admin host":      route(rp("10.8.0.2:80", nil)),
		"host override to the admin API":       route(rp("203.0.113.5:80", map[string]any{"headers": hostOverride("127.0.0.1:2019")})),
		"dynamic upstreams":                    route(map[string]any{"handler": "reverse_proxy", "dynamic_upstreams": map[string]any{"source": "a", "name": "x"}}),
		"upstream forward proxy to loopback": route(rp("203.0.113.5:80", map[string]any{
			"transport": map[string]any{"protocol": "http", "network_proxy": map[string]any{"from": "url", "url": "http://127.0.0.1:3128"}}})),
		"internal upstream hidden in a subroute": route(map[string]any{"handler": "subroute", "routes": []any{
			map[string]any{"handle": []any{rp("127.0.0.1:2019", nil)}}}}),
		"internal upstream hidden in handle_response": route(rp("203.0.113.5:80", map[string]any{"handle_response": []any{
			map[string]any{"routes": []any{map[string]any{"handle": []any{rp("127.0.0.1:2019", nil)}}}}}})),
	}
	for name, rt := range bad {
		if why := e.s.tenantRouteViolation(rt); why == "" {
			t.Errorf("%s: a non-admin's route was allowed", name)
		}
	}

	good := map[string]map[string]any{
		"public upstream":                   route(rp("app.example.com:443", nil)),
		"private LAN upstream":              route(rp("10.0.0.5:8080", nil)),
		"docker service name":               route(rp("my-app:3000", nil)),
		"tcp/ prefixed LAN upstream":        route(rp("tcp/10.0.0.5:8080", nil)),
		"ordinary host override":            route(rp("10.0.0.5:8080", map[string]any{"headers": hostOverride("app.example.com")})),
		"request placeholders are fine":     route(map[string]any{"handler": "static_response", "headers": map[string]any{"X-Host": []any{"{http.request.host}"}}, "body": "{http.request.uri.path}"}),
		"plain static response":             route(map[string]any{"handler": "static_response", "body": "ok"}),
		"a second LAN host that is no node": route(rp("10.8.0.3:80", nil)),
	}
	for name, rt := range good {
		if why := e.s.tenantRouteViolation(rt); why != "" {
			t.Errorf("%s: wrongly refused: %s", name, why)
		}
	}
}

func TestNeutraliseTenantPlaceholders(t *testing.T) {
	r := route(map[string]any{
		"handler": "static_response",
		"headers": map[string]any{"X-A": []any{"{env.SECRET}", "{http.request.host}"}},
		"body":    "{file./etc/passwd} and { ENV.X } and {http.request.uri}",
	})
	out, changed := neutraliseTenantPlaceholders(r)
	if !changed {
		t.Fatal("nothing was neutralised")
	}
	b, _ := json.Marshal(out)
	body := string(b)
	for _, bad := range []string{"{env.", "{file.", "{ ENV.", "{ env."} {
		if strings.Contains(body, bad) {
			t.Errorf("neutralised route still contains %q: %s", bad, body)
		}
	}
	if !strings.Contains(body, "{http.request.host}") || !strings.Contains(body, "{http.request.uri}") {
		t.Errorf("request placeholders must be left alone: %s", body)
	}
	if again, changedAgain := neutraliseTenantPlaceholders(out); changedAgain {
		t.Errorf("neutralising twice changed it again: %v", again)
	}
}

func TestTenantTextViolation(t *testing.T) {
	bad := map[string]string{
		"env substitution":           "example.com {\n\trespond \"{$CF_API_TOKEN}\"\n}",
		"runtime env placeholder":    "example.com {\n\theader X-T {env.CF_API_TOKEN}\n}",
		"file placeholder":           "example.com {\n\trespond {file./etc/passwd}\n}",
		"import of an absolute path": "import /data/caddy/certificates/x.key",
		"import of a glob":           "example.com {\n\timport /etc/*.conf\n}",
		"import with an extension":   "import secrets.env",
		"import inside a block":      "example.com { import /etc/shadow }",
	}
	for name, txt := range bad {
		if tenantTextViolation(txt) == "" {
			t.Errorf("%s: allowed", name)
		}
	}
	good := map[string]string{
		"plain":                    "example.com {\n\treverse_proxy 10.0.0.5:8080\n}",
		"import a snippet by name": "example.com {\n\timport my_snippet\n}",
		"snippet with dashes":      "example.com {\n\timport secure-headers\n}",
		"snippet definition":       "(common) {\n\theader X-A 1\n}\nexample.com {\n\timport common\n}",
		"request placeholders":     "example.com {\n\theader X-Host {http.request.host}\n}",
	}
	for name, txt := range good {
		if why := tenantTextViolation(txt); why != "" {
			t.Errorf("%s: refused: %s", name, why)
		}
	}
}

// --- sync-time enforcement ------------------------------------------------

// A row owned by a non-admin is neutralised or skipped when the live config is
// built, whichever save path (UI, REST, import, AI tool, clone) stored it — so
// a bad row that is already in the database can never reach Caddy.
func TestSyncTimeEnforcementOnlyAppliesToNonAdminOwnedRows(t *testing.T) {
	e := newSecEnv(t)
	hdr := `{"X-Leak":"{env.CF_API_TOKEN}"}`
	mk := func(owner int64) models.ProxyHost {
		return models.ProxyHost{
			Domains: "h.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080,
			Enabled: true, CustomRespHeaders: hdr, OwnerID: ownerNull(owner),
		}
	}
	build := func(p models.ProxyHost, rr models.RawRoute, rd models.RedirectionHost) string {
		routes := e.s.buildMergedRoutes([]models.ProxyHost{p}, []models.RedirectionHost{rd}, []models.RawRoute{rr})
		b, _ := json.Marshal(routes)
		return string(b)
	}
	rawJSON := `{"match":[{"host":["raw.example.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}]}]}`
	rd := func(owner int64) models.RedirectionHost {
		return models.RedirectionHost{Domains: "r.example.test", ForwardScheme: "https", ForwardDomain: "{file./etc/passwd}.evil.test", ForwardHTTPCode: 301, Enabled: true, OwnerID: ownerNull(owner)}
	}
	raw := func(owner int64) models.RawRoute {
		return models.RawRoute{Label: "raw", JSONData: rawJSON, Enabled: true, OwnerID: ownerNull(owner)}
	}

	// Owned by alice: neutralised / skipped.
	out := build(mk(e.ids["alice"]), raw(e.ids["alice"]), rd(e.ids["alice"]))
	if strings.Contains(out, "{env.") || strings.Contains(out, "{file.") {
		t.Errorf("a non-admin-owned route still carries a process-reading placeholder:\n%s", out)
	}
	if !strings.Contains(out, "{blocked-env.") {
		t.Errorf("expected the header placeholder to be neutralised, not dropped:\n%s", out)
	}
	if strings.Contains(out, "127.0.0.1:2019") || strings.Contains(out, "raw.example.test") {
		t.Errorf("a non-admin-owned route to the Caddy admin API was deployed:\n%s", out)
	}

	// Owned by the admin (owner NULL): untouched, including legitimate use of
	// {env.…} in the admin's own config.
	out = build(mk(0), raw(0), rd(0))
	if !strings.Contains(out, "{env.CF_API_TOKEN}") || !strings.Contains(out, "127.0.0.1:2019") || !strings.Contains(out, "{file./etc/passwd}") {
		t.Errorf("an admin-owned route was altered:\n%s", out)
	}
}

// --- through the real router ---------------------------------------------

// Caddy substitutes {$ENV} while ADAPTING and its errors echo parsed text, so a
// non-admin's Caddyfile text must be refused before it is sent to Caddy at all.
func TestNonAdminCaddyfileTextNeverReachesAdapt(t *testing.T) {
	e := newSecEnv(t)
	form := url.Values{
		"label":         {"x"},
		"caddyfile_src": {"x.example.test {\n\trespond \"{$CF_API_TOKEN}\"\n}"},
		"enabled":       {"on"},
	}
	rec := e.do(t, "alice", http.MethodPost, "/raw-routes", form)
	if rec.Code == http.StatusSeeOther {
		t.Fatalf("the route was accepted (redirect to %s)", rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Body.String(), "admin-only") {
		t.Errorf("the user should be told why: %s", excerpt(rec.Body.String(), "Not allowed"))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rq := range e.reqs {
		if strings.Contains(rq, "/adapt") && strings.Contains(rq, "CF_API_TOKEN") {
			t.Errorf("the risky text was sent to Caddy's /adapt: %s", rq)
		}
	}
}

func TestNonAdminCannotSaveRawRoutesAimedAtTheAdminAPI(t *testing.T) {
	e := newSecEnv(t)
	bad := `{"match":[{"host":["raw.example.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:2019"}],"headers":{"request":{"set":{"Host":["127.0.0.1:2019"]}}}}]}`

	// UI form
	rec := e.do(t, "alice", http.MethodPost, "/raw-routes", url.Values{"label": {"x"}, "json_data": {bad}, "enabled": {"on"}})
	if rec.Code == http.StatusSeeOther {
		t.Errorf("UI: the route was accepted")
	}
	// REST API
	rec = e.do(t, "alice", http.MethodPost, "/api/v1/raw-routes", url.Values{})
	_ = rec
	body, _ := json.Marshal(map[string]any{"label": "x", "json_data": bad, "enabled": true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/raw-routes", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	e.attachSession(req, "alice")
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("REST: status %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if rows, _ := models.ListRawRoutes(e.db, 1, 0, true, nil); len(rows) != 0 {
		t.Errorf("%d raw route(s) were stored", len(rows))
	}

	// The admin may.
	rec = e.do(t, "admin", http.MethodPost, "/raw-routes", url.Values{"label": {"x"}, "json_data": {bad}, "enabled": {"on"}})
	if rec.Code != http.StatusSeeOther {
		t.Errorf("admin: status %d, want a redirect", rec.Code)
	}
}

func TestNonAdminProxyHostCannotLeakProcessSecretsThroughHeadersOrAdvancedConfig(t *testing.T) {
	e := newSecEnv(t)
	n := 0
	base := func() url.Values {
		n++
		return url.Values{"domains": {"leak" + strconv.Itoa(n) + ".example.test"}, "forward_scheme": {"http"}, "forward_host": {"10.0.0.5"}, "forward_port": {"8080"}, "enabled": {"on"}}
	}
	stored := func() int {
		hosts, _ := models.ListProxyHosts(e.db, 1, 0, true, nil)
		return len(hosts)
	}

	// A custom response header carrying an env placeholder.
	f := base()
	f["header_resp_key"], f["header_resp_val"] = []string{"X-Leak"}, []string{"{env.CF_API_TOKEN}"}
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", f); rec.Code == http.StatusSeeOther {
		t.Error("a response header reading {env.…} was accepted")
	}
	// A custom request header with a file placeholder.
	f = base()
	f["header_req_key"], f["header_req_val"] = []string{"X-Leak"}, []string{"{file./data/caddy/x}"}
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", f); rec.Code == http.StatusSeeOther {
		t.Error("a request header reading {file.…} was accepted")
	}
	// Advanced config reading the environment at adapt time.
	f = base()
	f.Set("advanced_config", "respond \"{$CF_API_TOKEN}\"")
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", f); rec.Code == http.StatusSeeOther {
		t.Error("advanced config using {$ENV} was accepted")
	}
	// An upstream that is the Caddy admin API itself.
	f = base()
	f.Set("forward_host", "127.0.0.1")
	f.Set("forward_port", "2019")
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", f); rec.Code == http.StatusSeeOther {
		t.Error("an upstream of 127.0.0.1:2019 was accepted")
	}
	if got := stored(); got != 0 {
		t.Fatalf("%d host(s) were stored by the rejected requests", got)
	}

	// An ordinary host still works for the same user, and so does the admin's
	// own use of a placeholder.
	if rec := e.do(t, "alice", http.MethodPost, "/proxy-hosts", base()); rec.Code != http.StatusSeeOther {
		t.Errorf("a plain host was refused: %d %s", rec.Code, excerpt(rec.Body.String(), "Not allowed"))
	}
	f = base()
	f["header_resp_key"], f["header_resp_val"] = []string{"X-Mine"}, []string{"{env.MY_OWN}"}
	if rec := e.do(t, "admin", http.MethodPost, "/proxy-hosts", f); rec.Code != http.StatusSeeOther {
		t.Errorf("the admin's own {env.…} header was refused: %d", rec.Code)
	}
}

func TestHelperEndpointsNeedWriteAccessAndTheUpstreamGuard(t *testing.T) {
	e := newSecEnv(t)
	// An internal listener the CaddyUI process could reach.
	ln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ln.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ln.URL, "http://"))

	form := url.Values{"host": {host}, "port": {port}, "scheme": {"http"}}
	if rec := e.do(t, "viewer", http.MethodPost, "/api/proxy-hosts/test-upstream", form); rec.Code != http.StatusForbidden {
		t.Errorf("viewer test-upstream -> %d, want 403", rec.Code)
	}
	rec := e.do(t, "alice", http.MethodPost, "/api/proxy-hosts/test-upstream", form)
	if !strings.Contains(rec.Body.String(), `"ok":false`) || !strings.Contains(rec.Body.String(), "Not allowed") {
		t.Errorf("a non-admin probing a loopback listener got: %s", rec.Body.String())
	}
	rec = e.do(t, "admin", http.MethodPost, "/api/proxy-hosts/test-upstream", form)
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Errorf("the admin's probe of a reachable listener failed: %s", rec.Body.String())
	}
	for _, p := range []string{"/api/proxy-hosts/preview", "/api/raw-routes/validate"} {
		if rec := e.do(t, "viewer", http.MethodPost, p, url.Values{}); rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s -> %d, want 403", p, rec.Code)
		}
	}
}

func ownerNull(id int64) (n sql.NullInt64) {
	if id > 0 {
		n.Valid, n.Int64 = true, id
	}
	return n
}

var _ = strconv.Itoa
