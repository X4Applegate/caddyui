// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.61.0 (issue #126): Layer4 proxies that share an HTTP port through a
// caddy-l4 listener wrapper.

func sharedProxy(id int64, wrap, kind, hosts string) models.Layer4Proxy {
	return models.Layer4Proxy{ID: id, Name: "p", Protocol: "tcp", Mode: models.Layer4ModeShared, WrapServer: wrap, MatchKind: kind,
		MatchHosts: hosts, UpstreamHost: "10.0.0.7", UpstreamPort: 22, Enabled: true}
}

func TestValidateLayer4Shared(t *testing.T) {
	good := sharedProxy(0, "https", "tls_sni", "SSH.Example.com, *.rdp.example.com")
	if msg := validateLayer4Proxy(&good); msg != "" {
		t.Fatalf("valid shared proxy refused: %s", msg)
	}
	if good.MatchHosts != "ssh.example.com, *.rdp.example.com" || good.ListenPort != 443 || good.ListenAddr != "" || good.Protocol != "tcp" {
		t.Errorf("not normalised: %+v", good)
	}
	for name, mod := range map[string]func(*models.Layer4Proxy){
		"udp":                  func(p *models.Layer4Proxy) { p.Protocol = "udp" },
		"no wrap server":       func(p *models.Layer4Proxy) { p.WrapServer = "" },
		"bad wrap server":      func(p *models.Layer4Proxy) { p.WrapServer = "ftp" },
		"http host on https":   func(p *models.Layer4Proxy) { p.MatchKind = "http_host" },
		"sni on http":          func(p *models.Layer4Proxy) { p.WrapServer = "http" },
		"unknown matcher":      func(p *models.Layer4Proxy) { p.MatchKind = "any" },
		"sni without hosts":    func(p *models.Layer4Proxy) { p.MatchHosts = " " },
		"bad hostname":         func(p *models.Layer4Proxy) { p.MatchHosts = "ssh.example.com/x" },
		"placeholder hostname": func(p *models.Layer4Proxy) { p.MatchHosts = "{env.X}" },
		"bad upstream":         func(p *models.Layer4Proxy) { p.UpstreamHost = "a/b" },
	} {
		p := sharedProxy(0, "https", "tls_sni", "ssh.example.com")
		mod(&p)
		if msg := validateLayer4Proxy(&p); msg == "" {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, p := range map[string]models.Layer4Proxy{
		"ssh":         sharedProxy(0, "https", "ssh", ""),
		"rdp on http": sharedProxy(0, "http", "rdp", "ignored.example.com"),
		"postgres":    sharedProxy(0, "https", "postgres", ""),
		"http host":   sharedProxy(0, "http", "http_host", "app.example.com"),
	} {
		p := p
		if msg := validateLayer4Proxy(&p); msg != "" {
			t.Errorf("%s refused: %s", name, msg)
		}
		if (name == "ssh" || name == "rdp on http" || name == "postgres") && p.MatchHosts != "" {
			t.Errorf("%s kept stale hostnames: %q", name, p.MatchHosts)
		}
	}
	// Terminate TLS only means something for SNI.
	p := sharedProxy(0, "https", "ssh", "")
	p.TerminateTLS = true
	_ = validateLayer4Proxy(&p)
	if p.TerminateTLS {
		t.Error("terminate_tls was kept for a non-SNI matcher")
	}
	// A dedicated proxy still cannot take 443, and now says how to share it.
	ded := models.Layer4Proxy{Name: "x", Protocol: "tcp", ListenPort: 443, UpstreamHost: "10.0.0.1", UpstreamPort: 22}
	if msg := validateLayer4Proxy(&ded); !strings.Contains(msg, "sharing") {
		t.Errorf("reserved-port message does not point at sharing: %q", msg)
	}
}

func TestBuildLayer4ListenerWrappers(t *testing.T) {
	proxies := []models.Layer4Proxy{
		sharedProxy(1, "https", "tls_sni", "ssh.example.com"),
		func() models.Layer4Proxy {
			p := sharedProxy(2, "https", "tls_sni", "rds.example.com")
			p.TerminateTLS = true
			p.UpstreamPort = 3389
			return p
		}(),
		sharedProxy(3, "https", "ssh", ""),
		sharedProxy(4, "http", "http_host", "plain.example.com"),
		func() models.Layer4Proxy {
			p := sharedProxy(5, "https", "tls_sni", "off.example.com")
			p.Enabled = false
			return p
		}(),
		{ID: 6, Name: "dedicated", Protocol: "tcp", ListenPort: 5432, UpstreamHost: "10.0.0.5", UpstreamPort: 5432, Enabled: true},
	}
	got := buildLayer4ListenerWrappers(proxies)
	b, _ := json.Marshal(got)
	out := string(b)
	for _, want := range []string{
		`"srv0":{"routes":[`, `"wrapper":"layer4"`,
		`"match":[{"tls":{"sni":["ssh.example.com"]}}]`, `"dial":["tcp/10.0.0.7:22"]`,
		`"match":[{"tls":{"sni":["rds.example.com"]}}]`, `"handle":[{"handler":"tls"},{"handler":"proxy"`, `"dial":["tcp/10.0.0.7:3389"]`,
		`"match":[{"ssh":{}}]`,
		`"caddyui_http":{"routes":[`, `"match":[{"http":[{"host":["plain.example.com"]}]}]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s:\n%s", want, out)
		}
	}
	for _, bad := range []string{"off.example.com", "5432", "dedicated"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q must not appear in the wrappers: %s", bad, out)
		}
	}
	// Passthrough SNI routes carry no tls handler.
	if strings.Count(out, `{"handler":"tls"}`) != 1 {
		t.Errorf("only the terminate-TLS route may have a tls handler: %s", out)
	}
	// Shared proxies never become dedicated servers.
	servers := buildManagedLayer4Servers(proxies)
	if len(servers) != 1 || servers[layer4ServerPrefix+"6"] == nil {
		t.Errorf("dedicated servers = %v, want only #6", servers)
	}
}

func TestMergeListenerWrappersPutsLayer4BeforeTLSAndAfterOthers(t *testing.T) {
	ours := map[string]any{"wrapper": "layer4", "routes": []any{}}
	foreign := map[string]any{"wrapper": "proxy_protocol"}
	tlsW := map[string]any{"wrapper": "tls"}
	names := func(l []any) string {
		var n []string
		for _, w := range l {
			n = append(n, w.(map[string]any)["wrapper"].(string))
		}
		return strings.Join(n, ",")
	}
	// On a TLS server tls is listed explicitly right after ours — otherwise Caddy
	// applies TLS first and the layer4 matchers cannot read the raw bytes.
	if got := names(mergeListenerWrappers(nil, ours, false, true)); got != "layer4,tls" {
		t.Errorf("empty live list on a TLS server -> %s, want layer4,tls", got)
	}
	// Plain HTTP server: no tls wrapper is added.
	if got := names(mergeListenerWrappers(nil, ours, false, false)); got != "layer4" {
		t.Errorf("plain server -> %s, want layer4", got)
	}
	// Other wrappers keep their place ahead of ours (PROXY protocol must be
	// read before layer4 looks at the stream); an existing tls stays last.
	if got := names(mergeListenerWrappers([]any{foreign, tlsW}, ours, false, true)); got != "proxy_protocol,layer4,tls" {
		t.Errorf("order -> %s, want proxy_protocol,layer4,tls", got)
	}
	if got := names(mergeListenerWrappers([]any{tlsW, foreign}, ours, false, true)); got != "proxy_protocol,layer4,tls" {
		t.Errorf("tls listed first -> %s, want proxy_protocol,layer4,tls", got)
	}
	// An older layer4 wrapper is replaced, not duplicated.
	old := map[string]any{"wrapper": "layer4", "routes": []any{"old"}}
	if got := names(mergeListenerWrappers([]any{old, tlsW}, ours, true, true)); got != "layer4,tls" {
		t.Errorf("replace -> %s", got)
	}
	// Removing ours restores what was there: the tls wrapper we added goes too,
	// but foreign wrappers stay (and so does a tls entry the operator listed).
	if got := mergeListenerWrappers([]any{ours, tlsW}, nil, true, true); len(got) != 0 {
		t.Errorf("our wrapper plus the tls we added should leave nothing: %v", got)
	}
	if got := names(mergeListenerWrappers([]any{foreign, ours, tlsW}, nil, true, true)); got != "proxy_protocol,tls" {
		t.Errorf("removal with a foreign wrapper -> %s, want proxy_protocol,tls", got)
	}
	// Without ownership a live layer4 wrapper is left exactly as it is.
	if got := names(mergeListenerWrappers([]any{old, tlsW}, nil, false, true)); got != "layer4,tls" {
		t.Errorf("a layer4 wrapper CaddyUI never wrote was changed: %s", got)
	}
}

func TestLayer4SharedConflicts(t *testing.T) {
	a := sharedProxy(1, "https", "tls_sni", "ssh.example.com, rds.example.com")
	for name, c := range map[string]struct {
		o    models.Layer4Proxy
		want bool
	}{
		"same host":           {sharedProxy(2, "https", "tls_sni", "SSH.example.com"), true},
		"other host":          {sharedProxy(2, "https", "tls_sni", "other.example.com"), false},
		"other port":          {sharedProxy(2, "http", "http_host", "ssh.example.com"), false},
		"same banner kind":    {sharedProxy(2, "https", "ssh", ""), false},
		"dedicated vs shared": {models.Layer4Proxy{ID: 2, Protocol: "tcp", ListenPort: 5432}, false},
	} {
		if got := a.ConflictsWith(c.o); got != c.want {
			t.Errorf("%s: %v want %v", name, got, c.want)
		}
	}
	if !sharedProxy(1, "https", "ssh", "").ConflictsWith(sharedProxy(2, "https", "ssh", "")) {
		t.Error("two SSH matchers on one port must conflict (the first would shadow the second)")
	}
}

func (f *l4Fleet) sharedForm(extra url.Values) url.Values {
	v := url.Values{"name": {"SSH over 443"}, "mode": {"shared"}, "wrap_server": {"https"}, "match_kind": {"tls_sni"}, "match_hosts": {"ssh.example.com"},
		"upstream_host": {"10.0.0.7"}, "upstream_port": {"22"}, "enabled": {"on"}}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

func (f *l4Fleet) writesTo(fake *layer4FakeAdmin, needle string) []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var out []string
	for _, w := range fake.writes {
		if strings.Contains(w, needle) {
			out = append(out, w)
		}
	}
	return out
}

// A shared proxy is written as a listener wrapper on srv0 — not as a dedicated
// layer4 server — and other wrappers already on the server survive.
func TestSharedProxyIsWrittenAsAListenerWrapperKeepingForeignOnes(t *testing.T) {
	f := newL4Fleet(t)
	f.createProxy(t, "app.example.com", nil) // gives srv0 and caddyui_http something to carry
	f.fSource.mu.Lock()
	f.fSource.wrappersBody = `[{"wrapper":"proxy_protocol"}]`
	f.fSource.mu.Unlock()

	rec := f.create(t, f.source, f.sharedForm(nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create -> %d: %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
	rows := f.rows(t, f.source)
	if len(rows) != 1 || !rows[0].IsShared() || rows[0].WrapServer != "https" || rows[0].MatchKind != "tls_sni" || rows[0].MatchHosts != "ssh.example.com" || rows[0].ListenPort != 443 {
		t.Fatalf("stored row = %+v", rows)
	}
	w := f.writesTo(f.fSource, "/servers/srv0/listener_wrappers")
	if len(w) == 0 {
		t.Fatalf("no listener_wrappers write; writes: %v", f.fSource.writes)
	}
	last := w[len(w)-1]
	if !strings.HasPrefix(last, "PATCH ") {
		t.Errorf("expected a PATCH over the existing list: %.120s", last)
	}
	pi, li, ti := strings.Index(last, `"wrapper":"proxy_protocol"`), strings.Index(last, `"wrapper":"layer4"`), strings.LastIndex(last, `"wrapper":"tls"`)
	if pi < 0 || li < 0 || ti < 0 || !(pi < li && li < ti) {
		t.Errorf("want proxy_protocol, then layer4, then an explicit tls wrapper: %s", last)
	}
	if !strings.Contains(last, "tcp/10.0.0.7:22") || !strings.Contains(last, "ssh.example.com") {
		t.Errorf("route missing: %s", last)
	}
	// No dedicated layer4 server was generated for it.
	for _, wr := range f.fSource.writes {
		if strings.Contains(wr, "apps/layer4") && strings.Contains(wr, layer4ServerPrefix) {
			t.Errorf("a shared proxy was also written as a dedicated server: %.200s", wr)
		}
	}
}

func TestRemovingTheLastSharedProxyRemovesOnlyOurWrapper(t *testing.T) {
	f := newL4Fleet(t)
	f.createProxy(t, "app.example.com", nil)
	f.fSource.mu.Lock()
	f.fSource.wrappersBody = `[{"wrapper":"proxy_protocol"}]`
	f.fSource.mu.Unlock()
	f.create(t, f.source, f.sharedForm(nil))

	// The live config now carries our wrapper first, then the foreign one.
	f.fSource.mu.Lock()
	f.fSource.wrappersBody = `[{"wrapper":"layer4","routes":[]},{"wrapper":"proxy_protocol"}]`
	before := len(f.fSource.writes)
	f.fSource.mu.Unlock()

	id := strconv.FormatInt(f.rows(t, f.source)[0].ID, 10)
	rec := httptest.NewRecorder()
	f.s.deleteLayer4Proxy(rec, withChiURLParam(cookieReq(t, "/layer4-proxies/"+id+"/delete", url.Values{}, f.source), "id", id))

	f.fSource.mu.Lock()
	defer f.fSource.mu.Unlock()
	var patch string
	for _, w := range f.fSource.writes[before:] {
		if strings.Contains(w, "/servers/srv0/listener_wrappers") {
			patch = w
		}
	}
	if patch == "" || !strings.HasPrefix(patch, "PATCH ") {
		t.Fatalf("expected a PATCH removing only our wrapper; writes: %v", f.fSource.writes[before:])
	}
	if strings.Contains(patch, `"layer4"`) || !strings.Contains(patch, "proxy_protocol") {
		t.Errorf("our wrapper must go and the foreign one stay: %s", patch)
	}
}

// A layer4 wrapper CaddyUI never wrote is never touched.
func TestAForeignLayer4WrapperIsLeftAlone(t *testing.T) {
	f := newL4Fleet(t)
	f.createProxy(t, "app.example.com", nil)
	f.fSource.mu.Lock()
	f.fSource.wrappersBody = `[{"wrapper":"layer4","routes":[{"handle":[{"handler":"echo"}]}]}]`
	f.fSource.mu.Unlock()
	// A dedicated proxy triggers a normal sync; no shared proxy exists.
	if rec := f.create(t, f.source, f.form(nil)); rec.Code != http.StatusSeeOther {
		t.Fatalf("create -> %d", rec.Code)
	}
	if w := f.writesTo(f.fSource, "/listener_wrappers"); len(w) != 0 {
		t.Errorf("a layer4 wrapper CaddyUI does not own was modified: %v", w)
	}
}

func TestSharedProxyFormRefusesBadCombinationsAndConflicts(t *testing.T) {
	f := newL4Fleet(t)
	f.createProxy(t, "app.example.com", nil)
	for name, extra := range map[string]url.Values{
		"udp":          {"protocol": {"udp"}},
		"sni on http":  {"wrap_server": {"http"}},
		"no hosts":     {"match_hosts": {""}},
		"bad hostname": {"match_hosts": {"ssh.example.com:22"}},
	} {
		if rec := f.create(t, f.source, f.sharedForm(extra)); rec.Code == http.StatusSeeOther {
			t.Errorf("%s was accepted", name)
		}
	}
	if len(f.rows(t, f.source)) != 0 {
		t.Fatal("refused requests stored rows")
	}
	if rec := f.create(t, f.source, f.sharedForm(nil)); rec.Code != http.StatusSeeOther {
		t.Fatalf("first shared proxy -> %d: %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
	rec := f.create(t, f.source, f.sharedForm(url.Values{"name": {"dup"}}))
	if rec.Code == http.StatusSeeOther || !strings.Contains(rec.Body.String(), "already used") {
		t.Errorf("a second proxy for the same SNI name was accepted (%d)", rec.Code)
	}
	// A different name on the same port is fine, and SSH can sit beside it.
	if rec := f.create(t, f.source, f.sharedForm(url.Values{"name": {"rds"}, "match_hosts": {"rds.example.com"}})); rec.Code != http.StatusSeeOther {
		t.Errorf("a second SNI name was refused: %d", rec.Code)
	}
	if rec := f.create(t, f.source, f.sharedForm(url.Values{"name": {"ssh banner"}, "match_kind": {"ssh"}, "match_hosts": {""}})); rec.Code != http.StatusSeeOther {
		t.Errorf("an SSH matcher beside the SNI ones was refused: %d", rec.Code)
	}
}

func TestSharedProxiesAreDeployedLikeOthersAndShowInTheList(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	f.createProxy(t, "app.example.com", nil)
	if rec := f.create(t, f.source, f.sharedForm(nil)); rec.Code != http.StatusSeeOther {
		t.Fatalf("create -> %d", rec.Code)
	}
	got := f.rows(t, f.edge1)
	if len(got) != 1 || !got[0].IsShared() || got[0].MatchHosts != "ssh.example.com" || got[0].WrapServer != "https" {
		t.Fatalf("the target's copy = %+v", got)
	}

	rec := httptest.NewRecorder()
	f.s.listLayer4Proxies(rec, cookieReq(t, "/layer4-proxies", nil, f.source))
	body := rec.Body.String()
	if !strings.Contains(body, ":443 (shared)") || !strings.Contains(body, "TLS SNI ssh.example.com") {
		t.Errorf("the list does not describe the shared proxy:\n%s", excerpt(body, "shared"))
	}
}
