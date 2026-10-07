// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.60.0 (issue #124): reusable middleware profiles.

func ssoProfile() *models.MiddlewareProfile {
	return &models.MiddlewareProfile{
		Name: "Internal SSO", SecurityHeaders: true, XFrameOptions: "DENY", CSPHeader: "default-src 'self'",
		ForwardAuthURL: "http://authentik:9000/outpost.goauthentik.io/auth/caddy", ForwardAuthCopyHeaders: "X-Authentik-Username",
		ForwardAuthSkipPaths: "/health", AccessList: "10.0.0.0/8", IPBlocklist: "203.0.113.0/24",
		CustomReqHeaders: `{"X-Env":"prod","X-Both":"profile"}`, CustomRespHeaders: `{"X-Robots-Tag":"noindex"}`,
	}
}

func TestProfileFillsEmptyHostFieldsAndHostWins(t *testing.T) {
	prof := ssoProfile()

	// An empty host inherits everything.
	h := models.ProxyHost{}
	applyProfileToHost(&h, prof)
	if !h.SecurityHeadersEnabled || h.XFrameOptions != "DENY" || h.CSPHeader != "default-src 'self'" ||
		h.ForwardAuthURL != prof.ForwardAuthURL || h.ForwardAuthCopyHeaders != "X-Authentik-Username" || h.ForwardAuthSkipPaths != "/health" ||
		h.AccessList != "10.0.0.0/8" || h.IPBlocklist != "203.0.113.0/24" {
		t.Fatalf("empty host did not inherit the profile: %+v", h)
	}

	// Values set on the host win; forward auth is all-or-nothing.
	own := models.ProxyHost{
		XFrameOptions: "SAMEORIGIN", AccessList: "192.168.0.0/16",
		ForwardAuthURL: "http://authelia:9091/api/verify", ForwardAuthMethod: "POST",
		CustomReqHeaders: `{"X-Both":"host"}`,
	}
	applyProfileToHost(&own, prof)
	if own.XFrameOptions != "SAMEORIGIN" || own.AccessList != "192.168.0.0/16" {
		t.Errorf("host values were overridden: %+v", own)
	}
	if own.ForwardAuthURL != "http://authelia:9091/api/verify" || own.ForwardAuthMethod != "POST" || own.ForwardAuthCopyHeaders != "" || own.ForwardAuthSkipPaths != "" {
		t.Errorf("a host with its own forward auth must keep ONLY its own settings: %+v", own)
	}
	if own.IPBlocklist != "203.0.113.0/24" || own.CSPHeader != "default-src 'self'" {
		t.Errorf("unset host fields did not inherit: %+v", own)
	}
	if !strings.Contains(own.CustomReqHeaders, `"X-Env":"prod"`) || !strings.Contains(own.CustomReqHeaders, `"X-Both":"host"`) || strings.Contains(own.CustomReqHeaders, `"profile"`) {
		t.Errorf("request headers did not merge with the host winning: %s", own.CustomReqHeaders)
	}
	if !strings.Contains(own.CustomRespHeaders, "X-Robots-Tag") {
		t.Errorf("response headers lost: %s", own.CustomRespHeaders)
	}

	// No profile: untouched.
	untouched := models.ProxyHost{Domains: "a.example.com", AccessList: "1.2.3.0/24"}
	applyProfileToHost(&untouched, nil)
	if untouched.Domains != "a.example.com" || untouched.AccessList != "1.2.3.0/24" || untouched.ForwardAuthURL != "" || untouched.SecurityHeadersEnabled {
		t.Errorf("a nil profile changed the host: %+v", untouched)
	}
}

func TestValidateMiddlewareProfile(t *testing.T) {
	ok := func() *models.MiddlewareProfile { return ssoProfile() }
	if msg := validateMiddlewareProfile(ok()); msg != "" {
		t.Fatalf("valid profile refused: %s", msg)
	}
	for name, mod := range map[string]func(*models.MiddlewareProfile){
		"no name":           func(p *models.MiddlewareProfile) { p.Name = "  " },
		"long name":         func(p *models.MiddlewareProfile) { p.Name = strings.Repeat("a", 81) },
		"bad auth URL":      func(p *models.MiddlewareProfile) { p.ForwardAuthURL = "authentik:9000" },
		"bad method":        func(p *models.MiddlewareProfile) { p.ForwardAuthMethod = "DELETE" },
		"bad allow CIDR":    func(p *models.MiddlewareProfile) { p.AccessList = "10.0.0.0/33" },
		"bad block entry":   func(p *models.MiddlewareProfile) { p.IPBlocklist = "not-an-ip" },
		"headers not JSON":  func(p *models.MiddlewareProfile) { p.CustomReqHeaders = "X-Env: prod" },
		"bad header name":   func(p *models.MiddlewareProfile) { p.CustomRespHeaders = `{"Bad Name":"x"}` },
		"newline in value":  func(p *models.MiddlewareProfile) { p.CustomRespHeaders = `{"X-A":"a\nb"}` },
		"newline in CSP":    func(p *models.MiddlewareProfile) { p.CSPHeader = "a\r\nSet-Cookie: x=1" },
		"newline in prefix": func(p *models.MiddlewareProfile) { p.ForwardAuthHeadersPrefix = "X\nY" },
	} {
		p := ok()
		mod(p)
		if msg := validateMiddlewareProfile(p); msg == "" {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, mod := range map[string]func(*models.MiddlewareProfile){
		"IPv6 CIDR":         func(p *models.MiddlewareProfile) { p.AccessList = "fd00::/8, 10.1.2.3" },
		"newline separated": func(p *models.MiddlewareProfile) { p.IPBlocklist = "10.0.0.0/8\n192.168.0.0/16" },
		"empty everything":  func(p *models.MiddlewareProfile) { *p = models.MiddlewareProfile{Name: "empty"} },
		"https auth, POST": func(p *models.MiddlewareProfile) {
			p.ForwardAuthURL = "https://auth.example.com/v"
			p.ForwardAuthMethod = "POST"
		},
	} {
		p := ok()
		mod(p)
		if msg := validateMiddlewareProfile(p); msg != "" {
			t.Errorf("%s was refused: %s", name, msg)
		}
	}
}

// Profiles hold forward-auth upstreams and IP policy: admin-only to manage.
func TestMiddlewareProfilesAreAdminOnly(t *testing.T) {
	e := newSecEnv(t)
	form := url.Values{"name": {"x"}}
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/middleware-profiles"}, {http.MethodGet, "/middleware-profiles/new"}, {http.MethodPost, "/middleware-profiles"},
		{http.MethodGet, "/middleware-profiles/1/edit"}, {http.MethodPost, "/middleware-profiles/1"}, {http.MethodPost, "/middleware-profiles/1/delete"},
	} {
		for _, who := range []string{"alice", "viewer"} {
			var f url.Values
			if rt.method == http.MethodPost {
				f = form
			}
			if rec := e.do(t, who, rt.method, rt.path, f); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s -> %d, want 403", who, rt.method, rt.path, rec.Code)
			}
		}
	}
	for _, p := range []string{"/middleware-profiles", "/middleware-profiles/new"} {
		if rec := e.do(t, "admin", http.MethodGet, p, nil); rec.Code != http.StatusOK {
			t.Errorf("admin GET %s -> %d", p, rec.Code)
		}
	}
	if !strings.Contains(e.do(t, "admin", http.MethodGet, "/proxy-hosts", nil).Body.String(), `href="/middleware-profiles"`) {
		t.Error("the admin's navigation is missing Middleware Profiles")
	}
	if strings.Contains(e.do(t, "alice", http.MethodGet, "/proxy-hosts", nil).Body.String(), `href="/middleware-profiles"`) {
		t.Error("a non-admin's navigation links to Middleware Profiles")
	}
}

func profileForm(name string, extra url.Values) url.Values {
	v := url.Values{"name": {name}, "security_headers": {"on"}, "forward_auth_url": {"http://authentik:9000/outpost.goauthentik.io/auth/caddy"},
		"forward_auth_copy_headers": {"X-Authentik-Username"}, "ip_blocklist": {"203.0.113.0/24"}}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

func (f *l4Fleet) createProfile(t *testing.T, form url.Values) *models.MiddlewareProfile {
	t.Helper()
	rec := httptest.NewRecorder()
	f.s.createMiddlewareProfile(rec, cookieReq(t, "/middleware-profiles", form, f.source))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create profile -> %d: %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
	rows, _ := models.ListMiddlewareProfiles(f.conn)
	for i := range rows {
		if rows[i].Name == form.Get("name") {
			return &rows[i]
		}
	}
	t.Fatal("profile not stored")
	return nil
}

func (f *l4Fleet) lastSrv0Routes(t *testing.T, serverID int64) string {
	t.Helper()
	fake := map[int64]*layer4FakeAdmin{f.source: f.fSource, f.edge1: f.fEdge1, f.edge2: f.fEdge2}[serverID]
	fake.mu.Lock()
	defer fake.mu.Unlock()
	last := ""
	for _, w := range fake.writes {
		if strings.HasPrefix(w, "PATCH /config/apps/http/servers/srv0/routes") || strings.HasPrefix(w, "POST /config/apps/http/servers/srv0/routes") {
			last = w
		}
	}
	return last
}

func TestProfileReachesTheLiveConfigAndEditsResyncHosts(t *testing.T) {
	f := newL4Fleet(t)
	prof := f.createProfile(t, profileForm("Internal SSO", nil))
	f.createProxy(t, "app.example.com", url.Values{"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)}})

	host := f.proxyHosts(t, f.source)[0]
	if got := models.ProxyHostProfileID(f.conn, host.ID); got != prof.ID {
		t.Fatalf("attachment = %d, want %d", got, prof.ID)
	}
	// The host row itself is untouched — the profile is applied at build time.
	if host.ForwardAuthURL != "" || host.SecurityHeadersEnabled {
		t.Errorf("the profile was copied into the host row: %+v", host)
	}
	routes := f.lastSrv0Routes(t, f.source)
	for _, want := range []string{"authentik:9000", "/outpost.goauthentik.io/auth/caddy", "X-Authentik-Username", "203.0.113.0/24", "Strict-Transport-Security"} {
		if !strings.Contains(routes, want) {
			t.Errorf("the live route is missing %q from the profile:\n%.600s", want, routes)
		}
	}
	if strings.Contains(routes, `"handler":"forward_auth"`) {
		t.Error("the route still uses the nonexistent forward_auth handler")
	}

	// Editing the profile re-syncs the servers that use it.
	f.fSource.mu.Lock()
	n := len(f.fSource.writes)
	f.fSource.mu.Unlock()
	pid := strconv.FormatInt(prof.ID, 10)
	rec := httptest.NewRecorder()
	f.s.updateMiddlewareProfile(rec, withChiURLParam(cookieReq(t, "/middleware-profiles/"+pid, profileForm("Internal SSO", url.Values{"forward_auth_url": {"http://authelia:9091/api/verify"}}), f.source), "id", pid))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("update -> %d: %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
	f.fSource.mu.Lock()
	after := len(f.fSource.writes)
	f.fSource.mu.Unlock()
	if after <= n {
		t.Fatal("editing the profile did not re-sync the server")
	}
	if now := f.lastSrv0Routes(t, f.source); !strings.Contains(now, "authelia:9091") || strings.Contains(now, "authentik:9000") {
		t.Errorf("the edit did not reach Caddy:\n%.600s", now)
	}
}

func TestHostsOwnForwardAuthWinsOverTheProfile(t *testing.T) {
	f := newL4Fleet(t)
	prof := f.createProfile(t, profileForm("Internal SSO", nil))
	f.createProxy(t, "app.example.com", url.Values{
		"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)},
		"forward_auth_url":      {"http://authelia:9091/api/verify"},
	})
	routes := f.lastSrv0Routes(t, f.source)
	if !strings.Contains(routes, "authelia:9091") || strings.Contains(routes, "authentik:9000") {
		t.Errorf("the host's own forward auth must win:\n%.500s", routes)
	}
	if !strings.Contains(routes, "203.0.113.0/24") {
		t.Errorf("unset fields should still inherit the profile (blocklist missing)")
	}
}

func TestProfileCannotBeDeletedWhileInUseAndHostCleanupFreesIt(t *testing.T) {
	f := newL4Fleet(t)
	prof := f.createProfile(t, profileForm("Internal SSO", nil))
	f.createProxy(t, "app.example.com", url.Values{"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)}})
	pid := strconv.FormatInt(prof.ID, 10)

	rec := httptest.NewRecorder()
	f.s.deleteMiddlewareProfile(rec, withChiURLParam(cookieReq(t, "/middleware-profiles/"+pid+"/delete", url.Values{}, f.source), "id", pid))
	if got, _ := models.GetMiddlewareProfile(f.conn, prof.ID); got == nil {
		t.Fatal("a profile in use was deleted")
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
		t.Errorf("no error shown: %s", loc)
	}
	if rows, _ := models.ListMiddlewareProfiles(f.conn); rows[0].HostCount != 1 {
		t.Errorf("host count = %d, want 1", rows[0].HostCount)
	}

	// Deleting the host drops its attachment, which frees the profile.
	f.deleteProxy(t, f.proxyHosts(t, f.source)[0].ID)
	rec = httptest.NewRecorder()
	f.s.deleteMiddlewareProfile(rec, withChiURLParam(cookieReq(t, "/middleware-profiles/"+pid+"/delete", url.Values{}, f.source), "id", pid))
	if got, _ := models.GetMiddlewareProfile(f.conn, prof.ID); got != nil {
		t.Error("the unused profile was not deleted")
	}
}

func TestProfileNamesAreUniqueAndUnknownProfileIDsAreIgnored(t *testing.T) {
	f := newL4Fleet(t)
	f.createProfile(t, profileForm("Internal SSO", nil))
	rec := httptest.NewRecorder()
	f.s.createMiddlewareProfile(rec, cookieReq(t, "/middleware-profiles", profileForm("internal sso", nil), f.source))
	if rec.Code == http.StatusSeeOther {
		t.Error("a duplicate (case-insensitive) name was accepted")
	}
	f.createProxy(t, "app.example.com", url.Values{"middleware_profile_id": {"9999"}})
	if got := models.ProxyHostProfileID(f.conn, f.proxyHosts(t, f.source)[0].ID); got != 0 {
		t.Errorf("a nonexistent profile ID was attached: %d", got)
	}
}

func TestFleetCopyUsesTheSameProfileAndFollowsChanges(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	prof := f.createProfile(t, profileForm("Internal SSO", nil))
	f.createProxy(t, "app.example.com", url.Values{"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)}})
	target := f.proxyHosts(t, f.edge1)
	if len(target) != 1 {
		t.Fatalf("setup: target has %d hosts", len(target))
	}
	if got := models.ProxyHostProfileID(f.conn, target[0].ID); got != prof.ID {
		t.Errorf("the deployed copy has profile %d, want %d", got, prof.ID)
	}
	if routes := f.lastSrv0Routes(t, f.edge1); !strings.Contains(routes, "authentik:9000") {
		t.Errorf("the target's live route lacks the profile:\n%.400s", routes)
	}

	// Switching the host to no profile on the source reaches the copy.
	src := f.proxyHosts(t, f.source)[0]
	sid := strconv.FormatInt(src.ID, 10)
	form := url.Values{"domains": {"app.example.com"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"}, "middleware_profile_id": {"0"}}
	rec := httptest.NewRecorder()
	f.s.updateProxyHost(rec, withChiURLParam(cookieReq(t, "/proxy-hosts/"+sid, form, f.source), "id", sid))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("update -> %d: %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
	if got := models.ProxyHostProfileID(f.conn, f.proxyHosts(t, f.edge1)[0].ID); got != 0 {
		t.Errorf("the copy kept profile %d after the source detached it", got)
	}
}

func TestCloneKeepsTheProfileAndFormShowsThePicker(t *testing.T) {
	f := newL4Fleet(t)
	prof := f.createProfile(t, profileForm("Internal SSO", nil))
	f.createProxy(t, "app.example.com", url.Values{"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)}})
	src := f.proxyHosts(t, f.source)[0]
	sid := strconv.FormatInt(src.ID, 10)

	rec := httptest.NewRecorder()
	f.s.editProxyHost(rec, withChiURLParam(cookieReq(t, "/proxy-hosts/"+sid+"/edit", nil, f.source), "id", sid))
	body := rec.Body.String()
	if !strings.Contains(body, "data-middleware-profile") || !strings.Contains(body, `name="middleware_profile_id"`) {
		t.Fatal("the host form has no profile picker")
	}
	if !strings.Contains(body, `value="`+strconv.FormatInt(prof.ID, 10)+`" selected`) {
		t.Error("the attached profile is not preselected")
	}

	rec = httptest.NewRecorder()
	f.s.cloneProxyHost(rec, withChiURLParam(cookieReq(t, "/proxy-hosts/"+sid+"/clone", url.Values{}, f.source), "id", sid))
	hosts := f.proxyHosts(t, f.source)
	if len(hosts) != 2 {
		t.Fatalf("clone left %d hosts", len(hosts))
	}
	for _, h := range hosts {
		if got := models.ProxyHostProfileID(f.conn, h.ID); got != prof.ID {
			t.Errorf("host %d has profile %d, want %d (clone must keep it)", h.ID, got, prof.ID)
		}
	}
}
