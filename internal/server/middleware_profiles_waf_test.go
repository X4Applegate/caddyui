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

// v2.61.0: Coraza WAF in middleware profiles.

func wafProfileForm(name string, extra url.Values) url.Values {
	v := url.Values{"name": {name}, "waf_mode": {"block"}, "waf_crs": {"on"}, "waf_paranoia": {"2"}, "waf_directives": {"SecRuleRemoveById 942100"}}
	for k, vals := range extra {
		v[k] = vals
	}
	return v
}

// setWAFModule makes the fake Caddy answer the module probe like a Caddy that
// has (or lacks) the Coraza module.
func setWAFModule(f *layer4FakeAdmin, mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch mode {
	case "present":
		f.adaptStatus, f.adaptBody = http.StatusOK, `{"result":{"apps":{}}}`
	case "missing":
		f.adaptStatus, f.adaptBody = http.StatusBadRequest, `{"error":"adapting config using caddyfile: parsing caddyfile tokens for 'order': coraza_waf is not a registered directive, at Caddyfile:2"}`
	case "broken":
		f.adaptStatus, f.adaptBody = http.StatusInternalServerError, `{"error":"unrelated"}`
	}
}

func TestProfileWAFOverlayAndValidation(t *testing.T) {
	prof := &models.MiddlewareProfile{Name: "waf", WAFMode: "block", WAFCRS: true, WAFParanoia: 3, WAFDirectives: "SecRuleRemoveById 1"}
	h := models.ProxyHost{}
	applyProfileToHost(&h, prof)
	if h.WAF == nil || h.WAF.Mode != "block" || !h.WAF.CRS || h.WAF.Paranoia != 3 || h.WAF.Directives != "SecRuleRemoveById 1" {
		t.Fatalf("WAF not carried to the host copy: %+v", h.WAF)
	}
	// Paranoia 0 (older rows) behaves as 1; off carries nothing.
	h2 := models.ProxyHost{}
	applyProfileToHost(&h2, &models.MiddlewareProfile{WAFMode: "detect", WAFCRS: true})
	if h2.WAF == nil || h2.WAF.Paranoia != 1 {
		t.Errorf("paranoia 0 must become 1: %+v", h2.WAF)
	}
	h3 := models.ProxyHost{}
	applyProfileToHost(&h3, &models.MiddlewareProfile{WAFMode: ""})
	if h3.WAF != nil {
		t.Error("an Off profile attached a WAF")
	}

	ok := func() *models.MiddlewareProfile {
		return &models.MiddlewareProfile{Name: "p", WAFMode: "block", WAFCRS: true, WAFParanoia: 2}
	}
	if msg := validateMiddlewareProfile(ok()); msg != "" {
		t.Fatalf("valid WAF profile refused: %s", msg)
	}
	for name, mod := range map[string]func(*models.MiddlewareProfile){
		"unknown mode":       func(p *models.MiddlewareProfile) { p.WAFMode = "paranoid" },
		"paranoia 0 enabled": func(p *models.MiddlewareProfile) { p.WAFParanoia = 0 },
		"paranoia 5":         func(p *models.MiddlewareProfile) { p.WAFParanoia = 5 },
		"huge directives":    func(p *models.MiddlewareProfile) { p.WAFDirectives = strings.Repeat("a", 9000) },
		"NUL in directives":  func(p *models.MiddlewareProfile) { p.WAFDirectives = "SecRuleEngine\x00On" },
	} {
		p := ok()
		mod(p)
		if msg := validateMiddlewareProfile(p); msg == "" {
			t.Errorf("%s was accepted", name)
		}
	}
	// A profile with the WAF off needs no paranoia value.
	if msg := validateMiddlewareProfile(&models.MiddlewareProfile{Name: "x"}); msg != "" {
		t.Errorf("a WAF-off profile was refused: %s", msg)
	}
}

func TestWAFProfileIsRefusedWhenCaddyHasNoCorazaModuleAndAllowedWhenItDoes(t *testing.T) {
	f := newL4Fleet(t)
	setWAFModule(f.fSource, "missing")
	rec := httptest.NewRecorder()
	f.s.createMiddlewareProfile(rec, cookieReq(t, "/middleware-profiles", wafProfileForm("WAF", nil), f.source))
	if rec.Code == http.StatusSeeOther || !strings.Contains(rec.Body.String(), "Coraza") {
		t.Fatalf("a WAF profile was accepted for a Caddy without the module (%d)", rec.Code)
	}
	if rows, _ := models.ListMiddlewareProfiles(f.conn); len(rows) != 0 {
		t.Fatal("the refused profile was stored")
	}
	// A profile with the WAF off never needs the module.
	setWAFModule(f.fSource, "missing")
	if f.createProfile(t, profileForm("No WAF", nil)) == nil {
		t.Fatal("setup")
	}
	// Module present: fine.
	setWAFModule(f.fSource, "present")
	prof := f.createProfile(t, wafProfileForm("WAF", nil))
	if prof.WAFMode != "block" || !prof.WAFCRS || prof.WAFParanoia != 2 || prof.WAFDirectives != "SecRuleRemoveById 942100" {
		t.Errorf("stored WAF fields = %+v", prof)
	}
	// Could not ask (Caddy errors for another reason): do not block on it.
	setWAFModule(f.fSource, "broken")
	if rec := httptest.NewRecorder(); true {
		f.s.createMiddlewareProfile(rec, cookieReq(t, "/middleware-profiles", wafProfileForm("WAF2", nil), f.source))
		if rec.Code != http.StatusSeeOther {
			t.Errorf("an unreachable/odd Caddy blocked the save (%d)", rec.Code)
		}
	}
}

func TestEditingAWAFProfileChecksEveryServerThatUsesIt(t *testing.T) {
	f := newL4Fleet(t)
	setDefaultTargets(t, f.conn, f.source, f.edge1)
	setWAFModule(f.fSource, "present")
	setWAFModule(f.fEdge1, "present")
	prof := f.createProfile(t, profileForm("SSO", nil)) // WAF off at first
	f.createProxy(t, "app.example.com", url.Values{"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)}})
	if len(f.proxyHosts(t, f.edge1)) != 1 {
		t.Fatal("setup: no copy on the edge")
	}
	// The edge's Caddy lacks Coraza: turning the WAF on must be refused, naming it.
	setWAFModule(f.fEdge1, "missing")
	pid := strconv.FormatInt(prof.ID, 10)
	rec := httptest.NewRecorder()
	f.s.updateMiddlewareProfile(rec, withChiURLParam(cookieReq(t, "/middleware-profiles/"+pid, wafProfileForm("SSO", nil), f.source), "id", pid))
	if rec.Code == http.StatusSeeOther || !strings.Contains(rec.Body.String(), "Edge 1") {
		t.Fatalf("enabling the WAF was allowed although a server using the profile lacks the module (%d): %s", rec.Code, excerpt(rec.Body.String(), "Coraza"))
	}
	if got, _ := models.GetMiddlewareProfile(f.conn, prof.ID); got.WAFMode != "" {
		t.Error("the refused edit changed the profile")
	}
	setWAFModule(f.fEdge1, "present")
	rec = httptest.NewRecorder()
	f.s.updateMiddlewareProfile(rec, withChiURLParam(cookieReq(t, "/middleware-profiles/"+pid, wafProfileForm("SSO", nil), f.source), "id", pid))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("with the module everywhere the edit was refused: %d %s", rec.Code, excerpt(rec.Body.String(), "rror"))
	}
}

func TestAttachingAWAFProfileToAHostNeedsTheModuleOnThatServer(t *testing.T) {
	f := newL4Fleet(t)
	setWAFModule(f.fSource, "present")
	prof := f.createProfile(t, wafProfileForm("WAF", nil))
	setWAFModule(f.fSource, "missing")
	form := url.Values{"domains": {"app.example.com"}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"},
		"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)}}
	rec := httptest.NewRecorder()
	f.s.createProxyHost(rec, cookieReq(t, "/proxy-hosts", form, f.source))
	if rec.Code == http.StatusSeeOther {
		t.Fatal("a host with a WAF profile was saved on a Caddy without the Coraza module")
	}
	if len(f.proxyHosts(t, f.source)) != 0 {
		t.Fatal("the refused host was stored")
	}
}

func TestSyncWritesTheWAFHandlerForHostsOnAWAFProfile(t *testing.T) {
	f := newL4Fleet(t)
	setWAFModule(f.fSource, "present")
	prof := f.createProfile(t, wafProfileForm("WAF", url.Values{"waf_mode": {"detect"}}))
	f.createProxy(t, "app.example.com", url.Values{"middleware_profile_id": {strconv.FormatInt(prof.ID, 10)}})
	f.createProxy(t, "plain.example.com", nil)
	routes := f.lastSrv0Routes(t, f.source)
	if !strings.Contains(routes, `"handler":"waf"`) || !strings.Contains(routes, "SecRuleEngine DetectionOnly") || !strings.Contains(routes, `"load_owasp_crs":true`) {
		t.Fatalf("the WAF handler is missing from the live route:\n%.700s", routes)
	}
	if !strings.Contains(routes, "blocking_paranoia_level=2") || !strings.Contains(routes, "SecRuleRemoveById 942100") {
		t.Errorf("paranoia / custom directives missing:\n%.900s", routes)
	}
	// Exactly one host (the profiled one) carries it.
	if n := strings.Count(routes, `"handler":"waf"`); n != 1 {
		t.Errorf("%d waf handlers for 2 hosts, want 1 (only app.example.com)", n)
	}
	// The host row never stores the WAF.
	for _, h := range f.proxyHosts(t, f.source) {
		if h.WAF != nil {
			t.Errorf("WAF settings were stored on host %s", h.Domains)
		}
	}
}

func TestFriendlyCaddyErrorExplainsAMissingWAFModule(t *testing.T) {
	msg := friendlyCaddyError(`loading new config: loading http app module: provision http: ... unknown module: http.handlers.waf`)
	if !strings.Contains(msg, "Coraza") || !strings.Contains(msg, "applegater/caddyui-caddy") {
		t.Errorf("no hint added: %s", msg)
	}
	other := "some other rejection"
	if friendlyCaddyError(other) != other {
		t.Error("unrelated errors must pass through untouched")
	}
}

func TestProfileFormShowsTheWAFSectionWithSafeDefaults(t *testing.T) {
	f := newL4Fleet(t)
	rec := httptest.NewRecorder()
	f.s.newMiddlewareProfile(rec, cookieReq(t, "/middleware-profiles/new", nil, f.source))
	body := rec.Body.String()
	for _, want := range []string{`name="waf_mode"`, "Detection only", `name="waf_crs"`, `name="waf_paranoia"`, `name="waf_directives"`, "Start with Detection only"} {
		if !strings.Contains(body, want) {
			t.Errorf("the profile form is missing %q", want)
		}
	}
	if strings.Contains(body, `<option value="block" selected`) || strings.Contains(body, `<option value="detect" selected`) {
		t.Error("a new profile must not default to an enabled WAF")
	}
	if !strings.Contains(body, `name="waf_crs" checked`) {
		t.Error("the Core Rule Set should default to on")
	}
}
