// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.61.0: Coraza WAF from a middleware profile.

func TestBuildWAFDirectives(t *testing.T) {
	block := BuildWAFDirectives(&models.WAFSettings{Mode: models.WAFModeBlock, CRS: true, Paranoia: 1})
	for _, want := range []string{"Include @coraza.conf-recommended", "Include @crs-setup.conf.example", "Include @owasp_crs/*.conf", "SecRuleEngine On"} {
		if !strings.Contains(block, want) {
			t.Errorf("block mode lacks %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, "blocking_paranoia_level") {
		t.Errorf("paranoia 1 is the CRS default and must not be set explicitly:\n%s", block)
	}
	// Order matters: crs-setup before the paranoia action before the rules, and the
	// engine line after the includes.
	if !(strings.Index(block, "crs-setup") < strings.Index(block, "@owasp_crs") && strings.Index(block, "@owasp_crs") < strings.Index(block, "SecRuleEngine")) {
		t.Errorf("directive order wrong:\n%s", block)
	}

	detect := BuildWAFDirectives(&models.WAFSettings{Mode: models.WAFModeDetect, CRS: true, Paranoia: 3, Directives: "  SecRuleRemoveById 942100  "})
	if !strings.Contains(detect, "SecRuleEngine DetectionOnly") || strings.Contains(detect, "SecRuleEngine On") {
		t.Errorf("detect mode must be DetectionOnly:\n%s", detect)
	}
	if !strings.Contains(detect, `setvar:tx.blocking_paranoia_level=3`) {
		t.Errorf("paranoia 3 not applied:\n%s", detect)
	}
	if !(strings.Index(detect, "paranoia") < strings.Index(detect, "@owasp_crs")) {
		t.Errorf("the paranoia action must come before the rules are included:\n%s", detect)
	}
	if !strings.HasSuffix(strings.TrimSpace(detect), "SecRuleRemoveById 942100") || strings.Index(detect, "SecRuleRemoveById") < strings.Index(detect, "@owasp_crs") {
		t.Errorf("custom directives must come last, after the rules they tune:\n%s", detect)
	}

	noCRS := BuildWAFDirectives(&models.WAFSettings{Mode: models.WAFModeBlock, CRS: false, Paranoia: 4})
	if strings.Contains(noCRS, "crs") || strings.Contains(noCRS, "owasp") || strings.Contains(noCRS, "paranoia") {
		t.Errorf("CRS off must not mention the rule set or paranoia:\n%s", noCRS)
	}
}

func TestWAFHandlerIsFirstInTheRouteAndOnlyWhenEnabled(t *testing.T) {
	host := models.ProxyHost{Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 80, Enabled: true,
		ForwardAuthURL: "http://auth:9000/v", WWWRedirect: "to_www"}
	plain, _ := json.Marshal(BuildProxyRoute(host, nil))
	if strings.Contains(string(plain), `"handler":"waf"`) {
		t.Fatal("a host without a WAF got a waf handler")
	}
	host.WAF = &models.WAFSettings{Mode: models.WAFModeBlock, CRS: true, Paranoia: 1}
	b, _ := json.Marshal(BuildProxyRoute(host, nil))
	got := string(b)
	wi, ri, fi := strings.Index(got, `"handler":"waf"`), strings.Index(got, `"handler":"reverse_proxy"`), strings.Index(got, `"handler":"subroute"`)
	if wi < 0 || !(wi < fi) || !(wi < ri) {
		t.Errorf("the WAF must run before redirects, forward auth and the upstream:\n%s", got)
	}
	if !strings.Contains(got, `"load_owasp_crs":true`) {
		t.Errorf("load_owasp_crs missing:\n%s", got)
	}
	// An unknown mode adds nothing (never a half-configured WAF).
	host.WAF = &models.WAFSettings{Mode: "bogus"}
	if b, _ := json.Marshal(BuildProxyRoute(host, nil)); strings.Contains(string(b), `"handler":"waf"`) {
		t.Error("an unknown WAF mode produced a handler")
	}
}

func TestHasWAFModuleUsesAdaptAndNeverLoadsConfig(t *testing.T) {
	var hits []string
	mk := func(adaptStatus int, body string) *Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, r.Method+" "+r.URL.Path)
			w.WriteHeader(adaptStatus)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return &Client{AdminURL: srv.URL, HTTP: srv.Client()}
	}
	if present, known := mk(200, `{"result":{"apps":{}}}`).HasWAFModule(); !present || !known {
		t.Errorf("module present: got present=%v known=%v", present, known)
	}
	if present, known := mk(400, `{"error":"adapting config using caddyfile: parsing caddyfile tokens for 'order': coraza_waf is not a registered directive, at Caddyfile:2"}`).HasWAFModule(); present || !known {
		t.Errorf("module missing: got present=%v known=%v", present, known)
	}
	if present, known := mk(500, `{"error":"something unrelated"}`).HasWAFModule(); present || known {
		t.Errorf("an unrelated failure must be 'unknown', never 'missing': present=%v known=%v", present, known)
	}
	for _, h := range hits {
		if h != "POST /adapt" {
			t.Errorf("the probe made a %q request; it must only ever /adapt (a /load would reconfigure the live Caddy)", h)
		}
	}
}
