// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// T-0932: admin redirect (and proxy host) domains were written verbatim, so
// `Old.Example.Test.` broke the whole export ("subject does not qualify for
// certificate"). The live route normalises them (BuildRedirectRoute).

func TestExportNormalisesAdminRedirectDomains(t *testing.T) {
	r := models.RedirectionHost{ID: 61, Domains: "Old.Example.Test., b.example.test, OLD.example.test", ForwardScheme: "https", ForwardDomain: "new.example.test", ForwardHTTPCode: 301, Enabled: true}
	out := RenderServerCaddyfile("Primary", nil, []models.RedirectionHost{r}, nil, nil)
	if !strings.Contains(out, "\nold.example.test, b.example.test {\n") {
		t.Fatalf("want lower-cased, dot-stripped, de-duplicated addresses:\n%s", out)
	}
	// An admin's port and scheme stay as they were; only the host part is
	// normalised.
	r2 := models.RedirectionHost{ID: 62, Domains: "Port.Example.Test.:8443, HTTP://Scheme.Example.Test.", ForwardScheme: "https", ForwardDomain: "new.example.test", ForwardHTTPCode: 301, Enabled: true}
	out = RenderRedirectionCaddyfile(r2)
	if !strings.HasPrefix(out, "port.example.test:8443, http://scheme.example.test {\n") {
		t.Fatalf("want port/scheme kept with the host part normalised:\n%s", out)
	}
	// Nothing left once normalised: omitted with a comment, not silently.
	if out := RenderRedirectionCaddyfile(models.RedirectionHost{ID: 64, Domains: "., ..", ForwardDomain: "x.example.test"}); !strings.HasPrefix(out, "# Redirection host #64 omitted") {
		t.Fatalf("redirect with no host name: want an omitted comment, got %q", out)
	}
	if out := RenderProxyHostCaddyfile(models.ProxyHost{ID: 65, Domains: "..", ForwardHost: "203.0.113.1", ForwardPort: 80}); !strings.HasPrefix(out, "# Proxy host #65 omitted") {
		t.Fatalf("proxy host with no host name: want an omitted comment, got %q", out)
	}
	ph := models.ProxyHost{ID: 63, Domains: "App.Example.Test.", ForwardScheme: "http", ForwardHost: "203.0.113.30", ForwardPort: 80, Enabled: true, SSLEnabled: true, SSLForced: true}
	if out := RenderProxyHostCaddyfile(ph); !strings.Contains(out, "\napp.example.test {\n") && !strings.HasPrefix(out, "app.example.test {\n") {
		t.Fatalf("admin proxy host: want the normalised address:\n%s", out)
	}
}

func TestCaddyfileSiteAddress(t *testing.T) {
	for in, want := range map[string]string{
		"Old.Example.Test.":           "old.example.test",
		" a.example.test ":            "a.example.test",
		"*.Example.Test.":             "*.example.test",
		"Port.Example.Test.:8443":     "port.example.test:8443",
		"[FE80::1]:8443":              "[fe80::1]:8443",
		"[::1]":                       "[::1]",
		"192.0.2.1:80":                "192.0.2.1:80",
		"HTTPS://X.Example.Test:8443": "https://x.example.test:8443",
		"Example.Test./Path":          "example.test/Path",
		":8080":                       ":8080",
		".":                           "",
		"..":                          "",
		"{$SITE}":                     "{$SITE}",
	} {
		if got := caddyfileSiteAddress(in); got != want {
			t.Errorf("caddyfileSiteAddress(%q) = %q, want %q", in, got, want)
		}
	}
	got := caddyfileSiteAddresses([]string{"A.test", "a.test.", "A.test.:8443", "b.test", "a.test:8443"})
	if want := []string{"a.test", "a.test:8443", "b.test"}; !reflect.DeepEqual(got, want) {
		t.Errorf("caddyfileSiteAddresses: got %v, want %v", got, want)
	}
}

func TestExportAdminRedirectAdaptsWithLiveHosts(t *testing.T) {
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	r := models.RedirectionHost{ID: 61, Domains: "Old.Example.Test., b.example.test", ForwardScheme: "https", ForwardDomain: "new.example.test", ForwardHTTPCode: 301, Enabled: true}
	ph := models.ProxyHost{ID: 63, Domains: "App.Example.Test.", ForwardScheme: "http", ForwardHost: "203.0.113.30", ForwardPort: 80, Enabled: true, SSLEnabled: true, SSLForced: true}
	all := RenderServerCaddyfile("Primary", []models.ProxyHost{ph}, []models.RedirectionHost{r}, nil, nil)
	got := serverListenHosts(t, adaptText(t, bin, all))[":443"]
	var want []string
	for _, route := range []map[string]any{BuildRedirectRoute(r), BuildProxyRoute(ph, nil)} {
		for _, h := range asSlice(normaliseJSON(t, route["match"]).([]any)[0].(map[string]any)["host"]) {
			want = append(want, h.(string))
		}
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exported hosts %v, live route hosts %v\n%s", got, want, all)
	}
}
