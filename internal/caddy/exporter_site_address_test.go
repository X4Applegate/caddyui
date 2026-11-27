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
	// Admin ports and schemes stay as they are today.
	r2 := models.RedirectionHost{ID: 62, Domains: "Port.Example.Test.:8443, HTTP://Scheme.Example.Test.", ForwardScheme: "https", ForwardDomain: "new.example.test", ForwardHTTPCode: 301, Enabled: true}
	out = RenderRedirectionCaddyfile(r2)
	if !strings.Contains(out, "port.example.test:8443, http://scheme.example.test {\n") {
		t.Fatalf("want port/scheme kept with the host part normalised:\n%s", out)
	}
	ph := models.ProxyHost{ID: 63, Domains: "App.Example.Test.", ForwardScheme: "http", ForwardHost: "203.0.113.30", ForwardPort: 80, Enabled: true, SSLEnabled: true, SSLForced: true}
	if out := RenderProxyHostCaddyfile(ph); !strings.Contains(out, "\napp.example.test {\n") && !strings.HasPrefix(out, "app.example.test {\n") {
		t.Fatalf("admin proxy host: want the normalised address:\n%s", out)
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
