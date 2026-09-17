package caddy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

func TestBuildProxyRouteRateLimit(t *testing.T) {
	base := models.ProxyHost{ID: 7, Domains: "app.example.com", ForwardHost: "backend", ForwardPort: 8080}

	// Disabled (or incomplete) → no rate_limit handler.
	for _, p := range []models.ProxyHost{
		base,
		func() models.ProxyHost { c := base; c.RateLimitEnabled = true; return c }(),                          // no events/window
		func() models.ProxyHost { c := base; c.RateLimitEnabled = true; c.RateLimitEvents = 100; return c }(), // no window
		func() models.ProxyHost { c := base; c.RateLimitEvents = 100; c.RateLimitWindowSec = 60; return c }(), // not enabled
	} {
		blob, _ := json.Marshal(BuildProxyRoute(p, nil))
		if strings.Contains(string(blob), `"rate_limit"`) {
			t.Fatalf("did not expect a rate_limit handler for %+v", p)
		}
	}

	// Fully enabled → handler present with the right zone, key, window, max_events.
	p := base
	p.RateLimitEnabled = true
	p.RateLimitEvents = 100
	p.RateLimitWindowSec = 60
	blob, err := json.Marshal(BuildProxyRoute(p, nil))
	if err != nil {
		t.Fatal(err)
	}
	s := string(blob)
	for _, want := range []string{`"handler":"rate_limit"`, `"caddyui_rl_7"`, `"window":"60s"`, `"max_events":100`, `{http.request.client_ip}`} {
		if !strings.Contains(s, want) {
			t.Fatalf("rate_limit route missing %q in:\n%s", want, s)
		}
	}
}
