package caddy

import (
	"encoding/json"
	"strings"
	"testing"
)

// v2.36.1 (issue #64): importing a live config (or classifying a pasted one)
// must keep a non-standard server port on the routes it contributes, and must
// not auto-classify such routes into proxy hosts — those have no port.
func TestClassifyConfigKeepsCustomListenOnRawRoutes(t *testing.T) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(`{"apps":{"http":{"servers":{
	  "health":{"listen":[":7070"],"routes":[
	    {"match":[{"path":["/lbhealthcheck"]}],"handle":[{"handler":"static_response","status_code":200,"body":"Hi There!"}]},
	    {"match":[{"host":["api.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"api:8080"}]}]}]},
	  "srv0":{"listen":[":443"],"routes":[
	    {"match":[{"host":["web.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"web:80"}]}]}]}
	}}}}`), &cfg); err != nil {
		t.Fatal(err)
	}

	r := ClassifyConfig(cfg)
	if len(r.Proxies) != 1 || !strings.Contains(r.Proxies[0].Domains, "web.example.com") {
		t.Fatalf("proxies = %+v, want just web.example.com (the :443 route classifies as before)", r.Proxies)
	}
	if len(r.Passthrough) != 2 {
		t.Fatalf("passthrough = %+v, want both :7070 routes — including the proxy-shaped one", r.Passthrough)
	}
	for _, rr := range r.Passthrough {
		if rr.Listen != `[":7070"]` {
			t.Errorf("raw route %q listen = %q, want [\":7070\"]", rr.Label, rr.Listen)
		}
	}
}

func TestListenAddressesToleratesMissingOrOddValues(t *testing.T) {
	if got := listenAddresses(nil); got != nil {
		t.Errorf("nil listen -> %v, want nil", got)
	}
	if got := listenAddresses([]any{":7070", 42, " ", ":7071"}); len(got) != 2 || got[0] != ":7070" || got[1] != ":7071" {
		t.Errorf("listenAddresses = %v, want [:7070 :7071]", got)
	}
}
