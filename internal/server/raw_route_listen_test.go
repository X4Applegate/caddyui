package server

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.36.1 (issue #64): an Advanced route pasted as `:7070 { … }` must end up on
// its own :7070 listener, not nested under CaddyUI's :443/:80 servers.

const listenTestHealthRoute = `{"match":[{"path":["/lbhealthcheck"]}],"handle":[{"handler":"static_response","body":"Hi There!","status_code":200}]}`

func adaptedListenFixture(t *testing.T) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(`{"apps":{"http":{"servers":{
	  "srv1":{"listen":[":7070"],"routes":[`+listenTestHealthRoute+`]},
	  "srv0":{"listen":[":443"],"routes":[{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"static_response","status_code":200}]}]}
	}}}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestExtractAdaptedServerRoutesKeepsEachServersListen(t *testing.T) {
	got := extractAdaptedServerRoutes(adaptedListenFixture(t))
	if len(got) != 2 {
		t.Fatalf("routes = %d, want 2", len(got))
	}
	// Servers are visited in name order, so srv0 (:443) comes before srv1 (:7070).
	if !reflect.DeepEqual(got[0].Listen, []string{":443"}) || !reflect.DeepEqual(got[1].Listen, []string{":7070"}) {
		t.Fatalf("listen = %v / %v, want [:443] / [:7070]", got[0].Listen, got[1].Listen)
	}
	if models.NormalizeRawRouteListen(got[0].Listen) != "" {
		t.Error(":443 must normalise to default placement (empty)")
	}
	if got := models.NormalizeRawRouteListen(got[1].Listen); got != `[":7070"]` {
		t.Errorf(":7070 normalised to %q", got)
	}
	if n := len(extractAdaptedRoutes(adaptedListenFixture(t))); n != 2 {
		t.Errorf("extractAdaptedRoutes returned %d routes, want 2 (it must still see every server)", n)
	}
}

func TestNormalizeRawRouteListen(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"", "  "}, ""},
		{[]string{":443"}, ""},
		{[]string{":80", "0.0.0.0:443"}, ""},
		{[]string{":7070"}, `[":7070"]`},
		{[]string{"7070"}, `[":7070"]`},
		{[]string{" :7071 ", ":7070", ":7070"}, `[":7070",":7071"]`},
		{[]string{":7070", ":443"}, `[":7070"]`},
		{[]string{"127.0.0.1:7070"}, `["127.0.0.1:7070"]`},
	} {
		if got := models.NormalizeRawRouteListen(tc.in); got != tc.want {
			t.Errorf("NormalizeRawRouteListen(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := models.ParseRawRouteListenInput(" :7070, :7071;\n:7072 "); !reflect.DeepEqual(got, []string{":7070", ":7071", ":7072"}) {
		t.Errorf("ParseRawRouteListenInput = %q", got)
	}
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{":7070"}, "caddyui_listen_7070"},
		{[]string{"127.0.0.1:7070", ":7071"}, "caddyui_listen_127_0_0_1_7070_7071"},
		{nil, ""},
	} {
		if got := models.RawRouteListenServerName(tc.in); got != tc.want {
			t.Errorf("RawRouteListenServerName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	rr := models.RawRoute{Listen: `[":7070",":7071"]`}
	if got := rr.ListenDisplay(); got != ":7070, :7071" {
		t.Errorf("ListenDisplay = %q", got)
	}
	if (models.RawRoute{Listen: "not json"}).ListenAddrs() != nil {
		t.Error("ListenAddrs must tolerate a corrupt value by falling back to default placement")
	}
}

func TestRawListenServersAreGroupedByPortAndKeptOffSrv0(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn}
	raws := []models.RawRoute{
		{ID: 1, Label: "lb", Enabled: true, Listen: `[":7070"]`, JSONData: listenTestHealthRoute},
		{ID: 2, Label: "lb-2", Enabled: true, Listen: `[":7070"]`, JSONData: listenTestHealthRoute, BlockCommonExploits: true},
		{ID: 3, Label: "other", Enabled: true, Listen: `[":9090"]`, JSONData: listenTestHealthRoute},
		{ID: 4, Label: "disabled", Enabled: false, Listen: `[":7070"]`, JSONData: listenTestHealthRoute},
		{ID: 5, Label: "default", Enabled: true, JSONData: `{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"static_response","status_code":200}]}`},
	}

	servers := s.buildRawListenServers(raws)
	if len(servers) != 2 {
		t.Fatalf("servers = %v, want caddyui_listen_7070 and caddyui_listen_9090", keysOf(servers))
	}
	seven := servers["caddyui_listen_7070"]
	if seven == nil {
		t.Fatalf("no caddyui_listen_7070 server; got %v", keysOf(servers))
	}
	if !reflect.DeepEqual(seven["listen"], []any{":7070"}) {
		t.Errorf("caddyui_listen_7070 listen = %#v, want [:7070]", seven["listen"])
	}
	routes := seven["routes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("caddyui_listen_7070 has %d routes, want the two enabled :7070 routes (the disabled one excluded)", len(routes))
	}
	// The second route asked for the exploit blocker: the shared wrapper must
	// apply on per-port servers exactly as on srv0.
	handle := routes[1].(map[string]any)["handle"].([]any)
	if len(handle) != 2 || handle[0].(map[string]any)["handler"] != "subroute" {
		t.Errorf("block_common_exploits wrapper missing on a per-port route: handle = %#v", handle)
	}
	if nine := servers["caddyui_listen_9090"]; nine == nil || len(nine["routes"].([]any)) != 1 {
		t.Errorf("caddyui_listen_9090 = %#v, want one route", nine)
	}

	merged := s.buildMergedRoutes(nil, nil, raws)
	if len(merged) != 1 {
		t.Fatalf("srv0 routes = %d, want only the default-placement route", len(merged))
	}
	match := merged[0].(map[string]any)["match"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(match["host"], []any{"app.example.com"}) {
		t.Errorf("srv0 kept the wrong route: %#v", merged[0])
	}
	if httpRoutes := s.buildHTTPRoutes(nil, nil, raws); len(httpRoutes) != 1 {
		t.Errorf(":80 routes = %d, want only the default-placement route (own-listener routes never go on :80)", len(httpRoutes))
	}
}

func TestApplyRawListenServersReplacesStaleOnesAndLeavesOthers(t *testing.T) {
	cfg := map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
		"srv0":                map[string]any{"listen": []any{":443"}},
		"caddyui_http":        map[string]any{"listen": []any{":80"}},
		"caddyui_listen_9999": map[string]any{"listen": []any{":9999"}}, // stale: port changed / route deleted
		"health":              map[string]any{"listen": []any{":7071"}}, // operator-managed, must survive
	}}}}
	applyRawListenServers(cfg, map[string]map[string]any{
		"caddyui_listen_7070": {"listen": []any{":7070"}, "routes": []any{}},
	})
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	want := []string{"caddyui_http", "caddyui_listen_7070", "health", "srv0"}
	if got := keysOf(servers); !reflect.DeepEqual(got, want) {
		t.Fatalf("servers after apply = %v, want %v", got, want)
	}
}

func TestRawRouteListenRoundTripsThroughTheDatabase(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	id, err := models.CreateRawRoute(conn, 1, 0, &models.RawRoute{Label: "lb", JSONData: listenTestHealthRoute, Enabled: true, Listen: `[":7070"]`})
	if err != nil {
		t.Fatal(err)
	}
	got, err := models.GetRawRoute(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen != `[":7070"]` || !reflect.DeepEqual(got.ListenAddrs(), []string{":7070"}) {
		t.Fatalf("GetRawRoute listen = %q", got.Listen)
	}
	list, err := models.ListRawRoutes(conn, 1, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Listen != `[":7070"]` {
		t.Fatalf("ListRawRoutes listen = %+v", list)
	}
	got.Listen = ""
	if err := models.UpdateRawRoute(conn, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := models.GetRawRoute(conn, id); again.Listen != "" {
		t.Errorf("after clearing, listen = %q, want empty", again.Listen)
	}
}

func keysOf(m any) []string {
	var out []string
	switch v := m.(type) {
	case map[string]any:
		for k := range v {
			out = append(out, k)
		}
	case map[string]map[string]any:
		for k := range v {
			out = append(out, k)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
