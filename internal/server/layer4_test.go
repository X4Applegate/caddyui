// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/X4Applegate/caddyui/web"
	"github.com/go-chi/chi/v5"
)

// withChiURLParam attaches a chi URL parameter to req's context, for testing
// chi-routed handlers (e.g. updateServer's {id}) directly without a router.
func withChiURLParam(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// newRenderingTestServer builds a *Server whose s.render(...) actually works
// against the real embedded templates, for handler tests that must inspect a
// rendered error message. Unlike server.New, this does not start any of the
// production background loops (health poller, auto-sync, etc.) — those would
// otherwise outlive every individual test for the life of the test binary.
func newRenderingTestServer(t *testing.T, conn *sql.DB) *Server {
	t.Helper()
	tplFS, err := fs.Sub(web.FS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := parseTemplates(tplFS)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{DB: conn, Templates: tpl, Version: "test"}
}

// v2.56.0 (issue #113): layer4 (github.com/mholt/caddy-l4) app support. A
// per-server Layer4Caddyfile field holds a pasted `layer4 { ... }` Caddyfile
// block; it is adapted through that server's own admin API and only the
// resulting apps.layer4 subtree is merged into the config CaddyUI pushes.

// --- applyLayer4App / extractAdaptedLayer4App (pure, no network) ---

func TestApplyLayer4AppAddsAndRemoves(t *testing.T) {
	cfg := map[string]any{}
	applyLayer4App(cfg, map[string]any{"servers": map[string]any{"srv0": map[string]any{"listen": []any{":8443"}}}})

	apps, ok := cfg["apps"].(map[string]any)
	if !ok {
		t.Fatal("apps key missing after applying a non-empty layer4 app")
	}
	layer4, ok := apps["layer4"].(map[string]any)
	if !ok {
		t.Fatalf("apps.layer4 missing or wrong type: %#v", apps["layer4"])
	}
	if _, ok := layer4["servers"]; !ok {
		t.Fatal("layer4 servers subtree not preserved")
	}

	// Clearing (nil, mirroring an empty Layer4Caddyfile field) must remove
	// the subtree entirely, not just stop adding to it — a server that turns
	// this off expects layer4 gone from the live config.
	applyLayer4App(cfg, nil)
	apps = cfg["apps"].(map[string]any)
	if _, ok := apps["layer4"]; ok {
		t.Fatal("apps.layer4 should have been removed when layer4App is empty")
	}

	// An empty (non-nil) map behaves the same as nil.
	applyLayer4App(cfg, map[string]any{"servers": map[string]any{}})
	applyLayer4App(cfg, map[string]any{})
	if _, ok := cfg["apps"].(map[string]any)["layer4"]; ok {
		t.Fatal("apps.layer4 should have been removed for an empty map too")
	}
}

func TestExtractAdaptedLayer4AppOnlyTakesLayer4Key(t *testing.T) {
	cfg := map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{
			"layer4": map[string]any{"servers": map[string]any{"srv0": map[string]any{"listen": []any{":8443"}}}},
			"http":   map[string]any{"servers": map[string]any{"srv0": map[string]any{"listen": []any{":443"}}}},
		},
	}
	got := extractAdaptedLayer4App(cfg)
	if got == nil {
		t.Fatal("expected a non-nil layer4 subtree")
	}
	if len(got) != 1 {
		t.Fatalf("extracted layer4 app should hold only its own key, got %#v", got)
	}
	if _, ok := got["servers"]; !ok {
		t.Fatalf("layer4 servers missing: %#v", got)
	}

	if got := extractAdaptedLayer4App(map[string]any{"apps": map[string]any{"http": map[string]any{}}}); got != nil {
		t.Fatalf("expected nil when apps.layer4 is absent, got %#v", got)
	}
	if got := extractAdaptedLayer4App(map[string]any{}); got != nil {
		t.Fatalf("expected nil for a config with no apps key at all, got %#v", got)
	}
}

// --- buildLayer4App (talks to a fake admin API's /adapt) ---

func TestBuildLayer4AppSkipsAdaptForEmptyInput(t *testing.T) {
	var calls int
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()
	cl := caddy.New(admin.URL, "", "")

	app, err := buildLayer4App(cl, "")
	if err != nil {
		t.Fatalf("empty input should not error, got: %v", err)
	}
	if app != nil {
		t.Fatalf("expected nil app for empty input, got %#v", app)
	}

	app, err = buildLayer4App(cl, "   \n\t  ")
	if err != nil || app != nil {
		t.Fatalf("whitespace-only input should behave like empty, got app=%#v err=%v", app, err)
	}
	if calls != 0 {
		t.Fatalf("empty/whitespace-only input must never call the admin API, got %d call(s)", calls)
	}
}

// VERIFIED FACT #2 from issue #113's scoping comment: adapting a layer4 block
// produces a clean, self-contained apps.layer4 subtree. This test also mocks
// the response with an UNRELATED extra top-level key and an unrelated
// apps.http subtree alongside it, proving buildLayer4App discards everything
// except apps.layer4 — defense against a user pasting something unrelated.
func TestBuildLayer4AppExtractsOnlyLayer4KeyFromAdaptResponse(t *testing.T) {
	const block = "layer4 {\n\t:8443 {\n\t\troute {\n\t\t\tproxy 127.0.0.1:9000\n\t\t}\n\t}\n}"
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adapt" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "text/caddyfile" {
			http.Error(w, "unexpected content-type "+ct, http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "layer4") {
			http.Error(w, "expected layer4 block in request body, got "+string(body), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"result":{"apps":{"layer4":{"servers":{"srv0":{"listen":[":8443"],"routes":[{"handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:9000"]}]}]}]}}},"http":{"servers":{"srv0":{"listen":[":443"]}}}},"admin":{"disabled":true}}}`)
	}))
	defer admin.Close()

	app, err := buildLayer4App(caddy.New(admin.URL, "", ""), block)
	if err != nil {
		t.Fatalf("buildLayer4App failed: %v", err)
	}
	if len(app) != 1 {
		t.Fatalf("expected exactly the layer4 'servers' key (apps.http and admin must be discarded), got %#v", app)
	}
	servers, ok := app["servers"].(map[string]any)
	if !ok {
		t.Fatalf("servers subtree missing or wrong type: %#v", app)
	}
	srv0, ok := servers["srv0"].(map[string]any)
	if !ok {
		t.Fatalf("srv0 missing: %#v", servers)
	}
	if listen, _ := srv0["listen"].([]any); len(listen) != 1 || listen[0] != ":8443" {
		t.Fatalf("listen = %#v, want [:8443]", srv0["listen"])
	}
}

// A Caddy build without caddy-l4 compiled in (or a syntax error) must surface
// as a clear, actionable error — not a crash or a silently-dropped config.
func TestBuildLayer4AppSurfacesAdaptFailureClearly(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"adapting config using caddyfile adapter: parsing caddyfile tokens for 'layer4': unrecognized directive: layer4"}`)
	}))
	defer admin.Close()

	app, err := buildLayer4App(caddy.New(admin.URL, "", ""), "layer4 {\n\t:8443 {\n\t}\n}")
	if err == nil {
		t.Fatal("expected an error when Caddy rejects the layer4 block")
	}
	if app != nil {
		t.Fatalf("expected nil app on failure, got %#v", app)
	}
	if !strings.Contains(err.Error(), "unrecognized directive: layer4") {
		t.Fatalf("error should surface Caddy's diagnostic text, got: %v", err)
	}
}

// --- full sync pipeline against a fake Caddy admin API ---

// layer4FakeAdmin is a controllable fake Caddy admin API covering every
// endpoint syncCaddyInner's layer4 handling touches: GET /config (initial
// fetch), POST /adapt (layer4 Caddyfile adaptation), POST /load (validate),
// GET/POST /config/apps/layer4 (FetchPath/PutPath) and DELETE /apps/layer4.
// Everything else (routes, TLS, etc.) is answered with a generic 200 so
// these tests can isolate layer4 behavior specifically.
type layer4FakeAdmin struct {
	mu sync.Mutex

	baseConfig  string
	adaptStatus int
	adaptBody   string
	fetchBody   string // GET /config/apps/layer4 response body; "null" = unset

	loadCalls      int
	putBody        string
	putCalls       int
	deleteCalls    int
	fetchLayer4Hit int
}

func newLayer4FakeAdmin(t *testing.T, baseConfig string) (*httptest.Server, *layer4FakeAdmin) {
	t.Helper()
	f := &layer4FakeAdmin{baseConfig: baseConfig, adaptStatus: http.StatusOK, fetchBody: "null"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/config/" || r.URL.Path == "/config"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, f.baseConfig)
		case r.Method == http.MethodPost && r.URL.Path == "/adapt":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.adaptStatus)
			_, _ = io.WriteString(w, f.adaptBody)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/load"):
			f.loadCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{}")
		case r.Method == http.MethodGet && r.URL.Path == "/config/apps/layer4":
			f.fetchLayer4Hit++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, f.fetchBody)
		case r.Method == http.MethodPost && r.URL.Path == "/config/apps/layer4":
			body, _ := io.ReadAll(r.Body)
			f.putBody = string(body)
			f.putCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{}")
		case r.Method == http.MethodDelete && r.URL.Path == "/config/apps/layer4":
			f.deleteCalls++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{}")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

const layer4TestBlock = "layer4 {\n\t:8443 {\n\t\troute {\n\t\t\tproxy 127.0.0.1:9000\n\t\t}\n\t}\n}"

const layer4TestAdaptResponse = `{"result":{"apps":{"layer4":{"servers":{"srv0":{"listen":[":8443"],"routes":[{"handle":[{"handler":"proxy","upstreams":[{"dial":["127.0.0.1:9000"]}]}]}]}}}}}}`

// The common case: a server that already has at least one normal proxy host
// ALSO has a layer4 block configured. Both must be pushed in the same sync.
func TestSyncCaddyAppliesLayer4AppAlongsideNormalRoutes(t *testing.T) {
	admin, fake := newLayer4FakeAdmin(t, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
	fake.adaptBody = layer4TestAdaptResponse

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged,
		Layer4Caddyfile: layer4TestBlock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{
		Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn, Caddy: newCaddyClient(admin.URL, "", "")}
	if err := s.syncCaddy(serverID, false); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	if fake.putCalls != 1 {
		t.Fatalf("expected exactly one PUT to /config/apps/layer4, got %d", fake.putCalls)
	}
	var pushed map[string]any
	if err := json.Unmarshal([]byte(fake.putBody), &pushed); err != nil {
		t.Fatalf("pushed layer4 body is not JSON: %v (body=%s)", err, fake.putBody)
	}
	if _, ok := pushed["servers"]; !ok {
		t.Fatalf("pushed layer4 config missing servers: %#v", pushed)
	}
	if fake.deleteCalls != 0 {
		t.Fatalf("a configured layer4 app must not be deleted, got %d DELETE call(s)", fake.deleteCalls)
	}
}

// Zero behavior change: a server with no Layer4Caddyfile must never call
// /adapt, must never PUT or DELETE apps/layer4 (nothing to clean up when
// Caddy already reports it unset), and the pushed config carries no
// apps.layer4 key at all.
func TestSyncCaddyEmptyLayer4FieldIsANoOp(t *testing.T) {
	var adaptCalls int
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
		case r.URL.Path == "/adapt":
			adaptCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"result":{}}`)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "{}")
		}
	}))
	defer admin.Close()

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{
		Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn, Caddy: newCaddyClient(admin.URL, "", "")}
	if err := s.syncCaddy(serverID, false); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if adaptCalls != 0 {
		t.Fatalf("an empty Layer4Caddyfile must never call /adapt, got %d call(s)", adaptCalls)
	}
}

// A server dedicated to layer4 TCP/UDP routing — no proxies, redirects, raw
// routes, or certificates at all — must still sync instead of being refused
// by the "no entries in DB" empty-routes guard (issue #113's syncLayer4Only).
func TestSyncCaddyLayer4OnlyServerWithNoOtherRoutes(t *testing.T) {
	admin, fake := newLayer4FakeAdmin(t, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"]}}}}}`)
	fake.adaptBody = layer4TestAdaptResponse

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Layer4Node", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged,
		Layer4Caddyfile: layer4TestBlock,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn, Caddy: newCaddyClient(admin.URL, "", "")}
	if err := s.syncCaddy(serverID, false); err != nil {
		t.Fatalf("layer4-only sync should succeed, got: %v", err)
	}
	if fake.putCalls != 1 {
		t.Fatalf("expected one PUT to /config/apps/layer4, got %d", fake.putCalls)
	}
}

// A sync must abort with a clear error — not push a partial/broken config —
// when the stored layer4 block fails to adapt (e.g. a Caddy build without
// caddy-l4, or a block that was valid when saved but no longer is).
func TestSyncCaddyAbortsOnLayer4AdaptFailure(t *testing.T) {
	admin, fake := newLayer4FakeAdmin(t, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
	fake.adaptStatus = http.StatusBadRequest
	fake.adaptBody = `{"error":"unrecognized directive: layer4"}`

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged,
		Layer4Caddyfile: layer4TestBlock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{
		Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn, Caddy: newCaddyClient(admin.URL, "", "")}
	err = s.syncCaddy(serverID, false)
	if err == nil {
		t.Fatal("expected the sync to fail when the layer4 block fails to adapt")
	}
	if !strings.Contains(err.Error(), "unrecognized directive: layer4") {
		t.Fatalf("error should surface Caddy's diagnostic, got: %v", err)
	}
	if fake.loadCalls != 0 {
		t.Fatalf("a layer4 adapt failure must abort before any /load validation call, got %d", fake.loadCalls)
	}
	if fake.putCalls != 0 || fake.deleteCalls != 0 {
		t.Fatalf("a layer4 adapt failure must not write any subtree, got put=%d delete=%d", fake.putCalls, fake.deleteCalls)
	}
}

// --- model round trip ---

func TestCaddyServerLayer4CaddyfileRoundTrips(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	id, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: "http://10.8.0.3:2019", Type: models.CaddyServerTypeManaged,
		Layer4Caddyfile: " " + layer4TestBlock + " \n",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := models.GetCaddyServer(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Layer4Caddyfile != layer4TestBlock {
		t.Fatalf("GetCaddyServer Layer4Caddyfile = %q, want trimmed %q", got.Layer4Caddyfile, layer4TestBlock)
	}
	list, err := models.ListCaddyServers(conn)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, sr := range list {
		if sr.ID == id {
			found = sr.Layer4Caddyfile == layer4TestBlock
		}
	}
	if !found {
		t.Fatalf("ListCaddyServers lost the layer4 Caddyfile: %+v", list)
	}

	got.Layer4Caddyfile = ""
	if err := models.UpdateCaddyServer(conn, got); err != nil {
		t.Fatal(err)
	}
	again, err := models.GetCaddyServer(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if again.Layer4Caddyfile != "" {
		t.Errorf("after clearing, Layer4Caddyfile = %q, want empty", again.Layer4Caddyfile)
	}

	// A server created before this feature existed (migration backfill) must
	// read back as an empty string, not NULL/error.
	bare, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Bare", AdminURL: "http://10.8.0.4:2019", Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	bareRow, err := models.GetCaddyServer(conn, bare)
	if err != nil {
		t.Fatal(err)
	}
	if bareRow.Layer4Caddyfile != "" {
		t.Errorf("a server created without the field set must default to empty, got %q", bareRow.Layer4Caddyfile)
	}
}

// --- save-time validation (createServer / updateServer handlers) ---

func postForm(t *testing.T, path string, values url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestCreateServerRejectsBadLayer4CaddyfileAtSaveTime(t *testing.T) {
	admin, fake := newLayer4FakeAdmin(t, `{}`)
	fake.adaptStatus = http.StatusBadRequest
	fake.adaptBody = `{"error":"unrecognized directive: layer4"}`

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := newRenderingTestServer(t, conn)

	form := url.Values{
		"name":             {"Edge"},
		"admin_url":        {admin.URL},
		"type":             {"managed"},
		"layer4_caddyfile": {layer4TestBlock},
	}
	rec := httptest.NewRecorder()
	s.createServer(rec, postForm(t, "/servers", form))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected the form to be re-rendered with an error (200), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Layer4 Caddyfile rejected by Caddy") || !strings.Contains(rec.Body.String(), "unrecognized directive: layer4") {
		t.Fatalf("response should explain the rejection, got: %s", rec.Body.String())
	}
	if n, err := models.CountCaddyServers(conn); err != nil || n != 0 {
		t.Fatalf("a rejected layer4 block must not create the server, count=%d err=%v", n, err)
	}
}

func TestCreateServerAcceptsValidLayer4Caddyfile(t *testing.T) {
	admin, fake := newLayer4FakeAdmin(t, `{}`)
	fake.adaptBody = layer4TestAdaptResponse

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := newRenderingTestServer(t, conn)

	form := url.Values{
		"name":             {"Edge"},
		"admin_url":        {admin.URL},
		"type":             {"managed"},
		"layer4_caddyfile": {layer4TestBlock},
	}
	rec := httptest.NewRecorder()
	s.createServer(rec, postForm(t, "/servers", form))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect (303) on success, got %d: %s", rec.Code, rec.Body.String())
	}
	list, err := models.ListCaddyServers(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Layer4Caddyfile != layer4TestBlock {
		t.Fatalf("expected one server with the saved layer4 block, got %+v", list)
	}
}

func TestUpdateServerRejectsBadLayer4CaddyfileAtSaveTime(t *testing.T) {
	admin, fake := newLayer4FakeAdmin(t, `{}`)

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	id, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Edge", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	s := newRenderingTestServer(t, conn)

	fake.adaptStatus = http.StatusBadRequest
	fake.adaptBody = `{"error":"unrecognized directive: layer4"}`

	form := url.Values{
		"name":             {"Edge"},
		"admin_url":        {admin.URL},
		"type":             {"managed"},
		"layer4_caddyfile": {layer4TestBlock},
	}
	req := postForm(t, "/servers/"+strconv.FormatInt(id, 10), form)
	req = withChiURLParam(req, "id", strconv.FormatInt(id, 10))
	rec := httptest.NewRecorder()
	s.updateServer(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected the form to be re-rendered with an error (200), got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Layer4 Caddyfile rejected by Caddy") {
		t.Fatalf("response should explain the rejection, got: %s", rec.Body.String())
	}
	saved, err := models.GetCaddyServer(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Layer4Caddyfile != "" {
		t.Fatalf("a rejected layer4 block must not be persisted, got %q", saved.Layer4Caddyfile)
	}
}

// --- fleet replication ("Also copy to") ---

// One target accepts the adapt and gets the layer4 Caddyfile copied +
// synced; another target's Caddy rejects it (module not compiled in) and
// must be skipped without affecting the first target or erroring out the
// whole operation.
func TestCrossDeployLayer4CaddyfileValidatesPerTargetIndependently(t *testing.T) {
	goodAdmin, goodFake := newLayer4FakeAdmin(t, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
	goodFake.adaptBody = layer4TestAdaptResponse

	badAdmin, badFake := newLayer4FakeAdmin(t, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
	badFake.adaptStatus = http.StatusBadRequest
	badFake.adaptBody = `{"error":"unrecognized directive: layer4"}`

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	sourceID, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Source", AdminURL: "http://source:2019", Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	goodID, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Good", AdminURL: goodAdmin.URL, Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	badID, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Bad", AdminURL: badAdmin.URL, Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}
	s.crossDeployLayer4Caddyfile("tester", sourceID, layer4TestBlock, []int64{goodID, badID})

	good, err := models.GetCaddyServer(conn, goodID)
	if err != nil {
		t.Fatal(err)
	}
	if good.Layer4Caddyfile != layer4TestBlock {
		t.Fatalf("the accepting target should have the layer4 block copied, got %q", good.Layer4Caddyfile)
	}
	if goodFake.putCalls != 1 {
		t.Fatalf("the accepting target should have been synced (one PUT), got %d", goodFake.putCalls)
	}

	bad, err := models.GetCaddyServer(conn, badID)
	if err != nil {
		t.Fatal(err)
	}
	if bad.Layer4Caddyfile != "" {
		t.Fatalf("the rejecting target must not have the layer4 block saved, got %q", bad.Layer4Caddyfile)
	}
}
