// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.57.0 (issue #120): persistent default deployment targets. A source
// server lists the fleet servers that every web-UI save of a proxy host,
// redirection or advanced route is automatically mirrored to, so a fleet fed
// from one configuration source does not have to re-tick "Also deploy to" on
// every create and edit.

func TestDefaultDeployTargetIDsParsing(t *testing.T) {
	cases := map[string][]int64{
		"":             nil,
		"2":            {2},
		"3, 2,4":       {3, 2, 4},
		"2,2,3,2":      {2, 3},
		"x,0,-4,,7":    {7},
		" 5 ,\t6 ,abc": {5, 6},
	}
	for in, want := range cases {
		got := models.CaddyServer{DefaultDeployTargets: in}.DefaultDeployTargetIDs()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("DefaultDeployTargetIDs(%q) = %v, want %v", in, got, want)
		}
	}
	set := models.CaddyServer{DefaultDeployTargets: "2,5"}.DefaultDeployTargetSet()
	if !set[2] || !set[5] || set[3] {
		t.Errorf("DefaultDeployTargetSet = %v, want exactly {2,5}", set)
	}
	if got := models.JoinServerIDs([]int64{4, 9}); got != "4,9" {
		t.Errorf("JoinServerIDs = %q, want 4,9", got)
	}
}

// newDefaultTargetsFleet builds a source plus two edge servers, all managed.
func newDefaultTargetsFleet(t *testing.T) (s *Server, conn *sql.DB, sourceID, edge1, edge2 int64) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	mk := func(name string) int64 {
		admin, _ := newLayer4FakeAdmin(t, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
		id, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: name, AdminURL: admin.URL, Type: models.CaddyServerTypeManaged})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	sourceID, edge1, edge2 = mk("Source"), mk("Edge 1"), mk("Edge 2")
	return newRenderingTestServer(t, conn), conn, sourceID, edge1, edge2
}

func setDefaultTargets(t *testing.T, conn *sql.DB, serverID int64, targets ...int64) {
	t.Helper()
	srv, err := models.GetCaddyServer(conn, serverID)
	if err != nil {
		t.Fatal(err)
	}
	srv.DefaultDeployTargets = models.JoinServerIDs(targets)
	if err := models.UpdateCaddyServer(conn, srv); err != nil {
		t.Fatal(err)
	}
}

// --- persistence ---

func TestDefaultDeployTargetsPersistAndAreScrubbedWhenAServerIsDeleted(t *testing.T) {
	_, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
	setDefaultTargets(t, conn, source, edge1, edge2)

	got, err := models.GetCaddyServer(conn, source)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int64{edge1, edge2}; !reflect.DeepEqual(got.DefaultDeployTargetIDs(), want) {
		t.Fatalf("saved targets = %v, want %v", got.DefaultDeployTargetIDs(), want)
	}

	// Deleting a target must remove it from the source's list — otherwise a
	// later server that reuses the ID would silently start receiving the
	// source's resources.
	if err := models.DeleteCaddyServer(conn, edge1); err != nil {
		t.Fatal(err)
	}
	got, err = models.GetCaddyServer(conn, source)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int64{edge2}; !reflect.DeepEqual(got.DefaultDeployTargetIDs(), want) {
		t.Fatalf("targets after deleting edge1 = %v, want %v", got.DefaultDeployTargetIDs(), want)
	}
}

func TestCreateAndUpdateServerSaveDefaultDeployTargets(t *testing.T) {
	s, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
	admin, _ := newLayer4FakeAdmin(t, `{}`)

	// Update: tick edge1 + edge2, plus the layer4 picker's "deploy_to" for
	// edge2 only — the two fields must stay independent.
	form := url.Values{
		"name": {"Source"}, "admin_url": {admin.URL}, "type": {"managed"},
		"default_deploy_targets": {strconv.FormatInt(edge2, 10), strconv.FormatInt(edge1, 10)},
		"deploy_to":              {strconv.FormatInt(edge2, 10)},
	}
	req := withChiURLParam(postForm(t, "/servers/x", form), "id", strconv.FormatInt(source, 10))
	rec := httptest.NewRecorder()
	s.updateServer(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("update: want 303, got %d: %s", rec.Code, rec.Body.String())
	}
	got, _ := models.GetCaddyServer(conn, source)
	if want := []int64{edge1, edge2}; !reflect.DeepEqual(got.DefaultDeployTargetIDs(), want) {
		t.Fatalf("saved defaults = %v, want %v (stored ascending)", got.DefaultDeployTargetIDs(), want)
	}

	// Unticking everything clears them.
	form.Del("default_deploy_targets")
	rec = httptest.NewRecorder()
	s.updateServer(rec, withChiURLParam(postForm(t, "/servers/x", form), "id", strconv.FormatInt(source, 10)))
	got, _ = models.GetCaddyServer(conn, source)
	if got.DefaultDeployTargets != "" {
		t.Fatalf("defaults after unticking = %q, want empty", got.DefaultDeployTargets)
	}

	// Create persists them too.
	create := url.Values{
		"name": {"Brand new"}, "admin_url": {admin.URL}, "type": {"managed"},
		"default_deploy_targets": {strconv.FormatInt(edge1, 10)},
	}
	rec = httptest.NewRecorder()
	s.createServer(rec, postForm(t, "/servers", create))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: want 303, got %d: %s", rec.Code, rec.Body.String())
	}
	list, _ := models.ListCaddyServers(conn)
	last := list[len(list)-1]
	if last.Name != "Brand new" || !reflect.DeepEqual(last.DefaultDeployTargetIDs(), []int64{edge1}) {
		t.Fatalf("created server = %q defaults %v, want Brand new / [%d]", last.Name, last.DefaultDeployTargetIDs(), edge1)
	}
}

func TestParseDefaultDeployTargetsKeepsOnlyOtherManagedServers(t *testing.T) {
	s, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
	external, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Monitor", AdminURL: "http://mon:2019", Type: models.CaddyServerTypeExternal})
	if err != nil {
		t.Fatal(err)
	}
	id := func(n int64) string { return strconv.FormatInt(n, 10) }
	form := url.Values{"default_deploy_targets": {
		id(edge2), id(edge1), id(edge1), // order + duplicate
		id(source),   // itself
		id(external), // monitoring-only: can't be deployed to
		"9999",       // no such server
		"nonsense", "-3", "",
	}}
	r := httptest.NewRequest(http.MethodPost, "/servers", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()

	if got, want := s.parseDefaultDeployTargets(r, source), id(edge1)+","+id(edge2); got != want {
		t.Fatalf("parseDefaultDeployTargets = %q, want %q", got, want)
	}
}

// --- effective targets ---

func TestEffectiveDeployTargetsUnionsFormPicksWithDefaults(t *testing.T) {
	s, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
	setDefaultTargets(t, conn, source, edge1)

	if got, want := s.effectiveDeployTargets(source, nil), []int64{edge1}; !reflect.DeepEqual(got, want) {
		t.Errorf("defaults only = %v, want %v", got, want)
	}
	// A one-off extra pick is added; a pick that is already a default isn't
	// repeated; the source is never its own target.
	if got, want := s.effectiveDeployTargets(source, []int64{edge2, edge1, source, 0, -1}), []int64{edge2, edge1}; !reflect.DeepEqual(got, want) {
		t.Errorf("form + defaults = %v, want %v", got, want)
	}
}

// A server with no defaults must behave exactly as before this feature: only
// what the form ticked.
func TestEffectiveDeployTargetsWithoutDefaultsIsJustTheForm(t *testing.T) {
	s, _, source, edge1, edge2 := newDefaultTargetsFleet(t)
	if got := s.effectiveDeployTargets(source, nil); len(got) != 0 {
		t.Errorf("no defaults, no picks = %v, want nothing", got)
	}
	if got, want := s.effectiveDeployTargets(source, []int64{edge1, edge2}), []int64{edge1, edge2}; !reflect.DeepEqual(got, want) {
		t.Errorf("form picks only = %v, want %v", got, want)
	}
	// An unknown source row must degrade to the form's picks, not fail.
	if got, want := s.effectiveDeployTargets(4242, []int64{edge1}), []int64{edge1}; !reflect.DeepEqual(got, want) {
		t.Errorf("unknown source = %v, want %v", got, want)
	}
}

func TestOtherManagedServersFlagsDefaultTargetsForTheForms(t *testing.T) {
	s, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
	setDefaultTargets(t, conn, source, edge2)

	r := httptest.NewRequest(http.MethodGet, "/proxy-hosts/new", nil)
	r.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(source, 10)})
	flags := map[int64]bool{}
	for _, srv := range s.otherManagedServers(r) {
		flags[srv.ID] = srv.IsDefaultDeployTarget
	}
	if len(flags) != 2 || flags[edge1] || !flags[edge2] {
		t.Fatalf("default flags = %v, want edge2 only", flags)
	}
}

// --- the real create handlers ---

// cookieReq is a form POST from a signed-in admin with serverID selected, the
// way the real create/edit handlers see it.
func cookieReq(t *testing.T, path string, form url.Values, serverID int64) *http.Request {
	t.Helper()
	req := postForm(t, path, form)
	req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(serverID, 10)})
	admin := &models.User{ID: 1, Email: "admin@example.com", IsAdmin: true, Role: models.RoleAdmin}
	return req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, admin))
}

func TestCreateRedirectionHostDeploysToDefaultTargets(t *testing.T) {
	s, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
	setDefaultTargets(t, conn, source, edge1) // edge2 is NOT a default

	form := url.Values{
		"domains": {"old.example.com"}, "forward_scheme": {"https"},
		"forward_domain": {"new.example.com"}, "forward_http_code": {"301"}, "enabled": {"on"},
	}
	rec := httptest.NewRecorder()
	s.createRedirectionHost(rec, cookieReq(t, "/redirection-hosts", form, source))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body.String())
	}

	onEdge := func(id int64) int {
		rows, err := models.ListRedirectionHosts(conn, id, 0, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if n := onEdge(source); n != 1 {
		t.Fatalf("source has %d redirections, want 1", n)
	}
	if n := onEdge(edge1); n != 1 {
		t.Fatalf("default target has %d redirections, want 1 (automatic fan-out)", n)
	}
	if n := onEdge(edge2); n != 0 {
		t.Fatalf("non-default target has %d redirections, want 0", n)
	}

	// The form's one-off picker still adds a non-default target on top.
	form.Set("domains", "other.example.com")
	form["deploy_to"] = []string{strconv.FormatInt(edge2, 10)}
	rec = httptest.NewRecorder()
	s.createRedirectionHost(rec, cookieReq(t, "/redirection-hosts", form, source))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("second create: want 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if n := onEdge(edge1); n != 2 {
		t.Errorf("default target has %d redirections after second save, want 2", n)
	}
	if n := onEdge(edge2); n != 1 {
		t.Errorf("one-off target has %d redirections, want 1", n)
	}
}

func TestCreateProxyHostDeploysToDefaultTargetsUnlessNodeLocal(t *testing.T) {
	s, conn, source, edge1, _ := newDefaultTargetsFleet(t)
	setDefaultTargets(t, conn, source, edge1)

	form := url.Values{
		"domains": {"app.example.com"}, "forward_scheme": {"http"},
		"forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"},
	}
	rec := httptest.NewRecorder()
	s.createProxyHost(rec, cookieReq(t, "/proxy-hosts", form, source))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body.String())
	}
	hosts, err := models.ListProxyHosts(conn, edge1, 0, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Domains != "app.example.com" {
		t.Fatalf("default target proxy hosts = %+v, want the app.example.com copy", hosts)
	}

	// Node-local is the per-resource opt-out from the defaults.
	local := url.Values{
		"domains": {"db.internal.example.com"}, "forward_scheme": {"http"},
		"forward_host": {"203.0.113.11"}, "forward_port": {"5432"}, "enabled": {"on"},
		"node_local": {"on"},
	}
	rec = httptest.NewRecorder()
	s.createProxyHost(rec, cookieReq(t, "/proxy-hosts", local, source))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("node-local create: want 303, got %d: %s", rec.Code, rec.Body.String())
	}
	hosts, _ = models.ListProxyHosts(conn, edge1, 0, true, nil)
	if len(hosts) != 1 {
		t.Fatalf("default target has %d proxy hosts, want 1 — a node-local host must stay off other servers", len(hosts))
	}
}

// The forms must show default targets as always-on and keep the server form's
// new field distinct from the layer4 picker's "deploy_to".
func TestServerAndResourceFormsRenderDefaultTargets(t *testing.T) {
	s, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
	setDefaultTargets(t, conn, source, edge2)

	// Server edit form: the saved default is pre-checked under its own field.
	rec := httptest.NewRecorder()
	req := withChiURLParam(httptest.NewRequest(http.MethodGet, "/servers/x/edit", nil), "id", strconv.FormatInt(source, 10))
	s.editServerPage(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `name="default_deploy_targets" value="`+strconv.FormatInt(edge2, 10)+`" checked`) {
		t.Errorf("server form should pre-check the saved default target:\n%s", excerpt(body, "default_deploy_targets"))
	}
	if strings.Contains(body, `name="default_deploy_targets" value="`+strconv.FormatInt(edge1, 10)+`" checked`) {
		t.Error("server form pre-checked a server that is not a default target")
	}

	// Redirection form: the default is checked + disabled with a badge.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/redirection-hosts/new", nil)
	req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(source, 10)})
	s.newRedirectionHost(rec, req)
	body = rec.Body.String()
	if !strings.Contains(body, `name="deploy_to" value="`+strconv.FormatInt(edge2, 10)+`" checked disabled`) {
		t.Errorf("redirection form should show the default target as checked and disabled:\n%s", excerpt(body, "deploy_to"))
	}
	if strings.Contains(body, `name="deploy_to" value="`+strconv.FormatInt(edge1, 10)+`" checked`) {
		t.Error("redirection form pre-checked a server that is not a default target")
	}
	if !strings.Contains(body, ">default</span>") {
		t.Error("redirection form should label the default target")
	}
}

// excerpt returns a few lines around the first occurrence of needle, for
// readable failure output from a large rendered page.
func excerpt(body, needle string) string {
	i := strings.Index(body, needle)
	if i < 0 {
		return "(" + needle + " not found in " + strconv.Itoa(len(body)) + " bytes of output)"
	}
	start, end := max(0, i-200), min(len(body), i+400)
	return body[start:end]
}

// Editing is the other half of the issue: "later changes" must reach the
// defaults too, not just the first save. Each resource is created on the source
// with no deployment at all, then saved through the real edit handler.
func TestEditHandlersDeployToDefaultTargets(t *testing.T) {
	t.Run("proxy host", func(t *testing.T) {
		s, conn, source, edge1, _ := newDefaultTargetsFleet(t)
		setDefaultTargets(t, conn, source, edge1)
		h := &models.ProxyHost{Domains: "app.example.com", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true}
		id, err := models.CreateProxyHost(conn, source, 0, h)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := models.ListProxyHosts(conn, edge1, 0, true, nil); len(got) != 0 {
			t.Fatalf("precondition: edge already has %d proxy hosts", len(got))
		}

		form := url.Values{
			"domains": {"app.example.com"}, "forward_scheme": {"http"},
			"forward_host": {"203.0.113.10"}, "forward_port": {"9090"}, "enabled": {"on"},
		}
		sid := strconv.FormatInt(id, 10)
		rec := httptest.NewRecorder()
		s.updateProxyHost(rec, withChiURLParam(cookieReq(t, "/proxy-hosts/"+sid, form, source), "id", sid))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body.String())
		}
		got, _ := models.ListProxyHosts(conn, edge1, 0, true, nil)
		if len(got) != 1 || got[0].ForwardPort != 9090 {
			t.Fatalf("edge proxy hosts = %+v, want the edited copy on port 9090", got)
		}
	})

	t.Run("redirection", func(t *testing.T) {
		s, conn, source, edge1, _ := newDefaultTargetsFleet(t)
		setDefaultTargets(t, conn, source, edge1)
		rh := &models.RedirectionHost{Domains: "old.example.com", ForwardScheme: "https", ForwardDomain: "a.example.com", ForwardHTTPCode: 301, Enabled: true}
		id, err := models.CreateRedirectionHost(conn, source, 0, rh)
		if err != nil {
			t.Fatal(err)
		}

		form := url.Values{
			"domains": {"old.example.com"}, "forward_scheme": {"https"},
			"forward_domain": {"b.example.com"}, "forward_http_code": {"301"}, "enabled": {"on"},
		}
		sid := strconv.FormatInt(id, 10)
		rec := httptest.NewRecorder()
		s.updateRedirectionHost(rec, withChiURLParam(cookieReq(t, "/redirection-hosts/"+sid, form, source), "id", sid))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body.String())
		}
		got, _ := models.ListRedirectionHosts(conn, edge1, 0, true, nil)
		if len(got) != 1 || got[0].ForwardDomain != "b.example.com" {
			t.Fatalf("edge redirections = %+v, want the edited copy forwarding to b.example.com", got)
		}
	})

	t.Run("advanced route create and edit", func(t *testing.T) {
		s, conn, source, edge1, edge2 := newDefaultTargetsFleet(t)
		setDefaultTargets(t, conn, source, edge1)
		route := func(body string) string {
			return `{"match":[{"host":["raw.example.com"]}],"handle":[{"handler":"static_response","body":"` + body + `"}]}`
		}

		form := url.Values{"label": {"raw"}, "json_data": {route("v1")}, "enabled": {"on"}}
		rec := httptest.NewRecorder()
		s.createRawRoute(rec, cookieReq(t, "/raw-routes", form, source))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("create: want 303, got %d: %s", rec.Code, rec.Body.String())
		}
		onSource, _ := models.ListRawRoutes(conn, source, 0, true, nil)
		onEdge, _ := models.ListRawRoutes(conn, edge1, 0, true, nil)
		if len(onSource) != 1 || len(onEdge) != 1 {
			t.Fatalf("after create: source has %d, default target has %d advanced routes, want 1 and 1", len(onSource), len(onEdge))
		}
		if other, _ := models.ListRawRoutes(conn, edge2, 0, true, nil); len(other) != 0 {
			t.Fatalf("non-default target got %d advanced routes, want 0", len(other))
		}

		form.Set("json_data", route("v2"))
		sid := strconv.FormatInt(onSource[0].ID, 10)
		rec = httptest.NewRecorder()
		s.updateRawRoute(rec, withChiURLParam(cookieReq(t, "/raw-routes/"+sid, form, source), "id", sid))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("edit: want 303, got %d: %s", rec.Code, rec.Body.String())
		}
		onEdge, _ = models.ListRawRoutes(conn, edge1, 0, true, nil)
		if len(onEdge) != 1 || !strings.Contains(onEdge[0].JSONData, "v2") {
			t.Fatalf("default target routes after edit = %+v, want a single route carrying the v2 edit", onEdge)
		}
	})
}

// Two servers that deploy to each other would overwrite one another's copies on
// every save, so the second half of the loop is refused at save time.
func TestUpdateServerRefusesMutualDefaultDeployTargets(t *testing.T) {
	s, conn, source, edge1, _ := newDefaultTargetsFleet(t)
	setDefaultTargets(t, conn, source, edge1) // Source -> Edge 1

	edge, _ := models.GetCaddyServer(conn, edge1)
	form := url.Values{
		"name": {edge.Name}, "admin_url": {edge.AdminURL}, "type": {"managed"},
		"default_deploy_targets": {strconv.FormatInt(source, 10)}, // Edge 1 -> Source: a loop
	}
	sid := strconv.FormatInt(edge1, 10)
	rec := httptest.NewRecorder()
	s.updateServer(rec, withChiURLParam(postForm(t, "/servers/"+sid, form), "id", sid))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Pointing two servers at each other") {
		t.Fatalf("want the form re-rendered with the loop explained, got %d: %s", rec.Code, excerpt(rec.Body.String(), "each other"))
	}
	saved, _ := models.GetCaddyServer(conn, edge1)
	if saved.DefaultDeployTargets != "" {
		t.Fatalf("a refused loop must not be saved, got %q", saved.DefaultDeployTargets)
	}

	// A one-way chain is fine: Source -> Edge 1 and Edge 2 -> Edge 1.
	edge2Row, _ := models.ListCaddyServers(conn)
	var e2 models.CaddyServer
	for _, srv := range edge2Row {
		if srv.Name == "Edge 2" {
			e2 = srv
		}
	}
	ok := url.Values{
		"name": {e2.Name}, "admin_url": {e2.AdminURL}, "type": {"managed"},
		"default_deploy_targets": {strconv.FormatInt(edge1, 10)},
	}
	sid2 := strconv.FormatInt(e2.ID, 10)
	rec = httptest.NewRecorder()
	s.updateServer(rec, withChiURLParam(postForm(t, "/servers/"+sid2, ok), "id", sid2))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a one-way target must still be accepted, got %d: %s", rec.Code, rec.Body.String())
	}
}
