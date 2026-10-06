// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #121: an Advanced route whose Caddyfile uses explicit http:// site
// addresses is a deliberate plain-HTTP route. It must not keep a certificate,
// must not be force-redirected to HTTPS, and must not park the user on the
// "deploying" page that waits for an ACME certificate that will never exist.

func adaptedRouteFor(host string) string {
	return `{"result":{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[` +
		`{"match":[{"host":["` + host + `"]}],"handle":[{"handler":"static_response","body":"OK"}]}]}}}}}}`
}

func newHTTPOnlyFixture(t *testing.T, host string) (*Server, int64, string) {
	t.Helper()
	admin, fake := newLayer4FakeAdmin(t, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`)
	fake.adaptBody = adaptedRouteFor(host)
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	id, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Primary", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	return newRenderingTestServer(t, conn), id, admin.URL
}

func TestHTTPOnlyAdvancedRouteDropsCertificateAndForceSSLAndSkipsDeployingPage(t *testing.T) {
	s, serverID, _ := newHTTPOnlyFixture(t, "127.0.0.1")

	form := url.Values{
		"label":          {"health"},
		"caddyfile_src":  {"# local health check\nhttp://127.0.0.1 {\n\trespond /health \"OK\" 200\n}"},
		"enabled":        {"on"},
		"ssl_forced":     {"on"}, // contradicts the explicit http:// address
		"certificate_id": {"5"},  // a certificate cannot bind to an http:// route
	}
	rec := httptest.NewRecorder()
	s.createRawRoute(rec, cookieReq(t, "/raw-routes", form, serverID))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/raw-routes" {
		t.Fatalf("redirected to %q, want the route list — an http:// route has no certificate for the deploying page to wait on", loc)
	}
	rows, err := models.ListRawRoutes(s.DB, serverID, 0, true, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("saved routes = %d (%v), want 1", len(rows), err)
	}
	if rows[0].CertificateID != 0 || rows[0].ForceSSL {
		t.Fatalf("saved certificate_id=%d force_ssl=%v, want 0 and false for an explicit http:// route", rows[0].CertificateID, rows[0].ForceSSL)
	}
}

// An ordinary Advanced route is untouched: it keeps Force SSL and still goes
// to the deploying page.
func TestHTTPSAdvancedRouteKeepsForceSSLAndDeployingPage(t *testing.T) {
	s, serverID, _ := newHTTPOnlyFixture(t, "app.example.com")

	form := url.Values{
		"label":         {"app"},
		"caddyfile_src": {"app.example.com {\n\trespond \"hi\"\n}"},
		"enabled":       {"on"},
		"ssl_forced":    {"on"},
	}
	rec := httptest.NewRecorder()
	s.createRawRoute(rec, cookieReq(t, "/raw-routes", form, serverID))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d: %s", rec.Code, rec.Body.String())
	}
	rows, _ := models.ListRawRoutes(s.DB, serverID, 0, true, nil)
	if len(rows) != 1 || !rows[0].ForceSSL {
		t.Fatalf("an https route must keep Force SSL, got %+v", rows)
	}
	if loc := rec.Header().Get("Location"); loc != "/raw-routes/"+strconv.FormatInt(rows[0].ID, 10)+"/deploying" {
		t.Fatalf("redirected to %q, want the deploying page for an https route", loc)
	}
}

func TestHTTPOnlyAdvancedRouteEditAndDeployingPageSkipTheCertificateStep(t *testing.T) {
	s, serverID, _ := newHTTPOnlyFixture(t, "127.0.0.1")
	form := url.Values{
		"label":         {"health"},
		"caddyfile_src": {"http://127.0.0.1 {\n\trespond /health \"OK\" 200\n}"},
		"enabled":       {"on"},
	}
	rec := httptest.NewRecorder()
	s.createRawRoute(rec, cookieReq(t, "/raw-routes", form, serverID))
	rows, _ := models.ListRawRoutes(s.DB, serverID, 0, true, nil)
	if len(rows) != 1 {
		t.Fatalf("setup: want 1 route, got %d", len(rows))
	}
	sid := strconv.FormatInt(rows[0].ID, 10)

	// Editing it goes straight back to the list too.
	form.Set("label", "health v2")
	rec = httptest.NewRecorder()
	s.updateRawRoute(rec, withChiURLParam(cookieReq(t, "/raw-routes/"+sid, form, serverID), "id", sid))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/raw-routes" {
		t.Fatalf("edit: want 303 to /raw-routes, got %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// And if someone opens the deploying page directly, it bounces to the list
	// instead of polling for an ACME certificate.
	rec = httptest.NewRecorder()
	req := withChiURLParam(cookieReq(t, "/raw-routes/"+sid+"/deploying", nil, serverID), "id", sid)
	s.rawRouteDeploying(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/raw-routes" {
		t.Fatalf("deploying page: want 303 to /raw-routes, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}
