// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #184 review (blocking): a non-admin could save a Path matcher whose
// text breaks out of its Caddyfile token and adds a whole site block (here
// proxying the Caddy admin API) plus an `import` to the server-wide export —
// past validateProxyUpstreamsForUser, which only sees the harmless JSON route.
// The form and the JSON import must refuse it, and whatever is stored must
// export without the injected text.
func TestNonAdminPathMatcherCannotInjectIntoCaddyfileExport(t *testing.T) {
	s, conn, source, _, _ := newDefaultTargetsFleet(t)
	tenant := &models.User{ID: 2, Email: "tenant@example.com", Role: models.RoleUser}
	const payload = "/x`\\\"\n}\nevil.example.test {\n\treverse_proxy 127.0.0.1:2019\n}\nimport /etc/caddy/Caddyfile\nx.example.test {\n\t@caddyui_path path /\n#"

	exportClean := func(t *testing.T) {
		t.Helper()
		hosts, err := models.ListProxyHosts(conn, source, 0, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		out := caddy.RenderServerCaddyfile("", hosts, nil, nil, nil)
		if strings.Contains(out, "evil.example.test") || strings.Contains(out, "127.0.0.1:2019") || strings.Contains(out, "import /etc") {
			t.Fatalf("server export carries the injected text:\n%s", out)
		}
	}

	for _, typ := range []string{"regexp", "exact", ""} {
		form := url.Values{
			"domains": {"tenant-" + typ + ".example.com"}, "forward_scheme": {"http"},
			"forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"},
			"path_matcher": {payload}, "path_matcher_type": {typ},
		}
		req := postForm(t, "/proxy-hosts", form)
		req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(source, 10)})
		req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, tenant))
		rec := httptest.NewRecorder()
		s.createProxyHost(rec, req)
		if rec.Code == http.StatusSeeOther {
			t.Errorf("type %q: the injecting path matcher was saved", typ)
		} else if !strings.Contains(rec.Body.String(), "must not contain line breaks") {
			t.Errorf("type %q: expected the path matcher error, got %d", typ, rec.Code)
		}
		exportClean(t)
	}

	// The JSON import builds the host straight from the uploaded file.
	ph := models.ProxyHost{Domains: "imported.example.com", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080,
		PathMatcher: payload, PathMatcherType: "regexp"}
	body, _ := json.Marshal(ph)
	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("config_file", "host.json")
	_, _ = fw.Write(body)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/proxy-hosts/import", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(source, 10)})
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, tenant))
	rec := httptest.NewRecorder()
	s.importProxyHost(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("JSON import of the injecting matcher: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	exportClean(t)

	// An invalid regexp is refused with its own message; a valid one saves.
	for _, tc := range []struct {
		matcher string
		saved   bool
	}{{"^/(unclosed", false}, {"^/backend/", true}} {
		form := url.Values{
			"domains": {"re-" + strconv.FormatBool(tc.saved) + ".example.com"}, "forward_scheme": {"http"},
			"forward_host": {"203.0.113.10"}, "forward_port": {"8080"}, "enabled": {"on"},
			"path_matcher": {tc.matcher}, "path_matcher_type": {"regexp"},
		}
		req := postForm(t, "/proxy-hosts", form)
		req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(source, 10)})
		req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, tenant))
		rec := httptest.NewRecorder()
		s.createProxyHost(rec, req)
		if saved := rec.Code == http.StatusSeeOther; saved != tc.saved {
			t.Errorf("regexp %q: saved=%v, want %v (%d)", tc.matcher, saved, tc.saved, rec.Code)
		}
		if !tc.saved && !strings.Contains(rec.Body.String(), "not a valid regular expression") {
			t.Errorf("regexp %q: expected the regexp error message", tc.matcher)
		}
	}
}
