// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// T-0927: a proxy host saved with SSL off exported `tls off`, which Caddy
// v2.11 refuses, so export-all failed to load as a whole; for a tenant's
// host with an Advanced config the export veto's own adapt check failed on
// it, and the host came out as a 503 stand-in. Saved through the real form
// by an admin and by a tenant, with and without an Advanced config, every
// host must export as a real site that the whole file adapts with.
func TestSSLOffHostsExportAndAdapt(t *testing.T) {
	s, _, sid, caddyBin, admin, tenant := newExportFixture(t)
	requireCaddy(t, caddyBin, "saving the Advanced config and adapting the export")
	form := func(dom, adv string) url.Values {
		v := url.Values{"domains": {dom}, "forward_scheme": {"http"}, "forward_host": {"203.0.113.10"}, "forward_port": {"8080"},
			"enabled": {"on"}}
		if adv != "" {
			v.Set("advanced_config", adv)
		}
		return v
	}
	saves := []struct {
		user     *models.User
		dom, adv string
	}{
		{admin, "admin-plain.example.test", ""},
		{admin, "admin-adv.example.test", "header X-Admin yes"},
		{tenant, "tenant-plain.example.test", ""},
		{tenant, "tenant-adv.example.test", "header X-Tenant yes"},
	}
	for _, sv := range saves {
		rec := httptest.NewRecorder()
		s.createProxyHost(rec, asUser(postForm(t, "/proxy-hosts", form(sv.dom, sv.adv)), sid, sv.user, nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("save %s: %d %s", sv.dom, rec.Code, formError(rec.Body.String()))
		}
	}
	for _, u := range []*models.User{admin, tenant} {
		export := exportAs(t, s, sid, u)
		if strings.Contains(export, "tls off") || strings.Contains(export, "respond 503") {
			t.Errorf("export for %s: want no `tls off` and no fail-closed stand-in:\n%s", u.Email, export)
		}
		for _, sv := range saves {
			if !u.IsAdmin && sv.user != u {
				continue
			}
			if !strings.Contains(export, "http://"+sv.dom+", https://"+sv.dom+" {\n") {
				t.Errorf("export for %s: %s should be a site on http:// and https://:\n%s", u.Email, sv.dom, export)
			}
		}
		if _, err := adaptWithCaddy(caddyBin, []byte(export)); err != nil {
			t.Errorf("export for %s does not adapt: %v\n%s", u.Email, err, export)
		}
	}
}
