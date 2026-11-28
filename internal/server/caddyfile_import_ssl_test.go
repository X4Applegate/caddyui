// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// importAdapted runs postCaddyfileImport as an admin against a fake Caddy
// admin whose /adapt answers with adapted, and returns the stored rows.
func importAdapted(t *testing.T, src, adapted string) ([]models.ProxyHost, []models.RawRoute) {
	t.Helper()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":` + adapted + `}`))
	}))
	t.Cleanup(admin.Close)
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: admin.URL}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New(admin.URL, "", "")}
	user := &models.User{ID: 1, Email: "admin@test", Role: models.RoleAdmin}
	form := url.Values{"caddyfile": {src}}
	req := httptest.NewRequest(http.MethodPost, "/caddyfile-import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, user))
	s.postCaddyfileImport(httptest.NewRecorder(), req)
	hosts, _ := models.ListProxyHosts(conn, 1, 0, true, nil)
	raws, _ := models.ListRawRoutes(conn, 1, 0, true, nil)
	return hosts, raws
}

const importRoute = `{"match":[{"host":["twin.example.test"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"203.0.113.40:8080"}]}]}]}],"terminal":true}`

// Finding 12 of the T-0927 review (T-0947): an export of a host with Force
// SSL off re-imports as one host with Force SSL off, not as a Force SSL
// host (which turned the :80 redirect back on).
func TestCaddyfileImportRestoresForceSSLOff(t *testing.T) {
	src := "http://twin.example.test, https://twin.example.test {\n\treverse_proxy 203.0.113.40:8080\n}\n"
	for name, tc := range map[string]struct {
		adapted             string
		wantSSL, wantForced bool
	}{
		"http and https":  {`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[` + importRoute + `]},"srv1":{"listen":[":80"],"routes":[` + importRoute + `]}}}}}`, true, false},
		"plain HTTP only": {`{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[` + importRoute + `]}}}}}`, false, false},
		"HTTPS only":      {`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[` + importRoute + `]}}}}}`, true, true},
	} {
		t.Run(name, func(t *testing.T) {
			hosts, raws := importAdapted(t, src, tc.adapted)
			if len(hosts) != 1 || len(raws) != 0 {
				t.Fatalf("want one proxy host and no raw route, got %d hosts %#v, %d raw", len(hosts), hosts, len(raws))
			}
			if h := hosts[0]; h.SSLEnabled != tc.wantSSL || h.SSLForced != tc.wantForced {
				t.Fatalf("SSL %v / Force SSL %v, want %v / %v", h.SSLEnabled, h.SSLForced, tc.wantSSL, tc.wantForced)
			}
		})
	}
	// A :80 site whose body differs from the HTTPS one is not a twin.
	other := strings.Replace(importRoute, "8080", "9090", 1)
	hosts, _ := importAdapted(t, src, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[`+importRoute+`]},"srv1":{"listen":[":80"],"routes":[`+other+`]}}}}}`)
	if len(hosts) != 1 || !hosts[0].SSLForced {
		t.Fatalf("different :80 body must not turn Force SSL off: %#v", hosts)
	}
}

// The same round trip through a real `caddy adapt` of the export, for SSL
// on with ACME and with certificate files.
func TestCaddyfileExportReimportKeepsForceSSLOff(t *testing.T) {
	bin, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("SKIPPED: no `caddy` binary on PATH")
	}
	cert := &models.Certificate{ID: 4, Source: models.CertSourcePath, CertPath: "/c.pem", KeyPath: "/k.pem"}
	for name, c := range map[string]*models.Certificate{"ACME": nil, "certificate files": cert} {
		t.Run(name, func(t *testing.T) {
			p := models.ProxyHost{ID: 7, Domains: "twin.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.40", ForwardPort: 8080, Enabled: true, SSLEnabled: true}
			if c != nil {
				p.CertificateID = c.ID
			}
			src := caddy.RenderProxyHostCaddyfileWithCertificate(p, c)
			file := filepath.Join(t.TempDir(), "Caddyfile")
			if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(bin, "adapt", "--config", file, "--adapter", "caddyfile").Output()
			if err != nil {
				t.Fatalf("adapt: %v\n%s", err, src)
			}
			hosts, raws := importAdapted(t, src, string(out))
			if len(hosts) != 1 || len(raws) != 0 || hosts[0].SSLForced {
				t.Fatalf("want one host with Force SSL off, got %#v (raw %d)\n%s", hosts, len(raws), src)
			}
		})
	}
}
