// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Finding 10 of the T-0927 review (T-0947): buildHTTPRoutes serves every
// host with Force SSL off on :80 without a redirect, SSL on or not, so the
// export must too; with Force SSL on, :80 only redirects.
func TestExportForceSSLOffServesPlainHTTP(t *testing.T) {
	host := func(forced bool, certID int64) models.ProxyHost {
		return models.ProxyHost{ID: 70, Domains: "on.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.30", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, SSLForced: forced, CertificateID: certID}
	}
	cert := &models.Certificate{ID: 4, Source: models.CertSourcePath, CertPath: "/c.pem", KeyPath: "/k.pem"}
	cases := []struct {
		name     string
		p        models.ProxyHost
		cert     *models.Certificate
		wantHead string
		plain80  bool
	}{
		{"ACME, Force SSL off", host(false, 0), nil, "http://on.example.test, https://on.example.test {\n", true},
		{"ACME, Force SSL on", host(true, 0), nil, "on.example.test {\n", false},
		{"certificate files, Force SSL off", host(false, 4), cert, "on.example.test {\n\ttls /c.pem /k.pem\n", true},
		{"certificate files, Force SSL on", host(true, 4), cert, "on.example.test {\n\ttls /c.pem /k.pem\n", false},
	}
	bin := lookCaddy(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderProxyHostCaddyfileWithCertificate(tc.p, tc.cert)
			if !strings.HasPrefix(out, tc.wantHead) || strings.Contains(out, "respond 503") {
				t.Fatalf("want a site starting %q:\n%s", tc.wantHead, out)
			}
			if tc.cert != nil && strings.Count(out, "tls /c.pem") != 1 {
				t.Fatalf("want the tls line once, on the HTTPS site:\n%s", out)
			}
			if bin == "" {
				return
			}
			file := filepath.Join(t.TempDir(), "Caddyfile")
			if err := os.WriteFile(file, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
			adapted, raw := caddyAdapt(t, bin, file)
			servers := adapted.(map[string]any)["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
			served80 := false
			for _, s := range servers {
				srv := s.(map[string]any)
				if strings.Join(listenAddresses(srv["listen"]), ",") == ":80" && strings.Contains(func() string { b, _ := json.Marshal(srv); return string(b) }(), `"on.example.test"`) {
					served80 = true
				}
			}
			if served80 != tc.plain80 {
				t.Fatalf("served on plain :80 = %v, want %v:\n%s", served80, tc.plain80, raw)
			}
		})
	}
}
