// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #184 round-4 review (4): a domain the address check let through
// but Caddy does not read as an address — `import`, or a token ending in `{`
// — broke the fail-closed stand-in, and with it the whole export. Such a
// host must be left out with a comment, and its neighbours exported intact.
func TestUnreadableSiteAddressIsOmittedNotStoodIn(t *testing.T) {
	caddyBin := lookCaddy(t)
	good := models.ProxyHost{ID: 1, Domains: "good.example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080, Enabled: true, SSLEnabled: true}
	for _, domains := range []string{"import", "evil.example.test{", "a.example.test, import", "x{y.example.test"} {
		bad := models.ProxyHost{ID: 2, Domains: domains, ForwardScheme: "http", ForwardHost: "10.0.0.6", ForwardPort: 8080, Enabled: true, SSLEnabled: true}
		redirect := models.RedirectionHost{ID: 3, Domains: domains, ForwardDomain: "example.test", Enabled: true}
		export := RenderServerCaddyfile("", []models.ProxyHost{good, bad}, []models.RedirectionHost{redirect}, nil, nil)
		if _, err := checkCaddyfileSites(export, nil); err != nil {
			t.Errorf("domains %q break the export (%v):\n%s", domains, err, export)
			continue
		}
		if !strings.Contains(export, "# Proxy host #2 omitted") || !strings.Contains(export, "# Redirection host #3 omitted") {
			t.Errorf("domains %q: want the hosts omitted with a comment:\n%s", domains, export)
		}
		if !strings.Contains(export, "good.example.test {") {
			t.Errorf("domains %q: the neighbouring host is missing:\n%s", domains, export)
		}
		if caddyBin != "" {
			f := filepath.Join(t.TempDir(), "Caddyfile")
			_ = os.WriteFile(f, []byte(export), 0o644)
			caddyAdapt(t, caddyBin, f)
		}
	}
}
