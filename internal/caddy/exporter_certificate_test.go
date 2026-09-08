package caddy

import (
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.42.1 (issue #74): the Caddyfile view of a host with a custom
// certificate shows how Caddy gets it instead of a bare comment.
func TestRenderProxyHostCaddyfileWithCertificate(t *testing.T) {
	p := models.ProxyHost{Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true, SSLForced: true, CertificateID: 7}
	path := &models.Certificate{ID: 7, Name: "files", Source: models.CertSourcePath, CertPath: "/certs/app/fullchain.pem", KeyPath: "/certs/app/privkey.pem"}
	if out := RenderProxyHostCaddyfileWithCertificate(p, path); !strings.Contains(out, "\ttls /certs/app/fullchain.pem /certs/app/privkey.pem\n") {
		t.Errorf("file-path certificate should render a tls line:\n%s", out)
	}
	pem := &models.Certificate{ID: 7, Name: "uploaded", Source: models.CertSourcePEM}
	if out := RenderProxyHostCaddyfileWithCertificate(p, pem); !strings.Contains(out, `stored PEM certificate "uploaded"`) {
		t.Errorf("PEM certificate should be described:\n%s", out)
	}
	if out := RenderProxyHostCaddyfile(p); !strings.Contains(out, "Custom certificate ID 7") {
		t.Errorf("unknown certificate keeps the legacy comment:\n%s", out)
	}
	full := RenderServerCaddyfile("Primary", []models.ProxyHost{p}, nil, nil, []models.Certificate{*path})
	if !strings.Contains(full, "\ttls /certs/app/fullchain.pem /certs/app/privkey.pem\n") {
		t.Errorf("server export should resolve certificates:\n%s", full)
	}
}

// v2.42.1: the Advanced config's reverse_proxy block renders inside the
// generated reverse_proxy block, not as a second one; other directives stay.
func TestRenderProxyHostCaddyfileMergesAdvancedReverseProxyBlock(t *testing.T) {
	p := models.ProxyHost{Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true, SSLEnabled: true,
		AdvancedConfig: "encode gzip\nreverse_proxy {\n\tflush_interval -1\n\ttransport http {\n\t\tread_timeout 30s\n\t}\n}\n"}
	out := RenderProxyHostCaddyfile(p)
	if strings.Count(out, "reverse_proxy") != 1 {
		t.Errorf("expected exactly one reverse_proxy block:\n%s", out)
	}
	if !strings.Contains(out, "\t\tflush_interval -1\n") || !strings.Contains(out, "\t\tread_timeout 30s") || !strings.Contains(out, "\tencode gzip\n") {
		t.Errorf("sub-directives should sit inside the generated block and encode stay outside:\n%s", out)
	}
	rest, inner := splitAdvancedReverseProxyBlock("header X 1\n")
	if rest != "header X 1\n" || inner != nil {
		t.Errorf("no block: rest=%q inner=%v", rest, inner)
	}
}
