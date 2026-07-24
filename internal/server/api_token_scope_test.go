package server

import "testing"

func TestProxyWriteTokenCanWritePath(t *testing.T) {
	allowed := []string{
		"/api/v1/proxy-hosts",
		"/api/v1/proxy-hosts/123",
		"/api/v1/proxy-hosts/123/toggle",
		"/api/v1/proxy-hosts/123/maintenance",
	}
	for _, path := range allowed {
		if !proxyWriteTokenCanWritePath(path) {
			t.Fatalf("expected proxy_write token to allow %s", path)
		}
	}

	blocked := []string{
		"/api/v1/redirection-hosts",
		"/api/v1/raw-routes",
		"/api/v1/certificates",
		"/api/v1/proxy-hosts-extra",
		"/proxy-hosts",
	}
	for _, path := range blocked {
		if proxyWriteTokenCanWritePath(path) {
			t.Fatalf("expected proxy_write token to block %s", path)
		}
	}
}
