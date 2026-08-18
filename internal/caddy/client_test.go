package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetVersionFromAdminDoesNotUseProcessFallback(t *testing.T) {
	t.Setenv("CADDY_VERSION", "v2.99.0-local")
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "version unavailable", http.StatusServiceUnavailable)
	}))
	defer admin.Close()

	client := New(admin.URL, "", "")
	if version, err := client.GetVersionFromAdmin(context.Background()); err == nil || version != "" {
		t.Fatalf("strict admin version = %q, err=%v; want an error without local fallback", version, err)
	}
	if version, err := client.GetVersion(context.Background()); err != nil || version != "v2.99.0-local" {
		t.Fatalf("compatibility version = %q, err=%v; want process fallback", version, err)
	}
}
