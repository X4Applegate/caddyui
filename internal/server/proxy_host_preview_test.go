package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAPIProxyHostPreviewReturnsCaddyfileAndRouteJSON(t *testing.T) {
	form := url.Values{
		"domains":        {"preview.example.com"},
		"forward_scheme": {"https"},
		"forward_host":   {"app.internal"},
		"forward_port":   {"8443"},
		"ssl_enabled":    {"on"},
		"enabled":        {"on"},
		"extra_upstream": {"app-backup.internal:8443"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-hosts/preview", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	(&Server{}).apiPreviewProxyHost(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("preview status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response struct {
		Caddyfile string         `json:"caddyfile"`
		Route     map[string]any `json:"route"`
		Error     string         `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if response.Error != "" {
		t.Fatalf("preview error = %q", response.Error)
	}
	for _, expected := range []string{
		"preview.example.com {",
		"reverse_proxy https://app.internal:8443 app-backup.internal:8443",
	} {
		if !strings.Contains(response.Caddyfile, expected) {
			t.Fatalf("Caddyfile preview missing %q:\n%s", expected, response.Caddyfile)
		}
	}
	if len(response.Route) == 0 {
		t.Fatal("route JSON preview is empty")
	}
}

func TestAPIProxyHostPreviewPadsIncompleteRequiredFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-hosts/preview", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	(&Server{}).apiPreviewProxyHost(recorder, req)

	var response struct {
		Caddyfile string `json:"caddyfile"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if response.Error != "" {
		t.Fatalf("preview error = %q", response.Error)
	}
	for _, expected := range []string{"example.com {", "(your-upstream):0"} {
		if !strings.Contains(response.Caddyfile, expected) {
			t.Fatalf("placeholder Caddyfile missing %q:\n%s", expected, response.Caddyfile)
		}
	}
}
