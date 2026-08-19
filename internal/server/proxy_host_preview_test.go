package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
)

func TestAPIProxyHostPreviewReturnsCaddyfileAndRouteJSON(t *testing.T) {
	form := url.Values{
		"domains":           {"preview.example.com"},
		"forward_scheme":    {"https"},
		"forward_host":      {"app.internal"},
		"forward_port":      {"8443"},
		"ssl_enabled":       {"on"},
		"enabled":           {"on"},
		"extra_upstream":    {"app-backup.internal:8443"},
		"basicauth_enabled": {"on"},
		"basicauth_realm":   {"Members"},
		"basicauth_user":    {"alice"},
		"basicauth_hash":    {"saved-secret-bcrypt-hash"},
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
		"basic auth users",
	} {
		if !strings.Contains(response.Caddyfile, expected) {
			t.Fatalf("Caddyfile preview missing %q:\n%s", expected, response.Caddyfile)
		}
	}
	if len(response.Route) == 0 {
		t.Fatal("route JSON preview is empty")
	}
	responseJSON := recorder.Body.String()
	for _, expected := range []string{`"handler": "authentication"`, `"username": "alice"`, `"realm": "Members"`} {
		if !strings.Contains(responseJSON, expected) {
			t.Fatalf("Basic Auth preview missing %q:\n%s", expected, responseJSON)
		}
	}
	handlers, ok := response.Route["handle"].([]any)
	if !ok || len(handlers) == 0 {
		t.Fatalf("route handlers missing from preview: %#v", response.Route)
	}
	authHandler, _ := handlers[0].(map[string]any)
	providers, _ := authHandler["providers"].(map[string]any)
	httpBasic, _ := providers["http_basic"].(map[string]any)
	accounts, _ := httpBasic["accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("Basic Auth accounts = %#v, want one redacted account", accounts)
	}
	account, _ := accounts[0].(map[string]any)
	if account["password"] != "<redacted>" {
		t.Fatalf("Basic Auth password preview = %#v, want redacted", account["password"])
	}
	if strings.Contains(responseJSON, "saved-secret-bcrypt-hash") {
		t.Fatal("Basic Auth preview leaked the saved bcrypt hash")
	}
}

func TestAPIProxyHostPreviewIncludesAdaptedAdvancedHandlers(t *testing.T) {
	adapter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adapt" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"apps": map[string]any{
					"http": map[string]any{
						"servers": map[string]any{
							"srv0": map[string]any{
								"routes": []any{map[string]any{
									"handle": []any{map[string]any{"handler": "headers"}},
								}},
							},
						},
					},
				},
			},
		})
	}))
	t.Cleanup(adapter.Close)

	form := url.Values{
		"domains":         {"advanced.example.com"},
		"forward_scheme":  {"http"},
		"forward_host":    {"app.internal"},
		"forward_port":    {"8080"},
		"advanced_config": {"header X-Preview yes"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-hosts/preview", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	(&Server{Caddy: caddy.New(adapter.URL, "", "")}).apiPreviewProxyHost(recorder, req)

	var response struct {
		Route         map[string]any `json:"route"`
		AdvancedError string         `json:"advanced_error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode advanced preview response: %v", err)
	}
	if response.AdvancedError != "" {
		t.Fatalf("advanced preview error = %q", response.AdvancedError)
	}
	handlers, _ := response.Route["handle"].([]any)
	if len(handlers) < 2 {
		t.Fatalf("advanced preview handlers = %#v, want advanced + reverse proxy", handlers)
	}
	advanced, _ := handlers[0].(map[string]any)
	if advanced["handler"] != "headers" {
		t.Fatalf("first preview handler = %#v, want adapted headers handler", advanced)
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
