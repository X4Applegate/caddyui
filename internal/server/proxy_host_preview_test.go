package server

import (
	"encoding/base64"
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
		"domains":                   {"preview.example.com"},
		"forward_scheme":            {"https"},
		"forward_host":              {"app.internal"},
		"forward_port":              {"8443"},
		"ssl_enabled":               {"on"},
		"enabled":                   {"on"},
		"extra_upstream":            {"app-backup.internal:8443"},
		"basicauth_enabled":         {"on"},
		"basicauth_realm":           {"Members"},
		"basicauth_user":            {"alice"},
		"basicauth_hash":            {"saved-secret-bcrypt-hash"},
		"api_key_header":            {"X-Preview-Key"},
		"api_key_value":             {"live-api-secret"},
		"sticky_sessions":           {"on"},
		"lb_cookie_secret":          {"live-cookie-secret"},
		"http_basic_auth_upstream":  {"upstream-user:upstream-pass"},
		"health_check_uri":          {"/health"},
		"health_check_query_params": {"token=health-query-secret;mode=full"},
		"health_check_basic_auth":   {"probe-user:probe-pass"},
		"forward_proxy_url":         {"http://proxy-user:proxy-pass@proxy.internal:3128?api_key=proxy-query-secret"},
		"forward_auth_url":          {"https://auth.internal/check?credential=auth-query-secret&mode=strict"},
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
	var authHandler map[string]any
	for _, handler := range handlers {
		candidate, _ := handler.(map[string]any)
		if candidate["handler"] == "authentication" {
			authHandler = candidate
			break
		}
	}
	if authHandler == nil {
		t.Fatalf("Basic Auth handler missing from preview: %#v", handlers)
	}
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
	for _, secret := range []string{
		"live-api-secret",
		"live-cookie-secret",
		"upstream-user:upstream-pass",
		base64.StdEncoding.EncodeToString([]byte("upstream-user:upstream-pass")),
		"probe-user:probe-pass",
		base64.StdEncoding.EncodeToString([]byte("probe-user:probe-pass")),
		"proxy-user",
		"proxy-pass",
		"health-query-secret",
		"proxy-query-secret",
		"auth-query-secret",
	} {
		if strings.Contains(responseJSON, secret) {
			t.Fatalf("route preview leaked credential %q", secret)
		}
	}
	if !strings.Contains(responseJSON, "mode=full") || !strings.Contains(responseJSON, "mode=strict") {
		t.Fatalf("route preview removed non-sensitive URL query parameters: %s", responseJSON)
	}
}

func TestRedactPreviewURLFailsClosedForMalformedQueryKey(t *testing.T) {
	got := redactPreviewURL("/health?to%ZZken=malformed-query-secret;mode=full")
	if strings.Contains(got, "malformed-query-secret") {
		t.Fatalf("malformed URL query leaked its value: %q", got)
	}
	if !strings.Contains(got, "mode=full") {
		t.Fatalf("malformed URL query removed harmless parameters: %q", got)
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

func TestAPIProxyHostPreviewRejectsTerminalAdvancedHandlers(t *testing.T) {
	form := url.Values{
		"domains":         {"terminal.example.com"},
		"forward_scheme":  {"http"},
		"forward_host":    {"app.internal"},
		"forward_port":    {"8080"},
		"advanced_config": {"respond \"not deployable here\" 200"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/proxy-hosts/preview", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	(&Server{}).apiPreviewProxyHost(recorder, req)

	var response struct {
		Route         map[string]any `json:"route"`
		AdvancedError string         `json:"advanced_error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode terminal advanced preview response: %v", err)
	}
	if !strings.Contains(response.AdvancedError, "can't contain `respond`") {
		t.Fatalf("advanced preview error = %q, want terminal-directive rejection", response.AdvancedError)
	}
	handlers, _ := response.Route["handle"].([]any)
	if len(handlers) != 1 {
		t.Fatalf("terminal preview handlers = %#v, want only reverse proxy", handlers)
	}
	reverseProxy, _ := handlers[0].(map[string]any)
	if reverseProxy["handler"] != "reverse_proxy" {
		t.Fatalf("terminal preview handler = %#v, want reverse proxy", reverseProxy)
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
