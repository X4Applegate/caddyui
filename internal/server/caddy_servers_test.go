package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestAPIV1ListServersReturnsSafeFleetMetadata(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	id, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name:          "EDGE",
		AdminURL:      "http://caddy-edge:2019",
		Type:          models.CaddyServerTypeManaged,
		Tags:          "edge, production",
		AdminUsername: "secret-user",
		AdminPassword: "secret-password",
		PublicIP:      "203.0.113.10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := models.SetCaddyServerVersion(conn, id, "v2.10.0"); err != nil {
		t.Fatal(err)
	}
	contactedAt := time.Date(2026, 7, 30, 12, 34, 56, 0, time.UTC)
	if err := models.SetCaddyServerStatus(conn, id, models.CaddyServerStatusOnline, &contactedAt); err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, &models.User{
		ID: 1, Email: "admin@example.com", IsAdmin: true, Role: models.RoleAdmin,
	}))
	rec := httptest.NewRecorder()
	s.apiV1ListServers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("servers = %d, want 1", len(rows))
	}
	row := rows[0]
	if row["name"] != "EDGE" || row["type"] != "managed" || row["status"] != "online" || row["version"] != "v2.10.0" {
		t.Fatalf("unexpected server metadata: %#v", row)
	}
	if row["last_contact_at"] != "2026-07-30T12:34:56Z" {
		t.Fatalf("last_contact_at = %#v", row["last_contact_at"])
	}
	tags, ok := row["tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "edge" || tags[1] != "production" {
		t.Fatalf("tags = %#v", row["tags"])
	}
	for _, secretField := range []string{"admin_username", "admin_password", "public_ip"} {
		if _, found := row[secretField]; found {
			t.Fatalf("response leaked %q: %#v", secretField, row)
		}
	}
}

func TestAPIV1ListServersAllowsAuthenticatedNonAdmin(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: "http://caddy:2019", Type: models.CaddyServerTypeManaged,
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, &models.User{
		ID: 2, Email: "viewer@example.com", Role: models.RoleView,
	}))
	rec := httptest.NewRecorder()
	s.apiV1ListServers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestValidateProxyAdvancedUsesSelectedFleetServer(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var primaryAdaptCalls int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/adapt" {
			primaryAdaptCalls++
			http.Error(w, "wrong server", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	var selectedAdaptCalls int
	selected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adapt" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		selectedAdaptCalls++
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "header X-Test value") {
			t.Fatalf("adapt body = %q, want advanced config snippet", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"result":{"apps":{"http":{"servers":{"srv0":{"routes":[{"handle":[{"handler":"headers"}]}]}}}}}}`)
	}))
	defer selected.Close()

	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name:     "Primary",
		AdminURL: primary.URL,
		Type:     models.CaddyServerTypeManaged,
	}); err != nil {
		t.Fatal(err)
	}
	selectedID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name:     "Remote",
		AdminURL: selected.URL,
		Type:     models.CaddyServerTypeManaged,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := &Server{DB: conn}
	req := httptest.NewRequest(http.MethodPost, "/proxy-hosts", nil)
	req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(selectedID, 10)})

	if errMsg := s.validateProxyAdvanced(s.caddyForRequest(req), &models.ProxyHost{
		AdvancedConfig: "header X-Test value",
	}); errMsg != "" {
		t.Fatalf("validateProxyAdvanced() = %q, want success", errMsg)
	}
	if primaryAdaptCalls != 0 {
		t.Fatalf("primary adapt calls = %d, want 0", primaryAdaptCalls)
	}
	if selectedAdaptCalls != 1 {
		t.Fatalf("selected adapt calls = %d, want 1", selectedAdaptCalls)
	}
}
