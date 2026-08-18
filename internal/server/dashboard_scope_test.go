package server

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/caddy"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestOperationsTrafficAndCertificatesUseSelectedFleetServer(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	primaryID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "primary", AdminURL: "http://primary.invalid:2019",
	})
	if err != nil {
		t.Fatal(err)
	}
	selectedID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "selected", AdminURL: "http://selected.invalid:2019",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, serverID := range []int64{primaryID, selectedID} {
		if _, err := models.CreateProxyHost(conn, serverID, 0, &models.ProxyHost{
			Domains: "Shared.TEST", ForwardScheme: "http", ForwardHost: "backend", ForwardPort: 8080, Enabled: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := models.CreateCertificate(conn, primaryID, 0, &models.Certificate{Name: "primary-cert"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"selected-cert-a", "selected-cert-b"} {
		if _, err := models.CreateCertificate(conn, selectedID, 0, &models.Certificate{Name: name}); err != nil {
			t.Fatal(err)
		}
	}

	// Keep fixtures inside today's UTC bucket even when the test starts during
	// the first minute after midnight.
	now := time.Now().UTC().Truncate(24 * time.Hour).Add(time.Hour)
	events := []models.AccessEvent{
		{TS: now, ServerID: primaryID, ServerName: "primary", Host: "Shared.TEST", ClientIP: "192.0.2.1", BytesOut: 100},
		{TS: now, ServerID: selectedID, ServerName: "selected", Host: "Shared.TEST", ClientIP: "192.0.2.2", BytesOut: 20},
		{TS: now.Add(time.Second), ServerID: selectedID, ServerName: "selected", Host: "Shared.TEST", ClientIP: "192.0.2.3", BytesOut: 30},
	}
	for _, event := range events {
		if err := models.InsertAccessEvent(conn, event); err != nil {
			t.Fatal(err)
		}
	}

	dashboardTemplate := template.Must(template.New("dashboard.html").Parse(
		`{{define "layout"}}{{.TodayViews}}|{{.TodayVisitors}}|{{.TodayBandwidth}}|{{.CertCount}}{{end}}`,
	))
	s := &Server{
		DB: conn,
		Templates: map[string]*template.Template{
			"dashboard.html": dashboardTemplate,
		},
	}
	admin := &models.User{ID: 1, Email: "admin@example.com", IsAdmin: true, Role: models.RoleAdmin}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(selectedID, 10)})
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey, admin))
	rec := httptest.NewRecorder()
	s.dashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "2|2|50|2" {
		t.Fatalf("selected dashboard totals = %q, want 2|2|50|2", got)
	}

	sparkReq := httptest.NewRequest(http.MethodGet, "/api/dashboard-sparklines", nil)
	sparkReq.AddCookie(&http.Cookie{Name: serverCookie, Value: strconv.FormatInt(selectedID, 10)})
	sparkReq = sparkReq.WithContext(context.WithValue(sparkReq.Context(), auth.ContextUserKey, admin))
	sparkRec := httptest.NewRecorder()
	s.apiDashboardSparklines(sparkRec, sparkReq)
	var spark struct {
		Days []struct {
			Views     int   `json:"views"`
			Visitors  int   `json:"visitors"`
			Bandwidth int64 `json:"bandwidth"`
		} `json:"days"`
	}
	if err := json.NewDecoder(sparkRec.Body).Decode(&spark); err != nil {
		t.Fatal(err)
	}
	if len(spark.Days) != 7 {
		t.Fatalf("sparkline days = %d, want 7", len(spark.Days))
	}
	today := spark.Days[len(spark.Days)-1]
	if today.Views != 2 || today.Visitors != 2 || today.Bandwidth != 50 {
		t.Fatalf("selected sparkline today = %#v, want 2 views, 2 visitors, 50 bytes", today)
	}
}

func TestOperationsLiveCaddyDataUsesSelectedServerAndCredentials(t *testing.T) {
	var primaryCalls int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls++
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "v2.9.0-primary"})
	}))
	defer primary.Close()

	var versionCalls, upstreamCalls int
	selected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "monitor" || password != "secret" {
			http.Error(w, "missing selected-node credentials", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/":
			versionCalls++
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "v2.11.4-selected"})
		case "/reverse_proxy/upstreams":
			upstreamCalls++
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"address": "app-a:8080", "num_requests": 3, "fails": 0},
				{"address": "app-b:8080", "num_requests": 4, "fails": 1},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer selected.Close()

	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "primary", AdminURL: primary.URL}); err != nil {
		t.Fatal(err)
	}
	selectedID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "selected", AdminURL: selected.URL, AdminUsername: "monitor", AdminPassword: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, Caddy: caddy.New(primary.URL, "", "")}
	selectedCookie := &http.Cookie{Name: serverCookie, Value: strconv.FormatInt(selectedID, 10)}

	versionReq := httptest.NewRequest(http.MethodGet, "/api/caddy-version", nil)
	versionReq.AddCookie(selectedCookie)
	versionRec := httptest.NewRecorder()
	s.apiCaddyVersion(versionRec, versionReq)
	var versionBody map[string]any
	if err := json.NewDecoder(versionRec.Body).Decode(&versionBody); err != nil {
		t.Fatal(err)
	}
	if versionBody["version"] != "v2.11.4-selected" || int64(versionBody["server_id"].(float64)) != selectedID {
		t.Fatalf("selected version response = %#v", versionBody)
	}
	stored, err := models.GetCaddyServer(conn, selectedID)
	if err != nil || stored.Version != "v2.11.4-selected" {
		t.Fatalf("stored selected version = %#v, err=%v", stored, err)
	}

	statsReq := httptest.NewRequest(http.MethodGet, "/api/system-stats", nil)
	statsReq.AddCookie(selectedCookie)
	statsReq = statsReq.WithContext(context.WithValue(statsReq.Context(), auth.ContextUserKey, &models.User{
		ID: 1, Email: "admin@example.com", IsAdmin: true, Role: models.RoleAdmin,
	}))
	statsRec := httptest.NewRecorder()
	s.apiSystemStats(statsRec, statsReq)
	var stats map[string]any
	if err := json.NewDecoder(statsRec.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats["selected_server_name"] != "selected" || stats["active_requests"] != float64(7) {
		t.Fatalf("selected system stats = %#v", stats)
	}
	if stats["healthy_upstreams"] != float64(1) || stats["total_upstreams"] != float64(2) {
		t.Fatalf("selected upstream stats = %#v", stats)
	}
	if stats["host_scope"] != "caddyui" {
		t.Fatalf("host scope = %#v", stats["host_scope"])
	}
	if primaryCalls != 0 || versionCalls != 1 || upstreamCalls != 1 {
		t.Fatalf("calls primary=%d version=%d upstream=%d", primaryCalls, versionCalls, upstreamCalls)
	}
}
