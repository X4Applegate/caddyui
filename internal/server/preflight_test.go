package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// fakeCaddyAdmin answers the calls a preview validation and a sync make. A
// validate/load whose body mentions "/missing/" is rejected the way Caddy
// rejects an unreadable certificate file.
func fakeCaddyAdmin(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var loads []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/config"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[]}}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			loads = append(loads, r.URL.RawQuery)
			mu.Unlock()
			if strings.Contains(string(body), "/missing/") {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"loading config: loading new config: loading http app module: provision http: getting tls app: loading tls app module: provision tls: loading certificates: open /missing/fullchain.pem: no such file or directory"}`))
				return
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte("{}"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &loads
}

func newPreflightTestServer(t *testing.T) (*Server, int64) {
	t.Helper()
	admin, _ := fakeCaddyAdmin(t)
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	serverID, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Primary", AdminURL: admin.URL, Type: models.CaddyServerTypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{DB: conn, Caddy: newCaddyClient(admin.URL, "", "")}, serverID
}

// v2.42.1 (issue #74): a file-path certificate Caddy cannot open is refused
// before it is saved, with the container-path explanation; a readable one
// passes; a host referencing the bad certificate is refused too.
func TestPreviewValidationRefusesUnreadableCertificateFile(t *testing.T) {
	s, serverID := newPreflightTestServer(t)
	bad := &models.Certificate{Name: "letsencrypt-on-host", Domains: "app.example.test", Source: models.CertSourcePath, CertPath: "/missing/fullchain.pem", KeyPath: "/missing/privkey.pem"}
	msg := s.previewCertificateValidate(serverID, bad)
	if !strings.Contains(msg, "Caddy cannot open /missing/fullchain.pem") || !strings.Contains(msg, "inside the Caddy container") || !strings.Contains(msg, "letsencrypt-on-host") {
		t.Fatalf("message = %q", msg)
	}
	good := &models.Certificate{Name: "ok", Domains: "app.example.test", Source: models.CertSourcePath, CertPath: "/certs/fullchain.pem", KeyPath: "/certs/privkey.pem"}
	if msg := s.previewCertificateValidate(serverID, good); msg != "" {
		t.Fatalf("readable certificate should pass, got %q", msg)
	}

	// Once a bad certificate exists (say, from before this release), a host
	// attached to it is refused with the same explanation.
	badID, err := models.CreateCertificate(s.DB, serverID, 0, bad)
	if err != nil {
		t.Fatal(err)
	}
	host := &models.ProxyHost{Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true, SSLForced: true, CertificateID: badID}
	if msg := s.previewProxyHostValidate(serverID, host); !strings.Contains(msg, "Caddy cannot open /missing/fullchain.pem") {
		t.Fatalf("host with unreadable certificate should be refused, got %q", msg)
	}
	redirect := &models.RedirectionHost{Domains: "old.example.test", ForwardScheme: "https", ForwardDomain: "new.example.test", ForwardHTTPCode: 301, Enabled: true, SSLEnabled: true, CertificateID: badID}
	if msg := s.previewRedirectValidate(serverID, redirect); !strings.Contains(msg, "Caddy cannot open") {
		t.Fatalf("redirect with unreadable certificate should be refused, got %q", msg)
	}
	// A generic rejection keeps Caddy's words but says the change was not saved.
	if got := friendlyCaddyRejection("Caddy rejected the proposed config: something else", nil); !strings.HasPrefix(got, "Caddy rejected this change, so it was not saved: something else") {
		t.Errorf("generic message = %q", got)
	}
}

// A sync Caddy rejects is recorded for the banner and cleared by the next
// successful sync; a held server is left to the hold banner.
func TestSyncCaddyRecordsFailuresForTheBanner(t *testing.T) {
	s, serverID := newPreflightTestServer(t)
	bad := models.Certificate{Name: "bad", Domains: "app.example.test", Source: models.CertSourcePath, CertPath: "/missing/fullchain.pem", KeyPath: "/missing/privkey.pem"}
	badID, err := models.CreateCertificate(s.DB, serverID, 0, &bad)
	if err != nil {
		t.Fatal(err)
	}
	host := models.ProxyHost{Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true, SSLForced: true, CertificateID: badID}
	if _, err := models.CreateProxyHost(s.DB, serverID, 0, &host); err != nil {
		t.Fatal(err)
	}
	if err := s.syncCaddy(serverID, true); err == nil {
		t.Fatal("sync should fail while the certificate file is unreadable")
	}
	rec := s.syncErrorFor(serverID)
	if rec == nil || !strings.Contains(rec.Error, "no such file or directory") || rec.ServerName != "Primary" {
		t.Fatalf("recorded sync error = %+v", rec)
	}
	servers, _ := models.ListCaddyServers(s.DB)
	if banners := s.activeSyncErrors(servers); len(banners) != 1 || banners[0].ServerID != serverID {
		t.Fatalf("activeSyncErrors = %+v", banners)
	}

	// Fix the certificate → the next sync succeeds and clears the record.
	bad.ID = badID
	bad.CertPath, bad.KeyPath = "/certs/fullchain.pem", "/certs/privkey.pem"
	if err := models.UpdateCertificate(s.DB, &bad); err != nil {
		t.Fatal(err)
	}
	if err := s.syncCaddy(serverID, true); err != nil {
		t.Fatalf("sync should succeed now: %v", err)
	}
	if s.syncErrorFor(serverID) != nil {
		t.Fatal("a successful sync must clear the recorded error")
	}

	// A held server reports through the hold banner only.
	s.setSyncHold(syncHold{ServerID: serverID, ServerName: "Primary", Detail: "held"})
	_ = s.syncCaddy(serverID, true)
	if s.syncErrorFor(serverID) != nil {
		t.Fatal("no sync-error record while a hold is set")
	}
	s.clearSyncHold(serverID)
	s.setSyncError(serverID, "Primary", io.ErrUnexpectedEOF)
	raw, _ := models.GetSetting(s.DB, syncErrorKey(serverID))
	var stored syncError
	if json.Unmarshal([]byte(raw), &stored) != nil || stored.Error != io.ErrUnexpectedEOF.Error() {
		t.Fatalf("stored = %q", raw)
	}
	s.clearSyncError(serverID)
	if s.syncErrorFor(serverID) != nil {
		t.Fatal("clearSyncError should remove the record")
	}
}

// The banner's "back" redirect never follows a protocol-relative referer.
func TestRedirectBackStaysLocal(t *testing.T) {
	for referer, want := range map[string]string{
		"http://caddyui.local/certificates":    "/certificates",
		"http://caddyui.local//evil.example/x": "/",
		"":                                     "/",
		"http://caddyui.local/proxy-hosts?x=1": "/proxy-hosts",
	} {
		req := httptest.NewRequest(http.MethodPost, "/servers/1/sync-error/clear", nil)
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		rec := httptest.NewRecorder()
		redirectBack(rec, req)
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("referer %q → %q, want %q", referer, got, want)
		}
	}
	if e := (models.HostExpectation{Path: "//evil.example/x"}).Normalized(); e.Path != "/evil.example/x" {
		t.Errorf("expectation path = %q, want a single leading slash", e.Path)
	}
}
