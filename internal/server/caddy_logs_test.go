package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddylogs"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestDisableRuntimeLogCaptureRetainsStateAfterRemoteFailure(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer admin.Close()

	hub := caddylogs.New(nil)
	hub.SetCapture(caddylogs.CaptureState{
		ServerID: 4, ServerName: "edge", Level: "INFO", ExpiresAt: time.Now().Add(time.Minute),
	})
	timer := time.NewTimer(time.Hour)
	t.Cleanup(func() { timer.Stop() })
	s := &Server{
		caddyLogHub:      hub,
		runtimeLogTimers: map[int64]*time.Timer{4: timer},
	}
	server := models.CaddyServer{ID: 4, Name: "edge", AdminURL: admin.URL}
	if err := s.disableRuntimeLogCapture(server); err == nil {
		t.Fatal("disable returned nil after the Caddy admin API rejected cleanup")
	}
	if _, active := hub.Capture(server.ID); !active {
		t.Fatal("capture state was cleared even though the remote logger is still installed")
	}
	if s.runtimeLogTimers[server.ID] != timer {
		t.Fatal("cleanup timer was discarded after a failed remote disable")
	}
}

func TestDisableRuntimeLogCaptureClearsStateAfterSuccess(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer admin.Close()

	hub := caddylogs.New(nil)
	hub.SetCapture(caddylogs.CaptureState{ServerID: 8, ServerName: "edge"})
	timer := time.NewTimer(time.Hour)
	s := &Server{
		caddyLogHub:      hub,
		runtimeLogTimers: map[int64]*time.Timer{8: timer},
	}
	server := models.CaddyServer{ID: 8, Name: "edge", AdminURL: admin.URL}
	if err := s.disableRuntimeLogCapture(server); err != nil {
		t.Fatal(err)
	}
	if _, active := hub.Capture(server.ID); active {
		t.Fatal("capture state remains after successful remote cleanup")
	}
	if _, found := s.runtimeLogTimers[server.ID]; found {
		t.Fatal("cleanup timer remains after successful remote cleanup")
	}
}
