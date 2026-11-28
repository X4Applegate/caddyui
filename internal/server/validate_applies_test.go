// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// T-0965: the CrowdSec check must not touch the live config. It used to
// /load the current config plus a caddyui_crowdsec_probe server, which stayed.
func TestValidateCrowdSecServersOnlyAdapts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		adaptStatus int
		adaptBody   string
		wantErr     bool
	}{
		{"module present", 200, `{"result":{}}`, false},
		{"module missing", 400, `{"error":"Caddyfile:2: unrecognized global option: crowdsec"}`, true},
		{"caddy unreachable", 502, `{"error":"bad gateway"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits []string
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits = append(hits, r.Method+" "+r.URL.Path)
				if r.URL.Path == "/adapt" {
					w.WriteHeader(tc.adaptStatus)
					_, _ = w.Write([]byte(tc.adaptBody))
					return
				}
				http.NotFound(w, r)
			}))
			defer admin.Close()
			conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			id, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "edge", AdminURL: admin.URL})
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{DB: conn}
			err = s.validateCrowdSecServers(crowdSecConfig{Enabled: true, ServerIDs: map[int64]bool{id: true}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateCrowdSecServers error = %v, wantErr %v", err, tc.wantErr)
			}
			for _, h := range hits {
				if h != "POST /adapt" {
					t.Errorf("CrowdSec check made %q; it must only /adapt", h)
				}
			}
		})
	}
}

// Installs that ran the old CrowdSec check still have its probe server in
// the live config; every sync path drops it from the config it loads.
func TestRemoveCrowdSecProbeServer(t *testing.T) {
	var cfg map[string]any
	_ = json.Unmarshal([]byte(`{"apps":{"crowdsec":{"api_url":"http://lapi:8080"},"http":{"servers":{
		"srv0":{"listen":[":443"]},
		"caddyui_crowdsec_probe":{"listen":["127.0.0.1:0"],"routes":[{"handle":[{"handler":"crowdsec"}]}]}}}}}`), &cfg)
	if !removeCrowdSecProbeServer(cfg) {
		t.Fatal("probe server not reported as removed")
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	if _, ok := servers["caddyui_crowdsec_probe"]; ok {
		t.Fatal("probe server still present")
	}
	if _, ok := servers["srv0"]; !ok {
		t.Fatal("srv0 removed too")
	}
	if cfg["apps"].(map[string]any)["crowdsec"] == nil {
		t.Fatal("the crowdsec app must be left to applyCrowdSecApp, not removed here")
	}
	if removeCrowdSecProbeServer(cfg) {
		t.Fatal("second call reported a removal")
	}
	for _, empty := range []map[string]any{{}, {"apps": map[string]any{}}, {"apps": map[string]any{"http": map[string]any{}}}} {
		if removeCrowdSecProbeServer(empty) {
			t.Fatalf("removal reported on %#v", empty)
		}
	}
}

// A save that fails after its preview was accepted resyncs the database
// state; a save that reaches its own sync does not sync twice.
func TestPreviewResync(t *testing.T) {
	var synced []int64
	mk := func() *previewResync {
		return &previewResync{sync: func(id int64) { synced = append(synced, id) }, serverID: 7}
	}
	func() {
		r := mk()
		defer r.unlessSynced()
		// the DB write fails here and the handler returns
	}()
	if len(synced) != 1 || synced[0] != 7 {
		t.Fatalf("failed save: synced = %v, want [7]", synced)
	}
	synced = nil
	func() {
		r := mk()
		defer r.unlessSynced()
		r.synced()
	}()
	if len(synced) != 0 {
		t.Fatalf("saved: synced = %v, want none from the guard", synced)
	}
}
