// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestRestoreSnapshotPreservesPreviousConfig(t *testing.T) {
	for _, tc := range []struct {
		name                                           string
		fetchFails, saveFails, loadFails, autoDisabled bool
		wantStatus, wantLoads                          int
	}{
		{name: "success", wantStatus: http.StatusSeeOther, wantLoads: 1},
		{name: "fetch failure", fetchFails: true, wantStatus: http.StatusBadGateway},
		{name: "snapshot write failure", saveFails: true, wantStatus: http.StatusInternalServerError},
		{name: "Caddy rejects config", loadFails: true, wantStatus: http.StatusBadGateway, wantLoads: 1},
		{name: "automatic snapshots disabled", autoDisabled: true, wantStatus: http.StatusSeeOther, wantLoads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newCSRFTestServer(t)
			const previous = `{"apps":{"http":{"servers":{}}}}`
			const target = `{"apps":{}}`
			live := previous
			loads := 0
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/config/":
					if tc.fetchFails {
						http.Error(w, "unavailable", 503)
						return
					}
					_, _ = io.WriteString(w, live)
				case r.Method == http.MethodPost && r.URL.Path == "/load":
					loads++
					if r.URL.RawQuery != "" {
						t.Errorf("unexpected load query: %s", r.URL.RawQuery)
					}
					if !tc.autoDisabled {
						snaps, err := models.ListSnapshots(s.DB, 1, 100)
						if err != nil || len(snaps) != 2 || snaps[0].ConfigJSON != previous {
							t.Errorf("previous configuration must be saved BEFORE load: snapshots=%v err=%v", snaps, err)
						}
					}
					if tc.loadFails {
						http.Error(w, "invalid config", 400)
						return
					}
					body, _ := io.ReadAll(r.Body)
					live = string(body)
				default:
					t.Errorf("unexpected admin request: %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			}))
			defer admin.Close()
			s.Caddy = caddy.New(admin.URL, "", "")
			id, err := models.CreateSnapshot(s.DB, 1, models.SnapshotSourceManual, "restore target", target)
			if err != nil {
				t.Fatal(err)
			}
			if tc.autoDisabled {
				if err := models.SetSetting(s.DB, settingAutoSnapshots, "0"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.saveFails {
				_, err := s.DB.Exec(`CREATE TRIGGER fail_snapshot_insert BEFORE INSERT ON config_snapshots BEGIN SELECT RAISE(FAIL, 'test write failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
			}
			r := httptest.NewRequest(http.MethodPost, "/snapshots/"+strconv.FormatInt(id, 10)+"/restore", nil)
			routeCtx := chi.NewRouteContext()
			routeCtx.URLParams.Add("id", strconv.FormatInt(id, 10))
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
			w := httptest.NewRecorder()
			s.restoreSnapshot(w, r)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if loads != tc.wantLoads {
				t.Errorf("loads=%d, want %d", loads, tc.wantLoads)
			}
			wantLive := previous
			if tc.wantStatus == http.StatusSeeOther {
				wantLive = target
			}
			var got, want any
			if err := json.Unmarshal([]byte(live), &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(wantLive), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("live=%s, want %s", live, wantLive)
			}
		})
	}
}
