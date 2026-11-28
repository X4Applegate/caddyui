// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAdmin is a Caddy admin API that keeps one live config. /load replaces
// it unless the config carries "reject", which Caddy answers with 400 and no
// change, as real Caddy does.
type fakeAdmin struct {
	live        string
	loads       []string
	failRestore bool
}

func (f *fakeAdmin) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write([]byte(f.live))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			if r.URL.Query().Has("validate_only") {
				t.Errorf("/load sent with validate_only; Caddy ignores it, so the name would lie")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			b, _ := json.Marshal(body)
			f.loads = append(f.loads, string(b))
			if f.failRestore && len(f.loads) == 2 {
				http.Error(w, `{"error":"admin busy"}`, http.StatusInternalServerError)
				return
			}
			if _, bad := body["reject"]; bad {
				http.Error(w, `{"error":"loading new config: unknown field reject"}`, http.StatusBadRequest)
				return
			}
			f.live = string(b)
		default:
			http.NotFound(w, r)
		}
	})
}

const probeOriginal = `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"]}}}}}`

func newFakeAdmin(t *testing.T, f *fakeAdmin) *Client {
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return &Client{AdminURL: srv.URL, HTTP: srv.Client()}
}

// T-0965: ProbeLoad must put the original config back whether Caddy accepts
// or rejects the probe, so a check never leaves anything applied.
func TestProbeLoadAlwaysRestoresTheOriginalConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		probe   map[string]any
		wantErr string
	}{
		{"accepted", map[string]any{"apps": map[string]any{"http": map[string]any{"metrics": map[string]any{"per_host": true}}}}, ""},
		{"rejected", map[string]any{"reject": true}, "unknown field reject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeAdmin{live: probeOriginal}
			c := newFakeAdmin(t, f)
			err := c.ProbeLoad(setKeys(tc.probe))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("ProbeLoad: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ProbeLoad error = %v, want it to carry Caddy's %q", err, tc.wantErr)
			}
			if len(f.loads) != 2 {
				t.Fatalf("loads = %d (%v), want 2: the probe, then the restore", len(f.loads), f.loads)
			}
			if f.loads[1] != probeOriginal {
				t.Errorf("restore load = %s, want the original %s", f.loads[1], probeOriginal)
			}
			if f.live != probeOriginal {
				t.Errorf("live config after ProbeLoad = %s, want the original %s", f.live, probeOriginal)
			}
		})
	}
}

// A failed restore must be reported even when the probe itself was
// accepted: the server may still be running the probe config.
func TestProbeLoadReportsAFailedRestore(t *testing.T) {
	f := &fakeAdmin{live: probeOriginal, failRestore: true}
	c := newFakeAdmin(t, f)
	err := c.ProbeLoad(setKeys(map[string]any{"apps": map[string]any{}}))
	if err == nil || !strings.Contains(err.Error(), "restoring the previous config failed") {
		t.Fatalf("ProbeLoad error = %v, want a restore failure", err)
	}
}

// An empty Caddy (config null) is restored to an empty config, not left on
// the probe.
func TestProbeLoadRestoresAnEmptyConfig(t *testing.T) {
	f := &fakeAdmin{live: "null"}
	c := newFakeAdmin(t, f)
	if err := c.ProbeLoad(setKeys(map[string]any{"apps": map[string]any{"http": map[string]any{}}})); err != nil {
		t.Fatal(err)
	}
	if f.live != "{}" {
		t.Fatalf("live config after ProbeLoad = %s, want {}", f.live)
	}
}

// LoadConfig is the apply and says so: a plain /load.
func TestLoadConfigPostsPlainLoad(t *testing.T) {
	f := &fakeAdmin{live: probeOriginal}
	c := newFakeAdmin(t, f)
	if err := c.LoadConfig(map[string]any{"apps": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if len(f.loads) != 1 || f.live != `{"apps":{}}` {
		t.Fatalf("loads = %v live = %s", f.loads, f.live)
	}
}

// T-0965: the CrowdSec module check asks /adapt only. The old check loaded a
// caddyui_crowdsec_probe server into the live config, where it stayed.
func TestHasCrowdSecModuleUsesAdaptAndNeverLoadsConfig(t *testing.T) {
	var hits []string
	var bodies []string
	mk := func(adaptStatus int, body string) *Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, r.Method+" "+r.URL.Path)
			b := new(strings.Builder)
			buf := make([]byte, 4096)
			for {
				n, err := r.Body.Read(buf)
				b.Write(buf[:n])
				if err != nil {
					break
				}
			}
			bodies = append(bodies, b.String())
			w.WriteHeader(adaptStatus)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return &Client{AdminURL: srv.URL, HTTP: srv.Client()}
	}
	if present, known := mk(200, `{"result":{"apps":{"crowdsec":{}}}}`).HasCrowdSecModule(); !present || !known {
		t.Errorf("module present: got present=%v known=%v", present, known)
	}
	// What stock Caddy 2 answers (checked against caddy:2-alpine).
	if present, known := mk(400, `{"error":"Caddyfile:2: unrecognized global option: crowdsec"}`).HasCrowdSecModule(); present || !known {
		t.Errorf("module missing: got present=%v known=%v", present, known)
	}
	if present, known := mk(500, `{"error":"something unrelated"}`).HasCrowdSecModule(); present || known {
		t.Errorf("an unrelated failure must be 'unknown', never 'missing': present=%v known=%v", present, known)
	}
	for _, h := range hits {
		if h != "POST /adapt" {
			t.Errorf("the check made a %q request; it must only ever /adapt", h)
		}
	}
	for _, b := range bodies {
		if !strings.Contains(b, "crowdsec {") || !strings.Contains(b, "\t\tcrowdsec\n") {
			t.Errorf("probe Caddyfile must use both the crowdsec global option and the handler directive:\n%s", b)
		}
	}
}

// setKeys returns a ProbeLoad mutation that sets each key of keys.
func setKeys(keys map[string]any) func(map[string]any) {
	return func(cfg map[string]any) {
		for k, v := range keys {
			cfg[k] = v
		}
	}
}

// T-0966: the probe is built from the same read the restore uses, and the
// mutation gets a copy, not the original.
func TestProbeLoadMutatesACopyOfTheLiveConfig(t *testing.T) {
	f := &fakeAdmin{live: probeOriginal}
	c := newFakeAdmin(t, f)
	var seen map[string]any
	if err := c.ProbeLoad(func(cfg map[string]any) { seen = cfg; cfg["extra"] = true }); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen["extra"] != true {
		t.Fatalf("mutation did not run on the probe config: %v", seen)
	}
	if f.loads[1] != probeOriginal {
		t.Errorf("restore load = %s, want the untouched original %s", f.loads[1], probeOriginal)
	}
}

func TestProbeLoadRestoreErrorIsTyped(t *testing.T) {
	f := &fakeAdmin{live: probeOriginal, failRestore: true}
	c := newFakeAdmin(t, f)
	var re *RestoreError
	if err := c.ProbeLoad(nil); !errors.As(err, &re) {
		t.Fatalf("ProbeLoad error = %v, want a *RestoreError", err)
	}
}
