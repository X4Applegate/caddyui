// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// DeletePath must hit /config/<path> whether or not the caller already wrote
// the leading /config — real Caddy answers /config/config/... with HTTP 500.
func TestDeletePathNeverDoublesTheConfigPrefix(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := &Client{AdminURL: srv.URL, HTTP: srv.Client()}
	for _, in := range []string{
		"/apps/layer4",
		"/config/apps/http/servers/caddyui_http",
		"apps/crowdsec",
	} {
		if err := c.DeletePath(in); err != nil {
			t.Fatalf("DeletePath(%q): %v", in, err)
		}
	}
	want := []string{
		"DELETE /config/apps/layer4",
		"DELETE /config/apps/http/servers/caddyui_http",
		"DELETE /config/apps/crowdsec",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
}
