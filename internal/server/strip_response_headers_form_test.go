// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// The host form used to show two "Strip response headers" inputs bound to two
// different columns — the response-side twin of issue #167. The duplicate input
// is gone and strip_resp_headers is canonical, but the legacy
// strip_response_headers POST value is still accepted for one release so an old
// bookmarked form or an API client posting the v2.9.168 name does not silently
// lose data.
func TestParseProxyHostFormConsolidatesStripResponseHeaders(t *testing.T) {
	cases := []struct {
		name   string
		form   url.Values
		want   string
		reason string
	}{
		{
			name: "canonical field alone",
			form: url.Values{"strip_resp_headers": {"X-Powered-By, Server"}},
			want: "X-Powered-By, Server",
		},
		{
			name:   "legacy field alone is still accepted",
			form:   url.Values{"strip_response_headers": {"X-Legacy-Only"}},
			want:   "X-Legacy-Only",
			reason: "an old bookmarked form must not silently drop the value",
		},
		{
			name: "both posted are merged, not duplicated",
			form: url.Values{
				"strip_resp_headers":     {"Server"},
				"strip_response_headers": {"X-Powered-By"},
			},
			want:   "Server, X-Powered-By",
			reason: "neither value may be discarded",
		},
		{
			name: "same name in both collapses",
			form: url.Values{
				"strip_resp_headers":     {"X-Powered-By"},
				"strip_response_headers": {"x-powered-by"},
			},
			want:   "X-Powered-By",
			reason: "HTTP header names are case-insensitive",
		},
		{
			name: "neither posted stays empty",
			form: url.Values{},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			for k, v := range tc.form {
				form[k] = v
			}
			// parseProxyHostForm needs a minimally valid host.
			form.Set("domains", "example.com")
			form.Set("forward_scheme", "http")
			form.Set("forward_host", "backend")
			form.Set("forward_port", "8080")

			req := httptestPostForm(t, form)
			ph, err := parseProxyHostForm(req)
			if err != nil {
				t.Fatalf("parseProxyHostForm: %v", err)
			}
			if ph.StripRespHeaders != tc.want {
				msg := ""
				if tc.reason != "" {
					msg = " (" + tc.reason + ")"
				}
				t.Errorf("StripRespHeaders = %q, want %q%s",
					ph.StripRespHeaders, tc.want, msg)
			}
			// The legacy column must never be written again.
			if ph.StripResponseHeaders != "" {
				t.Errorf("legacy StripResponseHeaders = %q, want empty",
					ph.StripResponseHeaders)
			}
		})
	}
}

func httptestPostForm(t *testing.T, form url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/hosts", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// The global "Globally stripped response headers" setting applied itself to
// every host, and it used to read the legacy column. After the consolidation it
// must apply to the canonical field, prepending the global names and
// deduplicating against the per-host list.
func TestGlobalStripResponseHeadersAppliesToCanonicalField(t *testing.T) {
	cases := []struct {
		name     string
		global   string
		perHost  string
		want     string
		whyNotes string
	}{
		{
			name:    "per-host empty takes the global list",
			global:  "Server",
			perHost: "",
			want:    "Server",
		},
		{
			name:     "global applied ahead of per-host",
			global:   "Server",
			perHost:  "X-Powered-By",
			want:     "Server, X-Powered-By",
			whyNotes: "both must be stripped",
		},
		{
			name:     "overlap is deduplicated",
			global:   "Server, X-Powered-By",
			perHost:  "X-Powered-By",
			want:     "Server, X-Powered-By",
			whyNotes: "a header named in both used to be emitted twice",
		},
		{
			name:     "overlap dedupe is case-insensitive",
			global:   "X-Powered-By",
			perHost:  "x-powered-by",
			want:     "X-Powered-By",
			whyNotes: "HTTP header names are case-insensitive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := models.MergeHeaderNameLists(tc.global, tc.perHost)
			if got != tc.want {
				msg := ""
				if tc.whyNotes != "" {
					msg = " (" + tc.whyNotes + ")"
				}
				t.Errorf("merge(global=%q, perHost=%q) = %q, want %q%s",
					tc.global, tc.perHost, got, tc.want, msg)
			}
		})
	}
}
