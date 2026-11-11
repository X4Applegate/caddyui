// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// issue #167: the host form used to show two "Strip request headers" inputs
// bound to two different columns. The duplicate input is gone and
// strip_req_headers is canonical, but the legacy strip_request_headers POST
// value is still accepted for one release so an old bookmarked form or an API
// client posting the v2.9.250 name does not silently lose data.
func TestParseProxyHostFormConsolidatesStripRequestHeaders(t *testing.T) {
	cases := []struct {
		name   string
		form   url.Values
		want   string
		reason string
	}{
		{
			name: "canonical field alone",
			form: url.Values{"strip_req_headers": {"X-Internal-Token, Authorization"}},
			want: "X-Internal-Token, Authorization",
		},
		{
			name:   "legacy field alone is still accepted",
			form:   url.Values{"strip_request_headers": {"X-Legacy-Only"}},
			want:   "X-Legacy-Only",
			reason: "an old bookmarked form must not silently drop the value",
		},
		{
			name: "both posted are merged, not duplicated",
			form: url.Values{
				"strip_req_headers":     {"X-One"},
				"strip_request_headers": {"X-Two"},
			},
			want: "X-One, X-Two",
		},
		{
			name: "duplicate across both collapses case-insensitively",
			form: url.Values{
				"strip_req_headers":     {"Authorization"},
				"strip_request_headers": {"authorization"},
			},
			want: "Authorization",
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
			form.Set("forward_port", "8080")
			form.Set("domains", "app.example.com")
			form.Set("forward_host", "backend")

			req, err := http.NewRequest(http.MethodPost, "/hosts", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			ph, err := parseProxyHostForm(req)
			if err != nil {
				t.Fatalf("parseProxyHostForm: %v", err)
			}
			if ph.StripReqHeaders != tc.want {
				msg := ""
				if tc.reason != "" {
					msg = " (" + tc.reason + ")"
				}
				t.Errorf("StripReqHeaders = %q, want %q%s", ph.StripReqHeaders, tc.want, msg)
			}
			// The legacy column must never be written again, so the merged
			// value cannot be re-split into a second strip directive.
			if ph.StripRequestHeaders != "" {
				t.Errorf("StripRequestHeaders = %q, want empty — the legacy column is no longer written",
					ph.StripRequestHeaders)
			}
		})
	}
}
