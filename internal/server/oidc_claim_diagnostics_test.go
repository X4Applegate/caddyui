// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// Issue #158: unit coverage for the helpers behind the callback's log lines.

func decodeFailureFor(t *testing.T, payload string) string {
	t.Helper()
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	err := json.Unmarshal([]byte(payload), &claims)
	if err == nil {
		t.Fatalf("payload %s decoded cleanly; the callback would not reject it", payload)
	}
	return describeOIDCClaimsDecodeFailure([]byte(payload), err)
}

func TestClaimsDecodeFailureNamesClaimAndTypeButNotValue(t *testing.T) {
	cases := []struct {
		payload, want string
	}{
		{`{"email":"a@b.c","email_verified":"SECRET-VALUE"}`, `claim "email_verified" is a JSON string, but CaddyUI requires a JSON boolean`},
		{`{"email":"a@b.c","email_verified":1}`, `claim "email_verified" is a JSON number`},
		{`{"email":["SECRET-VALUE"],"email_verified":true}`, `claim "email" is a JSON array, but CaddyUI requires a JSON string`},
		{`{"email":"a@b.c","email_verified":true,"name":{"given":"SECRET-VALUE"}}`, `claim "name" is a JSON object`},
	}
	for _, c := range cases {
		got := decodeFailureFor(t, c.payload)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s:\n got %q\nwant substring %q", c.payload, got, c.want)
		}
		if strings.Contains(got, "SECRET-VALUE") || strings.Contains(got, "a@b.c") {
			t.Errorf("%s: a claim value leaked into the diagnostic: %q", c.payload, got)
		}
	}
}

func TestClaimsDecodeFailureReportsEveryMalformedClaim(t *testing.T) {
	got := decodeFailureFor(t, `{"email":7,"email_verified":"true"}`)
	for _, want := range []string{`claim "email" is a JSON number`, `claim "email_verified" is a JSON string`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestEmailRejectionReasonSeparatesAbsentFromFalse(t *testing.T) {
	fields := func(s string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct {
		payload, email, want string
	}{
		{`{"email":"a@b.c"}`, "a@b.c", "the ID token has no email_verified claim"},
		{`{"email":"a@b.c","email_verified":false}`, "a@b.c", "email_verified is false"},
		{`{"email":"a@b.c","email_verified":null}`, "a@b.c", "email_verified is null"},
		{`{"email_verified":true}`, "", "the ID token has no email claim"},
		{`{"email":"  ","email_verified":true}`, "", "the email claim is empty"},
		{`{}`, "", "the ID token has no email claim; the ID token has no email_verified claim"},
	}
	for _, c := range cases {
		if got := oidcEmailRejectionReason(fields(c.payload), c.email); got != c.want {
			t.Errorf("%s: got %q, want %q", c.payload, got, c.want)
		}
	}
}
