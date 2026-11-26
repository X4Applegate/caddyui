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

// rejectionReasonFor decodes payload exactly as the callback does and returns
// the reason it would log, failing if the payload would not be rejected.
func rejectionReasonFor(t *testing.T, payload string) string {
	t.Helper()
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		t.Fatalf("%s: does not decode, so it never reaches the email check: %v", payload, err)
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email != "" && claims.EmailVerified {
		t.Fatalf("%s: would be accepted", payload)
	}
	return oidcEmailRejectionReason([]byte(payload), email, claims.EmailVerified)
}

func TestEmailRejectionReasonSeparatesAbsentFromFalse(t *testing.T) {
	cases := []struct{ payload, want string }{
		{`{"email":"a@b.c"}`, "the ID token has no email_verified claim"},
		{`{"email":"a@b.c","email_verified":false}`, "email_verified is false"},
		{`{"email":"a@b.c","email_verified":null}`, "email_verified is null"},
		{`{"email_verified":true}`, "the ID token has no email claim"},
		{`{"email":null,"email_verified":true}`, "the email claim is null"},
		{`{"email":"  ","email_verified":true}`, "the email claim is empty"},
		{`{}`, "the ID token has no email claim; the ID token has no email_verified claim"},
	}
	for _, c := range cases {
		if got := rejectionReasonFor(t, c.payload); got != c.want {
			t.Errorf("%s: got %q, want %q", c.payload, got, c.want)
		}
	}
}

// The decision is made by encoding/json, which matches keys case-insensitively
// and lets the last duplicate win. The logged reason must follow the same
// rules, or it contradicts the decision it explains (review finding on #158).
func TestEmailRejectionReasonFollowsTheDecodersKeyMatching(t *testing.T) {
	cases := []struct{ payload, want string }{
		// Last duplicate wins: decoded as false, so it is false — not "".
		{`{"email":"a@x.test","email_verified":true,"Email_Verified":false}`, "email_verified is false"},
		// "EMAIL" is the email claim to the decoder, so it is not "absent".
		{`{"EMAIL":"a@x.test","email_verified":false}`, "email_verified is false"},
		{`{"Email":"a@x.test"}`, "the ID token has no email_verified claim"},
		// A null after a value leaves the decoded value alone.
		{`{"email":"a@x.test","email_verified":false,"EMAIL_VERIFIED":null}`, "email_verified is false"},
	}
	for _, c := range cases {
		if got := rejectionReasonFor(t, c.payload); got != c.want {
			t.Errorf("%s: got %q, want %q", c.payload, got, c.want)
		}
	}
}

func TestEmailRejectionReasonIsNeverEmpty(t *testing.T) {
	// Not reachable through the callback (it only asks when a check failed),
	// but a blank reason must never be logged whatever the caller passes.
	if got := oidcEmailRejectionReason([]byte(`{"email":"a@b.c","email_verified":true}`), "a@b.c", true); got == "" {
		t.Error("empty rejection reason")
	}
}

func TestClaimsDecodeFailureNamesCaseVariantClaims(t *testing.T) {
	got := decodeFailureFor(t, `{"email":"a@b.c","EMAIL_VERIFIED":"true"}`)
	// The decoder reports the key as the token spelled it; that names the
	// claim, which is all this needs. The value must still stay out.
	if !strings.Contains(strings.ToLower(got), `"email_verified"`) || strings.Contains(got, "a@b.c") || strings.Contains(got, `"true"`) {
		t.Errorf("case-variant key not diagnosed by name: %q", got)
	}
}
