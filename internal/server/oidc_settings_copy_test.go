// SPDX-License-Identifier: Apache-2.0

package server

import (
	"html"
	"net/http"
	"strings"
	"testing"
)

// Issue #158: the callback requires a non-empty email and a boolean
// email_verified=true for every SSO sign-in, before it looks up or creates an
// account. The settings page used to mention the requirement only under
// "Auto-create accounts", which read as if existing users were exempt. The
// requirement has to be stated where SSO is configured, and the auto-create
// help must not imply it is specific to provisioning.
func TestOIDCSettingsStateTheEmailRequirementForEverySignIn(t *testing.T) {
	en := translations().Catalog("en")
	req := en["settings.security.oidc.email_requirement"]
	for _, want := range []string{"Every SSO sign-in", "existing", "email_verified", "true", "Entra ID"} {
		if !strings.Contains(req, want) {
			t.Errorf("settings.security.oidc.email_requirement = %q, missing %q", req, want)
		}
	}
	if strings.Contains(en["settings.security.oidc.auto_create_help"], "(verified email required)") {
		t.Error("auto-create help still presents the verified-email rule as a provisioning-only requirement")
	}

	e := newSecEnv(t)
	rec := e.do(t, "admin", http.MethodGet, "/settings/security", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("security settings: HTTP %d", rec.Code)
	}
	if req == "" || !strings.Contains(rec.Body.String(), html.EscapeString(req)) {
		t.Error("the security settings page does not show the verified-email requirement")
	}
}
