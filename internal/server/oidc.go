// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Optional OIDC / SSO login (issue #106). CaddyUI can accept sign-ins from an
// external identity provider (Authelia, Authentik, Keycloak, Google, …) in
// addition to local password + TOTP. ID-token verification (JWKS, signature,
// iss/aud/exp, nonce) is delegated to the vetted go-oidc library rather than
// hand-rolled. Local login always remains available.
const (
	settingOIDCEnabled      = "oidc_enabled"
	settingOIDCIssuer       = "oidc_issuer"
	settingOIDCClientID     = "oidc_client_id"
	settingOIDCClientSecret = "oidc_client_secret"
	settingOIDCRedirectURL  = "oidc_redirect_url"
	settingOIDCAutoCreate   = "oidc_auto_create"
	settingOIDCButtonLabel  = "oidc_button_label"

	// v2.65.0 (issue #139): control what an auto-created SSO account may do.
	// Auto-created users were always given the read-only role with no way to
	// change that short of promoting each one by hand under Users.
	//
	// settingOIDCDefaultRole is the role for a new account when no group
	// mapping matches. Empty means "view", which is what every release
	// before this one did.
	settingOIDCDefaultRole = "oidc_default_role"
	// settingOIDCGroupsClaim names the ID-token claim holding the user's
	// groups ("groups", "roles", "wiki_groups", …). Empty disables mapping.
	settingOIDCGroupsClaim = "oidc_groups_claim"
	// settingOIDCRoleMappings maps those group values to CaddyUI roles, one
	// `group|role` rule per line. First match in file order wins.
	settingOIDCRoleMappings = "oidc_role_mappings"

	// settingOIDCAllowedDomains restricts which verified email domains may
	// sign in through SSO, one domain per line or comma-separated. Empty
	// means every identity the provider authenticates is accepted.
	//
	// v2.67.0: this matters most with a *public* provider. With a private
	// IdP, "anyone my IdP authenticates" is your own staff; with Google or
	// similar it is every account in the world, and with auto-create on that
	// is an account on your CaddyUI for anyone who finds the login page.
	settingOIDCAllowedDomains = "oidc_allowed_domains"

	oidcStateCookie        = "caddyui_oidc_state"
	oidcNonceCookie        = "caddyui_oidc_nonce"
	oidcDefaultButtonLabel = "Sign in with SSO"
)

type oidcConfig struct {
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AutoCreate   bool
	ButtonLabel  string
	// v2.65.0 (issue #139): role assignment for auto-created accounts.
	DefaultRole  string
	GroupsClaim  string
	RoleMappings []oidcRoleMapping
	// AllowedDomains is the set of verified email domains permitted to sign
	// in. Empty means no restriction. v2.67.0.
	AllowedDomains []string
}

// parseOIDCAllowedDomains reads the domain list. Entries are lowercased and a
// leading "@" is tolerated, because writing "@example.com" is the obvious
// mistake to make. Blank lines and `#` comments are skipped.
func parseOIDCAllowedDomains(raw string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	}) {
		d := strings.ToLower(strings.TrimSpace(f))
		d = strings.TrimPrefix(d, "@")
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		out = append(out, d)
	}
	return out
}

// emailDomainAllowed reports whether this verified address may sign in.
//
// The list gates SSO sign-in *entirely*, not just account creation. An
// administrator who writes "only example.com" means it, and the alternative —
// gating creation alone — would leave an existing outside account able to sign
// in through a provider the admin believes is restricted. Local password
// login is unaffected, so nobody is locked out of the product by this.
//
// Matching is on the exact domain after "@". Subdomains are not implied:
// listing example.com does not admit user@mail.example.com, which has to be
// listed separately.
func (c oidcConfig) emailDomainAllowed(email string) bool {
	if len(c.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range c.AllowedDomains {
		if domain == d {
			return true
		}
	}
	return false
}

// oidcRoleMapping grants a CaddyUI role to members of one IdP group.
type oidcRoleMapping struct {
	Group string
	Role  string
}

// validOIDCRole reports whether role is one CaddyUI recognises. Anything else
// is ignored rather than stored, so a typo in the mapping list cannot hand out
// an unintended level of access — or silently create an account with a role
// no permission check understands.
func validOIDCRole(role string) bool {
	switch role {
	case models.RoleAdmin, models.RoleUser, models.RoleView:
		return true
	}
	return false
}

// parseOIDCRoleMappings reads `group|role` rules, one per line. Blank lines
// and `#` comments are skipped, as is any rule naming a role CaddyUI does not
// have. Order is preserved: the first rule matching any of the user's groups
// decides, so the most privileged mappings belong at the top.
func parseOIDCRoleMappings(raw string) []oidcRoleMapping {
	var out []oidcRoleMapping
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		group := strings.TrimSpace(parts[0])
		role := strings.ToLower(strings.TrimSpace(parts[1]))
		if group == "" || !validOIDCRole(role) {
			continue
		}
		out = append(out, oidcRoleMapping{Group: group, Role: role})
	}
	return out
}

// invalidOIDCRoleMappingLines describes every line of a group→role list that
// parseOIDCRoleMappings would discard, so the operator is told at save time
// rather than finding out when someone signs in on the wrong role.
// v2.65.0 (issue #139).
func invalidOIDCRoleMappingLines(raw string) []string {
	var bad []string
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n := i + 1
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			bad = append(bad, fmt.Sprintf("line %d (%q) has no `|` separating the group from the role", n, line))
			continue
		}
		group := strings.TrimSpace(parts[0])
		role := strings.ToLower(strings.TrimSpace(parts[1]))
		switch {
		case group == "":
			bad = append(bad, fmt.Sprintf("line %d (%q) has no group name", n, line))
		case role == "":
			bad = append(bad, fmt.Sprintf("line %d (%q) has no role", n, line))
		case !validOIDCRole(role):
			bad = append(bad, fmt.Sprintf("line %d names the role %q, which does not exist", n, role))
		}
	}
	return bad
}

// roleForGroups returns the role to give a user with these IdP groups, and
// whether a mapping actually matched. Group comparison is case-insensitive;
// IdPs are inconsistent about casing and a near-miss would silently downgrade
// someone to the default role.
func (c oidcConfig) roleForGroups(groups []string) (string, bool) {
	for _, m := range c.RoleMappings {
		for _, g := range groups {
			if strings.EqualFold(strings.TrimSpace(g), m.Group) {
				return m.Role, true
			}
		}
	}
	return "", false
}

// defaultRole is the role for a new account when no mapping matched.
func (c oidcConfig) defaultRole() string {
	if validOIDCRole(c.DefaultRole) {
		return c.DefaultRole
	}
	return models.RoleView
}

func (s *Server) oidcConfig() oidcConfig {
	get := func(k string) string { return strings.TrimSpace(mustGetSetting(s.DB, k)) }
	label := get(settingOIDCButtonLabel)
	if label == "" {
		label = oidcDefaultButtonLabel
	}
	return oidcConfig{
		Enabled:        mustGetSetting(s.DB, settingOIDCEnabled) == "1",
		Issuer:         get(settingOIDCIssuer),
		ClientID:       get(settingOIDCClientID),
		ClientSecret:   strings.TrimSpace(mustGetSetting(s.DB, settingOIDCClientSecret)),
		RedirectURL:    get(settingOIDCRedirectURL),
		AutoCreate:     mustGetSetting(s.DB, settingOIDCAutoCreate) == "1",
		ButtonLabel:    label,
		DefaultRole:    strings.ToLower(get(settingOIDCDefaultRole)),
		GroupsClaim:    get(settingOIDCGroupsClaim),
		RoleMappings:   parseOIDCRoleMappings(mustGetSetting(s.DB, settingOIDCRoleMappings)),
		AllowedDomains: parseOIDCAllowedDomains(mustGetSetting(s.DB, settingOIDCAllowedDomains)),
	}
}

// ready reports whether SSO is enabled and has the minimum configuration to run.
func (c oidcConfig) ready() bool {
	return c.Enabled && c.Issuer != "" && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

// oidcStringValues normalises a claim value into a list of strings.
//
// v2.65.0 (issue #139): IdPs disagree about how to express group membership.
// Most send a JSON array of strings, some send a single string, and a few
// send a space- or comma-separated string in one field. Anything else — an
// array of objects, a number — yields no groups rather than an error, so an
// unexpected claim shape simply means "no mapping matched" and the user still
// signs in on the default role.
func oidcStringValues(v any) []string {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	case []string:
		return t
	case string:
		var out []string
		for _, s := range strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' }) {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// oidcIdentityClaimTypes lists the ID-token claims the callback decodes into
// typed fields, with the JSON type each must have. A claim of any other type
// fails the decode and so the sign-in.
//
// Issue #158: that failure used to redirect to the generic "Single sign-on
// failed" page with nothing in the log, so an administrator could not tell a
// malformed claim (an IdP emitting email_verified as the string "true", say)
// from any other problem. The type rules themselves are unchanged and stay
// strict: a string "true" is still refused, it is now just named in the log.
var oidcIdentityClaimTypes = []struct{ name, want string }{
	{"email", "string"},
	{"email_verified", "boolean"},
	{"name", "string"},
}

// oidcJSONType names the JSON type of one raw claim value without looking at
// more of it than the first byte.
func oidcJSONType(raw json.RawMessage) string {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 {
		return "empty value"
	}
	switch b[0] {
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	case '{':
		return "object"
	case '[':
		return "array"
	}
	return "number"
}

// describeOIDCClaimsDecodeFailure explains, for the server log, why the ID
// token's claims could not be decoded. It names the offending claim and the
// JSON type it arrived as, and never includes a claim value or any part of
// the token: the log is read by more people than the token was issued to.
func describeOIDCClaimsDecodeFailure(payload []byte, err error) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil {
		return "the claims are not a JSON object"
	}
	var problems []string
	for _, c := range oidcIdentityClaimTypes {
		raw, ok := fields[c.name]
		if !ok {
			continue
		}
		// null decodes as the zero value, so it is never the cause here.
		if got := oidcJSONType(raw); got != c.want && got != "null" {
			p := fmt.Sprintf("claim %q is a JSON %s, but CaddyUI requires a JSON %s", c.name, got, c.want)
			if c.want == "boolean" {
				p += " (a string such as \"true\" is not accepted; the provider must send true or false unquoted)"
			}
			problems = append(problems, p)
		}
	}
	if len(problems) > 0 {
		return strings.Join(problems, "; ")
	}
	// Not one of the claims above. The decoder's type error carries the field
	// name and the Go type; its message can carry a numeric literal, so build
	// the line from the fields rather than printing it.
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) && te.Field != "" {
		return fmt.Sprintf("claim %q has an unexpected JSON type (expected %s)", te.Field, te.Type)
	}
	return fmt.Sprintf("decoder error of type %T", err)
}

// oidcEmailRejectionReason says which half of the email requirement an ID
// token failed: whether the claims were absent or present with the wrong
// value. fields is the token's raw claim set; email is the trimmed address.
// Issue #158: a provider that simply never sends email_verified (Microsoft
// Entra ID, for one) used to log the same line as one that sent false.
func oidcEmailRejectionReason(fields map[string]json.RawMessage, email string) string {
	var reasons []string
	if _, ok := fields["email"]; !ok {
		reasons = append(reasons, "the ID token has no email claim")
	} else if email == "" {
		reasons = append(reasons, "the email claim is empty")
	}
	if raw, ok := fields["email_verified"]; !ok {
		reasons = append(reasons, "the ID token has no email_verified claim")
	} else if oidcJSONType(raw) == "null" {
		reasons = append(reasons, "email_verified is null")
	} else {
		var v bool
		if json.Unmarshal(raw, &v) == nil && !v {
			reasons = append(reasons, "email_verified is false")
		}
	}
	return strings.Join(reasons, "; ")
}

// oidcProviderCache memoises the discovery document per issuer so each login
// doesn't re-fetch /.well-known/openid-configuration.
var oidcProviderCache sync.Map // issuer -> *oidc.Provider

func oidcProviderFor(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if v, ok := oidcProviderCache.Load(issuer); ok {
		return v.(*oidc.Provider), nil
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	oidcProviderCache.Store(issuer, p)
	return p, nil
}

func (s *Server) oidcClients(ctx context.Context, cfg oidcConfig) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	provider, err := oidcProviderFor(ctx, cfg.Issuer)
	if err != nil {
		return nil, nil, err
	}
	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	return oauth2Cfg, verifier, nil
}

// ssoProviderLabel turns an issuer URL into something short enough for a
// badge: https://accounts.google.com -> "Google", https://sso.example.com ->
// "Example". The full issuer is shown alongside it wherever this appears, so
// a wrong guess is never the only thing on screen. v2.68.0.
func ssoProviderLabel(issuer string) string {
	u, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil || u.Host == "" {
		return "SSO"
	}
	host := strings.ToLower(u.Hostname())
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return "SSO"
	}
	// The registrable label, i.e. the one before the public suffix. Good
	// enough for a badge on the common cases; co.uk and friends just yield
	// the next label along, which is still recognisable.
	name := parts[len(parts)-2]
	if name == "" {
		return "SSO"
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func oidcRandom() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func oidcSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setOIDCFlowCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: 600,
		HttpOnly: true, Secure: oidcSecure(r), SameSite: http.SameSiteLaxMode,
	})
}

func clearOIDCFlowCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: oidcSecure(r), SameSite: http.SameSiteLaxMode,
	})
}

// getOIDCLogin starts the auth-code flow: mint state + nonce, stash them in
// short-lived cookies, and redirect to the provider.
func (s *Server) getOIDCLogin(w http.ResponseWriter, r *http.Request) {
	cfg := s.oidcConfig()
	if !cfg.ready() {
		log.Printf("oidc: sign-in requested but SSO is disabled or not fully configured")
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	oauth2Cfg, _, err := s.oidcClients(r.Context(), cfg)
	if err != nil {
		log.Printf("oidc: provider init: %v", err)
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	state, nonce := oidcRandom(), oidcRandom()
	setOIDCFlowCookie(w, r, oidcStateCookie, state)
	setOIDCFlowCookie(w, r, oidcNonceCookie, nonce)
	http.Redirect(w, r, oauth2Cfg.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusSeeOther)
}

// getOIDCCallback completes the flow: verify state, exchange the code, verify
// the ID token + nonce, then map the email to a CaddyUI user and sign in.
func (s *Server) getOIDCCallback(w http.ResponseWriter, r *http.Request) {
	cfg := s.oidcConfig()
	if !cfg.ready() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// One-time flow cookies — clear them regardless of outcome.
	stateCookie, _ := r.Cookie(oidcStateCookie)
	nonceCookie, _ := r.Cookie(oidcNonceCookie)
	clearOIDCFlowCookie(w, r, oidcStateCookie)
	clearOIDCFlowCookie(w, r, oidcNonceCookie)

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		log.Printf("oidc: provider returned error: %s", errParam)
		http.Redirect(w, r, "/login?error=sso_denied", http.StatusSeeOther)
		return
	}
	if stateCookie == nil || stateCookie.Value == "" || r.URL.Query().Get("state") != stateCookie.Value {
		// Neither value is logged: the state is a CSRF token for this flow.
		log.Printf("oidc: rejecting callback: state missing or does not match the flow cookie (cookie present=%v)", stateCookie != nil && stateCookie.Value != "")
		http.Redirect(w, r, "/login?error=sso_state", http.StatusSeeOther)
		return
	}

	ctx := r.Context()
	oauth2Cfg, verifier, err := s.oidcClients(ctx, cfg)
	if err != nil {
		log.Printf("oidc: provider init: %v", err)
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	token, err := oauth2Cfg.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("oidc: token exchange: %v", err)
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		log.Printf("oidc: token response from the provider carried no id_token")
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("oidc: id token verify: %v", err)
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	if nonceCookie == nil || nonceCookie.Value == "" || idToken.Nonce != nonceCookie.Value {
		log.Printf("oidc: rejecting sign-in: ID token nonce does not match the flow cookie (cookie present=%v)", nonceCookie != nil && nonceCookie.Value != "")
		http.Redirect(w, r, "/login?error=sso_nonce", http.StatusSeeOther)
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		// Issue #158: say which claim was malformed. The decision is
		// unchanged — a claim of the wrong JSON type still fails sign-in.
		var payload json.RawMessage
		_ = idToken.Claims(&payload)
		log.Printf("oidc: rejecting sign-in: ID token claims could not be decoded: %s", describeOIDCClaimsDecodeFailure(payload, err))
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	// v2.65.0 (issue #139): the groups claim is read separately and
	// defensively — its name is operator-configured and its shape varies by
	// IdP, so it must not be able to fail the whole sign-in.
	var groups []string
	if cfg.GroupsClaim != "" {
		var all map[string]any
		if err := idToken.Claims(&all); err == nil {
			groups = oidcStringValues(all[cfg.GroupsClaim])
		}
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || !claims.EmailVerified {
		// An unverified (or missing) email must not be trusted to match or
		// create an account — it would allow impersonation on IdPs that let a
		// user set an arbitrary address.
		var fields map[string]json.RawMessage
		_ = idToken.Claims(&fields)
		log.Printf("oidc: rejecting sign-in: email empty or unverified (%q verified=%v): %s; every SSO sign-in, including existing accounts, needs a non-empty email and email_verified=true",
			email, claims.EmailVerified, oidcEmailRejectionReason(fields, email))
		http.Redirect(w, r, "/login?error=sso_email", http.StatusSeeOther)
		return
	}
	// v2.67.0: the allowed-domain policy, checked before the account lookup
	// so it governs existing users as well as auto-created ones. Gating only
	// creation would let an account from outside the listed domains keep
	// signing in through a provider the administrator believes is restricted.
	if !cfg.emailDomainAllowed(email) {
		log.Printf("oidc: rejecting sign-in for %s: domain not in the allowed list %v", email, cfg.AllowedDomains)
		http.Redirect(w, r, "/login?error=sso_domain", http.StatusSeeOther)
		return
	}

	u, err := models.GetUserByEmail(s.DB, email)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// A real DB failure must not be mistaken for "no such user" (which
		// would wrongly deny — or, with auto-create on, try to provision).
		log.Printf("oidc: lookup %s: %v", email, err)
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	if u == nil {
		if !cfg.AutoCreate {
			log.Printf("oidc: no CaddyUI account for %s and auto-create is off", email)
			http.Redirect(w, r, "/login?error=sso_nouser", http.StatusSeeOther)
			return
		}
		name := strings.TrimSpace(claims.Name)
		if name == "" {
			name = email
		}
		// v2.65.0 (issue #139): the role comes from a group mapping when one
		// matches, otherwise the configured default (still "view" unless an
		// admin changed it). The password is an unusable random non-bcrypt
		// string, so the account cannot be used to password-log-in.
		role := cfg.defaultRole()
		if mapped, ok := cfg.roleForGroups(groups); ok {
			role = mapped
		}
		log.Printf("oidc: creating account for %s with role %q (groups=%v)", email, role, groups)
		if _, cerr := models.CreateUser(s.DB, email, oidcRandom(), name, role); cerr != nil {
			log.Printf("oidc: provision %s: %v", email, cerr)
			http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
			return
		}
		if u, err = models.GetUserByEmail(s.DB, email); err != nil || u == nil {
			log.Printf("oidc: re-reading newly provisioned account %q: %v", email, err)
			http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
			return
		}
	}

	// v2.68.0: record that the provider asserted this identity, and which
	// provider it was, so the Users page can show how each account signs in.
	// Written here rather than after the session is issued because this is
	// the point the identity provider has authenticated them — a local
	// second factor may still follow, and that is a separate gate.
	if err := models.RecordSSOLogin(s.DB, u.ID, cfg.Issuer); err != nil {
		// Never fail a sign-in over bookkeeping.
		log.Printf("oidc: recording SSO login for %s: %v", email, err)
	}

	// Honour a user's local TOTP as a second factor even over SSO — otherwise
	// enabling SSO would silently downgrade every TOTP-protected account. Route
	// through the same pending-TOTP challenge that local login uses.
	if u.TOTPEnabled && u.TOTPSecret != "" {
		tok := oidcRandom()
		s.pendingTOTP.Store(tok, u.ID)
		go func() {
			time.Sleep(5 * time.Minute)
			s.pendingTOTP.Delete(tok)
		}()
		http.Redirect(w, r, "/login/totp?t="+tok, http.StatusSeeOther)
		return
	}

	tok, exp, err := auth.CreateSessionWithTTL(s.DB, u.ID, s.sessionTTL())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, r, tok, exp)
	_ = models.LogActivity(s.DB, 0, u.Email, "login_success_sso", "ip:"+clientIPFromRequest(r), r.UserAgent(), true)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
