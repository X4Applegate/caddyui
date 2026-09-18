package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"strings"
	"sync"

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
}

func (s *Server) oidcConfig() oidcConfig {
	get := func(k string) string { return strings.TrimSpace(mustGetSetting(s.DB, k)) }
	label := get(settingOIDCButtonLabel)
	if label == "" {
		label = oidcDefaultButtonLabel
	}
	return oidcConfig{
		Enabled:      mustGetSetting(s.DB, settingOIDCEnabled) == "1",
		Issuer:       get(settingOIDCIssuer),
		ClientID:     get(settingOIDCClientID),
		ClientSecret: strings.TrimSpace(mustGetSetting(s.DB, settingOIDCClientSecret)),
		RedirectURL:  get(settingOIDCRedirectURL),
		AutoCreate:   mustGetSetting(s.DB, settingOIDCAutoCreate) == "1",
		ButtonLabel:  label,
	}
}

// ready reports whether SSO is enabled and has the minimum configuration to run.
func (c oidcConfig) ready() bool {
	return c.Enabled && c.Issuer != "" && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
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
		http.Redirect(w, r, "/login?error=sso_nonce", http.StatusSeeOther)
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
		return
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || !claims.EmailVerified {
		// An unverified (or missing) email must not be trusted to match or
		// create an account — it would allow impersonation on IdPs that let a
		// user set an arbitrary address.
		log.Printf("oidc: rejecting sign-in: email empty or unverified (%q verified=%v)", email, claims.EmailVerified)
		http.Redirect(w, r, "/login?error=sso_email", http.StatusSeeOther)
		return
	}

	u, err := models.GetUserByEmail(s.DB, email)
	if err != nil || u == nil {
		if !cfg.AutoCreate {
			log.Printf("oidc: no CaddyUI account for %s and auto-create is off", email)
			http.Redirect(w, r, "/login?error=sso_nouser", http.StatusSeeOther)
			return
		}
		name := strings.TrimSpace(claims.Name)
		if name == "" {
			name = email
		}
		// New SSO users get the read-only role and an unusable password (a
		// random non-bcrypt string), so they can't password-log-in. Promote
		// them under Users if they need more.
		if _, cerr := models.CreateUser(s.DB, email, oidcRandom(), name, models.RoleView); cerr != nil {
			log.Printf("oidc: provision %s: %v", email, cerr)
			http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
			return
		}
		if u, err = models.GetUserByEmail(s.DB, email); err != nil || u == nil {
			http.Redirect(w, r, "/login?error=sso", http.StatusSeeOther)
			return
		}
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
