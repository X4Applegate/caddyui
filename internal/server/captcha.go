package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Captcha providers. Stored in the settings table under the key
// settingCaptchaProvider. "off" means the captcha is disabled outright —
// the widget won't render and POST handlers skip verification. The value
// is case-insensitive on read; writes go through normalizeCaptchaProvider.
const (
	captchaProviderOff       = "off"
	captchaProviderTurnstile = "turnstile"
	captchaProviderRecaptcha = "recaptcha"
)

// Settings-table keys for captcha configuration. Turnstile's two keys
// predate v2.5.0 (shipped in v2.4.x) — we keep the names for back-compat
// so an upgrade doesn't wipe them. The new keys are for reCAPTCHA.
const (
	settingCaptchaProvider = "captcha_provider"

	// Turnstile keys live under their original names from v2.4.x.
	// (settingTurnstileSiteKey / settingTurnstileSecretKey are declared
	// in server.go — keeping one canonical declaration there.)

	// Google reCAPTCHA v3 keys. Site key goes in the page (public);
	// secret key never leaves the server.
	settingRecaptchaSiteKey   = "recaptcha_site_key"
	settingRecaptchaSecretKey = "recaptcha_secret_key"

	// reCAPTCHA v3 returns a score between 0.0 (bot) and 1.0 (human).
	// captchaDefaultMinScore is what we reject-below when the admin hasn't
	// tuned the threshold. Google recommends 0.5 as a starting point.
	settingRecaptchaMinScore = "recaptcha_min_score"
	captchaDefaultMinScore   = 0.5

	// Env-var kill switch. Set CADDYUI_CAPTCHA_DISABLE=1 to bypass the
	// captcha entirely (no verification, no widget render) without
	// touching the DB. Exists specifically for "Cloudflare outage +
	// I'm locked out of my own admin" scenarios — the user can restart
	// the container with this flag, log in, then unset it.
	envCaptchaDisable = "CADDYUI_CAPTCHA_DISABLE"
)

// captchaConfig is the snapshot of captcha settings resolved at request
// time. Built by loadCaptchaConfig and passed to handlers + templates as
// a single struct so nothing downstream has to poke at models.GetSetting.
type captchaConfig struct {
	// Provider is one of captchaProviderOff / captchaProviderTurnstile /
	// captchaProviderRecaptcha. If env CADDYUI_CAPTCHA_DISABLE=1 this is
	// forced to "off" even when the DB has a provider configured.
	Provider string

	// Site key is rendered into the page. Empty when Provider is "off"
	// or when the admin hasn't filled in the key for the active provider
	// yet (in which case Enabled() returns false and we skip the widget).
	SiteKey string

	// SecretKey is used server-side to call the provider's verify endpoint.
	// Never sent to the template.
	SecretKey string

	// MinScore is reCAPTCHA v3's rejection threshold. Ignored for
	// Turnstile (which returns a boolean). Defaults to captchaDefaultMinScore.
	MinScore float64
}

// Enabled returns true when both the provider and the keys are configured.
// Handlers use this to decide whether to verify; templates use it to
// decide whether to render the widget. A half-configured setup (provider
// set but keys blank) is treated as disabled rather than as a wall users
// can't get past.
func (c captchaConfig) Enabled() bool {
	if c.Provider == captchaProviderOff || c.Provider == "" {
		return false
	}
	return c.SiteKey != "" && c.SecretKey != ""
}

// loadCaptchaConfig reads the active captcha configuration from the DB,
// applies the env kill-switch, and normalises the provider name. Safe
// to call on every request — the settings table is small and backed
// by SQLite's page cache.
func loadCaptchaConfig(db *sql.DB) captchaConfig {
	// Env kill-switch short-circuits before any DB work. Any truthy value
	// ("1", "true", "yes", case-insensitive) disables the captcha.
	if captchaDisabledByEnv() {
		return captchaConfig{Provider: captchaProviderOff}
	}

	provider := normalizeCaptchaProvider(mustGetSetting(db, settingCaptchaProvider))

	cfg := captchaConfig{Provider: provider, MinScore: captchaDefaultMinScore}
	switch provider {
	case captchaProviderTurnstile:
		cfg.SiteKey = mustGetSetting(db, settingTurnstileSiteKey)
		cfg.SecretKey = mustGetSetting(db, settingTurnstileSecretKey)
	case captchaProviderRecaptcha:
		cfg.SiteKey = mustGetSetting(db, settingRecaptchaSiteKey)
		cfg.SecretKey = mustGetSetting(db, settingRecaptchaSecretKey)
		if raw := strings.TrimSpace(mustGetSetting(db, settingRecaptchaMinScore)); raw != "" {
			if f, err := strconv.ParseFloat(raw, 64); err == nil && f >= 0 && f <= 1 {
				cfg.MinScore = f
			}
		}
	}
	return cfg
}

// mustGetSetting is a thin wrapper over models.GetSetting that discards
// the error and returns "" on miss. Every caller in this file already
// wraps empties as "not configured", so surfacing the error would only
// add noise.
func mustGetSetting(db *sql.DB, key string) string {
	v, _ := models.GetSetting(db, key)
	return v
}

// normalizeCaptchaProvider coerces free-form input (from the settings
// form or a hand-edited DB) into one of the three canonical values.
// Unknown values collapse to "off" rather than being trusted — keeps
// /login from rendering a broken widget that would lock admins out.
func normalizeCaptchaProvider(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case captchaProviderTurnstile:
		return captchaProviderTurnstile
	case captchaProviderRecaptcha:
		return captchaProviderRecaptcha
	}
	return captchaProviderOff
}

// captchaDisabledByEnv reports whether the CADDYUI_CAPTCHA_DISABLE env var
// is set to a truthy value. Accepts 1/true/yes (case-insensitive) so
// docker-compose.yml can use any common form without surprising behaviour.
func captchaDisabledByEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(envCaptchaDisable)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// verifyCaptcha validates the captcha response that came back with the
// request. Dispatches to Turnstile's or reCAPTCHA's siteverify endpoint
// based on cfg.Provider. Returns (true, nil) on success, (false, err)
// on network/decode failure, (false, nil) when the provider said no.
//
// When cfg.Enabled() is false, this is a no-op that returns (true, nil)
// — handlers can call it unconditionally without first checking enabled.
func verifyCaptcha(cfg captchaConfig, r *http.Request) (bool, error) {
	if !cfg.Enabled() {
		return true, nil
	}

	// Remote IP goes to the provider as a hint. Prefer X-Forwarded-For's
	// first hop (we're behind Caddy, which always sets this). Fall back
	// to RemoteAddr when the header is absent — e.g. during local testing.
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
	}

	switch cfg.Provider {
	case captchaProviderTurnstile:
		token := r.FormValue("cf-turnstile-response")
		return verifyTurnstile(cfg.SecretKey, token, remoteIP)
	case captchaProviderRecaptcha:
		token := r.FormValue("g-recaptcha-response")
		return verifyRecaptcha(cfg.SecretKey, token, remoteIP, cfg.MinScore)
	}
	return true, nil
}

// verifyRecaptcha calls Google's reCAPTCHA v3 siteverify endpoint.
// Returns true when the challenge is valid AND the returned score is
// at or above minScore. v3 is invisible — no user interaction required —
// which is why we enforce a score threshold; v2 (checkbox) is not
// supported here to keep the UX consistent with Turnstile's managed mode.
//
// See https://developers.google.com/recaptcha/docs/verify for the
// response schema. The "action" field can be matched against what the
// client sent in grecaptcha.execute; we don't enforce it in v2.5.0 since
// we only call v3 from three forms and any human-valid token is fine.
func verifyRecaptcha(secretKey, token, remoteIP string, minScore float64) (bool, error) {
	if token == "" {
		// Empty token always fails. Don't bother hitting Google.
		return false, nil
	}
	// Short HTTP timeout so a Google outage doesn't wedge /login for
	// minutes. If Google is slow we'd rather surface a retry than block
	// a legit user behind a 30-second hang.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm("https://www.google.com/recaptcha/api/siteverify",
		url.Values{
			"secret":   {secretKey},
			"response": {token},
			"remoteip": {remoteIP},
		})
	if err != nil {
		return false, fmt.Errorf("recaptcha verify: %w", err)
	}
	defer resp.Body.Close()

	// v3 response schema: {"success":bool, "score":float, "action":str,
	//   "challenge_ts":ts, "hostname":str, "error-codes":[...]}
	var result struct {
		Success bool    `json:"success"`
		Score   float64 `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("recaptcha decode: %w", err)
	}
	if !result.Success {
		return false, nil
	}
	return result.Score >= minScore, nil
}

// captchaTemplateData returns the map the form templates merge into
// their render context to light up the widget. Keeps the field names
// consistent across login.html, totp_verify.html, and user_form.html
// so the shared widget partial can pick them up without per-page
// naming drift.
//
// Keys:
//
//	CaptchaProvider — "off" | "turnstile" | "recaptcha". Templates use
//	                  this in {{if eq .CaptchaProvider "turnstile"}}
//	CaptchaSiteKey  — public key to render into the widget's attribute
//	CaptchaEnabled  — convenience bool for {{if .CaptchaEnabled}} checks
func captchaTemplateData(cfg captchaConfig) map[string]any {
	return map[string]any{
		"CaptchaProvider": cfg.Provider,
		"CaptchaSiteKey":  cfg.SiteKey,
		"CaptchaEnabled":  cfg.Enabled(),
	}
}
