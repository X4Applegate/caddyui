package server

import (
	"os"
	"strings"
)

// Content-Security-Policy for CaddyUI's own UI.
//
// v2.30.0. The securityHeaders middleware in server.go has set X-Frame-Options,
// X-Content-Type-Options and Referrer-Policy since v2.10.3; CSP is the piece
// that was missing. The policy is defined here rather than inline so the
// allowlist and the reasoning for each entry stay together.
//
// HSTS remains deliberately unset — see the note on securityHeaders.

// defaultCSP allows exactly the third-party origins the templates actually
// load, and nothing else.
//
//   - cdn.tailwindcss.com   — the Tailwind runtime on authenticated pages
//     ('unsafe-eval' is required: the Play CDN compiles utility classes in the
//     browser). Unauthenticated pages use the committed web/static/auth.css
//     instead and don't touch it.
//   - challenges.cloudflare.com — Turnstile (script + the widget's iframe)
//   - www.google.com / www.gstatic.com — reCAPTCHA v3 (script, subresources,
//     and its iframe)
//
// 'unsafe-inline' in script-src is unavoidable today: the templates carry ~75
// inline event handlers plus many inline <script> blocks. Removing it means
// migrating those to addEventListener first — worth doing, but a much larger
// change than adding the header.
//
// The directives that carry real weight even with 'unsafe-inline' present are
// form-action (a script cannot post the admin's form to another origin),
// frame-ancestors (clickjacking), connect-src (no exfiltration via fetch), and
// object-src.
const defaultCSP = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://challenges.cloudflare.com https://www.google.com https://www.gstatic.com; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: https:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"frame-src https://challenges.cloudflare.com https://www.google.com; " +
	"frame-ancestors 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"object-src 'none'"

// cspPolicy resolves the policy to send.
//
// CADDYUI_CSP provides an escape hatch without a redeploy:
//
//	unset      — defaultCSP
//	"off"      — no CSP header at all
//	anything   — used verbatim
//
// The hatch exists because a CSP that is subtly wrong breaks the UI for
// everyone at once, and a self-hosted operator needs to be able to undo that
// without waiting for a patch release.
func cspPolicy() string {
	v, ok := os.LookupEnv("CADDYUI_CSP")
	if !ok {
		return defaultCSP
	}
	if strings.EqualFold(strings.TrimSpace(v), "off") {
		return ""
	}
	return v
}
