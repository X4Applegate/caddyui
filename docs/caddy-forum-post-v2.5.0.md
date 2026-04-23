# CaddyUI v2.5.0 — switchable CAPTCHA, timezone picker, branded error pages

Hey everyone 👋

Small update from the last time I posted — two releases shipped today that I thought the folks here might care about, since they're all Caddy-adjacent features and a few of you asked for them directly.

For context: **CaddyUI** is a self-hosted web UI that drives Caddy through its admin API. It stores everything in SQLite, pushes JSON config to Caddy on save, and covers proxy hosts, redirects, certs, advanced/raw routes, multi-server, multi-user, TOTP, snapshots, and paste-a-Caddyfile import. If you've seen Nginx Proxy Manager, the surface area is similar, but it speaks Caddy natively instead of translating to nginx.

---

## What's new in v2.5.0

### Switchable CAPTCHA protection

You can now pick one of three modes from **Settings → CAPTCHA protection**:

- **Off** (default on fresh installs)
- **Cloudflare Turnstile** (managed, free, privacy-friendly)
- **Google reCAPTCHA v3** (score-based, invisible)

…and it applies to three forms: `/login`, `/login/totp`, and `/users/new` (admin creating a new account).

**Why two providers?** A while back someone in the community had a Cloudflare outage that briefly made Turnstile unreachable, and they got stuck on their own login page. v2.5.0 ships a reCAPTCHA v3 fallback **plus** an env-var kill-switch:

```yaml
environment:
  CADDYUI_CAPTCHA_DISABLE: "1"
```

Set that, restart the container, and the widget stops rendering and the server stops verifying. Pull it back out once you've logged in. Intended specifically for "I'm locked out of my own admin" recovery.

Existing Turnstile keys from v2.4.x upgrade in place — the old settings keys are preserved, so if you had Turnstile configured, flip the provider to Turnstile and everything Just Works. Inactive-provider keys also stay in the DB across switches, so you can toggle between Turnstile and reCAPTCHA without re-typing credentials.

Small implementation details that might matter to you:

- TOTP captcha failure does **not** consume the pending-TOTP token (5-min auto-expire still caps abuse — wrong captcha ≠ burned 2FA slot).
- reCAPTCHA v3 uses a submit-hook: first submit fetches a token via `grecaptcha.execute`, populates a hidden input, then re-submits. If `api.js` fails to load (ad-blocker, outage), the fallback path just submits anyway so the server returns a clean "Security check failed" error instead of a stuck form.
- Verify-endpoint HTTP client has a 10s timeout — a slow siteverify can't wedge `/login` for 30+ seconds.

---

## Also bundled in v2.4.12 (shipped earlier today)

### Timezone picker

`Settings → Timezone` now has an IANA zone dropdown (`America/New_York`, `Europe/London`, etc.) with an "Other…" free-text fallback. Every DB-stored timestamp in the UI flows through it: cert expiry, activity log, snapshots, "last contact", "last sync". Resolution priority is:

1. DB value (what you picked)
2. `TZ` environment variable (Go's `time.Local` reads this at startup)
3. UTC

There's also a new `TZ: ${TZ:-UTC}` env entry on both services in `docker-compose.yml` — pair it with the same zone on your Caddy container so the access-log timestamps line up.

### Branded error pages

This one's Caddy-flavored and I'm curious what you think. CaddyUI now injects a set of routes into `apps.http.servers.srv0.errors.routes` so every 404/502/503/504 from Caddy itself (not from an upstream that returns its own error body) renders a dark-mode-aware HTML page with:

- The status code + short human-readable explanation
- **`{http.error.id}`** — Caddy's 9-char correlation ID (same one that ends up in the access log, which is the whole point: when a user screenshots a 502, you can grep the log)
- Current HTTP-Date timestamp

Had to bang my head on one thing worth mentioning: the `{err.status_code}` / `{err.id}` placeholders you see in the Caddyfile docs **only work through the Caddyfile adapter**. If you're pushing raw JSON to `/load` (which CaddyUI does), you have to use the full `{http.error.status_code}` / `{http.error.id}` paths. Lost an hour to that. Writing it down here so you don't.

E2E-validated against `caddy:2-alpine` with a reverse_proxy to a dead upstream — 502 returns the branded page with real `{http.error.id}` and `{time.now.http}` substitutions.

---

## Upgrade

```bash
docker pull applegater/caddyui:v2.5.0
# or
docker pull applegater/caddyui:latest
```

Multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance attestations, scratch base, non-root UID 10001.

No schema migration required — captcha settings default to "off" on fresh installs, and existing Turnstile keys carry over.

---

## Links

- **GitHub release**: https://github.com/X4Applegate/caddyui/releases/tag/v2.5.0
- **Full changelog**: https://github.com/X4Applegate/caddyui/blob/main/CHANGELOG.md
- **Docker Hub**: https://hub.docker.com/r/applegater/caddyui
- **Repo**: https://github.com/X4Applegate/caddyui

---

Happy to answer questions, take feature requests, or hear about things that break. Especially interested in feedback on the error-page design — it's the first time I've written HTML that Caddy itself serves, and I'd rather get the conventions right early.

Thanks again for approving the last thread — really appreciate the warm reception. 🙏
