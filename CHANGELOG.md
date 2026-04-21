# Changelog

All notable changes to Caddy UI are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2025-04-21

First stable release. Combines all features developed during the v0.x series.

### Added
- **Proxy Hosts** — create, edit, enable/disable, and delete reverse-proxy rules; custom TLS cert selection
- **Redirections** — 3xx redirect rules with configurable HTTP code
- **Advanced Routes** — raw Caddyfile paste and JSON editor for any Caddy handler
- **Certificates** — upload PEM certificates or reference on-disk paths; expiry parsing
- **Multi-server management** — add any number of Caddy instances; switch via sidebar dropdown; per-server cookie session
- **Multi-user with ownership** — admin and user roles; users see only their own resources; admin sees all with Owner column
- **SMTP email notifications** — cert-expiry alerts and upstream health alerts; STARTTLS / implicit TLS / plain; skip-verify option; test-send button
- **Webhook notifications** — optional JSON POST on cert-expiry and upstream state change
- **Upstream health monitoring** — polls Caddy's `/reverse_proxy/upstreams` API every 5 minutes; sends alerts on healthy↔down transitions; resolves Docker-internal hostnames correctly
- **Caddy admin API integration** — all config changes pushed live via admin API; no Caddy restart needed
- **Import from Caddy** — pull live config from Caddy into the DB on first run
- **Paste Caddyfile** — parse a Caddyfile block into an Advanced Route
- **Activity log** — every action recorded with actor, timestamp, target, and success flag
- **Snapshots** — manual and automatic SQLite snapshots; auto-snapshot on every sync; download via /backup
- **Dashboard** — server status card, counts, system stats (uptime, load, memory, active requests, upstream health), per-server data
- **Sidebar** — fixed viewport height so footer (profile + version) is always visible; nav scrolls independently
- **Dark mode** — toggleable via sidebar; system preference detected on first load
- **2FA / TOTP** — per-user TOTP setup and verification
- **PWA** — web app manifest, service worker, installable on desktop and mobile
- **Update notifications** — amber badge in sidebar when a newer Docker Hub tag is available; dismissible per version
- **Server version tracking** — display Caddy version in server list; manually updated via edit form
- **Settings page** — SMTP config, webhook URL, cert-expiry threshold, test buttons, notifier status panel, database backup
- **Security** — bcrypt password hashing, HTTP-only session cookies, CSRF protection on state-changing routes, Content-Security-Policy header

### Technical
- Go 1.22, `go-chi/chi v5` router, `modernc.org/sqlite` (no CGo), embedded `html/template`
- Single binary, single SQLite file, no external dependencies at runtime
- Multi-stage Docker build; final image based on `alpine:3.19` (~15 MB)
- Version injected at build time via `-ldflags "-X main.Version=vX.Y.Z"`
- Automatic SQLite migrations on startup; backwards-compatible `ALTER TABLE … ADD COLUMN` pattern

---

## [0.0.20] — 2025-04-21
- Moved system stats bar to the top of the dashboard
- Stats now include per-server active upstream requests and healthy upstream count from Caddy's API
- JS passes `?sid=` to stats endpoint so switching servers updates the Caddy-specific columns

## [0.0.19] — 2025-04-21
- Rewrote SMTP send logic: each security mode (TLS, STARTTLS, None) uses its own code path instead of `smtp.SendMail` for all
- STARTTLS now calls `c.StartTLS()` directly so `InsecureSkipVerify` is respected
- Added **Skip TLS certificate verification** checkbox in Settings for self-signed / transitional certs

## [0.0.18] — 2025-04-20
- **SMTP email notifications** — full SMTP configuration in Settings; cert-expiry and upstream health alerts sent via email
- **Upstream health notifier** — background check every 5 minutes per server; emails on state transitions
- Cert-expiry notifier now fires email alongside (or instead of) webhook
- Settings page overhauled: SMTP section, test-email button, notifier status shows both cert and upstream alert history
- Added `POST /settings/test-email` endpoint

## [0.0.17] — 2025-04-20
- Sidebar locked to viewport height (`md:h-screen md:overflow-hidden`) so profile/version footer is always visible
- Main content area scrolls independently (`md:overflow-y-auto`)
- Mobile layout unchanged

## [0.0.16] — 2025-04-19
- Fixed upstream health red dots for Docker-internal hostnames (e.g. `gitlab`, `snipeit-app`)
- CaddyUI now queries Caddy's own `/reverse_proxy/upstreams` admin API for authoritative health data
- Falls back to direct TCP probe only for upstreams not registered in Caddy

## [0.0.15] — 2025-04-19
- Multi-user ownership: each user can only see and manage their own proxy hosts, redirections, and raw routes
- Admin sees all resources with an Owner column
- `owner_id` column added to `proxy_hosts`, `redirection_hosts`, `raw_routes` via migration
- Domain conflict check always uses admin view (prevents cross-user conflicts)
- Added User role radio option in user form

## [0.0.14] — 2025-04-18
- Update notification badge in sidebar footer
- Polls Docker Hub tags API for latest `vX.Y.Z` tag; result cached 1 hour
- Badge is dismissible per version via localStorage

## [0.0.13] — 2025-04-18
- UI consistency pass: standardized spacing, button padding (`px-4 py-2`), form label style, focus rings, breakpoints, empty states
- Dark mode overhaul: full color family overrides for brand, red, amber, blue, purple
- Sidebar breakpoints changed from `lg:` to `md:` throughout

## [0.0.12] — 2025-04-18
- Fixed `var Version` placement (was before imports, causing compile error)
- Dockerfile: added `ARG VERSION=dev` and `-X main.Version=${VERSION}` ldflags
- Caddy server version displayed in server list and dashboard

---

[1.0.0]: https://github.com/applegater/caddyui/releases/tag/v1.0.0
[0.0.20]: https://github.com/applegater/caddyui/releases/tag/v0.0.20
[0.0.19]: https://github.com/applegater/caddyui/releases/tag/v0.0.19
[0.0.18]: https://github.com/applegater/caddyui/releases/tag/v0.0.18
[0.0.17]: https://github.com/applegater/caddyui/releases/tag/v0.0.17
[0.0.16]: https://github.com/applegater/caddyui/releases/tag/v0.0.16
[0.0.15]: https://github.com/applegater/caddyui/releases/tag/v0.0.15
[0.0.14]: https://github.com/applegater/caddyui/releases/tag/v0.0.14
[0.0.13]: https://github.com/applegater/caddyui/releases/tag/v0.0.13
[0.0.12]: https://github.com/applegater/caddyui/releases/tag/v0.0.12
