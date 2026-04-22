# Changelog

All notable changes to **Caddy UI** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.2.0] — 2026-04-22 · Porkbun DNS Integration

### Added
- **Porkbun DNS provider** (`internal/porkbun/`) — second managed-DNS integration alongside Cloudflare. CaddyUI can now create, update, and delete A records on Porkbun-registered domains automatically when proxy hosts change
  - New Settings card: paste API key + secret key (keep-blank-to-preserve UX) with the Porkbun control-panel "API Access per domain" gotcha called out inline
  - Proxy host form: replaced the CF-only toggle with a three-way provider radio (**None / Cloudflare / Porkbun**); the Cloudflare zone and Porkbun domain selectors appear conditionally and load on demand
  - Shared Server IP: Porkbun reuses the same Server IP field already configured for Cloudflare, so switching providers doesn't require re-entering it
  - IP-change retargeting: when Server IP changes in Settings, every Porkbun-managed record is re-pointed in the background (mirrors existing CF behaviour)
  - Full lifecycle on proxy-host create / edit / delete, including cross-provider switches (old CF/PB record is cleaned up when you change provider or clear the selection)
- **Docs page** — new "Porkbun DNS" tutorial section walking through API-key creation, per-domain API Access toggle, and the 600s TTL minimum

### Changed
- **Dashboard domain pills** — clicking a source domain now jumps to **Proxy Hosts** filtered to that host (with the matching row scrolled into view) instead of opening the live site in a new tab; much more useful for day-to-day management

### Database
- Added `pb_dns_record_id` and `pb_domain` columns to `proxy_hosts` via the same idempotent `columnExists → ALTER TABLE ADD COLUMN` pattern used elsewhere. Existing Cloudflare records are untouched

### Docker
- Published as `applegater/caddyui:v2.2.0` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.1.1] — 2026-04-22 · Blue PWA Icons & Theme Color

### Changed
- **PWA icons** — `icon-192.png` and `icon-512.png` regenerated with the new blue gradient (`#3b82f6 → #2563eb`); the white hexagon mark is preserved so the brand identity carries over
- **manifest theme_color** — updated from green (`#059669`) to blue (`#2563eb`) so the browser chrome and Add-to-Home-Screen splash match the refreshed in-app palette

### Docker
- Published as `applegater/caddyui:v2.1.1` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.1.0] — 2026-04-22 · Blue Theme, Admin API Auth, Unix Sockets, Docs

### Added
- **HTTP Basic Auth for Caddy admin API** — per-server `admin_username` / `admin_password` fields let you put port 2019 behind a reverse proxy that enforces Basic Auth (simpler alternative to WireGuard/Tailscale for remote admin)
  - Bootstrap server reads `CADDY_ADMIN_USER` / `CADDY_ADMIN_PASS` env vars
  - "Leave blank to keep current" UX on edit; explicit **Clear saved password** checkbox so masked inputs can't silently wipe credentials
  - `caddy.Client` refactored so health poller, config viewer, and sync all flow through the same auth + transport path
- **Unix domain socket transport** — admin URL now accepts `unix:///run/caddy-admin.sock` for zero network exposure on single-host setups; `http.Transport.DialContext` dials the socket while the URL presents as `http://unix` to the rest of the stack
- **HTTPS admin URLs** — `https://host:2019` accepted for TLS-wrapped admin APIs
- **Docs / Tutorial page** (`/docs`) — full walkthrough: first-time setup, proxy hosts, redirections (with HTTP-code explanations), advanced routes, certificates, Cloudflare DNS, import, snapshots, multi-server transports, users & 2FA, and a FAQ
- **Human-readable HTTP redirect codes** — redirection lists and the edit form now show the name next to the number (301 — Moved Permanently, 302 — Found, 307/308 — Temporary/Permanent Redirect) with a tooltip on hover and an inline explainer panel on the form
- **`.version-pill`** CSS class — same blue family as domain pills but smaller, so the Caddy server version chip reads as secondary metadata

### Changed
- **Domain pills** — grey → vivid blue gradient (`#3b82f6 → #2563eb`) with hover lift + soft blue glow; updated for both light and dark modes so proxy host / redirection / advanced route domains "pop" consistently everywhere they appear
- **Main content container** — widened from `max-w-6xl` to `max-w-[1600px]` so the Actions column stays in-frame on wide monitors
- **Database migration** — new `admin_username` and `admin_password` columns on `caddy_servers`, applied automatically at startup via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` check

### Docker
- Originally published as `applegater/caddyui:v2.1.0` (superseded by v2.1.1 — see above)

---

## [2.0.x] — 2026-04-21 · Concurrency & Mobile Fixes

### Fixed
- **SQLITE_BUSY under concurrent writes** — enabled WAL mode and `busy_timeout=5000`, capped `SetMaxOpenConns(1)` so the health poller, web requests, and notifier don't trip the SQLite write lock under load
- **Mobile layout** — raised the responsive breakpoint from `md` (768 px) to `lg` (1024 px) on list pages so narrow-viewport tablets get the mobile card layout instead of a cramped desktop table

### Added
- **Cloudflare DNS integration** (`internal/cloudflare/`) — optional auto-managed A records for proxy hosts; records auto-retarget when the server IP changes in Settings
- **Scratch-based Docker image** with SBOM + provenance attestation; non-root UID 10001
- **Cloudflare Turnstile** login protection (optional)

---

## [1.0.0] — 2025-04-21 · First Stable Release

The project started as a private tool to manage a home-lab Caddy setup without editing config files by hand.
Over roughly two months of active development it grew into a full-featured, multi-user, multi-server UI.
This release marks the point where it's stable enough to share.

### ✨ Core Features (built across the v0.x series)

**Proxy Hosts**
- Create, edit, enable/disable, and delete reverse-proxy rules
- Domain validation — prevents duplicate hostnames across all users
- Choose between automatic Caddy-managed TLS or a custom certificate
- HTTP/HTTPS/WebSocket upstream schemes
- Per-host enable/disable toggle with instant live sync to Caddy
- Mobile-responsive card list + desktop table with search/filter

**Redirections**
- 301 / 302 / 307 / 308 redirect rules from one hostname to another
- Forward scheme selection (http/https)
- Enable/disable toggle; search/filter on domain and destination
- Mobile cards + desktop table view

**Advanced Routes**
- Paste a raw Caddyfile block — CaddyUI adapts it to JSON via Caddy's own adapter and stores both the original source and the compiled JSON
- Write raw Caddy JSON directly for anything the UI can't model (custom handlers, per-path routing, multiple upstreams, file servers)
- Imported Caddyfile source shown in the list; adapted JSON expandable on demand

**Certificates**
- Upload PEM-encoded cert + key pairs
- Reference on-disk certificate files by path (for externally-managed certs e.g. Certbot, ACME.sh)
- Certificate expiry parsed from the PEM and shown in the list
- Safe deletion — warns if a certificate is still referenced by a proxy host or redirection

**Import from Caddy**
- Pull the live running config from Caddy's admin API into the CaddyUI database on first run
- Converts Caddy's JSON routes into proxy host and redirection records

**Paste Caddyfile**
- Paste any Caddyfile site block into a text area
- CaddyUI sends it through Caddy's adapter API, stores the resulting JSON as an Advanced Route, and preserves the original Caddyfile text for display

---

### 🖥️ Multi-Server Management

- Add any number of Caddy instances (managed or external) via the Caddy Servers page
- Each server has a name, admin API URL, type tag, and optional version label
- Switch the active server from a dropdown in the sidebar — all pages (proxy hosts, redirections, certificates, etc.) are scoped to the selected server
- Background health poller checks every server's admin API every 30 seconds; status badges (online / offline / unknown) update automatically
- "View live config" shows the raw JSON currently running on any server
- Cross-deploy: push a proxy host to multiple servers simultaneously

---

### 👥 Multi-User & Roles

- **Admin** — full access to all resources on all servers; sees Owner column in every list
- **User** — sees and manages only their own proxy hosts, redirections, and advanced routes; cannot access Caddy Servers, Users, or Settings pages
- Ownership tracked via `owner_id` on each resource row; NULL = global (admin-only)
- Domain conflict checking is always global — a user cannot claim a domain already in use by another user
- First user created during setup is automatically assigned the admin role

---

### 🔐 Authentication & Security

- First-run setup wizard — no default credentials; admin account created on first visit
- Passwords hashed with **bcrypt** (cost 12)
- Sessions use cryptographically random tokens in HTTP-only, SameSite=Lax cookies
- **TOTP / 2FA** — per-user time-based one-time passwords (RFC 6238); setup via QR code in the UI
- Content-Security-Policy header on all responses
- All state-changing routes require POST (CSRF mitigated by SameSite cookie policy)

---

### 📊 Dashboard

- Server status card — name, online/offline badge, managed/external label, admin URL, last contact time, last sync time
- Six stat tiles — proxy host count, enabled count, disabled count, redirections, advanced routes, certificates; each links to its page
- System stats bar (top of page) — host uptime, 1-minute load average, memory used / total, memory %, active upstream requests (from Caddy API), healthy upstream ratio (from Caddy API)
- Stats bar is per-server for the Caddy columns; switches when you change server
- Recent proxy hosts table for quick access
- Certificate expiry warning banner — shown when any custom cert expires within 30 days

---

### 🔔 Notifications

**Webhook**
- Configure a webhook URL in Settings
- CaddyUI POSTs a JSON payload when a certificate is nearing expiry or when an upstream changes health state
- Test-send button fires an immediate test payload

**Email (SMTP)**
- Full SMTP configuration in Settings — host, port, security mode, username, password, from/to addresses
- Security modes: STARTTLS (port 587), implicit TLS/SSL (port 465), plain (port 25)
- "Skip TLS verify" checkbox for self-signed or transitional certificates
- Password stored in DB; blank on save = keep existing (never re-displayed)
- Test-send button sends a real email immediately to verify connectivity
- Certificate expiry alert — fires once per 24 h per domain when within the configured threshold (default 14 days); subject includes domain and days remaining
- Upstream health alert — fires on every healthy→down or down→recovered transition (checked every 5 minutes per server via Caddy's admin API)
- Both channels (webhook + email) can be active simultaneously

**Notifier status panel** — shows last cert-check timestamp, recently alerted certificates, last upstream-check timestamp, and recent upstream alerts with event type and time

---

### 📸 Snapshots

- Manual snapshot — one click creates a consistent SQLite backup stored server-side
- Automatic snapshot — taken automatically before every sync to Caddy
- Download backup — `/backup` endpoint streams a consistent SQLite snapshot directly to the browser
- Restore instructions shown in Settings

---

### 📋 Activity Log

- Every create, edit, delete, enable/disable, sync, import, and settings change is recorded
- Log entries include: actor (user email or "system"), action, target, detail, success flag, timestamp, server context
- Visible to admins at `/activity`

---

### 🎨 UI & UX

**Layout**
- Sidebar fixed to viewport height — navigation items scroll inside the sidebar; profile + version footer always visible at the bottom
- Mobile: collapsible slide-in sidebar with hamburger button and scrim overlay
- Sticky server context bar below the sidebar on desktop — shows server name, status dot, and admin URL

**Dark mode**
- Toggle button in the sidebar footer (moon icon)
- Persists across sessions via localStorage
- Respects system `prefers-color-scheme` on first visit

**PWA (Progressive Web App)**
- Web app manifest — installable to home screen on Android, iOS, and desktop
- Service worker with offline caching for static assets
- Theme color, icons (192 × 192 and 512 × 512), and standalone display mode

**Update notification**
- Amber badge appears in the sidebar footer when a newer Docker Hub tag exists
- Tag comparison uses proper semantic versioning (v1.2.3 format)
- Docker Hub API response cached for 1 hour to avoid rate limiting
- Badge dismissible per version — stores dismissed version in localStorage

**Search & filter**
- Proxy hosts — live search across domains and upstream
- Redirections — live search across source and destination domains
- All searches run client-side with no page reload

**Responsive tables**
- Every list page has a mobile card layout and a desktop table layout
- Breakpoint: `md` (768 px)
- Empty states include icon, message, and quick-action links

---

### ⚙️ Settings

- Webhook URL and cert-expiry threshold (days before)
- Full SMTP configuration with test button
- Notifier status panel
- Database backup download
- All settings stored in a key-value SQLite table — no config files

---

### 🏗️ Technical Foundation

| Area | Choice | Reason |
|---|---|---|
| Language | Go 1.22 | Single binary, fast compile, no runtime deps |
| Router | `go-chi/chi v5` | Lightweight, idiomatic, middleware-friendly |
| Database | `modernc.org/sqlite` | Pure Go SQLite — no CGo, works in Alpine |
| Templates | `html/template` (stdlib) | Zero deps, auto-escaping, embedded in binary |
| Auth | `golang.org/x/crypto` bcrypt | Industry standard password hashing |
| 2FA | `pquerna/otp` | RFC 6238 TOTP, QR code generation |
| CSS | Tailwind CSS (CDN) | No build step; utility-first |
| Container | Alpine 3.19 multi-stage | Final image ~15 MB |

**Database migrations** run automatically at startup using backwards-compatible `ALTER TABLE … ADD COLUMN IF NOT EXISTS` checks — upgrading never requires manual DB changes.

**Version injection** — version string baked in at build time via `-ldflags "-X main.Version=vX.Y.Z"`, displayed in the sidebar footer and checked against Docker Hub for update notifications.

---

## [0.0.20] — 2025-04-21 · Dashboard Stats to Top

### Changed
- Moved the system stats bar from the bottom of the dashboard to the very top, above the server card and proxy list — always visible without scrolling
- Stats bar now spans 6 columns: Uptime, Load (1m), Memory Used, Memory %, Active Requests, Upstreams
- **Active Requests** and **Upstreams** columns query the selected server's Caddy admin API (`/reverse_proxy/upstreams`) — they change when you switch server
- Upstreams tile turns red when any upstream is failing, green when all healthy
- JS passes `?sid=` query param so the backend fetches stats from the correct Caddy instance

### Fixed
- Switching server in the dropdown now updates the Caddy-specific stat tiles immediately (previously all tiles were always from the CaddyUI host and never changed)

---

## [0.0.19] — 2025-04-21 · SMTP TLS Fix

### Fixed
- `tls: first record does not look like a TLS handshake` error when using STARTTLS mode — root cause was `smtp.SendMail` being used for all three security modes, which doesn't allow passing a custom `tls.Config`
- STARTTLS now dials plain and calls `c.StartTLS(tlsCfg)` directly, so `InsecureSkipVerify` is properly threaded through
- Implicit TLS (port 465) and plain (port 25) also rewritten to use manual `smtp.Client` for consistency
- Clarified when to use each mode — STARTTLS/587 is the correct choice for most mail servers including Mailu

### Added
- **Skip TLS certificate verification** checkbox in Settings — for self-signed certs or during certificate transitions (e.g. switching CA providers); labelled clearly as a security trade-off

---

## [0.0.18] — 2025-04-20 · SMTP Email Notifications

### Added
- **Email (SMTP) section** in Settings — host, port, security (STARTTLS / TLS / None), username, password, from, to (comma-separated), skip-verify
- Password field never pre-fills — blank on save means "keep existing"; prevents accidental exposure
- **Test Email** button — sends a real test message immediately; shows success or error inline
- **Cert-expiry email** — fires alongside (or instead of) the webhook when a custom certificate is within the configured threshold; subject: `[CaddyUI] Certificate expiring: domain.com (X days left)`; body includes domain, days remaining, expiry date, and link to /certificates
- **Upstream health notifier** — new background goroutine checks every server's Caddy API every 5 minutes; sends email and/or webhook notification on state transitions (healthy → down, down → recovered); subject: `[CaddyUI] Upstream host:port down on ServerName`
- Notifier status panel updated to show upstream check timestamp and recent upstream alerts (last 10, newest first) with colour coding (red = down, green = recovered)
- `POST /settings/test-email` endpoint
- Both cert and upstream notifiers started from `StartNotifier()` at boot

### Changed
- `runNotifierCheck` no longer exits early if only SMTP is configured (previously required a webhook URL)
- Cert notifier now iterates all servers instead of hardcoding `server_id = 1`

---

## [0.0.17] — 2025-04-20 · Sidebar Viewport Lock

### Fixed
- Sidebar scrolled away on long proxy host lists — profile and version footer disappeared off the bottom of the screen
- Outer layout wrapper changed from `min-h-screen` to `md:h-screen md:overflow-hidden` — desktop viewport is now exactly the screen height
- Main content area gets `md:overflow-y-auto` so the page content scrolls independently inside the right panel
- Sidebar nav already had `flex-1 overflow-y-auto` so nav items scroll within the sidebar if there are many; footer stays pinned

### Unchanged
- Mobile layout uses `min-h-screen` (normal scroll) — the sidebar is `fixed` on mobile so the viewport trick isn't needed

---

## [0.0.16] — 2025-04-19 · Upstream Health Fix for Docker Hostnames

### Fixed
- Proxy hosts using Docker-internal container names (e.g. `gitlab`, `snipeit-app`, `postgres`) showed a red health indicator even though the services were running correctly
- Root cause: CaddyUI was making direct TCP/HTTP probes from its own container — Docker-internal hostnames are only resolvable within the Caddy container's network, not from the CaddyUI container
- Fix: `apiUpstreamHealth` now calls Caddy's own admin API (`GET /reverse_proxy/upstreams`) first; Caddy can resolve its own upstream names correctly and reports `fails` count
- Falls back to a direct probe only for upstreams not yet registered in Caddy's upstream pool (e.g. first sync)
- Added `fetchCaddyUpstreams(adminURL)` helper; `caddyUpstreamInfo` struct (`address`, `num_requests`, `fails`)

---

## [0.0.15] — 2025-04-19 · Multi-User Proxy Ownership

### Added
- **User role** — new role alongside admin; added "User" radio in user creation/edit form
- `owner_id INTEGER NULL` column added to `proxy_hosts`, `redirection_hosts`, `raw_routes` via automatic migration on startup (NULL = global / admin-created)
- Non-admin users see and manage only the resources they created; admin sees everything
- **Owner column** appears in proxy host, redirection, and advanced route lists when logged in as admin
- Non-admin trying to edit/delete another user's resource gets a 403
- Domain conflict check always uses the full admin view — prevents a user from registering a domain already claimed by another user
- `ListProxyHosts`, `ListRedirectionHosts`, `ListRawRoutes` updated to accept `viewerID` and `isAdmin` parameters

### Changed
- Create handlers now set `owner_id` to the current user's ID (admins create global resources with NULL by default unless they switch to a user account)

---

## [0.0.14] — 2025-04-18 · Update Notification Badge

### Added
- Amber badge in the sidebar footer showing the latest available version when a newer Docker Hub tag exists
- Polls `hub.docker.com/v2/repositories/applegater/caddyui/tags/` on page load; result cached in-memory for 1 hour
- Semantic version comparison (`semverGT`, `semverValid`, `semverParts`) — only shows if the remote tag is strictly greater than the running version
- Badge text: `↑ vX.Y.Z available`; click to dismiss for that version (stored in localStorage under `caddyui-update-dismissed`)
- Does not show in `dev` builds (version string must be a valid `vX.Y.Z` tag)
- `GET /api/version-check` endpoint returns `{current, latest, has_update}`

---

## [0.0.13] — 2025-04-18 · UI Consistency & Dark Mode Overhaul

### Changed
- **Spacing** — header `mb-6` → `mb-8` across all list pages for consistent breathing room
- **Button padding** — `px-3 py-2` → `px-4 py-2` on all primary action buttons
- **Form labels** — changed from all-caps `text-xs uppercase tracking-wider text-ink-500` to `text-sm font-medium text-ink-800` for better readability
- **Focus rings** — `focus:ring-brand-100` → `focus:ring-brand-500/20` for more visible keyboard navigation
- **Breakpoints** — `lg:table` / `lg:hidden` → `md:table` / `md:hidden` on advanced routes and servers pages; tables appear at 768 px instead of 1024 px
- **Toggle labels** — mobile "on" / "off" → "enabled" / "disabled" to match desktop
- **Empty states** — all pages now have consistent icon + message + action link; padding standardised to `px-5 py-16`
- **Hint text** — `text-ink-400 mt-1` → `text-ink-500 mt-1.5` for better contrast

### Fixed
- Dark mode was missing overrides for many Tailwind utility classes — complete colour family set added to `app.css`:
  - Brand (green): `bg-brand-50/100`, `text-brand-600/700/800`, hover states, `border-brand-200`
  - Red (errors/delete): `bg-red-50`, `border-red-200`, `text-red-500/600/700/800`
  - Amber (warnings): `bg-amber-50`, `border-amber-200`, `text-amber-800`
  - Blue (HTTP codes): `bg-blue-50`, `border-blue-200`, `text-blue-700`
  - Purple (admin badges): `bg-purple-50/100`, `border-purple-200`, `text-purple-700`
  - Code/pre blocks: `bg-ink-900` retained in dark mode

---

## [0.0.12] — 2025-04-18 · Build System & Caddy Version Display

### Fixed
- `var Version = "dev"` was declared before the import block, causing a Go compile error (`imports must appear before other declarations`)
- Moved the declaration to after all imports and function definitions

### Added
- `ARG VERSION=dev` in Dockerfile — version can now be injected at build time: `docker build --build-arg VERSION=v0.0.12 .`
- `-ldflags "-s -w -X main.Version=${VERSION}"` baked into the Docker build RUN command
- Caddy server version field on the Servers page — manually set via the server edit form; displayed as a badge next to each server in the list and on the dashboard; hint text suggests `docker exec caddy caddy version`

---

## [0.0.1 – 0.0.11] — Initial Development

The first phase of the project built the entire foundation from scratch.

### Authentication
- First-run setup wizard — detects an empty database and prompts to create the initial admin account before anything else is accessible
- Login page with email + password; session cookie issued on success
- bcrypt password hashing (cost 12)
- Logout with session invalidation
- TOTP / 2FA — per-user setup via QR code scan; enforced on login when enabled; backup handled by re-setup

### Proxy Hosts
- Full CRUD — create, list, edit, delete
- Fields: domains (space-separated), forward scheme/host/port, enabled toggle, custom certificate selector
- Enable/disable toggle directly from the list page (no full edit required)
- Validation: duplicate domain detection (globally across all hosts), required fields
- Sync to Caddy on create/edit/delete — changes go live immediately via admin API

### Redirections
- Full CRUD for hostname → hostname redirects
- HTTP code selector (301, 302, 307, 308)
- Forward scheme selection
- Enable/disable toggle from list

### Advanced Routes
- Raw JSON editor with syntax reference
- Paste Caddyfile block → adapted to JSON via Caddy's `/adapt` API endpoint
- Stores original Caddyfile source alongside compiled JSON; source shown in list

### Certificates
- Upload PEM cert + key (paste into textarea)
- Reference on-disk cert/key by file path
- Certificate name and domain display
- Expiry parsed from PEM and shown in list
- In-use check before delete (won't delete if referenced by any host)

### Dashboard
- Server status card with online/offline badge and last-contact timestamp
- Six stat tiles: proxy hosts, enabled, disabled, redirections, advanced routes, certificates
- Recent proxy hosts table
- Certificate expiry warning banner (within 30 days)
- System stats (uptime, load, memory) fetched from `/proc` on the CaddyUI host

### Multi-Server
- Caddy Servers CRUD page (admin only)
- Server picker dropdown in the sidebar — sets a session cookie, redirects back to current page
- All resources scoped to the selected server
- Background health poller every 30 seconds

### Import from Caddy
- Reads the full live JSON config from the Caddy admin API
- Maps `reverse_proxy` routes to proxy host records
- Maps `redir` routes to redirection records
- Shows a summary of what was imported and what was skipped

### Users (admin only)
- Create, edit, delete users
- Role assignment: admin
- Password reset by admin

### Activity Log
- Persistent log of every action (create, edit, delete, sync, import, login, settings change)
- Columns: actor, action, target, detail, success, timestamp, server

### Snapshots
- Manual snapshot with a list of saved snapshots
- Auto-snapshot before every Caddy sync
- Download any snapshot as a file

### Settings
- Webhook URL for certificate expiry notifications
- Days-before-expiry threshold (default 14)
- Database backup download

### Sync Engine
- `SyncCaddy()` assembles the full Caddy JSON config from the database (all enabled hosts, redirections, raw routes, and certificates for the current server)
- Pushes to Caddy's `POST /load` endpoint — atomic replacement of the running config
- Optional startup sync via `CADDYUI_SYNC_ON_START=1`; waits up to 60 s for Caddy to become reachable before syncing

### PWA & UI
- Web app manifest with 192 and 512 px icons
- Service worker with cache-first strategy for static assets
- Mobile-responsive layout with collapsible sidebar
- Dark mode toggle with localStorage persistence and `prefers-color-scheme` detection
- Tailwind CSS via CDN — no build step

---

[1.0.0]: https://github.com/X4Applegate/caddyui/releases/tag/v1.0.0
[0.0.20]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.20
[0.0.19]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.19
[0.0.18]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.18
[0.0.17]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.17
[0.0.16]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.16
[0.0.15]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.15
[0.0.14]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.14
[0.0.13]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.13
[0.0.12]: https://github.com/X4Applegate/caddyui/releases/tag/v0.0.12
