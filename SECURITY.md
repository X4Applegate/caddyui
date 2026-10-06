# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest `2.x` release | ✅ Active — fixes ship on top of the newest release |
| Older `2.x`          | ⚠️ Please upgrade to the latest before reporting |
| `1.x` and earlier    | ❌ No longer supported — upgrade to the latest `2.x` |

Always run the most recent release; CaddyUI ships frequently and security fixes are not backported to older versions.

---

## Reporting a Vulnerability

**Please do not open a public GitHub Issue for security vulnerabilities.**

Report security issues privately by emailing:

**admin@richardapplegate.io**

Include in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (PoC)
- Affected version(s)
- Any suggested remediation if you have one

You will receive an acknowledgement within **72 hours**. If the vulnerability is confirmed, a fix will be prioritised and a patched release issued. You will be credited in the release notes (unless you prefer to remain anonymous).

---

## Security Design

### Authentication

- Passwords hashed with **bcrypt** (cost factor 12)
- Sessions use cryptographically random tokens stored in HTTP-only, SameSite=Lax cookies
- Optional **TOTP 2FA** per user (RFC 6238)
- First-run setup creates the admin account; no default credentials

### Transport

- CaddyUI itself is a plain HTTP server — it is designed to sit **behind Caddy** (which handles TLS termination)
- All state-changing routes use POST and require a per-session **CSRF token** (since v2.29.0), on top of the browser's SameSite=Lax cookie policy
- CaddyUI serves its own pages under a **Content-Security-Policy**. The sign-in, setup and password-reset pages use a vendored stylesheet; the authenticated pages still load the Tailwind CSS runtime from `cdn.tailwindcss.com`, which is why the policy allows inline script and `eval`. Self-hosting it is on the roadmap — until then, treat that CDN as part of your trust base.
- The Caddy admin API URL is configured server-side and never exposed to the browser

### Roles and the admin boundary

CaddyUI has three roles: **admin**, **user** (a customer or teammate who manages the resources they own) and **view** (read-only). Everything that exposes or replaces the live Caddy configuration, the database or stored credentials is **admin-only**: the live config page, database backup, snapshots (list, download, restore, upload), Import from Caddy, the Porkbun certificate import, notifier status, settings, users and the fleet list. Certificate export to a directory, pushing a certificate to other servers and copying certificates between servers are admin-only too.

A **user** account's proxy hosts, redirections and Advanced routes become Caddy routes that run with Caddy's full power, so CaddyUI inspects the *generated* route for every non-admin-owned resource, both when it is saved and again whenever the config is built (so a row stored by any path — UI, REST API, import, AI tool, clone — is covered):

- upstreams may not be loopback, link-local, cloud-metadata or any registered Caddy node's admin API, and may not use unix sockets, placeholders or dial-syntax tricks; the `Host` override and forward-proxy / forward-auth URLs are held to the same rule
- `file_server`, `templates`, `acme_server` and dynamic upstreams are refused
- `{env.…}`, `{file.…}` and Caddyfile `{$…}` placeholders are refused (Caddy expands them at request time, which would let a user read the Caddy process's environment — where the DNS API token usually lives — and any file the Caddy container can read); Caddyfile text containing them, or importing anything but a snippet by name, is refused *before* it is sent to Caddy
- proxy host domains must be plain hostnames and custom health checks are limited to GET/HEAD, because CaddyUI's own probes build URLs from them

Admins are never restricted by these rules.

Sign-in protection: set `max_login_attempts` (Settings → Security) to lock an address out after repeated failures; second-factor guesses are limited per login attempt and per account regardless of that setting, and a password change signs the account out everywhere.

Set **`CADDYUI_PUBLIC_URL`** (for example `https://caddyui.example.com`) so password-reset and invitation emails link to your real address; without it (or an OIDC redirect URL) the link falls back to the request's `Host` header.

### Data

- Data is stored in an embedded **SQLite** file by default, or an optional **MariaDB** backend, on infrastructure you control
- Credentials are not logged: the request log records the path only (never the query string, where one-time tokens travel), and webhook / ntfy URLs and `CADDY_ADMIN_URL` passwords are redacted from other log lines. Nothing is transmitted to a third party except what you configure (webhooks, SMTP, AI backends, DNS providers)
- SMTP passwords are stored in the SQLite settings table (encrypted at rest only if you use full-disk encryption on the host)

### Dependencies

Core runtime dependencies are minimal:

| Package | Purpose |
|---|---|
| `go-chi/chi` | HTTP routing |
| `modernc.org/sqlite` | SQLite (no CGo) |
| `go-sql-driver/mysql` | optional MariaDB backend |
| `golang.org/x/crypto` | bcrypt + TOTP primitives |
| `pquerna/otp` | TOTP code generation/verification |

All dependencies can be audited in `go.mod` / `go.sum`.

### AI Assistance

Development is assisted by Claude (Anthropic). No secrets, credentials, database contents, or user data are shared with Claude — only code structure and logic.

---

## Threat Model Notes

- CaddyUI is intended for **private/internal network** deployment. Exposing it directly to the public internet without authentication hardening (strong password + TOTP) is not recommended.
- The Caddy admin API (`CADDY_ADMIN_URL`) should not be exposed outside the Docker network. Default Docker Compose configuration keeps it on an internal bridge.
- Database backups contain hashed passwords and TOTP secrets — protect them accordingly.
