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
- CaddyUI serves its own pages under a **Content-Security-Policy** and ships no third-party runtime scripts
- The Caddy admin API URL is configured server-side and never exposed to the browser

### Data

- Data is stored in an embedded **SQLite** file by default, or an optional **MariaDB** backend, on infrastructure you control
- No credentials, API keys, or SMTP passwords are ever logged or transmitted to any third party
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
