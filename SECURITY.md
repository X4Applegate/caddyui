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

#### How `go.mod` is watched for advisories, and what that misses

Two checks cover the Go module set, and they look at different things:

| What | Covers | Source |
|---|---|---|
| Dependabot `gomod` | everything in `go.mod`, direct **and indirect** | GitHub's **global** advisory database |
| `scripts/check-pinned-modules.sh` (weekly) | the `--with` plugin pins in `Dockerfile.caddy` | OSV **and** GitHub's **repo-scoped** advisory list |

Dependabot does work on `go.mod`, including indirect dependencies: 19 Go advisories have been raised against this repo and all are now fixed, among them `GHSA-mgcc-cww5-fp2q` against `github.com/go-jose/go-jose/v4`, an indirect dependency.

**But it is keyed on GitHub's global advisory database, and that index omits advisories with no CVE id.** So `go.mod` has the same blind spot the `--with` pins had before their GitHub cross-check was added, for the same reason — and it is not theoretical:

> Five advisories against `github.com/go-jose/go-jose/v4` were published 2026-10-30 with **no CVE id**, affecting `<= v4.1.6` and fixed in `v4.1.7`: `GHSA-v6h2-qj3f-2h6v`, `GHSA-c67m-wr4h-2ccg`, `GHSA-p9j4-2j95-j4rv` (medium), `GHSA-r39w-98wm-9pp6`, `GHSA-27pc-rm86-68pq` (low). Measured 2026-11-12: all five are absent from OSV, absent from GitHub's global advisory database, and have raised **no Dependabot alert** — while `repos/go-jose/go-jose/security-advisories` returns all five. Every advisory Dependabot *has* raised here carries a CVE id.

The pattern is consistent across all three of this repo's advisory blind spots (the plugin pins, `go.mod`, and the Caddy base below): **a CVE-less advisory is visible only on the per-repository endpoint.** Any check built on an ecosystem-scoped or global index inherits the gap, whichever provider it comes from.

`govulncheck` does **not** close this gap either — verified 2026-11-12 against `vuln.go.dev` (DB of 2026-11-11): it reports none of the five. Closing it means asking the repo-scoped endpoint for `go.mod` modules the way `check-pinned-modules.sh` already does for the `--with` pins.

`govulncheck` is still worth adding for a different reason: it is the only one of these checks that reports **reachability**, and run on 2026-11-12 it found a called stdlib vulnerability no other check surfaces — `GO-2026-6859` (HTTP/1 server crash via a `MaxBytesReader` header race in `net/http`), reachable from this code and fixed in Go 1.27.4. Dependabot does not track the toolchain version, and Trivy's image scan compares against the previous image rather than against upstream.

What neither check covers is the **Caddy base image's own** module set, which is why the section below is maintained by hand.

### AI Assistance

Development is assisted by Claude (Anthropic). No secrets, credentials, database contents, or user data are shared with Claude — only code structure and logic.

### Caddy base advisories (fixed upstream; not yet in the published image)

Five CVE-less advisories published 2026-11-04 affected Caddy **2.11.7** and earlier, including one
**high** (`GHSA-r766-rf9f-588h`: `Host`/`:authority` values with dot segments escaping a
`{host}`-based document root). **All five are fixed in Caddy 2.11.8. This repository's `Dockerfile.caddy` now builds on
2.11.9**, which no Caddy advisory affects.

> **The published image has not caught up yet.** `applegater/caddyui-caddy:stable` currently
> serves the v2.68.11 artifact (`sha256:abdb5b0a4737…`), whose binary links **caddy v2.11.7** —
> verified with `go version -m` on the extracted binary, not inferred from the tag. So the five
> advisories, including the high, **still apply to the image you pull today**, and the
> preconditions listed below therefore still matter — in particular, do not build a document
> root from `{host}` until the next release is published. This note is removed when
> `go version -m` on the extracted `:stable` binary reports caddy v2.11.9.

None carried a CVE id, so none appeared in OSV or in CVE-keyed scanners — they were visible only
through GitHub's repository advisory endpoint. That blind spot is why the pinned-module watcher
cross-checks that endpoint per repository, and why a green image-gate scan is not on its own evidence
that a base image is clean.

If you run an older `caddyui-caddy` image, upgrade. Builds from 2.11.7 or earlier remain affected,
and the preconditions were admin-authored config: a `root` built from `{host}`, a `php_fastcgi` site,
`file_server` with the data directory fallen back to `./caddy`, or a `file` matcher or `rewrite` using
the file-matcher remainder. CaddyUI generates none of those, and `file_server`, `templates` and
`acme_server` are admin-only — see *Roles and Permissions*.
---

## Threat Model Notes

- CaddyUI is intended for **private/internal network** deployment. Exposing it directly to the public internet without authentication hardening (strong password + TOTP) is not recommended.
- The Caddy admin API (`CADDY_ADMIN_URL`) should not be exposed outside the Docker network. Default Docker Compose configuration keeps it on an internal bridge.
- Database backups contain hashed passwords and TOTP secrets — protect them accordingly.
