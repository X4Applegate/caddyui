# Caddy UI

A modern, self-hosted web UI for [Caddy](https://caddyserver.com/) — manage proxy hosts, redirections, SSL certificates, and advanced routes through a clean interface, without touching config files.

[![License: CaddyUI-SAL 1.0](https://img.shields.io/badge/license-CaddyUI--SAL%201.0-blue)](LICENSE)
[![Docker Hub](https://img.shields.io/docker/v/applegater/caddyui?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/applegater/caddyui)
[![Docker Pulls](https://img.shields.io/docker/pulls/applegater/caddyui?label=pulls)](https://hub.docker.com/r/applegater/caddyui)
[![Go 1.25](https://img.shields.io/badge/Go-1.25-00ADD8)](https://go.dev/)

**Lighthouse:** Performance **99** · Accessibility **100** · Best Practices **100** · SEO **100** *(measured on `/login` from Google's PageSpeed Insights against a residential-ISP install — `:v2.12.53` and later)*

---

## Install

```bash
docker pull applegater/caddyui:latest
```

Current Docker images target `linux/amd64` and include SBOM/provenance attestations. The CaddyUI container runs non-root (UID 10001). Native Linux release archives remain available for both `amd64` and `arm64`.

Docker remains the recommended install path, but tagged releases also include
native Linux binary archives for `amd64` and `arm64` hosts. See the
[non-Docker systemd install](#non-docker-systemd-install) below if you want to
run CaddyUI directly in an LXC, VM, or bare-metal host.

---

## Screenshots

| Dashboard | Proxy Hosts |
|-----------|-------------|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Proxy Hosts](docs/screenshots/proxy-hosts.png) |

| Edit Proxy Host | Certificates |
|-----------------|--------------|
| ![Edit Proxy Host](docs/screenshots/edit-proxy-host.png) | ![Certificates](docs/screenshots/certificates.png) |

| Caddy Servers | Snapshots |
|---------------|-----------|
| ![Caddy Servers](docs/screenshots/caddy-servers.png) | ![Snapshots](docs/screenshots/snapshots.png) |

| User Management | Settings & Notifications |
|-----------------|--------------------------|
| ![New User](docs/screenshots/new-user.png) | ![Settings](docs/screenshots/settings.png) |

---

## Features

### What's new in v2.21

- **Fleet file access logs** — independently write native JSON or console access logs to selected Caddy servers with HTTP/HTTPS scope and rotation controls while preserving CaddyUI Visitor Analytics.
- **CrowdSec request protection** — configure the LAPI, masked bouncer key, streaming, refresh, hard-fail, selected environments, host/path exclusions, module validation, and live connection testing from Settings.
- **Correct client IPs** — configure `client_ip_headers` alongside trusted proxy ranges so logging and CrowdSec evaluate Caddy's resolved client address behind Cloudflare or another load balancer.
- **Batteries-included custom Caddy** — `Dockerfile.caddy` includes the CrowdSec HTTP bouncer module and the repository Compose stack persists `/var/log/caddy`.

### Certificate cleanup in v2.20.1

- **Unused certificates are now named** — the Operations recommendation identifies affected PEM/file-path certificates and opens a filtered cleanup view with an **Unused** marker on each row.
- **No false positives for managed ACME** — standalone and wildcard certificates automated by Caddy are no longer classified as unused simply because they are not attached through a resource certificate ID.
- **Dismiss without permanent silence** — administrators can hide the recommendation for the selected environment. It returns automatically when the set of unused certificates changes.

### Enterprise workflows in v2.20

- **Guided first-run journey** — create the administrator account, verify the Caddy control plane, secure access, optionally configure DNS automation, and publish the first service through one live readiness guide.
- **Publish-service wizard** — new proxy hosts follow Hostname → Upstream → Policy → Review, with native validation and a deployment summary before anything is written to Caddy.
- **Enterprise semantic colors** — blue is action/current context, green is healthy/enabled/completed, amber is pending/degraded/maintenance, red is failure/offline/destructive, violet is TLS/automation/managed policy, and gray is disabled/unknown/informational.
- **Professional fleet operations** — Caddy environments are organized as an inventory with health, endpoint, management policy, last contact, and scoped actions; connecting a server follows Identify → Connect → Authorize.
- **Faster daily workflows** — a global Create menu, persistent environment context, consistent **Publish service** language, and a one-click advanced editor keep both new and experienced operators moving.

The guide reads real configuration state rather than a one-time “completed”
flag. DNS automation is optional and never prevents an otherwise operational
environment from reaching 100% readiness.

### Database and performance improvements in v2.19

- **MariaDB backend** — keep embedded SQLite for simple installs or connect CaddyUI to MariaDB for concurrent enterprise workloads, replication, and platform-managed backups.
- **Safe database migration** — copy an existing SQLite installation into an empty MariaDB database with a read-only, batched migration command. Large analytics histories can be intentionally skipped.
- **Faster Proxy Hosts** — request counters now use domain-scoped index lookups instead of scanning the complete analytics history, and live probes wait until after the initial browser paint.
- **Database-aware operations** — automatic schema migrations, portable sessions/retention/rollups, MariaDB-specific backup guidance, a Compose overlay, and dedicated MariaDB CI coverage.

### Enterprise operations UI in v2.18

- **Enterprise operations center** — the dashboard now leads with the active environment, route inventory, live system and upstream health, prioritized risks, fleet status, and recent configuration activity instead of a loose collection of cards.
- **Workflow-first application shell** — navigation is regrouped around Traffic, Observe, Configuration, Developer, and Administration workflows. The current Caddy environment is always visible and switching servers is faster.
- **Visible command search and primary actions** — search resources from the persistent top bar, create a proxy host, sync Caddy, or manage the fleet without hunting through menus. Read-only viewers never see the create action.
- **Shared enterprise design system** — semantic surfaces, status treatments, panels, buttons, metrics, tables, focus states, and responsive rules now provide a durable foundation for the rest of the product.
- **First-class mobile operations** — one compact mobile toolbar, responsive route/system metrics, stacked attention queues, fleet cards, and mobile host cards preserve the full operational picture without horizontal scrolling.
- **Theme and accessibility coverage** — the redesign supports light, dark, Carbon Orange, Forest, Rose, and Indigo themes, with keyboard focus visibility and reduced-motion handling.

### Certificate automation in v2.17

- **Visible Auto TLS certificate selection** — the **Caddy-managed (ACME)** table now names the managed wildcard used by each covered domain and labels uncovered hosts **Direct certificate**, so the UI no longer implies every hostname received a separate certificate. *(v2.17.3)*
- **Enforced Auto wildcard reuse** — Auto TLS suppresses redundant exact-host issuance when a managed wildcard covers the name. *(v2.17.2)*
- **Live per-server renewal status** — edit a managed certificate to inspect each server's live expiry, issuer, deployment, and renewal health. *(v2.17.2)*
- **Multi-server managed wildcard reuse** — copy managed certificate definitions to selected Caddy instances, or let proxy **Also deploy to** automatically discover and replicate a covering wildcard on each target. Every server keeps its own ACME order and private key. *(v2.17.1)*
- **Standalone managed wildcard certificates** — **Certificates → New → Managed ACME (DNS-01)** obtains and renews `*.example.com` or `*.sub.example.com` without a proxy host, pasted PEM, or exported private key. *(v2.17.0)*

See the [complete managed wildcard workflow](#managed-wildcard-certificates-v217) below.

### Earlier highlights

- **Import SSL from Porkbun** — new button on the Certificates page (visible when Porkbun credentials are saved) that opens a domain picker and pulls the SSL bundle directly from your Porkbun account into CaddyUI as a stored PEM certificate. *(v2.14.0)*
- **Porkbun API v3 full compatibility** — fixed JSON type mismatches where the Porkbun API returns integer fields (`whoisPrivacy`, `autoRenew`, `securityLock`, `apiAccess`, `notLocal`) as quoted strings; all domain and DNS decode paths now handle both forms transparently. SSL retrieve. *(v2.14.1, v2.14.2)*

- **⌘K / Ctrl+K command palette** — global search across every proxy host, redirection, raw route, and certificate. `↑/↓ Enter Esc`. Color-coded type pills. *(v2.11.5)*
- **Bulk multi-select on every list page** — checkbox + select-all + floating Enable / Disable / Delete bar on `/proxy-hosts`, `/redirection-hosts`, `/raw-routes`, and `/certificates`. *(v2.11.6, .9, .10)*
- **Drag-to-reorder rows** — HTML5 ⠿ handle on `/proxy-hosts` and `/redirection-hosts`. *(v2.11.11)*
- **Live route-JSON preview** on the proxy-host edit form — see the exact Caddy route JSON your form would push, refreshing as you type. *(v2.11.13)*
- **Multi-server health widget** on the dashboard — one card per registered Caddy server with status, host count, version, last seen. *(v2.11.16)*
- **AI assistant — bring your own backend** *(v2.11.15, v2.12.36+)* — opt-in floating chat button that answers Caddy / TLS / DNS questions and writes production-grade Caddyfile snippets on demand. Pick any backend in Settings → AI assistant: **Ollama (local)** for fully-offline on your GPU, **Ollama Cloud** for hosted MoE models that won't fit on a homelab card (qwen3-coder:480b, gpt-oss:120b, etc.), **Anthropic Claude** (Haiku 4.5 / Sonnet 4.6 / Opus 4.7), or **any OpenAI-compatible API** (also covers OpenRouter, Groq, Together, vLLM, LM Studio). Conversation memory (multi-turn), markdown rendering, and a custom system prompt setting are shared by every backend.
- **AI auto-fill — chat your hosts into existence** *(v2.12.11+)* — describe what you want in plain English (*"set up nextcloud at cloud.example.com pointing to nextcloud:80"*, *"redirect old.example.com to new.example.com permanently"*) and the assistant emits a structured `create_proxy_host(...)` / `create_redirection(...)` tool call. The chat panel renders a confirmation card with the exact arguments — click **Apply** and the resource is created, the form is filled in for you, and Caddy is auto-synced. Every AI-driven exec writes an `ai_tool_call` activity-log entry so admins can audit what the AI did. Works on Claude 4.x, GPT-4, qwen2.5+, llama3.1+, and gemma2.
- **DNS-01 certificate issuance** — select Managed DNS on a proxy, redirection, or advanced route and CaddyUI reuses that credential profile for Let's Encrypt DNS-01. Supports Cloudflare, Porkbun, Namecheap, GoDaddy, DigitalOcean, and Hetzner; the connected Caddy needs the matching `caddy-dns` plugin. Wildcards are supported. *(v2.16.7)*
- **Per-hostname DNS-record pre-flight** on multi-domain routes — checklist showing which records will be created vs already exist. *(v2.12.1)*
- **Managed DNS on redirections** — closes the long-standing gap where redirects had no DNS plumbing. Now creates A records per hostname on save, deletes on row removal. *(v2.12.2)*
- **Per-section Save buttons on Settings** — no more scroll-to-bottom for a one-toggle change. *(v2.12.6)*
- **Active-server-scoped dashboard cards** — Requests / Visitors / Bandwidth Today now reflect only the server selected in the picker, including traffic to wildcard SAN hostnames. *(v2.12.8, v2.12.9)*

### Managed wildcard certificates (v2.17+)

Use one DNS-01 wildcard across matching proxy hosts without exporting or copying its private key:

1. Go to **Settings → DNS** and save credentials for your DNS provider.
2. Go to **Certificates → New**, choose **Managed ACME (DNS-01)**, select that credential profile, and enter a subject such as `*.example.com`.
3. If you manage multiple Caddy servers, select them under **Also configure on**. Each server performs its own ACME order and keeps its own private key.
4. Leave matching proxy hosts on **Auto** TLS. CaddyUI detects the covering wildcard and prevents redundant exact-host certificate orders.
5. Edit the managed certificate later to see live deployment, issuer, expiry, and renewal health for every configured server.

Your Caddy build must include the matching `caddy-dns` provider module. The repository's [`Dockerfile.caddy`](Dockerfile.caddy) includes all six DNS providers supported by CaddyUI; the stock `caddy:2-alpine` image does not.

### Routing

- **Proxy Hosts** — point domains at upstream services with one-click TLS via Caddy's automatic HTTPS
- **Redirections** — 301/302/307/308 redirect rules across hostnames; path-based rules with `redirect_rules`; sunset-date 410 conversion; wildcard subdomain capture
- **Advanced Routes** — import raw Caddyfile blocks or write JSON directly for anything the UI can't model
- **Certificates** — upload custom PEM / path-based certificates or create standalone Caddy-managed DNS-01 wildcard certificates; expiry alerts via email or webhook
- **Managed DNS** — create the A record for a new proxy host, redirection, or advanced route without leaving CaddyUI; auto-deleted when the row is removed. The same credentials drive DNS-01 certificate issuance. Providers: **Cloudflare, DigitalOcean, Hetzner, Porkbun, GoDaddy, Namecheap**. Zone lookup is automatic from the domain.
- **Paste Caddyfile import** — convert a Caddyfile into managed proxy hosts / redirections / advanced routes; smart classifier auto-routes each block to the right table *(v2.10.7+)*. Re-classify button rescues older imports
- **Import from Caddy** — pull your existing live Caddy config into the DB on first run
- **Per-host options surface (~70 fields)** — request / response headers (X-Forwarded-*, security headers, cache hints), path-based upstream overrides, multi-upstream routing, active health checks, upstream TLS settings, request blocking (deny by path / query / user-agent / method)
- **Branded error pages** — CaddyUI-styled 404 / 502 / 503 / 504 pages are injected into Caddy automatically

### Multi-server

- **Remote Caddy management** — manage multiple Caddy instances from a single UI; switch with a dropdown. Edge hosts only need Caddy — no CaddyUI container required (see [Agent mode](#agent-mode-edge-only-caddy-no-caddyui))
- **Per-server scoping** — proxy hosts, redirections, routes, and certificates are all scoped to the active server; cross-server conflicts can't happen

### Access control

- **Three-role RBAC** — `admin` (full control), `user` (manage their own resources), `view` (read-only). Admin-only pages: Users, Groups, Settings, Caddy Servers, Snapshots
- **Per-user ownership** — proxy hosts, redirections, advanced routes, and certificates each belong to one user; only the owner (and admins) can edit or delete them. Admins can reassign ownership from any resource's edit form
- **Groups** *(v2.7.4)* — admin bundles `user`-role accounts into a team; every member sees every other member's resources in their list views (read-only), with a `Team` chip so it's clear which rows are "mine" vs. "my teammate's"
- **2FA / TOTP** — per-user time-based one-time passwords
- **Login CAPTCHA** — optional Cloudflare Turnstile or reCAPTCHA v3 gate on the login form

### Observability

- **Visitor analytics** *(v2.7.0)* — opt-in per-host traffic counters; top hosts, 24 h sparkline, status-code mix, unique visitors. Per-server filter for multi-Caddy fleets. The Caddy log writer uses soft-start failover so Caddy can boot while CaddyUI is offline
- **Upstream health** — live health check per proxy; polls Caddy's own admin API so Docker-internal hostnames work correctly
- **App health** — detects whether the upstream actually responds, not just whether its TCP port is open
- **Activity log** — every create / edit / delete / sync action is logged with actor, timestamp, and resource

### Operational

- **SQLite or MariaDB** — embedded SQLite by default; optional MariaDB backend for concurrent enterprise workloads, replication, and managed backups
- **Snapshots** — automatic and manual Caddy configuration snapshots on both backends; one-click full-file backup on SQLite
- **Email notifications** — SMTP support (STARTTLS / TLS / plain) for cert-expiry and upstream-health alerts
- **Webhook notifications** — generic JSON POST for cert-expiry (pair with any notifier that accepts webhooks)
- **Update notifications** — sidebar badge when a newer Docker Hub release is available
- **Dark mode** — toggleable, remembers your choice; system preference respected on first visit
- **PWA** — installable on desktop and mobile; offline-capable service worker

---

## AI Assistant

CaddyUI ships an opt-in chat assistant that knows the entire CaddyUI surface area — every page, every Settings field, every proxy-host form section — and can both **answer questions** about Caddy / TLS / DNS and **auto-fill new resources for you** via tool calling.

### Pick a backend

Go to **Settings → AI assistant** and choose one of:

| Backend | Best for | What you need |
|---|---|---|
| **Ollama (local)** | Fully-offline, runs on your GPU, no cloud calls | An Ollama container reachable from CaddyUI; recommended models: `qwen2.5:14b`, `qwen2.5-coder:14b`, `gemma2:9b`, `llama3.1:8b` |
| **Ollama Cloud** | Hosted MoE models that won't fit on a homelab GPU | API key from [ollama.com/settings/keys](https://ollama.com/settings/keys); models: `qwen3-coder:480b-cloud`, `gpt-oss:120b`, `deepseek-v3.1:671b` |
| **Anthropic Claude** | Strongest reasoning + Caddy knowledge out of the box | API key from [console.anthropic.com](https://console.anthropic.com); models: `claude-haiku-4-5-20251001` (fast), `claude-sonnet-4-6` (balanced), `claude-opus-4-7` (max) |
| **OpenAI-compatible** | OpenAI itself, OpenRouter, Groq, Together, self-hosted vLLM, LM Studio | Base URL + API key + model name |

Switching providers preserves the inactive providers' credentials, so you can flip back and forth without re-entering keys.

### What you can ask

**Knowledge questions** — the assistant has the full CaddyUI app map in its system prompt, so it points you at the *exact page → section → field* for whatever you're trying to do:

> *"How do I strip the X-Powered-By header globally?"*  
> → Settings → General → Globally stripped response headers.

> *"Where do I configure SSE flushing?"*  
> → Proxy host form → Timeouts → Stream flush interval ms (use `-1`).

**Caddyfile help** — production-grade snippets, not 3-line stubs. The default system prompt steers the model toward `encode zstd gzip` + path blocking + security headers + the `X-Forwarded-*` trio. Strip back to minimum only when you ask for *"just the basics"*.

### AI auto-fill (tool calling)

Describe what you want and the assistant calls a tool to create it:

> *"Set up nextcloud at cloud.example.com pointing to nextcloud:80 with auto-SSL"*  
> → emits `create_proxy_host(domains="cloud.example.com", forward_host="nextcloud", forward_port=80, ssl_enabled=true, ssl_forced=true)`.

The chat panel renders a **confirmation card** with the exact arguments. You click **Apply** and CaddyUI:

1. Creates the proxy host (or redirection).
2. Auto-syncs Caddy with the new config.
3. Writes an `ai_tool_call` row to the activity log so admins can see exactly what happened.

Tools currently available:

- `create_proxy_host(domains, forward_scheme, forward_host, forward_port, ssl_enabled, ssl_forced)`
- `create_redirection(domains, forward_scheme, forward_domain, forward_http_code, preserve_path)`

Models with native tool support — Claude 4.x, GPT-4 / GPT-4o, qwen2.5+, llama3.1+, gemma2 — will use these. Older or smaller models silently ignore the tools field and just chat.

### Custom system prompt

If you want a different persona, in-house naming conventions, or a leaner / chattier voice, paste your own steering text into **Settings → AI assistant → Custom system prompt**. Leaving it blank uses the built-in default that has the full CaddyUI knowledge map and the production-grade Caddyfile examples.

### Privacy

API keys are stored in CaddyUI's selected database. The Settings UI never renders saved keys back to the form (a `••••••••` placeholder shows when one is set; leave the field blank to keep the existing key). Local Ollama means the conversation never leaves your machine; cloud backends send the conversation to your chosen provider per their respective terms.

### Community integrations

- [CaddyUI-MCP](https://github.com/loryanstrant/CaddyUI-MCP) — a community-maintained MCP server that wraps CaddyUI's `/api/v1` REST API for agent-driven automation. `GET /api/v1/servers` supplies the fleet ID/name/type mapping integrations need without scraping HTML. Use a dedicated CaddyUI user and the narrowest API token scope that fits your workflow.

---

## Quick Start

### Docker Compose (recommended)

```yaml
services:
  caddy:
    image: caddy:2-alpine
    container_name: caddyui-caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - caddy_data:/data
      - caddy_config:/config
    environment:
      CADDY_ADMIN: 0.0.0.0:2019
    command: >-
      mkdir -p /config/caddy;
      [ -f /config/caddy/autosave.json ] || echo '{}' > /config/caddy/autosave.json;
      exec caddy run --config /config/caddy/autosave.json --resume --adapter json
    networks:
      - caddyui

  caddyui:
    image: applegater/caddyui:latest
    container_name: caddyui
    restart: unless-stopped
    depends_on:
      - caddy
    ports:
      - "8081:8080"
    volumes:
      - caddyui_data:/data
    environment:
      CADDYUI_DB: /data/caddyui.db
      CADDYUI_LISTEN: :8080
      CADDY_ADMIN_URL: http://caddy:2019
    networks:
      - caddyui

volumes:
  caddy_data:
  caddy_config:
  caddyui_data:

networks:
  caddyui:
    driver: bridge
```

> **💡 Fresh install:** On first boot Caddy has no saved config yet and would crash-loop without one. The `command` above seeds an empty `{}` config automatically on first start — you don’t need to do anything extra.

Open **http://localhost:8081** and complete the first-run setup (create an admin account).

### Docker Run (standalone)

```bash
docker run -d \
  --name caddyui \
  -p 8081:8080 \
  -v caddyui_data:/data \
  -e CADDY_ADMIN_URL=http://your-caddy-host:2019 \
  applegater/caddyui:latest
```

### MariaDB (optional enterprise backend)

SQLite remains the zero-configuration default. MariaDB is available for larger
installations that need concurrent UI reads, continuous analytics ingestion,
database replication, or platform-managed backups.

Use the included Compose overlay:

```bash
export CADDYUI_MARIADB_PASSWORD='replace-with-a-long-random-password'
export CADDYUI_MARIADB_ROOT_PASSWORD='replace-with-a-different-random-password'
docker compose -f docker-compose.yml -f docker-compose.mariadb.yml up -d
```

For an existing MariaDB server, configure CaddyUI directly:

```yaml
environment:
  CADDYUI_DB_DRIVER: mariadb
  CADDYUI_DB_DSN: caddyui:password@tcp(mariadb.example.internal:3306)/caddyui
```

Create the database and user before starting CaddyUI. CaddyUI creates and
migrates its tables automatically. The DSN is never written to application
logs.

To copy an existing SQLite installation, first create a timestamped copy of
`caddyui.db`, stop the normal CaddyUI container, start the empty MariaDB
service, and run:

```bash
docker compose -f docker-compose.yml -f docker-compose.mariadb.yml up -d mariadb
docker compose -f docker-compose.yml -f docker-compose.mariadb.yml run --rm --no-deps \
  caddyui migrate-db \
  --from-sqlite /data/caddyui.db
docker compose -f docker-compose.yml -f docker-compose.mariadb.yml up -d
```

The source SQLite file is opened read-only and the MariaDB destination must be
empty. Add `--skip-analytics` to migrate configuration, users, certificates,
health history, and activity while leaving large `access_events` and
`access_daily` tables behind. This is strongly recommended when the SQLite
database grew primarily because of visitor analytics.

MariaDB backups are managed with `mariadb-dump`, snapshots, or your database
platform's backup/PITR tooling. Caddy configuration snapshots inside CaddyUI
continue to work on both backends.

### Non-Docker systemd install

Tagged GitHub releases include `linux/amd64` and `linux/arm64` tarballs with
the `caddyui` binary and a sample `caddyui.service` unit. This is useful for
LXC/Proxmox labs, VMs, or hosts where you prefer to run CaddyUI directly under
systemd.

1. Install Caddy separately and make sure its admin API is reachable from the
   CaddyUI host. For a same-host install the default is
   `http://127.0.0.1:2019`.
2. Download the archive for your CPU architecture from the
   [latest GitHub release](https://github.com/X4Applegate/caddyui/releases).
3. Extract the archive and run the packaged installer:

```bash
tar -xvf ./caddyui_vX.Y.Z_linux_ARCH.tar.gz
cd caddyui_vX.Y.Z_linux_ARCH
./install.sh
```

The packaged service stores SQLite data at `/var/lib/caddyui/caddyui.db`,
listens on `127.0.0.1:8080`, talks to Caddy at `http://127.0.0.1:2019`, and
binds the optional visitor-analytics ingest listener to `127.0.0.1:9019`. The
ingest listener only matters if you enable CaddyUI visitor analytics; set
`CADDYUI_INGEST_LISTEN=` in a systemd drop-in to disable it. Override these
values if your Caddy admin API is on another host:

```bash
sudo systemctl edit caddyui
```

```ini
[Service]
Environment=CADDYUI_LISTEN=0.0.0.0:8080
Environment=CADDY_ADMIN_URL=http://10.8.0.2:2019
# Optional: disable visitor-analytics ingest if you do not use analytics.
Environment=CADDYUI_INGEST_LISTEN=
```

Then restart:

```bash
sudo systemctl restart caddyui
```

### Agent mode (edge-only Caddy, no CaddyUI)

For multi-host setups you only need **one** CaddyUI container. Every other
host — the "agent" or "edge" nodes — runs only Caddy, and the central CaddyUI
manages them remotely through Caddy's admin API (typically tunneled over
WireGuard or Tailscale).

On each edge host:

```yaml
services:
  caddy:
    image: caddy:2-alpine
    container_name: caddy
    restart: unless-stopped
    # --resume is required so admin-API pushes persist across Caddy restarts.
    command: >-
      mkdir -p /config/caddy;
      [ -f /config/caddy/autosave.json ] || echo '{}' > /config/caddy/autosave.json;
      exec caddy run --config /config/caddy/autosave.json --resume --adapter json
    ports:
      # Bind the admin API to your private tunnel IP (WireGuard / Tailscale).
      # Do NOT expose :2019 on a public interface.
      - "10.8.0.2:2019:2019"
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - caddy_data:/data
      - caddy_config:/config

volumes:
  caddy_data:
  caddy_config:
```

Then in the central CaddyUI, go to **System → Caddy Servers → Add Server** and
point it at `http://10.8.0.2:2019` (or whatever private address the edge listens
on). All proxy hosts, certificates, and routes for that edge are managed from
the central UI — no database, no UI container, no extra port to expose on the
edge.

> **Why `--resume`?** In default mode Caddy loads only the Caddyfile at boot
> and discards anything pushed to the admin API. With `--resume` Caddy boots
> from `autosave.json` (the last live config it received via the admin API),
> so CaddyUI's pushes survive `docker compose restart`.
>
> **Fresh install:** On first boot no `autosave.json` exists yet, so Caddy would
> crash-loop. The `command` above seeds an empty `{}` config on first start so
> Caddy comes up cleanly without any extra steps.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CADDYUI_DB_DRIVER` | `sqlite` | Database backend: `sqlite` or `mariadb` |
| `CADDYUI_DB` | `/data/caddyui.db` | Path to the SQLite database |
| `CADDYUI_DB_DSN` | *(unset)* | MariaDB DSN; required when `CADDYUI_DB_DRIVER=mariadb` |
| `CADDYUI_LISTEN` | `:8080` | Listen address |
| `CADDY_ADMIN_URL` | `http://caddy:2019` | Caddy admin API base URL |
| `CADDYFILE_PATH` | `/etc/caddy/Caddyfile` | Path to Caddyfile (optional) |
| `CADDYUI_SYNC_ON_START` | *(unset)* | Set to `1` to push DB state to Caddy on startup |

---

## Configuration

All configuration is done through the web UI. No config files needed beyond the environment variables above.

### First Run

1. Open the UI at your configured port.
2. Create the first administrator account in the account setup wizard.
3. Continue into **Getting Started**, which checks the real state of the selected environment.
4. Verify the bootstrap Caddy connection created from `CADDY_ADMIN_URL`.
5. Enable administrator TOTP and save the recovery codes.
6. Add DNS credentials only when you need managed records or DNS-01/wildcard certificates.
7. Select **Publish a service** and complete Hostname → Upstream → Policy → Review.

Add additional Caddy environments under **Administration → Caddy Fleet**.
The readiness guide stays available after setup, so it can be used as an
operational checklist whenever the environment changes.

### SMTP Notifications

Configure under **Administration → Settings → Email (SMTP)**:

- Supports STARTTLS (port 587), implicit TLS (port 465), and plain (port 25)
- Cert-expiry emails fire once per 24 h per domain when within the configured threshold
- Upstream health emails fire on state change (healthy → down, down → recovered), checked every 5 minutes

### Multi-Server

Add additional Caddy instances under **Administration → Caddy Fleet**. Switch the active environment with the selector in the application shell. All proxy hosts, redirections, routes, and certificates are scoped per server.

To deploy the selected environment's complete managed routing configuration to another Caddy, choose **Sync from current** on the target fleet row. The sync is a non-destructive merge: it creates missing proxy hosts, redirects, advanced routes, and managed certificate definitions; updates resources paired by earlier deployments; and leaves target-only resources in place. Target DNS records, custom certificate selections, ACME private keys, and uploaded private keys remain server-specific. Repeating either a full sync or an individual form's **Also deploy to** action is idempotent and does not create duplicate routes.

Edge / remote hosts do **not** need to run a CaddyUI container — just Caddy with its admin API reachable over a private network (WireGuard, Tailscale, VPC). See [Agent mode](#agent-mode-edge-only-caddy-no-caddyui) for the minimal compose file.

---

## Building from Source

CaddyUI can be built and run directly on Linux without Docker. Install Caddy
separately first, then make sure its admin API is reachable from the CaddyUI
host. For same-host installs, Caddy's default admin endpoint is usually
`http://127.0.0.1:2019`.

Install Go 1.25 or newer, then build:

```bash
git clone https://github.com/X4Applegate/caddyui.git
cd caddyui
git checkout "$(git tag --sort=-v:refname | head -n1)"
version="$(git describe --tags --always --dirty)"
CGO_ENABLED=0 go build \
  -trimpath \
  -ldflags "-s -w -X main.Version=${version}" \
  -o caddyui \
  ./cmd/caddyui
```

To test it before installing:

```bash
mkdir -p ./data
CADDYUI_DB="$PWD/data/caddyui.db" \
CADDYUI_LISTEN=127.0.0.1:8080 \
CADDY_ADMIN_URL=http://127.0.0.1:2019 \
CADDYUI_INGEST_LISTEN=127.0.0.1:9019 \
./caddyui
```

Open `http://127.0.0.1:8080` and complete the first-run setup.

To install your locally built binary as a systemd service:

```bash
id -u caddyui >/dev/null 2>&1 || sudo useradd --system --home /var/lib/caddyui --shell /usr/sbin/nologin caddyui
sudo install -d -o caddyui -g caddyui -m 0750 /var/lib/caddyui
sudo install -m 0755 caddyui /usr/local/bin/caddyui
sudo install -m 0644 packaging/systemd/caddyui.service /etc/systemd/system/caddyui.service
sudo systemctl daemon-reload
sudo systemctl enable --now caddyui
```

### Docker Build

```bash
docker build --build-arg VERSION=v1.0.0 -t caddyui:v1.0.0 .
```

### Dependencies

- [Go 1.25+](https://go.dev/)
- [Caddy 2.x](https://caddyserver.com/) with the admin API enabled (default)
- No external database required — embedded SQLite is the default; MariaDB is optional

---

## Architecture

```
cmd/caddyui/        Entry point, env config, startup
internal/
  auth/             Session, password hashing, TOTP
  caddy/            Admin API client, Caddyfile parser, importer
  db/               SQLite/MariaDB init, migrations, and data migration
  models/           Data types and DB queries
  server/           HTTP handlers, routes, notifiers, health poller
web/
  templates/        Go html/template pages
  static/           CSS, icons, PWA manifest & service worker
```

CaddyUI stores state in SQLite by default or MariaDB when configured. It communicates with Caddy exclusively through Caddy's HTTP admin API — no SSH and no direct Caddy configuration-file manipulation.

---

## Upgrading

1. Pull the new image tag from Docker Hub.
2. Recreate the container (Portainer: **Recreate** → enable **Re-pull image**; CLI: `docker compose pull && docker compose up -d`).
3. Database migrations run automatically on startup.
4. Check the [CHANGELOG](CHANGELOG.md) for any breaking changes.

---

## AI Assistance Disclosure

This project is developed with assistance from **Claude (Anthropic)**. Claude helps with debugging, feature implementation, code review, and documentation. All code is reviewed and tested by the project maintainer before release.

Bug reports and issues are triaged by the maintainer with Claude's assistance. If you find a bug, please open an issue — it will be looked at.

> **Note on privacy:** No proprietary code, credentials, database contents, or user data are ever shared with Claude. Only code structure and logic are discussed.

---

## License

[CaddyUI Source Available License 1.0](LICENSE)

- **Free** for personal use — homelab, home server, VPS, or any individual self-hosting.
- **Free** for non-profits, educational institutions, and small businesses (< 50 employees and < $5M revenue).
- **Free** for any organization using it internally (not reselling it).
- **Commercial license required** to offer CaddyUI as a hosted/managed service.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
