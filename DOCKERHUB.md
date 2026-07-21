# CaddyUI

A modern, self-hosted web UI for [Caddy](https://caddyserver.com/) — manage proxy hosts, redirections, SSL certificates, and advanced routes through a clean interface, without touching config files.

**Lighthouse:** Performance **99** · Accessibility **100** · Best Practices **100** · SEO **100**
*(measured on `/login` from Google's PageSpeed Insights — `:v2.12.53` and later)*

[GitHub](https://github.com/X4Applegate/caddyui) · [Issues](https://github.com/X4Applegate/caddyui/issues) · [CHANGELOG](https://github.com/X4Applegate/caddyui/blob/main/CHANGELOG.md) · [Releases](https://github.com/X4Applegate/caddyui/releases)

---

## 🚀 Quick start

```bash
docker pull applegater/caddyui:latest
```

### Docker Compose

```yaml
services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports: ["80:80", "443:443", "443:443/udp"]
    volumes:
      - caddy_data:/data
      - caddy_config:/config
    environment:
      CADDY_ADMIN: 0.0.0.0:2019
    command: >-
      mkdir -p /config/caddy;
      [ -f /config/caddy/autosave.json ] || echo '{}' > /config/caddy/autosave.json;
      exec caddy run --config /config/caddy/autosave.json --resume --adapter json

  caddyui:
    image: applegater/caddyui:latest
    restart: unless-stopped
    ports: ["8080:8080"]
    volumes:
      - caddyui_data:/data    # named volume — no chown needed
    environment:
      CADDY_ADMIN_URL: http://caddy:2019

volumes:
  caddy_data:
  caddy_config:
  caddyui_data:
```

> **💡 Fresh install:** On first boot Caddy has no saved config yet. The `command` above seeds an empty `{}` config automatically so Caddy starts cleanly without any extra steps. Without `--resume`, admin-API pushes from CaddyUI would be lost on every `docker compose restart`.

### Bind-mount note

If you bind-mount a host directory to `/data` instead of using a named volume, the host directory must be owned by uid `10001` (the non-root user the container runs as):

```bash
sudo chown 10001:10001 /path/to/caddyui_data
```

The container will print a clear error message at startup if the directory isn't writable.

---

## ✨ Headline features

### 🏆 Perfect Lighthouse score

After an eleven-version perf + a11y wave (v2.12.38 → v2.12.48), CaddyUI's `/login` page hits **99/100/100/100** on Google PageSpeed Insights against a residential-ISP install:

- **FCP 0.5 s · LCP 0.9 s · TBT 0 ms · CLS 0.001** (desktop)
- Self-hosted Inter font + htmx + auth.css for unauth pages — zero external CDN dependencies on cold loads where it matters
- Service worker rewrite that auto-purges stale caches per release (no more "feels broken after upgrade")
- Externalized inline JS to `/static/app.js` so it caches across navigations
- Cloudflare Turnstile support out of the box (replaces Google reCAPTCHA — drops ~3 s of mobile JS exec)
- Skip-to-main-content link, `aria-current` nav, label↔input pairing across every form

### 🤖 AI assistant — bring your own backend

Opt-in floating chat button that answers Caddy / TLS / DNS questions and writes production-grade Caddyfile snippets. Pick any backend in **Settings → AI assistant**:

| Backend | Best for | What you need |
|---|---|---|
| **Ollama (local)** | Fully-offline, runs on your GPU | Reachable Ollama; recommended `qwen2.5:14b` / `gemma2:9b` |
| **Ollama Cloud** | MoE models that won't fit on a homelab GPU | API key from [ollama.com/settings/keys](https://ollama.com/settings/keys) |
| **Anthropic Claude** | Strongest Caddy reasoning out of the box | API key from [console.anthropic.com](https://console.anthropic.com); Haiku 4.5 / Sonnet 4.6 / Opus 4.7 |
| **OpenAI-compatible** | OpenAI itself + OpenRouter, Groq, Together, vLLM, LM Studio | Base URL + API key + model |

**AI auto-fill** — describe what you want in natural language (*"set up nextcloud at cloud.example.com pointing to nextcloud:80 with auto-SSL"*) and the assistant emits a `create_proxy_host` / `create_redirection` tool call. Click Apply on the confirmation card and the resource is created, the form is filled in for you, and Caddy is auto-synced. Every AI-driven exec writes an `ai_tool_call` activity-log entry. Works on Claude 4.x, GPT-4, qwen2.5+, llama3.1+, gemma2.

### 📤 Caddyfile export — round-trip with the existing import

Inverse of CaddyUI's existing `/caddyfile-import` paste flow. Click **Export Caddyfile** on `/proxy-hosts` to download every enabled proxy host, redirection, and raw route on the active server as a single Caddyfile snapshot:

```
example.com {
    @blocked path /.env* /wp-admin* /wp-login* /phpmyadmin* /.git/* /xmlrpc.php
    respond @blocked 403
    encode zstd gzip
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        ...
    }
    reverse_proxy backend:8080 {
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Real-IP {remote_host}
    }
}
```

Per-host `# Notes:` block lists settings that don't fit cleanly into Caddyfile syntax (maintenance windows, basic-auth users, etc.) so users see what was elided rather than silently losing it on round-trip. Stable sort by hostname so two exports of the same DB diff cleanly. Same RBAC scoping as the existing JSON exports — admin gets the full server config, non-admin only their own resources.

Per-host export also available from the proxy-host edit page.

---

## 🛡️ Other features at a glance

- **⌘K command palette** — global resource search across every proxy host, redirection, raw route, certificate
- **Bulk multi-select + drag-to-reorder** on every list page
- **Wildcard DNS-01 cert auto-issuance** — type `*.example.com` in Domains and CaddyUI emits the matching `tls.automation.policies` using your stored Cloudflare token
- **Managed DNS** for Cloudflare, DigitalOcean, Hetzner, Porkbun, GoDaddy, Namecheap — auto-creates A records on save
- **Multi-server fleet management** — manage multiple Caddy instances from one UI; switch with a dropdown
- **Three-role RBAC** — admin / user / view, with per-user resource ownership and group-based shared visibility
- **2FA / TOTP**, login CAPTCHA (Turnstile or reCAPTCHA), session management
- **Snapshots** — one-click DB backup, auto-snapshot on sync
- **Notifications** — email (SMTP), webhook, [ntfy.sh](https://ntfy.sh) for cert-expiry + upstream-health alerts
- **Visitor analytics** — opt-in per-host traffic counters, top hosts, status-code mix, 24 h sparkline
- **Carbon Orange theme** — alternative palette with cross-device sync via per-user DB column
- **PWA** — installable on desktop and mobile; offline-capable service worker

---

## 🏷️ Image tags

| Tag | What it points at |
|---|---|
| `:vX.Y.Z` | Specific release, immutable. Recommended for production. |
| `:latest` | Rolling — retagged at significant feature waves. Currently `v2.15.3`. |
| `:stable` | Alias of `:latest`. |
| `:preview` | Rolling dev push — every commit to main. Test with this before pinning. |

Multi-arch: `linux/amd64` + `linux/arm64`. Scratch base image, runs as non-root uid `10001`.

---

## 🔧 Configuration

| Environment variable | Default | Purpose |
|---|---|---|
| `CADDY_ADMIN_URL` | `http://caddy:2019` | Caddy's admin API (the docker service name in the same compose network) |
| `CADDYUI_DB` | `/data/caddyui.db` | SQLite database path |
| `CADDYUI_LISTEN` | `:8080` | HTTP listen address |
| `CADDYUI_INGEST_LISTEN` | `:9019` | Visitor-analytics TCP ingest from Caddy's `net` log writer (empty string disables) |
| `CADDYFILE_PATH` | `/etc/caddy/Caddyfile` | Optional — only read if you mount a Caddyfile into the CaddyUI container for the paste-import auto-classifier reference |
| `CADDY_ADMIN_USER` / `CADDY_ADMIN_PASS` | (none) | Optional HTTP basic auth for Caddy's admin endpoint when proxied |

---

## 📜 License

[CaddyUI Source Available License 1.0](https://github.com/X4Applegate/caddyui/blob/main/LICENSE)

Free for personal use, non-profits, educational institutions, small businesses (<50 employees, <$5M revenue), and any organization using it internally. Commercial license required to offer CaddyUI as a hosted/managed service.

---

## 🐛 Found a bug?

Open an issue on GitHub: https://github.com/X4Applegate/caddyui/issues

— Richard
