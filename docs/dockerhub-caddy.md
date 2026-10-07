<!--
Source of truth for the Docker Hub repository overview at
https://hub.docker.com/r/applegater/caddyui-caddy

Everything below this comment is published verbatim as the Hub "full
description". Edit here first, then publish with the "Publish Docker Hub
overview" workflow (target: caddyui-caddy). The leading HTML comment is stripped.

short-description: Caddy with DNS-01 providers, CrowdSec, rate limiting and layer4 — the companion image for CaddyUI.
-->
# CaddyUI Caddy

A prebuilt **[Caddy](https://caddyserver.com/)** for use with **[CaddyUI](https://hub.docker.com/r/applegater/caddyui)**: stock Caddy plus the modules CaddyUI's features need, so you don't have to build one with `xcaddy` yourself. Multi-arch: `linux/amd64` and `linux/arm64`. Built from [`Dockerfile.caddy`](https://github.com/X4Applegate/caddyui/blob/main/Dockerfile.caddy) in the CaddyUI repository.

## What's included

| Module | Used for |
|---|---|
| [`caddy-dns`](https://github.com/caddy-dns) — Cloudflare, Porkbun, Namecheap, GoDaddy, DigitalOcean, Hetzner, Route 53, Gandi | ACME DNS-01 challenges and wildcard certificates, and CaddyUI's managed DNS |
| [`caddy-crowdsec-bouncer`](https://github.com/hslatman/caddy-crowdsec-bouncer) (HTTP) | CrowdSec IP blocking |
| [`caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit) | CaddyUI's per-host rate limiting |
| [`caddy-l4`](https://github.com/mholt/caddy-l4) | TCP/UDP routing, and sharing port 443/80 with other protocols (CaddyUI's Layer4 proxies) |
| [`coraza-caddy`](https://github.com/corazawaf/coraza-caddy) | Coraza web application firewall with the OWASP Core Rule Set (CaddyUI's middleware profiles, **v2.61.0+**) |

The base is the official `caddy:alpine` image; the current build ships **Caddy 2.11.7**.

## Tags

| Tag | Meaning |
|---|---|
| `:vX.Y.Z` | The CaddyUI release that last changed this image's module set or Caddy version. Recommended for production. |
| `:stable` | The newest build. |
| `:latest` | Kept in lockstep with `:stable`. |

The image is **not rebuilt on every CaddyUI release** — only when its modules or Caddy version change — so a plugin never changes under you silently.

## Quick start

```yaml
services:
  caddy:
    image: applegater/caddyui-caddy:stable
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      - "127.0.0.1:2019:2019"   # admin API — keep it private
    volumes:
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
```

Point CaddyUI at it with `CADDY_ADMIN_URL=http://caddy:2019`. See the [CaddyUI image](https://hub.docker.com/r/applegater/caddyui) for the full compose stack.

**Never expose the admin API (port 2019) to the internet** — it can rewrite Caddy's whole configuration.

## Links

- CaddyUI on GitHub: https://github.com/X4Applegate/caddyui
- Release notes: https://github.com/X4Applegate/caddyui/releases
- Licence: Apache-2.0
