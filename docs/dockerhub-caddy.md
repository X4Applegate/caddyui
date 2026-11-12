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

The base is the official `caddy:alpine` image; the current build ships **Caddy 2.11.8**.

## Tags

| Tag | Meaning |
|---|---|
| `:vX.Y.Z` | The CaddyUI release that last changed this image: its module set, Caddy version or a security fix. Recommended for production. |
| `:vX.Y.Z-pN` | Base-layer refresh **N** of that release — same Caddy build, newer Alpine layer. Immutable. |
| `:stable` | The newest build, i.e. the highest `-pN` of the newest `vX.Y.Z`. |
| `:latest` | Kept in lockstep with `:stable`. |

The image is **not rebuilt on every CaddyUI release** — only when its modules, Caddy version or security fixes change — so a plugin never changes under you silently.

## Base-layer refreshes: `:vX.Y.Z-pN`

This image's final stage runs `apk upgrade --no-cache`, so it ships Alpine security fixes the upstream `caddy:*-alpine` base has not been rebuilt for yet. Those fixes only reach you when something rebuilds the image — and a release rebuilds it only when `Dockerfile.caddy` changes, which is the right rule for the plugin set but lets the OS layer go stale between releases.

A scheduled job therefore rebuilds and re-scans this image weekly. When a rebuild closes vulnerabilities and introduces none, it is published as `:vX.Y.Z-pN`, and `:stable`/`:latest` move to it.

**`-pN` means exactly one thing: only the base OS layer moved.** `v2.68.8-p3` is `v2.68.8`'s Caddy build on a newer Alpine layer — no Caddy upgrade, no plugin change, nothing to re-test at the application level. `N` counts up from 1 and is never reused.

That is enforced, not assumed: before publishing, the pipeline diffs `caddy list-modules --versions` between the published image and the rebuild and refuses to publish on any difference. This matters because several plugin versions here are deliberately unpinned, so a rebuild *could* otherwise pick up a new DNS provider or WAF release; a plugin change has to go through a normal release instead, where it gets a version number and a CHANGELOG entry. You can check it yourself:

```sh
docker run --rm --entrypoint /usr/bin/caddy applegater/caddyui-caddy:stable list-modules --versions
```

Because `apk upgrade` is unpinned — that is how the image picks up fixes at all — two builds of the same source a week apart produce different images. So a tag names exactly one artifact and `:vX.Y.Z-pN` never changes under you, but the image is **not** bit-for-bit rebuildable from `Dockerfile.caddy` alone. Pin a digest if you need byte-level certainty:

```yaml
image: applegater/caddyui-caddy:v2.68.8-p2
# or, strictest:
image: applegater/caddyui-caddy@sha256:…
```

Every refresh is gated on a human review before it is published, and a rebuild that *introduces* a vulnerability — or that changes the Caddy module set — is blocked rather than shipped.

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
