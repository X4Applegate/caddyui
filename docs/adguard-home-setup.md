# AdGuard Home behind CaddyUI — step-by-step

End state: encrypted DNS (DoH, DoT, DoQ) for every device on your network, per-device filtering via ClientID, a single wildcard cert covering every `<device>.dns.yourdomain.com` name you'll ever use. Everything runs on the same box that already runs Caddy + CaddyUI.

This is the exact recipe from the v2.5.10 blog post, written as a copy-paste runbook. Substitute `dns.richardapplegate.io` for your own `dns.yourdomain.com` everywhere.

---

## What you'll end up with

| Endpoint | Port | Handled by |
|---|---|---|
| DoH — `https://phone.dns.yourdomain.com/dns-query` | 443/tcp | Caddy → AdGuard |
| DoT — `phone.dns.yourdomain.com:853` | 853/tcp | AdGuard (direct) |
| DoQ — `phone.dns.yourdomain.com:784` | 784/udp | AdGuard (direct) |
| Plain DNS (LAN) | 53/udp+tcp | AdGuard |
| Admin UI — `https://dns.yourdomain.com/` | 443/tcp | Caddy → AdGuard |

One wildcard cert (`*.dns.yourdomain.com` + `dns.yourdomain.com`) covers all of them.

---

## Prerequisites

- CaddyUI stack already running, with Caddy exposing 80+443 to the internet.
- A domain at Cloudflare (other providers work; the Caddyfile snippet below uses the `cloudflare` DNS-01 plugin).
- Cloudflare API token with **Zone · DNS · Edit** scoped to the zone. The CaddyUI Settings page validates it for you.
- Portainer installed — if you run `docker compose` directly instead, the stack YAML below still works, just `docker compose up -d` it from its own directory.
- A host path where AdGuard's state can live. I use `/mnt/1TB/adguard/{work,conf}` — use anything persistent.
- The Caddy data volume on the host filesystem (bind mount or a named volume you can read-only share). I use `/mnt/1TB/caddy/caddy_data`. If you're on the default named volume, see the [Named-volume footnote](#named-volume-footnote) at the bottom.

---

## Step 1 — Add the DNS records at Cloudflare

Two A records, both pointing at your server's public IP:

| Name | Type | Content |
|---|---|---|
| `dns` | A | `<your server IP>` |
| `*.dns` | A | `<your server IP>` |

**Keep the orange cloud OFF.** DoT/DoQ run on ports 853/784 — Cloudflare's proxy only passes 443, so proxying would break those protocols.

You can add these by hand in the Cloudflare dashboard, or let CaddyUI do it when you save the proxy host in Step 2 (Managed DNS → Cloudflare → pick the zone).

---

## Step 2 — Paste the Caddy site block into CaddyUI

Open CaddyUI → **Caddyfile Import** → paste:

```caddyfile
*.dns.richardapplegate.io, dns.richardapplegate.io {
  tls {
    dns cloudflare {env.CF_API_TOKEN}
  }

  reverse_proxy http://adguardhome:8080
}
```

Click Import. CaddyUI will:

1. Create one proxy-host row with both domains.
2. If Cloudflare is configured in Settings, create the A records for you.
3. Push the route to Caddy.
4. Caddy starts the DNS-01 challenge in the background.

Watch the **Deploying** page — within 30–60 seconds you'll see `cert_ok: true`. That means Let's Encrypt issued the wildcard and Caddy stored it.

> **Why `adguardhome:8080`?** AdGuard Home's admin UI *and* its DoH endpoint both live on port 8080 inside the container when `allow_unencrypted_doh: true` is set (see Step 5). One `reverse_proxy` handles everything — admin UI, `/dns-query`, per-device paths.

> **Gotcha.** A wildcard matches one label — `*.dns.yourdomain.com` covers `phone.dns.yourdomain.com` but NOT bare `dns.yourdomain.com`. The apex SAN in the site block (`dns.richardapplegate.io` after the comma) is what makes the single cert cover both.

---

## Step 3 — Free port 53 on the host

Most Linux distros ship with `systemd-resolved` listening on `127.0.0.53:53`, which occupies the DNS port AdGuard needs. If you skip this step, the stack in Step 4 will fail with `bind: address already in use`. Check first:

```bash
sudo ss -tulpn | grep ':53 '
```

If you see a line with `systemd-resolve` or `systemd-resolved`, it's in the way. Fix it:

**1. Disable the stub listener and point the OS at AdGuard**

Edit `/etc/systemd/resolved.conf` (use `sudo nano` or your editor of choice) and set these keys — uncomment if they already exist:

```ini
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
```

`DNS=127.0.0.1` tells the OS itself to resolve via AdGuard once AdGuard is running; `DNSStubListener=no` stops systemd-resolved from binding port 53.

**2. Replace the `/etc/resolv.conf` symlink**

By default `/etc/resolv.conf` points at systemd-resolved's stub. With the stub off, that symlink is dead. Repoint it at the real resolver:

```bash
sudo rm /etc/resolv.conf
sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
```

**3. Restart the service**

```bash
sudo systemctl restart systemd-resolved
```

**4. Verify port 53 is free**

```bash
sudo ss -tulpn | grep ':53 '
```

Output should be empty now. If anything else shows up (`dnsmasq`, `named`, `bind9`, `pihole`, …), stop and disable that service before continuing:

```bash
# Replace <service> with whatever the grep showed
sudo systemctl stop <service>
sudo systemctl disable <service>
```

> **Don't skip the symlink step.** If you turn off the stub listener without repointing `/etc/resolv.conf`, the host loses DNS entirely until AdGuard starts in Step 4 — `apt`, `curl`, `docker pull`, everything. If that happens, temporarily set `/etc/resolv.conf` to a single line `nameserver 1.1.1.1` to dig yourself out.

Other hosts:

- **Raspberry Pi OS** — `dnsmasq` sometimes runs by default. Check with the `ss` command above; disable the same way.
- **Synology NAS** — port 53 is occupied by the DNS Server package if it's installed. Uninstall DSM's DNS Server (Control Panel → Package Center).
- **Pi-hole** — either migrate to AdGuard (remove Pi-hole first) or run both on different IPs; you can't share port 53.

---

## Step 4 — Deploy the AdGuard Home Portainer stack

**Portainer → Stacks → Add stack →** paste this YAML:

```yaml
services:
  adguardhome:
    image: adguard/adguardhome:v0.107.56
    container_name: adguardhome
    restart: unless-stopped
    ports:
      # Plain DNS — must be reachable on the host for LAN clients
      - "53:53/tcp"
      - "53:53/udp"
      # DoT + DoQ — direct to AdGuard, NOT proxied through Caddy
      - "853:853/tcp"
      - "784:784/udp"
    environment:
      TZ: America/Los_Angeles
    volumes:
      - /mnt/1TB/adguard/work:/opt/adguardhome/work
      - /mnt/1TB/adguard/conf:/opt/adguardhome/conf
      # Read-only mount of Caddy's data dir so AdGuard can read the
      # wildcard cert Caddy already issued for us. Path under /caddy-certs
      # is identical to the layout inside Caddy's container.
      - /mnt/1TB/caddy/caddy_data:/caddy-certs:ro
    networks:
      - caddy-and-ui_caddy_net

networks:
  caddy-and-ui_caddy_net:
    external: true
```

Adjust:

- `TZ` to your timezone (must match what Caddy uses, otherwise log timestamps drift).
- `image` tag — pin a version. `:latest` will eventually eat a breaking change overnight.
- Host paths on the left side of each `volumes` entry.
- Network name — Portainer names networks `<stack-name>_<network-name>`. Check **Networks** in Portainer; mine is `caddy-and-ui_caddy_net` because my CaddyUI stack is named `caddy-and-ui` with network `caddy_net` in the compose file.

Click **Deploy the stack**. AdGuard boots. The first time you hit `http://<server>:8080` you get AdGuard's setup wizard.

---

## Step 5 — First-run wizard

Open `http://<your-server-IP>:3000` (AdGuard's wizard port, only for first boot) — or if the Caddy route is already live, `https://dns.yourdomain.com/` also works.

Click through:

1. **Admin interface** — accept port 8080 (not 80, which is Caddy's).
2. **DNS server** — accept 53 on all interfaces.
3. **Username + password** — set a strong one. This is the web-admin login, unrelated to DNS auth.
4. **Finish.**

After the wizard, AdGuard is running with plain DNS only. Encrypted DNS needs the TLS block from Step 5.

---

## Step 6 — Drop in the TLS block

SSH to the host and edit `/mnt/1TB/adguard/conf/AdGuardHome.yaml`. Find the existing `tls:` block (the wizard wrote a disabled stub) and replace it with:

```yaml
tls:
  enabled: true
  server_name: dns.richardapplegate.io
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  dnscrypt_config_file: ""
  allow_unencrypted_doh: true
  certificate_chain: ""
  private_key: ""
  certificate_path: /caddy-certs/caddy/certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.dns.richardapplegate.io/wildcard_.dns.richardapplegate.io.crt
  private_key_path:  /caddy-certs/caddy/certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.dns.richardapplegate.io/wildcard_.dns.richardapplegate.io.key
  strict_sni_check: false
```

What matters:

- **`allow_unencrypted_doh: true`** — AdGuard serves DoH as plain HTTP on 8080 (or whatever admin port). Caddy wraps the TLS. Without this, Caddy hits AdGuard on HTTP and AdGuard returns 502. This is safe because the only thing talking to AdGuard on `:8080` is Caddy on the same Docker network.
- **`port_https: 443`** — unused for DoH (Caddy proxies it) but AdGuard complains if it's 0. Leave it.
- **`strict_sni_check: false`** — without this, AdGuard rejects any SNI that doesn't exactly equal `server_name`. DoT clients sending `phone.dns.yourdomain.com` would fail the handshake.
- **`certificate_path` / `private_key_path`** — the file layout is Caddy-native. The `wildcard_.dns.richardapplegate.io` folder name is exactly how Caddy stores it: `wildcard_` prefix, then the zone with a leading dot. Substitute your own domain.
- **`port_dns_over_quic: 853`** — that value is a bug in AdGuard's default config; the DoQ port is actually separate. Either leave it as 853 and AdGuard silently reuses the DoT listener for DoQ, or change it to 784 to match the Portainer port mapping. Both work; 784 is cleaner.

Save and restart AdGuard:

```bash
docker restart adguardhome
```

Check `docker logs adguardhome` for lines like:

```
[info] TLS: loading certificate from /caddy-certs/...
[info] DNS-over-TLS listener started on :853
[info] DNS-over-QUIC listener started on :784
```

If you see `permission denied` on the cert, the host path owning the bind-mount isn't world-readable — `chmod -R a+rX /mnt/1TB/caddy/caddy_data` fixes it (the ro mount means AdGuard can't write, so this is safe).

---

## Step 7 — Test each endpoint


From any machine with a DNS tool:

```bash
# Plain DNS (LAN only)
dig @<server-ip> example.com

# DoT
kdig -d @dns.yourdomain.com +tls-ca example.com

# DoH
curl -H 'accept: application/dns-message' \
     'https://dns.yourdomain.com/dns-query?name=example.com&type=A'
```

All three should return an answer. The DoT/DoQ handshake validates against the wildcard cert Caddy issued — if the handshake fails, the cert path in `AdGuardHome.yaml` is wrong.

If the `curl` for DoH returns 502, `allow_unencrypted_doh` isn't set or AdGuard didn't reload after you edited the YAML.

---

## Step 8 — Point a device at it with a ClientID

This is the whole point: per-device filtering. Each device gets a name (ClientID), and you can apply different blocklists to each.

AdGuard extracts the ClientID three different ways:

| Protocol | URL / server |
|---|---|
| DoT / DoQ | `phone.dns.yourdomain.com` (port 853 for DoT, 784 for DoQ) |
| DoH (path form) | `https://dns.yourdomain.com/dns-query/phone` |
| DoH (hostname form) | `https://phone.dns.yourdomain.com/dns-query` |

The SNI/hostname forms are cleanest — ClientID lives in the hostname, which Android's and iOS's native private-DNS fields accept. The path-suffix form is a fallback for DoH clients that lock the URL.

**Android (any recent version)**

Settings → Network → Private DNS → *Private DNS provider hostname* → `phone.dns.yourdomain.com`

That's DoT on port 853. Done.

**iOS / iPadOS**

Install a DoH config profile. Easiest path: AdGuard's admin UI → **Setup Guide → DNS profile → Download .mobileconfig**, then hand-edit the domain to `phone.dns.yourdomain.com` before installing.

**Windows 11**

Settings → Network → DNS → *Encrypted DNS only*, set the server to `<your-server-ip>` and add `dns.yourdomain.com` as the DoH template. Windows uses path-form DoH, so include the per-device suffix if you want per-device ClientIDs: `https://dns.yourdomain.com/dns-query/laptop`.

**Router (AdGuard Home upstream)**

Point your router at plain DNS `<server-ip>:53`. AdGuard tags LAN clients by IP, so ClientID = whatever you set in **AdGuard → Settings → Clients → Add**.

Once a device is talking, you should see it by name under **AdGuard → Clients → Runtime clients** within a few minutes of DNS activity.

---

## Step 9 — Cert renewal care

Caddy renews the wildcard cert automatically every ~60 days. AdGuard reads the cert files **once at startup** — it does not auto-reload.

Add a monthly host-side cron so AdGuard picks up new certs within a month of issuance (well before the 30-day expiry buffer):

```cron
0 4 1 * * docker restart adguardhome
```

The restart is sub-second; DoT/DoQ clients reconnect on their next query.

---

## Troubleshooting

**Chrome says `DNS_PROBE_FINISHED_BAD_SECURE_CONFIG` on an alias** — this was the bug v2.5.10 fixed. On CaddyUI ≥ v2.5.10, adding an alias to an existing proxy host correctly provisions a DNS record. If you're stuck on an older version, save the proxy host once more; the edit-path re-runs DNS provisioning.

**Caddy logs say `no matching certificate`** — the wildcard covers one label only. `a.b.dns.yourdomain.com` does NOT match `*.dns.yourdomain.com`. Either keep every ClientID at one label deep (`phone.dns...` not `phone.lan.dns...`), or issue a second wildcard at `*.lan.dns...`.

**DoH works but DoT returns handshake failure** — SNI mismatch. Check `strict_sni_check: false` in `AdGuardHome.yaml`. Also check that the cert really covers the leftmost label: `openssl s_client -connect phone.dns.yourdomain.com:853 -servername phone.dns.yourdomain.com` should show the certificate's SANs include `*.dns.yourdomain.com`.

**AdGuard shows the source IP instead of the ClientID** — the SNI / hostname isn't reaching AdGuard. For DoH, the URL was probably hit without a per-device suffix AND without a per-device hostname. For DoT, `strict_sni_check: true` is blocking the per-device SNI. Recheck Step 5.

**502 Bad Gateway on DoH** — `allow_unencrypted_doh: false`. Caddy talks HTTP to AdGuard's admin port; AdGuard expects HTTPS and refuses. Set it to true and restart.

**Portainer stack won't come up: network not found** — your CaddyUI stack's network is named something other than `caddy-and-ui_caddy_net`. Run `docker network ls` on the host; find the network name matching your Caddy container, and paste it into the AdGuard stack's `networks.external.name`.

---

## Named-volume footnote

The Portainer stack above assumes Caddy's data directory is a host bind mount (`/mnt/1TB/caddy/caddy_data`). If your CaddyUI install uses Docker named volumes (the default from the stock `docker-compose.yml`), the volume name is something like `caddy-and-ui_caddy_data`. Swap the volume line in the AdGuard stack for:

```yaml
volumes:
  - caddy-and-ui_caddy_data:/caddy-certs:ro
  - /mnt/1TB/adguard/work:/opt/adguardhome/work
  - /mnt/1TB/adguard/conf:/opt/adguardhome/conf

volumes:
  caddy-and-ui_caddy_data:
    external: true
```

Sharing a named volume across stacks works the same way as sharing a network — one stack owns it, others declare it external.

---

That's the whole loop. First-boot to a device-filtering DoH/DoT/DoQ resolver behind a single wildcard cert took me about an hour; the second time, following these steps, would be closer to 15 minutes.
