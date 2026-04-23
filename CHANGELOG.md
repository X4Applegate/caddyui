# Changelog

All notable changes to **Caddy UI** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.4.11] — 2026-04-22 · Visible pencil-icon next to every identifier (dashboard pattern, now everywhere)

### Changed
- **Every admin table row now shows a small pencil icon next to the primary identifier** — the same pattern the dashboard already uses for proxy-host domain pills. The icon is the explicit edit affordance; rows themselves are not clickable on desktop. Applied to:
  - `/proxy-hosts` — pencil next to each domain pill (both regular rows and purple "advanced" rows)
  - `/redirection-hosts` — pencil next to each domain pill
  - `/raw-routes` — pencil next to the route `Label`
  - `/certificates` — pencil next to the cert `Name`
  - `/users` — pencil next to the user email
- **The sticky Actions column still only carries Delete** (no Edit button anywhere in the table) — same simplification that v2.4.10 shipped for proxy-hosts, just with a more discoverable alternative now.
- **Mobile cards are still whole-card-clickable to edit** — small touch targets make a dedicated pencil icon awkward on phones, so the card `data-edit-href` pattern stays. Cmd/Ctrl-click and middle-click still open edit in a new tab on both card and icon.

### Why
v2.4.10 removed the Edit button from `/proxy-hosts` and made the row clickable, but without a visible affordance some users couldn't tell rows were clickable — "where is edit button like square thing" was reasonable feedback. The dashboard already had a good answer: a tiny pencil icon right next to each domain pill. v2.4.11 just rolls that same pattern out everywhere.

### Implementation notes
- Icon is `w-6 h-6` wrapper with `w-3.5 h-3.5` SVG (matches the dashboard exactly). `text-ink-400 hover:text-brand-600 hover:bg-ink-100` so it sits quietly at rest and lights up on hover. Advanced-routes uses `hover:text-purple-600 hover:bg-purple-100` to match the purple row tint.
- Shared card-click handler in `layout.html` stays — it now only matters for mobile cards (`<div data-edit-href>`). Desktop `<tr>` no longer sets `data-edit-href`, so the handler is a no-op there.
- Users table: the `(you)` marker still appears after the email + icon. Pencil icon still lets you edit yourself; Delete still renders `—` for self.

### Docker
- Published as `applegater/caddyui:v2.4.11` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.10] — 2026-04-22 · Proxy-hosts rows are now clickable to edit (Edit button removed)

### Changed
- **The explicit "Edit" button has been removed from the `/proxy-hosts` table** (and its mobile card equivalent, and the advanced-routes rows on the same page). Clicking anywhere on a row now navigates to that host's edit page. The blue domain pills still open the external URL in a new tab, the enabled/disabled toggle still toggles, and the red Delete button still deletes — each owns its own click and stops the row-nav handler from firing.
- **Cmd/Ctrl-click and middle-click on a row open edit in a new tab** (same convention as any other navigational element).
- Rows get `cursor-pointer` so the affordance is obvious, plus a `title="Click row to edit"` tooltip for discoverability.

### Why
The sticky Actions column was carrying an Edit button and a Delete button side-by-side, taking up horizontal space for an action that could be driven by clicking the row itself. Removing Edit shrinks the pinned column to just Delete, and the row becomes the primary edit target — which is the pattern most admin tables already follow.

### Implementation notes
- `data-edit-href` attribute on each `<tr>` and mobile `<div>` carries the edit URL.
- A single `click` / `auxclick` handler skips clicks that land inside `a, button, form, input, select, textarea, label` — so every existing inline control (domain pill, toggle form, Delete form) keeps its behaviour unchanged.
- Middle-click is caught on `auxclick` because browsers don't fire `click` for button 1.

### Docker
- Published as `applegater/caddyui:v2.4.10` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.9] — 2026-04-22 · DNS "override" now only touches A / AAAA / CNAME — never MX / TXT / SRV / CAA

### Fixed
- **Critical: the v2.4.8 existing-record warning banner listed MX, TXT, SRV, CAA, and NS records alongside the A/CNAME it was actually about to replace — and "Override (delete & recreate)" then *deleted* every one of them.** On an apex domain with an existing MX + SPF TXT, clicking Override would silently wipe mail routing and SPF for the whole domain. Now:
  - **Warning filter** (`apiDNSCheckRecord`) only flags A / AAAA / CNAME at the target FQDN. MX, TXT, SRV, CAA, NS etc. are ignored — they cohabit with the web endpoint by design (email, SPF/DKIM/DMARC, cert issuance) and aren't a conflict.
  - **Override delete sweep** (`dnsOverrideExistingRecord`) has the same filter — even if a stale record list were somehow passed in, non-conflicting types are logged and skipped rather than deleted.
  - Shared helper `dns.IsProxyConflictingType(t)` is the single decision point so the two call sites can never drift apart.

### Why
A proxy host writes an A (or AAAA / CNAME) record at the FQDN. Every other record type at the same name belongs to a separate service:
- **MX** — mail exchange for incoming email
- **TXT** — SPF, DKIM, DMARC, domain-verification tokens
- **SRV** — service locations (XMPP, SIP, etc.)
- **CAA** — certificate-authority authorization

Deleting any of those during a "replace the A record" operation is always wrong — it breaks the user's email, SPF, or cert issuance without any warning. The v2.4.8 code path did exactly that for any user who clicked Override on a domain with existing MX/TXT records.

### Impact
If you upgraded to v2.4.8 and clicked "Override (delete & recreate)" on a proxy host whose domain had MX or TXT records, those records were deleted. Check your provider console and re-add them if so. Cloudflare/DigitalOcean/Hetzner keep a short audit log; GoDaddy/Porkbun/Namecheap don't, so you may need to restore from a zone-file backup or manual notes.

### Docker
- Published as `applegater/caddyui:v2.4.9` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.8] — 2026-04-22 · Sticky Actions column + "DNS record already exists" warning on proxy-host save

### Fixed
- **Actions column now sticks to the right edge of every admin table**, so Edit / Delete / Select / Restore stay visible no matter how narrow the viewport. Previously the final column scrolled off-screen on narrow windows (reported on the proxy-hosts page in particular). Applied the same `position: sticky` + opaque-background pattern to:
  - `/proxy-hosts` (Actions column was the original offender; purple "advanced" rows get a matching `bg-purple-50` so the sticky cell doesn't look transparent)
  - `/redirection-hosts`, `/raw-routes`, `/certificates`, `/servers`, `/users`, `/snapshots`
- Wrappers switched from `overflow-hidden` to `overflow-x-auto` with a `min-w` on the table so the other columns scroll underneath the pinned Actions cell rather than being cut off.

### Added — "DNS record already exists" warning on the proxy-host form
- New **existing-record warning banner** inside the Managed DNS section of the proxy-host form. As soon as you pick provider + zone and enter a first domain, CaddyUI queries the provider for records at that FQDN. If one (or more) exist, an amber warning shows up with:
  - A line listing what's already there (e.g. `A → 203.0.113.10, CNAME → example.pages.dev`)
  - **"Override (delete & recreate)"** button — flips the banner green and sets a hidden form flag so the backend will delete every matching record before creating the new A record on save
  - **"Keep existing record"** button — dismisses the warning; save proceeds normally (provider-dependent: Cloudflare/DO/Hetzner append a duplicate A, Porkbun errors, GoDaddy PATCH appends, Namecheap's `setHosts` replaces the whole host list anyway)
- **Cancel = just don't save** — the form's existing Cancel link still works. The banner's dismiss button only clears the *warning*, not the form.

### Why
Before this, saving a proxy host that targeted a domain with an existing A record was a quiet coin flip: the outcome depended on the provider's write semantics, and users only discovered what happened by checking DNS afterwards. Now the collision is surfaced at edit time, with a conscious Cancel / Override choice.

### Implementation notes
- **New `FindRecord(zone, fqdn) ([]Record, error)` method on the `dns.Provider` interface**, implemented in all six adapters:
  - Cloudflare — uses the existing `ListRecords(zoneID, name)` server-side filter
  - Porkbun — `ListRecords(domain)` + client-side filter (no server-side name filter on the `/dns/retrieve` endpoint)
  - Namecheap — reuses `fetchHosts(sld, tld)` + filters on short name (same one-fetch cost as every other call on this provider)
  - GoDaddy — `GET /v1/domains/{domain}/records?limit=500` + client-side filter; emits the same synthetic `TYPE|NAME` record IDs that `DeleteRecord` already consumes
  - DigitalOcean — `GET /v2/domains/{domain}/records?per_page=200` + client-side filter
  - Hetzner — `GET /records?zone_id=<id>&per_page=100` + client-side filter
- **New endpoint `GET /api/dns-zones/check-record?provider=&zone=&zone_name=&fqdn=`** returning `{ok, exists, records}`. Allow-list guarded (symmetrical with `apiDNSZones`).
- **New backend helper `dnsOverrideExistingRecord(p)`** called by `createProxyHost` / `updateProxyHost` when the form submits with `override_dns=1`. Best-effort: looks up every matching record, deletes them, logs per-record outcomes; the subsequent `dnsCreateRecord` then lands on a clean zone regardless of provider-specific semantics. Respects the per-provider zone allow-list from v2.4.7.
- **Front-end:** the existing DNS picker IIFE in `proxy_host_form.html` was extended with a debounced `checkExistingRecord()` that fires on provider / zone / domain change, caches the last result so switching back and forth doesn't refetch, and resets override / dismiss state whenever the (provider, zone, fqdn) triple changes.

### Docker
- Published as `applegater/caddyui:v2.4.8` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.7] — 2026-04-22 · Per-provider zone allow-list (keep CaddyUI out of domains you don't want it touching)

### Added
- **Per-provider "Limit to specific zones" textarea** inside each DNS provider card on `/settings`. Enter one base domain per line (or comma-separated). When set, CaddyUI will **only** create, update, or delete DNS records on the listed zones — every other zone the API key can see is:
  - Hidden from the proxy-host zone picker dropdown (filtered inside `apiDNSZones`)
  - Refused at the API layer even if a hand-crafted request tries to bypass the UI (`dnsCreateRecord`, `dnsDeleteRecord`, and the IP-retarget loop all call `zoneAllowed` before touching the provider)
- Empty textarea = unrestricted (original behaviour — every zone the credentials can reach is usable).
- The textarea auto-expands if you already have an allow-list set, and shows a small `N locked` badge in the summary so you can see at a glance that the provider is constrained.

### Why
GoDaddy's primary motivation: one API key has blanket access to every domain on the account. If you use CaddyUI to manage just one or two zones, the zone dropdown was previously offering every other domain as a target — one misclick away from writing a record into the wrong zone. Cloudflare / Porkbun / Namecheap / DigitalOcean / Hetzner all have similar exposure when the API scope is account-wide.

### How it behaves under edge cases
- **Zone removed from allow-list after a proxy host was created:** the host keeps its configured `dns_zone_name`, but `dnsCreateRecord` / `dnsDeleteRecord` / the retarget loop refuse to act. The existing DNS record on the provider stays exactly as-is — CaddyUI stops touching it. If you later re-add the zone, management resumes on the next save / IP change.
- **"Clear credentials" on a provider:** the allow-list is wiped alongside the API keys so a fresh key entry starts from an unrestricted state (no stale rules you forgot about).
- **Symmetry on delete:** a disallowed zone is refused for delete too — the point of the allow-list is "don't let CaddyUI touch this zone", which applies to cleanups just as much as to creates.

### Implementation notes
- New setting key `<providerid>_zone_allowlist` (e.g. `godaddy_zone_allowlist`), comma-separated lowercase base domains, normalised on save (dedup, trim, trailing-dot stripped).
- `zoneAllowed(providerID, zoneName)` is the single decision point — empty allow-list → allow everything; non-empty → case-insensitive membership check.
- Saved via the existing `postSettings` form handler (no new route). Textarea accepts commas, spaces, semicolons, or newlines as separators.

### Docker
- Published as `applegater/caddyui:v2.4.7` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.6] — 2026-04-22 · "Clear credentials" button per DNS provider in Settings

### Added
- **Per-provider "Clear credentials" button** inside each DNS provider card on `/settings` (Cloudflare, Porkbun, Namecheap, GoDaddy, DigitalOcean, Hetzner). One click (after a `confirm()` dialog) wipes every stored key/token for that provider from the `settings` table. For Cloudflare, the `cf_proxied` orange-cloud toggle is reset alongside the API token. Only shown when a provider is actually configured — no button on empty slots.
- **Amber confirmation banner** on redirect back (`?cleared=<id>`): *"Cloudflare credentials cleared. The provider is now disabled until you enter new credentials below."*
- **Audit log entry** (`dns_provider_clear`, target `dns:<id>`) so credential wipes show up in the activity log the same way saves do.

### Why
Before this, the only way to remove a saved token was to edit the SQLite settings table directly. Rotating credentials out, moving a domain to a different provider, or just cleaning up after a test account had no UI path.

### Implementation notes
- New route `POST /settings/dns-provider/{id}/clear` — admin-gated at the router (same middleware stack as the rest of `/settings`).
- Handler iterates `dnsProviderCredKeys[id]` and writes each key as an empty string via `models.SetSetting`. `dnsClient` already treats any empty credential as "provider not configured", so downstream behaviour is identical to a fresh install for that provider.
- Existing DNS records on the provider side are **not** touched — this only removes CaddyUI's local copy of the API keys. A follow-up sync will simply skip DNS updates until new credentials are entered.
- Template uses HTML5 `form="clear-dns-<id>"` to associate each button with an external empty form rather than nesting forms, so clicking "Clear credentials" does not accidentally submit the main Settings form.

### Docker
- Published as `applegater/caddyui:v2.4.6` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.5] — 2026-04-22 · App dot: amber "unknown" for split-horizon DNS (no more false red)

### Fixed
- **App dot flagging healthy sites as 🔴 `down — connection refused`** when caddyui's container resolves the public domain to a private/RFC1918 IP (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`, loopback, ULA, etc.). This happens on LAN setups with split-horizon DNS (router/pihole/unbound hands internal clients the LAN IP of the Caddy host), with `/etc/hosts` overrides, or via Docker's embedded DNS. Your browser sees the public IP and works; caddyui sees the private IP and either can't reach port 443 there or hits something else entirely — the probe result doesn't reflect reality.
- **App probe now short-circuits to 🟠 `unknown`** when DNS returns only private addresses. Tooltip explains what happened and where the IP came from:
  > App: unknown — DNS from caddyui points to 192.168.112.7 (private) — probe from here would be misleading; check your browser
- **Same softening applied post-failure**: if a dial error contains a private IP (Go's format: `dial tcp 192.168.x.x:443: …`), the result is reclassified from "down" to "unknown" — catches DNS-cache/IPv6 races the preflight missed.
- **No behaviour change for genuine public failures** — if a domain resolves to a public IP and the probe fails (refused / timeout / TLS), it's still 🔴 `down` as before.

### How to read the new state
If Port is 🟢 and App is 🟠 `unknown (private IP)`, the site is almost certainly working from the public internet — caddyui just can't probe from where it's running. Open in a browser to confirm. If it's working there, nothing to fix.

### Docker
- Published as `applegater/caddyui:v2.4.5` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.4] — 2026-04-22 · End-to-end "App" health dot (catches "port open but app wedged")

### Added
- **Second health dot per proxy host** — the destination column on the dashboard and `/proxy-hosts` now shows **two** dots side-by-side:
  - **Port** (existing): Caddy can TCP-dial the upstream
  - **App** (new): `HTTPS GET /<primary-domain>/` returned a sensible response end-to-end
  A new background poller (`StartAppHealthPoller`) hits each enabled host's public URL every 60s with a 5s timeout, follows up to 3 redirects, skips TLS verification, and caches the result. The existing `/api/upstream-health` endpoint now returns both `status` and `app_status` in the same response — no new endpoint.
- **App-status classification:**
  - 🟢 `ok` — `2xx` / `3xx` / `401` / `403` (app responded with something)
  - 🟠 `degraded` — `5xx` or `4xx` other than auth (app misconfigured or erroring)
  - 🔴 `down` — timeout / connection refused / TLS error
  - ⚪ `unknown` — DNS doesn't resolve publicly (WG/Tailscale-only edge), wildcard domain, or hasn't been polled yet
- **Tooltips** on each dot describe *which* check failed and why: `App: responding (HTTP 200 in 142ms)` vs `App: down — context deadline exceeded`

### Why this matters
The TCP/port dot only tells you Caddy can open a socket to the upstream. In v2.4.3 (status-server + MySQL case) the port dot stayed green for **hours** while the app was actually wedged on a MySQL timeout — every HTTP request hung for ~2 minutes then failed. The new App dot would have flagged that instantly.

### Docker
- Published as `applegater/caddyui:v2.4.4` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.3] — 2026-04-22 · Amber "unknown" for Docker-named backends + split source actions

### Added
- **Dashboard source column now gives you both actions**: clicking the domain pill opens the site in a new tab (previous behaviour was "filter list"; briefly in v2.4.1 it was "edit form"). A small pencil icon beside each pill opens the edit form directly. No more one-or-the-other

### Fixed
- **Red "down" dot on Docker-container backends** (e.g. `status-server:3000`, `snipeit-app:80`) even when the backend was serving traffic fine. CaddyUI asks Caddy for upstream health first, but when Caddy hasn't registered the upstream (e.g. newly added host), it fell back to a direct HTTP probe from the caddyui container. That probe can't resolve Docker service names because caddyui usually isn't on the target's Docker network. Now:
  - If the hostname has no dots (looks like a Docker service), skip the direct probe and render **amber "unknown"** with a helpful tooltip
  - If the direct probe fails with a DNS error (`no such host`), downgrade from "error" to "unknown" for the same reason
  - The dashboard and `/proxy-hosts` both recognise the new `unknown` state and render an amber dot instead of red

### Docker
- Published as `applegater/caddyui:v2.4.3` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.2] — 2026-04-22 · Stop health poller flapping over WG

### Fixed
- **Servers flapping "offline" then recovering on manual Sync.** The health poller marked a server offline after **one** failed 5-second ping — over WireGuard/Tailscale a single dropped UDP packet during rekey could miss the window. Now requires 3 consecutive failures before flipping to offline and the per-ping timeout is 8 s. A successful ping always resets the counter immediately
- **`startup sync: pushed DB state to Caddy` log was printed even when the sync was skipped** (empty DB or external server) — the inner `syncCaddy` already logs `caddy sync skipped: …` in that case, so the second contradictory line is gone

### Docker
- Published as `applegater/caddyui:v2.4.2` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.1] — 2026-04-22 · Dashboard UX + correct version string

### Added
- **Dashboard "Recent proxy hosts" source pills** now link directly to the edit form (`/proxy-hosts/{id}/edit`) instead of the filtered list — click a domain → edit → Save → back at `/proxy-hosts`
- **Upstream health dot** next to each destination on the dashboard (desktop table and mobile cards), matching the existing indicator on `/proxy-hosts`. Driven by the same `/api/upstream-health` endpoint the list page uses
- **Example `docker-compose.yml`** sets `CADDYUI_SYNC_ON_START: "1"` so `docker compose restart` automatically rehydrates Caddy from the DB. Still safe on first boot — `SyncCaddy` refuses to push when the DB is empty

### Fixed
- **UI showed `CaddyUI dev`** instead of the release tag — the published v2.4.0 image was built without `--build-arg VERSION=v2.4.0`, so `var Version = "dev"` was compiled in. Rebuilt v2.4.0 and v2.4.1 with the build arg; both multi-arch manifests were re-pushed

### Docker
- Published as `applegater/caddyui:v2.4.1` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.0] — 2026-04-22 · Per-server public IPs for managed DNS

### Added
- **Per-server public IP** on `caddy_servers` (new `public_ip` column, idempotent migration, auto-backfilled from the legacy global `cf_server_ip` setting on upgrade so existing records keep pointing at the right place)
- **Settings → DNS** now renders one IP input per registered Caddy server instead of one global field. Each server gets its own row (name · admin URL · editable IP). Editing an IP retargets **only that server's** managed DNS records in the background — a 3-server setup no longer rewrites all six provider record sets when one IP changes
- **Legacy fallback IP** kept as a collapsible `<details>` block so pre-v2.4.0 setups upgrade cleanly (the migration copies the old single global IP into every server row)
- **Proxy host form** shows which IP the A record will point at (the current server's public IP), with a direct link to Settings when it's empty
- **Docs** — new FAQ entry with copy-paste UFW + iptables commands for restricting port 2019 to a single source IP, plus notes on the Docker iptables-bypass pitfall

### Changed
- `dnsCreateRecord(serverID, hostID, p)` now takes the Caddy server ID so it can resolve the right A-record target per host; the old `serverID`-unaware signature is removed
- `dnsUpdateAllRecords(serverID, newIP)` now scopes to one server — pass 0 to fall back to global retarget
- `dnsProviderViewData(serverID)` resolves the per-server IP when rendering the proxy host form; the legacy global-IP check is gone from the picker's "enabled" gate
- `models.ListProxyHostsWithDNSRecords(db, serverID)` takes a server filter (0 = all)

### Fixed
- **Zone / Domain dropdown showed "undefined"** on the proxy host form — carried over from v2.3.2 fix (json tags on `dns.Zone`)
- **Missing Actions column** on the desktop proxy hosts table — carried over from v2.3.2 fix (overflow + min-width)

### Schema
- `ALTER TABLE caddy_servers ADD COLUMN public_ip TEXT NOT NULL DEFAULT ''`
- One-time backfill: `UPDATE caddy_servers SET public_ip = (SELECT value FROM settings WHERE key='cf_server_ip') WHERE public_ip = '' AND EXISTS (…)`

### Docker
- Published as `applegater/caddyui:v2.4.0` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.3.2] — 2026-04-22 · Hotfix — zone dropdown "undefined" + missing Actions column

### Fixed
- **Zone / Domain dropdown showed "undefined"** on the proxy host form after picking a provider — the `/api/dns-zones` response returned `{"ID":"…","Name":"…"}` (Go's default JSON encoding of the struct) but the picker JS reads `z.id` / `z.name`. Added `json:"id"` / `json:"name"` tags to `dns.Zone` (and the same for `dns.Record` while we're there) so the response is properly lowercased. All six providers affected (CF, Porkbun, Namecheap, GoDaddy, DO, Hetzner).
- **Missing Actions column** in the desktop proxy hosts table — the wrapper div used `overflow-hidden`, which clipped the Edit/Delete buttons off the right edge whenever the table was wider than the viewport. Changed to `overflow-x-auto` + `min-w-[900px]` on the table so the column stays reachable via horizontal scroll.

### Docker
- Published as `applegater/caddyui:v2.3.2` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.3.1] — 2026-04-22 · Hotfix — ambiguous column name on startup sync

### Fixed
- **Startup sync crash** (`SQL logic error: ambiguous column name: id`) — `ListProxyHosts` queries `proxy_hosts` joined with `users` for the owner email, but the shared `proxyHostBaseCols` constant used bare column names (`id`, `domains`, …). SQLite couldn't disambiguate `id` across the two tables and the query failed, aborting startup sync. Fixed by qualifying every column in `proxyHostBaseCols` with the `ph` alias and updating `GetProxyHost` to alias `proxy_hosts AS ph` in its FROM clause. No schema change.

### Docker
- Published as `applegater/caddyui:v2.3.1` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.3.0] — 2026-04-22 · Multi-Provider DNS (Namecheap, GoDaddy, DigitalOcean, Hetzner)

### Added
- **Four new managed-DNS providers**, all behind a single `dns.Provider` interface in `internal/dns/`:
  - **Namecheap** (`internal/dns/namecheap.go`) — XML API; serialises mutations since `setHosts` is a full-replace endpoint, synthetic `TYPE|NAME|VALUE` record IDs, splits SLD/TLD for the API call, requires per-account IP whitelisting
  - **GoDaddy** (`internal/dns/godaddy.go`) — `sso-key` auth, synthetic `TYPE|NAME` record IDs, uses `PATCH /records` (append) rather than `PUT` (replace-all); surfaces the 10-domain-minimum tier gate error verbatim
  - **DigitalOcean** (`internal/dns/digitalocean.go`) — clean REST API, domain-as-zone-ID, 30s minimum TTL
  - **Hetzner DNS** (`internal/dns/hetzner.go`) — `Auth-API-Token` header, opaque zone IDs separate from zone names
- **Unified DNS provider architecture** (`internal/dns/dns.go`):
  - Common `Provider` interface (`ID`, `DisplayName`, `Ping`, `ListZones`, `CreateRecord`, `DeleteRecord`) every provider implements
  - Descriptor registry with per-provider `CredentialField` metadata so Settings renders credential cards from a single `{{range .DNSProviders}}` loop — no template branching per provider
  - Helpers: `SubdomainOf`, `FirstDomain`, `MatchZone` for zone/record name translation
  - Keep-blank-to-preserve UX on every secret field; non-secret fields (Namecheap API user, whitelisted IP) are always-overwrite
- **Settings page refactor** — replaced hardcoded CF + PB credential cards with a data-driven loop over `dns.Descriptors()`; new shared "Server IP" field at the top of the DNS section (used by all providers), per-provider active/configured/disabled status pills, inline setup-guide links
- **Proxy host form refactor** — one provider dropdown + one zone selector (loaded on demand from `/api/dns-zones?provider=<id>`); switching providers clears the stale zone selection, provider-specific hints render inline (Porkbun per-domain API Access reminder, Namecheap IP-whitelist note, GoDaddy tier-gate warning)
- **Docs** — four new tutorial sections (Namecheap / GoDaddy / DigitalOcean / Hetzner) covering key creation, account requirements, and the provider-specific gotchas

### Changed
- **Cloudflare + Porkbun** ported to the new `dns.Provider` interface (thin adapters over `internal/cloudflare` and `internal/porkbun`); no behaviour changes, but Settings and the proxy host form are now driven by the registry rather than hardcoded
- **Server IP setting** renamed from `cf_server_ip` to `server_ip` (the old key is still read for backwards compatibility — existing databases upgrade cleanly)
- **IP-change retargeting** now walks every managed record across all six providers in a single pass (was CF + PB only)
- **`/api/cf-zones` and `/api/pb-domains` consolidated** into `/api/dns-zones?provider=<id>` (old routes removed — they were never used outside the proxy host form, which is updated in this release)

### Database
- Added unified `dns_provider` / `dns_zone_id` / `dns_zone_name` / `dns_record_id` columns to `proxy_hosts` via the idempotent `columnExists → ALTER TABLE` pattern
- **One-time backfill** at startup: existing rows with `cf_dns_record_id` or `pb_dns_record_id` set are auto-populated into the unified columns (guarded on `dns_provider = ''` so it only runs once). Legacy CF/PB columns are preserved for rollback safety — dropping columns in SQLite requires a table rebuild, which isn't worth the migration risk

### Docker
- Published as `applegater/caddyui:v2.3.0` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

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
