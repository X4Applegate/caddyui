# Changelog

All notable changes to **Caddy UI** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.5.7] — 2026-04-23 · Explicit Edit button next to Delete on list pages

### Changed
- **Edit button restored next to Delete** on proxy hosts, advanced (raw) routes, and redirection hosts — both the desktop table's Actions column and the mobile card footer. v2.4 had removed it in favour of a small pencil icon next to each domain pill, on the theory that the pencil served the same role with less visual noise. In practice multiple users kept looking for an explicit "Edit" action pair'd with "Delete" and weren't noticing the pencil, so the labelled button is back alongside the pencil (both navigate to the same `/edit` URL — the pencil lets you edit a specific domain variant from a multi-domain host, while the Edit button is the obvious big-target affordance). Affects `proxy_hosts.html`, `raw_routes.html`, and `redirection_hosts.html`.

### Docker
- Published as `applegater/caddyui:v2.5.7` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.6] — 2026-04-23 · Managed DNS for advanced routes + safer collision handling

### Added
- **Managed DNS on advanced (raw) routes.** The provider + zone picker that proxy hosts have had since v2.3.0 is now on the advanced-route form too, so saving a raw route whose JSON or Caddyfile source points at `example.com` auto-creates the A record in the same transaction instead of leaving you to go make it by hand in your provider's console. Mirrors the proxy-host flow end-to-end: create on save, retarget on FQDN / server-IP / zone change, delete on row delete, participates in the bulk "retarget all records" admin action, and appears in the `/api/dns-zones/check-record` collision probe. The deploying page also renders the new "DNS record created in &lt;provider&gt;" checkpoint when an advanced route carries a managed record.
- **Advanced-route FQDN detection reads both sources.** The client-side zone auto-suffix matcher pulls the domain from either the JSON `match[].host[0]` or the Caddyfile source site-block header (whichever is filled), so the suggestion works regardless of whether you're authoring raw JSON or pasting a Caddyfile snippet.

### Changed
- **DNS record collision no longer offers an "Override (delete & recreate)" button.** When the provider zone already has an A record at the FQDN you're saving, CaddyUI now just shows an amber warning with the existing record's content and tells you to delete it manually in your provider's console before saving. Rationale: on shared zones the override path could silently wipe out an A record belonging to an unrelated service (mail host, separate box, someone else's subdomain in the same account), and there was no way to undo it from the UI. Manual-delete-first is a couple extra clicks but makes it impossible for CaddyUI to destroy a record it didn't create. Applies to both the proxy-host form and the new advanced-route form.

### Implementation notes
- New columns on `raw_routes`: `dns_provider`, `dns_zone_id`, `dns_zone_name`, `dns_record_id` — each added with `ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT ''` via the existing `columnExists()` idempotent-migration helper, so upgrades from v2.5.5 (or any earlier 2.x) apply cleanly.
- `dnsCreateRecord(serverID, hostID, *ProxyHost)` refactored into a shared `dnsCreateRecordForFQDN(serverID, provider, zoneID, zoneName, fqdn) (recordID, zoneName)` core plus thin type-specific wrappers (`dnsCreateRecord` for proxy hosts, `dnsCreateRecordForRaw` for raw routes). Same allow-list / credentials / server-IP resolution logic for both; only the persistence target differs.
- `dnsUpdateAllRecords` (the admin "retarget every managed record after changing server IP" action) now iterates both tables via a closure-based per-row worker — `retarget(kind, rowID, provider, zoneID, zoneName, recordID, fqdn, persist)` — so raw-route records get retargeted alongside proxy hosts in the same pass.
- `dnsOverrideExistingRecord` and the `override_dns` form field are gone entirely. The `/api/dns-zones/check-record` endpoint still returns the collision payload; only the UI that consumed it changed. Any lingering `override_dns=1` on an inbound form is silently ignored — no 400s on old bookmarks.

### Docker
- Published as `applegater/caddyui:v2.5.6` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.5] — 2026-04-23 · Cloudflare-proxied cert check + deploying page for advanced routes

### Added
- **Deploying checklist now runs on advanced (raw) routes too.** Saving or editing an advanced route that has a host matcher (`match[].host[]` in its JSON) now redirects to a **`/raw-routes/{id}/deploying`** page with the same live checklist proxy hosts get — DNS propagation via Cloudflare DoH, HTTPS cert verified via a full TLS handshake with system-trust validation. Path-only / port-only routes (no hostname to probe) skip the page and bounce straight to the list like before. New read-only endpoint: `GET /api/raw-routes/{id}/deploy-status`.
- **Cloudflare-proxied cert check** (`proxied: true` on proxy hosts; auto-detected on raw routes). The cert probe now dials a resolved Cloudflare edge IP directly with `SNI = fqdn` instead of trying to reach Caddy's origin internally. For orange-cloud domains the user's browser sees CF's Universal SSL cert on the edge, not Caddy's origin cert — and the origin cert might legitimately be self-signed (CF Flexible SSL) or a staging cert, so checking it would false-negative the whole step. This also keeps the probe off the WAN hairpin entirely: CF edge IPs are always outside the LAN, so nothing loops back.

### Implementation notes
- New helper `firstRawRouteHost(jsonData)` pulls the first hostname out of a raw route's JSON `match[].host[]` array. Defensive against shape drift — returns "" when the JSON doesn't match the canonical Caddy route shape, which lets the save path fall through to the old "redirect to list" behaviour rather than erroring out on a malformed blob.
- Raw routes don't carry an explicit `proxied` flag (that's a proxy-host setting tied to a DNS provider), so the raw-route deploy-status handler **auto-detects** Cloudflare edge IPs from the DoH resolved IPs via a small `looksLikeCloudflareEdge()` check against the published CF v4 CIDR ranges. Embedded in-binary rather than fetched from `cloudflare.com/ips-v4` on every poll — one less network dependency on the hot path. The ranges only drift a couple times a year and a stale entry here is harmless (proxied-but-treated-as-direct just uses the original dial-caddy-internally path, which still works because CF sends traffic through to origin eventually).
- `tlsHandshakeOK` signature changed from `(serverID, fqdn)` to `(serverID, fqdn, proxied, resolvedIPs)`. Internal-only helper so no compat story needed; the proxy-host handler passes `resp["proxied"]` + `resp["resolved_ips"]` straight through.

### Docker
- Published as `applegater/caddyui:v2.5.5` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.4] — 2026-04-23 · Deploying-page cert check works behind hairpin-NAT-less routers

### Fixed
- **HTTPS certificate step on the deploying page now goes green on self-hosted setups behind consumer routers.** v2.5.2 / v2.5.3 checked cert readiness by performing a TLS handshake against `fqdn:443` from inside the caddyui container. On most prosumer / small-business setups the container resolves the public fqdn to the server's WAN IP and dials *out*, but the router doesn't hairpin WAN traffic back to the LAN — so the handshake times out even when the cert is fully issued and the site works for real users on the real internet. The page would sit on "⏳ Obtaining certificate…" the whole 120 s, time out, and dump you back to the proxy host list with an amber banner — and then clicking the domain would load it instantly over HTTPS, making the banner look wrong.
- Cert check now dials the Caddy server by its **admin-URL hostname** (the docker service name `caddy` for the primary, or the admin host for remote servers) and sends SNI = the proxy host's fqdn. This bypasses public DNS + WAN hairpin entirely, so the handshake either succeeds with the real cert (if Caddy has issued it) or fails fast (if it's still on the internal self-signed fallback). System trust verification is still on, so a staging-CA or expired cert correctly reports not-ready.

### Changed
- **"Still deploying after 2 minutes" banner text** softened to **"Still verifying after 2 minutes — the site may already be live. Opening the host list; click the domain to test it directly."** Cert-probe timeouts are often network-layer quirks (CGNAT, IPv6 vs IPv4 mismatch, restrictive egress) rather than actual deployment failures, so the banner now tells the user to try the site rather than implying something's broken.

### Implementation notes
- New helper `caddyDialHost(serverID)` parses the Caddy server's admin URL and returns its hostname. Unix-socket admin URLs (`unix://` scheme) return empty so the caller falls back to the public fqdn — dialling `:443` doesn't make sense over a unix socket. Works unchanged for remote-server setups where admin URLs are `http://10.x.x.x:2019` or `https://caddy.example.internal:2019`.
- This is still a **verification** step, not a reachability test. The dial only tests "has Caddy loaded a valid cert for this SNI?" — it intentionally doesn't speak HTTP afterwards. If the origin service behind Caddy is down, cert check still reports green; that's fine, the user has an explicit origin-health view elsewhere.

### Docker
- Published as `applegater/caddyui:v2.5.4` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.3] — 2026-04-22 · Deploying-page expected-IP fix for multi-server setups

### Fixed
- **Deploying page now compares against the right server IP.** The v2.5.2 "deploying" checklist read `host.ServerID` from a `GetProxyHost` result, but `proxyHostBaseCols` (the shared SELECT list) had never included `ph.server_id` — so `ServerID` came back as `0` on every read, and `serverIPFor(0)` fell through to the legacy global `server_public_ip` setting. On single-server installs that global happened to be correct, so nobody noticed; on multi-server setups the page would show e.g. `Got 50.191.208.172 — waiting for '50.191.208.169'` even though the DNS record had been correctly written with `.172` via the same request's `currentServerID(r)`. Added `ph.server_id` to `proxyHostBaseCols` and scanned it into `ProxyHost.ServerID` in `scanProxyHost`, so every read now carries the host's server binding. Affects `GetProxyHost` + both `ListProxyHosts` variants — all three funnel through the shared scanner.

### Implementation notes
- The column has existed in the DB since v2.4.0 (`ALTER TABLE proxy_hosts ADD COLUMN server_id INTEGER NOT NULL DEFAULT 1` in `internal/db/db.go`), so no migration is needed — this was purely a SELECT / Scan oversight that v2.5.2 surfaced because it was the first read path that actually consumed `host.ServerID`.

### Docker
- Published as `applegater/caddyui:v2.5.3` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.2] — 2026-04-22 · "Deploying…" page after save

### Added
- **Post-save "deploying" page** at `/proxy-hosts/{id}/deploying`. When you save a proxy host that created or changed a managed-DNS record, CaddyUI now parks you on a live checklist instead of dumping you back to the host list while DNS is still propagating. The checklist shows:
  1. ✅ Proxy host saved
  2. ✅ DNS record created in &lt;provider&gt;
  3. ⏳ **DNS propagating** — polls Cloudflare 1.1.1.1 via DNS-over-HTTPS every 3 seconds, verifies the A record resolves to your configured server public IP (or that *any* A record exists, for Cloudflare-proxied records)
  4. ⏳ **HTTPS certificate** — once DNS is live, does a real TLS handshake to `<fqdn>:443` with system-trust verification; goes green only when the public cert chain verifies. Skipped entirely when SSL is off on the host.
- **"Skip waiting"** button returns you to the host list immediately — the DNS record is already saved in your provider and Caddy's config, so closing the tab doesn't interrupt the deployment. You just lose the live progress view.
- **Hard 120-second timeout** before we give up and redirect back anyway, with an amber "still deploying — try again in a minute" toast. Propagation pathologies (slow recursive resolvers, CF edge lag) shouldn't trap you on the page forever.

### Changed
- **Create / edit of proxy hosts with Managed DNS now redirects to the deploying page** instead of straight to `/proxy-hosts`. Plain edits that don't touch DNS (renaming the upstream, toggling Basic Auth, etc.) still return to the list like before — the deploying page only shows when a record was actually created or changed.

### Implementation notes
- **DNS check** uses `https://cloudflare-dns.com/dns-query?type=A` (DoH) so we bypass the server's own recursive resolver and get what the public internet actually sees. 6-second HTTP timeout per poll so a slow upstream doesn't stall the UI.
- **Cert check** is a plain `tls.DialWithDialer(fqdn:443, &tls.Config{ServerName: fqdn})` with Go's default verification chain. No `InsecureSkipVerify`. A Caddy-internal self-signed fallback, an ACME-staging cert, or an expired cert all fail verification and correctly report not-ready.
- **Cloudflare-proxied records** (orange cloud) resolve to CF edge IPs rather than your origin, so for CF-proxied mode we relax the DNS check to "any A record present" and rely on the TLS handshake to test end-to-end reachability through CF.
- New API: `GET /api/proxy-hosts/{id}/deploy-status` returns `{fqdn, expected_ip, resolved_ips, ssl_enabled, proxied, dns_ready, cert_ready}`. Read-only and ownership-checked — non-admins can only poll their own hosts.

### Docker
- Published as `applegater/caddyui:v2.5.2` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.1] — 2026-04-22 · Smarter Managed-DNS zone picker

### Fixed
- **Proxy-host Managed DNS now auto-picks the correct zone** based on the domain you're adding. Previously, creating a proxy host for `test.example.io` with a Cloudflare account that also contained an unrelated zone (e.g. `something-else.com`) would select whichever zone the Cloudflare API returned first — often the wrong one. The picker now does a **longest-suffix match** against the first domain in the host, so `test.richardapplegate.io` resolves to the `richardapplegate.io` zone even when `applegatecloud.com` is in the same account. Auto-matching only runs on fresh hosts and before the user has manually touched the zone dropdown — any deliberate choice you make is kept.

### Added
- **"Domain doesn't match the selected zone" warning** under the Zone / Domain dropdown. Shows up when the first domain on the host isn't a subdomain of the currently picked zone — catches typos (`test.richardapplegate.ip`) and wrong-zone edits that previously would have silently created a record in the wrong place. Independent of the existing "record already exists" banner, which still fires for genuine collisions on save.

### Implementation notes
- Client-side only — no backend changes. The new logic lives in `web/templates/proxy_host_form.html`'s zone-picker IIFE: a `bestZoneMatch(fqdn, zones)` helper normalises both sides (lower-case, strips trailing dot, strips `*.` wildcard prefix) and picks the longest-matching zone name. `updateMismatchWarn()` re-runs on every provider / zone / domain change so the warning lights up the moment you type a typo.
- A `userPickedZone` flag flips to `true` the moment the user manually interacts with the zone `<select>` — after that, typing in the domain field no longer silently reshuffles their choice. Editing an existing proxy host starts in the user-picked state (the saved zone is treated as intentional), so v2.5.1 **never silently re-selects a zone on an existing host** — it just warns if the saved zone doesn't match the domain, letting you fix it deliberately.

### Docker
- Published as `applegater/caddyui:v2.5.1` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.0] — 2026-04-22 · Switchable CAPTCHA provider (Turnstile + reCAPTCHA v3)

### Added
- **Unified CAPTCHA setting** at `Settings → CAPTCHA protection` with three modes — **Off**, **Cloudflare Turnstile**, **Google reCAPTCHA v3**. Picking a provider shows only that provider's key fields; switching providers preserves the inactive provider's saved keys in the DB so you can toggle back without re-typing credentials. The active-provider status badge shows green "active" when both keys are filled, and a muted "keys missing" pill when the provider is selected but not yet configured.
- **Challenge applied to three forms**: `/login` (email + password), `/login/totp` (2FA code entry), and `/users/new` (admin creating a new account). Widget renders inline on all three — no separate "Test challenge" step. Turnstile shows its managed widget; reCAPTCHA v3 is invisible and hooks the form's submit event to `grecaptcha.execute(siteKey, {action: formID})` before submitting.
- **Env-var kill switch** `CADDYUI_CAPTCHA_DISABLE`. Set to `1`, `true`, `yes`, or `on` (case-insensitive) to bypass the challenge entirely without touching the DB — intended for "Cloudflare outage + I'm locked out of my own admin" scenarios where you can restart the container with this flag, log in, then unset it. When the env var is active, the Settings page shows an amber "overridden by env" badge on the CAPTCHA card.
- **reCAPTCHA v3 score threshold** input (0.0 = bot, 1.0 = human). Defaults to `0.5` (Google's starting recommendation). Challenges that Google scores below the threshold are rejected. Leaving the field blank falls back to the default at load time, but whatever you type is stored verbatim so the next render of the page shows your input.

### Changed
- **`/login` now uses the unified widget partial** (`{{template "captchaWidget" ...}}`) instead of the Turnstile-specific inline block that shipped in v2.4.x. Existing Turnstile keys continue to work unchanged — the v2.5.0 upgrade path is "install, set `captcha_provider=turnstile` (if you want the previous behaviour), and the existing site/secret keys apply as before." Setting stays blank by default on fresh installs (= "off").
- **Proxy-hosts table no longer draws horizontal divider lines** between rows or under the header. The `divide-y`/`border-b` lines were designed for light mode but read as bright white stripes across the table in dark mode, which made the list feel noisier than it needed to be. Row distinction still comes from the hover state and the purple tint on advanced-route rows.

### Implementation notes
- `internal/server/captcha.go` is the single source of truth: `loadCaptchaConfig(db)` reads the provider + keys, applies the env kill-switch, and returns a `captchaConfig` whose `Enabled()` method gates both template rendering and `verifyCaptcha`. Handlers call `verifyCaptcha(cfg, r)` unconditionally — it's a no-op when `Enabled()` is false.
- TOTP captcha failure does **not** consume the pending-TOTP token. A failed challenge at `/login/totp` re-renders the form with the same token instead of kicking the user back to `/login`. Rationale: captcha wrong ≠ TOTP slot burned; the 5-min auto-expire on the pending token still caps abuse.
- reCAPTCHA v3 uses a **submit-hook** pattern in the widget partial — the first submit is intercepted, `grecaptcha.execute` fetches a token, the token goes into a hidden `g-recaptcha-response` input, then the form is re-submitted. If `grecaptcha` fails to load (ad-blocker, Google outage), the fallback path submits anyway so the server returns the friendlier "Security check failed" error instead of the user getting stuck on a non-submitting form.
- `normalizeCaptchaProvider` coerces unknown values (tampered POST, hand-edited DB) to `"off"` rather than trusting them — keeps a bad setting from rendering a broken widget that would lock admins out of the UI.
- Verify-endpoint HTTP client has a **10-second timeout**. If Google or Cloudflare is slow, we'd rather surface a retry than block a legit user behind a 30-second hang.

### Docker
- Published as `applegater/caddyui:v2.5.0` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.4.12] — 2026-04-22 · Settings layout fix, timezone picker, branded error pages

### Added
- **Timezone setting** at `Settings → Timezone`. Pick an IANA zone from the common-zones dropdown or type any zone `time.LoadLocation` knows about via the "Other…" option. Every DB-stored timestamp rendered in the UI — cert expiry, activity log, snapshots, "last contact", "last sync" — flows through the active zone. Resolution priority is:
  1. DB value (what you picked in Settings)
  2. `TZ` environment variable (Go's `time.Local`, populated by the stdlib at startup)
  3. UTC
- **`TZ: ${TZ:-UTC}` environment variable** added to both `caddy` and `caddyui` services in `docker-compose.yml`, with inline comments explaining that the DB setting wins when both are set. Default is UTC when `TZ` is unset.
- **Branded 404 / 502 / 503 / 504 error pages** served by Caddy for every request that would otherwise return a plain-text error. Each page shows the status code, a short human-readable explanation of what probably went wrong, an **error ID** (`{http.error.id}` — 9-char correlation ID Caddy already logs per request), and the current HTTP-Date timestamp. Self-hosted dark-mode-aware layout, single HTML blob injected at `apps.http.servers.srv0.errors.routes` so it covers every proxy host. No customisation UI in this release — one hardcoded design for everyone.

### Changed
- **SMTP card now carries its own Save + Send-test-email buttons inline** at the bottom of the card. Same for the Webhook card (Save + Send-test-webhook). Previously you had to scroll down to a separate "Test buttons" section at the bottom of the page to trigger a test — which was far enough from the inputs that it felt disconnected from the values you'd just typed. The old out-of-form "Test buttons" card has been removed; its replacement lives in-card right where you just saved. All three existing submit buttons on the page (SMTP, Webhook, and the new Timezone card) submit the same form, so "Save settings" still writes every field at once.

### Template funcs (for custom layouts)
- `{{ fmtDate t }}` → `2006-01-02` in the active zone
- `{{ fmtDateTime t }}` → `2006-01-02 15:04` in the active zone
- `{{ fmtTime t }}` → `15:04:05` in the active zone
- `{{ fmtIn t "layout" }}` → arbitrary Go time layout in the active zone (used internally to keep existing visible formats unchanged)
- `{{ tzName }}` → the active zone's name (e.g. `America/New_York`)

### Implementation notes
- Timezone uses `atomic.Pointer[time.Location]` for lock-free reads on the hot path (every template render calls it). `postSettings` validates via `time.LoadLocation` before save, then hot-applies via `setActiveLocation` so the immediate redirect already renders in the new zone without a restart.
- Error pages use the full `{http.error.*}` placeholder path — the `{err.*}` shortcuts only work through the Caddyfile adapter; raw JSON needs the full path. E2E-validated against `caddy:2-alpine` with a reverse_proxy to a dead upstream: 502 returns the branded page with real `{http.error.id}` and `{time.now.http}` substitutions.
- `applyErrorPages` runs in both `syncCaddy` and `previewRawRouteValidate` so preview validation can't diverge from the real config push.

### Docker
- Published as `applegater/caddyui:v2.4.12` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

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
