# Changelog

All notable changes to **Caddy UI** are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.23.1] - 2026-08-12 - Route 53 DNS-01 reliability

### Fixed

- Route 53 DNS-01 automation now pins Caddy's provider configuration to the exact public hosted zone selected in CaddyUI. This prevents `_acme-challenge` TXT records from landing in a similarly named or split-horizon zone. ([#24](https://github.com/X4Applegate/caddyui/issues/24))
- Managed DNS automation policies now replace stale policies for the same certificate subjects while preserving unrelated and catch-all policies.
- DNS-01 provider configuration is included in Caddy's preflight validation, so a missing provider module or invalid configuration is reported before route subtrees are changed.
- Saving managed DNS with public A-record creation enabled now gives an actionable form error when the selected Caddy server has no public IP, instead of failing later at the provider.

### Added

- Proxy hosts, redirections, and advanced routes can disable **Create public A records** while continuing to use the selected provider and zone for ACME DNS-01. This supports internal and split-DNS services without publishing a WAN address.
- DNS-01-only mode is persisted across SQLite and MariaDB, preserved as target-specific policy during fleet sync, and shown explicitly in deployment status.

## [2.23.0] - 2026-08-12 - Amazon Route 53 managed DNS

### Added

- **Amazon Route 53 provider support** for public hosted-zone discovery and managed A-record creation, collision detection, retargeting, and cleanup across proxy hosts, redirections, and advanced routes. Existing records are never overwritten automatically. ([#24](https://github.com/X4Applegate/caddyui/issues/24))
- Route 53 credentials in Settings support long-lived IAM access keys plus optional STS session tokens and partition-specific regions. The access-key pair is also emitted to Caddy for ordinary and wildcard DNS-01 certificate issuance.
- The custom Caddy image now builds `github.com/caddy-dns/route53` v1.6.2, with regression tests covering provider configuration, pagination, aliases, and exact record-set deletion.
- The in-app guide includes a scoped IAM policy template covering the CaddyUI record lifecycle and Caddy's DNS-01 challenge flow.

### Security

- Private Route 53 hosted zones are intentionally excluded from the managed-DNS picker because public ACME resolvers cannot query them and split-horizon duplicate names are easy to select accidentally.
- Record cleanup preserves the complete Route 53 record-set shape for the exact-delete semantics required by AWS. CaddyUI refuses to delete Traffic Flow-managed records so it cannot leave a billable traffic-policy instance orphaned.

### Changed

- DNS credential descriptors can now mark region/session fields optional, and blank non-secret settings can be cleared without disturbing saved secret values.

---

## [2.22.0] - 2026-08-12 - Idempotent fleet configuration sync

### Added

- **One-click full routing sync** on Administration → Caddy Fleet merges every proxy host, redirection, advanced route, and managed certificate definition from the environment selected in the application shell into another managed Caddy server. Target-only routes remain intact, while target-specific DNS records and custom certificate choices are preserved. ([#23](https://github.com/X4Applegate/caddyui/issues/23))
- Fleet deployments now persist source-to-target resource mappings so later source edits—including hostname, label, and managed-certificate subject changes—update the same target rows.

### Fixed

- **“Also deploy to” is now idempotent.** Repeating a proxy, redirection, or managed-certificate deployment updates the existing target resource instead of inserting a duplicate.
- Cross-deploy validates managed source/target environments and applies the same proxy/redirect domain-collision safeguards as ordinary resource creation.
- Fleet copies no longer carry source DNS record IDs or custom certificate IDs into another server's configuration.

### Changed

- Added regression coverage for repeated deployment, tracked hostname changes, target-policy preservation, domain collisions, full routing sync, and SQLite/MariaDB schema parity.

---

## [2.21.2] - 2026-08-10 - Resilient analytics log forwarding

### Added

- **Analytics log forwarding can no longer make Caddy depend on CaddyUI at startup.** Settings → Analytics now exposes Caddy's network-writer `soft_start` option and enables it by default, so Caddy loads its config when the CaddyUI ingest listener is unavailable and sends logs to stderr until the connection recovers. ([#22](https://github.com/X4Applegate/caddyui/issues/22))
- **Configurable analytics connection timeout** limits network-writer connection attempts to 1–60 seconds and defaults to 5 seconds.

### Changed

- Enabled analytics loggers are reconciled across managed fleet servers when CaddyUI starts, allowing upgrades to apply the safer writer defaults without requiring an administrator to re-save Settings.
- Added regression tests for generated `soft_start` / `dial_timeout` JSON, upgrade defaults, explicit overrides, and startup reconciliation.

---

## [2.21.1] - 2026-08-10 - Proxy advanced config fleet validation

### Fixed

- **Proxy-host Advanced Config now validates against the selected Caddy Fleet server** instead of always adapting snippets through the default bootstrap client. Hosts saved while a non-primary server is selected no longer fail Advanced Config validation just because that environment uses a different admin URL or module set. ([#21](https://github.com/X4Applegate/caddyui/issues/21))
- Added a regression test covering request-scoped Advanced Config validation so future fleet changes keep using the active server's admin API during proxy-host save operations.

---

## [2.21.0] - 2026-08-01 - Fleet access logging and CrowdSec protection

### Added

- **Independent Caddy file access logs** in Settings, with fleet-server targeting, HTTP/HTTPS scope, native JSON or console encoding, absolute file path, maximum size, retained-file count, and retention-period controls.
- **Analytics-safe logging composition** preserves CaddyUI's existing network analytics logger when file logging is enabled; disabling either destination leaves the other destination intact.
- **CrowdSec bouncer integration** configures the `crowdsec` Caddy app and injects `http.handlers.crowdsec` before every protected CaddyUI-generated proxy, redirect, advanced, and plain-HTTP route.
- **CrowdSec fleet controls** include selected servers, masked keep-existing API keys, streaming mode, refresh interval, hard-fail policy, exact-host exclusions, path-pattern exclusions, pre-save module validation, and a live LAPI connection test.
- **Configurable client IP headers** complement trusted proxy ranges so CrowdSec and access logs can use Caddy's resolved client IP behind Cloudflare or another load balancer.
- The repository's custom Caddy build now includes `github.com/hslatman/caddy-crowdsec-bouncer/http`, and the Compose stack persists `/var/log/caddy` in a named volume.

### Fixed

- Trusted proxy and client-IP-header settings are now written to both CaddyUI-generated HTTP servers during sync and stale values are removed when cleared.

---

## [2.20.2] - 2026-07-30 - Fleet API and TLS/version reliability

### Fixed

- **Version checks now follow every Docker Hub tag page** and select the highest semantic version across the complete repository. Installations no longer report an old `v2.9.x` release after newer tags move beyond the first page.
- **Port-qualified proxy and redirection domains now use port-free Caddy host matchers and certificate identities**. A host such as `project.sub.example.com:8000` correctly reuses a managed `*.sub.example.com` wildcard instead of attempting an invalid exact certificate order containing `:8000`.
- DNS-01 automation subjects, custom-certificate exclusions, wildcard discovery, and cross-server wildcard deployment now share the same normalized hostname behavior.

### Added

- **Read-only fleet API**: authenticated clients can call `GET /api/v1/servers` with a session or API token to retrieve server IDs, names, admin URLs, management types, health, Caddy versions, tags, and last-contact timestamps without scraping the Caddy Fleet page.
- The fleet response intentionally excludes admin credentials and public IP configuration. It is available to every authenticated role, matching the fleet switcher already rendered in the signed-in application shell.

---

## [2.20.1] - 2026-07-29 - Actionable unused-certificate cleanup

### Fixed

- **Unused certificate recommendations now identify the certificates** instead of linking to an unfiltered list with only a count.
- **Managed ACME definitions are no longer reported as unused**. Standalone managed and wildcard certificates are intentionally automated by Caddy and are not attached through a resource `certificate_id`.
- Certificate usage is checked against every proxy host, redirection, and advanced route in the current environment, preventing tenant-scoped views from incorrectly labeling a shared certificate as unused.

### Added

- **Filtered cleanup view**: the Operations recommendation opens `/certificates?usage=unused`, where only unassigned PEM/file-path certificates appear and every row carries an **Unused** marker.
- **Named dashboard detail**: the recommendation includes the first affected certificate names before the operator leaves Operations.
- **Persistent dismissal**: administrators can dismiss the cleanup recommendation for the selected Caddy environment. The exact unused-certificate set is remembered; the recommendation automatically returns if a different certificate becomes unused later.
- **Cleanup guidance** explains that assigning or deleting the listed certificates clears the condition.

---

## [2.20.0] - 2026-07-29 - Enterprise workflows and guided operations

### Added

- **First-run account wizard**: new installations begin with a clear four-stage operating journey—create the administrator, connect Caddy, secure the account, and publish the first service.
- **Live readiness guide**: **Getting Started** derives progress from the actual selected Caddy environment, TOTP state, DNS profiles, and proxy inventory instead of storing a dismissible tutorial flag. Administrators can return to it whenever an environment changes.
- **Guided service publishing**: new proxy hosts now use a focused Hostname → Upstream → Policy → Review workflow. The final review shows the effective hostname, upstream, HTTPS policy, DNS automation, and initial state before CaddyUI writes configuration.
- **Advanced-editor escape hatch**: experienced operators can open the complete proxy-host editor with one click. Existing hosts continue to use the full editor, and guided creation preserves every established advanced default.
- **Global create menu**: the persistent application bar provides direct entry points for publishing a service, creating a redirection, adding a certificate, or building an advanced route.
- **Environment readiness on Operations**: incomplete environments receive a compact, actionable readiness summary that links back to the live guide.

### Changed

- **Semantic color contract** is now explicit and consistent: blue means action/current context, green means healthy/enabled/completed, amber means pending/degraded/maintenance, red means failure/offline/destructive, violet means TLS/automation/managed policy, and gray means disabled/unknown/informational.
- **Caddy fleet workflow** now presents registered environments as an operational inventory with environment, health, admin endpoint, management policy, last contact, and scoped actions.
- **Caddy connection form** now follows an Identify → Connect → Authorize sequence and explains safe admin-API connectivity before configuration is saved.
- **Proxy Hosts** has an enterprise page header, workflow language, and a primary **Publish service** action.
- **Required readiness** uses four foundations. DNS automation remains visible as an optional capability and never prevents an environment from reaching 100% readiness.
- **Navigation terminology** now uses **Caddy Fleet** and **Publish service** consistently where those labels better describe the operator's goal.

### Accessibility

- Guided steps expose current-state semantics, native form validation, predictable Back/Continue controls, keyboard focus targets, and a review stage before submission.
- Setup, onboarding, publishing, fleet, and connection workflows have dedicated compact layouts for narrow screens and retain the existing reduced-motion behavior.
- The enterprise workflow system supports light, dark, Carbon Orange, Forest, Rose, and Indigo themes through shared semantic tokens.

---

## [2.19.0] - 2026-07-29 - MariaDB and large-installation performance

### Added

- **Optional MariaDB backend**: set `CADDYUI_DB_DRIVER=mariadb` and `CADDYUI_DB_DSN` to run CaddyUI on MariaDB while SQLite remains the default.
- **Automatic MariaDB schema and migrations**: fresh databases receive the complete CaddyUI schema, including all current proxy-host fields and performance indexes.
- **Read-only SQLite → MariaDB migration command**: `caddyui migrate-db --from-sqlite /data/caddyui.db` preserves IDs and relationships, copies in bounded transactions, rejects non-empty destinations, and supports `--skip-analytics` for oversized traffic histories.
- **MariaDB deployment overlay and CI**: `docker-compose.mariadb.yml` provides a health-checked MariaDB 11.4 service; CI validates schema parity, core resource queries, and cross-database migration.

### Performance

- **Proxy Hosts traffic lookup** now queries only domains visible on the page. SQLite uses the existing `(host, ts)` covering index instead of scanning the complete analytics history.
- **Post-render upstream checks** start after the browser's initial paint and pause while the tab is hidden.
- **List-page indexes** cover proxy ordering, advanced routes, certificate options, and last-sync activity lookups.
- **Portable daily rollups** use timestamp ranges instead of engine-specific date conversion, improving index use on both SQLite and MariaDB.

### Changed

- Sessions, login throttling, activity retention, settings upserts, and analytics rollups now use portable SQL shared by both database backends.
- Settings explains that MariaDB backups belong to the database platform; Caddy configuration snapshots continue to work normally.

---

## [2.18.0] - 2026-07-29 - Enterprise operations UI

### Added

- **Enterprise operations center**: the dashboard now organizes active-server identity, route inventory, host health, traffic, system telemetry, recommendations, fleet status, recent changes, and live upstream reachability into one operational hierarchy.
- **Semantic design system**: reusable surface, border, text, brand, status, spacing, radius, shadow, panel, button, metric, table, and empty-state primitives establish a consistent foundation for future page migrations.
- **Persistent command search**: desktop users can open the existing resource search directly from the top bar; the button uses the same reset, fetch, focus, and keyboard navigation workflow as `Ctrl/⌘+K`.
- **Workflow-first actions**: Create proxy host, Sync Caddy, and Manage servers are visible at the point of use. The create action remains hidden for read-only viewers.

### Changed

- **Application navigation**: destinations are regrouped into Overview, Traffic, Observe, Configuration, Developer, and Administration sections without changing routes or role-based access.
- **Environment context**: the active Caddy server and status are promoted in both the sidebar and persistent top bar, with faster switching in multi-server installations.
- **Mobile shell**: the previous stacked mobile toolbars are consolidated into one compact bar with navigation, environment, search, theme, and account controls.
- **Dashboard density**: redundant cards are consolidated into structured panels and responsive data grids that scale from a phone to a wide operations display.
- **Dashboard documentation**: the README screenshot now reflects the enterprise operations layout.

### Accessibility

- **Keyboard focus visibility** is standardized across links, buttons, inputs, selects, textareas, and disclosure controls.
- **Reduced-motion support** disables nonessential application-shell transitions and animations when requested by the operating system.
- **Responsive validation** covers 390 px mobile and 1440 px desktop layouts without horizontal page overflow.

---

## [2.17.3] - 2026-07-29 - Visible certificate selection for Auto TLS

### Added

- **Certificate identity in the Caddy-managed table**: the Certificates page now shows which certificate each Auto TLS domain uses. Hosts covered by a managed wildcard display that certificate's CaddyUI name; hosts without wildcard coverage display **Direct certificate**.
- **Responsive certificate identity**: the same wildcard/direct distinction appears in both the desktop table and mobile certificate cards.

---

## [2.17.2] - 2026-07-29 - Enforced wildcard reuse and live renewal visibility

### Fixed

- **Auto TLS now reuses managed wildcards**: exact proxy, redirect, and advanced-route hostnames covered by a standalone managed wildcard are added to Caddy's `automatic_https.skip_certificates` list. HTTPS remains enabled, but Caddy no longer obtains an unnecessary exact-host certificate and instead serves the wildcard already managed in its cache.
- **Safe wildcard boundaries**: only exact hostnames covered by a one-label wildcard are skipped. The wildcard subject itself remains eligible for DNS-01 issuance; apex and multi-level names still obtain their own certificate unless separately covered.

### Added

- **Live per-server managed certificate status**: editing a managed certificate now shows every configured Caddy server, whether the definition is deployed there, the certificate actually served, issuer, expiration timestamp, days remaining, and renewal problems such as expired, mismatched, or unreachable certificates.
- **Wildcard-safe certificate probing**: CaddyUI uses a synthetic wildcard-covered SNI name and connects directly to each Caddy server, so a standalone wildcard can be inspected without creating public DNS for a fake hostname.
- **Managed wildcard documentation**: the GitHub README and Docker Hub overview now include the complete setup, multi-server deployment, Auto TLS reuse, provider-module requirement, and renewal-status workflow.

---

## [2.17.1] - 2026-07-29 - Multi-server wildcard certificate workflow

### Added

- **Managed certificate cross-deploy**: Certificates → New/Edit can copy a managed ACME DNS-01 definition to selected Caddy servers. Each server obtains and renews its own certificate and private key; secrets and certificate material are not copied between Caddy instances.
- **Automatic wildcard discovery during proxy cross-deploy**: when “Also deploy to” is selected on a proxy host, CaddyUI finds managed certificates on the source server that cover the hostname and ensures equivalent definitions exist on every target. This works for servers added later without permanent cross-server certificate links.
- **Wildcard matching safeguards**: automatic reuse follows WebPKI semantics—`*.example.com` covers `app.example.com`, but not the apex or multi-level `deep.app.example.com`.

### Fixed

- **Managed certificate expiry display**: standalone ACME rows now show **Auto-renewed** in the Expires column instead of an unexplained blank value.
- **Multi-server form guidance**: certificate and proxy forms now explain which configuration is replicated, that each Caddy instance owns its own key/order, and how managed wildcards are reused.

---

## [2.17.0] - 2026-07-29 - Standalone managed wildcard certificates

### Added

- **Managed ACME source on Certificates**: create `*.example.com`, `*.sub.example.com`, or ordinary SAN certificates using any saved DNS credential profile. Caddy obtains and renews them through DNS-01; CaddyUI never stores or exports the private key.
- **Certificate-only wildcard routes**: managed entries emit a terminal 404 fallback host route, which instructs Caddy Automatic HTTPS to manage the requested subjects without requiring a fake proxy upstream. Real proxy and redirect routes retain priority and reuse the wildcard certificate.
- **Guided setup**: the certificate form and built-in documentation explain the Settings → DNS prerequisite, provider-module requirement, expected 404 fallback, and how Caddy reuses the certificate.

### Changed

- **Certificate selectors stay unambiguous**: managed ACME entries do not appear in the custom-certificate dropdown because they are automatically selected by SNI rather than attached as uploaded PEM material.

---

## [2.16.10] - 2026-07-28 - DNS automation sync compatibility

### Fixed

- **Fresh Caddy DNS-01 sync**: Managed DNS automation policies now create the missing `apps.tls` configuration branch before writing `apps.tls.automation`. This prevents `sync_apply_automation_failed` with Caddy's `invalid traversal path at: config/apps/tls/automation` error on installations that do not already have a TLS app.
- **Existing TLS settings preserved**: installations that already have `apps.tls` continue using the narrow automation-only update, preserving unrelated TLS configuration and avoiding unnecessary TLS module reprovisioning.

---

## [2.16.9] - 2026-07-26 - Caddy HTTP listener compatibility

### Fixed

- **Default port-80 sync failure**: CaddyUI now owns one explicit HTTP server for both open-HTTP hosts and Force SSL redirects, while disabling Caddy's competing automatic redirect listener. Sync works with Caddy's default `http_port` and no longer requires moving that port as a workaround.
- **Force SSL routing**: proxy hosts, redirections, and advanced routes with Force SSL enabled receive a CaddyUI-managed permanent HTTPS redirect; routes with Force SSL disabled continue serving normally over both HTTP and HTTPS.
- **Safe listener transitions**: sync disables Caddy's automatic redirect listener before creating the CaddyUI listener, and reverses that order when removing it, so live subtree updates never attempt to bind port 80 twice.

---

## [2.16.8] - 2026-07-25 - Faster Proxy Hosts page

### Fixed

- **Proxy Hosts page load time**: the list now selects only the 19 fields it renders instead of loading and scanning every optional proxy-host field, including large advanced-config, header, rule, and custom-page blobs.
- **Duplicate live Caddy request**: the separate Live upstream status panel no longer starts a second Caddy admin request automatically when the page opens. Row health continues loading normally; the detailed panel refreshes on demand.
- **Health endpoint query size**: live row-health checks reuse the lightweight proxy-host summary query.

---

## [2.16.7] - 2026-07-25 - DNS-01 certificate support and Caddy sync compatibility

### Added

- **DNS-01 for every Managed DNS provider**: proxy hosts, redirections, and advanced routes with Managed DNS selected now reuse those credentials for Let's Encrypt DNS-01 issuance. Supported providers are Cloudflare, Porkbun, Namecheap, GoDaddy, DigitalOcean, and Hetzner; the connected Caddy build must include the matching `caddy-dns` module.
- **All-provider Caddy build**: `Dockerfile.caddy` now includes the six DNS provider modules supported by CaddyUI.

### Fixed

- **Caddy sync `skip_redirects` rejection**: CaddyUI no longer emits the unsupported `automatic_https.skip_redirects` field. Hosts with Force SSL disabled are served through an explicit CaddyUI-owned `:80` server, matching Caddy's native Caddyfile adaptation while retaining HTTPS on `:443`.
- **Affected config cleanup**: sync removes any stale `skip_redirects` key before validation, so existing installations recover on their next sync.

---

## [2.16.6] - 2026-07-24 - MCP community integration and token-scope hardening

### Added

- **Community MCP integration docs**: added a README link to the community-maintained [CaddyUI-MCP](https://github.com/loryanstrant/CaddyUI-MCP) project, with guidance to use dedicated users and narrow API token scopes for agent automation.
- **API token scope documentation**: the REST API reference now explains `read_only`, `proxy_write`, and `full` token behavior, including the expectation that integrations managing redirections, raw routes, or certificates need a full-access token from an appropriately limited user.

### Fixed

- **`proxy_write` API token enforcement**: `proxy_write` bearer tokens are now limited to writes under `/api/v1/proxy-hosts`. Other write routes remain read-only for that token scope instead of behaving like full access.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.16.6` published.

---

## [2.16.3] - 2026-07-21 - Dashboard recommendations and CI gate

### Added

- **Dashboard recommended actions**: the dashboard now surfaces a compact advisor panel for actionable operational issues, including down upstreams, maintenance mode, SSL-disabled enabled hosts, incomplete managed DNS, missing DNS profile references, expired or soon-expiring custom PEM certificates, stale or missing syncs, missing snapshots, disabled 2FA enforcement, and an empty admin IP allowlist.
- **Basic Go CI gate**: added a GitHub Actions workflow that runs `go test ./...`, `go vet ./...`, and `go build ./cmd/caddyui` on pushes and pull requests to `main`.
- **Dashboard advisor tests**: added focused unit tests covering operational recommendations, admin hardening recommendations, certificate expiry detection, and recommendation noise limits.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.16.3` published.

---

## [2.16.2] - 2026-07-21 - Proxy Hosts loading speed hotfix

### Fixed

- **Proxy Hosts page slowdown after v2.16.1**: the new bulk certificate selector now loads lightweight certificate options (`id`, `name`, `domains`) instead of full certificate PEM/key payloads. This avoids dragging private key blobs into the proxy-host list render path.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.16.2` published.

---

## [2.16.1] - 2026-07-21 - Bulk proxy certificate assignment

### Added

- **Bulk apply certificates for proxy hosts**: the proxy-host bulk action bar now includes a certificate selector. Select multiple proxy hosts, choose a custom certificate or `Auto / ACME`, and apply once.

### Changed

- **Single sync after bulk certificate changes**: CaddyUI updates the selected proxy hosts and syncs Caddy once with TLS refresh, avoiding the old one-host-at-a-time workflow when rotating renewed certificates across many containers.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.16.1` published.

---

## [2.16.0] - 2026-07-21 - Multiple DNS credential profiles

### Added

- **Multiple Cloudflare DNS credential profiles**: Settings → DNS now supports additional named Cloudflare profiles, each with its own API token, proxy mode, and zone allow-list. This lets one CaddyUI install manage domains split across multiple Cloudflare accounts or tokens.
- **Per-host DNS profile selection**: proxy hosts, redirection hosts, and raw routes can pick a specific DNS credential profile while the legacy provider-wide settings continue to work unchanged.

### Changed

- **Managed DNS lifecycle**: zone loading, existing-record checks, record create/delete, public-IP retargeting, and wildcard DNS-01 automation now resolve credentials from the selected profile.
- **Safety guard**: if a saved row references a deleted/missing DNS profile, provider calls no-op instead of falling back to the global token and risking changes in the wrong account.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.16.0` published.

---

## [2.15.3] - 2026-07-21 - Security dependency refresh

### Security

- **Dependabot crypto alerts**: updated `golang.org/x/crypto` from `v0.45.0` to `v0.52.0`, resolving the open GitHub Dependabot alerts for the module.
- **Go toolchain**: updated the module and Docker build stage to Go 1.25 so the patched crypto module can be used.
- **Transitive modules**: refreshed `golang.org/x/sys` from `v0.38.0` to `v0.45.0` via `go mod tidy`.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.15.3` published.

---

## [2.15.2] - 2026-05-25 - Simple mode keeps DNS & TLS visible

### Fixed

- **Proxy form Simple mode**: DNS and TLS sections (`ph-dns`, `ph-tls`) now stay visible in Simple mode — those are the two most essential sections for any proxy host. Previously Simple mode hid everything including those, making it unusable. All other advanced sections (Security, Headers, Path routing, Rewrites, etc.) remain hidden until Advanced mode is selected.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.15.2` published.

---

## [2.15.1] - 2026-05-25 - Cache-bust static assets so new themes load immediately

### Fixed

- **Static asset cache-busting**: `app.css`, `app.js`, and `htmx.min.js` URLs now include `?v={{.AppVersion}}` so browsers always fetch the latest version after an upgrade instead of serving the 24h-cached old file. This was why the Forest / Rose / Indigo themes appeared as blue on first load — the new CSS never arrived.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.15.1` published.

---

## [2.15.0] - 2026-05-25 - Major UI overhaul: toasts, sparklines, themes, cert bars, quick-mode form

### Added

- **Toast notifications**: all form success/error/warning banners now slide in as auto-dismissing toasts (bottom-right, spring animation). Errors stay until dismissed. Maintenance banners remain inline. `window.caddyuiToast(msg, type, duration)` exposed for programmatic use.
- **Dashboard sparklines**: the three stat cards (Requests / Visitors / Bandwidth) now show a 7-day trend sparkline inline with the number. Fetched from new `/api/dashboard-sparklines` endpoint after first paint.
- **Certificate expiry progress bars**: each certificate now shows a thin horizontal bar below the name — green (≥ 60 d), yellow (< 60 d), amber (< 30 d), red (< 15 d / expired). Visual urgency at a glance in both mobile cards and desktop table.
- **3 new color themes**: Forest Green, Rose / Crimson, Deep Indigo — each with full light + dark palette. Theme picker in Settings now offers 5 options (+ existing Default Slate Blue and Carbon Orange).
- **Proxy form Simple / Advanced mode**: a pill toggle above the proxy host form hides all `<details>` expansion sections in Simple mode, showing only Domain, Forward Host/Port, and SSL — perfect for new users. Preference persisted to `localStorage`. Defaults to Simple on `/new`, Advanced on edit.
- **Toast container** (`#toast-container`) added to layout — `pointer-events: none` wrapper so it never blocks clicks.

### Fixed

- **Dark mode inconsistency in Settings**: all `dark:*-gray-*` Tailwind utility classes in `settings.html` replaced with the canonical `ink-*` token system used everywhere else. Resolves card background mismatches in dark mode (e.g., `dark:bg-gray-900` vs the `.dark .bg-white` override).

### Backend

- **`GET /api/dashboard-sparklines`**: new authenticated endpoint returning 7 days of daily `{ views, visitors, bandwidth }` totals scoped to the active server's hostnames. Used by JS sparkline renderer.
- **Color theme validation**: `postMyColorTheme` now accepts `forest`, `rose`, `indigo` in addition to `default` and `orange`.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.15.0` published.

---

## [2.14.3] - 2026-05-15 - Fresh-install Caddy crash-loop fix

### Fixed

- **Fresh install**: `docker-compose.yml` command now bootstraps an empty `{}` config on first boot so Caddy starts cleanly when `autosave.json` doesn't exist yet on a fresh volume. Previously Caddy would crash-loop with `open /config/caddy/autosave.json: no such file or directory`. Existing installs are unaffected — the one-liner is guarded by `[ -f ... ] ||` and skips entirely when the file already exists. ([#7](https://github.com/X4Applegate/caddyui/issues/7))

### Docs

- `README.md` Quick Start and Agent mode compose examples updated with the bootstrap command.
- `DOCKERHUB.md` compose example updated with the bootstrap command and a fresh-install callout note.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.14.3` published.

---

## [2.14.2] - 2026-05-13 - Porkbun API spec full compatibility

### Fixed

- **Porkbun domain struct**: added `securityLock`, `apiAccess`, and `notLocal` fields to the `Domain` struct - previously missing, silently dropped during decode. All three use the flexible `pbInt` type to handle string-or-int like the other integer fields.
- **Porkbun SSL import**: `publickey` field from `/ssl/retrieve` is now captured and returned in the `SSLBundle`.
- **Porkbun DNS create**: `id` field in the create-record response is now decoded as `string` (matching the v3 spec) instead of `json.Number`.

> `:preview`, `:stable`, `:latest` updated. Pinned tag `:v2.14.2` published.

---

## [2.14.1] - 2026-05-13 - Porkbun whoisPrivacy / autoRenew type fix

### Fixed

- **Porkbun JSON type mismatch**: Porkbun's `/domain/listAll` returns `whoisPrivacy` and `autoRenew` as quoted strings instead of bare integers. Added a private `pbInt` type with a custom `UnmarshalJSON` that accepts both forms. Resolves the "cannot unmarshal string into Go struct field Domain.domains.whoisPrivacy of type int" error on the Import from Porkbun and DNS pages. (Reported: issue #6)

> `:preview` updated. Pinned tag `:v2.14.1` published.

---

## [2.14.0] — 2026-05-13 · Porkbun SSL certificate import

### Added
- **Import from Porkbun**: new button on the Certificates page (visible when Porkbun API credentials are configured) that opens a domain picker and pulls the SSL bundle directly from your Porkbun account into CaddyUI as a stored PEM certificate. Uses the  Porkbun API v3 endpoint.
-  method added to the internal Porkbun client ().
- New page at  with domain dropdown (lists all Porkbun domains via ).

## [2.13.0] — 2026-05-10 · REST API v1 — full coverage for raw routes and certificates

> `:preview` updated. Pinned tag `:v2.13.0` published.

### Added

- **v2.13.0 — REST API v1 for raw routes.** Full CRUD + toggle: `GET /api/v1/raw-routes`, `GET /api/v1/raw-routes/{id}`, `POST /api/v1/raw-routes`, `PUT /api/v1/raw-routes/{id}`, `DELETE /api/v1/raw-routes/{id}`, `POST /api/v1/raw-routes/{id}/toggle`. Create/update accept `label`, `json_data`, `caddyfile_src`, `enabled`, `certificate_id`, `force_ssl`, `block_common_exploits`. Responses include the same fields plus `owner_email`, `created_at`, `updated_at`. Caddy is synced after every write. Requires write-scoped token or admin/write role for mutations.
- **v2.13.0 — REST API v1 for certificates.** Full CRUD: `GET /api/v1/certificates`, `GET /api/v1/certificates/{id}`, `POST /api/v1/certificates`, `PUT /api/v1/certificates/{id}`, `DELETE /api/v1/certificates/{id}`. Create/update accept `name`, `domains`, `source` (`pem` or `path`), `cert_pem`, `key_pem`, `cert_path`, `key_path`. Delete is blocked with HTTP 409 if the certificate is still referenced by any proxy host, redirection host, or raw route. Respects the existing per-user ownership model — non-admin users see only their own uploads plus global (admin-owned) certs.
- **v2.13.0 — `models.ToggleRawRoute`.** Added `ToggleRawRoute` to the models package (mirrors `ToggleProxyHost` / `ToggleRedirectionHost`) to support the new API toggle endpoint cleanly.

---

## [2.12.54] — 2026-05-10 · REST API v1 — full proxy host field coverage + docs fixes

>  `:preview` updated. Pinned tag `:v2.12.54` published (multi-arch `linux/amd64` + `linux/arm64`).

### Added / Fixed

- **v2.12.54 — PUT /api/v1/proxy-hosts/{id} now applies all 42 fields.** The update handler previously merged only 16 of the 42 fields accepted by the create endpoint — CORS settings, compression, security headers, TLS minimum version, health-check URI/interval/method, maintenance message, upstream timeout, keepalive connections, sticky sessions, load-balancer policy, strip-response headers, blocked agents, upstream SNI, HSTS preload, max connections per host, upstream retries, force-HTTP/1, proxy protocol, extra upstreams, basic-auth enabled, and certificate ID were all silently ignored on PUT. Every field in `apiProxyHostInput` is now applied on update (strings: merge if non-empty; booleans/ints: always applied).
- **v2.12.54 — API docs corrected field names.** The `/api/docs` reference page used wrong field names in several examples: `domain_names` → `domains`, `forward_domain_name` → `forward_domain`, `http_code` → `forward_http_code`. Examples now show the actual JSON keys the API returns and include the full set of response fields.

---

## [2.12.53] — 2026-05-03 · Multi-provider AI + Lighthouse 99/100/100/100 + Caddyfile export + bug fixes (cumulative)

> **Patch wave on top of v2.12.35.** Pinned tag `:v2.12.53` (multi-arch `linux/amd64` + `linux/arm64`). `:latest` + `:stable` retag from v2.12.35 → v2.12.53. `:preview` rolls on every dev push.

Eighteen patch versions in one cumulative entry, covering the multi-provider AI assistant (v2.12.36), the long performance + accessibility wave that took PageSpeed from ~30 to **99 desktop / 76 mobile / 100 a11y / 100 SEO / 100 best-practices** on `/login`, the new Caddyfile export, and a critical SQL-INSERT column-count fix that affected fresh installs of v2.12.48–v2.12.52.

### Critical fix (v2.12.53)

- **v2.12.53 — proxy host INSERT had 331 placeholders for 330 columns.** Introduced in v2.12.52 when `disable_upstream_compression` was added and an unrelated field was partly reverted, leaving one stray `?` in the `VALUES (...)` line. Reproducible on a fresh DB: any "New Proxy Host" submit failed with `SQL logic error: 331 values for 330 columns (1)`. Reported via [issue #5](https://github.com/X4Applegate/caddyui/issues/5). Fixed by regenerating the `VALUES` line via Python so the count is provably correct, plus an audit script in the commit message that catches this kind of regression across every INSERT in `models.go`.
- **v2.12.53 — friendly bind-mount permission error.** Bind-mount users on docker-compose / podman-compose used to hit cryptic SQLite "unable to open database file (1)" errors when the host directory wasn't owned by uid 10001. The binary now probes `/data` writability at startup and prints an actionable multi-line error pointing at the three reasonable fixes (chown / `--user 0:0` / named volume).

### Caddyfile export (v2.12.49 + v2.12.50)

- **v2.12.49 — Caddyfile export, full-server.** New `GET /proxy-hosts/export-all.caddyfile` endpoint + UI button next to "Export JSON". Exports every enabled proxy host, redirection, and raw route on the active server as a Caddyfile, round-trippable through the existing `/caddyfile-import` paste flow for the directives it contains. Same RBAC scoping as the JSON exports — admin gets the full server config, non-admin only their own resources. Stable sort by hostname for diffability. Per-host `# Notes:` block lists settings that don't fit cleanly into Caddyfile syntax (maintenance windows, basic-auth users, scheduled blocks, IP allow/deny, URL rewrites, path-based upstreams, blocked agents) so users see what was elided rather than silently losing it on round-trip.
- **v2.12.50 — Caddyfile export, per-host.** Single-host download from the proxy-host edit page. Same renderer as the full-server export.

### Notification channels (v2.12.51)

- **v2.12.51 — ntfy.sh notification channel + sendNotification fan-out wrapper.** Adds [ntfy.sh](https://ntfy.sh) alongside the existing webhook + email notification channels. Useful for self-hosted push notifications without running a Discord/Slack workspace. Configure in **Settings → Notifications**: ntfy server URL (default `https://ntfy.sh`), topic name, optional auth token. The new `sendNotification` wrapper fans out cert-expiry / upstream-down events to every enabled channel in one call.

### Performance + accessibility wave (v2.12.38 → v2.12.48)

| Version | Change | Mobile | Desktop |
|---|---|---|---|
| ~v2.12.37 baseline | Pre-tuning | ~30–40 | ~50–60 |
| v2.12.38 | `Cache-Control: max-age=86400` on `/static/*` + custom request/response header `+ Add` buttons (the buttons existed but had no JS click handler) | ~40 | ~70 |
| v2.12.39 | Self-host Inter variable font + htmx (drop fonts.gstatic.com + unpkg.com from cold loads); service-worker rewrite (auto-purges stale caches per release) | ~50 | ~80 |
| v2.12.40 | Preload Inter font, preconnect cdn.tailwindcss.com | ~55 | **91** |
| v2.12.41 | Externalize 28 KB inline JS to `/static/app.js` (cached across navigations); TBT 2,230 ms → 690 ms | ~55 | ~95 |
| v2.12.42 | Preload `app.js`, defer non-critical `/api/version-check` + `/api/ai/status` past Lighthouse's measurement window; TBT 690 ms → 0 ms | 55 | ~96 |
| v2.12.43 | `auth.css` for `/login` (24 KB precompiled, drops 124 KB Tailwind CDN runtime on the page Lighthouse always tests) | **76** | ~99 |
| v2.12.44 | Section anchor pills on the proxy host form, ordered by usage frequency | 76 | 99 |
| v2.12.45 | Physical reorder of proxy host form sections to match the pill priority | 76 | 99 |
| v2.12.46 | `aria-current="page"` on active nav link, `aria-label`s on icon-only buttons, skip-to-main-content link | 76 | 99 |
| v2.12.47 | `<label for>` ↔ `<input id>` associations on every unauth page (login, setup, forgot/reset-password, accept-invite) | 76 | 99 |
| v2.12.48 | `<meta name="description">` on every page for SEO 100 | **76** | **99** |

End state on `/login`: **Performance 99 · Accessibility 100 · Best Practices 100 · SEO 100** with FCP 0.5 s, LCP 0.9 s, TBT 0 ms, CLS 0.001. Mobile 76 with the same metrics shape (FCP/LCP higher only because of Lighthouse's simulated 4× CPU + 1.6 Mbps mobile network — a residential ISP can't beat that without Cloudflare in front).

### Multi-provider AI assistant (v2.12.36 → v2.12.37)

- **v2.12.36 — AI assistant supports any backend.** New provider selector in **Settings → AI assistant**: Ollama (local) / Ollama Cloud / Anthropic Claude (Haiku 4.5 / Sonnet 4.6 / Opus 4.7) / any OpenAI-compatible API (also drives OpenRouter, Groq, Together, vLLM, LM Studio). Each provider has its own URL/key/model fields with show/hide JS. Three Go adapter funcs (`aiCallOllama`, `aiCallAnthropic`, `aiCallOpenAI`) translate messages + tool definitions to each provider's schema and normalize back to the existing `{reply, tool_calls}` contract so the chat panel didn't need to change. Adapters handle the per-provider quirks: Anthropic puts `system` at the top level (not in messages), tools use `input_schema` (no `function` wrapper), tool calls come as `tool_use` content blocks. OpenAI returns tool-call arguments as a JSON-encoded **string**, not an object — needs an extra `Unmarshal` pass.
- **v2.12.37 — F12 leak fix for AI provider keys.** v2.12.36 rendered saved Anthropic / OpenAI / Ollama Cloud keys directly into `<input value="...">` on the Settings page; `type="password"` masked them visually but DevTools → Elements showed each in plaintext. Fixed by matching the existing SMTP-password pattern: input always renders `value=""`, conditional placeholder `•••••••• (key set)` when stored, save only persists when the user types a fresh value (empty submit keeps existing key). `getSettings` passes only `*KeySet` booleans to the template — never the actual keys.

### Other v2.12.x patch-wave items

- **v2.12.36 + v2.12.37** also shipped a major README + landing-page rewrite with the AI multi-provider explainer + AI auto-fill walkthrough, and a docs/index.html cleanup (orphan files removed).
- **v2.12.41** also removed the Tailwind self-host attempt that produced a 3.76 MB tailwind.css due to opacity-modifier auto-expansion across the default theme.colors palette. Reverted; `cdn.tailwindcss.com` stays for authenticated pages where the JIT runtime makes sense (the `auth.css` work in v2.12.43 covered the unauth pages where it doesn't).
- **v2.12.52 — per-host "Disable upstream compression" toggle.** Emits `transport http { compression off }` so Caddy doesn't ask the upstream to send compressed responses. Useful when the host has the existing Compression toggle on (`encode zstd gzip`) — pairs cleanly so Caddy is the single source of truth for compression. Caddy JSON: `transport.http.compression: false`. Caddyfile: `compression off` inside the `transport http { ... }` block. Round-trips through `/caddyfile-import`.

### Upgrade

```
docker pull applegater/caddyui:v2.12.53  # pinned (this release)
docker pull applegater/caddyui:latest    # rolling, retagged from v2.12.35 → v2.12.53
docker pull applegater/caddyui:stable    # alias of :latest
docker pull applegater/caddyui:preview   # rolling dev push
```

In Portainer: **Recreate** → enable **Re-pull image**. Migrations run automatically. No downtime beyond the container restart.

> **One-time service-worker cleanup** if upgrading from v2.12.38 or earlier: F12 → **Application** → **Service Workers** → **Unregister** next to your CaddyUI domain, then Ctrl+Shift+R. The new SW (v2.12.39+) auto-purges old caches per release, so this is needed only once.

Multi-arch on Docker Hub (`linux/amd64` + `linux/arm64`, scratch base, non-root UID 10001).

### Per-version detail

The eighteen patch versions in this wave each have their own commit message with full per-version detail. See `git log v2.12.35..v2.12.53` for the chronological narrative, or the GitHub releases for v2.12.37, .39, .40, .43, .53 for the headline cuts.

---

## [2.12.35] — 2026-04-29 · Carbon Orange theme + UI modernization + AI assistant overhaul + sync/header fixes (cumulative)

> **Patch wave on top of v2.12.12.** Pinned tag `:v2.12.35` (multi-arch). Rolling Docker tags (`:latest`, `:stable`) untouched in this release; `:preview` reflects the latest dev push as usual.

23 patch versions in one cumulative entry, headlined by a new Carbon Orange color theme that syncs across devices, a UI modernization pass, and a deep AI-assistant overhaul that makes the chat panel actually understand CaddyUI's own surface area.

### Added

- **v2.12.34 — AI assistant gets full CaddyUI app knowledge.** Added a `CADDYUI APP KNOWLEDGE` section to the default system prompt mapping every sidebar page (Dashboard, Proxy Hosts, Redirections, Advanced, Certificates, Import, Caddyfile, Analytics, Live Traffic, Snapshots, Activity, Caddy Config, API, API Tokens, Servers, Users, Groups, Settings), every Settings section with field inventory, multi-server architecture, RBAC roles, cross-cutting features, and the proxy-host form's section structure. The model now points users at the exact page → section → field instead of guessing. Users with a custom system prompt won't inherit this — clear the field to pick up the new default.
- **v2.12.33 — AI assistant defaults to production-grade Caddyfiles.** Rewrote the prompt's example library from 3-line stubs to production-shape templates (encode zstd gzip, `@blocked` path filter, security header bundle, full `header_up` trio for `reverse_proxy`). Richer per-app templates for Nextcloud (with the well-known CalDAV/CardDAV redirects), HTTPS upstream + custom Host header + transport block, WebSocket/SSE/streaming backends with `flush_interval -1`, 301/302 redirects, and wildcard DNS-01 certs. New rule: model follows each Caddyfile with 3–6 bullets mapping each directive to its CaddyUI form field.
- **v2.12.28 — Server picker dropdown in the top bar.** The current server's status dot + name + URL in the persistent top bar is now a button that opens a dropdown listing every Caddy server with its status, name, admin URL, and a checkmark on the current selection. Submission goes to `/servers/{id}/select` (same endpoint the sidebar picker uses) so behaviour is identical — just reachable from every breakpoint. Single-server installs still get the read-only label.
- **v2.12.27 — Color theme syncs across devices via per-user DB column.** New `users.color_theme` column (`''` = default, `'orange'` = carbon orange) populated server-side so the layout renders `<html data-color-theme="...">` before any script runs (no paint flash). Bootstrap script reconciles localStorage with the server value. New `POST /api/me/color-theme` endpoint validates the theme name. Picker is fire-and-forget on change so the visual update is instant.
- **v2.12.25 — UI modernization pass.** (1) Avatar dropdown menu collapses Profile / 2FA / Sign out under the avatar+chevron, dropping the persistent top bar from 8 visible items to 4 on mobile. (2) Card shadows simplified from a double-stack to a single 1px lift, with a `shadow-card-hover` variant for elevated states. (3) Typography: `font-optical-sizing: auto` (Inter has a variable opsz axis), `font-feature-settings ss03+cv11`, tighter `-0.022em` letter-spacing on display sizes. (4) Spacing: Settings form `space-y-6` → `space-y-8`, dashboard `mb-6` → `mb-8` between section cards. (5) Sidebar section labels (Routes / Config / System) now render as inline caps + a thin trailing hairline divider instead of standalone uppercase text.
- **v2.12.22 — Carbon Orange color theme + per-device picker in Settings.** Adds an orange/black palette as an alternative to the default slate-blue, combinable with the existing light/dark/auto toggle. CSS overrides target Tailwind utility classes via `[data-color-theme="orange"]` attribute selectors layered after the `.dark` rules. Brand blue → orange (`#e8890a`/`#b86d08`/`#f4a85e`); dark+orange swaps the slate background for warm carbon blacks (`#0c0b09`/`#131210`/`#1a1814`) with cream text. Bootstrap script in `<head>` reads `localStorage('caddyui-color-theme')` synchronously before first paint to avoid flash. `window.caddyuiSetColorTheme()` exposed for programmatic use. Palette inspired by the BNN Label Automation page that prompted this work.
- **v2.12.14 — Global strip-response-headers setting.** New Settings → General → "Globally stripped response headers" field — comma-separated header names that get deleted from every proxy host's upstream response. Useful for apps that ship with `helmet` middleware adding `X-Frame-Options` / `X-Powered-By` etc. that you want gone fleet-wide. `syncCaddy` reads the setting once per sync and prepends the global list to each proxy host's `StripResponseHeaders` field before `BuildProxyRoute`. Per-host `strip_response_headers` still works independently — both lists concatenate.

### Fixed

- **v2.12.35 — Silenced `syncCaddy` errors + removed dead Upstream Network field.** ~23 handlers were calling `s.syncCaddy()` and silently dropping the error — proxy/redirect/cert/raw-route create+update+delete, AI tool calls, and several bulk actions all flipped state in the DB but never logged when Caddy rejected the new config. The v2.12.20 `network` field validation bug was undetectable in production for weeks because of this. New helper `trySyncCaddy(serverID, forceTLS)` does the call + logs on error; bulk-replaced every silent call site. Also removed the dead "Upstream Network" form field (DB column + model field kept for back-compat); replaced with a comment pointing to the legitimate "DNS Resolver" field.
- **v2.12.32 — AI chat input is a textarea (wraps + auto-grows + Enter-to-send).** Previously a single-line `<input type="text">` — pasting a multi-line Caddyfile compressed it to one horizontally-scrolling line. Now a `<textarea>` with `rows=1` default (matches the previous single-line look), auto-grow up to 8rem (~6 lines) on input, internal scroll past that, whitespace wrapping by default. `Enter` submits, `Shift+Enter` / `Ctrl+Enter` inserts a newline. Form's flex alignment changed from `items-center` to `items-end` so the Send button sits at the bottom-right of a tall textarea.
- **v2.12.31 — AI chat code blocks wrap long lines, no more horizontal overflow.** `<pre>` switched to `whitespace-pre-wrap break-all` so long lines wrap at any character instead of overflowing. Removed `overflow-x-auto`; added `max-w-full`. Bubble widened from `max-w-[85%]` to `max-w-[95%]` for code-heavy replies. `spellcheck="false"` suppresses the red-squiggle artifacts browsers drew on Caddyfile keywords like `keepalive_idle_conns`.
- **v2.12.30 — Proxy host form search hides empty `<details>` sections.** The form has 36 collapsible sections covering 300+ options. The existing field-search hid non-matching fields but left every `<details>` header visible — typing "X-Frame" produced a list of empty section labels with the actual hit buried inside. Now: any `<details>` that doesn't contain a matched field is hidden entirely; sections with matches stay visible AND auto-open as before. Empty query restores everything.
- **v2.12.29 — Carbon dropdown panels in dark+orange + toggle sync error logging + AI prompt feature inventory.** (1) User-menu and server-menu dropdowns in dark+orange were inheriting `dark:bg-slate-800` (bluish-slate) inside the otherwise warm orange theme; now explicitly painted with the carbon palette (`#131210` background, `#2a2720` borders). (2) The proxy host enable/disable toggle's auto-sync now logs sync errors instead of silently swallowing them — past bugs (the v2.12.20 `network` field) were invisible because of this. (3) AI assistant system prompt's UI feature inventory expanded so the model stops sending users to the non-existent "manual Caddyfile editing" path for things that ARE UI-supported (security headers bundle, path blocking, compression, custom headers, upstream TLS, keepalive, timeouts, `flush_interval`, etc.).
- **v2.12.26 — Green status dot + orange-accented top bar in orange theme.** (1) Server online status dot was using `bg-brand-500` (orange in the orange theme), conflicting with offline (red). Switched to `bg-emerald-500` — online = green is a universal UI convention we shouldn't break for theme aesthetics. (2) Persistent top bar now reads as part of the orange palette: `data-topbar` hook attribute, bottom border switches to orange `#e8890a` + 1px inset shadow, dark+orange uses warmer carbon `#1a1408` for the bar background.
- **v2.12.24 — Hide duplicate moon on mobile + polish top-bar icon buttons.** Two top bars stack on mobile (the dedicated `<header lg:hidden>` and the sticky persistent top bar visible at all widths). Both contained a theme-toggle moon, so squeezing the viewport showed two moons. Persistent top-bar moon now `hidden lg:inline-flex` — mobile keeps exactly one, desktop keeps exactly one. Search + theme buttons in the persistent top bar redone as consistent rounded-full pills (`w-8 h-8`) with subtle `bg-ink-100` hover.
- **v2.12.23 — Orange theme repaints `blue-*` utility classes too.** v2.12.22 only overrode `brand-*` color classes, but the codebase uses raw Tailwind `blue-*` utilities directly in places — notably `text-blue-400` on the active sidebar nav-item icon. Added overrides for `bg-blue-{50,100,400,500,600,700,900}`, `text-blue-{400,500,600,700}`, `ring-blue-500`, `bg-slate-700/60` (active nav background → semi-transparent orange tint), and `hover:bg-slate-800` (subtle orange hover for inactive items).
- **v2.12.21 — Defer all `response.delete/set` to actually catch upstream headers.** Caddy's `headers` handler runs request-side by default. Without `deferred: true`, a `response.delete` fires BEFORE `reverse_proxy` is called — the header doesn't exist yet, the delete is a no-op, and upstream's value flows through unchanged. Concrete bug: Settings → "Globally stripped response headers" with `X-Frame-Options` was leaking upstream's `SAMEORIGIN` value through to the client even with the strip handler in the route. Fix: a single loop in `BuildProxyRoute` post-hoc applies `deferred: true` to every response op rather than re-wiring 30+ emit sites in `client.go`.
- **v2.12.20 — Drop invalid `network` field from `reverse_proxy` transport.** Caddy's `http.reverse_proxy.transport.http` schema has no `network` field. v2.9.63 emitted `transport["network"] = p.UpstreamNetwork` to force IPv4/IPv6 — older Caddy silently ignored the unknown key, so it looked like it worked. Current Caddy versions reject the config at `/load` with `json: unknown field "network"`, breaking every Sync Caddy. Stop emitting the field. The `UpstreamNetwork` model field + Settings UI stay (so existing preferences aren't wiped) but the field is a no-op until a real implementation lands (`dial_address` with explicit-family resolver or a custom dialer module).
- **v2.12.19 — Sync Caddy button no longer triggers a "reload" file download.** `/caddy/reload` was returning `204 No Content` + an `HX-Trigger` response header — assuming the dashboard's Sync Caddy form was HTMX-driven. It isn't; it's a plain form POST. Recent Chromium versions treat a `204` from a plain form POST with no `Content-Type` as "save the URL's last segment as a file" — users were seeing repeated downloads of a zero-byte file named `reload`. `reloadCaddy` now redirects (303 See Other) back to the `Referer`, completing the form submit cleanly. `HX-Trigger` preserved for any future HTMX wiring.
- **v2.12.18 — Revert `stripHeaderWriter` (broke streaming/Content-Type) + auto-sync after Settings save.** (1) Reverted the `stripHeaderWriter` from v2.12.15 — it didn't implement `http.Flusher` / `http.Hijacker`, and some response paths (Caddy-served static, template streaming) lost their `Content-Type` handshake, causing `/admin` pages to come down as downloads. The conditional `stripped[...]` skips on the three explicit `Set` calls cover the actual case the global-strip was trying to address. (2) `postSettings` now spawns `syncCaddy(serverID, false)` as a goroutine before the redirect-back-to-`/settings` so changes affecting live Caddy config (`global_strip_response_headers`, `catch_all_404_html`, `global_maintenance`) take effect on save without manual Sync Caddy clicks.
- **v2.12.17 — Analytics page scope includes redirection hosts.** `scopedHostsForAnalytics` was iterating proxy hosts + raw routes but silently skipping redirection hosts. Result: when an admin scoped to a specific server in the analytics picker, traffic to redirect-only hostnames didn't contribute to today's totals, the 24h chart, or top-hosts. Now the scope-builder also lists `ListRedirectionHosts(serverID, ...)` and feeds each row's `DomainList()` into the allowed-hosts set — same treatment proxy hosts already get. Dashboard cards already counted redirections (v2.12.8); this brings the analytics page in line.
- **v2.12.16 — SecurityHeaders bundle skips headers in the global-strip list.** v2.12.14 + v2.12.15 stripped headers from upstream responses + from CaddyUI's own pages, but the per-host `SecurityHeadersEnabled` bundle was still emitting `response.set X-Frame-Options: SAMEORIGIN`. The bundle's set fires LAST in the response chain, so the strip's deletion was being undone. Fix: `BuildProxyRoute` filters the bundle map against `p.GlobalStripHeaders` before emitting — headers in both lists are removed from the bundle entirely. Empty bundle → handler block skipped entirely. New in-memory-only `GlobalStripHeaders` field on `ProxyHost` (`json:"-"`, not persisted); `syncCaddy` populates it once per sync.
- **v2.12.15 — Global strip-headers also strips CaddyUI's own response headers.** v2.12.14 only stripped from upstream proxy-host responses; the `securityHeaders` middleware on CaddyUI's own pages (login redirect, admin UI, `/api/*`) was still unconditionally setting `X-Frame-Options: SAMEORIGIN`. Now `securityHeaders` reads the global-strip list at request time and skips the unconditional `Set` for any header in the list. (Also added a `stripHeaderWriter` to drop matching headers downstream handlers tried to set on their own — *reverted in v2.12.18* after it broke streaming.)
- **v2.12.13 — `/analytics` defaults to active server (cross-fleet is opt-in).** Bare `/analytics` was hitting the cross-fleet hot path — single `AccessTotalsSince("")` query plus per-host iteration across every hostname any registered server routes. Slow on multi-server installs and almost never what the user wants. When `?server=` is absent, it now scopes to the picker-active server (`s.currentServerID(r)`, the same cookie that drives the rest of the UI). Cross-fleet still available — pick "All servers (slow)" in the page picker, which sends `?server=all` explicitly. `?server=0` still works as the cross-fleet alias for back-compat.

---

## [2.12.12] — 2026-04-28 · AI tool calling + dashboard scoping + 13 CodeQL fixes (cumulative)

> **Patch wave on top of v2.12.4.** Republishes `:latest`, `:stable`, `:preview`, and `:v2.12.12` (multi-arch). `:latest` retags from v2.12.4 → v2.12.12.

Eight patch versions in one image, headlined by a real LLM tool-calling pipeline that can actually create proxy hosts and redirections from a chat prompt.

### Added
- **v2.12.11 — AI tool calling.** The chat panel now exposes `create_proxy_host` and `create_redirection` as Ollama tools. The model decides when to emit a `tool_call` (vs. a Caddyfile snippet); the frontend renders a confirmation card with the exact arguments; the user clicks Apply, and the resource is actually created. Every exec writes an `ai_tool_call` activity-log row. Works on qwen2.5 / llama3.1+ / gemma2; older models silently ignore the tools field.
- **v2.12.10 — AI conversation memory + custom system prompt.** `/api/ai/chat` now accepts `{messages:[{role,content},...]}` for multi-turn context — "make one here" actually refers back to what was discussed. New "New chat" button in the modal header clears context. New Settings → AI assistant → Custom system prompt textarea overrides the built-in CaddyUI prompt without writing an Ollama Modelfile.
- **v2.12.7 — Markdown rendering in AI chat bubbles.** Llama / Qwen output `**bold**`, fenced code blocks, ` `inline code` `, lists. Tiny in-line renderer (no CDN, no library) handles them safely (HTML-escape first, then regex-replace markers).
- **v2.12.6 — Per-section Save buttons on Settings.** General / AI assistant / DNS IPs / Captcha sections now have Save buttons inline so users don't have to scroll to the page bottom for every toggle change.

### Fixed
- **v2.12.12 — 13 CodeQL js/xss-through-dom alerts** silenced by rewriting bulk-action-bar hidden-input building (`/proxy-hosts`, `/redirection-hosts`, `/raw-routes`, `/certificates`) and the path-based-upstream-rules row builder (proxy_host_form) from `innerHTML` string concat to DOM API (`createElement` + `.value` + `replaceChildren`). No behaviour change; just safer construction that CodeQL can verify.
- **v2.12.9 — Wildcard hostnames count traffic in dashboard + analytics.** Proxy hosts with `*.example.com` in Domains were being passed as a literal `host = '*.example.com'` filter to `AccessTotalsSince` / `BandwidthSince` — never matched. New `hostMatchClause` helper detects the `*.` prefix and translates to `host LIKE '%.example.com'`. Wildcard-routed traffic now contributes to per-server cards.
- **v2.12.8 — Dashboard cards scoped to active server.** Requests / Visitors / Bandwidth Today were summing across the whole fleet instead of the active picker selection. Now loops over the active server's hostnames and sums per-host (same pattern `/analytics?server=<id>` already used).
- **v2.12.5 — AI assistant beefed-up system prompt + model-size hint.** llama3.2:3b was hallucinating Caddy v1 trivia and inventing directives. Concrete Caddyfile examples in the prompt + an explicit "say I don't know" rule. Settings now warns about 3B-class models and recommends qwen2.5:14b / qwen2.5-coder:14b / gemma2:9b / llama3.1:8b for actually-correct answers.

---

## [2.12.4] — 2026-04-28 · Managed DNS on redirections + multi-domain checks (cumulative)

> **Patch wave on top of v2.12.0.** Republishes `:latest`, `:stable`, `:preview`, and `:v2.12.4` (multi-arch). `:latest` retags from v2.12.0 → v2.12.4.

This block consolidates four small releases that landed right after v2.12.0:

### Added
- **v2.12.1 — per-hostname DNS-record pre-flight on multi-domain routes.** The Managed-DNS form now iterates *every* hostname in the route's `match.host` (or the proxy host's Domains CSV) and shows a per-hostname status checklist: `⚠ already exists, will skip` vs `✓ will be created`. Backend has been creating records per hostname since v2.5.9; the form now matches.
- **v2.12.2 — Managed DNS for redirection hosts.** Closes the long-standing gap where proxy hosts and raw routes had Managed DNS but redirections didn't. New `dns_provider` / `dns_zone_id` / `dns_zone_name` / `dns_record_id` columns on `redirection_hosts`; new picker on the redirection edit form (right under TLS Certificate); `dnsCreateRecordForRedirection` mirrors the proxy-host helper. A record per hostname auto-created on save, deleted on row removal.

### Fixed
- **v2.12.3** — closed an unbalanced `{{if .AnyDNSEnabled}}` block in `redirection_host_form.html` that surfaced as `template: redirection_host_form.html:486: unexpected EOF` in the server log on every redirection-form render after v2.12.2.
- **v2.12.4** — redirection-host zone picker was checking `data.zones` but `/api/dns-zones` returns a flat `[{id,name},...]` array, so Cloudflare zones never populated. Picker now accepts both shapes.

---

## [2.12.0] — 2026-04-28 · UX & navigation polish — major release

> **Major release.** Published as `applegater/caddyui:v2.12.0`, `:preview`, `:stable`, and `:latest` (multi-arch `linux/amd64` + `linux/arm64`). Consolidates the v2.11.0 → v2.11.18 preview cycle into the new GA tag. **`:latest` now points at v2.12.0**, replacing the previous v2.11.7.

### What's included

The v2.11 preview cycle was the largest UX-only release in CaddyUI's history — 18 numbered preview builds spanning navigation, search, form ergonomics, bulk operations, and live-edit tooling. v2.12.0 ships all of it as one stable cut.

#### Navigation & search
- **⌘K / Ctrl+K command palette** searching every proxy host, redirection, raw route, and certificate (v2.11.5).
- **Live filter inputs** on `/raw-routes`, `/certificates`, `/redirection-hosts` (matching the existing `/proxy-hosts` pattern; v2.11.0).
- **Tri-state theme toggle** (auto / light / dark) tracking system preference by default (v2.11.0).
- **Quick-nav chord shortcuts** (`g d` / `g p` / `g r` / `g c` / `g a` / `g n`) (v2.11.0).
- **Keyboard-shortcut overlay** (`?`) listing every binding (v2.11.0).

#### Proxy-host edit form (top-down reorder)
After v2.11.0 → v2.11.8, the form reads:
1. Domain names
2. Forward Scheme + Host + Port + Test upstream
3. Enabled / Auto SSL / Force SSL
4. Managed DNS
5. TLS Certificate
6. Path matching + tags + notes (collapsed)
7. Upstream TLS & advanced settings (collapsed)
8. Options & Forwarded Headers (collapsed, ~70 fields)

Plus: configured-field count badges on every collapsed `<details>`, sticky save bar, live route-JSON preview.

#### Bulk operations on every list page
- `/proxy-hosts` (existing) — Enable / Disable / Delete / Maintenance bulk
- `/redirection-hosts` (v2.11.6) — Enable / Disable / Delete bulk
- `/raw-routes` (v2.11.9) — Enable / Disable / Delete bulk
- `/certificates` (v2.11.10) — Delete bulk (honours in-use guard)

#### Drag-to-reorder
Per-row ⠿ handles on `/proxy-hosts` and `/redirection-hosts` — UI-only, writes `sort_order = index*10` (v2.11.11).

#### Dashboard widgets
- **Recently edited** strip — last 8 CRUD events across all resource types (v2.11.12).
- **Caddy fleet status grid** — one card per registered server with status, host count, version, last seen (v2.11.16). Renders only when more than one server is registered.

#### Operational features
- **Live route-JSON preview** on the proxy-host form — shows the exact Caddy JSON the form would push, refreshing as you edit. Lenient on missing required fields (v2.11.13, fixes in v2.11.17 and v2.11.18).
- **Notifier covers ACME / Let's Encrypt managed live certs** — daily TLS dial against each enabled SSL-on proxy host, fires webhook + email when expiry is within threshold (v2.11.14).
- **AI assistant powered by local Ollama** — opt-in floating chat button. Settings: enable toggle, Ollama URL (default `http://ollama:11434`), model name (default `llama3.2:latest`). Runs locally, no cloud calls (v2.11.15).
- **Wildcard cert auto-issuance via DNS-01** — `*.example.com` in Domains now triggers an automatic `apps.tls.automation.policies` entry that drives Caddy's DNS-01 challenge using the Cloudflare token already configured for managed DNS. Frontend shows a live callout when wildcards are detected in the form. Cloudflare-only for v2.12.0; other DNS providers can be added incrementally (v2.11.19).

### Upgrade

```
docker compose pull && docker compose up -d
# or in Portainer: Recreate → enable Re-pull image
```

`:latest`, `:stable`, `:preview`, and `:v2.12.0` all point at the same multi-arch manifest. Migrations run automatically on startup. No downtime beyond the container restart.

### Per-version preview cycle

The v2.11.0 → v2.11.18 entries below remain for traceability — every preview build's individual changes are documented in this changelog.

---

## [2.11.19] — 2026-04-28 · Wildcard SAN auto-detection + DNS-01 ACME automation

> Preview build folded into v2.12.0.

### Added
- **Wildcard auto-detection on the proxy-host form.** When the Domains field has a `*.foo.bar` entry, a live callout under the field explains that DNS-01 ACME challenge will be used and asks for / confirms the Managed DNS provider selection.
- **Auto-emitted `apps.tls.automation.policies` for wildcard hosts.** `syncCaddy` now scans every enabled SSL-on proxy host, groups wildcard subjects by their Managed-DNS provider, and pushes a per-provider automation policy via the existing `pushAutomationPolicies` plumbing. The DNS provider's existing credentials (e.g. `cf_api_token`) are reused — no duplicate-entry friction.
- Cloudflare is the only provider mapped for v2.12.0. Other DNS providers slot into `caddyDNSProviderConfig` as their caddy-dns plugin schemas are confirmed.

### Caveats
- Caddy must include the `caddy-dns/<provider>` plugin (xcaddy build). Default `caddy:2-alpine` has no DNS plugins; users hitting "unknown module" errors should switch to a custom xcaddy build.
- The auto-emit is non-fatal: if Caddy rejects the policy, routes + apex certs are still applied. The failure surfaces as `sync_apply_automation_failed` in the activity log.

---

## [2.11.16] — 2026-04-28 · Multi-server health widget on the dashboard

> Preview build (`applegater/caddyui:v2.11.16` and `:preview`). `:latest` still pinned at v2.11.7.

### Added
- **Caddy fleet status grid on `/`.** One card per registered Caddy server with online/offline/unknown status, host count, Caddy version, and "last seen" relative timestamp. The active server (matching the picker) gets a brand-tinted ring; non-active rows show a "Switch to this server" button. External (read-only) servers carry a `read-only` tag so users remember they can observe but not push config there.
- Renders only when more than one Caddy server is registered. Single-server installs see no widget.

---

## [2.11.15] — 2026-04-28 · AI assistant powered by local Ollama

> Preview build (`applegater/caddyui:v2.11.15`).

### Added
- **Floating AI chat button** (bottom-right) that proxies prompts to a local Ollama instance. Useful for "explain this proxy host", "convert this Caddyfile snippet", "suggest headers for Nextcloud", etc. Runs locally on your GPU — no cloud calls.
- **New settings section** (Settings → AI assistant): enable toggle, Ollama base URL (default `http://ollama:11434`), model name (default `llama3.2:latest`).
- New endpoints `GET /api/ai/status` (so the floating button hides when AI is off) and `POST /api/ai/chat` (proxies to Ollama's `/api/chat` with a CaddyUI-flavoured system prompt that steers generic models toward Caddy / TLS / DNS answers).
- 60-second context-deadline on the upstream call so a slow / hung Ollama doesn't park a request handler indefinitely.
- MVP scope: single-shot Q&A, no server-side history. `Esc` closes the modal; `Enter` sends.

---

## [2.11.14] — 2026-04-28 · Notifier covers Let's Encrypt / ACME-managed live certs

> Preview build (`applegater/caddyui:v2.11.14`).

### Added
- **Cert-expiry alerts now cover Caddy-managed (ACME / LE / ZeroSSL) certs.** The existing notifier only inspected custom certs stored in CaddyUI's DB — production deployments using auto-issuance got no warning when those expired. v2.11.14 adds a daily TLS dial against `{first_domain}:443` for every enabled SSL-enabled proxy host, reads the peer cert chain, and fires the same webhook + email channels when expiry is within the configured threshold.

### Internal
- Reuses `notifierState.lastNotified` for 24h dedup; entries are keyed `proxy:<domain>` so they don't collide with custom-cert dedup keys.
- Wildcard SANs are skipped (can't dial `*.example.com` directly). Failed dials are silently retried tomorrow.

---

## [2.11.13] — 2026-04-28 · Live route-JSON preview on the proxy-host edit form

> Preview build (`applegater/caddyui:v2.11.13`).

### Added
- **Live route-JSON preview pane** at the bottom of the proxy-host edit form. Collapsed by default; expanding it shows the exact Caddy route JSON the form would push, refreshing ~500ms after the last keystroke or toggle. Useful for debugging why a header isn't being added or why a path matcher isn't firing.
- Reuses the same `parseProxyHostForm` + `caddy.BuildProxyRoute` path as `createProxyHost`, so what the user sees here is exactly what gets pushed on save. Lenient on missing fields — shows `⚠ strconv.Atoi: parsing "": invalid syntax` instead of breaking the pane.

### Internal
- New endpoint `POST /api/proxy-hosts/preview`. Skips fetches while the `<details>` is collapsed so background traffic stays minimal.

---

## [2.11.12] — 2026-04-28 · "Recently edited" widget on the dashboard

> Preview build (`applegater/caddyui:v2.11.12`).

### Added
- **Recent-CRUD activity strip on `/`.** Last 8 successful create / update / delete events across proxy hosts, redirects, raw routes, certificates, groups, and API tokens, plus `caddyfile_import` and `raw_reclassify`. Skips login / logout / sync_applied / snapshot / profile noise so the widget reads as "what just changed in CaddyUI".
- Each row shows a colour-coded resource pill matching the brand colours used elsewhere (Proxy / Redirect / Advanced / Cert / Group / API key), the actor, the verb (created / updated / deleted), the target, and a relative timestamp.

### Internal
- Adds `hasPrefix` and `hasSuffix` to the template `FuncMap` so action-string classification stays in the template.

---

## [2.11.11] — 2026-04-28 · Drag-to-reorder rows on /proxy-hosts and /redirection-hosts

> Preview build (`applegater/caddyui:v2.11.11`).

### Added
- **HTML5 drag handle (⠿)** in the leftmost cell of every desktop-table row on `/proxy-hosts` and `/redirection-hosts`. Drag the handle to reflow the row immediately; the new order POSTs to the matching `/reorder` endpoint and persists. Skips Caddy sync — list ordering is UI-only and doesn't change the generated config.

### Internal
- New endpoints `POST /proxy-hosts/reorder` and `POST /redirection-hosts/reorder`. Each accepts `ids[]` in desired display order and writes `sort_order = (index * 10)` per row. The `*10` multiplier leaves room for future single-row Sort Order edits to wedge between drag-saved rows without a full re-renumber.
- Non-admins can only reorder rows they own; foreign rows in the list are silently ignored.

---

## [2.11.10] — 2026-04-28 · Bulk delete on /certificates

> Preview build (`applegater/caddyui:v2.11.10`).

### Added
- **Floating bulk-action bar on `/certificates`** — Delete only since certs have no enable/disable state. Per-row checkbox is gated by `.CanEdit` so non-admins only see checkboxes on certs they own.

### Internal
- New endpoint `POST /certificates/bulk-delete`. Honours the same ownership + in-use guards as the single-row `deleteCertificate` handler — non-admins can only delete their own certs AND only when no other user's site still references the cert. A successful batch triggers a single `syncCaddy(forceTLS=true)` call so hosts that referenced any deleted cert revert to auto-issuance.

---

## [2.11.9] — 2026-04-28 · Bulk multi-select on /raw-routes

> Preview build (`applegater/caddyui:v2.11.9`).

### Added
- **Floating bulk-action bar on `/raw-routes`** — same pattern as `/proxy-hosts` and `/redirection-hosts`. Per-row checkbox, select-all in the header, **Enable / Disable / Delete** buttons that operate on every selected row in one shot.

### Internal
- New endpoints `POST /raw-routes/bulk-toggle` (action=enable|disable) and `POST /raw-routes/bulk-delete`. Both honour per-row ownership; each successful batch triggers a single `syncCaddy` call.

---

## [2.11.8] — 2026-04-28 · Proxy-form: hoist Forward Scheme / Host / Port + Test upstream to under Domain

> Preview build (`applegater/caddyui:v2.11.8`).

### Changed
- **Forward Scheme + Host + Port + Test upstream** moved to directly under the Domain row. Pairs naturally with the Domain field — no reason to scroll past Enabled / Auto-SSL / Managed-DNS / TLS-Cert / collapsed-metadata to set them.

### New top-of-form order
1. Domain names + www redirect + trailing slash
2. **Forward Scheme + Host + Port + Test upstream** ← v2.11.8
3. Enabled / Auto SSL / Force SSL ← v2.11.4
4. Managed DNS ← v2.11.7
5. TLS Certificate ← v2.11.7
6. *Path matching, query string, tags & notes* (collapsed)
7. *Upstream TLS & advanced settings* (collapsed)
8. *Options & Forwarded Headers* (collapsed)

---

## [2.11.7] — 2026-04-28 · Proxy-form: hoist Managed DNS + TLS Certificate to top, collapse path/metadata + upstream TLS

> **`:latest` retag.** Published as `applegater/caddyui:v2.11.7`, `:preview`, `:stable`, and `:latest` (multi-arch `linux/amd64` + `linux/arm64`). Fifteen features past v2.10.0 — the cadence rule (retag `:latest` every ~8 features) has been overdue since v2.11.0, and v2.11.7 is the moment.

### Changed
- **Managed DNS** and **TLS Certificate** sections moved to the top of the proxy-host edit form, directly under the v2.11.4 essentials row (Enabled / Auto SSL / Force SSL). They previously lived ~700 lines below, between the big Options block and the path-based upstream overrides — too far down for sections picked on almost every host. Both still carry `data-keep-open` so they stay open on both create and edit.
- **Path matching, query string, tags & notes** is now a single collapsed `<details>` covering Path prefix, Strip prefix, Strip query string, Delete query params, Add query params, Tags, Notes, Color label, and Sort Order. The v2.11.0 section badges count configured fields inside, so users can spot what's set without expanding.
- **Upstream TLS & advanced settings** is a new collapsed `<details>` covering Upstream TLS SNI, minimum TLS version, Forward proxy URL, Upstream path prefix, Strip path suffix, and Upstream Host header. Most users never touch any of these.

### Top of form now reads (top-down)
1. Domain names + www redirect + trailing slash
2. Enabled / Auto SSL / Force SSL
3. **Managed DNS** (visible)
4. **TLS Certificate** (visible)
5. *Path matching, query string, tags & notes* (collapsed)
6. Forward Scheme + Host + Port + Test-upstream button
7. *Upstream TLS & advanced settings* (collapsed)
8. *Options & Forwarded Headers* (collapsed, existing)

---

## [2.11.6] — 2026-04-28 · Bulk multi-select on /redirection-hosts

> Preview build (`applegater/caddyui:v2.11.6` and `:preview`). `:latest` still pinned at v2.10.0.

### Added
- **Bulk action bar on `/redirection-hosts`** — same floating bottom-bar pattern `/proxy-hosts` has had. Per-row checkbox, select-all in the header, and Enable / Disable / Delete buttons that act on every selected row in one shot. Each successful batch triggers a single `syncCaddy` call instead of one-per-row.

### Internal
- New routes: `POST /redirection-hosts/bulk-toggle` (action=enable|disable) and `POST /redirection-hosts/bulk-delete`. Both honour per-row ownership — non-admins can only toggle / delete their own rows.
- Mobile card view stays checkbox-free; bulk select is rare on a phone screen and matches the `/proxy-hosts` decision.

---

## [2.11.5] — 2026-04-28 · ⌘K / Ctrl+K command palette — global resource search

> Preview build (`applegater/caddyui:v2.11.5` and `:preview`).

### Added
- **Global command palette.** Press `⌘K` (macOS) or `Ctrl+K` (everywhere else) on any page to open a modal that searches across every proxy host, redirection, raw route, and certificate visible to the current user on the active server. `↑/↓` navigates results, `Enter` opens the highlighted item, `Esc` or backdrop-click closes.
- **Type pills** colour-code results: <span style="color:#1d4ed8">Proxy</span> · <span style="color:#0369a1">Redirect</span> · <span style="color:#7e22ce">Advanced</span> · <span style="color:#047857">Cert</span> — same brand colours used elsewhere in the app.
- **Keyboard-shortcut overlay (`?`)** updated to list the new binding.

### Internal
- New endpoint `GET /api/search` returns a flat list of `{type, id, label, sub, url}` items, scoped through the same viewer / peer / admin permission filtering the list pages already use.
- Frontend caches the response per palette open with a 60-second freshness window — reopening the palette is instant; a stale cache silently re-fetches in the background.

---

## [2.11.4] — 2026-04-28 · Proxy-form: hoist Enabled / Auto SSL / Force SSL to top

> Preview build (`applegater/caddyui:v2.11.4` and `:preview`).

### Changed
- **Three essential toggles** (`Enabled`, `Auto SSL (Let's Encrypt)`, `Force SSL (HTTPS redirect)`) now sit in their own always-visible row directly under the Domain names input — alongside Managed DNS and TLS Certificate as the form's "essentials" area. Previously they were buried inside the collapsed `Options & Forwarded Headers` section after v2.11.2, so flipping them required expanding a 50-field block first.

### Kept
- The `Options & Forwarded Headers` section keeps the rest (Verify Upstream TLS, X-Forwarded-* headers, blocking toggles, ~50 fields) collapsed by default — same `data-keep-open` / collapse pattern as before.

---

## [2.11.3] — 2026-04-27 · Proxy-form: collapse on edit too

> Preview build (`applegater/caddyui:v2.11.3` and `:preview`). `:latest` still pinned at v2.10.0.

### Changed
- **All `<details>` sections start collapsed on edit too**, not just create. Section badges (added in v2.11.0) carry the field-count summary so users can see what's configured without expanding. Avoids the form auto-expanding 8+ sections at once when opening a configured host.

### Kept
- **Managed DNS** and **TLS Certificate** remain auto-open on both create and edit via `data-keep-open` — the two sections users almost always need.

---

## [2.11.2] — 2026-04-27 · Proxy-form: wrap the Options/X-Forwarded block in `<details>`

> Preview build (`applegater/caddyui:v2.11.2`).

### Fixed
- **Options & Forwarded Headers block is now collapsible.** The ~50-field block of TLS settings, X-Forwarded-* toggles, and blocking flags was a plain `<div>`, so the v2.11.1 collapse-on-create logic didn't apply. Wrapped in a `<details>` so it follows the same pattern as every other section.

### Changed
- **Managed DNS + TLS Certificate marked `data-keep-open`** — they stay open regardless of the global collapse rule because they're picked on almost every host.

---

## [2.11.1] — 2026-04-27 · Proxy-form: collapse all sections on create

> Preview build (`applegater/caddyui:v2.11.1`).

### Changed
- On **create**, every `<details>` section starts collapsed so the user can expand one feature, edit it, collapse back, and move to the next without the form scrolling for pages.
- On **edit**, sections with configured fields still auto-open so users immediately see what's set. (Edit-side auto-open was later reverted in v2.11.3 — badges replaced it.)

---

## [2.11.0] — 2026-04-27 · UX & navigation polish — 8-feature batch

> Preview build (`applegater/caddyui:v2.11.0` and `:preview`). `:latest` still pinned at v2.10.0. Eight features that round off the v2.10 import-classification arc with nav, search, and form-ergonomics improvements.

### Added
- **Live filter on `/raw-routes`** — search input above the table, JS filters by host / label / Caddyfile content. Honours `?q=…` deep-links. Matches the `/proxy-hosts` and `/redirection-hosts` pattern.
- **Live filter on `/certificates`** — same pattern; matches by name, domain SAN list, or owner email.
- **Tri-state theme toggle** (`auto` / `light` / `dark`). Was a binary toggle — once a user clicked it, system preference was permanently overridden. New default is `auto` which actively tracks `prefers-color-scheme` via a `matchMedia` listener; explicit choices override. Cycles through the three states; icon + tooltip update to show the active mode.
- **Sticky save bar on `proxy_host_form`.** With ~70 per-host options plus the form-search, the in-form Save button is often offscreen. `IntersectionObserver` shows a floating Save / Cancel pill at the bottom of the viewport whenever the in-form actions row scrolls out of view. Re-uses the same `<form>` via the `form=` attribute so there's no duplicate state.
- **Section badges on `proxy_host_form`.** Each `<details>` section gets a small brand-coloured pill in its `<summary>` showing how many fields inside it are configured (non-default). Defaults: `input.value !== ''` for text, `.checked` for checkboxes, `selectedIndex > 0` for selects. Sections with set fields originally auto-opened (changed in v2.11.3 — badges-only).
- **Keyboard-shortcut overlay (`?`).** Press `?` on any page to open a modal listing every global shortcut. `Esc` closes; clicks outside dismiss. Bindings ignore key presses while typing in inputs / textareas / contenteditables so `/` etc. don't fire mid-edit.
- **Quick-nav chord shortcuts** (Vim-style `g` + letter):
  - `g d` → / (dashboard)
  - `g p` → /proxy-hosts
  - `g r` → /redirection-hosts
  - `g c` → /certificates
  - `g a` → /raw-routes
  - `g n` → /analytics
  - 1.2s window for the second key; out-of-window resets the chord.
- **Richer empty states on `/proxy-hosts` and `/redirection-hosts`.** Replaces the bare "No proxy hosts yet · + Create your first" with a card that explains what the resource IS, offers three on-ramps (manual / paste Caddyfile / import live config), and links to the docs. Brand-tinted (proxy = brand, redir = sky) so the visual identity matches the rest of the app.

---

## [2.10.0] — 2026-04-27 · Per-host options expansion + analytics speedup + path-routing + multi-upstream

> **Major release.** Published as `applegater/caddyui:v2.10.0` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`). Consolidates the entire v2.9.1 → v2.9.267 preview cycle into one released entry — the numeric tags in that range were internal-only builds during development. **`:latest` now points at v2.10.0**, replacing the previous v2.9.0 GA build.

### Added

This batch is a sustained expansion of the **per-host configuration surface** introduced in v2.9.0. Every option below is a column on `proxy_hosts`, a field on the proxy-host edit form, and a Caddy-JSON builder branch in `internal/caddy/client.go`. Defaults are off / empty so existing rows behave identically until you opt in. Grouped by category for readability.

#### Request headers forwarded to upstream
- **`add_x_real_ip`** (v2.9.149) — `X-Real-IP: {http.request.remote.host}`.
- **`add_x_real_scheme`** (v2.9.191) — `X-Real-Scheme: {http.request.scheme}`.
- **`add_x_forwarded_scheme`** (v2.9.143) — `X-Forwarded-Scheme: {http.request.scheme}`.
- **`add_x_forwarded_uri`** (v2.9.199) — `X-Forwarded-URI: {http.request.uri}`.
- **`strip_incoming_x_forwarded_for`** (v2.9.150) — drop client-supplied `X-Forwarded-For` before Caddy adds its own.
- **`add_x_request_path` / `add_x_request_method` / `add_x_request_query` / `add_x_request_hostname` / `add_x_request_referer` / `add_x_request_origin`** (v2.9.181, .188, .189, .201, .197, .198) — toggle individual `X-Request-*` debug/trace headers populated from `{http.request.*}` placeholders.
- **`add_x_request_start`** (v2.9.140) — `X-Request-Start: t={time.now.unix_ms}` for upstream latency tracing.
- **`add_origin_header`** (v2.9.159) — set a static `Origin` request header.
- **`add_x_forwarded_user` / `add_x_forwarded_email` / `add_x_forwarded_groups` / `add_x_forwarded_roles`** (v2.9.190, .194, .193, .195) — static identity headers for trusted-network impersonation patterns.
- **`add_x_request_remote_port` / `add_x_request_protocol`** (v2.9.212, .213) — toggle `X-Request-Remote-Port: {http.request.remote.port}` (client TCP source port) and `X-Request-Protocol: {http.request.proto}` (HTTP/1.1, HTTP/2, etc.).
- **`add_x_environment`** (v2.9.217) — static `X-Environment` value (`production` / `staging` / `dev`) for upstream-side env detection.
- **`add_x_trace_id` / `add_x_session_id`** (v2.9.218, .220) — `X-Trace-ID` and `X-Session-ID` populated from `{http.request.uuid}` so distributed-tracing pipelines have a stable per-request correlation key.
- **`add_x_request_local_addr` / `add_x_request_local_port`** (v2.9.222, .223) — Caddy's *listening* IP and port (vs the client-side remote IP/port) so multi-listener installs can route by which interface the request hit.
- **`add_x_request_path_info`** (v2.9.224) — `X-PathInfo: {http.request.uri.path}` for CGI-style backends that consume `PATH_INFO`.

#### Response headers (security & cache)
- **`add_x_permitted_cross_domain_policies` / `add_document_policy` / `add_origin_agent_cluster`** (v2.9.167, .156, .192) — modern cross-origin / isolation hints.
- **`add_x_xss_protection_disabled` / `add_x_download_options` / `add_x_no_archive` / `add_x_dns_prefetch_control`** (v2.9.202, .177, .200, .163) — security-hardening toggles.
- **`add_x_powered_by` / `add_x_clacks_overhead` / `add_x_ua_compatible`** (v2.9.154, .182, .183) — custom branding / legacy-IE / GNU-tradition headers.
- **`add_cors_vary_header`** (v2.9.152) — `Vary: Origin` on every response (CDN-correctness for CORS).
- **`add_link_preload`** (v2.9.145) — `Link: …` resource hints.
- **`add_accept_ranges`** (v2.9.164) — `Accept-Ranges: bytes` to advertise byte-range support.
- **`add_content_disposition` / `add_content_language`** (v2.9.165, .175) — content metadata headers.
- **`response_cache_ttl_sec`** (v2.9.144) — emits `Cache-Control: max-age=N`.
- **`add_age_zero` / `add_pragma_no_cache` / `add_surrogate_control` / `add_warning_header`** (v2.9.185, .179, .186, .187) — cache-bypass / CDN-only / RFC-7234 advisory directives.
- **`add_server_timing_header`** (v2.9.161) — `Server-Timing: upstream;dur=…` for browser DevTools timing.
- **`add_clear_site_data`** (v2.9.162) — `Clear-Site-Data` value for logout / data-purge endpoints.
- **`add_request_id_to_response`** (v2.9.147) — copy the request trace ID into the response.
- **`add_accept_ch` / `add_critical_ch`** (v2.9.173, .176) — Client Hints negotiation.
- **`add_alt_svc`** (v2.9.174) — advertise alternative services (HTTP/3 upgrade, etc.).
- **`add_service_worker_allowed`** (v2.9.172) — expand SW scope beyond script URL.
- **`add_report_to` / `add_nel_header`** (v2.9.169, .170) — Reporting API + Network Error Logging.
- **`strip_response_headers`** (v2.9.168) — comma-separated list of response headers to delete from upstream replies.
- **`add_save_data_vary`** (v2.9.214) — appends `Save-Data` to the `Vary` response header so caches keep separate copies for clients sending the `Save-Data: on` client hint.
- **`add_x_response_trace_id`** (v2.9.221) — sets `X-Response-Trace-ID` on the response to Caddy's per-request UUID so clients can correlate responses with server-side trace logs.

#### Request blocking (returns 403 / 405)
- **`deny_path_regexp`** (v2.9.146) — 403 when path matches a regexp.
- **`block_query_params`** (v2.9.155) — 403 when any of the named query parameters are present.
- **`block_query_param_regexp`** (v2.9.196) — 403 when the raw query string matches a regexp.
- **`deny_user_agent_regexp`** (v2.9.178) — 403 when User-Agent matches a regexp.
- **`block_http_methods`** (v2.9.171) — 405 with `Allow:` header for listed methods.

#### Active health checks
- **`health_check_tls_server_name`** (v2.9.148) — SNI override for probe connections.
- **`health_check_tls_insecure_skip_verify`** (v2.9.151) — skip cert verification on probes.
- **`health_check_user_agent`** (v2.9.180) — custom User-Agent for probe requests.
- **`health_check_query_params`** (v2.9.219) — query string appended to the active probe URL (e.g. `?token=abc&deep=1`) so endpoints requiring auth tokens or mode flags can be probed without baking them into `health_check_uri`.

#### Upstream TLS
- **`upstream_tls_alpn`** (v2.9.153) — ALPN protocol list for upstream TLS.
- **`upstream_tls_ca_pem_inline`** (v2.9.160) — inline PEM CA bundle for upstream verification.
- **`upstream_tls_server_name_from_host`** (v2.9.166) — derive upstream SNI from the incoming `Host` header (dynamic).

#### Forward auth
- **`forward_auth_skip_paths`** (v2.9.184) — comma-separated path prefixes that bypass `forward_auth` (health, metrics, public assets) by wrapping the auth handler in a `not { path … }` subroute.

#### Load balancing & connections
- **`lb_random_choose_count`** (v2.9.142) — number of upstreams sampled by the `random_choice` LB policy.
- **`upstream_keepalive_max_lifetime_sec`** (v2.9.158) — `transport.keep_alive.maximum_connection_lifetime`.

#### Maintenance window
- **`maintenance_window_timezone`** (v2.9.141) — evaluate the configured maintenance window in a specific IANA tz instead of the host clock.
- **`maintenance_redirect_url`** (v2.9.157) — when set, the maintenance handler returns a 302 redirect instead of the default 503 HTML page.

### Internal
- **DB migrations are additive only.** Each v2.9.x option lands as an `ALTER TABLE proxy_hosts ADD COLUMN <name> … DEFAULT <off>` guarded by `columnExists2`, so upgrading is a no-op for existing rows. Downgrade is supported (older builds simply ignore the new columns).
- **`scanProxyHost` / `proxyHostBaseCols` / `CreateProxyHost` / `UpdateProxyHost` extended uniformly.** No schema fan-out or feature-table indirection — every option is a flat column read by the same scan path. Cuts query overhead for list views to a single `SELECT`.

### Added — major new features (v2.9.228 → v2.9.267)

#### Advanced (raw routes)
- **Caddyfile / JSON tabbed editor on the raw-route form.** Either field can be filled; Caddyfile wins on save (re-runs through Caddy's `/adapt` to regenerate the JSON). New routes default to the Caddyfile tab — far more readable than the JSON shape. Existing rows open on whichever tab already has content. The plumbing was there since the import-Caddyfile feature shipped; v2.9.228 just exposed it as a UX-first toggle on every form. (v2.9.228)
- **Validate button on raw routes.** New endpoint `POST /api/raw-routes/validate`. For Caddyfile mode it round-trips through `/adapt` (true read-only validation). For JSON mode it parses + structurally checks (must have non-empty `handle[]`); deeper semantic errors surface at sync time. (v2.9.228 — initial broken implementation; **v2.9.233** rewrote it because the original POSTed to `/load?validate_only=true` which Caddy *ignores* — the synthetic config was actually applied to running Caddy. The fix avoids `/load` entirely.)

#### Redirections
- **Path-based redirect rules on redirection hosts.** New JSON column `redirect_rules`; each rule is `{path, code, destination}`. When non-empty, per-rule path matchers fire BEFORE the host-wide redirect catch-all, enabling partial-migration patterns (`/old-blog/* → newblog.com/{uri}`) without affecting the rest of the host. Empty destination + 410 = "Gone" for retired URLs. UI is a dynamic add/remove/edit table; a hidden input keeps the JSON array in sync for the form post. (v2.9.229)
- **`redirect_strip_path_prefix`** — drop a leading prefix from the captured path before composing Location. Mirrors the proxy-host `strip_path_prefix` lifted to redirects. (v2.9.230)
- **`redirect_wildcard_subdomain`** — substitute the matched subdomain label into the destination via `{http.request.host.labels.0}`. Enables `*.old.com → *.new.com` per-tenant migrations. (v2.9.231)
- **`sunset_at`** — ISO-8601 date column. Once today (UTC) is on or after the configured date, the redirect short-circuits to **410 Gone** with body "This URL has been retired." Compliance/cleanup helper for "redirect old → new until 2027-01-01, then drop." (v2.9.232)

#### Proxy hosts — multi-path routing
- **`proxy_redirect_rules`** — same JSON-array pattern as redirection hosts but on proxy hosts. Each rule's path matcher fires BEFORE the reverse_proxy. Drives the common Caddyfile pattern: `@root path / + redir @root /webmail 302` alongside a regular reverse_proxy. (v2.9.266)
- **`additional_upstream_rules`** — path-based upstream overrides. Each entry is `{path, scheme, host, port, strip_prefix, add_x_real_ip}`. Lets a single proxy host route different paths to different upstreams — what the user's Nextcloud Caddyfile needed (`/push/* → notify_push`, `/exapps/* → AppAPI`, everything else → Nextcloud, all on one host). `strip_prefix` mirrors Caddyfile's `handle_path`; `add_x_real_ip` is a per-rule override of the host-wide flag. UI is a dynamic table with two checkboxes per row for those flags. (v2.9.267)

### Added — per-host options expansion (continued from v2.9.234 onwards)

#### Identity / blocking / preload / health auth (v2.9.234-241)
- **`add_x_authenticated_user`**, **`add_x_remote_user`** — static auth identity request headers (Apache/Nginx CGI conventions). (v2.9.234, .237)
- **`block_path_extensions`** — comma-separated file extensions returning 403 (matches `*.<ext>` via path globs). Good for blocking `.php` / `.git` / `.bak` on non-PHP backends. (v2.9.235)
- **`add_link_modulepreload`** — `Link: <…>; rel=modulepreload` response header for ES module preloading. (v2.9.236)
- **`add_x_forwarded_path`** — `X-Forwarded-Path: {http.request.uri.path}` request header. (v2.9.238)
- **`add_x_geo_country_code`** — static `X-Geo-Country` header (CDN convention). (v2.9.239)
- **`add_x_request_priority`** — `X-Request-Priority` response header (RFC 9218). (v2.9.240)
- **`health_check_basic_auth`** — `user:pass` sent as Basic auth on every active health-check probe; encoded once at config-build time. (v2.9.241)

#### TLS visibility / debugging / blocking / reporting (v2.9.242-249)
- **`add_x_real_ssl_protocol` / `add_x_real_ssl_cipher`** — forward TLS version + negotiated cipher to upstream so backends can record / log / decide on the original handshake details. (v2.9.242, .243)
- **`add_x_cache_status`** — static `X-Cache-Status` response header. (v2.9.244)
- **`deny_referer_regexp`** — return 403 when Referer matches a regexp; symmetric with `deny_user_agent_regexp` / `block_query_param_regexp`. (v2.9.245)
- **`add_x_request_user_agent`** — echo UA to upstream as a separate header (debug / multi-proxy-chain visibility). (v2.9.246)
- **`add_reporting_endpoints`** — `Reporting-Endpoints` response header per RFC 8942 (modern successor to Report-To). (v2.9.247)
- **`add_x_request_byte_count`** — forward Content-Length as `X-Request-Byte-Count` for upstream bandwidth accounting. (v2.9.248)
- **`add_x_request_received_at`** — forward `{time.now}` as `X-Request-Received-At` for request-trace latency attribution. (v2.9.249)

#### Strip request headers / forwarding / tracing (v2.9.250-257)
- **`strip_request_headers`** — comma-separated request header names to delete before forwarding (symmetric with `strip_response_headers` from v2.9.168). (v2.9.250)
- **`add_x_forwarded_method`** — `X-Forwarded-Method: {http.request.method}`. (v2.9.251)
- **`add_x_request_original_host`** — preserve pre-rewrite Host header. (v2.9.252)
- **`add_x_request_dnt`** — forward DNT (Do Not Track) signal as `X-Request-DNT`. (v2.9.253)
- **`add_x_geo_region`** — static `X-Geo-Region` (ISO 3166-2 region code). (v2.9.254)
- **`add_x_request_secure`** — `X-Request-Secure` with TLS version (empty if plain). (v2.9.255)
- **`add_x_request_query_count`** — raw query string copied as `X-Request-Query-Count` (debug header). (v2.9.256)
- **`add_x_request_id_header_response`** — echo Caddy's request UUID to the response so clients can correlate API calls with server logs. (v2.9.257)

#### Canonical host / bot+admin blocking / Link hints / CSP / method override (v2.9.258-265)
- **`force_canonical_host`** — canonical Host for SEO consolidation. Any request whose Host doesn't equal this value gets a 301 redirect (path + query preserved). Common pattern: `www.example.com → example.com`. (v2.9.258)
- **`add_x_robots_noindex_quick`** — one-click `X-Robots-Tag: noindex, nofollow` toggle. (v2.9.259)
- **`block_bot_user_agents`** — built-in regex blocklist for AhrefsBot, SemrushBot, Bytespider, MJ12bot, DotBot, PetalBot, DataForSeoBot, YandexBot, BLEXBot, SerpstatBot. Doesn't touch Google/Bing. (v2.9.260)
- **`block_admin_paths`** — 404 on `/wp-admin`, `/wp-login`, `/.git`, `/.env`, `/phpmyadmin`, `/myadmin`, `/.svn`, `/.hg`, `/.aws`, `/.ssh`, `/admin/config.php`. 404 (not 403) so scanners don't learn the path exists. (v2.9.261)
- **`add_link_dns_prefetch` / `add_link_preconnect`** — `Link: <…>; rel=dns-prefetch` / `rel=preconnect` response headers. (v2.9.262, .263)
- **`add_x_csp_disabled`** — delete the upstream's `Content-Security-Policy` at the edge. (v2.9.264)
- **`add_x_request_method_override`** — rewrite request method from `X-HTTP-Method-Override` header (firewall workaround). (v2.9.265)

### Fixed
- **`/redirection-hosts` rendered an empty page.** The list template called `{{range .TagList}}` but `TagList()` was only defined on `ProxyHost`, never on `RedirectionHost`. `html/template` aborts execution on a missing method, so the page silently broke. Added the matching method on `RedirectionHost`. (v2.9.204)
- **"Test Upstream" button reported `host and port are required`** even with both fields filled in. Root cause: the handler called `r.ParseForm()` first, which initialises `r.Form` to non-nil for any content type — and `r.FormValue()` only triggers `ParseMultipartForm` automatically when `r.Form` is still nil. Result: multipart bodies (which the JS sends via `FormData`) were silently empty. Removed the redundant `ParseForm()` so `FormValue` auto-parses correctly. (v2.9.203)
- **Pasting the same Caddyfile twice silently created duplicate raw routes.** `postCaddyfileImport` blindly created a new row per adapted route while the parallel `postImport` path (sync from Caddy admin API) properly deduped against existing proxies, redirects, and raw routes. Brought `postCaddyfileImport` to parity — duplicates now report as `skipped` in the result table instead of being created. (v2.9.205)
- **`/api/docs` link to API Tokens went to `/settings`.** The hint paragraph at the top of the API reference used `<a href="/settings">Settings → API Tokens</a>` from when the tokens page was planned to live under Settings; the actual route is `/api-tokens`. Link now points there directly with text "API Tokens (sidebar → API Tokens)". (v2.9.208)
- **Successful logins, logouts, and TOTP attempts were never logged.** Only `login_fail` was written to `activity_log`; admins viewing `/activity` couldn't see who actually signed in or when. v2.9.210 adds `login_success`, `login_totp_success`, `login_totp_fail`, and `logout` events; the User-Agent goes into the Detail column for forensic context.
- **Activity log recorded `127.0.0.1` for every login.** Behind a reverse proxy (the typical CaddyUI setup — it sits behind the very Caddy it manages) `r.RemoteAddr` is always the proxy's loopback IP. New `clientIPFromRequest` helper checks `X-Real-IP` then `X-Forwarded-For` first entry then `r.RemoteAddr`, so the activity feed shows the real visitor's address. The brute-force-protection check at line 1349 also uses the helper now, so per-IP rate-limiting works correctly behind a proxy. (v2.9.210)
- **Login / logout / TOTP rows were invisible on `/activity`** even after the logging fix. `ListActivity` and `ListActivitySearch` filter `WHERE server_id = ?`, but auth events have no Caddy-server context (they use `server_id = 0`). Without explicit handling they got hidden by the per-server scope. Both queries now include `OR server_id = 0` so global auth events surface alongside the current server's rows. (v2.9.211)
- **"Test Upstream" error messages now carry actionable hints.** Generic Go net errors (`Get "https://Anthem-Omada:8043/": dial tcp: lookup … no such host`) are tedious to interpret, especially the very common DNS-from-container failures. The handler now classifies failures into DNS / TLS / connection refused / timeout categories and surfaces a one-liner hint below the raw error: e.g. for DNS it suggests `--add-host=name:ip` or `--dns=<router>` on the CaddyUI container. The form JS renders the hint as a second line under the red error. (v2.9.212)
- **Live upstream status panel painted every upstream red** even though Caddy reported all of them with `fails: 0` (healthy). The `UpstreamStatus.Healthy bool` field had no `json:"healthy"` tag, so Go marshalled it as `"Healthy"` (capital H); the proxy_hosts.html JS read `u.healthy` (lowercase) → undefined → falsy → `bg-red-500` for everyone. Single-character fix: added the `json:"healthy"` tag. (v2.9.216)
- **Validate button accidentally applied configs.** First implementation in v2.9.228 used `/load?validate_only=true`, which Caddy's admin API ignores — the synthetic test config was actually loaded into running Caddy each time someone clicked Validate, polluting autosave with a `_caddyui_validate` ghost server. v2.9.233 rewrote the handler: Caddyfile mode uses `/adapt` (true read-only), JSON mode uses parse + structural-shape check (no admin call). (v2.9.233)
- **DOM-text-as-URL hardening on two sites** (analytics server selector, layout row-click-to-edit). Both were server-rendered with trusted values, but the inputs went through type/shape validation now (`parseInt(this.value, 10) || 0` + `> 0` check; `href[0] === '/' && href[1] !== '/'` check) to satisfy CodeQL `js/xss-through-dom` and harden defense-in-depth against attribute tampering. (v2.9.226)

### Security
- **SMTP header CRLF injection fixed in both `sendEmail` and `sendEmailTo`.** Both functions interpolated `From` / `Subject` / recipient values straight into the message envelope without sanitisation. A user-controlled subject of `hi\r\nBcc: attacker@evil.com` would smuggle an extra `Bcc:` header into the outgoing mail. New `stripCRLF` helper replaces CR/LF with space on those header values before composing the message; body content is left alone (newlines in body are content, not header boundaries). Resolves the GitHub code-scanning **"Email content injection"** alert as a real fix, not a suppression. (v2.9.209 — `sendEmail`; v2.9.225 — `sendEmailTo`, the sibling function CodeQL flagged separately)
- **Log injection fixed in unauthenticated handler paths.** The `forgot-password` and `invite` handlers logged the user-submitted email verbatim. Attacker types `victim@example.com\n[CRITICAL] system compromised` into the form → log shows a forged line. New `sanitizeForLog` helper escapes `\r`/`\n` to literal `\\r`/`\\n` (preserves diagnostics, breaks line-injection vector). Applied to both call sites. (v2.9.225)
- **CodeQL custom config** — switched from GitHub default-setup to advanced via `.github/workflows/codeql.yml` + `.github/codeql/codeql-config.yml`. Four queries are excluded with documented rationale because their findings are intentional design for a reverse-proxy manager:
  - `go/disabled-certificate-check` — `InsecureSkipVerify: true` on probe-only HTTP clients (Test Upstream, active health checks, app-health poller) is required to reach self-signed/internal-CA backends; the flag is never set on the forward path Caddy serves to end users.
  - `go/request-forgery` — CaddyUI exists to issue HTTP requests to user-specified targets (Test Upstream, health checks, forward_auth subrequests, DNS provider APIs, NTFY/webhook notifications); SSRF as a class doesn't apply because the user driving these requests is the authenticated admin, not an untrusted external party.
  - `go/email-injection` — `stripCRLF` already neutralises the SMTP-header-smuggling vector in both email functions; CodeQL's data-flow analyser doesn't recognise the sanitiser.
  - `go/log-injection` — the remaining flagged sites are in DNS plumbing where the user-controlled values are FQDNs / zone names / provider IDs / IPs the admin themselves typed. The realistic threat is "an authenticated admin smuggles a forged log line by typing `\n` into their own DNS setting" — they can already do anything they want to the DB and log file. Unauthenticated input paths use `sanitizeForLog` (above). (v2.9.209, .225, .227)

### Performance — analytics
- **SQLite tuned for analytics workloads.** New PRAGMAs in the connection DSN: `cache_size=-262144` (256 MiB page cache, was ~2 MiB default), `mmap_size=268435456` (256 MiB mmap window for index scans), `synchronous=NORMAL` (safe with WAL, faster writes during analytics reads), `temp_store=MEMORY` (GROUP BY / DISTINCT temp tables stay in RAM). Existing WAL mode + busy_timeout retained. (v2.9.206)
- **`access_daily` rollup is now actually used.** The schema for it was added in v2.7.0 but never populated and never queried — every analytics card scanned `access_events` directly even for 30/90/365-day windows. v2.9.206 adds a startup + hourly aggregator (`AggregateAccessDaily`) that backfills missing UTC days. v2.9.207 extends the rollup with per-status-class buckets (`s2xx`/`s3xx`/`s4xx`/`s5xx`/`s_other`) and an idempotent column migration for existing tables. The aggregator detects pre-status-bucket rows and re-aggregates them.
- **`AccessTotalsSince` and `StatusBucketsSince` rollup-aware.** Long windows (≥ today's UTC midnight in the past) now read past-day totals from `access_daily` and only scan `access_events` for today, dropping the cost of "Last 30 days" / "Last 90 days" / status-pie cards from `O(rows-in-window)` to `O(rows-today + days-in-window)`. Multi-second scans become ~10ms lookups on installs with millions of events. Visitor counts from the rollup are best-effort approximate (same IP across multiple days counted multiple times) — schema comment already noted this. (v2.9.206 — totals; v2.9.207 — status)
- **Two missing indexes on `access_events`** for the status-code breakdown card and unique-visitor count: `idx_access_events_status_ts(status, ts)` and `idx_access_events_client_ip_ts(client_ip, ts)`. `path` was deliberately *not* indexed — high-cardinality and the index would be larger than the table; top-paths queries already use the `(host, ts)` range scan + GROUP BY which is fast enough. (v2.9.206)

### UI
- **API Tokens** sidebar entry added between **API** and the admin section (visible to all authenticated users, not just admin). The route, handler, and template existed since the API tokens feature shipped, but there was never a link to reach them from the UI. New `key` icon added to the icon helper. (v2.9.207)

### Docker
- Published as `applegater/caddyui:v2.10.0` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).
- The `:preview` tag was used during the v2.9.1 → v2.9.267 development cycle and now points at v2.10.0 as well.

### Upgrade note
- Just `docker pull` won't activate the new image — recreate the container (Portainer's **Recreate** button with "Pull latest image" toggled, or the `recreate.sh` helper script).
- DB schema migration runs automatically on first start; no manual SQL needed.
- All new options default to off / empty — existing rows behave identically until you edit them and opt in.
- On first start the access_daily backfill aggregator runs once for installs with historical events. Watch for `access_daily: aggregated N day(s)` in the log; subsequent loads of `/analytics` are then instant.
- If your CaddyUI container can't resolve the LAN hostnames your proxy hosts use (e.g. `Anthem-Omada`, `omada-controller` — Docker's embedded DNS at `127.0.0.11` doesn't see your LAN), add `--dns=<router-ip>` or `--add-host=<name>:<ip>` to the container args, or run with `--network=host`. The Live upstream panel reads from Caddy's authoritative view (which has its own resolver) so it's unaffected; only CaddyUI's own port-dot probe needs DNS.
- **Open the Validate button**: in v2.9.228 the original implementation accidentally polluted Caddy's autosave with a `_caddyui_validate` ghost server. v2.9.233 fixed the bug. If you're upgrading from v2.9.228-232 directly to v2.10.0 (skipping the in-between fix), trigger any sync from CaddyUI after the upgrade to overwrite autosave.

---

## [2.7.9] — 2026-04-26 · Source column on /raw-routes + Recent advanced routes on dashboard

### Added
- **Source column on `/raw-routes`.** Mirrors `/proxy-hosts` so the table reads the same way at a glance — leftmost column shows the route's `match.host[]` entries as clickable domain pills (each opens the hostname in a new tab). Path-only / port-only routes (no host matcher) render `— no host matcher` in italic ink-300 instead of an empty cell. Existing columns (Label, Config, Owner, Status, Actions) shift right one slot; empty-state colspan bumped from 4/5 to 5/6 to match. Mobile-card variant promotes the host pills above the label so the card has the same identifying anchor as the desktop row.
- **"Recent advanced routes" block on the dashboard.** Renders below the existing "Recent proxy hosts" block — same mobile-card / desktop-table split, same Source-style domain pills, same Edit-on-click behaviour. Only shows when there's at least one raw route in the DB so fresh installs stay uncluttered. Tile counters at the top of the dashboard already linked to `/raw-routes`; the new block surfaces the actual route list inline so users with mostly-advanced setups don't need to click through.
- **`rawRouteSourceHosts` template helper** (`internal/server/server.go` parseTemplates). Wraps the existing internal `rawRouteHosts(models.RawRoute)` so templates can extract `match.host[]` from a JSON string with `{{range rawRouteSourceHosts .JSONData}}`. Returns `nil` for path-only / port-only routes — templates fall back to the route label so the Source column never renders empty.

### Changed
- **Dashboard handler now passes the full `RawRoutes` slice** (in addition to the existing `RawCount`) so the new block can render. Same pattern as `ProxyHosts` / `RedirectionHosts` — no slicing or limit here, mirroring the existing "Recent proxy hosts" behaviour. If you have hundreds of advanced routes the block will render all of them; same caveat already applies to the proxy-hosts block.

### Docker
- Published as `applegater/caddyui:v2.7.9` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

---

## [2.7.8] — 2026-04-25 · Enforce zone ↔ hostname match on proxy hosts and raw routes

### Fixed
- **The DNS picker would let you save a hostname into the wrong zone.** Reported live: a route for `richardapplegate.io` ended up paired with the `applegatecloud.com` zone in the dropdown. The form rendered the v2.5.1 amber "isn't a subdomain of …" warning, but it was advisory only — clicking Save committed the row, and the subsequent `dnsCreateRecord` call either failed at the provider API or silently put the A record in the wrong zone. Symmetric on both the proxy-host form and the raw-route form, since both share the picker logic.
- **Front-end: hostname-derived zone now always wins.** `renderZones` (in both `web/templates/proxy_host_form.html` and `web/templates/raw_route_form.html`) used to call `bestZoneMatch(firstDomain, zones)` only when nothing was pre-selected and the user hadn't manually picked. That left two failure paths: (a) editing an existing row whose saved `dns_zone_id` was wrong — the dropdown stayed on the wrong zone — and (b) a manual mis-pick stuck around even after the user changed the hostname. v2.7.8 strips both gates: if any zone in the list is a parent of the route's first hostname, the dropdown snaps to it on every render. Falls back to the saved selection only when no zone matches (e.g. the user has zones for other domains and is willing to save without managed DNS, in which case they should pick "(none)" as the provider anyway).
- **Server-side: new `validateZoneMatchesHostname(provider, zoneID, zoneName, domains)` validator wired into all four DNS-aware save handlers** — `createProxyHost`, `updateProxyHost`, `createRawRoute`, `updateRawRoute`. Returns "" when no managed DNS is configured (provider or zoneID empty) or when the first hostname is a suffix of the zone name; otherwise returns a user-facing error and the row is refused. Matching is case-insensitive and trim-tolerant via the new `domainInZone(fqdn, zoneName)` helper, which mirrors how Caddy and every DNS provider we integrate with normalises FQDNs (case-insensitive, trailing-dot stripped). Validates the *first* hostname only (matching what `dnsCreateRecord` actually provisions records for) — extra entries in the comma-separated Domains field are SAN aliases on the same TLS cert, not separate DNS records.
- **Error message is actionable.** `Hostname "richardapplegate.io" doesn't live in DNS zone "applegatecloud.com". Pick a zone whose apex matches the hostname (e.g. zone "richardapplegate.io" for hostname "richardapplegate.io"), or change the DNS provider to (none) if you don't want CaddyUI to manage the A record.` The suggested apex comes from a `guessApex` helper that takes the rightmost two labels — good enough for `.com`/`.io`/`.net` style TLDs; doesn't try to be public-suffix-list-aware (the user picks the actual zone from the dropdown anyway, the suggestion is just a hint in the error text).

### Changed
- **Mismatch warning text strengthened** from "saving will create the DNS record in the wrong place otherwise" (advisory) to "Save will be rejected — pick a zone whose apex matches the hostname, or set the provider to (none) to skip managed DNS" (actionable). Matches the new server-side reality where the save is, in fact, rejected.

### Docker
- Published as `applegater/caddyui:v2.7.8` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

### Compatibility
- **Existing rows with mismatched zone/hostname pairings are not auto-cleaned.** The validator only fires on save. Re-saving an affected row (via the edit form) will surface the new error and force you to pick the correct zone before it'll save. Rows you don't re-save keep their current behaviour — the next `dnsCreateRecord` call still fails the same way it always did, but now the new amber warning text on the form makes it obvious why.

---

## [2.7.7] — 2026-04-25 · Reject duplicate domains across proxies and redirects

### Fixed
- **A proxy or redirect could silently shadow another row with the same hostname.** Reported by users seeing "my domain got overridden to a different upstream" after another teammate (or the same admin in a second tab) created a second proxy claiming the same FQDN. Caddy's route table only keeps one match per host, so on the next `syncCaddy` push the newer entry's `reverse_proxy` handler took the slot and the older row stopped working — even though both rows were still listed in `/proxy-hosts` as enabled. There was no save-time guard against this: the form accepted any hostname the user typed and `CreateProxyHost` / `UpdateProxyHost` wrote it straight to the DB.
- **Root cause: `ProxyHostDomainsConflict` (in `internal/models/models.go`) existed but was never called.** Dead code since v2.2 — none of the four save handlers (`createProxyHost`, `updateProxyHost`, `createRedirectionHost`, `updateRedirectionHost`) referenced it. The function also had a latent bug: the redirection-host loop didn't honour the `excludeID` parameter, so editing a redirect would have falsely flagged a self-conflict the moment we tried to wire it in.
- **Fix: rewrote the helper as `models.DomainsConflict(db, serverID, domains, excludeProxyID, excludeRedirectID)` and called it from all four handlers.** The two-exclude split is required because proxy hosts and redirection hosts live in separate tables with overlapping ID space — a single `excludeID` would be ambiguous. Create-path callers pass `(0, 0)` (nothing to exclude); update-path callers pass `(p.ID, 0)` for proxy edits and `(0, rh.ID)` for redirect edits, so a no-op save (e.g. toggling SSL on the same row) doesn't trip the new guard.
- **Comparison is case-insensitive and trim-tolerant.** `Example.com `, `example.com`, and `EXAMPLE.COM` all collapse to the same key, matching Caddy's host-matcher semantics. Returns the conflicting domain in its original casing so the error message reads back what the user actually typed.
- **Admin view (`isAdmin=true`) is forced for the conflict check** so user A can't claim `example.com` after user B already claimed it via a different account. Caddy resolves routes by hostname, not by who owns the row in the UI, so the conflict has to be evaluated globally — owner-scoped checking would let two users each create a working-looking proxy and only one would actually receive traffic.

### UX
- **Error renders inline on the form, the user's input is preserved.** Both `renderProxyHostFormError` and `renderRedirectionHostFormError` (the same paths the SSL-flag and Advanced-config validators already use) now surface the conflict message: `Domain "example.com" is already in use by another proxy or redirect on this server. Each domain can only be claimed once — edit the existing entry or remove it before reusing the name.` No 500, no half-saved row, no opaque sync error after the fact.

### Not changed
- **Raw routes are intentionally not part of the conflict check yet.** Their host matchers live inside the route's JSON body rather than a flat column, and the `postImport` flow already covers raw-route deduplication via `rawRouteHosts`. Most of the user complaints we received were proxy↔proxy or proxy↔redirect, so the v2.7.7 scope is those two; raw-route conflict checking can land separately when there's evidence it matters.

### Docker
- Published as `applegater/caddyui:v2.7.7` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

---

## [2.7.6] — 2026-04-24 · Fix /analytics server filter on multi-server installs

### Fixed
- **Picking a secondary Caddy server in the `/analytics` server filter showed "no data"** even on live, traffic-serving servers. Root cause: `applyAnalyticsToggle` (the function that wires Caddy's access-log forwarding when the admin flips the Analytics toggle in Settings) only called `EnableAccessLogs` / `DisableAccessLogs` on `s.Caddy` — the single primary client built from `CADDY_ADMIN_URL` — and ignored every other row in the `caddy_servers` table. Secondary Caddy instances registered through `/servers` never had the `caddyui_access` logger installed, so they never shipped access-log entries to the ingest listener; the `access_events` table had zero rows for any hostname routed by a secondary. When the `/analytics` filter narrowed the dashboard to a secondary server, `scopedHostsForAnalytics` correctly returned that server's hostnames, but the subsequent `AccessTotalsSince(host=...)` queries found no matching events and every card rendered zeros. The symptom only manifested on multi-server installs — single-server admins never noticed because their primary was (accidentally) the only server the toggle ever touched.
- **`applyAnalyticsToggle` now iterates every managed Caddy in the DB**, building a per-server `caddy.Client` via `newCaddyClient(adminURL, user, pass)` and applying the enable/disable action to each. External-type servers (rows with `type = 'external'` — CaddyUI-observed-but-not-authoritative) are skipped because their admin API isn't writable. Per-server errors are collected and returned as a single aggregated error at the end of the loop, so one unreachable Caddy doesn't short-circuit the wiring on the other three.
- **Fallback path preserved for fresh installs.** When `ListCaddyServers` returns an empty slice (DB just initialised, `SeedBootstrapServer` hasn't populated the primary row yet, or the servers table was manually cleared), the function falls back to the pre-2.7.6 single-`s.Caddy` call so first-boot analytics enable still works out of the box.

### Docker
- Published as `applegater/caddyui:v2.7.6` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

### Upgrade note
- After upgrading, **save your Analytics settings once** (Settings → Analytics → Save) even if nothing changed. That single save re-runs the toggle through the new multi-server loop and installs the `caddyui_access` logger on every secondary Caddy you've added through `/servers`. You should see events from every server in the ingest-health card within a minute of traffic hitting them.

---

## [2.7.5] — 2026-04-24 · Fix /backup download on scratch-based image

### Fixed
- **`/backup` download returned `backup failed: unable to open database file: unable to open database: /tmp/caddyui-backup-YYYYMMDD-HHMMSS.db (14)`.** Reported from a live install. SQLite error 14 is `SQLITE_CANTOPEN` — the `VACUUM INTO` target couldn't be created because the final image (`FROM scratch`, non-root UID 10001) simply has no `/tmp` directory and the unprivileged process can't mkdir it at the filesystem root. The regression landed in v2.7.0 when the Dockerfile switched to `scratch`; it didn't surface until a user actually tried the backup button on that image, and every install built from the pre-2.7.0 images kept working by coincidence. Two fixes, deliberately stacked:
  - **Handler-level fix.** `getBackup` now writes the temp file next to the live DB (`filepath.Dir(s.DBPath)`) instead of `os.TempDir()`. Same filesystem as the source DB, same UID ownership as the existing `caddyui.db` / `.db-wal` / `.db-shm`, zero chance of CANTOPEN on a directory that was already open two lines earlier. Falls back to `os.TempDir()` only if `DBPath` is empty — defence-in-depth against a future constructor regression.
  - **Image-level fix.** Dockerfile pre-creates `/tmp` with `1777` (sticky world-writable) in the build stage and copies it into the scratch final image. The backup handler doesn't need this any more, but mime/multipart file uploads, any third-party Go library that calls `os.TempDir()` internally, and anything we add later that reaches for `/tmp` would otherwise silently break the same way. Catches the *next* instance of this bug before a user has to file it.

### Changed
- **`server.New` takes a new `dbPath string` argument.** Plumbed from `main.go` (which already owns the `CADDYUI_DB` env lookup) through to `Server.DBPath`. Only the backup handler reads it today; future operational handlers (restore, compact, integrity-check) can reuse the same field instead of re-threading the env variable.

### Docker
- Published as `applegater/caddyui:v2.7.5` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

---

## [2.7.4] — 2026-04-24 · Groups: team-level resource visibility

### Added
- **Admin-managed Groups (`/groups`).** New admin-only page bundles `user`-role accounts into a team. Every member of a group sees every other member's proxy hosts, redirection hosts, advanced (raw) routes, and certificates in their own list views — **read-only** (edit / delete stays owner-scoped). Use case: a customer has two staff accounts, `alice@customer` and `bob@customer`; admin drops both into a `Customer X` group and they each see the full site roster without either being able to stomp the other's rows. Admins themselves see everything regardless and don't need to be in any group.
- **Team chip on shared rows.** Proxy-host / redirection-host / raw-route / certificate list rows that belong to a group teammate (not the viewer, not global) render a small amber `Team` chip next to the owner's email so it's clear at a glance which rows are "mine" vs. "my teammate's". Owner column stays visible on admin views; non-admin users in a group get the chip plus the teammate's email inline so they know who to ping about a row before trying to edit it.
- **Sidebar `Groups` item in the admin Access Control section.** Appears only for `admin`-role accounts, slots next to Users. Icon is a two-person cluster glyph (added inline to the shared `icon` template) to visually distinguish it from the single-person Users entry.

### Changed
- **`ListProxyHosts` / `ListRedirectionHosts` / `ListRawRoutes` / `ListCertificatesForUser` all take a new `peerIDs []int64` argument.** Non-admin viewer path now matches `owner_id IS NULL OR owner_id = viewerID OR owner_id IN (peerIDs...)` instead of the old two-term `OR`. `nil` / empty peerIDs collapses cleanly to the pre-2.7.4 two-term behaviour — users with no group membership see exactly what they saw before. Admin branch is unchanged (unfiltered).
- **`Server.groupPeerIDs(r)` is the single call site for teammate expansion.** Every list handler that previously passed `viewer.ID` to a `List*` call now also threads `s.groupPeerIDs(r)` as the new final argument. The helper short-circuits to `nil` for admin, view-role, and signed-out requests so the teammate-IDs query only runs on paths that will actually use it. Swallows DB errors to `nil` — a transient `groups`-table hiccup degrades to "no group visibility" rather than 500-ing the whole list page.
- **`advancedRouteRow` struct grew `OwnerEmail` / `CanEdit` / `IsTeamRow` fields.** The proxy-hosts advanced-routes table is the only place that uses this view struct (it's how raw routes surface on the `/proxy-hosts` page), and it wasn't plumbed through the ownership model at all before 2.7.4. Populated inline during the `advancedRows` loop using the same `isAdmin || (ownerID == viewerID)` predicate the proxy-host / cert paths use, so gating stays consistent across every resource on every page.

### Implementation notes
- **`groups` + `user_groups` schema ships via the idempotent `CREATE TABLE IF NOT EXISTS` migration block in `internal/db/db.go`.** Two tables: `groups(id, name, description, created_at, updated_at)` and a `user_groups(user_id, group_id)` many-to-many join with `ON DELETE CASCADE` on both foreign keys so deleting a user or a group cleans up membership rows automatically. An index on `user_groups(group_id)` keeps the `GroupPeerIDs` self-join fast even on servers with hundreds of memberships. No destructive migration — every pre-2.7.4 row keeps working because a user with no group memberships resolves to `peerIDs = nil` and takes the old query path.
- **`GroupPeerIDs(db, viewerID)` is a self-join on `user_groups`.** `SELECT DISTINCT ug2.user_id FROM user_groups ug1 INNER JOIN user_groups ug2 ON ug2.group_id = ug1.group_id WHERE ug1.user_id = ? AND ug2.user_id != ?` — finds every user that shares at least one group with the viewer, de-duped (two users in three shared groups still appears once), and excludes the viewer themselves (they're already covered by the `owner_id = viewerID` leg of the WHERE clause). De-dup happens at the SQL level so the returned slice can be spliced directly into an `IN (...)` without a downstream uniq pass.
- **`inClause(ids)` helper returns `("NULL", nil)` on empty input.** Keeps list-query callers branch-free — they can always splice the returned fragment into `owner_id IN (...)` without a nil-check, and `owner_id IN (NULL)` is always false in SQL three-valued logic, which is exactly the right behaviour when a viewer has no peers (no rows beyond their own + globals should appear). Non-empty input returns `("?,?,?", args)` with positional placeholders, so callers stay parameterised — no string-concat SQL.
- **Per-row `{{$canEdit := ...}}` pattern instead of a view-struct wrapper.** Rather than extend every model with a `view` wrapper type (as v2.7.2 did with `certView.CanEdit`), the group-visibility templates compute `$canEdit` and `$isTeam` inline at the top of each `{{range}}` block: `{{$canEdit := or (eq $.User.Role "admin") (and .OwnerID.Valid (eq .OwnerID.Int64 $.ViewerID))}}`. Value is reused across pencil icon, delete button, tap-to-edit wrapper, cursor-pointer classes, and Team chip visibility so the predicate can't drift between decorations. `ViewerID` is injected into the render context for the three list views that didn't already have it (`listProxyHosts`, `listRedirectionHosts`, `listRawRoutes`).
- **Group-form member picker is a checkbox array, POSTed as `member_ids[]`.** `SetGroupMembers(db, groupID, userIDs)` runs the membership rebuild as a single transaction — `DELETE FROM user_groups WHERE group_id = ?` then a bulk `INSERT` — so a group edit is atomic (no partial state if the request errors mid-rebuild). Re-submitting the same member list is a no-op from the caller's perspective. The form's error re-render rebuilds the `members` map from `r.Form["member_ids"]` so a validation failure (empty name, duplicate) doesn't drop the admin's check selections.
- **Routes gated via the existing `requireAdmin` group.** `/groups`, `/groups/new`, `/groups` POST, `/groups/{id}/edit`, `/groups/{id}` POST, `/groups/{id}/delete` all sit inside the `requireAdmin` chi group in `server.go` — non-admins get 404 on any of these URLs, same as `/users/*`. No per-handler role check needed inside the six handlers themselves because the router is the single enforcement point.
- **Edit / delete stays owner-scoped at both the route handler and the template.** Group visibility is strictly a read-share — a teammate viewing your proxy host sees it in the list (with the Team chip) but the Actions column shows an em-dash placeholder, the row isn't tap-to-edit, and the underlying `editProxyHost` / `updateProxyHost` handlers still 403 any non-owner non-admin POST. Same story for redirections, raw routes, and certificates. Admins can edit / delete anything, same as before.

### Docker
- Published as `applegater/caddyui:v2.7.4` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

---

## [2.7.3] — 2026-04-24 · Admin can reassign ownership per resource

### Added
- **Admin-only Owner picker on every ownership-aware resource form.** Proxy hosts, redirection hosts, advanced (raw) routes, and certificates now render an `Owner` `<select>` at the bottom of the new/edit form for admins. Options are `Global (admin — managed by you)` (the default, equivalent to `owner_id IS NULL`) plus one entry per `user`-role account. Use case: admin provisions a proxy host for a customer, then assigns it to them in one step — the row shows up in that user's dashboard, fully theirs to edit / delete, while the admin retains oversight.
- **Reassign-on-edit.** Editing any of the four resources re-posts the picker, so an admin can hand off an existing row (e.g. a proxy host initially set up under the admin account) to a customer without recreating anything. The TLS cert references on other routes keep working — cert resolution is by ID, not ownership.

### Changed
- **`Server.adminUserList(r)` returns only `user`-role accounts.** Admin and view-role accounts are filtered out before reaching the picker: neither can "own" a resource in the data model (admin ownership is modeled as `NULL` / global; view-role can't manage anything). Returning them would populate the dropdown with dead options. Non-admin viewers still get `nil` so their templates can't accidentally leak the user roster.

### Implementation notes
- **New model-layer helpers kept separate from `Update*`.** `SetProxyHostOwner`, `SetRedirectionHostOwner`, `SetRawRouteOwner`, `SetCertificateOwner` each run a single `UPDATE ... SET owner_id=?` statement. They are NOT folded into the existing `Update*` functions — the user-role edit path calls those same functions, and we never want a forged `owner_id` in a user's POST body to silently rewrite the row's owner. The handler gates the owner write on `isAdmin` before calling the dedicated setter.
- **Create-time assignment uses the same admin-gated form field.** `createProxyHost`, `createRedirectionHost`, `createRawRoute`, `createCertificate` read `r.FormValue("owner_id")` only when the current user is admin; a non-admin's branch ignores the field and short-circuits to `cu.ID`. An absent / blank `owner_id` on the edit path leaves ownership untouched (so the upgrade path — old form, no picker rendered — stays safe).
- **Template picker uses `{{if .Users}}` as the admin gate.** `adminUserList` returns `nil` for non-admin, and `{{if .Users}}` on a `nil` slice is false, so the picker markup is simply absent in non-admin DOMs — no conditional role check in the template.

### Docker
- Published as `applegater/caddyui:v2.7.3` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

---

## [2.7.2] — 2026-04-24 · Per-user certificate ownership

### Added
- **Users can upload and manage their own TLS certificates.** Until now, `/certificates` was admin-only — a `user`-role account could see the list and reference certs from the proxy-host dropdown but couldn't create, edit, or delete. v2.7.2 extends the same `owner_id` ownership model already used by proxy hosts / redirections / raw routes to the `certificates` table:
  - `owner_id IS NULL` → **global / admin-owned**. Visible to every user's proxy-host dropdown (so the admin wildcard still works for everyone). Only admins can edit or delete.
  - `owner_id = <user.ID>` → **private to that user**. The uploader can see, edit, and delete it; admins can do the same. Other user-role accounts never see it — not in the list, not in the dropdown.
  - Pre-2.7.2 rows migrate with `owner_id = NULL` (treated as global) so nothing existing changes behaviour for current admins.
- **Owner column on `/certificates` (admin view).** Shows the uploader's email for user-owned certs and a `Global` chip for admin-owned rows. Non-admin views don't render the column since the list is already scoped to their own uploads + globals.

### Changed
- **`+ New Certificate` is now writer-level, not admin-only.** Route `/certificates/new`, `/certificates` POST, `/certificates/{id}/edit`, `/certificates/{id}` POST moved from the `requireAdmin` group to the `requireWrite` group. Per-handler ownership checks in `editCertificate` / `updateCertificate` 403 a user trying to edit another owner's cert (or a global cert) so route loosening doesn't become a privilege escalation.
- **Delete is ownership-aware but still blast-radius-protected.** Admins can delete any cert. User-role accounts can delete a cert they own, *unless* a site belonging to another owner (or a global admin site) still references it — in which case the handler returns `403 this certificate is in use by another user's site — ask an admin to delete it`. The new `models.CertificateInUseByOthers(db, certID, excludeOwnerID)` helper drives the check.
- **Cert dropdown on proxy-host / redirection / raw-route forms is scoped to the viewer.** A user-role account picking a cert from the TLS dropdown now only sees their own uploads + global certs. The form never surfaces another user's private TLS material. Sync paths (`syncCaddy`, cert-expiry notifier background job) keep using the unscoped `models.ListCertificates` so the Caddy config is still built from every cert on the server.

### Fixed
- **Missing `+ New` button for user-role accounts on `/certificates`.** Reported from a live screenshot (`richard@joe.coffee`, role = `user`) showing the Actions column as em-dash placeholders and no New button in the header. The old template gated both on `{{if eq .User.Role "admin"}}`. v2.7.2 switches the header button to `{{if ne .User.Role "view"}}` and the per-row Edit/Delete buttons to the precomputed `.CanEdit` predicate, which is true for admin on any row and for user-role on their own rows only.

### Implementation notes
- **New helper `Server.certListForRequest(r)`.** Nine dropdown callsites across `newProxyHost` / `editProxyHost` / `newRedirectionHost` / `editRedirectionHost` / `newRawRoute` / `editRawRoute` / `renderRawRouteFormError` / `renderRedirectionHostFormError` / `renderProxyHostFormError` all ran the same `ListCertificates(db, currentServerID)` boilerplate. v2.7.2 consolidates to `s.certListForRequest(r)` which internally reads `currentUser` + `RoleAdmin` and calls `ListCertificatesForUser`. Keeps the dropdown behaviour consistent across every form — future form additions only need to pick the right helper.
- **`ListCertificatesForUser(db, serverID, viewerID, isAdmin)` mirrors the `ListProxyHosts` signature.** Admin path does a `LEFT JOIN users` to populate `OwnerEmail` for the Owner column; non-admin path skips the JOIN entirely (there's no column to populate and we shouldn't surface other users' emails to a user-role account anyway) and filters by `owner_id IS NULL OR owner_id = viewerID`.
- **`certView.CanEdit` is precomputed server-side, not re-derived in the template.** The template was already comparing `.User.Role` on every row; the ownership check adds `viewer.ID == row.OwnerID.Int64`. Doing that per-row in the Go code keeps the template readable (`{{if .CanEdit}}` vs. a three-term `{{if or … …}}`) and the predicate is the same one the server-side route handler uses, so they can't drift.
- **Delete handler keeps its inline role/ownership check.** The route is now in the `requireWrite` group which only filters the `view` role, so the handler itself is the single enforcement point for "can this user delete this specific cert". The handler logic is: admin → always OK; global cert → admin only; owned cert → uploader only, and only when no cross-owner references remain. Viewers don't reach the handler.

### Docker
- Published as `applegater/caddyui:v2.7.2` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

---

## [2.7.1] — 2026-04-24 · Analytics toggle fix, per-server filter, form layout polish

### Fixed
- **Enabling visitor analytics silently did nothing on a fresh Caddy config.** Two bugs compounded so Settings → Analytics reported "enabled" while Caddy was never actually shipping logs to CaddyUI. Both hit first-time installs and nobody who'd toggled it on then off on a Caddy that had already had any logger configured. Tracked down from a log line buried in `docker logs caddyui` that said `install access-log logger: caddy POST /config/logging/logs/caddyui_access status 500: {"error":"invalid traversal path at: config/logging/logs"}`.
  - **Bug 1 — checkbox value ignored on save.** `postSettings` read `analytics_enabled` via `r.FormValue()` which returns only the *first* value for a key. The form uses the standard hidden-input + checkbox pair (`<input type=hidden name=analytics_enabled value=0>` then `<input type=checkbox name=analytics_enabled value=1>`) so that unchecking posts a value, and the hidden `"0"` always came first in tree order. Every save stored `0`, the toggle always reverted. Fixed by scanning `r.PostForm["analytics_enabled"]` for `"1"` instead of relying on `FormValue`. Same scan was wrong on `smtp_skip_verify` and `cf_proxied` — fixed in the same patch; both had been silently broken since the toggle was introduced, admins just hadn't noticed because the visible side-effect was subtler.
  - **Bug 2 — Caddy admin-API rejected the PUT when `logging` didn't exist.** `EnableAccessLogs` ran `PUT /config/logging/logs/caddyui_access` which only works if the parent `logging.logs` map already exists. On a fresh Caddy boot the `logging` key is null, so the call returned `500 {"error":"invalid traversal path at: config/logging/logs"}` and no logger was installed. `EnableAccessLogs` now detects missing-parent phrasings via the shared `isCaddyMissingPathErr` predicate and falls back to `PUT /config/logging` with `{"logs": {"caddyui_access": …}}`. Fetches current config first so any other loggers the admin had (via Caddyfile or a prior patch) survive the bootstrap PUT.
  - **Same missing-parent error was breaking disable too.** The symmetric `DELETE /config/logging/logs/caddyui_access` returned the same "invalid traversal path" string when called on a Caddy with no logging key at all (fresh instance, toggle never enabled, user hits Save with the toggle off). `deletePathIgnoreMissing` now treats it as idempotent success alongside `"not found"` and `"unknown"`.

### Added
- **Per-server filter on `/analytics`.** New inline `<select>` appears in the page header when more than one Caddy server is registered; picks drive `?server=<id>` on the URL and narrow every card — totals, top-hosts table, 24-hour sparkline, status-mix pie. Admins with a fleet of 5+ servers can now focus on one box at a time without changing their global CurrentServer selection (the top-nav picker is deliberately untouched — this one is scoped to the analytics page only). `/analytics` with no filter still runs the fleet-wide hot path; scoped mode uses the same per-host loop non-admin users already go through. Subtitle copy switches from "every host this fleet routes" to "hosts routed by the selected server" when a scope is active.
- **`scopedHostsForAnalytics(u, serverID)` in `internal/server/analytics.go`.** Factored out from the old `userAllowedHosts` thin wrapper. Admin + `serverID=0` returns nil (no filter, hot path); admin + specific-server returns every host the selected server routes; non-admin intersects ownership with the server scope. Hosts are lowercased + deduped so downstream IN-clauses never see case variance.

### Changed
- **Managed DNS moved near the top of the proxy-host form.** Previously buried after IP Allowlist / Extra Upstreams / Basic Auth, which meant users who wanted to set up DNS for a new host had to scroll through five unrelated sections first. Now sits directly below Options, right after the Domain names field it depends on. Same `<details>` collapse, same auto-open-on-edit behaviour, same DOM IDs — zero JS changes, existing zone-loader + collision-checker JS attaches unchanged.
- **TLS Certificate collapsed into a `<details>` on all three route forms.** Proxy host, redirection host, and raw route forms all had TLS Certificate expanded by default even though most users want the Auto (Let's Encrypt) default. The dropdown now hides inside a `TLS Certificate (optional, defaults to auto Let's Encrypt)` summary that auto-opens on edit only when a non-default certificate is already bound. Consistent with Managed DNS / Advanced config / IP Allowlist / Extra Upstreams.

### Implementation notes
- **`isCaddyMissingPathErr` in `accesslog.go` is the single source of truth.** Both `EnableAccessLogs` (bootstrap-the-parent fallback) and `deletePathIgnoreMissing` (idempotent-success) funnel through it. Recognises three observed phrasings across Caddy versions — `"config path not found"` (modern 404), `"unknown key"` (older releases), `"invalid traversal path at: <path>"` (null parent). Keeping the predicate shared means future Caddy error-string changes can't desync the two paths.
- **Scoped-analytics flag is `allowedHosts != nil`, not `isAdmin`.** The old branches keyed on `isAdmin`, which conflated two independent axes: "does this user have visibility everywhere" and "are we filtering the result set". After v2.7.1 admin-with-filter takes the same per-host summation path non-admins take; only admin+unscoped hits the single-query hot path. Empty non-nil slice (admin picks a server with zero routes) returns all-zero totals rather than all-fleet, which is the correct semantics.
- **Hidden+checkbox pattern is in the HTML5 spec and the bug is in `FormValue` not the template.** Keeping the hidden `0` input is necessary for "unchecking means submit a value" — without it, an unchecked checkbox submits nothing and the server can't distinguish "user unchecked" from "user didn't touch the form". The bug was on our side reading via `FormValue` which returns only the first value. Scanning `PostForm[key]` is correct and handles any order of the two inputs.
- **Bootstrap PUT preserves existing loggers.** When `EnableAccessLogs` falls back to `PUT /config/logging`, it fetches the current config and merges any existing `logging.logs.*` entries other than `caddyui_access` into the new tree. The null-parent case never has anything to preserve (by definition), but the non-null case path is identical so the call is idempotent either way — repeat enables can't trample admin-configured loggers.

### Docker
- Published as `applegater/caddyui:v2.7.1` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`).

---

## [2.7.0] — 2026-04-24 · Visitor analytics, reCAPTCHA v3 fix, RBAC UI hardening

### Added
- **Privacy-light visitor analytics built from Caddy's access logs.** New `/analytics` overview page — "Live now" (5-minute distinct IPs), today's visitors + views, last-7-day totals, an HTTP-status mix pill, a per-host top-table (click a row to drill down), a 24-hour 1-hour-bucket sparkline, and an admin-only ingest-pipeline health card (connection count, events, excluded, errors, last-event relative time). Per-host drill-down at `/analytics/{host}` — window selector (24 hours / 7 days / 30 days), 4-up summary cards including a success-rate computation (`(2xx+3xx)/total`), bar chart in the chosen window, Top paths and Top visitors side-by-side tables with per-row bars, and a stacked HTTP-status breakdown bar. Admins see every host the fleet routes; non-admin users only see hosts they own (union of their proxy hosts and raw routes across every Caddy server in the DB — analytics is intentionally cross-server).
- **Settings → Analytics card** (jump-to anchor `#analytics`) — on/off toggle, ingest-target input with the `caddyui:9019` default shown as a placeholder, exclude-IPs textarea (one IP or CIDR per line, or comma-separated), plus live ingest metrics. Saving the form re-applies Caddy's logger config via the admin API; disabling removes the `caddyui_access` logger and the per-server `default_logger_name` pointers.
- **Analytics ingest listener in `internal/analytics/ingest.go`** — TCP NDJSON, binds `:9019` by default (override via `CADDYUI_INGEST_LISTEN`), one JSON object per line with a 64 KB `bufio.Scanner` ceiling, graceful shutdown via `ctx` + `WaitGroup` for in-flight connections. Parses Caddy's access-log schema — `request.host` / `request.uri` (query-string stripped, URI capped at 2 KB) / `request.method` / `request.remote_ip` (port stripped) / `request.headers.User-Agent` (capped at 512 bytes) / `status` / `size` / `duration` / `ts`. Excluded IPs (parsed with `net.ParseCIDR` + `net.ParseIP`, mixed is fine) drop before the DB insert. Atomic counters (`sync/atomic`) for Connections / Events / Excluded / Errors / LastEventAt so the Settings handler can display live stats without a lock.
- **Caddy admin-API client `internal/caddy/accesslog.go`** — `EnableAccessLogs(target)` PUTs `/config/logging/logs/caddyui_access` with a `{"writer":{"output":"net","address":"<target>"},"encoder":{"format":"json"}}` block and loops every HTTP server setting `default_logger_name: caddyui_access`. `DisableAccessLogs()` DELETEs the logger and each server's logs config, treating 404 / "not found" as success so idempotent disable from a clean state doesn't error.
- **DB tables `access_events` + indexes** — stored as unix seconds (`ts INTEGER`), single-writer pool (SQLite `pool=1`) safely handles >1 000 inserts/sec, covering index on `(ts)` for time-window scans plus a composite `(host, ts)` index for per-host drill-downs. `PruneAccessEvents(cutoff)` runs daily from `pruneAccessLoop` — keeps 30 days by default, one indexed DELETE.
- **Template helpers for chart math** — `mulDivInt`, `subInt`, `addInt`, `fmtRel` in the `parseTemplates` funcMap. `mulDivInt` gates on divide-by-zero (returns 0), `fmtRel` renders `30s` / `5m` / `2h` / `3d` / `2026-04-24` depending on interval size, handles future times ("in 2m", from clock skew) and zero values ("never"). Registered so analytics.html / analytics_host.html can compute SVG bar heights and humanize last-seen timestamps without a frontend toolchain.
- **Sidebar footer credits** — copyright notice, GitHub repo link, and license link tucked under the version string in the left-nav footer. One line of tiny ink-400 text; matches what users expected to find there when looking for "where's the project home?".

### Fixed
- **reCAPTCHA v3 "Security check failed" on login / TOTP / new-user forms.** Google's `grecaptcha.execute()` rejects action names containing anything other than alphanumerics and `/`; `login-form`, `totp-form`, and `new-user-form` all contained a hyphen and were getting rejected client-side with a vague error that bubbled up as the server's "no token in form" rejection. `web/templates/layout.html` now sanitizes the action name with `/[^a-zA-Z0-9\/]/g` before calling `grecaptcha.execute()` and falls back to `'submit'` if the result is empty. Same template also gained: pre-fetch of the token on page load via a `whenReady` poll (no more "checkbox appears to be the last thing that loaded"), `setInterval` refresh every 90 seconds so the 2-minute token TTL doesn't lapse while the user types their password, a submit-handler guard that refuses empty-token submits with an inline red error, and `describeErr()` to stringify Google's rejection object so the diagnostic says "Google rejected the request" instead of `[object Object]`. Server-side `internal/server/captcha.go` logs the posted form keys (filtering out password / TOTP code) plus user-agent + remote IP on empty-token rejects, so future regressions are one log line away from root cause.
- **Non-admins could see and attempt cert create / edit.** `/certificates/new` and `/certificates/{id}/edit` now require admin role at the handler level (previously anyone logged in could GET them and submit); the `+New certificate` and per-row `Edit` / `Delete` buttons are hidden on `certificates.html` for non-admins so the UI matches the backend. Matches the pattern already used on servers, users, and settings.
- **users.html role badge mislabelled a `user` role as `view`.** The template's switch block had `{{else if eq .Role "user"}}viewer-green pill{{end}}` instead of `{{else if eq .Role "view"}}…{{end}}`. Real `view`-role users showed as "viewer" (correct text, wrong CSS key) and `user`-role rows fell through to the default admin-red. Role strings in the DB are one of `admin` / `user` / `view`, so the branch was plain wrong. Fixed in `web/templates/users.html`.
- **"Switch server" link cleaned up; profile moved to the top bar.** The sidebar's legacy "Switch server" dropdown duplicated the server picker already in the top bar, so it's removed. The profile block (logged-in email + sign-out) relocated to the top bar so the sidebar is strictly navigation; matches the visual hierarchy modern admin UIs use.
- **Dashboard system-stats cards hidden from `user` / `view` roles.** Non-admins don't have permission to hit `/api/stats` anyway (it returns host CPU/memory stats about the CaddyUI container's host), but the cards were still rendered in the template — they just showed "Loading…" forever for non-admins. `dashboard.html` now wraps the three system cards in `{{if .IsAdmin}}…{{end}}` so they disappear cleanly for lower roles.

### Implementation notes
- **Analytics writes stay single-threaded against the SQLite pool.** The ingest goroutine calls `InsertAccessEvent` per request; SQLite's 1 000+ inserts/sec ceiling is well over the <100 rps a home/SMB Caddy typically sees. If that ever changes, the next step is a 1 000-event buffered channel + batching transaction rather than multi-writer Go + SQLite, because WAL mode on SQLite still funnels writes through a single lock.
- **Host scoping preserves privacy.** Non-admin analytics queries aggregate over the user's owned hosts in Go rather than SQL, because a user with 20 owned hosts would otherwise need a 20-way `IN (…)` clause on every card. Admin queries stay single-round-trip. `liveVisitorsAcrossHosts` is the exception — it has to union distinct IPs across owned hosts so an IP visiting two hosts isn't double-counted, and that's a single query with IN(…).
- **404 (not 403) on per-host analytics the user doesn't own.** Leaking "this host exists but you can't see it" would let a compromised user account enumerate other users' sites — so non-admins who GET `/analytics/otherhost.com` get the same "not found" they'd get for a host that genuinely has no events. Consistent with the proxy-host / raw-route list pages' ownership scoping.
- **Ingest filter changes take effect immediately.** `applyAnalyticsToggle` pushes the parsed exclude list to the live `*analytics.Ingest` *before* calling `EnableAccessLogs` / `DisableAccessLogs`, so even when the toggle is off, a future re-enable picks up whatever the admin configured in the meantime. No restart needed when an admin adds their home LAN to the exclude list.
- **TCP ingest listener exposed on `:9019` inside the container only.** The `docker-compose.yml` in the README doesn't bind a host port for it — the Caddy container connects via the shared Docker network using the service name `caddyui`. Admins on host-network deployments override `analytics_ingest_target` in Settings to `host.docker.internal:9019` or the LAN IP, and CaddyUI's `ingest.Start` binds the same port regardless.
- **Access-log schema we parse is conservative.** We care about `request.{host,uri,method,remote_ip,headers.User-Agent}`, `status`, `size`, `duration`, and `ts`. Everything else in Caddy's rich access-log format is ignored — no cookies, no request body, no TLS handshake metadata — because storing it would bloat the DB and risk leaking secrets (session IDs, auth tokens) in URL params. The URI's query string is stripped at ingest for the same reason.
- **Go `html/template` can't arithmetic, so we ship four helpers, not Sprig.** `mulDivInt`, `subInt`, `addInt` cover the three operations SVG bar-chart rendering needs. `fmtRel` is the one that'd otherwise push us to a CSS library — human-readable intervals don't fit cleanly into `time.Duration.String()`.
- **reCAPTCHA v3 only, not v2.** The layout-template widget writes a `<script src="https://www.google.com/recaptcha/api.js?render=SITE_KEY">` tag and calls `grecaptcha.execute(SITE_KEY, {action: SANITIZED})` — no checkbox, no image challenge. If Google ever ships a v4 with different rules, `describeErr()` will surface the breakage in the UI instead of silently rejecting every login.

### Documentation
- Settings → Analytics card ships with inline help text explaining the ingest target default, host-network override, the fact that changes take effect immediately (no Caddy reload needed), and the 30-day retention window.
- Top of `/analytics` clarifies the scope difference for admins vs non-admins ("You're seeing every host this fleet routes" / "You're seeing the hosts you own").
- Empty-state on the top-hosts table differs by role + enabled-state — an admin with analytics disabled sees "Enable access log forwarding in Settings → Analytics", an admin with it enabled sees "Waiting for Caddy to ship its first access log entry", a non-admin sees "No traffic has been recorded for the hosts you own yet".

### Docker
- Published as `applegater/caddyui:v2.7.0` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001).

---

## [2.5.11] — 2026-04-24 · XSS sinks in zone-picker error paths hardened

### Security
- **CodeQL flagged two "Exception text reinterpreted as HTML" findings; both fixed, plus two sibling sinks it hadn't seen yet.** `web/templates/proxy_host_form.html` (line 403) and `web/templates/raw_route_form.html` (line 337) each caught a `.catch(e) { zoneSel.innerHTML = '…' + e.message + '…' }` pattern in the DNS zone-picker dropdown. If a malicious `/api/dns-zones` response, a provider-side error string, or a MITM on the provider's HTTPS connection ever produced an error message containing raw HTML, string-concatenating it into `innerHTML` would let that HTML execute in an authenticated admin's browser. Real-world reachable? Only through a compromised DNS provider API or a MITM on the HTTPS connection to it — both unlikely in normal deployments — but the sink is an XSS sink regardless. The `data.error` branch two lines up had the same shape and got the same fix even though CodeQL hadn't flagged it yet, and likewise for the "Select a provider first" placeholder which built an `<option>` via concatenation out of habit.

### Implementation notes
- Swapped `zoneSel.innerHTML = '<option value="">' + text + '</option>'` for `zoneSel.replaceChildren(new Option(text, ''))`. `new Option(text, value)` sets the displayed text as a real DOM text node (textContent), never as HTML, so user-supplied strings can't break out of the tag. Same fix applied to all four call sites per form file — loading placeholder, server-error branch, fetch-catch, and no-provider placeholder — so the pattern is uniform across both templates.
- `replaceChildren()` is baseline-supported in every browser since 2020, same era as the `fetch` / Promise / arrow-function set CaddyUI already relies on; no polyfill needed.
- No behaviour change for users. The dropdown still shows "Loading zones…" / "Error: X" / "Failed to load zones: Y" / "Select a provider first" in the same visual form. The only difference is the text can no longer be interpreted as markup.
- CodeQL alerts #7 and #8 should auto-close on the next scan after this commit lands on `main`.

### Documentation
- Added `docs/adguard-home-setup.md` — a 9-step runbook for the AdGuard Home + Caddy encrypted-DNS recipe from the v2.5.10 blog post. Covers Cloudflare DNS records, Caddy wildcard cert via paste-import, freeing port 53 from `systemd-resolved` (the single biggest gotcha on fresh Linux hosts), Portainer stack deploy with the actual working YAML, first-run wizard, the AdGuardHome.yaml TLS block with a cert-share mount, endpoint tests for DoH/DoT/DoQ, per-protocol ClientID setup, and a monthly cron to pick up renewed certs. Reproducible end-to-end by anyone with a Cloudflare-managed domain and Portainer.

### Docker
- Published as `applegater/caddyui:v2.5.11` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001).

---

## [2.5.10] — 2026-04-23 · Edit-path Managed DNS now reacts to alias-only Domains changes

### Fixed
- **Adding or removing an alias on an existing proxy host or advanced route now actually provisions / removes the matching A record.** v2.5.9 fixed the *create* path and the server-IP *retarget* path to iterate every hostname, but the user-initiated *update* paths at `updateProxyHost` and `updateRawRoute` still detected "did the hostname change?" by comparing only `dns.FirstDomain(old.Domains)` vs `dns.FirstDomain(p.Domains)` (proxy) and `firstRawRouteHost(old.JSONData)` vs `firstRawRouteHost(rr.JSONData)` (raw). If the user kept the primary and just tacked on `try.example.com` as an alias, `domainChanged` / `fqdnChanged` was false, so `needCreate` was false, and no record was ever created for the new alias — the browser then got NXDOMAIN (which Chrome surfaces as `DNS_PROBE_FINISHED_BAD_SECURE_CONFIG` when Secure DNS / DoH is on, because the upstream resolver's DNSSEC-signed "no such name" reply can't be validated against the parent zone's wildcard expectation). The comparison is now `!slices.Equal(old.DomainList(), p.DomainList())` for proxy hosts and `!slices.Equal(rawRouteHosts(*old), rawRouteHosts(*rr))` for raw routes — any addition, removal, rename, or reorder triggers the delete-all-then-create-all cycle that `dnsCreateRecord` / `dnsCreateRecordForRaw` have done since v2.5.9. Matches the same behaviour the server-IP retargeter already took in `dnsUpdateAllRecords`, so all three mutation paths (create, edit, retarget) now agree on "every hostname in the list gets an A record."

### Implementation notes
- Adds `"slices"` to the `internal/server/server.go` import set (stdlib, no `go.mod` change). `slices.Equal` does element-wise comparison on the trimmed + de-empty-filtered output of `DomainList()` / `rawRouteHosts()`, so whitespace-only differences between saves don't trigger spurious retargets — only genuine set or order changes do.
- Order-sensitive comparison means a pure reorder of an otherwise-identical Domains list counts as a change and causes a retarget. Rare enough in practice (users don't usually rearrange aliases for fun) and the flutter is the same couple of seconds the IP retargeter already accepts, so not worth the extra code to sort-and-compare.
- Updates the stale docstring on `dns.FirstDomain` — the v2.3.0-era "DNS records are only ever created for the first domain — the rest are aliases handled by Caddy at the proxy level" was already wrong after v2.5.9; the comment now points readers at `ProxyHost.DomainList()` for DNS lifecycle and reserves `FirstDomain` for UI/probe use.
- No schema change, no migration. Existing rows keep whatever single-ID or comma-ID string they have in `dns_record_id`; the next save on a row with a stale alias list self-heals to the full multi-record state.

### Docker
- Published as `applegater/caddyui:v2.5.10` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.9] — 2026-04-23 · Managed DNS creates a record per hostname, not just the first

### Fixed
- **Multi-hostname proxy hosts and advanced routes now get a DNS record for every hostname.** Previously, `dnsCreateRecord` used `dns.FirstDomain(p.Domains)` and `dnsCreateRecordForRaw` used `firstRawRouteHost(rr.JSONData)`, so a row declaring `example.com, *.example.com` (or any alias list) would only ever get an A record for `example.com` — the wildcard / aliases got silently skipped, leaving clients that resolved them with no DNS pointing at the origin. The create paths now iterate every hostname in `ProxyHost.DomainList()` / `rawRouteHosts()`, call `dnsCreateRecordForFQDN` per host, and persist the resulting record IDs as a comma-separated string in the existing `dns_record_id` column. Cloudflare (and every other provider in the registry) accepts `*.foo` as a valid record name, so wildcards provision natively with no provider-specific branching.

### Implementation notes
- **Schema-free change.** The `dns_record_id` column stays `TEXT NOT NULL DEFAULT ''`. A single-ID row (`"abc123"`) and a multi-ID row (`"abc123,def456"`) both parse through the same `splitDNSRecordIDs()` helper, so there is zero DB migration — upgrades from any v2.x apply with just the binary swap.
- **`dnsDeleteRecord` now splits + loops internally.** All 6 call sites (proxy-host create/update/delete, raw-route create/update/delete) keep passing the raw `DNSRecordID` column value; the helper handles single-ID and comma-separated equally. Allow-list check stays at the top — refusing zone-level deletion still blocks every record in that zone, symmetric with the create path.
- **Retarget self-heals pre-v2.5.9 rows.** `dnsUpdateAllRecords` now takes `fqdns []string` instead of a single FQDN, deletes every old record, and creates one fresh record per current hostname. An existing multi-domain row whose DB only has the first hostname's record ID will, on first retarget, end up with records for ALL its hostnames — the missing-alias records get provisioned automatically. No manual backfill needed.
- **Existing rows not touched until edited or retargeted.** This is a fix, not a migration. A row that's never edited after the upgrade keeps its single-record state. The first time a user hits Save on that row (triggering the `needDelete` → recreate path) or retargets the server IP, it heals to full multi-record coverage.
- **Templates left as-is for now.** `proxy_host_form.html`, `proxy_host_deploying.html`, `raw_route_form.html`, `raw_route_deploying.html` all render `{{.DNSRecordID}}` directly — for multi-ID rows this shows a comma-separated list like `abc123,def456`. Cosmetic only; functionality is unchanged. A future minor can render pill chips per record.

### Docker
- Published as `applegater/caddyui:v2.5.9` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

---

## [2.5.8] — 2026-04-23 · Caddyfile paste-import now captures per-site TLS automation policies

### Fixed
- **Pasted `tls { dns <provider> ... }` directives are no longer dropped on import.** Previously, the Caddyfile paste-importer at `/caddyfile-import` only extracted `apps.http.servers.*.routes[]` from Caddy's `/adapt` output and ignored `apps.tls.automation.policies[]`. That meant a site block carrying a DNS-01 challenge config (or any per-site custom issuer) would have its routes saved and pushed to Caddy, but the automation policy — the piece that tells Caddy *how* to get the cert — never reached the live config. Caddy would then fall back to the default HTTP-01 challenge and fail for any host that wasn't reachable on `:80`, or issue via ZeroSSL fallback, or just sit retrying. The importer now extracts those policies too, merges them into live `apps.tls.automation` deduped by subject (so existing per-host policies and hand-set catch-alls are preserved), and POSTs the merged object back so DNS-01 providers baked into the Caddy binary (like the Cloudflare module in `Dockerfile.caddy`) actually get used. Applies to `/caddyfile-import`; the per-raw-route form's `adaptRawRouteCaddyfile` path has the same underlying pattern and is unchanged in this release — users authoring one route at a time should either use the form's dedicated DNS provider fields or push the policy via `curl http://caddy:2019/config/apps/tls/automation`.

### Implementation notes
- New helpers in `internal/server/server.go`: `extractAdaptedAutomationPolicies(cfg)` mirrors `extractAdaptedRoutes` but reads `apps.tls.automation.policies[]`; `mergeAutomationPolicies(existing, incoming)` strips subjects already covered by an existing policy and prepends the rest (Caddy scans policies in declaration order — more-specific ones must come first).
- `pushAutomationPolicies(r, incoming)` fetches the live config, merges, and writes the full `automation` object back via `PUT /config/apps/tls/automation`. Replacing the whole object (not just `.policies`) preserves other fields like `on_demand`, `renew_interval`, and `ocsp_interval`.
- Policy push is best-effort — a failure is logged but does not roll back the route import, since the routes themselves are already saved to the DB and in Caddy's live config. Users who see ACME fail after import should check `docker logs caddyui` for `automation-policy push failed`.

### Docker
- Published as `applegater/caddyui:v2.5.8` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001)

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
