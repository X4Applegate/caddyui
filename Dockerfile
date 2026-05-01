FROM golang:1.24-alpine AS build

# Install ca-certificates and tzdata in the build stage so they can be
# copied into the scratch final image. curl is needed for the v2.12.39
# vendored-asset downloads (Inter variable font + htmx) below.
# Create a dedicated non-root user.
RUN apk add --no-cache ca-certificates tzdata curl && \
    addgroup -S -g 10001 caddyui && \
    adduser  -S -G caddyui -u 10001 caddyui

WORKDIR /src
COPY . .

# v2.12.39: vendor Inter variable font + htmx at build time. Removes
# external CDN round-trips (fonts.googleapis.com, fonts.gstatic.com,
# unpkg.com). Files end up under web/static/ where Go's embed.FS picks
# them up at compile time, served by the existing /static/* handler
# with v2.12.38's Cache-Control: max-age=86400 wrapper.
#
# v2.12.43: also vendor a precompiled auth.css for unauthenticated
# pages — drops cdn.tailwindcss.com from /login / /setup /
# /reset-password / /forgot-password / /accept-invite. Authenticated
# pages still use the CDN runtime (300+ classes need the JIT). The
# auth.css file is committed pre-built (see tailwind.unauth.config.js
# + web/tailwind.input.css for the source). Re-run this command to
# refresh it after adding new classes to those pages:
#
#   docker run --rm -v "$PWD":/src -w /src alpine sh -c '
#     apk add --no-cache curl && \
#     curl -fsSL https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.15/tailwindcss-linux-x64 \
#       -o /usr/local/bin/tailwindcss && chmod +x /usr/local/bin/tailwindcss && \
#     tailwindcss -c tailwind.unauth.config.js -i web/tailwind.input.css \
#       -o web/static/auth.css --minify
#   '
#
# Full self-host of Tailwind (replacing the CDN on authenticated pages
# too) was attempted in v2.12.41 but reverted: on residential-ISP
# installs the global CDN's TTFB from Google's PageSpeed test geography
# beats a home server. If you move CaddyUI to a low-latency VPS, the
# trade-off flips and re-enabling becomes worthwhile — see git history
# (commit 7751ee3) for the original config.
RUN mkdir -p web/static/fonts && \
    curl -fsSL https://rsms.me/inter/font-files/InterVariable.woff2 \
      -o web/static/fonts/InterVariable.woff2 && \
    curl -fsSL https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js \
      -o web/static/htmx.min.js

# Note: BuildKit's docker-container driver (the multi-arch builder)
# has a bug where some web/static/ files don't make it into Go's
# embed.FS resolution. Reproduces with `docker buildx build --builder
# multiplatform` (buildkit v0.29.0) but NOT with the default docker
# driver. For now, build single-arch with the default builder until
# the bug is upstream-fixed. Multi-arch retag is on hold.

ARG VERSION=dev
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w -X main.Version=${VERSION}" \
      -o /out/caddyui ./cmd/caddyui

# Pre-create the data directory with the correct ownership so the volume
# initialises correctly when Docker creates it on first run.
RUN mkdir -p /out/data && chown 10001:10001 /out/data

# Pre-create /tmp so stdlib / third-party code that calls os.TempDir() has
# a writable directory at runtime. The backup handler is defensive (writes
# next to the DB instead, v2.7.5) but leaving /tmp missing would silently
# break anything else that reaches for it (mime/multipart uploads, etc.).
# 1777 is the standard sticky world-writable mode so any UID can use it.
RUN mkdir -p /out/tmp && chmod 1777 /out/tmp

# ── Final stage: scratch ──────────────────────────────────────────────────
# scratch has no shell, no package manager, and no OS packages, so there
# are zero OS-level CVEs in the final image.
FROM scratch

# HTTPS trust roots (needed for Turnstile verification, webhooks, update checks)
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Timezone database (needed for correct time formatting in logs and schedules)
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

# User/group files so USER directive and the app can resolve the username
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group  /etc/group

# Application binary
COPY --from=build /out/caddyui /app/caddyui

# Pre-created data directory (owned by caddyui uid 10001)
COPY --from=build --chown=10001:10001 /out/data /data

# World-writable /tmp (1777). v2.7.5 added this; --chmod preserves mode
# through the multi-stage COPY so non-root uid 10001 can write temp files.
# Without 1777, SQLite returns SQLITE_IOERR_GETTEMPPATH (6410) on any query
# that needs to spill a large sort to disk (e.g. GROUP BY host, ORDER BY views
# across millions of rows) — manifests as silently-empty analytics tables.
COPY --chmod=1777 --from=build /out/tmp /tmp

USER 10001

EXPOSE 8080
ENV CADDYUI_DB=/data/caddyui.db \
    CADDYUI_LISTEN=:8080 \
    CADDY_ADMIN_URL=http://caddy:2019
VOLUME ["/data"]
ENTRYPOINT ["/app/caddyui"]
