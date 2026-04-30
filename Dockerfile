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

# v2.12.39: vendor Inter variable font + htmx at build time so the
# runtime UI no longer fetches them from external CDNs. Removes three
# cold-load round-trips (fonts.googleapis.com, fonts.gstatic.com,
# unpkg.com).
#
# Tailwind self-host was attempted in v2.12.39 development but produced
# a 3.76 MB tailwind.css (Tailwind 3 auto-expands every color × shade ×
# opacity × hover/focus/dark variant for any opacity-modifier class
# found in templates — the default theme.colors set is too broad to
# build-time-compile cheaply). Reverted; cdn.tailwindcss.com stays for
# now. Proper self-host with a trimmed theme.colors palette is queued
# for v2.12.40.
#
# Both vendored files end up under web/static/ where Go's embed.FS picks
# them up at compile time, served by the existing /static/* handler with
# v2.12.38's Cache-Control: max-age=86400 wrapper.
RUN mkdir -p web/static/fonts && \
    curl -fsSL https://rsms.me/inter/font-files/InterVariable.woff2 \
      -o web/static/fonts/InterVariable.woff2 && \
    curl -fsSL https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js \
      -o web/static/htmx.min.js

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
