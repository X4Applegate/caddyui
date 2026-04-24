FROM golang:1.24-alpine AS build

# Install ca-certificates and tzdata in the build stage so they can be
# copied into the scratch final image. Create a dedicated non-root user.
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 10001 caddyui && \
    adduser  -S -G caddyui -u 10001 caddyui

WORKDIR /src
COPY . .
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

# World-writable /tmp (1777). v2.7.5.
COPY --from=build /out/tmp /tmp

USER 10001

EXPOSE 8080
ENV CADDYUI_DB=/data/caddyui.db \
    CADDYUI_LISTEN=:8080 \
    CADDY_ADMIN_URL=http://caddy:2019
VOLUME ["/data"]
ENTRYPOINT ["/app/caddyui"]
