FROM golang:1.24-alpine AS build
WORKDIR /src

COPY . .
ARG VERSION=dev
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /out/caddyui ./cmd/caddyui

FROM alpine:3.22
# Upgrade all packages to pick up latest security patches, then add only
# what we need. ca-certificates is required for outbound HTTPS (Turnstile,
# webhook, Docker Hub update checks). tzdata is needed for time-zone support.
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata

# Run as a non-root user for better security posture.
RUN addgroup -S caddyui && adduser -S -G caddyui caddyui

WORKDIR /app
COPY --from=build /out/caddyui /app/caddyui

# Create the data directory and make it owned by the app user.
RUN mkdir -p /data && chown -R caddyui:caddyui /data /app

USER caddyui

EXPOSE 8080
ENV CADDYUI_DB=/data/caddyui.db \
    CADDYUI_LISTEN=:8080 \
    CADDY_ADMIN_URL=http://caddy:2019
VOLUME ["/data"]
ENTRYPOINT ["/app/caddyui"]
