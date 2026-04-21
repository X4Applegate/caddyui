FROM golang:1.22-alpine AS build
WORKDIR /src

COPY . .
ARG VERSION=dev
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION}" -o /out/caddyui ./cmd/caddyui

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/caddyui /app/caddyui
RUN mkdir -p /data
EXPOSE 8080
ENV CADDYUI_DB=/data/caddyui.db \
    CADDYUI_LISTEN=:8080 \
    CADDY_ADMIN_URL=http://caddy:2019
VOLUME ["/data"]
ENTRYPOINT ["/app/caddyui"]
