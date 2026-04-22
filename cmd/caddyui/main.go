package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/server"
	"github.com/X4Applegate/caddyui/web"
)

func main() {
	dbPath := envOr("CADDYUI_DB", "/data/caddyui.db")
	listen := envOr("CADDYUI_LISTEN", ":8080")
	caddyAdmin := envOr("CADDY_ADMIN_URL", "http://caddy:2019")
	caddyfilePath := envOr("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
	// Optional HTTP Basic Auth for the bootstrap Caddy admin endpoint. Useful
	// when port 2019 is wrapped behind a reverse proxy that enforces basic auth
	// (a simpler alternative to WireGuard/Tailscale for remote admin). Empty
	// by default — the admin endpoint is assumed to be on an internal network.
	caddyAdminUser := os.Getenv("CADDY_ADMIN_USER")
	caddyAdminPass := os.Getenv("CADDY_ADMIN_PASS")

	conn, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer conn.Close()

	tplFS, err := fs.Sub(web.FS, "templates")
	if err != nil {
		log.Fatalf("templates fs: %v", err)
	}
	staticFS, err := fs.Sub(web.FS, "static")
	if err != nil {
		log.Fatalf("static fs: %v", err)
	}

	caddyClient := caddy.New(caddyAdmin, caddyAdminUser, caddyAdminPass)
	srv, err := server.New(conn, caddyClient, tplFS, staticFS, caddyfilePath, Version)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	if err := srv.SeedBootstrapServer(caddyAdmin, caddyAdminUser, caddyAdminPass); err != nil {
		log.Fatalf("seed bootstrap server: %v", err)
	}
	pollerCtx, cancelPoller := context.WithCancel(context.Background())
	defer cancelPoller()
	srv.StartHealthPoller(pollerCtx)

	// Feature F: start cert-expiry webhook notifier.
	server.StartNotifier(conn, caddyClient)

	// Opt-in startup sync. Default: no initial sync — pushing an empty config
	// would wipe Caddy's existing routes. Set CADDYUI_SYNC_ON_START=1 once all
	// live site blocks have equivalents in the CaddyUI DB; then on Caddy
	// restart, caddyui re-pushes the DB state so the Caddyfile only needs to
	// hold globals + snippets. Skipped when the DB has no entries — same
	// safety rule syncCaddy itself applies, prevents a first-boot wipe.
	if os.Getenv("CADDYUI_SYNC_ON_START") == "1" {
		go initialSync(srv, caddyClient)
	}

	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("caddyui listening on %s (db=%s caddy=%s caddyfile=%s)", listen, dbPath, caddyAdmin, caddyfilePath)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

// Version is set at build time via -ldflags "-X main.Version=vX.Y.Z".
var Version = "dev"

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// initialSync waits for the Caddy admin API to become reachable, then calls
// SyncCaddy once to push the DB state. syncCaddy itself refuses when the DB
// is empty, so this is safe on first boot. Retries the Caddy probe for up to
// ~60s to handle compose startup races where caddyui comes up before caddy.
func initialSync(srv *server.Server, cli *caddy.Client) {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, err := cli.FetchConfig(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err := srv.SyncCaddy(); err != nil {
		log.Printf("startup sync failed: %v", err)
		return
	}
	// syncCaddy prints "caddy sync skipped: …" on its own when it bails
	// (empty DB, external server). Don't print a second, contradictory
	// "pushed DB state" line after that.
}
