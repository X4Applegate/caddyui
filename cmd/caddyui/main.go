package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/X4Applegate/caddyui/internal/analytics"
	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/caddylogs"
	"github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/server"
	"github.com/X4Applegate/caddyui/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate-db" {
		runDatabaseMigration(os.Args[2:])
		return
	}

	dbDriver := strings.ToLower(strings.TrimSpace(envOr("CADDYUI_DB_DRIVER", "sqlite")))
	dbPath := envOr("CADDYUI_DB", "/data/caddyui.db")
	dbDSN := os.Getenv("CADDYUI_DB_DSN")
	listen := envOr("CADDYUI_LISTEN", ":8080")
	caddyAdmin := envOr("CADDY_ADMIN_URL", "http://caddy:2019")
	caddyfilePath := envOr("CADDYFILE_PATH", "/etc/caddy/Caddyfile")
	// v2.7.0: visitor-analytics ingest listener. Caddy's `net` log writer
	// connects here over plain TCP and streams one JSON access-log entry
	// per line. Default :9019 inside the container; host-mode deployments
	// should set CADDYUI_INGEST_LISTEN=127.0.0.1:9019 so the LAN can't
	// inject fake events. Empty value disables the listener entirely.
	ingestListen := envOr("CADDYUI_INGEST_LISTEN", ":9019")
	// Optional HTTP Basic Auth for the bootstrap Caddy admin endpoint. Useful
	// when port 2019 is wrapped behind a reverse proxy that enforces basic auth
	// (a simpler alternative to WireGuard/Tailscale for remote admin). Empty
	// by default — the admin endpoint is assumed to be on an internal network.
	caddyAdminUser := os.Getenv("CADDY_ADMIN_USER")
	caddyAdminPass := os.Getenv("CADDY_ADMIN_PASS")

	// v2.12.53: friendly error if the data directory isn't writable.
	// Container bind mounts and native systemd installs can both hit
	// "unable to open database file (1)" when the DB parent directory is
	// owned by another user. Probe with a temp-file write BEFORE db.Open so
	// the error message is actionable.
	if dbDriver == string(db.BackendSQLite) {
		if err := probeDataDir(dbPath); err != nil {
			log.Fatalf(`data directory is not writable by the current user (uid %d): %v

Fix by:
  • chown the data directory for the user running CaddyUI:
        sudo chown -R <user>:<group> /path/to/caddyui_data
  • OR use a writable named Docker volume for container installs
  • OR run the container with a matching --user value for your bind mount`, os.Geteuid(), err)
		}
	}

	conn, err := db.OpenConfig(db.Config{
		Backend:    db.Backend(dbDriver),
		SQLitePath: dbPath,
		MariaDBDSN: dbDSN,
	})
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
	srv, err := server.New(conn, caddyClient, tplFS, staticFS, caddyfilePath, Version, dbPath)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	if err := srv.SeedBootstrapServer(caddyAdmin, caddyAdminUser, caddyAdminPass); err != nil {
		log.Fatalf("seed bootstrap server: %v", err)
	}
	pollerCtx, cancelPoller := context.WithCancel(context.Background())
	defer cancelPoller()
	srv.StartHealthPoller(pollerCtx)
	// App-response health poller (v2.4.4): HTTPS GET /<domain> every 60s,
	// cached and surfaced next to the existing TCP/port health dot. Catches
	// "port open but app wedged" (e.g. DB unreachable) that the TCP probe
	// can't see.
	srv.StartAppHealthPoller(pollerCtx)

	// Feature F: start cert-expiry webhook notifier.
	server.StartNotifier(conn, caddyClient)

	// v2.7.0: analytics ingest listener. Started unconditionally when
	// an address is configured — the separate "analytics enabled" toggle
	// (in Settings) controls whether *Caddy* is configured to ship logs,
	// not whether we listen for them. A listener with no connections is
	// a few KB of RAM and no CPU, so there's no reason to gate it.
	var ingest *analytics.Ingest
	if ingestListen != "" {
		logHub := caddylogs.New(conn)
		ingest = &analytics.Ingest{DB: conn, Addr: ingestListen, RuntimeFn: logHub.AcceptLine}
		if err := ingest.Start(pollerCtx); err != nil {
			log.Printf("analytics: failed to start ingest on %s: %v (analytics disabled)", ingestListen, err)
			ingest = nil
		} else {
			srv.SetAnalyticsIngest(ingest)
			srv.SetCaddyLogHub(logHub)
		}
	}
	// Refresh an enabled analytics logger on startup so upgrades can add
	// connection safeguards (for example soft_start) to Caddy's persisted
	// config without waiting for an administrator to save Settings again.
	// Failures are non-fatal because CaddyUI must still start when one fleet
	// server is temporarily unreachable.
	if err := srv.ReconcileAnalyticsAccessLogs(); err != nil {
		log.Printf("analytics: startup reconciliation: %v", err)
	}
	if err := srv.ResetRuntimeLogs(); err != nil {
		log.Printf("server logs: startup cleanup: %v", err)
	}
	if err := srv.ReconcileCertificateLogs(); err != nil {
		log.Printf("certificate monitoring: startup reconciliation: %v", err)
	}

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
		log.Printf("caddyui listening on %s (db_driver=%s caddy=%s caddyfile=%s)", listen, dbDriver, caddyAdmin, caddyfilePath)
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
	if err := srv.ResetRuntimeLogs(); err != nil {
		log.Printf("server logs: shutdown cleanup: %v", err)
	}
	if ingest != nil {
		ingest.Stop()
	}
}

func runDatabaseMigration(args []string) {
	flags := flag.NewFlagSet("migrate-db", flag.ExitOnError)
	fromSQLite := flags.String("from-sqlite", "", "path to the source caddyui.db")
	toMariaDB := flags.String("to-mariadb-dsn", os.Getenv("CADDYUI_DB_DSN"), "MariaDB DSN (or set CADDYUI_DB_DSN)")
	skipAnalytics := flags.Bool("skip-analytics", false, "skip access_events and access_daily")
	batchSize := flags.Int("batch-size", 1000, "rows per MariaDB transaction")
	_ = flags.Parse(args)

	if strings.TrimSpace(*fromSQLite) == "" || strings.TrimSpace(*toMariaDB) == "" {
		flags.Usage()
		log.Fatal("both --from-sqlite and a MariaDB DSN are required")
	}
	log.Printf("starting read-only SQLite to MariaDB migration (skip_analytics=%t)", *skipAnalytics)
	err := db.MigrateSQLiteToMariaDB(context.Background(), *fromSQLite, *toMariaDB, db.DataMigrationOptions{
		SkipAnalytics: *skipAnalytics,
		BatchSize:     *batchSize,
		Progress: func(table string, copied, total int64) {
			if copied == 0 || copied == total || copied%100000 == 0 {
				log.Printf("migration: %-20s %d/%d", table, copied, total)
			}
		},
	})
	if err != nil {
		log.Fatalf("database migration failed: %v", err)
	}
	log.Printf("database migration completed successfully")
}

// Version is set at build time via -ldflags "-X main.Version=vX.Y.Z".
var Version = "dev"

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// probeDataDir — v2.12.53: write-test the parent directory of the SQLite
// DB path so we can produce an actionable "your bind-mount isn't writable
// by uid 10001" error, instead of the cryptic "unable to open database
// file (1)" SQLite returns when the dir isn't writable. Returns nil if
// the directory is writable, error otherwise.
func probeDataDir(dbPath string) error {
	dir := dbPath
	if i := strings.LastIndex(dir, "/"); i >= 0 {
		dir = dir[:i]
	}
	if dir == "" {
		dir = "."
	}
	// Ensure the directory exists. This is a no-op if it does.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Try to create + remove a sentinel file. If we can't, the bind-mount
	// is owned by some other UID and the container's uid 10001 can't write.
	probe := dir + "/.caddyui-write-probe"
	f, err := os.Create(probe)
	if err != nil {
		return fmt.Errorf("write %s: %w", dir, err)
	}
	f.Close()
	_ = os.Remove(probe)
	return nil
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
