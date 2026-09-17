package models_test

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.51.0 (issue #102): the rate-limit columns must survive a full
// create → read → update → read round trip. Guards against an accidental
// reordering of the three fields across the base-cols/scan/INSERT/UPDATE lists.
func TestProxyHostRateLimitFieldsRoundTrip(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	host := &models.ProxyHost{
		Domains:            "app.example.com",
		ForwardScheme:      "http",
		ForwardHost:        "app",
		ForwardPort:        8080,
		Enabled:            true,
		RateLimitEnabled:   true,
		RateLimitEvents:    100,
		RateLimitWindowSec: 60,
	}
	id, err := models.CreateProxyHost(conn, 1, 0, host)
	if err != nil {
		t.Fatal(err)
	}
	got, err := models.GetProxyHost(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RateLimitEnabled || got.RateLimitEvents != 100 || got.RateLimitWindowSec != 60 {
		t.Fatalf("after create: enabled=%v events=%d window=%d", got.RateLimitEnabled, got.RateLimitEvents, got.RateLimitWindowSec)
	}

	got.RateLimitEnabled = false
	got.RateLimitEvents = 5
	got.RateLimitWindowSec = 10
	if err := models.UpdateProxyHost(conn, got); err != nil {
		t.Fatal(err)
	}
	got2, err := models.GetProxyHost(conn, id)
	if err != nil {
		t.Fatal(err)
	}
	if got2.RateLimitEnabled || got2.RateLimitEvents != 5 || got2.RateLimitWindowSec != 10 {
		t.Fatalf("after update: enabled=%v events=%d window=%d", got2.RateLimitEnabled, got2.RateLimitEvents, got2.RateLimitWindowSec)
	}
}
