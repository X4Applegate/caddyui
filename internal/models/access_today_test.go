package models_test

import (
	"path/filepath"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func TestDomainRequestsTodayForDomainsScopesAndDeduplicates(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	now := time.Now().UTC().Unix()
	yesterday := time.Now().UTC().Add(-25 * time.Hour).Unix()
	rows := []struct {
		ts   int64
		host string
	}{
		{now, "one.example.com"},
		{now, "one.example.com"},
		{now, "two.example.com"},
		{now, "other.example.com"},
		{yesterday, "one.example.com"},
	}
	for _, row := range rows {
		if _, err := conn.Exec(
			`INSERT INTO access_events (ts, host) VALUES (?, ?)`,
			row.ts, row.host,
		); err != nil {
			t.Fatal(err)
		}
	}

	got, err := models.DomainRequestsTodayForDomains(conn, []string{
		" ONE.example.com ",
		"one.example.com",
		"two.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["one.example.com"] != 2 {
		t.Fatalf("one.example.com = %d, want 2", got["one.example.com"])
	}
	if got["two.example.com"] != 1 {
		t.Fatalf("two.example.com = %d, want 1", got["two.example.com"])
	}
	if _, ok := got["other.example.com"]; ok {
		t.Fatal("unrequested domain was returned")
	}
}

func TestDomainRequestsTodayForDomainsEmptyInput(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got, err := models.DomainRequestsTodayForDomains(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty map", got)
	}
}

func TestAggregateAccessDailyUsesPortableTimestampRanges(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	yesterday := time.Now().UTC().Truncate(24 * time.Hour).Add(-12 * time.Hour)
	for _, status := range []int{200, 204, 503} {
		if err := models.InsertAccessEvent(conn, models.AccessEvent{
			TS:       yesterday,
			Host:     "rollup.example.test",
			Method:   "GET",
			Status:   status,
			ClientIP: "192.0.2.1",
		}); err != nil {
			t.Fatal(err)
		}
	}

	written, err := models.AggregateAccessDaily(conn)
	if err != nil {
		t.Fatal(err)
	}
	if written != 1 {
		t.Fatalf("written = %d, want 1", written)
	}
	var views, s2xx, s5xx int
	if err := conn.QueryRow(`
		SELECT views, s2xx, s5xx
		  FROM access_daily
		 WHERE day = ? AND host = ?`,
		yesterday.Format("2006-01-02"), "rollup.example.test",
	).Scan(&views, &s2xx, &s5xx); err != nil {
		t.Fatal(err)
	}
	if views != 3 || s2xx != 2 || s5xx != 1 {
		t.Fatalf("rollup = views:%d 2xx:%d 5xx:%d", views, s2xx, s5xx)
	}

	written, err = models.AggregateAccessDaily(conn)
	if err != nil {
		t.Fatal(err)
	}
	if written != 0 {
		t.Fatalf("second written = %d, want 0", written)
	}
}
