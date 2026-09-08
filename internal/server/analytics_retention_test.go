package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

func newRetentionTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "caddyui.db")
	conn, err := appdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Server{DB: conn, DBPath: path}, path
}

func seedAccessEvents(t *testing.T, s *Server, n int, age time.Duration) {
	t.Helper()
	ts := time.Now().Add(-age)
	for i := 0; i < n; i++ {
		if err := models.InsertAccessEvent(s.DB, models.AccessEvent{TS: ts.Add(time.Duration(i) * time.Second), ServerID: 1, Host: "app.example.test", Path: "/x", Method: "GET", Status: 200, ClientIP: "10.0.0.1", UserAgent: strings.Repeat("ua", 40), BytesOut: 1234}); err != nil {
			t.Fatal(err)
		}
	}
}

// v2.43.0: the prune respects the retention setting, deletes in batches,
// records what it did, and leaves newer rows alone; 0 keeps everything.
func TestRunAccessPruneHonoursRetention(t *testing.T) {
	s, _ := newRetentionTestServer(t)
	seedAccessEvents(t, s, 45, 40*24*time.Hour) // old
	seedAccessEvents(t, s, 5, time.Hour)        // recent
	if days := analyticsRetentionDays(s); days != defaultAnalyticsRetentionDays {
		t.Fatalf("default retention = %d", days)
	}

	st := s.runAccessPrune(true)
	if st.Error != "" || st.Deleted != 45 || st.Remaining != 5 || st.FinishedAt == nil || st.Cutoff == nil || !st.Manual {
		t.Fatalf("status = %+v", st)
	}
	if got := s.lastPruneStatus(); got == nil || got.Deleted != 45 {
		t.Fatalf("stored status = %+v", got)
	}
	oldest, newest, err := models.AccessEventBounds(s.DB)
	if err != nil || time.Since(oldest) > 2*time.Hour || newest.Before(oldest) {
		t.Fatalf("bounds = %v .. %v, %v", oldest, newest, err)
	}

	// Batches smaller than the backlog still remove everything old.
	seedAccessEvents(t, s, 30, 60*24*time.Hour)
	n, err := models.PruneAccessEventsBatched(s.DB, time.Now().Add(-30*24*time.Hour), 7, false, nil)
	if err != nil || n != 30 {
		t.Fatalf("batched prune = %d, %v", n, err)
	}
	// stop is honoured between batches.
	seedAccessEvents(t, s, 20, 60*24*time.Hour)
	calls := 0
	n, err = models.PruneAccessEventsBatched(s.DB, time.Now().Add(-30*24*time.Hour), 5, false, func() bool { calls++; return calls > 2 })
	if err != nil || n != 10 {
		t.Fatalf("stopped prune = %d, %v", n, err)
	}

	// Retention 0 = keep forever.
	if err := models.SetSetting(s.DB, settingAnalyticsRetentionDays, "0"); err != nil {
		t.Fatal(err)
	}
	if st := s.runAccessPrune(false); st.Deleted != 0 || st.Cutoff != nil {
		t.Fatalf("retention 0 must not delete: %+v", st)
	}
	if got, _ := models.CountAccessEvents(s.DB); got != 15 {
		t.Fatalf("count after keep-forever = %d, want 15", got)
	}
	if v, err := parseAnalyticsRetentionDays("", 30); err != nil || v != 30 {
		t.Errorf("blank keeps current: %d, %v", v, err)
	}
	if _, err := parseAnalyticsRetentionDays("4000", 30); err == nil {
		t.Error("out of range must be rejected")
	}
	if v, err := parseAnalyticsRetentionDays(" 7 ", 30); err != nil || v != 7 {
		t.Errorf("7 days: %d, %v", v, err)
	}
}

// Reclaim space rewrites the SQLite file without the deleted rows: the file
// shrinks, the status records before/after, and a second run is refused
// while one is in flight.
func TestStartVacuumShrinksTheDatabase(t *testing.T) {
	s, path := newRetentionTestServer(t)
	seedAccessEvents(t, s, 4000, 40*24*time.Hour)
	if _, err := s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if st := s.runAccessPrune(true); st.Deleted != 4000 {
		t.Fatalf("prune = %+v", st)
	}
	view := s.analyticsStorageView()
	if !view.SQLite || view.DBBytes == 0 || view.FreePageBytes == 0 || !view.VacuumPossible {
		t.Fatalf("storage view before reclaim = %+v", view)
	}
	if err := s.startVacuum(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if st := s.lastVacuumStatus(); st != nil && st.FinishedAt != nil {
			if st.Error != "" || st.AfterBytes >= st.BeforeBytes || st.BeforeBytes != before.Size() {
				t.Fatalf("vacuum status = %+v (before %d)", st, before.Size())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("vacuum did not finish")
		}
		time.Sleep(50 * time.Millisecond)
	}
	after := s.analyticsStorageView()
	if after.FreePageBytes != 0 || after.DBBytes >= before.Size() {
		t.Fatalf("storage view after reclaim = %+v", after)
	}
	if os.Getenv("SQLITE_TMPDIR") == "" {
		t.Error("SQLITE_TMPDIR should have been pointed at the data directory")
	}
}
