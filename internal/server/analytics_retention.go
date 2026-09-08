package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.43.0: analytics retention.
//
// pruneAccessLoop existed since v2.7.0 but nothing ever started it, so
// access_events grew without bound: one production database reached 22 GB
// with 63 million rows older than the intended 30 days. The loop is now
// started with the other pollers, the retention is a setting, deletes run
// in batches so the write lock is never held for long, and Settings →
// Analytics shows what the table holds with Prune now and Reclaim space
// actions. Reclaiming (VACUUM) is what actually shrinks the SQLite file —
// deleting rows only frees pages inside it.

const (
	settingAnalyticsRetentionDays = "analytics_retention_days" // "" = default; "0" = keep forever
	settingAnalyticsPruneStatus   = "analytics_prune_status"
	settingAnalyticsVacuumStatus  = "analytics_vacuum_status"

	defaultAnalyticsRetentionDays = 30
	maxAnalyticsRetentionDays     = 3650
	accessPruneBatch              = 20000
	accessPruneEvery              = time.Hour
	accessPruneFirstAfter         = 60 * time.Second
)

// analyticsRetentionDays is the configured retention: default 30, 0 = keep
// forever, clamped to [1, 3650] otherwise.
func analyticsRetentionDays(s *Server) int {
	raw := strings.TrimSpace(mustGetSetting(s.DB, settingAnalyticsRetentionDays))
	if raw == "" {
		return defaultAnalyticsRetentionDays
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultAnalyticsRetentionDays
	}
	if n <= 0 {
		return 0
	}
	if n > maxAnalyticsRetentionDays {
		return maxAnalyticsRetentionDays
	}
	return n
}

type accessPruneStatus struct {
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Cutoff     *time.Time `json:"cutoff,omitempty"`
	Deleted    int64      `json:"deleted"`
	Remaining  int64      `json:"remaining"` // -1 = not counted
	Error      string     `json:"error,omitempty"`
	Manual     bool       `json:"manual,omitempty"`
}

type analyticsVacuumStatus struct {
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	BeforeBytes int64      `json:"before_bytes"`
	AfterBytes  int64      `json:"after_bytes"`
	Error       string     `json:"error,omitempty"`
}

func (s *Server) storeJSONSetting(key string, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	if err := models.SetSetting(s.DB, key, string(raw)); err != nil {
		log.Printf("analytics: store %s: %v", key, err)
	}
}

func (s *Server) lastPruneStatus() *accessPruneStatus {
	raw, err := models.GetSetting(s.DB, settingAnalyticsPruneStatus)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var st accessPruneStatus
	if json.Unmarshal([]byte(raw), &st) != nil {
		return nil
	}
	return &st
}

func (s *Server) lastVacuumStatus() *analyticsVacuumStatus {
	raw, err := models.GetSetting(s.DB, settingAnalyticsVacuumStatus)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var st analyticsVacuumStatus
	if json.Unmarshal([]byte(raw), &st) != nil {
		return nil
	}
	return &st
}

// runAccessPrune deletes events older than the retention, in batches, and
// records the outcome. It is serialized: a scheduled pass and a manual one
// never overlap. Returns the status it recorded.
func (s *Server) runAccessPrune(manual bool) accessPruneStatus {
	s.accessPruneMu.Lock()
	defer s.accessPruneMu.Unlock()
	st := accessPruneStatus{StartedAt: time.Now().UTC(), Remaining: -1, Manual: manual}
	days := analyticsRetentionDays(s)
	if days == 0 {
		done := time.Now().UTC()
		st.FinishedAt = &done
		s.storeJSONSetting(settingAnalyticsPruneStatus, st)
		return st
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UTC()
	st.Cutoff = &cutoff
	s.storeJSONSetting(settingAnalyticsPruneStatus, st) // visible as "running"
	mariadb := appdb.BackendOf(s.DB) == appdb.BackendMariaDB
	deleted, err := models.PruneAccessEventsBatched(s.DB, cutoff, accessPruneBatch, mariadb, nil)
	st.Deleted = deleted
	if err != nil {
		st.Error = err.Error()
		log.Printf("analytics: prune error after %d rows: %v", deleted, err)
	} else {
		if n, countErr := models.CountAccessEvents(s.DB); countErr == nil {
			st.Remaining = n
		}
		if deleted > 0 {
			log.Printf("analytics: pruned %d events older than %s (%d days); %d remain", deleted, cutoff.Format(time.RFC3339), days, st.Remaining)
		}
	}
	done := time.Now().UTC()
	st.FinishedAt = &done
	s.storeJSONSetting(settingAnalyticsPruneStatus, st)
	return st
}

// pruneAccessLoop runs the first prune shortly after start-up, then hourly.
// Started by New with the other pollers (it never was before v2.43.0).
func (s *Server) pruneAccessLoop() {
	timer := time.NewTimer(accessPruneFirstAfter)
	defer timer.Stop()
	for {
		<-timer.C
		s.runAccessPrune(false)
		timer.Reset(accessPruneEvery)
	}
}

// startAccessPrune runs a manual prune in the background unless one is
// already running. Returns false when it was.
func (s *Server) startAccessPrune() bool {
	if !s.accessPruneMu.TryLock() {
		return false
	}
	s.accessPruneMu.Unlock()
	go s.runAccessPrune(true)
	return true
}

// analyticsStorage is what Settings → Analytics shows about the table and
// the database file.
type analyticsStorage struct {
	SQLite          bool
	DBPath          string
	DBBytes         int64
	FreePageBytes   int64 // pages freed by deletes, not yet returned to the OS
	DiskFreeBytes   int64
	Oldest          time.Time
	Newest          time.Time
	RetentionDays   int
	LastPrune       *accessPruneStatus
	PruneRunning    bool
	LastVacuum      *analyticsVacuumStatus
	VacuumRunning   bool
	VacuumPossible  bool
	VacuumBlockedBy string
}

func (s *Server) analyticsStorageView() analyticsStorage {
	v := analyticsStorage{
		SQLite:        appdb.BackendOf(s.DB) != appdb.BackendMariaDB,
		DBPath:        s.DBPath,
		RetentionDays: analyticsRetentionDays(s),
		LastPrune:     s.lastPruneStatus(),
		LastVacuum:    s.lastVacuumStatus(),
	}
	if v.LastPrune != nil && v.LastPrune.FinishedAt == nil {
		v.PruneRunning = true
	}
	if v.LastVacuum != nil && v.LastVacuum.FinishedAt == nil {
		v.VacuumRunning = true
	}
	if oldest, newest, err := models.AccessEventBounds(s.DB); err == nil {
		v.Oldest, v.Newest = oldest, newest
	}
	if v.SQLite {
		if s.DBPath != "" {
			if fi, err := os.Stat(s.DBPath); err == nil {
				v.DBBytes = fi.Size()
			}
			v.DiskFreeBytes = diskFreeBytes(filepath.Dir(s.DBPath))
		}
		var pageSize, freelist int64
		if err := s.DB.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err == nil {
			if err := s.DB.QueryRow(`PRAGMA freelist_count`).Scan(&freelist); err == nil {
				v.FreePageBytes = pageSize * freelist
			}
		}
		switch {
		case s.DBPath == "":
			v.VacuumBlockedBy = "the database path is not known to this process"
		case v.VacuumRunning:
			v.VacuumBlockedBy = "a reclaim is already running"
		case v.DiskFreeBytes > 0 && v.DiskFreeBytes < v.DBBytes+v.DBBytes/10:
			v.VacuumBlockedBy = fmt.Sprintf("only %s free on the data volume; reclaiming needs room for a full copy (%s)", fmtBytesShort(v.DiskFreeBytes), fmtBytesShort(v.DBBytes))
		default:
			v.VacuumPossible = true
		}
	}
	return v
}

func diskFreeBytes(dir string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

func fmtBytesShort(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// startVacuum runs VACUUM in the background (SQLite only). Deleted rows only
// free pages inside the file; VACUUM rewrites it without them. It needs room
// for a full copy next to the database and blocks writers while it runs, so
// it is an explicit action with a status, never automatic.
func (s *Server) startVacuum() error {
	view := s.analyticsStorageView()
	if !view.SQLite {
		return fmt.Errorf("reclaiming space is a SQLite operation; on MariaDB run OPTIMIZE TABLE access_events")
	}
	if !view.VacuumPossible {
		return fmt.Errorf("cannot reclaim space now: %s", view.VacuumBlockedBy)
	}
	if !s.vacuumMu.TryLock() {
		return fmt.Errorf("a reclaim is already running")
	}
	st := analyticsVacuumStatus{StartedAt: time.Now().UTC(), BeforeBytes: view.DBBytes}
	s.storeJSONSetting(settingAnalyticsVacuumStatus, st)
	// SQLite writes VACUUM's working copy to a temp directory; the scratch
	// image has no /tmp, so point it at the data volume when nothing else
	// was set (the Dockerfile sets SQLITE_TMPDIR=/data too).
	if os.Getenv("SQLITE_TMPDIR") == "" {
		_ = os.Setenv("SQLITE_TMPDIR", filepath.Dir(s.DBPath))
	}
	go func() {
		defer s.vacuumMu.Unlock()
		_, err := s.DB.Exec("VACUUM")
		if err == nil {
			// In WAL mode the rewritten database reaches the main file, and
			// the file is truncated, only at a checkpoint — do it now so the
			// new size is real rather than pending.
			_, _ = s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		}
		done := time.Now().UTC()
		st.FinishedAt = &done
		if err != nil {
			st.Error = err.Error()
			log.Printf("analytics: reclaim space (VACUUM): %v", err)
		} else if fi, statErr := os.Stat(s.DBPath); statErr == nil {
			st.AfterBytes = fi.Size()
			log.Printf("analytics: reclaimed space: database %s → %s", fmtBytesShort(st.BeforeBytes), fmtBytesShort(st.AfterBytes))
		}
		s.storeJSONSetting(settingAnalyticsVacuumStatus, st)
		_ = models.LogActivity(s.DB, 0, "system", "analytics_vacuum", "database", fmt.Sprintf("%s → %s", fmtBytesShort(st.BeforeBytes), fmtBytesShort(st.AfterBytes)), err == nil)
	}()
	return nil
}

// pruneAnalyticsHandler: POST /settings/analytics/prune — Prune now.
func (s *Server) pruneAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.startAccessPrune() {
		log.Printf("analytics: manual prune requested while one is running")
	} else {
		_ = models.LogActivity(s.DB, 0, s.currentUserEmail(r), "analytics_prune", "access_events", fmt.Sprintf("manual prune, retention %d days", analyticsRetentionDays(s)), true)
	}
	http.Redirect(w, r, "/settings#analytics", http.StatusSeeOther)
}

// vacuumAnalyticsHandler: POST /settings/analytics/vacuum — Reclaim space.
func (s *Server) vacuumAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.startVacuum(); err != nil {
		_ = models.LogActivity(s.DB, 0, s.currentUserEmail(r), "analytics_vacuum", "database", err.Error(), false)
	}
	http.Redirect(w, r, "/settings#analytics", http.StatusSeeOther)
}

// parseAnalyticsRetentionDays validates the settings form value: blank keeps
// the current value, 0 = keep forever, else 1..3650.
func parseAnalyticsRetentionDays(raw string, current int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return current, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > maxAnalyticsRetentionDays {
		return 0, fmt.Errorf("analytics retention must be between 0 (keep forever) and %d days", maxAnalyticsRetentionDays)
	}
	return n, nil
}
