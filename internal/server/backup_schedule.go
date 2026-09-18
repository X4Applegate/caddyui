package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Scheduled off-host database backups (issue #104). A background loop writes a
// consistent SQLite snapshot (VACUUM INTO) to an admin-configured directory on
// an interval, keeping the newest N. Point the directory at a mounted volume /
// network share / object-store gateway to get the copy off the host. MariaDB is
// skipped — those installs use their platform's own backup tooling.
const (
	settingBackupScheduleEnabled  = "backup_schedule_enabled"
	settingBackupScheduleDir      = "backup_schedule_dir"
	settingBackupScheduleInterval = "backup_schedule_interval_hours"
	settingBackupScheduleKeep     = "backup_schedule_keep"

	backupFilePrefix = "caddyui-backup-"
	backupFileSuffix = ".db"
)

type backupScheduleConfig struct {
	Enabled       bool
	Dir           string
	IntervalHours int
	Keep          int // 0 = keep all
}

func loadBackupScheduleConfig(getSetting func(string) string) backupScheduleConfig {
	interval, _ := strconv.Atoi(strings.TrimSpace(getSetting(settingBackupScheduleInterval)))
	keep, _ := strconv.Atoi(strings.TrimSpace(getSetting(settingBackupScheduleKeep)))
	return backupScheduleConfig{
		Enabled:       getSetting(settingBackupScheduleEnabled) == "1",
		Dir:           strings.TrimSpace(getSetting(settingBackupScheduleDir)),
		IntervalHours: interval,
		Keep:          keep,
	}
}

func (s *Server) backupScheduleConfig() backupScheduleConfig {
	return loadBackupScheduleConfig(func(k string) string { return mustGetSetting(s.DB, k) })
}

// StartBackupScheduler runs the scheduled-backup loop until ctx is cancelled.
// It wakes every 10 minutes and backs up when the newest existing backup is
// older than the configured interval, so interval/dir changes take effect
// without a restart and a restart doesn't force an immediate backup.
func (s *Server) StartBackupScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		// A short initial delay so startup isn't competing with the first backup.
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Minute):
		}
		for {
			s.maybeRunScheduledBackup()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// maybeRunScheduledBackup runs a backup if one is due per the configured interval.
func (s *Server) maybeRunScheduledBackup() {
	cfg := s.backupScheduleConfig()
	if !cfg.Enabled || cfg.Dir == "" || cfg.IntervalHours <= 0 {
		return
	}
	if appdb.BackendOf(s.DB) == appdb.BackendMariaDB {
		return
	}
	newest := newestBackupModTime(cfg.Dir)
	if !newest.IsZero() && time.Since(newest) < time.Duration(cfg.IntervalHours)*time.Hour {
		return
	}
	if _, err := s.runScheduledBackupOnce(cfg.Dir, cfg.Keep); err != nil {
		log.Printf("scheduled backup: %v", err)
		_ = models.LogActivity(s.DB, 0, "system", "backup_scheduled_failed", cfg.Dir, err.Error(), false)
	}
}

// runScheduledBackupOnce writes one VACUUM INTO snapshot into dir and prunes to
// the newest `keep` backups. Returns the written file path. SQLite only.
func (s *Server) runScheduledBackupOnce(dir string, keep int) (string, error) {
	if appdb.BackendOf(s.DB) == appdb.BackendMariaDB {
		return "", fmt.Errorf("scheduled backups are SQLite-only; MariaDB is managed by your database server")
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", fmt.Errorf("no backup directory configured")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}
	// Millisecond resolution so a scheduled run and a manual "Back up now" in
	// the same second can't collide on the same path (VACUUM INTO fails if the
	// target already exists).
	ts := time.Now().Format("20060102-150405.000")
	path := filepath.Join(dir, backupFilePrefix+ts+backupFileSuffix)
	if _, err := s.DB.Exec("VACUUM INTO ?", path); err != nil {
		return "", fmt.Errorf("vacuum into %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		log.Printf("scheduled backup: chmod %s: %v", path, err)
	}
	pruneBackups(dir, keep)
	_ = models.LogActivity(s.DB, 0, "system", "backup_scheduled", path, fmt.Sprintf("keep=%d", keep), true)
	return path, nil
}

// postBackupRun runs one backup immediately (the "Back up now" button). Admin
// only. Uses the *saved* backup directory/retention — not values from the
// request — so an untrusted request path never reaches the filesystem (Save
// the directory first, then Back up now).
func (s *Server) postBackupRun(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil || u.Role != models.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg := s.backupScheduleConfig()
	if cfg.Dir == "" {
		http.Redirect(w, r, "/settings/backup?backuperr="+url.QueryEscape("set a backup directory and Save first"), http.StatusSeeOther)
		return
	}
	path, err := s.runScheduledBackupOnce(cfg.Dir, cfg.Keep)
	if err != nil {
		http.Redirect(w, r, "/settings/backup?backuperr="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/backup?backupok="+url.QueryEscape(filepath.Base(path)), http.StatusSeeOther)
}

// backupFiles returns the backup files in dir, sorted newest-first by mod time.
func backupFiles(dir string) []os.DirEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, backupFilePrefix) && strings.HasSuffix(name, backupFileSuffix) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ii, _ := out[i].Info()
		ji, _ := out[j].Info()
		if ii == nil || ji == nil {
			return false
		}
		return ii.ModTime().After(ji.ModTime())
	})
	return out
}

// newestBackupModTime returns the mod time of the most recent backup in dir, or
// the zero time if there are none.
func newestBackupModTime(dir string) time.Time {
	files := backupFiles(dir)
	if len(files) == 0 {
		return time.Time{}
	}
	info, err := files[0].Info()
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// pruneBackups deletes all but the newest `keep` backups in dir. keep <= 0
// keeps everything.
func pruneBackups(dir string, keep int) {
	if keep <= 0 {
		return
	}
	files := backupFiles(dir)
	if keep >= len(files) {
		return
	}
	for _, e := range files[keep:] {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}
