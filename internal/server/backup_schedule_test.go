// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
)

func TestLoadBackupScheduleConfig(t *testing.T) {
	vals := map[string]string{
		settingBackupScheduleEnabled:  "1",
		settingBackupScheduleDir:      " /backups ",
		settingBackupScheduleInterval: "24",
		settingBackupScheduleKeep:     "7",
	}
	cfg := loadBackupScheduleConfig(func(k string) string { return vals[k] })
	if !cfg.Enabled || cfg.Dir != "/backups" || cfg.IntervalHours != 24 || cfg.Keep != 7 {
		t.Fatalf("cfg = %+v", cfg)
	}
	// Disabled + junk numbers default to zero.
	cfg = loadBackupScheduleConfig(func(k string) string {
		if k == settingBackupScheduleInterval {
			return "nope"
		}
		return ""
	})
	if cfg.Enabled || cfg.Dir != "" || cfg.IntervalHours != 0 || cfg.Keep != 0 {
		t.Fatalf("empty cfg = %+v", cfg)
	}
}

func TestPruneBackupsKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-10 * time.Hour)
	// Create 5 backups with increasing mod times: bk0 oldest … bk4 newest.
	for i := 0; i < 5; i++ {
		p := filepath.Join(dir, backupFilePrefix+string(rune('a'+i))+backupFileSuffix)
		if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	// A non-backup file must never be touched.
	other := filepath.Join(dir, "keepme.txt")
	_ = os.WriteFile(other, []byte("x"), 0o640)

	pruneBackups(dir, 2)

	remaining := backupFiles(dir)
	if len(remaining) != 2 {
		t.Fatalf("kept %d backups, want 2", len(remaining))
	}
	// The two newest (e, d) must survive; ordered newest-first.
	if remaining[0].Name() != backupFilePrefix+"e"+backupFileSuffix || remaining[1].Name() != backupFilePrefix+"d"+backupFileSuffix {
		t.Fatalf("kept the wrong files: %s, %s", remaining[0].Name(), remaining[1].Name())
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("non-backup file was removed: %v", err)
	}

	// keep=0 keeps everything.
	pruneBackups(dir, 0)
	if len(backupFiles(dir)) != 2 {
		t.Fatalf("keep=0 should not prune")
	}
}

func TestRunScheduledBackupOnce(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "caddyui.db")
	conn, err := appdb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn, DBPath: dbPath}

	dir := filepath.Join(t.TempDir(), "backups")
	// Three backups, keep 2 → the oldest is pruned.
	var last string
	for i := 0; i < 3; i++ {
		p, err := s.runScheduledBackupOnce(dir, 2)
		if err != nil {
			t.Fatal(err)
		}
		last = p
		if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
			t.Fatalf("backup %q not written: %v", p, err)
		}
		time.Sleep(1100 * time.Millisecond) // distinct second-resolution timestamps
	}
	files := backupFiles(dir)
	if len(files) != 2 {
		t.Fatalf("kept %d backups, want 2", len(files))
	}
	if filepath.Base(last) != files[0].Name() {
		t.Fatalf("newest backup %q not first in %v", filepath.Base(last), files[0].Name())
	}
	// newestBackupModTime should be recent.
	if time.Since(newestBackupModTime(dir)) > time.Minute {
		t.Fatalf("newestBackupModTime looks stale")
	}
}
