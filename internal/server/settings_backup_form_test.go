// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #166, server half. web.TestSettingsFormEnclosesEverySectionControl
// proves the Backup card's controls sit inside the settings form; these
// tests prove the round trip they feed actually works.
//
// Together they cover what a human verifies by hand: tick scheduled backups,
// set a directory/interval/keep count, save, reload, see the values persist,
// then press "Back up now" and get a backup file.
//
// Before the fix the browser sent none of this — the inputs belonged to no
// form at all — so the save was a no-op however correct the handler was.
// That is why the handler-level tests that already existed all passed while
// the feature was completely unreachable from the UI.

// TestBackupSectionSavesAndReloads posts exactly what the fixed form posts,
// then reads the settings back.
func TestBackupSectionSavesAndReloads(t *testing.T) {
	s, _ := newPreflightTestServer(t)
	dir := t.TempDir()

	// Seed another page's value to confirm the backup save stays scoped to
	// its own keys, like every other settings page.
	if err := models.SetSetting(s.DB, settingSiteTitle, "Keep me"); err != nil {
		t.Fatal(err)
	}

	rec := postSettingsPage(t, s, url.Values{
		"settings_section":               {"backup"},
		"backup_schedule_enabled":        {"on"},
		"backup_schedule_dir":            {dir},
		"backup_schedule_interval_hours": {"12"},
		"backup_schedule_keep":           {"5"},
	})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings/backup?saved=1" {
		t.Fatalf("backup save → %d %s", rec.Code, rec.Header().Get("Location"))
	}

	// Reload. Persisting these four values is the exact thing issue #166
	// reported as impossible.
	cfg := s.backupScheduleConfig()
	if !cfg.Enabled {
		t.Error("scheduled backups did not stay enabled after save + reload")
	}
	if cfg.Dir != dir {
		t.Errorf("backup dir = %q, want %q", cfg.Dir, dir)
	}
	if cfg.IntervalHours != 12 {
		t.Errorf("interval = %d, want 12", cfg.IntervalHours)
	}
	if cfg.Keep != 5 {
		t.Errorf("keep = %d, want 5", cfg.Keep)
	}

	// Scoped: the backup page does not touch another page's settings.
	if got := setting(t, s, settingSiteTitle); got != "Keep me" {
		t.Errorf("backup save changed the site title: %q", got)
	}

	// Unticking the checkbox clears the flag. A checkbox posts nothing when
	// unchecked, so this is the path that has to turn the feature back off.
	rec = postSettingsPage(t, s, url.Values{
		"settings_section":               {"backup"},
		"backup_schedule_dir":            {dir},
		"backup_schedule_interval_hours": {"12"},
		"backup_schedule_keep":           {"5"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("backup save (unticked) → %d", rec.Code)
	}
	if s.backupScheduleConfig().Enabled {
		t.Error("unticking scheduled backups did not disable them")
	}
}

// TestBackupRunUsesSavedDirectory covers the "Back up now" button, which is a
// submit inside the settings form with formaction="/settings/backup/run". It
// must still produce a backup once it is inside a real form.
func TestBackupRunUsesSavedDirectory(t *testing.T) {
	s, _ := newPreflightTestServer(t)
	dir := t.TempDir()

	// With no directory saved, the button explains itself rather than failing
	// silently or 500-ing.
	rec := postBackupRunPage(t, s)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("backup run with no dir → %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "backuperr=") {
		t.Errorf("expected a backuperr redirect when no directory is saved, got %q", loc)
	}

	// Save a directory through the settings form, exactly as the UI does.
	rec = postSettingsPage(t, s, url.Values{
		"settings_section":               {"backup"},
		"backup_schedule_enabled":        {"on"},
		"backup_schedule_dir":            {dir},
		"backup_schedule_interval_hours": {"24"},
		"backup_schedule_keep":           {"7"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("backup save → %d", rec.Code)
	}

	// Now "Back up now" writes a real file into that directory.
	rec = postBackupRunPage(t, s)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("backup run → %d %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "backupok=") {
		t.Fatalf("expected a backupok redirect, got %q", loc)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var backups []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), backupFilePrefix) && strings.HasSuffix(e.Name(), backupFileSuffix) {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) != 1 {
		t.Fatalf("expected exactly one backup file in %s, got %v", dir, entries)
	}
	info, err := os.Stat(filepath.Join(dir, backups[0]))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Errorf("backup %s is empty", backups[0])
	}
}

// postBackupRunPage drives postBackupRun the way the form's "Back up now"
// submit button does.
func postBackupRunPage(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/settings/backup/run", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextUserKey,
		&models.User{ID: 1, Email: "admin@example.com", IsAdmin: true, Role: models.RoleAdmin}))
	rec := httptest.NewRecorder()
	s.postBackupRun(rec, req)
	return rec
}
