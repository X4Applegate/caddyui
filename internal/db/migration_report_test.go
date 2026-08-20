package db

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

// v2.30.0: schema-upgrade steps used to be written as `_, _ = db.Exec(...)`,
// so a failed ALTER left the column missing and the app failed later at query
// time, far from the cause. Issue #30 was that shape. These cover the
// reporting that replaced it.

func TestMigrationStepReportsFailures(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var logBuf bytes.Buffer
	restore := captureLog(&logBuf)
	defer restore()

	before := migrationFailures
	migrationStep(conn, `ALTER TABLE table_that_does_not_exist ADD COLUMN nope TEXT`)

	if migrationFailures != before+1 {
		t.Errorf("migrationFailures = %d, want %d — a failed step must be counted", migrationFailures, before+1)
	}
	out := logBuf.String()
	if !strings.Contains(out, "MIGRATION FAILED") {
		t.Errorf("failure was not logged; got %q", out)
	}
	if !strings.Contains(out, "table_that_does_not_exist") {
		t.Errorf("log should name the offending statement; got %q", out)
	}
}

func TestMigrationStepSucceedsQuietly(t *testing.T) {
	conn, err := Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var logBuf bytes.Buffer
	restore := captureLog(&logBuf)
	defer restore()

	before := migrationFailures
	migrationStep(conn, `CREATE INDEX IF NOT EXISTS idx_test_quiet ON proxy_hosts(id)`)

	if migrationFailures != before {
		t.Errorf("a successful step incremented the failure counter")
	}
	if strings.Contains(logBuf.String(), "MIGRATION FAILED") {
		t.Errorf("a successful step logged a failure: %q", logBuf.String())
	}
}

// A clean upgrade of a fresh database must report zero failures. If this ever
// fails, some migration is broken for every new install.
func TestMigrateOnFreshDatabaseHasNoFailures(t *testing.T) {
	var logBuf bytes.Buffer
	restore := captureLog(&logBuf)
	defer restore()

	conn, err := Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if migrationFailures != 0 {
		t.Errorf("fresh database reported %d migration failure(s):\n%s", migrationFailures, logBuf.String())
	}
	if strings.Contains(logBuf.String(), "MIGRATION FAILED") {
		t.Errorf("fresh database logged a migration failure:\n%s", logBuf.String())
	}
}

// Re-opening an existing database must also be clean — this is the upgrade
// path every existing install takes on deploy.
func TestMigrateIsIdempotentAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "caddyui.db")
	conn, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	var logBuf bytes.Buffer
	restore := captureLog(&logBuf)
	defer restore()

	conn2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	if migrationFailures != 0 {
		t.Errorf("re-opening an existing database reported %d failure(s):\n%s", migrationFailures, logBuf.String())
	}
}

func TestSummarizeMigrationTrimsLongStatements(t *testing.T) {
	long := `CREATE INDEX IF NOT EXISTS idx_a_very_long_name ON some_table (col_one, col_two, col_three, col_four, col_five)`
	got := summarizeMigration(long)
	if strings.Contains(got, "\n") {
		t.Error("summary must be a single line")
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("long statement should be elided, got %q", got)
	}

	short := `ALTER TABLE proxy_hosts ADD COLUMN x TEXT`
	if got := summarizeMigration(short); got != short {
		t.Errorf("short statement should pass through unchanged, got %q", got)
	}
}

// captureLog redirects the standard logger into buf and returns a restore func.
func captureLog(buf *bytes.Buffer) func() {
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	return func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}
}
