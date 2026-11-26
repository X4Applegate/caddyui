// SPDX-License-Identifier: Apache-2.0

package models_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #164: operator-chosen log source IDs on fleet servers.

func TestValidateLogSourceIDFormat(t *testing.T) {
	valid := []string{
		"", "edge-home", "edge_home", "edge.home", "a", "x1", "1a", "10.0.0.5",
		"inventory-host.example.internal", "1-2", strings.Repeat("a", models.LogSourceIDMaxLen),
	}
	for _, v := range valid {
		if err := models.ValidateLogSourceID(v); err != nil {
			t.Errorf("ValidateLogSourceID(%q) = %v, want valid", v, err)
		}
	}
	invalid := []string{
		"0", "42", "0042", // all digits: indistinguishable from a numeric caddyui_server_id
		"-42", ".edge", "_edge", // must start with a letter or digit
		strings.Repeat("a", models.LogSourceIDMaxLen+1), // too long
		"edge home", "edge/home", "edge:1", "edge'home", "edge\"home", "edge;drop",
		"edge\nhome", "edge\x00", "édge", "edge‮", "Edge", // not normalized (upper-case)
	}
	for _, v := range invalid {
		if err := models.ValidateLogSourceID(v); !errors.Is(err, models.ErrLogSourceIDInvalid) {
			t.Errorf("ValidateLogSourceID(%q) = %v, want ErrLogSourceIDInvalid", v, err)
		}
	}
	if got := models.NormalizeLogSourceID("  Edge-HOME \t"); got != "edge-home" {
		t.Fatalf("NormalizeLogSourceID = %q, want edge-home", got)
	}
}

func openModelsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestCaddyServerLogSourceIDIsNormalizedUniqueAndOptional(t *testing.T) {
	db := openModelsTestDB(t)

	// Any number of servers may leave it unset (stored as NULL).
	for _, name := range []string{"a", "b", "c"} {
		if _, err := models.CreateCaddyServer(db, &models.CaddyServer{Name: name, AdminURL: "http://" + name + ":2019"}); err != nil {
			t.Fatalf("create %s without a log source ID: %v", name, err)
		}
	}
	var nulls int
	if err := db.QueryRow(`SELECT COUNT(*) FROM caddy_servers WHERE log_source_id IS NULL`).Scan(&nulls); err != nil {
		t.Fatal(err)
	}
	if nulls != 3 {
		t.Fatalf("servers stored with NULL log_source_id = %d, want 3", nulls)
	}

	edgeID, err := models.CreateCaddyServer(db, &models.CaddyServer{
		Name: "Edge", AdminURL: "http://edge:2019", Type: models.CaddyServerTypeExternal, LogSourceID: "  Edge-Home ",
	})
	if err != nil {
		t.Fatal(err)
	}
	edge, err := models.GetCaddyServer(db, edgeID)
	if err != nil {
		t.Fatal(err)
	}
	if edge.LogSourceID != "edge-home" {
		t.Fatalf("stored log source ID = %q, want normalized edge-home", edge.LogSourceID)
	}

	// Duplicate on create, including one that differs only in case.
	for _, dup := range []string{"edge-home", "EDGE-HOME"} {
		_, err := models.CreateCaddyServer(db, &models.CaddyServer{Name: "Dup", AdminURL: "http://dup:2019", LogSourceID: dup})
		if !errors.Is(err, models.ErrLogSourceIDTaken) {
			t.Fatalf("create with duplicate %q: err = %v, want ErrLogSourceIDTaken", dup, err)
		}
	}

	// Duplicate on update.
	other, err := models.GetCaddyServer(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	other.LogSourceID = "edge-home"
	if err := models.UpdateCaddyServer(db, other); !errors.Is(err, models.ErrLogSourceIDTaken) {
		t.Fatalf("update to a duplicate: err = %v, want ErrLogSourceIDTaken", err)
	}
	// Re-saving a server with its own ID is not a duplicate.
	edge.Name = "Edge renamed"
	if err := models.UpdateCaddyServer(db, edge); err != nil {
		t.Fatalf("re-save with own log source ID: %v", err)
	}

	// Invalid formats are rejected on both paths and nothing is written.
	for _, bad := range []string{"12345", strings.Repeat("x", 65), "edge home", "-edge"} {
		if _, err := models.CreateCaddyServer(db, &models.CaddyServer{Name: "Bad", AdminURL: "http://bad:2019", LogSourceID: bad}); !errors.Is(err, models.ErrLogSourceIDInvalid) {
			t.Fatalf("create with %q: err = %v, want ErrLogSourceIDInvalid", bad, err)
		}
		other.LogSourceID = bad
		if err := models.UpdateCaddyServer(db, other); !errors.Is(err, models.ErrLogSourceIDInvalid) {
			t.Fatalf("update to %q: err = %v, want ErrLogSourceIDInvalid", bad, err)
		}
	}
	if n, _ := models.CountCaddyServers(db); n != 4 {
		t.Fatalf("servers = %d after rejected saves, want 4", n)
	}

	// Clearing it goes back to NULL, freeing the identifier for another server.
	edge.LogSourceID = ""
	if err := models.UpdateCaddyServer(db, edge); err != nil {
		t.Fatal(err)
	}
	other.LogSourceID = "edge-home"
	if err := models.UpdateCaddyServer(db, other); err != nil {
		t.Fatalf("reuse a cleared log source ID: %v", err)
	}
}

// The unique index is the backstop when the friendly pre-check is bypassed
// (e.g. a concurrent save): the raw constraint must exist and its violation
// must map to ErrLogSourceIDTaken, not leak a driver error.
func TestCaddyServerLogSourceIDUniqueIndexBackstop(t *testing.T) {
	db := openModelsTestDB(t)
	if _, err := db.Exec(`INSERT INTO caddy_servers (name, admin_url, log_source_id) VALUES ('a', 'http://a', 'edge-home')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO caddy_servers (name, admin_url, log_source_id) VALUES ('b', 'http://b', 'edge-home')`); err == nil {
		t.Fatal("a second row with the same log_source_id was accepted; the unique index is missing")
	}
}

func TestResolveLogServerRules(t *testing.T) {
	db := openModelsTestDB(t)
	edgeID, err := models.CreateCaddyServer(db, &models.CaddyServer{Name: "Edge", AdminURL: "http://edge:2019", LogSourceID: "edge-home"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		source    string
		numeric   int64
		wantID    int64
		wantVia   bool
		wantName  string
		fromNilDB bool
	}{
		{name: "numeric only", numeric: 7, wantID: 7},
		{name: "source only", source: "edge-home", wantID: edgeID, wantVia: true, wantName: "Edge"},
		{name: "source is case-insensitive", source: " EDGE-Home ", wantID: edgeID, wantVia: true, wantName: "Edge"},
		{name: "both: custom wins", source: "edge-home", numeric: 7, wantID: edgeID, wantVia: true, wantName: "Edge"},
		{name: "unknown source only", source: "nope", wantID: 0},
		{name: "unknown source falls back to numeric", source: "nope", numeric: 7, wantID: 7},
		{name: "all-digit source is not a match", source: "1", numeric: 0, wantID: 0},
		{name: "oversized source", source: strings.Repeat("a", 10000), numeric: 3, wantID: 3},
		{name: "injection attempt", source: "edge-home' OR '1'='1", numeric: 0, wantID: 0},
		{name: "nil db", source: "edge-home", numeric: 5, wantID: 5, fromNilDB: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := db
			if tc.fromNilDB {
				conn = nil
			}
			id, name, via := models.ResolveLogServer(conn, tc.source, tc.numeric)
			if id != tc.wantID || via != tc.wantVia || name != tc.wantName {
				t.Fatalf("ResolveLogServer(%.20q, %d) = (%d, %q, %t), want (%d, %q, %t)", tc.source, tc.numeric, id, name, via, tc.wantID, tc.wantName, tc.wantVia)
			}
		})
	}
}
