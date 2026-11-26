// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #164: access logs attributed through an operator-chosen
// caddyui_source_id instead of (or alongside) the numeric caddyui_server_id.

func newSourceIngest(t *testing.T) (*Ingest, *sql.DB, int64) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// Row 1 exists so a numeric ID and the custom one point at different servers.
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{Name: "Primary", AdminURL: "http://caddy:2019"}); err != nil {
		t.Fatal(err)
	}
	edgeID, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Edge Home", AdminURL: "http://edge:2019", Type: models.CaddyServerTypeExternal, LogSourceID: "edge-home",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Ingest{DB: conn}, conn, edgeID
}

// accessLine builds one forwarded access event. extra is spliced in verbatim
// (already-encoded JSON members), so tests control the exact wire shape.
func accessLine(path, extra string) []byte {
	if extra != "" {
		extra = "," + extra
	}
	return []byte(fmt.Sprintf(`{"ts":1700000000,"logger":"http.log.access.caddyui_access","msg":"handled request","request":{"client_ip":"192.0.2.1","method":"GET","host":"example.test","uri":%q},"status":200%s}`, path, extra))
}

func eventServer(t *testing.T, conn *sql.DB, path string) (int64, string) {
	t.Helper()
	var id int64
	var name string
	if err := conn.QueryRow(`SELECT server_id, server_name FROM access_events WHERE path = ?`, path).Scan(&id, &name); err != nil {
		t.Fatalf("event %s: %v", path, err)
	}
	return id, name
}

func TestIngestAttributesAccessLogsBySourceID(t *testing.T) {
	ing, conn, edgeID := newSourceIngest(t)

	ing.acceptAccessLine(accessLine("/numeric", `"caddyui_server_id":1,"caddyui_server_name":"Primary"`))
	ing.acceptAccessLine(accessLine("/source", `"caddyui_source_id":"edge-home"`))
	ing.acceptAccessLine(accessLine("/source-case", `"caddyui_source_id":"EDGE-Home"`))
	ing.acceptAccessLine(accessLine("/both", `"caddyui_server_id":1,"caddyui_server_name":"Primary","caddyui_source_id":"edge-home"`))
	ing.acceptAccessLine(accessLine("/both-reversed", `"caddyui_source_id":"edge-home","caddyui_server_id":"1"`))
	ing.acceptAccessLine(accessLine("/unknown", `"caddyui_source_id":"not-registered"`))
	ing.acceptAccessLine(accessLine("/unknown-with-numeric", `"caddyui_source_id":"not-registered","caddyui_server_id":1`))
	ing.acceptAccessLine(accessLine("/unknown-numeric", `"caddyui_server_id":999`))

	cases := []struct {
		path     string
		wantID   int64
		wantName string
	}{
		{"/numeric", 1, "Primary"},              // unchanged behaviour
		{"/source", edgeID, "Edge Home"},        // name filled from the fleet entry
		{"/source-case", edgeID, "Edge Home"},   // identifiers are case-insensitive
		{"/both", edgeID, "Edge Home"},          // custom identifier wins
		{"/both-reversed", edgeID, "Edge Home"}, // ... regardless of field order
		{"/unknown", 0, ""},                     // nothing to attribute to
		{"/unknown-with-numeric", 1, ""},        // falls back to the numeric ID
		{"/unknown-numeric", 999, ""},           // today's behaviour, untouched
	}
	for _, tc := range cases {
		if id, name := eventServer(t, conn, tc.path); id != tc.wantID || name != tc.wantName {
			t.Errorf("%s attributed to (%d, %q), want (%d, %q)", tc.path, id, name, tc.wantID, tc.wantName)
		}
	}
	// Unknown identifiers never create a server.
	if n, _ := models.CountCaddyServers(conn); n != 2 {
		t.Fatalf("servers = %d, want 2 (an unknown source ID must not create anything)", n)
	}
	if got := ing.Stats().Events; got != uint64(len(cases)) {
		t.Fatalf("persisted events = %d, want %d", got, len(cases))
	}
}

func TestIngestKeepsHistoryAttributedAfterSourceIDRename(t *testing.T) {
	ing, conn, edgeID := newSourceIngest(t)
	ing.acceptAccessLine(accessLine("/before-rename", `"caddyui_source_id":"edge-home"`))

	edge, err := models.GetCaddyServer(conn, edgeID)
	if err != nil {
		t.Fatal(err)
	}
	edge.LogSourceID = "edge-house"
	if err := models.UpdateCaddyServer(conn, edge); err != nil {
		t.Fatal(err)
	}
	ing.acceptAccessLine(accessLine("/old-id-after-rename", `"caddyui_source_id":"edge-home"`))
	ing.acceptAccessLine(accessLine("/new-id-after-rename", `"caddyui_source_id":"edge-house"`))

	if id, _ := eventServer(t, conn, "/before-rename"); id != edgeID {
		t.Fatalf("row ingested before the rename is attributed to %d, want %d", id, edgeID)
	}
	if id, _ := eventServer(t, conn, "/old-id-after-rename"); id != 0 {
		t.Fatalf("old identifier after rename attributed to %d, want 0 (no longer registered)", id)
	}
	if id, _ := eventServer(t, conn, "/new-id-after-rename"); id != edgeID {
		t.Fatalf("new identifier attributed to %d, want %d", id, edgeID)
	}
	// The server-scoped analytics query still finds the pre-rename row.
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM access_events WHERE server_id = ?`, edgeID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("events for the edge server = %d, want 2", n)
	}
}

// The identifier comes from an untrusted log line: hostile or malformed
// values must neither break the line, nor match, nor touch the schema.
func TestIngestTreatsHostileSourceIDsAsData(t *testing.T) {
	ing, conn, _ := newSourceIngest(t)
	hostile := map[string]string{
		"/digits":    `"caddyui_source_id":"2"`, // all digits: never a source ID, even though server 2 exists
		"/number":    `"caddyui_source_id":2`,   // wrong JSON type must not reject the whole line
		"/object":    `"caddyui_source_id":{"x":1}`,
		"/sqli":      `"caddyui_source_id":"edge-home' OR '1'='1"`,
		"/drop":      `"caddyui_source_id":"x'); DROP TABLE caddy_servers; --"`,
		"/newline":   `"caddyui_source_id":"edge-home\nINJECTED log line"`,
		"/oversized": `"caddyui_source_id":"` + strings.Repeat("a", 100000) + `"`,
		"/null":      `"caddyui_source_id":null`,
	}
	for path, extra := range hostile {
		ing.acceptAccessLine(accessLine(path, extra))
	}
	for path := range hostile {
		if id, _ := eventServer(t, conn, path); id != 0 {
			t.Errorf("%s attributed to server %d, want 0", path, id)
		}
	}
	if n, err := models.CountCaddyServers(conn); err != nil || n != 2 {
		t.Fatalf("caddy_servers after hostile input: n=%d err=%v, want 2 rows intact", n, err)
	}
}
