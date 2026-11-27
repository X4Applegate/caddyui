// SPDX-License-Identifier: Apache-2.0

package server

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #164: the server form's Log source ID field.

func TestServerFormSavesLogSourceIDAndRejectsDuplicatesAndBadFormats(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := newRenderingTestServer(t, conn)

	create := func(name, source string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.createServer(rec, postForm(t, "/servers", url.Values{
			"name": {name}, "admin_url": {"http://" + strings.ToLower(name) + ":2019"}, "type": {"external"}, "log_source_id": {source},
		}))
		return rec
	}

	if rec := create("Edge", " Edge-Home "); rec.Code != http.StatusSeeOther {
		t.Fatalf("create with a valid log source ID: %d %s", rec.Code, rec.Body.String())
	}
	edge, err := models.GetCaddyServer(conn, 1)
	if err != nil {
		t.Fatal(err)
	}
	if edge.LogSourceID != "edge-home" {
		t.Fatalf("saved log source ID = %q, want edge-home", edge.LogSourceID)
	}

	// Duplicate: the form is re-rendered with a friendly error naming the value
	// and keeps what was typed; nothing is created.
	rec := create("Second", "EDGE-HOME")
	body := html.UnescapeString(rec.Body.String())
	if rec.Code != http.StatusOK || !strings.Contains(body, `Log source ID "edge-home" is already used by another server.`) {
		t.Fatalf("duplicate create: code %d, body lacks the duplicate error:\n%s", rec.Code, excerpt(body, "Log source ID"))
	}
	if !strings.Contains(rec.Body.String(), `name="log_source_id" value="edge-home"`) {
		t.Fatalf("duplicate create did not keep the typed value in the field")
	}

	// Invalid formats.
	for _, bad := range []string{"12345", strings.Repeat("a", 65), "edge home", "-edge", "<script>"} {
		rec := create("Bad", bad)
		body := html.UnescapeString(rec.Body.String())
		if rec.Code != http.StatusOK || !strings.Contains(body, "Log source ID must be at most 64 characters") {
			t.Fatalf("create with %q: code %d, missing format error:\n%s", bad, rec.Code, excerpt(body, "Log source ID"))
		}
		if strings.Contains(rec.Body.String(), `value="<script>"`) {
			t.Fatalf("rejected value %q echoed unescaped", bad)
		}
	}
	if n, _ := models.CountCaddyServers(conn); n != 1 {
		t.Fatalf("servers = %d after rejected creates, want 1", n)
	}

	// Duplicate on edit.
	if rec := create("Lab", ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("create without a log source ID: %d", rec.Code)
	}
	labID := int64(2)
	rec = httptest.NewRecorder()
	s.updateServer(rec, withChiURLParam(postForm(t, "/servers/2", url.Values{
		"name": {"Lab"}, "admin_url": {"http://lab:2019"}, "type": {"external"}, "log_source_id": {"edge-home"},
	}), "id", strconv.FormatInt(labID, 10)))
	body = html.UnescapeString(rec.Body.String())
	if rec.Code != http.StatusOK || !strings.Contains(body, `Log source ID "edge-home" is already used by another server.`) {
		t.Fatalf("duplicate update: code %d:\n%s", rec.Code, excerpt(body, "Log source ID"))
	}
	if lab, _ := models.GetCaddyServer(conn, labID); lab.LogSourceID != "" {
		t.Fatalf("duplicate update was saved: %q", lab.LogSourceID)
	}

	// The fleet list shows the identifier.
	rec = httptest.NewRecorder()
	s.listServersPage(rec, httptest.NewRequest(http.MethodGet, "/servers", nil))
	if !strings.Contains(rec.Body.String(), `log source → <code class="font-mono">edge-home</code>`) {
		t.Fatalf("fleet list does not show the log source ID:\n%s", excerpt(rec.Body.String(), "edge-home"))
	}
}
