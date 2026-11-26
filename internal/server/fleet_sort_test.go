// SPDX-License-Identifier: Apache-2.0

package server

import (
	"html"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #154: the Caddy Fleet environment inventory is sortable client-side.
// The script never parses display text ("4 minutes ago", "Online"), so every
// row must carry machine-readable sort keys and every sortable header must be
// a keyboard-reachable button. Sorting is opt-in: nothing starts sorted.

var fleetRowRe = regexp.MustCompile(`<tr data-fleet-row([^>]*)>`)
var fleetAttrRe = regexp.MustCompile(`data-sort-([a-z]+)="([^"]*)"`)

func TestFleetInventoryRowsCarrySortKeys(t *testing.T) {
	e := newSecEnv(t)

	contacted := time.Date(2026, 11, 20, 8, 30, 0, 0, time.UTC)
	older := time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)
	mk := func(name, url, typ, status string, at *time.Time) {
		t.Helper()
		id, err := models.CreateCaddyServer(e.db, &models.CaddyServer{Name: name, AdminURL: url, Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		if status != "" {
			if err := models.SetCaddyServerStatus(e.db, id, status, at); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("edge-online", "http://edge:2019", models.CaddyServerTypeManaged, models.CaddyServerStatusOnline, &contacted)
	mk("lab-offline", "http://lab:2019", models.CaddyServerTypeExternal, models.CaddyServerStatusOffline, &older)
	mk("fresh-never", "http://fresh:2019", models.CaddyServerTypeExternal, "", nil)

	rec := e.do(t, "admin", http.MethodGet, "/servers", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /servers = %d", rec.Code)
	}
	body := rec.Body.String()

	rows := map[string]map[string]string{}
	for _, m := range fleetRowRe.FindAllStringSubmatch(body, -1) {
		attrs := map[string]string{}
		for _, a := range fleetAttrRe.FindAllStringSubmatch(m[1], -1) {
			attrs[a[1]] = html.UnescapeString(a[2])
		}
		rows[attrs["name"]] = attrs
	}
	if len(rows) != 4 { // the fixture's "primary" plus the three above
		t.Fatalf("found %d sortable fleet rows, want 4: %v", len(rows), rows)
	}

	want := map[string]map[string]string{
		"edge-online": {"health": "2", "policy": "0", "endpoint": "http://edge:2019", "contact": strconv.FormatInt(contacted.Unix(), 10)},
		"lab-offline": {"health": "0", "policy": "1", "endpoint": "http://lab:2019", "contact": strconv.FormatInt(older.Unix(), 10)},
		// Never contacted: an empty timestamp (the script keeps these last in
		// both directions), not 0 — which would sort as the oldest contact.
		"fresh-never": {"health": "1", "policy": "1", "endpoint": "http://fresh:2019", "contact": ""},
	}
	for name, keys := range want {
		got, ok := rows[name]
		if !ok {
			t.Errorf("no sortable row for %q", name)
			continue
		}
		for k, v := range keys {
			if gv, present := got[k]; !present || gv != v {
				t.Errorf("%s: data-sort-%s = %q (present=%v), want %q", name, k, gv, present, v)
			}
		}
	}

	// Sortable headers are buttons (keyboard-reachable); Actions is not sortable;
	// no column claims to be sorted before the user picks one.
	for _, col := range []string{"name", "health", "endpoint", "policy", "contact"} {
		if !strings.Contains(body, `<button type="button" class="fleet-sort" data-fleet-sort="`+col+`">`) {
			t.Errorf("header %q is not a sort button", col)
		}
	}
	if strings.Contains(body, `data-fleet-sort="actions"`) {
		t.Error("the Actions column must not be sortable")
	}
	if strings.Contains(body, `aria-sort=`) {
		t.Error("a column is marked sorted on load; sorting must be opt-in")
	}
}
