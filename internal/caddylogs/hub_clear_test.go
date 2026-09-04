package caddylogs

import "testing"

// v2.35.5 (issue #60): Clear must drop only the selected server's entries,
// keep IDs monotonic so a reconnecting page's cursor stays valid, and leave
// the buffer usable afterwards. Lines use logger=admin so they stay clear of
// the certificate-projection path, which is not what's under test.
func TestHubClearDropsOnlyThatServer(t *testing.T) {
	h := New(nil)
	h.AcceptLine([]byte(`{"ts":1.0,"level":"info","logger":"admin","msg":"one","caddyui_server_id":1}`))
	h.AcceptLine([]byte(`{"ts":2.0,"level":"info","logger":"admin","msg":"two","caddyui_server_id":2}`))
	h.AcceptLine([]byte(`{"ts":3.0,"level":"info","logger":"admin","msg":"three","caddyui_server_id":1}`))
	if got := len(h.Since(0, 0, 0)); got != 3 {
		t.Fatalf("seeded %d entries, want 3", got)
	}

	if n := h.Clear(1); n != 2 {
		t.Errorf("Clear(1) removed %d entries, want 2", n)
	}
	rest := h.Since(0, 0, 0)
	if len(rest) != 1 || rest[0].ServerID != 2 || rest[0].Message != "two" {
		t.Fatalf("after Clear(1) the buffer holds %+v, want only server 2's entry", rest)
	}
	if got := h.Since(0, 1, 0); len(got) != 0 {
		t.Errorf("server 1 still has %d entries after Clear(1)", len(got))
	}

	// IDs keep counting up: a page that reconnects with its old cursor (3)
	// must neither replay purged rows nor miss the next new one.
	h.AcceptLine([]byte(`{"ts":4.0,"level":"info","logger":"admin","msg":"four","caddyui_server_id":1}`))
	fresh := h.Since(3, 1, 0)
	if len(fresh) != 1 || fresh[0].ID != 4 || fresh[0].Message != "four" {
		t.Fatalf("after Clear(1) + one new line, Since(3, server 1) = %+v; want just the new entry with ID 4", fresh)
	}

	if n := h.Clear(0); n != 2 {
		t.Errorf("Clear(0) removed %d entries, want 2 (everything left)", n)
	}
	if got := len(h.Since(0, 0, 0)); got != 0 {
		t.Errorf("Clear(0) left %d entries behind", got)
	}
	// And the buffer still accepts lines afterwards.
	h.AcceptLine([]byte(`{"ts":5.0,"level":"info","logger":"admin","msg":"five","caddyui_server_id":2}`))
	if got := h.Since(0, 2, 0); len(got) != 1 || got[0].ID != 5 {
		t.Errorf("buffer unusable after Clear(0): Since(0, server 2) = %+v", got)
	}
}
