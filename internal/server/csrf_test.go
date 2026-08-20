package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
)

// v2.29.0: CSRF protection.

func newCSRFTestServer(t *testing.T) *Server {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Server{DB: conn}
}

func TestCSRFTokenIsSessionBoundAndStable(t *testing.T) {
	s := newCSRFTestServer(t)

	a1 := s.csrfTokenFor("session-alpha")
	a2 := s.csrfTokenFor("session-alpha")
	b := s.csrfTokenFor("session-beta")

	if a1 == "" {
		t.Fatal("token for a real session must not be empty")
	}
	if a1 != a2 {
		t.Error("token must be stable for the same session")
	}
	if a1 == b {
		t.Error("different sessions must produce different tokens")
	}
	if s.csrfTokenFor("") != "" {
		t.Error("empty session must yield an empty token, not a constant")
	}
	if strings.Contains(a1, "session-alpha") {
		t.Error("token must not leak the session value it derives from")
	}
}

// The secret must survive a restart, otherwise every live session's token is
// invalidated on deploy and users get a 403 on their next save.
func TestCSRFSecretPersistsAcrossServerInstances(t *testing.T) {
	dir := t.TempDir()
	conn, err := appdb.Open(filepath.Join(dir, "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	first := (&Server{DB: conn}).csrfTokenFor("session-alpha")
	second := (&Server{DB: conn}).csrfTokenFor("session-alpha")
	if first != second {
		t.Errorf("token changed across Server instances (%s vs %s) — secret was not persisted", first, second)
	}
}

func TestCSRFTokenMatchesRejectsEmptyAndMismatch(t *testing.T) {
	cases := []struct {
		expected, got string
		want          bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"", "", false},
		{"abc", "", false},
		{"", "abc", false},
		{"abc", "ab", false},
	}
	for _, c := range cases {
		if got := csrfTokenMatches(c.expected, c.got); got != c.want {
			t.Errorf("csrfTokenMatches(%q,%q) = %v, want %v", c.expected, c.got, got, c.want)
		}
	}
}

func TestCSRFInjectForms(t *testing.T) {
	field := []byte(`<input type="hidden" name="csrf_token" value="TOK">`)

	tests := []struct {
		name  string
		page  string
		count int
	}{
		{"simple post form", `<form method="post" action="/x">a</form>`, 1},
		{"uppercase tag and method", `<FORM METHOD="POST" action="/x">a</FORM>`, 1},
		{"single quoted method", `<form method='post'>a</form>`, 1},
		{"get form untouched", `<form method="get" action="/s">a</form>`, 0},
		{"method-less form untouched", `<form action="/s">a</form>`, 0},
		{"two post forms", `<form method="post">a</form><form method="post">b</form>`, 2},
		{"mixed", `<form method="get">a</form><form method="post">b</form>`, 1},
		{
			// A '>' inside an attribute value must not be mistaken for the end
			// of the tag — otherwise the field lands in the middle of markup.
			"angle bracket inside attribute",
			`<form method="post" onsubmit="return a>b" class="x">a</form>`,
			1,
		},
		{
			"multi-line opening tag",
			"<form method=\"post\" action=\"/bulk\"\n      id=\"bulk-form\"\n      class=\"inline\">a</form>",
			1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(csrfInjectForms([]byte(tc.page), field))
			if n := strings.Count(got, `name="csrf_token"`); n != tc.count {
				t.Fatalf("injected %d times, want %d\ngot: %s", n, tc.count, got)
			}
			if tc.count > 0 {
				// The field must land immediately after the opening tag, i.e.
				// inside the form element where it will actually be submitted.
				if !strings.Contains(got, `>`+string(field)) {
					t.Errorf("field not placed directly after the opening tag: %s", got)
				}
			}
		})
	}
}

func TestCSRFInjectFormsNoTokenLeavesPageUntouched(t *testing.T) {
	page := `<form method="post">a</form>`
	if got := string(csrfInjectForms([]byte(page), nil)); got != page {
		t.Errorf("page altered with an empty field: %s", got)
	}
}

func TestCSRFSafeMethods(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		if !csrfSafeMethod(m) {
			t.Errorf("%s should be safe", m)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if csrfSafeMethod(m) {
			t.Errorf("%s must not be treated as safe", m)
		}
	}
}

// The middleware is the actual control. These exercise it end to end.
func TestRequireCSRFMiddleware(t *testing.T) {
	s := newCSRFTestServer(t)
	const session = "session-alpha"
	token := s.csrfTokenFor(session)

	reached := false
	h := s.requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	withSession := func(r *http.Request) *http.Request {
		r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: session})
		return r
	}
	formPost := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/proxy-hosts", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return withSession(r)
	}

	t.Run("GET passes without a token", func(t *testing.T) {
		reached = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withSession(httptest.NewRequest(http.MethodGet, "/", nil)))
		if !reached || w.Code != http.StatusOK {
			t.Fatalf("safe method blocked: code=%d reached=%v", w.Code, reached)
		}
	})

	t.Run("POST without a token is rejected", func(t *testing.T) {
		reached = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, formPost("domains=evil.example.com"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", w.Code)
		}
		if reached {
			t.Fatal("handler ran despite a missing token")
		}
	})

	t.Run("POST with a wrong token is rejected", func(t *testing.T) {
		reached = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, formPost("csrf_token=deadbeef&domains=evil.example.com"))
		if w.Code != http.StatusForbidden || reached {
			t.Fatalf("forged token accepted: code=%d reached=%v", w.Code, reached)
		}
	})

	t.Run("POST with another session's token is rejected", func(t *testing.T) {
		reached = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, formPost("csrf_token="+s.csrfTokenFor("session-beta")))
		if w.Code != http.StatusForbidden || reached {
			t.Fatalf("cross-session token accepted: code=%d reached=%v", w.Code, reached)
		}
	})

	t.Run("POST with the form field passes", func(t *testing.T) {
		reached = false
		w := httptest.NewRecorder()
		h.ServeHTTP(w, formPost("csrf_token="+token+"&domains=ok.example.com"))
		if w.Code != http.StatusOK || !reached {
			t.Fatalf("valid form token rejected: code=%d reached=%v", w.Code, reached)
		}
	})

	t.Run("POST with the header passes", func(t *testing.T) {
		reached = false
		r := withSession(httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(`{"a":1}`)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(csrfHeaderName, token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !reached {
			t.Fatalf("valid header token rejected: code=%d reached=%v", w.Code, reached)
		}
	})

	t.Run("no session cookie falls through to requireAuth", func(t *testing.T) {
		reached = false
		r := httptest.NewRequest(http.MethodPost, "/proxy-hosts", strings.NewReader(""))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK || !reached {
			t.Fatalf("anonymous request should be left to requireAuth: code=%d", w.Code)
		}
	})
}

// A JSON handler must still see its body after the middleware has looked for a
// token. Reading the form off a JSON request would drain the body and leave the
// handler with nothing.
func TestRequireCSRFLeavesJSONBodyIntact(t *testing.T) {
	s := newCSRFTestServer(t)
	const session = "session-alpha"

	var seen string
	h := s.requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64)
		n, _ := r.Body.Read(buf)
		seen = string(buf[:n])
	}))

	r := httptest.NewRequest(http.MethodPost, "/api/ai/chat", strings.NewReader(`{"msg":"hi"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(csrfHeaderName, s.csrfTokenFor(session))
	r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: session})

	h.ServeHTTP(httptest.NewRecorder(), r)
	if seen != `{"msg":"hi"}` {
		t.Errorf("handler saw body %q, want the original JSON", seen)
	}
}
