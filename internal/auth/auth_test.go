package auth_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/auth"
	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// v2.30.0: this package had no tests of its own — it was only ever exercised
// indirectly through internal/server. It holds session issuance, expiry and
// cookie flags, so a regression here is an authentication bug.

func newDB(t *testing.T) (*sql.DB, int64) {
	t.Helper()
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	uid, err := models.CreateUser(conn, "user@example.com", hash, "User", models.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return conn, uid
}

func TestPasswordHashing(t *testing.T) {
	const pw = "correct-horse-battery-staple"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if hash == pw {
		t.Fatal("password stored in plaintext")
	}
	if !auth.CheckPassword(hash, pw) {
		t.Error("the correct password was rejected")
	}
	if auth.CheckPassword(hash, pw+"x") {
		t.Error("a wrong password was accepted")
	}
	if auth.CheckPassword(hash, "") {
		t.Error("an empty password was accepted")
	}
	if auth.CheckPassword("not-a-bcrypt-hash", pw) {
		t.Error("a malformed hash must not validate")
	}

	// bcrypt salts, so the same input must not produce the same digest twice.
	other, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if other == hash {
		t.Error("hashes are unsalted — identical passwords produced identical hashes")
	}
}

func TestSessionLifecycle(t *testing.T) {
	conn, uid := newDB(t)

	token, expires, err := auth.CreateSession(conn, uid)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("empty session token")
	}
	if len(token) < 32 {
		t.Errorf("session token is only %d chars — too short to resist guessing", len(token))
	}
	if !expires.After(time.Now()) {
		t.Error("session expires in the past")
	}

	got, err := auth.UserFromSession(conn, token)
	if err != nil || got == nil {
		t.Fatalf("valid session did not resolve: %v", err)
	}
	if got.ID != uid {
		t.Errorf("session resolved to user %d, want %d", got.ID, uid)
	}

	// Two sessions must never collide.
	token2, _, err := auth.CreateSession(conn, uid)
	if err != nil {
		t.Fatal(err)
	}
	if token2 == token {
		t.Error("two sessions produced the same token")
	}

	if err := auth.DeleteSession(conn, token); err != nil {
		t.Fatal(err)
	}
	if u, err := auth.UserFromSession(conn, token); err == nil && u != nil {
		t.Error("a deleted session still resolves to a user")
	}
	// Deleting one session must not affect another.
	if u, err := auth.UserFromSession(conn, token2); err != nil || u == nil {
		t.Error("deleting one session invalidated an unrelated one")
	}
}

func TestUnknownAndExpiredSessionsRejected(t *testing.T) {
	conn, uid := newDB(t)

	if u, err := auth.UserFromSession(conn, "definitely-not-a-real-token"); err == nil && u != nil {
		t.Error("an unknown token resolved to a user")
	}
	if u, err := auth.UserFromSession(conn, ""); err == nil && u != nil {
		t.Error("an empty token resolved to a user")
	}

	// Expire a real session by backdating its row. CreateSessionWithTTL
	// deliberately clamps a non-positive TTL to the default (see below), so it
	// cannot be used to mint an already-expired session.
	token, _, err := auth.CreateSession(conn, uid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`UPDATE sessions SET expires_at = ? WHERE token = ?`,
		time.Now().Add(-time.Hour), token); err != nil {
		t.Fatal(err)
	}
	if u, err := auth.UserFromSession(conn, token); err == nil && u != nil {
		t.Error("an expired session still authenticates")
	}

	// The expired row should also be cleaned up rather than lingering.
	var count int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = ?`, token).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Error("an expired session row was left behind after a failed lookup")
	}
}

// A non-positive TTL falls back to the default rather than minting a session
// that is already dead — otherwise a misconfigured session-duration setting
// would lock every user out instantly.
func TestCreateSessionWithTTLClampsNonPositive(t *testing.T) {
	conn, uid := newDB(t)

	for _, ttl := range []time.Duration{0, -time.Hour} {
		token, expires, err := auth.CreateSessionWithTTL(conn, uid, ttl)
		if err != nil {
			t.Fatal(err)
		}
		if !expires.After(time.Now()) {
			t.Errorf("ttl=%v produced an already-expired session", ttl)
		}
		if u, err := auth.UserFromSession(conn, token); err != nil || u == nil {
			t.Errorf("ttl=%v produced an unusable session: %v", ttl, err)
		}
	}

	// An explicit short TTL is honoured as given.
	_, expires, err := auth.CreateSessionWithTTL(conn, uid, 90*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(expires); d > 2*time.Hour {
		t.Errorf("explicit 90m TTL produced %v — the caller's value was ignored", d)
	}
}

// Cookie flags are the difference between a session that survives XSS and one
// that doesn't, so pin them explicitly.
func TestSessionCookieFlags(t *testing.T) {
	t.Run("plain http", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://caddyui.local/", nil)
		auth.SetSessionCookie(w, r, "tok", time.Now().Add(time.Hour))

		c := parseCookie(t, w, auth.SessionCookie)
		if !c.HttpOnly {
			t.Error("session cookie must be HttpOnly")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want Lax", c.SameSite)
		}
		if c.Secure {
			t.Error("Secure must not be set over plain HTTP, or the cookie is silently dropped")
		}
	})

	t.Run("forwarded https", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://caddyui.local/", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		auth.SetSessionCookie(w, r, "tok", time.Now().Add(time.Hour))

		c := parseCookie(t, w, auth.SessionCookie)
		if !c.Secure {
			t.Error("Secure must be set when the request arrived over HTTPS via a proxy")
		}
	})

	t.Run("clearing expires the cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://caddyui.local/", nil)
		auth.ClearSessionCookie(w, r)

		c := parseCookie(t, w, auth.SessionCookie)
		if c.Value != "" {
			t.Errorf("cleared cookie still carries a value %q", c.Value)
		}
		if c.MaxAge >= 0 {
			t.Errorf("MaxAge = %d, want negative so the browser drops it", c.MaxAge)
		}
		if !c.HttpOnly {
			t.Error("the cleared cookie should keep HttpOnly")
		}
	})
}

func parseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q was not set", name)
	return nil
}
