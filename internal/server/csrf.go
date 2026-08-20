package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/X4Applegate/caddyui/internal/auth"
	"github.com/X4Applegate/caddyui/internal/models"
)

// CSRF protection for cookie-authenticated, state-changing requests.
//
// v2.29.0. Session cookies are SameSite=Lax, which already blocks the classic
// cross-site form POST in current browsers, but that is a single layer resting
// on a browser default. This adds a synchroniser token as defence in depth.
//
// The token is HMAC-SHA256(secret, sessionToken), so it needs no storage of
// its own and is automatically bound to one session: logging out or logging in
// again produces a new session token and therefore a new CSRF token. An
// attacker cannot compute it without reading the victim's session cookie,
// which is HttpOnly.
//
// Requests authenticated by bearer token are exempt. A browser never attaches
// an Authorization header to a cross-site request on its own, so those calls
// are not CSRF-reachable, and requiring a token would break API clients.

const (
	csrfFieldName  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"
	settingCSRFKey = "csrf_secret"
)

// csrfSecret returns the process-wide HMAC key, generating and persisting one
// on first use. Kept in the settings table rather than derived from something
// like the DB path so tokens stay valid across restarts — regenerating on boot
// would invalidate every live session's token and 403 users mid-flow.
func (s *Server) csrfSecret() []byte {
	s.csrfSecretOnce.Do(func() {
		if existing, err := models.GetSetting(s.DB, settingCSRFKey); err == nil {
			if raw, err := hex.DecodeString(strings.TrimSpace(existing)); err == nil && len(raw) == 32 {
				s.csrfSecretCache = raw
				return
			}
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			// crypto/rand failing is not recoverable in any useful way here.
			// Panicking beats silently falling back to a predictable key that
			// would make every token forgeable.
			panic("csrf: generate secret: " + err.Error())
		}
		if err := models.SetSetting(s.DB, settingCSRFKey, hex.EncodeToString(buf)); err != nil {
			// Persisting failed — keep the in-memory key so this process still
			// works. Tokens simply won't survive a restart.
			log.Printf("csrf: persist secret: %v", err)
		}
		s.csrfSecretCache = buf
	})
	return s.csrfSecretCache
}

// csrfTokenFor derives the token for a session token. Returns "" for an empty
// session so anonymous pages render no token rather than a constant one.
func (s *Server) csrfTokenFor(sessionToken string) string {
	if sessionToken == "" {
		return ""
	}
	mac := hmac.New(sha256.New, s.csrfSecret())
	mac.Write([]byte(sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// csrfTokenForRequest reads the session cookie and derives its token.
func (s *Server) csrfTokenForRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	cookie, err := r.Cookie(auth.SessionCookie)
	if err != nil || cookie.Value == "" {
		return ""
	}
	return s.csrfTokenFor(cookie.Value)
}

// csrfField renders the hidden input that templates embed in every POST form.
// Returns empty HTML when there is no session, so the login and setup pages
// (which have no session to protect) render unchanged.
func (s *Server) csrfField(r *http.Request) template.HTML {
	token := s.csrfTokenForRequest(r)
	if token == "" {
		return ""
	}
	// token is hex from HMAC output — no user input reaches it, so it cannot
	// break out of the attribute.
	return template.HTML(`<input type="hidden" name="` + csrfFieldName + `" value="` + token + `">`)
}

// csrfInjectForms inserts the hidden token input immediately after the opening
// tag of every POST form in a rendered page.
//
// Done here, on the rendered output, rather than by adding {{$.CSRFField}} to
// each of the ~75 forms in web/templates. One choke point means a form added
// later is protected automatically instead of silently 403-ing the first time
// someone submits it, and it avoids the template-scoping trap where `.` inside
// a {{range}} is not the root data.
//
// The scan is quote-aware so a '>' inside an attribute value (an inline
// onclick, say) doesn't terminate the tag early. Template actions are already
// evaluated by this point, so only quoting has to be handled.
func csrfInjectForms(page, field []byte) []byte {
	if len(field) == 0 || len(page) == 0 {
		return page
	}
	var out []byte
	pos := 0
	for {
		idx := indexFoldASCII(page[pos:], "<form")
		if idx < 0 {
			break
		}
		start := pos + idx
		end := csrfTagEnd(page, start)
		if end < 0 {
			break // malformed tag; leave the remainder untouched
		}
		tag := page[start:end]
		if !bytesContainsFold(tag, `method="post"`) && !bytesContainsFold(tag, "method='post'") {
			out = append(out, page[pos:end]...)
			pos = end
			continue
		}
		out = append(out, page[pos:end]...)
		out = append(out, field...)
		pos = end
	}
	if out == nil {
		return page
	}
	return append(out, page[pos:]...)
}

// csrfTagEnd returns the index just past the '>' closing the tag that starts at
// `start`, skipping quoted attribute values. Returns -1 if unterminated.
func csrfTagEnd(page []byte, start int) int {
	var quote byte
	for i := start; i < len(page); i++ {
		c := page[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '>':
			return i + 1
		}
	}
	return -1
}

// indexFoldASCII is a case-insensitive bytes.Index for an ASCII needle.
func indexFoldASCII(haystack []byte, needle string) int {
	n := len(needle)
	if n == 0 || len(haystack) < n {
		return -1
	}
	for i := 0; i+n <= len(haystack); i++ {
		if equalFoldASCII(haystack[i:i+n], needle) {
			return i
		}
	}
	return -1
}

func bytesContainsFold(haystack []byte, needle string) bool {
	return indexFoldASCII(haystack, needle) >= 0
}

func equalFoldASCII(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		x, y := b[i], s[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// csrfSafeMethod reports whether a method is defined as safe and so needs no
// token. HEAD and OPTIONS are included alongside GET per RFC 9110.
func csrfSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// requireCSRF rejects state-changing requests that do not carry a token
// matching the caller's session.
//
// Ordering matters: this must run *inside* requireAuth, because it relies on
// requireAuth having already established how the request is authenticated.
func (s *Server) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if csrfSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		// Bearer-token clients are not CSRF-reachable — see the package note.
		if currentAPITokenScope(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		expected := s.csrfTokenForRequest(r)
		if expected == "" {
			// No session cookie: nothing to protect, and requireAuth has
			// already decided whether this request may proceed at all.
			next.ServeHTTP(w, r)
			return
		}
		if !csrfTokenMatches(expected, csrfTokenFromRequest(r)) {
			log.Printf("csrf: rejected %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			http.Error(w, "CSRF token missing or invalid — reload the page and try again.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfTokenFromRequest pulls the token from the form field or the header. The
// header path is what the JSON/fetch callers use; see the fetch wrapper in
// web/static/app.js.
//
// Reading the form value would normally consume the body, so this only parses
// form-encoded content types. JSON handlers keep an intact body and are
// expected to send the header instead.
func csrfTokenFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get(csrfHeaderName)); v != "" {
		return v
	}
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data") {
		// ParseForm caches its result on the request, so the downstream
		// handler's own ParseForm call is a no-op rather than a second read of
		// an already-drained body.
		if err := r.ParseForm(); err == nil {
			return strings.TrimSpace(r.PostFormValue(csrfFieldName))
		}
	}
	return ""
}

// csrfTokenMatches compares in constant time.
func csrfTokenMatches(expected, got string) bool {
	if expected == "" || got == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(got))
}
