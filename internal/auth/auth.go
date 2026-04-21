package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookie  = "caddyui_session"
	SessionTTL     = 7 * 24 * time.Hour
	ContextUserKey ctxKey = "user"
)

type ctxKey string

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func CreateSession(db *sql.DB, userID int64) (string, time.Time, error) {
	tok, err := newToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().Add(SessionTTL)
	_, err = db.Exec(
		`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)`,
		tok, userID, expires,
	)
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, expires, nil
}

func DeleteSession(db *sql.DB, token string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func UserFromSession(db *sql.DB, token string) (*models.User, error) {
	if token == "" {
		return nil, errors.New("no session")
	}
	var userID int64
	var expires time.Time
	err := db.QueryRow(
		`SELECT user_id, expires_at FROM sessions WHERE token = ?`, token,
	).Scan(&userID, &expires)
	if err != nil {
		return nil, err
	}
	if time.Now().After(expires) {
		_ = DeleteSession(db, token)
		return nil, errors.New("expired")
	}
	return models.GetUserByID(db, userID)
}

// isSecure returns true when the request arrived over HTTPS (direct TLS or
// via a reverse-proxy that sets X-Forwarded-Proto).
func isSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}
