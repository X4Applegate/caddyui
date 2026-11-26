// SPDX-License-Identifier: Apache-2.0

package models

import (
	"database/sql"
	"errors"
	"strings"
)

// Issue #164: an optional, user-chosen "log source ID" on a fleet server.
//
// Forwarded log lines identify their node with caddyui_server_id — the
// caddy_servers row ID. That ID does not exist until CaddyUI has created the
// row, which inverts the dependency for a node provisioned by Ansible or
// similar: register first, read the generated ID back, then feed it into the
// inventory. A log source ID is chosen up front instead, configured on both
// sides, and carried on the wire as caddyui_source_id.
//
// Resolution rules (shared by the access-log ingest and the runtime/certificate
// log hub, see ResolveLogServer):
//
//   - A line carrying a caddyui_source_id that names a server is attributed to
//     that server, even when it also carries caddyui_server_id. The custom ID
//     wins because someone set it deliberately.
//   - Otherwise caddyui_server_id is used exactly as before, so existing
//     configurations keep working unchanged.
//   - A source ID that names no server is treated like a line with no source
//     ID at all: nothing is created for it.
//
// The resolved numeric server ID is what gets stored on ingested rows, so
// renaming a server's source ID later never detaches its history.

// LogSourceIDMaxLen bounds a log source ID. The value also arrives on
// untrusted log lines, so the bound applies there before any lookup.
const LogSourceIDMaxLen = 64

var (
	// ErrLogSourceIDInvalid is returned for a log source ID outside the
	// allowed format (see ValidateLogSourceID).
	ErrLogSourceIDInvalid = errors.New("invalid log source ID")
	// ErrLogSourceIDTaken is returned when another server already uses the
	// log source ID.
	ErrLogSourceIDTaken = errors.New("log source ID already in use")
)

// NormalizeLogSourceID trims and lower-cases a log source ID. Identifiers are
// case-insensitive (they are typically host or inventory names) and are stored
// lower-case so uniqueness means the same thing on SQLite (binary comparison)
// and MariaDB (case-insensitive collation).
func NormalizeLogSourceID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidateLogSourceID reports whether a normalized log source ID is
// acceptable. Empty means "not set" and is valid. Otherwise it must be 1–64
// characters from [a-z0-9._-], start with a letter or digit, and contain at
// least one character that is not a digit — an all-digit value would be
// indistinguishable from a numeric caddyui_server_id.
func ValidateLogSourceID(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > LogSourceIDMaxLen {
		return ErrLogSourceIDInvalid
	}
	nonDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z':
			nonDigit = true
		case (c == '.' || c == '_' || c == '-') && i > 0:
			nonDigit = true
		default:
			return ErrLogSourceIDInvalid
		}
	}
	if !nonDigit {
		return ErrLogSourceIDInvalid
	}
	return nil
}

// nullableLogSourceID maps "not set" to SQL NULL so the unique index on
// caddy_servers.log_source_id admits any number of servers without one.
func nullableLogSourceID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CheckLogSourceID normalizes c.LogSourceID in place and rejects an invalid
// value or one another server (any ID other than selfID) already uses. The
// unique index is the backstop for a concurrent save; isLogSourceIDConflict
// maps that error to the same ErrLogSourceIDTaken.
func CheckLogSourceID(db *sql.DB, c *CaddyServer, selfID int64) error {
	c.LogSourceID = NormalizeLogSourceID(c.LogSourceID)
	if err := ValidateLogSourceID(c.LogSourceID); err != nil {
		return err
	}
	if c.LogSourceID == "" {
		return nil
	}
	var other int64
	err := db.QueryRow(`SELECT id FROM caddy_servers WHERE log_source_id = ? AND id <> ?`, c.LogSourceID, selfID).Scan(&other)
	switch {
	case err == nil:
		return ErrLogSourceIDTaken
	case errors.Is(err, sql.ErrNoRows):
		return nil
	default:
		return err
	}
}

// isLogSourceIDConflict recognises a unique-index violation on log_source_id
// from either backend: SQLite reports "UNIQUE constraint failed:
// caddy_servers.log_source_id", MariaDB "Duplicate entry ... for key
// 'idx_caddy_servers_log_source_id'".
func isLogSourceIDConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "log_source_id") &&
		(strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "Duplicate entry"))
}

// ResolveLogServer attributes one forwarded log line to a fleet server from
// its raw caddyui_source_id and its already-parsed caddyui_server_id, following
// the rules at the top of this file. It returns the server ID to store (0 =
// unattributed); when the line was resolved through its source ID, viaSource
// is true and serverName is that server's current name.
//
// sourceID is untrusted: it is normalized, bounded and format-checked before
// it reaches the (parameterized) lookup, and a value that fails the check is
// simply not a match. db may be nil, in which case only numericID is used.
func ResolveLogServer(db *sql.DB, sourceID string, numericID int64) (serverID int64, serverName string, viaSource bool) {
	if db == nil || sourceID == "" || len(sourceID) > LogSourceIDMaxLen+16 {
		return numericID, "", false
	}
	sourceID = NormalizeLogSourceID(sourceID)
	if sourceID == "" || ValidateLogSourceID(sourceID) != nil {
		return numericID, "", false
	}
	var id int64
	var name string
	if err := db.QueryRow(`SELECT id, name FROM caddy_servers WHERE log_source_id = ?`, sourceID).Scan(&id, &name); err != nil {
		return numericID, "", false
	}
	return id, name, true
}
