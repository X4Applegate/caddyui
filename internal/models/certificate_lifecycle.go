package models

import (
	"database/sql"
	"strings"
	"time"
)

// CertificateLifecycleStatus is the latest ACME state observed in Caddy's
// structured TLS logs for one identifier on one fleet server.
type CertificateLifecycleStatus struct {
	ServerID   int64     `json:"server_id"`
	ServerName string    `json:"server_name"`
	Identifier string    `json:"identifier"`
	Phase      string    `json:"phase"`
	Level      string    `json:"level"`
	Message    string    `json:"message"`
	Error      string    `json:"error,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func normalizeCertificateIdentifier(identifier string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(identifier)), ".")
}

// UpsertCertificateLifecycle stores only the latest state. UPDATE-then-INSERT
// is portable across SQLite and MariaDB, unlike their different UPSERT
// syntaxes. Timestamp guards prevent delayed log lines from replacing newer
// state, and the final UPDATE handles an unlikely duplicate insert race.
func UpsertCertificateLifecycle(db *sql.DB, state CertificateLifecycleStatus) error {
	state.Identifier = normalizeCertificateIdentifier(state.Identifier)
	if state.ServerID <= 0 || state.Identifier == "" {
		return nil
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	args := []any{
		state.ServerName, state.Phase, state.Level, state.Message, state.Error,
		state.UpdatedAt.Unix(), state.ServerID, state.Identifier, state.UpdatedAt.Unix(),
	}
	result, err := db.Exec(`UPDATE certificate_lifecycle
		SET server_name=?, phase=?, level=?, message=?, error=?, updated_at=?
		WHERE server_id=? AND identifier=? AND updated_at <= ?`, args...)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n > 0 {
		return nil
	}
	var currentUpdated int64
	if err := db.QueryRow(`SELECT updated_at FROM certificate_lifecycle
		WHERE server_id=? AND identifier=?`, state.ServerID, state.Identifier).Scan(&currentUpdated); err == nil {
		return nil
	} else if err != sql.ErrNoRows {
		return err
	}
	_, insertErr := db.Exec(`INSERT INTO certificate_lifecycle
		(server_id, server_name, identifier, phase, level, message, error, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		state.ServerID, state.ServerName, state.Identifier, state.Phase,
		state.Level, state.Message, state.Error, state.UpdatedAt.Unix())
	if insertErr == nil {
		return nil
	}
	result, retryErr := db.Exec(`UPDATE certificate_lifecycle
		SET server_name=?, phase=?, level=?, message=?, error=?, updated_at=?
		WHERE server_id=? AND identifier=? AND updated_at <= ?`, args...)
	if retryErr != nil {
		return retryErr
	}
	if n, _ := result.RowsAffected(); n > 0 {
		return nil
	}
	if err := db.QueryRow(`SELECT updated_at FROM certificate_lifecycle
		WHERE server_id=? AND identifier=?`, state.ServerID, state.Identifier).Scan(&currentUpdated); err == nil {
		return nil
	}
	return insertErr
}

func ListCertificateLifecycle(db *sql.DB, serverID int64) ([]CertificateLifecycleStatus, error) {
	q := `SELECT server_id, server_name, identifier, phase, level, message, error, updated_at
		FROM certificate_lifecycle`
	var args []any
	if serverID > 0 {
		q += ` WHERE server_id=?`
		args = append(args, serverID)
	}
	q += ` ORDER BY updated_at DESC, identifier ASC`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertificateLifecycleStatus
	for rows.Next() {
		var state CertificateLifecycleStatus
		var updated int64
		if err := rows.Scan(&state.ServerID, &state.ServerName, &state.Identifier,
			&state.Phase, &state.Level, &state.Message, &state.Error, &updated); err != nil {
			return nil, err
		}
		state.UpdatedAt = time.Unix(updated, 0).UTC()
		out = append(out, state)
	}
	return out, rows.Err()
}
