// Package caddylogs consumes Caddy's structured runtime logs. It keeps a
// bounded in-memory ring for the admin Server Logs page and persists only the
// latest certificate lifecycle projection; raw runtime logs never touch disk.
package caddylogs

import (
	"database/sql"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

const maxEntries = 1000

type Entry struct {
	ID         uint64         `json:"id"`
	TS         time.Time      `json:"ts"`
	ServerID   int64          `json:"server_id"`
	ServerName string         `json:"server_name"`
	Level      string         `json:"level"`
	Logger     string         `json:"logger"`
	Message    string         `json:"message"`
	Fields     map[string]any `json:"fields,omitempty"`
}

type CaptureState struct {
	ServerID   int64     `json:"server_id"`
	ServerName string    `json:"server_name"`
	Level      string    `json:"level"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Hub struct {
	DB *sql.DB

	mu      sync.RWMutex
	nextID  uint64
	entries []Entry
	active  map[int64]CaptureState

	persistMu sync.Mutex
}

func New(db *sql.DB) *Hub {
	return &Hub{DB: db, active: map[int64]CaptureState{}}
}

// AcceptLine consumes one NDJSON record. Access events are deliberately
// ignored here because the analytics ingest has its own persistence and UI.
func (h *Hub) AcceptLine(line []byte) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return
	}
	logger := strings.TrimSpace(stringField(raw["logger"]))
	if strings.HasPrefix(logger, "http.log.access") {
		return
	}
	message := strings.TrimSpace(stringField(raw["msg"]))
	if logger == "" && message == "" {
		return
	}
	entry := Entry{
		TS:         logTime(raw["ts"]),
		ServerID:   int64Field(raw["caddyui_server_id"]),
		ServerName: strings.TrimSpace(stringField(raw["caddyui_server_name"])),
		Level:      strings.ToUpper(strings.TrimSpace(stringField(raw["level"]))),
		Logger:     logger,
		Message:    message,
		Fields:     remainingFields(raw),
	}
	if entry.TS.IsZero() {
		entry.TS = time.Now().UTC()
	}
	if entry.Level == "" {
		entry.Level = "INFO"
	}

	h.mu.Lock()
	h.nextID++
	entry.ID = h.nextID
	h.entries = append(h.entries, entry)
	if len(h.entries) > maxEntries {
		copy(h.entries, h.entries[len(h.entries)-maxEntries:])
		h.entries = h.entries[:maxEntries]
	}
	h.mu.Unlock()

	states := certificateStates(entry, raw)
	if len(states) == 0 || h.DB == nil {
		return
	}
	h.persistMu.Lock()
	defer h.persistMu.Unlock()
	for _, state := range states {
		if err := models.UpsertCertificateLifecycle(h.DB, state); err != nil {
			log.Printf("certificate lifecycle: store %s on server %d: %v", state.Identifier, state.ServerID, err)
		}
	}
}

func (h *Hub) Since(cursor uint64, serverID int64, limit int) []Entry {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Entry, 0, limit)
	for _, entry := range h.entries {
		if entry.ID <= cursor || (serverID > 0 && entry.ServerID != serverID) {
			continue
		}
		entry.Fields = cloneFields(entry.Fields)
		out = append(out, entry)
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func (h *Hub) SetCapture(state CaptureState) {
	h.mu.Lock()
	h.active[state.ServerID] = state
	h.mu.Unlock()
}

func (h *Hub) ClearCapture(serverID int64) {
	h.mu.Lock()
	delete(h.active, serverID)
	h.mu.Unlock()
}

func (h *Hub) Captures() []CaptureState {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]CaptureState, 0, len(h.active))
	for _, state := range h.active {
		out = append(out, state)
	}
	return out
}

func (h *Hub) Capture(serverID int64) (CaptureState, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	state, ok := h.active[serverID]
	return state, ok
}

func remainingFields(raw map[string]any) map[string]any {
	fields := make(map[string]any, len(raw))
	for key, value := range raw {
		switch key {
		case "ts", "level", "logger", "msg", "caddyui_server_id", "caddyui_server_name":
			continue
		}
		fields[key] = value
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func cloneFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}

func logTime(value any) time.Time {
	switch v := value.(type) {
	case float64:
		seconds := int64(v)
		nanos := int64((v - float64(seconds)) * float64(time.Second))
		return time.Unix(seconds, nanos).UTC()
	case json.Number:
		if number, err := v.Float64(); err == nil {
			return logTime(number)
		}
	case string:
		if parsed, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func int64Field(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n
	default:
		return 0
	}
}

func stringField(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return ""
	}
}

func certificateStates(entry Entry, raw map[string]any) []models.CertificateLifecycleStatus {
	eventName := strings.ToLower(strings.TrimSpace(stringField(raw["name"])))
	isTLSEvent := strings.HasPrefix(entry.Logger, "tls")
	isCertificateEvent := entry.Logger == "events" && strings.HasPrefix(eventName, "cert_")
	if entry.ServerID <= 0 || (!isTLSEvent && !isCertificateEvent) {
		return nil
	}
	message := strings.ToLower(entry.Message)
	phase := ""
	switch {
	case eventName == "cert_revoked" || strings.Contains(message, "revoked"):
		phase = "revoked"
	case eventName == "cert_obtained" || eventName == "cert_cached" ||
		strings.Contains(message, "certificate obtained") ||
		strings.Contains(message, "certificate renewed") ||
		strings.Contains(message, "renewed certificate") ||
		strings.Contains(message, "cached managed certificate") ||
		strings.Contains(message, "loaded certificate") ||
		strings.Contains(message, "certificate loaded"):
		phase = "active"
	case strings.Contains(message, "will retry"):
		phase = "retrying"
	case eventName == "cert_failed" || entry.Level == "ERROR" || strings.Contains(message, "could not get certificate") ||
		strings.Contains(message, "failed") || strings.Contains(message, "giving up"):
		phase = "error"
	case strings.Contains(message, "renewing certificate") || strings.Contains(message, "started certificate renewal"):
		phase = "renewing"
	case strings.Contains(message, "obtaining certificate") || strings.Contains(message, "trying to solve challenge") ||
		strings.Contains(message, "starting certificate issuance"):
		phase = "obtaining"
	default:
		// Namespace-only classification is deliberately avoided. Follow-up
		// lines such as tls.obtain/releasing lock arrive after success and used
		// to regress an Issued certificate back to Obtaining.
		return nil
	}

	identifiers := certificateIdentifiers(raw)
	errText := truncate(stringField(raw["error"]), 2000)
	if len(identifiers) == 0 && errText != "" {
		if identifier := bracketIdentifier(errText); identifier != "" {
			identifiers = append(identifiers, identifier)
		}
	}
	if len(identifiers) == 0 {
		return nil
	}
	states := make([]models.CertificateLifecycleStatus, 0, len(identifiers))
	for _, identifier := range identifiers {
		identifier = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(identifier)), ".")
		if identifier == "" {
			continue
		}
		states = append(states, models.CertificateLifecycleStatus{
			ServerID: entry.ServerID, ServerName: entry.ServerName,
			Identifier: identifier, Phase: phase, Level: entry.Level,
			Message: truncate(entry.Message, 500), Error: errText, UpdatedAt: entry.TS,
		})
	}
	return states
}

func certificateIdentifiers(raw map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	collect := func(fields map[string]any) {
		add(stringField(fields["identifier"]))
		for _, key := range []string{"identifiers", "subjects", "sans", "names"} {
			if values, ok := fields[key].([]any); ok {
				for _, value := range values {
					add(stringField(value))
				}
			}
		}
	}
	collect(raw)
	if data, _ := raw["data"].(map[string]any); data != nil {
		collect(data)
	}
	return out
}

func bracketIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") {
		return ""
	}
	end := strings.IndexByte(value, ']')
	if end <= 1 {
		return ""
	}
	return value[1:end]
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
