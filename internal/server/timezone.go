package server

import (
	"database/sql"
	"log"
	"sync/atomic"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

// settingTimezone is the settings-table key for the IANA timezone name the
// admin picked in Settings → Timezone. Empty string means "no DB override —
// fall back to the TZ env var (Go's time.Local), then UTC".
const settingTimezone = "timezone"

// activeLoc holds the timezone CaddyUI currently renders DB-stored timestamps
// in. Set once at startup from loadActiveLocation(), then updated whenever an
// admin saves a new timezone in Settings. Reads are hot (every page render,
// every template fmtDate call), so we use atomic.Pointer to stay lock-free.
var activeLoc atomic.Pointer[time.Location]

// loadActiveLocation resolves the timezone to use for rendering, in priority
// order:
//  1. DB value from the settings table (admin picked it in /settings)
//  2. TZ env var — Go's time.Local is already populated from this at startup
//  3. UTC — final fallback if nothing else is configured
//
// Called once from Server.New so the very first request renders in the right
// zone. Returns the resolved location so callers can log which zone won.
func loadActiveLocation(db *sql.DB) *time.Location {
	// DB wins over env. Empty string means "no override" — fall through.
	if name, _ := models.GetSetting(db, settingTimezone); name != "" {
		if loc, err := time.LoadLocation(name); err == nil {
			activeLoc.Store(loc)
			return loc
		}
		// Bad zone in DB — log and fall through so we don't crash on boot
		// just because someone edited the DB by hand.
		log.Printf("timezone: invalid DB value %q, falling back to TZ env/UTC", name)
	}
	// No DB override — Go's time.Local already reflects the TZ env var
	// (auto-read by the stdlib at init). If TZ was unset it's UTC.
	activeLoc.Store(time.Local)
	return time.Local
}

// setActiveLocation validates name as an IANA zone and swaps the active
// location atomically. Empty name resets to time.Local (TZ env var). Returns
// the error from time.LoadLocation so postSettings can surface it to the
// admin instead of silently saving garbage.
func setActiveLocation(name string) error {
	if name == "" {
		activeLoc.Store(time.Local)
		return nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return err
	}
	activeLoc.Store(loc)
	return nil
}

// activeLocation returns the timezone every template fmtDate/fmtDateTime call
// converts through. Safe to call from any goroutine. Falls back to UTC if
// somehow never initialised (shouldn't happen — New calls loadActiveLocation).
func activeLocation() *time.Location {
	if loc := activeLoc.Load(); loc != nil {
		return loc
	}
	return time.UTC
}

// commonTimezones is the short list rendered in the Settings → Timezone
// dropdown. Covers most CaddyUI users without forcing them to type an IANA
// name. Users who need a zone outside this list can pick "Other…" and type
// one; time.LoadLocation accepts anything tzdata knows about.
//
// Order: UTC first (safe default), then Americas → Europe → Asia → Oceania
// roughly west-to-east within each region so the list reads like a map.
var commonTimezones = []string{
	"UTC",
	"America/Los_Angeles",
	"America/Denver",
	"America/Chicago",
	"America/New_York",
	"America/Sao_Paulo",
	"Europe/London",
	"Europe/Paris",
	"Europe/Berlin",
	"Europe/Moscow",
	"Africa/Johannesburg",
	"Asia/Dubai",
	"Asia/Kolkata",
	"Asia/Singapore",
	"Asia/Shanghai",
	"Asia/Tokyo",
	"Australia/Sydney",
	"Pacific/Auckland",
}
