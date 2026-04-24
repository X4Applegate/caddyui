// Package dns exposes a unified interface over the DNS providers CaddyUI
// knows how to drive (currently Cloudflare, Porkbun, Namecheap, GoDaddy,
// DigitalOcean, Hetzner).
//
// The goal is a single set of operations — list zones, create/delete a record
// pointing at the proxy-host's server IP, test credentials — that server.go
// can call without caring which provider is behind it. Each provider's
// quirks (Porkbun's subdomain-only record names, Namecheap's SOAP setHosts
// full-replace semantic, Cloudflare's orange-cloud flag) are hidden inside
// the per-provider adapter.
//
// A proxy_hosts row carries three unified columns:
//
//	dns_provider    — one of Cloudflare/Porkbun/Namecheap/GoDaddy/DigitalOcean/Hetzner IDs, or empty
//	dns_zone_id     — provider-native zone identifier (opaque for CF/Hetzner; bare domain for others)
//	dns_zone_name   — base domain name for display ("example.com")
//	dns_record_id   — provider-native record identifier, set after CreateRecord
//
// Callers always pass FQDNs to CreateRecord/UpdateRecord — the provider
// converts to whatever shape its API expects.
package dns

import (
	"fmt"
	"sort"
	"strings"
)

// Provider IDs. Keep lowercase and URL-safe — they're stored in the
// proxy_hosts.dns_provider column and used as path segments in
// /api/dns-zones?provider=<id>.
const (
	Cloudflare   = "cloudflare"
	Porkbun      = "porkbun"
	Namecheap    = "namecheap"
	GoDaddy      = "godaddy"
	DigitalOcean = "digitalocean"
	Hetzner      = "hetzner"
)

// Zone is a provider-agnostic view of a DNS zone on the user's account.
// JSON tags are lowercase because the proxy-host form's zone picker JS
// reads z.id / z.name — without tags Go would marshal "ID"/"Name" and
// the dropdown would show "undefined".
type Zone struct {
	ID   string `json:"id"`   // provider-native identifier (CF: opaque ID; PB/DO/GD/NC: domain name; Hetzner: opaque ID)
	Name string `json:"name"` // base domain, e.g. "example.com"
}

// Record is the minimal record descriptor CaddyUI tracks after creation.
// Only ID + Name are load-bearing — Name is returned to aid logging.
type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"` // FQDN ("app.example.com")
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// Provider is the interface every DNS integration implements. All methods
// are synchronous and should timeout after ~15s; callers wrap them in
// goroutines for the not-blocking-the-request-path lifecycle writes.
type Provider interface {
	// ID returns the stable lowercase identifier ("cloudflare", etc.).
	// Must match one of the package-level constants.
	ID() string

	// DisplayName returns a human-readable label for the Settings UI
	// ("Cloudflare", "DigitalOcean", etc.).
	DisplayName() string

	// Ping validates the credentials and returns a short status string
	// suitable for the "Test connection" button (e.g. the account email
	// or "ok"). Returns an error when credentials are invalid.
	Ping() (string, error)

	// ListZones returns every zone/domain the configured credentials can
	// manage. Used to populate the domain-picker dropdown when editing
	// a proxy host.
	ListZones() ([]Zone, error)

	// CreateRecord creates a single DNS record in the given zone.
	//   zone     — Zone{ID,Name} returned by ListZones (whichever the user picked)
	//   fqdn     — full hostname, e.g. "app.example.com"
	//   content  — usually the public IP of the Caddy server
	//   rtype    — "A" (IPv4), "AAAA" (IPv6), or "CNAME"
	//   ttl      — seconds; providers with a floor (Porkbun 600) clamp internally
	//
	// Returns the record ID assigned by the provider, which the caller
	// persists on the proxy_hosts row for later deletion/update.
	CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error)

	// DeleteRecord removes a record by ID. Called on proxy-host delete
	// and when the user disables DNS management on an existing host.
	DeleteRecord(zone Zone, recordID string) error

	// FindRecord returns every record in zone whose name matches fqdn. Used
	// by the proxy-host form to warn when a host is about to shadow an
	// existing DNS entry — the UI can then offer Cancel / Override instead
	// of silently appending (or, on providers with REPLACE semantics,
	// clobbering) what's already there.
	//
	// A zone with no matches is a legitimate result — implementations return
	// an empty slice and nil error. The returned records carry provider-native
	// IDs so callers can hand them straight back to DeleteRecord when the
	// user picks "override".
	FindRecord(zone Zone, fqdn string) ([]Record, error)
}

// Factory builds a Provider from a credentials map. Each provider declares
// the keys it expects (see Descriptor.Credentials below). A nil return
// signals "credentials incomplete" — callers should treat the provider as
// disabled rather than reporting an error.
type Factory func(creds map[string]string) Provider

// CredentialField describes one secret the provider needs.
type CredentialField struct {
	Key         string // settings-table key ("cf_api_token")
	Label       string // UI label ("API Token")
	Help        string // inline help text shown under the field
	Placeholder string // input placeholder
	Secret      bool   // render as password-style (masked, with paste-to-reveal)
}

// Descriptor is the registration record for a provider — metadata plus a
// factory. Used by the Settings page to render credential cards and by
// server.go to look up the active Provider for a proxy host.
type Descriptor struct {
	ID          string
	DisplayName string
	// DocsAnchor is the #id in /docs where the provider's tutorial lives
	// (e.g. "cloudflare", "porkbun"). Used to wire the "Setup guide" link
	// on the Settings credential card.
	DocsAnchor  string
	Credentials []CredentialField
	Factory     Factory
}

var registry = map[string]Descriptor{}

// Register adds a provider to the global registry. Intended to be called
// from each provider file's init() so the set is fixed at program start.
func Register(d Descriptor) {
	if d.ID == "" {
		panic("dns.Register: empty provider ID")
	}
	if _, dup := registry[d.ID]; dup {
		panic(fmt.Sprintf("dns.Register: duplicate provider %q", d.ID))
	}
	registry[d.ID] = d
}

// Descriptors returns all registered providers in a stable, Settings-friendly
// order (Cloudflare first since it's the most common, then alphabetical).
func Descriptors() []Descriptor {
	out := make([]Descriptor, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Keep Cloudflare first — it's the flagship integration and users
		// expect it at the top of the Settings page.
		if out[i].ID == Cloudflare && out[j].ID != Cloudflare {
			return true
		}
		if out[j].ID == Cloudflare && out[i].ID != Cloudflare {
			return false
		}
		return out[i].DisplayName < out[j].DisplayName
	})
	return out
}

// Lookup returns the descriptor for the given provider ID, or false if it
// isn't registered. IDs are lowercased before lookup.
func Lookup(id string) (Descriptor, bool) {
	d, ok := registry[strings.ToLower(strings.TrimSpace(id))]
	return d, ok
}

// Build instantiates the Provider for id using the given credentials.
// Returns nil if the provider isn't registered OR if the factory decides
// the credentials are incomplete. Callers should guard every DNS call
// behind a nil check on the result — "DNS not configured" is a normal
// state, not an error.
func Build(id string, creds map[string]string) Provider {
	d, ok := Lookup(id)
	if !ok {
		return nil
	}
	return d.Factory(creds)
}

// CredsComplete returns true when every declared credential for the
// provider has a non-empty value in creds. Used by the Settings page to
// render "Configured" vs "Not configured" badges without having to build
// a client and call Ping.
func CredsComplete(id string, creds map[string]string) bool {
	d, ok := Lookup(id)
	if !ok {
		return false
	}
	for _, f := range d.Credentials {
		if strings.TrimSpace(creds[f.Key]) == "" {
			return false
		}
	}
	return true
}

// SubdomainOf returns the subdomain portion of fqdn relative to baseDomain.
// Used by providers that want the record name in short form (Porkbun,
// Namecheap, GoDaddy, DigitalOcean — most non-Cloudflare providers).
//
//	SubdomainOf("example.com",     "example.com") → "@"   (apex)
//	SubdomainOf("www.example.com", "example.com") → "www"
//	SubdomainOf("a.b.example.com", "example.com") → "a.b"
//	SubdomainOf("other.com",       "example.com") → "other.com" (no match)
//
// The apex is returned as "@" because every provider except Porkbun uses
// that convention; Porkbun's adapter translates "@" back to empty.
func SubdomainOf(fqdn, baseDomain string) string {
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	baseDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(baseDomain)), ".")
	if fqdn == baseDomain {
		return "@"
	}
	suffix := "." + baseDomain
	if strings.HasSuffix(fqdn, suffix) {
		return fqdn[:len(fqdn)-len(suffix)]
	}
	return fqdn
}

// IsProxyConflictingType reports whether a record of type t would collide
// with the A/AAAA/CNAME record CaddyUI writes for a proxy host at the same
// name. MX / TXT / SRV / CAA / NS and friends cohabit happily — email,
// SPF/DKIM/DMARC, and cert-issuance records live at the same FQDN as the
// web endpoint and must never be touched by the Override path.
//
// Used by:
//   - /api/dns-zones/check-record  — to filter the warning banner so we
//     only alarm the user about records that would actually conflict.
//   - dnsOverrideExistingRecord    — to scope the delete sweep. An errant
//     delete of an MX or TXT record would silently break mail or SPF for
//     the user's whole domain.
func IsProxyConflictingType(t string) bool {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "A", "AAAA", "CNAME":
		return true
	}
	return false
}

// FirstDomain extracts the first comma-separated domain from a ProxyHost's
// Domains field. Used where a single representative hostname is needed
// (UI labels, deploying-page probes, etc.). v2.5.9 stopped treating "first
// domain" as the sole DNS-managed entry — the create/update/retarget paths
// now iterate ProxyHost.DomainList() so every hostname gets its own A
// record — so do NOT use FirstDomain for DNS lifecycle decisions.
func FirstDomain(domains string) string {
	for _, d := range strings.Split(domains, ",") {
		if d = strings.TrimSpace(d); d != "" {
			return d
		}
	}
	return ""
}

// MatchZone picks the best-matching zone for an FQDN. It returns the zone
// whose Name is the longest suffix of fqdn (so "a.b.example.com" matches
// "example.com", and an explicit "b.example.com" zone wins over
// "example.com" if both exist). Returns (Zone{}, false) if nothing matches.
//
// Used by server.go as a sanity check when the user picks a zone from the
// dropdown — and as a fallback for the IP-retarget job where only the FQDN
// is available but the zone list is regenerated from the provider.
func MatchZone(zones []Zone, fqdn string) (Zone, bool) {
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	var best Zone
	bestLen := 0
	for _, z := range zones {
		name := strings.TrimSuffix(strings.ToLower(z.Name), ".")
		if fqdn == name || strings.HasSuffix(fqdn, "."+name) {
			if len(name) > bestLen {
				best = z
				bestLen = len(name)
			}
		}
	}
	if bestLen == 0 {
		return Zone{}, false
	}
	return best, true
}
