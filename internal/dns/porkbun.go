package dns

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/porkbun"
)

// porkbunProvider adapts the existing internal/porkbun client to the
// unified Provider interface. Key translations:
//
//   - Zone.ID == Zone.Name == the bare domain ("example.com"). Porkbun has
//     no zone-ID concept, so we use the domain name in both slots and let
//     server.go persist it as dns_zone_id for lifecycle calls.
//   - CreateRecord takes an FQDN but Porkbun expects subdomain-only names
//     — we strip the base domain here via SubdomainOf. Apex ("@") becomes
//     an empty string for the API.
type porkbunProvider struct {
	client *porkbun.Client
}

func init() {
	Register(Descriptor{
		ID:          Porkbun,
		DisplayName: "Porkbun",
		DocsAnchor:  "porkbun",
		Credentials: []CredentialField{
			{
				Key:         "pb_api_key",
				Label:       "API Key",
				Help:        "Create a key pair at porkbun.com/account/api. Then toggle \"API Access\" ON for every domain you want CaddyUI to manage.",
				Placeholder: "pk1_...",
				Secret:      true,
			},
			{
				Key:         "pb_secret_key",
				Label:       "Secret Key",
				Help:        "Shown once when you create the API key pair — save it somewhere safe.",
				Placeholder: "sk1_...",
				Secret:      true,
			},
		},
		Factory: func(creds map[string]string) Provider {
			apiKey := creds["pb_api_key"]
			secret := creds["pb_secret_key"]
			if apiKey == "" || secret == "" {
				return nil
			}
			return &porkbunProvider{client: porkbun.New(apiKey, secret)}
		},
	})
}

func (p *porkbunProvider) ID() string          { return Porkbun }
func (p *porkbunProvider) DisplayName() string { return "Porkbun" }

// Ping hits /ping which returns the caller's public IP — useful as a
// "yep, credentials work" indicator on the Settings test button.
func (p *porkbunProvider) Ping() (string, error) {
	ip, err := p.client.Ping()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (caller IP: %s)", ip), nil
}

func (p *porkbunProvider) ListZones() ([]Zone, error) {
	raw, err := p.client.ListDomains()
	if err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(raw))
	for _, d := range raw {
		// Porkbun has no zone-ID, so ID == Name for us. server.go stores
		// the domain name in dns_zone_id, same shape as every other call.
		out = append(out, Zone{ID: d.Name, Name: d.Name})
	}
	return out, nil
}

func (p *porkbunProvider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	sub := SubdomainOf(fqdn, zone.Name)
	if sub == "@" {
		sub = "" // Porkbun uses empty string for apex
	}
	if ttl < 600 {
		ttl = 600 // PB's documented TTL floor — the API silently clamps otherwise
	}
	rec, err := p.client.CreateRecord(zone.ID, rtype, sub, content, ttl)
	if err != nil {
		return nil, err
	}
	return &Record{
		ID:      rec.ID,
		Name:    fqdn,
		Type:    rtype,
		Content: content,
		TTL:     ttl,
	}, nil
}

func (p *porkbunProvider) DeleteRecord(zone Zone, recordID string) error {
	// zone.ID is the domain name for Porkbun — the record ID is scoped to it.
	return p.client.DeleteRecord(zone.ID, recordID)
}

// FindRecord pulls every record on the domain and filters by name. Porkbun
// has no server-side name filter on /dns/retrieve, so we pay the scan — but
// a single domain rarely exceeds a few dozen records, so the extra bytes
// are cheap.
func (p *porkbunProvider) FindRecord(zone Zone, fqdn string) ([]Record, error) {
	raw, err := p.client.ListRecords(zone.ID)
	if err != nil {
		return nil, err
	}
	want := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	out := []Record{}
	for _, r := range raw {
		name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
		if name != want {
			continue
		}
		ttl, _ := strconv.Atoi(r.TTL)
		out = append(out, Record{
			ID:      r.ID,
			Name:    r.Name,
			Type:    r.Type,
			Content: r.Content,
			TTL:     ttl,
		})
	}
	return out, nil
}
