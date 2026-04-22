package dns

import (
	"fmt"

	"github.com/X4Applegate/caddyui/internal/cloudflare"
)

// cloudflareProvider adapts the existing internal/cloudflare client to the
// unified Provider interface. The underlying API client predates the dns
// package and is kept as-is; this file is a thin translation layer only.
type cloudflareProvider struct {
	client  *cloudflare.Client
	proxied bool // whether new records should route through CF's orange cloud
}

func init() {
	Register(Descriptor{
		ID:          Cloudflare,
		DisplayName: "Cloudflare",
		DocsAnchor:  "cloudflare",
		Credentials: []CredentialField{
			{
				Key:         "cf_api_token",
				Label:       "API Token",
				Help:        "Scoped token with Zone:DNS:Edit permission. Create one at dash.cloudflare.com → My Profile → API Tokens.",
				Placeholder: "paste token here",
				Secret:      true,
			},
		},
		Factory: func(creds map[string]string) Provider {
			token := creds["cf_api_token"]
			if token == "" {
				return nil
			}
			// The "proxied" toggle lives in a separate setting so the
			// Settings page can expose it as a checkbox independently of
			// the credential. Default false — users have to opt in to
			// the orange cloud.
			proxied := creds["cf_proxied"] == "1"
			return &cloudflareProvider{
				client:  cloudflare.New(token),
				proxied: proxied,
			}
		},
	})
}

func (c *cloudflareProvider) ID() string          { return Cloudflare }
func (c *cloudflareProvider) DisplayName() string { return "Cloudflare" }

// Ping issues a cheap zone list to validate the token. CF has no dedicated
// /user/tokens/verify for scoped tokens that's any cheaper, so we reuse
// ListZones and report how many zones the token can see.
func (c *cloudflareProvider) Ping() (string, error) {
	zones, err := c.client.ListZones()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (%d zones accessible)", len(zones)), nil
}

func (c *cloudflareProvider) ListZones() ([]Zone, error) {
	raw, err := c.client.ListZones()
	if err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(raw))
	for _, z := range raw {
		out = append(out, Zone{ID: z.ID, Name: z.Name})
	}
	return out, nil
}

// CreateRecord creates an A/AAAA/CNAME record. Cloudflare expects the FQDN
// as the record name (unlike Porkbun's subdomain-only convention), so we
// pass fqdn through unchanged. TTL=1 means "auto" to Cloudflare; we map
// the caller's 0 to 1 to keep that behaviour.
func (c *cloudflareProvider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	if ttl == 0 {
		ttl = 1 // CF auto
	}
	rec, err := c.client.CreateRecord(zone.ID, rtype, fqdn, content, c.proxied, ttl)
	if err != nil {
		return nil, err
	}
	return &Record{
		ID:      rec.ID,
		Name:    rec.Name,
		Type:    rec.Type,
		Content: rec.Content,
		TTL:     rec.TTL,
	}, nil
}

func (c *cloudflareProvider) DeleteRecord(zone Zone, recordID string) error {
	return c.client.DeleteRecord(zone.ID, recordID)
}
