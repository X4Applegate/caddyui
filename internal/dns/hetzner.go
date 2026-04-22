package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// hetznerProvider talks to the Hetzner DNS Console API.
//
// Auth header is "Auth-API-Token: <token>" (not Bearer). Zones have
// opaque IDs distinct from the domain name — so Zone.ID ≠ Zone.Name
// (mirroring Cloudflare's shape rather than Porkbun's). Record names
// use "@" for apex, subdomain-only for everything else.
//
// API reference: https://dns.hetzner.com/api-docs

const hetznerAPIBase = "https://dns.hetzner.com/api/v1"

type hetznerProvider struct {
	token      string
	httpClient *http.Client
}

func init() {
	Register(Descriptor{
		ID:          Hetzner,
		DisplayName: "Hetzner",
		DocsAnchor:  "hetzner",
		Credentials: []CredentialField{
			{
				Key:         "hetzner_api_token",
				Label:       "API Token",
				Help:        "Create a DNS API token at dns.hetzner.com/settings/api-token. (This is separate from the Hetzner Cloud API token.)",
				Placeholder: "paste token here",
				Secret:      true,
			},
		},
		Factory: func(creds map[string]string) Provider {
			token := creds["hetzner_api_token"]
			if token == "" {
				return nil
			}
			return &hetznerProvider{
				token:      token,
				httpClient: &http.Client{Timeout: 15 * time.Second},
			}
		},
	})
}

func (h *hetznerProvider) ID() string          { return Hetzner }
func (h *hetznerProvider) DisplayName() string { return "Hetzner" }

func (h *hetznerProvider) do(method, path string, body any, out any) error {
	var req *http.Request
	var err error
	if body != nil {
		b, _ := json.Marshal(body)
		req, err = http.NewRequest(method, hetznerAPIBase+path, bytes.NewReader(b))
	} else {
		req, err = http.NewRequest(method, hetznerAPIBase+path, nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Auth-API-Token", h.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// Hetzner returns errors as {"error":{"message":"...","code":N}}
		var e struct {
			Error struct {
				Message string `json:"message"`
				Code    int    `json:"code"`
			} `json:"error"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		msg := e.Error.Message
		if msg == "" {
			msg = e.Message
		}
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("hetzner: %s (%s)", msg, resp.Status)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (h *hetznerProvider) Ping() (string, error) {
	zones, err := h.ListZones()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (%d zones accessible)", len(zones)), nil
}

func (h *hetznerProvider) ListZones() ([]Zone, error) {
	var resp struct {
		Zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"zones"`
	}
	// per_page max is 100.
	if err := h.do("GET", "/zones?per_page=100", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(resp.Zones))
	for _, z := range resp.Zones {
		out = append(out, Zone{ID: z.ID, Name: z.Name})
	}
	return out, nil
}

func (h *hetznerProvider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	if ttl == 0 {
		ttl = 3600
	}
	name := SubdomainOf(fqdn, zone.Name)
	payload := map[string]any{
		"zone_id": zone.ID,
		"type":    rtype,
		"name":    name,
		"value":   content,
		"ttl":     ttl,
	}
	var resp struct {
		Record struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Name  string `json:"name"`
			Value string `json:"value"`
			TTL   int    `json:"ttl"`
		} `json:"record"`
	}
	if err := h.do("POST", "/records", payload, &resp); err != nil {
		return nil, err
	}
	return &Record{
		ID:      resp.Record.ID,
		Name:    fqdn,
		Type:    resp.Record.Type,
		Content: resp.Record.Value,
		TTL:     resp.Record.TTL,
	}, nil
}

func (h *hetznerProvider) DeleteRecord(zone Zone, recordID string) error {
	return h.do("DELETE", "/records/"+url.PathEscape(recordID), nil, nil)
}
