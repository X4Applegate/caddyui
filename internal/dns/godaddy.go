package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// godaddyProvider talks to the GoDaddy Domains API.
//
// Gotchas worth documenting in the Settings tutorial:
//
//   - As of 2024-04, GoDaddy restricts API access to accounts holding
//     10+ domains OR a Discount Domain Club membership. Keys issued on
//     lower-tier accounts return 403 ACCESS_DENIED. This isn't a bug on
//     our side — we surface the error verbatim so the user can see it.
//   - There is no discrete "record ID" in the API. Records are addressed
//     by (type, name) and updates to a subdomain REPLACE all records of
//     that type+name combination. We store "type|name" as our record ID
//     so DeleteRecord can round-trip it back.
//   - Auth header is "Authorization: sso-key <key>:<secret>".
//
// API reference: https://developer.godaddy.com/doc/endpoint/domains

const godaddyAPIBase = "https://api.godaddy.com/v1"

type godaddyProvider struct {
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

func init() {
	Register(Descriptor{
		ID:          GoDaddy,
		DisplayName: "GoDaddy",
		DocsAnchor:  "godaddy",
		Credentials: []CredentialField{
			{
				Key:         "gd_api_key",
				Label:       "API Key",
				Help:        "Production key from developer.godaddy.com/keys. Note: GoDaddy limits API access to accounts with 10+ domains or Discount Domain Club.",
				Placeholder: "paste key here",
				Secret:      true,
			},
			{
				Key:         "gd_api_secret",
				Label:       "API Secret",
				Help:        "Paired secret shown alongside the API key.",
				Placeholder: "paste secret here",
				Secret:      true,
			},
		},
		Factory: func(creds map[string]string) Provider {
			key := creds["gd_api_key"]
			secret := creds["gd_api_secret"]
			if key == "" || secret == "" {
				return nil
			}
			return &godaddyProvider{
				apiKey:     key,
				apiSecret:  secret,
				httpClient: &http.Client{Timeout: 15 * time.Second},
			}
		},
	})
}

func (g *godaddyProvider) ID() string          { return GoDaddy }
func (g *godaddyProvider) DisplayName() string { return "GoDaddy" }

func (g *godaddyProvider) do(method, path string, body any, out any) error {
	var req *http.Request
	var err error
	if body != nil {
		b, _ := json.Marshal(body)
		req, err = http.NewRequest(method, godaddyAPIBase+path, bytes.NewReader(b))
	} else {
		req, err = http.NewRequest(method, godaddyAPIBase+path, nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "sso-key "+g.apiKey+":"+g.apiSecret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		msg := e.Message
		if e.Code != "" {
			msg = fmt.Sprintf("%s (%s)", e.Message, e.Code)
		}
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("godaddy: %s", msg)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (g *godaddyProvider) Ping() (string, error) {
	zones, err := g.ListZones()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (%d domains accessible)", len(zones)), nil
}

// ListZones returns domains in "ACTIVE" status. We filter client-side
// because /v1/domains returns pending/expired/transferred states too
// and the picker should only show domains DNS calls will succeed on.
func (g *godaddyProvider) ListZones() ([]Zone, error) {
	var raw []struct {
		Domain string `json:"domain"`
		Status string `json:"status"`
	}
	if err := g.do("GET", "/domains?statuses=ACTIVE&limit=1000", nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(raw))
	for _, r := range raw {
		out = append(out, Zone{ID: r.Domain, Name: r.Domain})
	}
	return out, nil
}

// CreateRecord uses PATCH /v1/domains/{domain}/records, which *appends*
// records (PUT to the same path replaces all records — a footgun we
// deliberately avoid). GoDaddy returns 200 with no body on success, so
// we synthesise the "record ID" as "TYPE|NAME" — which is what DeleteRecord
// needs to target the right entry via DELETE /records/{type}/{name}.
func (g *godaddyProvider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	if ttl < 600 {
		ttl = 600 // GoDaddy's documented minimum
	}
	name := SubdomainOf(fqdn, zone.Name)
	rtype = strings.ToUpper(rtype)
	payload := []map[string]any{{
		"type": rtype,
		"name": name,
		"data": content,
		"ttl":  ttl,
	}}
	if err := g.do("PATCH", "/domains/"+url.PathEscape(zone.ID)+"/records", payload, nil); err != nil {
		return nil, err
	}
	return &Record{
		ID:      rtype + "|" + name, // synthetic — DeleteRecord parses this
		Name:    fqdn,
		Type:    rtype,
		Content: content,
		TTL:     ttl,
	}, nil
}

// DeleteRecord parses the synthetic "TYPE|NAME" record ID and calls
// DELETE /records/{type}/{name}. Silently returns nil if the ID is
// malformed — matches the defensive behaviour of the other adapters.
func (g *godaddyProvider) DeleteRecord(zone Zone, recordID string) error {
	parts := strings.SplitN(recordID, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("godaddy: invalid record id %q (expected TYPE|NAME)", recordID)
	}
	rtype, name := parts[0], parts[1]
	return g.do("DELETE",
		"/domains/"+url.PathEscape(zone.ID)+"/records/"+url.PathEscape(rtype)+"/"+url.PathEscape(name),
		nil, nil)
}
