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

// digitalOceanProvider talks to the DigitalOcean Networking API's DNS endpoints.
// DO identifies zones by the bare domain name (like Porkbun) but uses a
// bearer token (like Cloudflare) and returns record IDs as integers.
//
// API reference: https://docs.digitalocean.com/reference/api/api-reference/#tag/Domains
// and https://docs.digitalocean.com/reference/api/api-reference/#tag/Domain-Records

const doAPIBase = "https://api.digitalocean.com/v2"

type digitalOceanProvider struct {
	token      string
	httpClient *http.Client
}

func init() {
	Register(Descriptor{
		ID:          DigitalOcean,
		DisplayName: "DigitalOcean",
		DocsAnchor:  "digitalocean",
		Credentials: []CredentialField{
			{
				Key:         "do_api_token",
				Label:       "API Token",
				Help:        "Create a Personal Access Token with write scope at cloud.digitalocean.com/account/api/tokens.",
				Placeholder: "dop_v1_...",
				Secret:      true,
			},
		},
		Factory: func(creds map[string]string) Provider {
			token := creds["do_api_token"]
			if token == "" {
				return nil
			}
			return &digitalOceanProvider{
				token:      token,
				httpClient: &http.Client{Timeout: 15 * time.Second},
			}
		},
	})
}

func (d *digitalOceanProvider) ID() string          { return DigitalOcean }
func (d *digitalOceanProvider) DisplayName() string { return "DigitalOcean" }

// do executes an authenticated request and JSON-decodes the response into out.
// body may be nil.
func (d *digitalOceanProvider) do(method, path string, body any, out any) error {
	var reader *bytes.Reader
	var req *http.Request
	var err error
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
		req, err = http.NewRequest(method, doAPIBase+path, reader)
	} else {
		req, err = http.NewRequest(method, doAPIBase+path, nil)
	}
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e struct {
			ID      string `json:"id"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		msg := e.Message
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("digitalocean: %s (%s)", msg, resp.Status)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Ping lists domains as the cheapest credential-validation call DO offers.
func (d *digitalOceanProvider) Ping() (string, error) {
	zones, err := d.ListZones()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (%d domains accessible)", len(zones)), nil
}

func (d *digitalOceanProvider) ListZones() ([]Zone, error) {
	var resp struct {
		Domains []struct {
			Name string `json:"name"`
		} `json:"domains"`
	}
	// per_page caps at 200 and we don't expect hobbyists to exceed that.
	if err := d.do("GET", "/domains?per_page=200", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(resp.Domains))
	for _, dom := range resp.Domains {
		out = append(out, Zone{ID: dom.Name, Name: dom.Name})
	}
	return out, nil
}

// CreateRecord creates a DNS record. DO uses "@" for apex, subdomain-only
// for everything else — same shape as our SubdomainOf helper.
func (d *digitalOceanProvider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	if ttl == 0 {
		ttl = 3600
	}
	name := SubdomainOf(fqdn, zone.Name)
	// DigitalOcean minimum TTL is 30, documented floor is 1800 on legacy
	// plans — the API clamps anything lower, no need for client-side math.
	payload := map[string]any{
		"type": strings.ToUpper(rtype),
		"name": name,
		"data": content,
		"ttl":  ttl,
	}
	var resp struct {
		Record struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
			Data string `json:"data"`
			TTL  int    `json:"ttl"`
		} `json:"domain_record"`
	}
	if err := d.do("POST", "/domains/"+url.PathEscape(zone.ID)+"/records", payload, &resp); err != nil {
		return nil, err
	}
	return &Record{
		ID:      fmt.Sprintf("%d", resp.Record.ID),
		Name:    fqdn,
		Type:    resp.Record.Type,
		Content: resp.Record.Data,
		TTL:     resp.Record.TTL,
	}, nil
}

func (d *digitalOceanProvider) DeleteRecord(zone Zone, recordID string) error {
	return d.do("DELETE", "/domains/"+url.PathEscape(zone.ID)+"/records/"+recordID, nil, nil)
}

// FindRecord returns every record on the domain whose short name matches
// the subdomain derived from fqdn. DigitalOcean's records endpoint supports
// a ?name= filter but it matches against the short name as stored — we
// filter client-side to stay consistent with the other adapters and avoid
// surprises around apex ("@").
func (d *digitalOceanProvider) FindRecord(zone Zone, fqdn string) ([]Record, error) {
	var resp struct {
		Records []struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
			Data string `json:"data"`
			TTL  int    `json:"ttl"`
		} `json:"domain_records"`
	}
	if err := d.do("GET", "/domains/"+url.PathEscape(zone.ID)+"/records?per_page=200", nil, &resp); err != nil {
		return nil, err
	}
	want := SubdomainOf(fqdn, zone.Name)
	out := []Record{}
	for _, r := range resp.Records {
		if !strings.EqualFold(r.Name, want) {
			continue
		}
		out = append(out, Record{
			ID:      fmt.Sprintf("%d", r.ID),
			Name:    fqdn,
			Type:    r.Type,
			Content: r.Data,
			TTL:     r.TTL,
		})
	}
	return out, nil
}
