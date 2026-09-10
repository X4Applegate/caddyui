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

// gandiProvider talks to Gandi's LiveDNS v5 API (v2.45.0, discussion #72).
//
// Auth is a Personal Access Token sent as "Authorization: Bearer <token>".
// Zones are domains: Zone.ID == Zone.Name == the bare domain, like Porkbun.
// Records are RRsets keyed by (name, type) with a list of values and no
// per-record ID, so CaddyUI's record ID is the composite "name/type"
// ("app/A", "@/A" for the apex) and DeleteRecord removes the whole RRset
// CaddyUI created. Names are relative to the zone, "@" for the apex. TTL
// floor is 300 seconds.
//
// API reference: https://api.gandi.net/docs/livedns/

const gandiAPIBase = "https://api.gandi.net/v5/livedns"

type gandiProvider struct {
	token      string
	apiBase    string
	httpClient *http.Client
}

func init() {
	Register(Descriptor{
		ID:          Gandi,
		DisplayName: "Gandi",
		DocsAnchor:  "gandi",
		Credentials: []CredentialField{
			{
				Key:         "gandi_api_token",
				Label:       "Personal Access Token",
				Help:        "Create a Personal Access Token at admin.gandi.net → User settings → Personal Access Token (PAT), for the organization that owns the domains, with permission to manage domain name technical configurations. LiveDNS must be enabled on each domain (it is by default).",
				Placeholder: "paste token here",
				Secret:      true,
			},
		},
		Factory: func(creds map[string]string) Provider {
			token := strings.TrimSpace(creds["gandi_api_token"])
			if token == "" {
				return nil
			}
			return &gandiProvider{
				token:      token,
				apiBase:    gandiAPIBase,
				httpClient: &http.Client{Timeout: 15 * time.Second},
			}
		},
	})
}

func (g *gandiProvider) ID() string          { return Gandi }
func (g *gandiProvider) DisplayName() string { return "Gandi" }

// gandiRRSet is one record set as LiveDNS returns and accepts it.
type gandiRRSet struct {
	Name   string   `json:"rrset_name"`
	Type   string   `json:"rrset_type"`
	TTL    int      `json:"rrset_ttl"`
	Values []string `json:"rrset_values"`
}

// do performs one request; a nil out ignores the body. Callers that need
// the status (409 on create, 404 on lookup) get it back.
func (g *gandiProvider) do(method, path string, body any, out any) (int, error) {
	var req *http.Request
	var err error
	if body != nil {
		b, _ := json.Marshal(body)
		req, err = http.NewRequest(method, g.apiBase+path, bytes.NewReader(b))
	} else {
		req, err = http.NewRequest(method, g.apiBase+path, nil)
	}
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// Gandi errors look like {"code":403,"message":"...","object":"HTTPForbidden","cause":"Forbidden"}
		var e struct {
			Message string `json:"message"`
			Cause   string `json:"cause"`
			Errors  []struct {
				Description string `json:"description"`
				Name        string `json:"name"`
			} `json:"errors"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		msg := e.Message
		if msg == "" {
			msg = e.Cause
		}
		for _, fe := range e.Errors {
			if fe.Description != "" {
				msg += " — " + fe.Name + ": " + fe.Description
			}
		}
		if msg == "" {
			msg = resp.Status
		}
		return resp.StatusCode, fmt.Errorf("gandi: %s (%s)", msg, resp.Status)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

func (g *gandiProvider) Ping() (string, error) {
	zones, err := g.ListZones()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (%d domains on LiveDNS)", len(zones)), nil
}

// ListZones lists every LiveDNS domain the token can see, following the
// page size limit of 100.
func (g *gandiProvider) ListZones() ([]Zone, error) {
	var out []Zone
	for page := 1; page <= 50; page++ {
		var domains []struct {
			FQDN string `json:"fqdn"`
		}
		if _, err := g.do("GET", fmt.Sprintf("/domains?per_page=100&page=%d", page), nil, &domains); err != nil {
			return nil, err
		}
		for _, d := range domains {
			name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.FQDN)), ".")
			if name != "" {
				out = append(out, Zone{ID: name, Name: name})
			}
		}
		if len(domains) < 100 {
			break
		}
	}
	return out, nil
}

// gandiRecordID is the composite record ID CaddyUI stores for an RRset.
func gandiRecordID(name, rtype string) string {
	return name + "/" + strings.ToUpper(rtype)
}

func gandiSplitRecordID(id string) (name, rtype string, ok bool) {
	i := strings.LastIndex(id, "/")
	if i <= 0 || i == len(id)-1 {
		return "", "", false
	}
	return id[:i], id[i+1:], true
}

func (g *gandiProvider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	name := SubdomainOf(fqdn, zone.Name)
	if ttl < 300 {
		ttl = 300 // LiveDNS minimum
	}
	rtype = strings.ToUpper(rtype)
	body := gandiRRSet{Name: name, Type: rtype, TTL: ttl, Values: []string{content}}
	status, err := g.do("POST", "/domains/"+url.PathEscape(zone.ID)+"/records", body, nil)
	if err != nil {
		if status == http.StatusConflict {
			return nil, fmt.Errorf("gandi: a %s record set named %q already exists in %s — CaddyUI never overwrites records it did not create; remove or change that set in the Gandi console, then save again", rtype, name, zone.Name)
		}
		return nil, err
	}
	return &Record{
		ID:      gandiRecordID(name, rtype),
		Name:    fqdn,
		Type:    rtype,
		Content: content,
		TTL:     ttl,
	}, nil
}

// DeleteRecord removes the whole RRset the composite ID names. A missing
// RRset is not an error — the record is gone either way.
func (g *gandiProvider) DeleteRecord(zone Zone, recordID string) error {
	name, rtype, ok := gandiSplitRecordID(recordID)
	if !ok {
		return fmt.Errorf("gandi: malformed record id %q (want name/type)", recordID)
	}
	status, err := g.do("DELETE", "/domains/"+url.PathEscape(zone.ID)+"/records/"+url.PathEscape(name)+"/"+url.PathEscape(rtype), nil, nil)
	if err != nil && status != http.StatusNotFound {
		return err
	}
	return nil
}

// FindRecord returns every RRset at fqdn's name, one Record per type with
// the values joined, so the collision check can show what is there.
func (g *gandiProvider) FindRecord(zone Zone, fqdn string) ([]Record, error) {
	name := SubdomainOf(fqdn, zone.Name)
	var sets []gandiRRSet
	status, err := g.do("GET", "/domains/"+url.PathEscape(zone.ID)+"/records/"+url.PathEscape(name), nil, &sets)
	if err != nil {
		if status == http.StatusNotFound {
			return []Record{}, nil
		}
		return nil, err
	}
	out := make([]Record, 0, len(sets))
	for _, rs := range sets {
		out = append(out, Record{
			ID:      gandiRecordID(rs.Name, rs.Type),
			Name:    fqdn,
			Type:    strings.ToUpper(rs.Type),
			Content: strings.Join(rs.Values, ", "),
			TTL:     rs.TTL,
		})
	}
	return out, nil
}
