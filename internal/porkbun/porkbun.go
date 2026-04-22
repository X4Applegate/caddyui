// Package porkbun provides a minimal Porkbun API v3 client scoped to DNS
// record management (list domains, create / delete / list records).
//
// Porkbun's API differs from Cloudflare in a few ways worth knowing up front:
//   - Every request is POST, including listing/retrieving.
//   - Auth is a JSON body `{"apikey":"...", "secretapikey":"..."}` on every
//     request — there's no bearer-token header form.
//   - There is no "zone ID" — operations take the bare domain name in the URL
//     path (e.g. /dns/create/example.com).
//   - Record `name` is the subdomain only (empty for apex, "www" for
//     www.example.com), NOT the FQDN like Cloudflare expects.
//   - Each domain must have "API Access" toggled ON in the Porkbun control
//     panel before it's usable by the API, regardless of API key permissions.
package porkbun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const apiBase = "https://api.porkbun.com/api/json/v3"

// Client is a Porkbun API v3 client authenticated by API key + secret key pair.
type Client struct {
	APIKey     string
	SecretKey  string
	httpClient *http.Client
}

// New returns a Client authenticated with the given key pair.
func New(apiKey, secretKey string) *Client {
	return &Client{
		APIKey:     apiKey,
		SecretKey:  secretKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Domain represents a domain on the Porkbun account.
type Domain struct {
	Name         string `json:"domain"`
	Status       string `json:"status"`
	TLD          string `json:"tld"`
	CreateDate   string `json:"createDate"`
	ExpireDate   string `json:"expireDate"`
	AutoRenew    int    `json:"autoRenew"`
	WhoisPrivacy int    `json:"whoisPrivacy"`
}

// DNSRecord represents a single Porkbun DNS record.
type DNSRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`    // FQDN as returned by the API
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
	Prio    string `json:"prio,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

// pbResponse is the common Porkbun API envelope. On success Status == "SUCCESS";
// on error Status == "ERROR" and Message carries the human-readable reason.
type pbResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// do executes an authenticated API request. The API key/secret are injected
// into the JSON body on every call; callers pass the rest of the payload.
func (c *Client) do(path string, payload map[string]any) ([]byte, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["apikey"] = c.APIKey
	payload["secretapikey"] = c.SecretKey
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", apiBase+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Ping validates the credentials and returns the caller's public IP.
// Useful as a "test connection" action on the Settings page.
func (c *Client) Ping() (string, error) {
	raw, err := c.do("/ping", nil)
	if err != nil {
		return "", err
	}
	var r struct {
		pbResponse
		YourIP string `json:"yourIp"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("porkbun: decode ping: %w", err)
	}
	if r.Status != "SUCCESS" {
		return "", pbErrorMsg(r.Message)
	}
	return r.YourIP, nil
}

// ListDomains returns all domains on the account. Populates the provider
// picker in the proxy-host form (analogous to Cloudflare's ListZones).
func (c *Client) ListDomains() ([]Domain, error) {
	raw, err := c.do("/domain/listAll", nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		pbResponse
		Domains []Domain `json:"domains"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("porkbun: decode listAll: %w", err)
	}
	if r.Status != "SUCCESS" {
		return nil, pbErrorMsg(r.Message)
	}
	return r.Domains, nil
}

// CreateRecord creates a DNS record on the given domain. `name` is the
// subdomain portion (empty for apex, "www" for www.domain). recordType is
// typically "A" or "CNAME". Porkbun's TTL minimum is 600 seconds; lower
// values will be silently clamped by the API — we default to 600.
func (c *Client) CreateRecord(domain, recordType, name, content string, ttl int) (*DNSRecord, error) {
	if ttl < 600 {
		ttl = 600
	}
	payload := map[string]any{
		"type":    recordType,
		"name":    name,
		"content": content,
		"ttl":     fmt.Sprintf("%d", ttl),
	}
	raw, err := c.do("/dns/create/"+domain, payload)
	if err != nil {
		return nil, err
	}
	var r struct {
		pbResponse
		ID json.Number `json:"id"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("porkbun: decode create: %w", err)
	}
	if r.Status != "SUCCESS" {
		return nil, pbErrorMsg(r.Message)
	}
	return &DNSRecord{
		ID:      r.ID.String(),
		Name:    strings.TrimPrefix(name+"."+domain, "."),
		Type:    recordType,
		Content: content,
		TTL:     fmt.Sprintf("%d", ttl),
	}, nil
}

// DeleteRecord removes a DNS record on the given domain by record ID.
func (c *Client) DeleteRecord(domain, recordID string) error {
	raw, err := c.do("/dns/delete/"+domain+"/"+recordID, nil)
	if err != nil {
		return err
	}
	var r pbResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("porkbun: decode delete: %w", err)
	}
	if r.Status != "SUCCESS" {
		return pbErrorMsg(r.Message)
	}
	return nil
}

// ListRecords returns every DNS record on the given domain. Currently used
// only for debugging / potential future "detect existing record" UI.
func (c *Client) ListRecords(domain string) ([]DNSRecord, error) {
	raw, err := c.do("/dns/retrieve/"+domain, nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		pbResponse
		Records []DNSRecord `json:"records"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("porkbun: decode retrieve: %w", err)
	}
	if r.Status != "SUCCESS" {
		return nil, pbErrorMsg(r.Message)
	}
	return r.Records, nil
}

// SubdomainOf returns the subdomain portion of fqdn relative to domain.
// Exported so server.go can compute the correct `name` argument for
// CreateRecord from the proxy host's first Domains entry plus the selected
// Porkbun domain. Examples:
//
//	SubdomainOf("example.com",       "example.com") → ""
//	SubdomainOf("www.example.com",   "example.com") → "www"
//	SubdomainOf("a.b.example.com",   "example.com") → "a.b"
//	SubdomainOf("other.com",         "example.com") → "other.com"  (no match)
func SubdomainOf(fqdn, domain string) string {
	fqdn = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if fqdn == domain {
		return ""
	}
	suffix := "." + domain
	if strings.HasSuffix(fqdn, suffix) {
		return fqdn[:len(fqdn)-len(suffix)]
	}
	return fqdn
}

func pbErrorMsg(msg string) error {
	if msg == "" {
		return fmt.Errorf("porkbun: unknown error")
	}
	return fmt.Errorf("porkbun: %s", msg)
}
