// Package cloudflare provides a minimal Cloudflare API v4 client scoped to
// DNS record management (list zones, create / delete / list records).
package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

// Client is a Cloudflare API v4 client authenticated via an API token.
type Client struct {
	APIToken   string
	httpClient *http.Client
}

// New returns a Client authenticated with the given API token.
func New(apiToken string) *Client {
	return &Client{
		APIToken:   apiToken,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// Zone represents a Cloudflare DNS zone.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DNSRecord represents a single Cloudflare DNS record.
type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// cfResponse is the common Cloudflare API envelope.
type cfResponse[T any] struct {
	Success bool    `json:"success"`
	Errors  []cfErr `json:"errors"`
	Result  T       `json:"result"`
}

type cfErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// do executes an authenticated API request. body may be nil for GET/DELETE.
func (c *Client) do(method, path string, body any) (*http.Response, error) {
	// Validate the path to prevent injection.
	if _, err := url.ParseRequestURI(apiBase + path); err != nil {
		return nil, fmt.Errorf("cloudflare: invalid path: %w", err)
	}
	var req *http.Request
	var err error
	if body != nil {
		b, _ := json.Marshal(body)
		req, err = http.NewRequest(method, apiBase+path, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, apiBase+path, nil)
		if err != nil {
			return nil, err
		}
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	return c.httpClient.Do(req)
}

// ListZones returns all DNS zones accessible with the current API token.
func (c *Client) ListZones() ([]Zone, error) {
	resp, err := c.do("GET", "/zones?per_page=50", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result cfResponse[[]Zone]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, cfErrorMsg(result.Errors)
	}
	return result.Result, nil
}

// CreateRecord creates a new DNS record in the specified zone.
// recordType is typically "A" or "CNAME".
// ttl=1 means "auto" in Cloudflare's API.
// proxied=true routes traffic through Cloudflare's network (orange cloud).
func (c *Client) CreateRecord(zoneID, recordType, name, content string, proxied bool, ttl int) (*DNSRecord, error) {
	if ttl == 0 {
		ttl = 1 // auto
	}
	payload := map[string]any{
		"type":    recordType,
		"name":    name,
		"content": content,
		"ttl":     ttl,
		"proxied": proxied,
	}
	resp, err := c.do("POST", "/zones/"+zoneID+"/dns_records", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result cfResponse[*DNSRecord]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, cfErrorMsg(result.Errors)
	}
	return result.Result, nil
}

// DeleteRecord removes a DNS record from the specified zone.
func (c *Client) DeleteRecord(zoneID, recordID string) error {
	resp, err := c.do("DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result cfResponse[map[string]string]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if !result.Success {
		return cfErrorMsg(result.Errors)
	}
	return nil
}

// ListRecords returns DNS records in the zone, optionally filtered by exact name.
func (c *Client) ListRecords(zoneID, name string) ([]DNSRecord, error) {
	path := "/zones/" + zoneID + "/dns_records?per_page=100"
	if name != "" {
		path += "&name=" + url.QueryEscape(name)
	}
	resp, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result cfResponse[[]DNSRecord]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, cfErrorMsg(result.Errors)
	}
	return result.Result, nil
}

func cfErrorMsg(errs []cfErr) error {
	if len(errs) == 0 {
		return fmt.Errorf("cloudflare: unknown error")
	}
	return fmt.Errorf("cloudflare: %s (code %d)", errs[0].Message, errs[0].Code)
}
