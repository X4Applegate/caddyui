package models

import (
	"encoding/json"
	"fmt"
	"strings"
)

// HostExpectation is one post-apply check attached to a proxy host
// (v2.38.0). After every config sync CaddyUI requests
// Scheme://<primary domain>Path with Method and verifies the answer; if any
// enabled expectation on a server fails and auto-rollback is on, the live
// Caddy config is restored to what it was before the sync and further
// automatic syncs are held until the operator re-applies. Stored as a JSON
// array in proxy_hosts.expectations_json, edited from the host form.
type HostExpectation struct {
	Label          string `json:"label,omitempty"`
	Method         string `json:"method"`                    // GET by default; any MonitorMethods entry
	Scheme         string `json:"scheme"`                    // https by default; http for redirect checks
	Path           string `json:"path"`                      // "/" by default
	ExpectStatus   int    `json:"expect_status"`             // 0 = any 2xx/3xx
	ExpectLocation string `json:"expect_location,omitempty"` // when set, the Location header must start with this
	MaxLatencyMS   int    `json:"max_latency_ms,omitempty"`  // 0 = no limit
	VerifyTLS      bool   `json:"verify_tls,omitempty"`      // require a valid certificate chain
	Disabled       bool   `json:"disabled,omitempty"`
}

// Normalized returns a canonical copy: upper-case whitelisted method (GET for
// anything else), lower-case scheme (https unless "http"), a leading-slash
// path ("/" when blank), a status of 100–599 or 0, non-negative latency.
func (e HostExpectation) Normalized() HostExpectation {
	e.Label = strings.TrimSpace(e.Label)
	e.Method = NormalizeMonitorMethod(e.Method)
	if strings.EqualFold(strings.TrimSpace(e.Scheme), "http") {
		e.Scheme = "http"
	} else {
		e.Scheme = "https"
	}
	e.Path = strings.TrimSpace(e.Path)
	if e.Path == "" {
		e.Path = "/"
	} else if !strings.HasPrefix(e.Path, "/") {
		e.Path = "/" + e.Path
	}
	if e.ExpectStatus < 100 || e.ExpectStatus > 599 {
		e.ExpectStatus = 0
	}
	e.ExpectLocation = strings.TrimSpace(e.ExpectLocation)
	if e.MaxLatencyMS < 0 {
		e.MaxLatencyMS = 0
	}
	return e
}

// Describe renders the expectation for humans: "GET https /healthz → 200 (≤ 500 ms)".
func (e HostExpectation) Describe() string {
	e = e.Normalized()
	want := "2xx/3xx"
	if e.ExpectStatus > 0 {
		want = fmt.Sprintf("%d", e.ExpectStatus)
	}
	s := fmt.Sprintf("%s %s %s → %s", e.Method, e.Scheme, e.Path, want)
	if e.ExpectLocation != "" {
		s += " to " + e.ExpectLocation
	}
	if e.MaxLatencyMS > 0 {
		s += fmt.Sprintf(" (≤ %d ms)", e.MaxLatencyMS)
	}
	if e.VerifyTLS {
		s += " [valid TLS]"
	}
	if e.Label != "" {
		return e.Label + ": " + s
	}
	return s
}

// ParseHostExpectations decodes the JSON column. Nil for blank or malformed
// input. Every entry comes back normalized.
func ParseHostExpectations(raw string) []HostExpectation {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	var out []HostExpectation
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	for i := range out {
		out[i] = out[i].Normalized()
	}
	return out
}

// NormalizeHostExpectationsJSON is what the form parser stores: the input
// re-encoded in canonical form, or "" when it holds nothing usable.
func NormalizeHostExpectationsJSON(raw string) string {
	list := ParseHostExpectations(raw)
	if len(list) == 0 {
		return ""
	}
	b, err := json.Marshal(list)
	if err != nil {
		return ""
	}
	return string(b)
}

// ExpectationList parses the host's post-apply checks. v2.38.0.
func (p *ProxyHost) ExpectationList() []HostExpectation {
	return ParseHostExpectations(p.Expectations)
}

// ActiveExpectations is ExpectationList without disabled entries.
func (p *ProxyHost) ActiveExpectations() []HostExpectation {
	var out []HostExpectation
	for _, e := range p.ExpectationList() {
		if !e.Disabled {
			out = append(out, e)
		}
	}
	return out
}
