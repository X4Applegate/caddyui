package server

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// adaptedAdvanced mimics what Caddy's adapter returns for a site block: a
// subroute wrapping one route per directive group.
func adaptedAdvanced(routes ...map[string]any) []any {
	rs := make([]any, 0, len(routes))
	for _, r := range routes {
		rs = append(rs, r)
	}
	return []any{map[string]any{"handler": "subroute", "routes": rs}}
}

// v2.40.0: a reverse_proxy block is lifted out of the pre-handlers and its
// fields returned for merging; the other directives keep running before the
// proxy; matched or upstream-bearing blocks are refused.
func TestExtractReverseProxyOverrides(t *testing.T) {
	headers := map[string]any{"handler": "headers", "response": map[string]any{"set": map[string]any{"X-Frame-Options": []any{"DENY"}}}}
	rp := map[string]any{"handler": "reverse_proxy", "flush_interval": -1, "headers": map[string]any{"request": map[string]any{"set": map[string]any{"X-Real-Ip": []any{"{http.request.remote.host}"}}}}}

	rest, overrides, err := extractReverseProxyOverrides(adaptedAdvanced(map[string]any{"handle": []any{headers, rp}}))
	if err != nil {
		t.Fatal(err)
	}
	if overrides["flush_interval"] != -1 || overrides["handler"] != nil || overrides["headers"] == nil {
		t.Errorf("overrides = %v", overrides)
	}
	sub := rest[0].(map[string]any)
	kept := sub["routes"].([]any)[0].(map[string]any)["handle"].([]any)
	if len(rest) != 1 || len(kept) != 1 || kept[0].(map[string]any)["handler"] != "headers" {
		t.Errorf("the headers handler should remain before the proxy: %v", rest)
	}

	// A block that was the only directive leaves no pre-handlers at all.
	rest, overrides, err = extractReverseProxyOverrides(adaptedAdvanced(map[string]any{"handle": []any{rp}}))
	if err != nil || len(rest) != 0 || overrides["flush_interval"] != -1 {
		t.Errorf("only-block: rest=%v overrides=%v err=%v", rest, overrides, err)
	}

	// No block at all: handlers pass through untouched.
	rest, overrides, err = extractReverseProxyOverrides(adaptedAdvanced(map[string]any{"handle": []any{headers}}))
	if err != nil || overrides != nil || len(rest) != 1 {
		t.Errorf("no block: rest=%v overrides=%v err=%v", rest, overrides, err)
	}

	withUpstream := map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": "other:80"}}}
	if _, _, err := extractReverseProxyOverrides(adaptedAdvanced(map[string]any{"handle": []any{withUpstream}})); err == nil || !strings.Contains(err.Error(), "Forward host / port") {
		t.Errorf("an upstream in the block must be refused, got %v", err)
	}
	matched := map[string]any{"match": []any{map[string]any{"path": []any{"/api/*"}}}, "handle": []any{rp}}
	if _, _, err := extractReverseProxyOverrides(adaptedAdvanced(matched)); err == nil || !strings.Contains(err.Error(), "matcher") {
		t.Errorf("a matched block must be refused, got %v", err)
	}
	if _, _, err := extractReverseProxyOverrides(adaptedAdvanced(map[string]any{"handle": []any{rp, rp}})); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Errorf("two blocks must be refused, got %v", err)
	}
}

// Bare sub-directives are explained before Caddy ever sees them; a
// reverse_proxy block is no longer banned; terminal handlers still are.
func TestValidateProxyAdvancedDirectivesExplainsSubdirectives(t *testing.T) {
	msg := validateProxyAdvancedDirectives("flush_interval -1\nencode gzip")
	if !strings.Contains(msg, "`flush_interval` is a reverse_proxy sub-directive") || !strings.Contains(msg, "reverse_proxy {") || !strings.Contains(msg, "Flush immediately") {
		t.Errorf("flush_interval message = %q", msg)
	}
	if msg := validateProxyAdvancedDirectives("header_up X-Real-IP {remote_host}"); !strings.Contains(msg, "`header_up`") {
		t.Errorf("header_up message = %q", msg)
	}
	if msg := validateProxyAdvancedDirectives("reverse_proxy {\n\tflush_interval -1\n\theader_up X-Real-IP {remote_host}\n}\nencode gzip"); msg != "" {
		t.Errorf("a reverse_proxy block must pass validation, got %q", msg)
	}
	if msg := validateProxyAdvancedDirectives("respond \"hi\""); !strings.Contains(msg, "`respond`") {
		t.Errorf("respond must still be banned, got %q", msg)
	}
	// Inside a block the words are not directives.
	if msg := validateProxyAdvancedDirectives("request_body {\n\tmax_size 10MB\n}\n"); msg != "" {
		t.Errorf("nested lines must not trigger, got %q", msg)
	}
}

// Opt-in end-to-end check against a real Caddy admin API: adapt a block
// through /adapt and merge it into a built route. Set
// CADDYUI_TEST_CADDY_ADMIN=http://127.0.0.1:2019 to run it.
func TestAdvancedReverseProxyBlockThroughRealCaddy(t *testing.T) {
	admin := os.Getenv("CADDYUI_TEST_CADDY_ADMIN")
	if admin == "" {
		t.Skip("CADDYUI_TEST_CADDY_ADMIN not set")
	}
	s := &Server{}
	p := models.ProxyHost{Domains: "app.example.test", ForwardScheme: "http", ForwardHost: "app", ForwardPort: 8080, Enabled: true,
		AdvancedConfig: "header X-Frame-Options DENY\nreverse_proxy {\n\tflush_interval -1\n\theader_up X-Real-IP {remote_host}\n\ttransport http {\n\t\tread_timeout 30s\n\t}\n}\n"}
	handlers, overrides, err := s.adaptProxyAdvancedWithClient(caddy.New(admin, "", ""), p)
	if err != nil {
		t.Fatal(err)
	}
	route := caddy.BuildProxyRoute(p, handlers)
	if !caddy.MergeReverseProxyOverrides(route, overrides) {
		t.Fatal("merge found no reverse_proxy handler")
	}
	rp := route["handle"].([]any)[len(route["handle"].([]any))-1].(map[string]any)
	if rp["handler"] != "reverse_proxy" || rp["flush_interval"] != float64(-1) && rp["flush_interval"] != -1 {
		t.Errorf("flush_interval not merged: %v", rp)
	}
	if rp["upstreams"].([]any)[0].(map[string]any)["dial"] != "app:8080" {
		t.Errorf("upstream must come from the form: %v", rp["upstreams"])
	}
	if rp["transport"].(map[string]any)["read_timeout"] == nil {
		t.Errorf("transport read_timeout not merged: %v", rp["transport"])
	}
	if s.validateProxyAdvanced(caddy.New(admin, "", ""), &p) != "" {
		t.Errorf("validateProxyAdvanced should accept the block")
	}
	// v2.42.1: a bare sub-directive is wrapped, so it is simply accepted…
	bare := p
	bare.AdvancedConfig = "flush_interval -1"
	if msg := s.validateProxyAdvanced(caddy.New(admin, "", ""), &bare); msg != "" {
		t.Errorf("bare sub-directive should be repaired and accepted, got %q", msg)
	}
	// …while a genuinely unknown option gets the v2.42.2 explanation.
	bogus := p
	bogus.AdvancedConfig = "reverse_proxy {\n\tbogus_option 1\n}\n"
	if msg := s.validateProxyAdvanced(caddy.New(admin, "", ""), &bogus); !strings.Contains(msg, "`bogus_option` is not an option Caddy knows there") {
		t.Errorf("unknown option should be explained, got %q", msg)
	}
}

// v2.42.1: bare reverse_proxy sub-directives are moved into a reverse_proxy
// block (merged into an existing one), blocks travel intact, and sources
// with nothing to move come back byte-identical.
func TestWrapBareReverseProxySubdirectives(t *testing.T) {
	got, names := wrapBareReverseProxySubdirectivesNamed("flush_interval -1\nencode gzip\n")
	if got != "encode gzip\nreverse_proxy {\n\tflush_interval -1\n}\n" || len(names) != 1 || names[0] != "flush_interval" {
		t.Errorf("simple wrap = %q (%v)", got, names)
	}
	got, _ = wrapBareReverseProxySubdirectivesNamed("flush_interval -1")
	if got != "reverse_proxy {\n\tflush_interval -1\n}\n" {
		t.Errorf("only a sub-directive = %q", got)
	}
	got, names = wrapBareReverseProxySubdirectivesNamed("header X-Frame-Options DENY\ntransport http {\n\tread_timeout 30s\n}\nreverse_proxy {\n\theader_up X-Real-IP {remote_host}\n}\n")
	want := "header X-Frame-Options DENY\nreverse_proxy {\n\theader_up X-Real-IP {remote_host}\n\ttransport http {\n\tread_timeout 30s\n\t}\n}\n"
	if got != want || len(names) != 1 || names[0] != "transport" {
		t.Errorf("merge into existing block = %q (%v)\nwant %q", got, names, want)
	}
	for _, unchanged := range []string{"", "encode gzip\n", "reverse_proxy {\n\tflush_interval -1\n}\n", "request_body {\n\tmax_size 10MB\n}\n"} {
		if got, names := wrapBareReverseProxySubdirectivesNamed(unchanged); got != unchanged || names != nil {
			t.Errorf("%q should be untouched, got %q (%v)", unchanged, got, names)
		}
	}
	// After wrapping, validation no longer complains and the block adapts.
	if msg := validateProxyAdvancedDirectives(wrapBareReverseProxySubdirectives("flush_interval -1")); msg != "" {
		t.Errorf("wrapped source should validate, got %q", msg)
	}
}

// v2.42.2: JSON-style transport names are respelled and transport options
// under reverse_proxy move into its transport block — including the exact
// config from the report (flush_interval plus a transport block using
// read_buffer_size / write_buffer_size).
func TestNormalizeProxyAdvancedConfigRepairsTransportOptions(t *testing.T) {
	reported := "flush_interval -1\n\ntransport http {\n    dial_timeout 30s\n    response_header_timeout 300s\n    read_buffer_size 16384\n    write_buffer_size 16384\n}\n"
	got := normalizeProxyAdvancedConfig(reported)
	for _, want := range []string{"reverse_proxy {", "\tflush_interval -1", "read_buffer 16384", "write_buffer 16384", "dial_timeout 30s"} {
		if !strings.Contains(got, want) {
			t.Errorf("normalized config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "read_buffer_size") || strings.Contains(got, "write_buffer_size") {
		t.Errorf("JSON names should be respelled:\n%s", got)
	}
	if msg := validateProxyAdvancedDirectives(got); msg != "" {
		t.Errorf("normalized config should validate, got %q", msg)
	}

	// Transport options typed directly under reverse_proxy move into a new transport block.
	got = relocateTransportSubdirectives("reverse_proxy {\n\tflush_interval -1\n\tread_buffer 8192\n\tdial_timeout 10s\n}\n")
	want := "reverse_proxy {\n\tflush_interval -1\n\ttransport http {\n\t\tread_buffer 8192\n\t\tdial_timeout 10s\n\t}\n}\n"
	if got != want {
		t.Errorf("relocate into new block = %q\nwant %q", got, want)
	}
	// … or into the existing one.
	got = relocateTransportSubdirectives("reverse_proxy {\n\tread_buffer 8192\n\ttransport http {\n\t\tdial_timeout 10s\n\t}\n}\n")
	want = "reverse_proxy {\n\ttransport http {\n\t\tdial_timeout 10s\n\t\tread_buffer 8192\n\t}\n}\n"
	if got != want {
		t.Errorf("relocate into existing block = %q\nwant %q", got, want)
	}
	for _, unchanged := range []string{"", "encode gzip\n", "reverse_proxy {\n\tflush_interval -1\n\ttransport http {\n\t\tread_buffer 1\n\t}\n}\n"} {
		if got := normalizeProxyAdvancedConfig(unchanged); got != unchanged {
			t.Errorf("%q should be untouched, got %q", unchanged, got)
		}
	}
	if got := respellTransportAliases("  max_response_header_size 64KiB # note"); got != "  max_response_header 64KiB # note" {
		t.Errorf("respell = %q", got)
	}

	err := errors.New(`caddy rejected Caddyfile: {"error":"adapting config using caddyfile adapter: parsing caddyfile tokens for 'reverse_proxy': unrecognized subdirective read_buffer_size, at Caddyfile:7"}`)
	msg := friendlyAdvancedRejection(err)
	if !strings.Contains(msg, "`read_buffer_size` is not an option Caddy knows there") || !strings.Contains(msg, "spelled `read_buffer`") || !strings.Contains(msg, "Upstream") || !strings.Contains(msg, "Caddy said:") {
		t.Errorf("friendly message = %q", msg)
	}
	if msg := friendlyAdvancedRejection(errors.New("something else")); msg != "Advanced config rejected by Caddy: something else" {
		t.Errorf("non-subdirective errors pass through, got %q", msg)
	}
}

// The reported config adapts through a real Caddy once repaired; set
// CADDYUI_TEST_CADDY_ADMIN to run.
func TestReportedTransportConfigThroughRealCaddy(t *testing.T) {
	admin := os.Getenv("CADDYUI_TEST_CADDY_ADMIN")
	if admin == "" {
		t.Skip("CADDYUI_TEST_CADDY_ADMIN not set")
	}
	s := &Server{}
	p := models.ProxyHost{Domains: "cloud.example.test", ForwardScheme: "http", ForwardHost: "nextcloud", ForwardPort: 80, Enabled: true,
		AdvancedConfig: "flush_interval -1\n\ntransport http {\n    dial_timeout 30s\n    response_header_timeout 300s\n    read_buffer_size 16384\n    write_buffer_size 16384\n}\n"}
	if msg := s.validateProxyAdvanced(caddy.New(admin, "", ""), &p); msg != "" {
		t.Fatalf("repaired config should be accepted, got %q", msg)
	}
	handlers, overrides, err := s.adaptProxyAdvancedWithClient(caddy.New(admin, "", ""), p)
	if err != nil {
		t.Fatal(err)
	}
	route := caddy.BuildProxyRoute(p, handlers)
	caddy.MergeReverseProxyOverrides(route, overrides)
	rp := route["handle"].([]any)[len(route["handle"].([]any))-1].(map[string]any)
	transport, _ := rp["transport"].(map[string]any)
	if transport == nil || transport["read_buffer_size"] == nil || transport["write_buffer_size"] == nil || transport["response_header_timeout"] == nil || rp["flush_interval"] == nil {
		t.Errorf("merged handler = %v", rp)
	}
}
