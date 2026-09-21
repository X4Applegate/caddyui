// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// --- Feature B: Upstream health checks ---

type upstreamHealthResult struct {
	ID      int64  `json:"id"`
	Domains string `json:"domains"`
	// Status is the port-level (TCP) health: "ok", "error", "unknown", or
	// "disabled". Sourced from Caddy's /reverse_proxy/upstreams (authoritative
	// since Caddy is on the upstream's Docker network); falls back to a
	// direct dial for public/dotted hostnames not yet in Caddy's upstream map.
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`

	// AppStatus is the end-to-end HTTP-response health: "ok", "degraded",
	// "down", "unknown", or "disabled". Sourced from the app-health poller,
	// which does an HTTPS GET against the public domain every 60s. This is
	// what catches "port open but app wedged" (e.g. DB connection stuck) —
	// something Status (TCP) alone can't see.
	AppStatus    string `json:"app_status,omitempty"`
	AppCode      int    `json:"app_code,omitempty"`
	AppLatencyMS int64  `json:"app_latency_ms,omitempty"`
	AppError     string `json:"app_error,omitempty"`
}

// postMyColorTheme — v2.12.27: persist the signed-in user's preferred
// color theme to the DB so it follows the account across devices. The
// picker in Settings POSTs here on change. Body is form-encoded with a
// single `theme` field. Empty string and "default" both clear the
// preference (use the default palette); "orange" picks the carbon-orange
// palette; "forest", "rose", and "indigo" pick their respective palettes
// (v2.15.0). Anything else returns 400 so we don't store junk that the
// CSS layer wouldn't recognise.
func (s *Server) postMyColorTheme(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	if u == nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	theme := strings.TrimSpace(r.FormValue("theme"))
	// Normalise "default" to empty string in storage so the column reads
	// as "no opinion" by default and we don't carry a magic value around.
	if theme == "default" {
		theme = ""
	}
	switch theme {
	case "", "orange", "forest", "rose", "indigo":
		// allowed
	default:
		http.Error(w, "unknown theme", http.StatusBadRequest)
		return
	}
	if err := models.UpdateUserColorTheme(s.DB, u.ID, theme); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiAIStatus — v2.11.15: reports whether AI assist is enabled and which
// model is configured. Frontend uses this to decide whether to render the
// floating AI button at page load.
//
// v2.12.36: model now reflects the active provider's selected model so the
// chat-panel header reads "Claude (Sonnet)" / "OpenAI (gpt-4o)" / etc.
// instead of always showing the Ollama model name.
func (s *Server) apiAIStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled, _ := models.GetSetting(s.DB, settingAIEnabled)
	provider, model := activeAIProviderModel(s.DB)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled":  enabled == "1",
		"provider": provider,
		"model":    model,
	})
}

// activeAIProviderModel — v2.12.36: read the AI provider selector and return
// the provider name + the model name for that provider (with fallbacks).
// Used by /api/ai/status and by /api/ai/chat dispatch.
func activeAIProviderModel(db *sql.DB) (provider, model string) {
	provider, _ = models.GetSetting(db, settingAIProvider)
	switch provider {
	case "ollama_cloud":
		model, _ = models.GetSetting(db, settingAIOllamaCloudModel)
		if strings.TrimSpace(model) == "" {
			model = "qwen3-coder:480b-cloud"
		}
	case "anthropic":
		model, _ = models.GetSetting(db, settingAIAnthropicModel)
		if strings.TrimSpace(model) == "" {
			model = "claude-haiku-4-5-20251001"
		}
	case "openai":
		model, _ = models.GetSetting(db, settingAIOpenAIModel)
		if strings.TrimSpace(model) == "" {
			model = "gpt-4o-mini"
		}
	default: // "ollama" or "" (legacy installs default to local Ollama)
		provider = "ollama"
		model, _ = models.GetSetting(db, settingAIOllamaModel)
		if strings.TrimSpace(model) == "" {
			model = "llama3.2:latest"
		}
	}
	return
}

// apiAIChat — v2.11.15: proxies a user prompt to the configured Ollama
// /api/chat endpoint. Single-shot — no server-side conversation history.
// Streaming is disabled (stream=false) so we can return the full message
// in one JSON response.
//
// The system prompt frames Ollama as a CaddyUI assistant, so generic
// model knowledge gets steered toward Caddy / reverse-proxy / DNS / TLS
// answers without needing a fine-tuned model.
func (s *Server) apiAIChat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled, _ := models.GetSetting(s.DB, settingAIEnabled)
	if enabled != "1" {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "AI assist is disabled — turn it on under Settings."})
		return
	}

	// v2.12.10: accept multi-turn message arrays for conversation memory
	// while keeping back-compat with the single {message:""} shape.
	var body struct {
		Message  string              `json:"message"`
		Messages []map[string]string `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "could not parse JSON body"})
		return
	}
	turns := body.Messages
	if len(turns) == 0 && strings.TrimSpace(body.Message) != "" {
		turns = []map[string]string{{"role": "user", "content": body.Message}}
	}
	if len(turns) == 0 {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "send {messages:[{role,content},...]} or {message:'...'}"})
		return
	}
	// Cap conversation length so a long-running tab doesn't blow past the
	// model's context window. ~20 messages = 5–10 conversational rounds.
	if len(turns) > 20 {
		turns = turns[len(turns)-20:]
	}

	// v2.12.5: beefed-up system prompt. Small models (e.g. llama3.2:3b) were
	// hallucinating Caddy v1 trivia and inventing directives. Concrete
	// Caddyfile examples plus an explicit "say I don't know" rule helps.
	// v2.12.10: relaxed the "be concise" constraint and added an explicit
	// rule about respecting prior conversation turns. Custom system prompt
	// (settingAISystemPrompt) overrides this default when the user sets one
	// in Settings.
	defaultSystemPrompt := `You are an assistant inside CaddyUI, a web app for managing the Caddy reverse proxy. Caddy v2 ONLY — never reference Caddy v1.

When the user asks for a Caddy config, default to a PRODUCTION-GRADE Caddyfile — not a 3-line minimum viable one. The user already knows the bare minimum is ` + "`" + `reverse_proxy backend:80` + "`" + `; what they want from you is a config that's actually ready to ship. That means: compression, security path blocking, security headers, sensible upstream timeouts, X-Forwarded-* request headers. Only strip back to the minimum when the user explicitly says "just the basics" or "minimal".

The default production template:

  hostname.example.com {
    encode zstd gzip

    @blocked path /.env* /wp-admin* /wp-login* /phpmyadmin* /.git/* /xmlrpc.php
    respond @blocked 403

    header {
      Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
      X-Content-Type-Options "nosniff"
      X-Frame-Options "SAMEORIGIN"
      Referrer-Policy "strict-origin-when-cross-origin"
      X-XSS-Protection "1; mode=block"
    }

    reverse_proxy backend:8080 {
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-Proto {scheme}
      header_up X-Real-IP {remote_host}
    }
  }

App-specific tweaks to apply on top of the default template:

  # Nextcloud — needs CalDAV/CardDAV well-known redirects + WebDAV:
  cloud.example.com {
    encode zstd gzip
    redir /.well-known/carddav /remote.php/dav 301
    redir /.well-known/caldav /remote.php/dav 301
    @blocked path /.env* /wp-admin* /wp-login* /phpmyadmin* /.git/* /xmlrpc.php
    respond @blocked 403
    header {
      Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
      X-Content-Type-Options "nosniff"
      Referrer-Policy "no-referrer"
      X-Frame-Options "SAMEORIGIN"
    }
    reverse_proxy nextcloud:80 {
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-Proto {scheme}
      header_up X-Real-IP {remote_host}
    }
  }

  # HTTPS upstream with self-signed cert + custom Host header (Apache vhost / Unifi):
  internal.example.com {
    encode zstd gzip
    @blocked path /.env* /wp-admin* /wp-login* /phpmyadmin* /.git/* /xmlrpc.php
    respond @blocked 403
    header {
      Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
      X-Content-Type-Options "nosniff"
      X-Frame-Options "SAMEORIGIN"
      Referrer-Policy "strict-origin-when-cross-origin"
    }
    reverse_proxy https://upstream:8443 {
      header_up Host internal.example.com
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-Proto {scheme}
      header_up X-Real-IP {remote_host}
      transport http {
        tls
        tls_insecure_skip_verify
        tls_server_name internal.example.com
        keepalive 30s
        keepalive_idle_conns 50
        dial_timeout 5s
        response_header_timeout 30s
      }
    }
  }

  # WebSocket / SSE / long-poll backend (n8n, Grafana live, monitoring):
  app.example.com {
    encode zstd gzip
    header {
      Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
      X-Content-Type-Options "nosniff"
    }
    reverse_proxy backend:5678 {
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-Proto {scheme}
      header_up X-Real-IP {remote_host}
      flush_interval -1
    }
  }

  # 301/302 redirect (no proxying):
  old.example.com {
    redir https://new.example.com{uri} 301
  }

  # Wildcard cert via DNS-01 (needs the caddy-dns/cloudflare plugin):
  *.example.com, example.com {
    tls {
      dns cloudflare {env.CF_API_TOKEN}
    }
    encode zstd gzip
    reverse_proxy backend:8080 {
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-Proto {scheme}
      header_up X-Real-IP {remote_host}
    }
  }

After the Caddyfile, write 3-6 bullet points explaining what each block does and which CaddyUI form fields map to which directive. The user is filling in form fields next to this chat — they want to know "the encode block = the Compression toggle on the form".

Rules:
- Site blocks ALWAYS start with hostnames followed by a space and an opening brace.
- NEVER invent directives. If you don't know the exact Caddy v2 directive name, say "I'm not certain — check https://caddyserver.com/docs" instead of guessing.
- Output valid Caddyfile syntax — directives like ` + "`" + `reverse_proxy` + "`" + `, ` + "`" + `redir` + "`" + `, ` + "`" + `tls` + "`" + `, ` + "`" + `header` + "`" + `, ` + "`" + `handle` + "`" + `, ` + "`" + `handle_path` + "`" + `, ` + "`" + `respond` + "`" + `, ` + "`" + `file_server` + "`" + `, ` + "`" + `encode` + "`" + `, ` + "`" + `transport http` + "`" + `, ` + "`" + `header_up` + "`" + `, ` + "`" + `flush_interval` + "`" + `. Don't make up new ones.
- Treat earlier messages in the conversation as binding context — when the user says "make one here" or "add to that", refer back to what was discussed instead of inventing an unrelated example.
- Default to PRODUCTION-GRADE Caddyfiles. Strip back to the minimum only when the user explicitly says "minimal" / "just the basics" / "simplest" / "shortest".
- Always include the X-Forwarded-Host / X-Forwarded-Proto / X-Real-IP header_up trio inside reverse_proxy blocks unless the user's app explicitly doesn't want them.
- The user is editing a config in CaddyUI alongside this chat. When relevant, point them at form fields: Domain names, Forward Host/Port, Auto SSL toggle, Managed DNS picker, Upstream Host Header, etc.

CADDYUI APP KNOWLEDGE — answer "where do I configure X" / "how does X work" / "does CaddyUI support X" using this map:

PAGES (left sidebar nav):
- Dashboard (/) — overview cards, traffic stats, all Caddy servers grid, last sync
- Routes:
  - Proxy Hosts (/proxy-hosts) — primary feature; reverse_proxy table; search, bulk toggle, drag-reorder, status filter tabs (All/Enabled/Disabled/Maintenance), tag filter
  - Redirections (/redirection-hosts) — 301/302 redirects, path stripping, sunset dates, wildcard subdomain
  - Advanced (/raw-routes) — raw JSON or Caddyfile snippets for features the form doesn't expose
- Config:
  - Certificates (/certificates) — upload PEM bundles; see ACME/managed certs; expiry tracking
  - Import from Caddy (/import) — pull existing routes from a running Caddy admin endpoint
  - Paste Caddyfile (/caddyfile-import) — convert pasted Caddyfile to UI rows
- System:
  - Analytics (/analytics) — request counts, top hosts, status code breakdown, last-7-days, per-host drill-down
  - Live Traffic (/live-traffic) — real-time tail of incoming requests via Caddy's access log
  - Snapshots (/snapshots) — DB backup/restore + auto-snapshot rotation
  - Activity (/activity) — audit log of user actions
  - Caddy Config (/caddy-config) — view live JSON config from Caddy admin API
  - API (/api/docs) — public REST API reference
  - API Tokens (/api-tokens) — manage tokens for the public REST API
  - Caddy Servers (/servers) — manage multi-server setup; admin only
  - Users (/users) — manage user accounts; admin only
  - Groups (/groups) — bundle users for shared host visibility; admin only
  - Settings (/settings) — global app configuration

SETTINGS SECTIONS (/settings — anchor links: #settings-general etc.):
- General: site title, favicon URL, custom 404 HTML, global maintenance mode, periodic auto-sync interval, activity log retention days, globally stripped response headers, color theme (default / Carbon Orange — v2.12.22+, per-account v2.12.27+)
- AI Assistant: enable toggle, AI provider selector (Ollama local / Ollama Cloud / Anthropic Claude / OpenAI-compatible), per-provider URL/key/model, custom system prompt (this is where the prompt YOU are reading lives — Settings → AI → Custom system prompt)
- SMTP: outbound email for password reset / invite
- Notifications: webhook URL for state-change events
- Time zone: display tz for activity log
- DNS / IPs: Cloudflare API token, server public IP override, public IP version (4/6/auto), trusted_proxies CIDRs
- Captcha: Turnstile / reCAPTCHA for login form
- Security: admin allowlist CIDRs, require 2FA, max login attempts, session days
- Analytics: enable access logs (TCP-forward from Caddy to caddyui:9019)

MULTI-SERVER:
- Each Caddy backend is a row in caddy_servers; CaddyUI manages many at once
- Server picker in top bar (v2.12.28+) switches active context — also reachable on mobile
- "Sync Caddy" pushes the active server's config via Caddy admin /load
- Settings are GLOBAL across all managed servers; proxy/redirect hosts are PER-server (server_id FK)

ROLES:
- admin: everything
- user: own hosts + group-shared visibility (read-only on others')
- view: read-only across the board

FEATURES (broader than just proxy hosts):
- Drag-to-reorder rows on proxy hosts list
- Bulk enable/disable (checkbox + bulk action bar)
- Fuzzy search filter (proxy hosts list — domains, forward_host, tags, notes)
- Per-form search (inside proxy host edit — fuzzy match on labels/placeholders/help text; v2.12.30 hides empty <details> sections so only matches show)
- Per-host maintenance mode + global maintenance mode (Settings)
- Snapshots: manual + auto-rolling DB backup, restore from any snapshot
- Activity log (audit trail with retention)
- Dark/light/auto top-bar toggle + Carbon Orange color theme (Settings → Color theme — synced across devices via users.color_theme)
- ⌘K / Ctrl+K global command palette: search across hosts, redirects, certs, raw routes
- ? keyboard shortcut overlay
- Public REST API at /api/v1/* with token auth (admin generates tokens)
- AI Assistant (this) — backed by your choice of Ollama (local), Ollama Cloud, Anthropic Claude, or any OpenAI-compatible API; supports tool calling that proposes proxy_host / redirection creates and shows a confirmation card before applying

PROXY HOST FORM (form structure roughly mirrored by collapsible <details> sections):
- Identity & SSL: Domain names, Forward Scheme (HTTP/HTTPS), Forward Host, Forward Port, Auto SSL, Force SSL, HTTP/2, www redirect (to_www / to_bare), Certificate (auto-ACME or pick uploaded), Owner, Color tag
- Managed DNS: pick provider (Cloudflare/etc), zone, record name; CaddyUI auto-creates the DNS record on save
- TLS Certificate: load custom PEM, pick CA (Let's Encrypt / ZeroSSL / custom)
- Routing: Path matcher (prefix/exact/regex)
- Block common exploits: ON by default — blocks /.env, /wp-admin, /wp-login, /phpmyadmin, /.git, xmlrpc.php
- Compression: Enable + gzip/zstd/brotli sub-toggles + min size KB + level + prefer gzip + exclude regex
- Security headers: HSTS (subdomains/preload), nosniff, X-Frame-Options, Referrer-Policy, X-XSS-Protection, Permissions-Policy, CSP, CSP-Report-Only
- Custom request/response headers (set + delete) + Strip request/response headers (comma list)
- Forwarded headers: X-Forwarded-Host, X-Forwarded-Proto, X-Real-IP, X-Forwarded-Port, X-Forwarded-Path, etc. (many individual toggles)
- Upstream TLS: Verify cert, Custom CA PEM, TLS server name from Host, TLS server name explicit, TLS min/max version, cipher suites, early data
- Upstream Host Header: override the Host sent upstream (header_up Host XYZ)
- Keepalive: Disable, Max idle conns per host, Max idle conns total, Idle timeout sec, Max lifetime sec, Probes
- Timeouts: Dial timeout, Response header timeout, Request body read timeout, Read header timeout, TLS handshake timeout, Expect-continue timeout, Stream flush interval ms (-1 = SSE/WebSocket flush every byte)
- Authentication: Basic auth users (bcrypt), Access list CIDRs, HTTP basic auth upstream
- Load balancing: Extra upstreams, LB policy (random/round-robin/ip-hash/least-conn/cookie), active + passive health checks, LB cookie config
- Maintenance mode: per-host toggle + Allowed IPs (CIDRs that bypass)
- Notes & Tags (free text + comma-separated tags, tag clicks filter the list)
- Advanced raw config: appended Caddyfile/JSON snippet for features outside the form

When a user asks "how do I do X", first check this map. If X is in CaddyUI, point at the EXACT page → section → field. If X is genuinely not in the form, say so and recommend "Advanced raw config" as the escape hatch.

Most Caddy directives ARE configurable through CaddyUI's proxy host form — do NOT tell the user "you have to manually edit the Caddyfile." Specifically these are all UI-supported:
  - encode (compression): toggle "Enable compression" + zstd/gzip/brotli sub-toggles + min size + level
  - Security path blocking (/.env, /wp-admin, /.git, etc.): "Block common exploits" toggle (always on by default in CaddyUI)
  - Security headers bundle (HSTS / X-Content-Type-Options / X-Frame-Options / Referrer-Policy / X-XSS-Protection / Permissions-Policy / CSP): "Security headers" bundle toggle on the host
  - Strip / set custom request and response headers: "Custom request headers" + "Custom response headers" + "Strip request headers" + "Strip response headers" fields
  - Upstream Host header override: "Upstream Host Header" field (header_up Host XYZ)
  - X-Real-IP / X-Forwarded-Host / X-Forwarded-Proto: enabled by default; toggles in the Forwarded Headers section
  - Upstream TLS (https:// upstreams): "Forward Scheme: HTTPS" + "Verify upstream TLS cert" toggle + "Upstream TLS server name from host" + custom CA PEM
  - Keepalive: "Keepalive max idle conns" + "Keepalive idle timeout sec" + "Disable keepalive" + "Max idle conns per host"
  - Timeouts: "Dial timeout sec" + "Response header timeout sec" + "Request body read timeout sec" + "Read header timeout sec" + "TLS handshake timeout sec" + "Expect-continue timeout sec" + "Stream flush interval ms"
  - Buffering / streaming: "Stream flush interval ms" (use -1 for SSE/streaming, 0 for default buffering)
  - Health check + load balancing: "Extra upstreams" + "LB policy" + active/passive health check fields

When the user asks for "this Caddyfile" → produce form values, not "edit the file manually." If a feature genuinely isn't UI-supported (rare), say so explicitly and point them at the "Advanced config" raw-Caddyfile field as the escape hatch.

If you are NOT sure about a specific Caddy directive or behavior, say so. Hallucinated config is worse than "I don't know."

TOOLS:
You can call tools that ACTUALLY CREATE resources in CaddyUI. The user sees a confirmation card with the parameters and clicks Apply before anything happens — you don't have to ask permission, just call the tool when appropriate.

When to call ` + "`" + `create_proxy_host` + "`" + ` or ` + "`" + `create_redirection` + "`" + `:
- "create a proxy host for X" / "set up X" / "add X" / "make a proxy for X" → create_proxy_host
- "redirect old.com to new.com" / "set up a 301 from X" → create_redirection
- "what's the Caddyfile for X" / "explain X" / "show me how X looks" → just write a Caddyfile snippet, DO NOT call a tool

When you call a tool, do not also write a Caddyfile in the same response — the tool call is the response.`

	systemPrompt := defaultSystemPrompt
	if customPrompt, _ := models.GetSetting(s.DB, settingAISystemPrompt); strings.TrimSpace(customPrompt) != "" {
		systemPrompt = customPrompt
	}

	// v2.12.11: tool definitions sent on every chat turn. Models that
	// don't support tools (older / smaller ones) ignore the field; for
	// qwen2.5/llama3.1+/gemma2 / Claude / GPT-4 the model can decide to
	// emit tool_calls in its response, which the frontend renders as a
	// confirmation card.
	tools := aiToolDefinitions()

	// v2.12.36: dispatch to the configured provider's adapter. Adapters
	// normalize back to the existing {reply, tool_calls, model} contract
	// so the frontend doesn't need to know which backend answered.
	provider, model := activeAIProviderModel(s.DB)

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	var (
		reply   string
		calls   []frontendTC
		callErr error
	)
	switch provider {
	case "anthropic":
		apiKey, _ := models.GetSetting(s.DB, settingAIAnthropicAPIKey)
		if strings.TrimSpace(apiKey) == "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Anthropic API key is empty — set one under Settings → AI assistant."})
			return
		}
		reply, calls, callErr = aiCallAnthropic(ctx, apiKey, model, systemPrompt, turns, tools)
	case "openai":
		apiKey, _ := models.GetSetting(s.DB, settingAIOpenAIAPIKey)
		if strings.TrimSpace(apiKey) == "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "OpenAI API key is empty — set one under Settings → AI assistant."})
			return
		}
		base, _ := models.GetSetting(s.DB, settingAIOpenAIBaseURL)
		if strings.TrimSpace(base) == "" {
			base = "https://api.openai.com/v1"
		}
		reply, calls, callErr = aiCallOpenAI(ctx, base, apiKey, model, systemPrompt, turns, tools)
	case "ollama_cloud":
		apiKey, _ := models.GetSetting(s.DB, settingAIOllamaCloudAPIKey)
		if strings.TrimSpace(apiKey) == "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Ollama Cloud API key is empty — set one under Settings → AI assistant."})
			return
		}
		reply, calls, callErr = aiCallOllama(ctx, "https://ollama.com", apiKey, model, systemPrompt, turns, tools)
	default: // ollama (local)
		baseURL, _ := models.GetSetting(s.DB, settingAIOllamaURL)
		if strings.TrimSpace(baseURL) == "" {
			baseURL = "http://ollama:11434"
		}
		reply, calls, callErr = aiCallOllama(ctx, baseURL, "", model, systemPrompt, turns, tools)
	}

	if callErr != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": callErr.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"reply":      strings.TrimSpace(reply),
		"tool_calls": calls,
		"model":      model,
		"provider":   provider,
	})
}

// frontendTC — v2.12.11: tool-call shape returned to the chat panel for the
// confirmation-card render. Hoisted out of apiAIChat in v2.12.36 so the
// per-provider adapters can return it directly.
type frontendTC struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// aiCallOllama — v2.12.36: send a chat turn to an Ollama-compatible /api/chat
// endpoint. apiKey is empty for local Ollama and a bearer token for Ollama
// Cloud (https://ollama.com). The on-the-wire schema is identical otherwise.
//
// Returns the assistant's text reply, any tool calls the model emitted, and
// an error normalized to mention the upstream by name.
func aiCallOllama(ctx context.Context, baseURL, apiKey, model, systemPrompt string, turns []map[string]string, tools []map[string]any) (string, []frontendTC, error) {
	finalMessages := make([]map[string]string, 0, len(turns)+1)
	finalMessages = append(finalMessages, map[string]string{"role": "system", "content": systemPrompt})
	finalMessages = append(finalMessages, turns...)

	payload := map[string]any{
		"model":    model,
		"stream":   false,
		"messages": finalMessages,
		"tools":    tools,
	}
	pb, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/chat", bytes.NewReader(pb))
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("ollama %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("decode ollama response: %w", err)
	}
	calls := make([]frontendTC, 0, len(out.Message.ToolCalls))
	for _, tc := range out.Message.ToolCalls {
		calls = append(calls, frontendTC{Name: tc.Function.Name, Args: tc.Function.Arguments})
	}
	return out.Message.Content, calls, nil
}

// aiCallAnthropic — v2.12.36: send a chat turn to the Anthropic Messages API.
// Anthropic's schema differs from Ollama/OpenAI in three notable ways:
//   - system prompt is a TOP-LEVEL field, not a system message
//   - tools use `input_schema` not `parameters`, and have no outer `function`
//     wrapper
//   - tool calls come back as content blocks of type "tool_use"
func aiCallAnthropic(ctx context.Context, apiKey, model, systemPrompt string, turns []map[string]string, tools []map[string]any) (string, []frontendTC, error) {
	// Translate the Ollama-flavoured tool definitions to Anthropic's shape.
	anthroTools := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		fn, ok := t["function"].(map[string]any)
		if !ok {
			continue
		}
		anthroTools = append(anthroTools, map[string]any{
			"name":         fn["name"],
			"description":  fn["description"],
			"input_schema": fn["parameters"],
		})
	}

	payload := map[string]any{
		"model":      model,
		"max_tokens": 4096,
		"system":     systemPrompt,
		"messages":   turns,
	}
	if len(anthroTools) > 0 {
		payload["tools"] = anthroTools
	}
	pb, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(pb))
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("anthropic: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("anthropic %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Content []struct {
			Type  string         `json:"type"`
			Text  string         `json:"text"`
			Name  string         `json:"name"`
			Input map[string]any `json:"input"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("decode anthropic response: %w", err)
	}
	var (
		textParts []string
		calls     []frontendTC
	)
	for _, c := range out.Content {
		switch c.Type {
		case "text":
			textParts = append(textParts, c.Text)
		case "tool_use":
			calls = append(calls, frontendTC{Name: c.Name, Args: c.Input})
		}
	}
	return strings.Join(textParts, "\n"), calls, nil
}

// aiCallOpenAI — v2.12.36: send a chat turn to an OpenAI-compatible
// /chat/completions endpoint (also covers OpenRouter, Groq, Together, vLLM,
// LM Studio — anything that exposes the OpenAI schema).
//
// The tool-definition shape matches Ollama's so we reuse it as-is. The
// quirk: tool_calls.function.arguments comes back as a JSON STRING, not an
// object — needs an extra Unmarshal pass.
func aiCallOpenAI(ctx context.Context, baseURL, apiKey, model, systemPrompt string, turns []map[string]string, tools []map[string]any) (string, []frontendTC, error) {
	finalMessages := make([]map[string]string, 0, len(turns)+1)
	finalMessages = append(finalMessages, map[string]string{"role": "system", "content": systemPrompt})
	finalMessages = append(finalMessages, turns...)

	payload := map[string]any{
		"model":    model,
		"messages": finalMessages,
	}
	if len(tools) > 0 {
		payload["tools"] = tools
	}
	pb, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/chat/completions", bytes.NewReader(pb))
	if err != nil {
		return "", nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("openai: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("openai %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"` // JSON-encoded string per OpenAI spec
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, fmt.Errorf("decode openai response: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", nil, nil
	}
	msg := out.Choices[0].Message
	calls := make([]frontendTC, 0, len(msg.ToolCalls))
	for _, tc := range msg.ToolCalls {
		var args map[string]any
		if tc.Function.Arguments != "" {
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
		}
		if args == nil {
			args = map[string]any{}
		}
		calls = append(calls, frontendTC{Name: tc.Function.Name, Args: args})
	}
	return msg.Content, calls, nil
}

// aiToolDefinitions — v2.12.11: schema for every AI-callable tool. Sent on
// every chat turn so the model knows what's available; models without tool
// support silently ignore the field.
func aiToolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"type": "function",
			"function": map[string]any{
				"name":        "create_proxy_host",
				"description": "Create a new proxy host in CaddyUI. Use this when the user asks to actually create / set up / add a proxy host (not just explain or show a config snippet). The user will see a confirmation card with the arguments before this runs.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"domains":        map[string]any{"type": "string", "description": "Comma-separated list of domain names. Wildcards allowed (e.g. '*.example.com,example.com')."},
						"forward_scheme": map[string]any{"type": "string", "enum": []string{"http", "https"}, "description": "Scheme used when proxying to the upstream. Default 'http'."},
						"forward_host":   map[string]any{"type": "string", "description": "Upstream hostname or IP (docker service name like 'adguardhome', or an IP)."},
						"forward_port":   map[string]any{"type": "integer", "description": "Upstream TCP port, 1–65535."},
						"ssl_enabled":    map[string]any{"type": "boolean", "description": "Enable Caddy automatic HTTPS via Let's Encrypt. Default true."},
						"ssl_forced":     map[string]any{"type": "boolean", "description": "Redirect plain HTTP requests to HTTPS. Default true."},
					},
					"required": []string{"domains", "forward_host", "forward_port"},
				},
			},
		},
		{
			"type": "function",
			"function": map[string]any{
				"name":        "create_redirection",
				"description": "Create a new redirection (HTTP 301/302/307/308) in CaddyUI. Use this when the user asks to redirect one hostname to another.",
				"parameters": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"domains":           map[string]any{"type": "string", "description": "Comma-separated source domains (the old hostnames being redirected away)."},
						"forward_scheme":    map[string]any{"type": "string", "enum": []string{"auto", "http", "https"}, "description": "Scheme for the redirect target. 'auto' (default) preserves the request scheme."},
						"forward_domain":    map[string]any{"type": "string", "description": "Target hostname (where the user gets redirected to)."},
						"forward_http_code": map[string]any{"type": "integer", "enum": []int{301, 302, 307, 308}, "description": "Redirect status code. 301 = permanent (default), 302 = temporary, 307/308 preserve method."},
						"preserve_path":     map[string]any{"type": "boolean", "description": "Keep the path+query from the request when redirecting. Default true."},
					},
					"required": []string{"domains", "forward_domain"},
				},
			},
		},
	}
}

// apiAIExecTool — v2.12.11: executes a tool call the AI proposed. Called
// from the frontend after the user confirms via the chat-bubble card. All
// resources are created with admin / global ownership (or current user's
// ownership for non-admins). Every successful exec writes an
// `ai_tool_call` activity-log row so admins can audit what the AI did.
func (s *Server) apiAIExecTool(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled, _ := models.GetSetting(s.DB, settingAIEnabled)
	if enabled != "1" {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "AI assist is disabled."})
		return
	}
	cu := s.currentUser(r)
	if cu == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	var body struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "could not parse JSON body"})
		return
	}
	sid := s.currentServerID(r)
	var ownerID int64
	if cu.Role != models.RoleAdmin {
		ownerID = cu.ID
	}

	switch body.Name {
	case "create_proxy_host":
		ph := &models.ProxyHost{
			Domains:       toolStr(body.Args, "domains"),
			ForwardScheme: toolStrDefault(body.Args, "forward_scheme", "http"),
			ForwardHost:   toolStr(body.Args, "forward_host"),
			ForwardPort:   toolInt(body.Args, "forward_port"),
			SSLEnabled:    toolBoolDefault(body.Args, "ssl_enabled", true),
			SSLForced:     toolBoolDefault(body.Args, "ssl_forced", true),
			Enabled:       true,
		}
		if ph.Domains == "" || ph.ForwardHost == "" || ph.ForwardPort == 0 {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing required argument (domains, forward_host, forward_port)"})
			return
		}
		// Domain conflict guard — same as the form path.
		if conflict, err := models.DomainsConflict(s.DB, sid, ph.DomainList(), 0, 0); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "validate domains: " + err.Error()})
			return
		} else if conflict != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("domain %q is already used by another proxy or redirect on this server", conflict)})
			return
		}
		id, err := models.CreateProxyHost(s.DB, sid, ownerID, ph)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "create proxy host: " + err.Error()})
			return
		}
		_ = models.LogActivity(s.DB, sid, cu.Email, "ai_tool_call", fmt.Sprintf("proxy:%d", id), "create_proxy_host: "+ph.Domains, true)
		s.trySyncCaddy(sid, ph.CertificateID != 0)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"summary": fmt.Sprintf("✓ Created proxy host #%d — %s → %s:%d", id, ph.Domains, ph.ForwardHost, ph.ForwardPort),
			"url":     fmt.Sprintf("/proxy-hosts/%d/edit", id),
		})

	case "create_redirection":
		code := toolIntDefault(body.Args, "forward_http_code", 301)
		if code != 301 && code != 302 && code != 307 && code != 308 {
			code = 301
		}
		rh := &models.RedirectionHost{
			Domains:         toolStr(body.Args, "domains"),
			ForwardScheme:   toolStrDefault(body.Args, "forward_scheme", "auto"),
			ForwardDomain:   toolStr(body.Args, "forward_domain"),
			ForwardHTTPCode: code,
			PreservePath:    toolBoolDefault(body.Args, "preserve_path", true),
			SSLEnabled:      true,
			SSLForced:       true,
			Enabled:         true,
		}
		if rh.Domains == "" || rh.ForwardDomain == "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing required argument (domains, forward_domain)"})
			return
		}
		if conflict, err := models.DomainsConflict(s.DB, sid, rh.DomainList(), 0, 0); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "validate domains: " + err.Error()})
			return
		} else if conflict != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("domain %q is already used by another proxy or redirect on this server", conflict)})
			return
		}
		id, err := models.CreateRedirectionHost(s.DB, sid, ownerID, rh)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "create redirection: " + err.Error()})
			return
		}
		_ = models.LogActivity(s.DB, sid, cu.Email, "ai_tool_call", fmt.Sprintf("redirect:%d", id), "create_redirection: "+rh.Domains+" → "+rh.ForwardDomain, true)
		s.trySyncCaddy(sid, false)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"summary": fmt.Sprintf("✓ Created redirection #%d — %s → %s (%d)", id, rh.Domains, rh.ForwardDomain, code),
			"url":     fmt.Sprintf("/redirection-hosts/%d/edit", id),
		})

	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unknown tool: " + body.Name})
	}
}

// toolStr / toolInt / toolBool — v2.12.11: tiny helpers that pull strongly-
// typed values out of the model-supplied tool argument map. Models can be
// loose with types (numbers as strings, booleans as strings, etc.), so
// these tolerate the common drift cases.
func toolStr(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	if v, ok := args[key]; ok {
		switch s := v.(type) {
		case string:
			return strings.TrimSpace(s)
		case float64:
			return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", s), "0"), ".")
		case bool:
			if s {
				return "true"
			}
			return "false"
		}
	}
	return ""
}
func toolStrDefault(args map[string]any, key, def string) string {
	if v := toolStr(args, key); v != "" {
		return v
	}
	return def
}
func toolInt(args map[string]any, key string) int {
	if args == nil {
		return 0
	}
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case string:
			i, _ := strconv.Atoi(strings.TrimSpace(n))
			return i
		}
	}
	return 0
}
func toolIntDefault(args map[string]any, key string, def int) int {
	if v := toolInt(args, key); v != 0 {
		return v
	}
	return def
}
func toolBoolDefault(args map[string]any, key string, def bool) bool {
	if args == nil {
		return def
	}
	if v, ok := args[key]; ok {
		switch b := v.(type) {
		case bool:
			return b
		case string:
			s := strings.ToLower(strings.TrimSpace(b))
			if s == "true" || s == "1" || s == "yes" {
				return true
			}
			if s == "false" || s == "0" || s == "no" {
				return false
			}
		}
	}
	return def
}

// apiPreviewProxyHost — live previews of both the readable Caddyfile excerpt
// and generated route JSON for the in-progress proxy-host edit form. Reuses
// the same form parser as createProxyHost so unsaved changes are represented
// in both views.
//
// v2.11.17: pads required fields with visible placeholders so a partly-
// filled form still renders a representative preview. The previous
// version leaked the raw `strconv.Atoi: parsing "": invalid syntax`
// from the strict parser into the user's face the moment they expanded
// the panel before filling in Forward port.
func (s *Server) apiPreviewProxyHost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// v2.11.18: the frontend sends FormData (multipart). r.ParseForm only
	// handles application/x-www-form-urlencoded bodies; for multipart we
	// also need ParseMultipartForm. Calling both means r.Form is populated
	// regardless of how the JS chose to encode the request.
	_ = r.ParseForm()
	_ = r.ParseMultipartForm(32 << 20)
	pad := func(key, fallback string) {
		if strings.TrimSpace(r.Form.Get(key)) == "" {
			r.Form.Set(key, fallback)
			if r.PostForm != nil {
				r.PostForm.Set(key, fallback)
			}
		}
	}
	pad("forward_port", "0")
	pad("forward_host", "(your-upstream)")
	pad("domains", "example.com")

	p, err := parseProxyHostForm(r)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	p.ExtraUpstreams = marshalExtraUpstreams(r)
	var previewHandlers []any
	if r.FormValue("basicauth_enabled") == "on" {
		p.BasicAuthEnabled = true
		users := previewBasicAuthUsers(r)
		usersJSON, _ := json.Marshal(users)
		p.BasicAuthUsers = string(usersJSON)
		if authHandler := buildBasicAuthPreviewHandler(users, p.BasicAuthRealm); authHandler != nil {
			previewHandlers = append(previewHandlers, authHandler)
		}
	}
	advancedError := ""
	var previewOverrides map[string]any
	if strings.TrimSpace(p.AdvancedConfig) != "" {
		if validationError := validateProxyAdvancedDirectives(p.AdvancedConfig); validationError != "" {
			advancedError = validationError
		} else {
			caddyClient := s.Caddy
			if s.DB != nil {
				caddyClient = s.caddyForRequest(r)
			}
			if caddyClient == nil {
				advancedError = "Caddy adapter is unavailable"
			} else if handlers, overrides, adaptErr := s.adaptProxyAdvancedWithClient(caddyClient, *p); adaptErr != nil {
				advancedError = adaptErr.Error()
			} else {
				previewHandlers = append(previewHandlers, handlers...)
				previewOverrides = overrides
			}
		}
	}
	previewProxy := *p
	if previewProxy.APIKeyValue != "" {
		previewProxy.APIKeyValue = previewRedacted
	}
	if previewProxy.LBCookieSecret != "" {
		previewProxy.LBCookieSecret = previewRedacted
	}
	if previewProxy.HTTPBasicAuthUpstream != "" {
		previewProxy.HTTPBasicAuthUpstream = "redacted:redacted"
	}
	if previewProxy.HealthCheckBasicAuth != "" {
		previewProxy.HealthCheckBasicAuth = "redacted:redacted"
	}
	previewProxy.ForwardProxyURL = redactPreviewURL(previewProxy.ForwardProxyURL)
	previewProxy.ForwardAuthURL = redactPreviewURL(previewProxy.ForwardAuthURL)
	route := caddy.BuildProxyRoute(previewProxy, previewHandlers)
	caddy.MergeReverseProxyOverrides(route, previewOverrides)
	route = redactProxyRoutePreview(route).(map[string]any)
	caddyfile := caddy.RenderProxyHostCaddyfileWithCertificate(*p, s.certificateForCaddyfile(p.CertificateID))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	response := map[string]any{"route": route, "caddyfile": caddyfile}
	if advancedError != "" {
		response["advanced_error"] = advancedError
	}
	_ = enc.Encode(response)
}

// globalSearch — v2.11.5: ⌘K / Ctrl+K command palette. Returns a flat list of
// every proxy host, redirection, raw route, and certificate visible to the
// current user on the active server. The frontend caches the result and
// filters client-side; one fetch per palette open (with a 60-second
// freshness window).
func (s *Server) globalSearch(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	if cu == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := cu.Role == models.RoleAdmin
	viewerID := cu.ID
	peers := s.groupPeerIDs(r)
	sid := s.currentServerID(r)

	type item struct {
		Type  string `json:"type"`
		ID    int64  `json:"id"`
		Label string `json:"label"`
		Sub   string `json:"sub"`
		URL   string `json:"url"`
	}
	items := make([]item, 0, 256)

	if hosts, err := models.ListProxyHosts(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, h := range hosts {
			items = append(items, item{
				Type:  "proxy",
				ID:    h.ID,
				Label: h.Domains,
				Sub:   fmt.Sprintf("→ %s:%d", h.ForwardHost, h.ForwardPort),
				URL:   fmt.Sprintf("/proxy-hosts/%d/edit", h.ID),
			})
		}
	}
	if redirs, err := models.ListRedirectionHosts(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, h := range redirs {
			items = append(items, item{
				Type:  "redirect",
				ID:    h.ID,
				Label: h.Domains,
				Sub:   fmt.Sprintf("→ %s://%s (%d)", h.ForwardScheme, h.ForwardDomain, h.ForwardHTTPCode),
				URL:   fmt.Sprintf("/redirection-hosts/%d/edit", h.ID),
			})
		}
	}
	if raws, err := models.ListRawRoutes(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, rr := range raws {
			label := rr.Label
			if label == "" {
				label = fmt.Sprintf("Advanced route #%d", rr.ID)
			}
			items = append(items, item{
				Type:  "raw",
				ID:    rr.ID,
				Label: label,
				Sub:   "Advanced route",
				URL:   fmt.Sprintf("/raw-routes/%d/edit", rr.ID),
			})
		}
	}
	if certs, err := models.ListCertificatesForUser(s.DB, sid, viewerID, isAdmin, peers); err == nil {
		for _, c := range certs {
			items = append(items, item{
				Type:  "cert",
				ID:    c.ID,
				Label: c.Name,
				Sub:   c.Domains,
				URL:   fmt.Sprintf("/certificates/%d/edit", c.ID),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": items})
}

func (s *Server) apiUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	cu := s.currentUser(r)
	isAdmin := cu != nil && cu.Role == models.RoleAdmin
	var viewerID int64
	if cu != nil {
		viewerID = cu.ID
	}
	sid := s.currentServerID(r)
	hosts, err := models.ListProxyHostSummaries(s.DB, sid, viewerID, isAdmin, s.groupPeerIDs(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Ask Caddy's admin API for its own upstream health data.
	// This is the authoritative source — Caddy can reach Docker-internal hosts
	// by name (e.g. "gitlab", "snipeit-app") that CaddyUI cannot resolve.
	// Falls back to direct probe only for upstreams not yet in Caddy's config.
	caddyUpstreams := map[string]caddyUpstreamInfo{}
	if srv, err := models.GetCaddyServer(s.DB, sid); err == nil {
		caddyUpstreams = fetchCaddyUpstreams(srv.AdminURL)
	}

	results := make([]upstreamHealthResult, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{Timeout: 3 * time.Second}

	for i, h := range hosts {
		results[i] = upstreamHealthResult{ID: h.ID, Domains: h.Domains}
		if !h.Enabled {
			results[i].Status = "disabled"
			continue
		}
		// v2.28.0 (issue #39): monitoring switched off for this host. Reading
		// Caddy's own upstream map would be harmless, but reporting a verdict
		// from it would contradict the UI's "monitoring off" state, and the
		// fallback branch below would emit exactly the probe traffic the
		// operator asked us to stop. Skip the host entirely.
		if h.MonitoringDisabled() {
			results[i].Status = "off"
			results[i].Error = "monitoring disabled for this host"
			continue
		}

		// Check Caddy's upstream map first (host:port key).
		key := fmt.Sprintf("%s:%d", h.ForwardHost, h.ForwardPort)
		if info, ok := caddyUpstreams[key]; ok {
			if info.Fails > 0 {
				results[i].Status = "error"
				results[i].Error = fmt.Sprintf("%d failed health check(s)", info.Fails)
			} else {
				results[i].Status = "ok"
			}
			continue
		}

		// Not in Caddy's upstream list yet (newly added / not yet synced,
		// or using an unmanaged handler the /reverse_proxy/upstreams API
		// doesn't expose). For Docker-internal backends (no dots in the
		// hostname — e.g. "status-server", "snipeit-app") a direct probe
		// from the caddyui container will fail with "no such host" since
		// caddyui usually isn't on the target's Docker network. Don't flag
		// that as error — mark it "unknown" (grey dot) so users don't see
		// a red "down" badge on a backend that's actually working. For
		// dotted hostnames (e.g. "api.example.com") we still try the probe.
		if isInternalHostname(h.ForwardHost) {
			results[i].Status = "unknown"
			results[i].Error = "caddyui cannot resolve " + h.ForwardHost + " — check via Caddy admin"
			continue
		}
		// Fall back to a direct probe for public / dotted hostnames.
		wg.Add(1)
		go func(idx int, h models.ProxyHost) {
			defer wg.Done()
			url := fmt.Sprintf("%s://%s:%d/", h.ForwardScheme, h.ForwardHost, h.ForwardPort)
			start := time.Now()
			resp, err2 := client.Head(url)
			if err2 != nil {
				resp, err2 = client.Get(url)
			}
			latency := time.Since(start).Milliseconds()
			if resp != nil {
				_ = resp.Body.Close()
			}
			mu.Lock()
			defer mu.Unlock()
			if err2 != nil {
				// DNS errors → "unknown" not "error": caddyui's network
				// namespace may legitimately not be able to resolve the
				// name even though Caddy can.
				if isDNSError(err2) {
					results[idx].Status = "unknown"
					results[idx].Error = err2.Error()
				} else {
					results[idx].Status = "error"
					results[idx].Error = err2.Error()
				}
			} else {
				results[idx].Status = "ok"
				results[idx].LatencyMS = latency
			}
		}(i, h)
	}

	wg.Wait()

	// Layer in cached app-response health (HTTPS GET / from the app-health
	// poller). Read under the RW lock; the poller writes on its own cadence
	// so this is a cheap map lookup per host. Hosts we haven't polled yet
	// (e.g. first ~60s after boot, or just-created hosts) simply leave
	// AppStatus empty — the UI renders "checking…" in that case.
	s.appHealthMu.RLock()
	for i := range results {
		if e, ok := s.appHealth[results[i].ID]; ok {
			results[i].AppStatus = e.Status
			results[i].AppCode = e.Code
			results[i].AppLatencyMS = e.LatencyMS
			results[i].AppError = e.Error
		}
	}
	s.appHealthMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

// caddyUpstreamInfo holds health data from Caddy's /reverse_proxy/upstreams API.
type caddyUpstreamInfo struct {
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
}

// isInternalHostname returns true when the forward host looks like a Docker
// service name or short intranet hostname — i.e. no dots, not an IP literal,
// not "localhost". In that case caddyui (in its own container) almost
// certainly cannot resolve it, but Caddy on the target network can. Use this
// to downgrade health-probe results from "error" to "unknown" so the UI
// doesn't flag working backends as down.
func isInternalHostname(host string) bool {
	if host == "" || host == "localhost" {
		return false
	}
	if strings.Contains(host, ".") {
		return false
	}
	// IPv6 without brackets or with scope? Anything with a colon is unusual
	// in ForwardHost (we store port separately) — treat as external.
	if strings.Contains(host, ":") {
		return false
	}
	return true
}

// isDNSError returns true when err is a DNS resolution failure (as opposed
// to a connection refused / timeout / TLS error). DNS failure from the
// caddyui container doesn't imply the backend is down — Caddy on a
// different Docker network may resolve it fine.
func isDNSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "server misbehaving") ||
		strings.Contains(s, "Temporary failure in name resolution")
}

// fetchCaddyUpstreams queries the Caddy admin API for current upstream health.
// Returns a map keyed by "host:port" (matching ProxyHost.ForwardHost:ForwardPort).
func fetchCaddyUpstreams(adminURL string) map[string]caddyUpstreamInfo {
	out := map[string]caddyUpstreamInfo{}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(adminURL + "/reverse_proxy/upstreams")
	if err != nil || resp.StatusCode != http.StatusOK {
		return out
	}
	defer resp.Body.Close()
	var list []caddyUpstreamInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err != nil {
		return out
	}
	for _, u := range list {
		out[u.Address] = u
	}
	return out
}

// apiCaddyUpstreams proxies Caddy's /reverse_proxy/upstreams endpoint, returning
// raw upstream health data from Caddy's admin API.
// Returns JSON: {"upstreams": [...], "error": "..."}
func (s *Server) apiCaddyUpstreams(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sid := s.currentServerID(r)
	srv, err := models.GetCaddyServer(s.DB, sid)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"upstreams": nil, "error": err.Error()})
		return
	}
	cl := caddy.New(srv.AdminURL, srv.AdminUsername, srv.AdminPassword)
	upstreams, err := cl.GetUpstreamHealth(ctx)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"upstreams": nil, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"upstreams": upstreams})
}

// apiTestUpstream checks whether a given upstream host:port is reachable.
// Accepts POST with form fields: host, port, scheme (http/https).
// Returns JSON: {ok: bool, status: int, latency_ms: int, error: string}.
func (s *Server) apiTestUpstream(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Accept both multipart/form-data (FormData from JS) and
	// application/x-www-form-urlencoded. r.FormValue auto-detects when
	// r.Form is still nil — calling r.ParseForm() first would short-circuit
	// the multipart path and leave the fields empty.
	host := strings.TrimSpace(r.FormValue("host"))
	port := strings.TrimSpace(r.FormValue("port"))
	scheme := strings.TrimSpace(r.FormValue("scheme"))
	if host == "" || port == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "host and port are required"})
		return
	}
	if scheme != "https" {
		scheme = "http"
	}
	targetURL := fmt.Sprintf("%s://%s:%s/", scheme, host, port)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	resp, err := client.Get(targetURL)
	latencyMs := time.Since(start).Milliseconds()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		// v2.9.212: surface actionable hints for the most common failure
		// classes so users don't have to interpret raw Go net errors.
		// DNS failures from inside the caddyui container are extremely
		// common when targeting LAN device hostnames (NetBIOS / mDNS / a
		// router's DHCP-resolved name) — the Caddy that will actually
		// proxy to it may resolve fine while caddyui's container can't.
		hint := ""
		msg := err.Error()
		switch {
		case isDNSError(err):
			hint = "DNS lookup failed inside the CaddyUI container. The hostname may resolve fine for the actual Caddy server but not from CaddyUI's DNS resolver. Try the upstream's IP address directly, add `--add-host=" + host + ":<ip>` to the CaddyUI container, or point the container at your LAN DNS with `--dns=<router-ip>`."
		case strings.Contains(msg, "x509") || strings.Contains(msg, "tls:") || strings.Contains(msg, "certificate"):
			hint = "TLS handshake failed even with cert verification disabled. The upstream may not be listening on " + port + " over TLS, or it speaks plain HTTP. Try scheme=http instead of https."
		case strings.Contains(msg, "connection refused"):
			hint = "TCP connection refused — the upstream isn't listening on " + host + ":" + port + ", or a firewall is blocking the CaddyUI container from reaching it."
		case strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "deadline exceeded"):
			hint = "Request timed out after 5s. Upstream may be unreachable from the CaddyUI container's network, or it's too slow to respond."
		}
		out := map[string]any{
			"ok":         false,
			"latency_ms": latencyMs,
			"error":      msg,
		}
		if hint != "" {
			out["hint"] = hint
		}
		json.NewEncoder(w).Encode(out)
		return
	}
	resp.Body.Close()
	json.NewEncoder(w).Encode(map[string]any{
		"ok":         resp.StatusCode < 500,
		"status":     resp.StatusCode,
		"latency_ms": latencyMs,
		"error":      "",
	})
}

// apiValidateRawRoute checks whether a draft raw route is shaped correctly
// before it's saved. Accepts either form field:
//   - caddyfile_src: a Caddyfile block — runs through Caddy's /adapt which
//     parses + validates Caddyfile syntax without applying anything.
//   - json_data: raw JSON — done client-side (well, server-side parse)
//     because Caddy's admin API has no JSON-only validate mode in v2.7+.
//     We surface JSON parse errors and structural-shape errors (must have
//     match/handle keys), but a route that's syntactically valid JSON yet
//     semantically wrong won't be caught here — that surfaces at sync time.
//
// v2.9.228 originally posted to /load?validate_only=true thinking that
// query param was honoured. Caddy ignores it entirely, so the synthetic
// config was applied to the running instance, polluting autosave.json
// with a `_caddyui_validate` ghost server. v2.9.233 drops that path.
func (s *Server) apiValidateRawRoute(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	respond := func(ok bool, msg string) {
		out := map[string]any{"ok": ok}
		if msg != "" {
			out["error"] = msg
		}
		_ = json.NewEncoder(w).Encode(out)
	}
	cfSrc := strings.TrimSpace(r.FormValue("caddyfile_src"))
	jsonData := strings.TrimSpace(r.FormValue("json_data"))
	if cfSrc != "" {
		// Caddy's /adapt parses Caddyfile syntax and runs the adapter
		// pipeline — that catches the bulk of bugs (unknown directives,
		// missing args, malformed blocks). It does NOT apply the config
		// to Caddy's running state.
		_, _, err := s.adaptRawRouteCaddyfile(s.caddyForRequest(r), cfSrc)
		if err != nil {
			respond(false, "Caddyfile rejected by Caddy: "+err.Error())
			return
		}
		// If Caddyfile is fine and JSON is empty (most common case), we're
		// done. If JSON is also filled, fall through to validate it too.
		if jsonData == "" {
			respond(true, "")
			return
		}
	}
	if jsonData == "" {
		respond(false, "Provide a Caddyfile block or JSON to validate.")
		return
	}
	// JSON-only validation: parse + structural check.
	var probe any
	if err := json.Unmarshal([]byte(jsonData), &probe); err != nil {
		respond(false, "Invalid JSON: "+err.Error())
		return
	}
	checkRoute := func(m map[string]any) string {
		if _, ok := m["handle"]; !ok {
			return `route is missing "handle" array`
		}
		if h, ok := m["handle"].([]any); !ok || len(h) == 0 {
			return `"handle" must be a non-empty array`
		}
		// match is optional — a route with no matcher matches everything.
		return ""
	}
	switch v := probe.(type) {
	case map[string]any:
		if msg := checkRoute(v); msg != "" {
			respond(false, msg)
			return
		}
	case []any:
		if len(v) == 0 {
			respond(false, "Route JSON array is empty.")
			return
		}
		for i, e := range v {
			m, ok := e.(map[string]any)
			if !ok {
				respond(false, fmt.Sprintf("entry %d is not an object", i))
				return
			}
			if msg := checkRoute(m); msg != "" {
				respond(false, fmt.Sprintf("entry %d: %s", i, msg))
				return
			}
		}
	default:
		respond(false, "Route JSON must be an object or array of route objects.")
		return
	}
	respond(true, "")
}
