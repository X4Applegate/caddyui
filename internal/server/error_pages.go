package server

import (
	"fmt"
	"strings"
)

// errorPageStatuses lists the HTTP status codes CaddyUI injects a branded
// error page for. 502/503/504 fire when a reverse_proxy upstream is down,
// overloaded, or timing out — the most useful ones to humanise since
// self-hosters hit them during deploys and the stock Caddy response
// ("502 Bad Gateway") gives operators nothing to grep for. 404 catches
// handler-raised not-found (e.g. file_server misses, proxied app 404s).
//
// Keep the list small and stable: every status here produces a ~2KB HTML
// blob in Caddy's config, so adding 5xx wildcards would bloat the JSON.
var errorPageStatuses = []int{404, 502, 503, 504}

// errorPageTitles maps each status to the big headline on the page. Kept
// separate from the body so we can render consistent typography without
// embedding status-specific strings in Caddy placeholders.
var errorPageTitles = map[int]string{
	404: "Not found",
	502: "Bad gateway",
	503: "Service unavailable",
	504: "Gateway timeout",
}

// errorPageMessages maps each status to a short human explanation of what
// probably went wrong and what to do next. Written for the person who hit
// the URL, not the ops team — ops gets the error ID + timestamp in the
// footer to correlate with logs.
var errorPageMessages = map[int]string{
	404: "The page you were looking for does not exist on this server. Check the URL for typos, or go back to the previous page.",
	502: "The server is running, but the application behind it is not responding correctly. This usually means the app crashed or is still starting up.",
	503: "The server is temporarily unable to handle your request. The application may be overloaded, restarting, or undergoing maintenance. Please try again in a minute.",
	504: "The server is running but the application behind it did not respond in time. This usually means the app is very slow or stuck processing something else.",
}

// buildErrorPageRoutes returns the Caddy JSON routes block that goes under
// apps.http.servers.srv0.errors.routes. One route per status code; each
// matches on {http.error.status_code} via the expression matcher and
// responds with a static HTML page that includes:
//
//   - the status code and title
//   - a short human explanation
//   - Caddy's generated {http.error.id} (9-char correlation ID, auto-set
//     by the handler subsystem — useful for grepping access logs)
//   - the current timestamp in HTTP-Date form (from {time.now.http})
//
// The {err.*} shortcuts only work through the Caddyfile adapter; raw JSON
// requires the full {http.error.*} placeholder path. Learned this the hard
// way when the 502 page rendered with a blank body — match never fired.
//
// No customisation UI for v2.4.12 — scope is "hardcoded default only" per
// the feature scoping call. Later versions may promote this to a template
// admins can edit in /settings.
func buildErrorPageRoutes() []any {
	routes := make([]any, 0, len(errorPageStatuses))
	for _, code := range errorPageStatuses {
		html := renderErrorPageHTML(code, errorPageTitles[code], errorPageMessages[code])
		routes = append(routes, map[string]any{
			"match": []any{
				map[string]any{
					// Caddy's expression matcher uses CEL. Compare as int
					// (no quotes around the number).
					"expression": fmt.Sprintf("{http.error.status_code} == %d", code),
				},
			},
			"handle": []any{
				map[string]any{
					"handler":     "static_response",
					"status_code": fmt.Sprintf("%d", code),
					"headers": map[string]any{
						// text/html so browsers render our layout instead
						// of treating it as plaintext. Cache-Control: no-store
						// so intermediaries don't pin an old error page past
						// the outage.
						"Content-Type":  []any{"text/html; charset=utf-8"},
						"Cache-Control": []any{"no-store"},
					},
					"body": html,
				},
			},
		})
	}
	return routes
}

// renderErrorPageHTML builds the HTML body for a single status code. Kept
// as a plain string concat (no template) because the content is small,
// static, and needs to be embeddable in Caddy JSON — the simpler the
// escaping story, the better.
//
// Placeholders Caddy substitutes at serve time:
//
//	{http.error.id}   — 9-char random correlation ID Caddy logs per request
//	{time.now.http}   — current UTC time in HTTP-Date format
//	                    (e.g. "Thu, 23 Apr 2026 05:07:23 GMT")
func renderErrorPageHTML(code int, title, message string) string {
	// Inline CSS keeps the page self-contained — error pages must render
	// even if /static is unreachable (which it usually is during a 502).
	// Style roughly matches CaddyUI's Tailwind palette (ink-700, brand-600)
	// so the branded page feels consistent with the admin UI.
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>`)
	b.WriteString(fmt.Sprintf("%d %s", code, title))
	b.WriteString(`</title>
<style>
  :root { color-scheme: light dark; }
  html, body { margin: 0; padding: 0; height: 100%; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: #f7f7f8;
    color: #1f2937;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    max-width: 520px;
    margin: 2rem;
    padding: 2.5rem 2rem;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 16px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    text-align: center;
  }
  .code {
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #6b7280;
    margin-bottom: 0.75rem;
  }
  h1 {
    margin: 0 0 0.75rem;
    font-size: 1.75rem;
    font-weight: 600;
    color: #111827;
  }
  p {
    margin: 0 0 1.25rem;
    font-size: 0.95rem;
    line-height: 1.55;
    color: #4b5563;
  }
  .meta {
    margin-top: 1.5rem;
    padding-top: 1.25rem;
    border-top: 1px solid #f3f4f6;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.75rem;
    color: #9ca3af;
    display: grid;
    gap: 0.25rem;
  }
  .meta span { word-break: break-all; }
  @media (prefers-color-scheme: dark) {
    body { background: #0f172a; color: #e5e7eb; }
    .card { background: #1e293b; border-color: #334155; }
    h1 { color: #f1f5f9; }
    p { color: #cbd5e1; }
    .code { color: #94a3b8; }
    .meta { border-top-color: #334155; color: #64748b; }
  }
</style>
</head>
<body>
  <div class="card">
    <div class="code">`)
	b.WriteString(fmt.Sprintf("Error %d", code))
	b.WriteString(`</div>
    <h1>`)
	b.WriteString(title)
	b.WriteString(`</h1>
    <p>`)
	b.WriteString(message)
	b.WriteString(`</p>
    <div class="meta">
      <span>Error ID: {http.error.id}</span>
      <span>Time: {time.now.http}</span>
    </div>
  </div>
</body>
</html>`)
	return b.String()
}

// applyErrorPages injects the branded error pages into Caddy's JSON config
// under apps.http.servers.srv0.errors.routes. Called from syncCaddy right
// alongside applyRoutes/applyListen so every config push carries the same
// error handlers.
//
// Safe to call repeatedly — it always overwrites srv0.errors with CaddyUI's
// canonical block. If a future version lets admins disable the branded
// pages, this is where the opt-out would live.
func applyErrorPages(cfg map[string]any) {
	apps := ensureMap(cfg, "apps")
	httpApp := ensureMap(apps, "http")
	servers := ensureMap(httpApp, "servers")
	srv := ensureMap(servers, "srv0")
	srv["errors"] = map[string]any{
		"routes": buildErrorPageRoutes(),
	}
}
