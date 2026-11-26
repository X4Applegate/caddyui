// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Caddyfile export safety (issue #184 review). The exporter concatenates
// text from many owners into one file, and Caddy expands {$ENV} across the
// raw file before lexing, so a value that is harmless inside its own block
// can still rewrite a neighbour's. Every emitted block is therefore checked
// with checkCaddyfileSites, which mirrors Caddy's own lexer, and every
// user value written outside a comment goes through caddyfileToken or
// caddyfileBareSafe. Anything that fails is emitted fail-closed.

// errCaddyfileUnsafe is returned by the structural checks below.
var errCaddyfileUnsafe = errors.New("caddyfile text is not self-contained")

// cfToken is one Caddyfile token as Caddy's lexer would produce it.
type cfToken struct {
	text   string
	quoted bool
	line   int
}

// lexCaddyfile tokenizes src the way Caddy v2.11's caddyfile lexer does
// (caddyconfig/caddyfile/lexer.go, Apache-2.0), with two deliberate
// differences that only ever refuse input: heredocs are an error, and so
// is input that ends inside a quote or after a line-continuation backslash
// (Caddy would let those run into whatever text follows). A byte-order mark
// is refused too: Caddy drops one only at the very start of the file, and
// these snippets never are.
func lexCaddyfile(src string) ([]cfToken, error) {
	if !utf8.ValidString(src) || strings.ContainsRune(src, '\uFEFF') {
		return nil, errCaddyfileUnsafe
	}
	runes := []rune(src)
	pos, line, skipped := 0, 1, 0
	var toks []cfToken
	for {
		var val []rune
		var comment, quoted, btQuoted, escaped bool
		tok := cfToken{line: line}
		done := false
		for !done {
			if pos >= len(runes) {
				if quoted || btQuoted || escaped {
					return nil, errCaddyfileUnsafe
				}
				if len(val) > 0 {
					tok.text = string(val)
					toks = append(toks, tok)
				}
				return toks, nil
			}
			ch := runes[pos]
			pos++
			if !quoted && !btQuoted && len(val) > 1 && val[0] == '<' && val[1] == '<' {
				return nil, errCaddyfileUnsafe // heredoc
			}
			if !escaped && !btQuoted && ch == '\\' {
				escaped = true
				continue
			}
			if quoted || btQuoted {
				if quoted && escaped {
					if ch != '"' {
						val = append(val, '\\')
					}
					escaped = false
				} else if (quoted && ch == '"') || (btQuoted && ch == '`') {
					tok.text, tok.quoted = string(val), true
					toks = append(toks, tok)
					done = true
					continue
				}
				if ch == '\n' {
					line += 1 + skipped
					skipped = 0
				}
				val = append(val, ch)
				continue
			}
			if unicode.IsSpace(ch) {
				if ch == '\r' {
					continue
				}
				if ch == '\n' {
					if escaped {
						skipped++
						escaped = false
					} else {
						line += 1 + skipped
						skipped = 0
					}
					comment = false
				}
				if len(val) > 0 {
					tok.text = string(val)
					toks = append(toks, tok)
					done = true
				}
				continue
			}
			if ch == '#' && len(val) == 0 {
				comment = true
			}
			if comment {
				continue
			}
			if len(val) == 0 {
				tok = cfToken{line: line}
				if ch == '"' {
					quoted = true
					continue
				}
				if ch == '`' {
					btQuoted = true
					continue
				}
			}
			if escaped {
				if ch == '<' {
					return nil, errCaddyfileUnsafe // escaped heredoc marker
				}
				val = append(val, '\\')
				escaped = false
			}
			val = append(val, ch)
		}
	}
}

// checkCaddyfileSites reports how many site blocks src holds when it is
// safe to concatenate with other such text: no {$ anywhere (Caddy expands
// it across the whole file before lexing), no import, braces balanced, and
// every top-level block is a site — addresses followed by `{ … }` — rather
// than a global options block, snippet or named route, with nothing left
// outside a block.
func checkCaddyfileSites(src string) (int, error) {
	if strings.Contains(src, "{$") {
		return 0, errCaddyfileUnsafe
	}
	toks, err := lexCaddyfile(src)
	if err != nil {
		return 0, err
	}
	depth, addrs, sites := 0, 0, 0
	for _, t := range toks {
		switch {
		case t.text == "import":
			return 0, errCaddyfileUnsafe
		case t.text == "{" && !t.quoted:
			if depth == 0 {
				if addrs == 0 {
					return 0, errCaddyfileUnsafe
				}
				sites++
				addrs = 0
			}
			depth++
		case t.text == "}" && !t.quoted:
			if depth == 0 {
				return 0, errCaddyfileUnsafe
			}
			depth--
		case depth == 0:
			if addrs == 0 && (strings.HasPrefix(t.text, "(") || strings.HasPrefix(t.text, "&(")) {
				return 0, errCaddyfileUnsafe
			}
			addrs++
		}
	}
	if depth != 0 || addrs != 0 {
		return 0, errCaddyfileUnsafe
	}
	return sites, nil
}

// caddyfileSimpleShorthands and caddyfileComplexShorthands mirror the
// placeholder shorthands Caddy's HTTP Caddyfile adapter rewrites in every
// token (caddyconfig/httpcaddyfile/shorthands.go, v2.11). The JSON route
// carries values verbatim, so a value containing one of these would mean
// something different once exported.
var caddyfileSimpleShorthands = []string{
	"{host}", "{hostport}", "{port}", "{orig_method}", "{orig_uri}", "{orig_path}",
	"{orig_dir}", "{orig_file}", "{orig_query}", "{orig_?query}", "{method}", "{uri}",
	"{%uri}", "{path}", "{%path}", "{dir}", "{file}", "{query}", "{%query}", "{?query}",
	"{remote}", "{remote_host}", "{remote_port}", "{scheme}", "{uuid}", "{tls_cipher}",
	"{tls_version}", "{tls_client_fingerprint}", "{tls_client_issuer}", "{tls_client_serial}",
	"{tls_client_subject}", "{tls_client_certificate_pem}", "{tls_client_certificate_der_base64}",
	"{upstream_hostport}", "{client_ip}",
}

var caddyfileComplexShorthands = regexp.MustCompile(`{(header|cookie|labels|path|file|query|vars|file_match)\.[\w-]*}|{(re|rp|resp|err)\.[\w-.]*}`)

// caddyfileRewritesValue reports whether Caddy would not read s back
// verbatim from a Caddyfile token: {$ENV} expansion or a placeholder
// shorthand. Regexp syntax such as \p{L}, {2,3} or \{host\} is untouched.
func caddyfileRewritesValue(s string) bool {
	if strings.Contains(s, "{$") || caddyfileComplexShorthands.MatchString(s) {
		return true
	}
	for _, sh := range caddyfileSimpleShorthands {
		if strings.Contains(s, sh) {
			return true
		}
	}
	return false
}

// caddyfileToken renders s as one Caddyfile token whose value Caddy reads
// back unchanged. Plain text is left bare; anything else is wrapped in
// backticks, which the lexer takes literally up to the next backtick. ok is
// false — and the caller must fail closed — when no such token exists: a
// backtick (backslash escaping is deliberately never attempted), control
// characters, Unicode line separators, invalid UTF-8, or text the adapter
// would rewrite (caddyfileRewritesValue).
func caddyfileToken(s string) (string, bool) {
	if s == "" || !utf8.ValidString(s) || caddyfileRewritesValue(s) {
		return "", false
	}
	bare := true
	for _, r := range s {
		switch {
		case r == '`', unicode.IsControl(r), r == ' ', r == ' ':
			return "", false
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("/.-_*^$()[]|+?:~!%&=,;", r):
		default:
			bare = false
		}
	}
	if bare {
		return s, true
	}
	return "`" + s + "`", true
}

// caddyfileBareSafe reports whether every value can be written as one
// unquoted Caddyfile token that Caddy reads back unchanged: no whitespace,
// control characters or backslashes (which split or escape), nothing the
// adapter rewrites, and no token-initial `"`, backtick, `#`, `@`, `<<` or a
// lone brace, which open a quote, comment, matcher, heredoc or block.
func caddyfileBareSafe(values ...string) bool {
	for _, s := range values {
		if s == "" || !utf8.ValidString(s) || s == "{" || s == "}" ||
			strings.ContainsAny(s[:1], "\"`#@") || strings.HasPrefix(s, "<<") ||
			strings.ContainsRune(s, '\\') || caddyfileRewritesValue(s) {
			return false
		}
		for _, r := range s {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == ' ' || r == ' ' {
				return false
			}
		}
	}
	return true
}

// caddyfileAddressSafe is caddyfileBareSafe for site addresses, which also
// must not start with `(` or `&(` — that would define a snippet or a named
// route instead of a site.
func caddyfileAddressSafe(values ...string) bool {
	for _, s := range values {
		if !caddyfileBareSafe(s) || strings.HasPrefix(s, "(") || strings.HasPrefix(s, "&") {
			return false
		}
	}
	return true
}

// caddyfileHeaderNameRe is an RFC 9110 field name that starts with a letter
// or digit, so it cannot be read as a matcher (`@`, `/`, `*`) or as one of
// the header directive's operation prefixes (`+`, `-`, `?`, `>`).
var caddyfileHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$%&'*+.^_|~-]*$`)

// caddyfileWordRe matches the fixed keywords CaddyUI stores for options such
// as the load-balancing policy and the client-auth mode.
var caddyfileWordRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// caddyfileComment makes s safe inside a `#` comment line: anything that
// could end the line becomes a space, and braces become parentheses so the
// comment can never hold `{$`, which Caddy expands before it sees comments.
func caddyfileComment(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), r == ' ', r == ' ':
			return ' '
		case r == '{':
			return '('
		case r == '}':
			return ')'
		}
		return r
	}, s)
}

// caddyfileDirectiveOrder is Caddy v2.11's default HTTP handler directive
// order (caddyconfig/httpcaddyfile/directives.go).
var caddyfileDirectiveOrder = []string{
	"tracing", "map", "vars", "fs", "root", "log_append", "skip_log", "log_skip", "log_name", "log_level",
	"header", "copy_response_headers", "request_body", "timeouts", "redir", "method", "rewrite", "uri",
	"try_files", "basicauth", "basic_auth", "forward_auth", "request_header", "encode", "push",
	"intercept", "templates", "invoke", "handle", "handle_path", "route", "abort", "error",
	"copy_response", "respond", "metrics", "reverse_proxy", "php_fastcgi", "file_server", "acme_server",
}

// caddyfileSiteOnlyDirectives configure the site rather than add handlers,
// so their position does not matter and they cannot go inside `route`.
var caddyfileSiteOnlyDirectives = map[string]bool{"tls": true, "bind": true, "log": true}

// splitAdvancedForRoute splits an Advanced config into the lines that must
// stay at site level (tls/bind/log) and the lines that can be moved inside
// a `route { }` block without changing their order. ok is false when moving
// them would change behaviour: inside `route` directives run as written,
// while the JSON route ran them in Caddy's sorted order, so the handler
// directives must already be in strictly increasing directive order (a
// repeated directive would be sorted by matcher, which this does not model)
// and must all be known handler directives.
func splitAdvancedForRoute(src string) (site, inRoute string, ok bool) {
	toks, err := lexCaddyfile(src)
	if err != nil {
		return "", "", false
	}
	lines := strings.Split(src, "\n")
	type segment struct {
		name             string
		startLine, depth int
	}
	var segs []segment
	depth, lastLine := 0, -1
	for _, t := range toks {
		if depth == 0 && t.line != lastLine && !(t.text == "}" && !t.quoted) {
			segs = append(segs, segment{name: t.text, startLine: t.line})
		}
		lastLine = t.line
		if !t.quoted && t.text == "{" {
			depth++
		} else if !t.quoted && t.text == "}" {
			if depth == 0 {
				return "", "", false
			}
			depth--
		}
	}
	if depth != 0 {
		return "", "", false
	}
	order := map[string]int{}
	for i, d := range caddyfileDirectiveOrder {
		order[d] = i
	}
	var siteB, routeB strings.Builder
	last := -1
	for i, sg := range segs {
		end := len(lines)
		if i+1 < len(segs) {
			end = segs[i+1].startLine - 1
		}
		text := strings.Join(lines[sg.startLine-1:end], "\n") + "\n"
		switch idx, known := order[sg.name]; {
		case strings.HasPrefix(sg.name, "@"):
			routeB.WriteString(text) // matcher definition
		case caddyfileSiteOnlyDirectives[sg.name]:
			siteB.WriteString(text)
		case !known || idx <= last:
			return "", "", false
		default:
			last = idx
			routeB.WriteString(text)
		}
	}
	return siteB.String(), routeB.String(), true
}
