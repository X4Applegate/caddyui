// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"regexp"
	"strings"
)

// What the tenant text rules measure beyond bytes (issue #184 round 13).
//
// Caddy's adapter needs memory in proportion to the tokens it handles, not
// only their bytes: an empty token costs it as much as a long one. And a
// named matcher (`@name …`) is copied, whole, into the JSON of every
// handler that names it, so the adapted config can grow with the number of
// references times the size of the definitions. The functions here count,
// for a run of tokens, the tokens themselves, the matcher references (a
// token holding `@` that does not start its line) and the matcher
// definitions (a line whose first token starts with `@`, with the block it
// opens), so the server can charge each of them.

// CaddyfileMinTokenWeight is the least a token weighs in the tenant text
// rules (issue #184 round 13): Caddy's adapter spends memory per token, so
// a run of empty or one-letter tokens costs it far more than its bytes
// say. Measured on Caddy 2.11.9; see MaxCaddyfileNestingDepth.
const CaddyfileMinTokenWeight = 4

// CaddyfileTokenWeight is what one token of the given text weighs: its
// bytes and a separator, and at least CaddyfileMinTokenWeight.
func CaddyfileTokenWeight(text string) int {
	return max(len(text)+1, CaddyfileMinTokenWeight)
}

// cfMatcherFacts returns, for each token of toks (depths is cfDepths),
// whether it may name a matcher (ref) and whether it belongs to a matcher
// definition (def). Both err towards more: any token holding `@` that is
// not the first of its line is a reference, and a definition's block runs
// to the brace that brings the depth back, as cfDepths counts it.
func cfMatcherFacts(toks []cfToken, depths []int) (ref, def []bool) {
	n := len(toks)
	ref = make([]bool, n)
	def = make([]bool, n)
	for i := 0; i < n; i++ {
		if !cfIsNewLine(toks, i) {
			ref[i] = strings.Contains(toks[i].text, "@")
			continue
		}
		if !strings.HasPrefix(toks[i].text, "@") {
			continue
		}
		j := i + 1
		for j < n && !cfIsNewLine(toks, j) {
			j++
		}
		for k := i; k < j; k++ {
			def[k] = true
		}
		if last := j - 1; !toks[last].quoted && toks[last].text == "{" {
			for k := j; k < n && depths[k] > depths[last]; k++ {
				def[k] = true
			}
		}
	}
	return ref, def
}

// cfArgsPlaceholderRe matches one whole `{args[…]}` or `{args.…}`
// placeholder inside a token.
var cfArgsPlaceholderRe = regexp.MustCompile(`\{args(?:\[[^\[\]{}]*\]|\.[^{}]*)\}`)

// cfExactArgsPlaceholder reports whether a token is exactly one
// `{args[…]}` or `{args.…}` placeholder.
func cfExactArgsPlaceholder(text string) bool {
	loc := cfArgsPlaceholderRe.FindStringIndex(text)
	return loc != nil && loc[0] == 0 && loc[1] == len(text)
}

// cfVariadic reports whether a token may be a variadic `{args[a:b]}`,
// which Caddy replaces with any number of the importer's arguments —
// possibly none (importargs.go parseVariadic).
func cfVariadic(text string) bool {
	return strings.HasPrefix(text, "{args[") && strings.HasSuffix(text, "]}") && strings.Contains(text, ":")
}

// cfKeepsLiteral reports whether a token holding `{args…}` placeholders
// keeps, once they are replaced, a character of its own that is not a
// brace: whatever the arguments are, Caddy cannot read it as `{`, `}` or
// an empty token. A token that is exactly one placeholder is replaced by
// one argument, which the server holds to the same.
func cfKeepsLiteral(text string) bool {
	rest := cfArgsPlaceholderRe.ReplaceAllString(text, "")
	return strings.Trim(rest, "{}") != ""
}

// cfSnippetShape is what CaddyfileSnippets learns about where a snippet's
// placeholders sit (issue #184 round 13).
type cfSnippetShape struct {
	// placeholderLineStart: an `{args…}` token can be the first token of
	// a line once the snippet is imported.
	placeholderLineStart bool
	// placeholderNoLiteral: a token mixes placeholders without a
	// character of its own, so arguments alone decide what it reads as.
	placeholderNoLiteral bool
	// blockNotAlone: a `{block}` / `{blocks.…}` token shares its line
	// with another token.
	blockNotAlone bool
	// defBlock: a `{block}` / `{blocks.…}` token sits in a matcher
	// definition.
	defBlock bool
}

// cfSnippetPlacement checks where body's placeholders sit. A token is
// anchored when a token earlier on its line is always put in by Caddy,
// on that line, as one token: one of the snippet's own (no placeholder),
// or an `{args…}` token that is not variadic (Caddy replaces it in place,
// so it stays one token; a variadic one may vanish). Caddy reads a token
// as the start of a line when the one before it ends on an earlier line
// or comes from another import (lexer.go isNextOnNewLine): the importer's
// block, which `{block}` puts in, keeps the importer's import chain, so
// what follows it starts a line too.
func cfSnippetPlacement(body []cfToken, def []bool) cfSnippetShape {
	var sh cfSnippetShape
	anchored := false
	for i, t := range body {
		if cfIsNewLine(body, i) {
			anchored = false
		}
		if cfBlockPlaceholder(t.text) {
			if !cfIsNewLine(body, i) || (i+1 < len(body) && !cfIsNewLine(body, i+1)) {
				sh.blockNotAlone = true
			}
			if def[i] {
				sh.defBlock = true
			}
			anchored = false
			continue
		}
		if !strings.Contains(t.text, "{args") {
			anchored = true
			continue
		}
		if !anchored {
			sh.placeholderLineStart = true
		}
		if !cfExactArgsPlaceholder(t.text) && !cfKeepsLiteral(t.text) {
			sh.placeholderNoLiteral = true
		}
		if !cfVariadic(t.text) {
			anchored = true
		}
	}
	return sh
}

// cfSiteListeners returns the most distinct listener ports any one site
// block of toks names in its addresses (issue #184 round 13): Caddy
// adapts a site block once for every listener its addresses put it on,
// so its routes are copied that many times. toks is a whole Caddyfile;
// the head of a block is every token at depth 0 before its `{`, other
// than an `import` line and a snippet definition, which errs towards
// more. An address with no port counts as 443, or 80 with http://.
func cfSiteListeners(toks []cfToken) int {
	most := 0
	var head []string
	depth := 0
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		structural := !t.quoted && (t.text == "{" || t.text == "}")
		if depth == 0 && !structural {
			if t.text == "import" && cfIsNewLine(toks, i) {
				for i++; i < len(toks) && !cfIsNewLine(toks, i); i++ {
				}
				i--
				continue
			}
			head = append(head, t.text)
			continue
		}
		if !structural {
			continue
		}
		if t.text == "{" {
			if depth == 0 {
				most = max(most, cfDistinctPorts(head))
				head = nil
			}
			depth++
		} else if depth > 0 && (i+1 >= len(toks) || cfIsNewLine(toks, i+1)) {
			depth--
		}
	}
	return most
}

// cfDistinctPorts counts the distinct listener ports of a site block's
// address tokens. A snippet definition's `(name)` names none.
func cfDistinctPorts(head []string) int {
	ports := map[string]bool{}
	for _, tok := range head {
		for _, key := range strings.Split(tok, ",") {
			key = strings.TrimSpace(key)
			if key == "" || (strings.HasPrefix(key, "(") && strings.HasSuffix(key, ")")) {
				continue
			}
			port := "443"
			rest := key
			if scheme, after, ok := strings.Cut(key, "://"); ok {
				rest = after
				if strings.EqualFold(scheme, "http") {
					port = "80"
				}
			}
			if j := strings.IndexAny(rest, "/"); j >= 0 {
				rest = rest[:j]
			}
			if j := strings.LastIndex(rest, ":"); j >= 0 && !strings.HasSuffix(rest, "]") {
				port = rest[j+1:]
			}
			ports[port] = true
		}
	}
	return len(ports)
}

// cfHeadKeys returns the most tokens a line of body, at its depth 0, has
// before an opening brace: imported at the top level of a file, those
// tokens are a site block's addresses (issue #184 round 13).
func cfHeadKeys(body []cfToken, depths []int) int {
	most, start := 0, 0
	for i, t := range body {
		if cfIsNewLine(body, i) {
			start = i
		}
		if depths[i] == 0 && !t.quoted && t.text == "{" {
			most = max(most, i-start)
		}
	}
	return most
}
