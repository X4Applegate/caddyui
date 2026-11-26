// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"strings"
	"unicode"
)

// SplitCaddyfileBlocks splits a Caddyfile into top-level blocks. Each returned
// block includes its site-address line(s) and the full "{ ... }" body.
// The global-options block (one that has no site address before its "{") is
// returned as the first element with an empty site-address line so callers can
// distinguish it — or simply discard it since it doesn't map to a route.
//
// Blocks are found on the tokens Caddy's own lexer produces
// (lexCaddyfileLenient, issue #184 round 10), so quotes, backtick strings,
// heredocs and comments delimit text exactly as they do for Caddy, and only
// an unquoted `{` or `}` token opens or closes a block — the rule of
// Caddy's parser (isOpenCurlyBrace / isCloseCurlyBrace). A top-level
// `import` line is not part of any block. Snippet definitions "(name) { ... }"
// appear as their own blocks; see ExtractSnippets and CaddyfileSnippets.
// Text Caddy's lexer refuses (a malformed heredoc) yields no blocks.
func SplitCaddyfileBlocks(src string) []string {
	blocks, _ := caddyfileBlocks(src)
	out := make([]string, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, b.text)
	}
	return out
}

// cfBlock is one top-level block found by caddyfileBlocks.
type cfBlock struct {
	text    string // source text, first head token through the closing brace
	head    string // source text before the opening brace, trimmed
	snippet string // the snippet name when the block defines one, else ""
	// first indexes the block's first token in toks, open and close its
	// braces; bodyBytes is the size of the source between the braces.
	first, open, close int
	bodyBytes          int
}

// caddyfileBlocks returns the top-level blocks of src and its tokens. A
// block starts at the first token after the previous block (a top-level
// `import` line is skipped) and ends at the unquoted `}` that balances its
// first unquoted `{`. Text after the last balanced block is ignored.
func caddyfileBlocks(src string) ([]cfBlock, []cfToken) {
	toks, startByte, endByte, err := lexCaddyfileLenient(src)
	if err != nil {
		return nil, nil
	}
	open := func(i int) bool { return toks[i].text == "{" && !toks[i].quoted }
	closing := func(i int) bool { return toks[i].text == "}" && !toks[i].quoted }
	// first returns where token i's source starts, including a backslash
	// that escapes its first character: the lexer's start skips it, and
	// Caddy's lexer keeps it pending across spaces and tabs.
	first := func(i int) int {
		b := startByte[i]
		j := b
		for j > 0 && (src[j-1] == ' ' || src[j-1] == '\t' || src[j-1] == '\r') {
			j--
		}
		if j > 0 && src[j-1] == '\\' && (i == 0 || j-1 >= endByte[i-1]) {
			return j - 1
		}
		return b
	}
	var blocks []cfBlock
	for i := 0; i < len(toks); {
		if toks[i].text == "import" && cfIsNewLine(toks, i) {
			for i++; i < len(toks) && !cfIsNewLine(toks, i); i++ {
			}
			continue
		}
		head := i
		for i < len(toks) && !open(i) {
			if closing(i) {
				return blocks, toks // a stray `}`: Caddy refuses the file
			}
			i++
		}
		if i >= len(toks) {
			break
		}
		openIdx := i
		depth := 1
		for i++; i < len(toks) && depth > 0; i++ {
			if open(i) {
				depth++
			} else if closing(i) {
				depth--
			}
		}
		if depth != 0 {
			break
		}
		closeIdx := i - 1
		b := cfBlock{
			// A token's span runs over the carriage returns Caddy's lexer
			// skips after it; the block ends at its brace.
			text:      strings.TrimRight(src[first(head):endByte[closeIdx]], "\r"),
			head:      strings.TrimSpace(src[first(head):startByte[openIdx]]),
			first:     head,
			open:      openIdx,
			close:     closeIdx,
			bodyBytes: startByte[closeIdx] - endByte[openIdx],
		}
		// Caddy's isSnippet: the block's one key is `(name)`. CaddyUI also
		// requires the `{` on the key's line, as Caddy's addresses() does
		// for any block.
		// The closing brace must be written as one: at the end of the
		// text Caddy also reads `"}` or `}\` as `}`, but such a block would
		// swallow whatever is put after it.
		if k := toks[head].text; openIdx == head+1 && !cfIsNewLine(toks, openIdx) &&
			len(k) >= 2 && strings.HasPrefix(k, "(") && strings.HasSuffix(k, ")") &&
			strings.TrimRight(src[startByte[closeIdx]:endByte[closeIdx]], "\r") == "}" {
			b.snippet = k[1 : len(k)-1]
		}
		blocks = append(blocks, b)
	}
	return blocks, toks
}

// HeadOfBlock returns the site-address line(s) before a block's opening brace.
// For "example.com, www.example.com {\n  ...\n}" it returns
// "example.com, www.example.com". For a global-options block "{ ... }" it returns "".
// The brace is the first unquoted `{` token, read as Caddy's lexer reads
// the block (issue #184 round 10).
func HeadOfBlock(block string) string {
	if toks, startByte, _, err := lexCaddyfileLenient(block); err == nil {
		for i, t := range toks {
			if t.text == "{" && !t.quoted {
				return strings.TrimSpace(block[:startByte[i]])
			}
		}
		return strings.TrimSpace(block)
	}
	i := strings.IndexByte(block, '{')
	if i < 0 {
		return strings.TrimSpace(block)
	}
	return strings.TrimSpace(block[:i])
}

// ExtractSnippets returns the snippet-definition blocks — "(name) { ... }" — from
// a Caddyfile source. Global-options blocks and site blocks are skipped. Used to
// auto-load reusable snippets from a mounted Caddyfile so a user's paste can
// `import` them without re-typing the definition.
func ExtractSnippets(src string) []string {
	var out []string
	for _, s := range CaddyfileSnippets(src) {
		out = append(out, s.Text)
	}
	return out
}

// CaddyfileSnippet is one snippet definition found by CaddyfileSnippets,
// with what it costs Caddy's adapter when imported (issue #184 round 10).
type CaddyfileSnippet struct {
	Name string
	// Order is the definition's position among the snippets of its file.
	Order int
	// Text is the definition's source, `(name) {` through its `}`.
	Text string
	// BodyBytes is the size of the source between the braces.
	BodyBytes int
	// Depth is how deeply the body nests blocks (0 for a flat body).
	Depth int
	// Imports are the `import` directives in the body, with the block
	// depth (within the body) each one sits at.
	Imports []CaddyfileImport
}

// CaddyfileImport is one `import` directive: the name it imports ("" when
// it has none) and the block depth it sits at.
type CaddyfileImport struct {
	Name  string
	Depth int
}

// CaddyfileSnippets returns the snippet definitions of src, read the way
// Caddy's lexer and parser read them (see SplitCaddyfileBlocks), in order.
func CaddyfileSnippets(src string) []CaddyfileSnippet {
	blocks, toks := caddyfileBlocks(src)
	var out []CaddyfileSnippet
	for _, b := range blocks {
		if b.snippet == "" {
			continue
		}
		body := toks[b.open+1 : b.close]
		depths := cfDepths(body)
		s := CaddyfileSnippet{Name: b.snippet, Order: len(out), Text: b.text, BodyBytes: b.bodyBytes, Depth: cfMaxNestingDepth(body)}
		for i, t := range body {
			if t.text != "import" || !cfIsNewLine(toks, b.open+1+i) {
				continue
			}
			name := ""
			if i+1 < len(body) && !cfIsNewLine(toks, b.open+2+i) {
				name = body[i+1].text
			}
			s.Imports = append(s.Imports, CaddyfileImport{Name: name, Depth: depths[i]})
		}
		out = append(out, s)
	}
	return out
}

// CaddyfileHTTPOnly reports whether every site block in src addresses itself
// with an explicit plain-HTTP address: an http:// scheme (http://127.0.0.1,
// http://health.example.com) or the plain-HTTP port (:80, host:80). Snippet
// definitions and the global-options block are ignored. It is false when src
// has no site block at all, and false as soon as one address is https://, has
// another scheme, or names no port or scheme — Caddy serves those over TLS by
// default, so only a block that says "http" explicitly is HTTP-only.
//
// CaddyUI uses this for Advanced routes (issue #121): a route written as
// `http://127.0.0.1 { ... }` is a deliberate plain-HTTP route, so it needs no
// certificate, must not be force-redirected to HTTPS, and has nothing to wait
// for on the "deploying" page.
func CaddyfileHTTPOnly(src string) bool {
	sites := 0
	for _, block := range SplitCaddyfileBlocks(src) {
		// A comment line above the address is part of the block's head text
		// (SplitCaddyfileBlocks keeps comments), so drop them before reading
		// the addresses.
		head := stripCaddyfileComments(HeadOfBlock(block))
		if head == "" || (strings.HasPrefix(head, "(") && strings.HasSuffix(head, ")")) {
			continue
		}
		addrs := strings.FieldsFunc(head, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
		if len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			if !isPlainHTTPAddress(addr) {
				return false
			}
		}
		sites++
	}
	return sites > 0
}

func isPlainHTTPAddress(addr string) bool {
	addr = strings.ToLower(addr)
	if strings.HasPrefix(addr, "http://") {
		return true
	}
	if strings.Contains(addr, "://") {
		return false // https:// or some other scheme
	}
	i := strings.LastIndex(addr, ":")
	return i >= 0 && addr[i+1:] == "80"
}

// stripCaddyfileComments removes "# ..." comments, line by line, from a
// block head. Site addresses never contain '#'.
func stripCaddyfileComments(head string) string {
	lines := strings.Split(head, "\n")
	for i, line := range lines {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			lines[i] = line[:j]
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// CaddyfileLineHeads returns the first token of every line of src that sits
// at block depth 0, read the way Caddy's lexer reads src (a quoted,
// backtick or heredoc value is one token, wherever its newlines fall); ok
// is false when Caddy's lexer would refuse src.
func CaddyfileLineHeads(src string) (heads []string, ok bool) {
	toks, _, _, err := lexCaddyfileLenient(src)
	if err != nil {
		return nil, false
	}
	depths := cfDepths(toks)
	for i, t := range toks {
		if depths[i] == 0 && cfIsNewLine(toks, i) && !(t.text == "}" && !t.quoted) {
			heads = append(heads, t.text)
		}
	}
	return heads, true
}

// CaddyfileHasMultilineValue reports whether a value in src — a quoted or
// backtick string, or a heredoc — spans more than one line, or whether
// src cannot be lexed at all. Line-based rewrites of such text would edit
// inside the value.
func CaddyfileHasMultilineValue(src string) bool {
	toks, _, _, err := lexCaddyfileLenient(src)
	if err != nil {
		return true
	}
	for _, t := range toks {
		if t.heredoc || strings.Contains(t.text, "\n") {
			return true
		}
	}
	return false
}
