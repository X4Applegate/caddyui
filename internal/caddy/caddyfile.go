package caddy

import (
	"strings"
)

// SplitCaddyfileBlocks splits a Caddyfile into top-level blocks. Each returned
// block includes its site-address line(s) and the full "{ ... }" body.
// The global-options block (one that has no site address before its "{") is
// returned as the first element with an empty site-address line so callers can
// distinguish it — or simply discard it since it doesn't map to a route.
//
// This is a brace-depth parser, not a full Caddyfile lexer. It handles:
//   - Line comments starting with '#'
//   - Double-quoted strings (with \\ and \" escapes) so braces inside strings
//     don't affect depth
//   - Single-line directives with no braces (e.g. top-level "import ...") —
//     these are NOT returned as blocks, only "... { ... }" snippets are.
//
// It does NOT handle Caddyfile snippets "(name) { ... }" specially — those will
// appear as their own blocks and callers should filter by whether the head starts
// with '('.
func SplitCaddyfileBlocks(src string) []string {
	var blocks []string
	var cur strings.Builder
	depth := 0
	// blockStart marks the index in cur where the current top-level block began.
	// When we close the block (depth returns to 0), we emit cur[blockStart:].
	blockStart := -1

	writeAndMaybeStart := func(b byte) {
		if depth == 0 && blockStart == -1 {
			// Starting a new potential block — but only if this byte is non-whitespace
			// and not a separator. Whitespace/newlines between blocks are ignored.
			if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
				blockStart = cur.Len()
				cur.WriteByte(b)
			}
			return
		}
		cur.WriteByte(b)
	}

	i := 0
	for i < len(src) {
		c := src[i]
		switch c {
		case '#':
			// Line comment — include in the current block (if any) but don't scan for braces.
			for i < len(src) && src[i] != '\n' {
				writeAndMaybeStart(src[i])
				i++
			}
		case '"':
			writeAndMaybeStart(c)
			i++
			for i < len(src) {
				if src[i] == '\\' && i+1 < len(src) {
					cur.WriteByte(src[i])
					cur.WriteByte(src[i+1])
					i += 2
					continue
				}
				cur.WriteByte(src[i])
				if src[i] == '"' {
					i++
					break
				}
				i++
			}
		case '{':
			writeAndMaybeStart(c)
			depth++
			i++
		case '}':
			cur.WriteByte(c)
			depth--
			i++
			if depth == 0 && blockStart != -1 {
				blocks = append(blocks, strings.TrimSpace(cur.String()[blockStart:]))
				// Truncate cur back to the block's start so leftover text between
				// blocks doesn't accumulate.
				s := cur.String()[:blockStart]
				cur.Reset()
				cur.WriteString(s)
				blockStart = -1
			}
		default:
			writeAndMaybeStart(c)
			i++
		}
	}
	return blocks
}

// HeadOfBlock returns the site-address line(s) before a block's opening brace.
// For "example.com, www.example.com {\n  ...\n}" it returns
// "example.com, www.example.com". For a global-options block "{ ... }" it returns "".
func HeadOfBlock(block string) string {
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
	for _, block := range SplitCaddyfileBlocks(src) {
		head := HeadOfBlock(block)
		if strings.HasPrefix(head, "(") && strings.HasSuffix(head, ")") {
			out = append(out, block)
		}
	}
	return out
}
