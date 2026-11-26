// SPDX-License-Identifier: Apache-2.0

package caddy

import "strings"

// LegacySnippetHeads returns the heads — "(name)" — of the blocks that
// CaddyUI's brace-depth splitter up to v2.68.16 (replaced in issue #184 round 10)
// read as snippet definitions in src. That splitter knew double quotes
// and comments but not backtick strings or heredocs, so text inside one
// could read to it as a `(name) { … }` block Caddy never sees; the
// administrator's snippet of that name was then left out of the text sent
// to Caddy, and an `import` of it read a file instead. CaddyUI keeps
// it only in tests, to show a fixture fooled the old splitter. It is the
// old code, unchanged.
func LegacySnippetHeads(src string) map[string]bool {
	out := map[string]bool{}
	for _, block := range legacySplitCaddyfileBlocks(src) {
		head := legacyHeadOfBlock(block)
		if strings.HasPrefix(head, "(") && strings.HasSuffix(head, ")") {
			out[head] = true
		}
	}
	return out
}

func legacyHeadOfBlock(block string) string {
	i := strings.IndexByte(block, '{')
	if i < 0 {
		return strings.TrimSpace(block)
	}
	return strings.TrimSpace(block[:i])
}

func legacySplitCaddyfileBlocks(src string) []string {
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
