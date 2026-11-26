// SPDX-License-Identifier: Apache-2.0
//
// This file is adapted from Caddy v2.11.9, caddyconfig/caddyfile/lexer.go:
//
//	Copyright 2015 Matthew Holt and The Caddy Authors
//	Licensed under the Apache License, Version 2.0
//	https://github.com/caddyserver/caddy
//
// Modifications for CaddyUI (issue #184): reads a string instead of a
// reader, keeps only what the export safety checks need, and refuses —
// rather than tolerates — input that ends inside a quote or after a
// line-continuation backslash, and any byte-order mark (Caddy drops one
// only at the very start of a file, which these snippets never are).

package caddy

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// cfToken is one Caddyfile token as Caddy's lexer produces it.
type cfToken struct {
	text      string
	line      int
	quoted    bool
	heredoc   bool
	lineBreak int // NumLineBreaks: newlines in text, plus 2 for a heredoc
}

// lexCaddyfile tokenizes src exactly as Caddy's lexer does, heredocs
// included. Any error means the caller must treat src as unsafe.
func lexCaddyfile(src string) ([]cfToken, error) {
	if !utf8.ValidString(src) || strings.ContainsRune(src, '\uFEFF') {
		return nil, errCaddyfileUnsafe
	}
	l := cfLexer{runes: []rune(src), line: 1}
	var toks []cfToken
	for {
		tok, found, err := l.next()
		if err != nil {
			return nil, err
		}
		if !found {
			return toks, nil
		}
		tok.lineBreak = strings.Count(tok.text, "\n")
		if tok.heredoc {
			tok.lineBreak += 2
		}
		toks = append(toks, tok)
	}
}

type cfLexer struct {
	runes        []rune
	pos          int
	line         int
	skippedLines int
}

func (l *cfLexer) next() (cfToken, bool, error) {
	var val []rune
	var comment, quoted, btQuoted, inHeredoc, heredocEscaped, escaped bool
	var heredocMarker string
	var heredocPrefix []int
	var heredocMatched int
	tok := cfToken{line: l.line}

	for {
		if l.pos >= len(l.runes) {
			if quoted || btQuoted || escaped || inHeredoc {
				return tok, false, errCaddyfileUnsafe
			}
			if len(val) > 0 {
				tok.text = string(val)
				return tok, true, nil
			}
			return tok, false, nil
		}
		ch := l.runes[l.pos]
		l.pos++

		if !quoted && !btQuoted && !inHeredoc && !heredocEscaped && len(val) > 1 && string(val[:2]) == "<<" {
			if ch == ' ' {
				tok.text = string(val)
				return tok, true, nil
			}
			if ch == '\r' {
				continue
			}
			if ch == '\n' {
				if len(val) == 2 || string(val[:3]) == "<<<" {
					return tok, false, errCaddyfileUnsafe
				}
				heredocMarker = string(val[2:])
				if !cfIsHeredocMarker(heredocMarker) {
					return tok, false, errCaddyfileUnsafe
				}
				heredocPrefix = make([]int, len(heredocMarker))
				for i, matched := 1, 0; i < len(heredocMarker); i++ {
					for matched > 0 && heredocMarker[i] != heredocMarker[matched] {
						matched = heredocPrefix[matched-1]
					}
					if heredocMarker[i] == heredocMarker[matched] {
						matched++
					}
					heredocPrefix[i] = matched
				}
				inHeredoc = true
				l.skippedLines++
				val = nil
				continue
			}
			val = append(val, ch)
			continue
		}

		if inHeredoc {
			val = append(val, ch)
			if ch == '\n' {
				l.skippedLines++
			}
			for heredocMatched > 0 && ch != rune(heredocMarker[heredocMatched]) {
				heredocMatched = heredocPrefix[heredocMatched-1]
			}
			if ch == rune(heredocMarker[heredocMatched]) {
				heredocMatched++
			}
			if heredocMatched == len(heredocMarker) {
				out, err := cfFinalizeHeredoc(val, heredocMarker)
				if err != nil {
					return tok, false, err
				}
				l.line += l.skippedLines
				l.skippedLines = 0
				tok.text, tok.quoted, tok.heredoc = string(out), true, true
				return tok, true, nil
			}
			continue
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
				return tok, true, nil
			}
			if ch == '\n' {
				l.line += 1 + l.skippedLines
				l.skippedLines = 0
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
					l.skippedLines++
					escaped = false
				} else {
					l.line += 1 + l.skippedLines
					l.skippedLines = 0
				}
				comment = false
			}
			if len(val) > 0 {
				tok.text = string(val)
				return tok, true, nil
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
			tok = cfToken{line: l.line}
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
				heredocEscaped = true
			} else {
				val = append(val, '\\')
			}
			escaped = false
		}

		val = append(val, ch)
	}
}

func cfFinalizeHeredoc(val []rune, marker string) ([]rune, error) {
	stringVal := string(val)
	lastNewline := strings.LastIndex(stringVal, "\n")
	lines := strings.Split(stringVal[:lastNewline+1], "\n")
	paddingToStrip := stringVal[lastNewline+1 : len(stringVal)-len(marker)]
	var out string
	for _, lineText := range lines[:len(lines)-1] {
		if lineText == "" || lineText == "\r" {
			out += "\n"
			continue
		}
		if strings.Index(lineText, paddingToStrip) != 0 {
			return nil, errCaddyfileUnsafe
		}
		out += strings.ReplaceAll(lineText[len(paddingToStrip):]+"\n", "\r", "")
	}
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return []rune(out), nil
}

func cfIsHeredocMarker(marker string) bool {
	if len(marker) == 0 {
		return false
	}
	for i := range len(marker) {
		c := marker[i]
		isAlnum := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
		if !isAlnum && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// cfIsNewLine is Caddy's isNextOnNewLine for two tokens of one file.
func cfIsNewLine(toks []cfToken, i int) bool {
	if i < 1 {
		return true
	}
	if i >= len(toks) {
		return false
	}
	return toks[i-1].line+toks[i-1].lineBreak < toks[i].line
}
