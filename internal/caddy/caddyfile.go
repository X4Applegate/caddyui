// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"fmt"
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
	// text is the block's source: any comment lines just above it (issue
	// #184 round 11: the Caddyfile paste import stores them with the
	// block), its first head token, through the closing brace.
	text string
	// own is text without those comment lines.
	own     string
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
	// lead returns where the comment lines just above token i start, or
	// first(i) when there are none: the first `#` on a line of its own
	// after the end of the line the previous text ended on.
	lead := func(prevEnd, i int) int {
		start := first(i)
		gap := src[prevEnd:start]
		if prevEnd > 0 {
			nl := strings.IndexByte(gap, '\n')
			if nl < 0 {
				return start
			}
			prevEnd += nl + 1
			gap = src[prevEnd:start]
		}
		if h := strings.IndexByte(gap, '#'); h >= 0 {
			return prevEnd + h
		}
		return start
	}
	var blocks []cfBlock
	prevEnd := 0
	for i := 0; i < len(toks); {
		if toks[i].text == "import" && cfIsNewLine(toks, i) {
			for i++; i < len(toks) && !cfIsNewLine(toks, i); i++ {
			}
			prevEnd = endByte[i-1]
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
		// A token's span runs over the carriage returns Caddy's lexer
		// skips after it; the block ends at its brace.
		end := len(strings.TrimRight(src[:endByte[closeIdx]], "\r"))
		b := cfBlock{
			text:      src[lead(prevEnd, head):end],
			own:       src[first(head):end],
			head:      strings.TrimSpace(src[first(head):startByte[openIdx]]),
			first:     head,
			open:      openIdx,
			close:     closeIdx,
			bodyBytes: startByte[closeIdx] - endByte[openIdx],
		}
		prevEnd = endByte[closeIdx]
		// The closing brace must be written as one: at the end of the
		// text Caddy also reads `"}` or `}\` as `}`, but such a block would
		// swallow whatever is put after it.
		if name, ok := cfSnippetName(toks, head, openIdx); ok &&
			strings.TrimRight(src[startByte[closeIdx]:endByte[closeIdx]], "\r") == "}" {
			b.snippet = name
		}
		blocks = append(blocks, b)
	}
	return blocks, toks
}

// cfSnippetName reports the snippet a block defines whose head is
// toks[head:open], read as Caddy's parser reads it (issue #184 round 11,
// parse.go addresses() and isSnippet()): the head's keys — tokens with a
// trailing comma dropped, and empty ones skipped — are exactly one
// `(name)`. The list of keys ends at the end of a line unless the line
// ends with a comma, so the `{` may sit on a later line than the key
// (`(name)` then `{` on the next line defines a snippet too); a head that
// runs on past such a line end, ends with a comma, or holds something
// Caddy refuses in an address is no snippet (Caddy refuses the file).
func cfSnippetName(toks []cfToken, head, open int) (string, bool) {
	var keys []string
	expecting := false
	for k := head; k < open; k++ {
		if k > head && !expecting && cfIsNewLine(toks, k) {
			return "", false
		}
		v := toks[k].text
		if strings.HasPrefix(v, "@") || (!toks[k].quoted && strings.HasSuffix(v, "{")) || (v == "import" && cfIsNewLine(toks, k)) {
			return "", false
		}
		if v == "" {
			continue
		}
		expecting = strings.HasSuffix(v, ",")
		v = strings.TrimSuffix(v, ",")
		if strings.Contains(v, ",") {
			return "", false
		}
		if v != "" {
			keys = append(keys, v)
		}
	}
	if expecting || len(keys) != 1 {
		return "", false
	}
	k := keys[0]
	if len(k) < 2 || !strings.HasPrefix(k, "(") || !strings.HasSuffix(k, ")") {
		return "", false
	}
	return k[1 : len(k)-1], true
}

// HeadOfBlock returns the site-address line(s) before a block's opening brace.
// For "example.com, www.example.com {\n  ...\n}" it returns
// "example.com, www.example.com". For a global-options block "{ ... }" it returns "".
// The brace is the first unquoted `{` token, read as Caddy's lexer reads
// the block (issue #184 round 10); comment lines above the block (which
// SplitCaddyfileBlocks keeps) are not part of the head.
func HeadOfBlock(block string) string {
	if toks, startByte, _, err := lexCaddyfileLenient(block); err == nil {
		if len(toks) == 0 {
			return ""
		}
		from := startByte[0]
		for from > 0 && (block[from-1] == ' ' || block[from-1] == '\t' || block[from-1] == '\\') {
			from--
		}
		for i, t := range toks {
			if t.text == "{" && !t.quoted {
				return strings.TrimSpace(block[from:startByte[i]])
			}
		}
		return strings.TrimSpace(block[from:])
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
	// Imports are the `import` tokens in the body, wherever they sit
	// (issue #184 round 11): Caddy executes an `import` that opens the
	// body or follows an `import … { … }` block on its line, because the
	// tokens a snippet brings in start a new line wherever they land.
	Imports []CaddyfileImport
	// ArgUses counts the `{args` placeholders in the body's tokens: each
	// can be replaced by the importer's arguments (issue #184 round 11).
	ArgUses int
	// BlockUses counts the `{block}` and `{blocks.…}` tokens in the body:
	// each is replaced by the block the importer writes after the import.
	BlockUses int
	// BlockDepth is the deepest block depth (within the body) of such a
	// token, or -1 when there is none.
	BlockDepth int
	// First is the text of the body's first token ("" for an empty body).
	// Caddy's parser fails on a snippet imported at the top level whose
	// first token expands to nothing (issue #184 round 12).
	First string
	// BlockNotAlone is set when a `{block}` or `{blocks.…}` token shares
	// its line with another token (issue #184 round 12, narrowed to one
	// line in round 13: Caddy starts a new line after the importer's
	// block wherever it is put, so only the same line matters).
	BlockNotAlone bool
	// PlaceholderLineStart is set when an `{args…}` token can be the
	// first token of a line once the snippet is imported (issue #184
	// round 13): no token earlier on its line is always put in by Caddy
	// on that line (see cfSnippetPlacement). The importer's arguments
	// would then choose the directive — `import` of a file among them.
	PlaceholderLineStart bool
	// PlaceholderNoLiteral is set when a token holds `{args…}`
	// placeholders and no character of its own but braces, other than a
	// token that is exactly one placeholder (round 13): the arguments
	// alone decide what it is, `{` or `}` included.
	PlaceholderNoLiteral bool
	// DefBlock is set when the importer's block is put inside a matcher
	// definition (round 13: its size then counts as the definition's).
	DefBlock bool
	// BodyWeight is the body's tokens weighed as the tenant rules count
	// them (CaddyfileTokenWeight), and never less than BodyBytes;
	// BodyRefs counts the tokens that may name a matcher; BodyDefWeight
	// weighs the matcher definitions written in the body, and DefArgUses
	// counts the `{args` placeholders in them (issue #184 round 13; see
	// cfMatcherFacts).
	BodyWeight, BodyRefs, BodyDefWeight, DefArgUses int
	// HeadKeys is the most tokens a line at the body's depth 0 has before
	// an opening brace (cfHeadKeys): imported at the top level of a file,
	// they are a site block's addresses (issue #184 round 13).
	HeadKeys int
	// MidLineClose is set when a `}` in the body is followed by more of
	// the body on its line (issue #184 round 12). Caddy finds the body's
	// end by counting braces, but a block inside it ends only at a `}`
	// that ends its line: such a block runs on past the body, into
	// whatever the importer writes after the import.
	MidLineClose bool
	// BlockKeyed is set when the body holds a `{blocks.…}` token (issue
	// #184 round 14): Caddy then reads the importer's block as lines of
	// `key value…`, and puts a key's values in where that token stands, so
	// the first value starts a line there (see CaddyfileImport.KeyArgs).
	BlockKeyed bool
	// Withheld is set by the server, not here: why a non-admin may not
	// import the snippet, which is then also left out of the text CaddyUI
	// adapts for one (issue #184 round 11).
	Withheld string
}

// CaddyfileImport is one `import` directive and what it brings in beyond
// the snippet it names (issue #184 round 11). Sizes are counted in token
// bytes: each token's text plus one separator.
type CaddyfileImport struct {
	// Name is the snippet or file the import names, "" when it names none.
	Name string
	// Depth is the block depth the import sits at.
	Depth int
	// Opaque is set when what the import adds cannot be bounded: the
	// `import` is itself an argument of another import, or passes a
	// `{block}` as arguments.
	Opaque bool
	// ArgBytes is the size of the import's arguments; ArgArgUses and
	// ArgBlockUses count the snippet placeholders among them.
	ArgBytes, ArgArgUses, ArgBlockUses int
	// ArgCount is how many arguments follow the name (issue #184 round
	// 12: a variadic `{args[…]}` may expand to none).
	ArgCount int
	// BraceArg is set when an argument is `{` or `}`: put in a snippet's
	// place for {args…}, it opens or closes a block.
	BraceArg bool
	// ArgImport is set when an argument holds the word `import`, and
	// ArgNewline when one holds a line break (issue #184 round 13): put
	// in a snippet's place, a line break moves the tokens after it to a
	// new line, where a directive starts.
	ArgImport, ArgNewline bool
	// ArgWeight and BlockWeight weigh the arguments' and the block's
	// tokens as the tenant rules count them (CaddyfileTokenWeight);
	// ArgRefs and BlockRefs count those that may name a matcher;
	// BlockDefWeight weighs the matcher definitions in the block; and
	// InMatcherDef is set when the import sits in a matcher definition
	// (issue #184 round 13; see cfMatcherFacts).
	ArgWeight, ArgRefs, BlockWeight, BlockRefs, BlockDefWeight int
	InMatcherDef                                               bool
	// BlockBytes is the size of the block written after the import (its
	// contents, between the braces), 0 when there is none; BlockArgUses
	// and BlockBlockUses count the snippet placeholders in it.
	BlockBytes, BlockArgUses, BlockBlockUses int
	// BlockNest is how deeply the block's contents nest blocks, and
	// BlockPlaceholderDepth the deepest depth within them of a `{block}`
	// or `{blocks.…}` token (-1 when there is none).
	BlockNest, BlockPlaceholderDepth int
	// Within is 1 + the index of the import whose block holds this one,
	// or 0 when none does.
	Within int
	// BlockBraceNotLast is set when an unquoted `{` or `}` in the
	// import's block — the `{` that opens it included — has another
	// token after it on its line (issue #184 round 14). Caddy collects an
	// import's block with its dispenser, which, unlike its parser, takes
	// a token on the line of a `{` into the block and skips a `}` that has
	// one after it: the token after the import's `{` is then the first of
	// the block, and starts a line wherever the snippet puts the block —
	// a matcher definition the text itself does not start a line with —
	// and a skipped brace moves where the block ends.
	BlockBraceNotLast bool
	// KeyArgs are, for an import with a block, the token after the first of each line at the
	// block's own level, when it is on that line and not a brace (issue
	// #184 round 14). A snippet that uses `{blocks.KEY}` puts the rest of
	// the line whose first token is KEY in its place, and the first of
	// those tokens then starts a line.
	KeyArgs []CaddyfileTokenAt
}

// CaddyfileTokenAt is one token of a Caddyfile: its text and the line it
// starts on (1 for the first line).
type CaddyfileTokenAt struct {
	Line int
	Text string
}

// CaddyfileLineStartSensitive reports whether a token means something
// else when it starts a line (issue #184 round 14): a matcher definition
// (`@name`), a snippet or named-route definition (`(name)`, `&(name)`), or
// `import`.
func CaddyfileLineStartSensitive(text string) bool {
	return strings.HasPrefix(text, "@") || strings.HasPrefix(text, "(") || strings.HasPrefix(text, "&(") || text == "import"
}

// CaddyfileLineStarts returns the tokens of src that start a line, read
// the way Caddy's lexer reads src (issue #184 round 14, for the
// differential test of the tenant rules); ok is false when Caddy's lexer
// would refuse src.
func CaddyfileLineStarts(src string) (starts []CaddyfileTokenAt, ok bool) {
	toks, err := lexCaddyfile(src)
	if err != nil {
		return nil, false
	}
	for i, t := range toks {
		if cfIsNewLine(toks, i) {
			starts = append(starts, CaddyfileTokenAt{Line: t.line, Text: t.text})
		}
	}
	return starts, true
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
		s := CaddyfileSnippet{Name: b.snippet, Order: len(out), Text: b.own, BodyBytes: b.bodyBytes, Depth: cfMaxNestingDepth(body), BlockDepth: -1}
		if len(body) > 0 {
			s.First = body[0].text
		}
		ref, def := cfMatcherFacts(body, depths)
		sh := cfSnippetPlacement(body, def)
		s.BlockNotAlone, s.PlaceholderLineStart, s.PlaceholderNoLiteral, s.DefBlock = sh.blockNotAlone, sh.placeholderLineStart, sh.placeholderNoLiteral, sh.defBlock
		weight := 0
		for i, t := range body {
			weight += CaddyfileTokenWeight(t.text)
			if t.text == "}" && !t.quoted && i+1 < len(body) && !cfIsNewLine(body, i+1) {
				s.MidLineClose = true
			}
			s.ArgUses += strings.Count(t.text, "{args")
			if ref[i] {
				s.BodyRefs++
			}
			if def[i] {
				s.DefArgUses += strings.Count(t.text, "{args")
				s.BodyDefWeight += CaddyfileTokenWeight(t.text)
			}
			if cfBlockPlaceholder(t.text) {
				s.BlockKeyed = s.BlockKeyed || t.text != "{block}"
				s.BlockUses++
				s.BlockDepth = max(s.BlockDepth, depths[i])
			}
		}
		s.BodyWeight = max(weight, s.BodyBytes)
		// Issue #184 round 14: Caddy records only the innermost import in
		// a token's import chain, so two expansions of one `import` line
		// of a snippet that end up back to back compare by line numbers,
		// and inside a block the second one's first line then continues
		// the first one's last line. Its first token may therefore be a
		// matcher reference rather than a definition, and when the last
		// line is a matcher definition, the next first line (and the
		// block it opens) is part of that definition.
		if len(body) > 0 {
			if strings.Contains(body[0].text, "@") {
				s.BodyRefs++
			}
			if def[len(body)-1] {
				s.BodyDefWeight, s.DefArgUses = s.BodyWeight, s.ArgUses
			}
		}
		s.HeadKeys = cfHeadKeys(body, depths)
		// The body's first token starts a line wherever it is written.
		s.Imports = cfImportSites(body, depths, func(i int) bool { return body[i].text == "import" }, true)
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
	depths := cfDepthsUpper(toks)
	for i, t := range toks {
		if depths[i] == 0 && cfIsNewLine(toks, i) && !(t.text == "}" && !t.quoted) {
			heads = append(heads, t.text)
		}
	}
	return heads, true
}

// MaskCaddyfileValues prepares src for an edit that works line by line
// (issue #184 round 11): every quoted, backtick or heredoc value is
// replaced by a one-line stand-in token, and a line Caddy's lexer joins to
// the previous one with a trailing backslash is put back on that line, so
// the edit sees each directive whole, on its own line, and cannot change
// text inside a value; unmask puts the original text back. The stand-ins
// hold no brace, `#` or space. ok is false when src cannot be read the way
// Caddy reads it, or already holds the stand-ins' marker characters; the
// caller must then leave src as it is.
func MaskCaddyfileValues(src string) (masked string, unmask func(string) string, ok bool) {
	if strings.ContainsAny(src, "\x01\x02") {
		return "", nil, false
	}
	toks, startByte, endByte, err := lexCaddyfileLenient(src)
	if err != nil {
		return "", nil, false
	}
	var b strings.Builder
	var pairs []string
	last := 0
	for i, t := range toks {
		if i > 0 && !cfIsNewLine(toks, i) && strings.Contains(src[endByte[i-1]:startByte[i]], "\n") {
			// A continued line: the gap holds the escaped line break.
			stand := fmt.Sprintf(" \x02%d\x02 ", len(pairs)/2)
			b.WriteString(src[last:endByte[i-1]])
			b.WriteString(stand)
			pairs = append(pairs, stand, src[endByte[i-1]:startByte[i]])
			last = startByte[i]
		}
		if t.quoted {
			stand := fmt.Sprintf("\x01%d\x01", len(pairs)/2)
			b.WriteString(src[last:startByte[i]])
			b.WriteString(stand)
			pairs = append(pairs, stand, src[startByte[i]:endByte[i]])
			last = endByte[i]
		}
	}
	if len(pairs) == 0 {
		return src, func(s string) string { return s }, true
	}
	b.WriteString(src[last:])
	r := strings.NewReplacer(pairs...)
	return b.String(), r.Replace, true
}
