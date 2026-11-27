// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// round11HiddenImports are administrator snippets whose `import` does not
// start a line, but which Caddy executes when the snippet is imported: the
// tokens a snippet brings in start a new line wherever they land, so an
// `import` that opens the body runs, and so does one written after an
// `import … { … }` block on that block's closing line.
var round11HiddenImports = map[string]string{
	"first token of the body": "(tag) { import inc }\n",
	"after an import block":   "(x) {\n\tX-A {block}\n}\n(tag) {\n\timport x {\n\t\ty\n\t} import inc\n}\n",
}

// Issue #184 round-11 review (1): every `import` in a snippet body is
// recorded, wherever it sits, with the name it imports.
func TestSnippetImportsAreRecordedWherever(t *testing.T) {
	for name, src := range round11HiddenImports {
		var tag *CaddyfileSnippet
		for _, sn := range CaddyfileSnippets(src) {
			if sn.Name == "tag" {
				tag = &sn
			}
		}
		if tag == nil {
			t.Fatalf("%s: snippet tag not found", name)
		}
		var names []string
		for _, imp := range tag.Imports {
			names = append(names, imp.Name)
		}
		if !slices.Contains(names, "inc") {
			t.Errorf("%s: imports %v, want inc among them", name, names)
		}
	}
	// An `import` that is another import's argument cannot be counted.
	sn := CaddyfileSnippets("(s) {\n\timport t import u\n}\n")
	if len(sn) != 1 || len(sn[0].Imports) != 2 || sn[0].Imports[0].Opaque || !sn[0].Imports[1].Opaque {
		t.Errorf("an import as an argument: %+v", sn)
	}
}

// Issue #184 round-11 review (1): differential check against Caddy. For
// every hidden-import shape, Caddy reads the file when the snippet is
// imported, and CaddyfileSnippets reports that import.
func TestHiddenSnippetImportsAgreeWithCaddy(t *testing.T) {
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	for name, file := range round11HiddenImports {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "inc"), []byte("X-From file\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cf := filepath.Join(dir, "Caddyfile")
		if err := os.WriteFile(cf, []byte(file+"probe.test {\n\theader {\n\t\timport tag\n\t}\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "adapt", "--config", cf, "--adapter", "caddyfile").Output()
		if err != nil {
			t.Errorf("%s: caddy adapt failed: %v", name, err)
			continue
		}
		if !strings.Contains(string(out), `"X-From":["file"]`) {
			t.Errorf("%s: fixture: Caddy did not read the file:\n%s", name, out)
		}
	}
}

// Issue #184 round-11 review (8): Caddy reads `(name)` with its `{` on the
// next line as a snippet, and so do `"" (name) {` and `} (name) {` after
// a block on one line; CaddyUI counts them the same way. Two keys, or a
// key list that runs past a line end, define none.
func TestSnippetDefinitionFormsAgreeWithCaddy(t *testing.T) {
	cases := map[string]bool{
		"(tag)\n{\n\theader X-From snippet\n}\n":                                true,
		"(tag)\n\n# note\n{\n\theader X-From snippet\n}\n":                      true,
		"\"\" (tag) {\n\theader X-From snippet\n}\n":                            true,
		"a.test {\n\trespond 1\n} (tag) {\n\theader X-From snippet\n}\n":        true,
		"(tag) (other) {\n\theader X-From snippet\n}\n":                         false,
		"a.test {\n\trespond 1\n}\n(tag) {\n\theader X-From snippet\n}\n":       true,
		"# headers\n(tag) {\n\theader X-From snippet\n}\n":                      true,
		"\uFEFF(tag) {\n\theader X-From snippet\n}\n":                           true,
		"a.test {\n\trespond `}\n(tag) {\n}\n{` 200\n}\n":                       false,
		"(tag)   # c\n\n{\n\theader X-From snippet\n}\n":                        true,
		"(tag),\n(other) {\n\theader X-From snippet\n}\n":                       false,
		"a.test {\n\theader {\n\t\timport probe\n\t}\n}\n(tag) {\n\tX-A b\n}\n": true,
	}
	for src, want := range cases {
		got := false
		for _, sn := range CaddyfileSnippets(src) {
			if sn.Name == "tag" {
				got = true
			}
		}
		if got != want {
			t.Errorf("%q: snippet tag defined=%v, want %v", src, got, want)
		}
	}
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	for src, want := range cases {
		if strings.Contains(src, "import probe") {
			continue
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "tag"), []byte("header X-From file\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cf := filepath.Join(dir, "Caddyfile")
		if err := os.WriteFile(cf, []byte(src+"\nprobe.test {\n\timport tag\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "adapt", "--config", cf, "--adapter", "caddyfile").CombinedOutput()
		fromSnippet := err == nil && strings.Contains(string(out), `"X-From":["snippet"]`)
		if want && !fromSnippet {
			t.Errorf("%q: CaddyUI counts a snippet, Caddy did not use one (err %v):\n%s", src, err, out)
		}
		if !want && fromSnippet {
			t.Errorf("%q: Caddy used a snippet CaddyUI does not count:\n%s", src, out)
		}
	}
}

// Issue #184 round-11 review (7): a snippet definition right after a
// top-level block's `}` on the same line is one, for a non-admin's text
// too; a `(name)` that is an argument is not.
func TestSnippetDefinedAfterABlockOnItsLine(t *testing.T) {
	for src, want := range map[string]bool{
		"a.test {\n\trespond 1\n} (x) {\n\theader X 1\n}\n":   true,
		"a.test {\n\trespond 1\n}   (x) {\n\theader X 1\n}\n": true,
		"a.test {\n\trespond (x) 200\n}\n":                    false,
		"a.test {\n\troute {\n\t} (x)\n}\n":                   false,
	} {
		use, ok := CaddyfileImportUse(src)
		if !ok || use.SnippetDefined != want {
			t.Errorf("%q: SnippetDefined=%v ok=%v, want %v", src, use.SnippetDefined, ok, want)
		}
	}
}

// cfSnippetPlaceholderReference is round 10's cfSnippetPlaceholder, which
// tried every later `}` for every `{args.`: the linear scan must agree.
func cfSnippetPlaceholderReference(text string) bool {
	if text == "{block}" || (strings.HasPrefix(text, "{blocks.") && strings.HasSuffix(text, "}")) {
		return true
	}
	if !strings.Contains(text, "{args") {
		return false
	}
	keyRe := regexp.MustCompile(`^args\.[+-]?[0-9]+$`)
	lastBracketClose := strings.LastIndex(text, "]}")
	for i := strings.Index(text, "{args"); i >= 0; {
		rest := text[i+1:]
		switch {
		case strings.HasPrefix(rest, "args."):
			for j := strings.IndexByte(rest, '}'); j >= 0; {
				if keyRe.MatchString(rest[:j]) {
					return true
				}
				next := strings.IndexByte(rest[j+1:], '}')
				if next < 0 {
					break
				}
				j += 1 + next
			}
		case strings.HasPrefix(rest, "args[") && lastBracketClose > i+6:
			return true
		}
		next := strings.Index(rest, "{args")
		if next < 0 {
			break
		}
		i += 1 + next
	}
	return false
}

// Issue #184 round-11 review (3): the `{args.` scan is linear. A 65 KB
// value of 5,400 `{args.` and 33,000 `}` took seconds; it must take
// milliseconds, and the result is unchanged from the quadratic scan.
func TestArgsPlaceholderScanIsLinear(t *testing.T) {
	value := strings.Repeat("{args.", 5400) + strings.Repeat("}", 33000)
	src := "a.test {\n\trespond `" + value + "` 200\n}\n"
	start := time.Now()
	use, ok := CaddyfileImportUse(src)
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Errorf("CaddyfileImportUse took %v on %d bytes", took, len(src))
	}
	if !ok || use.SnippetPlaceholder {
		t.Errorf("ok=%v SnippetPlaceholder=%v, want a plain value", ok, use.SnippetPlaceholder)
	}
	frags := []string{"{args", ".", "[", "]", "}", "{", "1", "+", "-", "x", "\\", "0", "args"}
	rng := rand.New(rand.NewSource(11))
	for range 200000 {
		var b strings.Builder
		for range 1 + rng.Intn(12) {
			b.WriteString(frags[rng.Intn(len(frags))])
		}
		s := b.String()
		if got, want := cfSnippetPlaceholder(s), cfSnippetPlaceholderReference(s); got != want {
			t.Fatalf("%q: %v, the quadratic scan says %v", s, got, want)
		}
	}
}

// Issue #184 round-11 review (6): an import reports what it passes to the
// snippet — the size of its arguments and of its block, how deeply the
// block nests, a lone brace among the arguments — and which import's
// block it sits in.
func TestImportSitesDescribeArgumentsAndBlock(t *testing.T) {
	src := "a.test {\n\timport s one \"two three\" {\n\t\troute {\n\t\t\timport t\n\t\t}\n\t}\n\timport u \"{\"\n}\n"
	use, ok := CaddyfileImportUse(src)
	if !ok || len(use.Imports) != 3 {
		t.Fatalf("ok=%v imports %+v", ok, use.Imports)
	}
	s, inner, brace := use.Imports[0], use.Imports[1], use.Imports[2]
	if s.Name != "s" || s.ArgBytes != len("one")+1+len("two three")+1 || s.BlockNest != 1 || s.Within != 0 || s.Depth != 1 {
		t.Errorf("import s: %+v", s)
	}
	if want := len("route") + 1 + 2 + len("import") + 1 + len("t") + 1 + 2; s.BlockBytes != want {
		t.Errorf("import s: block bytes %d, want %d", s.BlockBytes, want)
	}
	if inner.Name != "t" || inner.Within != 1 || inner.Depth != 3 {
		t.Errorf("import t: %+v", inner)
	}
	if brace.Name != "u" || !brace.BraceArg || brace.Within != 0 {
		t.Errorf("import u: %+v", brace)
	}
	sn := CaddyfileSnippets("(p) {\n\theader {\n\t\t{block}\n\t}\n\trespond {args[0]} {args[:]}\n\timport q {args[0]} {\n\t\t{block}\n\t}\n}\n")
	if len(sn) != 1 {
		t.Fatalf("snippets %+v", sn)
	}
	p := sn[0]
	if p.ArgUses != 3 || p.BlockUses != 2 || p.BlockDepth != 1 || len(p.Imports) != 1 {
		t.Errorf("snippet p: %+v", p)
	}
	if q := p.Imports[0]; q.Name != "q" || q.ArgArgUses != 1 || q.BlockBlockUses != 1 || q.BlockPlaceholderDepth != 0 || q.Opaque {
		t.Errorf("import q: %+v", q)
	}
}

// Issue #184 round-11 review (2): the masking the Advanced config repairs
// work on hides every quoted, backtick and heredoc value, joins a line
// continued with a backslash to its line, and puts all of it back.
func TestMaskCaddyfileValuesRoundTrips(t *testing.T) {
	src := "respond /down \"line1\nflush_interval -1\" 503\nheader X `a {\n}` \nrespond <<EOF\n\tread_buffer_size 4k\n\t}\n\tEOF 200\nheader_up X \\\n\ty\nflush_interval -1 # {\n"
	masked, unmask, ok := MaskCaddyfileValues(src)
	if !ok {
		t.Fatal("not masked")
	}
	for _, inside := range []string{"line1", "read_buffer_size", "a {"} {
		if strings.Contains(masked, inside) {
			t.Errorf("masked text still holds %q:\n%s", inside, masked)
		}
	}
	if strings.Count(masked, "\n") != 5 {
		t.Errorf("masked text has %d lines, want one per directive:\n%q", strings.Count(masked, "\n"), masked)
	}
	if got := unmask(masked); got != src {
		t.Errorf("round trip:\n%q\nwant\n%q", got, src)
	}
	if _, _, ok := MaskCaddyfileValues("respond <<EOF\nno end"); ok {
		t.Error("text Caddy's lexer refuses must not be masked")
	}
	if _, _, ok := MaskCaddyfileValues("header X \x01"); ok {
		t.Error("text holding the marker must not be masked")
	}
}

// Issue #184 round-11 review (9): the comment lines just above a block
// stay with it, and are not part of its head.
func TestSplitKeepsCommentsAboveABlock(t *testing.T) {
	src := "# site A\na.test {\n\trespond 1\n} # trailing\n\n# site B\n#   more\nb.test {\n\trespond 2\n}\nimport common\n# site C\nc.test {\n}\n"
	blocks := SplitCaddyfileBlocks(src)
	want := []string{
		"# site A\na.test {\n\trespond 1\n}",
		"# site B\n#   more\nb.test {\n\trespond 2\n}",
		"# site C\nc.test {\n}",
	}
	if !slices.Equal(blocks, want) {
		t.Fatalf("blocks %q, want %q", blocks, want)
	}
	for i, h := range []string{"a.test", "b.test", "c.test"} {
		if got := HeadOfBlock(blocks[i]); got != h {
			t.Errorf("head of %q: %q, want %q", blocks[i], got, h)
		}
	}
	sn := CaddyfileSnippets("# note\n(tag) {\n\tX 1\n}\n")
	if len(sn) != 1 || sn[0].Text != "(tag) {\n\tX 1\n}" {
		t.Errorf("a snippet's text does not carry the comment above it: %+v", sn)
	}
}

// round11TenantPositionalImports are a non-admin's texts with an `import`
// that does not start a line, and what Caddy 2.11.9 does with each: it
// executes the one after an `import … { … }` block on that block's closing
// line and the one right after a site's `{`, and refuses the one after a
// directive's `{` ("Unexpected next token after '{' on same line").
var round11TenantPositionalImports = map[string]bool{
	"(x) {\n\tX-A a\n}\na.test {\n\theader {\n\t\timport x {\n\t\t} import inc\n\t}\n}\n": true,
	"a.test { import inc\n\trespond 1\n}\n":                                               true,
	"a.test {\n\theader { import inc\n\t}\n}\n":                                           false,
}

// Issue #184 round-11 review (1): a non-admin's `import` that does not
// start a line is refused whatever Caddy would do with it.
func TestTenantPositionalImportsAreRefused(t *testing.T) {
	for src := range round11TenantPositionalImports {
		own := src
		if i := strings.Index(src, "a.test"); i > 0 {
			own = src[i:] // the tenant's part; (x) stands for an administrator snippet
		}
		use, ok := CaddyfileImportUse(own)
		if !ok || !use.ImportAsArgument {
			t.Errorf("%q: ImportAsArgument=%v ok=%v, want refused", own, use.ImportAsArgument, ok)
		}
	}
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	for src, reads := range round11TenantPositionalImports {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "inc"), []byte("X-From file\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cf := filepath.Join(dir, "Caddyfile")
		if err := os.WriteFile(cf, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		out, _ := exec.Command(bin, "adapt", "--config", cf, "--adapter", "caddyfile").CombinedOutput()
		if got := strings.Contains(string(out), "X-From"); got != reads {
			t.Errorf("%q: Caddy read the file=%v, want %v:\n%s", src, got, reads, out)
		}
	}
}

// cfImportSitesReference measures each import's block by walking it, as
// a first version did — quadratic when imports nest, so only a reference.
func cfImportSitesReference(toks []cfToken, depths []int, isImport func(i int) bool, bodyStart bool) []CaddyfileImport {
	var sites []CaddyfileImport
	var ranges [][2]int
	argOf := map[int]bool{}
	open := func(i int) bool { return !toks[i].quoted && toks[i].text == "{" }
	ref, def := cfMatcherFacts(toks, depths)
	for i := range toks {
		if !isImport(i) {
			continue
		}
		site := CaddyfileImport{Depth: depths[i], BlockPlaceholderDepth: -1, Opaque: bodyStart && argOf[i], InMatcherDef: def[i]}
		for p := len(sites) - 1; p >= 0; p-- {
			if ranges[p][0] <= i && i < ranges[p][1] {
				site.Within = p + 1
				break
			}
		}
		j := i + 1
		if j < len(toks) && !cfIsNewLine(toks, j) && !open(j) {
			site.Name = toks[j].text
			argOf[j] = true
			for j++; j < len(toks) && !cfIsNewLine(toks, j) && !open(j); j++ {
				t := toks[j].text
				argOf[j] = true
				site.ArgCount++
				site.ArgBytes += len(t) + 1
				site.ArgWeight += CaddyfileTokenWeight(t)
				if ref[j] {
					site.ArgRefs++
				}
				site.ArgImport = site.ArgImport || strings.Contains(t, "import")
				site.ArgNewline = site.ArgNewline || strings.ContainsAny(t, "\n\r") || toks[j].heredoc
				site.ArgArgUses += strings.Count(t, "{args")
				if cfBlockPlaceholder(t) {
					site.ArgBlockUses++
					site.Opaque = site.Opaque || bodyStart
				}
				if t == "{" || t == "}" {
					site.BraceArg = true
				}
			}
		}
		from, to := len(toks), len(toks)
		if j < len(toks) && !cfIsNewLine(toks, j) && open(j) {
			from = j + 1
			depth := depths[j] + 1
			for k := from; k < len(toks); k++ {
				if !toks[k].quoted && toks[k].text == "{" {
					depth++
				} else if !toks[k].quoted && toks[k].text == "}" && depth > 0 { // every `}` closes (round 15)
					depth--
				}
				if depth == depths[j] {
					to = k
					break
				}
			}
			contents := toks[from:to]
			// Round 15: nesting as Caddy closes blocks (cfDepths), not the
			// upper bound cfMaxNestingDepth keeps for administrators' text.
			for k, d := range cfDepths(contents) {
				if !contents[k].quoted && contents[k].text == "{" {
					site.BlockNest = max(site.BlockNest, d+1)
				}
			}
			for k, t := range contents {
				site.BlockBytes += len(t.text) + 1
				site.BlockWeight += CaddyfileTokenWeight(t.text)
				if ref[from+k] {
					site.BlockRefs++
				}
				if def[from+k] {
					site.BlockDefWeight += CaddyfileTokenWeight(t.text)
				}
				site.BlockArgUses += strings.Count(t.text, "{args")
				if cfBlockPlaceholder(t.text) {
					site.BlockBlockUses++
					site.BlockPlaceholderDepth = max(site.BlockPlaceholderDepth, depths[from+k]-depths[j]-1)
				}
			}
			// Round 14: braces with more on their line, the import's own
			// `{` and closing `}` included; and the second token of each
			// line at the block's level.
			for k := j; k <= to && k < len(toks); k++ {
				if !toks[k].quoted && (toks[k].text == "{" || toks[k].text == "}") && k+1 < len(toks) && !cfIsNewLine(toks, k+1) {
					site.BlockBraceNotLast = true
				}
			}
			// Round 15: the block's closing `}` may have more after it on
			// its line (every `}` closes); a line it starts counts too,
			// which errs towards more key words.
			for k := from; k <= to && k+1 < len(toks); k++ {
				if depths[k] == depths[j]+1 && cfIsNewLine(toks, k) && !cfIsNewLine(toks, k+1) {
					if a := toks[k+1]; a.quoted || (a.text != "{" && a.text != "}") {
						site.KeyArgs = append(site.KeyArgs, CaddyfileTokenAt{Line: a.line, Text: a.text})
					}
				}
			}
		}
		sites = append(sites, site)
		ranges = append(ranges, [2]int{from, to})
	}
	return sites
}

// Issue #184 round 11 (3, audit): describing imports is linear however
// they nest — 64 KiB of nested `import … {` takes milliseconds — and
// agrees with walking each block.
func TestImportSitesAreLinearAndAgreeWithAWalk(t *testing.T) {
	src := "a.test {\n" + strings.Repeat("import a {\n", 5900) + strings.Repeat("}\n", 5900) + "}\n"
	start := time.Now()
	use, ok := CaddyfileImportUse(src)
	if took := time.Since(start); took > 200*time.Millisecond || !ok || len(use.Imports) != 5900 {
		t.Errorf("nested imports: took %v, ok=%v, %d imports", took, ok, len(use.Imports))
	}
	frags := []string{"import", "a", "{", "}", "\n", " ", "{block}", "{args[:]}", "\"{\"", "x", "{blocks.k}", "`}`", "\t"}
	rng := rand.New(rand.NewSource(1184))
	for range 50000 {
		var b strings.Builder
		for range 1 + rng.Intn(30) {
			b.WriteString(frags[rng.Intn(len(frags))])
			b.WriteString(" ")
		}
		toks, err := lexCaddyfile(b.String())
		if err != nil {
			continue
		}
		depths := cfDepths(toks)
		for _, body := range []bool{false, true} {
			isImport := func(i int) bool { return toks[i].text == "import" && (body || cfIsNewLine(toks, i)) }
			got := cfImportSites(toks, depths, isImport, body)
			want := cfImportSitesReference(toks, depths, isImport, body)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%q (body=%v):\n got %+v\nwant %+v", b.String(), body, got, want)
			}
		}
	}
}
