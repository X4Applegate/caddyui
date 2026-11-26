// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// round10Lookalikes are texts whose quoted, backtick or heredoc values
// look like a top-level `(tag) { }` block to a scanner that does not read
// them the way Caddy does.
var round10Lookalikes = map[string]string{
	"backtick":          "a.test {\n\trespond `}\n(tag) {\n}\n{` 200\n\theader {\n\t\timport tag\n\t}\n}\n",
	"heredoc":           "a.test {\n\trespond <<EOF\n\t}\n\t(tag) {\n\t}\n\t{\n\tEOF 200\n\theader {\n\t\timport tag\n\t}\n}\n",
	"quote in backtick": "a.test {\n\theader X-Q `\"`\n\trespond \"}\n(tag) {\n}\n{\" 200\n\theader {\n\t\timport tag\n\t}\n}\n",
}

// Issue #184 round 10 (1): the block splitter reads text on Caddy's own
// tokens, so a value that only looks like a snippet definition defines
// none — for Caddy, and now for CaddyUI. The splitter before the fix
// (LegacySnippetHeads) read one in each of these.
func TestSnippetLookalikesInValuesDefineNothing(t *testing.T) {
	for name, src := range round10Lookalikes {
		if got := ExtractSnippets(src); len(got) != 0 {
			t.Errorf("%s: ExtractSnippets found %q", name, got)
		}
		if got := CaddyfileSnippets(src); len(got) != 0 {
			t.Errorf("%s: CaddyfileSnippets found %v", name, got)
		}
		if !LegacySnippetHeads(src)["(tag)"] {
			t.Errorf("%s: fixture: the pre-fix splitter must read a (tag) block here", name)
		}
		blocks := SplitCaddyfileBlocks(src)
		if len(blocks) != 1 || HeadOfBlock(blocks[0]) != "a.test" {
			t.Errorf("%s: want one block for a.test, got %q", name, blocks)
		}
	}
	// A real definition next to such a value is still found, whole.
	src := "(tag) {\n\theader X-Tag `}{`\n}\n\n" + round10Lookalikes["backtick"]
	got := CaddyfileSnippets(src)
	if len(got) != 1 || got[0].Name != "tag" || got[0].Text != "(tag) {\n\theader X-Tag `}{`\n}" {
		t.Errorf("want the one real definition, got %+v", got)
	}
}

// Issue #184 round 10 (1): differential check of the splitter against the
// lexer. Every block starts and ends on a token boundary and lexes to
// exactly the tokens it covers in the whole text, with balanced unquoted
// braces; and the snippet names it reports are exactly the blocks whose
// only key is `(name)`. Inputs are random mixes of quotes, backticks,
// heredocs, comments, escapes and braces.
func TestSplitterAgreesWithTheLexer(t *testing.T) {
	frags := []string{"(tag)", "(x)", "{", "}", "\n", " ", "\t", "`", "\"", "\\", "#", "a.test", "respond", "import tag",
		"<<EOF\n", "\nEOF", "EOF", "}\n(tag) {\n}\n{", "\r\n", "{}", ",", "\"\"", "\uFEFF", "\xe9"}
	rng := rand.New(rand.NewSource(184))
	checked := 0
	for range 20000 {
		var b strings.Builder
		for range 1 + rng.Intn(24) {
			b.WriteString(frags[rng.Intn(len(frags))])
		}
		src := b.String()
		all, _, _, err := lexCaddyfileLenient(src)
		blocks, toks := caddyfileBlocks(src)
		if err != nil {
			if blocks != nil {
				t.Fatalf("%q: text the lexer refuses must give no blocks", src)
			}
			continue
		}
		if len(toks) != len(all) {
			t.Fatalf("%q: token mismatch", src)
		}
		for _, bl := range blocks {
			checked++
			// A leading space keeps a byte-order mark that starts the
			// block a token, as it is mid-text.
			sub, _, _, err := lexCaddyfileLenient(" " + bl.text)
			if err != nil {
				t.Fatalf("%q: block %q does not lex: %v", src, bl.text, err)
			}
			whole := all[bl.first : bl.close+1]
			if len(sub) != len(whole) {
				t.Fatalf("%q: block %q lexes to %d tokens, %d in the whole text", src, bl.text, len(sub), len(whole))
			}
			depth := 0
			for i, tk := range sub {
				if tk.text != whole[i].text || tk.quoted != whole[i].quoted || tk.heredoc != whole[i].heredoc {
					t.Fatalf("%q: block %q token %d: %q, whole text %q", src, bl.text, i, tk.text, whole[i].text)
				}
				if !tk.quoted && tk.text == "{" {
					depth++
				} else if !tk.quoted && tk.text == "}" {
					depth--
				}
				if depth == 0 && i < len(sub)-1 && i >= bl.open-bl.first {
					t.Fatalf("%q: block %q closes early", src, bl.text)
				}
			}
			// The closing token is an unquoted `}`; at the end of the text
			// it may be written `"}` or `}\`, which Caddy's lexer reads so.
			if last := sub[len(sub)-1]; depth != 0 || last.text != "}" || last.quoted {
				t.Fatalf("%q: block %q does not end on its balancing brace", src, bl.text)
			}
			// Round 11: a snippet's key is read as Caddy's addresses()
			// reads it (cfSnippetName; checked against Caddy in
			// TestSnippetDefinitionFormsAgreeWithCaddy).
			want := ""
			if name, ok := cfSnippetName(all, bl.first, bl.open); ok && strings.HasSuffix(bl.text, "}") {
				want = name
			}
			if bl.snippet != want {
				t.Fatalf("%q: block %q: snippet %q, want %q", src, bl.text, bl.snippet, want)
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d blocks checked", checked)
	}
}

// Issue #184 round 10 (1): what CaddyfileSnippets reports agrees with
// Caddy. For each admin-style file, every name it reports resolves as a
// snippet when imported (Caddy adapts `import name` without looking for a
// file), and the lookalike names it does not report make Caddy look for a
// file — which here exists, so the difference is visible in the result.
func TestSnippetDefinitionsAgreeWithCaddy(t *testing.T) {
	bin := lookCaddy(t)
	if bin == "" {
		return
	}
	files := map[string]string{
		"real":      "(tag) {\n\theader X-From snippet\n}\n",
		"quoted":    "(tag) {\n\theader X-From \"snippet }{\"\n}\n",
		"backtick":  "(tag) {\n\theader X-From `snip\n}\n(fake) {\n}\n{pet`\n}\n",
		"heredoc":   "(tag) {\n\theader X-From <<EOF\n\t\t}\n\t\t(fake) {\n\t\t}\n\t\t{\n\t\tEOF\n}\n",
		"lookalike": "a.test {\n\trespond `}\n(fake) {\n}\n{` 200\n}\n",
	}
	for name, file := range files {
		got := map[string]bool{}
		for _, s := range CaddyfileSnippets(file) {
			got[s.Name] = true
		}
		for _, probe := range []string{"tag", "fake"} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, probe), []byte("header X-From file\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cf := filepath.Join(dir, "Caddyfile")
			src := file + "\nprobe.test {\n\timport " + probe + "\n}\n"
			if err := os.WriteFile(cf, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(bin, "adapt", "--config", cf, "--adapter", "caddyfile").Output()
			if err != nil {
				t.Errorf("%s/%s: caddy adapt failed: %v", name, probe, err)
				continue
			}
			fromFile := strings.Contains(string(out), `"X-From":["file"]`)
			if got[probe] == fromFile {
				t.Errorf("%s: CaddyUI says snippet %q defined=%v, but Caddy read the file=%v:\n%s", name, probe, got[probe], fromFile, out)
			}
		}
	}
}

// Issue #184 round 10 (4): the adapt client's depth limit applies to text
// CaddyUI's strict lexer refuses but Caddy reads — a byte-order mark
// mid-text, a Latin-1 byte in a comment — so it never reaches Caddy too
// deep; shallow text like that still goes to Caddy.
func TestDepthLimitCountsTextCaddyReadsLeniently(t *testing.T) {
	var calls atomic.Int64
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"result":{}}`)
	}))
	defer fake.Close()
	cl := New(fake.URL, "", "")
	deep := func(extra string) string {
		return "x.test {\n" + extra + strings.Repeat("route {\n", 1500) + "respond 1\n" + strings.Repeat("}\n", 1500) + "}\n"
	}
	for name, src := range map[string]string{
		"BOM mid-text":        deep("\theader X-A \uFEFFb\n"),
		"Latin-1 in comment":  deep("\t# caf\xe9\n"),
		"invalid UTF-8 token": deep("\theader X-A \xff\xfe\n"),
	} {
		if _, ok := lexCaddyfile(src); ok == nil {
			t.Fatalf("%s: fixture: the strict lexer must refuse this text", name)
		}
		calls.Store(0)
		if _, err := cl.Adapt(src); err == nil || !strings.Contains(err.Error(), "levels deep") {
			t.Errorf("%s, depth 1501: want refused for its depth, got %v", name, err)
		}
		if calls.Load() != 0 {
			t.Errorf("%s, depth 1501: the text reached the adapter", name)
		}
	}
	shallow := "x.test {\n\t# caf\xe9\n\theader X-A \uFEFFb\n\trespond 1\n}\n"
	calls.Store(0)
	if _, err := cl.Adapt(shallow); err != nil || calls.Load() != 1 {
		t.Errorf("shallow text with a Latin-1 comment: want adapted, got %v (calls %d)", err, calls.Load())
	}
	if bin := lookCaddy(t); bin != "" {
		f := filepath.Join(t.TempDir(), "Caddyfile")
		if err := os.WriteFile(f, []byte(shallow), 0o644); err != nil {
			t.Fatal(err)
		}
		caddyAdapt(t, bin, f) // fails the test if Caddy refuses it
	}
}

// caddyFinalizeHeredoc is Caddy v2.11.9's finalizeHeredoc (lexer.go),
// quadratic `out +=` included: the reference cfFinalizeHeredoc must match.
func caddyFinalizeHeredoc(val []rune, marker string) ([]rune, error) {
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
			return nil, fmt.Errorf("bad padding")
		}
		out += strings.ReplaceAll(lineText[len(paddingToStrip):]+"\n", "\r", "")
	}
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return []rune(out), nil
}

// Issue #184 round 10 (5): heredoc lexing is linear, with output identical
// to Caddy's.
func TestHeredocLexingIsLinearAndUnchanged(t *testing.T) {
	for _, body := range []string{
		"EOF", "a\nEOF", "\ta\n\tb\n\tEOF", "\ta\n\n\tb\n\tEOF", "\ta\r\n\r\n\tb\r\n\tEOF", "  x\n\n\n  y\n  EOF", "a\n b\n\tEOF",
	} {
		val := []rune(body)
		want, wantErr := caddyFinalizeHeredoc(val, "EOF")
		got, gotErr := cfFinalizeHeredoc(val, "EOF")
		if (wantErr == nil) != (gotErr == nil) || string(got) != string(want) {
			t.Errorf("%q: got %q (%v), Caddy %q (%v)", body, string(got), gotErr, string(want), wantErr)
		}
	}
	big := "x.test {\n\trespond <<EOF\n" + strings.Repeat("\n", 64<<10) + "\tEOF 200\n}\n"
	start := time.Now()
	if _, err := lexCaddyfile(big); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("64 KiB of blank heredoc lines took %v to lex", d)
	}
}

// Issue #184 round 10 (7): `{args.x}` with a non-numeric key is text to
// Caddy, so it is not a snippet placeholder; `{args.N}` still is.
func TestArgsPlaceholderNeedsANumericKey(t *testing.T) {
	for src, want := range map[string]bool{
		"x {\n\ta \"const s = `${args.x}`\"\n}": false,
		"x {\n\ta {args.x}\n}":                  false,
		"x {\n\ta {args.1x}\n}":                 false,
		"x {\n\ta {args.1}\n}":                  true,
		"x {\n\ta {args.+1}\n}":                 true,
		"x {\n\ta {args.01}\n}":                 true,
		"x {\n\ta {args.x}{args.2}\n}":          true,
		"x {\n\ta {args.x}}{args.y}\n}":         false,
		"x {\n\ta {args[x]}\n}":                 true,
	} {
		use, ok := CaddyfileImportUse(src)
		if !ok || use.SnippetPlaceholder != want {
			t.Errorf("%q: SnippetPlaceholder=%v ok=%v, want %v", src, use.SnippetPlaceholder, ok, want)
		}
	}
}

// Issue #184 round 10 (6): nesting is counted for every kind of block, not
// only `handle`, and import depths are reported per import.
func TestNestingDepthCountsEveryBlockKind(t *testing.T) {
	kinds := []string{"route {", "handle_path /p/* {", "@m {", "header {", "reverse_proxy {", "handle {", "handle_errors {"}
	for _, k := range kinds {
		for _, n := range []int{1, 7, 33} {
			src := "x.test {\n" + strings.Repeat(k+"\n", n) + "respond 1\n" + strings.Repeat("}\n", n) + "}\n"
			if d, ok := CaddyfileNestingDepth(src); !ok || d != n+1 {
				t.Errorf("%q ×%d: depth %d ok=%v, want %d", k, n, d, ok, n+1)
			}
			use, ok := CaddyfileImportUse(src)
			if !ok || use.MaxDepth != n+1 {
				t.Errorf("%q ×%d: CaddyfileImportUse depth %d, want %d", k, n, use.MaxDepth, n+1)
			}
		}
	}
	mixed := "x.test {\n" + strings.Join(kinds, "\n") + "\nimport tag\n" + strings.Repeat("}\n", len(kinds)) + "import tag\n}\n"
	use, ok := CaddyfileImportUse(mixed)
	if !ok || use.MaxDepth != len(kinds)+1 || !slices.Equal(use.ImportDepths, []int{len(kinds) + 1, 1}) {
		t.Errorf("mixed: depth %d, import depths %v", use.MaxDepth, use.ImportDepths)
	}
	sn := CaddyfileSnippets("(s) {\n\troute {\n\t\theader {\n\t\t\timport t\n\t\t}\n\t}\n}\n(t) {\n\tX-A b\n}\n")
	if len(sn) != 2 || sn[0].Depth != 2 || len(sn[0].Imports) != 1 || sn[0].Imports[0].Name != "t" || sn[0].Imports[0].Depth != 2 || sn[1].Depth != 0 {
		t.Errorf("snippet body depths: %+v", sn)
	}
}
