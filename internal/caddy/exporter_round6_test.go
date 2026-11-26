// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/models"
)

// cfValues lexes src and returns every token's value, or fails the test.
func cfValues(t *testing.T, src string) []cfToken {
	t.Helper()
	toks, err := lexCaddyfile(src)
	if err != nil {
		t.Fatalf("does not lex: %v\n%s", err, src)
	}
	return toks
}

// Issue #184 round-5 review (1b): the exporter took a `reverse_proxy {` line
// out of the Advanced config by counting lines and braces, so one inside a
// quoted string became real reverse_proxy sub-directives in the export.
// The split now reads the text as Caddy's lexer does.
func TestSplitAdvancedReverseProxyBlockNeverSplitsStrings(t *testing.T) {
	notSplit := map[string]string{
		"double-quoted": "vars caddyui_note \"\nreverse_proxy {\n\tto 127.0.0.1:2019\n}\n\"",
		"backtick":      "vars caddyui_note `\nreverse_proxy {\n\thandle_response {\n\t\tfile_server\n\t}\n}\n`",
		"heredoc":       "respond <<TXT\n\treverse_proxy {\n\t\tto 127.0.0.1:2019\n\t}\n\tTXT 200",
		"escaped quote": "vars n \"a \\\"\nreverse_proxy {\n\tto 127.0.0.1:2019\n}\n\"",
		"with matcher":  "reverse_proxy @x {\n\tflush_interval -1\n}",
		"with upstream": "reverse_proxy 10.0.0.1:80 {\n\tflush_interval -1\n}",
		"nested":        "handle /x {\n\treverse_proxy {\n\t\tto 10.0.0.1:80\n\t}\n}",
		"continued":     "header X a \\\nreverse_proxy {\n\tflush_interval -1\n}",
		"quoted brace":  "reverse_proxy \"{\"\n\tflush_interval -1\n}",
		"comment":       "# reverse_proxy {\n#\tto 127.0.0.1:2019\n# }",
	}
	for name, src := range notSplit {
		rest, inner := splitAdvancedReverseProxyBlock(src)
		if rest != src || inner != "" {
			t.Errorf("%s: must not be split, got rest=%q inner=%q", name, rest, inner)
		}
	}

	split := []struct{ name, src, rest, inner string }{
		{"plain", "encode gzip\nreverse_proxy {\n\tflush_interval -1\n}\n", "encode gzip\n", "\tflush_interval -1\n"},
		{"at end without newline", "reverse_proxy {\n\tflush_interval -1\n}", "", "\tflush_interval -1\n"},
		{"nested block", "reverse_proxy {\n\ttransport http {\n\t\tread_timeout 30s\n\t}\n}\nheader X 1", "header X 1", "\ttransport http {\n\t\tread_timeout 30s\n\t}\n"},
		{"string inside block", "reverse_proxy {\n\theader_up X-Note \"}\nfile_server\"\n}\n", "", "\theader_up X-Note \"}\nfile_server\"\n"},
		{"comment after brace", "reverse_proxy { # merged\n\tflush_interval -1\n} # end\nencode gzip", "encode gzip", "\tflush_interval -1\n"},
		{"two blocks", "reverse_proxy {\n\tflush_interval -1\n}\nencode gzip\nreverse_proxy {\n\tlb_try_duration 5s\n}\n", "encode gzip\n", "\tflush_interval -1\n\tlb_try_duration 5s\n"},
	}
	for _, tc := range split {
		rest, inner := splitAdvancedReverseProxyBlock(tc.src)
		if rest != tc.rest || inner != tc.inner {
			t.Errorf("%s: got rest=%q inner=%q, want rest=%q inner=%q", tc.name, rest, inner, tc.rest, tc.inner)
		}
	}
}

// The review's two payloads, rendered for a tenant: the quoted text stays
// one quoted token with its value unchanged, nothing becomes a
// reverse_proxy sub-directive, and the veto is handed exactly the block
// that is written.
func TestQuotedReverseProxyTextExportsAsText(t *testing.T) {
	payloads := map[string]string{
		"file_server": "vars caddyui_note \"\nreverse_proxy {\n\thandle_response {\n\t\troot * /\n\t\tfile_server browse\n\t}\n}\n\"",
		"admin API":   "vars caddyui_note \"\nreverse_proxy {\n\tto 127.0.0.1:2019\n}\n\"",
	}
	for name, adv := range payloads {
		var judged string
		opts := ExportOptions{
			TenantOwned:   func(sql.NullInt64) bool { return true },
			ProxyHostVeto: func(_ models.ProxyHost, site string) string { judged = site; return "" },
		}
		p := models.ProxyHost{ID: 1, Domains: "fs.example.test", ForwardScheme: "http", ForwardHost: "203.0.113.10", ForwardPort: 8080, Enabled: true, SSLEnabled: true, AdvancedConfig: adv}
		out := RenderProxyHostCaddyfileWithOptions(p, nil, opts)
		if judged != out {
			t.Errorf("%s: the veto must judge exactly the block written\njudged:\n%s\nwritten:\n%s", name, judged, out)
		}
		want := cfValues(t, adv)[2].text
		var got []string
		for _, tok := range cfValues(t, out) {
			if tok.quoted {
				got = append(got, tok.text)
			}
			if !tok.quoted && (tok.text == "to" || tok.text == "file_server" || tok.text == "handle_response") {
				t.Errorf("%s: %q became a directive in the export:\n%s", name, tok.text, out)
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: the quoted value must be written unchanged, got %q want %q:\n%s", name, got, want, out)
		}
	}
}

// Indenting the Advanced text into the site block leaves string values and
// heredocs exactly as they were.
func TestCaddyfileIndentKeepsValues(t *testing.T) {
	src := "header X \"a\n  b\"\nrespond <<TXT\n\t\tline one\n\n\t\t  two\n\t\tTXT 200\n\theader Y `c\nd`\n"
	before := cfValues(t, src)
	for _, dedent := range []bool{false, true} {
		out := caddyfileIndent(src, "\t\t", dedent)
		after := cfValues(t, out)
		if len(before) != len(after) {
			t.Fatalf("dedent=%v: token count changed:\n%s", dedent, out)
		}
		for i := range before {
			if before[i].text != after[i].text {
				t.Errorf("dedent=%v: token %d changed: %q -> %q\n%s", dedent, i, before[i].text, after[i].text, out)
			}
		}
	}
}

// Issue #184 round-5 review (2): an Advanced config that defines a matcher
// with the generated name (`@caddyui_path`, `@blocked`) adapted fine on its
// own, but the export then defined the name twice and Caddy refused the
// whole file. The generated matchers now take a free name, and
// checkCaddyfileSites refuses any duplicate definition.
func TestGeneratedMatcherNamesNeverCollide(t *testing.T) {
	adv := "@caddyui_path path /zzz\n@blocked path /private\nheader @caddyui_path X-Z 1\nhandle /n {\n\t@caddyui_path_2 path /q\n\theader @caddyui_path_2 X-Q 1\n}\nabort @blocked"
	admin := ExportOptions{TenantOwned: func(sql.NullInt64) bool { return false }}
	var hosts []models.ProxyHost
	for i, strip := range []bool{false, true} {
		p := models.ProxyHost{ID: int64(i + 1), Domains: "m" + string(rune('a'+i)) + ".example.test", ForwardScheme: "http", ForwardHost: "10.0.0.5", ForwardPort: 8080,
			Enabled: true, SSLEnabled: true, BlockCommonExploits: true, PathMatcher: "/api", StripPathPrefix: strip, AdvancedConfig: adv}
		hosts = append(hosts, p)
		out := RenderProxyHostCaddyfileWithOptions(p, nil, admin)
		if strings.Contains(out, "respond 503") {
			t.Fatalf("strip=%v: host must export, got:\n%s", strip, out)
		}
		for _, want := range []string{"@caddyui_path_3 path /api /api/*", "reverse_proxy @caddyui_path_3 ", "@blocked_2 path /.env*", "respond @blocked_2 403", "@caddyui_path path /zzz", "@blocked path /private"} {
			if !strings.Contains(out, want) {
				t.Errorf("strip=%v: want %q in:\n%s", strip, want, out)
			}
		}
	}
	// Without a clash the names are unchanged.
	plain := hosts[0]
	plain.AdvancedConfig = "header X 1"
	if out := RenderProxyHostCaddyfile(plain); !strings.Contains(out, "\t@blocked path ") || !strings.Contains(out, "reverse_proxy @caddyui_path ") {
		t.Errorf("default names must stay:\n%s", out)
	}

	dupCorpus := []struct {
		src string
		ok  bool
	}{
		{"a.test {\n\t@x path /a\n\t@x path /b\n}\n", false},
		{"a.test {\n\t@x path /a\n\thandle /h {\n\t\t@x path /b\n\t}\n}\n", false},
		{"a.test {\n\t@x path /a\n\troute {\n\t\t@x path /b\n\t}\n}\n", false},
		{"a.test {\n\thandle /a {\n\t\t@x path /a\n\t}\n\thandle /b {\n\t\t@x path /b\n\t}\n}\n", true},
		{"a.test {\n\t@x path /a\n\treverse_proxy 10.0.0.1:80 {\n\t\t@x status 5xx\n\t\thandle_response @x {\n\t\t\trespond no\n\t\t}\n\t}\n}\n", true},
		{"a.test {\n\t@x {\n\t\tpath /a\n\t}\n}\nb.test {\n\t@x path /b\n}\n", true},
	}
	for _, tc := range dupCorpus {
		_, err := checkCaddyfileSites(tc.src, nil)
		if (err == nil) != tc.ok {
			t.Errorf("checkCaddyfileSites(%q) error = %v, want ok=%v", tc.src, err, tc.ok)
		}
	}

	caddyBin := lookCaddy(t)
	if caddyBin == "" {
		return
	}
	// The two hosts and their export adapt as one file; so do Caddy's
	// verdicts on the duplicate-definition corpus above.
	dir := t.TempDir()
	f := filepath.Join(dir, "Caddyfile")
	_ = os.WriteFile(f, []byte(RenderServerCaddyfile("", hosts, nil, nil, nil, admin)), 0o644)
	caddyAdapt(t, caddyBin, f)
	for i, tc := range dupCorpus {
		f := filepath.Join(dir, "dup"+string(rune('a'+i)))
		_ = os.WriteFile(f, []byte(tc.src), 0o644)
		err := exec.Command(caddyBin, "adapt", "--config", f, "--adapter", "caddyfile").Run()
		if (err == nil) != tc.ok {
			t.Errorf("Caddy disagrees on %q: adapt error = %v, checkCaddyfileSites ok=%v", tc.src, err, tc.ok)
		}
	}
}

// Issue #184 round-5 review (4): Caddy expands `import` whatever quoting
// its name token has.
func TestCaddyfileImportArgumentsFindsQuotedImports(t *testing.T) {
	for src, want := range map[string]string{
		"x.test {\n\t\"import\" /etc/passwd\n}":    "/etc/passwd",
		"x.test {\n\t`import` /etc/passwd\n}":      "/etc/passwd",
		"x.test {\n\timport \"/etc/passwd\"\n}":    "/etc/passwd",
		"x.test {\n\theader X a\n\timport snip\n}": "snip",
		"x.test {\n\t<<I\n\timport\n\tI /etc/x\n}": "/etc/x",
	} {
		args, ok := CaddyfileImportArguments(src)
		if !ok || len(args) != 1 || args[0] != want {
			t.Errorf("%q: got %q ok=%v, want [%q]", src, args, ok, want)
		}
	}
	for _, src := range []string{"x.test {\n\theader X \"import /etc/passwd\"\n}", "x.test {\n\trespond import 200\n}", "x.test {\n\theader X a \\\n\timport /etc/passwd\n}"} {
		if args, ok := CaddyfileImportArguments(src); !ok || len(args) != 0 {
			t.Errorf("%q: no import directive here, got %q ok=%v", src, args, ok)
		}
	}
	if _, ok := CaddyfileImportArguments("x.test {\n\t\"import /etc/passwd\n}"); ok {
		t.Errorf("text that does not lex must be reported")
	}
}
