// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
)

// round15Blocker is what follows the non-admin's opening lines in the
// round-15 review's shapes: a `}` with more after it on its line, which
// Caddy reads as closing the block there.
const round15Blocker = "header {\n\t} header X 1\n}\n"

// round15PanicRepro is the round-15 review's first shape: the import that
// follows runs where Caddy, but not the old reading of the text, is at the
// top level of the file.
func round15PanicRepro() (admin, raw, adv string) {
	admin = "(s) {\n\t{block}\n\theader X 1\n}\n"
	raw = "t.example.test {\n\t" + round15Blocker + "import s\n"
	adv = "header {\n} header X 1\n}\nimport s\nx.example.test {\n"
	return admin, raw, adv
}

// round15MemoryRepro is the round-15 review's second shape, a site block
// passed to a snippet as an import's block, on the given number of ports.
func round15MemoryRepro(ports int) (admin, raw, adv string) {
	admin = "(s) {\n\t{block}\n}\n"
	var b strings.Builder
	b.WriteString("import s {\n\t")
	for p := 0; p < ports; p++ {
		if p > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, ":%d", 10001+p)
	}
	b.WriteString(" {\n\t\t@m path" + strings.Repeat(" /x", 200) + "\n\t\t@z path /z\n\t\troute {\n")
	for i := 0; i < 130; i++ {
		b.WriteString("\t\t\tabort @m\n\t\t\tabort @z\n")
	}
	b.WriteString("\t\t}\n\t}\n}\n")
	raw = "t.example.test {\n\t" + round15Blocker + b.String()
	adv = "header {\n} header X 1\n}\n" + b.String() + "x.example.test {\n"
	return admin, raw, adv
}

// Issue #184 round-15 review (security 1): Caddy's parser closes a block
// at any unquoted `}`, wherever it sits on its line, so text that puts
// more after a `}` on its line ends a site block where the old reading of
// the text kept it open, and an import after it runs at the top level.
// Both review shapes are refused before Caddy (0 adapts) on every path,
// the raw-route and proxy-host Advanced saves among them.
func TestCloseBraceFollowedByTokensIsRefusedBeforeCaddy(t *testing.T) {
	t.Run("panic shape", func(t *testing.T) {
		admin, raw, adv := round15PanicRepro()
		round13RefusedEverywhere(t, admin, raw, adv)
	})
	t.Run("memory shape", func(t *testing.T) {
		admin, raw, adv := round15MemoryRepro(500)
		if len(raw) > maxTenantCaddyfileBytes {
			t.Fatalf("the repro is %d bytes", len(raw))
		}
		round13RefusedEverywhere(t, admin, raw, adv)
	})
}

// Issue #184 round 15: in a non-admin's text an unquoted `}` must end its
// line — read the way Caddy's lexer reads lines, so a trailing comment is
// no token, a backslash continues the line, and a quoted or backtick `}`
// is a value — and every other shape stays available.
func TestCloseBraceMustEndItsLine(t *testing.T) {
	set := tenantSnippetSetFrom(caddy.CaddyfileSnippets("(s) {\n\theader X-S 1\n}\n"))
	lim := tenantTextLimits{maxDepth: tenantMaxNestingDepth, maxBytes: maxTenantCaddyfileBytes}
	refused := map[string]string{
		"token after":   "t.example.test {\n\theader {\n\t} header X 1\n}\n",
		"site after":    "a.example.test {\n\theader X 1\n} b.example.test {\n\theader Y 1\n}\n",
		"brace after":   "t.example.test {\n\theader {\n\t} }\n",
		"continued":     "t.example.test {\n\theader {\n\t}\\\nheader X 1\n}\n",
		"CRLF":          "t.example.test {\r\n\theader {\r\n\t} header X 1\r\n}\r\n",
		"in import":     "t.example.test {\n\timport s\n\theader {\n\t} import s\n}\n",
		"quoted after":  "t.example.test {\n\theader {\n\t} \"}\"\n}\n",
		"comment later": "t.example.test {\n\theader {\n\t} x # y\n}\n",
	}
	for name, text := range refused {
		why, _, _ := tenantTextCheck(text, set, lim)
		if !strings.Contains(why, "closing `}` must end its line") {
			t.Errorf("%s: want the closing-brace refusal, got %q", name, why)
		}
		if why := tenantAdaptTextRules(tenantSnippetPrefix(set)+text, set); why == "" {
			t.Errorf("%s: allowed on its way to the adapter", name)
		}
	}
	allowed := map[string]string{
		"comment after": "t.example.test {\n\theader {\n\t\tX 1\n\t} # done\n}\n",
		"comment only":  "t.example.test {\n\theader X 1\n} #}\n",
		"quoted brace":  "t.example.test {\n\trespond \"}\" 200\n\trespond `}` 200\n}\n",
		"CRLF":          "t.example.test {\r\n\theader {\r\n\t\tX 1\r\n\t}\r\n}\r\n",
		"multi-line": "a.example.test, b.example.test {\n\timport s\n\t@api path /api/*\n\troute @api {\n\t\theader {\n\t\t\tX-A 1\n\t\t}\n\t\treverse_proxy 127.0.0.1:8080 {\n\t\t\theader_up X-B 2\n\t\t}\n\t}\n\thandle {\n\t\trespond \"ok\" 200\n\t}\n}\n" +
			"c.example.test {\n\tredir https://a.example.test{uri}\n}\n",
	}
	for name, text := range allowed {
		if why, _, _ := tenantTextCheck(text, set, lim); why != "" {
			t.Errorf("%s: refused: %q", name, why)
		}
		if why := tenantAdaptTextRules(tenantSnippetPrefix(set)+text, set); why != "" {
			t.Errorf("%s: refused on its way to the adapter: %q", name, why)
		}
	}
}

// Issue #184 round 15: legitimate text — a `}` followed by a comment, and
// a site written over many lines — still reaches the adapter on every
// path (the recorder answers each adapt with an error, so a path that
// adapts reports that answer, never the closing-brace refusal).
func TestCloseBraceRuleKeepsLegitimateText(t *testing.T) {
	adv := "@api path /api/*\nheader @api {\n\tX-A 1\n} # api\nimport s\nhandle_path /static/* {\n\troot * /srv\n\tfile_server\n}\n"
	raw := "t.example.test {\n" + adv + "}\n"
	s, conn, sid, rec, _, tenant := newAdaptRecorderFixture(t)
	round13Admin(t, s, "(s) {\n\theader X-S 1\n}\n")
	for path, resp := range tenantCaddyfilePaths(t, s, conn, sid, tenant, raw, adv) {
		body := resp.Body.String()
		if strings.Contains(body, "closing `}`") || strings.Contains(body, "Not allowed") {
			t.Errorf("%s: refused (%.300s)", path, body)
		}
	}
	if len(rec.seen()) == 0 {
		t.Errorf("no text reached Caddy's adapter")
	}
}

// Issue #184 round 15: the guard's reading of blocks matches Caddy's —
// a `}` closes a block wherever it sits on its line — so an import after
// such a line is at the depth Caddy reads it at, and a site's listeners
// are counted for the site Caddy reads.
func TestGuardDepthsCloseAtEveryBrace(t *testing.T) {
	_, raw, _ := round15PanicRepro()
	use, ok := caddy.CaddyfileImportUse(raw)
	if !ok || len(use.Imports) != 1 {
		t.Fatalf("ok=%v imports=%d", ok, len(use.Imports))
	}
	if d := use.Imports[0].Depth; d != 0 {
		t.Errorf("the import after `} header X 1` is at depth %d; Caddy reads it at the top level", d)
	}
	if !use.CloseNotLast {
		t.Errorf("CloseNotLast is not set")
	}
	two := "a.example.test {\n\theader {\n\t} x\n}\n:1 :2 :3 {\n\trespond 1\n}\n"
	if use, _ := caddy.CaddyfileImportUse(two); use.SiteListeners != 3 {
		t.Errorf("SiteListeners = %d, want 3", use.SiteListeners)
	}
}
