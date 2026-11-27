// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"fmt"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

// caddyfileTransportLines returns the `transport http` options the export
// writes for p's own Upstream settings, one per line, unindented; nil when
// none is set. They mirror the transport BuildProxyRoute generates for the
// options the export represents. An https upstream is not verified unless
// SSL verify upstream is on (v2.9.9), so the export says so too: without
// tls_insecure_skip_verify the exported proxy would refuse the self-signed
// upstream the live route accepts (T-0931).
func caddyfileTransportLines(p models.ProxyHost) []string {
	var l []string
	if p.ForwardScheme == "https" {
		l = append(l, "tls")
		if !p.SSLVerifyUpstream {
			l = append(l, "tls_insecure_skip_verify")
		}
	}
	if p.UpstreamSNI != "" {
		l = append(l, "tls_server_name "+caddyfileValue(p.UpstreamSNI))
	}
	if p.KeepaliveConns > 0 {
		l = append(l, fmt.Sprintf("keepalive_idle_conns %d", p.KeepaliveConns))
	}
	if p.UpstreamTimeoutSec > 0 {
		l = append(l, fmt.Sprintf("dial_timeout %ds", p.UpstreamTimeoutSec))
		l = append(l, fmt.Sprintf("response_header_timeout %ds", p.UpstreamTimeoutSec))
	}
	if p.DisableUpstreamCompression {
		l = append(l, "compression off") // v2.12.52
	}
	return l
}

// advancedTransport is the `transport` sub-directive of a proxy host's
// Advanced `reverse_proxy { … }` block, as takeAdvancedTransport found it.
type advancedTransport struct {
	found     bool   // the block has a transport sub-directive
	mergeable bool   // exactly one, `transport http`, laid out so it can be taken out
	module    string // the transport module named
	body      string // the text between its braces, verbatim ("" without a block)
}

// takeAdvancedTransport finds the transport sub-directive in inner, the
// contents of the Advanced config's reverse_proxy block. When it can be
// merged with the generated options it is taken out of inner (rest is
// inner without it); otherwise rest is inner unchanged.
//
// The live sync merges the Advanced reverse_proxy block's transport over
// the generated one key by key (MergeReverseProxyOverrides). Written as a
// second `transport` block in a Caddyfile, it would instead replace the
// generated one whole, losing the upstream TLS settings (T-0931). One
// `transport http` block holding the generated options first and the
// Advanced ones after them adapts to the merged transport: Caddy applies
// a block's options in order, so where both set one, the Advanced one wins,
// as it does live.
//
// Only a transport directive at the block's top level that starts its line
// and is followed by its module on that line, with nothing after its
// closing brace on that line, is taken out. Tokens are read with the
// Caddy-faithful lexer, so text inside a quoted string, backtick string or
// heredoc is never mistaken for one.
func takeAdvancedTransport(inner string) (rest string, t advancedTransport) {
	if strings.TrimSpace(inner) == "" {
		return inner, t
	}
	toks, err := lexCaddyfile(inner)
	if err != nil {
		return inner, t
	}
	brace := func(i int, b string) bool { return toks[i].text == b && !toks[i].quoted }
	at, depth := -1, 0
	for i := range toks {
		if depth == 0 && toks[i].text == "transport" && cfIsNewLine(toks, i) {
			t.found = true
			if at >= 0 {
				// Two of them: Caddy keeps the last, the live merge folds
				// both; neither reads like one merged block.
				return inner, advancedTransport{found: true}
			}
			at = i
		}
		if brace(i, "{") {
			depth++
		} else if brace(i, "}") {
			depth--
		}
	}
	if at < 0 {
		return inner, t
	}
	if at+1 >= len(toks) || cfIsNewLine(toks, at+1) || brace(at+1, "{") {
		return inner, t
	}
	t.module = toks[at+1].text
	if t.module != "http" {
		return inner, t
	}
	runes := []rune(inner)
	lineStart := func(off int) int {
		for off > 0 && runes[off-1] != '\n' {
			off--
		}
		return off
	}
	afterLine := func(off int) int {
		for off < len(runes) && runes[off] != '\n' {
			off++
		}
		if off < len(runes) {
			off++
		}
		return off
	}
	from := lineStart(toks[at].start)
	var to int
	switch {
	case at+2 >= len(toks) || cfIsNewLine(toks, at+2):
		// `transport http` with no block.
		to = afterLine(toks[at+1].end)
	case brace(at+2, "{"):
		d, j := 1, at+3
		for ; j < len(toks) && d > 0; j++ {
			if brace(j, "{") {
				d++
			} else if brace(j, "}") {
				d--
			}
		}
		closeTok := j - 1
		if d != 0 || (j < len(toks) && !cfIsNewLine(toks, j)) {
			return inner, t
		}
		t.body = string(runes[toks[at+2].end:toks[closeTok].start])
		to = afterLine(toks[closeTok].end)
	default:
		return inner, t
	}
	t.mergeable = true
	return string(runes[:from]) + string(runes[to:]), t
}

// writeTransportBlock writes the reverse_proxy block's transport: the
// generated options merged with the Advanced block's `transport http`
// when there is one (see takeAdvancedTransport). When the Advanced block
// sets a transport that cannot take them, it is written as given and a
// comment names the generated options it replaces.
func writeTransportBlock(b *strings.Builder, gen []string, adv advancedTransport) {
	if len(gen) == 0 {
		return
	}
	if adv.found && !adv.mergeable {
		fmt.Fprintf(b, "\t\t# Upstream transport settings from CaddyUI (%s) are not written here: the Advanced config sets its own transport, which replaces them in a Caddyfile.\n",
			caddyfileComment(strings.Join(gen, "; ")))
		return
	}
	b.WriteString("\t\ttransport http {\n")
	for _, l := range gen {
		b.WriteString("\t\t\t" + l + "\n")
	}
	if body := strings.TrimRight(strings.TrimLeft(adv.body, "\r\n"), " \t\r\n"); strings.TrimSpace(body) != "" {
		b.WriteString("\t\t\t# from Advanced config\n")
		b.WriteString(caddyfileIndent(body+"\n", "\t\t\t", true))
	}
	b.WriteString("\t\t}\n")
}
