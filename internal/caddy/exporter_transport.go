// SPDX-License-Identifier: Apache-2.0

package caddy

import (
	"fmt"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

// caddyfileTransportLines returns the `transport http` options the export
// writes for p's own Upstream settings, one per line, unindented; nil when
// none is set. These are the options the export has always written (the
// keep-alive pool is only approximated: live sets keep_alive's per-host
// limit and idle timeout); BuildProxyRoute generates more, which the export
// leaves out. An https upstream is not verified unless
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
	mergeable bool   // the last one is `transport http`, and each is laid out so it can be taken out
	module    string // the module the last one names
	body      string // the last one's text between its braces, verbatim ("" without a block)
	dropped   int    // earlier transport sub-directives taken out (Caddy keeps only the last)
}

// takeAdvancedTransport finds the transport sub-directives in inner, the
// contents of the Advanced config's reverse_proxy block. When they can be
// merged with the generated options they are taken out of inner (rest is
// inner without them); otherwise rest is inner unchanged.
//
// The live sync adapts the Advanced reverse_proxy block through Caddy,
// which keeps only its last transport, and merges that over the generated
// transport key by key (MergeReverseProxyOverrides). Written as a second
// `transport` block in a Caddyfile, it would instead replace the generated
// one whole, losing the upstream TLS settings (T-0931). One `transport
// http` block holding the generated options first and the last Advanced
// block's options after them adapts to the merged transport: Caddy applies
// a block's options in order, so where both set one, the Advanced one wins,
// as it does live. Earlier Advanced transport blocks are left out, as Caddy
// leaves them out.
//
// Only a transport directive at the block's top level that starts its line
// and is followed by its module on that line, with nothing after its
// closing brace on that line, can be taken out. Tokens are read with the
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
	var ats []int
	depth := 0
	for i := range toks {
		if depth == 0 && toks[i].text == "transport" && cfIsNewLine(toks, i) {
			ats = append(ats, i)
		}
		if brace(i, "{") {
			depth++
		} else if brace(i, "}") {
			depth--
		}
	}
	if len(ats) == 0 {
		return inner, t
	}
	t.found = true
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
	// span returns the source range of the transport directive at token
	// at, whole lines, plus its module and the text between its braces.
	span := func(at int) (from, to int, module, body string, ok bool) {
		if at+1 >= len(toks) || cfIsNewLine(toks, at+1) || brace(at+1, "{") {
			return 0, 0, "", "", false
		}
		module = toks[at+1].text
		from = lineStart(toks[at].start)
		switch {
		case at+2 >= len(toks) || cfIsNewLine(toks, at+2):
			// `transport http` with no block.
			return from, afterLine(toks[at+1].end), module, "", true
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
				return 0, 0, "", "", false
			}
			return from, afterLine(toks[closeTok].end), module, string(runes[toks[at+2].end:toks[closeTok].start]), true
		}
		return 0, 0, "", "", false
	}
	var b strings.Builder
	kept := 0
	for k, at := range ats {
		from, to, module, body, ok := span(at)
		if !ok {
			return inner, advancedTransport{found: true}
		}
		if k == len(ats)-1 {
			t.module, t.body = module, body
		}
		b.WriteString(string(runes[kept:from]))
		kept = to
	}
	if t.module != "http" {
		return inner, advancedTransport{found: true, module: t.module}
	}
	b.WriteString(string(runes[kept:]))
	t.mergeable = true
	t.dropped = len(ats) - 1
	return b.String(), t
}

// writeTransportBlock writes the reverse_proxy block's transport: the
// generated options merged with the Advanced block's last `transport http`
// when there is one (see takeAdvancedTransport). When the Advanced block
// sets a transport that cannot take them (another module, or a layout that
// cannot be taken out), it is written as given and a comment names the
// generated options it replaces.
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
	body := adv.body
	// A comment after the opening brace, on its line, goes on a line of its
	// own, so it does not set the indentation the rest is measured against.
	head := ""
	if h, tail, ok := strings.Cut(body, "\n"); ok {
		if h = strings.TrimSpace(h); h == "" || strings.HasPrefix(h, "#") {
			head, body = h, tail
		}
	}
	body = strings.TrimRight(strings.TrimLeft(body, "\r\n"), " \t\r\n")
	if adv.dropped > 0 || head != "" || strings.TrimSpace(body) != "" {
		b.WriteString("\t\t\t# from Advanced config\n")
	}
	if adv.dropped > 0 {
		fmt.Fprintf(b, "\t\t\t# (%d earlier transport block(s) in the Advanced config left out: Caddy uses only the last one)\n", adv.dropped)
	}
	if head != "" {
		b.WriteString("\t\t\t" + head + "\n")
	}
	if strings.TrimSpace(body) != "" {
		b.WriteString(caddyfileIndent(body+"\n", "\t\t\t", true))
	}
	b.WriteString("\t\t}\n")
}
