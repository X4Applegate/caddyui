// SPDX-License-Identifier: Apache-2.0

// T-0713 precedence probe for the caddy-l4 listener wrapper.
//
// WHAT THIS MEASURES
// ------------------
// caddy-l4 v0.1.3 rewrote part of the matching loop (layer4/routes.go). v0.1.2
// tracked pending routes with one watermark, `lastNeedsMoreIdx`; v0.1.3 adds
// `anyRouteNeedsMore(before)`, which consults the per-route status map instead:
//
//	anyRouteNeedsMore := func(before int) bool {
//		for i, s := range routesStatus {
//			if s == routeNeedsMore && i > lastMatchedRouteIdx && i < before {
//				return true
//			}
//		}
//		return false
//	}
//
// used in two places: the catch-all guard, and the decision to keep looping for
// more bytes. The upstream comment names what the watermark got wrong — "a
// conclusively unmatched route can bury an earlier one that is still waiting for
// data" — and that is exactly the shape this probe builds.
//
// So the SAME first bytes can land on a DIFFERENT route between versions. This
// program sends each of a set of crafted first-byte sequences, reads back the
// label of whichever upstream answered, and prints a table.
//
// WHY IT IS A DIFFERENTIAL AND NOT A PASS/FAIL GATE
// -------------------------------------------------
// The other two v0.1.3 fixes have a right answer: a leaked ClientHello and a
// deadlocked reload are defects on any reading, so T-0631's harness can demand
// that the buggy image FAIL. A precedence change has no such anchor — until the
// intended behaviour is established, "the catch-all won" is not self-evidently
// worse than "the pending route won". Asserting one would bake today's guess
// into a gate.
//
// So: `-baseline` writes the observed table, `-compare` reads one back and
// reports differences. Differences are reported as DIFFERENCES, exit 0.
//
// Exit non-zero is reserved for what is broken under ANY version:
//
//	-strict        a probe reached no destination at all (nothing answered)
//	(always)       a route answered for a protocol it does not match, which is
//	               not a precedence question but a matcher bug
//
// WHY EACH PROBE IS SENT IN TWO WRITES
// ------------------------------------
// The divergence needs a FIRST packet that leaves at least one matcher
// inconclusive. Writing the whole sequence at once usually lands it in a single
// TCP segment, so every matcher gets all the bytes on the first prefetch, no
// route is ever `routeNeedsMore`, and both versions agree — the probe would
// measure nothing. So a probe sends `head`, waits `gap`, then sends `tail`: the
// first prefetch sees only `head`.
//
// This is a real client pattern, not a contrivance: an SSH client sends its
// identification string and waits, and an RDP client's connection request can
// straddle segments on a slow link.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// probe is one crafted first-byte sequence.
type probe struct {
	Name string
	// head is sent first and is what the FIRST prefetch sees. Keeping a matcher
	// short of its threshold here is what makes it `routeNeedsMore`.
	Head []byte
	// tail is sent after Gap, so matching has to loop to see it.
	Tail []byte
	Gap  time.Duration
	// Why this sequence is interesting, printed with the result so a table row
	// is self-explaining.
	Why string
	// Expect names the route that SHOULD win on a protocol reading of the
	// bytes, when there is one. Empty means "no single defensible answer" —
	// those rows are recorded, never asserted.
	Expect string
}

// Matcher byte thresholds, measured from the caddy-l4 v0.1.3 matcher sources
// rather than assumed:
//
//	ssh       4 bytes   bytes.Equal(p, []byte("SSH-"))                  l4ssh/matcher.go
//	postgres  8 bytes   4-byte length + 4-byte code, readFirstMessage   l4postgres/matcher.go
//	rdp      19 bytes   TPKTHeaderBytesTotal + X224CrqBytesTotal        l4rdp/matcher.go
//	tls       full ClientHello
const (
	sshThreshold      = 4
	postgresThreshold = 8
	rdpThreshold      = 19
)

func probes() []probe {
	// A valid RDP connection request: TPKT header (version 3, reserved 0,
	// 16-bit length) followed by an X.224 connection request. 19 bytes total,
	// which is RDPConnReqBytesMin.
	rdpFull := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT: version 3, reserved 0, length 0x13 = 19
		0x0e, 0xe0, // X224 Crq: length 14, PDU type 0xe0 (CR)
		0x00, 0x00, 0x00, 0x00, 0x00, // dst ref, src ref, class
		0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP negotiation request
	}

	// A PostgreSQL SSLRequest: length 8, code 80877103.
	pgSSL := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

	return []probe{
		// ---- controls: one packet, fully conclusive for one route ----------
		// These must agree across versions. A difference here would mean
		// something far more basic than precedence changed, so they are the
		// harness's own sanity check.
		{
			Name: "ssh-complete-1packet",
			Head: []byte("SSH-2.0-T0713\r\n"),
			Why:  "control: 15 bytes, conclusive for ssh on the first prefetch",
			// ssh is route 0 and matches on 4 bytes, so it wins before any
			// later route is even consulted. No pending route exists.
			Expect: "ssh",
		},
		{
			Name: "rdp-complete-1packet",
			Head: rdpFull,
			Why:  "control: full 19-byte RDP connection request in one write",
			// ssh (route 0) and postgres (route 1) are both conclusive-false on
			// these bytes, rdp (route 2) is conclusive-true.
			Expect: "rdp",
		},
		{
			Name: "postgres-complete-1packet",
			Head: pgSSL,
			Why:  "control: full 8-byte PostgreSQL SSLRequest in one write",
			// NOTE the ordering consequence, which is a CaddyUI fact rather than
			// a caddy-l4 one: postgres is route 1 only because its proxy was
			// created second. ListLayer4Proxies sorts by (protocol, port, id),
			// so creation order IS precedence and the operator cannot change it.
			Expect: "postgres",
		},

		// ---- the divergence shape -----------------------------------------
		// MEASURED BOUNDARY, by scanning every head length 1..19 against both
		// images: the two versions agree for head <= 4, diverge for head 5..18,
		// and agree again at 19 (the whole request arrives in the first prefetch,
		// so rdp is conclusive immediately and no route is ever pending).
		//
		// The boundary is the SSH threshold of 4 bytes, NOT the postgres one. That
		// is worth writing down because it is the opposite of the obvious guess,
		// and the obvious guess was made here first and was wrong:
		//
		//   head <= 4   ssh (route 0) cannot decide either -- 4 bytes is exactly
		//               its threshold and io.ReadFull needs all 4 -- so route 0 is
		//               itself routeNeedsMore. v0.1.2's watermark is left pointing
		//               AT a genuinely pending route, the `lastNeedsMoreIdx <
		//               len(routes)` test at routes.go:238 holds, matching loops
		//               for more bytes on its own, and both versions land rdp.
		//
		//   head >= 5   ssh DECIDES: the bytes are not "SSH-", conclusive-false.
		//               The `i >= lastNeedsMoreIdx` branch advances the watermark
		//               to 1; each later deciding route advances it again, until it
		//               equals len(routes) while rdp is still routeNeedsMore.
		//               routes.go:238 is then false, matching STOPS, and under
		//               v0.1.2 the connection reaches no route at all.
		//
		// So the route that buries the pending one is ssh at index 0 -- the
		// EARLIEST route, not a later one. anyRouteNeedsMore repairs it by
		// scanning routesStatus rather than trusting a single watermark, which is
		// precisely what the upstream comment claims for it.
		//
		// Note what v0.1.2 does with the dropped connection: it closes at ~301ms,
		// when the tail arrives, NOT at the 3s matching_timeout. It is not a slow
		// client being timed out; matching concluded and nothing was left to run.
		{
			Name: "rdp-split-after-4",
			Head: rdpFull[:4],
			Tail: rdpFull[4:],
			Gap:  300 * time.Millisecond,
			Why: fmt.Sprintf("%d of %d RDP bytes: AT the ssh threshold, so ssh is pending too",
				sshThreshold, rdpThreshold),
			// The agreeing side of the boundary, and the control that localises the
			// change: same protocol, same split pattern, ONE byte less than the
			// diverging probe below. Keep this paired with rdp-split-after-5.
			Expect: "rdp",
		},
		{
			Name: "rdp-split-after-5",
			Head: rdpFull[:5],
			Tail: rdpFull[5:],
			Gap:  300 * time.Millisecond,
			Why:  "5 of 19 RDP bytes: ONE byte past the ssh threshold -- the exact boundary",
			// The diverging side. Together with rdp-split-after-4 these two probes
			// straddle the boundary in a single byte, which is the tightest
			// statement the harness can make about where the behaviour changed.
			Expect: "rdp",
		},
		{
			Name: "rdp-split-after-7",
			Head: rdpFull[:7],
			Tail: rdpFull[7:],
			Gap:  300 * time.Millisecond,
			Why:  "7 of 19 RDP bytes: one byte short of the postgres threshold",
			// Inside the diverging window. This probe exists because it falsified
			// the first hypothesis: if the postgres threshold were the boundary, 7
			// bytes would agree across versions. It diverges, so it does not.
			Expect: "rdp",
		},
		{
			Name: "rdp-split-after-8",
			Head: rdpFull[:8],
			Tail: rdpFull[8:],
			Gap:  300 * time.Millisecond,
			Why:  "8 of 19 RDP bytes: past the postgres threshold, still short for rdp",
			// Inside the diverging window, with ssh AND postgres both decided and
			// rdp still pending -- two buried routes rather than one.
			Expect: "rdp",
		},
		{
			Name: "rdp-split-after-18",
			Head: rdpFull[:18],
			Tail: rdpFull[18:],
			Gap:  300 * time.Millisecond,
			Why:  "18 of 19 RDP bytes: one byte short of the rdp threshold",
			// The upper edge: a single missing byte is the difference between a
			// conclusive matcher and a pending one. Pairs with the
			// rdp-complete-1packet control at 19, which agrees across versions.
			Expect: "rdp",
		},
		{
			Name: "postgres-split-after-4",
			Head: pgSSL[:4],
			Tail: pgSSL[4:],
			Gap:  300 * time.Millisecond,
			Why:  "4 of 8 PostgreSQL bytes: postgres inconclusive, ssh conclusive-false",
			// Pending route (1) is EARLIER than the conclusive ones after it
			// (2, 3), so this exercises the scan's `i > lastMatchedRouteIdx`
			// bound from the other side.
			Expect: "postgres",
		},
		{
			Name: "ssh-split-after-2",
			Head: []byte("SS"),
			Tail: []byte("H-2.0-T0713\r\n"),
			Gap:  300 * time.Millisecond,
			Why:  fmt.Sprintf("2 of %d ssh bytes: the FIRST route is the pending one", sshThreshold),
			// Route 0 pending with nothing matched yet: lastMatchedRouteIdx is
			// -1, so `i > lastMatchedRouteIdx` admits index 0. Both versions
			// should loop here (the watermark still points AT 0), so this row
			// is the one that shows the two versions agreeing on the simple
			// case — a difference here would be a surprise worth chasing.
			Expect: "ssh",
		},
		{
			Name:   "ssh-split-after-3",
			Head:   []byte("SSH"),
			Tail:   []byte("-2.0-T0713\r\n"),
			Gap:    300 * time.Millisecond,
			Why:    "3 of 4 ssh bytes: one byte short on the first route",
			Expect: "ssh",
		},

		// ---- no defensible single answer: recorded, never asserted ---------
		{
			Name: "junk-5-bytes-then-nothing",
			Head: []byte{0xde, 0xad, 0xbe, 0xef, 0x01},
			Why:  "5 bytes matching nothing, no tail: every matcher conclusive-false or starved",
			// ssh rejects (not "SSH-"), postgres rejects (length 0xdeadbeef is
			// absurd), rdp is INCONCLUSIVE forever because the tail never comes,
			// tls is inconclusive. Where this lands is a timeout-ordering
			// question, not a protocol one — so no Expect.
			Expect: "",
		},
		{
			Name: "junk-20-bytes",
			Head: []byte{
				0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			Why: "20 bytes matching nothing: every layer4 matcher conclusive-false",
			// All four routes decide and reject, so this should fall through to
			// the wrapped listener. Under a CaddyUI config "passthrough" is the
			// correct destination, which is why it is the expectation and not a
			// blank.
			Expect: "passthrough",
		},
		{
			Name: "single-byte-then-nothing",
			Head: []byte{0x16},
			Why:  "one byte, the TLS record type, no tail: tls and rdp both starved",
			// 0x16 is the TLS handshake record type, so this is the first byte
			// of a real ClientHello that never arrives — the slow-client shape
			// `matching_timeout` exists for. Where it lands is a timeout
			// question.
			Expect: "",
		},
	}
}

// observation is one probe's measured outcome.
type observation struct {
	Probe    string `json:"probe"`
	Landed   string `json:"landed"` // the label the upstream announced
	Bytes    int    `json:"bytes"`  // bytes the upstream received
	Hex      string `json:"hex"`    // first bytes as the upstream saw them
	Err      string `json:"err,omitempty"`
	Why      string `json:"why"`
	Expect   string `json:"expect,omitempty"`
	Duration string `json:"duration"`
}

type record struct {
	Image    string        `json:"image"`
	L4       string        `json:"caddy_l4"`
	CatchAll bool          `json:"catch_all_route"`
	Observed []observation `json:"observed"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18453", "shared host:port under test")
	image := flag.String("image", "", "image label for the record")
	l4 := flag.String("l4", "", "caddy-l4 version, read from the binary by run.sh")
	catchAll := flag.Bool("catch-all", false, "the config carries a hand-added catch-all route")
	baseline := flag.String("baseline", "", "write the observed table to this file")
	compare := flag.String("compare", "", "compare against a previously written table")
	strict := flag.Bool("strict", false, "exit 1 if any probe reached no destination at all")
	repeat := flag.Int("repeat", 3, "runs per probe; a landing that is not stable is reported as unstable")
	flag.Parse()

	ps := probes()
	fmt.Printf("== phase: route precedence (%d probes x %d runs) ==\n", len(ps), *repeat)
	if *l4 != "" {
		fmt.Printf("   caddy-l4: %s   catch-all route: %v\n", *l4, *catchAll)
	}

	rec := record{Image: *image, L4: *l4, CatchAll: *catchAll}
	unstable := 0
	unreached := 0

	for _, p := range ps {
		// Repeat each probe. A landing that varies run to run is a real finding
		// in its own right (it would mean precedence here is a race), and
		// recording one sample as if it were THE behaviour is how a flaky
		// result becomes a documented fact.
		var got []observation
		for i := 0; i < *repeat; i++ {
			got = append(got, run(*addr, p))
			time.Sleep(50 * time.Millisecond)
		}
		obs := got[0]
		stable := true
		for _, g := range got[1:] {
			if g.Landed != obs.Landed {
				stable = false
			}
		}
		if !stable {
			unstable++
			var seen []string
			for _, g := range got {
				seen = append(seen, g.Landed)
			}
			obs.Landed = "UNSTABLE:" + strings.Join(seen, "/")
		}
		if obs.Landed == "none" {
			unreached++
		}
		rec.Observed = append(rec.Observed, obs)

		flag := "  "
		switch {
		case !stable:
			flag = "!!"
		case obs.Expect != "" && obs.Landed != obs.Expect:
			// Not an error: on a differential the point is to SEE this.
			flag = " *"
		}
		fmt.Printf("   %s %-28s -> %-14s (%d bytes, %s)  %s\n",
			flag, p.Name, obs.Landed, obs.Bytes, obs.Duration, p.Why)
		if obs.Expect != "" && obs.Landed != obs.Expect {
			fmt.Printf("        note: a protocol reading of these bytes says %q\n", obs.Expect)
		}
		if obs.Err != "" {
			fmt.Printf("        err: %s\n", obs.Err)
		}
	}

	exit := 0

	// A route answering for a protocol it does not match is a MATCHER bug, not a
	// precedence question, so it fails under any version. Checked explicitly
	// because the differential's whole posture is "do not assert", and this is
	// the one thing that must still be asserted.
	for i, o := range rec.Observed {
		if o.Landed == "ssh" && !strings.HasPrefix(ps[i].Name, "ssh") {
			fmt.Printf("   FAIL %s landed on the ssh route, which matches only a \"SSH-\" prefix\n", ps[i].Name)
			exit = 1
		}
	}

	if *baseline != "" {
		b, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "precedence: marshal: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(*baseline, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "precedence: write %s: %v\n", *baseline, err)
			os.Exit(2)
		}
		fmt.Printf("   wrote %s\n", *baseline)
	}

	if *compare != "" {
		b, err := os.ReadFile(*compare)
		if err != nil {
			fmt.Fprintf(os.Stderr, "precedence: read %s: %v\n", *compare, err)
			os.Exit(2)
		}
		var old record
		if err := json.Unmarshal(b, &old); err != nil {
			fmt.Fprintf(os.Stderr, "precedence: parse %s: %v\n", *compare, err)
			os.Exit(2)
		}
		if diffs := report(old, rec); diffs == 0 {
			fmt.Printf("\n   no precedence differences between %s and %s\n", old.Image, rec.Image)
		}
	}

	if unstable > 0 {
		fmt.Printf("\n   %d probe(s) did not land on the same route every run.\n", unstable)
		fmt.Printf("   That is a finding, not a flake: precedence for those bytes is timing-dependent.\n")
	}
	if unreached > 0 {
		fmt.Printf("\n   %d probe(s) reached NO destination.\n", unreached)
		if *strict {
			fmt.Printf("   -strict: treating that as a failure.\n")
			exit = 1
		} else {
			fmt.Printf("   Not scored as a failure: with no tail and every matcher starved, a\n")
			fmt.Printf("   connection dropped at matching_timeout is a legitimate outcome.\n")
		}
	}
	os.Exit(exit)
}

// report prints the differences between two recorded tables.
func report(old, new record) int {
	byName := map[string]observation{}
	for _, o := range old.Observed {
		byName[o.Probe] = o
	}
	type diff struct{ probe, from, to, why string }
	var diffs []diff
	for _, n := range new.Observed {
		o, ok := byName[n.Probe]
		if !ok {
			continue
		}
		if o.Landed != n.Landed {
			diffs = append(diffs, diff{n.Probe, o.Landed, n.Landed, n.Why})
		}
	}
	if len(diffs) == 0 {
		return 0
	}
	sort.Slice(diffs, func(i, j int) bool { return diffs[i].probe < diffs[j].probe })

	fmt.Printf("\n== precedence differential: %s (caddy-l4 %s) vs %s (caddy-l4 %s) ==\n",
		old.Image, old.L4, new.Image, new.L4)
	fmt.Printf("\n| probe | %s | %s | what the bytes are |\n", old.L4, new.L4)
	fmt.Printf("| --- | --- | --- | --- |\n")
	for _, d := range diffs {
		fmt.Printf("| `%s` | %s | %s | %s |\n", d.probe, d.from, d.to, d.why)
	}
	fmt.Printf("\n   %d probe(s) land on a DIFFERENT route between these versions.\n", len(diffs))
	fmt.Printf("   This is reported, not failed: a precedence change is not a defect until the\n")
	fmt.Printf("   intended behaviour is established. Read the table before a host depends on it.\n")
	return len(diffs)
}

// run sends one probe and reports where it landed.
//
// The return is NAMED so the deferred duration write lands in the returned
// value. With an unnamed return the defer writes to a local the caller never
// sees, and every row reported duration "" — measured, not theorised: the first
// version of this harness printed an empty duration column on all 24 rows.
// Duration matters here because it is what distinguishes a route that matched
// promptly from one that only landed after matching_timeout elapsed.
func run(addr string, p probe) (o observation) {
	o = observation{Probe: p.Name, Why: p.Why, Expect: p.Expect, Landed: "none"}
	t0 := time.Now()
	defer func() { o.Duration = time.Since(t0).Round(time.Millisecond).String() }()

	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		o.Err = "dial: " + err.Error()
		return o
	}
	defer c.Close()

	// Generous but bounded. caddy-l4's default matching_timeout is 3s, so a
	// starved probe is resolved well inside this; a deadline shorter than the
	// matching timeout would cut off a legitimate slow landing and read as
	// "nothing answered".
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err := c.Write(p.Head); err != nil {
		o.Err = "write head: " + err.Error()
		return o
	}
	if len(p.Tail) > 0 {
		// The gap is the point: it forces the first prefetch to see only head,
		// which is what leaves a matcher inconclusive.
		time.Sleep(p.Gap)
		if _, err := c.Write(p.Tail); err != nil {
			// Not fatal. If the connection was already closed (a route matched
			// and its handler finished, or matching timed out), the head alone
			// decided the outcome and that IS the measurement.
			o.Err = "write tail: " + err.Error()
		}
	}

	// Read the sink's announcement, or Caddy's passthrough response.
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil && line == "" {
		if o.Err == "" {
			o.Err = "read: " + err.Error()
		}
		return o
	}
	o.Landed, o.Bytes, o.Hex = parseLanding(line)
	return o
}

// parseLanding reads the sink's "LANDED=<label> BYTES=<n> HEX=<...>" line, or
// recognises Caddy's own HTTP response as the pass-through landing.
func parseLanding(line string) (label string, n int, hexs string) {
	line = strings.TrimSpace(line)

	// Caddy answering means the connection fell through the wrapper to the
	// wrapped listener. On an HTTP server that reply is an HTTP error for
	// non-HTTP bytes, which is still an unambiguous "passthrough" signal.
	if strings.HasPrefix(line, "HTTP/") {
		return "passthrough", 0, ""
	}
	if strings.Contains(line, "LANDED=passthrough") {
		return "passthrough", 0, ""
	}
	if !strings.HasPrefix(line, "LANDED=") {
		// Something answered that is neither a sink nor Caddy. Return it
		// verbatim rather than guessing: an unrecognised answer must not be
		// silently folded into a known bucket.
		return "unrecognised:" + truncate(line, 40), 0, ""
	}
	for _, f := range strings.Fields(line) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "LANDED":
			label = v
		case "BYTES":
			_, _ = fmt.Sscanf(v, "%d", &n)
		case "HEX":
			hexs = v
			if _, err := hex.DecodeString(v); err != nil {
				hexs = ""
			}
		}
	}
	if label == "" {
		label = "unrecognised"
	}
	return label, n, hexs
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
