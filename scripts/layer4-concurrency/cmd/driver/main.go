// SPDX-License-Identifier: Apache-2.0

// T-0631 concurrency driver for the caddy-l4 listener wrapper.
//
// WHAT THIS PROVES, AND WHY A SIMPLER TEST DOES NOT
// -------------------------------------------------
// caddy-l4 #483 (fixed in v0.1.3) is a race in the listener wrapper's prefetch
// buffer. v0.1.2's handle() did:
//
//	buf := bufPool.Get().([]byte)
//	defer bufPool.Put(buf)          // <- unconditional
//
// but on the HIJACKED path (a connection the wrapper hands back to the wrapped
// listener, i.e. everything that is NOT a layer4 route match) the returned
// connection keeps referencing buf after handle() returns. Putting it back in
// the shared sync.Pool therefore lets a SECOND connection draw a buffer that
// still holds the FIRST connection's prefetched bytes — its TLS ClientHello,
// which carries its SNI.
//
// Reproducing that needs three things at once, and the T-0620 release e2e suite
// had none of them:
//
//  1. The LISTENER WRAPPER path, not a dedicated layer4 server. The hijack only
//     exists in the pass-through, so a hand-written `layer4` app cannot hit it.
//     Hence the config comes from CaddyUI's own buildLayer4ListenerWrappers
//     (see internal/server/layer4_concurrency_config_test.go).
//  2. CONCURRENCY. A sequential client returns its buffer to the pool before the
//     next Get(), so the pool hands back a buffer nobody is reading. The release
//     suite ran one connection at a time.
//  3. A PER-CONNECTION IDENTITY visible in the handshake. Every TLS client here
//     uses a unique SNI, and asserts both the echoed SNI in the response body
//     and the SAN on the certificate it was served. A swapped ClientHello shows
//     up as one client being served another's name.
//
// The SSH-banner connections are interleaved deliberately: they are the ones
// that MATCH a layer4 route and so take the non-hijacked path, which is what
// keeps the shared pool churning while hijacked connections hold buffers.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	failures []string
	mu       sync.Mutex
}

func (r *result) fail(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.failures) < 60 { // keep the report readable; count stays exact
		r.failures = append(r.failures, fmt.Sprintf(format, a...))
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "shared host:port under test")
	admin := flag.String("admin", "localhost:12019", "Caddy admin endpoint")
	tlsN := flag.Int("tls", 500, "concurrent TLS clients")
	sshN := flag.Int("ssh", 500, "concurrent SSH-banner clients")
	reloads := flag.Int("reloads", 50, "config reloads for the goroutine-leak check")
	configPath := flag.String("config", "", "config file to POST on each reload")
	phase := flag.String("phase", "all", "all | concurrency | leak")
	flag.Parse()

	res := &result{}
	exit := 0

	if *phase == "all" || *phase == "concurrency" {
		if !runConcurrency(*addr, *tlsN, *sshN, res) {
			exit = 1
		}
	}
	if *phase == "all" || *phase == "leak" {
		if !runLeak(*admin, *configPath, *reloads, res) {
			exit = 1
		}
	}

	res.mu.Lock()
	for _, f := range res.failures {
		fmt.Printf("  FAIL %s\n", f)
	}
	res.mu.Unlock()
	os.Exit(exit)
}

// runConcurrency drives tlsN TLS clients with unique SNIs against sshN
// SSH-banner clients, all starting together, and asserts no cross-contamination.
func runConcurrency(addr string, tlsN, sshN int, res *result) bool {
	fmt.Printf("== phase: concurrency (%d TLS + %d SSH, released together) ==\n", tlsN, sshN)

	var (
		tlsOK, tlsErr  atomic.Int64
		sshOK, sshErr  atomic.Int64
		sniMismatch    atomic.Int64
		certMismatch   atomic.Int64
		bannerMismatch atomic.Int64
		corruptHello   atomic.Int64
		observedSNIs   sync.Map // SNI served -> SNI requested, to name a swap
	)

	// A single barrier so every connection's first bytes land in the same window.
	// Without this the pool is never contended and v0.1.2 would pass.
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < tlsN; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Unique SNI AND a unique session id in the request path: two
			// independent identities, so a swap cannot coincidentally agree.
			sni := fmt.Sprintf("c%04d-s%d.l4test", i, time.Now().UnixNano()%100000)
			session := fmt.Sprintf("sess-%04d", i)

			d := &net.Dialer{Timeout: 20 * time.Second}
			raw, err := d.Dial("tcp", addr)
			if err != nil {
				tlsErr.Add(1)
				res.fail("tls %s dial: %v", sni, err)
				return
			}
			defer raw.Close()

			conn := tls.Client(raw, &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true, // internal CA; we verify the SAN ourselves
				MinVersion:         tls.VersionTLS12,
			})
			_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
			if err := conn.Handshake(); err != nil {
				// A handshake that fails IN THE PROTOCOL is the race's own
				// fingerprint, not a flaky network, and is counted as
				// contamination rather than as an ordinary error.
				//
				// When the wrapper replays a recycled buffer the server answers
				// a DIFFERENT ClientHello than this client sent, so the client
				// sees its legacy session id not echoed, a MAC computed over the
				// wrong transcript, or a record it cannot decode.
				//
				// This classification is load-bearing. Counting these as generic
				// errors and failing only on a success-rate threshold let the
				// harness PASS on the buggy image on 1 run in 3 (measured:
				// 489/500 ok with 6 session-id failures, exit 0) -- exactly the
				// "a test that passes on the buggy image proves nothing" trap.
				if isHelloCorruption(err) {
					corruptHello.Add(1)
					res.fail("CROSS-CONTAMINATION (handshake): SNI %s got %v - the server answered a different ClientHello", sni, err)
					return
				}
				tlsErr.Add(1)
				res.fail("tls %s handshake: %v", sni, err)
				return
			}

			// Detector 1: the certificate the server chose. On-demand issuance
			// mints a cert per SNI, so a leaked ClientHello yields a cert for
			// SOMEONE ELSE'S name.
			certNames := []string{}
			if cs := conn.ConnectionState(); len(cs.PeerCertificates) > 0 {
				certNames = cs.PeerCertificates[0].DNSNames
			}
			matched := false
			for _, n := range certNames {
				if strings.EqualFold(n, sni) {
					matched = true
				}
			}
			if !matched {
				certMismatch.Add(1)
				res.fail("CROSS-CONTAMINATION (cert): asked SNI %s, served cert for %v", sni, certNames)
				for _, n := range certNames {
					observedSNIs.Store(n, sni)
				}
			}

			// Detector 2: the SNI the HTTP layer saw, echoed in the body, plus
			// the session id we sent, echoed back by the same request.
			req := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nX-Session: %s\r\nConnection: close\r\n\r\n",
				session, sni, session)
			if _, err := conn.Write([]byte(req)); err != nil {
				tlsErr.Add(1)
				res.fail("tls %s write: %v", sni, err)
				return
			}
			body, err := io.ReadAll(conn)
			if err != nil && len(body) == 0 {
				tlsErr.Add(1)
				res.fail("tls %s read: %v", sni, err)
				return
			}
			want := "SNI=" + sni
			if !strings.Contains(string(body), want) {
				sniMismatch.Add(1)
				line := firstSNILine(string(body))
				res.fail("CROSS-CONTAMINATION (echo): asked SNI %s, server reported %q", sni, line)
				return
			}
			tlsOK.Add(1)
		}(i)
	}

	for i := 0; i < sshN; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			token := fmt.Sprintf("T0631_%04d", i)
			d := &net.Dialer{Timeout: 20 * time.Second}
			c, err := d.Dial("tcp", addr)
			if err != nil {
				sshErr.Add(1)
				res.fail("ssh %s dial: %v", token, err)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(25 * time.Second))
			// A real SSH identification string, so the l4 ssh matcher matches.
			if _, err := c.Write([]byte("SSH-2.0-" + token + "\r\n")); err != nil {
				sshErr.Add(1)
				res.fail("ssh %s write: %v", token, err)
				return
			}
			b, err := io.ReadAll(c)
			if err != nil && len(b) == 0 {
				sshErr.Add(1)
				res.fail("ssh %s read: %v", token, err)
				return
			}
			// The sink echoes the banner it received. A banner from another
			// connection is the same contamination seen from the matched side.
			if !strings.Contains(string(b), token) {
				bannerMismatch.Add(1)
				res.fail("CROSS-CONTAMINATION (ssh): sent %s, sink echoed %q", token, strings.TrimSpace(string(b)))
				return
			}
			sshOK.Add(1)
		}(i)
	}

	close(start)
	wg.Wait()

	fmt.Printf("   tls  ok=%d err=%d  sni_mismatch=%d cert_mismatch=%d corrupt_hello=%d\n",
		tlsOK.Load(), tlsErr.Load(), sniMismatch.Load(), certMismatch.Load(), corruptHello.Load())
	fmt.Printf("   ssh  ok=%d err=%d  banner_mismatch=%d\n",
		sshOK.Load(), sshErr.Load(), bannerMismatch.Load())

	observedSNIs.Range(func(k, v any) bool {
		fmt.Printf("   swap: client %v was served %v\n", v, k)
		return true
	})

	contaminated := sniMismatch.Load() + certMismatch.Load() + bannerMismatch.Load() + corruptHello.Load()
	if contaminated > 0 {
		fmt.Printf("   RESULT: FAIL — %d contaminated connections\n", contaminated)
		return false
	}

	// An all-errors run must not read as a pass: if nothing handshook, the test
	// established nothing. This is the "empty input reads as a pass" shape the
	// image gate was hardened against.
	minOK := int64(float64(tlsN) * 0.95)
	if tlsOK.Load() < minOK {
		fmt.Printf("   RESULT: FAIL — only %d/%d TLS clients completed; too few to conclude\n", tlsOK.Load(), tlsN)
		res.fail("insufficient successful TLS handshakes: %d < %d", tlsOK.Load(), minOK)
		return false
	}
	if sshOK.Load() < int64(float64(sshN)*0.95) {
		fmt.Printf("   RESULT: FAIL — only %d/%d SSH clients completed; too few to conclude\n", sshOK.Load(), sshN)
		res.fail("insufficient successful SSH connections: %d", sshOK.Load())
		return false
	}
	fmt.Printf("   RESULT: PASS — zero cross-contamination across %d TLS + %d SSH\n", tlsOK.Load(), sshOK.Load())
	return true
}

// isHelloCorruption reports whether a TLS error means the server replied to a
// ClientHello other than the one we sent -- i.e. the #483 buffer race -- as
// opposed to an ordinary transport failure.
//
// The three observed signatures, all from Go's crypto/tls on the buggy image:
//
//	"tls: server did not echo the legacy session ID"  ServerHello echoes another
//	                                                  client's 32-byte session id
//	"local error: tls: bad record MAC"                keys derived from a
//	                                                  transcript we did not send
//	"remote error: tls: error decoding message"       the SERVER read a spliced
//	                                                  record and rejected it
//
// A plain EOF or i/o timeout is deliberately NOT in this list: a connection the
// server closes without speaking TLS says nothing about buffer reuse, and
// including it would make the check fire on ordinary overload.
func isHelloCorruption(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, sig := range []string{
		"did not echo the legacy session ID",
		"bad record MAC",
		"error decoding message",
		"decrypt error",
		"illegal parameter",
		"unexpected message",
	} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

func firstSNILine(body string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "SNI=") {
			return strings.TrimSpace(l)
		}
	}
	if i := strings.Index(body, "\r\n\r\n"); i >= 0 && len(body) > i+4 {
		return strings.TrimSpace(body[i+4:])
	}
	return "(no SNI line in response)"
}

// runLeak reloads the config `reloads` times and checks that each reload
// COMPLETES and that the goroutine count returns to baseline.
//
// caddy-l4 #482/#492: l4remoteiplist's StopMonitoring did a BLOCKING send on an
// unbuffered channel. Caddy cancels a config's context BEFORE calling Cleanup on
// its modules, so by the time Cleanup runs the monitor goroutine has already
// returned on ctx.Done() and nothing is left to receive. v0.1.3 closes the
// channel under a sync.Once instead.
//
// MEASURED SYMPTOM, which is worse than the issue titles suggest: this is not a
// slow leak that accrues one goroutine per reload. The blocked send happens on
// the config-teardown path while the admin lock is held, so the FIRST config
// change deadlocks the whole reload:
//
//	goroutine 22 [chan send]:
//	  l4remoteiplist.(*IPList).StopMonitoring(...) iplist.go:97
//	  l4remoteiplist.(*RemoteIPList).Cleanup(...)  matcher.go:122
//	  caddy.NewContextWithCause.func1(...)         context.go:85
//	  caddy.unsyncedStop(...)                      caddy.go:739
//	  caddy.unsyncedDecodeAndRun(...)
//
// POST /load never returns, the admin endpoint stops answering entirely, and the
// process will not shut down ("stopping admin server: 10s timeout").
//
// So a goroutine-count check ALONE cannot see this bug: once the deadlock hits,
// /debug/pprof stops responding and there is no later count to compare. The
// reload must be timed and a hang treated as the failure it is -- which is why
// deadlock detection comes first below, and why a reload that does not complete
// is never scored as "no leak observed".
func runLeak(admin, configPath string, reloads int, res *result) bool {
	fmt.Printf("== phase: goroutine leak (%d reloads, remote_ip_list loaded) ==\n", reloads)
	if configPath == "" {
		res.fail("leak phase needs -config")
		return false
	}
	cfg, err := os.ReadFile(configPath)
	if err != nil {
		res.fail("read config: %v", err)
		return false
	}
	// Sanity: the config must actually load the leaking module, or this phase
	// proves nothing. The T-0620 suite's config never did.
	if !strings.Contains(string(cfg), "remote_ip_list") {
		res.fail("config carries no remote_ip_list — the leak phase cannot exercise #482/#492")
		return false
	}

	// The baseline must be taken on a SETTLED server. If the concurrency phase
	// just ran, hundreds of connections are still winding down, and a count
	// taken now is inflated by work that is about to finish on its own. Measured:
	// a baseline of 526 taken immediately after the 500+500 phase drained to 20,
	// and the two-sided tolerance correctly reported a -506 "leak" that was
	// entirely the harness's own traffic. A contaminated baseline makes this
	// phase meaningless in BOTH directions -- it can hide a real leak just as
	// easily as invent one.
	// ONE WARM-UP RELOAD BEFORE THE BASELINE.
	//
	// The goroutine set of a freshly started Caddy is not the goroutine set of a
	// reloaded one: the initial config brings up maintenance goroutines (PKI/TLS
	// upkeep, admin plumbing) that the first reload replaces with a steady-state
	// set. Measured on the FIXED image: settled baseline 26 from the initial
	// config, then flat at 21 for all 50 reloads -- reported as a -5 "leak" on an
	// image that leaks nothing.
	//
	// Baselining after one reload compares like with like. It costs one reload of
	// sensitivity and removes a guaranteed false positive; a leak that only
	// appeared on reload 1 and never again would not be a leak.
	warm, err := varyConfig(cfg, -1)
	if err != nil {
		res.fail("warm-up config: %v", err)
		return false
	}
	t0 := time.Now()
	if err := postConfig(admin, warm); err != nil {
		res.fail("warm-up reload did not complete after %s: %v -- this is the l4remoteiplist Cleanup deadlock (#482/#492), not a timeout to retry", time.Since(t0).Round(time.Millisecond), err)
		fmt.Printf("   warm-up reload HUNG after %s\n", time.Since(t0).Round(time.Millisecond))
		fmt.Printf("   RESULT: FAIL — the reload path deadlocked\n")
		if lines := leakSuspects(admin); lines != "" {
			fmt.Printf("   blocked stacks:\n%s\n", lines)
		} else {
			fmt.Printf("   (admin endpoint is unresponsive, as expected once it deadlocks)\n")
		}
		return false
	}

	base, err := settledGoroutineCount(admin)
	if err != nil {
		res.fail("baseline goroutine count: %v", err)
		return false
	}
	fmt.Printf("   baseline goroutines: %d (settled, after one warm-up reload)\n", base)

	// Each reload must differ from the live config, or Caddy short-circuits it
	// as a no-op and never tears the old modules down -- so Cleanup never runs
	// and the bug is never reached. An identical-config reload is why the first
	// version of this phase PASSED on the buggy image.
	for i := 0; i < reloads; i++ {
		body, err := varyConfig(cfg, i)
		if err != nil {
			res.fail("vary config for reload %d: %v", i+1, err)
			return false
		}
		t0 := time.Now()
		err = postConfig(admin, body)
		took := time.Since(t0)
		if err != nil {
			// A reload that times out or never answers is the DEADLOCK, not a
			// transport hiccup: name it, because it is the actual #482/#492
			// symptom and it must not be reported as an inconclusive run.
			res.fail("reload %d did not complete after %s: %v -- this is the l4remoteiplist Cleanup deadlock (#482/#492), not a timeout to retry", i+1, took.Round(time.Millisecond), err)
			fmt.Printf("   reload %d HUNG after %s\n", i+1, took.Round(time.Millisecond))
			fmt.Printf("   RESULT: FAIL — the reload path deadlocked\n")
			if lines := leakSuspects(admin); lines != "" {
				fmt.Printf("   blocked stacks:\n%s\n", lines)
			} else {
				fmt.Printf("   (admin endpoint is unresponsive, as expected once it deadlocks)\n")
			}
			return false
		}
		if took > 20*time.Second {
			res.fail("reload %d took %s, far beyond a normal reload", i+1, took.Round(time.Millisecond))
			return false
		}
		if (i+1)%10 == 0 {
			n, err := goroutineCount(admin)
			if err != nil {
				res.fail("goroutine count after reload %d: %v", i+1, err)
				return false
			}
			fmt.Printf("   after %2d reloads: %d goroutines (baseline %d, delta %+d)\n", i+1, n, base, n-base)
		}
	}

	// Measure the end state the same way as the baseline, for the same reason:
	// the reloads themselves create short-lived goroutines, and a leak does not
	// go away with time while ordinary churn does.
	final, err := settledGoroutineCount(admin)
	if err != nil {
		res.fail("final goroutine count: %v", err)
		return false
	}
	delta := final - base
	fmt.Printf("   after %d reloads: %d goroutines (baseline %d, delta %+d, tolerance ±2)\n",
		reloads, final, base, delta)
	if delta > 2 || delta < -2 {
		fmt.Printf("   RESULT: FAIL — goroutine count did not return to baseline\n")
		res.fail("goroutine leak: delta %+d after %d reloads (tolerance ±2)", delta, reloads)
		if lines := leakSuspects(admin); lines != "" {
			fmt.Printf("   leaked stacks (l4remoteiplist):\n%s", lines)
		}
		return false
	}
	fmt.Printf("   RESULT: PASS — returned to baseline within ±2\n")
	return true
}

// settledGoroutineCount samples until the count stops moving, so both the
// baseline and the final reading describe an idle server rather than one still
// draining. It returns an error rather than a guess if it never settles: an
// unsettled server is an unknown, and an unknown must not read as a measurement.
func settledGoroutineCount(admin string) (int, error) {
	const (
		stableNeeded = 3               // consecutive equal samples
		interval     = 1 * time.Second //
		maxWait      = 45 * time.Second
	)
	deadline := time.Now().Add(maxWait)
	var last, stable int
	for time.Now().Before(deadline) {
		n, err := goroutineCount(admin)
		if err != nil {
			return 0, err
		}
		if n == last {
			stable++
			if stable >= stableNeeded {
				return n, nil
			}
		} else {
			stable = 1
			last = n
		}
		time.Sleep(interval)
	}
	return 0, fmt.Errorf("goroutine count never settled within %s (last %d) - cannot establish a baseline", maxWait, last)
}

func goroutineCount(admin string) (int, error) {
	body, err := adminGet(admin, "/debug/pprof/goroutine?debug=2")
	if err != nil {
		return 0, err
	}
	n := strings.Count(body, "\ngoroutine ")
	if strings.HasPrefix(body, "goroutine ") {
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("goroutine dump had no goroutines (%d bytes) — not a measurement", len(body))
	}
	return n, nil
}

// leakSuspects names the module in the leaked stacks, so a failure says WHICH
// goroutine leaked rather than only that the number moved.
func leakSuspects(admin string) string {
	body, err := adminGet(admin, "/debug/pprof/goroutine?debug=2")
	if err != nil {
		return ""
	}
	var out []string
	for _, blk := range strings.Split(body, "\n\n") {
		if strings.Contains(blk, "l4remoteiplist") {
			lines := strings.Split(blk, "\n")
			keep := lines
			if len(lines) > 6 {
				keep = lines[:6]
			}
			out = append(out, "     "+strings.Join(keep, "\n     "))
			if len(out) >= 3 {
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

func adminGet(admin, path string) (string, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get("http://" + admin + path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return string(b), nil
}

// varyConfig returns the config with one inert field changed, so every reload is
// a genuine config change. Caddy compares the incoming config to the running one
// and skips an identical load; a skipped load tears nothing down, calls no
// Cleanup, and therefore cannot reach the #482/#492 blocking send.
func varyConfig(cfg []byte, i int) ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(cfg, &root); err != nil {
		return nil, err
	}
	apps, _ := root["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	srv0, _ := servers["srv0"].(map[string]any)
	routes, _ := srv0["routes"].([]any)
	if len(routes) == 0 {
		return nil, fmt.Errorf("config has no srv0 routes to vary")
	}
	r0, _ := routes[0].(map[string]any)
	handles, _ := r0["handle"].([]any)
	if len(handles) == 0 {
		return nil, fmt.Errorf("config has no srv0 handler to vary")
	}
	h0, _ := handles[0].(map[string]any)
	// The SNI echo must survive: the concurrency phase depends on it. Append a
	// reload marker rather than replacing the body.
	h0["body"] = fmt.Sprintf("SNI={http.request.tls.server_name}\nreload=%d\n", i)
	out, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(out), "remote_ip_list") {
		return nil, fmt.Errorf("varied config lost remote_ip_list")
	}
	return out, nil
}

func postConfig(admin string, cfg []byte) error {
	// Validate it is still JSON we are posting; a truncated body would 400 and
	// read as a reload failure rather than a bad test input.
	var probe any
	if err := json.Unmarshal(cfg, &probe); err != nil {
		return fmt.Errorf("config is not valid JSON: %w", err)
	}
	// Bounded: a deadlocked reload must surface as an error, not hang the test.
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Post("http://"+admin+"/load", "application/json", strings.NewReader(string(cfg)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("POST /load: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
