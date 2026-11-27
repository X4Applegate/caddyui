# Layer4 listener-wrapper concurrency test (T-0631)

```bash
./scripts/layer4-concurrency/run.sh --prove
```

## When to run it (decided in T-0714)

This harness is **on demand, not in CI.** It runs on two triggers, and nothing
else schedules it:

1. **Before the first shared-port Layer4 proxy goes live on any host.** As of
   2026-11-25 no host runs layer4 — all six report only the `http` and `tls`
   apps — so nothing is unguarded today. The first host that enables it must
   not be the test.
2. **Before any `caddy-l4` pin bump in `Dockerfile.caddy`.** The reminder lives
   on a comment directly above the pin, so a bumper cannot miss it. Record the
   `--prove` result in the bump's card.

It is deliberately **not** wired into `release-docker.yml` or run weekly. It
guards a *configuration* change plus one specific pin, so a calendar schedule
would re-prove an unchanged pin and become noise — the alert-fatigue failure
mode already documented for the pin watcher in T-0636. Wiring it into the
release gate, conditional on the `caddy-l4` pin moving, stays the right answer
the first time such a bump is actually proposed (see T-0714 for that follow-up).

`--prove` is the only run worth trusting. It tests the fixed image (must pass)
*and* the buggy one (must fail). A concurrency test that passes on the buggy
image proves nothing — and this harness caught itself doing exactly that twice
while being built (see [Traps](#traps-that-produced-a-false-pass)).

## What it tests, and why the release suite could not

CaddyUI v2.68.11 ships `caddy-l4` v0.1.3. Its two headline fixes are both on the
**listener-wrapper** path:

| issue | bug | v0.1.3 fix |
| --- | --- | --- |
| [#483](https://github.com/mholt/caddy-l4/issues/483) | the prefetch buffer went back to a shared `sync.Pool` even on the **hijacked** path, so a second connection could draw a buffer still holding the first client's TLS ClientHello | `bufPool.Put(buf)` moved inside the `!errors.Is(err, errHijacked)` branch |
| [#482](https://github.com/mholt/caddy-l4/issues/482) / [#492](https://github.com/mholt/caddy-l4/issues/492) | `l4remoteiplist.StopMonitoring` did a **blocking send** on an unbuffered channel; Caddy cancels a config's context *before* calling `Cleanup`, so the receiver was already gone | `close(b.stop)` under a `sync.Once` |

Both were verified for that release **by reading the source diff**. The release
e2e suite could not have caught either one, for three separate reasons:

1. It drove a **dedicated layer4 server**. The hijack only exists in the
   `listener_wrappers` pass-through, so the #483 code path was never executed.
2. It ran **sequential single connections**. A sequential client returns its
   buffer to the pool before the next `Get()`, so the pool never hands back a
   buffer anyone is still reading.
3. Its config **never loaded `l4remoteiplist`**, so #482/#492 was unreachable.

That was fine at the time: no host ran layer4 at all. This harness exists so the
first host that does is not the test.

## How it is built

- **The config comes from CaddyUI's own `buildLayer4ListenerWrappers`**, emitted
  by `TestEmitLayer4ConcurrencyConfig` in
  `internal/server/layer4_concurrency_config_test.go`. Hand-writing a layer4
  server would test something CaddyUI does not generate. The test also asserts
  `mergeListenerWrappers` puts layer4 *before* tls, which is what keeps the
  matchers looking at raw rather than decrypted bytes.
- **One shared port (`:18443`)** carries both kinds of traffic, as a real
  shared-port deployment would: SSH banners match the layer4 route, everything
  else falls through to Caddy's own TLS and HTTP.
- **~500 TLS clients, each with a unique SNI**, released from a single barrier so
  their first bytes land in the same window.
- **~500 SSH-banner connections interleaved with them.** These are the ones that
  *match* a route and so take the non-hijacked path — they are what keeps the
  shared pool churning while hijacked connections hold buffers.
- **~50 reloads** with `remote_ip_list` configured, each one a genuine config
  change.

## Three independent contamination detectors

A single detector could agree with a swap by coincidence. These cannot all agree:

1. **Certificate SAN.** On-demand issuance mints a cert per SNI, so a leaked
   ClientHello yields a certificate for *someone else's* name.
2. **Echoed SNI.** The server returns `SNI={http.request.tls.server_name}`, and
   each client also sends a unique session id it checks in the same response.
3. **TLS protocol failures.** `server did not echo the legacy session ID`,
   `bad record MAC`, `error decoding message` — these *are* the race, counted
   directly as contamination. A plain `EOF` or dial timeout is deliberately **not**
   in that list: a connection the server closes without speaking TLS says nothing
   about buffer reuse, and including it would make the check fire on ordinary
   overload.

The SSH side gets the same treatment from the matched direction: the sink echoes
the banner it received, and each client asserts its own token came back.

## Measured results

`--prove`, 500 TLS + 500 SSH, 50 reloads:

| image | caddy-l4 | concurrency | reload |
| --- | --- | --- | --- |
| `v2.68.11` | v0.1.3 | **PASS** — 500/500 TLS, 500/500 SSH, 0 contaminated | **PASS** — flat at baseline across 50 reloads |
| `v2.68.9` | v0.1.2 | **FAIL** — 6–19 contaminated per run, 5/5 runs | **FAIL** — reload 1 deadlocks |

The #482/#492 symptom is worse than the issue titles suggest. It is **not** a
slow leak of one goroutine per reload: the blocked send happens on the
config-teardown path while the admin lock is held, so the **first** config change
deadlocks the whole reload. `POST /load` never returns, the admin endpoint stops
answering, and the process will not shut down (`stopping admin server: 10s
timeout`). Captured stack:

```
goroutine 22 [chan send]:
  l4remoteiplist.(*IPList).StopMonitoring(...)  iplist.go:97
  l4remoteiplist.(*RemoteIPList).Cleanup(...)   matcher.go:122
  caddy.NewContextWithCause.func1(...)          context.go:85
  caddy.unsyncedStop(...)                       caddy.go:739
  caddy.unsyncedDecodeAndRun(...)
```

A goroutine-count check **alone cannot see this**: once it deadlocks,
`/debug/pprof` stops responding and there is no later count to compare. So the
reload is timed, and a hang is reported as the deadlock it is rather than as an
inconclusive run.

## Traps that produced a false PASS

Both of these were real, both read as green, and both are now guarded in code.
They are the reason `--prove` exists.

**A. Scoring TLS protocol errors as generic failures.** The first version counted
`did not echo the legacy session ID` as an ordinary error and failed only on a
95%-success threshold. On the buggy image that **passed 1 run in 3** — 489/500
ok, 6 real contamination events, exit 0. Contamination must be counted as
contamination, never inferred from a success rate.

**B. Reloading an identical config.** Caddy short-circuits a no-op load, so
nothing is torn down, `Cleanup` never runs, and the deadlock is never reached.
With identical reloads the buggy image sat flat at 21 goroutines for 50 reloads
and reported PASS. `varyConfig` now changes an inert field on every reload.

**And a third, caught by the two-sided tolerance.** The leak phase first took its
baseline immediately after the concurrency phase, while ~500 connections were
still draining: baseline 526, final 20, reported as a **−506 "leak"** on the
*fixed* image. A contaminated baseline is dangerous in both directions — it can
hide a real leak as easily as invent one — so both readings now come from
`settledGoroutineCount`, which samples until the count stops moving and returns
an **error** rather than a guess if it never settles.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | pass |
| 1 | a real failure |
| 2 | the harness could not run — **not** a pass |

Exit 2 is separate on purpose. A harness that cannot start must not be
indistinguishable from one that ran and found nothing.

## Multi-route precedence is a separate harness

This one uses a single SSH route plus pass-through, so it says nothing about
which of several competing routes wins a given first packet. v0.1.3 also changed
that — `anyRouteNeedsMore` replaced the single `lastNeedsMoreIdx` watermark in
`layer4/routes.go` — and it is covered by:

```bash
./scripts/layer4-concurrency/precedence.sh
```

See [PRECEDENCE.md](PRECEDENCE.md). That one is a **differential**, not a
pass/fail gate, and the distinction is the point: the two bugs *this* harness
tests are wrong on any reading, so `--prove` can demand the buggy image fail. A
precedence change has no such anchor, so the precedence harness records the
landing route per image and reports the differences instead of asserting one
answer.

Headline measured result: on `caddy-l4` v0.1.2 a split RDP connection request
reached **no route at all** (and landed on the **catch-all** when one was
present); on v0.1.3 it reaches the `rdp` route. The boundary is the `ssh`
matcher's 4-byte threshold, not the one you would guess.
