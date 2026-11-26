# `caddy-image-coverage-floor.json` — the absolute coverage floor (T-0811)

This file pins the **Go-module name set** observed in `applegater/caddyui-caddy` at the last
tagged release. `scripts/caddy-image-gate.sh` check 5e asserts that a rebuild still intersects it
by `floor_percent` (50%).

## Why it exists

Every other coverage floor in the gate is **relative to the baseline**: the published `:stable`
image defines what "scanned properly" means. Checks 5b and 5c anchor the *findings-bearing*
packages to observed vulnerabilities, but nothing anchors the **denominator** — so a baseline that
has itself lost coverage permanently lowers the bar for every later release, and no relative check
can see that it happened.

Measured against the real `:stable` scan with checks 1–7 in place, each step keeping every
findings-bearing package at its baseline version (so 5b and 5c are satisfied honestly, not evaded),
publishing, and becoming the next baseline:

```
237 -> 119 -> 60 -> 30 -> 15 -> 8 -> 4 Go modules, in SIX releases
rc=0 and "scan coverage OK" printed at every single step
```

With this fixture committed, the same ratchet stops at step 2:

```
step 1:  237 -> 119   rc=0   (119/237 = exactly the 50% floor; marginal by design)
step 2:  119 ->  60   rc=2   BLOCKED — retains only 60 of 237 pinned names
```

Nothing a rebuild fabricates can raise that number, because the fixture is not derived from the
rebuild.

## When to refresh

Refresh **in the release PR**, so the change is reviewed as a diff. That is the point: an edit a
human has to look at beats the baseline's erosion, which happens inside a published image with no
diff anywhere.

Refresh when a release **legitimately** changes the Go module set — adding or removing a plugin
(which takes its whole dependency subtree with it), or a Caddy major bump. You do **not** need to
refresh for an ordinary base-layer refresh (`-pN`) or a release that only moves module *versions*:
measured across 21 real captured pairs on this repo's images, Go-module **name** retention is
99–100%, with 20 of 21 at exactly 100%. Versions are checks 5c/5d's business, not this one's.

**How staleness actually behaves.** This is an intersection against an old set, so for a release
that **adds** modules or only moves their **versions**, a fixture that is behind asserts *less* —
names it does not know about cannot be missed from it. Those are the releases this image actually
has, which is why the check is quiet in practice.

It is **not** unconditionally permissive. **Renames and removals accumulate**: each one permanently
leaves the pinned set, so a fixture that is never refreshed drifts toward its own floor. Measured by
the security review, chaining honest rebuilds that each rename 30 more modules and publishing every
step the *relative* checks accept:

| cumulative renamed | relative checks | 5e | fixture intersection |
| --- | --- | --- | --- |
| 90 | pass | pass | 147/237 |
| **120** | **pass** | **BLOCK** | **117/237** |
| 150 | pass | BLOCK | 87/237 |

At 120 the rebuild reports all 237 of its own modules and still carries both baseline findings —
genuinely observed, nothing hidden — and 5e is the only thing stopping it. So the honest statement
is: a stale fixture **cannot be exploited to hide anything**, and cannot block a release that adds
or re-versions modules, but **cumulative renames will eventually require a refresh**.

Two reasons that is acceptable. It fails in the **safe** direction — the block is loud, names this
file, and says what to do, where the alternative is silent erosion nobody sees. And it is far away:
real Go-module name retention on this image is 99–100% across 21 captured pairs, so reaching 50%
cumulative rename drift takes a sustained change of character in the dependency graph, not ordinary
churn. The gate prints the `captured` date and the current **margin** on every pass line, so drift
is visible in green runs rather than only in the one that finally fails.

## How to refresh

```sh
scripts/refresh-caddy-image-coverage-floor.sh            # scans :stable
scripts/refresh-caddy-image-coverage-floor.sh applegater/caddyui-caddy:v2.68.12
git diff -- scripts/fixtures/caddy-image-coverage-floor.json
```

Commit the diff in the release PR. Review it the way you would any security-relevant change: a
refresh that *drops* a large number of names is the thing this file exists to make visible, so it
needs a reason in the PR description.

## One fixture serves both arches

The gate runs `assert_scan_coverage` once per architecture, and this file is captured from
`linux/amd64` only. That is correct rather than an oversight: Go **module names** are a property of
the source dependency graph, not of the build target, so they do not vary by arch. Verified against
the live image — the amd64-captured 237 names intersect the `linux/arm64` scan at **237/237**, and
the arm64 pass reports `absolute floor (linux/arm64): usr/bin/caddy retains 237/237`.

Module *versions* and the OS package set can and do differ by arch, which is another reason this
check is keyed on names only.

## Scoping, and why it is narrow

- **`gobinary` only.** No OS-layer fixture. `apk upgrade --no-cache` is unpinned by design and
  `FROM caddy:*-alpine` is a moving tag, so the alpine name set legitimately drops to ~65% on a
  minor bump (measured on 3.23→3.24). An absolute floor there would block the refresh it exists to
  protect, and would then be switched off for everything. The gate **refuses** a fixture declaring
  any other type rather than only documenting this.
- **Names, not versions, and not counts.** A raw count floor is the strictly weaker shape: a padded
  list of fabricated names clears it. That gap was closed for the relative checks and must not
  return here.
- **Compared per *target*, not per type.** `gobinary` can appear more than once, so a type-level
  intersection is payable with a decoy Go binary carrying the fixture's names while the shipped
  `usr/bin/caddy` is gutted. Regression-tested.

## Turning it off

Set `COVERAGE_FLOOR_FILE=` (empty) in the caller. An **absent** file is a visible skip with a NOTE;
a file that is present but unparseable, empty, or wrongly typed is a **hard stop**, because a check
that disables itself when its own input is corrupted is the fail-open shape the whole gate exists
to close.

Regression tests: `scripts/test-image-gate-coverage.sh` cases 48–63.
