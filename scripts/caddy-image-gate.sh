#!/usr/bin/env bash
# The publish gate for applegater/caddyui-caddy.
#
# Decides whether a rebuilt Caddy image may replace the published one. Used by
# BOTH workflows that move this image's :stable/:latest tags:
#
#   caddy-image-refresh.yml  the weekly base-layer refresh, from its unattended
#                            scan AND its post-approval publish
#   release-docker.yml       the release that publishes :vX.Y.Z, after the push
#                            and before the moving tags are created
#
# One copy, so the standard cannot drift between the paths: the check that
# gave a reviewer their verdict is byte-for-byte the check that guards the
# moving tags.
#
# Usage:
#   caddy-image-gate.sh <new-image-ref> <baseline-image-ref> <out-dir> [arches]
#
#   new-image-ref       The rebuild. Locally loaded tag, or repo@sha256:… .
#   baseline-image-ref  The currently-published image, normally <repo>:stable.
#   out-dir             Written to: per-arch scans, id lists, module lists,
#                       summary.md, and verdict.
#   arches              Space-separated, default "amd64 arm64".
#
# Environment:
#   TRIVY_SEVERITY      Severities to scan. Default UNKNOWN,LOW,…,CRITICAL.
#   FS_DELTA            on | off (default). Gate 4, the filesystem delta. OFF by
#                       default because it is the only gate that costs a full
#                       image export per side per arch; intended for the weekly
#                       refresh rather than every release. Once on, it follows
#                       MODULE_DRIFT_POLICY for block-vs-report like gates 2/3.
#   FS_ALLOW_RE         Extended regex of paths a NEW file may appear at under
#                       gate 4 without objection. Defaulted in the body; see
#                       the note there before widening it.
#   MODULE_DRIFT_POLICY block (default) | report. Governs gates 2 AND 3 below.
#                       The default is the strict one so a caller that forgets
#                       the variable gets the SAFER behaviour, never the weaker
#                       one. The name predates gate 3 and is kept because all
#                       three call sites set it; it reads as "how strict is
#                       drift", which is what it now means for both gates.
#   COVERAGE_FLOOR_FILE Path to the committed absolute coverage floor for
#                       coverage check 5e. Default
#                       scripts/fixtures/caddy-image-coverage-floor.json,
#                       resolved against the REPO (cwd), because both CI callers
#                       `cp` this script into $RUNNER_TEMP and run it from the
#                       checkout. Set EMPTY to run with no absolute floor. An
#                       absent file is a visible skip; a file that is present
#                       but unparseable, empty or wrongly typed is a hard stop.
#                       See scripts/fixtures/README-caddy-image-coverage-floor.md.
#
# Requires: trivy, jq, docker. Trivy's DB must already be downloaded
# (`trivy image --download-db-only`): the caller does that ONCE so every scan
# in a run compares against the same DB version. A subset comparison across
# two DB versions is meaningless, which is why this script never updates it.
#
# Writes "verdict=<improved|unchanged|blocked>" plus the summary to stdout and,
# when GITHUB_OUTPUT is set, to that file. Exit status:
#   0  improved or unchanged  (safe: nothing new)
#   1  blocked                (a human must look)
#   2  the gate could not run (treat as blocked)
#
# A COVERAGE PRECONDITION, then FOUR independent gates (the fourth opt-in):
#
#  0. Scan coverage. Before either gate runs, assert the new image's Trivy scan
#     actually looked at the image: an OS was detected, it is not end-of-life,
#     every scan target the baseline had is still present, each shared target's
#     package count has not collapsed, the retained packages are the SAME
#     packages by name, at least half of them at the same name@version, and
#     (for the pinned Go module types, under the strict policy) no
#     findings-bearing package has moved version while its findings vanished,
#     and the Go binary the baseline scanned is still being scanned. This is a
#     precondition rather than a gate because it produces no verdict -- it
#     exits 2 ("the gate could not run"), which all three call sites already
#     treat as blocking.
#
#     That sentence is deliberately long. An earlier spelling said "the SAME
#     packages by name AND at the same versions", which promised more than
#     any of these checks deliver; over-claiming in a security control's own
#     summary is how a later reader trusts more than the code enforces, and
#     review has now caught that twice on this function.
#
#     The later checks are there because a COUNT IS NOT AN IDENTITY (T-0638).
#     The count floor asks "are there still at least half as many rows", so it
#     is cleared by a package list that was replaced rather than retained --
#     padding with fabricated names keeps the count up while every finding
#     against a dropped real package cancels out of gate 1 as though the
#     rebuild had fixed it. Likewise "a gobinary result exists" is not "the
#     binary this image runs was scanned", since Trivy emits one result per Go
#     binary it finds. Every bypass named here was demonstrated end-to-end
#     against the real :stable scan before being closed.
#
#     BE PRECISE ABOUT WHAT THE NAME FLOOR DOES AND DOES NOT PROMISE. A 50%
#     intersection is NOT "the same packages", and on its own it is weaker
#     than it looks in two specific ways, both measured:
#
#       - it is indifferent to WHICH names survive, so a rebuild may retain
#         119 innocuous modules of 237, drop exactly the five that carry
#         findings, and clear the floor by one;
#       - its denominator is the BASELINE's name set, and a published image
#         becomes the baseline. Fabricated names therefore carry forward and
#         count as retained on the next release, which made the blinding
#         ratchet FASTER than the count floor alone, not slower.
#
#     Check 5b is what actually closes both, and it is the load-bearing one:
#     a package carrying a finding in the baseline must still be reported by
#     the rebuild, with no percentage. It is anchored to observed
#     vulnerabilities rather than to whatever the previous image listed, so a
#     fabricated name can never satisfy it and cannot be inherited. Read the
#     name floor as coarse protection against wholesale replacement, and 5b
#     as the rule that makes "this finding is gone" mean fixed rather than
#     unobserved.
#
#     Checks 4, 5 and 5b are per TYPE, and that aggregation is itself a
#     bypass when a type has several results: a decoy Go binary carrying the
#     baseline's whole name set pays for the shipped binary's coverage while
#     usr/bin/caddy is gutted to a single package. Check 7 applies the same
#     identity floor per retained gobinary TARGET, which is what stops it.
#
#     AND A NAME IS NOT A VERSION (T-0810). Checks 5, 5b and 7 all compare
#     `.Packages[].Name`; until T-0810 nothing compared `.Packages[].Version`
#     anywhere in this function. So a rebuild could report an identical
#     package name set -- 237/237 intersection, every floor cleared, every
#     findings-bearing package still present -- while the versions behind
#     those names were entirely different. Measured against the real :stable
#     scan: keep all 237 names, replace every version, and the precondition
#     printed "scan coverage OK" while gate 1 reported ADDED=0 REMOVED=7,
#     verdict=improved, exit 0.
#
#     Two checks close it, in the same relationship 5 and 5b have:
#
#       5c  a package carrying findings in the baseline must still be
#           reported AT THE SAME VERSION, unless EVERY ONE of those findings
#           is still reported against it. This is the load-bearing half. The
#           targeted form of the attack -- swap the versions of only the five
#           findings-bearing modules -- sits at 97% name@version retention
#           and clears any ratio, exactly as pass A's targeted drop cleared
#           check 5's.
#
#           "EVERY ONE", compared as an ID SET, is load-bearing and not
#           pedantry. Asking merely whether the package still carries SOME
#           finding exempted a package carrying several by retaining any one
#           of them, and the real baseline reports three CVEs against
#           github.com/go-jose/go-jose/v3 -- so that spelling laundered two
#           of them as fixed, under the strict policy, with no note. Set
#           comparison against the BASELINE's ids also means a fabricated
#           finding cannot buy the exemption, which is the standard 5b holds
#           itself to.
#       5d  a loose 50% name@version floor per type, which catches the
#           wholesale replacement 5c's narrow rule is indifferent to.
#
#     NEITHER MAKES gate 1 VERSION-AWARE, and that is deliberate: `ids_from`
#     still keys findings on ID+package only, for the reason written out
#     above it. 5c's first limb is what keeps the two compatible -- a package
#     that moved version and STILL CARRIES the finding is the upgrade
#     `ids_from` exists to protect, and it satisfies 5c outright. Verified on
#     the documented case (x/crypto v0.57.0 -> v0.58.0 still reporting
#     GO-2026-5932): gate 1 reports added=0 removed=0 and 5c passes.
#
#     5c's hard stop is scoped to `gobinary`/`gomod`, because those versions
#     are reproducible by construction (every xcaddy --with is pinned) while
#     `apk upgrade --no-cache` is unpinned BY DESIGN and picking up new OS
#     package versions is the whole purpose of a refresh. Unscoped, it would
#     have blocked the T-0592 refresh -- the one that fixed CVE-2026-4738 by
#     moving zlib 1.3.2-r1 -> 1.4-r0.
#
#     It exists because gate 1 is set arithmetic, and set arithmetic reads an
#     EMPTY findings list as a perfect score. That made this the ONE fail-open
#     path in the script: an image Trivy cannot analyse has no findings to add,
#     so the subset check passes and the verdict comes out `improved` precisely
#     because nothing could be seen. See assert_scan_coverage below.
#
#  1. Vulnerability subset. The rebuild's findings must be a SUBSET of the
#     published image's, per arch. Deliberately not "zero findings": every
#     image to date carries GO-2026-5932 (x/crypto/openpgp unmaintained, no
#     fix, not reached by the binary), so a zero-findings rule could never
#     publish anything. Because such a standing finding is present on BOTH
#     sides it cancels out of the set arithmetic by construction, with no
#     allowlist to maintain and no exception that could quietly start hiding
#     something real.
#
#     Compared as ID+package, not ID alone: the same CVE ID appearing against
#     a DIFFERENT package is a new exposure, and comparing bare IDs would let
#     it cancel out.
#
#  2. Module set, from `caddy list-modules --versions`. Every --with argument
#     in Dockerfile.caddy now carries a version, so a rebuild should reproduce
#     the same module set; this gate is the independent check that it actually
#     did. It catches what gate 1 cannot: a resolver, proxy or toolchain change
#     that moves a DNS provider, caddy-l4 or Coraza with no CVE change at all,
#     and a pin edit that reached the image without going through a release.
#
#     What a module-set change MEANS depends on which path is running, so this
#     gate has two policies and the caller picks:
#
#       block   (default, the refresh path) Any drift is wrong BY DEFINITION.
#               A refresh rebuilds an UNCHANGED Dockerfile.caddy from a release
#               tag, so the module set must come out identical; if it did not,
#               something re-resolved and a timer is about to ship a plugin bump
#               to :stable. Blocking is the whole point.
#
#       report  (the release path) Drift is the EXPECTED OUTCOME of a release
#               that edits Dockerfile.caddy — that is how a plugin bump is
#               meant to arrive. Blocking here would mean no module change
#               could ever be released, i.e. the gate would forbid the one
#               legitimate route it tells refreshes to use. So the diff is
#               computed, printed in full and carried into the job summary,
#               and the verdict is decided by gate 1 alone.
#
#     report does NOT weaken gate 1: a release that introduces a NEW
#     vulnerability still blocks, under either policy. Drift stops being an
#     automatic verdict; it does not stop being reviewed. The release diff is
#     the reviewable record of what the module set change actually was.
#
#  3. Image configuration, from `docker image inspect`. Gates 1 and 2 read the
#     image's CONTENTS -- its packages and its linked Go modules -- and neither
#     reads the metadata that decides how those contents are EXECUTED. A
#     release editing Dockerfile.caddy could add `USER root`, repoint
#     ENTRYPOINT at a wrapper that runs something before exec'ing caddy, add
#     `ENV HTTP_PROXY=` or `SSL_CERT_FILE=`, or change EXPOSE/VOLUME/WORKDIR,
#     and pass the coverage precondition, gate 1 and gate 2 untouched: the
#     package set is identical, the module set is identical, and no CVE moved.
#
#     That gap matters more here than it would for most images. This one is
#     pulled by six public-facing edge proxies that hold DNS-provider API
#     credentials for TLS issuance, so the difference between "runs as caddy"
#     and "runs as root", or between "execs caddy" and "execs a wrapper", is
#     the difference between a reverse proxy and a credential exfiltration
#     foothold. None of it needs an extra scan: the data comes from an inspect
#     the script already runs to verify each side's architecture.
#
#     Fields compared: Config.User, Config.Entrypoint, Config.Cmd, Config.Env,
#     Config.ExposedPorts, Config.Volumes, Config.WorkingDir. Deliberately NOT
#     Labels (every build stamps fresh org.opencontainers.image.* values, so it
#     differs on every single build and would make this gate meaningless noise)
#     and NOT Healthcheck/StopSignal (absent on both sides today; add them here
#     if that changes rather than carrying a field that is always empty).
#
#     ONE CLASS OF CONFIG CHANGE IS BLOCKING UNDER BOTH POLICIES: a variable
#     that redirects the binary's outbound TLS TRUST. A newly-added or modified
#     SSL_CERT_FILE, SSL_CERT_DIR, AWS_CA_BUNDLE, CURL_CA_BUNDLE,
#     REQUESTS_CA_BUNDLE, GIT_SSL_CAINFO, NODE_EXTRA_CA_CERTS or GODEBUG is
#     asserted on regardless of MODULE_DRIFT_POLICY, the way gate 4's
#     trust-store rows are blocking while ordinary file modification is only
#     reported.
#
#     MATCHED ON THE NAME, NEVER ON THE VALUE, because config_from's `clean`
#     truncates each entry to 400 characters before this check reads it. A
#     pattern needing part of the VALUE to survive that cut is fail-open by
#     construction: the first spelling used GODEBUG=.*x509, and padding the
#     list with ordinary settings pushed x509usefallbackroots=1 past the cut so
#     the gate reported "TLS trust env: none" over an image whose container got
#     the variable in full. GODEBUG therefore blocks WHOLE; see trust_env_of.
#
#     AWS_CA_BUNDLE is load-bearing, not prophylactic: Dockerfile.caddy links
#     caddy-dns/route53, and the AWS SDK reads that variable to override the CA
#     bundle for its own HTTP client. Go's crypto/x509 reads only the two
#     SSL_CERT_* names, so it is a separate trust path -- guarding the Route53
#     DNS-01 credential that issues this fleet's certificates.
#
#     Why this one class and not all config drift on releases: making every
#     config change blocking would forbid the deliberate EXPOSE/WORKDIR edit
#     that `report` exists to allow. But a release may change configuration
#     without being allowed to change WHO THE BINARY TRUSTS. SSL_CERT_FILE
#     pointed at an attacker-controlled path redirects ALL outbound TLS trust
#     for this binary -- ACME issuance and the DNS provider's API -- with no
#     filesystem delta at all, so gate 4 cannot see it either: the file it
#     names can be one the image already legitimately contains. It is the same
#     silent-MITM outcome gate 4 exists to prevent, reached through
#     configuration rather than through files. Under `report` alone it would
#     merely be PRINTED into the summary while gate 1, seeing no new CVE,
#     passed the release.
#
#     None of them is present in the published image today, so this asserts on
#     keeping it that way. Nothing in the CODE depends on that, though: the
#     comparison is a whole-line diff against the baseline, so a legitimately
#     introduced value cancels once published and only a CHANGE to it blocks
#     thereafter. Accommodate such a value through the diff, never by narrowing
#     the pattern back toward matching on values.
#
#     Otherwise the same two policies as gate 2, for the same reason, so the
#     caller's existing MODULE_DRIFT_POLICY choice governs the REST of this
#     gate:
#
#       block   (the refresh path) A refresh rebuilds an UNCHANGED
#               Dockerfile.caddy from a release tag, so the config must come
#               out byte-identical. A difference is not "unexpected", it is
#               impossible-unless-something-is-wrong, which makes blocking
#               strictly correct rather than merely cautious.
#
#       report  (the release path) A release MAY legitimately change config --
#               that is how a deliberate EXPOSE or WORKDIR change ships. So the
#               diff is computed, printed in full and carried into the summary,
#               and gate 1 decides the verdict. The reviewer approving the
#               release is the control, and this gate's job is to make sure the
#               change is in front of them rather than invisible.
#               EXCEPT for the trust-redirecting variables above, which block
#               under this policy too. That includes an ordinary GODEBUG: the
#               variable is matched whole because its value cannot be trusted
#               to survive truncation, so a release setting one needs a
#               reviewed decision. Deliberate -- a filter an attacker chooses
#               whether to satisfy is worse than a slightly broad one.
#
#  4. Filesystem delta, from `docker export` of a created (never started)
#     container. OPT-IN via FS_DELTA=on; see that variable for why this one
#     gate is not on by default.
#
#     Gates 1-3 read packages, linked Go modules and execution configuration.
#     A file that is simply ADDED to the image and carries no CVE is invisible
#     to all three: an extra script or binary (`COPY`/`ADD`, or a build-time
#     `curl | sh`), a root CA dropped into the trust store, or a `chmod u+s` on
#     a binary that is otherwise unchanged. The package set is identical, the
#     module set is identical, the config is identical, and no CVE moved.
#
#     The added-CA row is the one that matters most for THIS image, for the
#     same reason gate 3 matters: six public-facing edge proxies that terminate
#     TLS and hold DNS-provider API credentials for DNS-01. A CA added to the
#     image's trust store is trusted by every outbound TLS connection those
#     proxies make, which includes ACME issuance and the DNS provider's API --
#     so it buys silent interception of both, with nothing for the other three
#     gates to report.
#
#     Asserts on three things rather than on the raw diff being non-empty,
#     because a base-layer refresh legitimately rewrites every file of every
#     upgraded package and a raw-diff trigger would fire on every run:
#       (a) any added or replaced file under the trust stores
#       (b) any setuid/setgid entry absent from the baseline at that path+mode
#       (c) any NEW path outside FS_ALLOW_RE
#     The full diff is still produced and carried into the summary as the
#     reviewable record behind those three.
#
#     The file list is (mode, size, path). TWO KNOWN LIMITS, both deliberate
#     and both measured rather than supposed:
#
#       - Size is not a content hash. A modification that preserves a file's
#         exact length is invisible to this gate. Hashing would mean extracting
#         every file of a 133 MB image twice per arch, a different cost class
#         entirely for an attack that has to hit an exact byte count; size
#         catches the realistic forms (an appended certificate, a swapped
#         binary) for free, since tar prints it already.
#       - Modification outside the trust stores is REPORTED, not asserted on.
#         It lands in the raw diff, which a reviewer reads; it does not by
#         itself set the verdict, because `apk upgrade` rewrites hundreds of
#         files on a legitimate refresh. The trust stores are the exception
#         precisely because nothing in a base-layer refresh should be editing
#         them, which is why (a) matches modifications and not just additions.
#
#     Both were found by testing rather than reasoning: the first spelling of
#     this gate omitted size, and a variant that appended one certificate to
#     the existing /etc/ssl/certs/ca-certificates.crt produced a ZERO-LINE diff
#     and passed with verdict=unchanged -- the stealthiest form of the exact
#     attack this gate exists to catch.
#
#     Measured before building it, per T-0641: `trivy --scanners
#     misconfig,secret` (the cheaper route T-0642 proposes) reports ZERO
#     findings on :stable and on purpose-built variants carrying each of these
#     shapes -- misconfig finds no config files inside the image to scan, and a
#     certificate is not a credential pattern. So that scanner pair does not
#     substitute for this gate.
set -euo pipefail

die() { echo "::error::$*" >&2; exit 2; }

[ $# -ge 3 ] || die "usage: $0 <new-image> <baseline-image> <out-dir> [arches]"

NEW_IMAGE="$1"
BASELINE="$2"
OUT="$3"
ARCHES="${4:-amd64 arm64}"

mkdir -p "$OUT"

# Remove the outputs left by a PREVIOUS run in this directory, before anything
# that can `die`.
#
# This runs BEFORE the dependency checks below, not after. A missing trivy/jq/
# docker is exactly the "the gate could not run" case these files misreport, so
# clearing them after those checks would leave the stale-verdict hole open for
# the aborts most likely to hit it. Only argument parsing precedes this, and
# that cannot leave a stale file behind because $OUT is not yet known.
#
# The refresh path reads the verdict FILE rather than the exit status
# (`cat scan/verdict 2>/dev/null || echo error`) and turns a missing file into
# verdict=error, which fails the job. That is what makes exit 2 blocking there.
# A stale file from an earlier run in the same directory would be read as THIS
# run's answer, so a gate that aborted at exit 2 would be reported as whatever
# the last run concluded -- including `improved`. Deleting it up front means an
# aborted gate always presents as an ABSENT verdict, never an old one.
#
# Every file this script writes is cleared, not just the verdict.
#
# `summary.md` is the other output a caller reads back from disk: the refresh
# workflow renders `cat scan/summary.md || echo "_gate did not run_"` into the
# report a human reads and into the 30-day artifact. A stale summary survives
# an abort, the `|| echo` fallback is defeated because the file EXISTS, and the
# job then fails with the previous run's reassuring "improved / no new
# findings" attached -- the opposite of what the reader needs at exactly the
# moment the gate could not run. The id and module lists are cleared for the
# same reason: they are inputs to the next summary.
#
# Hosted runners get a clean workspace per job, so this is not reachable on
# either CI path today. It is reachable for a local run and for any future
# self-hosted runner, and it defeats a fallback the workflow deliberately
# wrote for this case.
rm -f "$OUT/verdict" "$OUT/summary.md" \
      "$OUT"/added-*.ids "$OUT"/removed-*.ids \
      "$OUT"/new-*.ids "$OUT"/old-*.ids \
      "$OUT"/mods-*.txt "$OUT"/cfg-*.txt "$OUT"/fs-*.txt \
      "$OUT"/.cov-*.names 2>/dev/null || true
# cfg-trustenv-*.txt is covered by the cfg-*.txt glob above, and the verdict
# reads its LINE COUNT rather than merely testing the diff, so a stale copy
# would be counted as this run's finding -- i.e. it would BLOCK a clean image
# on evidence from a previous run. That makes the clearing above load-bearing
# for it in a way it is not for the diffs: keep the name prefixed `cfg-` if it
# is ever renamed.
#
# .cov-*.names are the scratch files of coverage checks 5, 5b, 5c, 5d, 5e and 7
# (T-0638, T-0810, T-0811). Each is removed as soon as its target has been compared,
# so they do not normally survive a run -- but a `die` from a LATER target, or
# a kill between the two writes, leaves one behind. Cleared for the same
# reason: this directory is reused on a local run, and those checks read the
# paths back, so a stale file would be read as this run's package list for
# that target.
#
# KEEP THE .names SUFFIX on any scratch file added to those checks. 5d's
# name@version lists are `.cov-old-nv-*.names` rather than `*.nv` precisely so
# this glob keeps covering them; a new suffix would fall outside the sweep
# without anything failing visibly.

command -v trivy >/dev/null || die "trivy not found"
command -v jq    >/dev/null || die "jq not found"
command -v docker >/dev/null || die "docker not found"

# A per-run delimiter for the $GITHUB_OUTPUT heredoc, so that even if a value
# reaching summary.md were ever un-sanitized again, it cannot name the token
# that closes the block. `ids_from` already restricts the fields that land
# there; this is the second layer, and it is the pattern GitHub documents.
SUMMARY_DELIM="GATE_SUMMARY_EOF_$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n')"
[ "$SUMMARY_DELIM" = "GATE_SUMMARY_EOF_" ] && SUMMARY_DELIM="GATE_SUMMARY_EOF_$$_$(date +%s)"
readonly SUMMARY_DELIM

SEVERITY="${TRIVY_SEVERITY:-UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}"

# Unset or empty means block: a caller that forgets this variable gets the
# strict refresh behaviour. Only the two spellings are accepted — a typo such
# as MODULE_DRIFT_POLICY=Report must not silently fall through to the weaker
# policy, so it is a hard stop rather than a default.
DRIFT_POLICY="${MODULE_DRIFT_POLICY:-block}"
case "$DRIFT_POLICY" in
  block|report) ;;
  *) die "MODULE_DRIFT_POLICY must be 'block' or 'report' (got: $DRIFT_POLICY)" ;;
esac

# Gate 4 (filesystem delta) is OPT-IN, unlike the other three.
#
# It is the only gate that costs a full image export per side per arch -- four
# exports of a 133 MB image for a two-arch run -- so T-0641 scoped it to the
# weekly refresh rather than to every release. Default `off` therefore means
# "the release path is unchanged by this gate", which is a deliberate choice
# and not the usual safer-default rule: the three existing gates and the
# coverage precondition all still run, so turning this one on adds a check
# rather than removing one.
#
# Spelled as its own variable rather than folded into MODULE_DRIFT_POLICY
# because the two answer different questions -- that one is "how strict", this
# one is "run it at all". Once on, it follows MODULE_DRIFT_POLICY for
# block-vs-report exactly as gates 2 and 3 do, so a caller has one strictness
# dial, not three.
#
# Only the two spellings are accepted, same as above: a typo must not fall
# through to the weaker behaviour silently.
FS_DELTA="${FS_DELTA:-off}"
case "$FS_DELTA" in
  on|off) ;;
  *) die "FS_DELTA must be 'on' or 'off' (got: $FS_DELTA)" ;;
esac

# The committed absolute coverage floor (T-0811). See check 5e.
#
# Resolved relative to the REPO, not to this script's own directory, because
# both CI callers `cp` the script into $RUNNER_TEMP and run it from the repo
# checkout as cwd -- so `dirname $0` points at a temp directory holding one
# file, and a fixture looked up there would be permanently absent, i.e. the
# check would be silently off on the exact path it exists to guard. cwd is the
# repo on both paths and for a local run from the repo root.
#
# Overridable so the test harness can point at a crafted fixture, and so a
# local run from elsewhere can still find it. An EMPTY value is accepted and
# means "no fixture", which is how a caller deliberately turns 5e off; it is
# distinct from a path that is set but unreadable, which 5e treats as a fault.
COVERAGE_FLOOR_FILE="${COVERAGE_FLOOR_FILE-scripts/fixtures/caddy-image-coverage-floor.json}"

# Paths a NEW file may legitimately appear at without the gate objecting.
#
# Deliberately short. The refresh path rebuilds an unchanged Dockerfile.caddy,
# where the only thing that may add files is `apk upgrade` replacing package
# contents -- and a replaced file is not a NEW PATH, so it is not matched here
# at all. So this allowlist covers the genuinely unstable paths an export picks
# up, not "places a release may add things": the point of the gate is that a
# release adding a file has to be seen.
#
# Each entry earns its place:
#   - apk's own database and cache are rewritten by `apk upgrade`, and its
#     per-package file lists legitimately gain entries when a package version
#     changes.
#   - /etc/ssl/certs is NOT here on purpose: a new file there is the attack
#     this gate exists to catch, so it is asserted on separately (a) rather
#     than excused. ca-certificates genuinely being upgraded will show up
#     there and is expected to be read by a human -- that is the intended
#     cost, and it is why the trust-store rows are extracted rather than
#     buried in the diff.
#   - the machine-id and resolv.conf style runtime files an export captures
#     from the created container rather than from the image.
#
# Overridable so a caller can widen it for a deliberate change without editing
# this script, but it is NOT meant to grow casually: every addition is a class
# of file the gate stops looking at.
#
# EVERY ENTRY IS FULLY ANCHORED. Both halves of this were real bypasses, both
# found in review, both reproduced end-to-end, and both are covered by
# scripts/test-caddy-image-gate-fs-allow.sh:
#
#  1. Unbounded bare NAMES. With only a start anchor, `etc/machine-id` matched
#     `etc/machine-id-EVIL/payload`, and `etc/hosts` -- a file -- matched
#     `etc/hosts/subdir/evil.sh`, i.e. replace the file with a directory and
#     get an unlimited allowlisted payload tree. Each file entry is now
#     terminated with `$`.
#
#  2. Whole-SUBTREE prefixes. `etc/apk/`, `lib/apk/` and `var/cache/apk/` were
#     allowlisted entire, so `etc/apk/.hook.sh`, `lib/apk/db/evilbin` and
#     `var/cache/apk/payload.sh` were invisible to assertion (c) -- a planted
#     executable in a directory excused as "package manager noise". The gate
#     returned verdict=unchanged on an image carrying one.
#     `etc/apk/protected_paths.d/` was the sharper half: it decides which paths
#     apk protects, so it is trust-store POLICY, not churn.
#
# So the apk entries now name the specific files that actually move during an
# `apk upgrade`, rather than the directories containing them. The rule for
# extending this list: name a FILE, anchor it, and never allow a directory that
# can contain an executable. Every addition is a class of file the gate stops
# looking at, and these three directories are exactly where an attacker would
# rather be than /usr/local/bin.
# The default is assembled in SINGLE quotes so the trailing `$` is a literal
# dollar in the variable's value, i.e. a real end-of-line anchor when grep reads
# it. Writing the whole thing double-quoted needs `\$`, and bash then stores the
# backslash-stripped form -- which works for this script but leaves the SOURCE
# text reading `...)\$`, where a `\$` is a literal dollar sign and matches
# nothing. That bit twice over: the regression suite extracts the pattern from
# this line with sed, and a caller exporting FS_ALLOW_RE copies it from here, so
# both would get the broken spelling while the script itself looked fine.
FS_ALLOW_DEFAULT='^/?(lib/apk/db/(installed|scripts\.tar|triggers|lock)|etc/apk/world|var/cache/apk/[^/]*\.(index|tar\.gz)|etc/machine-id|etc/resolv\.conf|etc/hostname|etc/hosts|\.dockerenv)$'
FS_ALLOW_RE="${FS_ALLOW_RE:-$FS_ALLOW_DEFAULT}"

# VALIDATE IT HERE, because an invalid regex fails OPEN further down.
#
# Assertion (c) ends in `grep -Ev "$FS_ALLOW_RE" > file || true`. `grep -E` exits
# 2 on an invalid pattern, the `|| true` swallows that, the output file is empty,
# and empty means "0 new paths outside the allowlist" means clean. Measured: with
# FS_ALLOW_RE='^(unclosed[' an image carrying an added CA passed as exit 0 /
# verdict=unchanged.
#
# That is the same fail-open shape as gate 1 reading an empty findings list as a
# perfect score -- the thing assert_scan_coverage exists to prevent -- recreated
# one level down, and reachable by a TYPO in a caller override rather than only
# by malice. The `|| true` cannot simply be dropped: grep legitimately exits 1
# when nothing matches, which is the common case.
#
# So distinguish grep's exit codes once, up front, where it is still a
# configuration error rather than a silent clean verdict. Exit 1 (no match) on
# empty input is the expected answer; only 2+ means the pattern itself is bad.
# Written as `if ! …; then` rather than running the grep bare and testing `$?`
# on the next line: `set -e` aborts on the failing grep BEFORE the test runs, so
# the bare form exits 2 with no message at all -- the right code for the wrong
# reason, and silent. A command inside `if` is exempt from `set -e`, so this
# keeps the diagnosis.
fs_allow_rc=0
printf '' | grep -Eq "$FS_ALLOW_RE" 2>/dev/null || fs_allow_rc=$?
[ "$fs_allow_rc" -le 1 ] \
  || die "FS_ALLOW_RE is not a valid POSIX extended regex (grep exit $fs_allow_rc): $FS_ALLOW_RE"

# A finding is identified by ID *and* package, and DELIBERATELY NOT by the
# installed version.
#
# Target is excluded because it contains the image reference, which differs
# between the two sides by definition, so including it would make every finding
# look new.
#
# InstalledVersion is excluded for a sharper reason: including it made an
# UPGRADE of a still-affected package look like a brand-new exposure. Measured
# on the real images — GO-2026-5932 (x/crypto, unmaintained openpgp, no fix
# available) sits on both sides of v2.61.0 -> v2.68.9, at v0.57.0 and v0.58.0.
# Keyed with the version it appeared as one finding removed plus one added, so
# the subset gate BLOCKED; keyed on ID+package it correctly cancels out and the
# added count is zero.
#
# That mattered little while this gate only guarded refreshes, where the
# package set is not supposed to move at all. On the release path it would
# block the ordinary case of a security release: bump a module to a newer
# version that is still affected by one standing advisory, and the gate calls
# your fix a regression. Fixing forward would block the same way.
#
# What this gives up is small and recoverable: a same-ID finding against the
# same package whose version moved is no longer counted as new. The version
# change is still visible in the per-arch JSON kept as a build artifact, and a
# genuinely new exposure means a new ID or a new package, which is still
# caught.
# Both fields are sanitized HERE, at the single point they enter the script,
# rather than at each place they are printed.
#
# `PkgName` is attacker-chosen for a `gobinary` result: Trivy copies it from
# the Go build info of the binary in the image, and on the release path the
# image is built from a Dockerfile the submitter controls -- the actor this
# gate exists to constrain. These values flow into `$OUT/*.ids`, into the
# per-finding rows of `summary.md`, and from there into BOTH this script's
# `summary<<GATE_SUMMARY_EOF` heredoc and the refresh workflow's own
# `summary<<SUMMARY_EOF` heredoc. A newline in either field therefore let the
# scanned image write arbitrary lines into `$GITHUB_OUTPUT`: a line reading
# exactly the delimiter closed the heredoc early and the rest parsed as
# further step outputs, and GitHub takes the LAST value for a duplicated key,
# so a crafted module path could forge `verdict=improved` against a run whose
# verdict was `blocked`. Confirmed reachable before this fix.
#
# A real Trivy ID or package name is a plain token, so restricting the
# character set costs nothing legitimate: anything outside it is replaced
# rather than dropped, keeping the row readable and visibly tampered. Field
# order is preserved by sanitizing inside jq, so the tab-separated structure
# the readers rely on cannot be broken by embedding a tab either.
ids_from() {
  jq -r '[.Results[]?.Vulnerabilities[]?
          | ((.VulnerabilityID // "") | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:120]) as $id
          | ((.PkgName // "") | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160]) as $pkg
          | "\($id)\t\($pkg)"]
         | unique | .[]' "$1"
}

# ---------------------------------------------------------------------------
# Scan coverage: did Trivy actually LOOK at the new image?
#
# Gate 1 is set arithmetic on two findings lists, so it reads an EMPTY findings
# list as a perfect result. Every other failure mode in this script is
# fail-closed; this one is fail-OPEN, and that is the dangerous direction. An
# image Trivy cannot analyse produces no findings to add, so the subset check
# passes and the verdict comes out `improved` *because* nothing could be seen.
# Fewer findings is read as better rather than as blind, and the moving tags
# then advance onto an unscanned image.
#
# Reachable without anything exotic. A release may edit Dockerfile.caddy
# freely, and all of these produce it:
#   - the base becomes scratch or distroless, so there is no OS package
#     database to detect and the `alpine` result disappears
#   - the Go build info is stripped (-ldflags, a trimmed binary, a different
#     builder), so the `gobinary` result disappears and with it every Go
#     module finding
#   - the binary moves, so Trivy's language-file walk no longer finds it
#   - a Trivy upgrade, a missing java-db, or an analyser error degrades one
#     target silently and exits 0 anyway
#
# Measured on the real images to be sure this is not theoretical: the published
# :stable scan yields exactly two results, `alpine` (32 packages) and
# `gobinary` (236 packages). Delete the `gobinary` result alone and all 8
# findings vanish; the gate then reports 8 removed, 0 added, verdict=improved,
# exit 0 -- and :stable and :latest move.
#
# So before comparing, assert the new scan is actually a scan. Each check is a
# hard stop (exit 2, "the gate could not run") rather than a verdict, because
# "I could not see" is not a result and must never be averaged with one. Exit 2
# is already blocking in all three call sites.
#
# Checked against the BASELINE rather than against hardcoded expectations: the
# baseline is a real scan of the image the fleet is running, so it defines what
# "looked at this image properly" means for this image, and it moves forward on
# its own as the image changes. A hardcoded list of expected types would have
# to be edited by the same release that is being gated -- which is precisely
# the actor this check exists to constrain.
scan_types() {
  jq -r '[.Results[]?.Type | select(. != null and . != "")] | unique | .[]' "$1"
}

# Scan-derived strings are UNTRUSTED. .Metadata.OS.Family and .Results[].Type
# come from the image under test, which on the release path is built from a
# Dockerfile the submitter controls -- i.e. the exact actor this gate exists to
# constrain. These values are interpolated into `::error::` lines, and the
# summary they land in is also appended to $GITHUB_OUTPUT inside a
# `summary<<GATE_SUMMARY_EOF` heredoc.
#
# A newline in such a value therefore lets the image forge GitHub Actions
# workflow commands, and a line reading exactly GATE_SUMMARY_EOF closes the
# heredoc early so the rest is parsed as further step outputs -- including
# `verdict=improved`. Verified reachable through all three new messages before
# this was added.
#
# So flatten to one line and strip the two metacharacter sequences that give a
# log line authority: `::` (a workflow command) and `%` (the encoding GitHub
# uses for escaped newlines in those commands). Truncated, because an
# arbitrarily long field is its own denial-of-readability.
#
# Collapse any RUN of colons to one, rather than replacing the pair `::`.
# `s/::/:/g` consumes non-overlapping pairs, so `:::error` -> `::error` leaves
# exactly the sequence being removed; `:::::` -> `:::`. A run-collapse has no
# such residue for any number of colons. Flattening newlines already stops a
# forged command from starting a line, which is what GitHub actually requires,
# but the two are independent defences and neither should carry this alone.
safe_text() {
  printf '%s' "$1" \
    | tr '\n\r\t' '   ' \
    | sed -e 's/:\{2,\}/:/g' -e 's/%/pct/g' \
    | cut -c1-200
}

# Packages are present even under `--scanners vuln` (verified: 32 OS packages,
# 236 Go modules on :stable), so a per-type package count is available without
# a second scan. This is the check that catches a PARTIAL blinding, where the
# result type still exists but has been reduced to almost nothing -- which set
# arithmetic cannot distinguish from a genuine fix.
#
# Counts the Packages ARRAY rather than its entries, so "the key is absent or
# null" is distinguishable from "the key is an empty list". Emits the literal
# `unmeasurable` for the former. A count that cannot be taken must not be
# reported as 0: 0 reads as "nothing to compare" and skips the floor, which is
# the same fail-open shape this whole function exists to close, one level down.
pkg_count_for_type() {
  jq -r --arg t "$2" '
    [ .Results[]? | select(.Type == $t) ] as $r
    | if ($r | length) == 0 then "absent"
      elif ($r | map(select((.Packages | type) == "array")) | length) == 0 then "unmeasurable"
      else ( $r | map(.Packages // [] | length) | add )
      end' "$1"
}

# The set of package NAMES for a type, deduplicated and sorted, one per line.
#
# This is what check 5 compares, and it is the answer to the half of the
# coverage problem a COUNT cannot reach. pkg_count_for_type counts ROWS; two
# package lists of the same length are not the same package list. A rebuild
# that drops 120 real Go modules and adds 120 fabricated ones has the same
# count, clears the 50% floor outright, and contributes no findings for any of
# the 120 it dropped -- which then cancel out of gate 1's set arithmetic as
# "closed by the rebuild". Measured on the real images by security pass A:
# alpine 16 / gobinary 118 with ZERO vulnerabilities passes every count-based
# check and reports verdict=improved, and padding with 500 fabricated entries
# passes too, because names were never compared.
#
# Names are sanitized on the same grounds as ids_from and config_from: for a
# `gobinary` result Trivy copies PkgName out of the Go build info of a binary
# built from a Dockerfile the submitter controls, so these strings are
# attacker-chosen and they flow into ::error:: lines and into summary.md, which
# is appended to $GITHUB_OUTPUT inside a heredoc. Sanitizing INSIDE jq keeps
# one name per line, so an embedded newline cannot forge extra list entries
# either -- which matters more here than in ids_from, because this list is fed
# to `comm` and a split row would be a spurious set member on both sides.
#
# Sorted with LC_ALL=C so the ordering matches `comm`'s expectation exactly;
# a locale-dependent collation is the classic way to make comm silently
# under-report an intersection.
pkg_names_for_type() {
  jq -r --arg t "$2" '
    [ .Results[]? | select(.Type == $t) | .Packages[]?.Name
      | select(. != null and . != "")
      | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160] ]
    | unique | .[]' "$1" | LC_ALL=C sort -u
}

# The same, for ONE RESULT identified by its .Target rather than for a whole
# type. Checks 4 and 5 aggregate every result of a type together, and that
# aggregation is itself a bypass (found by the security review of the first
# spelling of check 6):
#
#   ship usr/bin/caddy gutted to a single package, and ALONGSIDE it a decoy
#   Go binary at usr/bin/helper carrying all 237 of the baseline's real module
#   names. The type-level count is 238 and the type-level name intersection is
#   237/237, so checks 4 and 5 are satisfied; check 6 is satisfied too, because
#   usr/bin/caddy IS still a scanned target -- it is simply empty. All 7
#   findings vanish and the verdict is `improved`. Reproduced end to end
#   against the real :stable scan before check 7 below was written.
#
# So the per-type checks cannot be the only ones: a type whose results are
# per-FILE needs its floors applied per file, or one file's coverage can be
# paid for with another's.
pkg_names_for_target() {
  jq -r --arg tg "$2" '
    [ .Results[]? | select((.Target // "") == $tg) | .Packages[]?.Name
      | select(. != null and . != "")
      | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160] ]
    | unique | .[]' "$1" | LC_ALL=C sort -u
}

# name@version pairs for a type (T-0810).
#
# Checks 5, 5b and 7 all compare `.Packages[].Name`, and NOTHING compares
# `.Packages[].Version`, so a rebuild can report an identical package name set
# -- 237/237 intersection, every floor cleared -- while the versions behind
# those names are entirely different from the baseline's. Measured against the
# real :stable scan: keep all 237 names, replace every version, zero the
# findings, and the precondition prints "scan coverage OK" while gate 1 reports
# ADDED=0 REMOVED=7, verdict=improved, exit 0.
#
# Packages with no readable Version are SKIPPED rather than rendered as
# `name@` or `name@null`. Trivy does not populate Version for every row -- on
# the real gobinary result the root `caddy` package carries none, so 236 of 237
# rows have one -- and a synthetic empty version would otherwise be a pair that
# matches on both sides for free, diluting the ratio in the attacker's favour.
# The denominator is therefore the number of pairs that CAN be compared, which
# is the same shape as check 5 counting distinct names rather than rows.
pkg_vers_for_type() {
  jq -r --arg t "$2" '
    [ .Results[]? | select(.Type == $t) | .Packages[]?
      | select((.Name // "") != "" and (.Version // "") != "")
      | ((.Name | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160]) + "@" +
         (.Version | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:120])) ]
    | unique | .[]' "$1" | LC_ALL=C sort -u
}

# The NAMES of the rows pkg_vers_for_type emitted a pair for -- i.e. the rows
# that HAVE a readable version -- for the denominator-ratchet check below.
#
# This exists instead of recovering the name by splitting the pair on its last
# `@`, which is what the first spelling of that check did and which the round-2
# review broke. The split is correct when the NAME contains `@` (Go module
# paths legitimately do), but wrong when the VERSION does -- and the sanitizer
# charclass permits `@`, so an attacker-chosen version survives into the
# compared string. `name@v0.58.0@1` splits to `name@v0.58.0`, which is in
# NEITHER name list, so `comm -12` drops the row and the ratchet never counts
# it. Reproduced end to end against a baseline whose x/crypto version was
# `v0.58.0@1`: the rebuild dropped the Version key and the CVE, coverage
# printed OK and gate 1 reported the finding as REMOVED, under STRICT policy.
# The control with a plain version blocked, so the `@` was the whole bug.
#
# Deriving the name from `.Name` directly has no parse step to confuse: it is
# the SAME select and the SAME sanitization as pkg_vers_for_type, so the two
# outputs correspond row for row by construction rather than by agreement
# between a formatter and a parser. No legitimacy cost: for any row whose
# version contains no `@` the two spellings agree exactly, and the real scans
# contain no such version -- so this can only ever ADD rows the split silently
# dropped, never remove one it counted.
pkg_versioned_names_for_type() {
  jq -r --arg t "$2" '
    [ .Results[]? | select(.Type == $t) | .Packages[]?
      | select((.Name // "") != "" and (.Version // "") != "")
      | (.Name | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160]) ]
    | unique | .[]' "$1" | LC_ALL=C sort -u
}

# Count rows whose Version would be CHANGED by the 120-character truncation
# pkg_vers_for_type and pkg_ver_of_name apply.
#
# Truncation makes two versions sharing their first 120 sanitized characters
# indistinguishable, and that is a laundering channel rather than a cosmetic
# limit: plant `v0.58.0+build.<140 chars>` in one release -- which compares
# EQUAL to itself, keeps its finding and so passes silently, looking like
# ordinary `+build` metadata -- and from then on that package's version can be
# changed beyond character 120 while 5c and 5d see no movement at all.
# Reproduced in review against the real :stable scan: the second step dropped
# a CVE with the gate reporting coverage OK.
#
# A real Go module version or apk revision is far shorter than 120 characters
# -- measured across the captured pairs, the longest is a 37-character Go
# pseudo-version -- so refusing to compare a version that does not survive the
# cut costs nothing legitimate and removes the channel rather than widening
# the window.
# Counted on BOTH sides by the caller, because the plant has to be accepted
# once before it can be exploited.
long_version_count() {
  jq -r --arg t "$2" '
    [ .Results[]? | select(.Type == $t) | .Packages[]?
      | select((.Name // "") != "" and (.Version // "") != "")
      | (.Version | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?"))
      | select(length > 120) ]
    | length' "$1"
}

# The version a given package name is reported at, for one type. Used by 5c to
# ask whether a findings-bearing package MOVED, as distinct from whether it is
# still present (which is 5b's question).
#
# A name listed at several versions yields several lines; the caller treats any
# difference in the set as a move, which is the conservative reading.
#
# SANITIZE .Name INSIDE THE SELECT, because the needle this is called with is
# ALREADY sanitized: it comes from the vulnerability list, which is written
# through the same gsub/truncate. Comparing a sanitized needle against a raw
# haystack silently matches NOTHING for any name carrying a character outside
# the allowed class or longer than 160 bytes -- `old_v` then comes back empty
# and 5c skips the package as "no readable version". That is fail-OPEN on the
# load-bearing check, and directly attacker-selectable, since a `gobinary`
# PkgName is copied from Go build info in a submitter-controlled image: one
# `~` in a module path was enough to turn 5c off. Found in review; the control
# with a plain name blocks correctly, so the asymmetry was the whole bug.
# Both sides must pass through the SAME transformation.
pkg_ver_of_name() {
  jq -r --arg t "$2" --arg n "$3" '
    [ .Results[]? | select(.Type == $t) | .Packages[]?
      | select((((.Name // "") | tostring
                 | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160]) == $n)
               and (.Version // "") != "")
      | (.Version | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:120]) ]
    | unique | .[]' "$1" | LC_ALL=C sort -u
}

# The set of finding IDs reported against one package name, for one type.
#
# 5c's exemption asks whether a package that MOVED VERSION still carries the
# findings it carried in the baseline. That question must be asked per FINDING,
# not per package: a package carrying several findings would otherwise be
# exempted by retaining any ONE of them while the rest cancel out of gate 1 as
# fixed. That is not hypothetical on this image -- the real :stable baseline
# reports THREE CVEs against github.com/go-jose/go-jose/v3.
#
# Both the ID and the name are sanitized here, for the reason pkg_ver_of_name
# is: the caller's needle is sanitized, and the baseline's ID set is compared
# against the rebuild's, so the two must be rendered identically or a name
# needing sanitization silently yields an empty set on one side.
#
# An EMPTY id is kept rather than filtered, and that is deliberate: `ids_from`
# has no such filter, so a row whose VulnerabilityID is "" or absent is a
# finding gate 1 counts. Filtering it here but not there made it invisible to
# this set while still cancelling out of gate 1 -- so it could vanish while the
# package's version moved, and 5c would exempt. Whatever the two functions
# disagree about is laundering surface; they must render the same row the same
# way. A whitespace-only id sanitizes to `???` and was already caught.
vuln_ids_for_pkg() {
  jq -r --arg t "$2" --arg n "$3" '
    [ .Results[]? | select(.Type == $t) | .Vulnerabilities[]?
      | select((((.PkgName // "") | tostring
                 | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160]) == $n))
      | ((.VulnerabilityID // "") | tostring
         | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:120]) ]
    | unique | .[]' "$1" | LC_ALL=C sort -u
}

assert_scan_coverage() {
  local new="$1" old="$2" arch="$3"
  local os_family new_types old_types missing t new_pkgs old_pkgs floor eosl
  local old_names_f new_names_f old_named retained name_floor
  local vuln_names_f lost_vuln lost_vuln_1l
  local vuln_names_f_keep vn old_v new_v moved_vuln moved_vuln_1l moved_vuln_n lost_ids_n
  local vuln_ver_blocking
  local old_nv_f new_nv_f old_nv nv_retained nv_floor
  local nv_names_f nv_newnames_f dropped_ver long_old long_new
  local old_gotargets new_gotargets lost_go old_gocount

  # The baseline must be a readable scan before it can define the standard.
  #
  # Checks 3 and 4 are RELATIVE: they ask what the baseline could see and
  # require the rebuild to still see it. A baseline that is empty or unreadable
  # therefore demands nothing, and the whole coverage assertion degrades to
  # check 1 alone -- which is the fail-open shape again, one more level out.
  # A truncated download, a disk-full write or a Trivy crash produces exactly
  # this: a zero-byte or partial JSON that jq reads as null without failing.
  #
  # Asserted on the BASELINE's own terms (it has results at all), not against
  # anything else, since there is nothing further back to compare it to.
  if ! jq -e 'has("Results") and (.Results | type) == "array" and (.Results | length) > 0' \
       "$old" >/dev/null 2>&1; then
    die "the published image's scan of linux/$arch has no usable results (empty, truncated or unparseable JSON): there is no baseline to compare against, and every coverage check below it is relative to one. Refusing to gate against an unreadable baseline."
  fi

  # 1. The OS layer was identified.
  #
  # Absent Family means Trivy could not tell what the base was, so the `alpine`
  # result and every OS package finding are missing by definition. jq prints
  # the string "null" for a missing key, so test for that spelling too.
  os_family="$(jq -r '.Metadata.OS.Family // ""' "$new")"
  case "$os_family" in
    ""|null)
      die "no OS detected in the rebuild's scan of linux/$arch (.Metadata.OS.Family absent): Trivy could not analyse this image, so an empty findings list means BLIND, not clean. Refusing to read it as an improvement." ;;
  esac

  # 2. The OS is still supported by the vulnerability database.
  #
  # Trivy omits EOSL entirely when false and emits only `"EOSL": true`
  # (verified on both alpine 3.23.6 and 3.23.7), so test for true rather than
  # for presence -- `has("EOSL")` would be false on every healthy image and
  # `// ""` would make absent indistinguishable from false.
  #
  # Past end-of-life the distro stops publishing advisories, so OS findings
  # stop appearing while the packages stay just as vulnerable. That is the same
  # fail-open shape as a missing scanner: the list shrinks because the data
  # stopped, not because the image got better.
  eosl="$(jq -r '.Metadata.OS.EOSL // false' "$new")"
  if [ "$eosl" = true ]; then
    die "the rebuild's base OS ($(safe_text "$os_family")) is flagged END-OF-LIFE in the vulnerability database for linux/$arch: advisories are no longer published for it, so a short findings list reflects missing DATA rather than a fixed image. Rebase onto a supported release."
  fi

  # 3. Every scan target the baseline had, the rebuild still has.
  #
  # This is the check that catches a vanished `gobinary`. A target that was
  # scanned before and is not scanned now is an ERROR, not an improvement:
  # whatever it used to report is now simply unobserved. Direction matters --
  # the rebuild may ADD types (a new ecosystem is more coverage, which is
  # fine), it may not LOSE them.
  new_types="$(scan_types "$new")"
  old_types="$(scan_types "$old")"
  missing="$(comm -13 <(printf '%s\n' "$new_types" | sort) \
                      <(printf '%s\n' "$old_types" | sort))"
  if [ -n "$missing" ]; then
    # tr-join each list onto one line, then trim the trailing separator, so the
    # message reads as prose instead of "gobinary-- that target".
    local missing_1l old_1l new_1l
    missing_1l="$(safe_text "$(printf '%s' "$missing"   | tr '\n' ' ')")"; missing_1l="${missing_1l% }"
    old_1l="$(safe_text "$(printf '%s' "$old_types"    | tr '\n' ' ')")"; old_1l="${old_1l% }"
    new_1l="$(safe_text "$(printf '%s' "$new_types"    | tr '\n' ' ')")"; new_1l="${new_1l% }"
    die "the rebuild's scan of linux/$arch lost scan target(s) the published image has: $missing_1l -- that target is now UNOBSERVED, not clean, so any finding it used to report would silently cancel out of the subset comparison. (published: $old_1l / rebuild: $new_1l)"
  fi

  # 4. A package-count floor per shared target.
  #
  # Checks 1-3 catch a target that disappeared; this catches one that is still
  # present but has been gutted -- a stripped binary that still parses as
  # `gobinary` but yields 3 modules instead of 236, or an OS database read
  # partially. Set arithmetic cannot tell that from a real fix.
  #
  # The floor is deliberately loose (50% of baseline), because a legitimate
  # release really can remove packages: dropping a plugin removes its whole
  # dependency subtree. The purpose is to catch a COLLAPSE in visibility, not
  # to police ordinary churn -- a tight floor here would block real releases
  # and get switched off, which is worse than a loose one that stays on.
  # Measured for scale: the Go module count moved 213 -> 236 across v2.55.0 ->
  # :stable, i.e. ~10% and upward, nowhere near this floor.
  #
  # Rounded UP, not down. Rounded down, a baseline of 1 package yields floor 0,
  # and `0 -lt 0` is false, so a target the baseline could see one package in
  # and the rebuild can see NONE in would pass. Rounding up makes a floor of at
  # least 1 for any non-empty baseline, so "the baseline saw something here and
  # the rebuild sees nothing" is always caught.
  #
  # Only types present on BOTH sides are compared. A type the rebuild added has
  # no baseline to be measured against, and check 3 has already established
  # nothing was lost.
  # Globbing off for the unquoted expansion below. Trivy type names contain no
  # whitespace, so word-splitting is what is wanted, but a `Type` of `*` comes
  # from the image's own scan metadata and would otherwise expand against the
  # working directory. `grep -qxF` already stops such a value from matching a
  # real baseline type, so this is not a known bypass -- it is removing the
  # expansion entirely rather than relying on the next check to absorb it.
  set -f
  for t in $new_types; do
    printf '%s\n' "$old_types" | grep -qxF "$t" || continue
    new_pkgs="$(pkg_count_for_type "$new" "$t")"
    old_pkgs="$(pkg_count_for_type "$old" "$t")"

    # An unmeasurable count is a hard stop, on EITHER side, rather than a
    # skipped check. `unmeasurable` means the result exists but its Packages is
    # absent or not a list, so the count cannot be taken -- and check 3 cannot
    # help here, because the type IS present on both sides. Treating it as
    # "nothing to compare" would let a rebuild be gutted for exactly the
    # targets whose baseline count happens to be unreadable.
    case "$new_pkgs" in
      unmeasurable|absent)
        die "the rebuild's '$(safe_text "$t")' scan of linux/$arch reports no readable package list (Packages absent or not an array), so its package count cannot be taken and the target's contents are UNOBSERVED rather than clean. Refusing to compare against it." ;;
    esac
    case "$old_pkgs" in
      absent) continue ;;
      unmeasurable)
        die "the published image's '$(safe_text "$t")' scan of linux/$arch reports no readable package list, so there is no measurable baseline for this target and a collapse in the rebuild's coverage could not be detected. Refusing to treat an unmeasurable baseline as nothing to check." ;;
    esac

    # Both counts are integers from here: jq's `add` over array lengths.
    #
    # A baseline of zero packages is a broken baseline, not a free pass. The
    # earlier spelling of this line was `[ "$old_pkgs" -gt 0 ] || continue`,
    # which skipped the floor entirely for such a target -- and that is
    # self-perpetuating rather than transient: check 3 still passes (the TYPE
    # is present on both sides), so one event that empties a target's package
    # list while leaving the result in place publishes once, and from then on
    # :stable IS the blind baseline. Every later release hits the same zero,
    # skips the floor, and prints "scan coverage OK" over a target that is
    # 100% unobserved on both sides.
    if [ "$old_pkgs" -eq 0 ]; then
      die "the published image's '$(safe_text "$t")' scan of linux/$arch reports 0 packages: the baseline is itself blind for this target, so it cannot define a coverage floor and a rebuild equally blind here would compare as clean. Re-scan the baseline, or rebase onto an image Trivy can read."
    fi
    # Absolute, not relative: a target present but entirely unobserved is never
    # an improvement, whatever the baseline says.
    [ "$new_pkgs" -gt 0 ] || die "the rebuild's '$(safe_text "$t")' scan of linux/$arch reports 0 packages: that target is present but entirely UNOBSERVED, so it has no findings to contribute and would cancel the baseline's out of the comparison."
    floor=$(( (old_pkgs + 1) / 2 ))
    if [ "$new_pkgs" -lt "$floor" ]; then
      die "the rebuild's '$(safe_text "$t")' scan of linux/$arch sees $new_pkgs package(s) where the published image has $old_pkgs (floor $floor): the target is present but its contents largely could not be read, so most of it is UNOBSERVED rather than fixed. A findings list this far short of the baseline's cannot be compared against it."
    fi

    # 5. The retained packages must be the SAME packages (T-0638).
    #
    # Check 4 is arithmetic on row counts, and a count is not an identity. It
    # asks "are there still at least half as many rows", never "are these the
    # same packages". So it is cleared by a list that has been REPLACED rather
    # than retained: drop the real modules, pad with fabricated names, keep the
    # count up. Every finding against a dropped package then has nothing to
    # match on the new side and cancels out of gate 1 as though the rebuild had
    # fixed it.
    #
    # So apply the SAME 50% floor to the INTERSECTION instead of to the raw
    # count: of the packages the baseline could see, at least half must still
    # be present BY NAME. Padding is now useless, because a fabricated name
    # does not intersect the baseline and therefore cannot contribute to the
    # number being floored.
    #
    # Deliberately the same loose 50%, and deliberately an intersection rather
    # than a subset assertion, for the reason check 4's floor is loose: a
    # legitimate release really does remove packages, and dropping a plugin
    # removes its whole dependency subtree. Requiring the baseline's names to
    # be a strict SUBSET of the rebuild's would block that ordinary case and
    # get the check switched off. Measured for scale against the real pair:
    # v2.68.12 retains 237/237 gobinary and 32/32 alpine names from :stable,
    # i.e. 100% against a 50% floor -- the same order of slack check 4 has.
    #
    # This does NOT replace check 4. Count catches a target gutted down to
    # nothing; identity catches one swapped out for something else. The two
    # compose, which is why both run: a list half the size made of entirely
    # real retained packages passes 5 and is caught by 4's absolute floors,
    # and a full-size list made of fabricated names passes 4 and is caught
    # here.
    old_names_f="$OUT/.cov-old-$arch-$(printf '%s' "$t" | tr -c 'A-Za-z0-9._-' '_').names"
    new_names_f="$OUT/.cov-new-$arch-$(printf '%s' "$t" | tr -c 'A-Za-z0-9._-' '_').names"
    pkg_names_for_type "$old" "$t" > "$old_names_f"
    pkg_names_for_type "$new" "$t" > "$new_names_f"

    # Count DISTINCT names, not rows: the floor below is computed from this
    # number, so it has to be the same denominator the intersection is drawn
    # from. A result that lists one package twice would otherwise set a floor
    # the intersection cannot reach.
    old_named=$(wc -l < "$old_names_f")
    old_named=${old_named//[[:space:]]/}

    # A baseline whose rows carry no usable names cannot define an identity
    # floor. Not a die: .Packages[].Name is guaranteed for neither every
    # ecosystem nor every Trivy version, and check 4's count floor has already
    # run on this target, so the coverage assertion still has a measurement
    # here. Skipping is sound precisely because this check is additive.
    #
    # SKIP THIS CHECK ONLY -- DO NOT `continue` THE TYPE. The earlier spelling
    # was a `continue`, which was correct while 5 and 5b were the only checks
    # below it and both keyed on .Packages[].Name. It stopped being correct
    # when 5c and 5d were added (T-0810): 5c keys on the VULNERABILITY's
    # .PkgName, a different field that can be populated when the package rows
    # are not, and 5d keys on name@version. A `continue` therefore disabled
    # every version check for a baseline whose package rows carry versions but
    # no names -- found in review, reproduced, and exactly the
    # self-perpetuating shape documented for check 4's zero-package baseline
    # above: check 3 still passes because the TYPE is present on both sides,
    # so one such image publishes once and :stable IS the blind baseline from
    # then on.
    if [ "$old_named" -eq 0 ]; then
      : # no identity floor available for this target; 5b/5c/5d still apply
    else
      retained=$(LC_ALL=C comm -12 "$old_names_f" "$new_names_f" | wc -l)
      retained=${retained//[[:space:]]/}
      name_floor=$(( (old_named + 1) / 2 ))
      if [ "$retained" -lt "$name_floor" ]; then
        rm -f "$old_names_f" "$new_names_f"
        die "the rebuild's '$(safe_text "$t")' scan of linux/$arch retains only $retained of the published image's $old_named package name(s) (floor $name_floor), though it reports $new_pkgs package(s) in total: the package list was REPLACED rather than retained, so the baseline's findings for the missing packages would cancel out of the comparison as though they had been fixed. A package count is not a package identity."
      fi
    fi

    # 5b. Every package that CARRIES A FINDING in the baseline must still be
    #     present in the rebuild, by name. No percentage.
    #
    # The 50% floor above is deliberately loose and deliberately indifferent
    # to WHICH names survive, and those are the same property viewed twice:
    # an attacker may retain any 119 of 237 names, so they retain innocuous
    # ones and drop exactly the packages whose findings they want gone.
    # Measured against the real pair: dropping the five findings-bearing Go
    # modules while padding back to 237 clears the floor BY ONE and gate 1
    # then reports ADDED=0 REMOVED=7, verdict=improved, and the moving tags
    # advance onto an image whose vulnerabilities were simply hidden.
    #
    # So the loose floor keeps its job -- tolerating ordinary churn and
    # legitimate plugin drops -- and this narrower, absolute rule covers the
    # packages that actually decide the verdict. A finding only cancels out
    # of gate 1's subset arithmetic as FIXED if its package stops being
    # reported; requiring those packages to still be observed is what makes
    # "this finding is gone" mean "gone" rather than "unobserved".
    #
    # This also removes the CARRY CHANNEL that the name floor alone has
    # across releases. Fabricated names become baseline names once published,
    # so they count toward the next release's intersection and the floor can
    # be walked down much faster than the count floor alone allowed. A
    # fabricated name never carries a finding, so it can never satisfy THIS
    # rule -- it is anchored to real, observed vulnerabilities rather than to
    # whatever the previous image happened to list.
    #
    # Measured cost on the real pair: ZERO. The baseline's five
    # findings-bearing modules are all present in the rebuild, so the refresh
    # path and an ordinary release are unaffected.
    #
    # A genuine plugin removal CAN legitimately drop a vulnerable package, so
    # this is absolute only under the strict policy. Under `report` -- the
    # release path, where removing a plugin is a documented reason to edit
    # Dockerfile.caddy -- it is printed and carried into the summary for the
    # reviewer instead, exactly as gates 2 and 3 treat their drift. That
    # keeps the rule from being the one that gets switched off, while still
    # putting the disappearance in front of the human approving the release.
    vuln_names_f="$OUT/.cov-vuln-$arch-$(printf '%s' "$t" | tr -c 'A-Za-z0-9._-' '_').names"
    jq -r --arg t "$t" '
      [ .Results[]? | select(.Type == $t) | .Vulnerabilities[]?.PkgName
        | select(. != null and . != "")
        | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160] ]
      | unique | .[]' "$old" | LC_ALL=C sort -u > "$vuln_names_f"
    lost_vuln="$(LC_ALL=C comm -23 "$vuln_names_f" "$new_names_f")"
    # Kept for check 5c below, which asks a different question of the same
    # list -- not "is this package still present" but "is it still the same
    # version". Removed at the end of 5c rather than here.
    vuln_names_f_keep="$vuln_names_f"
    if [ -n "$lost_vuln" ]; then
      lost_vuln_1l="$(safe_text "$(printf '%s' "$lost_vuln" | tr '\n' ' ')")"
      lost_vuln_1l="${lost_vuln_1l% }"
      if [ "$DRIFT_POLICY" = block ]; then
        rm -f "$old_names_f" "$new_names_f" "$vuln_names_f_keep"
        die "the rebuild's '$(safe_text "$t")' scan of linux/$arch no longer reports package(s) that carry findings in the published image: $lost_vuln_1l -- those findings have nothing to match against on the new side, so they would cancel out of the comparison as FIXED when they are merely unobserved. A rebuild of an unchanged Dockerfile must not drop a package the baseline is reporting a vulnerability for."
      fi
      printf 'NOTE (linux/%s): the rebuild no longer reports %s package(s) that carry findings in the published image: %s. Those findings will read as fixed in the comparison below; confirm the package was removed deliberately.\n' \
        "$arch" "$(safe_text "$t")" "$lost_vuln_1l"
    fi

    # 5c. A package that CARRIES FINDINGS in the baseline must still be
    #     reported AT THE SAME VERSION -- unless EVERY ONE of those findings
    #     is still reported against it (T-0810).
    #
    # 5b makes "this finding is gone" mean the package is still observed. It
    # does not make it mean the SAME package was observed. Checks 5/5b/7 all
    # compare names, so swapping only the versions of the findings-bearing
    # packages satisfies every one of them while the findings still cancel
    # out of gate 1 as fixed. Measured against the real :stable scan: swap
    # the versions of just the five findings-bearing Go modules and the
    # name@version retention is 231/236 = 97%, far above any ratio floor,
    # while all 7 findings disappear and the verdict comes out improved.
    # That is pass A's "drop exactly the packages that decide the verdict"
    # recurring one level down, and a ratio cannot catch it for the same
    # reason it could not catch the first one.
    #
    # WHY THIS IS NOT ids_from's EXCLUDED VERSION, REINTRODUCED.
    # ---------------------------------------------------------
    # ids_from deliberately keys findings on ID+package and NOT on
    # InstalledVersion, because including it made an UPGRADE of a
    # still-affected package look like one finding removed plus one added --
    # measured on GO-2026-5932 across v0.57.0 -> v0.58.0 -- so a security
    # release that bumps a module still carrying a standing advisory could
    # never ship. Nothing here changes that: gate 1's set arithmetic is
    # untouched and stays version-blind.
    #
    # The rule's FIRST limb is what keeps the two compatible. A package whose
    # version moved and which STILL CARRIES THE FINDING on the new side is
    # exactly the upgrade ids_from protects, and it satisfies this check
    # outright -- the finding did not cancel, so there is nothing to
    # misread. Verified on the documented case: with the baseline's x/crypto
    # at v0.57.0 and the rebuild's at v0.58.0 still reporting GO-2026-5932,
    # gate 1 reports added=0 removed=0 and this check passes.
    #
    # So the only state this blocks is the one that is genuinely ambiguous:
    # the finding vanished AND the thing it was reported against is no longer
    # the same thing. Under `block` -- the refresh path, rebuilding an
    # UNCHANGED Dockerfile.caddy from a release tag -- a findings-bearing
    # package cannot legitimately change version at all, so that state is
    # wrong by definition and blocking is the whole point. Under `report` --
    # the release path -- an upgrade that actually FIXES the advisory
    # produces precisely this shape and is the normal reason to cut a
    # security release, so it is printed for the reviewer instead, exactly
    # as 5b and gates 2/3 treat their drift. The scan alone cannot tell a
    # real fix from a substituted version; the release diff and the pin set
    # in Dockerfile.caddy can, and that is the reviewer's job.
    #
    # WHY THIS BLOCKS ONLY WHERE VERSIONS ARE REPRODUCIBLE BY CONSTRUCTION.
    # ---------------------------------------------------------------------
    # The argument above -- "a refresh rebuilds an unchanged Dockerfile, so a
    # findings-bearing package cannot legitimately change version" -- is true
    # for Go modules and FALSE for OS packages, and the difference is written
    # into Dockerfile.caddy. Every xcaddy `--with` carries a version (pinned
    # in v2.68.9), so the module set is reproducible and any movement in it
    # is drift the refresh path already blocks on through gate 2. The alpine
    # layer is the opposite: `apk upgrade --no-cache` is UNPINNED BY DESIGN
    # and `FROM caddy:2.11.9-alpine` is a moving tag, so picking up new OS
    # package versions is not drift -- it is the entire purpose of a weekly
    # refresh.
    #
    # Measured, not reasoned: the T-0592 refresh moved alpine-release
    # 3.23.7-r0 -> 3.23.8-r0, apk-tools and libapk 3.0.8-r0 -> 3.0.9-r0, and
    # zlib 1.3.2-r1 -> 1.4-r0, and that last one is what FIXED CVE-2026-4738.
    # Blocking OS version movement under `block` would therefore have blocked
    # the refresh that delivered a security fix -- the same "the gate calls
    # your fix a regression" failure ids_from exists to avoid, reappearing in
    # a different place. A rule that blocks the fix it is meant to protect
    # gets switched off, and then protects nothing.
    #
    # So the hard stop is scoped to the types whose versions are pinned, and
    # everything else is reported with the same note. That is not a weaker
    # rule where it matters: the supply-chain substitution this check exists
    # for is a swapped Go MODULE, which is exactly where the block applies.
    # An OS package version that moves while its finding disappears is the
    # ordinary, expected shape of an `apk upgrade`, and the note puts it in
    # front of the reviewer either way.
    #
    # The block limb therefore forbids nothing the refresh path already
    # allowed: a Go module whose version moved is module drift, and gate 2
    # diffs `caddy list-modules --versions` and fails the whole run on any
    # drift under this same policy. What this adds is a second observation of
    # the same fact derived from the scan rather than from executing the
    # binary, which matters because the two can disagree.
    #
    # BE HONEST ABOUT HOW INDEPENDENT THAT SECOND OBSERVATION ACTUALLY IS.
    # It is not two separate safety nets on the release path. Gate 2 and this
    # check are governed by the SAME MODULE_DRIFT_POLICY variable, and
    # release-docker.yml sets it from whether the submitter edited
    # Dockerfile.caddy -- so the attacker's own change selects the weaker
    # posture for BOTH at once, and both degrade to advisory together. Gate 2
    # is also the stronger evidence where it runs, because it executes the
    # binary while this check reads JSON the image authored. Read 5c as a
    # cross-check ON gate 2, not as independent cover FOR it: where they
    # disagree, one of them is being lied to, and the scan is the likelier
    # liar.
    # Measured on the real release pair v2.68.9 -> v2.68.12, which fixed three
    # CVEs by upgrading go-jose/v4, x/net and stdlib: under `report` all three
    # are printed as notes and the release passes, which is the intended
    # outcome -- the reviewer is told the findings cleared because versions
    # moved, and the release diff says whether those moves were the ones asked
    # for.
    case "$t" in
      gobinary|gomod) vuln_ver_blocking=1 ;;
      *)              vuln_ver_blocking=0 ;;
    esac

    # Measured cost on the real pair: ZERO under both policies. All five
    # findings-bearing modules are reported at identical versions on both
    # sides of v2.68.12 vs :stable.
    # Counted as well as listed. safe_text caps every interpolated string at
    # 200 characters -- a deliberate log-injection defence, not a bug -- so a
    # long list is truncated mid-package in both the die and the note. A
    # reviewer reading a truncated list would not know how much was cut, and
    # on the release path that note is the ONLY thing standing between a
    # substituted version and an approval. The count is generated here rather
    # than taken from the string, so it survives the cut.
    moved_vuln=""
    moved_vuln_n=0
    while IFS= read -r vn; do
      [ -n "$vn" ] || continue
      # EXEMPT ONLY ON FULL RETENTION OF THE BASELINE'S FINDINGS FOR THIS
      # PACKAGE, compared as an ID SET rather than as a count.
      #
      # The first spelling of this asked `length > 0` -- "does this package
      # name appear in any vulnerability row on the new side" -- and that is
      # wrong in two ways, both found in review and both reproduced against
      # the real :stable scan.
      #
      # (1) PER-PACKAGE, NOT PER-FINDING. A package carrying several findings
      #     was exempted by retaining any ONE of them while the others
      #     cancelled as fixed. Live on this image: the baseline reports three
      #     CVEs against github.com/go-jose/go-jose/v3, so substituting its
      #     version and keeping one of the three gave coverage OK, ADDED=0
      #     REMOVED=2, verdict=improved, exit 0 -- under the STRICT policy,
      #     and with no note printed either.
      #
      # (2) THE EXEMPTION ACCEPTED A FABRICATED FINDING. Every string in this
      #     JSON is attacker-chosen, so the image could manufacture its own
      #     exemption by adding one invented vulnerability row naming the
      #     package. That failed the standard 5b sets for itself a few lines
      #     up -- anchored to real, observed vulnerabilities -- while claiming
      #     to follow it.
      #
      # Comparing the BASELINE's ID set against the new side's fixes both: a
      # fabricated ID is not in the baseline set so it cannot complete it, and
      # a partial retention is not a full one. `comm -23` is the baseline IDs
      # not present on the new side; empty means every one survived, which is
      # the upgrade case ids_from protects and the only state exempted here.
      #
      # COUNTED BY LINE, NOT TESTED FOR EMPTINESS. An empty VulnerabilityID is
      # a finding `ids_from` counts (it keys on "\($id)\t\($pkg)", with no
      # filter on $id), so it must be a member of this set too -- but a set
      # whose ONLY lost member is the empty id is a single empty line, and
      # command substitution strips it to a zero-length string. `[ -n ... ]`
      # then reads "nothing was lost" and 5c exempts the version move, while
      # gate 1 still cancels that finding as FIXED. Reproduced: baseline
      # go-jose/v3 with three CVEs plus one empty-id row, rebuild moving the
      # version and keeping the three -- coverage OK, the empty-id finding
      # removed. `wc -l` counts the line the string cannot hold.
      lost_ids_n="$(LC_ALL=C comm -23 \
                      <(vuln_ids_for_pkg "$old" "$t" "$vn") \
                      <(vuln_ids_for_pkg "$new" "$t" "$vn") | wc -l)"
      lost_ids_n=${lost_ids_n//[[:space:]]/}
      [ "$lost_ids_n" -gt 0 ] || continue
      old_v="$(pkg_ver_of_name "$old" "$t" "$vn")"
      new_v="$(pkg_ver_of_name "$new" "$t" "$vn")"
      # No readable version on either side: 5b already asserted presence and
      # there is nothing further to compare. Not a die, for the reason check
      # 5 skips a nameless baseline -- the check is additive.
      [ -n "$old_v" ] || continue
      # Absent from the new side entirely is 5b's case, already handled above.
      [ -n "$new_v" ] || continue
      if [ "$old_v" != "$new_v" ]; then
        moved_vuln="$moved_vuln$vn ($(printf '%s' "$old_v" | tr '\n' ',' | sed 's/,$//') -> $(printf '%s' "$new_v" | tr '\n' ',' | sed 's/,$//')) "
        moved_vuln_n=$(( moved_vuln_n + 1 ))
      fi
    done < "$vuln_names_f_keep"
    if [ -n "$moved_vuln" ]; then
      moved_vuln_1l="$(safe_text "${moved_vuln% }")"
      if [ "$DRIFT_POLICY" = block ] && [ "$vuln_ver_blocking" -eq 1 ]; then
        rm -f "$old_names_f" "$new_names_f" "$vuln_names_f_keep"
        die "the rebuild's '$(safe_text "$t")' scan of linux/$arch reports $moved_vuln_n package(s) that carry findings in the published image at a DIFFERENT version, and no longer reports those findings: $moved_vuln_1l -- the finding cancels out of the comparison as FIXED, but the package it was reported against is not the same one, so nothing establishes it was fixed rather than substituted. Every xcaddy --with in Dockerfile.caddy carries a version, so a rebuild of an unchanged Dockerfile must reproduce the same module versions; a module that moved here did not come from the pin set. Cut a release if the bump is intended."
      fi
      printf 'NOTE (linux/%s): the rebuild reports %s %s package(s) at a different version than the published image, and no longer reports the finding(s) they carried: %s. Those findings read as FIXED in the comparison below on the strength of the version change alone, so confirm each new version is the intended upgrade rather than a substitution. (List truncated at 200 characters; the count is exact.)\n' \
        "$arch" "$moved_vuln_n" "$(safe_text "$t")" "$moved_vuln_1l"
    fi
    rm -f "$vuln_names_f_keep"

    # 5d. A loose name@VERSION identity floor (T-0810).
    #
    # 5c covers the packages that decide the verdict, the way 5b does for
    # presence. This covers the wholesale case the way check 5 does: a
    # rebuild that keeps every name but replaces every version behind them.
    # That image is not the baseline's dependency set under another label --
    # it is a different set of code wearing the same names, and a finding
    # absent from it is unobserved rather than fixed.
    #
    # Deliberately the SAME loose 50% as checks 4, 5 and 7, and for the same
    # reason: a legitimate release really does move versions, and a tight
    # floor here would block ordinary releases and get switched off.
    # Measured on the real pairs -- v2.68.12 vs :stable retains 235/236
    # gobinary and 32/32 alpine name@version pairs (99% / 100%), and the
    # T-0592 security release, which is the heaviest real churn on record
    # because it moved the whole alpine base to fix CVE-2026-4738, retains
    # 28/32 alpine (87%) and 235/235 gobinary (100%). The wholesale swap
    # retains 0/236. The separation between a legitimate release and the
    # attack is the entire range, so a 50% floor sits in open space rather
    # than on a boundary.
    #
    # This does NOT subsume 5c and 5c does not subsume this, for exactly the
    # relationship check 4 and check 5 have: a ratio catches the wholesale
    # replacement that 5c's narrow rule ignores, and 5c catches the targeted
    # five-package swap that sits at 97% and clears any ratio.
    # Named `.names` like every other scratch file here, NOT `.nv`, so the
    # stale-output sweep at the top of the script clears them: that sweep
    # globs "$OUT"/.cov-*.names, and a new suffix would silently fall outside
    # it. A stale file would then be read back as this run's name@version list
    # for this target -- the exact failure the sweep exists to prevent, and
    # one that fails OPEN here, since a stale baseline list that happens to
    # intersect would clear the floor.
    old_nv_f="$OUT/.cov-old-nv-$arch-$(printf '%s' "$t" | tr -c 'A-Za-z0-9._-' '_').names"
    new_nv_f="$OUT/.cov-new-nv-$arch-$(printf '%s' "$t" | tr -c 'A-Za-z0-9._-' '_').names"
    pkg_vers_for_type "$old" "$t" > "$old_nv_f"
    pkg_vers_for_type "$new" "$t" > "$new_nv_f"
    old_nv=$(wc -l < "$old_nv_f"); old_nv=${old_nv//[[:space:]]/}

    # A VERSION THAT DOES NOT SURVIVE TRUNCATION CANNOT BE COMPARED.
    #
    # See long_version_count. Checked on BOTH sides and before any floor is
    # taken, because the plant must be accepted once before it can be used,
    # and because a baseline already carrying one is a baseline whose version
    # comparison is already blind for that row.
    long_old=$(long_version_count "$old" "$t")
    long_new=$(long_version_count "$new" "$t")
    if [ "$long_old" -gt 0 ] || [ "$long_new" -gt 0 ]; then
      rm -f "$old_nv_f" "$new_nv_f" "$old_names_f" "$new_names_f"
      die "the '$(safe_text "$t")' scan of linux/$arch reports package version(s) longer than 120 characters (published: $long_old, rebuild: $long_new): versions are compared truncated to that length, so two versions agreeing only up to it are indistinguishable here and a later change beyond the cut would move a package without this check seeing it. A real module version or package revision is far shorter; refusing to compare one this long closes a laundering channel rather than widening the window."
    fi

    # THE DENOMINATOR MUST NOT BE ATTACKER-SHRINKABLE ACROSS RELEASES.
    #
    # `old_nv` counts only baseline rows that HAVE a readable version, and a
    # published image becomes the next baseline. So stripping Version from
    # just under half the packages each release clears the 50% floor every
    # time while halving the denominator for the next one -- names stay
    # untouched, so checks 4, 5, 5b and 7 never fire, and the standard walks
    # down to a single pair. That is the same inherited-denominator ratchet
    # that made fabricated NAMES dangerous (closed by 5b), one level down,
    # and 5b does not cover it because a stripped version is not a missing
    # package.
    #
    # So a baseline package that HAD a version and whose rebuild row no
    # longer carries one counts as a LOST pair rather than as nothing to
    # compare. That is the honest reading anyway: the version stopped being
    # observable, and an unobservable version cannot establish that a finding
    # was fixed. Legitimate cost is nil -- Trivy populates Version for every
    # gobinary row but the synthetic root package, and for every alpine row,
    # on both real pairs.
    # Only packages the rebuild STILL REPORTS are asked this. One that is gone
    # altogether is 5 and 5b's question, and counting it here as well would
    # turn a legitimate plugin removal -- which both of those deliberately
    # tolerate -- into a hard stop.
    #
    # The two name lists come from pkg_versioned_names_for_type, NOT from
    # splitting the pairs on their last `@`. See that function: the version is
    # attacker-chosen and the sanitizer permits `@`, so a split recovers the
    # wrong name whenever the VERSION contains one, and the row then matches
    # neither list and is never counted. Reading `.Name` directly has no parse
    # step to confuse.
    nv_names_f="$OUT/.cov-oldnv-names-$arch-$(printf '%s' "$t" | tr -c 'A-Za-z0-9._-' '_').names"
    nv_newnames_f="$OUT/.cov-newnv-names-$arch-$(printf '%s' "$t" | tr -c 'A-Za-z0-9._-' '_').names"
    pkg_versioned_names_for_type "$old" "$t" > "$nv_names_f"
    pkg_versioned_names_for_type "$new" "$t" > "$nv_newnames_f"
    dropped_ver=$(LC_ALL=C comm -12 "$nv_names_f" "$new_names_f" \
                  | LC_ALL=C comm -23 - "$nv_newnames_f" | wc -l)
    dropped_ver=${dropped_ver//[[:space:]]/}
    rm -f "$nv_names_f" "$nv_newnames_f"
    if [ "$dropped_ver" -gt 0 ]; then
      rm -f "$old_nv_f" "$new_nv_f" "$old_names_f" "$new_names_f"
      die "the rebuild's '$(safe_text "$t")' scan of linux/$arch reports $dropped_ver package(s) WITHOUT a version that the published image reported WITH one, while still reporting the package itself: an unobservable version cannot establish that a finding against that package was fixed rather than substituted, and because a published image becomes the next baseline, accepting this would shrink the version floor's denominator for every later release. Re-scan, or rebase onto an image Trivy can read versions from."
    fi

    # A baseline carrying no readable versions cannot define a version floor.
    # Skipped rather than fatal for the reason check 5 skips a nameless
    # baseline: .Packages[].Version is guaranteed for neither every ecosystem
    # nor every Trivy version, checks 4 and 5 have already measured this
    # target, and this check is additive. The denominator ratchet above is
    # what stops this skip from being walked toward deliberately.
    if [ "$old_nv" -eq 0 ]; then
      rm -f "$old_nv_f" "$new_nv_f"
    else
      nv_retained=$(LC_ALL=C comm -12 "$old_nv_f" "$new_nv_f" | wc -l)
      nv_retained=${nv_retained//[[:space:]]/}
      nv_floor=$(( (old_nv + 1) / 2 ))
      rm -f "$old_nv_f" "$new_nv_f"
      if [ "$nv_retained" -lt "$nv_floor" ]; then
        rm -f "$old_names_f" "$new_names_f"
        die "the rebuild's '$(safe_text "$t")' scan of linux/$arch retains only $nv_retained of the published image's $old_nv package name@version pair(s) (floor $nv_floor), though it retains $retained of $old_named package NAME(s): the names were kept while the versions behind them were replaced, so this is a different dependency set wearing the baseline's labels and its findings would read as fixed when they are merely unobserved. A package name is not a package version."
      fi
    fi

    rm -f "$old_names_f" "$new_names_f"
  done
  # Restore globbing: the rest of the script relies on it (the summary's
  # `for _ in $ARCHES` and the module-diff paths), and a `die` above exits the
  # whole script anyway, so this only needs to cover the success path.
  set +f

  # 5e. An ABSOLUTE floor, pinned to a committed fixture (T-0811).
  #
  # WHAT THIS IS FOR, AND WHY THE RELATIVE FLOORS ARE NOT ENOUGH.
  # ------------------------------------------------------------
  # Every floor above is RELATIVE to the baseline: the published image defines
  # what "scanned properly" means. 5b and 5c anchor the findings-bearing
  # packages to observed vulnerabilities, which closed the carry channel where
  # fabricated names became next release's baseline names. What they do not
  # anchor is the DENOMINATOR -- the 50% name floor and the count floor both
  # take their scale from whatever :stable happens to report, so a baseline
  # that is itself partially degraded permanently lowers the bar for every
  # later release, and nothing above can see that it has happened.
  #
  # Measured under T-0811 against the real :stable scan, using checks 1-7 as
  # they stand: each step keeping every findings-bearing package at its
  # baseline VERSION (so 5b and 5c are satisfied honestly, not evaded) and the
  # minimum number of others at their baseline name@version (so 5 and 5d are),
  # then publishing and becoming the next baseline --
  #
  #   237 -> 119 -> 60 -> 30 -> 15 -> 8 -> 6 Go modules, in SIX releases,
  #   rc=0 and "scan coverage OK" printed at every single step.
  #
  # The floor is multiplicative, so each step halves. And the end state buys
  # real blindness: binary-searched, a healthy 237-package baseline accepts a
  # smallest rebuild of 119 (49% may be unobserved), while the degraded
  # 6-package baseline accepts 1 (83%). The SAME 6-package image is exit 2
  # against the healthy baseline and "coverage OK" against the degraded one --
  # the standard itself moved, which is precisely what no relative check can
  # detect.
  #
  # A fixture stops that at step 2 outright: pinned at 237 names, the ratchet's
  # steps are 50% / 25% / 12% / ... intersections against the fixture, so step 2
  # (60/237 = 25%) blocks and step 1 (119/237 = 50%) is marginal. Nothing the
  # rebuild fabricates can raise that number, because the fixture is not
  # derived from the rebuild.
  #
  # WHY A COMMITTED FILE IS ACCEPTABLE HERE, GIVEN T-0638 DECLINED ONE.
  # ------------------------------------------------------------------
  # T-0638 rejected an absolute floor on the grounds that a file committed next
  # to the Dockerfile "is editable by the same release it constrains", which is
  # the actor the gate exists to constrain. That objection is real but it is
  # comparative, and it comes out the other way: the edit is a REVIEWABLE DIFF
  # in the PR Richard approves per release, whereas the baseline's erosion is
  # invisible -- it happens in the published image, with no diff anywhere. A
  # change that has to be shown to a human beats one that does not.
  #
  # THREE DELIBERATE SCOPINGS, each measured rather than assumed.
  #
  #   (1) `gobinary` ONLY; no OS-layer fixture. `apk upgrade --no-cache` is
  #       unpinned by design and `FROM caddy:2.11.9-alpine` is a moving tag, so
  #       the alpine name set legitimately drops to 65% on a minor bump -- the
  #       3.23->3.24 figure measured under T-0810. A rule that blocks the
  #       refresh it exists to protect gets switched off, which is the same
  #       reason 5c is scoped the way it is. The OS layer keeps the relative
  #       floors it already has. Enforced here by reading the fixture's own
  #       declared `type` rather than by looping: a fixture that names a type
  #       whose churn is legitimate is a mistake this check should not make
  #       easy to write.
  #
  #   (2) NAMES, not versions, and not counts alone. Versions are 5c/5d's
  #       business and churn legitimately every release. A raw COUNT floor --
  #       the `gobinary >= 100` form T-0638's card proposed -- is the strictly
  #       weaker shape, because a padded list of fabricated names clears it:
  #       exactly the gap T-0638 closed for the relative checks, and it must
  #       not be reintroduced here one level out.
  #
  #   (3) REFRESHED AT RELEASE, in the release PR. See the fixture's own
  #       _comment field and the release runbook.
  #
  # WHY STALENESS CANNOT BLOCK A LEGITIMATE RELEASE.
  # -----------------------------------------------
  # This is an INTERSECTION against an old set, so a fixture that is behind
  # simply asserts LESS: names the fixture does not know about cannot be missed
  # from it. It degrades permissively, never restrictively. That removes the
  # "a release blocked by a stale fixture" failure mode, which was the main
  # argument against doing this at all -- the cost the card weighed does not
  # exist in this shape.
  #
  # MEASURED COST, from every captured real pair on this host (21 pairs,
  # v2.55-era through v2.68.12): Go-module NAME retention is 99-100%, with 20
  # of 21 at exactly 100%; the widest span available (the 236-package era vs
  # the current 237) is also 100%. The attack is 2% (6 of 237). So a 50% floor
  # sits in open space rather than on a boundary: legitimate releases move
  # module VERSIONS, not module NAMES.
  #
  # Compared PER TARGET, not per type, and against the fixture's declared
  # target. Check 7 exists because `gobinary` is a type that can appear more
  # than once, and a type-level intersection is payable with a decoy binary:
  # ship usr/bin/caddy gutted to one package and a second Go binary elsewhere
  # carrying all 237 fixture names, and a type-level 5e reads 237/237 while the
  # binary the image actually runs is unobserved. That is the bypass check 7
  # was written for, reproduced end to end against the real scan, and this
  # check must not reopen it one level out.
  if [ -n "$COVERAGE_FLOOR_FILE" ]; then
    if [ ! -f "$COVERAGE_FLOOR_FILE" ]; then
      # ABSENT is not a fault. The script is run by hand and from worktrees
      # that predate the fixture, and every check above still ran. Noted
      # rather than silent, so "5e did not run" is visible in the log and in
      # the summary instead of being indistinguishable from "5e passed".
      printf 'NOTE (linux/%s): no committed coverage floor at %s, so the absolute floor (check 5e) did not run; the relative floors above still did.\n' \
        "$arch" "$(safe_text "$COVERAGE_FLOOR_FILE")"
      # Wording asserted on by the test harness, which checks that this skip
      # is VISIBLE rather than silent -- a silent skip reads exactly like a
      # pass, and that is how a check stays off after someone moves the file.
    else
      # PRESENT BUT UNUSABLE IS A HARD STOP, unlike absent.
      #
      # The two cases are deliberately asymmetric. "No fixture" is a
      # configuration this repo supports; "a fixture that cannot be read" is
      # the fail-open shape this entire function exists to close, and it is
      # the one an attacker reaches for -- truncate the file, or corrupt one
      # byte of it, and a skip-on-error check turns itself off while still
      # printing coverage OK. Validated as a whole document before any field
      # is trusted.
      local fx_type fx_target fx_pct fx_names_f fx_count fx_retained fx_floor
      local fx_new_f fx_valid
      fx_valid="$(jq -r '
        if (type == "object")
           and ((.schema // 0) == 1)
           and (((.type // "") | type) == "string") and ((.type // "") != "")
           and (((.target // "") | type) == "string") and ((.target // "") != "")
           and ((.floor_percent // null) | type == "number")
           and ((.names | type) == "array")
        then "ok" else "bad" end' "$COVERAGE_FLOOR_FILE" 2>/dev/null || echo bad)"
      [ "$fx_valid" = ok ] \
        || die "the committed coverage floor $(safe_text "$COVERAGE_FLOOR_FILE") is not a readable schema-1 floor document (needs object with schema=1, non-empty string type and target, numeric floor_percent, array names). A floor that cannot be parsed asserts nothing while still appearing to be configured, which is the fail-open shape every check in this function exists to close. Fix or remove the file; do not leave it unparseable."

      fx_type="$(jq -r '.type' "$COVERAGE_FLOOR_FILE")"
      fx_target="$(jq -r '.target' "$COVERAGE_FLOOR_FILE")"
      fx_pct="$(jq -r '.floor_percent | floor' "$COVERAGE_FLOOR_FILE")"

      # Scoping (1), enforced rather than documented. An OS-layer fixture
      # would block the base-image bump it exists to protect (alpine names
      # drop to 65% on a legitimate minor bump), and the first time it did,
      # the check would be switched off for everything.
      [ "$fx_type" = gobinary ] \
        || die "the committed coverage floor declares type '$(safe_text "$fx_type")', but this check is deliberately scoped to 'gobinary' only. The OS layer's package names legitimately drop to ~65% on an alpine minor bump because 'apk upgrade --no-cache' is unpinned by design and the base tag moves, so an absolute floor there would block the refresh it exists to protect. Keep the OS layer on the relative floors above."

      [ "$fx_pct" -ge 1 ] && [ "$fx_pct" -le 100 ] \
        || die "the committed coverage floor declares floor_percent=$(safe_text "$fx_pct"), which is outside 1-100. A floor of 0 asserts nothing and a floor above 100 can never be met; neither is a usable setting."

      fx_names_f="$OUT/.cov-fixture-$arch.names"
      # Sanitized and sorted through the SAME transformation as
      # pkg_names_for_target, because the two outputs are fed to `comm`. A
      # fixture rendered even slightly differently from the scan side would
      # under-report the intersection and block legitimate releases -- the
      # noisy-check failure mode that gets a check switched off. Same LC_ALL=C
      # ordering, for the reason documented on pkg_names_for_type.
      jq -r '[ .names[]? | select(. != null and . != "")
               | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160] ]
             | unique | .[]' "$COVERAGE_FLOOR_FILE" | LC_ALL=C sort -u > "$fx_names_f"
      fx_count=$(wc -l < "$fx_names_f")
      fx_count=${fx_count//[[:space:]]/}

      if [ "$fx_count" -eq 0 ]; then
        # An EMPTY names array parses fine and asserts nothing, so it is the
        # quietest possible way to disable this check while leaving a
        # plausible-looking fixture committed. A caller that means to turn 5e
        # off sets COVERAGE_FLOOR_FILE= explicitly, which is visible.
        rm -f "$fx_names_f"
        die "the committed coverage floor $(safe_text "$COVERAGE_FLOOR_FILE") lists zero package names, so it imposes no floor at all while still being present and parseable. To run without an absolute floor, unset the file or pass COVERAGE_FLOOR_FILE= explicitly; do not commit an empty one."
      fi

      # Per TARGET (see above), so a decoy Go binary cannot pay for the real
      # one's coverage.
      fx_new_f="$OUT/.cov-fixnew-$arch.names"
      pkg_names_for_target "$new" "$fx_target" > "$fx_new_f"
      fx_retained=$(LC_ALL=C comm -12 "$fx_names_f" "$fx_new_f" | wc -l)
      fx_retained=${fx_retained//[[:space:]]/}
      # Rounded UP, for the reason check 4's floor is: rounded down, a small
      # fixture yields floor 0 and "the rebuild retains none of them" would
      # pass.
      fx_floor=$(( (fx_count * fx_pct + 99) / 100 ))
      rm -f "$fx_names_f" "$fx_new_f"

      if [ "$fx_retained" -lt "$fx_floor" ]; then
        die "the rebuild's '$(safe_text "$fx_target")' scan of linux/$arch retains only $fx_retained of the $fx_count Go module name(s) recorded at the last tagged release (floor $fx_floor = $fx_pct%), as pinned in $(safe_text "$COVERAGE_FLOOR_FILE"). Unlike the floors above, this one is NOT relative to the published baseline, so a baseline that has itself lost coverage cannot lower it. Either this rebuild sees far less of the shipped binary than the last release did, or the baseline it is being compared against has already degraded. If the drop is deliberate -- a plugin removed with its dependency subtree -- refresh the fixture in this release's PR so the change is reviewed as a diff."
      fi
      printf 'absolute floor (linux/%s): %s retains %s/%s pinned Go module name(s) (floor %s = %s%%)\n' \
        "$arch" "$(safe_text "$fx_target")" "$fx_retained" "$fx_count" "$fx_floor" "$fx_pct"
    fi
  fi

  # 6. The scanned binary is the SHIPPED binary (T-0638).
  #
  # Checks 3-5 are per TYPE, and `gobinary` is a type that can legitimately
  # appear more than once: Trivy emits one result per Go binary it finds, keyed
  # by its path in .Target. So "a gobinary result exists" is not "the binary
  # this image runs was scanned". A rebuild that leaves /usr/bin/caddy
  # unreadable to Trivy -- stripped build info, moved, replaced after the
  # scanner's walk -- but ships any OTHER Go binary at some other path still
  # has a `gobinary` type present, and checks 3-5 then measure THAT binary's
  # packages against the baseline's caddy packages.
  #
  # Asserted against the baseline's own gobinary targets rather than a
  # hardcoded `usr/bin/caddy`, for the reason the whole function is relative:
  # a hardcoded path would have to be edited by the release being gated. The
  # baseline is a real scan of the image the fleet runs, and on the real
  # :stable that path is exactly `usr/bin/caddy`, which is where
  # Dockerfile.caddy's final `COPY --from=builder` puts it.
  #
  # Scoped to gobinary deliberately. OS results carry the image REFERENCE in
  # .Target ("repo:tag (alpine 3.24.4)"), which differs between the two sides
  # by definition, so comparing targets for every type would report drift on
  # every run. Language results carry a PATH, which is the thing worth
  # asserting on.
  old_gotargets="$(jq -r '[.Results[]? | select(.Type == "gobinary") | .Target
                           | select(. != null and . != "")] | unique | .[]' "$old")"

  # "No Go binaries in the baseline" and "Go binaries whose paths were not
  # recorded" are different states, and only the first is a safe skip.
  #
  # The jq above drops null and empty Targets, so a baseline with gobinary
  # RESULTS but no usable .Target on any of them yields an empty list, which a
  # bare `-n` test cannot distinguish from a baseline that simply has no Go
  # binary at all. Skipping on that is the self-perpetuating shape already
  # closed for check 4's zero-package baseline above: checks 3-5 still pass
  # because the gobinary TYPE is present on both sides, so a rebuild that
  # scans an entirely DIFFERENT binary goes unnoticed, and once such an image
  # is published it IS the baseline and check 6 is disarmed from then on.
  #
  # Trivy 0.76.1 always populates .Target for a gobinary result, so this is
  # defence in depth rather than a live bypass -- which is exactly what the
  # old_pkgs -eq 0 case was when it was judged worth closing rather than
  # tracking. Counted BEFORE the filter, so the two states are separable.
  old_gocount="$(jq -r '[.Results[]? | select(.Type == "gobinary")] | length' "$old")"
  if [ "$old_gocount" -gt 0 ] && [ -z "$old_gotargets" ]; then
    die "the published image's scan of linux/$arch has $old_gocount gobinary result(s) but no usable .Target on any of them: the set of Go binaries the baseline covered cannot be established, so a rebuild that scans a DIFFERENT binary than the one this image runs could not be detected. Re-scan the baseline."
  fi

  if [ -n "$old_gotargets" ]; then
    new_gotargets="$(jq -r '[.Results[]? | select(.Type == "gobinary") | .Target
                             | select(. != null and . != "")] | unique | .[]' "$new")"
    lost_go="$(LC_ALL=C comm -13 <(printf '%s\n' "$new_gotargets" | LC_ALL=C sort -u) \
                                 <(printf '%s\n' "$old_gotargets" | LC_ALL=C sort -u))"
    if [ -n "$lost_go" ]; then
      local lost_1l old_go_1l new_go_1l
      lost_1l="$(safe_text "$(printf '%s' "$lost_go"       | tr '\n' ' ')")";   lost_1l="${lost_1l% }"
      old_go_1l="$(safe_text "$(printf '%s' "$old_gotargets" | tr '\n' ' ')")"; old_go_1l="${old_go_1l% }"
      new_go_1l="$(safe_text "$(printf '%s' "$new_gotargets" | tr '\n' ' ')")"; new_go_1l="${new_go_1l% }"
      die "the rebuild's scan of linux/$arch no longer covers the Go binary at: $lost_1l -- the gobinary TYPE is still present, so the per-type checks above compared a DIFFERENT binary against the published one's. The binary this image actually runs is therefore unobserved, and its findings would cancel out of the comparison. (published: $old_go_1l / rebuild: $new_go_1l)"
    fi

    # 7. PER-BINARY identity floor.
    #
    # Check 6 establishes the baseline's Go binaries are still SCANNED. It
    # does not establish any of them was scanned usefully, because checks 4
    # and 5 pool every gobinary result of the type together. A decoy binary
    # therefore pays for the real one's coverage: gut usr/bin/caddy to one
    # package, add usr/bin/helper carrying the baseline's 237 real module
    # names, and the type-level count (238) and type-level intersection
    # (237/237) both clear while the binary the image actually runs is
    # entirely unobserved. Verified against the real :stable scan -- every
    # earlier check passed and all 7 findings disappeared.
    #
    # So apply the same 50% identity floor AGAIN, per retained target. Same
    # threshold and same intersection semantics as check 5: this narrows
    # WHERE the floor is applied, not how strict it is, so it cannot block a
    # release check 5 would have allowed on a single-binary image. On today's
    # image the two are identical, because there is exactly one gobinary
    # result.
    local gt gt_old_f gt_new_f gt_old_n gt_ret gt_floor
    while IFS= read -r gt; do
      [ -n "$gt" ] || continue
      gt_old_f="$OUT/.cov-tgt-old-$arch-$(printf '%s' "$gt" | tr -c 'A-Za-z0-9._-' '_').names"
      gt_new_f="$OUT/.cov-tgt-new-$arch-$(printf '%s' "$gt" | tr -c 'A-Za-z0-9._-' '_').names"
      pkg_names_for_target "$old" "$gt" > "$gt_old_f"
      pkg_names_for_target "$new" "$gt" > "$gt_new_f"
      gt_old_n=$(wc -l < "$gt_old_f"); gt_old_n=${gt_old_n//[[:space:]]/}
      if [ "$gt_old_n" -eq 0 ]; then
        rm -f "$gt_old_f" "$gt_new_f"
        continue
      fi
      gt_ret=$(LC_ALL=C comm -12 "$gt_old_f" "$gt_new_f" | wc -l); gt_ret=${gt_ret//[[:space:]]/}
      gt_floor=$(( (gt_old_n + 1) / 2 ))
      rm -f "$gt_old_f" "$gt_new_f"
      if [ "$gt_ret" -lt "$gt_floor" ]; then
        die "the rebuild's scan of the Go binary at '$(safe_text "$gt")' on linux/$arch retains only $gt_ret of the published image's $gt_old_n package name(s) for THAT BINARY (floor $gt_floor): the binary is still a scan target but its own contents were not retained, so its findings would cancel out of the comparison even though the type-level totals look healthy. Coverage of one binary cannot be paid for with another's."
      fi
    done <<EOF
$old_gotargets
EOF
  fi

  printf 'scan coverage OK (linux/%s): os=%s, targets=%s\n' \
    "$arch" "$(safe_text "$os_family")" "$(safe_text "$(printf '%s' "$new_types" | tr '\n' ' ')")"
}

# `caddy list-modules --versions` from inside the image. The image is
# distroless-ish with caddy as its entrypoint, so --entrypoint is required;
# without it the binary boots a server instead of answering.
#
# THIS EXECUTES THE ARTEFACT UNDER TEST, so it runs sandboxed (T-0632).
# ---------------------------------------------------------------------
# Gate 2 has to run the image to read its module set, which means every
# plugin's `init()` runs -- on a runner holding Docker Hub WRITE credentials.
# Those credentials are not reachable from inside the container (nothing is
# bind-mounted, no socket is passed, and ~/.docker/config.json lives on the
# runner filesystem), but a default `docker run` still grants outbound network
# and the default capability set. That is far more than printing a list needs.
#
#   --network none          no egress; the listing is computed in-process
#   --read-only             no writes to the container filesystem
#   --cap-drop ALL          empties the effective capability set (CapEff: 0)
#   --security-opt no-new-privileges   no privilege gain through exec
#   --user 65534            nobody, not root
#
# WHY --cap-add NET_BIND_SERVICE IS REQUIRED, AND WHY IT GRANTS NOTHING
# ---------------------------------------------------------------------
# Do not "simplify" this to a bare --cap-drop ALL: that makes the gate fail
# closed on EVERY run, on both paths. /usr/bin/caddy carries the file
# capability `cap_net_bind_service=ep` so Caddy can bind :80/:443 as non-root.
# The `e` (effective) bit means the KERNEL refuses to exec the file at all
# unless that capability is in the container's bounding set, so dropping it
# fails before any Caddy code runs:
#
#   exec /usr/bin/caddy: operation not permitted
#
# Re-adding it restores only the BOUNDING set entry the exec check needs. The
# process still runs with no effective capabilities, confirmed against the
# published image:
#
#   CapEff: 0000000000000000    CapBnd: 0000000000000400
#
# So this keeps the whole point of --cap-drop ALL while letting the binary
# start. Because the failure is an exec-time kernel refusal rather than a
# Caddy error, stderr is captured to $out and surfaced in the die message
# below; discarding it (the previous 2>/dev/null) would have reported this
# class of breakage as an unexplained "cannot list modules".
#
# LIMIT OF THIS FIX: a hostile image can still print any module list it likes,
# because the list comes from the image's own binary. Sandboxing bounds the
# blast radius of running it; it does not make gate 2's output trustworthy
# against a deliberately malicious Dockerfile.caddy. That remains code review
# of the tagged commit.
modules_from() {
  local ref="$1" arch="$2" out="$3"
  if ! docker run --rm --platform "linux/$arch" \
        --network none --read-only \
        --cap-drop ALL --cap-add NET_BIND_SERVICE \
        --security-opt no-new-privileges --user 65534 \
        --entrypoint /usr/bin/caddy \
        "$ref" list-modules --versions >"$out" 2>&1; then
    die "cannot list modules in $ref ($arch); refusing to guess the module set: $(safe_text "$(head -3 "$out" | tr '\n' ' ')")"
  fi
  # Drop blank lines and the "Standard modules"/"Non-standard" headings so the
  # diff is module lines only.
  grep -E '^[a-z0-9_.]+ v' "$out" | sort -o "$out"
  [ -s "$out" ] || die "no modules parsed from $ref ($arch)"
}

# The image's execution configuration, as a stable one-field-per-line text so
# the comparison can be a plain `diff -u` like gate 2's and the output is
# readable by whoever has to approve it.
#
# Three normalisations, each load-bearing:
#
#  - null collapses to empty. The real published image reports `User: null` and
#    `Volumes: null`, not "" and {}. Docker is inconsistent about which of the
#    two it emits for an unset field across versions and across build paths
#    (buildx vs a plain build), so comparing them raw would report drift for a
#    field that is unset on BOTH sides -- a false block on the refresh timer,
#    which is the failure mode that gets a gate switched off.
#
#  - ExposedPorts and Volumes are JSON OBJECTS whose values are empty objects;
#    only their keys carry meaning, and object key order is not guaranteed
#    stable. So take `keys` and sort. Dropping the (always-{}) values also
#    keeps the line readable.
#
#  - Env is a LIST whose order reflects the order of ENV/base-image layers
#    rather than anything semantic, so it is sorted and emitted one variable
#    per line. Per-line means a single added variable shows up in the diff as
#    one added line instead of rewriting the whole field, which is the
#    difference between a reviewable diff and a wall of JSON.
#
# Every value here is UNTRUSTED in exactly the sense documented for ids_from
# and safe_text above: on the release path the image is built from a
# Dockerfile the submitter controls, and these strings flow into $OUT/cfg-*,
# into summary.md, and from there into BOTH this script's
# `summary<<GATE_SUMMARY_EOF` heredoc and the refresh workflow's own
# `summary<<SUMMARY_EOF` heredoc. An `ENV` value is free-form and can contain
# a newline, so without sanitising, `ENV X="<newline>GATE_SUMMARY_EOF..."`
# would close the heredoc early and let the scanned image forge step outputs
# -- including verdict=improved over a blocked run. That is the hole closed in
# e1c4677 for package names; an env var is the same hole through a different
# field, so it gets the same treatment at the same single point of entry.
#
# Sanitising happens INSIDE jq, so the tab-separated field/value structure
# cannot be broken by embedding a tab either. The character class is wider
# than ids_from's because a legitimate PATH or Cmd contains spaces, commas,
# quotes and brackets; it excludes the control characters and `%` that give a
# workflow-command line its authority. Replaced rather than dropped, so a
# tampered value stays readable and visibly tampered.
config_from() {
  local ref="$1" out="$2"
  local raw
  if ! raw="$(docker image inspect --format '{{json .Config}}' "$ref" 2>/dev/null)" \
     || [ -z "$raw" ] || [ "$raw" = null ]; then
    die "cannot inspect the image configuration of $ref; refusing to guess it"
  fi
  printf '%s' "$raw" | jq -r '
    def clean: tostring | gsub("[^A-Za-z0-9._:/@+=,() \\[\\]{}\"'"'"'*?!#$^&~`|<>-]"; "?") | .[0:400];
    def nlist: if . == null then [] else . end;
    def nobj:  if . == null then {} else . end;
    [ "User\t"         + ((.User // "")       | clean),
      "WorkingDir\t"   + ((.WorkingDir // "") | clean),
      "Entrypoint\t"   + ((.Entrypoint | nlist | map(clean)) | @json),
      "Cmd\t"          + ((.Cmd        | nlist | map(clean)) | @json),
      "ExposedPorts\t" + ((.ExposedPorts | nobj | keys | sort | map(clean)) | @json),
      "Volumes\t"      + ((.Volumes      | nobj | keys | sort | map(clean)) | @json)
    ]
    + ((.Env | nlist | map(clean) | sort) | map("Env\t" + .))
    | .[]' > "$out" \
    || die "cannot parse the image configuration of $ref"
  # A non-empty result is guaranteed by construction (six fixed lines), so an
  # empty file means jq produced nothing despite exiting 0 -- treat it as a
  # failed read rather than as "no configuration", which would compare clean.
  [ -s "$out" ] || die "no image configuration parsed from $ref"
}

# The image's FILESYSTEM, as "<path> <mode> <size>" per line, for gate 4.
#
# PATH FIRST so the list sorts by path. Sorting by the leading field is what
# makes the diff readable: with mode or size leading, a single changed file
# appears as a removed line and an added line hundreds of lines apart, ordered
# by a number nobody is looking for -- measured on the real v2.68.11 ->
# v2.68.12 pair, where `1056 var/log/apk.log` sorted into the middle of the
# Mozilla certificate bundle. Path-first groups every change at the path it
# happened to, which is the question a reviewer is asking.
#
# `docker create` + `docker export` rather than `docker save`. save streams
# per-layer tars, so a path added in one layer and deleted in a later one is
# still present in the stream, and a whiteout has to be interpreted by hand --
# the diff would report files the running container does not have. export
# streams the FLATTENED filesystem, i.e. exactly what the container sees, which
# is the thing being gated. The container is created but never started, so
# nothing in the image under test executes: that matters because the release
# path builds this image from a Dockerfile the submitter controls, and a gate
# that ran the artefact it is judging would be the wrong shape entirely.
#
# Mode bits are taken from the tar header, which is where the setuid row of
# this gate's table lives. tar's numeric mode is the full st_mode permission
# word, so 04755 and 0755 differ textually and a `chmod u+s` on an existing,
# unchanged binary shows up as a changed line rather than as nothing at all.
#
# Why not Trivy. Measured 2026-11-13 against the real images, which is what
# T-0641 asked to establish before building this: `trivy image --scanners
# misconfig,secret` reports 0 misconfigurations and 0 secrets on :stable AND on
# purpose-built variants carrying an added root CA, a setuid busybox copy and a
# planted shell script. misconfig logs "Detected config files num=0" -- it
# looks for IaC/Dockerfile sources inside the image, and this image contains
# none -- and secret matches credential PATTERNS, which a certificate and a
# `curl | sh` script are not. So [[T-0642]] does not subsume this gate; the two
# cover different things and neither is a cheaper spelling of the other.
#
# Paths are sorted with LC_ALL=C so the ordering does not depend on the
# runner's locale; a locale-dependent sort would produce spurious diff hunks
# between two machines that agree about the files.
fs_from() {
  local ref="$1" arch="$2" out="$3" cid=""

  # --platform so the created container matches the arch being gated, exactly
  # as modules_from does. The refs passed in are already per-arch digests, but
  # being explicit costs nothing and keeps the two paths reading alike.
  if ! cid="$(docker create --platform "linux/$arch" "$ref" 2>/dev/null)" || [ -z "$cid" ]; then
    die "cannot create a container from $ref ($arch) to export its filesystem; refusing to guess the file list"
  fi

  # Remove the container whatever happens below, including on a `die` in the
  # pipeline: an aborted gate must not leave created containers behind on a
  # self-hosted runner or a local run.
  #
  # EXIT as well as RETURN, deliberately. `die` calls `exit`, which unwinds
  # past a RETURN trap without running it, so a RETURN-only trap would leak a
  # created container on exactly the failure paths below -- the ones most
  # likely to be hit. Both are set, and `docker rm` of an already-removed id
  # is a harmless no-op, so the double fire costs nothing.
  # shellcheck disable=SC2064
  trap "docker rm -f '$cid' >/dev/null 2>&1 || true" RETURN EXIT

  # `tar -tv` gives mode, owner, SIZE, date and path. Fields are fixed-position
  # up to the name, so awk reconstructs the path from field 6 onward to survive
  # a filename containing spaces. Directories are dropped: their presence is
  # implied by their contents and they add ~200 lines of noise to every diff.
  # Symlink and hardlink TARGETS are kept on the line, because a link repointed
  # at a different file is precisely the kind of change this gate exists to see.
  #
  # OUTPUT IS TAB-SEPARATED COLUMNS: path<TAB>mode<TAB>size<TAB>linktarget.
  # The separator is the whole point, so it is a contract rather than a format
  # choice, and every consumer below splits on tab instead of counting fields.
  #
  # It used to be space-separated with tar's ` -> target` suffix left inside
  # the path field, and both downstream helpers rebuilt "the path" as
  # all-but-the-last-two fields. That made the comparison key for a symlink
  # `path + target`, with three consequences, all measured (T-0784):
  #
  #  1. REPOINTING AN EXISTING SYMLINK READ AS ONE REMOVED PATH PLUS ONE ADDED
  #     PATH. On this image that is not a corner case: 236 of the 237 entries
  #     under `etc/ssl/certs/` are symlinks, so the trust store is almost
  #     entirely links. Assertion (c) is the one that catches the `COPY`/`ADD`
  #     row, and teaching a reviewer that add+remove pairs are ordinary churn
  #     in the one directory that matters most is how (c) stops being read.
  #     With columns, a repoint is a changed TARGET on one path: (c) sees no
  #     new path, and the raw diff shows one changed line at the path it
  #     happened to.
  #
  #  2. A path containing a literal ` -> ` could forge a benign-looking key.
  #     A tab cannot be smuggled in: it is outside the path character class
  #     below and is replaced with `?`, which is what makes splitting on it
  #     safe rather than merely tidier.
  #
  #  3. The sharper half was in `suid_of`. A path with a space before the mode
  #     (`bin/evil tool\t-rwsr-xr-x\t1234` in the old spelling, i.e. the
  #     space-separated `bin/evil tool -rwsr-xr-x 1234 -rwsr-xr-x 1234`) put a
  #     forged `-rwsr-xr-x 1234` INSIDE the rebuilt path, so the setuid
  #     comparison key was partly attacker-controlled. Columns end that: the
  #     mode is read from its own column and cannot be spelled into a filename.
  #
  # A LINK TARGET IS ITS OWN COLUMN, not a suffix, so it is compared as data
  # rather than as part of the name. Non-links get an empty fourth column.
  #
  # SIZE IS ON THE LINE, and it is load-bearing rather than informational.
  # Without it the list is (mode, path) only, so MODIFYING an existing file
  # changes nothing: the path already existed and the mode did not move.
  # Measured on a variant that appends a certificate to the existing
  # /etc/ssl/certs/ca-certificates.crt -- gate 4 produced a ZERO-LINE diff and
  # the whole gate returned verdict=unchanged, exit 0. That is the single most
  # important shape this gate exists to catch (a trusted root reaching a
  # TLS-terminating proxy) in its stealthiest form, and the first spelling of
  # this function missed it completely.
  #
  # Size is not a content hash and does not pretend to be: a same-length edit
  # still reads as unchanged. A real hash would mean extracting every file of a
  # 133 MB image twice per arch, which is a different cost class. Size catches
  # the realistic version of this attack (a certificate appended or a binary
  # swapped both change length) and costs nothing, since tar already prints it.
  # The residual same-length gap is recorded as a known limit rather than
  # papered over -- see the gate 4 block in the header.
  #
  # The date field is deliberately NOT included: it moves on every rebuild for
  # ordinary reasons and would make this gate fire on every single run.
  #
  # A path is attacker-chosen on the release path, same as every other value
  # documented above, and it lands in summary.md and both heredocs. So the
  # character class is restricted here, at the single point of entry, for the
  # same reason and in the same way as ids_from/safe_text/config_from.
  # Status is read from PIPESTATUS, not from the pipeline's own exit code.
  # `cmd | tar | awk | sort` reports only `sort`'s status, and sort succeeds
  # perfectly well on a truncated stream -- so a `docker export` that died
  # halfway, or a `tar` that gave up on a malformed archive, would produce a
  # SHORT file list and exit 0. That is the fail-open direction: a short list
  # compares as "no new paths" and the gate passes because it could not see.
  # The 100-file floor below is the backstop, but a failure should be reported
  # as a failure rather than inferred from the size of its output.
  local st
  docker export "$cid" 2>/dev/null \
     | tar -tv 2>/dev/null \
     | awk '$1 !~ /^d/ {
         mode = $1
         size = $3
         path = $6
         for (i = 7; i <= NF; i++) path = path " " $i
         # Split tar s ` -> target` suffix off into its own column. Only tar
         # produces this separator, and only for a link, so it is matched at
         # the LAST occurrence: a path may legitimately contain the string.
         target = ""
         if (match(path, /^.* -> /)) {
           target = substr(path, RLENGTH + 1)
           path   = substr(path, 1, RLENGTH - 4)
         }
         gsub(/[^A-Za-z0-9._:\/@+=,() \[\]{}"'"'"'*?!#$^&~`|<>-]/, "?", path)
         gsub(/[^A-Za-z0-9._:\/@+=,() \[\]{}"'"'"'*?!#$^&~`|<>-]/, "?", target)
         gsub(/[^A-Za-z0-9.+-]/, "?", mode)
         gsub(/[^0-9]/, "?", size)
         printf "%s\t%s\t%s\t%s\n", substr(path, 1, 300), substr(mode, 1, 16), \
                                    substr(size, 1, 20), substr(target, 1, 300)
       }' \
     | LC_ALL=C sort -u > "$out"
  st="${PIPESTATUS[*]}"
  case "$st" in
    '0 0 0 0') ;;
    *) die "cannot export the filesystem of $ref ($arch) (export|tar|awk|sort exited: $st); refusing to guess the file list" ;;
  esac

  # A real image has thousands of files, so a short list means the export or
  # the tar read degraded rather than that the image is small. An empty or
  # near-empty file list would compare as "no new paths" and pass this gate
  # silently -- the same fail-open shape assert_scan_coverage exists to close
  # for gate 1, so it gets the same treatment here.
  local n
  n="$(wc -l < "$out")"
  if [ "$n" -lt 100 ]; then
    die "the export of $ref ($arch) yielded only $n file(s): that is a degraded read, not a small image, and an empty file list would compare as 'no new paths'. Refusing to gate on it."
  fi
}

for arch in $ARCHES; do
  echo "::group::gate: linux/$arch"

  # Make sure the right architecture of each side is in the local daemon.
  #
  # A baseline that cannot be obtained is a HARD STOP, not an empty set. An
  # empty baseline would make every finding look new (noisy but safe) or, read
  # the other way, "nothing to compare" (silent and dangerous). Neither is a
  # verdict, so fail instead.
  #
  # A pull failure is only fatal when the image is not already local at the
  # right arch: in CI the rebuild is a locally-loaded tag that does not exist
  # in any registry, and in a local dry-run the baseline may be too.
  #
  # A MUTABLE TAG CANNOT NAME AN ARCHITECTURE. One tag is one entry in the
  # local image store, so after the amd64 pass `:stable` is resolved to amd64
  # there, and whether a later `docker pull --platform linux/arm64` of the
  # same tag replaces that entry is daemon- and store-dependent: it does on a
  # plain overlay2 host, and does NOT on the GitHub runner, where the arm64
  # pass then died with "cannot obtain baseline ... (local arch: amd64)".
  # So for a registry image, resolve the tag through its manifest list to the
  # DIGEST for the arch being gated and use that digest as the reference.
  # A digest names exactly one artifact, cannot be shadowed by the other
  # arch's copy of the same tag, and does not depend on pull-replaces-tag
  # semantics. Returns the reference to actually use, on stdout.
  resolve_ref() {
    local ref="$1" want="$2" role="$3" have digest repo

    # Already local at the right arch (the locally-built rebuild, or a
    # dry-run baseline that was loaded by hand): use it as given. Checked
    # first so a locally-loaded tag never needs a registry at all.
    have="$(docker image inspect --format '{{.Architecture}}' "$ref" 2>/dev/null || true)"
    if [ "$have" = "$want" ] && ! printf '%s' "$ref" | grep -q '@sha256:'; then
      printf '%s\n' "$ref"
      return 0
    fi

    # A DIGEST IS NOT NECESSARILY ONE ARTIFACT. A multi-arch push reports the
    # INDEX digest, and an index names one child manifest per arch, so pulling
    # it yields the host's native arch exactly like a tag does. Treating
    # `@sha256:` as inherently unambiguous is what made the first real publish
    # abort: the amd64 pass gated `improved`, then the arm64 pass pulled the
    # same index digest, got amd64, and died with "cannot obtain rebuild image
    # ... (got: amd64)" — after the -pN tag had already been pushed.
    # So resolve through the manifest list for BOTH forms below, and only fall
    # back to pulling the reference as given when it has no manifest list
    # (a true single-arch image digest, or an unreachable registry).
    #
    # Reduce the reference to its repository before appending the child digest.
    # Strip a trailing @digest first, then a trailing :tag — and only when that
    # colon is in the LAST path segment, because `%%:*` would otherwise eat a
    # registry port ("registry:5000/ns/img" -> "registry").
    repo="${ref%%@*}"
    case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
    digest="$(docker manifest inspect "$ref" 2>/dev/null | jq -r --arg a "$want" '
      if .manifests then
        [ .manifests[]
          | select(.platform.architecture == $a and .platform.os == "linux")
          | .digest ] | first // empty
      else empty end' || true)"

    if [ -n "$digest" ]; then
      docker pull --quiet "$repo@$digest" >/dev/null 2>&1 || true
      have="$(docker image inspect --format '{{.Architecture}}' "$repo@$digest" 2>/dev/null || true)"
      [ "$have" = "$want" ] \
        || die "cannot obtain $role image $repo@$digest for linux/$want (got: ${have:-absent}); refusing to compare against an unknown image"
      printf '%s\n' "$repo@$digest"
      return 0
    fi

    # No manifest list (single-arch image, or the registry is unreachable).
    # Fall back to the platform pull, then VERIFY the arch, so a
    # single-arch repo still gates and a wrong arch is still a hard stop.
    docker pull --quiet --platform "linux/$want" "$ref" >/dev/null 2>&1 || true
    have="$(docker image inspect --format '{{.Architecture}}' "$ref" 2>/dev/null || true)"
    [ "$have" = "$want" ] \
      || die "cannot obtain $role image $ref for linux/$want (local arch: ${have:-absent}); refusing to compare against an unknown image"
    printf '%s\n' "$ref"
  }

  base_ref="$(resolve_ref "$BASELINE"  "$arch" baseline)"
  new_ref="$(resolve_ref "$NEW_IMAGE" "$arch" rebuild)"

  trivy image --skip-db-update --scanners vuln --severity "$SEVERITY" \
    --format json --output "$OUT/new-$arch.json" "$new_ref"
  trivy image --skip-db-update --scanners vuln --severity "$SEVERITY" \
    --format json --output "$OUT/old-$arch.json" "$base_ref"

  # Before ANY comparison: prove the new scan actually looked at the image.
  # Gate 1 cannot tell an image with no vulnerabilities from an image Trivy
  # could not read, so that distinction has to be made here, against the
  # baseline, while both scans are in hand. Hard-stops at exit 2 on failure.
  assert_scan_coverage "$OUT/new-$arch.json" "$OUT/old-$arch.json" "$arch"

  ids_from "$OUT/new-$arch.json" | sort > "$OUT/new-$arch.ids"
  ids_from "$OUT/old-$arch.json" | sort > "$OUT/old-$arch.ids"
  comm -23 "$OUT/new-$arch.ids" "$OUT/old-$arch.ids" > "$OUT/added-$arch.ids"
  comm -13 "$OUT/new-$arch.ids" "$OUT/old-$arch.ids" > "$OUT/removed-$arch.ids"

  modules_from "$new_ref"  "$arch" "$OUT/mods-new-$arch.txt"
  modules_from "$base_ref" "$arch" "$OUT/mods-old-$arch.txt"
  diff -u "$OUT/mods-old-$arch.txt" "$OUT/mods-new-$arch.txt" \
    > "$OUT/mods-diff-$arch.txt" || true

  # Gate 3: the execution configuration. Read from the SAME resolved refs the
  # other two gates used -- the per-arch digest, not the mutable tag -- so this
  # cannot end up describing the other arch's copy of :stable. No extra pull
  # and no extra scan: both images are already local by this point.
  config_from "$new_ref"  "$OUT/cfg-new-$arch.txt"
  config_from "$base_ref" "$OUT/cfg-old-$arch.txt"
  diff -u "$OUT/cfg-old-$arch.txt" "$OUT/cfg-new-$arch.txt" \
    > "$OUT/cfg-diff-$arch.txt" || true

  # The ONE class of config change that blocks under BOTH policies: a variable
  # that redirects where the Caddy binary looks for its TLS trust roots.
  #
  # Extracted SEPARATELY from the diff above, and asserted on, for exactly the
  # reason gate 4 extracts its trust-store rows rather than leaning on the raw
  # diff: under `report` the diff is only PRINTED, and a reader approving a
  # release that legitimately moved EXPOSE has no reason to treat one more
  # added Env line as different in kind. It is different in kind. Pointed at an
  # attacker-controlled path, SSL_CERT_FILE redirects every outbound TLS
  # connection this binary makes -- ACME issuance and the DNS provider's API --
  # and does it with NO filesystem delta, because the file it names can be one
  # the image already legitimately contains. Gates 1, 2 and 4 are all blind to
  # it: same packages, same modules, no CVE moved, no file added.
  #
  # Read from the two cfg-*.txt files rather than from a fresh inspect, so this
  # sees exactly the values gate 3 compared -- already sanitized and already
  # one-variable-per-line by config_from. Note what that view COSTS, and why
  # the match below is on names only: `clean` truncates each entry to 400
  # characters, so the value is not reliable evidence here.
  #
  # MATCHED ON THE VARIABLE NAME ALONE, never on the value.
  #
  # The name is the only part of the line truncation cannot reach, and that is
  # load-bearing rather than tidy. A pattern needing a substring of the VALUE
  # to survive the cut is fail-open by construction. The first spelling of this
  # check used `GODEBUG=.*x509`, and a code review broke it end-to-end: GODEBUG
  # is a comma-separated list whose entries reorder freely, so
  #
  #   GODEBUG=<29x "http2client=0,">x509usefallbackroots=1
  #
  # cuts at char 400 with the `x509` gone. Measured on this host: trustenv
  # lines 0, trustenv_total 0, summary printing "TLS trust env: none" and the
  # quiet line claiming the trust environment was unchanged -- over an image
  # whose container gets the variable in full, because `clean` only truncates
  # the GATE'S VIEW. That is T-0786 reproduced against the fix for T-0786.
  #
  # So GODEBUG blocks WHOLE and the x509 narrowing is gone. The cost is
  # accepted deliberately: a release setting an ordinary GODEBUG (http2client,
  # madvdontneed) now blocks and needs a reviewed decision. That is the right
  # trade, because the alternative is a filter an attacker chooses whether to
  # satisfy. GODEBUG is absent from the published image, so it costs nothing
  # today, and a legitimate future one is accommodated the same way every other
  # value is -- it lands on both sides and cancels (see the comm note below) --
  # not by narrowing the match again.
  #
  # Anchored after the `Env\t` prefix and terminated by `=`, so a variable
  # merely CONTAINING one of these names (`MY_SSL_CERT_FILE_NOTE`) does not
  # match, and so a value mentioning one cannot satisfy it either. An empty
  # value still matches, which is correct: `SSL_CERT_DIR=` is not harmless, it
  # drops the default search path.
  #
  # AWS_CA_BUNDLE is here because Dockerfile.caddy links
  # caddy-dns/route53@v1.6.2, and the AWS SDK for Go reads that variable to
  # override the CA bundle for ITS OWN HTTP client, on top of Go's defaults.
  # Go's crypto/x509 loadSystemRoots() consults only SSL_CERT_FILE and
  # SSL_CERT_DIR (root_unix.go), so the SDK's knob is a genuinely separate
  # trust path, not a duplicate of them -- and the credential it protects is
  # the Route53 DNS-01 API key that issues this fleet's certificates, i.e.
  # exactly the asset this whole check exists for. Found by security review;
  # the first spelling missed it.
  #
  # The remaining four are prophylactic, for a future `--with`: CURL_CA_BUNDLE,
  # REQUESTS_CA_BUNDLE, GIT_SSL_CAINFO and NODE_EXTRA_CA_CERTS are the
  # conventional CA-bundle overrides of the other runtimes a plugin could pull
  # in. None can false-positive: the published image's entire environment is
  # PATH, CADDY_VERSION, XDG_CONFIG_HOME and XDG_DATA_HOME.
  #
  # ONE grep producing ONE globally sorted stream, deliberately, not several
  # appended. `comm` below requires its inputs sorted as a WHOLE, and
  # separately-sorted groups are not: `Env\tAWS_CA_BUNDLE=` sorts before
  # `Env\tSSL_CERT_FILE=`, so emitting groups in pattern order would hand comm
  # an out-of-order file and it would silently miss lines rather than fail.
  #
  # `|| true` on the grep because no match is the NORMAL case here -- none of
  # these is present in the published image -- and grep exits 1 for it. Under
  # `set -e` an unguarded non-match would abort the gate on every healthy run.
  # Note this also swallows grep's exit 2 for a BAD PATTERN, which would be
  # fail-open; that is why the pattern is a literal here and not caller-
  # overridable, unlike FS_ALLOW_RE, which needed an explicit validation step
  # for exactly that reason.
  #
  # A LITERAL TAB, via $'...', NOT the two characters \t. POSIX ERE has no \t
  # escape and GNU grep -E does not add one: in a `grep -E '^Env\t…'` pattern
  # the backslash is dropped and it matches the literal letter `t`, i.e.
  # `Envt…`, which matches NOTHING against config_from's `Env<TAB>NAME=VALUE`
  # lines. That failure is SILENT and fail-open -- the extract comes out empty,
  # comm reports nothing, and the gate prints "TLS trust env: none" over an
  # image that just added SSL_CERT_FILE. Verified on this host before fixing.
  # If this pattern is ever rewritten, keep the tab literal; do not "tidy" it
  # into \t.
  #
  # LC_ALL=C on BOTH the sort here and the comm below, for the reason T-0785
  # established for gate 4: comm only WARNS about disorder, so an input sorted
  # under one collation and validated under another is a correctness problem it
  # reports rather than enforces. Pinning both ends keeps them in agreement
  # whatever locale the runner has.
  trust_env_of() {
    { grep -E $'^Env\t(SSL_CERT_FILE|SSL_CERT_DIR|AWS_CA_BUNDLE|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|GIT_SSL_CAINFO|NODE_EXTRA_CA_CERTS|GODEBUG)=' "$1" || true; } \
      | LC_ALL=C sort -u
  }
  trust_env_of "$OUT/cfg-new-$arch.txt" > "$OUT/cfg-trustenv-new-$arch.txt" || true
  trust_env_of "$OUT/cfg-old-$arch.txt" > "$OUT/cfg-trustenv-old-$arch.txt" || true

  # COMPARED on the whole line (name and value), even though the MATCH above is
  # on the name alone. The two are deliberately different: matching on the name
  # is what makes the check un-evadable by truncation, while diffing the whole
  # line is what catches a MODIFIED value as well as a newly-added variable.
  # `comm -23` reports any line present on the new side and not on the
  # baseline's.
  #
  # This is also what makes the check survive its own premise changing. Nothing
  # in the CODE depends on these variables being absent: the day one is
  # legitimately introduced and published, it sits on both sides, cancels, and
  # only a CHANGE to it blocks thereafter. Do not re-narrow the pattern to
  # accommodate such a value; let the diff do it.
  #
  # A truncated value is compared truncated on BOTH sides, since both come
  # through the same `clean`. So truncation can no longer hide a variable (the
  # name is matched), and it cannot make an unchanged one look changed either
  # -- only a change within the first 400 characters is visible, which is a
  # reporting limit of gate 3 as a whole rather than of this check.
  LC_ALL=C comm -23 "$OUT/cfg-trustenv-new-$arch.txt" "$OUT/cfg-trustenv-old-$arch.txt" \
    > "$OUT/cfg-trustenv-$arch.txt" || true

  if [ -s "$OUT/cfg-trustenv-$arch.txt" ]; then
    echo "::warning::trust-redirecting environment variable introduced or changed (linux/$arch): $(wc -l < "$OUT/cfg-trustenv-$arch.txt" | tr -d ' ') line(s) -- blocking under both drift policies"
  fi

  # Gate 4: the filesystem delta. Off by default -- it costs a full image
  # export per side per arch, which is why T-0641 scoped it to the weekly
  # refresh rather than to every release. Same resolved per-arch refs as the
  # other three gates.
  if [ "$FS_DELTA" = on ]; then
    fs_from "$new_ref"  "$arch" "$OUT/fs-new-$arch.txt"
    fs_from "$base_ref" "$arch" "$OUT/fs-old-$arch.txt"
    diff -u "$OUT/fs-old-$arch.txt" "$OUT/fs-new-$arch.txt" \
      > "$OUT/fs-diff-$arch.txt" || true

    # The three assertions T-0641 names, computed from the two file lists.
    #
    # Kept SEPARATE from the raw diff on purpose. The raw diff of a base-layer
    # refresh is legitimately long -- an `apk upgrade` rewrites every file of
    # every upgraded package -- so a reviewer handed only that diff reads a few
    # hundred lines of ordinary churn and learns nothing. These three extracts
    # are the rows that cannot be ordinary, and they are what the gate asserts
    # on; the full diff is kept as the reviewable record behind them.

    # a) New or changed files under the trust stores. This is the row that
    #    matters most for this image: six public-facing edge proxies that
    #    terminate TLS and call a DNS provider's API for DNS-01, so a root CA
    #    added here buys silent MITM of both. Any added OR modified line under
    #    either store counts -- a REPLACED ca-certificates.crt is the same
    #    attack as an added one, and only the added side of the diff would miss
    #    it being swapped rather than appended.
    #    NOTE THE ABSENT LEADING SLASH. `tar -tv` emits archive member names
    #    relative to the archive root -- `etc/ssl/certs/foo`, not
    #    `/etc/ssl/certs/foo`. An anchored `/etc/ssl/certs/` pattern therefore
    #    matches NOTHING, which is a silently empty assertion rather than a
    #    failure: measured on the added-CA variant, this row reported 0 while
    #    the certificate was plainly in the diff, and only the new-path check
    #    (c) caught it. A REPLACED ca-certificates.crt is not a new path, so
    #    with that spelling it would have passed the whole gate. The optional
    #    leading slash keeps the intent if the list is ever produced some
    #    other way.
    #
    #    The diff line is `+<path> <mode> <size>`, so the path follows the `+`
    #    directly. Anchored there rather than matched loosely, so a path that
    #    merely CONTAINS one of these strings further along cannot satisfy it.
    #
    #    THE PATH SET IS THE WHOLE ASSERTION, AND IT WAS WRONG ONCE. On this
    #    image `/etc/ssl/certs/*.pem` are SYMLINKS; the certificate bytes live
    #    in `/usr/share/ca-certificates/mozilla/` (237 entries, measured on
    #    :stable). An earlier spelling covered only etc/ssl/certs,
    #    usr/local/share/ca-certificates and etc/ca-certificates, so
    #    overwriting a Mozilla root in place -- the real trust anchor, reached
    #    through both `/etc/ssl/certs/ca-cert-<name>.pem` and the `<hash>.0`
    #    links -- changed no watched path, added no path, and the gate returned
    #    exit 0 / verdict=unchanged while the summary stated the filesystem was
    #    unchanged. Found by security review with a working end-to-end fixture.
    #    That is worse than having no gate, because the summary affirms a
    #    property that does not hold.
    #
    #    So: enumerate every location that can supply a trust anchor to this
    #    image, not the ones a cert is conventionally INSTALLED to.
    #      usr/share/ca-certificates/        where the bytes actually are
    #      etc/ssl/certs/                    the symlink farm + the bundle
    #      etc/ssl/cert.pem                  symlink, in Go's x509 fallback list
    #      etc/ssl/ca-bundle.pem, etc/ssl1.1/, etc/pki/   other distro spellings
    #      usr/local/share/ca-certificates/  the admin drop-in dir
    #      etc/ca-certificates.conf, etc/ca-certificates/  which certs are TRUSTED
    #    The last pair is policy rather than material: editing the .conf alone
    #    changes what the bundle is rebuilt from.
    #
    #    THE THREE WHOLE-FILE ENTRIES ARE TERMINATED WITH A TAB, the directory
    #    prefixes are not. Since fs_from emits `path<TAB>mode<TAB>size<TAB>target`
    #    (T-0784), the tab is the end of the path, so `etc/ssl/cert\.pem\t`
    #    cannot also be satisfied by `etc/ssl/cert.pem.attacker-suffix`. Under
    #    the old space-separated format these three were unterminated, which is
    #    the same unbounded-bare-name shape that was a real bypass in
    #    FS_ALLOW_DEFAULT above -- harmless in an allowlist's mirror image
    #    (it over-matches INTO the assertion, i.e. toward blocking) but wrong,
    #    and worth fixing while the format is changing anyway.
    #    The tab is spelled as a LITERAL via $'...' so this stays `grep -E`.
    #    `\t` is a PCRE escape, not a POSIX ERE one: `grep -E '\t'` matches a
    #    literal `t` on a GNU grep, so the pattern would have silently matched
    #    nothing after the path -- a quietly empty assertion, which is the one
    #    failure shape this gate is most carefully hardened against.
    grep -E '^\+' "$OUT/fs-diff-$arch.txt" | grep -v '^+++' \
      | grep -E $'^\\+/?(usr/share/ca-certificates/|usr/local/share/ca-certificates/|etc/ssl/certs/|etc/ssl/cert\\.pem\t|etc/ssl/ca-bundle\\.pem\t|etc/ssl1\\.1/|etc/pki/|etc/ca-certificates\\.conf\t|etc/ca-certificates/)' \
      > "$OUT/fs-ca-$arch.txt" || true

    # b) Any setuid/setgid bit on the new side that the baseline does not have
    #    at the same path. tar renders these as `s` or `S` in the user/group
    #    execute position, so the MODE field is matched rather than the path.
    #
    #    The size field is stripped before comparing. A setuid binary that is
    #    legitimately rebuilt changes length, and keeping size on the line
    #    would make that read as "a new setuid entry" every time -- the
    #    always-on signal that gets a check ignored. Mode+path is the question
    #    being asked here; the size change is still in the raw diff.
    #
    #    PATH AND MODE ARE READ AS TAB COLUMNS ($1 and $2), not reconstructed
    #    by counting fields from the end. The field-counting spelling put a
    #    forged mode inside the rebuilt path on any filename containing a
    #    space -- see the contract note on fs_from (T-0784). A tab cannot
    #    appear in either column, so the split is unambiguous.
    #
    #    MATCHES BOTH MODE RENDERINGS. GNU tar prints symbolic modes
    #    (-rwsr-xr-x) and that is what ubuntu-latest gives us, but a `[sS]`
    #    test against a tar that prints the NUMERIC permission word (04755)
    #    matches nothing -- and an assertion that matches nothing reports zero
    #    setuid entries, i.e. it reads as clean rather than as broken. That is
    #    the silent-empty-assertion shape this script is hardened against
    #    elsewhere, so the numeric form is matched too: a leading 2, 4 or 6 in
    #    the four/five-digit word is setgid/setuid/both.
    suid_of() {
      awk -F'\t' '{
        path = $1
        mode = $2
        if (mode !~ /[sS]/ && mode !~ /^0?[2467][0-7][0-7][0-7]$/) next
        printf "%s\t%s\n", path, mode
      }' "$1" | LC_ALL=C sort -u
    }
    suid_of "$OUT/fs-new-$arch.txt" > "$OUT/fs-suid-new-$arch.txt" || true
    suid_of "$OUT/fs-old-$arch.txt" > "$OUT/fs-suid-old-$arch.txt" || true
    # LC_ALL=C ON THE COMM, NOT JUST THE SORT. The inputs above are built with
    # `LC_ALL=C sort`, but `comm` inherits the runner's locale, and it requires
    # input sorted in ITS OWN collation. C and en_US.UTF-8 order real paths from
    # this image differently (punctuation-leading names such as `.dockerenv`
    # move), and on mis-ordered input comm SILENTLY DROPS entries rather than
    # failing -- so a genuinely new setuid entry can vanish from the difference.
    # Not hypothetical: runs of this gate emitted "comm: file 1 is not in sorted
    # order" / "comm: input is not in sorted order" to stderr, where the `|| true`
    # meant nothing acted on it. Pinning both sides to C makes the sort that
    # produces the file and the comm that reads it agree by construction.
    LC_ALL=C comm -23 "$OUT/fs-suid-new-$arch.txt" "$OUT/fs-suid-old-$arch.txt" \
      > "$OUT/fs-suid-$arch.txt" || true

    # c) New paths outside the allowlist. Compared on PATH only, so a file the
    #    baseline already has whose contents changed is not reported here --
    #    that is base-layer churn, and it is caught by the size field in the
    #    raw diff and by assertion (a) when it is a trust-store file.
    #    A genuinely NEW path is the `COPY`/`ADD`/`curl | sh` row.
    #
    #    The path is the FIRST TAB COLUMN. It is taken as a column rather than
    #    rebuilt from all-but-the-last-two fields, because the latter folded a
    #    symlink's target into the key: repointing one of the 236 symlinks
    #    under etc/ssl/certs/ then read as one removed path plus one added
    #    path, which trains a reviewer to skim exactly this assertion. A
    #    repoint is now a target-column change on an unchanged path, so it is
    #    correctly absent here and visible in the raw diff (T-0784).
    paths_of() {
      awk -F'\t' '{ print $1 }' "$1" | LC_ALL=C sort -u
    }
    paths_of "$OUT/fs-new-$arch.txt" > "$OUT/fs-paths-new-$arch.txt"
    paths_of "$OUT/fs-old-$arch.txt" > "$OUT/fs-paths-old-$arch.txt"
    # Same collation pinning as (b) above, for the same reason.
    LC_ALL=C comm -23 "$OUT/fs-paths-new-$arch.txt" "$OUT/fs-paths-old-$arch.txt" \
      | grep -Ev "$FS_ALLOW_RE" > "$OUT/fs-newpaths-$arch.txt" || true

    echo "filesystem delta (linux/$arch): $(wc -l < "$OUT/fs-newpaths-$arch.txt" | tr -d ' ') new path(s) outside the allowlist, $(wc -l < "$OUT/fs-suid-$arch.txt" | tr -d ' ') new setuid/setgid entr(ies), $(wc -l < "$OUT/fs-ca-$arch.txt" | tr -d ' ') trust-store change(s)"
  fi

  echo "::endgroup::"
done

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
added_total=0
removed_total=0
moddrift=0
cfgdrift=0
trustenv_total=0
fsdrift=0
fs_newpaths_total=0
fs_suid_total=0
fs_ca_total=0
for arch in $ARCHES; do
  added_total=$(( added_total + $(wc -l < "$OUT/added-$arch.ids") ))
  removed_total=$(( removed_total + $(wc -l < "$OUT/removed-$arch.ids") ))
  [ -s "$OUT/mods-diff-$arch.txt" ] && moddrift=1
  [ -s "$OUT/cfg-diff-$arch.txt" ] && cfgdrift=1
  trustenv_total=$(( trustenv_total + $(wc -l < "$OUT/cfg-trustenv-$arch.txt") ))
  # Gate 4 keys on the three ASSERTIONS, not on the raw diff being non-empty.
  # A base-layer refresh legitimately rewrites hundreds of files, so a raw-diff
  # trigger would fire on every single run and the gate would be switched off
  # inside a month -- the same reasoning the package-count floor uses for being
  # deliberately loose.
  if [ "$FS_DELTA" = on ]; then
    fs_newpaths_total=$(( fs_newpaths_total + $(wc -l < "$OUT/fs-newpaths-$arch.txt") ))
    fs_suid_total=$((     fs_suid_total     + $(wc -l < "$OUT/fs-suid-$arch.txt") ))
    fs_ca_total=$((       fs_ca_total       + $(wc -l < "$OUT/fs-ca-$arch.txt") ))
  fi
done
if [ "$FS_DELTA" = on ] \
   && { [ "$fs_newpaths_total" -gt 0 ] || [ "$fs_suid_total" -gt 0 ] || [ "$fs_ca_total" -gt 0 ]; }; then
  fsdrift=1
fi

# Gates 2 and 3 contribute to the verdict only under the block policy. Under
# report the drift is still measured, still diffed and still printed below — it
# just does not decide the verdict, because on the release path a deliberate
# change is the intended result rather than a fault.
drift_blocks=0
if [ "$moddrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
  drift_blocks=1
fi
cfg_blocks=0
if [ "$cfgdrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
  cfg_blocks=1
fi

# The trust-redirecting subset of gate 3 blocks under BOTH policies, so it is
# NOT gated on $DRIFT_POLICY. This is the only assertion in the script that
# ignores the caller's strictness dial, and it does so deliberately: `report`
# exists to let a release change configuration, not to let it change who the
# binary trusts. See the trust_env_of block above and gate 3's header.
#
# Kept as its own variable rather than folded into cfg_blocks so the verdict
# reason stays legible in the summary below -- a reader needs to know that the
# block came from this specific class and not from config drift generally,
# because the remedy is completely different.
trustenv_blocks=0
if [ "$trustenv_total" -gt 0 ]; then
  trustenv_blocks=1
fi
fs_blocks=0
if [ "$fsdrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
  fs_blocks=1
fi

if [ "$added_total" -gt 0 ] || [ "$drift_blocks" -eq 1 ] || [ "$cfg_blocks" -eq 1 ] \
   || [ "$trustenv_blocks" -eq 1 ] || [ "$fs_blocks" -eq 1 ]; then
  verdict=blocked
elif [ "$removed_total" -gt 0 ]; then
  verdict=improved
else
  verdict=unchanged
fi

{
  # The heading names the path, because this script now guards two of them and
  # a summary headed "refresh" on a release run would be actively misleading.
  if [ "$DRIFT_POLICY" = block ]; then
    echo "### Caddy image refresh — \`$verdict\`"
  else
    echo "### Caddy image release gate — \`$verdict\`"
  fi
  echo
  echo "\`$NEW_IMAGE\` vs published \`$BASELINE\`"
  echo
  printf '| | %s |\n' "$(echo "$ARCHES" | tr ' ' '|')"
  printf '|---|%s\n' "$(for _ in $ARCHES; do printf -- '---|'; done)"
  for label in old new removed added; do
    case "$label" in
      old)     name='findings, published' ;;
      new)     name='findings, rebuilt' ;;
      removed) name='closed by the rebuild' ;;
      added)   name='**newly introduced**' ;;
    esac
    row="| $name |"
    for arch in $ARCHES; do
      row+=" $(wc -l < "$OUT/$label-$arch.ids" | tr -d ' ') |"
    done
    echo "$row"
  done
  row='| module-set drift |'
  for arch in $ARCHES; do
    if [ -s "$OUT/mods-diff-$arch.txt" ]; then
      # Say which policy is in force on the row itself: "yes" alone reads as a
      # failure, and on the release path it is not one.
      if [ "$DRIFT_POLICY" = block ]; then row+=' **yes** |'; else row+=' yes (expected) |'; fi
    else
      row+=' none |'
    fi
  done
  echo "$row"
  row='| image-config drift |'
  for arch in $ARCHES; do
    if [ -s "$OUT/cfg-diff-$arch.txt" ]; then
      # Unlike module drift, a config change is NOT the expected outcome of an
      # ordinary release either -- most releases change the module set and
      # leave User/Entrypoint/Env alone. So it is flagged for review under
      # report rather than labelled "expected".
      if [ "$DRIFT_POLICY" = block ]; then row+=' **yes** |'; else row+=' yes (review) |'; fi
    else
      row+=' none |'
    fi
  done
  echo "$row"
  # The trust-redirecting subset gets its OWN row rather than being folded into
  # the config row above, because it carries a different verdict rule: that row
  # reads "yes (review)" under `report`, and this one never does. A reader
  # scanning the table must not have to know that one of the lines inside a
  # "review" diff was in fact blocking.
  row='| TLS trust env |'
  for arch in $ARCHES; do
    if [ -s "$OUT/cfg-trustenv-$arch.txt" ]; then
      row+=' **yes (blocking)** |'
    else
      row+=' none |'
    fi
  done
  echo "$row"
  # Only emit the filesystem row when the gate actually ran. A row reading
  # "none" for a check that was never performed is worse than no row: it is an
  # assurance the gate did not earn, and this summary is the artifact a
  # reviewer approves from.
  if [ "$FS_DELTA" = on ]; then
    row='| filesystem delta |'
    for arch in $ARCHES; do
      if [ -s "$OUT/fs-newpaths-$arch.txt" ] || [ -s "$OUT/fs-suid-$arch.txt" ] \
         || [ -s "$OUT/fs-ca-$arch.txt" ]; then
        if [ "$DRIFT_POLICY" = block ]; then row+=' **yes** |'; else row+=' yes (review) |'; fi
      else
        row+=' none |'
      fi
    done
    echo "$row"
  else
    echo "| filesystem delta | $(for _ in $ARCHES; do printf 'not checked |'; done)"
  fi
  echo

  if [ "$added_total" -gt 0 ]; then
    echo "**Gate 1 FAILED — the rebuild introduces findings the published image does not have:**"
    echo
    echo '```'
    for arch in $ARCHES; do
      while IFS=$'\t' read -r id pkg; do
        [ -n "${id:-}" ] || continue
        printf '%s  %s  %s\n' "$arch" "$id" "$pkg"
      done < "$OUT/added-$arch.ids"
    done
    echo '```'
    echo
    if [ "$DRIFT_POLICY" = block ]; then
      echo "A refresh must only ever remove findings. Investigate before publishing."
    else
      echo "A release may change the module set, but it must not introduce a vulnerability the published image does not already have. The immutable \`:vX.Y.Z\` tag exists; \`:stable\` and \`:latest\` were NOT moved. Investigate before moving them."
    fi
    echo
  fi

  if [ "$moddrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
    echo "**Gate 2 FAILED — the Caddy module set changed.** A refresh may change the OS layer and nothing else."
    echo
    echo "Every \`--with\` in Dockerfile.caddy is pinned, so a module-set change here means the build did not reproduce the pinned set — a re-resolved DNS provider, caddy-l4 or Coraza, or a pin edit that never went through a release. That is a Caddy change, not a base-layer refresh, and it must go through a normal release (edit \`Dockerfile.caddy\`, cut a tag) so it is reviewed and versioned rather than arriving on \`:stable\` via a timer."
    echo
  elif [ "$moddrift" -eq 1 ]; then
    echo "**Module set changed — reported, not blocked.** This is the release path, where editing \`Dockerfile.caddy\` is how a plugin bump is *supposed* to arrive, so the diff below is the expected result rather than a fault."
    echo
    echo "Read it anyway: it is the authoritative record of what this release actually did to the module set, taken from \`caddy list-modules --versions\` inside the pushed image rather than from the Dockerfile diff. Modules can move **without** a \`--with\` edit (a transitive dependency of a bumped plugin), and a \`--with\` edit can fail to move anything. Anything here you did not intend to change is a finding."
    echo
  fi

  if [ "$moddrift" -eq 1 ]; then
    for arch in $ARCHES; do
      if [ -s "$OUT/mods-diff-$arch.txt" ]; then
        echo "<details><summary>Module diff, linux/$arch (published → rebuilt)</summary>"
        echo
        echo '```diff'
        cat "$OUT/mods-diff-$arch.txt"
        echo '```'
        echo
        echo "</details>"
        echo
      fi
    done
  fi

  # Printed BEFORE the general config section, and unconditionally on both
  # policies, because it is the one config finding whose verdict does not
  # depend on the path. Under `report` the section below it opens with "this is
  # allowed to ship", and a reader who met that sentence first would carry the
  # wrong frame into this one.
  if [ "$trustenv_blocks" -eq 1 ]; then
    echo "**Gate 3 FAILED — the image introduces or changes a variable that redirects TLS trust.** This blocks under BOTH drift policies, including on the release path."
    echo
    echo "\`SSL_CERT_FILE\` and \`SSL_CERT_DIR\` decide where this binary looks for its trust roots; \`AWS_CA_BUNDLE\` does the same for the AWS SDK linked by \`caddy-dns/route53\`, which holds the DNS-01 credential that issues this fleet's certificates; and \`GODEBUG\` can change how the root pool is built at all. Pointed at a path an attacker controls, they redirect **every outbound TLS connection this image makes** — ACME issuance and the DNS provider's API — with **no filesystem delta at all**, because the file named can be one the image already legitimately contains. Gate 1 sees no new CVE, gate 2 sees no module change, and gate 4 sees no added file, so nothing else here reports it."
    echo
    echo "That is the same silent-interception outcome the trust-store rows of gate 4 exist to prevent, reached through configuration instead of through files — so it is asserted on the same way, rather than merely printed. A release is allowed to change \`EXPOSE\`, \`WORKDIR\` or an ordinary \`ENV\`; it is not allowed to change who the binary trusts."
    echo
    # DERIVED, not asserted. The code deliberately outlives the claim that
    # these variables are absent: `comm -23` compares whole lines, so a
    # legitimately-introduced and published variable lands on both sides,
    # cancels, and only a CHANGE to it blocks thereafter. A hardcoded "none of
    # these is present" would keep printing after that day and tell the
    # approver a modification was an addition -- in the one artifact they
    # approve the release from. So ask the baseline extract instead.
    baseline_had_any=no
    for arch in $ARCHES; do
      [ -s "$OUT/cfg-trustenv-old-$arch.txt" ] && baseline_had_any=yes
    done
    if [ "$baseline_had_any" = no ]; then
      echo "**None of these variables is present in the published image**, so there is no legitimate existing value being compared against: any line below is new. If this was deliberate, it needs a reviewed decision of its own and a change to this gate — not a tag move."
    else
      echo "The published image already carries at least one of these variables, so a line below is either a NEW variable or a CHANGE to an existing one — check which against the baseline extract in the artifacts. Either way it needs a reviewed decision of its own, not a tag move."
    fi
    echo
    for arch in $ARCHES; do
      if [ -s "$OUT/cfg-trustenv-$arch.txt" ]; then
        echo "Introduced or changed, linux/$arch:"
        echo
        echo '```'
        cat "$OUT/cfg-trustenv-$arch.txt"
        echo '```'
        echo
      fi
    done
  fi

  if [ "$cfgdrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
    echo "**Gate 3 FAILED — the image's execution configuration changed.** A refresh may change the OS layer and nothing else."
    echo
    echo "This compares \`User\`, \`Entrypoint\`, \`Cmd\`, \`Env\`, \`ExposedPorts\`, \`Volumes\` and \`WorkingDir\` from \`docker image inspect\`. A refresh rebuilds an **unchanged** \`Dockerfile.caddy\` from a release tag, so every one of these must come out identical — a difference here cannot be a side effect of a base-layer bump, it means the build produced a different image than the released one describes. Six public-facing edge proxies pull this image and hold DNS-provider TLS credentials, so a change to who it runs as or what it executes first is not a cosmetic diff."
    echo
  elif [ "$cfgdrift" -eq 1 ]; then
    echo "**Image configuration changed — reported, not blocked.** This is the release path, where a deliberate \`EXPOSE\`, \`WORKDIR\` or \`ENV\` edit is allowed to ship."
    echo
    echo "Read this one closely even so. Gates 1 and 2 cover the image's *contents* — its packages and its linked Go modules — and neither sees how those contents are **executed**. \`USER root\`, an \`ENTRYPOINT\` repointed at a wrapper that runs something before exec'ing caddy, or an added \`HTTP_PROXY\` passes both of them untouched: same packages, same modules, no CVE moved. If you did not intend a line below, do not move \`:stable\`."
    echo
    echo "The trust-redirecting variables (\`SSL_CERT_FILE\`, \`SSL_CERT_DIR\`, \`AWS_CA_BUNDLE\`, \`CURL_CA_BUNDLE\`, \`REQUESTS_CA_BUNDLE\`, \`GIT_SSL_CAINFO\`, \`NODE_EXTRA_CA_CERTS\`, \`GODEBUG\`) are the exception to this section: they are **blocking** on this path too, and are reported separately above rather than left in this diff for a reader to notice."
    echo
  fi

  if [ "$cfgdrift" -eq 1 ]; then
    for arch in $ARCHES; do
      if [ -s "$OUT/cfg-diff-$arch.txt" ]; then
        echo "<details><summary>Image config diff, linux/$arch (published → rebuilt)</summary>"
        echo
        echo '```diff'
        cat "$OUT/cfg-diff-$arch.txt"
        echo '```'
        echo
        echo "</details>"
        echo
      fi
    done
  fi

  if [ "$fsdrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
    echo "**Gate 4 FAILED — the image's filesystem gained files the published image does not have.** A refresh may change the OS layer and nothing else."
    echo
    echo "Gates 1-3 read the image's packages, its linked Go modules and its execution configuration. None of them sees a file that is simply **added** and carries no CVE: an extra script or binary, a root CA dropped into the trust store, or a setuid bit. This gate diffs the flattened filesystem (\`docker export\`) of both sides and asserts on the three shapes that cannot be ordinary base-layer churn."
    echo
  elif [ "$fsdrift" -eq 1 ]; then
    echo "**Filesystem changed — reported, not blocked.** This is the release path, where adding a file can be a deliberate part of a release."
    echo
    echo "Read the rows below regardless. A new root CA under \`/etc/ssl/certs\` is the one that matters most for this image: these are TLS-terminating edge proxies that call a DNS provider's API for DNS-01, so a CA added here buys silent interception of both ACME issuance and that API traffic — with no CVE, no module change and no config change to show for it."
    echo
  fi

  if [ "$fsdrift" -eq 1 ]; then
    for arch in $ARCHES; do
      # fs_from emits tab-separated columns (T-0784), so these two extracts
      # carry tabs. Rendered through `column -t` with an explicit header, since
      # a raw tab inside a code fence lands wherever the next tab stop happens
      # to be and the whole point of the column format is that a reviewer can
      # see WHICH field moved. `column` is from util-linux and is present on
      # ubuntu-latest; if it is ever missing, `|| cat` keeps the rows rather
      # than emitting an empty block over a non-empty assertion.
      if [ -s "$OUT/fs-ca-$arch.txt" ]; then
        echo "**Trust store changed, linux/$arch** — an added or replaced CA here is trusted by every outbound TLS connection this proxy makes:"
        echo
        echo '```'
        { printf '%s\t%s\t%s\t%s\n' 'PATH' 'MODE' 'SIZE' 'LINK-TARGET'
          cat "$OUT/fs-ca-$arch.txt"
        } | column -t -s $'\t' 2>/dev/null || cat "$OUT/fs-ca-$arch.txt"
        echo '```'
        echo
      fi
      if [ -s "$OUT/fs-suid-$arch.txt" ]; then
        echo "**New setuid/setgid entries, linux/$arch** — present in the rebuild, absent from the published image at the same path and mode:"
        echo
        echo '```'
        { printf '%s\t%s\n' 'PATH' 'MODE'
          cat "$OUT/fs-suid-$arch.txt"
        } | column -t -s $'\t' 2>/dev/null || cat "$OUT/fs-suid-$arch.txt"
        echo '```'
        echo
      fi
      if [ -s "$OUT/fs-newpaths-$arch.txt" ]; then
        echo "<details><summary>New paths outside the allowlist, linux/$arch ($(wc -l < "$OUT/fs-newpaths-$arch.txt" | tr -d ' '))</summary>"
        echo
        echo '```'
        cat "$OUT/fs-newpaths-$arch.txt"
        echo '```'
        echo
        echo "</details>"
        echo
      fi
      if [ -s "$OUT/fs-diff-$arch.txt" ]; then
        echo "<details><summary>Full filesystem diff, linux/$arch (published → rebuilt) — includes ordinary <code>apk upgrade</code> churn</summary>"
        echo
        echo '```diff'
        cat "$OUT/fs-diff-$arch.txt"
        echo '```'
        echo
        echo "</details>"
        echo
      fi
    done
  fi

  if [ "$verdict" != blocked ]; then
    # Say which of the two drift gates were quiet, rather than asserting both.
    # The old wording claimed "the module set is unchanged" whenever gate 2 was
    # quiet, which under `report` would now be printed over an unmentioned
    # config change -- a reassurance the gate had not actually earned.
    # Name every gate that was quiet, and never claim a gate was quiet when it
    # did not run. The reassurance is assembled from the gates that actually
    # reported, for the reason the old two-gate wording was fixed in 29de334:
    # a blanket "nothing changed" printed over an unmentioned change is a
    # reassurance the gate has not earned, and under `report` this summary is
    # the whole basis for approving the release.
    quiet=""
    [ "$moddrift" -eq 0 ] && quiet="$quiet the module set,"
    # Named separately from "the image configuration" because it is checked
    # separately: under `report` the config diff can be non-empty (so not
    # listed as quiet) while this assertion still passed, and that IS a
    # reassurance worth stating -- the release changed config but did not touch
    # TLS trust. Only claimed when the assertion actually came out empty.
    #
    # Not mirrored on the `noisy` side below: this block only runs when the
    # verdict is NOT blocked, and a non-empty trust-env extract forces
    # `blocked` under both policies, so trustenv_total is necessarily 0 here.
    # A `noisy` entry for it would be unreachable rather than merely redundant.
    [ "$trustenv_total" -eq 0 ] && quiet="$quiet the TLS trust environment,"
    [ "$cfgdrift" -eq 0 ] && quiet="$quiet the image configuration,"
    [ "$FS_DELTA" = on ] && [ "$fsdrift" -eq 0 ] && quiet="$quiet the filesystem,"
    noisy=""
    [ "$moddrift" -eq 1 ] && noisy="$noisy the module set,"
    [ "$cfgdrift" -eq 1 ] && noisy="$noisy the image configuration,"
    [ "$FS_DELTA" = on ] && [ "$fsdrift" -eq 1 ] && noisy="$noisy the filesystem,"
    quiet="${quiet# }"; quiet="${quiet%,}"
    noisy="${noisy# }"; noisy="${noisy%,}"

    printf '%s' "No new findings: every vulnerability in the rebuilt image is already present in the published image, against the same package."
    [ -n "$quiet" ] && printf ' Unchanged: %s.' "$quiet"
    [ -n "$noisy" ] && printf ' **Changed and diffed above, needs reading: %s.**' "$noisy"
    if [ "$FS_DELTA" != on ]; then
      printf '%s' " The filesystem was **not checked** (\`FS_DELTA=off\`), so this verdict says nothing about files added to the image."
    fi
    printf '\n'
    echo

    # What "no new findings" is NOT evidence of.
    #
    # Printed only on a non-blocked verdict, because that is the one a reader
    # over-reads. A blocked summary already tells them to look; a green one is
    # where "the gate passed" quietly becomes "there are no known advisories",
    # and those are different statements.
    #
    # Two independent limits, both measured in this repo rather than supposed:
    #
    #  - Trivy's vulnerability data is OSV-derived, and gate 1 is set
    #    arithmetic over it. An advisory OSV has not ingested is in NEITHER
    #    findings list, so it cannot appear in the added set and cannot block.
    #    Measured during T-0624: five go-jose/v4 advisories published
    #    2026-10-30, affecting every version through 4.1.6, were absent from
    #    OSV thirteen days later (`/v1/vulns/GHSA-v6h2-qj3f-2h6v` -> code 5,
    #    not found) and absent from Trivy's scan of the image that contained
    #    them. All five lack a CVE id, which is the likely reason. The repo
    #    nearly shipped a release calling that image clean.
    #
    #  - The gate is a DIFFERENCE, by design (see gate 1's rationale: a
    #    zero-findings rule could never publish, because GO-2026-5932 sits on
    #    every image). So a finding present on both sides cancels out and is
    #    reported under "closed by this rebuild"/counts, never as a reason to
    #    stop. `unchanged` means "no worse than what the fleet already runs",
    #    which is the question this gate asks and the only one it answers.
    #
    # The pin watcher is named because it is the check that DOES ask the other
    # question, against GitHub's repo-scoped advisory index (T-0634) — so the
    # reader is pointed at a real second source rather than merely warned.
    #
    # But it is named for what it ACTUALLY covers: the `--with` plugin pins,
    # not CaddyUI's own `go.mod`. Measured 2026-11-12 (T-0654): `go.mod` is
    # watched by Dependabot's gomod ecosystem, which keys on GitHub's GLOBAL
    # advisory database -- and that index omits CVE-less advisories just as
    # OSV does. The same five go-jose records are absent from it, and no
    # Dependabot alert was ever raised for them, while all 19 alerts this repo
    # HAS received carry a CVE id. So pointing a reader at the pin watcher for
    # a go.mod question would be sending them to a check that does not look
    # there. Both scopes are stated rather than one implied.
    echo "<details><summary>What this verdict is not evidence of</summary>"
    echo
    echo "**It is not a statement that the image has no known advisories.** Two limits, both deliberate:"
    echo
    echo "- **Trivy's vulnerability data is OSV-derived, and this gate is set arithmetic over it.** An advisory OSV has not ingested is missing from *both* findings lists, so it cannot be \"added\" and cannot block. That is not hypothetical here: five \`go-jose/v4\` advisories published 2026-10-30, affecting every version through 4.1.6, were still absent from OSV thirteen days later and absent from Trivy's scan of the image containing them. None of the five has a CVE id, and a CVE-less advisory is reliably visible only on GitHub's **per-repository** endpoint."
    echo "  - For the \`--with\` plugin pins, the weekly pin watcher (\`check-pinned-modules.sh\`) asks that endpoint — read it, not this gate, for \"are there known advisories\"."
    echo "  - For CaddyUI's own \`go.mod\`, **nothing currently asks it.** Dependabot covers \`go.mod\` but keys on GitHub's *global* advisory index, which omits CVE-less records the same way OSV does. See \`SECURITY.md\` → \"How \`go.mod\` is watched for advisories\"."
    echo "- **This gate is a difference, not an audit.** A finding present on both images cancels out by construction, because a zero-findings standard could never publish anything. \`$verdict\` means *no worse than the image the fleet already runs* — which is the question it asks, and the only one it answers."
    echo
    echo "</details>"
    echo
  fi

  if [ "$removed_total" -gt 0 ]; then
    echo "<details><summary>Closed by this rebuild</summary>"
    echo
    echo '```'
    for arch in $ARCHES; do
      while IFS=$'\t' read -r id pkg; do
        [ -n "${id:-}" ] || continue
        printf '%s  %s  %s\n' "$arch" "$id" "$pkg"
      done < "$OUT/removed-$arch.ids"
    done
    echo '```'
    echo
    echo "</details>"
    echo
  fi
} > "$OUT/summary.md"

cat "$OUT/summary.md"
echo "$verdict" > "$OUT/verdict"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  # Belt and braces: refuse rather than emit if the delimiter is ever present
  # in the body. `ids_from` already restricts what can get there, and the
  # delimiter is random per run, so reaching this means an assumption broke --
  # and a corrupt $GITHUB_OUTPUT is worse than a failed step.
  if grep -qxF "$SUMMARY_DELIM" "$OUT/summary.md"; then
    die "the gate summary contains the generated output delimiter: refusing to append a heredoc that cannot be closed unambiguously."
  fi
  {
    echo "verdict=$verdict"
    echo "added_count=$added_total"
    echo "removed_count=$removed_total"
    echo "module_drift=$moddrift"
    echo "config_drift=$cfgdrift"
    # A COUNT, not a 0/1 flag, and reported separately from config_drift: a
    # caller must be able to tell "config changed but trust did not" from
    # "trust was redirected", because only the second one is blocking under
    # `report`. Folding it into config_drift would lose exactly the
    # distinction this check exists to draw.
    echo "trust_env_changes=$trustenv_total"
    echo "fs_delta=$FS_DELTA"
    echo "fs_drift=$fsdrift"
    echo "fs_new_paths=$fs_newpaths_total"
    echo "fs_new_suid=$fs_suid_total"
    echo "fs_ca_changes=$fs_ca_total"
    echo "module_drift_policy=$DRIFT_POLICY"
    echo "summary<<$SUMMARY_DELIM"
    cat "$OUT/summary.md"
    echo "$SUMMARY_DELIM"
  } >> "$GITHUB_OUTPUT"
fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi

# The trailing `exit 0` is REQUIRED, not redundant. `[ ... ] && exit 1` returns
# 1 when the test is false, so if this were the last command of the script a
# non-blocked verdict would exit 1 under `set -e` -- wrongly blocking every
# good image. Do not "tidy away" the explicit exit below.
[ "$verdict" = blocked ] && exit 1
exit 0
