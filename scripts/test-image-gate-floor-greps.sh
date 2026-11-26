#!/usr/bin/env bash
# Regression suite for Dockerfile.caddy's BUILD-TIME security-floor greps (T-0840).
#
# WHY THIS FILE EXISTS. T-0840 added two floors -- otel/sdk/log@v1.47.0 and
# x/crypto/chacha20@v0.59.0 -- each enforced by a hand-rolled `grep -qE` against
# `go version -m` output inside the builder stage. Those greps are the only
# thing standing between a future pin edit and an image that ships the
# advisory-bearing version anyway, and they shipped with NO on-disk suite: the
# commit's "15/15 regex cases pass" was measured in a scratch directory and
# committed nothing, so nothing in the repo could re-run it and ci.yml's
# "every suite on disk is actually run" cross-check could not see a file that
# did not exist. A regression test nobody can run is a regression test that
# does not exist (T-0816 defect #4) -- hence this file.
#
# THE PATTERNS ARE EXTRACTED FROM THE LIVE DOCKERFILE, NEVER COPIED HERE.
# A copy drifts from the shipped logic silently and would then certify a
# pattern the build does not use. Same principle as test-floor-versions.sh
# case 25, which extracts the Dockerfile's own `case` statement.
#
# Run: ./scripts/test-image-gate-floor-greps.sh   (no docker, no network)
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DF="$REPO/Dockerfile.caddy"
pass=0
fail=0

check() { # $1=label $2=expected $3=actual
  if [ "$2" = "$3" ]; then
    pass=$((pass + 1)); printf 'PASS  %s\n' "$1"
  else
    fail=$((fail + 1)); printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"
  fi
}

# Pull each floor's regex out of the real file by the module path it names, so
# a renamed variable or a reordered block cannot silently yield an empty
# pattern. An empty pattern would match everything, which is the one outcome
# this suite must never certify, so presence is asserted before use.
pattern_for() { # $1=module path as spelled in the grep
  sed -n "s/.*grep -qE '\\(\\^\\[\\[:space:\\]\\]\\*dep.*$1[^']*\\)'.*/\\1/p" "$DF" | head -1
}
otel_re="$(grep -oE "\\^\\[\\[:space:\\]\\]\\*dep\\[\\[:space:\\]\\]\\+go\\\\\\.opentelemetry[^']*" "$DF" | head -1)"
xcrypto_re="$(grep -oE "\\^\\[\\[:space:\\]\\]\\*dep\\[\\[:space:\\]\\]\\+golang\\\\\\.org/x/crypto\\[\\[:space:\\]\\]\\+v0[^']*" "$DF" | head -1)"

echo "=== 0. both floor patterns were extracted from the live Dockerfile ==="
# Asserted FIRST and by content, not just by non-emptiness: an extraction that
# silently returned a truncated or wrong pattern would make every case below
# pass against something the build never runs.
check "otel pattern extracted"    "yes" "$( [ -n "$otel_re" ] && echo yes || echo no )"
check "x/crypto pattern extracted" "yes" "$( [ -n "$xcrypto_re" ] && echo yes || echo no )"
check "otel pattern names its module" "yes" \
  "$(printf '%s' "$otel_re" | grep -q 'otel/sdk/log' && echo yes || echo no)"
check "x/crypto pattern names its module" "yes" \
  "$(printf '%s' "$xcrypto_re" | grep -q 'x/crypto' && echo yes || echo no)"
# The floors the patterns are FOR are also still in the file as --with pins. A
# pattern guarding a pin nobody passes is a check with no subject.
check "otel floor pin still present" "1" \
  "$(grep -c -- '--with go\.opentelemetry\.io/otel/sdk/log@v1\.47\.0' "$DF")"
check "x/crypto floor pin still present" "1" \
  "$(grep -c -- '--with golang\.org/x/crypto/chacha20@v0\.59\.0' "$DF")"

# Builds one `go version -m` dep line in the real tab-delimited shape and
# reports whether the extracted pattern accepts it.
verdict() { # $1=regex $2=module $3=version -> accepted|rejected
  if printf '\tdep\t%s\t%s\th1:x=\n' "$2" "$3" | grep -qE "$1"; then
    echo accepted
  else
    echo rejected
  fi
}

echo
echo "=== 1. otel/sdk/log: at, above and below the v1.47.0 floor ==="
M=go.opentelemetry.io/otel/sdk/log
while IFS='|' read -r ver want; do
  [ -n "$ver" ] || continue
  check "otel $ver" "$want" "$(verdict "$otel_re" "$M" "$ver")"
done <<'CASES'
v1.47.0|accepted
v1.47.1|accepted
v1.48.0|accepted
v1.59.9|accepted
v2.0.0|accepted
v1.46.0|rejected
v1.46.9|rejected
v0.22.0|rejected
v1.4.0|rejected
v1.7.0|rejected
CASES

echo
echo "=== 2. x/crypto: at, above and below the v0.59.0 floor ==="
MC=golang.org/x/crypto
while IFS='|' read -r ver want; do
  [ -n "$ver" ] || continue
  check "x/crypto $ver" "$want" "$(verdict "$xcrypto_re" "$MC" "$ver")"
done <<'CASES'
v0.59.0|accepted
v0.59.1|accepted
v0.60.0|accepted
v0.99.9|accepted
v0.58.0|rejected
v0.5.0|rejected
v0.9.0|rejected
CASES

echo
echo "=== 3. A PRERELEASE OR PSEUDO-VERSION IS BELOW ITS RELEASE, SO IT MUST BE REJECTED ==="
# The defect independent review found: both patterns matched as an UNANCHORED
# SUBSTRING, so `v1.47.0-rc.1` and `v1.47.0-0.<ts>-<sha>` -- which sort BELOW
# v1.47.0 in semver and in Go module order -- satisfied the floor while the
# binary still carried the advisory. Reachable, not theoretical: this
# Dockerfile already pins `certificates@v0.30.3-0.20261105213751-6d5a251fbe01`
# via --replace, and T-0816's analysis names --replace as the only mechanism
# that can pull a module BELOW what MVS would choose. Fixed by requiring no
# `-` before the field boundary; pinned here so it cannot come back.
while IFS='|' read -r ver want; do
  [ -n "$ver" ] || continue
  check "otel $ver" "$want" "$(verdict "$otel_re" "$M" "$ver")"
done <<'CASES'
v1.47.0-rc.1|rejected
v1.47.0-rc1|rejected
v1.47.0-0.20260101000000-abcdef123456|rejected
v1.48.0-beta.2|rejected
v2.0.0-alpha|rejected
CASES
while IFS='|' read -r ver want; do
  [ -n "$ver" ] || continue
  check "x/crypto $ver" "$want" "$(verdict "$xcrypto_re" "$MC" "$ver")"
done <<'CASES'
v0.59.0-rc.1|rejected
v0.59.0-0.20251101000000-abcdef123456|rejected
v0.60.0-beta.1|rejected
CASES

echo
echo "=== 4. the pattern must not match a DIFFERENT module at a passing version ==="
# Each grep is anchored on its own module path. A sibling or prefix-sharing
# module sitting at an acceptable-looking version must not satisfy the floor
# for the module that is actually being guarded -- otherwise the presence of
# any otel package would certify sdk/log.
check "otel pattern vs otel/sdk (not sdk/log)" "rejected" \
  "$(verdict "$otel_re" "go.opentelemetry.io/otel/sdk" "v1.47.0")"
check "otel pattern vs otel/trace" "rejected" \
  "$(verdict "$otel_re" "go.opentelemetry.io/otel/trace" "v1.47.0")"
check "otel pattern vs sdk/logtest decoy" "rejected" \
  "$(verdict "$otel_re" "go.opentelemetry.io/otel/sdk/logtest" "v1.47.0")"
check "x/crypto pattern vs x/net" "rejected" \
  "$(verdict "$xcrypto_re" "golang.org/x/net" "v0.62.0")"
check "x/crypto pattern vs x/cryptobyte decoy" "rejected" \
  "$(verdict "$xcrypto_re" "golang.org/x/cryptobyte" "v0.59.0")"

echo
echo "=== 5. the line SHAPE matters: only a 'dep' row at the start of a line counts ==="
# `go version -m` emits `mod`, `dep` and `=>` rows. A floor satisfied by a
# `=>` replace row or by the module appearing inside some other text would be
# reading the wrong thing. Also guards against the module name turning up in
# build settings (`build\t-ldflags=...`), which is free-form.
check "a '=>' replace row does not satisfy the floor" "rejected" \
  "$(printf '\t=>\t%s\tv1.47.0\th1:x=\n' "$M" | grep -qE "$otel_re" && echo accepted || echo rejected)"
check "a 'mod' row does not satisfy the floor" "rejected" \
  "$(printf '\tmod\t%s\tv1.47.0\th1:x=\n' "$M" | grep -qE "$otel_re" && echo accepted || echo rejected)"
check "the name inside a build setting does not satisfy it" "rejected" \
  "$(printf '\tbuild\t-ldflags="-X %s=v1.47.0"\n' "$M" | grep -qE "$otel_re" && echo accepted || echo rejected)"

echo
echo "=== 6. NEGATIVE CONTROL: the patterns can actually fail ==="
# A pattern that accepted everything would satisfy every 'accepted' case above
# while certifying nothing, so each one is shown rejecting a real input, and
# an empty module list -- the shape a broken `go version -m` produces -- is
# shown rejecting too rather than passing vacuously.
check "otel pattern rejects an empty module list" "rejected" \
  "$(printf '' | grep -qE "$otel_re" && echo accepted || echo rejected)"
check "x/crypto pattern rejects an empty module list" "rejected" \
  "$(printf '' | grep -qE "$xcrypto_re" && echo accepted || echo rejected)"
check "otel pattern rejects a missing module" "rejected" \
  "$(printf '\tdep\tgithub.com/other/thing\tv9.9.9\th1:x=\n' | grep -qE "$otel_re" && echo accepted || echo rejected)"

echo
echo "=== 7. KNOWN LIMIT, asserted so it is a decision and not a surprise ==="
# The numeric alternations top out at two digits, so a future v1.100.0 (otel)
# or v0.100.0 (x/crypto) is a FALSE FAIL: the build breaks loudly rather than
# shipping something unverified. That is the safe direction, and it is pinned
# here so whoever hits it finds this case instead of a mystery build failure.
# When upstream rolls over, widen the alternation AND move these two rows.
check "otel v1.100.0 currently false-fails (safe direction)" "rejected" \
  "$(verdict "$otel_re" "$M" "v1.100.0")"
check "x/crypto v0.100.0 currently false-fails (safe direction)" "rejected" \
  "$(verdict "$xcrypto_re" "$MC" "v0.100.0")"

echo
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
