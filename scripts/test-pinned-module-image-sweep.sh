#!/usr/bin/env bash
# Tests for check-pinned-modules.sh's IMAGE sweep — the base image and the
# built binary's module graph (T-0669, from T-0660 item 4).
#
#   ./scripts/test-pinned-module-image-sweep.sh      # exit 0 = all pass
#
# A sibling of test-pinned-module-floors.sh and test-pinned-module-crosscheck.sh.
#
# WHY THIS SUITE EXISTS AT ALL. For its whole life the watcher took its input
# from `--with` arguments and nothing else, so the base image — the core of
# this image — was swept by nothing, and at the 2.11.7 the image shipped that
# meant five live advisories behind a report that said every pin was current.
# The acceptance condition the card asks for is a DISPROOF, and it is case 1:
# `caddyserver/caddy` at 2.11.7 must report exactly the five advisories whose
# range covers it, while an OSV package+version query at the same version
# returns zero.
#
# ---------------------------------------------------------------------------
# Two things this suite is deliberately built around
# ---------------------------------------------------------------------------
#
# 1. THE RANGE PREDICATE IS EXTRACTED FROM THE SHIPPED SCRIPT, NOT COPIED.
#    A copied predicate passes forever after the original changes, which makes
#    the suite worse than nothing — it reports green about code it is no longer
#    testing. Same discipline as the cross-check suite.
#
# 2. THE ADVISORY FIXTURE IS A REAL CAPTURED RESPONSE, and the expected counts
#    are derived from it by an independent route (jq over the fixture) rather
#    than written as literals. A hand-written "5" would still pass if the
#    filter silently dropped the right number of wrong rows.
#
# The live end-to-end path is rate-limited (GitHub allows 60 unauthenticated
# calls an hour and this image's graph is 236 modules), so the cases that need
# a full run are driven offline from the fixture. Case 9 exercises the real
# network path when a token is available and SKIPS rather than failing when it
# is not — a test that cannot run must not read as a test that passed.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check-pinned-modules.sh"
FIXTURES="$(cd "$(dirname "$0")" && pwd)/fixtures"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0; skip=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS  %s\n' "$1"; pass=$((pass+1))
  else
    printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1))
  fi
}
skipped() { printf 'SKIP  %s\n        %s\n' "$1" "$2"; skip=$((skip+1)); }

# Extract the predicate under test from the shipped script. `awk` on the
# function's own braces, so a rename or a signature change breaks the suite
# loudly instead of testing a stale copy.
# BOTH exclusions are extracted, and both are applied in the helpers below.
# The sweep drops a row when EITHER fires, so a suite that modelled only the
# range filter would report counts the sweep never produces -- which is how
# this suite first reported 10 where the sweep renders 5.
# Matched on the literal opening line and the closing brace at column 0, with
# no dynamic regex: building one from the function name needs three levels of
# escaping through awk -v and silently matched nothing, which the `-z` guard
# below caught only because it is there. A literal index comparison cannot
# drift that way.
extract_fn() { # $1 = function name
  awk -v want="$1() {" '
    index($0, want) == 1 { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }' "$SCRIPT"
}
for fn in range_excludes_version patch_already_in_version; do
  fn_src="$(extract_fn "$fn")"
  if [ -z "$fn_src" ]; then
    echo "FATAL: could not extract $fn() from $SCRIPT" >&2
    exit 1
  fi
  eval "$fn_src"
done

CADDY_FIXTURE="$FIXTURES/caddyserver-caddy-advisories.json"
if [ ! -f "$CADDY_FIXTURE" ]; then
  echo "FATAL: missing fixture $CADDY_FIXTURE" >&2
  exit 1
fi

# Apply the shipped predicate to every vulnerability entry in the fixture and
# count the DISTINCT advisories that survive for a given version — the same
# shape the sweep renders, including its one-row-per-GHSA de-duplication.
# Apply BOTH shipped exclusions to every vulnerability entry in the fixture
# and report the DISTINCT advisories that survive for a given version -- the
# same shape the sweep renders, including its one-row-per-GHSA collapse.
live_ids() { # $1 = version
  local ver="$1" ghsa range patched
  while IFS=$'\t' read -r ghsa range patched; do
    [ -n "$ghsa" ] || continue
    range_excludes_version "$range" "$ver" && continue
    patch_already_in_version "$patched" "$ver" && continue
    printf '%s\n' "$ghsa"
  done < <(jq -r '.[] | . as $a | (.vulnerabilities // [])[]
                  | [($a.ghsa_id // ""), (.vulnerable_version_range // ""),
                     (.patched_versions // "")] | @tsv' \
             "$CADDY_FIXTURE") | sort -u
}
live_count() { # $1 = version
  live_ids "$1" | wc -l | tr -d ' '
}

echo "=== the acceptance condition (T-0669 item 4) ==="

# Case 1. THE CARD'S FIXTURE. At 2.11.7 exactly five advisories apply, and all
# five are CVE-less — which is why OSV cannot see them (case 2).
check "1  caddy@2.11.7 reports exactly 5 live advisories" \
  "5" "$(live_count 2.11.7)"

check "1b the five are the expected GHSA ids" \
  "GHSA-25cw-38mq-q7m6 GHSA-69hv-5jfc-mvmv GHSA-f278-mgc7-46j3 GHSA-jf74-f69g-hcj9 GHSA-r766-rf9f-588h" \
  "$(live_ids 2.11.7 | paste -sd' ' -)"

cveless_live="$(for g in $(live_ids 2.11.7); do
  jq -r --arg g "$g" '.[] | select(.ghsa_id == $g) | (.cve_id // "NO-CVE")' "$CADDY_FIXTURE"
done | sort -u | paste -sd',' -)"
check "1c every one of the five is CVE-less, which is why OSV is blind to them" \
  "NO-CVE" "$cveless_live"

# Case 2. THE DISPROOF. OSV returns zero at the same version. This is a live
# call because the claim is about OSV today, not about a recorded answer; it
# skips if OSV is unreachable rather than passing.
osv_n="$(curl -fsS --max-time 20 -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"github.com/caddyserver/caddy/v2","ecosystem":"Go"},"version":"2.11.7"}' \
  2>/dev/null | jq -r '(.vulns // []) | length' 2>/dev/null || echo unreachable)"
if [ "$osv_n" = "unreachable" ]; then
  skipped "2  OSV returns 0 at the same version (the disproof)" "OSV unreachable"
else
  check "2  OSV package+version at 2.11.7 returns 0 (the disproof)" "0" "$osv_n"
fi

echo
echo "=== the count-inflation guard (item 3) ==="

# Case 3. Eight advisories are CVE-less, but three are bounded below 2.11.7 and
# must not be counted. Reporting 8 where 5 apply is as wrong as reporting 0.
check "3  the fixture really does carry 8 CVE-less advisories" \
  "8" "$(jq -r '[ .[] | select(.cve_id == null) ] | length' "$CADDY_FIXTURE")"
check "3b of those 8, only 5 apply at 2.11.7 — the other 3 are already fixed" \
  "5" "$(live_ids 2.11.7 | wc -l | tr -d ' ')"

# Case 4. The three that must be excluded, named individually, so a future
# change that re-inflates the count says which row came back.
for g in GHSA-6365-7ppr-5r92 GHSA-wwhq-w58m-w29c GHSA-gx7w-56w6-g48x; do
  check "4  $g (bounded below 2.11.7) is excluded" \
    "no" "$(live_ids 2.11.7 | grep -qx "$g" && echo yes || echo no)"
done

echo
echo "=== the fix is visible: 2.11.8 and 2.11.9 clear all five ==="

# Case 5. The whole point of the base bump. ZERO is the correct answer at
# 2.11.8 and 2.11.9, and getting it requires the two-sided-range handling:
# before that fix this returned NINE at 2.11.9, which is the count-inflation
# failure produced by the count-inflation guard itself.
check "5  caddy@2.11.8 has 0 live advisories" "0" "$(live_count 2.11.8)"
check "5b caddy@2.11.9 has 0 live advisories" "0" "$(live_count 2.11.9)"
check "5c caddy@2.11.4 is NOT clean (the predicate is not just returning 0)" \
  "yes" "$([ "$(live_count 2.11.4)" -gt 0 ] && echo yes || echo no)"

# Case 6. A positive control on the direction of the comparison. If the
# predicate inverted, 2.11.0 would be clean and 2.11.9 would not.
check "6  older versions carry MORE advisories, not fewer" \
  "yes" "$([ "$(live_count 2.11.0)" -gt "$(live_count 2.11.7)" ] && echo yes || echo no)"

echo
echo "=== the base image is parsed out of the Dockerfile ==="

# Case 7. Both FROM lines are read, and a mismatch between them is an error
# rather than a coin toss over which one the parser saw first.
mk_df() { # $1=dest $2=builder-ver $3=runtime-ver
  { printf 'FROM --platform=$BUILDPLATFORM caddy:%s-builder AS builder\n' "$2"
    echo 'RUN xcaddy build \'
    echo '    --with github.com/caddy-dns/route53@v1.6.2'
    printf 'FROM caddy:%s-alpine\n' "$3"
  } > "$1"
}

mk_df "$WORK/df-ok" 2.11.9 2.11.9
check "7  both FROM lines parse to the same version" \
  "2.11.9 2.11.9" \
  "$(sed -n 's/^FROM .*[[:space:]]caddy:\([0-9][^[:space:]]*\)-builder[[:space:]].*$/\1/p' "$WORK/df-ok" | head -1) $(sed -n 's/^FROM[[:space:]]\+caddy:\([0-9][^[:space:]]*\)-alpine[[:space:]]*$/\1/p' "$WORK/df-ok" | head -1)"

mk_df "$WORK/df-split" 2.11.9 2.11.7
# NOT run with `--offline-fixture`: `--offline-fixture /dev/null` dies on the
# script's own `[ -f ]` precondition BEFORE the base parser runs, so the case
# passed vacuously against a run that never reached the code under test. It
# was the `-z` guard shape in reverse -- a test that cannot reach its subject
# reporting on it anyway. `PINWATCH_SKIP_GITHUB=1` is enough to keep it off
# the network.
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-split" \
  --out-dir "$WORK/o-split" 2>&1 || true)"
check "7b a builder/runtime base MISMATCH is reported, not silently halved" \
  "yes" "$(printf '%s' "$out" | grep -q 'different Caddy versions' && echo yes || echo no)"
check "7c a base mismatch reaches the error verdict" \
  "yes" "$(printf '%s' "$out" | grep -q 'verdict=error' && echo yes || echo no)"

# Case 8. A Dockerfile with NO parseable base must be an error. The core of the
# image going unswept is the exact gap this card closed, so a parser that can
# no longer find it must not fall through quietly.
{ echo 'FROM scratch'
  echo 'RUN xcaddy build \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
} > "$WORK/df-nobase"
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-nobase" \
  --out-dir "$WORK/o-nobase" 2>&1 || true)"
check "8  an unparseable base image is an ERROR, not a silent skip" \
  "yes" "$(printf '%s' "$out" | grep -q 'core of this image and was NOT swept' && echo yes || echo no)"
check "8b an unparseable base image reaches the error verdict" \
  "yes" "$(printf '%s' "$out" | grep -q 'verdict=error' && echo yes || echo no)"

echo
echo "=== an unswept component never reads as a clean one ==="

# Case 9. The property that matters most, and the one a naive implementation
# gets wrong: with the sweep disabled, the report must say so and must NOT
# print the all-clear sentence. Verified against the real exhausted-rate-limit
# run that prompted this case: 0 calls succeeded, and the report said
# "Base image: NOT swept" / "166 components NOT swept" rather than reporting
# zero findings.
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-ok" \
  --out-dir "$WORK/o-skip" 2>&1 || true)"
check "9  a disabled sweep says the base image was NOT swept" \
  "yes" "$(printf '%s' "$out" | grep -q 'NOT swept' && echo yes || echo no)"
check "9b a disabled sweep never prints the all-clear sentence" \
  "no" "$(printf '%s' "$out" | grep -q 'The image itself was swept too' && echo yes || echo no)"
check "9c a disabled sweep is named as disabled, not merely absent" \
  "yes" "$(printf '%s' "$out" | grep -q 'PINWATCH_SKIP_GITHUB' && echo yes || echo no)"

# Case 10. No `--binary` is a NARROWER run, not a broken one: it must say the
# graph was not run, and must still sweep the base image.
check "10 no --binary reports the graph as not run" \
  "yes" "$(printf '%s' "$out" | grep -q 'not run' && echo yes || echo no)"

# Case 11. A `--binary` that is not a Go binary must be an error, not an empty
# graph. An empty graph would read as "swept, nothing found".
echo 'not a go binary' > "$WORK/notabinary"
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-ok" \
  --binary "$WORK/notabinary" --out-dir "$WORK/o-bad" 2>&1 || true)"
check "11 a non-Go --binary is an error, not an empty graph" \
  "yes" "$(printf '%s' "$out" | grep -q 'read no module graph' && echo yes || echo no)"

# Case 12. A missing --binary path likewise.
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-ok" \
  --binary "$WORK/does-not-exist" --out-dir "$WORK/o-missing" 2>&1 || true)"
check "12 a nonexistent --binary is an error" \
  "yes" "$(printf '%s' "$out" | grep -q 'does not exist' && echo yes || echo no)"

echo
echo "=== the advisory's own stated fix (patched_versions) ==="

# The second, independent exclusion. It exists because the range filter is
# conservative by design, and on a repo whose ranges are mostly free text that
# conservatism left five CVE-bearing rows at 2.11.9 whose ranges are a bare
# version, a commit hash, or "v2.4.0 and later" -- unplaceable by any parser --
# while every one states a fix at or below v2.11.3.
check "17 a fix below the shipped version excludes the row" \
  "drop" "$(patch_already_in_version 'v2.11.0' 2.11.9 && echo drop || echo keep)"
check "17b a fix EQUAL to the shipped version excludes it (the fix is in)" \
  "drop" "$(patch_already_in_version 'v2.11.8' 2.11.8 && echo drop || echo keep)"
check "17c a fix ABOVE the shipped version does NOT exclude it" \
  "keep" "$(patch_already_in_version '2.11.8' 2.11.7 && echo drop || echo keep)"

# It can only ever remove a row it has positive evidence for: a missing or
# unreadable field excludes nothing. That direction is the false clean this
# file is written against, so each shape is asserted individually.
for bad in '' 'null' 'none' '2.11' 'unknown' 'see advisory'; do
  check "17d patched_versions=$(printf '%q' "$bad") excludes nothing" \
    "keep" "$(patch_already_in_version "$bad" 2.11.9 && echo drop || echo keep)"
done

# Only the LOWEST stated fix counts: a multi-branch fix is evidence only for
# the branch the image is on.
check "17e a multi-branch fix uses the LOWEST version" \
  "drop" "$(patch_already_in_version '2.11.8, 3.0.1' 2.11.9 && echo drop || echo keep)"
check "17f and the same fix does not clear an older version" \
  "keep" "$(patch_already_in_version '3.0.1, 2.11.8' 2.11.7 && echo drop || echo keep)"

# The real data contains a typo (`v.2.11.5`), which must still parse rather
# than silently excluding nothing or silently excluding everything.
check "17g the real-data typo 'v.2.11.5' still parses" \
  "drop" "$(patch_already_in_version 'v.2.11.5' 2.11.9 && echo drop || echo keep)"

# A non-comparable SHIPPED version cannot be judged either.
check "17h a pseudo-version being judged excludes nothing" \
  "keep" "$(patch_already_in_version 'v2.11.0' v0.0.0-20250606074528-04bde2867106 && echo drop || echo keep)"

# Case 18. The two exclusions are INDEPENDENT: neither alone gets 2.11.9 to
# zero, which is why both are needed rather than one being redundant.
range_only=0
while IFS=$'\t' read -r g r _p; do
  [ -n "$g" ] || continue
  range_excludes_version "$r" 2.11.9 && continue
  range_only=$((range_only+1))
done < <(jq -r '.[] | . as $a | (.vulnerabilities // [])[]
                | [($a.ghsa_id // ""), (.vulnerable_version_range // ""),
                   (.patched_versions // "")] | @tsv' "$CADDY_FIXTURE")
check "18 the range filter ALONE does not reach 0 at 2.11.9" \
  "yes" "$([ "$range_only" -gt 0 ] && echo yes || echo no)"

patch_only=0
while IFS=$'\t' read -r g r p; do
  [ -n "$g" ] || continue
  patch_already_in_version "$p" 2.11.9 && continue
  patch_only=$((patch_only+1))
done < <(jq -r '.[] | . as $a | (.vulnerabilities // [])[]
                | [($a.ghsa_id // ""), (.vulnerable_version_range // ""),
                   (.patched_versions // "")] | @tsv' "$CADDY_FIXTURE")
check "18b the patched_versions filter ALONE does not reach 0 either" \
  "yes" "$([ "$patch_only" -gt 0 ] && echo yes || echo no)"
check "18c together they do" "0" "$(live_count 2.11.9)"

echo
echo "=== the graph cap is derived from the API budget, not fixed ==="

# Case 19. A fixed cap of 60 against ~162 sweepable modules left >=102 unswept
# on every authenticated run, which made `image_unswept` an always-on signal
# and made "an unswept component is not a clean component" vacuous. The cap is
# for the unauthenticated 60/hour budget; a token lifts it to 5000/hour.
cap_with_token="$(GH_TOKEN=x PINWATCH_GRAPH_CAP= bash -c '
  if [ -n "${PINWATCH_GRAPH_CAP:-}" ]; then echo "$PINWATCH_GRAPH_CAP";
  elif [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then echo 400; else echo 40; fi')"
cap_without="$(env -u GH_TOKEN -u GITHUB_TOKEN -u PINWATCH_GRAPH_CAP bash -c '
  if [ -n "${PINWATCH_GRAPH_CAP:-}" ]; then echo "$PINWATCH_GRAPH_CAP";
  elif [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then echo 400; else echo 40; fi')"
check "19 a token raises the cap above the graph size" \
  "yes" "$([ "$cap_with_token" -gt 162 ] && echo yes || echo no)"
check "19b unauthenticated it stays inside the 60/hour budget" \
  "yes" "$([ "$cap_without" -lt 60 ] && echo yes || echo no)"
check "19c PINWATCH_GRAPH_CAP overrides either way" \
  "0" "$(PINWATCH_GRAPH_CAP=0 GH_TOKEN=x bash -c '
    if [ -n "${PINWATCH_GRAPH_CAP:-}" ]; then echo "$PINWATCH_GRAPH_CAP";
    elif [ -n "${GH_TOKEN:-}" ]; then echo 400; else echo 40; fi')"

# Case 20. An unauthenticated run that actually skipped components must SAY it
# was the budget, so a reader can tell a transient cap from a permanently
# unsweepable module.
#
# Asserted on the RENDERING rather than through a live run: the sentence is
# emitted only when `img_unswept > 0`, and reaching that state offline is not
# possible (`PINWATCH_SKIP_GITHUB=1` sweeps nothing, so the counter is 0 and
# the whole block is correctly silent). Driving it with a real capped sweep
# would need the network and the rate-limited endpoint, which is what case 16
# is for. So the guarded text is extracted from the script and checked to be
# both PRESENT and CONDITIONAL on the token -- a sentence that printed
# unconditionally would tell an authenticated run its cap was a budget limit,
# which is false.
cap_block="$(grep -A4 'COULD have been swept and were NOT' "$SCRIPT")"
check "20 the unswept sentence names this run's actual cap" \
  "yes" "$(printf '%s' "$cap_block" | grep -q 'GRAPH_SWEEP_CAP' && echo yes || echo no)"
check "20b and the budget explanation is conditional on there being no token" \
  "yes" "$(printf '%s' "$cap_block" | grep -q 'GH_TOKEN' && echo yes || echo no)"

# Case 21. "Out of scope" and "not swept" are SEPARATE counters, and that
# separation is what keeps the second one readable. 74 of this image's 236
# graph modules are not on github.com (`cel.dev`, `cloud.google.com`,
# `golang.org/x/...`), so they have no per-repository advisory endpoint --
# ever. Counting them as unswept made that counter permanently non-zero, which
# would fire any alert on it every single run and drain the meaning from "an
# unswept component is not a clean component" by applying it to a third of the
# graph by design.
check "21 out-of-scope is counted separately from not-swept" \
  "yes" "$(grep -q 'img_out_of_scope=0' "$SCRIPT" && echo yes || echo no)"
# Asserted by RUNNING the script against a graph whose modules are all
# non-github.com, rather than by grepping for the increment: a source grep
# passes on code that is present but unreachable, and the anchor it keys on is
# one reword away from silently matching nothing. `--also` targets are the
# lever here because they go through the same scope test as graph rows.
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-ok" \
  --out-dir "$WORK/o-scope" --json \
  --also golang.org/x/net@v0.62.0 --also cel.dev/cel-go@v0.32.0 2>&1 || true)"
# PINWATCH_SKIP_GITHUB stops the sweep before the scope test, so the counters
# are read from a run that does reach it: drive it with the cap instead.
PINWATCH_GRAPH_CAP=0 "$SCRIPT" --dockerfile "$WORK/df-ok" \
  --out-dir "$WORK/o-scope2" --json \
  --also golang.org/x/net@v0.62.0 --also cel.dev/cel-go@v0.32.0 >/dev/null 2>&1 || true
if [ -f "$WORK/o-scope2/result.json" ]; then
  oos="$(jq -r '.image_out_of_scope' "$WORK/o-scope2/result.json")"
  check "21b two non-github.com targets are counted OUT OF SCOPE" \
    "yes" "$([ "${oos:-0}" -ge 2 ] && echo yes || echo no)"
else
  skipped "21b two non-github.com targets are counted OUT OF SCOPE" \
    "the run produced no result.json (network unavailable)"
fi
check "21c the report says out-of-scope is a limit, not a failed sweep" \
  "yes" "$(grep -q 'not\*\* a sweep that failed' "$SCRIPT" && echo yes || echo no)"
# And the all-clear must still require BOTH to be zero: an out-of-scope
# remainder is honest about coverage, so it must not read as full coverage.
check "21d the all-clear requires out_of_scope to be zero too" \
  "yes" "$(grep -q 'img_out_of_scope" -eq 0' "$SCRIPT" && echo yes || echo no)"
check "20c an all-swept run prints no unswept sentence at all" \
  "no" "$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-ok" \
    --out-dir "$WORK/o-cap" 2>&1 | grep -q 'were NOT swept' && echo yes || echo no)"

echo
echo "=== named targets are swept before graph bulk ==="

# Case 13. The ordering bug this suite was extended for. Alphabetical order
# spent the entire 60/hour budget on modules beginning a-c and never reached
# `caddyserver`, so the base image went unswept on a run that named it. The
# priority column must put every non-graph row first.
printf 'github.com/zzz/z\tv1.0.0\tmodule graph\ngithub.com/caddyserver/caddy\t2.11.9\tbase image\ngithub.com/aaa/a\tv1.0.0\tmodule graph\ngithub.com/caddyserver/caddy\t2.11.7\t--also\n' \
  > "$WORK/targets"
ordered="$(sort -u "$WORK/targets" \
  | awk -F'\t' '{ print ($3 == "module graph" ? 1 : 0) "\t" $0 }' \
  | sort -s -k1,1n | cut -f2- | cut -f3 | paste -sd',' -)"
check "13 base image and --also sort ahead of module-graph rows" \
  "--also,base image,module graph,module graph" "$ordered"

echo
echo "=== --also argument validation ==="

out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-ok" \
  --also 'github.com/x/y' --out-dir "$WORK/o-also" 2>&1 || true)"
check "14 --also without @version is rejected" \
  "yes" "$(printf '%s' "$out" | grep -q 'expects module@version' && echo yes || echo no)"

# `--also` as the FINAL argument, which is the shape that used to hang: with no
# following token `${2:-}` is empty and `shift 2` fails, so `$#` never
# decreases and the loop spins until CI kills the job -- a typo that reads as a
# network hang. `need_value` is what makes it a one-line rejection, and this
# case is the one that proves it. A trailing `--out-dir` would be consumed AS
# the value and prove nothing, which is how this case first passed vacuously.
out="$(timeout 20 env PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/df-ok" \
  --out-dir "$WORK/o-also2" --also 2>&1; echo "rc=$?")"
check "15 --also with no value is rejected, not looped on" \
  "yes" "$(printf '%s' "$out" | grep -q 'requires a non-empty value\|requires a value' && echo yes || echo no)"
check "15b and it exits rather than hanging" \
  "no" "$(printf '%s' "$out" | grep -q 'rc=124' && echo yes || echo no)"

echo
echo "=== the live network path (skipped without a token) ==="

# Case 16. The end-to-end path against the real endpoint. Rate-limited to 60
# calls an hour unauthenticated, which this image's graph exceeds on its own,
# so it runs only with a token and SKIPS otherwise. A test that cannot run must
# not read as one that passed.
gh_tok="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$gh_tok" ]; then
  skipped "16 live sweep of caddy@2.11.7 reports exactly 5" \
    "no GH_TOKEN/GITHUB_TOKEN; the unauthenticated 60/hour budget cannot cover this"
else
  rl="$(curl -fsS -H "Authorization: Bearer $gh_tok" https://api.github.com/rate_limit 2>/dev/null \
        | jq -r '.rate.remaining' 2>/dev/null || echo 0)"
  if [ "${rl:-0}" -lt 10 ]; then
    skipped "16 live sweep of caddy@2.11.7 reports exactly 5" \
      "only $rl GitHub API calls remaining"
  else
    PINWATCH_GRAPH_CAP=0 "$SCRIPT" --dockerfile "$WORK/df-ok" \
      --out-dir "$WORK/o-live" --json \
      --also github.com/caddyserver/caddy@2.11.7 >/dev/null 2>&1 || true
    n="$(awk -F'\t' '$1=="github.com/caddyserver/caddy" && $2=="2.11.7"' \
          "$WORK/o-live/image-extra.tsv" 2>/dev/null | wc -l | tr -d ' ')"
    check "16 live sweep of caddy@2.11.7 reports exactly 5" "5" "$n"
    n9="$(awk -F'\t' '$1=="github.com/caddyserver/caddy" && $2=="2.11.9"' \
           "$WORK/o-live/image-extra.tsv" 2>/dev/null | wc -l | tr -d ' ')"
    check "16b live sweep of the shipped 2.11.9 base reports 0" "0" "$n9"
  fi
fi

echo
printf 'pass=%d fail=%d skip=%d\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
