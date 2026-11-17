#!/usr/bin/env bash
# Regression tests for assert_scan_coverage in caddy-image-gate.sh.
#
# WHAT THESE COVER, AND WHY THEY ARE SCAN-LEVEL RATHER THAN IMAGE-LEVEL
# ---------------------------------------------------------------------
# The coverage precondition reads exactly two things: the rebuild's Trivy JSON
# and the baseline's Trivy JSON. So it can be tested by feeding it crafted
# pairs of those documents, with no image build and no scan -- which is what
# makes this harness runnable in seconds and in CI, rather than being a manual
# exercise with purpose-built images that nobody re-runs.
#
# The fixtures are SHAPED LIKE THE REAL SCANS, not minimal: the baseline is the
# real :stable shape (alpine 32 packages, gobinary 237 at usr/bin/caddy, with
# findings), because the gap being regression-tested here -- a padded package
# list clearing a count floor -- only exists at realistic sizes. A 3-package
# fixture would pass or fail for the wrong arithmetic.
#
# The attack cases are the ones security passes A and B reproduced end-to-end
# against this gate before T-0638 closed them. Cases 6 and 7 FAIL against the
# pre-T-0638 script and pass against this one; the rest are the existing
# behaviour, kept so the new checks cannot be bought by weakening an old one.
#
# Usage: scripts/test-image-gate-coverage.sh
# Exit 0 = all pass.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/caddy-image-gate.sh"
[ -r "$GATE" ] || { echo "cannot read $GATE" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

# Source the gate's functions WITHOUT running its body.
#
# The script is `set -euo pipefail` with an argument check and a dependency
# check at the top, so it cannot simply be sourced. Extract from the first
# function definition to the end of assert_scan_coverage instead: that range is
# pure function definitions, so sourcing it defines them and runs nothing.
#
# `die` is defined ABOVE that range, so it is re-declared here rather than
# extracted. It must be a FAITHFUL copy of the gate's: an `exit 2` and not a
# `return`, because every assertion in assert_scan_coverage relies on die not
# returning to its caller. A `return`-shaped stub silently turns every block
# case into a pass -- which is exactly how the first spelling of this harness
# reported 5/12 with the new checks firing correctly underneath.
die() { echo "::error::$*" >&2; exit 2; }

extract_functions() {
  awk '
    /^ids_from\(\) \{/        { grab = 1 }
    grab                      { print }
    /^\}$/ && grab && seen_cov { exit }
    /^assert_scan_coverage\(\) \{/ { seen_cov = 1 }
  ' "$GATE"
}

# shellcheck disable=SC1090
. <(printf 'set -euo pipefail\ndie() { echo "::error::$*" >&2; exit 2; }\n'; extract_functions)

command -v jq >/dev/null || { echo "jq not found" >&2; exit 2; }

# A scan document in the real :stable shape.
#
#   $1 out path
#   $2 number of alpine packages
#   $3 number of gobinary packages
#   $4 gobinary package NAME prefix ("real" reproduces the baseline's names;
#      anything else fabricates a disjoint set, which is the padding attack)
#   $5 gobinary Target path
#   $6 extra top-level JSON merged over the result (e.g. drop a result)
mkscan() {
  local out="$1" nalpine="$2" ngo="$3" prefix="$4" gotarget="$5"
  jq -n \
    --argjson nalpine "$nalpine" \
    --argjson ngo "$ngo" \
    --arg prefix "$prefix" \
    --arg gotarget "$gotarget" '
    {
      Metadata: { OS: { Family: "alpine", Name: "3.24.4" } },
      Results: [
        {
          Target: "applegater/caddyui-caddy:stable (alpine 3.24.4)",
          Class: "os-pkgs",
          Type: "alpine",
          Packages: [ range(0; $nalpine) | { Name: ("alpkg-" + (. | tostring)) } ],
          Vulnerabilities: []
        },
        {
          Target: $gotarget,
          Class: "lang-pkgs",
          Type: "gobinary",
          Packages: [ range(0; $ngo)
                      | { Name: (if $prefix == "real"
                                 then "example.com/mod-" + (. | tostring)
                                 else $prefix + "/mod-" + (. | tostring) end) } ],
          Vulnerabilities: []
        }
      ]
    }' > "$out"
}

# Run assert_scan_coverage in a subshell so a `die` (exit 2) does not kill the
# harness, and capture both its status and its message.
#
# The `|| COV_RC=$?` is load-bearing: this harness runs under `set -e`, and a
# command substitution whose subshell exits non-zero makes the ASSIGNMENT fail,
# which aborts the harness at the first blocking case instead of recording it.
# The first spelling read `COV_RC=$?` on the following line, which `set -e`
# never reached -- the run stopped silently after the last passing test.
run_cov() {
  local new="$1" old="$2"
  COV_RC=0
  COV_OUT="$( (
      OUT="$WORK"
      export OUT
      assert_scan_coverage "$new" "$old" amd64
    ) 2>&1 )" || COV_RC=$?
  return 0
}

check() {
  local name="$1" want="$2"   # want: pass | block
  if [ "$want" = pass ] && [ "$COV_RC" -eq 0 ]; then
    printf 'ok   %s\n' "$name"; PASS=$((PASS + 1)); return
  fi
  if [ "$want" = block ] && [ "$COV_RC" -ne 0 ]; then
    printf 'ok   %s  (blocked: %s)\n' "$name" "$(printf '%s' "$COV_OUT" | head -c 90)"
    PASS=$((PASS + 1)); return
  fi
  printf 'FAIL %s  (want %s, rc=%s)\n     %s\n' "$name" "$want" "$COV_RC" "$COV_OUT"
  FAIL=$((FAIL + 1))
}

B="$WORK/baseline.json"
mkscan "$B" 32 237 real usr/bin/caddy

# ---------------------------------------------------------------------------
# 1. The healthy case: an identical rebuild passes.
mkscan "$WORK/t1.json" 32 237 real usr/bin/caddy
run_cov "$WORK/t1.json" "$B"
check "identical rebuild passes" pass

# 2. Ordinary churn passes: packages move a little, names mostly retained.
mkscan "$WORK/t2.json" 33 240 real usr/bin/caddy
run_cov "$WORK/t2.json" "$B"
check "ordinary upward churn passes" pass

# 3. A lost scan target blocks (pre-existing check 3).
jq 'del(.Results[] | select(.Type == "gobinary"))' "$B" > "$WORK/t3.json"
run_cov "$WORK/t3.json" "$B"
check "lost gobinary target blocks" block

# 4. A collapsed package count blocks (pre-existing check 4).
mkscan "$WORK/t4.json" 32 50 real usr/bin/caddy
run_cov "$WORK/t4.json" "$B"
check "gobinary collapsed below 50% count floor blocks" block

# 5. A zero-package baseline blocks (closed in a433a3b).
mkscan "$WORK/t5-base.json" 32 0 real usr/bin/caddy
mkscan "$WORK/t5.json" 32 237 real usr/bin/caddy
run_cov "$WORK/t5.json" "$WORK/t5-base.json"
check "zero-package baseline blocks" block

# ---------------------------------------------------------------------------
# T-0638: the cases a COUNT cannot catch. Both pass the pre-T-0638 script.

# 6. The padding attack: full-size package list, entirely fabricated names.
#    Count floor is cleared outright (237 >= 119); identity floor is 0/237.
mkscan "$WORK/t6.json" 32 237 attacker.invalid usr/bin/caddy
run_cov "$WORK/t6.json" "$B"
check "padded gobinary list with disjoint names blocks" block

# 7. Security pass A's exact shape: alpine 16 / gobinary 118, zero findings.
#    118 >= 119 is false by one, so the count floor already catches the go
#    side -- use 119 to put it exactly AT the count floor and show that
#    identity is what stops it.
mkscan "$WORK/t7.json" 16 119 attacker.invalid usr/bin/caddy
run_cov "$WORK/t7.json" "$B"
check "replaced list sitting exactly at the count floor blocks" block

# 8. Half the real names retained, at the floor: passes.
#    This is the legitimate case the loose floor exists for -- a release that
#    drops a plugin and its whole dependency subtree.
jq '(.Results[] | select(.Type == "gobinary") | .Packages)
      |= (.[0:120])' "$B" > "$WORK/t8.json"
run_cov "$WORK/t8.json" "$B"
check "half the real packages retained passes (legitimate plugin drop)" pass

# 9. The scanned Go binary moved: gobinary type present, different path.
mkscan "$WORK/t9.json" 32 237 real usr/local/bin/other
run_cov "$WORK/t9.json" "$B"
check "gobinary scanned at a different path blocks" block

# 10. An ADDED gobinary alongside the real one passes: more coverage is fine.
jq '.Results += [ { Target: "usr/bin/helper", Class: "lang-pkgs",
                    Type: "gobinary",
                    Packages: [ { Name: "example.com/helper" } ],
                    Vulnerabilities: [] } ]' "$WORK/t1.json" > "$WORK/t10.json"
run_cov "$WORK/t10.json" "$B"
check "an additional gobinary alongside the real one passes" pass

# 11. Alpine list replaced wholesale: identity floor catches it at full count.
jq '(.Results[] | select(.Type == "alpine") | .Packages)
      |= [ range(0; 32) | { Name: ("fake-" + (. | tostring)) } ]' "$B" > "$WORK/t11.json"
run_cov "$WORK/t11.json" "$B"
check "replaced alpine package list blocks" block

# 12. Unnamed baseline packages skip the identity floor rather than dying.
#     Count floor still applies, so coverage is still measured.
jq '(.Results[] | select(.Type == "gobinary") | .Packages)
      |= [ range(0; 237) | { Version: "1.0.0" } ]' "$B" > "$WORK/t12-base.json"
mkscan "$WORK/t12.json" 32 237 real usr/bin/caddy
run_cov "$WORK/t12.json" "$WORK/t12-base.json"
check "baseline packages without names skip identity floor, do not die" pass

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
