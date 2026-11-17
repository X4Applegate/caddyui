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

# The gate sets DRIFT_POLICY outside the extracted function range, and check
# 5b reads it. Default to the gate's own default (`block`), so a test that
# does not say otherwise exercises the STRICT path -- the same
# safer-by-default rule the script itself applies to a caller that forgets the
# variable.
DRIFT_POLICY="${MODULE_DRIFT_POLICY:-block}"

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
#
#    The rebuild keeps 50 of the baseline's REAL names, so it is caught by
#    check 4's count floor (50 < 119) -- but 50 retained names is also below
#    check 5's identity floor of 119, so check 5 would catch it too and this
#    test alone cannot tell which one fired. Test 22 is the one that isolates
#    check 4; this case is kept for the ordinary collapse shape.
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

# 13. A baseline whose gobinary results carry NO usable .Target blocks.
#     Found by the independent code review of the first spelling of check 6:
#     the `-n "$old_gotargets"` guard conflated "the baseline has no Go
#     binaries" (a safe skip) with "the baseline's Go binaries have no recorded
#     path" (not safe -- checks 3-5 still pass because the TYPE is present on
#     both sides, so a rebuild scanning a DIFFERENT binary went unnoticed, and
#     once published that image IS the baseline). Asserted with the rebuild's
#     binary MOVED, which is precisely what check 6 exists to catch.
jq '(.Results[] | select(.Type == "gobinary") | .Target) |= null' "$B" > "$WORK/t13-base.json"
mkscan "$WORK/t13.json" 32 237 real somewhere/else
run_cov "$WORK/t13.json" "$WORK/t13-base.json"
check "baseline gobinary results with no usable Target block" block

# 14. A baseline with NO gobinary results at all still passes: check 6 has
#     nothing to assert, and that skip is the legitimate one 13 is contrasted
#     against. Guards against fixing 13 by making every absent target fatal.
jq 'del(.Results[] | select(.Type == "gobinary"))' "$B" > "$WORK/t14-base.json"
jq 'del(.Results[] | select(.Type == "gobinary"))' "$WORK/t1.json" > "$WORK/t14.json"
run_cov "$WORK/t14.json" "$WORK/t14-base.json"
check "baseline with no gobinary results at all passes" pass

# 15. THE DECOY BINARY. Found by the security review of the first spelling of
#     check 6, and the reason check 7 exists: the shipped binary is gutted to
#     one package while a SECOND Go binary carries the baseline's whole real
#     name set. Type-level count and type-level intersection both clear, and
#     check 6 is satisfied literally because usr/bin/caddy is still a scanned
#     target -- it is simply empty. Only a per-TARGET floor catches this.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |= [ { Name: "caddy" } ]
    | .Results += [ { Target: "usr/bin/helper", Class: "lang-pkgs", Type: "gobinary",
                      Packages: [ range(0;237)
                                  | { Name: ("example.com/mod-" + (. | tostring)) } ],
                      Vulnerabilities: [] } ]' "$B" > "$WORK/t15.json"
run_cov "$WORK/t15.json" "$B"
check "decoy binary carrying the real names does not pay for the shipped one" block

# 16. The same shape WITHOUT the decoy: shipped binary gutted to one package.
#     Already caught by check 4's count floor, kept so a future edit that
#     narrows check 7 cannot quietly open the simpler case.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |= [ { Name: "caddy" } ]' \
   "$B" > "$WORK/t16.json"
run_cov "$WORK/t16.json" "$B"
check "shipped binary gutted to one package blocks" block

# 17. A second Go binary ADDED alongside an intact one still passes. Check 7
#     must only measure targets the BASELINE had, or adding a helper binary
#     to a legitimate release would be fatal.
jq '.Results += [ { Target: "usr/bin/helper", Class: "lang-pkgs", Type: "gobinary",
                    Packages: [ { Name: "example.com/helper" } ],
                    Vulnerabilities: [] } ]' "$WORK/t1.json" > "$WORK/t17.json"
run_cov "$WORK/t17.json" "$B"
check "an added second Go binary alongside an intact one passes" pass

# ---------------------------------------------------------------------------
# Check 5b: the baseline's findings-bearing packages must survive.
#
# These use a baseline that actually HAS vulnerabilities, since 5b is keyed on
# .Vulnerabilities[].PkgName. The fixtures above carry none.
BV="$WORK/baseline-vuln.json"
jq '(.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "GO-2026-0001", PkgName: "example.com/mod-5" },
        { VulnerabilityID: "GO-2026-0002", PkgName: "example.com/mod-9" } ]' "$B" > "$BV"

# 18. Pass A's attack: retain enough names to clear the 50% floor, but drop
#     exactly the packages that carry the findings. Clears check 5 by design
#     -- 5b is what catches it.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      ([ .[] | select(.Name != "example.com/mod-5" and .Name != "example.com/mod-9") ][0:119]
       + [ range(0;118) | { Name: ("attacker.invalid/pad-" + (. | tostring)) } ])
    | (.Results[] | .Vulnerabilities) |= []' "$BV" > "$WORK/t18.json"
run_cov "$WORK/t18.json" "$BV"
check "dropping only the findings-bearing packages blocks under block policy" block

# 19. The same input under MODULE_DRIFT_POLICY=report is REPORTED, not fatal:
#     a release may legitimately remove a plugin, and its whole subtree with
#     it. The reviewer sees the note; gate 1 decides the verdict.
SAVED_POLICY="$DRIFT_POLICY"
DRIFT_POLICY=report
run_cov "$WORK/t18.json" "$BV"
if [ "$COV_RC" -eq 0 ] && printf '%s' "$COV_OUT" | grep -q 'carry findings'; then
  printf 'ok   %s\n' "report policy notes the dropped vulnerable package instead of dying"
  PASS=$((PASS + 1))
else
  printf 'FAIL %s (rc=%s)\n     %s\n' "report policy notes the dropped vulnerable package instead of dying" \
    "$COV_RC" "$COV_OUT"
  FAIL=$((FAIL + 1))
fi
DRIFT_POLICY="$SAVED_POLICY"

# 20. An honest rebuild that keeps the findings-bearing packages passes.
run_cov "$BV" "$BV"
check "rebuild retaining the findings-bearing packages passes" pass

# 21. Pass B's ratchet, second step: the baseline now CONTAINS the fabricated
#     names planted by a previous release, so they are legitimate
#     intersection members and the name floor alone is satisfied. 5b is what
#     stops it, because a fabricated name never carries a finding.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      ([ { Name: "caddy" } ]
       + [ range(0;118) | { Name: ("attacker.invalid/pad-" + (. | tostring)) } ]
       + [ range(0;118) | { Name: ("attacker.invalid/pad2-" + (. | tostring)) } ])
    | (.Results[] | .Vulnerabilities) |= []' "$BV" > "$WORK/t21.json"
run_cov "$WORK/t21.json" "$BV"
check "carried-over fabricated names cannot satisfy the floor (ratchet step 2)" block

# 22. Check 4 ISOLATED: a nameless baseline with a readable count, against a
#     rebuild that collapses below the count floor (T-0812).
#
#     Every other blocking case in this file is also caught by check 5, so
#     deleting check 4's count floor outright -- replacing its condition with
#     `if false; then` -- left the whole suite reporting 21 passed, 0 failed.
#     A check no test can observe is a check a future edit can remove in
#     silence, so this case exists to make that mutation fail.
#
#     The shape is test 12's baseline (237 gobinary rows carrying no .Name,
#     which is a real Trivy possibility -- .Packages[].Name is guaranteed for
#     neither every ecosystem nor every version) paired with test 4's
#     collapse instead of test 12's intact rebuild. Because the baseline has
#     no usable names, check 5 takes its `old_named -eq 0` skip and never
#     looks at this target, and 5b has no named findings to assert on. Check
#     4 is then the ONLY thing standing between a 237-package baseline and a
#     40-package rebuild: 40 < 119 blocks, and with check 4 removed the same
#     input passes as "scan coverage OK".
#
#     This is why check 4 is NOT redundant with check 5, contrary to what
#     security pass B concluded. Count and identity cover different holes:
#     identity needs names to work at all, and the count floor is what still
#     measures coverage when names are unavailable.
jq '(.Results[] | select(.Type == "gobinary") | .Packages)
      |= [ range(0; 237) | { Version: "1.0.0" } ]' "$B" > "$WORK/t22-base.json"
mkscan "$WORK/t22.json" 32 40 real usr/bin/caddy
run_cov "$WORK/t22.json" "$WORK/t22-base.json"
check "nameless baseline + collapsed count blocks (check 4 alone)" block

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
