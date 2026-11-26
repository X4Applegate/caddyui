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

# Check 5e reads this, and it is set OUTSIDE the extracted function range too,
# so `set -u` would abort the harness on the first case without it.
#
# Defaults to EMPTY -- i.e. no absolute floor -- deliberately, so the 47 cases
# that predate T-0811 exercise exactly the checks they were written for and
# cannot be made to pass or fail by a fixture they do not know about. The 5e
# cases set it per-case instead.
#
# shellcheck disable=SC2034  # read by assert_scan_coverage, which is sourced above
COVERAGE_FLOOR_FILE=""

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

# ---------------------------------------------------------------------------
# T-0810: checks 5c and 5d. A NAME IS NOT A VERSION.
#
# Checks 5, 5b and 7 all compare .Packages[].Name, and until T-0810 nothing
# compared .Packages[].Version anywhere in the function. So a rebuild could
# keep every name -- clearing every floor above, INCLUDING 5b, since the
# findings-bearing packages are all still reported -- while the versions
# behind those names were entirely different.
#
# The fixtures above carry no versions at all, so these build their own. BVV
# is the :stable shape WITH versions, two of whose gobinary packages carry
# findings.
BVV="$WORK/baseline-vers.json"
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |= [ .[] | .Version = "v1.0.0" ]
    | (.Results[] | select(.Type == "alpine")   | .Packages) |= [ .[] | .Version = "1.0-r0" ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
        [ { VulnerabilityID: "GO-2026-0001", PkgName: "example.com/mod-5",
            InstalledVersion: "v1.0.0" },
          { VulnerabilityID: "GO-2026-0002", PkgName: "example.com/mod-9",
            InstalledVersion: "v1.0.0" } ]' "$B" > "$BVV"

# 22. An identical rebuild WITH versions passes: the new checks must not
#     block the ordinary case.
run_cov "$BVV" "$BVV"
check "identical rebuild with versions passes" pass

# 23. THE WHOLESALE SWAP. Every name retained (so 5, 5b and 7 are all
#     satisfied outright), every version replaced, findings zeroed. This is
#     the gap T-0810 was filed for, reproduced against the real :stable scan
#     before being closed. 5d catches it at 0/237 name@version retention.
jq '(.Results[] | .Packages) |= [ .[] | .Version = "v0.0.0-attacker" ]
    | (.Results[] | .Vulnerabilities) |= []' "$BVV" > "$WORK/t23.json"
run_cov "$WORK/t23.json" "$BVV"
check "every name retained but every version replaced blocks" block

# 24. THE TARGETED SWAP, and the reason a ratio alone is not enough. Swap the
#     versions of ONLY the findings-bearing packages: name@version retention
#     stays at 235/237 = 99%, far above any floor, while both findings
#     disappear. This is pass A's "drop exactly the packages that decide the
#     verdict" recurring one level down. Only 5c catches it.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if (.Name == "example.com/mod-5" or .Name == "example.com/mod-9")
              then .Version = "v9.9.9-swapped" else . end ]
    | (.Results[] | .Vulnerabilities) |= []' "$BVV" > "$WORK/t24.json"
run_cov "$WORK/t24.json" "$BVV"
check "swapping only the findings-bearing versions blocks (5c, ratio cannot see it)" block

# 25. Prove 24 really is invisible to a ratio, so a future edit cannot
#     "simplify" 5c away into 5d's floor. Measured, not asserted.
t25_old=$(jq -r '[.Results[]?|select(.Type=="gobinary")|.Packages[]?
                  |select((.Name//"")!="" and (.Version//"")!="")
                  |"\(.Name)@\(.Version)"]|unique|.[]' "$BVV" | LC_ALL=C sort -u)
t25_new=$(jq -r '[.Results[]?|select(.Type=="gobinary")|.Packages[]?
                  |select((.Name//"")!="" and (.Version//"")!="")
                  |"\(.Name)@\(.Version)"]|unique|.[]' "$WORK/t24.json" | LC_ALL=C sort -u)
t25_tot=$(printf '%s\n' "$t25_old" | grep -c .)
t25_ret=$(LC_ALL=C comm -12 <(printf '%s\n' "$t25_old") <(printf '%s\n' "$t25_new") | grep -c .)
if [ "$t25_ret" -ge $(( (t25_tot + 1) / 2 )) ]; then
  printf 'ok   the targeted swap clears 5d'"'"'s ratio (%s/%s retained) -- 5c is load-bearing\n' \
    "$t25_ret" "$t25_tot"
  PASS=$((PASS + 1))
else
  printf 'FAIL the targeted swap should clear 5d'"'"'s ratio but did not (%s/%s)\n' "$t25_ret" "$t25_tot"
  FAIL=$((FAIL + 1))
fi

# 26. THE ids_from CASE, which is the whole reason this could not be bolted
#     on. A findings-bearing module UPGRADED but STILL AFFECTED must pass:
#     `ids_from` deliberately excludes InstalledVersion because keying on it
#     made exactly this look like one finding removed plus one added, which
#     would stop a security release that bumps a still-affected module.
#     5c's first limb is what keeps the two compatible -- the finding did not
#     cancel, so there is nothing to misread.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then .Version = "v2.0.0" else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "GO-2026-0001", PkgName: "example.com/mod-5",
          InstalledVersion: "v2.0.0" },
        { VulnerabilityID: "GO-2026-0002", PkgName: "example.com/mod-9",
          InstalledVersion: "v1.0.0" } ]' "$BVV" > "$WORK/t26.json"
run_cov "$WORK/t26.json" "$BVV"
check "upgraded module still carrying its finding passes (the ids_from case)" pass

# 27. A genuine FIX -- module upgraded and the finding really gone -- is
#     blocking under `block` and reported under `report`. Under block the
#     caller is the refresh path, which rebuilds an UNCHANGED Dockerfile from
#     a release tag, so a pinned module cannot move at all; gate 2 fails the
#     same run for the same reason. Cutting a release is the documented route.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then .Version = "v2.0.0" else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "GO-2026-0002", PkgName: "example.com/mod-9",
          InstalledVersion: "v1.0.0" } ]' "$BVV" > "$WORK/t27.json"
run_cov "$WORK/t27.json" "$BVV"
check "fixed-by-upgrade module blocks under block policy (refresh: pins must not move)" block

# 28. The same input under `report` -- the release path -- is a NOTE, not
#     fatal. A security release that upgrades a module to clear an advisory is
#     the normal reason to cut one, and blocking it would be the "the gate
#     calls your fix a regression" failure ids_from exists to avoid.
SAVED_POLICY="$DRIFT_POLICY"
DRIFT_POLICY=report
run_cov "$WORK/t27.json" "$BVV"
if [ "$COV_RC" -eq 0 ] && printf '%s' "$COV_OUT" | grep -q 'different version'; then
  printf 'ok   report policy notes the fixed-by-upgrade module instead of dying\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL report policy should note the fixed-by-upgrade module (rc=%s)\n     %s\n' \
    "$COV_RC" "$COV_OUT"
  FAIL=$((FAIL + 1))
fi
DRIFT_POLICY="$SAVED_POLICY"

# 29. AN OS PACKAGE UPGRADE THAT FIXES ITS FINDING PASSES UNDER BLOCK.
#     `apk upgrade --no-cache` is unpinned BY DESIGN and `FROM
#     caddy:<ver>-alpine` is a moving tag, so picking up new OS package
#     versions is the entire purpose of a weekly refresh. Unscoped, 5c would
#     have blocked the real T-0592 refresh -- the one that fixed
#     CVE-2026-4738 by moving zlib 1.3.2-r1 -> 1.4-r0. This is the regression
#     test for that scoping; do not widen 5c's block limb past gobinary/gomod
#     without replacing this case.
jq '(.Results[] | select(.Type == "alpine") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-2026-4738", PkgName: "alpkg-3",
          InstalledVersion: "1.0-r0" } ]' "$BVV" > "$WORK/t29-base.json"
jq '(.Results[] | select(.Type == "alpine") | .Packages) |=
      [ .[] | if .Name == "alpkg-3" then .Version = "1.1-r0" else . end ]
    | (.Results[] | .Vulnerabilities) |= []' "$WORK/t29-base.json" > "$WORK/t29.json"
run_cov "$WORK/t29.json" "$WORK/t29-base.json"
check "OS package upgraded to fix its finding passes under block (apk is unpinned by design)" pass

# 30. ...but a WHOLESALE OS version replacement is still caught, by 5d's
#     ratio. Scoping 5c away from alpine must not leave the OS layer with no
#     version check at all.
jq '(.Results[] | select(.Type == "alpine") | .Packages) |= [ .[] | .Version = "99.9-r0" ]
    | (.Results[] | .Vulnerabilities) |= []' "$BVV" > "$WORK/t30.json"
run_cov "$WORK/t30.json" "$BVV"
check "wholesale OS version replacement still blocks via the ratio floor" block

# 31. A baseline carrying NO versions skips the version checks rather than
#     dying, the way check 5 skips a nameless baseline. .Packages[].Version is
#     guaranteed for neither every ecosystem nor every Trivy version, and
#     checks 4 and 5 have already measured this target.
run_cov "$WORK/t1.json" "$B"
check "baseline without versions skips the version checks, does not die" pass

# 32. A rebuild that drops versions while the BASELINE had them is caught:
#     the name@version intersection collapses to zero. Otherwise stripping
#     version metadata would be a way to opt out of the check entirely.
jq '(.Results[] | .Packages) |= [ .[] | del(.Version) ]
    | (.Results[] | .Vulnerabilities) |= []' "$BVV" > "$WORK/t32.json"
run_cov "$WORK/t32.json" "$BVV"
check "rebuild that strips versions a versioned baseline had blocks" block

# 33. Legitimate churn at realistic scale passes. Measured against the real
#     pairs: v2.68.12 vs :stable retains 235/236 gobinary and 32/32 alpine
#     name@version pairs, and the T-0592 refresh -- the heaviest real churn on
#     record -- retains 28/32 alpine. 12 of 237 moved is well past both.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ to_entries[] | if .key < 12 then (.value | .Version = "v1.1.0") else .value end ]' \
   "$BVV" > "$WORK/t33.json"
run_cov "$WORK/t33.json" "$BVV"
check "ordinary version churn at realistic scale passes" pass


# ---------------------------------------------------------------------------
# T-0810 round 2: the five bypasses the review passes found in 5c/5d.
#
# Every one was reproduced end to end against the real :stable scan before
# being closed, and every one passed the 33-case suite above — which is why
# they are here. They are the regression tests for fixes that are easy to
# "simplify" back into the bug.

# 34. THE MULTI-FINDING BYPASS, and the reason 5c compares an ID SET.
#     5c's exemption first asked "does this package still carry ANY finding".
#     A package carrying several was then exempted by retaining one of them
#     while the rest cancelled as fixed. Live on the real image: :stable
#     reports THREE CVEs against github.com/go-jose/go-jose/v3, so this gave
#     coverage OK, ADDED=0 REMOVED=2, verdict=improved, exit 0 under the
#     STRICT policy and with no note printed.
BMV="$WORK/baseline-multivuln.json"
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |= [ .[] | .Version = "v1.0.0" ]
    | (.Results[] | select(.Type == "alpine")   | .Packages) |= [ .[] | .Version = "1.0-r0" ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
        [ { VulnerabilityID: "CVE-1", PkgName: "example.com/mod-5", InstalledVersion: "v1.0.0" },
          { VulnerabilityID: "CVE-2", PkgName: "example.com/mod-5", InstalledVersion: "v1.0.0" },
          { VulnerabilityID: "CVE-3", PkgName: "example.com/mod-5", InstalledVersion: "v1.0.0" } ]' \
   "$B" > "$BMV"
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then .Version = "v1.0.0-attacker" else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-1", PkgName: "example.com/mod-5",
          InstalledVersion: "v1.0.0-attacker" } ]' "$BMV" > "$WORK/t34.json"
run_cov "$WORK/t34.json" "$BMV"
check "package keeping 1 of 3 findings cannot move version (5c is per-finding)" block

# 35. ...and retaining ALL of them still passes, so 34 is not bought by
#     making every version move fatal. This is the ids_from upgrade case for
#     a multi-finding package.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then .Version = "v2.0.0" else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-1", PkgName: "example.com/mod-5", InstalledVersion: "v2.0.0" },
        { VulnerabilityID: "CVE-2", PkgName: "example.com/mod-5", InstalledVersion: "v2.0.0" },
        { VulnerabilityID: "CVE-3", PkgName: "example.com/mod-5", InstalledVersion: "v2.0.0" } ]' \
   "$BMV" > "$WORK/t35.json"
run_cov "$WORK/t35.json" "$BMV"
check "upgraded package still carrying ALL its findings passes" pass

# 36. A FABRICATED finding must not buy the exemption. Every string in the
#     scan is attacker-chosen, so the image could otherwise manufacture its
#     own exemption with one invented vulnerability row. 5b holds itself to
#     "anchored to real, observed vulnerabilities"; 5c must too. The ID set
#     is compared against the BASELINE's, so an invented id cannot complete
#     it.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then .Version = "v1.0.0-attacker" else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-FABRICATED", PkgName: "example.com/mod-5",
          InstalledVersion: "v1.0.0-attacker" } ]' "$BMV" > "$WORK/t36.json"
run_cov "$WORK/t36.json" "$BMV"
check "a fabricated finding cannot buy 5c's exemption" block

# 37. SANITIZATION ASYMMETRY. 5c's needle comes from the vulnerability list,
#     which is written through gsub+truncate, so pkg_ver_of_name must apply
#     the SAME transformation to .Name or the select matches nothing and the
#     package is skipped as "no readable version" — fail-open on the
#     load-bearing check, and attacker-selectable, since a gobinary PkgName
#     is copied from Go build info in a submitter-controlled image. One `~`
#     was enough.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) += [ { Name: "example.com/mod~x", Version: "v1.0.0" } ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-T", PkgName: "example.com/mod~x", InstalledVersion: "v1.0.0" } ]' \
   "$BVV" > "$WORK/t37-base.json"
jq '(.Results[] | select(.Type == "gobinary") | .Packages) += [ { Name: "example.com/mod~x", Version: "v9.9.9-swapped" } ]
    | (.Results[] | .Vulnerabilities) |= []' "$BVV" > "$WORK/t37.json"
run_cov "$WORK/t37.json" "$WORK/t37-base.json"
check "5c fires for a package name needing sanitization (no raw-vs-sanitized gap)" block

# 38. CHECK 5's NAMELESS-BASELINE SKIP MUST NOT DISABLE 5b/5c/5d. It was a
#     `continue`, which was right while 5 and 5b both keyed on
#     .Packages[].Name. 5c keys on the VULNERABILITY's .PkgName — a different
#     field, populated here while the package rows are not — and 5d keys on
#     name@version. A `continue` therefore turned off every version check,
#     and that is the self-perpetuating shape already closed for check 4's
#     zero-package baseline: check 3 still passes, so one such image
#     publishes once and IS the blind baseline from then on.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |= [ .[] | del(.Name) | .Version = "v1.0.0" ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-N", PkgName: "example.com/mod-5", InstalledVersion: "v1.0.0" } ]' \
   "$B" > "$WORK/t38-base.json"
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |= [ .[] | del(.Name) | .Version = "v0-swapped" ]
    | (.Results[] | .Vulnerabilities) |= []' "$B" > "$WORK/t38.json"
run_cov "$WORK/t38.json" "$WORK/t38-base.json"
check "nameless baseline does not disable the version checks" block

# 39. THE VERSION-STRIPPING RATCHET. 5d's denominator counts only baseline
#     rows that HAVE a version, and a published image becomes the next
#     baseline — so dropping versions while keeping names shrinks the
#     standard for every later release, with checks 4/5/5b/7 silent because
#     the names are untouched. Same inherited-denominator shape that made
#     fabricated names dangerous, one level down. Dropping a version from a
#     package the rebuild still reports is now a hard stop.
#
#     Stripped at EXACTLY the ratio floor, not wholesale: dropping 150 of 237
#     at once is already caught by 5d's own ratio (87 < 118), so a wholesale
#     fixture would pass against the buggy code too and prove nothing. The
#     ratchet works precisely because each step stays inside the floor —
#     measured against the pre-fix gate, 237 -> 119 -> 60 -> 30 with rc=0 at
#     every step. Keep this fixture at the floor if it is ever edited.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      ( reduce .[] as $p ({n: 0, out: []};
          if (($p.Version // "") != "")
          then (if .n < 119
                then {n: (.n + 1), out: (.out + [$p])}
                else {n: (.n + 1), out: (.out + [$p | del(.Version)])} end)
          else {n: .n, out: (.out + [$p])} end) | .out )' \
   "$BVV" > "$WORK/t39.json"
run_cov "$WORK/t39.json" "$BVV"
check "dropping versions from still-reported packages blocks (denominator ratchet)" block

# 40. ...but a package that is GONE ALTOGETHER is 5/5b's question, not 5d's.
#     Counting it here too would turn the legitimate plugin drop that checks
#     4 and 5 deliberately tolerate into a hard stop.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |= .[0:150]' "$BVV" > "$WORK/t40.json"
run_cov "$WORK/t40.json" "$BVV"
check "a removed package is not counted as a dropped version" pass

# 41. THE 120-CHARACTER TRUNCATION COLLISION. Versions are compared truncated
#     to 120 characters, so two agreeing up to that length are
#     indistinguishable. Planting `v…+build.<140 chars>` compares equal to
#     itself, keeps its finding and passes silently as ordinary build
#     metadata; from then on that package's version can be changed beyond
#     the cut invisibly. Reproduced against the real scan. The longest real
#     version on either captured pair is 37 characters, so refusing to
#     compare one over 120 costs nothing legitimate.
LONGV="v1.0.0+build.$(printf 'a%.0s' $(seq 1 140))"
jq --arg v "$LONGV" '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then .Version = $v else . end ]' "$BVV" > "$WORK/t41.json"
run_cov "$WORK/t41.json" "$BVV"
check "a version longer than the comparison cut blocks (truncation collision)" block

# 42. A long version in the BASELINE blocks too. The plant has to be accepted
#     once before it can be exploited, and a baseline already carrying one is
#     already blind for that row — the same reason a zero-package baseline is
#     fatal rather than skipped.
run_cov "$BVV" "$WORK/t41.json"
check "a long version in the baseline blocks as well" block

# 43. A realistic long-ish version still passes, so 41/42 are not a cap on
#     ordinary pseudo-versions. Go pseudo-versions on the real image run to
#     37 characters; this is 60.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5"
              then .Version = "v0.0.0-20260908205506-85c1c2202aba+incompatible.build1"
              else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "GO-2026-0001", PkgName: "example.com/mod-5",
          InstalledVersion: "v0.0.0-20260908205506-85c1c2202aba+incompatible.build1" },
        { VulnerabilityID: "GO-2026-0002", PkgName: "example.com/mod-9",
          InstalledVersion: "v1.0.0" } ]' "$BVV" > "$WORK/t43.json"
run_cov "$WORK/t43.json" "$BVV"
check "an ordinary long Go pseudo-version still passes" pass

# ---------------------------------------------------------------------------
# ROUND-2 REVIEW. The fixes above passed their own 43-case suite and were still
# wrong in two ways, both reproduced end to end by independent review. Each
# case below FAILS against the round-1 code and passes against the current
# gate, so they prove the bugs rather than asserting the fixes.

# 44. AN '@' IN THE BASELINE'S VERSION DEFEATED 5d's RATCHET. The ratchet
#     recovered the package name by splitting the `name@version` pair on its
#     LAST `@` -- correct when the NAME carries one (Go module paths do), wrong
#     when the VERSION does. The sanitizer charclass permits `@`, so an
#     attacker-chosen version survives into the compared string:
#     `name@v0.58.0@1` split to `name@v0.58.0`, which is in NEITHER name list,
#     so `comm -12` dropped the row and it was never counted.
#
#     The name is now read from `.Name` directly (pkg_versioned_names_for_type),
#     which has no parse step to confuse. Keep it that way: a split here is a
#     formatter and a parser that have to agree about attacker input.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if (.Version // "") != "" then .Version = (.Version + "@1") else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "GO-2026-5932", PkgName: "example.com/mod-5",
          InstalledVersion: "v1.0.0@1" } ]' "$BVV" > "$WORK/t44-base.json"
# Rebuild keeps every NAME, drops mod-5's Version key, and drops the finding.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then del(.Version)
              else (if (.Version // "") != "" then .Version = (.Version + "@1") else . end) end ]
    | (.Results[] | .Vulnerabilities) |= []' "$BVV" > "$WORK/t44.json"
run_cov "$WORK/t44.json" "$WORK/t44-base.json"
check "an '@' in the baseline version cannot hide a dropped version (5d ratchet)" block

# 45. The same shape with a PLAIN version is the control: it blocked before
#     this fix too, which is what localises 44 to the `@` rather than to the
#     ratchet being broken in general.
jq '(.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "GO-2026-5932", PkgName: "example.com/mod-5",
          InstalledVersion: "v1.0.0" } ]' "$BVV" > "$WORK/t45-base.json"
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then del(.Version) else . end ]
    | (.Results[] | .Vulnerabilities) |= []' "$BVV" > "$WORK/t45.json"
run_cov "$WORK/t45.json" "$WORK/t45-base.json"
check "the same drop with a plain version blocks (control for 44)" block

# 46. AN EMPTY VulnerabilityID ESCAPED 5c's ID SET. `ids_from` keys findings on
#     "\($id)\t\($pkg)" with no filter on $id, so a row whose VulnerabilityID is
#     "" or absent IS a finding gate 1 counts -- but `vuln_ids_for_pkg` ended
#     with `select(. != "")` and dropped it, so it was invisible to 5c and could
#     vanish while the package's version moved.
#
#     TWO defects, and fixing only the filter is not enough: with the filter
#     gone the lost set is a single EMPTY LINE, and command substitution strips
#     that to a zero-length string, so `[ -n "$lost_ids" ]` still read "nothing
#     lost". The count is therefore taken with `wc -l`, which counts the line
#     the string cannot hold. Do not fold this back into an emptiness test.
jq '(.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-2026-1111", PkgName: "example.com/mod-5",
          InstalledVersion: "v1.0.0" },
        { VulnerabilityID: "", PkgName: "example.com/mod-5",
          InstalledVersion: "v1.0.0" } ]' "$BVV" > "$WORK/t46-base.json"
# Rebuild moves mod-5's version, KEEPS the real CVE, drops only the empty-id row.
jq '(.Results[] | select(.Type == "gobinary") | .Packages) |=
      [ .[] | if .Name == "example.com/mod-5" then .Version = "v9.9.9" else . end ]
    | (.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-2026-1111", PkgName: "example.com/mod-5",
          InstalledVersion: "v9.9.9" } ]' "$BVV" > "$WORK/t46.json"
run_cov "$WORK/t46.json" "$WORK/t46-base.json"
check "an empty VulnerabilityID is a finding 5c must not lose" block

# 47. An ABSENT VulnerabilityID key behaves identically to an empty one --
#     `ids_from` renders both as "", so 5c must too. Separate case because the
#     `// ""` default is easy to drop on one side while keeping it on the other.
jq '(.Results[] | select(.Type == "gobinary") | .Vulnerabilities) |=
      [ { VulnerabilityID: "CVE-2026-1111", PkgName: "example.com/mod-5",
          InstalledVersion: "v1.0.0" },
        { PkgName: "example.com/mod-5", InstalledVersion: "v1.0.0" } ]' \
   "$BVV" > "$WORK/t47-base.json"
run_cov "$WORK/t46.json" "$WORK/t47-base.json"
check "an absent VulnerabilityID key behaves like an empty one" block

# ---------------------------------------------------------------------------
# T-0811: check 5e, the ABSOLUTE floor pinned to a committed fixture.
#
# These cases use a DEGRADED baseline, because that is the whole point of 5e:
# against a healthy baseline the relative floors already block, so a case run
# against "$B" would not distinguish 5e from check 5 and would still pass if
# 5e were deleted. The baseline here is the T-0811 ratchet's late output (8 Go
# modules), which every relative floor is satisfied by -- measured as rc=0
# "scan coverage OK" -- and which only a fixture can object to.

# A fixture document in the committed shape.
mkfixture() {
  local out="$1" n="$2" pct="$3" type="${4:-gobinary}" target="${5:-usr/bin/caddy}"
  jq -n --argjson n "$n" --argjson pct "$pct" \
        --arg type "$type" --arg target "$target" '
    { schema: 1, captured: "2026-11-25", source_digest: "sha256:test",
      type: $type, target: $target, floor_percent: $pct,
      names: [ range(0; $n) | "example.com/mod-" + (. | tostring) ] }' > "$out"
}

FX="$WORK/floor.json"
mkfixture "$FX" 237 50

# The degraded baseline the ratchet reaches, and a rebuild below it.
mkscan "$WORK/t48-base.json" 32 8 real usr/bin/caddy
mkscan "$WORK/t48.json" 32 4 real usr/bin/caddy

# 48. CONTROL, fixture OFF. The degraded baseline accepts a 4-module rebuild.
#     Asserted as a PASS so the cases below cannot be satisfied by a relative
#     floor having changed: this is the hole, demonstrated.
COVERAGE_FLOOR_FILE="" run_cov "$WORK/t48.json" "$WORK/t48-base.json"
check "control: degraded baseline accepts a 4-module rebuild with no fixture" pass

# 49. THE CARD'S THESIS. Same pair, fixture ON: 4/237 is 2%, floor is 119.
#     Nothing about the baseline changed -- only that the standard is now
#     pinned to a release rather than to whatever :stable reports.
COVERAGE_FLOOR_FILE="$FX" run_cov "$WORK/t48.json" "$WORK/t48-base.json"
check "fixture blocks what a degraded baseline accepts (5e)" block

# 50. The ratchet's step 2, which T-0811 measured as the first one a fixture
#     stops outright: 60/237 = 25% against a 119 floor.
mkscan "$WORK/t50-base.json" 32 119 real usr/bin/caddy
mkscan "$WORK/t50.json" 32 60 real usr/bin/caddy
COVERAGE_FLOOR_FILE="$FX" run_cov "$WORK/t50.json" "$WORK/t50-base.json"
check "ratchet step 2 (60/237) blocks against the fixture" block

# 51. Step 1 is MARGINAL by design: 119/237 is exactly the 50% floor, so it
#     passes. Documented rather than tightened -- the floor is loose for the
#     same reason every other floor here is, and this is the boundary.
mkscan "$WORK/t51.json" 32 119 real usr/bin/caddy
COVERAGE_FLOOR_FILE="$FX" run_cov "$WORK/t51.json" "$B"
check "ratchet step 1 (119/237) is exactly at the floor and passes" pass

# 52. A healthy rebuild passes with the fixture on. This is the legitimacy
#     case: measured Go-module name retention across 21 real captured pairs is
#     99-100%, so an ordinary release must not notice 5e at all.
COVERAGE_FLOOR_FILE="$FX" run_cov "$WORK/t1.json" "$B"
check "identical rebuild still passes with the fixture on" pass

# 53. Ordinary upward churn passes too (the real release shape: names retained,
#     a few added).
COVERAGE_FLOOR_FILE="$FX" run_cov "$WORK/t2.json" "$B"
check "ordinary upward churn passes with the fixture on" pass

# 54. A STALE fixture degrades PERMISSIVELY, never restrictively. This is the
#     claim that removed the card's main objection -- "a release blocked by a
#     stale fixture" -- so it is asserted rather than argued. A fixture pinning
#     only 100 names (behind the real 237) asserts LESS, and cannot block.
mkfixture "$WORK/t54-fx.json" 100 50
COVERAGE_FLOOR_FILE="$WORK/t54-fx.json" run_cov "$WORK/t1.json" "$B"
check "a stale (behind) fixture asserts less and cannot block" pass

# 55. THE DECOY-BINARY BYPASS, which check 7 was written for and which 5e must
#     not reopen one level out. usr/bin/caddy is gutted to 4 modules while a
#     SECOND Go binary at usr/bin/helper carries all 237 fixture names. A
#     type-level intersection reads 237/237; the per-target one reads 4/237.
jq --argjson n 237 '
  .Results += [ { Target: "usr/bin/helper", Class: "lang-pkgs", Type: "gobinary",
                  Packages: [ range(0; $n)
                              | { Name: ("example.com/mod-" + (. | tostring)) } ],
                  Vulnerabilities: [] } ]' "$WORK/t48.json" > "$WORK/t55.json"
COVERAGE_FLOOR_FILE="$FX" run_cov "$WORK/t55.json" "$WORK/t48-base.json"
check "a decoy Go binary cannot pay for the shipped binary's floor (5e per-target)" block

# 56. An UNPARSEABLE fixture is a hard stop, not a skip. A check that turns
#     itself off when its own input is corrupted is the fail-open shape this
#     whole function exists to close, and it is the cheapest thing to attack:
#     truncate one byte.
printf '{ "schema": 1, "names": [ ' > "$WORK/t56-fx.json"
COVERAGE_FLOOR_FILE="$WORK/t56-fx.json" run_cov "$WORK/t1.json" "$B"
check "a truncated fixture blocks rather than skipping the check" block

# 57. A fixture of the WRONG SCHEMA blocks. Separate from 56 because valid JSON
#     missing the fields reads as null rather than failing to parse, and a
#     `// 0` default on the wrong side would accept it.
printf '{ "names": ["example.com/mod-0"] }' > "$WORK/t57-fx.json"
COVERAGE_FLOOR_FILE="$WORK/t57-fx.json" run_cov "$WORK/t1.json" "$B"
check "a fixture with no schema/type/target blocks" block

# 58. An EMPTY names array blocks. It parses, it looks configured, and it
#     asserts nothing -- the quietest way to disable 5e while leaving a
#     plausible file committed.
mkfixture "$WORK/t58-fx.json" 0 50
COVERAGE_FLOOR_FILE="$WORK/t58-fx.json" run_cov "$WORK/t1.json" "$B"
check "an empty fixture names array blocks rather than asserting nothing" block

# 59. An OS-LAYER fixture is REFUSED, enforcing scoping (1) rather than only
#     documenting it. alpine names legitimately drop to ~65% on a minor bump
#     (measured under T-0810), so such a fixture would block the refresh it
#     exists to protect, and would then be switched off for everything.
mkfixture "$WORK/t59-fx.json" 32 50 alpine "applegater/caddyui-caddy:stable (alpine 3.24.4)"
COVERAGE_FLOOR_FILE="$WORK/t59-fx.json" run_cov "$WORK/t1.json" "$B"
check "an alpine-typed fixture is refused (gobinary-only scoping)" block

# 60. A floor_percent outside 1-100 blocks. 0 asserts nothing, which is the
#     same quiet-disable shape as case 58 by a different field.
mkfixture "$WORK/t60-fx.json" 237 0
COVERAGE_FLOOR_FILE="$WORK/t60-fx.json" run_cov "$WORK/t1.json" "$B"
check "floor_percent=0 blocks rather than asserting nothing" block

# 61. An ABSENT fixture is NOT a fault: the script is run by hand and from
#     worktrees predating the file, and every check above still ran. Passes,
#     and the NOTE is what makes "5e did not run" visible.
COVERAGE_FLOOR_FILE="$WORK/does-not-exist.json" run_cov "$WORK/t1.json" "$B"
check "an absent fixture skips 5e and passes" pass

# 62. ...and the skip is NOTED, not silent. Asserted on the output, because a
#     silent skip is indistinguishable from a pass and that is how a check
#     stays off after someone moves the file.
if printf '%s' "$COV_OUT" | grep -q 'absolute floor (check 5e) did not run'; then
  printf 'ok   an absent fixture says so in the output\n'; PASS=$((PASS + 1))
else
  printf 'FAIL an absent fixture says so in the output\n     %s\n' "$COV_OUT"
  FAIL=$((FAIL + 1))
fi

# 63. The COMMITTED fixture, against the real :stable scan shape it was built
#     from. Guards the thing most likely to break silently: a fixture rendered
#     differently from the scan side (sanitization, sort order, locale) would
#     under-report the intersection and block legitimate releases. Skipped
#     rather than failed when the real scan is not available locally, since
#     this harness is meant to run in seconds without a scan.
REAL_FX="$HERE/fixtures/caddy-image-coverage-floor.json"
REAL_SCAN="${T0811_REAL_SCAN:-}"
if [ -r "$REAL_FX" ] && [ -n "$REAL_SCAN" ] && [ -r "$REAL_SCAN" ]; then
  COVERAGE_FLOOR_FILE="$REAL_FX" run_cov "$REAL_SCAN" "$REAL_SCAN"
  check "the committed fixture matches the real :stable scan it was built from" pass
else
  printf 'skip the committed fixture vs the real scan (set T0811_REAL_SCAN to run)\n'
fi


# 64. The fixture is captured from ONE arch, and the gate runs per arch, so it
#     must not block the other. Go module NAMES come from the source dependency
#     graph rather than the build target, so they do not vary by arch -- but
#     that is a claim worth holding down, because a fixture that blocked arm64
#     would be found at release time, on the path that moves :stable.
#     Measured on the live image: the amd64-captured 237 names intersect the
#     real arm64 scan at 237/237.
if [ -r "$REAL_FX" ] && [ -n "${T0811_REAL_SCAN_ARM64:-}" ] && [ -r "${T0811_REAL_SCAN_ARM64:-}" ]; then
  COVERAGE_FLOOR_FILE="$REAL_FX" run_cov "$T0811_REAL_SCAN_ARM64" "$T0811_REAL_SCAN_ARM64"
  check "the amd64-captured fixture does not block the arm64 scan" pass
else
  printf 'skip the fixture vs the real arm64 scan (set T0811_REAL_SCAN_ARM64 to run)\n'
fi


# 65. A DUPLICATE .Target cannot pay for a gutted binary's floor.
#     Found by probing 5e rather than by reading it: .Target is metadata the
#     submitted image controls, and pkg_names_for_target aggregates every
#     result matching it, so a second result filed under the SAME path carries
#     the fixture's names while the real one is gutted and all findings vanish.
#     This shape ALSO defeats checks 5 and 7 as they stand (verified: it passes
#     with COVERAGE_FLOOR_FILE empty), which is tracked separately -- the point
#     here is that 5e, the floor a rebuild cannot fabricate past, must not
#     inherit it.
jq '([.Results[]?|select(.Type=="gobinary")|.Vulnerabilities[]?.PkgName]|unique) as $v
  | ([.Results[]|select(.Type=="gobinary")|.Packages[]]) as $all
  | .Results = ([.Results[] | if .Type=="gobinary"
        then (.Packages = [$all[]|select(([.Name]|inside($v)))]) | (.Vulnerabilities = [])
        else . end]
      + [{Target:"usr/bin/caddy", Class:"lang-pkgs", Type:"gobinary",
          Packages:$all, Vulnerabilities:[]}])' "$B" > "$WORK/t65.json"
mkfixture "$WORK/t65-fx.json" 237 50
COVERAGE_FLOOR_FILE="$WORK/t65-fx.json" run_cov "$WORK/t65.json" "$B"
check "a duplicate .Target cannot pay for a gutted binary's absolute floor" block

# 66. A fixture path that EXISTS but is not a regular file is a hard stop, not
#     a skip. `-f` is false for a directory and for a dangling symlink, so the
#     first spelling treated both as "absent" and skipped -- fail-open on two
#     states that are faults rather than configurations.
mkdir -p "$WORK/t66-dir.json"
COVERAGE_FLOOR_FILE="$WORK/t66-dir.json" run_cov "$WORK/t1.json" "$B"
check "a directory at the fixture path blocks rather than skipping" block

# 67. The same for a DANGLING symlink, which is the likelier accident (a moved
#     or pruned fixture) and reads as absent to `-f`.
ln -sfn "$WORK/definitely-not-here.json" "$WORK/t67-link.json"
COVERAGE_FLOOR_FILE="$WORK/t67-link.json" run_cov "$WORK/t1.json" "$B"
check "a dangling symlink at the fixture path blocks rather than skipping" block

# 68. An unwritable $OUT must not report the floor as satisfied. The scratch
#     lists 5e compares are written there, and an unchecked redirect would make
#     `comm` read nothing -- a computed-as-zero floor, or worse a cleared one.
COV_RC=0
COV_OUT="$( (
    OUT="/proc/t0811-cannot-exist"
    export OUT
    # shellcheck disable=SC2034  # read by assert_scan_coverage, called below
    COVERAGE_FLOOR_FILE="$FX"
    assert_scan_coverage "$WORK/t1.json" "$B" amd64
  ) 2>&1 )" || COV_RC=$?
check "an unwritable \$OUT blocks rather than reporting the floor satisfied" block

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
