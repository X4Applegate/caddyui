#!/usr/bin/env bash
# test-go-toolchain-watch.sh — regression tests for scripts/check-go-toolchain.sh (T-0745).
#
# WHAT IS WORTH ASSERTING HERE. The script answers "is the pinned Go toolchain
# covered by a published advisory?". It has exactly two interesting failure
# modes and neither is a crash:
#
#   1. A REASSURING ANSWER IT WAS NOT ENTITLED TO GIVE. An unreachable release
#      list, an unparsable index, an advisory that could not be fetched — each
#      must reach `could not run` (exit 3), never `ok`. This is the discipline
#      T-0634/T-0646/T-0669 were all filed about, and it is the reason the
#      default arm of every classification in the script is the failure.
#
#   2. CRYING WOLF ON A BACKPORT. Go fixes a stdlib bug on two release
#      branches at once, and `index/modules.json` records only the HIGHEST fix
#      — GO-2026-6859 reads `fixed: 1.27.4` while it is equally fixed in
#      1.26.11. A check that believed the index would report a correctly
#      patched 1.26.11 toolchain as vulnerable every week, and a weekly false
#      alarm is how a report stops being read. So the index is a shortlist and
#      each candidate's own OSV ranges decide. Case 4 is that assertion, and
#      it fails on the obvious implementation.
#
# EVERY CASE IS OFFLINE. The three fixture flags replace all three network
# calls, so this suite runs on a PR with no outbound access. Fixtures live in
# scripts/fixtures/go-toolchain/ and are REAL responses, trimmed to the fields
# the script reads: a hand-written range would test the test's idea of OSV
# rather than OSV.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/check-go-toolchain.sh"
FIX="$HERE/fixtures/go-toolchain"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
want_rc() { if [ "$RC" = "$1" ]; then ok "$2"; else bad "$2 (exit $RC, expected $1)"; fi; }
want_in() { if grep -qF -- "$1" "$OUT"; then ok "$2"; else bad "$2 (output does not contain '$1')"; fi; }
want_not_in() { if grep -qF -- "$1" "$OUT"; then bad "$2 (output contains '$1' and must not)"; else ok "$2"; fi; }

[ -x "$SCRIPT" ] || { echo "FAIL: $SCRIPT is missing or not executable"; exit 1; }
for f in go-releases.json vuln-index.json; do
  [ -f "$FIX/$f" ] || { echo "FAIL: fixture $FIX/$f is missing"; exit 1; }
done

n=0
run() { # run <pinned> [extra args...]
  n=$((n+1))
  local pin="$1"; shift
  OUT="$TMP/out.$n"
  rm -rf "$TMP/o.$n"
  "$SCRIPT" --toolchain "$pin" --out-dir "$TMP/o.$n" \
    --releases-fixture "$FIX/go-releases.json" \
    --index-fixture "$FIX/vuln-index.json" \
    --advisory-dir "$FIX/advisories" \
    "$@" > "$OUT" 2>&1
  RC=$?
}

# Same, but with the fixture paths under the caller's control so a missing or
# broken input can be driven.
run_raw() {
  n=$((n+1))
  OUT="$TMP/out.$n"
  rm -rf "$TMP/o.$n"
  "$SCRIPT" --out-dir "$TMP/o.$n" "$@" > "$OUT" 2>&1
  RC=$?
}

echo "check-go-toolchain.sh:"

# ---------------------------------------------------------------------------
# 1. The current pin is clean. The fixture's newest stable IS go1.27.4 and
#    every fixture advisory is fixed at or below it.
# ---------------------------------------------------------------------------
run go1.27.4
want_rc 0 "1  a current, unaffected toolchain is ok (exit 0)"
want_in "is current and no advisory applies" "1a report says current"
want_not_in "Advisories whose affected range covers" "1b no advisory table on a clean run"

# ---------------------------------------------------------------------------
# 2. One patch behind on the SAME branch, and covered by advisories. The
#    urgent verdict must win over the staleness one — an advisory beats
#    behind, the same precedence check-pinned-modules.sh uses.
# ---------------------------------------------------------------------------
run go1.27.3
want_rc 2 "2  a toolchain covered by an advisory is exit 2"
want_in "GO-2026-6859" "2a names the stdlib advisory"
want_in "GO-2026-6848" "2b names the toolchain advisory, not only the stdlib one"
want_in "a published advisory covers" "2c the heading states the advisory, not the staleness"
want_in "1.26.11, 1.27.4" "2d lists BOTH branch fixes, so a reader can pick the right bump"

# ---------------------------------------------------------------------------
# 3. go1.27.3 is NOT affected by GO-2026-6809 (fixed in 1.27.3), and that
#    must be ruled out by range rather than by the index's single `fixed`.
# ---------------------------------------------------------------------------
want_not_in "GO-2026-6809" "3  an advisory fixed exactly at the pinned version is ruled out"

# ---------------------------------------------------------------------------
# 4. THE BACKPORT CASE — the one that fails on the obvious implementation.
#
#    go1.26.11 is the newest release on its own branch and carries the
#    backported fixes for GO-2026-6859 and GO-2026-6848. The index says both
#    are `fixed: 1.27.4`, which is ABOVE 1.26.11, so an implementation that
#    trusted the index would report two advisories against a fully patched
#    toolchain. Ruling them out requires walking the ranges.
# ---------------------------------------------------------------------------
run go1.26.11
want_rc 0 "4  a backport-patched toolchain on the older supported branch is ok"
want_not_in "GO-2026-6859" "4a the 1.26 backport is recognised (index alone would cry wolf)"
want_not_in "GO-2026-6848" "4b same for the toolchain advisory"
want_in "ruled out by range" "4c the report says how they were ruled out"

# ---------------------------------------------------------------------------
# 5. Behind on its own branch, and affected. 1.26.9 predates the 1.26.10 fix
#    for GO-2026-6809 as well as the 1.26.11 ones.
# ---------------------------------------------------------------------------
run go1.26.9
want_rc 2 "5  an out-of-date toolchain on a supported branch is exit 2"
want_in "GO-2026-6809" "5a the branch-only advisory is found"
want_in "GO-2026-6859" "5b and the one fixed one patch later"

# ---------------------------------------------------------------------------
# 6. Behind, but NOT affected: 1.27.4 is current, so construct staleness with
#    a release list whose newest 1.27 is higher than the pin while no fixture
#    advisory covers it.
# ---------------------------------------------------------------------------
cat > "$TMP/rel-future.json" <<'JSON'
[{"version":"go1.27.9","stable":true},{"version":"go1.26.11","stable":true}]
JSON
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
"$SCRIPT" --toolchain go1.27.4 --out-dir "$TMP/o.$n" \
  --releases-fixture "$TMP/rel-future.json" \
  --index-fixture "$FIX/vuln-index.json" \
  --advisory-dir "$FIX/advisories" > "$OUT" 2>&1
RC=$?
want_rc 1 "6  behind on its own branch with no advisory is attention (exit 1), not ok"
want_in "is behind, no advisory applies" "6a the heading separates staleness from an advisory"
want_in "behind \`go1.27.9\`" "6b names the release it is behind"

# ---------------------------------------------------------------------------
# 7. An UNSUPPORTED branch. Go supports the two newest; a pin on an older one
#    gets no further fixes, so "no advisory applies" is a much weaker
#    statement and must be labelled as such rather than reported as ok.
# ---------------------------------------------------------------------------
#    go1.24.3 is ALSO covered by the fixture advisories whose range starts at
#    `introduced: 0`, which is the honest result: an advisory beats a
#    branch-support note. So the branch warning is asserted alongside exit 2
#    rather than instead of it.
run go1.24.3
want_rc 2 "7  an unsupported branch covered by an open-ended range is exit 2"
want_in "not one of the supported stable branches" "7a says the branch is unsupported anyway"
want_in "receives no further security fixes" "7b says what that means"

#    And where nothing in the index covers it, the unsupported branch is the
#    only finding -- which must still not be `ok`, because "no advisory is
#    published against it" is not "it is maintained".
cat > "$TMP/idx-old-only.json" <<'JSON'
[{"path":"stdlib","vulns":[{"id":"GO-2021-0067","fixed":"1.16.1"}]},
 {"path":"toolchain","vulns":[]}]
JSON
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
"$SCRIPT" --toolchain go1.24.3 --out-dir "$TMP/o.$n" \
  --releases-fixture "$FIX/go-releases.json" --index-fixture "$TMP/idx-old-only.json" \
  --advisory-dir "$FIX/advisories" > "$OUT" 2>&1
RC=$?
want_rc 1 "7c an unsupported branch with no applicable advisory is attention, never ok"
want_in "not one of the supported stable branches" "7d and says why"

# ---------------------------------------------------------------------------
# 8. An `introduced:` that is not 0. GO-2021-0067 runs [1.16.0-0, 1.16.1), so
#    a 1.16.0 pin is inside it and a 1.15.x pin is BELOW the introduced
#    version and therefore not affected. A walk that ignored `introduced`
#    would report 1.15 as vulnerable.
# ---------------------------------------------------------------------------
cat > "$TMP/rel-116.json" <<'JSON'
[{"version":"go1.16.1","stable":true},{"version":"go1.15.9","stable":true}]
JSON
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
"$SCRIPT" --toolchain go1.16.0 --out-dir "$TMP/o.$n" \
  --releases-fixture "$TMP/rel-116.json" --index-fixture "$FIX/vuln-index.json" \
  --advisory-dir "$FIX/advisories" > "$OUT" 2>&1
RC=$?
want_rc 2 "8  a pin inside a non-zero introduced range is affected"
want_in "GO-2021-0067" "8a names it"

n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
"$SCRIPT" --toolchain go1.15.9 --out-dir "$TMP/o.$n" \
  --releases-fixture "$TMP/rel-116.json" --index-fixture "$FIX/vuln-index.json" \
  --advisory-dir "$FIX/advisories" > "$OUT" 2>&1
RC=$?
want_not_in "GO-2021-0067" "8b a pin BELOW the introduced version is not affected"

# ---------------------------------------------------------------------------
# 9. EXPLICIT UNKNOWN, four ways. Each must be exit 3 and must not say ok.
# ---------------------------------------------------------------------------
run_raw --toolchain go1.27.4 --releases-fixture "$TMP/nope.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$FIX/advisories"
want_rc 3 "9  an unreadable release list is could-not-run"
want_in "could not run" "9a and says so"
want_not_in "is current and no advisory applies" "9b and never says current"

echo '{"message":"API rate limit exceeded"}' > "$TMP/rel-obj.json"
run_raw --toolchain go1.27.4 --releases-fixture "$TMP/rel-obj.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$FIX/advisories"
want_rc 3 "10 a JSON OBJECT where an array was expected is could-not-run"
want_in "not a JSON array" "10a names the reason (a rate-limit body must not read as zero releases)"

echo '[]' > "$TMP/rel-empty.json"
run_raw --toolchain go1.27.4 --releases-fixture "$TMP/rel-empty.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$FIX/advisories"
want_rc 3 "11 a release list with no stable release is could-not-run"
want_in "contains no stable release" "11a names the reason"

# An index missing the stdlib/toolchain entries entirely. Zero candidates
# would otherwise parse to a clean run, which is the exact fail-open shape.
echo '[{"path":"github.com/foo/bar","vulns":[]}]' > "$TMP/idx-wrong.json"
run_raw --toolchain go1.27.4 --releases-fixture "$FIX/go-releases.json" \
  --index-fixture "$TMP/idx-wrong.json" --advisory-dir "$FIX/advisories"
want_rc 3 "12 an index with no stdlib/toolchain entry is could-not-run, not zero findings"
want_in "not the index this check knows how to read" "12a names the reason"

# A candidate advisory that cannot be fetched. One missing advisory makes the
# whole answer partial, so it is exit 3 even though the others came back.
mkdir -p "$TMP/adv-partial"
cp "$FIX/advisories/GO-2026-6859.json" "$TMP/adv-partial/"
run_raw --toolchain go1.27.3 --releases-fixture "$FIX/go-releases.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$TMP/adv-partial"
want_rc 3 "13 one unreadable candidate advisory is could-not-run, not a partial all-clear"
want_in "is not an answer" "13a says a partial answer is not an answer"

# A candidate whose advisory file is not an OSV record.
mkdir -p "$TMP/adv-junk"
cp "$FIX"/advisories/*.json "$TMP/adv-junk/"
echo 'not json at all' > "$TMP/adv-junk/GO-2026-6859.json"
run_raw --toolchain go1.27.3 --releases-fixture "$FIX/go-releases.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$TMP/adv-junk"
want_rc 3 "14 an unparsable advisory is could-not-run"
want_in "did not parse as an OSV record" "14a names the reason"

# ---------------------------------------------------------------------------
# 15. The pinned toolchain is read from go.mod, with the `toolchain` directive
#     beating the `go` directive — that is what CI's `go-version-file: go.mod`
#     resolves, so judging the `go` line when a toolchain line exists would
#     report on a version nothing builds with.
# ---------------------------------------------------------------------------
cat > "$TMP/go.mod" <<'EOF'
module example.com/x

go 1.26.0

toolchain go1.27.3
EOF
run_raw --gomod "$TMP/go.mod" --releases-fixture "$FIX/go-releases.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$FIX/advisories"
want_rc 2 "15 the toolchain directive is read from go.mod"
want_in "toolchain directive in" "15a and the report says where the version came from"
want_in "go1.27.3" "15b the toolchain line wins over the go line"

cat > "$TMP/go-noline.mod" <<'EOF'
module example.com/x

go 1.27.3
EOF
run_raw --gomod "$TMP/go-noline.mod" --releases-fixture "$FIX/go-releases.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$FIX/advisories"
want_rc 2 "16 with no toolchain line the go directive is used"
want_in "there is no toolchain line" "16a and the absence is stated, not hidden"

cat > "$TMP/go-bad.mod" <<'EOF'
module example.com/x
EOF
run_raw --gomod "$TMP/go-bad.mod" --releases-fixture "$FIX/go-releases.json" \
  --index-fixture "$FIX/vuln-index.json" --advisory-dir "$FIX/advisories"
want_rc 3 "17 a go.mod with no version at all is could-not-run"

# ---------------------------------------------------------------------------
# 18. A fixture run must SAY it used fixtures. A green report from canned data
#     is not evidence about today, and the weekly job's reader cannot tell the
#     difference from the table alone.
# ---------------------------------------------------------------------------
run go1.27.4
want_in "used fixtures, not live data" "18 a fixture run discloses that it used fixtures"

# ---------------------------------------------------------------------------
# 19. Outputs for the workflow. A verdict file and GITHUB_OUTPUT keys, because
#     the `Flag the result` style step keys off them rather than on exit codes.
# ---------------------------------------------------------------------------
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
GITHUB_OUTPUT="$TMP/gh.$n" GITHUB_STEP_SUMMARY="$TMP/sum.$n" \
  "$SCRIPT" --toolchain go1.27.3 --out-dir "$TMP/o.$n" \
  --releases-fixture "$FIX/go-releases.json" --index-fixture "$FIX/vuln-index.json" \
  --advisory-dir "$FIX/advisories" > "$OUT" 2>&1
RC=$?
OUT="$TMP/gh.$n"
want_in "verdict=advisory" "19 writes verdict= to GITHUB_OUTPUT"
want_in "rc=2" "19a writes rc="
want_in "pinned=go1.27.3" "19b writes the version it judged"
OUT="$TMP/o.$n/verdict"
want_in "advisory" "19c writes the verdict file"
OUT="$TMP/sum.$n"
want_in "a published advisory covers" "19d appends to the step summary"

# An unknown run must write verdict=unknown rather than leaving the key empty:
# an empty verdict read by a `case` with a success default is the fail-open
# shape the pin watch had to fix.
n=$((n+1)); rm -rf "$TMP/o.$n"
GITHUB_OUTPUT="$TMP/gh.$n" "$SCRIPT" --toolchain go1.27.4 --out-dir "$TMP/o.$n" \
  --releases-fixture "$TMP/nope.json" --index-fixture "$FIX/vuln-index.json" \
  --advisory-dir "$FIX/advisories" > /dev/null 2>&1
OUT="$TMP/gh.$n"
want_in "verdict=unknown" "20 a could-not-run writes verdict=unknown, not an empty key"
want_in "advisories=unknown" "20a and does not report 0 advisories"

# ---------------------------------------------------------------------------
# 21. Argument handling: an unknown flag is exit 3, not a silently ignored
#     option that makes the run mean something else.
# ---------------------------------------------------------------------------
n=$((n+1)); OUT="$TMP/out.$n"
"$SCRIPT" --not-a-flag > "$OUT" 2>&1; RC=$?
want_rc 3 "21 an unknown argument is rejected with the could-not-run status"

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
