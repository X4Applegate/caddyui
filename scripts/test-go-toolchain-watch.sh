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

# ---------------------------------------------------------------------------
# 22. AFFECTEDNESS IS A UNION OVER RANGES, NOT A FOLD ACROSS THEM, so the
#     verdict cannot depend on the order OSV happens to list `affected` in.
#
#     An advisory patched on two release branches carries one `affected`
#     entry per branch, and OSV guarantees no ordering between them. Folding
#     a single state variable over the concatenation loses findings: for the
#     real GO-2026-6603 (fixed 1.26.9 AND 1.27.2) against a pinned go1.27.0,
#     the 1.27 entry sets affected, and then the 1.26 entry's `fixed 1.26.9`
#     satisfies `1.27.0 >= 1.26.9` and clears it again. A genuinely affected
#     toolchain then reported "no advisory applies" with `advisories=0`, so
#     the weekly alert stayed silent -- the exact crying-wolf-in-reverse this
#     file's header says case 4 guards the other direction of.
#
#     Both orderings of the SAME real record must reach exit 2. Six live
#     stdlib advisories have this two-entry shape.
# ---------------------------------------------------------------------------
IDX22="$TMP/idx22.json"
cat > "$IDX22" <<'JSON'
[
  { "path": "stdlib", "vulns": [ { "id": "GO-2026-6603", "modified": "2026-10-08T22:31:09Z", "fixed": "1.27.2" } ] },
  { "path": "toolchain", "vulns": [] }
]
JSON
mkdir -p "$TMP/adv22-fwd" "$TMP/adv22-rev"
cp "$FIX/advisories/GO-2026-6603.json" "$TMP/adv22-fwd/GO-2026-6603.json"
jq '.affected = [ .affected[1], .affected[0] ]'   "$FIX/advisories/GO-2026-6603.json" > "$TMP/adv22-rev/GO-2026-6603.json"

for ord in fwd rev; do
  n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
  "$SCRIPT" --toolchain go1.27.0 --out-dir "$TMP/o.$n" \
    --releases-fixture "$FIX/go-releases.json" \
    --index-fixture "$IDX22" --advisory-dir "$TMP/adv22-$ord" > "$OUT" 2>&1
  RC=$?
  want_rc 2 "22 a two-branch advisory covers the pin whichever order its entries are in ($ord)"
  want_in "GO-2026-6603" "22a and names it ($ord)"
done

# And the backport direction still holds on the same record: 1.27.2 IS the
# fix for the 1.27 branch, so a pin at or above it is clean rather than
# reported, even though the other entry's range is open below 1.26.9.
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
"$SCRIPT" --toolchain go1.27.2 --out-dir "$TMP/o.$n" \
  --releases-fixture "$FIX/go-releases.json" \
  --index-fixture "$IDX22" --advisory-dir "$TMP/adv22-rev" > "$OUT" 2>&1
RC=$?
want_rc 1 "22b a pin at the branch fix is not reported as covered"
want_in "no advisory" "22c and says no advisory applies"

# ---------------------------------------------------------------------------
# 23. A COMPARISON THAT COULD NOT BE MADE IS NOT A "NO".
#
#     `ge` returns 2 when either side is an unreadable version, and folding
#     that into an `if` puts it in the FALSE branch -- so an unparsable
#     `introduced` read as "the pin is below the affected range", i.e. clean,
#     and an unparsable `fixed` could clear an established affectedness. Both
#     reported `verdict=ok` on a candidate whose range was never evaluated,
#     which is the fail-open shape every other path in this script refuses.
#
#     An advisory record is third-party input. It does not have to be
#     well-formed for the answer to be honest -- it has to be ADMITTED as
#     unreadable.
# ---------------------------------------------------------------------------
IDX23="$TMP/idx23.json"
cat > "$IDX23" <<'JSON'
[
  { "path": "stdlib", "vulns": [ { "id": "GO-9999-0001", "modified": "2026-11-01T00:00:00Z", "fixed": "1.99.0" } ] },
  { "path": "toolchain", "vulns": [] }
]
JSON

mk23() { # mk23 <dir> <json>
  mkdir -p "$TMP/$1"
  printf '%s\n' "$2" > "$TMP/$1/GO-9999-0001.json"
}

mk23 adv23-badintro '{ "id": "GO-9999-0001", "summary": "unparsable introduced",
 "affected": [ { "package": { "name": "stdlib", "ecosystem": "Go" },
 "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "v1.0.0-beta.pseudo+meta.garbage" }, { "fixed": "1.99.0" } ] } ] } ] }'

mk23 adv23-badfixed '{ "id": "GO-9999-0001", "summary": "unparsable fixed",
 "affected": [ { "package": { "name": "stdlib", "ecosystem": "Go" },
 "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "not-a-version" } ] } ] } ] }'

mk23 adv23-norange '{ "id": "GO-9999-0001", "summary": "shortlisted for stdlib but carries no stdlib range",
 "affected": [ { "package": { "name": "golang.org/x/net", "ecosystem": "Go" },
 "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "0" }, { "fixed": "0.60.0" } ] } ] } ] }'

for c in badintro badfixed norange; do
  n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
  GITHUB_OUTPUT="$TMP/gh23.$c" "$SCRIPT" --toolchain go1.27.4 --out-dir "$TMP/o.$n" \
    --releases-fixture "$FIX/go-releases.json" \
    --index-fixture "$IDX23" --advisory-dir "$TMP/adv23-$c" > "$OUT" 2>&1
  RC=$?
  want_rc 3 "23 an unevaluable advisory range is could-not-run, not clean ($c)"
  want_in "could not run" "23a and says so ($c)"
  OUT="$TMP/gh23.$c"
  want_in "verdict=unknown" "23b and writes verdict=unknown ($c)"
  want_in "advisories=unknown" "23c and refuses to report an advisory count ($c)"
done

# ---------------------------------------------------------------------------
# 24. AN UNPARSED INDEX IS NOT AN EMPTY ONE.
#
#     The shortlist filter used to be read straight from a process
#     substitution, so a failing `jq` was invisible: the loop read nothing,
#     the candidate list stayed empty, and the run reported "0 candidates, no
#     advisory applies" with exit 0. The two guards before it do not cover
#     this -- an index can be a JSON array carrying BOTH the `stdlib` and
#     `toolchain` entries and still break the filter, e.g. when `vulns` is a
#     string rather than an array. That is a clean pass manufactured by a
#     parser that failed, which is the one thing this script must never do.
# ---------------------------------------------------------------------------
IDX24="$TMP/idx24.json"
cat > "$IDX24" <<'JSON'
[
  { "path": "stdlib", "vulns": "not-an-array" },
  { "path": "toolchain", "vulns": [] }
]
JSON

# It really does pass the two earlier guards, or this case would be proving
# something else.
n=$((n+1))
if jq -e 'type == "array"' "$IDX24" >/dev/null 2>&1 \
   && jq -e '[.[] | select(.path == "stdlib" or .path == "toolchain")] | length == 2' "$IDX24" >/dev/null 2>&1; then
  ok "24 the crafted index passes the array and both-entries guards"
else
  bad "24 the crafted index no longer passes the earlier guards, so case 24a proves nothing"
fi

n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
GITHUB_OUTPUT="$TMP/gh24" "$SCRIPT" --toolchain go1.27.4 --out-dir "$TMP/o.$n" \
  --releases-fixture "$FIX/go-releases.json" --index-fixture "$IDX24" > "$OUT" 2>&1
RC=$?
want_rc 3 "24a an index that cannot be parsed into rows is could-not-run, not clean"
want_in "could not run" "24b and says so"
want_in "not an empty one" "24c naming why an unparsed index is not an empty one"
OUT="$TMP/gh24"
want_in "verdict=unknown" "24d and writes verdict=unknown"
want_in "advisories=unknown" "24e and refuses to report an advisory count"

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
