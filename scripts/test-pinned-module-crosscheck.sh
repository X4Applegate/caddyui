#!/usr/bin/env bash
# Tests for check-pinned-modules.sh's GitHub advisory cross-check PACKAGE MATCH
# (T-0666).
#
#   ./scripts/test-pinned-module-crosscheck.sh      # exit 0 = all pass
#
# Sibling of test-pinned-module-floors.sh, which covers the floor mechanism.
# Split rather than appended because the two need different machinery: the
# floor tests drive the whole script with `--offline-fixture` and assert on
# counters, whereas the thing under test here is the jq predicate that decides
# whether a GitHub advisory record belongs to a given pin. Driving the whole
# script to reach it would need either a live network or a GitHub API stub, and
# would assert on a verdict several layers downstream of the decision.
#
# So the PREDICATE IS EXTRACTED FROM THE SHIPPED SCRIPT and run directly
# against JSON fixtures. Extracted, not copied: a copy is a second source of
# truth that passes forever after the original changes, which is the one
# failure mode a regression test must not have. If the extraction stops
# finding the program, that is a hard failure here rather than a silent skip.
#
# ---------------------------------------------------------------------------
# What this exists to catch
# ---------------------------------------------------------------------------
#
# The original match took the REPO ELEMENT of the module path (`.[2]`, i.e.
# "go-jose" for github.com/go-jose/go-jose/v4) and tested the advisory package
# name against it. That matched a SIBLING MAJOR VERSION of the same repo:
# go-jose publishes v3 and v4 together, and each of its five CVE-less
# advisories carries a v4 entry (`<= v4.1.6`, patched v4.1.7) AND a v3 entry
# (range `all`, no patch). The v3 entries attached themselves to the v4 pin,
# the downstream textual range filter could not drop a bound-less `all`, and
# the report rendered five live advisories against `go-jose/v4@v4.1.7` — the
# version that patches every one of them — with verdict=advisory.
#
# Case 1 is that exact shape and FAILS on the pre-T-0666 predicate.
#
# Cases 2-5 are the regression guard in the other direction, which is the one
# that matters more: every loosening the old predicate was deliberately built
# for must still match, because a dropped row is invisible and reads as a
# clean pin. Case 5 in particular (a package inside the module) was broken by
# the first attempt at this fix and would have hidden an advisory on one of
# the two CVE floors.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check-pinned-modules.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v jq >/dev/null 2>&1 || { echo "FATAL: jq is required" >&2; exit 1; }
[ -f "$SCRIPT" ] || { echo "FATAL: no such script: $SCRIPT" >&2; exit 1; }

pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS  %s\n' "$1"; pass=$((pass+1))
  else
    printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1))
  fi
}

# ---------------------------------------------------------------------------
# Extract the jq program from the shipped script.
#
# Anchored on the `jq -j --arg mod "$g_module"` invocation and its final
# `join(...)` line, then the shell wrapper is trimmed off both ends. The
# extracted text is compiled before any case runs, so a failed extraction or a
# jq syntax error is one loud failure here rather than N confusing ones.
#
# It also catches a trap that cost a cycle while writing the fix: the jq
# program is a SINGLE-QUOTED shell argument whose comments are part of that
# string, so an apostrophe in a comment ("this image's pins") terminates the
# argument and bash parses the rest of the filter as shell. That shows up as a
# bash syntax error on a jq line. `bash -n` on the real script is asserted
# first, below, so the next person to write a possessive in there is told.
# ---------------------------------------------------------------------------
bash -n "$SCRIPT" 2>"$WORK/bash-n.txt" \
  && check "the shipped script is syntactically valid bash" y y \
  || { check "the shipped script is syntactically valid bash" y n; sed 's/^/        /' "$WORK/bash-n.txt"; }

PRED="$WORK/pred.jq"
sed -n '/done < <(jq -j --arg mod "\$g_module"/,/join("\\u001f") + "\\u0000"/p' "$SCRIPT" \
  | sed '1s/^.*jq -j --arg mod "\$g_module" .//' \
  | sed "\$s/'.*\$//" > "$PRED"

if ! [ -s "$PRED" ]; then
  echo "FATAL: could not extract the cross-check jq program from $SCRIPT" >&2
  echo "       (did the jq invocation or its final join() line change shape?)" >&2
  exit 1
fi
# `--arg mod` is required: the program references $mod, and without it jq
# reports "$mod is not defined" as a COMPILE error, which the check below
# would then read as a broken program. Compiled against an empty array so
# there is no runtime output to discard either.
if ! jq -n --arg mod github.com/example/mod -f "$PRED" >/dev/null 2>"$WORK/jq-compile.txt"; then
  # `jq -n` on a program expecting an array errors at RUNTIME on null input,
  # which is fine and expected; only a COMPILE error means the program is
  # broken. They are distinguished by the message jq uses.
  if grep -qi 'compile error\|syntax error' "$WORK/jq-compile.txt"; then
    echo "FATAL: the extracted cross-check program does not compile:" >&2
    sed 's/^/       /' "$WORK/jq-compile.txt" >&2
    exit 1
  fi
fi
check "cross-check predicate extracted from the shipped script" y y

# The pre-T-0666 predicate, kept verbatim so case 1 can be shown to fail on it
# and pass on the current one. Without this, "the test passes" says nothing
# about whether it would have caught the bug.
OLD_PRED="$WORK/old.jq"
cat > "$OLD_PRED" <<'OLDJQ'
.[]
| . as $a
| (.vulnerabilities // [])[]
| select((.package.name // "") | ascii_downcase
         | (test("(^|[/ ])" + ($mod | ascii_downcase | split("/") | .[2] | gsub("\\."; "\\\\.")) + "($|[/ @])")
            or test($mod | ascii_downcase | gsub("\\."; "\\\\."))))
| [ ($a.ghsa_id // ""), ($a.cve_id // ""), ($a.severity // ""),
    (.vulnerable_version_range // "") ]
| join("\u001f") + "\u0000"
OLDJQ

# Run a predicate and print the matched GHSA ids, space-separated and sorted
# so a case asserts on a set rather than on jq traversal order.
matches() { # $1=predicate-file $2=fixture $3=module
  jq -j --arg mod "$3" -f "$1" "$2" 2>/dev/null \
    | tr '\0' '\n' | awk -F'\x1f' 'NF {print $1}' | sort | paste -sd' ' - | sed 's/ *$//'
}

# ---------------------------------------------------------------------------
# Fixtures. Shapes are taken from REAL observed API responses, not invented:
# the go-jose two-entry advisory and the four `package.name` spellings below
# were all read off api.github.com while this was being written. A fixture
# that does not match a real response shape tests a predicate against a world
# that does not exist.
# ---------------------------------------------------------------------------

# The T-0666 shape: one advisory, two entries, patched in v4 and open in v3.
cat > "$WORK/go-jose.json" <<'JSON'
[
  {"ghsa_id":"GHSA-c67m-wr4h-2ccg","cve_id":null,"severity":"moderate",
   "vulnerabilities":[
     {"package":{"ecosystem":"go","name":"github.com/go-jose/go-jose/v4"},
      "vulnerable_version_range":"<= v4.1.6","patched_versions":"v4.1.7"},
     {"package":{"ecosystem":"go","name":"github.com/go-jose/go-jose/v3"},
      "vulnerable_version_range":"all","patched_versions":""}]},
  {"ghsa_id":"GHSA-c5q2-7r4c-mv6g","cve_id":"CVE-2024-28180","severity":"low",
   "vulnerabilities":[
     {"package":{"ecosystem":"go","name":"github.com/go-jose/go-jose/v4"},
      "vulnerable_version_range":"< 4.0.1","patched_versions":"4.0.1"},
     {"package":{"ecosystem":"go","name":"github.com/go-jose/go-jose/v3"},
      "vulnerable_version_range":"< 3.0.3","patched_versions":"3.0.3"},
     {"package":{"ecosystem":"go","name":"gopkg.in/go-jose/go-jose.v2"},
      "vulnerable_version_range":"< 2.6.3","patched_versions":"2.6.3"}]}
]
JSON

# The four free-text `package.name` spellings the predicate comment documents,
# plus the unrelated-repo case the anchors exist for, plus a package inside a
# module, plus a sibling major version.
cat > "$WORK/spellings.json" <<'JSON'
[
  {"ghsa_id":"GHSA-fullpath","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/go-chi/chi/v5"},
     "vulnerable_version_range":"<=5.4.0"}]},
  {"ghsa_id":"GHSA-urlspace","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"https://github.com/go-chi/chi "},
     "vulnerable_version_range":"<=5.4.0"}]},
  {"ghsa_id":"GHSA-ownerrepo","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"go-chi/chi"},
     "vulnerable_version_range":"<=5.4.0"}]},
  {"ghsa_id":"GHSA-barerepo","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"chi"},
     "vulnerable_version_range":"<=5.4.0"}]},
  {"ghsa_id":"GHSA-unrelated","cve_id":null,"severity":"low",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/unrelated/archive"},
     "vulnerable_version_range":"<=1.0.0"}]},
  {"ghsa_id":"GHSA-siblingmajor","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/go-chi/chi/v4"},
     "vulnerable_version_range":"all"}]},
  {"ghsa_id":"GHSA-nopkg","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":null,"vulnerable_version_range":"all"}]}
]
JSON

# A package INSIDE a module, which is how three of this image pins are shaped.
cat > "$WORK/subpkg.json" <<'JSON'
[
  {"ghsa_id":"GHSA-subpkg","cve_id":"CVE-2026-44982","severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/crowdsecurity/crowdsec/pkg/apiclient"},
     "vulnerable_version_range":"<= 1.7.7"}]},
  {"ghsa_id":"GHSA-wholemod","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/crowdsecurity/crowdsec"},
     "vulnerable_version_range":"<= 1.7.7"}]}
]
JSON

# A module with no /vN suffix at all (legal for v0/v1), named both ways.
cat > "$WORK/nomajor.json" <<'JSON'
[
  {"ghsa_id":"GHSA-bare","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"golang.org/x/net"},
     "vulnerable_version_range":"< 0.62.0"}]},
  {"ghsa_id":"GHSA-v1suffixed","cve_id":null,"severity":"high",
   "vulnerabilities":[{"package":{"ecosystem":"go","name":"github.com/caddy-dns/route53/v1"},
     "vulnerable_version_range":"< 1.6.0"}]}
]
JSON

echo "=== 1. THE BUG: a sibling major version must not match (T-0666) ==="
# The whole point. GHSA-c67m has only a v3 entry that is open; its v4 entry is
# `<= v4.1.6`, which the pinned v4.1.7 is past. Matching the v3 entry to the v4
# pin is what produced a permanent verdict=advisory on the patched pin.
check "v4 pin matches only its own entries" \
  "GHSA-c5q2-7r4c-mv6g GHSA-c67m-wr4h-2ccg" \
  "$(matches "$PRED" "$WORK/go-jose.json" github.com/go-jose/go-jose/v4)"
# Asserted on the FULL record list for the v4 pin: both advisories still match
# by id (their v4 entries are real), and the test below proves it is the v4
# ENTRY that matched, not the v3 one — which is the distinction the bug blurred.
check "the matched entry for v4 is the v4 range, not v3 'all'" \
  "< 4.0.1|<= v4.1.6" \
  "$(jq -j --arg mod github.com/go-jose/go-jose/v4 -f "$PRED" "$WORK/go-jose.json" 2>/dev/null \
     | tr '\0' '\n' | awk -F'\x1f' 'NF {print $4}' | sort -u | paste -sd'|' -)"
# And the demonstration that this case is a real regression guard: the old
# predicate ALSO returns the v3 `all` range, which is the false advisory.
OLD_RANGES="$(jq -j --arg mod github.com/go-jose/go-jose/v4 -f "$OLD_PRED" "$WORK/go-jose.json" 2>/dev/null \
  | tr '\0' '\n' | awk -F'\x1f' 'NF {print $4}' | sort -u | paste -sd'|' -)"
case "$OLD_RANGES" in
  *all*) check "case 1 FAILS on the pre-T-0666 predicate (so it guards something)" y y ;;
  *)     check "case 1 FAILS on the pre-T-0666 predicate (so it guards something)" y n ;;
esac

echo
echo "=== 2. the v3 residual still surfaces where v3 is what is pinned ==="
# The five `all` rows are REAL advisories about real unfixed code: go-jose/v3
# has no patched version for any of them (T-0645). The fix must not silence
# them, only attribute them correctly — a filter that made them vanish
# everywhere would be a false clean, which is strictly worse than the noise.
check "v3 pin sees its own entries" \
  "GHSA-c5q2-7r4c-mv6g GHSA-c67m-wr4h-2ccg" \
  "$(matches "$PRED" "$WORK/go-jose.json" github.com/go-jose/go-jose/v3)"
check "the v3 'all' range is among what the v3 pin matched" \
  "yes" \
  "$(jq -j --arg mod github.com/go-jose/go-jose/v3 -f "$PRED" "$WORK/go-jose.json" 2>/dev/null \
     | tr '\0' '\n' | awk -F'\x1f' '$4 == "all" {found=1} END {print found ? "yes" : "no"}')"
# gopkg.in/go-jose/go-jose.v2 is a third line of the same library on a
# different host. It is neither v3 nor v4 and must match neither.
check "gopkg.in v2 line does not match the v4 pin" \
  "no" \
  "$(jq -j --arg mod github.com/go-jose/go-jose/v4 -f "$PRED" "$WORK/go-jose.json" 2>/dev/null \
     | tr '\0' '\n' | awk -F'\x1f' 'NF {print $4}' | grep -q '2\.6\.3' && echo yes || echo no)"

echo
echo "=== 3. every free-text spelling still matches (regression guard) ==="
# These four are why the match is loose at all. Each is an observed real value.
# A fix that tightened them away would hide advisories, so they are asserted
# individually rather than as a count.
for id in GHSA-fullpath GHSA-urlspace GHSA-ownerrepo GHSA-barerepo; do
  case " $(matches "$PRED" "$WORK/spellings.json" github.com/go-chi/chi/v5) " in
    *" $id "*) check "free-text spelling still matches: $id" y y ;;
    *)         check "free-text spelling still matches: $id" y n ;;
  esac
done

echo
echo "=== 4. the anchored-repo and sibling exclusions both hold ==="
# The unrelated-repo case the anchors were added for ("chi" inside "archive").
case " $(matches "$PRED" "$WORK/spellings.json" github.com/go-chi/chi/v5) " in
  *" GHSA-unrelated "*) check "unrelated repo excluded (anchors)" y n ;;
  *)                    check "unrelated repo excluded (anchors)" y y ;;
esac
# chi/v4 against a chi/v5 pin: same repo, different major. This is the T-0666
# shape on a second repo, so the fix is not special-cased to go-jose.
case " $(matches "$PRED" "$WORK/spellings.json" github.com/go-chi/chi/v5) " in
  *" GHSA-siblingmajor "*) check "sibling major excluded on a second repo" y n ;;
  *)                       check "sibling major excluded on a second repo" y y ;;
esac
# A null package must not crash the predicate or match everything.
case " $(matches "$PRED" "$WORK/spellings.json" github.com/go-chi/chi/v5) " in
  *" GHSA-nopkg "*) check "null package name does not match" y n ;;
  *)                check "null package name does not match" y y ;;
esac

echo
echo "=== 5. a package inside the module still matches (the near-miss) ==="
# The first attempt at this fix compared full module paths for EQUALITY only,
# which dropped this row: an advisory on `crowdsec/pkg/apiclient` against the
# resolved module `crowdsec`. That is one of the two CVE floors in this image,
# so the "fix" would have turned a false advisory into a false clean on a
# CVE-bearing pin. Both directions of containment are asserted.
check "advisory on a sub-package matches the module pin" \
  "GHSA-subpkg GHSA-wholemod" \
  "$(matches "$PRED" "$WORK/subpkg.json" github.com/crowdsecurity/crowdsec)"
check "advisory on the module matches a sub-package pin" \
  "GHSA-subpkg GHSA-wholemod" \
  "$(matches "$PRED" "$WORK/subpkg.json" github.com/crowdsecurity/crowdsec/pkg/apiclient)"

echo
echo "=== 6. a module with no major suffix (v0/v1) ==="
# `/vN` is absent from a v0/v1 module path by Go rule, and GitHub sometimes
# names it with a `/v1` anyway. At most one side carrying a suffix is the same
# module; two DIFFERENT suffixes never are.
check "bare path matches a bare pin" \
  "GHSA-bare" \
  "$(matches "$PRED" "$WORK/nomajor.json" golang.org/x/net)"
check "a /v1-suffixed name matches the bare module pin" \
  "GHSA-v1suffixed" \
  "$(matches "$PRED" "$WORK/nomajor.json" github.com/caddy-dns/route53)"
# ...but a v2 pin of that same module must not pick up the v1 record.
check "a /v1-suffixed name does NOT match a /v2 pin" \
  "" \
  "$(matches "$PRED" "$WORK/nomajor.json" github.com/caddy-dns/route53/v2)"

echo
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
