#!/usr/bin/env bash
# Tests for check-pinned-modules.sh's `--gomod` sweep — CaddyUI's OWN Go
# dependencies (T-0676, from T-0654 item 1).
#
#   ./scripts/test-pinned-module-gomod-sweep.sh      # exit 0 = all pass
#
# A sibling of test-pinned-module-image-sweep.sh, and built to the same two
# rules (see that file's header): the range predicates are EXTRACTED from the
# shipped script rather than copied, and the expected counts are DERIVED from a
# captured fixture by an independent route (jq) rather than written as literals.
#
# ---------------------------------------------------------------------------
# WHY THIS SUITE EXISTS
# ---------------------------------------------------------------------------
# Three indexes were asked about CaddyUI's own `go.mod` and all three said it
# was clean while five advisories were live against the `go-jose/v4 v4.1.6` it
# selected:
#
#   Dependabot (GitHub's GLOBAL advisory index)  6 advisories for go-jose/v4,
#                                                every one carrying a CVE id,
#                                                none of them the five.
#   OSV (package+version at 4.1.6)               zero. Each of the five is a
#                                                404 by GHSA id.
#   govulncheck (vuln.go.dev)                    none of the five; that DB is
#                                                CVE-keyed too.
#
# The five appear on GitHub's PER-REPOSITORY advisory endpoint and, as measured,
# nowhere else. Dependabot's `gomod` ecosystem is configured here and does work
# — 19 Go advisories have been raised on this repo and all were fixed — so the
# failure is not a missing integration. It is that a CVE-less advisory is
# absent from every CVE-keyed index, and until this change nothing asked the
# one endpoint that carries it.
#
# So the acceptance condition is a DISPROOF, the pattern T-0646 established:
# case 1 shows the repo endpoint reporting exactly five at 4.1.6 and zero at
# 4.1.7, and cases 2-4 show each of the three alternatives reporting ZERO for
# the same module at the same version. A check that finds the five is only
# interesting if the things it replaces demonstrably do not.
#
# A NOTE ON THE SIXTH. The fixture carries SIX CVE-less advisories, not five.
# GHSA-6mp9-8xrw-74r4 is bounded `< v4.1.5`, strictly below 4.1.6, so the
# count-inflation guard (T-0645/T-0660) correctly excludes it. Case 1d asserts
# that explicitly: reporting six where five apply would be as wrong as
# reporting zero, and this fixture is the case that proves the guard earns its
# place on this input too.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check-pinned-modules.sh"
FIXTURES="$(cd "$(dirname "$0")" && pwd)/fixtures"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

# Extract the predicates under test from the shipped script, on the function's
# own braces. A copied predicate passes forever after the original changes,
# which makes a suite worse than nothing.
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

JOSE_FIXTURE="$FIXTURES/go-jose-go-jose-advisories.json"
if [ ! -f "$JOSE_FIXTURE" ]; then
  echo "FATAL: missing fixture $JOSE_FIXTURE" >&2
  exit 1
fi

# Both shipped exclusions applied to every vulnerability entry, collapsed to
# one row per GHSA — the same shape the sweep renders.
#
# THE MAJOR-VERSION FILTER IS PART OF THE MODEL, not an optimisation (T-0666).
# This fixture is the live data that makes it matter: each of the five
# advisories carries a SECOND `vulnerabilities` entry, for
# `go-jose/go-jose/v3`, with range `all` and an EMPTY `patched_versions`.
# Range `all` matches every version and an empty patch excludes nothing, so
# modelling the two exclusions alone reports all five as still live at 4.1.7 —
# against `/v4`, the module that patched them. That is precisely the bug
# T-0666 fixed in the sweep, and a suite that omitted this filter would be
# asserting the buggy answer and calling the fixed code wrong.
#
# `$1` is the module path under test, so the v3 rows are rejected for a v4
# query and accepted for a v3 one, exactly as the shipped jq `select` does.
live_ids() { # $1 = version, $2 = module path (default go-jose/v4)
  local ver="$1" mod="${2:-github.com/go-jose/go-jose/v4}"
  local ghsa range patched pkg
  local want_maj="" mod_base="$mod"
  case "$mod" in */v[0-9]*) want_maj="${mod##*/}"; mod_base="${mod%/*}" ;; esac
  while IFS=$'\t' read -r ghsa pkg range patched; do
    [ -n "$ghsa" ] || continue
    # Same discipline as the shipped filter: two different /vN suffixes never
    # match. A suffix-less package name still matches the module base.
    local pkg_maj="" pkg_base="$pkg"
    case "$pkg" in */v[0-9]*) pkg_maj="${pkg##*/}"; pkg_base="${pkg%/*}" ;; esac
    [ "$pkg_base" = "$mod_base" ] || continue
    if [ -n "$pkg_maj" ] && [ -n "$want_maj" ] && [ "$pkg_maj" != "$want_maj" ]; then
      continue
    fi
    range_excludes_version "$range" "$ver" && continue
    patch_already_in_version "$patched" "$ver" && continue
    printf '%s\n' "$ghsa"
  done < <(jq -r '.[] | . as $a | (.vulnerabilities // [])[]
                  | [($a.ghsa_id // ""), (.package.name // ""),
                     (.vulnerable_version_range // ""),
                     (.patched_versions // "")] | @tsv' \
             "$JOSE_FIXTURE") | sort -u
}
live_count() { live_ids "$1" "${2:-}" | wc -l | tr -d ' '; }

echo "=== the acceptance condition (T-0676 item 3) ==="

# Case 1. The card's condition: five at 4.1.6, zero at 4.1.7.
check "1  go-jose/v4@4.1.6 reports exactly 5 live advisories" \
  "5" "$(live_count 4.1.6)"

check "1b go-jose/v4@4.1.7 reports ZERO — the fix clears all five" \
  "0" "$(live_count 4.1.7)"

# Derived, not asserted as a literal list the fixture could drift away from:
# every surviving advisory at 4.1.6 must be CVE-less. That is the mechanism,
# and if a CVE-bearing row ever survives here the premise has changed.
cveless_live="$(for g in $(live_ids 4.1.6); do
  jq -r --arg g "$g" '.[] | select(.ghsa_id == $g) | (.cve_id // "NO-CVE")' "$JOSE_FIXTURE"
done | sort -u | paste -sd',' -)"
check "1c every one of the five is CVE-less, which is why every CVE-keyed index misses them" \
  "NO-CVE" "$cveless_live"

# Case 1d. The sixth CVE-less advisory is bounded below 4.1.6 and must NOT be
# counted. Six-where-five-apply is the count inflation of T-0645/T-0660.
total_cveless="$(jq -r '[.[] | select(.cve_id == null)] | length' "$JOSE_FIXTURE")"
check "1d the fixture has 6 CVE-less advisories but only 5 apply at 4.1.6" \
  "6 5" "$total_cveless $(live_count 4.1.6)"

below="$(jq -r '.[] | select(.cve_id == null)
                | select((.vulnerabilities // [])[0].vulnerable_version_range // ""
                         | test("4\\.1\\.5")) | .ghsa_id' "$JOSE_FIXTURE" | head -1)"
check "1e the excluded one is the \`< v4.1.5\` record, not an arbitrary drop" \
  "yes" "$([ -n "$below" ] && ! live_ids 4.1.6 | grep -qx "$below" && echo yes || echo no)"

# Case 1f. T-0666's bug, in live data. Every one of the five carries a second
# entry for `go-jose/go-jose/v3` with range `all` and NO patched version. If
# the major-version suffix is ignored, those rows match a `/v4` pin, never
# expire, and report all five as live against 4.1.7 — the release that fixes
# them. `go.mod` carries both module shapes, so this fixture is the case that
# would have made T-0666 louder here had it not already been fixed.
v3_all="$(jq -r '[.[] | (.vulnerabilities // [])[]
                 | select((.package.name // "") == "github.com/go-jose/go-jose/v3")
                 | select((.vulnerable_version_range // "") == "all")] | length' "$JOSE_FIXTURE")"
check "1f the fixture really does carry unpatched \`all\`-range v3 rows (T-0666's trap)" \
  "yes" "$([ "$v3_all" -ge 5 ] && echo yes || echo no)"
check "1g those v3 rows do NOT match a /v4 query at 4.1.7" \
  "0" "$(live_count 4.1.7 github.com/go-jose/go-jose/v4)"
check "1h and they DO match a /v3 query, so the filter is not just dropping them" \
  "yes" "$([ "$(live_count 4.1.7 github.com/go-jose/go-jose/v3)" -ge 5 ] && echo yes || echo no)"

echo
echo "=== the disproof: every alternative index reports ZERO ==="

# Case 2. OSV, by package+version. Live, because the claim is about OSV today
# rather than about a recorded answer; skips rather than passing if OSV is
# unreachable.
osv_body="$(curl -fsS --max-time 20 -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package":{"name":"github.com/go-jose/go-jose/v4","ecosystem":"Go"},"version":"4.1.6"}' \
  2>/dev/null)"
if [ -z "$osv_body" ]; then
  skipped "2  OSV reports zero at 4.1.6" "OSV unreachable"
else
  check "2  OSV reports ZERO vulns for go-jose/v4@4.1.6" \
    "0" "$(jq -r '(.vulns // []) | length' <<<"$osv_body" 2>/dev/null || echo ERR)"
fi

# Case 3. Each of the five is a 404 on OSV BY ID. Stronger than case 2: it
# shows the records are absent from OSV entirely, not merely unmatched by a
# version query.
if [ -n "$osv_body" ]; then
  codes="$(for g in $(live_ids 4.1.6); do
    curl -s -o /dev/null -w '%{http_code} ' --max-time 15 "https://api.osv.dev/v1/vulns/$g"
  done | tr -s ' ' | sed 's/ $//')"
  check "3  all five are 404 on OSV by GHSA id — absent, not merely unmatched" \
    "404 404 404 404 404" "$codes"
else
  skipped "3  the five are 404 on OSV by id" "OSV unreachable"
fi

# Case 4. GitHub's GLOBAL advisory index — the one Dependabot keys on. This is
# the measurement that makes the card's answer "no, Dependabot does not cover
# this": the global endpoint answers, and every advisory it returns carries a
# CVE id, so none of the five is among them.
gh_auth=()
[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ] && gh_auth=(-H "Authorization: Bearer ${GH_TOKEN:-$GITHUB_TOKEN}")
glob="$(curl -fsS --max-time 20 \
  -H 'Accept: application/vnd.github+json' \
  "${gh_auth[@]+"${gh_auth[@]}"}" \
  'https://api.github.com/advisories?ecosystem=go&affects=github.com/go-jose/go-jose/v4&per_page=100' \
  2>/dev/null)"
if [ -z "$glob" ] || ! jq -e 'type == "array"' <<<"$glob" >/dev/null 2>&1; then
  skipped "4  the global index carries none of the five" "GitHub global endpoint unavailable (rate limit, or no token)"
else
  # Intersection of the global index with the five. Must be empty.
  overlap="$(comm -12 \
    <(jq -r '.[].ghsa_id' <<<"$glob" | sort -u) \
    <(live_ids 4.1.6) | wc -l | tr -d ' ')"
  check "4  the GLOBAL index (what Dependabot keys on) carries NONE of the five" \
    "0" "$overlap"
  check "4b every advisory the global index DOES return carries a CVE id" \
    "0" "$(jq -r '[.[] | select(.cve_id == null)] | length' <<<"$glob")"
fi

echo
echo "=== the module set is read correctly ==="

# Case 5. `go list -m all` is preferred over the require block, because
# go-jose was reached as an `// indirect` transitive dependency — exactly what
# a require-only read is weakest on.
if command -v go >/dev/null 2>&1; then
  out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
    --gomod "$REPO_ROOT/go.mod" --out-dir "$WORK/o-src" --json 2>/dev/null || true)"
  check "5  the sweep prefers \`go list -m all\` over the require block" \
    "go list -m all" "$(jq -r '.gomod_source // "MISSING"' <<<"$(printf '%s' "$out" | sed -n '/^{/,/^}/p')" 2>/dev/null || echo ERR)"
  check "5b it reads a module set larger than the require block alone" \
    "yes" "$([ "$(jq -r '.gomod_modules // 0' <<<"$(printf '%s' "$out" | sed -n '/^{/,/^}/p')" 2>/dev/null || echo 0)" -gt 30 ] && echo yes || echo no)"
else
  skipped "5  go list -m all is preferred" "go toolchain unavailable"
fi

# Case 6. A go.mod with NO toolchain available falls back to the require block
# and SAYS SO. A narrower input reported as the wider one is a quiet
# downgrade, and the indirect dependency that carried all five is precisely
# what the narrow read can miss.
mkdir -p "$WORK/fallback"
cat > "$WORK/fallback/go.mod" <<'GOMOD'
module example.com/fallback

go 1.26.0

require (
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/stretchr/testify v1.11.1
)
GOMOD
# `go` is hidden from PATH so the fallback arm is actually reached rather than
# assumed -- without this the case tests the `go list` path and passes
# vacuously.
#
# Hidden with a SHIM DIRECTORY, not by emptying PATH. `PATH=/nonexistent`
# removes `curl`, `jq` and `sed` too, so the script dies in its preconditions
# and the case then passes or fails for reasons that have nothing to do with
# the fallback (measured: it never reached the code under test). The shim
# keeps the real PATH and shadows exactly one command: a `go` that is not
# executable, so `command -v go` fails the way an absent toolchain does.
mkdir -p "$WORK/shim"
: > "$WORK/shim/go"
chmod 0644 "$WORK/shim/go"
out="$(PATH="$WORK/shim:$PATH" PINWATCH_SKIP_GITHUB=1 bash "$SCRIPT" \
  --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
  --gomod "$WORK/fallback/go.mod" --out-dir "$WORK/o-fb" 2>&1 || true)"
check "6  with no toolchain it falls back to the require block" \
  "yes" "$(printf '%s' "$out" | grep -q 'go.mod require block' && echo yes || echo no)"
check "6b the fallback NAMES the transitive graph as missing, not silently narrower" \
  "yes" "$(printf '%s' "$out" | grep -q 'TRANSITIVE GRAPH NOT INCLUDED' && echo yes || echo no)"

# Case 7. A missing --gomod path is an ERROR, not an empty module set. An
# empty set would read as "swept, nothing found".
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
  --gomod "$WORK/does-not-exist/go.mod" --out-dir "$WORK/o-missing" 2>&1 || true)"
check "7  a missing --gomod is an ERROR, not an empty module set" \
  "yes" "$(printf '%s' "$out" | grep -q "does not exist; caddyui's own module set was NOT swept" && echo yes || echo no)"
# The verdict is asserted as "never ok", NOT as "error". On this repo a real
# advisory is live, and `advisory` outranks `error` in the verdict ladder — so
# demanding `error` here would assert that a missing file DOWNGRADES a genuine
# advisory finding, which would be the wrong behaviour to lock in. What must
# hold is that the failure cannot read as clean.
check "7b a missing --gomod never reaches the \`ok\` verdict" \
  "no" "$(printf '%s' "$out" | grep -q '^verdict=ok' && echo yes || echo no)"
# Read from $GITHUB_OUTPUT, not stdout. The `gomod=` key is a job output and
# is written only there; grepping stdout for it reports "no" for a script that
# is emitting it correctly, which is a test asserting the absence of something
# it never looked at.
gho="$WORK/gho-missing.txt"
: > "$gho"
GITHUB_OUTPUT="$gho" PINWATCH_SKIP_GITHUB=1 "$SCRIPT" \
  --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
  --gomod "$WORK/does-not-exist/go.mod" --out-dir "$WORK/o-missing2" >/dev/null 2>&1 || true
check "7c and it is recorded in the job output as an error state" \
  "yes" "$(grep -qx 'gomod=error' "$gho" && echo yes || echo no)"

echo
echo "=== an unswept module set never reads as a clean one ==="

# Case 8. THE PROPERTY THAT MATTERS MOST. With the sweep disabled, the report
# must say go.mod was not swept and must NOT print the all-clear.
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
  --gomod "$REPO_ROOT/go.mod" --out-dir "$WORK/o-skip" 2>&1 || true)"
check "8  a disabled sweep never prints the all-clear sentence" \
  "no" "$(printf '%s' "$out" | grep -q "CaddyUI's own .* Go modules were swept" && echo yes || echo no)"

# Case 9. No `--gomod` at all must not let the all-clear claim go.mod was
# checked. This is the regression that defines the card: for its whole life
# this report could print an all-clear while nothing had ever asked the one
# endpoint that carries a CVE-less advisory.
out="$(PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
  --out-dir "$WORK/o-nogomod" 2>&1 || true)"
check "9  with no --gomod the all-clear does not mention go.mod" \
  "no" "$(printf '%s' "$out" | grep -q "CaddyUI's own .* Go modules were swept" && echo yes || echo no)"
check "9b with no --gomod the verdict is never \`ok\`" \
  "no" "$(printf '%s' "$out" | grep -q '^verdict=ok' && echo yes || echo no)"

# Case 10. A PARTIAL sweep must not say "no advisory covers a version go.mod
# selects". Measured on a real exhausted-rate-limit run: 11 of 29 modules
# swept, and that sentence printed anyway while 18 modules had been asked
# about by nobody — one of which, on a full run, carried five findings. The
# counters and the verdict were both right; the prose was the last place the
# false clean could live. Driven here by a cap of 0, which makes every
# github.com module unswept deterministically and offline.
out="$(PINWATCH_GRAPH_CAP=0 PINWATCH_SKIP_GITHUB=1 "$SCRIPT" \
  --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
  --gomod "$REPO_ROOT/go.mod" --out-dir "$WORK/o-partial" 2>&1 || true)"
check "10 a partial sweep never claims no advisory covers a selected version" \
  "no" "$(grep -q 'No advisory on the per-repository endpoint covers a version `go.mod` selects' \
            "$WORK/o-partial/report.md" 2>/dev/null && echo yes || echo no)"

# Case 11. The machine output must not say `ok` for a module set nobody
# queried. `gomod_state` alone means "the module LIST was read", and with the
# sweep disabled the list parses fine while nothing is checked -- so an `ok`
# here would tell the workflow's `case ... ok) ;;` arm to stay silent. The
# prose was fixed in case 10; this is the same false clean re-entering through
# the job output, which is the surface the alerting actually reads.
gho2="$WORK/gho-disabled.txt"
: > "$gho2"
GITHUB_OUTPUT="$gho2" PINWATCH_SKIP_GITHUB=1 "$SCRIPT" \
  --dockerfile "$REPO_ROOT/Dockerfile.caddy" \
  --gomod "$REPO_ROOT/go.mod" --out-dir "$WORK/o-gho2" >/dev/null 2>&1 || true
check "11 a disabled sweep never reports \`gomod=ok\` to the workflow" \
  "no" "$(grep -qx 'gomod=ok' "$gho2" && echo yes || echo no)"
check "11b it reports \`not-swept\`, distinct from \`not-run\` and from an unreadable file" \
  "yes" "$(grep -qx 'gomod=not-swept' "$gho2" && echo yes || echo no)"

echo
printf 'pass %d  fail %d  skip %d\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ] || exit 1
