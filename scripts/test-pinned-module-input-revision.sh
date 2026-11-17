#!/usr/bin/env bash
# Tests for check-pinned-modules.sh's input-provenance footer (T-0656).
#
#   ./scripts/test-pinned-module-input-revision.sh      # exit 0 = all pass
#
# WHY THIS FILE EXISTS
# --------------------
# The watcher reads $DOCKERFILE by plain path and used to record nothing about
# which revision that was. Two local runs minutes apart disagreed about one
# pin -- `caddy-l4` at v0.1.3, then v0.1.2 -- which reads exactly like a bump
# having silently not landed. Nothing was wrong: the file was briefly dirty
# during the first run. The cost in the moment was a few minutes of looking
# for a lost commit.
#
# The cost that matters is the STORED ARTEFACT. The weekly workflow keeps its
# report for 90 days, and `pinned v0.1.3` with no revision attached is
# indistinguishable from the same sentence taken against a committed pin.
# Anyone auditing "what were we pinned to on date X" gets an answer that may
# describe somebody's uncommitted edit.
#
# A first pass (057d031) added `(clean vs HEAD)` / `(**UNCOMMITTED CHANGES**)`
# and stopped there. That is a half-fix, and the half it is missing is the
# half the audit needs: the marker distinguishes dirty from clean IN THE
# MOMENT, while two clean reports against different commits remain the same
# sentence. So the cases below assert the SHA is present and correct, not
# merely that a dirty run is flagged.
#
# The remaining cases are the degenerate inputs, each of which must disclose
# rather than fail or -- worse -- render as clean:
#
#   - no git checkout at all (the card's point 2);
#   - a git repo with no commits, so there is a --git-dir but no HEAD;
#   - a file git has never seen, which `git diff --quiet` calls CLEAN. That
#     one is why `ls-files` is checked first: a fixture Dockerfile under
#     $TMPDIR would otherwise be reported `clean vs HEAD` while being absent
#     from that commit entirely.
#   - a --dockerfile OUTSIDE the current directory. Every git call is scoped
#     to the Dockerfile's own directory, because a bare `git rev-parse` would
#     report the revision of whatever repo the caller was standing in and
#     attach it to a Dockerfile from somewhere else. A wrong provenance claim
#     is worse than none, since this footer exists to be trusted.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check-pinned-modules.sh"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Same derivation as the other suites: a fixture must name the SAME Caddy base
# as the shipped Dockerfile, so a base bump cannot leave these tests
# exercising a mix of tags.
BUILDER_FROM="$(sed -n 's/^FROM .*\(caddy:[0-9][^ ]*-builder\) AS builder$/\1/p' \
  "$REPO/Dockerfile.caddy" | head -1)"
if [ -z "$BUILDER_FROM" ]; then
  echo "FATAL: could not read the caddy builder tag from Dockerfile.caddy" >&2
  exit 1
fi
FROM_LINE="FROM $BUILDER_FROM AS builder"

RUNTIME_FROM="$(sed -n 's/^FROM[[:space:]]\+\(caddy:[0-9][^[:space:]]*-alpine\)[[:space:]]*$/\1/p' \
  "$REPO/Dockerfile.caddy" | head -1)"
if [ -z "$RUNTIME_FROM" ]; then
  echo "FATAL: could not read the caddy runtime tag from Dockerfile.caddy" >&2
  exit 1
fi
RUNTIME_LINE="FROM $RUNTIME_FROM"

# The base sweep is not what these cases are about and costs a network round
# trip per run, so it is skipped throughout.
export PINWATCH_SKIP_GITHUB=1

# Git needs an identity to commit, and the runner may have none configured.
# Scoped to this process so a developer's own config is untouched.
export GIT_AUTHOR_NAME=pinwatch-test    GIT_AUTHOR_EMAIL=pinwatch@example.invalid
export GIT_COMMITTER_NAME=pinwatch-test GIT_COMMITTER_EMAIL=pinwatch@example.invalid

pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS  %s\n' "$1"; pass=$((pass+1))
  else
    printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1))
  fi
}

run() { # $1=dockerfile $2=fixture -> prints json; RC/LASTOUT via rc(), lastout()
  local out rc
  out="$(mktemp -d "$WORK/out.XXXXXX")"
  "$SCRIPT" --dockerfile "$1" --offline-fixture "$2" --out-dir "$out" --json \
    > "$out/stdout.txt" 2>"$out/stderr.txt"
  rc=$?
  printf '%s' "$rc"  > "$WORK/.rc"
  printf '%s' "$out" > "$WORK/.lastout"
  cat "$out/result.json" 2>/dev/null || echo '{}'
}
rc()      { cat "$WORK/.rc"; }
lastout() { cat "$WORK/.lastout"; }
j() { jq -r "$1" <<<"$2"; }

footer() { grep -o 'Read from `[^`]*`' "$(lastout)/report.md" | tail -1; }

# Every case uses the same one-pin content; what varies is the TREE it sits in.
write_dockerfile() { # $1=path
  { echo "$FROM_LINE"
    echo 'RUN xcaddy build \'
    echo '    --with github.com/caddy-dns/route53@v1.6.2'
    echo "$RUNTIME_LINE"
  } > "$1"
}
FX="$WORK/fx.tsv"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' > "$FX"

echo "=== 1. a committed, unmodified Dockerfile reports its SHA and reads clean ==="
# The headline case. Before T-0656 the footer said `(clean vs HEAD)` with no
# SHA, so this assertion -- that the report names the actual revision -- is
# the one that fails on the half-fix.
R1="$WORK/repo-clean"; mkdir -p "$R1"
git -C "$R1" init -q
write_dockerfile "$R1/Dockerfile.caddy"
git -C "$R1" add Dockerfile.caddy
git -C "$R1" commit -qm "pin route53"
SHA1="$(git -C "$R1" rev-parse --short HEAD)"
J="$(run "$R1/Dockerfile.caddy" "$FX")"
check "input_state=clean"              "clean" "$(j .input_state "$J")"
check "input_rev is the real HEAD"     "$SHA1" "$(j .input_rev "$J")"
grep -q "@ $SHA1 (clean)" "$(lastout)/report.md" \
  && check "footer names the SHA" y y || check "footer names the SHA: $(footer)" y n

echo
echo "=== 2. an uncommitted edit is flagged AND still carries the SHA ==="
# The dirty marker must not replace the revision: "which commit is this NOT
# equal to" is exactly what the reader needs in order to go and look.
sed -i 's/v1.6.2/v1.6.3/' "$R1/Dockerfile.caddy"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.3\n' > "$WORK/fx.dirty"
J="$(run "$R1/Dockerfile.caddy" "$WORK/fx.dirty")"
check "input_state=dirty"          "dirty" "$(j .input_state "$J")"
check "input_rev still present"    "$SHA1" "$(j .input_rev "$J")"
grep -q 'UNCOMMITTED CHANGES' "$(lastout)/report.md" \
  && check "footer flags the dirty tree" y y || check "footer flags the dirty tree" y n
grep -q "@ $SHA1 " "$(lastout)/report.md" \
  && check "dirty footer keeps the SHA" y y || check "dirty footer keeps the SHA: $(footer)" y n
git -C "$R1" checkout -q -- Dockerfile.caddy

echo
echo "=== 3. a committed change moves the reported SHA ==="
# The close condition in the other direction: if the revision never changed,
# it would be decoration rather than provenance.
sed -i 's/v1.6.2/v1.6.4/' "$R1/Dockerfile.caddy"
git -C "$R1" commit -qam "bump route53"
SHA2="$(git -C "$R1" rev-parse --short HEAD)"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.4\n' > "$WORK/fx.bumped"
J="$(run "$R1/Dockerfile.caddy" "$WORK/fx.bumped")"
check "input_state=clean again" "clean" "$(j .input_state "$J")"
check "input_rev moved to the new commit" "$SHA2" "$(j .input_rev "$J")"
[ "$SHA1" != "$SHA2" ] \
  && check "the two runs are distinguishable" y y || check "the two runs are distinguishable" y n

echo
echo "=== 4. outside a git checkout: revision unknown, NOT an error ==="
# The card's point 2. The script must keep working; a failed rev-parse is
# "revision unknown", and silence here would read as a clean tree.
BARE="$WORK/not-a-repo"; mkdir -p "$BARE"
write_dockerfile "$BARE/Dockerfile.caddy"
J="$(run "$BARE/Dockerfile.caddy" "$FX")"
check "input_state=no-git" "no-git" "$(j .input_state "$J")"
check "input_rev is empty, not a fake SHA" "" "$(j .input_rev "$J")"
# rc is NOT asserted to be 0 here. An offline fixture cannot answer the
# commit-scoped OSV query, so every case in this file ends at rc=3
# (advisory_unknown=1) exactly as the sibling suites do -- that is the
# pre-existing fixture behaviour, not something this input affects. What
# matters is that running outside a checkout does not ADD an error, asserted
# directly below on $errors.
check "no error was recorded" "" "$(cat "$(lastout)/errors.txt")"
grep -q 'revision unknown' "$(lastout)/report.md" \
  && check "footer says revision unknown" y y || check "footer says revision unknown: $(footer)" y n
# Scoped to the footer, not the whole report: the body legitimately contains
# the word "clean" in other sentences.
footer | grep -q 'clean' \
  && check "the footer does NOT claim clean" n y || check "the footer does NOT claim clean" n n

echo
echo "=== 5. a git repo with no commits: --git-dir exists, HEAD does not ==="
# The degenerate case between 1 and 4. `rev-parse --short HEAD` fails here
# while `--git-dir` succeeds, so a guard that only checks the latter would
# emit an empty SHA into the footer.
R2="$WORK/repo-empty"; mkdir -p "$R2"
git -C "$R2" init -q
write_dockerfile "$R2/Dockerfile.caddy"
J="$(run "$R2/Dockerfile.caddy" "$FX")"
check "no error was recorded" "" "$(cat "$(lastout)/errors.txt")"
check "input_rev is empty, not a fake SHA" "" "$(j .input_rev "$J")"
grep -q 'revision unknown' "$(lastout)/report.md" \
  && check "footer says revision unknown" y y || check "footer says revision unknown: $(footer)" y n
grep -q '@  ' "$(lastout)/report.md" \
  && check "no empty '@' in the footer" n y || check "no empty '@' in the footer" n n

echo
echo "=== 6. an untracked Dockerfile is NOT reported clean ==="
# `git diff --quiet` succeeds for a file git has never seen, so the half-fix
# calls this `clean vs HEAD` while the file is absent from that commit
# entirely -- the exact false-clean shape this script is written against.
write_dockerfile "$R1/Dockerfile.untracked"
J="$(run "$R1/Dockerfile.untracked" "$FX")"
check "input_state=untracked" "untracked" "$(j .input_state "$J")"
grep -q 'UNTRACKED' "$(lastout)/report.md" \
  && check "footer says UNTRACKED" y y || check "footer says UNTRACKED: $(footer)" y n
grep -qE '\(clean\)' "$(lastout)/report.md" \
  && check "it does NOT claim clean" n y || check "it does NOT claim clean" n n

echo
echo "=== 7. the revision describes the DOCKERFILE's repo, not the caller's ==="
# Every git call is scoped to the Dockerfile's directory. Run from inside a
# DIFFERENT repo and the footer must still name R1's commit; a bare
# `git rev-parse` would report the caller's and be confidently wrong.
R3="$WORK/repo-other"; mkdir -p "$R3"
git -C "$R3" init -q
echo other > "$R3/f"; git -C "$R3" add f; git -C "$R3" commit -qm other
SHA3="$(git -C "$R3" rev-parse --short HEAD)"
J="$(cd "$R3" && run "$R1/Dockerfile.caddy" "$WORK/fx.bumped")"
check "input_rev is the Dockerfile's repo" "$SHA2" "$(j .input_rev "$J")"
[ "$(j .input_rev "$J")" != "$SHA3" ] \
  && check "NOT the caller's repo" y y || check "NOT the caller's repo" y n

echo
echo "=== 8. the footer and the JSON cannot disagree ==="
# Two renderings of one fact. They are produced by the same variables, and
# this asserts that stays true -- a machine consumer reading input_rev and a
# human reading the footer must not be able to get different answers.
J="$(run "$R1/Dockerfile.caddy" "$WORK/fx.bumped")"
JREV="$(j .input_rev "$J")"
grep -q "@ $JREV " "$(lastout)/report.md" \
  && check "footer SHA == result.json input_rev" y y \
  || check "footer SHA == result.json input_rev ($JREV vs $(footer))" y n
check "input path is reported too" "$R1/Dockerfile.caddy" "$(j .input "$J")"

echo
echo "=== 9. the die() path reports the input, and reports it UNKNOWN ==="
# A failed run writes $GITHUB_OUTPUT too, and its provenance keys must not be
# absent (the workflow would read an empty value) nor empty (which is what a
# SUCCESSFUL run emits for "checked, and there is no revision"). They are
# `unknown`, matching every other key on that path.
#
# This case also pins a bug introduced while writing this feature: `die` is
# reachable from argument parsing, which runs BEFORE the parser section where
# `clean_scalar` used to be defined, so `input=$(clean_scalar ...)` was
# `command not found` and emitted an empty path. The sanitiser is now hoisted
# above `die`; this asserts it stays there.
DIE_OUT="$WORK/die-output"
DIE_ERR="$WORK/die-stderr"
GITHUB_OUTPUT="$DIE_OUT" "$SCRIPT" --dockerfile "$WORK/definitely-absent/Dockerfile.caddy" \
  >/dev/null 2>"$DIE_ERR"
check "verdict=error" "verdict=error" "$(grep -m1 '^verdict=' "$DIE_OUT")"
check "input is the path" "input=$WORK/definitely-absent/Dockerfile.caddy" \
  "$(grep -m1 '^input=' "$DIE_OUT")"
check "input_rev=unknown" "input_rev=unknown" "$(grep -m1 '^input_rev=' "$DIE_OUT")"
check "input_state=unknown" "input_state=unknown" "$(grep -m1 '^input_state=' "$DIE_OUT")"
grep -q 'command not found' "$DIE_ERR" \
  && check "no helper is called before it is defined" n y \
  || check "no helper is called before it is defined" n n

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
