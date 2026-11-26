#!/usr/bin/env bash
# Regression suite for the gate's age preflight, assert_baseline_not_newer
# (T-0863).
#
# WHAT IT EXISTS FOR
# ------------------
# The gate had no notion of the two images' ages, so comparing a rebuild
# against a NEWER baseline -- caller error, not a defect in either image --
# came out as an ordinary gate 1 block: rc=1, verdict=blocked, 15 added
# findings. Gate 1 is set arithmetic over two scans, so run backwards it
# reports everything the baseline has FIXED since as newly ADDED. The answer is
# arithmetically correct and completely misleading, and one session spent a
# full control run against the gate's own unmodified code to establish that the
# new coverage floors had not broken a legitimate release.
#
# This suite asserts the three properties the preflight was specified to have,
# and -- the part that makes it worth having rather than decorative -- it
# asserts the two that are FAIL-OPEN shapes, where a check that merely
# "does not fire" would look exactly like a check that passed.
#
# WHY IT IS FUNCTION-LEVEL AND NEEDS NO DOCKER
# --------------------------------------------
# The preflight reads two strings. The gate's arch loop obtains them with
# `docker image inspect --format '{{.Created}}'` and passes them in, so every
# property of the comparison is testable by calling the real function with
# crafted strings -- no image, no build, no scan, a few hundred milliseconds.
# The DOCKER side (that `.Created` is readable on a pulled image, on a locally
# built one and on a per-arch child digest, in both RFC3339 spellings) is not
# testable here and was verified by hand against the real images; see T-0863's
# log for the measured values.
#
# The function is EXTRACTED from the shipped script rather than copied, for the
# reason the trust-env suite spells out: a copy is a second source of truth
# that keeps passing after the original changes.
#
# Usage: scripts/test-caddy-image-gate-age.sh
# Exit 0 = all pass.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/caddy-image-gate.sh"
[ -r "$GATE" ] || { echo "FAIL: cannot read $GATE" >&2; exit 2; }

# Pull the function out of the shipped script. An EMPTY extraction must be a
# hard error and not zero tests: the one failure mode this suite must not have
# is reporting success because it tested nothing. (Same reasoning as ci.yml's
# explicit suite list rather than a glob.)
extract_fn() {
  awk '
    /^assert_baseline_not_newer\(\) \{/ { grab = 1 }
    grab                                { print }
    /^\}$/ && grab                      { exit }
  ' "$GATE"
}

FN="$(extract_fn)"
printf '%s' "$FN" | grep -q 'assert_baseline_not_newer() {' || {
  echo "FAIL: could not extract assert_baseline_not_newer from $GATE." >&2
  echo "      It was probably renamed or reindented; fix this extraction" >&2
  echo "      rather than inlining a copy of the function." >&2
  exit 2
}

# `die` is defined above the extracted range, so it is re-declared here. It
# must be a FAITHFUL copy of the gate's -- an `exit 2`, never a `return` --
# because every assertion in the function relies on die not returning to its
# caller. A `return`-shaped stub turns every blocking case into a pass, which
# is how the coverage harness first reported a green run with the checks
# firing correctly underneath. Same for safe_text, which the die messages
# call: a stub that drops its argument would hide the timestamps the messages
# are required to echo, so this one prints its input.
PRELUDE='set -euo pipefail
die() { echo "::error::$*" >&2; exit 2; }
safe_text() { printf %s "$1"; }
'

PASS=0
FAIL=0
OUT=""
RC=0

# Run the extracted function in a subshell, so an `exit 2` ends the case and
# not the suite.
run_age() {
  set +e
  OUT="$(printf '%s%s\nassert_baseline_not_newer "$1" "$2" "$3"\n' \
           "$PRELUDE" "$FN" | bash -s -- "$1" "$2" "${3:-amd64}" 2>&1)"
  RC=$?
  set -e
}

# want=pass -> rc 0; want=die -> rc 2 AND a message. A non-zero rc that is not
# 2 is a FAILURE, not a pass: the three call sites treat 2 as "the gate could
# not run" and 1 as "blocked", and this is a precondition, not a verdict.
check() {
  local name="$1" want="$2"
  if [ "$want" = pass ]; then
    if [ "$RC" -eq 0 ]; then
      printf 'ok   %s\n' "$name"; PASS=$((PASS + 1)); return
    fi
  else
    if [ "$RC" -eq 2 ] && printf '%s' "$OUT" | grep -q '::error::'; then
      printf 'ok   %s  (exit 2: %s)\n' "$name" "$(printf '%s' "$OUT" | head -c 80)"
      PASS=$((PASS + 1)); return
    fi
  fi
  printf 'FAIL %s  (want %s, rc=%s)\n     %s\n' "$name" "$want" "$RC" "$OUT"
  FAIL=$((FAIL + 1))
}

# The two real spellings, measured on real images: a pulled image reports UTC
# with a Z, a locally built one reports a numeric offset.
PULLED='2026-11-25T21:10:45.193977204Z'
LOCAL='2026-11-25T16:07:17.287461012-08:00'

# ---------------------------------------------------------------------------
# PROPERTY 2 first: the ordinary cases must not start blocking. A precondition
# that blocks a legitimate release is worse than the confusion it replaces.

# 1. The release shape: a rebuild built now, a baseline published earlier.
run_age "$PULLED" '2026-11-13T03:45:00Z'
check "rebuild newer than the published image passes" pass

# 2. The mixed-spelling shape, which is what a LOCAL control run looks like:
#    locally built rebuild (numeric offset) vs pulled baseline (Z). The two
#    strings are 5h3m apart with the rebuild later, which is only true once
#    the offset is applied -- compared as text, '16:07' sorts before '21:10'
#    and this case would block. So it is also the regression guard against
#    anyone replacing the epoch conversion with a string comparison.
run_age "$LOCAL" "$PULLED"
check "a local build (offset) newer than a pulled baseline (Z) passes" pass

# 3. EQUAL timestamps pass. `:stable` vs `:stable` is a legitimate degenerate
#    call and is this repo's free control for proving the gate discriminates,
#    so the test must be STRICTLY newer. A newer-or-equal spelling breaks it.
run_age "$PULLED" "$PULLED"
check "identical timestamps pass (:stable vs itself)" pass

# 4. One second newer is still newer. Guards the boundary from the other side.
run_age '2026-11-25T21:10:46Z' '2026-11-25T21:10:45Z'
check "one second newer passes" pass

# 5. Fractional seconds are not required, and a whole-second baseline against a
#    fractional rebuild at the same second is not "older".
run_age '2026-11-25T21:10:45Z' '2026-11-25T21:10:45.999Z'
check "sub-second difference at the same second passes" pass

# ---------------------------------------------------------------------------
# PROPERTY 3: the backwards comparison dies, naming the cause.

# 6. The measured case the card was filed for: v2.68.12 (2026-11-13) gated
#    against :stable (v2.68.14, 2026-11-25).
run_age '2026-11-13T00:42:00Z' '2026-11-25T21:06:56Z'
check "a baseline newer than the rebuild dies" die

# 7. ...and it must say the BASELINE IS NEWER, not merely that something is
#    wrong. The whole value of the check is the sentence it prints.
run_age '2026-11-13T00:42:00Z' '2026-11-25T21:06:56Z'
if printf '%s' "$OUT" | grep -qi 'PUBLISHED image is NEWER'; then
  printf 'ok   ...and names the cause, not the symptom\n'; PASS=$((PASS + 1))
else
  printf 'FAIL ...and names the cause, not the symptom\n     %s\n' "$OUT"
  FAIL=$((FAIL + 1))
fi

# 8. ...and it must echo BOTH timestamps, so the reader does not have to
#    re-derive them from two docker inspects.
if printf '%s' "$OUT" | grep -q '2026-11-13T00:42:00Z' \
   && printf '%s' "$OUT" | grep -q '2026-11-25T21:06:56Z'; then
  printf 'ok   ...and echoes both timestamps\n'; PASS=$((PASS + 1))
else
  printf 'FAIL ...and echoes both timestamps\n     %s\n' "$OUT"
  FAIL=$((FAIL + 1))
fi

# 9. One second older is already backwards. The check is strict, so this is
#    the smallest failing difference and the other half of case 4's boundary.
run_age '2026-11-25T21:10:45Z' '2026-11-25T21:10:46Z'
check "one second older dies (strictly newer boundary)" die

# 10. Across the offset, where a text comparison would get the wrong answer in
#     the other direction: the baseline's local-time string LOOKS earlier
#     ('16:07' < '21:10') but is 5h3m LATER once the offset is applied. A
#     string comparison would pass this; the epoch comparison must not.
run_age "$PULLED" "$LOCAL"
check "a baseline newer only once its offset applies still dies" die

# ---------------------------------------------------------------------------
# PROPERTY 1: an unreadable timestamp is not a pass. These are the fail-open
# cases -- the ones where a check that merely does not fire is indistinguishable
# from a check that passed.

# 11. Absent on the rebuild side (what `docker image inspect` yields through the
#     gate's `|| true` when the format fails or the image vanished).
run_age '' "$PULLED"
check "an empty rebuild timestamp exits 2, not 0" die

# 12. Absent on the baseline side.
run_age "$PULLED" ''
check "an empty baseline timestamp exits 2, not 0" die

# 13. Both absent. Must not cancel out into "equal, therefore fine" -- which is
#     what a naive string comparison of two empty strings does.
run_age '' ''
check "two empty timestamps exit 2 rather than comparing equal" die

# 14. RELATIVE expressions are refused. `date -d now` succeeds and yields the
#     current time, so without a form check an image declaring the word 'now'
#     would always read as current and never be judged older. .Created comes
#     out of the image config, i.e. the artefact under test.
run_age 'now' "$PULLED"
check "the relative word 'now' is refused, not resolved" die

# 15. The same for an @epoch, which `date -d` also accepts.
run_age '@0' "$PULLED"
check "an @epoch form is refused" die

# 16. ...and for a baseline naming a relative past, which would otherwise make
#     any rebuild look newer.
run_age "$PULLED" 'yesterday'
check "a relative baseline is refused" die

# 17. An RFC3339 instant EMBEDDED in a longer string is refused: the pattern is
#     anchored at both ends, because an unanchored one matches the instant
#     inside hostile text and then hands the whole string to date.
run_age "x ${PULLED} y" "$PULLED"
check "a timestamp embedded in a longer string is refused (anchoring)" die

# 18. Outright garbage.
run_age 'not-a-date' "$PULLED"
check "an unparseable timestamp exits 2" die

# 19. A form-valid date that is not a real one. Passes the regex and fails in
#     `date`, which is the path that would leave an empty epoch in a `[ -gt ]`
#     test -- a shell ERROR, i.e. the shape that turns a check into a no-op.
run_age '2026-13-45T99:99:99Z' "$PULLED"
check "a form-valid impossible date exits 2 rather than erroring" die

# 20. The ZERO time, which is what a timestamp-rewriting reproducible build
#     emits. It parses, and comparing it would block every legitimate release
#     while blaming the baseline, so it is refused BY NAME with its own
#     message. This is the case most likely to be hit by a future buildx
#     change, and the one where a generic "baseline is newer" would send the
#     reader looking at the wrong image.
run_age '0001-01-01T00:00:00Z' "$PULLED"
check "the zero creation time is refused by name" die
if printf '%s' "$OUT" | grep -qi 'ZERO creation timestamp'; then
  printf 'ok   ...and says so rather than blaming the baseline\n'; PASS=$((PASS + 1))
else
  printf 'FAIL ...and says so rather than blaming the baseline\n     %s\n' "$OUT"
  FAIL=$((FAIL + 1))
fi

# 21. The zero time on the BASELINE side is refused too. Note this one would
#     otherwise PASS the age comparison (year 1 is older than anything), so it
#     is the case that proves the zero-time guard is about not being able to
#     ORDER the images rather than about the direction of the result.
run_age "$PULLED" '0001-01-01T00:00:00Z'
check "the zero creation time on the baseline side is refused too" die

# ---------------------------------------------------------------------------
# FOUND IN INDEPENDENT REVIEW. Each of these three passed the first version of
# the preflight; they are here so the fixes cannot be undone silently.

# 22. A TWO-LINE timestamp whose first line is a valid instant and whose second
#     is a GNU relative item. The first spelling used `grep -Eq`, which anchors
#     `^`/`$` PER LINE -- so this satisfied the form check and `date` then read
#     the whole string and applied the shift: rc=0, "age OK", on a rebuild
#     TWELVE DAYS OLDER than its baseline. The fix is bash's `=~`, whose ERE
#     has no multiline mode. This is the single most important case in the
#     file: it is the one where the check said pass and the answer was wrong.
run_age "$(printf '2026-11-13T00:42:00Z\n+ 10 years')" '2026-11-25T21:06:56Z'
check "a multi-line timestamp carrying a relative item is refused" die

# 23. The same shape on the baseline side, which shifts the comparison the
#     other way.
run_age "$PULLED" "$(printf '2026-11-13T00:42:00Z\nnext year')"
check "a multi-line baseline timestamp is refused too" die

# 24. A trailing newline alone -- the mildest version of case 22, and the one
#     that shows `$` is end-of-STRING here rather than end-of-line. Written
#     with ANSI-C quoting on purpose: `$(printf '%s\n' ...)` cannot express
#     this input at all, because command substitution strips trailing
#     newlines -- which is also why the call site, where the value comes out
#     of `$(docker image inspect ...)`, can never produce it. Tested anyway,
#     because the function must hold without relying on its caller.
run_age $'2026-11-25T21:10:45.193977204Z\n' '2026-11-13T03:45:00Z'
check "a timestamp with a trailing newline is refused" die

# 25. THE REAL ZERO TIME IS 1970, NOT 0001. The first version named only
#     `0001-01-01` as "what a reproducible build emits"; measured on buildx
#     v0.38.1, SOURCE_DATE_EPOCH=0 emits `1970-01-01T00:00:00Z`. So the case
#     the guard was written for took the "PUBLISHED image is NEWER" branch
#     instead and blamed the baseline for a build-flag change.
run_age '1970-01-01T00:00:00Z' "$PULLED"
check "the 1970 zero time is refused by name" die
if printf '%s' "$OUT" | grep -qi 'ZERO creation timestamp'; then
  printf 'ok   ...under the zero-time message, not "baseline is newer"\n'; PASS=$((PASS + 1))
else
  printf 'FAIL ...under the zero-time message, not "baseline is newer"\n     %s\n' "$OUT"
  FAIL=$((FAIL + 1))
fi

# 26. ...and with fractional seconds, which buildkit also emits.
run_age '1970-01-01T00:00:00.000000000Z' "$PULLED"
check "the 1970 zero time with fractional seconds is refused" die

# 27. An ordinary 1970-adjacent timestamp that is NOT the zero instant must
#     still reach the age comparison rather than the zero-time message, so the
#     guard stays a guard on one value and does not swallow a whole year.
run_age '1970-06-01T12:00:00Z' "$PULLED"
check "a non-zero 1970 timestamp is judged on age, not refused by name" die
if printf '%s' "$OUT" | grep -qi 'PUBLISHED image is NEWER'; then
  printf 'ok   ...and says the baseline is newer, which it is\n'; PASS=$((PASS + 1))
else
  printf 'FAIL ...and says the baseline is newer, which it is\n     %s\n' "$OUT"
  FAIL=$((FAIL + 1))
fi

# 28. NON-GNU `date` IS AN ENVIRONMENT FAULT, NOT AN IMAGE FAULT.
#     `date -u -d <rfc3339> +%s` is a GNU extension; busybox says "invalid
#     date" and on BSD/macOS `-d` is the DST flag. Without the probe both
#     conversions came back empty and the run died blaming the two images for
#     a missing coreutils. Fails closed either way -- the point of this case is
#     the DIAGNOSIS, since a message naming the wrong thing sends the reader
#     to the wrong place on a blocked publish.
stubdir="$(mktemp -d)"
cat > "$stubdir/date" <<'STUB'
#!/bin/sh
for a in "$@"; do
  case "$a" in -d) echo "date: invalid date" >&2; exit 1 ;; esac
done
exec /bin/date "$@"
STUB
chmod +x "$stubdir/date"
set +e
OUT="$(PATH="$stubdir:$PATH" bash -c '
  '"$PRELUDE$FN"'
  assert_baseline_not_newer "$1" "$2" amd64' -- "$LOCAL" '2026-11-13T03:45:00Z' 2>&1)"
RC=$?
set -e
rm -rf "$stubdir"
check "a date(1) without GNU -d exits 2 on a legitimate pair" die
if printf '%s' "$OUT" | grep -qi 'GNU coreutils'; then
  printf 'ok   ...and blames the toolchain, not either image\n'; PASS=$((PASS + 1))
else
  printf 'FAIL ...and blames the toolchain, not either image\n     %s\n' "$OUT"
  FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# NEGATIVE CONTROL. Everything above would also pass against a function that
# does nothing at all, if the suite were only checking rc=0 cases -- so assert
# that the blocking cases DO fail without the check. Proves this suite would
# have caught the absence, not merely that today's code agrees with itself.
STUB='assert_baseline_not_newer() { :; }'
stub_rc=0
for pair in '2026-11-13T00:42:00Z|2026-11-25T21:06:56Z' "|$PULLED" "now|$PULLED" \
            "0001-01-01T00:00:00Z|$PULLED"; do
  set +e
  printf '%s%s\nassert_baseline_not_newer "$1" "$2" amd64\n' "$PRELUDE" "$STUB" \
    | bash -s -- "${pair%%|*}" "${pair##*|}" >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || stub_rc=1
done
if [ "$stub_rc" -eq 0 ]; then
  printf 'ok   negative control: every blocking case above passes with the check removed\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL negative control: a blocking case failed even with the check stubbed,\n'
  printf '     so this suite is not measuring what it claims\n'
  FAIL=$((FAIL + 1))
fi

# And the preflight must actually be CALLED. A function nobody invokes is the
# same hole as a suite nobody runs (T-0812), and this one is called from the
# arch loop rather than from another function, so nothing else would notice.
if grep -q '^  assert_baseline_not_newer \\' "$GATE"; then
  printf 'ok   the gate calls the preflight from its arch loop\n'; PASS=$((PASS + 1))
else
  printf 'FAIL the gate defines assert_baseline_not_newer but no longer calls it\n'
  FAIL=$((FAIL + 1))
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
