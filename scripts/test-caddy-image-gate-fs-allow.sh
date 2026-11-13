#!/usr/bin/env bash
# Regression suite for gate 4's FS_ALLOW_RE (T-0641).
#
# The bug this exists for: the allowlist is a START-ANCHORED alternation, and
# its FILE entries originally had no right-hand boundary. `etc/machine-id` then
# matched `etc/machine-id-EVIL/payload`, so an attacker could add arbitrary new
# paths under a name that reads as ordinary runtime noise and assertion (c) --
# gate 4's main assertion -- would excuse them.
#
# Two things make this suite worth having rather than decorative:
#
#   1. It EXTRACTS the pattern from the shipped script with sed rather than
#      copying it. A copied regex is a second source of truth that keeps passing
#      after the original changes, which is the one failure mode a regression
#      test must not have.
#   2. It asserts the key cases FAIL under the old pattern, so a green run says
#      something about whether the suite would have caught the bug, not merely
#      that today's code agrees with itself.
#
# Usage: scripts/test-caddy-image-gate-fs-allow.sh
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
gate="$here/caddy-image-gate.sh"
[ -r "$gate" ] || { echo "FAIL: cannot read $gate" >&2; exit 2; }

# Pull the DEFAULT out of the shipped assignment, so this tests the real thing.
# The line is: FS_ALLOW_DEFAULT='<regex>'
RE=$(sed -n "s/^FS_ALLOW_DEFAULT='\(.*\)'\$/\1/p" "$gate")
[ -n "$RE" ] || {
  echo "FAIL: could not extract FS_ALLOW_DEFAULT from $gate." >&2
  echo "      The assignment was probably reformatted; fix this extraction" >&2
  echo "      rather than inlining a copy of the regex." >&2
  exit 2
}

# The extracted text is used AS A REGEX here, exactly as grep will see it in the
# gate. So this also catches a default whose anchor only works after bash quote
# removal: a source spelling of `)\$` extracts as a literal dollar sign, matches
# nothing, and every legitimate path starts reporting as blocked. That is a real
# failure this suite found once already -- do not "fix" it by pre-processing the
# extracted string.
case "$RE" in
  *'\$') echo "FAIL: the default ends in a literal \\\$, not an anchor; use single quotes" >&2; exit 2 ;;
  *'$')  ;;
  *) echo "FAIL: the default is not end-anchored (expected a trailing \$)" >&2; exit 2 ;;
esac

# The pre-fix spelling, kept ONLY so the suite can prove it catches the bugs.
# Two independent defects lived in this one line: unbounded bare NAMES, and
# whole-SUBTREE apk prefixes that can hold an executable.
OLD_RE='^(/?(etc/apk/|lib/apk/|var/cache/apk/|etc/machine-id|etc/resolv\.conf|etc/hostname|etc/hosts|\.dockerenv))'

rc=0
pass=0; fail=0

# allowed <path>  -- the allowlist SHOULD excuse this (gate stays quiet)
# blocked <path>  -- the allowlist must NOT excuse it (assertion (c) fires)
check() {
  local want=$1 path=$2 re=${3:-$RE} label=${4:-current}
  local excused=no
  printf '%s\n' "$path" | grep -Eq "$re" && excused=yes
  local got=blocked; [ "$excused" = yes ] && got=allowed
  if [ "$got" = "$want" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1)); rc=1
    printf 'FAIL [%s] %-34s want=%s got=%s\n' "$label" "$path" "$want" "$got"
  fi
}

echo "== 1. legitimate runtime/apk noise is still excused =="
check allowed 'etc/apk/world'
check allowed 'lib/apk/db/installed'
check allowed 'lib/apk/db/scripts.tar'
check allowed 'lib/apk/db/triggers'
check allowed 'var/cache/apk/APKINDEX.tar.gz'
check allowed 'etc/machine-id'
check allowed 'etc/resolv.conf'
check allowed 'etc/hostname'
check allowed 'etc/hosts'
check allowed '.dockerenv'
check allowed '/etc/machine-id'          # optional leading slash still works
check allowed '/etc/apk/world'

echo "== 2. the bypass: a prefix of an allowlisted FILE name must NOT be excused =="
check blocked 'etc/machine-id-EVIL/payload'
check blocked 'etc/machine-idX'
check blocked 'etc/hostname.evil'
check blocked 'etc/hostname-backdoor.sh'
check blocked 'etc/hosts-backdoor'
check blocked 'etc/hosts/evil.crt'
check blocked '.dockerenv-evil'
check blocked '.dockerenvil'
# resolv.conf's `.` is escaped in the pattern, so this is about the tail only.
check blocked 'etc/resolv.conf.evil'
check blocked 'etc/resolv.conf/payload'

echo "== 2b. the apk SUBTREES must no longer excuse arbitrary files =="
# These three directories were allowlisted entire. A planted executable there
# was invisible to assertion (c) while reading as package-manager noise.
check blocked 'etc/apk/.hook.sh'
check blocked 'etc/apk/evil.sh'
check blocked 'etc/apk/protected_paths.d/ca-certificates.list'  # trust POLICY
check blocked 'lib/apk/db/evilbin'
check blocked 'var/cache/apk/payload.sh'
check blocked 'etc/hosts/subdir/evil.sh'   # file replaced by a directory

echo "== 3. ordinary new paths are blocked (the gate's whole point) =="
check blocked 'usr/local/bin/backdoor'
check blocked 'etc/ssl/certs/evil-root.pem'
check blocked 'usr/local/share/ca-certificates/evil.crt'
check blocked 'usr/share/ca-certificates/evil/evil-root.crt'
check blocked 'usr/share/ca-certificates/mozilla/ISRG_Root_X2.crt'

echo "== 4. the suite would have caught the bug: key cases FAIL on the old pattern =="
# Each of these was excused before the fix. If any now reports 'allowed' under
# OLD_RE it means this negative control has stopped exercising the bug, and a
# green run above would no longer mean anything.
old_caught=0
for p in 'etc/machine-id-EVIL/payload' 'etc/hostname.evil' '.dockerenv-evil' 'etc/hosts-backdoor' \
         'etc/apk/.hook.sh' 'lib/apk/db/evilbin' 'var/cache/apk/payload.sh' 'etc/hosts/subdir/evil.sh'; do
  if printf '%s\n' "$p" | grep -Eq "$OLD_RE"; then
    printf '  old pattern excused %-32s <- the bug, reproduced\n' "$p"
    old_caught=$((old_caught+1))
  else
    printf 'FAIL: old pattern did NOT excuse %s; this control no longer tests the bug\n' "$p"
    fail=$((fail+1)); rc=1
  fi
done
[ "$old_caught" -eq 8 ] || { echo "FAIL: expected 8 reproductions, got $old_caught"; rc=1; }

echo "== 5. anchoring =="
# Must be start-anchored: an allowlisted name deeper in the path is not excused.
check blocked 'usr/local/etc/machine-id'
check blocked 'opt/.dockerenv'

echo "== 6. an INVALID FS_ALLOW_RE must hard-stop, not read as clean =="
# `grep -E` exits 2 on a bad pattern and assertion (c) ends in `|| true`, so
# without an up-front check the output file is empty, empty means "0 new paths",
# and a poisoned image passes as verdict=unchanged. Measured before the fix.
# This runs the real gate far enough to hit the validation; it needs no images,
# because the check sits above any docker work.
bad_out=$(FS_DELTA=on FS_ALLOW_RE='^(unclosed[' "$gate" \
            no-such-image:test no-such-base:test "${TMPDIR:-/tmp}/t0641-fsallow-$$" amd64 2>&1 || true)
bad_rc=$(FS_DELTA=on FS_ALLOW_RE='^(unclosed[' "$gate" \
            no-such-image:test no-such-base:test "${TMPDIR:-/tmp}/t0641-fsallow-$$" amd64 >/dev/null 2>&1; echo $?)
rm -rf "${TMPDIR:-/tmp}/t0641-fsallow-$$"
if [ "$bad_rc" = 2 ]; then
  pass=$((pass+1))
else
  fail=$((fail+1)); rc=1
  printf 'FAIL: invalid FS_ALLOW_RE exited %s, want 2\n' "$bad_rc"
fi
# Exit 2 alone is not enough -- `set -e` aborting on the failing grep also exits
# 2, silently, which is the right code for the wrong reason. Require the
# diagnosis too.
if printf '%s' "$bad_out" | grep -q 'FS_ALLOW_RE is not a valid'; then
  pass=$((pass+1))
else
  fail=$((fail+1)); rc=1
  echo 'FAIL: invalid FS_ALLOW_RE produced no diagnostic (set -e aborted before the check?)'
fi

echo "== 7. comm is collation-pinned, so it agrees with the LC_ALL=C sort feeding it =="
# comm requires input sorted in ITS OWN collation and silently drops entries
# otherwise. The inputs are built with `LC_ALL=C sort`, so an unpinned comm can
# disagree -- real runs of this gate emitted "comm: input is not in sorted order".
# Gate 1's comm calls sort and compare in the same inherited locale, so they are
# self-consistent and out of scope here; only gate 4's fs-* pair must be pinned.
if grep -E '^[[:space:]]*comm -' "$gate" | grep -q 'fs-'; then
  fail=$((fail+1)); rc=1
  echo 'FAIL: a gate-4 comm over fs-* files is not LC_ALL=C pinned'
else
  pass=$((pass+1))
fi

echo "== 8. assertion (b) matches BOTH tar mode renderings =="
# GNU tar prints symbolic modes and that is what ubuntu-latest gives us, but a
# `[sS]`-only test against a tar printing the numeric permission word (04755)
# matches nothing -- and an assertion matching nothing reports zero setuid
# entries, i.e. reads as clean rather than broken. Extracted from the shipped
# script so this tests the real predicate.
suid_pred=$(sed -n 's/.*if (mode !~ \(.*\)) next.*/\1/p' "$gate" | head -1)
if [ -z "$suid_pred" ]; then
  fail=$((fail+1)); rc=1
  echo 'FAIL: could not extract the suid_of mode predicate from the gate'
else
  suid_check() { # want(yes|no) mode
    local want=$1 mode=$2 got=no
    printf 'some/path %s 100\n' "$mode" \
      | awk "{ mode=\$(NF-1); if (mode !~ $suid_pred) next; print }" \
      | grep -q . && got=yes
    if [ "$got" = "$want" ]; then
      pass=$((pass+1))
    else
      fail=$((fail+1)); rc=1
      printf 'FAIL: mode %-12s flagged=%s want=%s\n' "$mode" "$got" "$want"
    fi
  }
  suid_check yes '-rwsr-xr-x'   # symbolic setuid
  suid_check yes '-rwxr-sr-x'   # symbolic setgid
  suid_check yes '04755'        # numeric setuid
  suid_check yes '02755'        # numeric setgid
  suid_check yes '06755'        # numeric both
  suid_check no  '-rwxr-xr-x'   # ordinary executable
  suid_check no  '0755'         # ordinary, numeric
  suid_check no  '00755'        # ordinary, numeric, 5-digit
fi

echo
echo "pass=$pass fail=$fail"
[ "$rc" -eq 0 ] && echo "OK: FS_ALLOW_RE bounds both ends and the negative control reproduces the bug"
exit "$rc"
