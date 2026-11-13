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

echo
echo "pass=$pass fail=$fail"
[ "$rc" -eq 0 ] && echo "OK: FS_ALLOW_RE bounds both ends and the negative control reproduces the bug"
exit "$rc"
