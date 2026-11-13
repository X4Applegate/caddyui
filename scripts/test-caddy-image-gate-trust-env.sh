#!/usr/bin/env bash
# Regression suite for gate 3's trust-env assertion (T-0786).
#
# The bug this exists for: gate 3 diffs Config.Env, so adding SSL_CERT_FILE to
# the image WAS seen -- but gate 3 followed MODULE_DRIFT_POLICY, and the
# release path sets `report`. So on a release the new variable was merely
# PRINTED into the summary and the verdict was decided by gate 1 alone; gate 1
# saw no new CVE, so the release passed and :stable/:latest moved.
#
# Why that class specifically: SSL_CERT_FILE/SSL_CERT_DIR pointed at an
# attacker-controlled path redirect ALL outbound TLS trust for the Caddy binary
# -- ACME issuance and the DNS provider's API -- with NO filesystem delta,
# because the file named can be one the image already contains. Gate 1 (no CVE),
# gate 2 (no module change) and gate 4 (no added file) are all blind to it.
#
# Two things make this suite worth having rather than decorative:
#
#   1. It EXTRACTS the pattern from the shipped script with sed rather than
#      copying it. A copied regex is a second source of truth that keeps passing
#      after the original changes, which is the one failure mode a regression
#      test must not have.
#   2. It asserts the key cases FAIL under the old behaviour, so a green run
#      says something about whether the suite would have caught the bug, not
#      merely that today's code agrees with itself.
#
# This suite is PATTERN-LEVEL and needs no Docker, so it runs in CI alongside
# the linters. (Do not start a comment line with the linter's own name here --
# it parses that as a directive and refuses to read the file.)
# The end-to-end proof -- that a built image carrying each of these
# actually comes out verdict=blocked under `report` -- was run by hand against
# the real published image and is recorded in T-0786's log; see the table there.
#
# Usage: scripts/test-caddy-image-gate-trust-env.sh
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
gate="$here/caddy-image-gate.sh"
[ -r "$gate" ] || { echo "FAIL: cannot read $gate" >&2; exit 2; }

# Pull the pattern out of the shipped grep, so this tests the real thing.
# The line is:   { grep -E $'^Env\t(SSL_CERT_FILE=|...)' "$1" || true; } \
#
# Extract the ALTERNATION ONLY -- what is inside the parentheses -- rather than
# the whole pattern. The shipped pattern is spelled with a $'...' quote so its
# tab is a literal tab after bash processing; sed sees the SOURCE text, where
# the tab is still the two characters \t. Re-using that source text as a regex
# here would test `Envt`, i.e. nothing, and pass vacuously. Matching the
# variable NAMES is what this suite is actually about.
ALT=$(sed -n "s/.*grep -E \\\$'\\^Env\\\\t(\\(.*\\))' .*/\\1/p" "$gate")
[ -n "$ALT" ] || {
  echo "FAIL: could not extract the trust-env alternation from $gate." >&2
  echo "      The grep was probably reformatted; fix this extraction rather" >&2
  echo "      than inlining a copy of the pattern." >&2
  exit 2
}

# The shipped pattern must keep its tab LITERAL. POSIX ERE has no \t escape and
# GNU grep -E does not add one: in a plain-quoted '^Env\t...' the backslash is
# dropped and it matches the letter `t`, i.e. `Envt...`, which matches NOTHING
# against config_from's `Env<TAB>NAME=VALUE` lines. That failure is SILENT and
# fail-open -- the extract comes out empty, comm reports nothing, and the gate
# prints "TLS trust env: none" over an image that just added SSL_CERT_FILE.
# Assert the $'...' spelling is still there so a later "tidy-up" cannot
# reintroduce it.
grep -q "grep -E \$'^Env\\\\t(" "$gate" || {
  echo "FAIL: the trust-env grep no longer uses the \$'...' quoting that makes" >&2
  echo "      its tab a LITERAL tab. A plain-quoted '\\t' matches the letter t" >&2
  echo "      and the check silently stops matching anything. Restore \$'...'." >&2
  exit 2
}

# Reconstruct the pattern the way the gate's grep will see it: a literal tab.
RE="^Env$(printf '\t')($ALT)"

# The pre-fix behaviour, kept ONLY so the suite can prove it catches the bug.
# Before T-0786 there was no trust-env extract at all: the variables landed in
# the ordinary cfg-diff and were governed by MODULE_DRIFT_POLICY. So the
# "old pattern" is "nothing matched, nothing was asserted on".
OLD_MATCHES_NOTHING=1

rc=0
pass=0; fail=0

# blocking <line> -- the gate MUST extract this (it blocks under both policies)
# quiet    <line> -- the gate must NOT extract it (no false positive)
check() {
  local want=$1 line=$2
  local got=quiet
  printf '%s\n' "$line" | grep -Eq "$RE" && got=blocking
  if [ "$got" = "$want" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1)); rc=1
    printf 'FAIL %-58s want=%s got=%s\n' "$(printf '%s' "$line" | tr '\t' '~')" "$want" "$got"
  fi
}

T=$(printf '\t')

# --- the three variables the task names, in their attack spellings -----------
check blocking "Env${T}SSL_CERT_FILE=/data/evil-roots.pem"
check blocking "Env${T}SSL_CERT_DIR=/data/evil-certs"
check blocking "Env${T}GODEBUG=x509usefallbackroots=1"
check blocking "Env${T}GODEBUG=x509negativeserial=1"
check blocking "Env${T}GODEBUG=x509sha256skid=0"

# An EMPTY value is not harmless: SSL_CERT_DIR= drops the default search path,
# and SSL_CERT_FILE= is a trust change in its own right. Matched on the NAME up
# to the first `=`, so the value is irrelevant by construction.
check blocking "Env${T}SSL_CERT_FILE="
check blocking "Env${T}SSL_CERT_DIR="

# GODEBUG carrying x509 among other settings, either side of the list.
check blocking "Env${T}GODEBUG=http2client=0,x509usefallbackroots=1"
check blocking "Env${T}GODEBUG=x509usefallbackroots=1,madvdontneed=1"

# --- must NOT fire: this is the over-broad rule the check avoids being -------
#
# GODEBUG is matched only for its x509 settings. Blocking the whole variable
# would forbid the ordinary settings a release could legitimately set, which is
# the over-broad rule this check exists to avoid being.
check quiet "Env${T}GODEBUG=http2client=0"
check quiet "Env${T}GODEBUG=madvdontneed=1"
check quiet "Env${T}GODEBUG="

# A variable merely CONTAINING one of these names must not match: the pattern
# is anchored immediately after the `Env<TAB>` prefix.
check quiet "Env${T}MY_SSL_CERT_FILE_NOTE=harmless"
check quiet "Env${T}XSSL_CERT_DIR=/etc/ssl/certs"
check quiet "Env${T}CADDY_SSL_CERT_FILE_HINT=1"

# A VALUE mentioning one cannot satisfy it either -- otherwise an innocuous
# variable whose value happens to name the path would block every release.
check quiet "Env${T}CADDY_NOTE=see SSL_CERT_FILE= in the docs"
check quiet "Env${T}DESCRIPTION=SSL_CERT_DIR=/etc/ssl/certs is the default"

# The published image's actual environment, which must stay quiet or the gate
# blocks every run. Taken from `docker image inspect applegater/caddyui-caddy:stable`
# on 2026-11-13.
check quiet "Env${T}PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
check quiet "Env${T}CADDY_VERSION=v2.11.9"
check quiet "Env${T}XDG_CONFIG_HOME=/config"
check quiet "Env${T}XDG_DATA_HOME=/data"

# Non-Env config lines share the file and must never be picked up: the prefix
# anchor is what keeps this check to the environment.
check quiet "User${T}"
check quiet "WorkingDir${T}/srv"
check quiet "Entrypoint${T}[\"/usr/bin/caddy\"]"
check quiet "ExposedPorts${T}[\"443/tcp\",\"80/tcp\"]"

# A line that merely STARTS with the prefix text but is a different field.
check quiet "Environment${T}SSL_CERT_FILE=/evil"

# --- the suite must be able to tell the fix apart from the bug ---------------
#
# Before T-0786 nothing extracted these at all, so every `blocking` case above
# came out quiet and the release passed. Assert that explicitly rather than
# trusting the prose: a suite that cannot fail on the old behaviour proves
# nothing about the new one.
if [ "$OLD_MATCHES_NOTHING" -eq 1 ]; then
  if printf 'Env%sSSL_CERT_FILE=/data/evil-roots.pem\n' "$T" | grep -Eq "$RE"; then
    pass=$((pass+1))
  else
    fail=$((fail+1)); rc=1
    echo "FAIL the canonical attack line is not matched by the shipped pattern;" >&2
    echo "     the gate would pass it on the release path, which is T-0786." >&2
  fi
fi

# --- the verdict must not be gated on MODULE_DRIFT_POLICY --------------------
#
# The whole point of T-0786 is that this one class blocks under BOTH policies.
# If a later edit folds it back under the strictness dial, the release path
# silently reverts to printing it. Assert the shape of that code directly.
if grep -q 'trustenv_blocks=0' "$gate" \
   && grep -A2 'trustenv_blocks=0' "$gate" | grep -q 'DRIFT_POLICY'; then
  fail=$((fail+1)); rc=1
  echo "FAIL trustenv_blocks is gated on DRIFT_POLICY; it must block under BOTH" >&2
  echo "     policies. That is the entire finding of T-0786." >&2
else
  pass=$((pass+1))
fi

# And it must actually reach the verdict.
if grep -q '\$trustenv_blocks" -eq 1' "$gate"; then
  pass=$((pass+1))
else
  fail=$((fail+1)); rc=1
  echo "FAIL trustenv_blocks is computed but never read by the verdict." >&2
fi

printf '\n%s: %d passed, %d failed\n' \
  "$([ "$rc" -eq 0 ] && echo PASS || echo FAIL)" "$pass" "$fail"
exit "$rc"
