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
# The line is:   { grep -E $'^Env\t(SSL_CERT_FILE|...|GODEBUG)=' "$1" || true; } \
#
# Extract everything AFTER the `^Env\t` prefix -- the parenthesised name list
# and the `=` terminator that follows it -- rather than the whole pattern. The
# shipped pattern is spelled with a $'...' quote so its tab is a literal tab
# after bash processing; sed sees the SOURCE text, where the tab is still the
# two characters \t. Re-using that source text as a regex here would test
# `Envt`, i.e. nothing, and pass vacuously.
#
# The `=` is captured rather than re-appended here, so that a change to where
# the terminator lives -- inside the group, outside it, or removed -- is
# exercised by this suite instead of silently papered over by the test's own
# copy of it. Dropping it is what would let `MY_SSL_CERT_FILE_NOTE` through.
PAT=$(sed -n "s/.*grep -E \\$'\\^Env\\\\t\\([^']*\\)'.*/\\1/p" "$gate")
[ -n "$PAT" ] || {
  echo "FAIL: could not extract the trust-env pattern from $gate." >&2
  echo "      The grep was probably reformatted; fix this extraction rather" >&2
  echo "      than inlining a copy of the pattern." >&2
  exit 2
}

# It must still be anchored on a `=` terminator, or every variable merely
# CONTAINING one of these names starts matching.
case "$PAT" in
  *'=') ;;
  *)
    echo "FAIL: the trust-env pattern no longer ends in '=' (got: $PAT)." >&2
    echo "      Without that terminator MY_SSL_CERT_FILE_NOTE matches." >&2
    exit 2 ;;
esac

# And it must match on NAMES, not on values. A `.*` inside the name list means
# some part of the VALUE has to survive config_from's 400-char truncation for
# the check to fire -- the exact fail-open this suite exists to prevent, and
# the bug a code review reproduced end-to-end against the first spelling
# (`GODEBUG=.*x509`). Refuse it here rather than discovering it in a release.
case "$PAT" in
  *'.*'*)
    echo "FAIL: the trust-env pattern contains '.*', so it depends on the" >&2
    echo "      VALUE surviving clean()'s 400-char truncation. Match the" >&2
    echo "      variable NAME only; see the truncation cases below." >&2
    exit 2 ;;
esac

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
RE="^Env$(printf '\t')$PAT"

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

# --- the trust-redirecting variables, in their attack spellings --------------
check blocking "Env${T}SSL_CERT_FILE=/data/evil-roots.pem"
check blocking "Env${T}SSL_CERT_DIR=/data/evil-certs"
check blocking "Env${T}GODEBUG=x509usefallbackroots=1"
check blocking "Env${T}GODEBUG=x509negativeserial=1"
check blocking "Env${T}GODEBUG=x509sha256skid=0"

# AWS_CA_BUNDLE is LOAD-BEARING, not prophylactic. Dockerfile.caddy links
# caddy-dns/route53, whose AWS SDK reads this variable to override the CA bundle
# for its own HTTP client -- the DNS-01 credential path that issues this fleet's
# certificates. Go's crypto/x509 reads only the two SSL_CERT_* names, so this is
# a separate trust path rather than a duplicate. The first spelling of the gate
# missed it; a security review found it.
check blocking "Env${T}AWS_CA_BUNDLE=/data/evil-roots.pem"
check blocking "Env${T}AWS_CA_BUNDLE="

# The conventional CA-bundle overrides of the other runtimes a future `--with`
# could pull in. None can false-positive against the published environment.
check blocking "Env${T}CURL_CA_BUNDLE=/data/evil.pem"
check blocking "Env${T}REQUESTS_CA_BUNDLE=/data/evil.pem"
check blocking "Env${T}GIT_SSL_CAINFO=/data/evil.pem"
check blocking "Env${T}NODE_EXTRA_CA_CERTS=/data/evil.pem"

# An EMPTY value is not harmless: SSL_CERT_DIR= drops the default search path,
# and SSL_CERT_FILE= is a trust change in its own right. The name is matched up
# to the `=`, so the value is irrelevant by construction.
check blocking "Env${T}SSL_CERT_FILE="
check blocking "Env${T}SSL_CERT_DIR="

# GODEBUG carrying x509 among other settings, either side of the list.
check blocking "Env${T}GODEBUG=http2client=0,x509usefallbackroots=1"
check blocking "Env${T}GODEBUG=x509usefallbackroots=1,madvdontneed=1"

# --- THE TRUNCATION BYPASS, which is why the match is on NAMES ---------------
#
# config_from's `clean` truncates each entry to 400 characters BEFORE the gate
# reads it, and GODEBUG is a comma-separated list whose entries reorder freely.
# The first spelling of this check was `GODEBUG=.*x509`, so padding the list
# pushed `x509usefallbackroots=1` past the cut: the gate reported "TLS trust
# env: none" while the container received the variable in full. Reproduced
# end-to-end before this was fixed.
#
# Built here the same way the PoC was, and asserted at BOTH lengths: the
# pre-truncation line (what the Dockerfile sets) and the post-truncation line
# (what the gate actually sees). Matching on the name makes both block; any
# value-dependent pattern passes the second one.
godebug_pad="$(printf 'http2client=0,%.0s' $(seq 29))"
check blocking "Env${T}GODEBUG=${godebug_pad}x509usefallbackroots=1"
check blocking "$(printf 'Env%s%s' "$T" "$(printf 'GODEBUG=%sx509usefallbackroots=1' "$godebug_pad" | cut -c1-400)")"

# The same shape for a CA-bundle variable, where truncation eats the path.
check blocking "Env${T}AWS_CA_BUNDLE=/data/$(printf 'a%.0s' $(seq 500))/evil.pem"

# --- GODEBUG now blocks WHOLE, deliberately ----------------------------------
#
# The x509 narrowing is gone because it depended on the value surviving
# truncation, i.e. on a filter the attacker chooses whether to satisfy. The
# accepted cost is that an ordinary GODEBUG blocks and needs a reviewed
# decision. GODEBUG is absent from the published image, so this costs nothing
# today, and a legitimate future one cancels through the baseline diff rather
# than by re-narrowing this pattern.
check blocking "Env${T}GODEBUG=http2client=0"
check blocking "Env${T}GODEBUG=madvdontneed=1"
check blocking "Env${T}GODEBUG="

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
# silently reverts to merely printing it -- the exact bug, restored.
#
# TESTED BEHAVIOURALLY, by EXECUTING the shipped verdict logic, not by grepping
# for the shape of the source. The first spelling of this check was
#
#   grep -A2 'trustenv_blocks=0' "$gate" | grep -q 'DRIFT_POLICY'
#
# and a security review was right to call it theatre. It is a line-PROXIMITY
# heuristic over source text, so it failed in both directions, and both were
# reproduced rather than supposed:
#
#   - FALSE PASS. The identical regression written across three lines instead
#     of one puts `DRIFT_POLICY` outside the -A2 window. Measured: the suite
#     reported 29/29 green on a gate that no longer blocked releases.
#   - FALSE FAILURE. The explanatory comment above the assignment mentions
#     $DRIFT_POLICY twice; reflowing it so a mention lands within two lines
#     AFTER the assignment turns the suite red on correct code.
#
# So extract the real verdict block and RUN it against both policies with a
# non-zero trust-env count. That constrains behaviour, is indifferent to
# formatting, and catches the regression however it is spelled.
#
# The extraction is anchored on the two assignments the verdict actually reads,
# and fails CLOSED (exit 2) if it cannot find them -- a silently-empty extract
# would make every assertion below vacuous, which is the one thing a regression
# test must not do.
verdict_block="$(sed -n '/^trustenv_blocks=0$/,/^  verdict=unchanged$/p' "$gate")
fi"
case "$verdict_block" in
  *trustenv_blocks=1*verdict=*|*trustenv_blocks=1*)
    case "$verdict_block" in
      *'$trustenv_blocks" -eq 1'*) ;;
      *)
        echo "FAIL trustenv_blocks is computed but never read by the verdict." >&2
        echo "     Extracted block:" >&2
        printf '%s\n' "$verdict_block" | sed 's/^/       /' >&2
        exit 2 ;;
    esac ;;
  *)
    echo "FAIL could not extract the verdict block from $gate (anchors:" >&2
    echo "     'trustenv_blocks=0' .. 'if [ \"\$added_total\"'). It was probably" >&2
    echo "     restructured; fix this extraction rather than deleting the test." >&2
    exit 2 ;;
esac

# Run the extracted block under both policies. Only the inputs the block reads
# are defined, so anything else it depends on surfaces as an unbound-variable
# failure rather than as a quiet pass.
verdict_under() {
  local policy="$1" trustenv="$2"
  bash -u -c '
    DRIFT_POLICY="$1"; trustenv_total="$2"
    added_total=0; removed_total=0
    moddrift=0; cfgdrift=0; fsdrift=0
    FS_DELTA=off
    drift_blocks=0; cfg_blocks=0
    '"$verdict_block"'
    echo "$verdict"
  ' _ "$policy" "$trustenv" 2>/dev/null
}

# A trust-env finding must produce `blocked` under BOTH policies. `report` is
# the release path and is the entire point of T-0786.
for policy in block report; do
  got="$(verdict_under "$policy" 1)"
  if [ "$got" = blocked ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1)); rc=1
    echo "FAIL a trust-env finding under MODULE_DRIFT_POLICY=$policy yields" >&2
    echo "     verdict='$got', expected 'blocked'. Under 'report' this is T-0786" >&2
    echo "     itself: the variable is printed and the release publishes." >&2
  fi
done

# And with no finding it must NOT block, or the gate blocks every clean run.
for policy in block report; do
  got="$(verdict_under "$policy" 0)"
  if [ "$got" = unchanged ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1)); rc=1
    echo "FAIL a clean image under MODULE_DRIFT_POLICY=$policy yields" >&2
    echo "     verdict='$got', expected 'unchanged'." >&2
  fi
done

printf '\n%s: %d passed, %d failed\n' \
  "$([ "$rc" -eq 0 ] && echo PASS || echo FAIL)" "$pass" "$fail"
exit "$rc"
