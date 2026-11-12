#!/usr/bin/env bash
# Tests for check-pinned-modules.sh's intentional-floor mechanism (T-0651).
#
#   ./scripts/test-pinned-module-floors.sh      # exit 0 = all pass
#
# Most cases use `--offline-fixture`, because that is the only way to control
# what upstream's newest version is — and therefore the only way to test
# RE-ARMING, which needs upstream to move PAST the version a floor was declared
# against. A floor that cannot be shown to expire is indistinguishable from an
# ignore list, which is the thing this mechanism is specifically not.
#
# Note that fixture mode asks OSV nothing, so `advisory_unknown` is non-zero
# and the verdict is always `error` there — correctly, since an unchecked pin
# is not a clean pin. So the fixture tests assert on the floor counters and the
# report text rather than on the verdict, and the two properties that need real
# data get live tests: the verdict reachable with a floor present (case 20 via
# the live Dockerfile) and ADVISORY PRECEDENCE (case 21, chi v5.4.0's two live
# CVEs must still produce exit 2 through a valid floor).
#
# When adding a case, prefer one that would FAIL on the implementation this
# replaced: several cases here exist because a first attempt passed a weaker
# check. Cases 10/17/18 are the positional-pairing hole (a re-pin silently
# inheriting an old decision), and 19/20 are the prose-harvesting false alarm
# the Dockerfile's own documentation triggered.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check-pinned-modules.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS  %s\n' "$1"; pass=$((pass+1))
  else
    printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1))
  fi
}

# A minimal Dockerfile with two pins: one floored, one not.
mk_dockerfile() { # $1=dest $2=directive-line (may be empty)
  { echo 'FROM caddy:2.11.7-builder AS builder'
    echo 'RUN xcaddy build \'
    [ -n "$2" ] && printf '    %s\n' "$2"
    echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
    echo '    --with github.com/caddy-dns/route53@v1.6.2'
  } > "$1"
}

mk_fixture() { # $1=dest $2=crowdsec-latest $3=route53-latest
  printf 'github.com/crowdsecurity/crowdsec/pkg/apiclient\tgithub.com/crowdsecurity/crowdsec\t%s\n' "$2" > "$1"
  printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\t%s\n' "$3" >> "$1"
}

# `run` is called in a command substitution, so a plain RC=$? assignment would
# be lost with the subshell. RC and LASTOUT are passed through files instead.
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

echo "=== 1. no directive: both pins behind (the pre-T-0651 baseline) ==="
mk_dockerfile "$WORK/Dockerfile.none" ""
mk_fixture "$WORK/fx.none" "v1.8.2" "v1.6.3"
J="$(run "$WORK/Dockerfile.none" "$WORK/fx.none")"
check "behind=2"                "2"         "$(j .behind "$J")"
check "floors_acknowledged=0"   "0"         "$(j .floors_acknowledged "$J")"
# Fixture mode asks OSV nothing, so advisory_unknown always forces
# verdict=error here. That is pre-existing, correct behaviour (an unchecked
# pin is not a clean pin), so the floor logic is asserted on its own counters
# and on the behind count; verdict/rc are proven in the live run instead.
check "adv_unknown forces error in fixture mode" "error" "$(j .verdict "$J")"

echo
echo "=== 2. floor declared, upstream AT against=: acknowledged, verdict ok ==="
mk_dockerfile "$WORK/Dockerfile.ack" \
  '# pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=v1.7.8 fixes all four crowdsec advisories; raising it would break a 1.7.x bouncer and fix nothing.'
mk_fixture "$WORK/fx.ack" "v1.8.2" "v1.6.2"   # route53 current, so only the floor is behind
J="$(run "$WORK/Dockerfile.ack" "$WORK/fx.ack")"
check "behind=0 (floor excluded)"  "0"  "$(j .behind "$J")"
check "floors_acknowledged=1"      "1"  "$(j .floors_acknowledged "$J")"
check "floors_expired=0"           "0"  "$(j .floors_expired "$J")"
grep -q 'Intentional floors' "$(lastout)/report.md" \
  && check "report has Intentional floors heading" y y \
  || check "report has Intentional floors heading" y n
grep -q 'fixes all four crowdsec advisories' "$(lastout)/report.md" \
  && check "reason printed in full" y y || check "reason printed in full" y n
grep -q 'T-0636' "$(lastout)/report.md" \
  && check "ref printed" y y || check "ref printed" y n
# The all-clear sentence is only reachable when every other counter is zero,
# which fixture mode cannot be (it asks OSV nothing). Asserted in the live run.

echo
echo "=== 3. the task's sanity check: floored pin quiet, un-decided pin still behind ==="
mk_fixture "$WORK/fx.both" "v1.8.2" "v1.6.3"
J="$(run "$WORK/Dockerfile.ack" "$WORK/fx.both")"
check "behind=1 (route53 only)"    "1"         "$(j .behind "$J")"
check "floors_acknowledged=1"      "1"         "$(j .floors_acknowledged "$J")"
grep -q 'route53' "$(lastout)/report.md" && grep -q '1 pin(s) behind' "$(lastout)/report.md" \
  && check "route53 still reported behind" y y || check "route53 still reported behind" y n

echo
echo "=== 4. RE-ARM: upstream moves PAST against= -> floor expires, back to behind ==="
mk_fixture "$WORK/fx.expired" "v1.9.0" "v1.6.2"
J="$(run "$WORK/Dockerfile.ack" "$WORK/fx.expired")"
check "behind=1 (re-armed)"        "1"         "$(j .behind "$J")"
check "floors_acknowledged=0"      "0"         "$(j .floors_acknowledged "$J")"
check "floors_expired=1"           "1"         "$(j .floors_expired "$J")"
grep -q 'EXPIRED' "$(lastout)/report.md" \
  && check "report says EXPIRED" y y || check "report says EXPIRED" y n

echo
echo "=== 5. re-arm uses version order, not string order (v1.10.0 > v1.8.2) ==="
mk_fixture "$WORK/fx.v110" "v1.10.0" "v1.6.2"
J="$(run "$WORK/Dockerfile.ack" "$WORK/fx.v110")"
check "v1.10.0 expires the floor"  "1"  "$(j .floors_expired "$J")"
mk_dockerfile "$WORK/Dockerfile.ack110" \
  '# pin-watch: floor pin=v1.7.8 against=v1.10.0 ref=T-0636 reason=decided against the v1.10 series.'
J="$(run "$WORK/Dockerfile.ack110" "$WORK/fx.v110")"
check "against=v1.10.0 vs v1.10.0 is NOT expiry" "0" "$(j .floors_expired "$J")"
check "  and is acknowledged"                    "1" "$(j .floors_acknowledged "$J")"

echo
echo "=== 6. a missing reason= is an ERROR, not a quiet floor ==="
mk_dockerfile "$WORK/Dockerfile.noreason" '# pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636'
J="$(run "$WORK/Dockerfile.noreason" "$WORK/fx.ack")"
check "rc=3"                    "3"     "$(rc)"
check "floors_acknowledged=0"   "0"     "$(j .floors_acknowledged "$J")"
grep -q 'is missing' "$(lastout)/report.md" \
  && check "report explains what is missing" y y || check "report explains what is missing" y n

echo
echo "=== 7. a missing against= is an ERROR ==="
mk_dockerfile "$WORK/Dockerfile.noagainst" '# pin-watch: floor reason=because I say so'
J="$(run "$WORK/Dockerfile.noagainst" "$WORK/fx.ack")"
check "floors_acknowledged=0" "0"     "$(j .floors_acknowledged "$J")"

echo
echo "=== 8. a non-version against= is an ERROR (re-arm cannot be computed) ==="
mk_dockerfile "$WORK/Dockerfile.badver" '# pin-watch: floor pin=v1.7.8 against=newest reason=whatever'
J="$(run "$WORK/Dockerfile.badver" "$WORK/fx.ack")"
check "floors_acknowledged=0" "0"     "$(j .floors_acknowledged "$J")"

echo
echo "=== 9. an unknown directive kind is an ERROR, not a skip ==="
mk_dockerfile "$WORK/Dockerfile.unknown" '# pin-watch: ignore reason=nope'
J="$(run "$WORK/Dockerfile.unknown" "$WORK/fx.ack")"
check "floors_acknowledged=0" "0" "$(j .floors_acknowledged "$J")"
check "crowdsec still behind"  "1" "$(j .behind "$J")"
check "rc=3"                   "3" "$(rc)"
grep -q 'only .*floor.* is understood' "$(lastout)/report.md" \
  && check "report names the unknown kind" y y || check "report names the unknown kind" y n

echo
echo "=== 10. a directive matching no pin is an ERROR (stale after a re-pin) ==="
{ echo 'FROM caddy:2.11.7-builder AS builder'
  echo 'RUN xcaddy build \'
  echo '    # pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=stale, this was written for v1.7.8 and the pin is now v1.8.0.'
  echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.8.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
} > "$WORK/Dockerfile.stale"
mk_fixture "$WORK/fx.stale" "v1.8.2" "v1.6.2"
J="$(run "$WORK/Dockerfile.stale" "$WORK/fx.stale")"
check "floors_acknowledged=0" "0"     "$(j .floors_acknowledged "$J")"
grep -q 'the pin moved and the acknowledgement did not follow it' "$(lastout)/report.md" \
  && check "report names the moved pin" y y || check "report names the moved pin" y n

echo
echo "=== 11. a dangling directive with no --with after it is an ERROR ==="
{ echo 'FROM caddy:2.11.7-builder AS builder'
  echo 'RUN xcaddy build \'
  echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo '# pin-watch: floor pin=v1.7.8 against=v1.8.2 reason=orphaned at end of file'
} > "$WORK/Dockerfile.dangle"
J="$(run "$WORK/Dockerfile.dangle" "$WORK/fx.ack")"
grep -q 'acknowledges nothing' "$(lastout)/report.md" \
  && check "report says it acknowledges nothing" y y \
  || check "report says it acknowledges nothing" y n

echo
echo "=== 12. the --with count reconciliation still passes with a directive present ==="
J="$(run "$WORK/Dockerfile.ack" "$WORK/fx.ack")"
grep -q 'could not run' "$(lastout)/report.md" \
  && check "no 'could not run'" y n || check "no 'could not run'" y y

echo
echo "=== 13. intervening prose between directive and pin still pairs ==="
{ echo 'FROM caddy:2.11.7-builder AS builder'
  echo 'RUN xcaddy build \'
  echo '    # pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=paired across an explanatory comment.'
  echo '    # an ordinary explanatory comment that must not break the pairing'
  echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
} > "$WORK/Dockerfile.prose"
J="$(run "$WORK/Dockerfile.prose" "$WORK/fx.ack")"
check "still acknowledged" "1"  "$(j .floors_acknowledged "$J")"

echo
echo "=== 14. a floor does NOT silence a pin that is current (no false row) ==="
mk_fixture "$WORK/fx.current" "v1.7.8" "v1.6.2"
J="$(run "$WORK/Dockerfile.ack" "$WORK/fx.current")"
check "floors_acknowledged=0 when not behind" "0"  "$(j .floors_acknowledged "$J")"
grep -q 'Intentional floors' "$(lastout)/report.md" \
  && check "no floors section when nothing is behind" y n \
  || check "no floors section when nothing is behind" y y

echo
echo "=== 15. a pipe in the reason cannot forge a table column ==="
mk_dockerfile "$WORK/Dockerfile.pipe" \
  '# pin-watch: floor pin=v1.7.8 against=v1.8.2 reason=a | b | c forged columns'
J="$(run "$WORK/Dockerfile.pipe" "$WORK/fx.ack")"
check "still acknowledged" "1" "$(j .floors_acknowledged "$J")"
row="$(grep '^| `github.com/crowdsecurity' "$(lastout)/report.md" | grep 'acknowledged')"
check "reason's pipes are escaped" "a \\| b \\| c forged columns" \
  "$(printf '%s' "$row" | awk -F' \\| ' '{print $NF}' | sed 's/ |$//')"
# 6 real columns: splitting on UNESCAPED pipes must give 6 cells.
nf="$(printf '%s' "$row" | sed 's/\\|/\x01/g' | awk -F'|' '{print NF-2}')"
check "floors row has exactly 6 columns" "6" "$nf"

echo
echo "=== 16. the directive string in a NON-comment line declares nothing ==="
{ echo 'FROM caddy:2.11.7-builder AS builder'
  echo 'RUN echo "pin-watch: floor pin=v1.7.8 against=v1.8.2 reason=forged from a build line" && xcaddy build \'
  echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
} > "$WORK/Dockerfile.forge"
J="$(run "$WORK/Dockerfile.forge" "$WORK/fx.ack")"
check "no floor from a non-comment line" "0" "$(j .floors_acknowledged "$J")"
check "crowdsec still behind"            "1" "$(j .behind "$J")"

echo
echo "=== 17. a missing pin= is an ERROR (no silent positional fallback) ==="
mk_dockerfile "$WORK/Dockerfile.nopin" \
  '# pin-watch: floor against=v1.8.2 ref=T-0636 reason=no pin= field, so a re-pin would inherit this.'
J="$(run "$WORK/Dockerfile.nopin" "$WORK/fx.ack")"
check "floors_acknowledged=0" "0" "$(j .floors_acknowledged "$J")"
check "crowdsec still behind"  "1" "$(j .behind "$J")"
check "rc=3"                   "3" "$(rc)"
grep -q 'is missing pin=' "$(lastout)/report.md" \
  && check "report explains the missing pin=" y y \
  || check "report explains the missing pin=" y n

echo
echo "=== 18. pin= naming a DIFFERENT version than the pin is an ERROR ==="
mk_dockerfile "$WORK/Dockerfile.pinmismatch" \
  '# pin-watch: floor pin=v1.7.0 against=v1.8.2 reason=written for v1.7.0, pin is v1.7.8.'
J="$(run "$WORK/Dockerfile.pinmismatch" "$WORK/fx.ack")"
check "floors_acknowledged=0" "0" "$(j .floors_acknowledged "$J")"
check "crowdsec still behind"  "1" "$(j .behind "$J")"
grep -q 'but the pin below it is now' "$(lastout)/report.md" \
  && check "report names both versions" y y || check "report names both versions" y n

echo
echo "=== 19. header PROSE quoting the directive is not a directive ==="
# The real Dockerfile documents the mechanism in its header and quotes
# '# pin-watch: floor' while doing so. An earlier version read that sentence
# as a second declaration and reported "two directives in a row" on a correct
# file, while the real directive below went unread. Reproduced on the live
# Dockerfile; locked down here.
{ echo 'FROM caddy:2.11.7-builder AS builder'
  echo '# Security pins:'
  echo '#   - A pin behind upstream ON PURPOSE carries a `# pin-watch: floor`'
  echo '#     comment above it, read by scripts/check-pinned-modules.sh.'
  echo 'RUN xcaddy build \'
  echo '    # pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=the real one.'
  echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
} > "$WORK/Dockerfile.prosehdr"
J="$(run "$WORK/Dockerfile.prosehdr" "$WORK/fx.ack")"
check "the real directive is honoured" "1" "$(j .floors_acknowledged "$J")"
check "behind=0"                       "0" "$(j .behind "$J")"
grep -q 'two .*directives in a row' "$(lastout)/report.md" \
  && check "no false 'two directives' error" y n \
  || check "no false 'two directives' error" y y
grep -q 'the real one' "$(lastout)/report.md" \
  && check "the real reason is printed" y y || check "the real reason is printed" y n

echo
echo "=== 20. the live Dockerfile parses with no floor-parser error ==="
LIVE_OUT="$(mktemp -d "$WORK/live.XXXXXX")"
# Offline fixture so this asserts the PARSER, not the network.
printf 'x\tx\tv0.0.0\n' > "$WORK/fx.live"
"$SCRIPT" --dockerfile "$(cd "$(dirname "$0")/.." && pwd)/Dockerfile.caddy" \
  --offline-fixture "$WORK/fx.live" --out-dir "$LIVE_OUT" >/dev/null 2>&1
if grep -q 'pin-watch' "$LIVE_OUT/errors.txt" 2>/dev/null; then
  check "no pin-watch error on the live Dockerfile" y n
  sed -n 's/^/        /p' "$LIVE_OUT/errors.txt"
else
  check "no pin-watch error on the live Dockerfile" y y
fi
check "live Dockerfile declares exactly 1 floor" "1" \
  "$(wc -l < "$LIVE_OUT/floors.tsv" | tr -d ' ')"

echo
echo "=== 21. ADVISORY PRECEDENCE: exit 2 beats an acknowledged floor (live OSV) ==="
# Task point 4. Needs real OSV data, so this one is deliberately not a
# fixture test: chi v5.4.0 is the T-0634 case and carries two live CVEs via
# the GIT-range query. A floor must not be able to silence that.
# Probe with a real query: the API root returns 404, so `curl -f` on it
# reports "no network" on a perfectly reachable host and silently skipped the
# one test that proves an advisory still wins.
if curl -fsS --max-time 15 -X POST https://api.osv.dev/v1/query \
     -H 'Content-Type: application/json' \
     -d '{"package":{"name":"github.com/go-chi/chi/v5","ecosystem":"Go"},"version":"v5.4.0"}' \
     >/dev/null 2>&1; then
  { echo 'FROM caddy:2.11.7-builder AS builder'
    echo 'RUN xcaddy build \'
    echo '    # pin-watch: floor pin=v5.4.0 against=v5.5.0 ref=TEST reason=acknowledged on purpose, to prove an advisory still wins.'
    echo '    --with github.com/go-chi/chi/v5@v5.4.0 \'
    echo '    --with github.com/caddy-dns/cloudflare@v0.2.4'
  } > "$WORK/Dockerfile.advwins"
  ADV_OUT="$(mktemp -d "$WORK/adv.XXXXXX")"
  PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$WORK/Dockerfile.advwins" \
    --out-dir "$ADV_OUT" --json >/dev/null 2>&1
  arc=$?
  AJ="$(cat "$ADV_OUT/result.json" 2>/dev/null || echo '{}')"
  check "verdict=advisory despite the floor" "advisory" "$(j .verdict "$AJ")"
  check "rc=2"                               "2"        "$arc"
  check "floor NOT applied to an advisory row" "0"      "$(j .floors_acknowledged "$AJ")"
  check "the pin stays counted as behind"      "1"      "$(j .behind "$AJ")"
else
  echo "SKIP  no network to api.osv.dev"
fi

echo
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
