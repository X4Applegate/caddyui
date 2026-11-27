#!/usr/bin/env bash
# Tests for assert-floor-versions.sh (T-0667).
#
#   ./scripts/test-floor-versions.sh      # exit 0 = all pass
#
# The assertion compares a Dockerfile's `# pin-watch: floor` pins against the
# module versions actually linked into a built binary. Testing it needs a
# binary whose module graph is KNOWN and CONTROLLABLE, which a real caddy
# build is not: the whole point of the bug is that MVS decides the version, so
# a test that builds the real image would assert whatever MVS chose that day
# and would pass for the wrong reason.
#
# So the graph is faked. `go version -m` is a plain-text reader, so the cases
# below build tiny Go programs with the right module paths... which is slow and
# needs a network. Instead the script's one external read is stubbed: PATH is
# prefixed with a directory containing a `go` that prints a fixture graph.
# That is a smaller lie than it sounds -- the format is stable, documented and
# three fields wide, and the behaviour under test is the COMPARISON, not go's
# ability to print.
#
# Case 5 is the one that matters most: it is the real measured divergence
# (crowdsec pinned v1.7.8, linked v1.8.1) that the downgrade grep cannot see.
# Case 6 is its mirror and must FAIL the build. Case 8 is the fail-open shape
# the script exists to remove: a floor naming a module the binary does not
# contain must not exit 0.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/assert-floor-versions.sh"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BUILDER_FROM="$(sed -n 's/^FROM .*\(caddy:[0-9][^ ]*-builder\) AS builder$/\1/p' \
  "$REPO/Dockerfile.caddy" | head -1)"
[ -n "$BUILDER_FROM" ] || { echo "FATAL: cannot read builder tag" >&2; exit 1; }
FROM_LINE="FROM $BUILDER_FROM AS builder"

pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'PASS  %s\n' "$1"; pass=$((pass+1))
  else
    printf 'FAIL  %s\n        expected: %s\n        actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1))
  fi
}

# A stub `go` that prints a fixture graph for `go version -m <path>`.
mk_go_stub() { # $1=dir $2=graph-file
  mkdir -p "$1"
  cat > "$1/go" <<STUB
#!/usr/bin/env bash
if [ "\${1:-}" = "version" ] && [ "\${2:-}" = "-m" ]; then
  cat "$2"
  exit 0
fi
exit 1
STUB
  chmod +x "$1/go"
}

mk_graph() { # $1=dest ; then module<TAB>version pairs on stdin
  : > "$1"
  echo "	path	github.com/caddyserver/caddy/v2/cmd/caddy" >> "$1"
  echo "	mod	github.com/caddyserver/caddy/v2	v2.11.9	h1:fake=" >> "$1"
  while IFS=$'\t' read -r m v; do
    [ -n "$m" ] || continue
    printf '\tdep\t%s\t%s\th1:fake=\n' "$m" "$v" >> "$1"
  done
}

mk_dockerfile() { # $1=dest $2=directive $3=pin-line
  { echo "$FROM_LINE"
    echo 'RUN xcaddy build \'
    [ -n "$2" ] && printf '    %s\n' "$2"
    printf '    %s\n' "$3"
    echo '    --with github.com/caddy-dns/route53@v1.6.2'
  } > "$1"
}

run() { # $1=dockerfile $2=graph [extra args...]
  local df="$1" gf="$2"; shift 2
  local stub="$WORK/stub.$$.$RANDOM"
  mk_go_stub "$stub" "$gf"
  PATH="$stub:$PATH" "$SCRIPT" --binary "$WORK/fakebin" --dockerfile "$df" "$@" \
    > "$WORK/out.txt" 2>"$WORK/err.txt"
  printf '%s' "$?" > "$WORK/.rc"
  rm -rf "$stub"
}
rc()  { cat "$WORK/.rc"; }
out() { cat "$WORK/out.txt"; }
err() { cat "$WORK/err.txt"; }

: > "$WORK/fakebin"

echo "=== 1. no floor directive: nothing to assert, and it says so ==="
mk_dockerfile "$WORK/D1" "" '--with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
mk_graph "$WORK/G1" <<< $'github.com/crowdsecurity/crowdsec\tv1.7.8'
run "$WORK/D1" "$WORK/G1"
check "rc=0"                 "0" "$(rc)"
check "says nothing to assert" "1" "$(out | grep -c 'nothing to assert')"

echo
echo "=== 2. floor exactly equal to the linked version: ok ==="
mk_dockerfile "$WORK/D2" '# pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=test' \
  '--with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
mk_graph "$WORK/G2" <<< $'github.com/crowdsecurity/crowdsec\tv1.7.8'
run "$WORK/D2" "$WORK/G2"
check "rc=0"            "0" "$(rc)"
check "reports [ok]"    "1" "$(out | grep -c '\[ok\]')"
check "1 checked"       "1" "$(out | grep -c '1 floor(s) checked: 0 violation(s), 0 divergence(s)')"

echo
echo "=== 3. package path walks up to its module path (trap 1) ==="
# The --with argument is a PACKAGE (.../pkg/apiclient); the graph only ever
# contains the MODULE (.../crowdsec). A script that matched exactly would find
# no row and, before this, would have had nothing to say about it.
check "graph has no package row" "0" "$(grep -c 'pkg/apiclient' "$WORK/G2")"
check "but the floor resolved"   "1" "$(out | grep -c 'pinned v1.7.8, linked v1.7.8')"

echo
echo "=== 4. major-version suffix is part of the module path, not stripped ==="
mk_dockerfile "$WORK/D4" '# pin-watch: floor pin=v5.5.0 against=v5.6.0 ref=T-0652 reason=test' \
  '--with github.com/go-chi/chi/v5@v5.5.0 \'
mk_graph "$WORK/G4" <<< $'github.com/go-chi/chi/v5\tv5.5.0'
run "$WORK/D4" "$WORK/G4"
check "rc=0"           "0" "$(rc)"
check "matched at /v5" "1" "$(out | grep -c 'pinned v5.5.0, linked v5.5.0')"

echo
echo "=== 5. THE MEASURED CASE: a plugin raised the floor past its pin ==="
# crowdsec pinned v1.7.8, bouncer v0.15.0 requires v1.8.1, MVS resolves to
# 1.8.1. A real xcaddy build of this prints no `go: downgraded` line, so the
# Dockerfile's grep is silent and the binary disagrees with the pin.
mk_dockerfile "$WORK/D5" '# pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=test' \
  '--with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
mk_graph "$WORK/G5" <<< $'github.com/crowdsecurity/crowdsec\tv1.8.1'
run "$WORK/D5" "$WORK/G5"
check "rc=0 (reported, not failed)" "0" "$(rc)"
check "reports [DIVERGED]"          "1" "$(out | grep -c '\[DIVERGED\]')"
check "names both versions"         "1" "$(out | grep -c 'pinned v1.7.8, LINKED v1.8.1')"
check "counts 1 divergence"         "1" "$(out | grep -c '0 violation(s), 1 divergence(s)')"

echo
echo "=== 5b. the same case under --strict fails the build ==="
run "$WORK/D5" "$WORK/G5" --strict
check "rc=1"            "1" "$(rc)"
check "says --strict"   "1" "$(out | grep -c -- '--strict: a floor was raised')"

echo
echo "=== 6. linked BELOW the floor: a violation, always fatal ==="
mk_graph "$WORK/G6" <<< $'github.com/crowdsecurity/crowdsec\tv1.7.0'
run "$WORK/D5" "$WORK/G6"
check "rc=1"                  "1" "$(rc)"
check "reports [VIOLATED]"    "1" "$(out | grep -c '\[VIOLATED\]')"
check "says BELOW the pin"    "1" "$(out | grep -c 'BELOW the pin')"
check "counts 1 violation"    "1" "$(out | grep -c '1 violation(s)')"

echo
echo "=== 7. ordering is version-aware, not lexical ==="
# v1.10.0 > v1.9.0 numerically but sorts BEFORE it as a string. A lexical
# comparison would call this a violation and fail a correct build.
mk_dockerfile "$WORK/D7" '# pin-watch: floor pin=v1.9.0 against=v1.11.0 ref=T-0667 reason=test' \
  '--with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.9.0 \'
mk_graph "$WORK/G7" <<< $'github.com/crowdsecurity/crowdsec\tv1.10.0'
run "$WORK/D7" "$WORK/G7"
check "rc=0 (1.10.0 is above 1.9.0)" "0" "$(rc)"
check "reports DIVERGED not VIOLATED" "1" "$(out | grep -c '\[DIVERGED\]')"

echo
echo "=== 8. FAIL-OPEN GUARD: a floor whose module is not in the binary ==="
# "no row matched" must never exit the same as "matched and was fine".
mk_graph "$WORK/G8" <<< $'github.com/caddy-dns/route53\tv1.6.2'
run "$WORK/D5" "$WORK/G8"
check "rc=1"                "1" "$(rc)"
check "reports [ERROR] row" "1" "$(out | grep -c '\[ERROR\]')"
check "explains asserts nothing" "1" "$(err | grep -c 'asserts nothing')"

echo
echo "=== 9. an unreadable binary is not a clean one ==="
mk_graph "$WORK/G9" < /dev/null
: > "$WORK/G9"
run "$WORK/D5" "$WORK/G9"
check "rc=2 (could not run)" "2" "$(rc)"
check "says unreadable"      "1" "$(err | grep -c 'listed no modules')"

echo
echo "=== 10. a directive whose pin= no longer matches is a hard error ==="
# The re-pin hole: without this the new version silently inherits the old
# decision's assertion and is compared against the wrong number.
mk_dockerfile "$WORK/D10" '# pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=test' \
  '--with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.8.0 \'
mk_graph "$WORK/G10" <<< $'github.com/crowdsecurity/crowdsec\tv1.8.0'
run "$WORK/D10" "$WORK/G10"
check "rc=2"                   "2" "$(rc)"
check "names both versions"    "1" "$(err | grep -c 'written for .*v1.7.8.* but the pin below it is .*v1.8.0')"

echo
echo "=== 11. a directive with no pin= is a hard error ==="
mk_dockerfile "$WORK/D11" '# pin-watch: floor against=v1.8.2 ref=T-0636 reason=test' \
  '--with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
run "$WORK/D11" "$WORK/G2"
check "rc=2"          "2" "$(rc)"
check "says no pin="  "1" "$(err | grep -c 'has no pin=')"

echo
echo "=== 12. header prose mentioning the directive must not parse as one ==="
# Dockerfile.caddy documents its own syntax in a comment. The watcher had this
# exact false-positive; anchoring on the comment's FIRST token is what fixes it.
{ echo "$FROM_LINE"
  echo '# A pin that is behind on purpose carries a `# pin-watch: floor` comment.'
  echo 'RUN xcaddy build \'
  echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
} > "$WORK/D12"
run "$WORK/D12" "$WORK/G2"
check "rc=0"                   "0" "$(rc)"
check "nothing to assert"      "1" "$(out | grep -c 'nothing to assert')"

echo
echo "=== 13. equals/quote/tab spellings of --with are read identically ==="
mk_dockerfile "$WORK/D13" '# pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=test' \
  '--with="github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8" \'
run "$WORK/D13" "$WORK/G5"
check "rc=0"                "0" "$(rc)"
check "still diverged"      "1" "$(out | grep -c '\[DIVERGED\]')"

echo
echo "=== 14. multiple floors are each asserted ==="
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    # pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0636 reason=test'
  echo '    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
  echo '    # pin-watch: floor pin=v0.62.0 against=v0.63.0 ref=T-0667 reason=test'
  echo '    --with golang.org/x/net/http2@v0.62.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
} > "$WORK/D14"
mk_graph "$WORK/G14" <<EOF
github.com/crowdsecurity/crowdsec	v1.8.1
golang.org/x/net	v0.62.0
EOF
run "$WORK/D14" "$WORK/G14"
check "rc=0"           "0" "$(rc)"
check "2 checked"      "1" "$(out | grep -c '2 floor(s) checked: 0 violation(s), 1 divergence(s)')"

echo
echo "=== 15. --json emits the per-floor states ==="
run "$WORK/D5" "$WORK/G5" --json
check "json state=above" "above" "$(out | grep '^{' | jq -r '.floors[0].state')"
check "json linked"      "v1.8.1" "$(out | grep '^{' | jq -r '.floors[0].linked')"

echo
echo "=== 16. GITHUB_OUTPUT cannot report a clean run on an error ==="
GO_OUT="$WORK/ghout.txt"; : > "$GO_OUT"
stub="$WORK/stub.err"; mk_go_stub "$stub" "$WORK/G9"
PATH="$stub:$PATH" GITHUB_OUTPUT="$GO_OUT" "$SCRIPT" --binary "$WORK/fakebin" \
  --dockerfile "$WORK/D5" >/dev/null 2>&1
check "violations=unknown not 0" "1" "$(grep -c 'floor_violations=unknown' "$GO_OUT")"
rm -rf "$stub"

echo
echo "=== 16b. \`security\` directives are asserted too (T-0667 coverage) ==="
# Keying the assertion on `floor` alone covered ONE of the four security pins
# and reported clean for the other three -- this file's own failure mode,
# reproduced inside the fix. The `security` kind exists so a pin that is AT
# upstream can be asserted against the artefact WITHOUT being filed as
# "intentionally behind" and exempted from the staleness check.
mk_dockerfile "$WORK/D16b" '# pin-watch: security pin=v0.62.0 ref=T-0667 reason=CVE floor' \
  '--with golang.org/x/net/http2@v0.62.0 \'
mk_graph "$WORK/G16b" <<< $'golang.org/x/net	v0.62.0'
run "$WORK/D16b" "$WORK/G16b"
check "rc=0"                   "0" "$(rc)"
check "asserted, not skipped"  "1" "$(out | grep -c '1 floor(s) checked')"
check "labelled (security)"    "1" "$(out | grep -c '(security)')"

echo
echo "=== 16c. a security pin linked BELOW its minimum still fails ==="
mk_graph "$WORK/G16c" <<< $'golang.org/x/net	v0.60.0'
run "$WORK/D16b" "$WORK/G16c"
check "rc=1"                "1" "$(rc)"
check "reports [VIOLATED]"  "1" "$(out | grep -c '\[VIOLATED\]')"

echo
echo "=== 16d. security pins require pin= exactly as floors do ==="
# Without it the directive pairs positionally and a re-pin silently inherits
# the decision, comparing the binary against a version nobody chose.
mk_dockerfile "$WORK/D16d" '# pin-watch: security ref=T-0667 reason=no pin field' \
  '--with golang.org/x/net/http2@v0.62.0 \'
run "$WORK/D16d" "$WORK/G16b"
check "rc=2"                     "2" "$(rc)"
check "names the kind in error"  "1" "$(err | grep -c 'security directive .* has no pin=')"

echo
echo "=== 17. against the REAL Dockerfile and the REAL measured graph ==="
# The live Dockerfile parses, and EVERY declared floor is asserted — both
# `floor` kinds and all three `security` kinds, not just the one the watcher
# knew about first. The graph is the one measured on the published image, so
# this is the shipped-image case end to end.
#
# THIS FIXTURE TRACKS THE LIVE DOCKERFILE AND WILL GO STALE WHEN A FLOOR IS
# ADDED OR REPINNED. It has three times: route53 gained a `# pin-watch: floor`
# directive (T-0637) after this case was written, I182 added a `security`
# floor on aws-sdk-go-v2/service/route53, and T-0753 repinned crowdsec to
# v1.8.1 and go-jose to v4.1.9. Because a floor whose module has no
# row in the graph is a hard error rather than a pass — correctly, that is the
# fail-open shape assert-floor-versions.sh exists to remove — each drift
# surfaced as failures here rather than as a silent miscount. Keeping this case
# green therefore means updating the graph when a pin moves; that coupling is
# the point, not an inconvenience.
#
# The graph below is what the PUBLISHED binary links, measured with
# `go version -m` on /usr/bin/caddy extracted from applegater/caddyui-caddy:stable.
# Since T-0753 the written pins equal it exactly, so the live file has no
# divergence left and passes under --strict — which is the condition the
# publish paths now depend on, asserted here against the real file.
mk_graph "$WORK/G17" <<EOF
github.com/crowdsecurity/crowdsec	v1.8.1
golang.org/x/net	v0.62.0
github.com/go-chi/chi/v5	v5.5.0
github.com/go-jose/go-jose/v4	v4.1.9
github.com/aws/aws-sdk-go-v2/service/route53	v1.59.4
github.com/caddy-dns/route53	v1.6.2
EOF
run "$REPO/Dockerfile.caddy" "$WORK/G17"
check "rc=0"                      "0" "$(rc)"
check "no divergence left"        "0" "$(out | grep -c '\[DIVERGED\]')"
check "no parse error"            "0" "$(err | grep -c 'ERROR')"
# The coverage assertion. A regression that drops a directive would still
# exit 0 with a clean-looking report, so the COUNT is checked explicitly.
check "all 6 declared floors checked" "1" "$(out | grep -c '6 floor(s) checked')"
check "all 6 are [ok]"                "6" "$(out | grep -c '\[ok\]')"
# The publish paths pass --strict (T-0753), so the live file must satisfy the
# strict reading too. If it does not, every release fails — which is a thing to
# learn here rather than from a red pipeline.
run "$REPO/Dockerfile.caddy" "$WORK/G17" --strict
check "live pins pass --strict"       "0" "$(rc)"

echo
echo "=== 18. the live Dockerfile is readable by the WATCHER too ==="
# The two scripts parse the same directives. A `security` kind the watcher
# rejects would turn the weekly run into verdict=error, so the Dockerfile
# edit and the watcher change have to land together.
if "$REPO/scripts/check-pinned-modules.sh" --dockerfile "$REPO/Dockerfile.caddy" \
     --offline-fixture /dev/null --out-dir "$WORK/w18" >/dev/null 2>&1; then :; fi
# `grep -c` exits 1 on zero matches, so the `|| echo 0` fallback appends a
# SECOND line to the substitution rather than replacing it, and the check
# compares "0\n0" against "0". Count through wc instead, which always exits 0.
check "no unknown-kind error" "0" \
  "$(grep 'unknown .*pin-watch' "$WORK/w18/errors.txt" 2>/dev/null | wc -l | tr -d ' ')"
check "4 security pins recorded" "4" \
  "$(wc -l < "$WORK/w18/security-pins.tsv" 2>/dev/null | tr -d ' ')"

echo
echo "=== 18b. --expect catches reading a DIFFERENT file than was built ==="
# `docker build -f Dockerfile.variant .` builds the variant, but a
# `COPY Dockerfile.caddy` inside it fetches the CONTEXT's copy. Measured: a
# variant demanding crowdsec v1.9.0 built clean, exited 0 and produced a
# byte-identical image digest, because the edited directive was never read.
# A clean result computed from the wrong file is the fail-open shape this
# whole script exists to remove, so it had to be closed inside the fix too.
run "$WORK/D5" "$WORK/G5" --expect "github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8"
check "matching --expect passes" "0" "$(rc)"
run "$WORK/D5" "$WORK/G5" --expect "github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.9.0"
check "mismatched --expect exits 2" "2" "$(rc)"
check "names both versions" "1" "$(err | grep -c 'but .* has github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8')"
check "says it is the wrong file" "1" "$(err | grep -c 'is not the one built')"

echo
echo "=== 18c. --expect names a pin the Dockerfile does not have at all ==="
run "$WORK/D5" "$WORK/G5" --expect "github.com/not/here@v1.0.0"
check "rc=2"                 "2" "$(rc)"
check "says no such argument" "1" "$(err | grep -c 'no such --with argument')"

echo
echo "=== 18d. the live Dockerfile satisfies its OWN FLOOR_SELFCHECK ARG ==="
# The ARG default in Dockerfile.caddy is a hand-kept echo of the pins, so it
# can drift from them. It must not drift silently: this reads the ARG out of
# the real file and feeds it back, which is exactly what the build does.
LIVE_EXPECT="$(sed -n 's/^ARG FLOOR_SELFCHECK="\(.*\)"$/\1/p' "$REPO/Dockerfile.caddy" | head -1)"
check "ARG is present" "0" "$( [ -n "$LIVE_EXPECT" ] && echo 0 || echo 1 )"
run "$REPO/Dockerfile.caddy" "$WORK/G17" --expect "$LIVE_EXPECT"
check "live ARG matches live pins" "0" "$(rc)"
check "no mismatch reported"       "0" "$(err | grep -c 'is not the one built')"

echo
echo "=== 19. the real file runs under BUSYBOX ASH, not just bash ==="
# Dockerfile.caddy runs this inside caddy:*-builder, WHICH HAS NO BASH. The
# shebang says bash, so every local run and every CI run uses bash and a
# bash-only construct would pass all of the above and fail only inside
# `docker build` -- where the error reads as a broken build, not a broken
# check. So the real file is executed by busybox ash here, in both the
# clean-exit and the fail-exit direction.
#
# Skipped rather than failed when docker is unavailable: a developer without
# docker should still be able to run this suite, and a skipped case that says
# so is honest where a silent pass would not be.
if command -v docker >/dev/null 2>&1 \
   && docker image inspect "$BUILDER_FROM" >/dev/null 2>&1; then
  ASHWORK="$WORK/ash"; mkdir -p "$ASHWORK"
  cp "$SCRIPT" "$ASHWORK/assert.sh"
  # The `go` stub for THIS case must be POSIX too, with a /bin/sh shebang.
  # mk_go_stub above writes `#!/usr/bin/env bash`, and the builder image has
  # no bash, so the stub itself fails to execute: `go version -m` then returns
  # nothing, the script correctly reports an empty graph and exits 2, and the
  # case looks exactly like the script being bash-only -- which is the one
  # thing this case exists to tell apart. Caught while writing it.
  cat > "$ASHWORK/go" <<'ASHSTUB'
#!/bin/sh
if [ "${1:-}" = "version" ] && [ "${2:-}" = "-m" ]; then
  cat /w/graph.txt
  exit 0
fi
exit 1
ASHSTUB
  chmod +x "$ASHWORK/go"
  printf '\tmod\tgithub.com/caddyserver/caddy/v2\tv2.11.9\th1:x=\n' > "$ASHWORK/graph.txt"
  printf '\tdep\tgithub.com/crowdsecurity/crowdsec\tv1.8.1\th1:x=\n' >> "$ASHWORK/graph.txt"
  cp "$WORK/D5" "$ASHWORK/Dockerfile.probe"
  : > "$ASHWORK/fakebin"
  ash_rc() { # $1=extra args
    docker run --rm -v "$ASHWORK:/w" -w /w "$BUILDER_FROM" \
      sh -c "PATH=/w:\$PATH sh assert.sh --binary /w/fakebin --dockerfile /w/Dockerfile.probe $1 >/w/ash.out 2>/w/ash.err"
    printf '%s' "$?"
  }
  r="$(ash_rc '')"
  check "ash: divergence exits 0" "0" "$r"
  check "ash: found the divergence" "1" "$(grep -c '\[DIVERGED\]' "$ASHWORK/ash.out" 2>/dev/null || echo 0)"
  check "ash: no shell syntax error" "0" \
    "$(grep -ciE 'syntax error|bad substitution|not found' "$ASHWORK/ash.err" 2>/dev/null | head -1)"
  # The direction that must fail the build.
  printf '\tdep\tgithub.com/crowdsecurity/crowdsec\tv1.7.0\th1:x=\n' > "$ASHWORK/graph.txt"
  printf '\tmod\tgithub.com/caddyserver/caddy/v2\tv2.11.9\th1:x=\n' >> "$ASHWORK/graph.txt"
  r="$(ash_rc '')"
  check "ash: violation exits 1" "1" "$r"
else
  echo "SKIP  docker or $BUILDER_FROM unavailable; cannot test under busybox ash"
fi

echo
echo "=== 20. version ordering is SEMVER, not \`sort -V\` ==="
# The comparison used `sort -V`, which is a filename-version sort with no
# concept of a prerelease, so it ordered v1.7.8-rc1 ABOVE v1.7.8 and a binary
# linked BELOW its floor was reported as a divergence with exit 0 -- a clean
# answer on the exact condition the floor exists to catch.
#
# Every expectation below is Go's: `golang.org/x/mod/semver.Compare`, which is
# what `go get` itself orders versions with. The full cross product of 40
# versions (1600 pairs) was differential-tested against that function while
# this was written, with zero disagreements; these cases are the subset a
# regression would most likely break, kept here because the oracle needs a Go
# toolchain and a module download and this file must run anywhere.
#
# The pseudo-version rows are the reachable ones: `v<X.Y.Z>-0.<ts>-<sha>` is
# what Go emits for a commit pin, Dockerfile.caddy already carries one, and
# `--replace` is the only mechanism that can pull a module below MVS's choice.
mk_ver_df() { # $1=dest $2=pin
  { echo "$FROM_LINE"
    echo 'RUN xcaddy build \'
    printf '    # pin-watch: security pin=%s ref=T-0816 reason=ordering probe\n' "$2"
    printf '    --with github.com/go-jose/go-jose/v4@%s \\\n' "$2"
    echo '    --with github.com/caddy-dns/route53@v1.6.2'
  } > "$1"
}
ver_state() { # $1=pin $2=linked -> "<state> rc=<n>"
  mk_ver_df "$WORK/Dv" "$1"
  mk_graph "$WORK/Gv" <<EOF
github.com/go-jose/go-jose/v4	$2
github.com/caddy-dns/route53	v1.6.2
EOF
  run "$WORK/Dv" "$WORK/Gv"
  local s
  if   out | grep -q '\[VIOLATED\]';   then s=below
  elif out | grep -q '\[DIVERGED\]';   then s=above
  elif out | grep -q 'NOT ORDERABLE';  then s=unordered
  elif out | grep -q '\[ok\]        github.com/go-jose'; then s=equal
  else s="unreported"; fi
  printf '%s rc=%s' "$s" "$(rc)"
}
# pin                                    linked                                  expected
while IFS='|' read -r v_pin v_linked v_want; do
  [ -n "$v_pin" ] || continue
  check "pin $v_pin vs linked $v_linked" "$v_want" "$(ver_state "$v_pin" "$v_linked")"
done <<'CASES'
v4.1.7|v4.1.7|equal rc=0
v4.1.7|v4.1.9|above rc=0
v4.1.9|v4.1.7|below rc=1
v1.9.0|v1.10.0|above rc=0
v1.10.0|v1.9.0|below rc=1
v1.7.8|v1.7.8-rc1|below rc=1
v1.7.8-rc1|v1.7.8|above rc=0
v1.7.8-rc2|v1.7.8-rc1|below rc=1
v1.0.0-alpha|v1.0.0-alpha.1|above rc=0
v1.0.0-alpha.1|v1.0.0-alpha|below rc=1
v1.0.0-beta.11|v1.0.0-beta.2|below rc=1
v1.0.0-beta.2|v1.0.0-beta.11|above rc=0
v1.0.0|v1.0.0+meta|equal rc=0
v0.92.1|v0.92.1-0.20261105213751-6d5a251fbe01|below rc=1
v0.92.0|v0.92.1-0.20261105213751-6d5a251fbe01|above rc=0
v0.30.3-0.20261201000000-aaaaaaaaaaaa|v0.30.3-0.20261105213751-6d5a251fbe01|below rc=1
CASES

echo
echo "=== 21. the guard cannot disarm itself ==="
# Three one-step edits each left the assertion exiting 0 having checked
# nothing. They are the worst shape available to a check -- an affirmative
# pass on its own absence -- so each is pinned with its own case.
#
# The live Dockerfile and its real ARG value are used, because what is being
# tested is that THIS build's configuration cannot be neutered, not that a
# fixture can.
LIVE_DF="$REPO/Dockerfile.caddy"
LIVE_EXPECT_21="$(sed -n 's/^ARG FLOOR_SELFCHECK="\(.*\)"$/\1/p' "$LIVE_DF" | head -1)"
check "the live ARG is readable" "0" "$( [ -n "$LIVE_EXPECT_21" ] && echo 0 || echo 1 )"

# 21a. Delete the directives, keep the pins and the ARG. Was: "nothing to
# assert", exit 0. --expect checks `--with` ARGUMENTS by design, so it saw
# nothing wrong; it now also requires each named pin to carry a directive.
grep -v '# pin-watch:' "$LIVE_DF" > "$WORK/D21a"
run "$WORK/D21a" "$WORK/G17" --expect "$LIVE_EXPECT_21"
check "21a directives stripped -> rc=2"  "2" "$(rc)"
# Counted as yes/no, not as an exact number: there is one error line per
# declared floor, so pinning the count here would make adding a floor fail a
# case about something else.
check "21a says the pin is UNASSERTED"   "yes" \
  "$( [ "$(err | grep -c 'present and UNASSERTED')" -gt 0 ] && echo yes || echo no )"

# 21b. Mistype the kinds. Was: silently skipped with a note that the weekly
# watcher would catch it -- true, and the wrong place for it, because this is
# what runs inside every `docker build`.
sed -e 's/# pin-watch: security /# pin-watch: Security /g' \
    -e 's/# pin-watch: floor /# pin-watch: floorx /g' "$LIVE_DF" > "$WORK/D21b"
run "$WORK/D21b" "$WORK/G17"
check "21b mistyped kind -> rc=2"        "2" "$(rc)"
check "21b names the unknown kind"       "yes" \
  "$( [ "$(err | grep -c 'unknown .*pin-watch.* kind')" -gt 0 ] && echo yes || echo no )"
# One mistyped directive among valid ones must also fail, not be absorbed.
sed -e '0,/# pin-watch: security /s//# pin-watch: securty /' "$LIVE_DF" > "$WORK/D21c"
check "21b one mistyped kind is enough"  "2" "$(run "$WORK/D21c" "$WORK/G17"; rc)"

# 21c. An --expect that contains no token. `[ -n " " ]` is true and
# `for want in $EXPECT` then iterates zero times, so every pin "agreed".
# Reachable as `docker build --build-arg FLOOR_SELFCHECK=" "`.
run "$LIVE_DF" "$WORK/G17" --expect "   "
check "21c blank --expect -> rc=2"       "2" "$(rc)"
check "21c says nothing was compared"    "1" "$(err | grep -c 'no .*pkg@version.* token')"

# And the control: with all three left alone, the live file still passes.
run "$LIVE_DF" "$WORK/G17" --expect "$LIVE_EXPECT_21"
check "21 control: untouched still rc=0" "0" "$(rc)"
echo
echo "=== 22. --strict turns a divergence into a build failure ==="
# The reporting/strict split IS the T-0753 decision, so both readings of the
# same input are asserted rather than one. Same Dockerfile, same graph, one
# flag apart.
mk_dockerfile "$WORK/D20" '# pin-watch: floor pin=v1.7.8 against=v1.8.2 ref=T-0753 reason=test' \
  '--with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \'
mk_graph "$WORK/G20" <<< $'github.com/crowdsecurity/crowdsec\tv1.8.1'
run "$WORK/D20" "$WORK/G20"
check "reporting: lift exits 0"      "0" "$(rc)"
check "reporting: names it diverged" "1" "$(out | grep -c '\[DIVERGED\]')"
run "$WORK/D20" "$WORK/G20" --strict
check "strict: lift exits 1"         "1" "$(rc)"
check "strict: still names it"       "1" "$(out | grep -c '\[DIVERGED\]')"
# --strict must not change the BELOW-pin answer, which was never optional.
mk_graph "$WORK/G20b" <<< $'github.com/crowdsecurity/crowdsec\tv1.7.0'
run "$WORK/D20" "$WORK/G20b"
check "below pin fails without --strict too" "1" "$(rc)"
# And a clean run is still clean under --strict: the flag escalates the
# divergence and nothing else. Without this case a --strict that failed
# unconditionally would satisfy every other assertion here.
mk_graph "$WORK/G20c" <<< $'github.com/crowdsecurity/crowdsec\tv1.7.8'
run "$WORK/D20" "$WORK/G20c" --strict
check "strict: equal is still ok"    "0" "$(rc)"

echo
echo "=== 23. a pin BEHIND the artefact fails --strict, which is what T-0753 fixed ==="
# The state this card found: go-jose written v4.1.7 while the binary shipped
# v4.1.9, because the go.step.sm/crypto --replace (T-0718) requires v4.1.9.
# Nothing reported it until the pins were asserted against the artefact. The
# pre-T-0753 Dockerfile is reconstructed here so the regression cannot return
# silently: whatever the live file says, THIS shape must still fail --strict.
mk_dockerfile "$WORK/D21" '# pin-watch: security pin=v4.1.7 ref=T-0646 reason=test' \
  '--with github.com/go-jose/go-jose/v4@v4.1.7 \'
mk_graph "$WORK/G21" <<EOF
github.com/go-jose/go-jose/v4	v4.1.9
github.com/caddy-dns/route53	v1.6.2
EOF
run "$WORK/D21" "$WORK/G21"
check "reporting: the stale pin builds"  "0" "$(rc)"
check "reporting: and is named"          "1" "$(out | grep -c '\[DIVERGED\]')"
run "$WORK/D21" "$WORK/G21" --strict
check "strict: the stale pin does NOT"   "1" "$(rc)"

echo
echo "=== 24. every publish path passes FLOOR_STRICT=1 ==="
# A build-arg is invisible to every other check in this repo. The Dockerfile
# defaults to the REPORTING reading on purpose, so a publish step that loses
# `FLOOR_STRICT=1` keeps building, keeps passing, and publishes under the
# weaker standard with nothing to show it happened. Hence a structural
# assertion against the workflows rather than a review habit.
#
# The step list is DERIVED from the YAML at run time, not written here: the set
# of steps that build Dockerfile.caddy is whatever the workflows say today, so a
# new publish step is covered the moment it is added rather than when somebody
# remembers to extend a fixture.
# Reviewer-found gaps (independent review of this card), all fixed here:
#   - `with.file` was matched by exact string, so `file: ./Dockerfile.caddy`
#     silently dropped a step out of scope. Matched by basename now.
#   - only `missing == 0` was asserted, never `total`, so a deleted publish
#     step read as a pass having examined nothing. `total` is now pinned to
#     the real count of Dockerfile.caddy build steps in THIS tree, read from
#     the files rather than hard-coded, so adding a step is still covered.
#   - the negative control only ever de-stricted release-docker.yml, so a
#     dropped flag on caddy-image-refresh.yml's OWN three build steps was
#     unexercised. The control now runs once per workflow file that actually
#     has a Dockerfile.caddy build step, and asserts the sed edit really
#     changed something before trusting its result.
if python3 -c 'import yaml' 2>/dev/null; then
  probe="$WORK/strict-probe.py"
  cat > "$probe" <<'PY'
import sys, pathlib, yaml
root = pathlib.Path(sys.argv[1])
bad, total = [], 0
for wf in sorted(root.glob("*.yml")):
    doc = yaml.safe_load(wf.read_text()) or {}
    for jname, job in (doc.get("jobs") or {}).items():
        for step in (job.get("steps") or []):
            with_ = step.get("with") or {}
            raw = str(with_.get("file", "")).strip().strip('"').strip("'")
            if pathlib.PurePosixPath(raw).name != "Dockerfile.caddy":
                continue
            total += 1
            args = with_.get("build-args") or ""
            if isinstance(args, list):
                args = "\n".join(str(a) for a in args)
            pairs = [l.strip() for l in str(args).splitlines() if l.strip()]
            if "FLOOR_STRICT=1" not in pairs:
                bad.append("%s:%s:%s" % (wf.name, jname, step.get("name", "?")))
print("total=%d" % total)
print("missing=%d" % len(bad))
for b in bad:
    print("BAD %s" % b)
PY
  python3 -I "$probe" "$REPO/.github/workflows" > "$WORK/strict.txt" 2>&1 || true
  st_total="$(sed -n 's/^total=//p' "$WORK/strict.txt" | head -1)"
  st_missing="$(sed -n 's/^missing=//p' "$WORK/strict.txt" | head -1)"
  # A parse failure leaves both empty, and an empty total would let the
  # missing-count check pass having examined nothing. "No publish step was
  # found" and "every publish step is strict" must not share a result, so the
  # count is asserted to be a positive number FIRST.
  case "${st_total:-}" in
    ''|*[!0-9]*) parsed="no: $(head -3 "$WORK/strict.txt" | tr '\n' ' ')" ;;
    0)           parsed="no: found no Dockerfile.caddy build step at all" ;;
    *)           parsed=yes ;;
  esac
  check "workflows parsed, steps found"          "yes" "$parsed"
  # EXACTLY 4, not merely ">0": the live count of Dockerfile.caddy build steps
  # across every workflow today (caddy-image-refresh.yml's 2 scan builds + 1
  # publish build, release-docker.yml's 1 publish build). A step silently
  # removed or renamed out of scope must fail THIS check, not read as
  # "nothing to report". When a step is legitimately added or removed, update
  # this number in the same change.
  check "exactly 4 Dockerfile.caddy build steps found" "4" "${st_total:-0}"
  check "every Dockerfile.caddy build is strict" "0"   "${st_missing:-unparsed}"
  [ "${st_missing:-1}" = "0" ] || grep '^BAD ' "$WORK/strict.txt" || true
  # The probe must be able to FAIL, against EVERY workflow file that has a
  # Dockerfile.caddy build step -- not just one of them, which is what let a
  # dropped flag on caddy-image-refresh.yml's three build steps go unexercised
  # (reviewer finding). One de-stricted copy per such file, each checked alone
  # so a miss on any one is attributable.
  neg_dir="$WORK/wfneg"
  mkdir -p "$neg_dir"
  for wf in "$REPO"/.github/workflows/*.yml; do
    grep -q 'file: Dockerfile.caddy' "$wf" || continue
    wfname="$(basename "$wf")"
    rm -rf "$neg_dir"; mkdir -p "$neg_dir"
    sed 's/^\( *\)FLOOR_STRICT=1$/\1FLOOR_STRICT=0/' "$wf" > "$neg_dir/$wfname"
    # The control's own precondition: the sed edit must have changed
    # something, or "nothing to flip" and "probe caught it" are indistinguishable.
    check "$wfname: the negative control actually flipped a line" "1" \
      "$( ! diff -q "$wf" "$neg_dir/$wfname" >/dev/null 2>&1 && echo 1 || echo 0 )"
    python3 -I "$probe" "$neg_dir" > "$WORK/strict-neg-$wfname.txt" 2>&1 || true
    # The sed flips EVERY FLOOR_STRICT=1 line in the file, so a file with
    # several build steps (caddy-image-refresh.yml has 3) reports several
    # missing, not exactly 1. The property under test is "the probe noticed",
    # i.e. non-zero, not a specific count tied to today's step count.
    neg_missing="$(sed -n 's/^missing=//p' "$WORK/strict-neg-$wfname.txt" | head -1)"
    check "$wfname: the probe catches a dropped flag" "caught" \
      "$( [ "${neg_missing:-0}" -gt 0 ] 2>/dev/null && echo caught || echo "not caught (missing=${neg_missing:-?})" )"
  done
else
  echo "SKIP  python3 yaml unavailable; cannot assert the workflows' FLOOR_STRICT"
  check "python3 yaml is available (do not silently skip the FLOOR_STRICT guard)" "1" "0"
fi

echo
echo "=== 25. FLOOR_STRICT is validated, not interpolated ==="
# The Dockerfile derives the flag from the ARG through a `case`. A typo must be
# a hard error, because silently building the WEAKER way is the one outcome
# that would make the strict reading losable by accident.
dfp="$REPO/Dockerfile.caddy"
check "ARG FLOOR_STRICT defaults to 0" "1" \
  "$(grep -c '^ARG FLOOR_STRICT=0$' "$dfp")"
# Comment lines are stripped first: the block above DOCUMENTS the unsafe form
# in prose, so a grep over the whole file matches the explanation and reports
# the very defect it is warning about. Checked in both directions — the raw ARG
# must never reach the script's argument list, and the DERIVED variable must,
# because "neither is passed" would satisfy a one-sided check while silently
# dropping --strict everywhere.
check "the ARG never reaches the arg list" "0" \
  "$(grep -v '^[[:space:]]*#' "$dfp" | grep -cE '(assert-floor-versions\.sh|--expect).*\$FLOOR_STRICT' || true)"
check "the derived flag does"              "1" \
  "$(grep -cE '^[[:space:]]+\$strict$' "$dfp" || true)"
check "an unknown value is rejected" "1" \
  "$(grep -c 'FLOOR_STRICT must be 0 or 1' "$dfp")"
# Runs the Dockerfile's OWN case statement, extracted from the file, so this
# tests the shipped logic rather than a copy of it that can drift from it.
case_src="$(sed -n '/^ARG FLOOR_STRICT=0$/,/^    sh \/tmp\/assert-floor-versions.sh/p' "$dfp" \
            | sed -e '1d' -e '$d' -e 's/^RUN //' -e 's/\\$//')"
check "the case statement was extracted" "1" \
  "$(printf '%s' "$case_src" | grep -c 'case "\$FLOOR_STRICT" in')"
strict_of() { # $1=FLOOR_STRICT value -> prints "rc=<n> strict=<selected flag>"
  local v="$1" rc=0 res
  res="$(FLOOR_STRICT="$v" sh -c "$case_src"' printf "%s" "${strict-}"' 2>/dev/null)" || rc=$?
  printf 'rc=%s strict=%s' "$rc" "$res"
}
check "1 selects --strict"      "rc=0 strict=--strict" "$(strict_of 1)"
check "0 selects reporting"     "rc=0 strict="         "$(strict_of 0)"
# '' used to be in the reporting arm, so an unset/blank --build-arg silently
# built the weaker way (reviewer finding). ARG FLOOR_STRICT=0 already covers
# "not passed at all"; an EXPLICITLY blank value is now a hard error like any
# other unrecognised spelling, not a second way to ask for reporting.
check "explicit empty is rejected, not silent reporting" "rc=2 strict=" "$(strict_of '')"
check "true selects --strict"   "rc=0 strict=--strict" "$(strict_of true)"
check "a typo is exit 2"        "rc=2 strict="         "$(strict_of stirct)"
check "junk is exit 2"          "rc=2 strict="         "$(strict_of '--strict; echo pwned')"

echo
echo "=== 26. zero directives without --expect (T-0906) ==="
# 21a covers the stripped file WITH --expect. Without it, a hand run used to
# get "nothing to assert", exit 0 -- the fail-open this pins shut.
run "$WORK/D21a" "$WORK/G17" --strict
check "26a stripped, --strict, no --expect -> rc=2" "2" "$(rc)"
check "26a names the cause" "1" "$(err | grep -c 'under --strict; nothing was asserted')"
run "$WORK/D21a" "$WORK/G17" --min-floors 1
check "26b stripped, --min-floors 1 -> rc=2" "2" "$(rc)"
check "26b names the count" "1" "$(err | grep -c 'parsed 0 .*--min-floors requires at least 1')"
LIVE_MIN_22="$(sed -n 's/^ARG FLOOR_MIN=\([0-9]*\)$/\1/p' "$LIVE_DF" | head -1)"
check "26c the live FLOOR_MIN is readable" "0" "$( [ -n "$LIVE_MIN_22" ] && echo 0 || echo 1 )"
check "26c FLOOR_MIN equals the pins in FLOOR_SELFCHECK" "$(echo $LIVE_EXPECT_21 | wc -w | tr -d ' ')" "$LIVE_MIN_22"
run "$LIVE_DF" "$WORK/G17" --expect "$LIVE_EXPECT_21" --min-floors "$LIVE_MIN_22" --strict
check "26d live file at its own FLOOR_MIN -> rc=0" "0" "$(rc)"
run "$LIVE_DF" "$WORK/G17" --min-floors "$(( LIVE_MIN_22 + 1 ))"
check "26e one more than the live count -> rc=2" "2" "$(rc)"
run "$WORK/D21a" "$WORK/G17" --min-floors 'x1'
check "26f non-integer --min-floors -> rc=2" "2" "$(rc)"
check "26g Dockerfile passes --min-floors" "1" "$(grep -c -- '--min-floors "\$FLOOR_MIN"' "$LIVE_DF")"
# Case 1 is unchanged on purpose: no --strict, no --min-floors, zero
# directives is still "nothing to assert", exit 0.

echo
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
