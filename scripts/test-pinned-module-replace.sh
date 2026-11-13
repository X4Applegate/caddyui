#!/usr/bin/env bash
# Tests for check-pinned-modules.sh's `--replace` parsing (T-0710).
#
#   ./scripts/test-pinned-module-replace.sh      # exit 0 = all pass
#
# WHY THIS FILE EXISTS
# --------------------
# The watcher parsed `--with` only. T-0645 added two `--replace` pins to
# Dockerfile.caddy -- `github.com/smallstep/certificates` and
# `go.step.sm/crypto`, the pair that keeps `go-jose/go-jose/v3` out of the
# binary -- and neither was ever seen: no staleness comparison, no OSV query,
# no GitHub advisory query. The report listed every `--with` pin and said
# nothing about either, which reads exactly like a clean result.
#
# That is the T-0657 failure shape (a legal spelling the parser missed,
# silently unwatching a pin) with a worse blast radius, because the event the
# image is WAITING for -- certificates tagging its v3 removal -- is the event
# that retires both lines, and an unwatched pin is silent on it.
#
# So the cases below assert on the two properties the card named as its close
# condition, both of which FAIL on the `--with`-only implementation:
#
#   - a `--replace` pin reaches pins.tsv and the report table, with its
#     RIGHT-HAND-SIDE module and version;
#   - deleting a `--replace` line changes the table.
#
# Everything else here exists because an earlier attempt at this change passed
# a weaker check. Cases 5-7 are the region-boundary bugs: a flag name inside a
# shell error message is not a pin (and the real T-0645 Dockerfile has one), a
# comment between two pins does not end the argument list, and the `&&` in
# `RUN set -o pipefail && ... xcaddy build` is not the end of the arguments.
# Each of those produced a WRONG count on the real file, in both directions.
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

# The runtime `FROM caddy:<ver>-alpine` is required as well: T-0669's base
# sweep treats a Dockerfile it cannot find a base in as NOT SWEPT and writes an
# error, which would make every case here fail on an unrelated complaint rather
# than on what it is testing.
RUNTIME_FROM="$(sed -n 's/^FROM[[:space:]]\+\(caddy:[0-9][^[:space:]]*-alpine\)[[:space:]]*$/\1/p' \
  "$REPO/Dockerfile.caddy" | head -1)"
if [ -z "$RUNTIME_FROM" ]; then
  echo "FATAL: could not read the caddy runtime tag from Dockerfile.caddy" >&2
  exit 1
fi
RUNTIME_LINE="FROM $RUNTIME_FROM"

# The base sweep is not what these cases are about, and it costs a network
# round trip per run, so it is skipped throughout. The real Dockerfile's base
# is covered by test-pinned-module-image-sweep.sh.
export PINWATCH_SKIP_GITHUB=1

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

# There is no pin count in result.json, so it is read from pins.tsv -- which is
# the artefact the report table is built from, i.e. the thing the card's close
# condition is actually about.
pins() { wc -l < "$(lastout)/pins.tsv" | tr -d ' '; }

# Fixture rows are <pin-arg> <module> <upstream-latest>, written inline per
# case. A `--replace` pin is keyed by its RIGHT-HAND-SIDE module, which is the
# whole point: that is the code compiled in, and so the thing to compare and
# query.

echo "=== 1. a --replace pin is parsed, keyed on the RIGHT-hand side ==="
# Would fail before T-0710: pins.tsv held only the --with line.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.basic"
printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'                      > "$WORK/fx.basic"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' >> "$WORK/fx.basic"
J="$(run "$WORK/Dockerfile.basic" "$WORK/fx.basic")"
check "pin_count=2 (the --replace counts)" "2" "$(pins)"
grep -qx 'go.step.sm/crypto	v0.92.0' "$(lastout)/pins.tsv" \
  && check "pins.tsv has crypto@v0.92.0" y y || check "pins.tsv has crypto@v0.92.0" y n
grep -q 'go.step.sm/crypto' "$(lastout)/report.md" \
  && check "report table names the module" y y || check "report table names the module" y n
# The LEFT side is the path being removed; it ships nothing, so it must not be
# the thing compared or queried. For a self-replacement the two coincide, so
# this is asserted on an asymmetric case in 2 below.

echo
echo "=== 2. old=new: the NEW module is checked, the OLD one is not ==="
# A --replace may redirect to a different module entirely. Checking the
# left-hand side would report staleness and advisories for code that is not in
# the binary, while saying nothing about the code that is.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace github.com/old/gone=github.com/caddy-dns/route53@v1.6.2 \'
  echo '    --with github.com/caddy-dns/cloudflare@v0.2.4'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.rename"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n'     > "$WORK/fx.rename"
printf 'github.com/caddy-dns/cloudflare\tgithub.com/caddy-dns/cloudflare\tv0.2.4\n' >> "$WORK/fx.rename"
J="$(run "$WORK/Dockerfile.rename" "$WORK/fx.rename")"
check "pin_count=2" "2" "$(pins)"
grep -q 'github.com/caddy-dns/route53' "$(lastout)/pins.tsv" \
  && check "the REPLACEMENT is watched" y y || check "the REPLACEMENT is watched" y n
grep -q 'github.com/old/gone' "$(lastout)/pins.tsv" \
  && check "the replaced path is NOT watched" n y || check "the replaced path is NOT watched" n n

echo
echo "=== 3. an untagged pseudo-version --replace is compared, not rejected ==="
# T-0645's certificates pin is a pseudo-version ahead of every tag. It must be
# reported against upstream HEAD, not treated as malformed and dropped -- the
# untagged case is the one least able to tolerate being unwatched.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace github.com/smallstep/certificates=github.com/smallstep/certificates@v0.30.3-0.20261105213751-6d5a251fbe01 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.pseudo"
printf 'github.com/smallstep/certificates\tgithub.com/smallstep/certificates\tv0.30.2\n' > "$WORK/fx.pseudo"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n'            >> "$WORK/fx.pseudo"
J="$(run "$WORK/Dockerfile.pseudo" "$WORK/fx.pseudo")"
check "pin_count=2" "2" "$(pins)"
grep -q 'v0.30.3-0.20261105213751-6d5a251fbe01' "$(lastout)/pins.tsv" \
  && check "the pseudo-version is kept intact" y y || check "the pseudo-version is kept intact" y n
check "no parse error" "" "$(cat "$(lastout)/errors.txt")"

echo
echo "=== 4. deleting a --replace line changes the table (the close condition) ==="
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.deleted"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' > "$WORK/fx.deleted"
J="$(run "$WORK/Dockerfile.deleted" "$WORK/fx.deleted")"
check "pin_count drops to 1" "1" "$(pins)"
grep -q 'go.step.sm/crypto' "$(lastout)/report.md" \
  && check "crypto gone from the table" n y || check "crypto gone from the table" n n

echo
echo "=== 5. a flag name inside a shell message is NOT a pin ==="
# The real T-0645 Dockerfile ends its build with:
#   echo 'go-jose/v3 is linked again: the --replace pins above no longer remove it'
# That line is not a comment, so the comment filter keeps it, and the
# quote-stripping that makes --with="mod@ver" visible turns its quotes into
# spaces -- leaving a bare `--replace ` token followed by prose. Before the
# region was narrowed to xcaddy's argument list, the token counter saw 19 and
# the parser produced 18, dying `error` on a file whose pins were all fine.
# A weekly false alarm on the one job meant to be read is how a real finding
# gets skimmed past, so this is a regression test, not a nicety.
{ echo "$FROM_LINE"
  echo 'RUN set -o pipefail && xcaddy build \'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2 \'
  echo '    2>&1 | tee /tmp/xcaddy.log \'
  echo "    && if grep -q 'go-jose/v3' /tmp/mods.txt; then \\"
  echo "         echo 'go-jose/v3 is linked again: the --replace pins above no longer remove it' >&2; exit 1; \\"
  echo '       fi'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.prose"
printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'                      > "$WORK/fx.prose"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' >> "$WORK/fx.prose"
J="$(run "$WORK/Dockerfile.prose" "$WORK/fx.prose")"
check "pin_count=2, prose not counted" "2" "$(pins)"
check "no reconciliation error"        ""  "$(cat "$(lastout)/errors.txt")"

echo
echo "=== 6. a comment between two pins does not end the argument list ==="
# Docker strips comment lines out of a RUN, so a `# pin-watch:` directive sits
# between two pins with no trailing backslash and is still inside the
# invocation. Terminating the region on it cut the T-0645 file after its first
# two pins and then reported the crowdsec floor as acknowledging a pin that
# was not there.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    # pin-watch: floor pin=v1.6.2 against=v1.6.3 ref=TEST reason=a comment here must not end the region.'
  echo '    --with github.com/caddy-dns/route53@v1.6.2 \'
  echo '    --with github.com/caddy-dns/cloudflare@v0.2.4'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.midcomment"
printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'                           > "$WORK/fx.midcomment"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.3\n'      >> "$WORK/fx.midcomment"
printf 'github.com/caddy-dns/cloudflare\tgithub.com/caddy-dns/cloudflare\tv0.2.4\n' >> "$WORK/fx.midcomment"
J="$(run "$WORK/Dockerfile.midcomment" "$WORK/fx.midcomment")"
check "all 3 pins parsed past the comment" "3" "$(pins)"
check "no error"                           ""  "$(cat "$(lastout)/errors.txt")"

echo
echo '=== 7. the shell && before xcaddy build is not the end of the arguments ==='
# `RUN set -o pipefail && GOOS=... xcaddy build \` legitimately begins with
# shell. Searching the whole line for a command separator matched that `&&`
# and ended the region before a single pin was read -- 0 pins, which the
# zero-pins guard then reported as "did its format change?".
{ echo "$FROM_LINE"
  echo 'RUN set -o pipefail && GOOS=linux GOARCH=amd64 xcaddy build \'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.leadingshell"
printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'                      > "$WORK/fx.leadingshell"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' >> "$WORK/fx.leadingshell"
J="$(run "$WORK/Dockerfile.leadingshell" "$WORK/fx.leadingshell")"
check "pin_count=2 despite the leading &&" "2" "$(pins)"

echo
echo "=== 8. --replace= and a TAB separator parse like --with does ==="
# The normalisation is shared with --with on purpose (one code path), so these
# spellings should work for free. Asserted anyway: "should work for free" is
# what was believed about --replace itself.
printf 'FROM %s AS builder\nRUN xcaddy build \\\n    --replace=go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \\\n    --with\tgithub.com/caddy-dns/route53@v1.6.2\nFROM %s\n' \
  "$BUILDER_FROM" "$RUNTIME_FROM" > "$WORK/Dockerfile.spellings"
printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'                      > "$WORK/fx.spellings"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' >> "$WORK/fx.spellings"
J="$(run "$WORK/Dockerfile.spellings" "$WORK/fx.spellings")"
check "--replace= and TAB both parse" "2" "$(pins)"
check "no error"                      ""  "$(cat "$(lastout)/errors.txt")"

echo
echo "=== 9. a quoted --replace cannot silently drop out of the count ==="
# T-0657's shape. Both the parser and the token counter read the same
# quote-stripped region, so a quoted spelling either parses or is a loud
# error -- never a silently unwatched pin.
printf 'FROM %s AS builder\nRUN xcaddy build \\\n    "--replace" "go.step.sm/crypto=go.step.sm/crypto@v0.92.0" \\\n    --with github.com/caddy-dns/route53@v1.6.2\nFROM %s\n' \
  "$BUILDER_FROM" "$RUNTIME_FROM" > "$WORK/Dockerfile.quoted"
printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'                      > "$WORK/fx.quoted"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' >> "$WORK/fx.quoted"
J="$(run "$WORK/Dockerfile.quoted" "$WORK/fx.quoted")"
check "the quoted --replace is parsed, not dropped" "2" "$(pins)"

echo
echo "=== 10. a malformed --replace is loud, not silent ==="
# `--replace foo` replaces nothing. It must not vanish: the parser rejects it
# as not a module path and the token counter still counts the flag, so the two
# disagree and the run dies `error`. That is the designed behaviour -- an
# unparsed pin is never allowed to look like a clean one.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace notamodule \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.malformed"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' > "$WORK/fx.malformed"
J="$(run "$WORK/Dockerfile.malformed" "$WORK/fx.malformed")"
check "rc=3 could-not-run" "3" "$(rc)"
grep -q 'silently unwatched' "$(lastout)/stderr.txt" \
  && check "the error names the risk" y y || check "the error names the risk" y n

echo
echo "=== 11. a pin-watch floor above a --replace line is honoured ==="
# A --replace pushes a module FORWARD, past upstream's newest tag -- the
# mirror image of a floor holding one back, and it wants the same
# acknowledgement rather than a permanent finding nobody can silence.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    # pin-watch: floor pin=v0.92.0 against=v0.93.0 ref=T-0710 reason=held here deliberately while upstream settles.'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.floorrep"
printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.93.0\n'                      > "$WORK/fx.floorrep"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n' >> "$WORK/fx.floorrep"
J="$(run "$WORK/Dockerfile.floorrep" "$WORK/fx.floorrep")"
check "floors_acknowledged=1" "1" "$(j .floors_acknowledged "$J")"
check "behind=0 (floor excluded)" "0" "$(j .behind "$J")"
grep -q 'held here deliberately' "$(lastout)/report.md" \
  && check "the reason is printed" y y || check "the reason is printed" y n

echo
echo "=== 12. that floor is paired to the RIGHT-hand module ==="
# If the floor parser took the left-hand side while the pin parser took the
# right, the "floor names a pin that exists" check would fire on a correct
# Dockerfile -- two sides disagreeing about which half of `a=b@v` is the
# module. Asserted on an asymmetric replace so the two cannot coincide.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    # pin-watch: floor pin=v1.6.2 against=v1.6.3 ref=T-0710 reason=paired against the replacement, not the replaced path.'
  echo '    --replace github.com/old/gone=github.com/caddy-dns/route53@v1.6.2 \'
  echo '    --with github.com/caddy-dns/cloudflare@v0.2.4'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.floorside"
printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.3\n'       > "$WORK/fx.floorside"
printf 'github.com/caddy-dns/cloudflare\tgithub.com/caddy-dns/cloudflare\tv0.2.4\n' >> "$WORK/fx.floorside"
J="$(run "$WORK/Dockerfile.floorside" "$WORK/fx.floorside")"
check "floors_acknowledged=1" "1" "$(j .floors_acknowledged "$J")"
check "no 'no such pin' error" "" "$(cat "$(lastout)/errors.txt")"

echo
echo '=== 14. a --with under a replaced module is reported as NOT applied ==='
# xcaddy environment.go:226-230 skips `go get` for any --with whose package
# path is prefixed by a replaced module path + "/", with no error and no log
# line. The pin then sits in the Dockerfile looking enforced while having no
# effect -- this card's own "a pin that reads as present has no effect" shape,
# and the watcher is the only thing that could notice, because the skip is
# inside xcaddy rather than in the file.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    --with go.step.sm/crypto/kms@v0.92.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.shadow"
{ printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'
  printf 'go.step.sm/crypto/kms\tgo.step.sm/crypto\tv0.92.0\n'
  printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n'
} > "$WORK/fx.shadow"
J="$(run "$WORK/Dockerfile.shadow" "$WORK/fx.shadow")"
grep -q 'xcaddy SKIPS' "$(lastout)/errors.txt" \
  && check "the shadowed pin is reported" y y || check "the shadowed pin is reported" y n
grep -q 'go.step.sm/crypto/kms' "$(lastout)/errors.txt" \
  && check "the finding names the pin" y y || check "the finding names the pin" y n
# It is an $errors finding, not a notice: a pin whose version is not applied
# makes every comparison and advisory answer for it describe code that is not
# in the binary.
check "rc=3 (the numbers cannot be trusted)" "3" "$(rc)"

echo
echo '=== 15. an EXACT replace of a --with module is not a finding ==='
# xcaddy compares against `repl+"/"`, so `--replace X` plus `--with X@v` does
# not take the skip branch. Reporting it would be a false alarm on the most
# natural pairing of the two flags.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    --with go.step.sm/crypto@v0.92.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.exactrep"
{ printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'
  printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n'
} > "$WORK/fx.exactrep"
J="$(run "$WORK/Dockerfile.exactrep" "$WORK/fx.exactrep")"
grep -q 'xcaddy SKIPS' "$(lastout)/errors.txt" \
  && check "an exact match is NOT reported" n y || check "an exact match is NOT reported" n n

echo
echo '=== 16. a sibling path that merely shares a prefix is not a finding ==='
# `go.step.sm/cryptoX` is not under `go.step.sm/crypto/`. Matching on the bare
# prefix rather than prefix + "/" would report it, which is the same
# off-by-one-separator error the cross-check suite tests for /v1 vs /v2.
{ echo "$FROM_LINE"
  echo 'RUN xcaddy build \'
  echo '    --replace go.step.sm/crypto=go.step.sm/crypto@v0.92.0 \'
  echo '    --with go.step.sm/cryptoextra@v1.0.0 \'
  echo '    --with github.com/caddy-dns/route53@v1.6.2'
  echo "$RUNTIME_LINE"
} > "$WORK/Dockerfile.sibling"
{ printf 'go.step.sm/crypto\tgo.step.sm/crypto\tv0.92.0\n'
  printf 'go.step.sm/cryptoextra\tgo.step.sm/cryptoextra\tv1.0.0\n'
  printf 'github.com/caddy-dns/route53\tgithub.com/caddy-dns/route53\tv1.6.2\n'
} > "$WORK/fx.sibling"
J="$(run "$WORK/Dockerfile.sibling" "$WORK/fx.sibling")"
grep -q 'xcaddy SKIPS' "$(lastout)/errors.txt" \
  && check "a prefix-sharing sibling is NOT reported" n y || check "a prefix-sharing sibling is NOT reported" n n

echo
echo '=== 17. the shipped Dockerfile.caddy still reconciles ==='
# The region narrowing is the kind of change that can quietly stop finding the
# real file's pins, so the shipped Dockerfile is parsed with no fixture and
# only the parse is asserted (the verdict depends on live upstream data).
REAL_OUT="$(mktemp -d "$WORK/real.XXXXXX")"
PINWATCH_SKIP_GITHUB=1 "$SCRIPT" --dockerfile "$REPO/Dockerfile.caddy" \
  --out-dir "$REAL_OUT" --json >/dev/null 2>"$REAL_OUT/stderr.txt"
REAL_PINS="$(wc -l < "$REAL_OUT/pins.tsv" | tr -d ' ')"
EXPECT_PINS="$(awk '
  !inblock {
    where = match($0, /xcaddy[ \t]+build/)
    if (!where) next
    inblock = 1
    next
  }
  /^[[:space:]]*#/ { next }
  { if (match($0, /2>&1|[|;]|&&/)) exit }
  { print }
' "$REPO/Dockerfile.caddy" | grep -cE -- '(^|[[:space:]])--(with|replace)[=[:space:]]')"
check "shipped Dockerfile: pins parsed = flags present" "$EXPECT_PINS" "$REAL_PINS"
grep -q 'silently unwatched' "$REAL_OUT/stderr.txt" \
  && check "no reconciliation failure on the real file" n y \
  || check "no reconciliation failure on the real file" n n

echo
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
