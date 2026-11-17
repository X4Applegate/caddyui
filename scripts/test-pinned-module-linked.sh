#!/usr/bin/env bash
# Tests for check-pinned-modules.sh's `linked` column — what the built binary
# actually contains, beside what the Dockerfile asks for (T-0752, option C
# from T-0667).
#
#   ./scripts/test-pinned-module-linked.sh      # exit 0 = all pass
#
# A sibling of test-pinned-module-floors.sh, test-pinned-module-image-sweep.sh
# and test-floor-versions.sh.
#
# ---------------------------------------------------------------------------
# WHY THIS SUITE EXISTS
# ---------------------------------------------------------------------------
# The pin table read the Dockerfile TEXT, so it said
# `crowdsec/pkg/apiclient v1.7.8` while the shipped binary carried
# `crowdsec v1.8.1` — accurate about intent, silent about outcome. The column
# closes that gap, and the thing most likely to go wrong with it is NOT the
# happy path:
#
#   THE DEGRADATION STORY IS THE RISK. A run without `--binary` must say
#   *not measured*. An empty cell there would read as "nothing was linked" —
#   the most alarming possible reading of the most common run, and precisely
#   the unswept/clean confusion the image sweep already had to fix once.
#   Cases 2, 7 and 8 exist for that and nothing else.
#
#   A MISS MUST NOT LOOK LIKE A MATCH. A `--with` argument is a PACKAGE path
#   and `go version -m` reports MODULE paths, so the lookup walks the path up.
#   If that walk silently failed, every row would render **not linked** and a
#   reader would conclude the binary was empty. Case 3 pins the walk.
#
# Fixtures are faked the same way test-floor-versions.sh fakes them: a stub
# `go` that prints a graph file for `go version -m`. `go version -m` is a
# plain-text reader, so a fixture graph is a faithful stand-in and the suite
# needs neither a toolchain nor a 236-module image to run.
#
# PINWATCH_SKIP_GITHUB=1 throughout: this suite is about rendering a local
# fact, and the advisory network path is covered by its own suites. It also
# keeps the run off GitHub's 60/hour unauthenticated budget.
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

# A graph in `go version -m` layout: leading TAB, tab-separated fields.
# The `mod` row is deliberately `(devel)`, which is what a locally built
# binary really reports and which case 6 asserts is never rendered.
mk_graph() { # $1=dest ; then module<TAB>version pairs on stdin
  : > "$1"
  printf '\tpath\tgithub.com/caddyserver/caddy/v2/cmd/caddy\n' >> "$1"
  printf '\tmod\tcaddy\t(devel)\t\n' >> "$1"
  while IFS=$'\t' read -r m v; do
    [ -n "$m" ] || continue
    printf '\tdep\t%s\t%s\th1:fake=\n' "$m" "$v" >> "$1"
  done
}

FROM_LINE='FROM caddy:2.11.9-builder AS builder'

mk_dockerfile() { # $1=dest ; then full --with lines on stdin
  { echo "$FROM_LINE"
    echo 'RUN xcaddy build \'
    cat
  } > "$1"
}

# Run the watcher. `--binary` is passed only when a graph is given, so the
# no-binary degradation path is exercised by the same helper.
run() { # $1=dockerfile $2=graph-or-empty [extra args...]
  local df="$1" gf="$2"; shift 2
  local stub="$WORK/stub.$$.$RANDOM"
  local out="$WORK/out.$$.$RANDOM"
  rm -rf "$WORK/report"; mkdir -p "$WORK/report"
  if [ -n "$gf" ]; then
    mk_go_stub "$stub" "$gf"
    PATH="$stub:$PATH" PINWATCH_SKIP_GITHUB=1 "$SCRIPT" \
      --dockerfile "$df" --binary "$WORK/fakebin" --out-dir "$WORK/report" \
      > "$WORK/stdout.txt" 2>"$WORK/stderr.txt"
  else
    PINWATCH_SKIP_GITHUB=1 "$SCRIPT" \
      --dockerfile "$df" --out-dir "$WORK/report" \
      > "$WORK/stdout.txt" 2>"$WORK/stderr.txt"
  fi
  printf '%s' "$?" > "$WORK/.rc"
  rm -rf "$stub" "$out"
}

# The `linked` cell of the row whose module column contains $1.
cell() { # $1=substring of the module cell
  awk -F'|' -v m="$1" '$2 ~ m { gsub(/^ +| +$/, "", $4); print $4; exit }' \
    "$WORK/report/report.md"
}
report() { cat "$WORK/report/report.md"; }

: > "$WORK/fakebin"

# ---------------------------------------------------------------------------
echo "=== 1. the header gains the column ==="
# ---------------------------------------------------------------------------
mk_dockerfile "$WORK/D1" <<'EOF'
    --with github.com/caddy-dns/route53@v1.6.2 \
EOF
mk_graph "$WORK/G1" <<< $'github.com/caddy-dns/route53\tv1.6.2'
run "$WORK/D1" "$WORK/G1"
check "header names linked between pinned and upstream" \
  "1" "$(report | grep -c '^| module | pinned | linked | upstream | advisories |$')"
check "separator row widened to 5 columns" \
  "1" "$(report | grep -c '^| --- | --- | --- | --- | --- |$')"

# ---------------------------------------------------------------------------
echo
echo "=== 2. NO BINARY: not measured, never an empty cell ==="
# ---------------------------------------------------------------------------
# The core degradation case. An empty cell here reads as "nothing linked".
run "$WORK/D1" ""
check "cell says not measured"      "*not measured*" "$(cell 'route53')"
check "no empty linked cell anywhere" \
  "0" "$(awk -F'|' '/^\| `/ { gsub(/ /,"",$4); if ($4=="") n++ } END{print n+0}' \
         "$WORK/report/report.md")"
check "summary states the column was not measured" \
  "1" "$(report | grep -c 'The `linked` column was not measured')"
check "summary does NOT claim a clean comparison" \
  "0" "$(report | grep -c 'exactly its written version')"

# ---------------------------------------------------------------------------
echo
echo "=== 3. package path walks up to its module path (trap 1) ==="
# ---------------------------------------------------------------------------
# The real crowdsec case: --with names a PACKAGE, the graph holds the MODULE.
mk_dockerfile "$WORK/D3" <<'EOF'
    --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \
EOF
mk_graph "$WORK/G3" <<< $'github.com/crowdsecurity/crowdsec\tv1.8.1'
run "$WORK/D3" "$WORK/G3"
check "package path resolves to its module and reports raised" \
  '`v1.8.1` (raised)' "$(cell 'apiclient')"
check "it is NOT reported as not linked" \
  "0" "$(report | grep -c 'not linked')"
check "summary counts the divergence" \
  "1" "$(report | grep -c '1 of 1 pin(s) do not match the built binary')"
check "summary explains raised is not an error" \
  "1" "$(report | grep -c 'not an error')"

# ---------------------------------------------------------------------------
echo
echo "=== 4. equal, below and absent are three distinct renderings ==="
# ---------------------------------------------------------------------------
mk_dockerfile "$WORK/D4" <<'EOF'
    --with github.com/caddy-dns/route53@v1.6.2 \
    --with github.com/go-chi/chi/v5@v5.5.0 \
    --with github.com/example/ghost@v1.0.0 \
EOF
mk_graph "$WORK/G4" <<EOF
github.com/caddy-dns/route53	v1.6.2
github.com/go-chi/chi/v5	v5.4.0
EOF
run "$WORK/D4" "$WORK/G4"
check "equal renders as the bare version"    '`v1.6.2`'             "$(cell 'route53')"
check "below the pin is flagged lowered"     '`v5.4.0` (**lowered**)' "$(cell 'chi')"
check "a module not in the graph is not linked" '**not linked**'    "$(cell 'ghost')"
check "equal row is not called a divergence" \
  "1" "$(report | grep -c '2 of 3 pin(s) do not match')"
check "lowered is tied to the build-time guard" \
  "1" "$(report | grep -c 'assert-floor-versions.sh` fails the build')"

# ---------------------------------------------------------------------------
echo
echo "=== 5. /vN major-version suffix matches at full length ==="
# ---------------------------------------------------------------------------
# chi/v5 is its own module path; the walk must stop there and must not strip
# the suffix and match a different major.
mk_dockerfile "$WORK/D5" <<'EOF'
    --with github.com/go-chi/chi/v5@v5.5.0 \
EOF
mk_graph "$WORK/G5" <<EOF
github.com/go-chi/chi	v1.0.0
github.com/go-chi/chi/v5	v5.5.0
EOF
run "$WORK/D5" "$WORK/G5"
check "v5 matches v5, not the v1 module" '`v5.5.0`' "$(cell 'chi')"

# ---------------------------------------------------------------------------
echo
echo "=== 6. (devel) main module is never rendered as a version ==="
# ---------------------------------------------------------------------------
# A locally built binary reports its main module with the literal version
# `(devel)` rather than a semver. If a pin's walk landed on a row like that,
# the cell would print a string that looks like a version and is not one.
#
# The graph below puts `(devel)` on a REAL module path that a pin resolves to,
# which is the only way the walk can reach it. Without the version filter in
# the index builder this renders `linked (devel)`.
mk_dockerfile "$WORK/D6" <<'EOF'
    --with github.com/example/devel/pkg/sub@v1.0.0 \
EOF
: > "$WORK/G6"
printf '\tpath\tgithub.com/caddyserver/caddy/v2/cmd/caddy\n'  >> "$WORK/G6"
printf '\tmod\tgithub.com/example/devel\t(devel)\t\n'        >> "$WORK/G6"
printf '\tdep\tgithub.com/caddy-dns/route53\tv1.6.2\th1:f=\n' >> "$WORK/G6"
run "$WORK/D6" "$WORK/G6"
check "(devel) is never rendered as a version" "0" "$(report | grep -c 'devel)')"
check "the pin reports not linked instead" '**not linked**' "$(cell 'example/devel')"

# ---------------------------------------------------------------------------
echo
echo "=== 7. an unreadable binary is not-measured, not a clean run ==="
# ---------------------------------------------------------------------------
# `go version -m` producing no module rows must degrade exactly like the
# no-binary case, NOT render every pin as **not linked** (which would read as
# a binary containing nothing).
: > "$WORK/G7"          # an empty graph: no dep/mod rows at all
run "$WORK/D1" "$WORK/G7"
check "cell is not measured, not 'not linked'" "*not measured*" "$(cell 'route53')"
check "no row claims not linked"               "0" "$(report | grep -c '\*\*not linked\*\*')"
check "summary says the column was not measured" \
  "1" "$(report | grep -c 'The `linked` column was not measured')"

# ---------------------------------------------------------------------------
echo
echo "=== 8. a fully matching run says so positively ==="
# ---------------------------------------------------------------------------
# The clean statement must be reachable, and must be distinguishable from the
# not-measured run -- otherwise the reader cannot tell "checked and fine" from
# "never checked", which is the whole point of the column.
mk_dockerfile "$WORK/D8" <<'EOF'
    --with github.com/caddy-dns/route53@v1.6.2 \
    --with github.com/go-chi/chi/v5@v5.5.0 \
EOF
mk_graph "$WORK/G8" <<EOF
github.com/caddy-dns/route53	v1.6.2
github.com/go-chi/chi/v5	v5.5.0
EOF
run "$WORK/D8" "$WORK/G8"
check "states every pin is linked at its written version" \
  "1" "$(report | grep -c 'Every pin above is linked into the built binary at exactly its written version (2 measured)')"
check "does not also claim a divergence" \
  "0" "$(report | grep -c 'do not match the built binary')"
check "clean run is distinguishable from not-measured" \
  "0" "$(report | grep -c 'was not measured')"

# ---------------------------------------------------------------------------
echo
echo "=== 9. the column does not disturb the other columns ==="
# ---------------------------------------------------------------------------
# A row is now 5 cells wide. A renderer that lost a field would shift the
# advisory cell into upstream, which reads as a clean row.
run "$WORK/D8" "$WORK/G8"
check "every pin row has exactly 5 cells" \
  "0" "$(awk -F'|' '/^\| `/ { if (NF != 7) n++ } END{print n+0}' \
         "$WORK/report/report.md")"
check "pinned column still holds the written pin" \
  "1" "$(awk -F'|' '$2 ~ /route53/ { gsub(/ |`/,"",$3); print ($3=="v1.6.2") }' \
         "$WORK/report/report.md")"

# ---------------------------------------------------------------------------
echo
echo "=== 10. machine output: not-measured is not 0 ==="
# ---------------------------------------------------------------------------
# The same distinction the column draws, carried into --json and
# GITHUB_OUTPUT. A consumer branching on `linked_raised == 0` must not read
# "measured and matching" out of a run that measured nothing.
jrun() { # $1=dockerfile $2=graph-or-empty
  local df="$1" gf="$2"
  local stub="$WORK/stub.j.$RANDOM"
  rm -rf "$WORK/report"; mkdir -p "$WORK/report"
  : > "$WORK/gho"
  if [ -n "$gf" ]; then
    mk_go_stub "$stub" "$gf"
    PATH="$stub:$PATH" PINWATCH_SKIP_GITHUB=1 GITHUB_OUTPUT="$WORK/gho" "$SCRIPT" \
      --dockerfile "$df" --binary "$WORK/fakebin" --out-dir "$WORK/report" --json \
      >/dev/null 2>&1
  else
    PINWATCH_SKIP_GITHUB=1 GITHUB_OUTPUT="$WORK/gho" "$SCRIPT" \
      --dockerfile "$df" --out-dir "$WORK/report" --json >/dev/null 2>&1
  fi
  rm -rf "$stub"
}

if command -v jq >/dev/null 2>&1; then
  jrun "$WORK/D3" "$WORK/G3"
  check "json counts the raised pin" \
    "1" "$(jq -r '.linked_raised' "$WORK/report/result.json")"
  check "json counts it as measured" \
    "1" "$(jq -r '.linked_measured' "$WORK/report/result.json")"

  jrun "$WORK/D3" ""
  check "json reports null, NOT 0, when nothing was measured" \
    "null" "$(jq -r '.linked_raised' "$WORK/report/result.json")"
  check "json linked_measured is null too" \
    "null" "$(jq -r '.linked_measured' "$WORK/report/result.json")"
  check "GITHUB_OUTPUT says not-measured, NOT 0" \
    "linked_raised=not-measured" "$(grep '^linked_raised=' "$WORK/gho")"
else
  echo "SKIP  json assertions (jq not available)"
fi

echo
printf '%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
