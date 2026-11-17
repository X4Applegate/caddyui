#!/usr/bin/env bash
# test-caddy-base-drift.sh — regression tests for scripts/caddy-base-drift.sh.
#
# The script answers a security question: "is the published Caddy image missing base-layer
# fixes?". The failure that matters is therefore NOT a crash — it is a reassuring answer the
# script was not entitled to give. So most of what is asserted here is the shape of the
# WRONG answers:
#
#   - it must never print `unchanged` when it could not actually compare (fail-open);
#   - it must never print `moved` when nothing that ships differs (cry wolf, which trains the
#     reader to ignore the one run that matters).
#
# Two layers, because they fail differently:
#
#   1. COMPARATOR  — the embedded python is EXTRACTED FROM THE SHIPPED SCRIPT and driven with
#      synthetic indexes. Extraction rather than a copy is deliberate: a copied comparator
#      silently stops testing the real one the first time either is edited. This is the only
#      way to exercise `moved`, which the live registry cannot currently produce because the
#      real base has not moved.
#   2. SHELL      — the registry calls are stubbed by putting a fake `docker` on PATH, so the
#      error paths (call fails, empty output, junk output, no provenance) can be driven
#      without touching the network.
#
# No network access is required and no test contacts Docker Hub.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/caddy-base-drift.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()   { printf '  ok    %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
check(){ # name expected actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}
# `A && ok ... || bad ...` is not if-then-else (shellcheck SC2015), so assertions use this.
want_rc(){ # expected_rc name
  if [ "$RC" = "$1" ]; then ok "$2"; else bad "$2 (exit $RC, expected $1)"; fi
}

# ---------------------------------------------------------------------------
# 1. the comparator, extracted from the shipped script
# ---------------------------------------------------------------------------
echo "comparator (extracted from caddy-base-drift.sh):"

python3 -I - "$SCRIPT" "$TMP/comparator.py" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'verdict="\$\(printf[^\n]*python3 -I -c \'\n(.*?)\n\'\)"', src, re.S)
if not m:
    sys.exit("could not extract the comparator from the script; has its shape changed?")
open(sys.argv[2], "w").write(m.group(1))
PY
[ -s "$TMP/comparator.py" ] || { echo "  FAIL  comparator extraction"; exit 1; }

cmp_run() { # upstream_json recorded_json -> "status<TAB>detail"
  printf '%s\n\x00\n%s\n' "$1" "$2" | python3 -I "$TMP/comparator.py"
}

# Build an OCI index listing the given "platform=digest" pairs, plus an attestation manifest
# (architecture "unknown") which must always be ignored.
idx() {
  python3 -I -c '
import json, sys
mans = []
for arg in sys.argv[1:]:
    k, _, d = arg.partition("=")
    parts = k.split("/")
    p = {"os": parts[0], "architecture": parts[1]}
    if len(parts) > 2:
        p["variant"] = parts[2]
    mans.append({"platform": p, "digest": d})
mans.append({"platform": {"os": "unknown", "architecture": "unknown"}, "digest": "sha256:" + "a"*64})
print(json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": mans}))
' "$@"
}

A="sha256:$(printf '1%.0s' $(seq 64))"
B="sha256:$(printf '2%.0s' $(seq 64))"
C="sha256:$(printf '3%.0s' $(seq 64))"

# The real-world shape: the two INDEX digests differ (a tag re-push) but every platform
# manifest is identical. Measured on caddy:2.11.9-alpine. Must be `unchanged`, or the check
# cries wolf on an ordinary re-push.
r="$(cmp_run "$(idx "linux/amd64=$A" "linux/arm64/v8=$B")" "$(idx "linux/amd64=$A" "linux/arm64=$B")")"
check "identical manifests, arm64 spelled v8 upstream" unchanged "${r%%	*}"

r="$(cmp_run "$(idx "linux/amd64=$C" "linux/arm64/v8=$B")" "$(idx "linux/amd64=$A" "linux/arm64=$B")")"
check "amd64 manifest differs -> moved" moved "${r%%	*}"
case "$r" in *linux/amd64*) ok "moved names the platform" ;; *) bad "moved does not name the platform" ;; esac

# BOTH built platforms must actually be compared. Asserting only that a mixed index is
# `moved` does NOT establish this: a check that silently compared amd64 alone would pass
# every test above, while missing a stale arm64 base on a fleet that runs arm64. A negative
# control proved it -- narrowing the comparison to amd64 left the suite fully green. So
# drive a case where ONLY arm64 differs, and require it to be caught and named.
r="$(cmp_run "$(idx "linux/amd64=$A" "linux/arm64/v8=$C")" "$(idx "linux/amd64=$A" "linux/arm64=$B")")"
check "ONLY arm64 differs -> moved (arm64 is really compared)" moved "${r%%	*}"
case "$r" in *linux/arm64*) ok "an arm64-only move names arm64" ;; *) bad "an arm64-only move was not attributed to arm64: $r" ;; esac
# ...and the count must say two, not one: a comparison that skipped arm64 would report 1.
r="$(cmp_run "$(idx "linux/amd64=$A" "linux/arm64/v8=$B")" "$(idx "linux/amd64=$A" "linux/arm64=$B")")"
case "$r" in *"2 platform(s)"*) ok "both platforms counted as compared" ;; *) bad "expected 2 platforms compared, got: $r" ;; esac

r="$(cmp_run "$(idx "linux/amd64=$C" "linux/arm64/v8=$C")" "$(idx "linux/amd64=$A" "linux/arm64=$B")")"
check "both platforms differ -> moved" moved "${r%%	*}"

# A platform this project does not build must not raise an alarm.
r="$(cmp_run "$(idx "linux/amd64=$A" "linux/arm64/v8=$B" "linux/ppc64le=$C")" "$(idx "linux/amd64=$A" "linux/arm64=$B" "linux/ppc64le=$A")")"
check "ppc64le differs but is not built here" unchanged "${r%%	*}"

# Nothing comparable, malformed input, and a non-index image must all be `unknown` — never
# `unchanged`. This is the fail-open assertion.
r="$(cmp_run "$(idx "linux/s390x=$A")" "$(idx "linux/s390x=$A")")"
check "no built platform present -> unknown" unknown "${r%%	*}"

r="$(printf 'not json\n\x00\n{}\n' | python3 -I "$TMP/comparator.py")"
check "malformed upstream JSON -> unknown" unknown "${r%%	*}"

r="$(printf '{}\n\x00\nnot json\n' | python3 -I "$TMP/comparator.py")"
check "malformed recorded JSON -> unknown" unknown "${r%%	*}"

single='{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"'"$A"'"},"layers":[]}'
r="$(cmp_run "$single" "$single")"
check "single-manifest (non-index) base -> unknown" unknown "${r%%	*}"

# ---------------------------------------------------------------------------
# 2. the shell, with the registry stubbed
# ---------------------------------------------------------------------------
echo
echo "shell paths (docker stubbed, no network):"

mkdir -p "$TMP/bin"
mk_docker() { printf '#!/usr/bin/env bash\n%s\n' "$1" > "$TMP/bin/docker"; chmod +x "$TMP/bin/docker"; }

printf 'FROM caddy:2.11.9-builder AS builder\nFROM caddy:2.11.9-alpine\n' > "$TMP/Dockerfile.caddy"

run_script() { # -> sets OUT and RC
  OUT="$(cd "$TMP" && PATH="$TMP/bin:$PATH" GITHUB_OUTPUT="$TMP/gho" \
         bash "$SCRIPT" "$@" applegater/caddyui-caddy:stable "$TMP/Dockerfile.caddy" 2>&1)"
  RC=$?
}

verdict_is() { case "$OUT" in *"verdict:     $1"*) return 0 ;; *) return 1 ;; esac; }

# A failing registry call must NOT be read as success. This is the exact fail-open the
# `if ! var=$(...)` guards exist to prevent; with `2>&1` and a `$?` test it regressed to a
# pass, because the error text made the variable non-empty.
#
# ASSERT WHICH GUARD FIRED, not just the exit code. Exit 2 alone does NOT distinguish a
# working guard from a broken one: when the FIRST guard is bypassed the script runs on and
# trips a LATER guard, still exiting 2 with a still-reassuring-free verdict. A negative
# control proved this — reintroducing the bug left an exit-code-only suite fully green, so
# it was testing nothing. The first guard must stop it at the FIRST call.
mk_docker 'echo "ERROR: failed to read metadata: unauthorized" >&2; exit 1'
run_script
want_rc 2 "registry call fails -> exit 2 (unknown)"
case "$OUT" in *unchanged*) bad "registry failure reported 'unchanged' -- FAIL-OPEN" ;; *) ok "registry failure never says unchanged" ;; esac
case "$OUT" in
  *"could not resolve $(printf 'caddy:2.11.9-alpine') upstream"*)
    ok "the FIRST guard stops a failed upstream call (not a later one)" ;;
  *)
    bad "a failed upstream call was not caught by its own guard; the script continued and stopped later -- the guard is bypassed. Output: $OUT" ;;
esac

# Same assertion for the provenance call: make ONLY that call fail, and require its own
# guard to be the one that reports.
mk_docker '
case "$*" in
  *Provenance*) echo "ERROR: unauthorized" >&2; exit 1 ;;
  *) echo "{\"manifests\":[]}" ;;
esac
exit 0'
run_script
case "$OUT" in
  *"could not read provenance"*) ok "the provenance guard catches its own failed call" ;;
  *) bad "a failed provenance call was not caught by its guard. Output: $OUT" ;;
esac

# Succeeds but prints nothing.
mk_docker 'exit 0'
run_script
want_rc 2 "empty registry output -> exit 2"

# Succeeds and prints junk.
mk_docker 'echo "<html>502 Bad Gateway</html>"; exit 0'
run_script
want_rc 2 "junk registry output -> exit 2"
case "$OUT" in *unchanged*) bad "junk output reported 'unchanged' -- FAIL-OPEN" ;; *) ok "junk output never says unchanged" ;; esac

# An image with NO provenance attestation: `--format '{{ json .Provenance }}'` prints the
# literal `null` and exits 0, so this is valid JSON that says nothing. Must be unknown.
mk_docker 'case "$*" in *Provenance*) echo null ;; *) echo "{}" ;; esac; exit 0'
run_script
want_rc 2 "image without provenance -> exit 2"
case "$OUT" in *unchanged*) bad "no provenance reported 'unchanged' -- FAIL-OPEN" ;; *) ok "no provenance never says unchanged" ;; esac

# Provenance that names a DIFFERENT base than the pin (e.g. the pin was bumped since the
# published image was built) cannot be compared, so it must be unknown rather than moved.
mk_docker '
case "$*" in
  *Provenance*) echo "{\"linux/amd64\":{\"SLSA\":{\"buildDefinition\":{\"resolvedDependencies\":[{\"uri\":\"pkg:docker/caddy@2.10.0-alpine?platform=linux%2Famd64\",\"digest\":{\"sha256\":\"'"${A#sha256:}"'\"}}]}}}}" ;;
  *) echo "{}" ;;
esac
exit 0'
run_script
want_rc 2 "provenance names a different base -> exit 2"

# A Dockerfile with no FROM.
printf '# no FROM here\n' > "$TMP/empty.Dockerfile"
OUT="$(cd "$TMP" && PATH="$TMP/bin:$PATH" bash "$SCRIPT" applegater/caddyui-caddy:stable "$TMP/empty.Dockerfile" 2>&1)"; RC=$?
want_rc 2 "Dockerfile without FROM -> exit 2"

# --advisory must collapse every verdict to exit 0 for the release workflow, AFTER reporting.
mk_docker 'echo "ERROR: nope" >&2; exit 1'
run_script --advisory
want_rc 0 "--advisory exits 0 on an unknown verdict"

# The drift key must be written on every path, so the workflow step can read it.
rm -f "$TMP/gho"; : > "$TMP/gho"
mk_docker 'echo "ERROR: nope" >&2; exit 1'
run_script
if grep -qx 'drift=unknown' "$TMP/gho"; then
  ok "drift=unknown written to GITHUB_OUTPUT"
else
  bad "no drift=unknown in GITHUB_OUTPUT: $(cat "$TMP/gho")"
fi

# "Could not verify" must never be worded, or annotated, like "verified clean". Both leave
# the step green on the release path, so the wording is the only thing that separates them;
# an `unknown` that reads as reassuring recreates the silent-skip defect one level up.
mk_docker 'echo "ERROR: nope" >&2; exit 1'
SUM="$TMP/summary.md"; : > "$SUM"
OUT="$(cd "$TMP" && PATH="$TMP/bin:$PATH" GITHUB_STEP_SUMMARY="$SUM" \
       bash "$SCRIPT" applegater/caddyui-caddy:stable "$TMP/Dockerfile.caddy" 2>&1)"
case "$(cat "$SUM")" in
  *"NOT VERIFIED"*) ok "unknown is worded NOT VERIFIED in the summary" ;;
  *) bad "unknown verdict is not clearly worded: $(cat "$SUM")" ;;
esac
case "$(cat "$SUM")" in
  *"VERIFIED CURRENT"*) bad "unknown verdict claimed VERIFIED CURRENT -- FAIL-OPEN WORDING" ;;
  *) ok "unknown never claims VERIFIED CURRENT" ;;
esac
case "$OUT" in
  *"::warning::"*) ok "unknown emits a ::warning:: annotation (visible on the run header)" ;;
  *) bad "unknown produced no annotation, so a green step hides it: $OUT" ;;
esac

# A malformed digest in the provenance must be REJECTED, not pasted into an image reference.
# Quoted expansion makes it inert today; validation is what keeps it that way.
#
# ASSERT THE REJECTION, not just the exit code. Exit 2 alone does not prove the digest was
# validated: with both validations removed the run still ends at 2, because whatever junk
# was interpolated simply fails to resolve further down. A negative control proved that --
# deleting both checks left an exit-code-only assertion fully green. So require that the
# malformed value is NAMED as malformed and never reaches the "recorded:" line.
#
# The upstream index here is deliberately WELL-FORMED and populated: an empty manifest list
# would end the run as unknown on its own and mask the very path being tested.
mk_docker '
case "$*" in
  *Provenance*) echo "{\"linux/amd64\":{\"SLSA\":{\"buildDefinition\":{\"resolvedDependencies\":[{\"uri\":\"pkg:docker/caddy@2.11.9-alpine?platform=linux%2Famd64\",\"digest\":{\"sha256\":\"notadigest --builder evil\"}}]}}}}" ;;
  *) echo "{\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\"},\"digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"}]}" ;;
esac
exit 0'
run_script
want_rc 2 "malformed base digest in provenance -> exit 2"
case "$OUT" in *unchanged*) bad "malformed digest reported unchanged -- FAIL-OPEN" ;; *) ok "malformed digest never says unchanged" ;; esac
case "$OUT" in
  *"malformed base digest"*) ok "the malformed digest is rejected by name" ;;
  *) bad "a malformed digest was not rejected as such; it was accepted and failed later. Output: $OUT" ;;
esac
case "$OUT" in
  *"recorded:    sha256:notadigest"*)
    bad "the malformed digest reached the recorded: line, so it was interpolated into an image reference unvalidated" ;;
  *) ok "the malformed digest never reaches an image reference" ;;
esac

# The runtime base is the LAST FROM, not the builder. Getting this wrong would compare the
# wrong image and report confidently on a layer that ships nothing.
printf 'FROM golang:1.26 AS builder\nFROM caddy:2.11.9-alpine\n' > "$TMP/two.Dockerfile"
mk_docker 'echo "ERROR: x" >&2; exit 1'
OUT="$(cd "$TMP" && PATH="$TMP/bin:$PATH" bash "$SCRIPT" applegater/caddyui-caddy:stable "$TMP/two.Dockerfile" 2>&1)"
case "$OUT" in *"base pin:    caddy:2.11.9-alpine"*) ok "reads the runtime FROM, not the builder" ;;
               *) bad "picked the wrong FROM: $OUT" ;; esac

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
