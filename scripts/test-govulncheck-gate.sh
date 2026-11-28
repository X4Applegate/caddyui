#!/usr/bin/env bash
# test-govulncheck-gate.sh — regression tests for scripts/govulncheck-gate.sh
# (T-0740, T-0744, T-0746).
#
# WHAT IS WORTH ASSERTING. The gate's subject is the difference between
# "scanned and clean" and "did not scan", so almost every case here drives a
# WRONG answer rather than the happy path:
#
#   - A scanner older than the tree must produce "scanner is stale" and exit
#     3, never the `package patterns` load error that reads as an operator
#     mistake and records as a pass. That is T-0740, reproduced for real on
#     2026-11-25 with a go1.26.11-built govulncheck against a go1.27.4 tree:
#     exit 1, zero findings, and a message pointing at `./...`.
#   - An empty, truncated, non-JSON or module-level stream must be exit 3.
#     Each of them otherwise parses to zero findings, which is the fail-open
#     shape T-0646/T-0669 were filed about.
#   - A called finding must fail only under `--fail-on called`, and a linked
#     binary-mode finding must be worded as LINKED, not called (T-0729: the
#     linker's view is not the run-time one).
#   - An acknowledgement must suppress only the exit code, must expire, and
#     must re-arm the moment a fix becomes available.
#
# EVERY CASE IS OFFLINE AND NEEDS NO SCANNER. `--offline-fixture` feeds saved
# streams, and the staleness guard is driven by putting a stub `go` on PATH
# (the guard reads `go version -m <tool>`, so faking `go` exercises the real
# comparison rather than a test-only backdoor in the script).
#
# THE STREAM FIXTURES ARE REAL govulncheck OUTPUT, trimmed to the advisories
# their own findings reference:
#   source-uncalled.json  `govulncheck ./...` on caddyui itself — 1 finding,
#                         module-level only (the x/crypto/openpgp residual).
#   source-called.json    a throwaway module that calls
#                         openpgp.ReadArmoredKeyRing — genuinely called, with
#                         real call traces.
#   binary-linked.json    `-mode=binary` on applegater/caddyui-caddy:stable —
#                         two linked findings, the real published image.
# A hand-written stream would test this suite's idea of the format.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/govulncheck-gate.sh"
FIX="$HERE/fixtures/govulncheck"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
want_rc() { if [ "$RC" = "$1" ]; then ok "$2"; else bad "$2 (exit $RC, expected $1)"; fi; }
want_in() { if grep -qF -- "$1" "$OUT"; then ok "$2"; else bad "$2 (output does not contain '$1')"; fi; }
want_not_in() { if grep -qF -- "$1" "$OUT"; then bad "$2 (output contains '$1' and must not)"; else ok "$2"; fi; }

[ -x "$SCRIPT" ] || { echo "FAIL: $SCRIPT is missing or not executable"; exit 1; }
for f in source-uncalled.json source-called.json binary-linked.json empty.json no-config.json module-level.json not-json.json; do
  [ -f "$FIX/$f" ] || { echo "FAIL: fixture $FIX/$f is missing"; exit 1; }
done

# A go.mod to judge against, independent of the repo's own current pin so the
# assertions do not change when the real toolchain is bumped.
cat > "$TMP/go.mod" <<'EOF'
module example.com/x

go 1.26.0

toolchain go1.27.4
EOF

# A stub `go` whose only job is to answer `go version -m <path>` with a chosen
# release. Nothing else in the gate's fixture path calls `go`.
make_stub_go() { # make_stub_go <dir> <goX.Y.Z>
  mkdir -p "$1"
  cat > "$1/go" <<EOF
#!/usr/bin/env bash
if [ "\$1" = version ] && [ "\$2" = -m ]; then
  printf '%s: %s\n' "\$3" "$2"
  exit 0
fi
exit 1
EOF
  chmod +x "$1/go"
}

n=0
# run <fixture> [extra args...]
run() {
  n=$((n+1))
  local fx="$1"; shift
  OUT="$TMP/out.$n"
  rm -rf "$TMP/o.$n"
  "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
    --out-dir "$TMP/o.$n" --offline-fixture "$fx" "$@" > "$OUT" 2>&1
  RC=$?
}

echo "govulncheck-gate.sh:"

# ---------------------------------------------------------------------------
# 1. A finding that is present but NOT called. Report-only and under
#    --fail-on called it is the same answer: exit 1, never 0 (something was
#    found) and never 2 (nothing is reachable).
# ---------------------------------------------------------------------------
run "$FIX/source-uncalled.json"
want_rc 1 "1  a present-but-uncalled finding is attention (exit 1)"
want_in "present but not called" "1a it is reported under the uncalled heading"
want_in "GO-2026-5932" "1b and named"
want_not_in "#### called" "1c and NOT reported as called"

run "$FIX/source-uncalled.json" --fail-on called
want_rc 1 "2  --fail-on called does not fail on an uncalled finding"

# ---------------------------------------------------------------------------
# 3. A CALLED finding. This is the T-0744 decision in one assertion: it fails
#    under --fail-on called and only reports without it.
# ---------------------------------------------------------------------------
run "$FIX/source-called.json" --fail-on called
want_rc 2 "3  a called finding fails under --fail-on called (exit 2)"
want_in "called finding(s)" "3a the heading says called"
want_in "reachable from this code" "3b source mode claims reachability"
want_in "ReadArmoredKeyRing" "3c and names the symbol"

run "$FIX/source-called.json"
want_rc 1 "4  the same finding is report-only by default (exit 1)"
want_in "Report-only: no finding fails this check" "4a and the report says it did not gate"

# ---------------------------------------------------------------------------
# 5. BINARY mode wording. T-0729 measured govulncheck naming a symbol in a
#    binary whose decoder the linker had dropped, so binary findings must be
#    described as linked and must carry the caveat. Reporting them as "called"
#    would overclaim on the one path where the claim is weakest.
# ---------------------------------------------------------------------------
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
: > "$TMP/fakebin"
"$SCRIPT" --binary "$TMP/fakebin" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/binary-linked.json" \
  --fail-on called > "$OUT" 2>&1
RC=$?
want_rc 2 "5  a linked binary finding fails under --fail-on called"
want_in "linked finding(s)" "5a the heading says linked, not called"
want_in "NOT proven reachable at run time" "5b the reachability caveat is present"
want_in "zstd decoder had been dropped" "5c and cites the measurement behind it"
want_in "only the runner's own architecture" "5d the single-arch limit is stated"
want_in "GO-2026-6974" "5e names the otel finding found on the real :stable image"
want_not_in "#### called" "5f never uses the word called for a binary scan"

# ---------------------------------------------------------------------------
# 6. THE STALENESS GUARD (T-0740). A scanner older than the tree must be
#    refused BEFORE it runs, with a verdict that says what to do.
# ---------------------------------------------------------------------------
make_stub_go "$TMP/stub-old" go1.26.11
: > "$TMP/faketool"; chmod +x "$TMP/faketool"
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
PATH="$TMP/stub-old:$PATH" "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/source-called.json" \
  --tool "$TMP/faketool" --fail-on called > "$OUT" 2>&1
RC=$?
want_rc 3 "6  a scanner older than the tree is could-not-run (exit 3)"
want_in "older than the tree it was asked to scan" "6a and says so plainly"
want_in "reinstall" "6b and says what to do"
want_in "go install golang.org/x/vuln/cmd/govulncheck@v1.9.0" "6c with the command, naming the PINNED version"
want_not_in "govulncheck@latest" "6c2 and never @latest, which cannot parse go1.27 (finding 6)"
want_in "go1.26.11" "6d naming the scanner's own version"
want_in "go1.27.4" "6e and the version required"
want_not_in "called finding(s)" "6f and reports no finding from the stream it never trusted"
want_in "could not run" "6g the heading is could-not-run"

# The same scanner on an EQUAL toolchain is fine — the guard is a floor, not
# an equality check, so a newer scanner must not be refused either.
make_stub_go "$TMP/stub-eq" go1.27.4
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
PATH="$TMP/stub-eq:$PATH" "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/source-uncalled.json" \
  --tool "$TMP/faketool" > "$OUT" 2>&1
RC=$?
want_rc 1 "7  a scanner matching the toolchain is accepted"

make_stub_go "$TMP/stub-new" go1.28.0
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
PATH="$TMP/stub-new:$PATH" "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/source-uncalled.json" \
  --tool "$TMP/faketool" > "$OUT" 2>&1
RC=$?
want_rc 1 "8  a scanner NEWER than the toolchain is accepted (a floor, not equality)"

# A scanner whose version cannot be read is a NOTE, not a pass and not a
# refusal: the comparison could not be made, and saying so is the point.
make_stub_go "$TMP/stub-mute" go1.27.4
cat > "$TMP/stub-mute/go" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$TMP/stub-mute/go"
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
PATH="$TMP/stub-mute:$PATH" "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/source-uncalled.json" \
  --tool "$TMP/faketool" > "$OUT" 2>&1
RC=$?
want_in "could not be read" "9  an unreadable scanner version is stated, not assumed"

# --skip-tool-check must say the guard was switched off. A weakened run that
# looks like a normal one is how the guard stops existing.
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
PATH="$TMP/stub-old:$PATH" "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/source-uncalled.json" \
  --tool "$TMP/faketool" --skip-tool-check > "$OUT" 2>&1
RC=$?
want_rc 1 "10 --skip-tool-check lets a stale scanner through, as documented"
want_in "staleness guard was disabled" "10a but the report says the guard was disabled"

# ---------------------------------------------------------------------------
# 11. EXPLICIT UNKNOWN for every unreadable stream. Each of these parses to
#     zero findings on a naive reader.
# ---------------------------------------------------------------------------
run "$FIX/empty.json"
want_rc 3 "11 an empty stream is could-not-run, not zero findings"
want_in "NO OUTPUT AT ALL" "11a and says the output was empty"

run "$FIX/not-json.json"
want_rc 3 "12 a non-JSON stream (the T-0740 load error itself) is could-not-run"
want_in "not valid JSON" "12a and says why"

run "$FIX/no-config.json"
want_rc 3 "13 a stream with no config message is could-not-run"
want_in "never started a scan" "13a and says the scan never started"

run "$FIX/module-level.json" --fail-on called
want_rc 3 "14 a module-level scan cannot answer the reachability question"
want_in "cannot distinguish a called finding" "14a and says exactly that"
want_not_in "called finding(s)" "14b so it reports no called count from it"

run "$TMP/does-not-exist.json"
want_rc 3 "15 a missing stream is could-not-run"

# An absent scanner, with no fixture: nothing was scanned, and that must not
# be a pass either. A directory with no `govulncheck` in it is prepended and
# the rest of PATH is kept, so the failure under test is the missing SCANNER
# rather than a missing `jq` or `sed` -- an empty PATH makes everything fail
# and proves nothing about this check.
#
# The REASON is asserted as well as the status, because a function called in
# `$( )` loses its notes to the subshell: this case first came back with the
# right exit code and the wrong explanation.
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
mkdir -p "$TMP/no-scanner"
PATH="$TMP/no-scanner:$PATH" GOVULNCHECK_UNUSED=1 \
  env PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v '^/root/go/bin$' | paste -sd:)" \
  "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" > "$OUT" 2>&1
RC=$?
want_rc 3 "16 an absent govulncheck is could-not-run, not a clean scan"
want_in "govulncheck is not on \$PATH" "16a and says the scanner is missing, not something else"
want_in "go install golang.org/x/vuln/cmd/govulncheck@v1.9.0" "16b with the install command, naming the PINNED version"
want_not_in "govulncheck@latest" "16b2 and never @latest, which cannot parse go1.27 (finding 6)"

# A binary that does not exist.
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
"$SCRIPT" --binary "$TMP/nope-bin" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/binary-linked.json" > "$OUT" 2>&1
RC=$?
want_rc 3 "17 a missing binary is could-not-run"
want_in "does not exist, so nothing was scanned" "17a and says nothing was scanned"

# ---------------------------------------------------------------------------
# 18. ACKNOWLEDGEMENTS. An ack holds the exit code and nothing else.
# ---------------------------------------------------------------------------
cat > "$TMP/ack-live.txt" <<'EOF'
# a comment, and a blank line, both ignored

GO-2026-5932 expires=2099-01-01 ref=T-0744 reason=openpgp is unmaintained upstream and there is no release to take
EOF
run "$FIX/source-called.json" --fail-on called --acks "$TMP/ack-live.txt"
want_rc 1 "18 a live acknowledgement holds the urgent verdict (exit 1, not 2)"
want_in "acknowledged (reported, not failed)" "18a the finding is still reported"
want_in "GO-2026-5932" "18b still named"
want_in "no release to take" "18c with the reason, so the decision is visible"

cat > "$TMP/ack-expired.txt" <<'EOF'
GO-2026-5932 expires=2020-01-01 ref=T-0744 reason=an acknowledgement that has run out
EOF
run "$FIX/source-called.json" --fail-on called --acks "$TMP/ack-expired.txt"
want_rc 2 "19 an EXPIRED acknowledgement no longer holds"
want_in "no longer in force" "19a and says so"
want_in "expired on 2020-01-01" "19b naming the date"

# The re-arm that matters: fixed_in. The tree is go1.27.4, so an ack excused
# by "no fix before go1.27.0" is spent whatever its date says.
cat > "$TMP/ack-rearm.txt" <<'EOF'
GO-2026-5932 expires=2099-01-01 fixed_in=go1.27.0 ref=T-0744 reason=no fix existed before go1.27.0
EOF
run "$FIX/source-called.json" --fail-on called --acks "$TMP/ack-rearm.txt"
want_rc 2 "20 fixed_in re-arms the gate once the tree reaches it, whatever the date"
want_in "at or past fixed_in=go1.27.0" "20a and says why"

cat > "$TMP/ack-future.txt" <<'EOF'
GO-2026-5932 expires=2099-01-01 fixed_in=go1.99.0 ref=T-0744 reason=no fix before go1.99.0
EOF
run "$FIX/source-called.json" --fail-on called --acks "$TMP/ack-future.txt"
want_rc 1 "21 fixed_in ABOVE the tree's toolchain keeps the acknowledgement live"

# Required fields. Each omission is could-not-run, not a quiet exclusion.
for bad_line in \
  'GO-2026-5932 reason=no expiry at all' \
  'GO-2026-5932 expires=2099-01-01' \
  'GO-2026-5932 expires=not-a-date reason=unparsable expiry' \
  'GO-2026-5932 expires=2026-02-31 reason=impossible date' \
  'GO-2026-5932 expires=2099-01-01 fixed_in=banana reason=unparsable fixed_in' \
  'GO-2026-5932 expires=2099-01-01 nonsense=1 reason=unknown field' \
  'CVE-2026-1234 expires=2099-01-01 reason=wrong id scheme'
do
  printf '%s\n' "$bad_line" > "$TMP/ack-bad.txt"
  run "$FIX/source-called.json" --fail-on called --acks "$TMP/ack-bad.txt"
  want_rc 3 "22 a malformed acknowledgement is could-not-run: ${bad_line:0:46}..."
done

printf 'GO-2026-5932 expires=2099-01-01 reason=one\nGO-2026-5932 expires=2099-01-01 reason=two\n' > "$TMP/ack-dup.txt"
run "$FIX/source-called.json" --fail-on called --acks "$TMP/ack-dup.txt"
want_rc 3 "23 the same id acknowledged twice is could-not-run"
want_in "acknowledged twice" "23a and says so"

# An ack matching nothing is reported for removal rather than left standing.
cat > "$TMP/ack-stale.txt" <<'EOF'
GO-2026-9999 expires=2099-01-01 reason=matches nothing in this scan
EOF
run "$FIX/source-uncalled.json" --acks "$TMP/ack-stale.txt"
want_rc 1 "24 an acknowledgement matching no finding is reported"
want_in "matches no finding in this scan" "24a and says to remove it"
want_in "standing permission" "24b naming why that matters"

# A named-but-absent acks file is a configuration error, not an empty list.
run "$FIX/source-called.json" --fail-on called --acks "$TMP/no-such-acks.txt"
want_rc 3 "25 a named acks file that does not exist is could-not-run"

# ---------------------------------------------------------------------------
# 26. The report must always state what a clean run is NOT evidence of.
#     That sentence is the only thing standing between this check and being
#     read as cover for the CVE-less advisory gap (T-0675, T-0676).
# ---------------------------------------------------------------------------
run "$FIX/source-uncalled.json"
want_in "CVE-keyed" "26 the CVE-keyed limitation is stated on every run"
want_in "check-pinned-modules.sh --gomod" "26a and points at the check that covers it"

# ---------------------------------------------------------------------------
# 27. Workflow plumbing: outputs, verdict file, step summary.
# ---------------------------------------------------------------------------
n=$((n+1)); rm -rf "$TMP/o.$n"
GITHUB_OUTPUT="$TMP/gh.$n" GITHUB_STEP_SUMMARY="$TMP/sum.$n" \
  "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none --out-dir "$TMP/o.$n" \
  --offline-fixture "$FIX/source-called.json" --fail-on called > /dev/null 2>&1
OUT="$TMP/gh.$n"
want_in "verdict=advisory" "27 writes verdict= to GITHUB_OUTPUT"
want_in "rc=2" "27a writes rc="
want_in "called=1" "27b writes the called count"
OUT="$TMP/o.$n/verdict"
want_in "advisory" "27c writes the verdict file"
OUT="$TMP/sum.$n"
want_in "called finding(s)" "27d appends to the step summary"
OUT="$TMP/o.$n/findings.tsv"
want_in "GO-2026-5932" "27e leaves the parsed rows as an artifact"

# A could-not-run must write a verdict of `unknown` rather than an empty key,
# so a `case` in a workflow step cannot fall through to a success arm.
n=$((n+1)); rm -rf "$TMP/o.$n"
GITHUB_OUTPUT="$TMP/gh.$n" "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/empty.json" > /dev/null 2>&1
OUT="$TMP/gh.$n"
want_in "verdict=unknown" "28 a could-not-run writes verdict=unknown"
want_in "called=unknown" "28a and refuses to report a called count of 0"

# ---------------------------------------------------------------------------
# 29. Argument handling. A typo must not change what the run means.
# ---------------------------------------------------------------------------
n=$((n+1)); OUT="$TMP/out.$n"
"$SCRIPT" --source "$TMP" --fail-on everything > "$OUT" 2>&1; RC=$?
want_rc 3 "29 an unknown --fail-on value is rejected"
n=$((n+1)); OUT="$TMP/out.$n"
"$SCRIPT" --not-a-flag > "$OUT" 2>&1; RC=$?
want_rc 3 "30 an unknown argument is rejected"
n=$((n+1)); OUT="$TMP/out.$n"
"$SCRIPT" --out-dir "$TMP/o.$n" > "$OUT" 2>&1; RC=$?
want_rc 3 "31 neither --source nor --binary is rejected rather than defaulted"

# A finding summary containing a tab or a newline must not be able to add a
# field or a row to the parsed output: advisory text is third-party input.
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
python3 -I - "$FIX/source-called.json" "$TMP/inject.json" <<'PY'
import json, sys
out = []
with open(sys.argv[1]) as fh:
    dec = json.JSONDecoder()
    buf = fh.read()
    i = 0
    while i < len(buf):
        while i < len(buf) and buf[i].isspace():
            i += 1
        if i >= len(buf):
            break
        obj, i = dec.raw_decode(buf, i)
        if "osv" in obj and obj["osv"].get("id") == "GO-2026-5932":
            obj["osv"]["summary"] = "pwn\tGO-0000-0000\tyes\nextra\trow"
        out.append(obj)
with open(sys.argv[2], "w") as fh:
    for o in out:
        fh.write(json.dumps(o) + "\n")
PY
"$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none --out-dir "$TMP/o.$n" \
  --offline-fixture "$TMP/inject.json" --fail-on called > "$OUT" 2>&1
RC=$?
want_rc 2 "32 a summary carrying tabs and newlines still yields one finding"
OUT="$TMP/o.$n/findings.tsv"
if [ "$(wc -l < "$TMP/o.$n/findings.tsv")" = 1 ]; then
  ok "32a and exactly one parsed row, so the text cannot forge a second"
else
  bad "32a injected text produced $(wc -l < "$TMP/o.$n/findings.tsv") rows, expected 1"
fi
OUT="$TMP/out.$n"
want_not_in "GO-0000-0000 |" "32b and the forged id is not rendered as its own advisory"

# ---------------------------------------------------------------------------
# 33. AN UNPARSED STREAM IS NOT AN EMPTY ONE.
#
#     The row filter used to end in `|| { : > "$rows_file"; }`: when it
#     failed, the rows file was truncated and the run carried on, so `total`,
#     `called_total` and `called_live` all read 0 and the report said "no
#     findings" with exit 0. A full clean pass, produced by a parser that had
#     failed.
#
#     Case 18 already covers a stream that is not JSON at all. This is the
#     harder one: the fixture IS valid JSON, so it passes the `jq -e .`
#     validity check, and it breaks the filter one level further in -- a
#     non-string `.osv.id` makes `from_entries` fail. And it carries a CALLED
#     finding, so the old behaviour hid exactly what the gate exists to catch.
# ---------------------------------------------------------------------------
n=$((n+1))
if jq -e . "$FIX/unparseable-osv-id.json" >/dev/null 2>&1; then
  ok "33 the crafted stream is valid JSON, so it passes the validity check"
else
  bad "33 the crafted stream is not valid JSON, so case 33a proves nothing"
fi

n=$((n+1))
if [ "$(jq -s -r 'map(select(.finding)|.finding)|map(select(.trace[0].function))|length' "$FIX/unparseable-osv-id.json")" = 1 ]; then
  ok "33a and it carries a called finding, which is what must not be lost"
else
  bad "33a the crafted stream no longer carries a called finding"
fi

run "$FIX/unparseable-osv-id.json" --fail-on called
want_rc 3 "33b a stream that cannot be parsed into findings is could-not-run, not clean"
want_in "could not run" "33c and says so"
want_in "not an empty one" "33d naming why an unparsed stream is not an empty one"
want_not_in "no findings" "33e and never reports 'no findings'"

n=$((n+1)); rm -rf "$TMP/o.$n"
GITHUB_OUTPUT="$TMP/gh33" "$SCRIPT" --source "$TMP" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/unparseable-osv-id.json" \
  --fail-on called > /dev/null 2>&1
OUT="$TMP/gh33"
want_in "verdict=unknown" "33f and writes verdict=unknown"
want_in "called=unknown" "33g and refuses to report a called count of 0"

# ---------------------------------------------------------------------------
# 34. AN UNEVALUABLE `fixed_in=` RE-ARM IS NOT A LIVE ACK.
#
#     `fixed_in=` is what makes an acknowledgement self-healing, so the one
#     thing it must not do is quietly stay honoured when the comparison could
#     not be made. It used to: the re-arm was skipped outright when the tree
#     had no readable `toolchain`, so an ack excused by "unfixed before
#     go1.0.0" kept suppressing the gate even though nothing could say
#     whether the fix was available. A question that could not be answered
#     rendered as suppression, which is the inverse of this file's subject.
#
#     The safe direction is to treat the ack as no longer in force, so the
#     finding goes back to failing and the note says why.
# ---------------------------------------------------------------------------
printf 'module acktest\n' > "$TMP/gomod-noversion"

n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
printf 'GO-2026-5932 expires=2099-01-01 fixed_in=go1.0.0 reason=unevaluable re-arm\n' > "$TMP/acks34"
"$SCRIPT" --source "$TMP" --gomod "$TMP/gomod-noversion" --acks "$TMP/acks34" \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/source-called.json" \
  --fail-on called --skip-tool-check > "$OUT" 2>&1
RC=$?
want_rc 2 "34 an ack whose fixed_in re-arm cannot be evaluated does not suppress the gate"
want_in "could not be evaluated" "34a and the report says the re-arm could not be evaluated"

# Control: the SAME ack against a tree that does have a toolchain is honoured,
# so case 34 is about the unevaluable comparison and not about the ack format.
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
printf 'module acktest\ngo 1.0\ntoolchain go0.9.0\n' > "$TMP/gomod-old"
printf 'GO-2026-5932 expires=2099-01-01 fixed_in=go99.0.0 reason=no fix yet\n' > "$TMP/acks34b"
"$SCRIPT" --source "$TMP" --gomod "$TMP/gomod-old" --acks "$TMP/acks34b" \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/source-called.json" \
  --fail-on called --skip-tool-check > "$OUT" 2>&1
RC=$?
want_rc 1 "34b a live ack with an unreached fixed_in is still honoured"
want_in "acknowledged" "34c and is reported as acknowledged"

# ---------------------------------------------------------------------------
# 35. BINARY NEWER THAN THE TREE (T-0893). The caddy binary's Go comes from the
#     upstream builder image, not go.mod. When it moves ahead, the stale-scanner
#     verdict must name the BINARY's Go as the floor and must NOT prescribe
#     `go-version-file: go.mod` -- that is what produced the stale scanner.
# ---------------------------------------------------------------------------
mkdir -p "$TMP/stub-split"
cat > "$TMP/stub-split/go" <<EOF
#!/usr/bin/env bash
if [ "\$1" = version ] && [ "\$2" = -m ]; then
  case "\$3" in
    "$TMP/faketool") printf '%s: go1.27.4\n' "\$3" ;;
    *)               printf '%s: go1.28.1\n' "\$3" ;;
  esac
  exit 0
fi
exit 1
EOF
chmod +x "$TMP/stub-split/go"
: > "$TMP/fakebin"
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
PATH="$TMP/stub-split:$PATH" "$SCRIPT" --binary "$TMP/fakebin" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/binary-linked.json" \
  --tool "$TMP/faketool" > "$OUT" 2>&1
RC=$?
want_rc 3 "35 a binary built on a newer Go than the tree refuses a tree-toolchain scanner"
want_in "needs at least \`go1.28.1\`" "35a naming the binary's Go as the floor"
want_in "the BINARY's Go, not this tree's" "35b and saying whose Go that is"
want_in "go-version: stable" "35c with the remedy that actually tracks upstream"
want_not_in "then \`go install\`)" "35d and NOT the circular go.mod remedy"

# The same split with a scanner built on the binary's Go is accepted.
cat > "$TMP/stub-split/go" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = version ] && [ "$2" = -m ]; then printf '%s: go1.28.1\n' "$3"; exit 0; fi
exit 1
EOF
n=$((n+1)); OUT="$TMP/out.$n"; rm -rf "$TMP/o.$n"
PATH="$TMP/stub-split:$PATH" "$SCRIPT" --binary "$TMP/fakebin" --gomod "$TMP/go.mod" --acks none \
  --out-dir "$TMP/o.$n" --offline-fixture "$FIX/binary-linked.json" \
  --tool "$TMP/faketool" > "$OUT" 2>&1
RC=$?
want_rc 1 "36 a scanner on the binary's (newer) Go scans it"

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
