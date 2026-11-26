#!/usr/bin/env bash
# test-govulncheck-ci-step.sh — prove ci.yml's reachability step CLASSIFIES the
# gate's exit status instead of propagating it (T-0744).
#
# WHAT THIS GUARDS
# ----------------
# govulncheck-gate.sh returns a RESULT, not a pass/fail, on the convention
# check-pinned-modules.sh established:
#
#   0  clean          1  attention (findings, none called)
#   2  a called finding, unacknowledged
#   3  the check could not run -- UNKNOWN, never a pass
#
# A GitHub `run:` step fails on any non-zero status, so handing that status
# straight to the runner conflates `1` with `2`. T-0744's decision is that a
# CALLED finding fails and a merely PRESENT one reports; propagating the raw
# status instead fails every unrelated PR on an uncalled residual. This tree
# has exactly such a residual today (GO-2026-5932, x/crypto/openpgp, which has
# no ordinary release to take -- its fix is a pseudo-version), so the
# unclassified form was red on every PR, which is the state that gets a gate
# deleted. That is the failure mode T-0744 exists to prevent, so it is worth a
# test rather than a comment.
#
# The other half matters just as much: exit 3 MUST still fail. A scan that
# could not run is unknown, not clean, and letting it pass recreates the
# T-0740 defect one level up -- a check that silently stops checking.
#
# HOW IT TESTS
# ------------
# It extracts the step's script FROM ci.yml and runs it against a stub gate
# that exits with a chosen status. Copying the case arms into the test would
# let the two drift and pass while the workflow was wrong, which is the whole
# defect being guarded. The stub makes every case offline: no Go, no
# govulncheck, no network.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
wf="$repo/.github/workflows/ci.yml"
[ -f "$wf" ] || { echo "missing $wf" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- extract the step's script, verbatim, from the workflow ----------------
python3 - "$wf" "$tmp/step.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(wf))
steps = [s for s in d["jobs"]["govulncheck"]["steps"] if s.get("id") == "govulncheck"]
if len(steps) != 1:
    sys.exit(f"expected exactly one govulncheck step with id 'govulncheck', found {len(steps)}")
run = steps[0]["run"]
if "govulncheck-gate.sh" not in run:
    sys.exit("the govulncheck step no longer invokes govulncheck-gate.sh")
open(out, "w").write("#!/usr/bin/env bash\n" + run)
PY
rc=$?
[ "$rc" = 0 ] || { echo "FAIL: could not extract the step from ci.yml" >&2; exit 2; }
chmod +x "$tmp/step.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL  %s\n' "$1"; }

# Run the extracted step with a stub gate that exits $1. The stub lives in a
# `scripts/` dir inside a scratch workdir, because the step calls it by the
# relative path `./scripts/govulncheck-gate.sh`.
run_step() { # run_step <gate-exit-status>
  local want="$1" d
  d="$(mktemp -d "$tmp/w.XXXXXX")"
  mkdir -p "$d/scripts"
  cat > "$d/scripts/govulncheck-gate.sh" <<EOF
#!/usr/bin/env bash
echo "stub gate: pretending to exit $want"
exit $want
EOF
  chmod +x "$d/scripts/govulncheck-gate.sh"
  ( cd "$d" && bash -e "$tmp/step.sh" ) > "$d/out" 2>&1
  STEP_RC=$?
  OUT="$d/out"
}

want_step_rc() { # want_step_rc <expected> <label>
  if [ "$STEP_RC" = "$1" ]; then ok "$2"; else bad "$2 (step exit $STEP_RC, expected $1)"; fi
}
want_in() { if grep -qF -- "$1" "$OUT"; then ok "$2"; else bad "$2 (output lacks '$1')"; fi; }

echo "ci.yml reachability step:"

# ---------------------------------------------------------------------------
# 1. A clean scan passes.
# ---------------------------------------------------------------------------
run_step 0
want_step_rc 0 "1 a clean scan (gate 0) passes the step"

# ---------------------------------------------------------------------------
# 2. THE CASE THAT WAS RED ON EVERY PR. A present-but-uncalled finding is
#    reported and the step still passes -- T-0744's stated granularity.
# ---------------------------------------------------------------------------
run_step 1
want_step_rc 0 "2 a present-but-uncalled finding (gate 1) does NOT fail the step"
want_in "::notice::" "2a and is surfaced as a notice rather than silence"

# ---------------------------------------------------------------------------
# 3. A called finding fails. This is what the promotion bought.
# ---------------------------------------------------------------------------
run_step 2
want_step_rc 1 "3 a CALLED finding (gate 2) fails the step"
want_in "::error::" "3a with an error annotation"

# ---------------------------------------------------------------------------
# 4. A scan that could not run fails. Unknown is not clean (T-0740); a gate
#    that passes here is a check that silently stopped checking.
# ---------------------------------------------------------------------------
run_step 3
want_step_rc 1 "4 a could-not-run (gate 3) fails the step"
want_in "::error::" "4a with an error annotation"

# ---------------------------------------------------------------------------
# 5. An unrecognised status is not assumed benign. A future gate revision that
#    grows a fourth verdict must not land in a success arm by default.
# ---------------------------------------------------------------------------
run_step 7
want_step_rc 1 "5 an unexpected gate status (7) fails the step rather than defaulting to success"

# ---------------------------------------------------------------------------
# 6. The step asks the gate to fail on a called finding at all. Dropping
#    `--fail-on called` would restore report-only silently, and every case
#    above would still pass because the stub ignores its arguments.
# ---------------------------------------------------------------------------
OUT="$tmp/step.sh"
want_in "--fail-on called" "6 the step still passes --fail-on called to the gate"

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
