#!/usr/bin/env bash
# Run the check-pinned-modules.sh regression suites and report honestly (T-0712).
#
#   ./scripts/run-pinwatch-suites.sh offline   # no network; PR path
#   ./scripts/run-pinwatch-suites.sh network   # the rest; weekly path
#   ./scripts/run-pinwatch-suites.sh all       # everything
#
# WHY THIS WRAPPER EXISTS, rather than six `run:` lines in the workflow.
#
# The suites guard check-pinned-modules.sh, a ~3000-line script whose entire
# subject is the difference between "checked and clean" and "not checked".
# T-0634, T-0651, T-0666 and T-0669 are all the same bug in different places:
# something that was never evaluated rendered as something that passed. A CI
# step that runs those suites and then lets a skip count as a pass reproduces
# that bug one level up, in the thing meant to catch it. So the wrapper's job
# is not to run the suites — `bash foo.sh` does that — it is to make a
# suite that did not actually test anything impossible to mistake for a green
# check.
#
# Three properties, each of which had to be built rather than assumed:
#
# 1. SKIPS ARE COUNTED AND SURFACED. Three suites print `skip=N` in their own
#    summary; the floors suite prints a bare `SKIP` line with no counter at
#    all, so its live OSV case (21, advisory-precedence) vanishing to a
#    network failure is invisible in both its output and its exit status. The
#    wrapper therefore does not trust the summary line: it greps the captured
#    log for SKIP markers itself, which works uniformly across all five.
#
# 2. A SKIP IS NOT A PASS. Skips never fail the build — that is deliberate,
#    because a runner that cannot reach OSV is not a code defect and blocking
#    a PR on it would train people to ignore the job. They are raised as
#    GitHub ::warning:: annotations, counted in the step summary, and named
#    line by line. The build stays green; the gap is on the face of the run
#    rather than inferred from its absence.
#
# 3. EVERY SUITE RUNS EVEN AFTER ONE FAILS. `set -e` around a test loop
#    reports the first failure and hides the other four, which is the wrong
#    trade when the suites are independent. Each is run under `|| true` with
#    its status captured, and the aggregate status is computed at the end.
#
# Exit 0 = every selected suite passed. Exit 1 = at least one failed.
# Exit 2 = the wrapper itself could not run (missing/non-executable suite),
# which is deliberately distinct from a test failure: "the tests say no" and
# "there were no tests" are different answers and must not share an exit code.
set -uo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)" || { echo "::error::cannot reach the repository root"; exit 2; }

# Which suites need the network, and for what. Keep this list in sync when a
# suite is added — an unlisted suite is simply not run, so the count printed
# at the end is the check: it must match `ls scripts/test-pinned-module-*.sh`.
#
# offline: no outbound call on any case. Safe on every PR.
# network: at least one case calls out, and self-skips when it cannot.
OFFLINE_SUITES=(
  test-pinned-module-crosscheck.sh   # jq predicate vs local JSON fixtures
  test-pinned-module-replace.sh      # PINWATCH_SKIP_GITHUB=1 throughout
)
NETWORK_SUITES=(
  test-pinned-module-floors.sh       # case 21 -> api.osv.dev
  test-pinned-module-gomod-sweep.sh  # proxy/OSV
  test-pinned-module-image-sweep.sh  # case 16 -> GitHub advisories, needs a token
)

mode="${1:-all}"
case "$mode" in
  offline) suites=("${OFFLINE_SUITES[@]}") ;;
  network) suites=("${NETWORK_SUITES[@]}") ;;
  all)     suites=("${OFFLINE_SUITES[@]}" "${NETWORK_SUITES[@]}") ;;
  *) echo "usage: $0 [offline|network|all]" >&2; exit 2 ;;
esac

# A suite named here but absent from the tree is a wrapper fault, not a test
# failure: it means the list drifted from the repo. Exit 2, loudly, rather
# than quietly running four of five and reporting success.
for s in "${suites[@]}"; do
  if [ ! -f "scripts/$s" ]; then
    echo "::error::scripts/$s is listed in $0 but does not exist"
    exit 2
  fi
  if [ ! -x "scripts/$s" ]; then
    echo "::error::scripts/$s exists but is not executable"
    exit 2
  fi
done

# Cross-check the list against the tree in the other direction too, so adding
# a suite without adding it here is visible. This is a warning rather than an
# error only in `offline`/`network` mode, where a partial list is the point;
# in `all` mode an unlisted suite means something genuinely goes unrun.
if [ "$mode" = all ]; then
  for f in scripts/test-pinned-module-*.sh; do
    b="$(basename "$f")"
    found=no
    for s in "${suites[@]}"; do [ "$s" = "$b" ] && found=yes && break; done
    if [ "$found" = no ]; then
      echo "::warning::$b is not listed in $0, so it did NOT run; add it to OFFLINE_SUITES or NETWORK_SUITES"
    fi
  done
fi

summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
log_dir="$(mktemp -d)"
trap 'rm -rf "$log_dir"' EXIT

# THE SUITES MUST NOT INHERIT $GITHUB_STEP_SUMMARY.
#
# They exercise check-pinned-modules.sh dozens of times over fixture
# Dockerfiles, and that script appends a full "Pinned xcaddy plugin watch"
# report to $GITHUB_STEP_SUMMARY on every invocation. Inherited, a single
# `offline` run appends ~15 reports about temp-file Dockerfiles, and the table
# this script writes ends up beneath all of them. On the weekly workflow the
# damage is worse than cosmetic: watch-pins' own summary is the actual
# deliverable of that job, and fixture reports interleaved with it are
# indistinguishable at a glance from reports about the real image -- several
# of them say things like "NOT swept" and "1 pinned version(s) match a
# published advisory" about Dockerfiles that exist only inside a test.
#
# Pointed at a scratch file rather than unset, because the suites assert on
# what the script writes to it (gomod-sweep cases 11a/11b grep $GITHUB_OUTPUT
# and friends); unsetting it would change the behaviour under test.
suite_summary="$log_dir/suite-step-summary.md"
: > "$suite_summary"
export GITHUB_STEP_SUMMARY="$suite_summary"

total_fail=0
total_skip=0
rows=()

for s in "${suites[@]}"; do
  echo "::group::$s"
  log="$log_dir/$s.log"
  start=$SECONDS
  # A non-zero status is a RESULT to be collected, not a reason to abandon the
  # remaining suites. `|| rc=$?` keeps the status, where a bare `|| true` would
  # discard the very number being collected.
  rc=0
  ./"scripts/$s" >"$log" 2>&1 || rc=$?
  elapsed=$((SECONDS - start))
  cat "$log"
  echo "::endgroup::"

  # Counted from the LOG, not from the suite's own summary line: the floors
  # suite has no skip counter, so its summary cannot be trusted to mention a
  # skip at all. `^SKIP` matches the marker all five use.
  n_skip=$(grep -c '^SKIP' "$log" || true)
  n_skip=${n_skip:-0}
  total_skip=$((total_skip + n_skip))

  if [ "$rc" -eq 0 ]; then
    verdict=pass
  else
    verdict=FAIL
    total_fail=$((total_fail + 1))
    echo "::error::$s failed (exit $rc)"
  fi

  # Each skipped case is named in the log and in an annotation. A count alone
  # is skimmable past; the name of the case that did not run is not.
  if [ "$n_skip" -gt 0 ]; then
    echo "::warning::$s skipped $n_skip case(s) - a skipped case is NOT a passed case"
    while IFS= read -r line; do
      [ -n "$line" ] && echo "::warning::$s: ${line#SKIP}"
    done < <(grep '^SKIP' "$log" || true)
  fi

  rows+=("| \`$s\` | $verdict | $n_skip | ${elapsed}s |")
done

{
  echo "### Pin-watch regression suites (\`$mode\`)"
  echo
  echo "| suite | result | skipped | time |"
  echo "| --- | --- | --- | --- |"
  printf '%s\n' "${rows[@]}"
  echo
  if [ "$total_skip" -gt 0 ]; then
    echo "⚠️ **$total_skip case(s) were skipped and therefore prove nothing.**"
    echo "A skip is usually no network or no \`GITHUB_TOKEN\`. It is reported"
    echo "rather than failed, but it is not a pass — see the warnings above."
  else
    echo "Every case in every selected suite ran."
  fi
} >> "$summary"

echo
echo "suites=${#suites[@]} failed=$total_fail skipped=$total_skip"
[ "$total_fail" -eq 0 ]
