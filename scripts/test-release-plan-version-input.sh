#!/usr/bin/env bash
# test-release-plan-version-input.sh — prove release-docker.yml's plan job only
# accepts a release-shaped version that is really a TAG, and hands the build
# jobs a ref that cannot be steered to a same-named branch (T-0755).
#
# WHAT THIS GUARDS
# ----------------
# The plan job decides `kind` from `$version` as a string, and `kind=stable` is
# what authorises :stable and :latest on both images. Two things had to be true
# for that to be safe, and neither was checked:
#
#   1. the name is a tag in this repository, not merely tag-SHAPED;
#   2. the ref handed downstream resolves to that tag, not to a branch of the
#      same name.
#
# (2) is not a theoretical nicety. actions/checkout resolves an UNQUALIFIED ref
# branch-first — getCheckoutInfo() tries refs/remotes/origin/<ref> and only
# then refs/tags/<ref> (src/ref-helper.ts) — which is the opposite of plain
# `git rev-parse`. So `refs/heads/<newest release tag>`, pushed once, gave
# kind=stable computed from the real tag and applied to branch content.
#
# HOW IT TESTS
# ------------
# It extracts the plan step's script FROM THE WORKFLOW ITSELF and runs it
# against throwaway repositories. Copying the logic into the test would let the
# two drift and pass while the workflow was wrong — the defect this file exists
# to catch is precisely a mismatch between what is checked and what is built.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
wf="$repo/.github/workflows/release-docker.yml"
[ -f "$wf" ] || { echo "missing $wf" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ---- extract the plan step's script, verbatim, from the workflow ------------
python3 - "$wf" "$tmp/plan.sh" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(wf))
steps = [s for s in d["jobs"]["plan"]["steps"] if s.get("id") == "p"]
if len(steps) != 1:
    sys.exit(f"expected exactly one plan step with id 'p', found {len(steps)}")
open(out, "w").write("#!/usr/bin/env bash\n" + steps[0]["run"])
PY
chmod +x "$tmp/plan.sh"

pass=0 fail=0
ok()   { pass=$((pass+1)); printf '  ok    %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL  %s\n' "$1"; }

# Build a repo with tags v1.0.0, v1.0.1 (newest) plus whatever extra refs the
# caller asks for. Returns its path.
make_repo() {
  local d; d="$(mktemp -d "$tmp/r.XXXXXX")"
  git init -q --initial-branch=main "$d"
  git -C "$d" config user.email t@example.com
  git -C "$d" config user.name  t
  echo one > "$d/f"; git -C "$d" add f; git -C "$d" commit -qm one
  git -C "$d" tag v1.0.0
  echo two > "$d/f"; git -C "$d" commit -qam two
  git -C "$d" tag v1.0.1
  printf '%s\n' "$d"
}

# Run the extracted plan step in $1 with INPUT_VERSION=$2, capturing outputs.
# Echoes "rc=<n>" then the GITHUB_OUTPUT contents.
run_plan() {
  local d="$1" input="$2" rc=0 outf="$tmp/gh-out.$$"
  : > "$outf"
  ( cd "$d" && \
    GITHUB_OUTPUT="$outf" \
    GITHUB_STEP_SUMMARY=/dev/null \
    GITHUB_REF_NAME=main \
    GITHUB_REF=refs/heads/main \
    INPUT_VERSION="$input" \
    WANT_PUSH=true WANT_CADDY=false \
    DH_USER=u DH_TOKEN=t \
    bash "$tmp/plan.sh" >/dev/null 2>&1 ) || rc=$?
  printf 'rc=%s\n' "$rc"
  cat "$outf"
}

field() { sed -n "s/^$2=//p" <<<"$1" | tail -1; }

echo "T-0755 — plan job version-input validation"

# 1. the normal release: newest real tag -> kind=stable, ref qualified
d="$(make_repo)"
out="$(run_plan "$d" v1.0.1)"
[ "$(field "$out" rc)" = 0 ]                     && ok "v1.0.1 (newest tag) succeeds"            || bad "v1.0.1 (newest tag) should succeed: $out"
[ "$(field "$out" kind)" = stable ]              && ok "v1.0.1 -> kind=stable"                   || bad "v1.0.1 -> kind=$(field "$out" kind), want stable"
[ "$(field "$out" ref)" = refs/tags/v1.0.1 ]     && ok "v1.0.1 -> ref=refs/tags/v1.0.1 (qualified)" \
                                                 || bad "v1.0.1 -> ref=$(field "$out" ref), want refs/tags/v1.0.1"

# 2. an older real tag -> kind=older, still qualified, moving tags untouched
out="$(run_plan "$d" v1.0.0)"
[ "$(field "$out" kind)" = older ]               && ok "v1.0.0 (older tag) -> kind=older"        || bad "v1.0.0 -> kind=$(field "$out" kind), want older"
[ "$(field "$out" ref)" = refs/tags/v1.0.0 ]     && ok "v1.0.0 -> ref qualified"                 || bad "v1.0.0 -> ref=$(field "$out" ref)"

# 3. THE DEFECT: a BRANCH named exactly the newest release tag.
#    Before the fix this reached kind=stable (the string equals the newest tag)
#    and actions/checkout would have built the BRANCH. It must now fail, and it
#    must fail even though a tag of that name also exists — because what made it
#    dangerous was the ref, not the name. The qualified ref is what closes it.
d2="$(make_repo)"
echo evil > "$d2/f"; git -C "$d2" commit -qam evil
git -C "$d2" update-ref refs/heads/v1.0.1 "$(git -C "$d2" rev-parse HEAD)"
out="$(run_plan "$d2" v1.0.1)"
[ "$(field "$out" kind)" = stable ]              && ok "branch+tag v1.0.1 still resolves kind=stable from the TAG" \
                                                 || bad "branch+tag v1.0.1 -> kind=$(field "$out" kind)"
[ "$(field "$out" ref)" = refs/tags/v1.0.1 ]     && ok "branch+tag v1.0.1 -> ref pinned to refs/tags/ (branch unreachable)" \
                                                 || bad "branch+tag v1.0.1 -> ref=$(field "$out" ref) — build job could take the branch"

# 4. a release-shaped BRANCH with NO tag of that name: must fail the plan job
d3="$(make_repo)"
git -C "$d3" branch v2.0.0
out="$(run_plan "$d3" v2.0.0)"
[ "$(field "$out" rc)" != 0 ]                    && ok "branch v2.0.0 with no such tag FAILS the plan job" \
                                                 || bad "branch v2.0.0 should fail, got rc=0 kind=$(field "$out" kind)"
[ -z "$(field "$out" kind)" ]                    && ok "branch v2.0.0 emits no kind"             || bad "branch v2.0.0 emitted kind=$(field "$out" kind)"

# 5. a release-shaped name that is no ref at all: must fail
out="$(run_plan "$d" v3.1.4)"
[ "$(field "$out" rc)" != 0 ]                    && ok "v3.1.4 (no such ref) FAILS the plan job" || bad "v3.1.4 should fail, got rc=0"

# 6. prereleases get the same treatment
d4="$(make_repo)"
git -C "$d4" tag v1.1.0-rc.1
out="$(run_plan "$d4" v1.1.0-rc.1)"
[ "$(field "$out" kind)" = pre ]                 && ok "v1.1.0-rc.1 (real tag) -> kind=pre"      || bad "v1.1.0-rc.1 -> kind=$(field "$out" kind), want pre"
[ "$(field "$out" ref)" = refs/tags/v1.1.0-rc.1 ] && ok "v1.1.0-rc.1 -> ref qualified"            || bad "v1.1.0-rc.1 -> ref=$(field "$out" ref)"
git -C "$d4" branch v1.2.0-rc.9
out="$(run_plan "$d4" v1.2.0-rc.9)"
[ "$(field "$out" rc)" != 0 ]                    && ok "prerelease-shaped BRANCH v1.2.0-rc.9 FAILS the plan job" \
                                                 || bad "prerelease-shaped branch should fail, got rc=0 kind=$(field "$out" kind)"

# 7. the build-only branch dispatch is UNCHANGED: a non-release name is
#    kind=none, version=dev, push=false, and keeps its unqualified ref.
d5="$(make_repo)"
git -C "$d5" branch feature/x
out="$(run_plan "$d5" feature/x)"
[ "$(field "$out" kind)" = none ]                && ok "feature/x -> kind=none"                  || bad "feature/x -> kind=$(field "$out" kind)"
[ "$(field "$out" version)" = dev ]              && ok "feature/x -> version=dev"                || bad "feature/x -> version=$(field "$out" version)"
[ "$(field "$out" push)" = false ]               && ok "feature/x -> push=false"                 || bad "feature/x -> push=$(field "$out" push)"
[ "$(field "$out" ref)" = feature/x ]            && ok "feature/x -> ref left unqualified (build-only)" \
                                                 || bad "feature/x -> ref=$(field "$out" ref)"

# 7b. $GITHUB_OUTPUT INJECTION. A workflow_dispatch input may contain newlines,
#     and every output is written as a bare name=value line, so a crafted
#     non-release input could append forged `kind=stable` / `push=true` lines.
#     Two accidents defused it: a newline cannot satisfy the $-anchored regexes
#     (bash has no multiline flag), and `ref=` is written before the legitimate
#     keys so last-writer-wins overwrites the forgeries. The second is the
#     undocumented duplicate-key precedence the gate step further down the
#     workflow deliberately refuses to depend on, so the value is validated
#     instead. Assert the run FAILS, rather than that the forged keys lost a race.
inj_nl="$(printf 'feature/x\nkind=stable\npush=true')"
out="$(run_plan "$d5" "$inj_nl")"
[ "$(field "$out" rc)" != 0 ]                    && ok "newline-injecting ref FAILS the plan job" \
                                                 || bad "newline-injecting ref should fail, got rc=0"
[ "$(field "$out" kind)" != stable ]             && ok "newline-injecting ref never yields kind=stable" \
                                                 || bad "newline-injecting ref forged kind=stable"
for inj in 'feature/x;id' 'feature/$(id)' '--upload-pack=evil' 'a..b' '-leading'; do
  out="$(run_plan "$d5" "$inj")"
  [ "$(field "$out" rc)" != 0 ] && ok "rejected build-only ref '$inj'" \
                                || bad "build-only ref '$inj' accepted (rc=0, ref=$(field "$out" ref))"
done
# a legitimate branch name with a slash and a dot must STILL be accepted: the
# build-only branch dispatch is a documented path and must not regress.
d7="$(make_repo)"
git -C "$d7" branch release/2.x
out="$(run_plan "$d7" release/2.x)"
{ [ "$(field "$out" rc)" = 0 ] && [ "$(field "$out" ref)" = release/2.x ]; } \
  && ok "ordinary branch 'release/2.x' still accepted for a build-only run" \
  || bad "release/2.x rejected: rc=$(field "$out" rc) ref=$(field "$out" ref)"

# 8. a tag-push run (no dispatch input) still works off GITHUB_REF_NAME
d6="$(make_repo)"
rc=0; outf="$tmp/gh-push"; : > "$outf"
( cd "$d6" && GITHUB_OUTPUT="$outf" GITHUB_STEP_SUMMARY=/dev/null \
  GITHUB_REF_NAME=v1.0.1 GITHUB_REF=refs/tags/v1.0.1 INPUT_VERSION='' \
  WANT_PUSH=true WANT_CADDY=false DH_USER=u DH_TOKEN=t \
  bash "$tmp/plan.sh" >/dev/null 2>&1 ) || rc=$?
pout="$(cat "$outf")"
[ "$rc" = 0 ] && [ "$(field "$pout" kind)" = stable ] \
  && ok "tag push v1.0.1 (no input) -> kind=stable" || bad "tag push -> rc=$rc kind=$(field "$pout" kind)"
[ "$(field "$pout" ref)" = refs/tags/v1.0.1 ] && ok "tag push -> ref qualified" || bad "tag push -> ref=$(field "$pout" ref)"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
