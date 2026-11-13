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
#
# $3 optionally overrides DH_USER (default `$DH_USER_NONE`), for the T-0760
# cases that need the username to be a substring of the version or the ref.
#
# The default must be a string that occurs in NO ref name used anywhere in this
# file, or the T-0760 guard fires in unrelated cases. A single letter is a trap:
# the original `u` is inside "feat-u-re/x", so it refused the build-only
# dispatch tests. Keep this a realistic, distinctive account-like name.
DH_USER_NONE=zzdockerhubacct
run_plan() {
  local d="$1" input="$2" dh_user="${3-$DH_USER_NONE}" rc=0 outf="$tmp/gh-out.$$"
  # Only meaningful for the default placeholder: the T-0760 cases pass a
  # username that is SUPPOSED to occur in the input.
  if [ "$dh_user" = "$DH_USER_NONE" ]; then
    case "$input" in
      *"$DH_USER_NONE"*) printf '%s\n' "$input" >> "$collisions_file" ;;
    esac
  fi
  : > "$outf"
  ( cd "$d" && \
    GITHUB_OUTPUT="$outf" \
    GITHUB_STEP_SUMMARY=/dev/null \
    GITHUB_REF_NAME=main \
    GITHUB_REF=refs/heads/main \
    INPUT_VERSION="$input" \
    WANT_PUSH=true WANT_CADDY=false \
    DH_USER="$dh_user" DH_TOKEN=t \
    bash "$tmp/plan.sh" >/dev/null 2>&1 ) || rc=$?
  printf 'rc=%s\n' "$rc"
  cat "$outf"
}

field() { sed -n "s/^$2=//p" <<<"$1" | tail -1; }

echo "T-0755 — plan job version-input validation"

# The default DH_USER must not be a substring of any ref name used below, or
# the T-0760 guard fires in cases that have nothing to do with it and the
# failures look like guard bugs. `u` was exactly that trap (it is inside
# "feature/x").
#
# This is recorded inside run_plan on EVERY default-DH_USER call rather than
# against a hand-written list, because a hand-written list silently goes stale:
# a case added later would not be covered, and the cases that assert only
# `rc != 0` would then pass for the wrong reason, masking the very trap this
# check exists to catch. Deriving it from the actual inputs cannot drift.
#
# run_plan is always called inside $( ), i.e. a SUBSHELL, so a shell variable
# incremented there would be discarded. The collisions are therefore recorded
# in a FILE, which survives the subshell, and reported once at the end.
collisions_file="$tmp/dh-user-collisions"
: > "$collisions_file"

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
  WANT_PUSH=true WANT_CADDY=false DH_USER="$DH_USER_NONE" DH_TOKEN=t \
  bash "$tmp/plan.sh" >/dev/null 2>&1 ) || rc=$?
pout="$(cat "$outf")"
[ "$rc" = 0 ] && [ "$(field "$pout" kind)" = stable ] \
  && ok "tag push v1.0.1 (no input) -> kind=stable" || bad "tag push -> rc=$rc kind=$(field "$pout" kind)"
[ "$(field "$pout" ref)" = refs/tags/v1.0.1 ] && ok "tag push -> ref qualified" || bad "tag push -> ref=$(field "$pout" ref)"

# 9. T-0760 — a release name containing the DOCKERHUB_USERNAME secret.
#
#    GitHub silently drops any job output whose value contains a secret, so
#    such a name would blank BOTH `version` and `ref` on their way to the build
#    jobs and fail there with "tag is needed when pushing to registry". The
#    plan job refuses the name instead. `pre_re` allows letters in the suffix,
#    which is what makes this reachable at all.
#
#    Asserting rc!=0 alone would be too weak: it cannot tell a refusal apart
#    from any other failure, and the whole point is that NOTHING carrying the
#    secret reaches $GITHUB_OUTPUT. So each case also asserts the outputs are
#    clean, which is the property GitHub would otherwise enforce by blanking.
d8="$(make_repo)"
git -C "$d8" tag v1.1.0-applegater
out="$(run_plan "$d8" v1.1.0-applegater applegater)"
[ "$(field "$out" rc)" != 0 ]                    && ok "prerelease tag containing DH_USER FAILS the plan job" \
                                                 || bad "v1.1.0-applegater should fail, got rc=0 version=$(field "$out" version)"
! grep -q applegater <<<"$out"                   && ok "prerelease tag containing DH_USER emits no output carrying the secret" \
                                                 || bad "outputs leaked the DH_USER substring GitHub would blank: $out"

#    The same name is harmless when it is NOT the username: this must refuse
#    the collision, not the tag shape. Guards against 'fix' it by tightening
#    pre_re, which is a different (policy) decision and would break this.
out="$(run_plan "$d8" v1.1.0-applegater someoneelse)"
[ "$(field "$out" rc)" = 0 ]                     && ok "the same tag succeeds when DH_USER does not occur in it" \
                                                 || bad "v1.1.0-applegater with unrelated DH_USER should succeed: $out"
[ "$(field "$out" kind)" = pre ]                 && ok "letters in a prerelease suffix are still allowed (kind=pre)" \
                                                 || bad "v1.1.0-applegater -> kind=$(field "$out" kind), want pre"

#    WHY THE GUARD ITERATES OVER BOTH VALUES, and which assertions pin which
#    half (so a half-removed guard cannot pass this suite):
#
#      - `$ref_out` half: load-bearing ONLY on the kind=none path, where
#        `version` is the literal "dev" and cannot carry the username however
#        the branch is named. The build-only assertions above are what catch
#        its removal.
#      - `$version` half: for kind!=none, `ref` is refs/tags/$version, so the
#        two collide and EITHER check would catch a bad tag. What makes this
#        half independently necessary is a username that the version contains
#        but the ref string does not -- see the case immediately below, where
#        DH_USER is "dev": the kind=none path writes version=dev while
#        ref=feature/x contains no "dev".
#
#    That last case is the only shape in which the `$version` check fires
#    where the `$ref_out` check does not, so it is what keeps M2-style
#    mutation (dropping "$version" from the loop) detectable.
d10="$(make_repo)"
git -C "$d10" branch feature/x
out="$(run_plan "$d10" feature/x dev)"
[ "$(field "$out" rc)" != 0 ]                    && ok "DH_USER='dev' refuses the kind=none path (version=dev carries it, ref does not)" \
                                                 || bad "version=dev should be refused when DH_USER is literally 'dev': $out"
! grep -q '^version=dev$' <<<"$out"              && ok "DH_USER='dev' emits no version output carrying the secret" \
                                                 || bad "version=dev written while DH_USER='dev': $out"

#    An UNSET DH_USER must not make the empty string match every version. A
#    fork, or this repo before the secrets exist, still has to build.
out="$(run_plan "$d8" v1.0.1 '')"
[ "$(field "$out" rc)" = 0 ]                     && ok "empty DH_USER does not match every version" \
                                                 || bad "empty DH_USER wrongly rejected v1.0.1: $out"
[ "$(field "$out" kind)" = stable ]              && ok "empty DH_USER -> v1.0.1 still kind=stable" \
                                                 || bad "empty DH_USER -> kind=$(field "$out" kind), want stable"

#    The check is not limited to prereleases: a plain vX.Y.Z that contains the
#    username is refused too. Unreachable today (a plain release tag is all
#    digits and dots), but the guard sits after kind-resolution deliberately so
#    it cannot be bypassed by a future loosening of stable_re.
out="$(run_plan "$d8" v1.0.1 1.0)"
[ "$(field "$out" rc)" != 0 ]                    && ok "a STABLE tag containing DH_USER is refused too" \
                                                 || bad "stable tag containing DH_USER should fail, got rc=0"

#    THE kind=none PATH IS THE DANGEROUS ONE, and checking `$version` alone
#    would miss it entirely. On that path `version` is reassigned to the
#    literal 'dev' BEFORE any guard could see the real input, while `ref_out`
#    is built from the raw INPUT_VERSION independently. So a build-only
#    dispatch of a branch named feature/applegater emits ref=feature/applegater
#    -- carrying the secret -- with version=dev.
#
#    And an empty `ref` does NOT fail: actions/checkout documents ref: '' as
#    "the ref that triggered the workflow, otherwise the default branch". So
#    this one fails OPEN -- it would silently build the default branch and
#    report green -- where the version case fails closed. That asymmetry is
#    why the guard checks both values, after both are final.
d9="$(make_repo)"
git -C "$d9" branch feature/applegater
out="$(run_plan "$d9" feature/applegater applegater)"
[ "$(field "$out" rc)" != 0 ]                    && ok "build-only branch containing DH_USER FAILS the plan job" \
                                                 || bad "feature/applegater must be refused: ref would be blanked and the default branch built silently: $out"
! grep -q applegater <<<"$out"                   && ok "build-only branch containing DH_USER emits no output carrying the secret" \
                                                 || bad "ref leaked the DH_USER substring GitHub would blank: $out"

#    The same branch is fine when it does NOT collide with the username: the
#    build-only dispatch path must not regress for ordinary names.
out="$(run_plan "$d9" feature/applegater someoneelse)"
[ "$(field "$out" rc)" = 0 ]                     && ok "build-only branch runs when DH_USER does not occur in it" \
                                                 || bad "feature/applegater with unrelated DH_USER should succeed: $out"
[ "$(field "$out" version)" = dev ]              && ok "build-only branch -> version=dev" \
                                                 || bad "feature/applegater -> version=$(field "$out" version), want dev"
[ "$(field "$out" ref)" = feature/applegater ]   && ok "build-only branch -> ref preserved" \
                                                 || bad "feature/applegater -> ref=$(field "$out" ref)"

# The placeholder-collision property, reported once. run_plan checks every
# call it makes; section 8 drives the plan script directly, so cover its
# GITHUB_REF_NAME too.
_s8ref=v1.0.1
case "$_s8ref" in *"$DH_USER_NONE"*) printf '%s\n' "$_s8ref" >> "$collisions_file" ;; esac
n_collisions="$(wc -l < "$collisions_file" | tr -d ' ')"
if [ "$n_collisions" -eq 0 ]; then
  ok "default DH_USER '$DH_USER_NONE' collides with no test input (checked on every call)"
else
  bad "default DH_USER '$DH_USER_NONE' occurs in $n_collisions test input(s) — pick another placeholder: $(tr '\n' ' ' < "$collisions_file")"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
