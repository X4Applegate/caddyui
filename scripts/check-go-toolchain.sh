#!/usr/bin/env bash
# Advisory + staleness watch for the Go TOOLCHAIN itself (T-0745).
#
# THE GAP THIS CLOSES. Every other input to this repo's advisory watch has
# something asking about it on a schedule:
#
#   `--with` / `--replace` plugin pins   check-pinned-modules.sh (weekly)
#   Caddy base image + module graph      check-pinned-modules.sh --binary
#   go.mod module set                    check-pinned-modules.sh --gomod, Dependabot
#   reachability of either               govulncheck-gate.sh
#   THE GO TOOLCHAIN                     nothing, until this script
#
# Nothing watched it, and nothing was going to:
#
#   - Dependabot's `gomod` ecosystem watches module REQUIREMENTS. It does not
#     touch the `go` or `toolchain` directive.
#   - The image gate compares the rebuilt image against the PREVIOUS image, so
#     a toolchain that is behind upstream is not a diff and never appears.
#   - govulncheck surfaces a stdlib finding, but reactively: it reports what a
#     scan happened to hit, it does not ask whether the pinned toolchain is
#     behind a release that fixes something. And a report is only read when
#     someone opens the job.
#
# So the sequence was: an advisory lands against the stdlib -> CI goes on
# passing -> someone eventually reads a job summary. Same shape as the gap
# T-0646 and T-0676 closed elsewhere: a component nothing asks about is not a
# clean component.
#
# THE INDEX QUESTION IS THE OPPOSITE OF T-0676's. For modules, `vuln.go.dev`
# and OSV are CVE-keyed and therefore blind to the five CVE-less go-jose
# advisories — which is why the module watch asks GitHub's per-repository
# endpoint instead. For the STDLIB that objection does not apply:
# `vuln.go.dev` is the authoritative index for Go stdlib and toolchain
# advisories, it is maintained by the Go security team, and stdlib advisories
# do carry GO- ids whether or not they also carry a CVE. So this script reads
# it directly.
#
# WHY IT FETCHES INDIVIDUAL ADVISORIES RATHER THAN TRUSTING THE INDEX.
# `index/modules.json` gives one `fixed` version per advisory, which is the
# HIGHEST fix across release branches. Go backports: GO-2026-6859 is fixed in
# BOTH 1.26.11 and 1.27.4, and the index says only 1.27.4. Believing the index
# alone would report a correctly-patched 1.26.11 toolchain as vulnerable — a
# false alarm, and false alarms are how a weekly report stops being read. So
# the index is used only to SHORTLIST (any advisory whose highest fix is above
# the pinned version is a candidate, which is a safe superset) and each
# candidate's own OSV ranges then decide.
#
# AN UNREACHABLE OR UNPARSED ANSWER IS `could not run`, NEVER `current`. Every
# such path exits 3, including one candidate advisory that could not be
# fetched while the others came back clean: a partial answer about which
# advisories apply is not an answer.
#
# Usage:
#   check-go-toolchain.sh [--gomod PATH] [--out-dir DIR]
#                         [--releases-fixture FILE] [--index-fixture FILE]
#                         [--advisory-dir DIR] [--toolchain goX.Y.Z]
#
#   --gomod               go.mod to read the pinned toolchain from
#                         (default: the one beside this script)
#   --toolchain           override the pinned version, for a what-if run
#   --out-dir DIR         where the report and verdict are written
#                         (default: toolchain-watch)
#   --releases-fixture    read go.dev/dl JSON from a file instead of the network
#   --index-fixture       read vuln.go.dev/index/modules.json from a file
#   --advisory-dir DIR    read <ID>.json from DIR instead of vuln.go.dev/ID/
#                         (the three fixture flags are what make the regression
#                         suite offline; a run with any of them says so in its
#                         report, because a fixture is not evidence about today)
#
# Exit codes (the check-pinned-modules.sh convention):
#   0  ok         the pinned toolchain is a current stable release and no
#                 advisory applies to it
#   1  attention  the pinned toolchain is behind a current stable release, but
#                 no known advisory applies to it
#   2  advisory   a published GO- advisory covers the PINNED toolchain
#   3  the check could not run — treat as UNKNOWN, never as a pass
set -uo pipefail

PROG="check-go-toolchain"

GOMOD=""
OUT_DIR="toolchain-watch"
RELEASES_FIXTURE=""
INDEX_FIXTURE=""
ADVISORY_DIR=""
PINNED_OVERRIDE=""

REPO_ROOT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)"
DL_URL="https://go.dev/dl/?mode=json"
INDEX_URL="https://vuln.go.dev/index/modules.json"
ADVISORY_BASE="https://vuln.go.dev/ID"

die_usage() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 3; }

while [ $# -gt 0 ]; do
  case "$1" in
    --gomod)             GOMOD="${2:-}";            [ -n "$GOMOD" ] || die_usage "--gomod needs a path"; shift ;;
    --out-dir)           OUT_DIR="${2:-}";          [ -n "$OUT_DIR" ] || die_usage "--out-dir needs a directory"; shift ;;
    --releases-fixture)  RELEASES_FIXTURE="${2:-}"; [ -n "$RELEASES_FIXTURE" ] || die_usage "--releases-fixture needs a file"; shift ;;
    --index-fixture)     INDEX_FIXTURE="${2:-}";    [ -n "$INDEX_FIXTURE" ] || die_usage "--index-fixture needs a file"; shift ;;
    --advisory-dir)      ADVISORY_DIR="${2:-}";     [ -n "$ADVISORY_DIR" ] || die_usage "--advisory-dir needs a directory"; shift ;;
    --toolchain)         PINNED_OVERRIDE="${2:-}";  [ -n "$PINNED_OVERRIDE" ] || die_usage "--toolchain needs a version"; shift ;;
    -h|--help)
      sed -n '2,/^# Exit codes/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die_usage "unknown argument: $1" ;;
  esac
  shift
done

command -v jq >/dev/null 2>&1 || { printf '%s: jq is required\n' "$PROG" >&2; exit 3; }

mkdir -p "$OUT_DIR" || { printf '%s: cannot create %s\n' "$PROG" "$OUT_DIR" >&2; exit 3; }
REPORT="$OUT_DIR/summary.md"
VERDICT_FILE="$OUT_DIR/verdict"
: > "$REPORT"

notes=()
note() { notes+=("$1"); }
gh_out() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; return 0; }

# ---------------------------------------------------------------------------
# Version handling. Shared semantics with govulncheck-gate.sh: a prerelease
# sorts BELOW the matching release, which is what OSV's `1.27.0-0` introduced
# marker means ("from the first 1.27 prerelease onwards").
# ---------------------------------------------------------------------------
go_version_fields() {
  local v="${1:-}"
  v="${v#go}"
  local pre=1
  case "$v" in
    *rc*|*beta*|*alpha*|*-*) pre=0 ;;
  esac
  v="${v%%rc*}"; v="${v%%beta*}"; v="${v%%alpha*}"; v="${v%%-*}"; v="${v%%+*}"
  case "$v" in
    ''|*[!0-9.]*) return 1 ;;
  esac
  local maj min pat
  IFS=. read -r maj min pat <<<"$v"
  [ -n "${maj:-}" ] || return 1
  min="${min:-0}"; pat="${pat:-0}"
  case "$min$pat" in *[!0-9]*) return 1 ;; esac
  printf '%s %s %s %s\n' "$maj" "$min" "$pat" "$pre"
}

go_version_cmp() {
  local a b
  a="$(go_version_fields "${1:-}")" || return 1
  b="$(go_version_fields "${2:-}")" || return 1
  local a1 a2 a3 a4 b1 b2 b3 b4 i x y
  read -r a1 a2 a3 a4 <<<"$a"
  read -r b1 b2 b3 b4 <<<"$b"
  for i in 1 2 3 4; do
    case "$i" in
      1) x=$a1; y=$b1 ;;
      2) x=$a2; y=$b2 ;;
      3) x=$a3; y=$b3 ;;
      4) x=$a4; y=$b4 ;;
    esac
    if [ "$x" -lt "$y" ]; then printf -- '-1\n'; return 0; fi
    if [ "$x" -gt "$y" ]; then printf '1\n'; return 0; fi
  done
  printf '0\n'
}

ge() { local c; c="$(go_version_cmp "$1" "$2")" || return 2; [ "$c" != "-1" ]; }

# ---------------------------------------------------------------------------
# What is pinned?
# ---------------------------------------------------------------------------
pinned=""
pinned_src=""
if [ -n "$PINNED_OVERRIDE" ]; then
  pinned="$PINNED_OVERRIDE"
  pinned_src="--toolchain override"
else
  if [ -z "$GOMOD" ] && [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/go.mod" ]; then GOMOD="$REPO_ROOT/go.mod"; fi
  if [ -n "$GOMOD" ] && [ -f "$GOMOD" ]; then
    pinned="$(sed -n 's/^toolchain[[:space:]]\{1,\}\(go[0-9][^[:space:]]*\).*/\1/p' "$GOMOD" | head -1)"
    if [ -n "$pinned" ]; then
      pinned_src="toolchain directive in $GOMOD"
    else
      # No toolchain line. The `go` directive is then the floor CI's
      # `go-version-file: go.mod` resolves, so it is the right thing to judge,
      # and the absence is worth saying out loud rather than papering over.
      pinned="$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][^[:space:]]*\).*/go\1/p' "$GOMOD" | head -1)"
      [ -n "$pinned" ] && pinned_src="go directive in $GOMOD (there is no toolchain line)"
    fi
  fi
fi

fail_unknown() {
  {
    echo "### Go toolchain watch — **could not run**"
    echo
    echo "This run established **nothing** about the pinned Go toolchain. It is not a clean result."
    echo
    for n in "${notes[@]}"; do echo "- $n"; done
    echo
    echo "_Exit 3 is this repo's \"the check could not run\" status, deliberately distinct from 0 (the same convention as \`check-pinned-modules.sh\`)._"
  } >> "$REPORT"
  cat "$REPORT" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  cat "$REPORT"
  echo unknown > "$VERDICT_FILE"
  gh_out "verdict=unknown"
  gh_out "rc=3"
  gh_out "pinned=${pinned:-unknown}"
  gh_out "advisories=unknown"
  printf '::error::%s: the Go toolchain watch could not run, so its result is UNKNOWN, not clean\n' "$PROG"
  for n in "${notes[@]}"; do printf '::error::%s\n' "$n"; done
  exit 3
}

if [ -z "$pinned" ]; then
  note "no Go toolchain could be read${GOMOD:+ from $GOMOD}, so there is nothing to compare"
  fail_unknown
fi
if ! go_version_fields "$pinned" >/dev/null; then
  note "the pinned toolchain \`$pinned\` ($pinned_src) is not a readable Go version"
  fail_unknown
fi

# ---------------------------------------------------------------------------
# Fetch. `curl -fsS` so an HTTP error is a failure rather than an error page
# parsed as data, and a bounded number of retries so one hiccup is not a
# weekly false unknown.
# ---------------------------------------------------------------------------
fetch() {
  local url="$1" dest="$2" i
  for i in 1 2 3; do
    if curl -fsS --max-time 30 -o "$dest" "$url" 2>/dev/null; then
      [ -s "$dest" ] && return 0
    fi
    sleep $(( i * 2 ))
  done
  return 1
}

releases_json="$OUT_DIR/go-releases.json"
if [ -n "$RELEASES_FIXTURE" ]; then
  [ -f "$RELEASES_FIXTURE" ] || { note "the releases fixture $RELEASES_FIXTURE does not exist"; fail_unknown; }
  cp "$RELEASES_FIXTURE" "$releases_json"
elif ! fetch "$DL_URL" "$releases_json"; then
  note "could not read the Go release list from \`$DL_URL\`, so whether the pinned toolchain is current is unknown"
  fail_unknown
fi

if ! jq -e 'type == "array"' "$releases_json" >/dev/null 2>&1; then
  note "the Go release list is not a JSON array, so it was not parsed (a rate-limit or error body is an object, and must not read as zero releases)"
  fail_unknown
fi

mapfile -t stable_versions < <(jq -r '.[] | select(.stable == true) | .version' "$releases_json" 2>/dev/null)
if [ "${#stable_versions[@]}" -eq 0 ]; then
  note "the Go release list contains no stable release, which cannot be true; it was not trusted"
  fail_unknown
fi

# The newest stable, and the newest stable ON THE PINNED MINOR BRANCH. Both
# matter: Go supports two branches at a time, so a toolchain on the older
# supported branch is not necessarily behind in the sense that matters.
latest_stable=""
branch_latest=""
pin_fields="$(go_version_fields "$pinned")"
read -r p_maj p_min _ _ <<<"$pin_fields"
for v in "${stable_versions[@]}"; do
  go_version_fields "$v" >/dev/null || continue
  if [ -z "$latest_stable" ] || ge "$v" "$latest_stable"; then latest_stable="$v"; fi
  read -r v_maj v_min _ _ <<<"$(go_version_fields "$v")"
  if [ "$v_maj" = "$p_maj" ] && [ "$v_min" = "$p_min" ]; then
    if [ -z "$branch_latest" ] || ge "$v" "$branch_latest"; then branch_latest="$v"; fi
  fi
done

index_json="$OUT_DIR/vuln-index.json"
if [ -n "$INDEX_FIXTURE" ]; then
  [ -f "$INDEX_FIXTURE" ] || { note "the advisory index fixture $INDEX_FIXTURE does not exist"; fail_unknown; }
  cp "$INDEX_FIXTURE" "$index_json"
elif ! fetch "$INDEX_URL" "$index_json"; then
  note "could not read the Go advisory index from \`$INDEX_URL\`, so whether an advisory covers the pinned toolchain is unknown"
  fail_unknown
fi

if ! jq -e 'type == "array"' "$index_json" >/dev/null 2>&1; then
  note "the Go advisory index is not a JSON array, so it was not parsed"
  fail_unknown
fi

# `stdlib` and `toolchain` are two distinct pseudo-modules in this index and
# both are the Go release: `stdlib` for library code, `toolchain` for `go`,
# `gofmt`, the linker and friends. Watching one and not the other was never an
# option — four of the ids in the toolchain list are command-line tools that
# run in CI.
if ! jq -e '[.[] | select(.path == "stdlib" or .path == "toolchain")] | length == 2' "$index_json" >/dev/null 2>&1; then
  note "the advisory index does not contain both a \`stdlib\` and a \`toolchain\` entry, so it is not the index this check knows how to read"
  fail_unknown
fi

# SHORTLIST. Anything whose highest fix is above the pinned version. This is a
# superset by construction: an advisory every one of whose fixes is at or
# below the pinned version cannot have a range covering it.
candidates=()
while IFS=$'\037' read -r path id fixed; do
  [ -n "$id" ] || continue
  if [ -z "$fixed" ]; then
    # An advisory with no fix at all can never be ruled out by version, so it
    # is always a candidate.
    candidates+=("$path|$id|")
    continue
  fi
  c="$(go_version_cmp "$fixed" "$pinned")" || { note "advisory $id records fixed=$fixed, which is not a readable Go version, so it could not be ruled in or out"; fail_unknown; }
  if [ "$c" = "1" ]; then candidates+=("$path|$id|$fixed"); fi
done < <(jq -r '
  .[] | select(.path == "stdlib" or .path == "toolchain")
  | .path as $p | .vulns[]
  | [ $p, .id, (.fixed // "") ] | join("\u001f")
' "$index_json")

# ---------------------------------------------------------------------------
# Decide each candidate against its own OSV ranges.
#
# Standard OSV evaluation: walk the events in order holding an `affected`
# flag. `introduced: V` sets it when the pinned version is at or above V;
# `fixed: V` clears it when the pinned version is at or above V. Go's
# branch backports appear as repeated introduced/fixed pairs in one range,
# which is exactly what this walk handles and what the index's single `fixed`
# value cannot express.
# ---------------------------------------------------------------------------
affected_rows=()
cleared=0
adv_dir="$OUT_DIR/advisories"
mkdir -p "$adv_dir"

for cand in "${candidates[@]}"; do
  IFS='|' read -r c_path c_id _ <<<"$cand"
  f="$adv_dir/$c_id.json"
  if [ -n "$ADVISORY_DIR" ]; then
    if [ -f "$ADVISORY_DIR/$c_id.json" ]; then
      cp "$ADVISORY_DIR/$c_id.json" "$f"
    else
      note "advisory $c_id is a candidate but $ADVISORY_DIR/$c_id.json does not exist, so whether it covers \`$pinned\` is unknown. A partial answer about which advisories apply is not an answer."
      fail_unknown
    fi
  elif ! fetch "$ADVISORY_BASE/$c_id.json" "$f"; then
    # One unreachable candidate is enough to make the whole answer partial.
    note "could not fetch advisory $c_id, so whether it covers \`$pinned\` is unknown. A partial answer about which advisories apply is not an answer."
    fail_unknown
  fi
  if ! jq -e '.id' "$f" >/dev/null 2>&1; then
    note "advisory $c_id did not parse as an OSV record"
    fail_unknown
  fi

  # Only the ranges for the module this candidate came from. An advisory can
  # name several modules (a stdlib one sometimes also names a x/ module), and
  # another module's range says nothing about the toolchain.
  state=0
  while IFS=$'\037' read -r kind ver; do
    [ -n "$kind" ] || continue
    case "$kind" in
      introduced)
        if [ "$ver" = "0" ]; then state=1
        elif ge "$pinned" "$ver"; then state=1
        fi ;;
      fixed)
        if ge "$pinned" "$ver"; then state=0; fi ;;
    esac
  done < <(jq -r --arg m "$c_path" '
    [ .affected[]? | select(.package.name == $m) | .ranges[]? | .events[]? ]
    | .[]
    | to_entries[]
    | [ .key, (.value | tostring) ] | join("\u001f")
  ' "$f")

  summary="$(jq -r '.summary // .details // ""' "$f" | head -1)"
  aliases="$(jq -r '(.aliases // []) | join(" ")' "$f")"
  fixes="$(jq -r --arg m "$c_path" '
    [ .affected[]? | select(.package.name == $m) | .ranges[]? | .events[]? | .fixed // empty ] | join(", ")
  ' "$f")"
  if [ "$state" = 1 ]; then
    affected_rows+=("| \`$c_id\` | $c_path | ${fixes:-**no fix published**} | ${summary//|/\\|} | ${aliases:-none} |")
  else
    cleared=$((cleared + 1))
  fi
done

# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------
rc=0
verdict=ok
behind=0
if [ -n "$branch_latest" ]; then
  c="$(go_version_cmp "$pinned" "$branch_latest")" || c=""
  [ "$c" = "-1" ] && behind=1
else
  # The pinned branch is not a supported stable branch at all, which is worse
  # than being a patch behind: it receives no security fixes.
  behind=2
fi

if [ "${#affected_rows[@]}" -gt 0 ]; then
  rc=2; verdict=advisory
elif [ "$behind" != 0 ]; then
  rc=1; verdict=attention
fi

using_fixtures=""
[ -n "$RELEASES_FIXTURE$INDEX_FIXTURE$ADVISORY_DIR" ] && using_fixtures=yes

{
  case "$verdict" in
    ok)        echo "### Go toolchain watch — \`$pinned\` is current and no advisory applies" ;;
    attention) echo "### Go toolchain watch — \`$pinned\` is behind, no advisory applies" ;;
    advisory)  echo "### Go toolchain watch — **a published advisory covers \`$pinned\`**" ;;
  esac
  echo
  echo "| | |"
  echo "| --- | --- |"
  echo "| pinned | \`$pinned\` ($pinned_src) |"
  echo "| newest stable | \`${latest_stable:-unknown}\` |"
  echo "| newest on the \`${p_maj}.${p_min}\` branch | \`${branch_latest:-none — this branch is no longer a supported stable branch}\` |"
  echo "| advisories checked | ${#candidates[@]} candidate(s) from \`stdlib\` + \`toolchain\`, $cleared ruled out by range, ${#affected_rows[@]} applying |"
  if [ -n "$using_fixtures" ]; then
    echo
    echo "⚠️ **This run used fixtures, not live data** (\`--releases-fixture\`, \`--index-fixture\` or \`--advisory-dir\`). It proves the logic, not today's advisory state."
  fi

  if [ "${#affected_rows[@]}" -gt 0 ]; then
    echo
    echo "#### Advisories whose affected range covers the pinned toolchain"
    echo
    echo "| advisory | module | fixed in | summary | aliases |"
    echo "| --- | --- | --- | --- | --- |"
    printf '%s\n' "${affected_rows[@]}"
    echo
    echo "A stdlib or toolchain advisory is fixed by a **toolchain bump**: edit the \`toolchain\` line in \`go.mod\` to a release at or above one of the fixed versions above. CI reads that line through \`go-version-file: go.mod\`, so the bump is the whole change."
  fi

  if [ "$behind" = 1 ]; then
    echo
    echo "The pinned toolchain is behind \`$branch_latest\` on its own branch. That is work, not an emergency — no advisory above covers it — but a patch release exists."
  elif [ "$behind" = 2 ]; then
    echo
    echo "⚠️ **\`${p_maj}.${p_min}\` is not one of the supported stable branches** (\`$(printf '%s ' "${stable_versions[@]}")\`). Go supports the two newest; an unsupported branch receives no further security fixes, so \"no advisory applies\" here means only \"none is published against it yet\"."
  fi

  if [ "${#notes[@]}" -gt 0 ]; then
    echo
    echo "#### notes"
    echo
    for n in "${notes[@]}"; do echo "- $n"; done
  fi

  echo
  echo "**Scope.** This watches the Go toolchain only — the one input to this repo's advisory watch that nothing else asks about. Dependabot's \`gomod\` ecosystem tracks module requirements and not the \`go\`/\`toolchain\` directive; the image gate compares a rebuild against the previous image, so a toolchain behind upstream is not a diff. Module advisories are \`check-pinned-modules.sh\`'s job and reachability is \`govulncheck-gate.sh\`'s."
  echo
  echo "Unlike the module watch, the index here is not a limitation: \`vuln.go.dev\` is the authoritative source for Go stdlib and toolchain advisories, and they carry \`GO-\` ids whether or not they also carry a CVE. The CVE-less blind spot that drove \`--gomod\` onto GitHub's per-repository endpoint does not apply to this input."
} >> "$REPORT"

cat "$REPORT" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
cat "$REPORT"

echo "$verdict" > "$VERDICT_FILE"
gh_out "verdict=$verdict"
gh_out "rc=$rc"
gh_out "pinned=$pinned"
gh_out "latest_stable=${latest_stable:-}"
gh_out "branch_latest=${branch_latest:-}"
gh_out "advisories=${#affected_rows[@]}"
gh_out "candidates=${#candidates[@]}"
gh_out "behind=$behind"

case "$verdict" in
  advisory)  printf '::error::%s: %d published advisory/advisories cover the pinned Go toolchain %s - bump the toolchain line in go.mod\n' "$PROG" "${#affected_rows[@]}" "$pinned" ;;
  attention)
    if [ "$behind" = 2 ]; then
      printf '::warning::%s: Go %s.%s is not a supported stable branch, so the pinned toolchain %s receives no security fixes\n' "$PROG" "$p_maj" "$p_min" "$pinned"
    else
      printf '::notice::%s: the pinned Go toolchain %s is behind %s on its own branch; no advisory applies\n' "$PROG" "$pinned" "$branch_latest"
    fi ;;
esac

exit "$rc"
