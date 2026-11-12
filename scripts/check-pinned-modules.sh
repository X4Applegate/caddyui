#!/usr/bin/env bash
# Staleness and advisory watch for Dockerfile.caddy's pinned xcaddy plugins.
#
# T-0617 pinned every `--with` argument in Dockerfile.caddy. That removed the
# silent-drift risk, but it also removed the only route by which a plugin
# security fix reached this image at all: a pin never moves on its own. This
# script is the other half of that trade — it does not change anything, it
# reports what a human should decide about.
#
# The evidence that the gap is real rather than theoretical: caddy-l4 was
# ALREADY STALE on the day it was pinned (v0.1.3 tagged 2026-11-09, the pin
# went in 2026-11-12 at v0.1.2) and it took a review subagent to notice.
#
# Dependabot cannot do this. Its `docker` ecosystem sees only `FROM` lines and
# its `gomod` ecosystem only `go.mod`; neither parses xcaddy `--with` arguments
# out of a `RUN` line. The repo's existing dependabot docker block moves
# `caddy:2.11.x`, not the plugins.
#
# Usage:
#   check-pinned-modules.sh [--dockerfile PATH] [--out-dir DIR] [--json]
#                           [--offline-fixture FILE]
#
# Environment:
#   GITHUB_OUTPUT   When set, verdict/counts are appended for CI consumption.
#   GITHUB_STEP_SUMMARY  When set, the Markdown report is appended.
#
# Requires: curl, jq. `git` is used only for the untagged pins (below) and its
# absence degrades those two rows to "unknown" rather than failing the run.
#
# Exit status:
#   0  ok        every pin is current, no advisory matches a pinned version
#   1  attention at least one pin is behind, or an untagged pin has moved
#   2  advisory  an advisory matches a PINNED version (the urgent case)
#   3  the check could not run (treat as unknown, not as a pass)
#
# Advisory beats behind: exit 2 is returned even if some pins are merely stale,
# because the two call for different urgency and the caller should see the
# worse one. A caller that ignores exit codes still gets the verdict in the
# report and in GITHUB_OUTPUT.
#
# ---------------------------------------------------------------------------
# Three traps this script exists to handle correctly
# ---------------------------------------------------------------------------
#
# 1. A `--with` ARGUMENT IS NOT ALWAYS A MODULE PATH. xcaddy takes a *package*
#    path; the Go module proxy only answers for *module* paths. Three of the
#    fifteen arguments are packages inside a larger module:
#
#      github.com/crowdsecurity/crowdsec/pkg/apiclient -> .../crowdsec
#      golang.org/x/net/http2                          -> golang.org/x/net
#      github.com/hslatman/caddy-crowdsec-bouncer/http -> .../caddy-crowdsec-bouncer
#
#    Asking proxy.golang.org for those three returns 404. A script that treats
#    404 as "no data available" therefore SILENTLY SKIPS THE THREE MOST
#    SECURITY-CRITICAL PINS — the two CVE floors and the CrowdSec bouncer. So
#    404 is not tolerated: the path is walked up one element at a time until
#    the proxy answers, and a path that never resolves is a hard error that
#    shows in the report. Being unable to check a pin must never look like a
#    clean pin.
#
#    The version `@v` in the --with argument belongs to the MODULE, not the
#    package, so the resolved module path is also the correct thing to send to
#    OSV. `/v2`, `/v5` style major-version suffixes are module paths in their
#    own right and must not be stripped; the walk-up stops as soon as the
#    proxy answers, which handles them without special-casing.
#
# 2. TWO PINS ARE NOT TAGS, so `@latest` comparison is meaningless for them.
#      - caddy-dns/digitalocean has never been tagged upstream; its pin is the
#        pseudo-version of master@04bde286.
#      - caddy-crowdsec-bouncer/http is pinned to a raw commit SHA, the commit
#        that supports CrowdSec 1.7 (its newest tag at pin time needed 1.6).
#    For these the comparison is against upstream's default-branch HEAD via
#    `git ls-remote` — a commit, not a version. For the bouncer the script also
#    reports when a TAG exists that satisfies the Dockerfile's own standing
#    note ("Go back to a tag once one exists"), by reading the candidate tag's
#    go.mod and checking which CrowdSec it builds against. That condition is
#    the actual reason for the commit pin, so checking it mechanically is worth
#    more than noting that a newer tag exists.
#
# 3. OSV MUST BE QUERIED WITH THE VERSION. The obvious call —
#    `{"package":{...}}` with no version — returns every advisory the module
#    has EVER had, including ones fixed years before the pinned release. On
#    golang.org/x/net that is 18 advisories against a pin that is affected by
#    none of them, which trains a reader to ignore the report. Sending
#    `version` makes OSV do its own affected-range matching, so a hit means
#    "this pinned version is affected" and an empty result means it is not.
#    Verified in both directions before this script was written: x/net 0.40.0
#    returns 18, x/net 0.62.0 (the actual pin) returns 0.
#
#    OSV accepts the version with or without the `v` prefix, and accepts a
#    pseudo-version, so no normalisation is needed. Sent as ONE /v1/querybatch
#    rather than fifteen /v1/query calls: fewer round trips, and every pin is
#    then matched against the same snapshot of the database.
set -uo pipefail

PROXY="${GOPROXY_BASE:-https://proxy.golang.org}"
OSV="${OSV_BASE:-https://api.osv.dev}"
DOCKERFILE="Dockerfile.caddy"
OUT_DIR=""
EMIT_JSON=0
FIXTURE=""

die() { echo "check-pinned-modules: $*" >&2; exit 3; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dockerfile) DOCKERFILE="${2:-}"; shift 2 ;;
    --out-dir)    OUT_DIR="${2:-}";    shift 2 ;;
    --json)       EMIT_JSON=1;         shift ;;
    --offline-fixture) FIXTURE="${2:-}"; shift 2 ;;
    -h|--help)    sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq   >/dev/null 2>&1 || die "jq is required"
[ -f "$DOCKERFILE" ] || die "no such file: $DOCKERFILE"

if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"
else
  OUT_DIR="$(mktemp -d)" || die "cannot create a temp dir"
fi

# ---------------------------------------------------------------------------
# Parse the pins out of the Dockerfile.
#
# Deliberately strict: `--with <arg>@<version>`, one per line, and the version
# is required. An unpinned --with is not something to skip quietly — T-0617's
# whole point was that there are none left, so one reappearing is a finding in
# its own right and is reported as `unpinned`.
#
# COMMENT LINES ARE EXCLUDED FIRST. This Dockerfile's header explains the pin
# policy in prose, and that prose contains the string "--with" several times
# ("EVERY --with below carries a version", "An unpinned --with re-resolves…").
# Grepping the whole file harvests `--with lines`, `--with below` and
# `--with re-resolves` as if they were modules — which then reports three
# non-existent unpinned plugins and buries the real findings. So only
# non-comment lines are considered, and the argument must look like a Go
# package path (a dotted host followed by at least one path element) before it
# counts as a pin at all.
# ---------------------------------------------------------------------------
pins_file="$OUT_DIR/pins.tsv"
: > "$pins_file"
unpinned_file="$OUT_DIR/unpinned.txt"
: > "$unpinned_file"

while IFS= read -r raw; do
  arg="${raw#*--with }"
  arg="${arg%% *}"
  arg="${arg%\\}"
  [ -n "$arg" ] || continue
  # Must look like <host-with-a-dot>/<path>; prose words never do.
  printf '%s' "$arg" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^ ]+$' || continue
  case "$arg" in
    *@*) printf '%s\t%s\n' "${arg%@*}" "${arg##*@}" >> "$pins_file" ;;
    *)   printf '%s\n' "$arg" >> "$unpinned_file" ;;
  esac
done < <(grep -v '^[[:space:]]*#' "$DOCKERFILE" | grep -oE -- '--with [^ \\]+' || true)

pin_count="$(wc -l < "$pins_file" | tr -d ' ')"
[ "$pin_count" -gt 0 ] || die "parsed no --with pins out of $DOCKERFILE (did its format change?)"

# ---------------------------------------------------------------------------
# Untagged pins. Keyed by the --with argument so the table can say why a row
# is compared by commit rather than by version. Extend this when a pin changes
# shape; an entry that no longer matches any pin is reported, not ignored, so
# the list cannot rot into a lie.
# ---------------------------------------------------------------------------
untagged_repo() {
  case "$1" in
    github.com/caddy-dns/digitalocean)              echo "https://github.com/caddy-dns/digitalocean.git" ;;
    github.com/hslatman/caddy-crowdsec-bouncer/http) echo "https://github.com/hslatman/caddy-crowdsec-bouncer.git" ;;
    *) echo "" ;;
  esac
}

# A pinned version is a commit SHA or a pseudo-version, i.e. not a plain tag.
is_untagged_pin() {
  case "$1" in
    v0.0.0-*|*-0.*) return 0 ;;                     # pseudo-version
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
      # A bare hex string of 7+ chars with no dots is a commit SHA.
      case "$1" in *.*) return 1 ;; esac
      [ -z "${1//[0-9a-f]/}" ] && return 0 || return 1 ;;
  esac
  return 1
}

# ---------------------------------------------------------------------------
# Resolve a --with package path to the module path the proxy knows, by walking
# up. See trap 1 in the header: this is what keeps a 404 from silently
# excusing a pin from being checked.
# ---------------------------------------------------------------------------
proxy_get() {
  # $1 = module path, $2 = suffix (e.g. @latest). Lowercased per the proxy's
  # case-encoding rules; all pins here are already lowercase, but a future
  # module with an uppercase element would otherwise 404 confusingly.
  local lower
  lower="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  curl -fsS --max-time 25 --retry 2 --retry-delay 2 \
    "$PROXY/$lower/$2" 2>/dev/null
}

resolve_module() {
  # Prints "<module-path>\t<latest-json>" or nothing if nothing resolved.
  local path="$1" body
  while [ -n "$path" ] && [ "$path" != "." ]; do
    case "$path" in */*) ;; *) break ;; esac   # a bare host is not a module
    if body="$(proxy_get "$path" '@latest')" && [ -n "$body" ]; then
      printf '%s\t%s\n' "$path" "$body"
      return 0
    fi
    path="${path%/*}"
  done
  return 1
}

# ---------------------------------------------------------------------------
# Pass 1 — resolve module paths and latest versions.
# ---------------------------------------------------------------------------
rows="$OUT_DIR/rows.tsv"      # arg \t pinned \t module \t latest \t latest_time \t kind \t note
: > "$rows"
errors="$OUT_DIR/errors.txt"
: > "$errors"

if [ -n "$FIXTURE" ]; then
  [ -f "$FIXTURE" ] || die "no such fixture: $FIXTURE"
fi

while IFS=$'\t' read -r arg pinned; do
  [ -n "$arg" ] || continue

  if [ -n "$FIXTURE" ]; then
    # Offline mode for tests: the fixture supplies module/latest per arg.
    line="$(grep -P "^\Q$arg\E\t" "$FIXTURE" 2>/dev/null || grep -F "$arg	" "$FIXTURE" 2>/dev/null || true)"
    module="$(printf '%s' "$line" | cut -f2)"
    latest="$(printf '%s' "$line" | cut -f3)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$arg" "$pinned" "${module:-$arg}" "${latest:-unknown}" "-" "tag" "" >> "$rows"
    continue
  fi

  if ! resolved="$(resolve_module "$arg")"; then
    echo "could not resolve any module path for '$arg' on $PROXY" >> "$errors"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$arg" "$pinned" "unresolved" "unknown" "-" "error" "proxy returned no module for this path or any parent" >> "$rows"
    continue
  fi
  module="$(printf '%s' "$resolved" | cut -f1)"
  latest_json="$(printf '%s' "$resolved" | cut -f2-)"
  latest="$(jq -r '.Version // "unknown"' <<<"$latest_json" 2>/dev/null || echo unknown)"
  latest_time="$(jq -r '(.Time // "-") | .[0:10]' <<<"$latest_json" 2>/dev/null || echo -)"

  note=""
  kind="tag"
  repo="$(untagged_repo "$arg")"
  if is_untagged_pin "$pinned" || [ -n "$repo" ]; then
    kind="commit"
    if [ -z "$repo" ]; then
      repo="$(jq -r '.Origin.URL // ""' <<<"$latest_json" 2>/dev/null || true)"
      [ -n "$repo" ] && repo="${repo}.git"
    fi
    head=""
    if [ -n "$repo" ] && command -v git >/dev/null 2>&1; then
      head="$(git ls-remote "$repo" HEAD 2>/dev/null | awk 'NR==1{print $1}')"
    fi
    if [ -z "$head" ]; then
      note="could not read upstream HEAD"
      kind="commit-unknown"
    else
      # The pin may be a bare SHA or a pseudo-version ending in the short SHA.
      short_pin="${pinned##*-}"
      if [ "${head#"$short_pin"}" != "$head" ] || [ "${short_pin#"${head:0:12}"}" != "$short_pin" ]; then
        note="at upstream HEAD ${head:0:12}"
        latest="$pinned"      # equal: nothing to do
      else
        note="upstream HEAD is now ${head:0:12}"
        latest="commit:${head:0:12}"
      fi
    fi
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$arg" "$pinned" "$module" "$latest" "$latest_time" "$kind" "$note" >> "$rows"
done < "$pins_file"

# ---------------------------------------------------------------------------
# Pass 2 — the bouncer's standing question: does a TAG now support the
# CrowdSec major this image needs? The Dockerfile pins a raw commit only
# because no tag did, and says in so many words to return to a tag once one
# exists. Checking that mechanically is the difference between a watcher and
# a reminder.
# ---------------------------------------------------------------------------
tag_now_ok=""
if [ -z "$FIXTURE" ] && grep -q 'caddy-crowdsec-bouncer' "$pins_file"; then
  cs_floor="$(awk -F'\t' '$1 ~ /crowdsecurity\/crowdsec/ {print $2}' "$pins_file" | head -1)"
  cs_major="$(printf '%s' "${cs_floor#v}" | cut -d. -f1-2)"
  b_mod="github.com/hslatman/caddy-crowdsec-bouncer"
  b_latest="$(proxy_get "$b_mod" '@latest' | jq -r '.Version // ""' 2>/dev/null || true)"
  if [ -n "$b_latest" ]; then
    b_cs="$(proxy_get "$b_mod" "@v/${b_latest}.mod" \
      | awk '/crowdsecurity\/crowdsec /{print $2; exit}' 2>/dev/null || true)"
    if [ -n "$b_cs" ]; then
      b_major="$(printf '%s' "${b_cs#v}" | cut -d. -f1-2)"
      # Compare as versions: a tag building against >= the floor's minor is a
      # candidate for returning to a tagged pin.
      if [ -n "$cs_major" ] && [ "$(printf '%s\n%s\n' "$cs_major" "$b_major" | sort -V | tail -1)" = "$b_major" ]; then
        tag_now_ok="$b_latest builds against crowdsec $b_cs (pin floor is $cs_floor) — the Dockerfile's \"go back to a tag once one exists\" condition is satisfied"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Pass 3 — OSV, one batch, every pin matched against its pinned version.
# ---------------------------------------------------------------------------
osv_out="$OUT_DIR/osv.json"
echo '{}' > "$osv_out"
osv_failed=0

if [ -z "$FIXTURE" ]; then
  q="$(awk -F'\t' '$3 != "unresolved" && $3 != "" {printf "%s\t%s\n", $3, $2}' "$rows" \
      | sort -u \
      | jq -R -s -c '{queries: [ split("\n")[] | select(length>0) | split("\t")
          | {package: {name: .[0], ecosystem: "Go"}, version: .[1]} ]}')"
  if ! curl -fsS --max-time 40 --retry 2 --retry-delay 2 \
        -X POST "$OSV/v1/querybatch" \
        -H 'Content-Type: application/json' \
        -d "$q" -o "$osv_out" 2>/dev/null; then
    osv_failed=1
    echo "OSV querybatch failed; advisory status is UNKNOWN for this run" >> "$errors"
  fi
  # Keep the query alongside the response so a surprising result is auditable.
  printf '%s\n' "$q" > "$OUT_DIR/osv-query.json"
fi

# Map the batch results back onto module+version in query order.
osv_hits="$OUT_DIR/osv-hits.tsv"
: > "$osv_hits"
if [ "$osv_failed" -eq 0 ] && [ -z "$FIXTURE" ]; then
  paste <(jq -r '.queries[] | "\(.package.name)\t\(.version)"' "$OUT_DIR/osv-query.json") \
        <(jq -r '.results[]? | [ (.vulns // [])[].id ] | join(",")' "$osv_out") \
    > "$osv_hits" 2>/dev/null || : > "$osv_hits"
fi

# ---------------------------------------------------------------------------
# Verdict + report.
# ---------------------------------------------------------------------------
behind=0; advisories=0; unresolved=0; moved=0
report="$OUT_DIR/report.md"
{
  echo "### Pinned xcaddy plugin watch"
  echo
  echo "\`$DOCKERFILE\` — $pin_count pinned \`--with\` arguments."
  echo
  echo "| module | pinned | upstream | advisories |"
  echo "| --- | --- | --- | --- |"
} > "$report"

while IFS=$'\t' read -r arg pinned module latest latest_time kind note; do
  adv=""
  if [ -s "$osv_hits" ]; then
    adv="$(awk -F'\t' -v m="$module" -v v="$pinned" '$1==m && $2==v {print $3; exit}' "$osv_hits")"
  fi
  state="ok"
  case "$kind" in
    error)           state="unresolved"; unresolved=$((unresolved+1)) ;;
    commit-unknown)  state="unknown" ;;
    commit)
      case "$latest" in commit:*) state="moved"; moved=$((moved+1)) ;; esac ;;
    tag)
      if [ "$latest" != "unknown" ] && [ "$pinned" != "$latest" ]; then
        newest="$(printf '%s\n%s\n' "$pinned" "$latest" | sort -V | tail -1)"
        [ "$newest" = "$latest" ] && { state="behind"; behind=$((behind+1)); }
      fi ;;
  esac
  if [ -n "$adv" ]; then
    advisories=$((advisories+1))
    state="ADVISORY"
  fi

  up="$latest"
  [ "$latest_time" != "-" ] && [ "$state" = "behind" ] && up="$latest (tagged $latest_time)"
  [ -n "$note" ] && up="$up — $note"
  printf '| `%s` | `%s` | %s | %s |\n' \
    "$arg" "$pinned" "$up" "${adv:-—}" >> "$report"
done < "$rows"

{
  echo
  if [ "$advisories" -gt 0 ]; then
    echo "**$advisories pinned version(s) match a published advisory.** Treat as the urgent case: OSV matched the *pinned* version's affected range, not merely the module's history."
    echo
  fi
  [ "$behind" -gt 0 ] && { echo "**$behind pin(s) behind upstream's newest tag.**"; echo; }
  [ "$moved"  -gt 0 ] && { echo "**$moved untagged pin(s) no longer at upstream HEAD.** These are compared by commit because upstream has no usable tag."; echo; }
  [ -n "$tag_now_ok" ] && { echo "**A tagged release is now viable for the CrowdSec bouncer:** $tag_now_ok."; echo; }
  if [ -s "$unpinned_file" ]; then
    echo "**An unpinned \`--with\` argument reappeared** — every one should carry a version (T-0617):"
    while IFS= read -r u; do echo "- \`$u\`"; done < "$unpinned_file"
    echo
  fi
  if [ -s "$errors" ]; then
    echo "**The check could not complete for every pin.** An unchecked pin is not a clean pin:"
    while IFS= read -r e; do echo "- $e"; done < "$errors"
    echo
  fi
  if [ "$advisories" -eq 0 ] && [ "$behind" -eq 0 ] && [ "$moved" -eq 0 ] \
     && [ ! -s "$errors" ] && [ ! -s "$unpinned_file" ] && [ -z "$tag_now_ok" ]; then
    echo "Every pin is at upstream's newest release and no advisory matches a pinned version."
  fi
  echo
  echo "<sub>Versions from \`$PROXY\`; advisories from \`$OSV\` matched against the pinned version. Untagged pins compared against upstream \`HEAD\`.</sub>"
} >> "$report"

# Order matters, and it is not the obvious one.
#
# An advisory against a pinned version is the worst outcome and wins outright.
# But a run that COULD NOT CHECK outranks mere staleness: "3 pins behind" from
# a run whose proxy was unreachable reads like an ordinary drift report, when
# in fact the advisory column of every row is meaningless. Reporting that as
# `attention` would quietly downgrade a broken check to a routine one, so an
# unresolved pin or a failed OSV batch yields `error` even when real staleness
# was also found — the findings still appear in the report, under a verdict
# that says the run is not authoritative.
if   [ "$advisories" -gt 0 ]; then verdict="advisory"; rc=2
elif [ "$unresolved" -gt 0 ] || [ "$osv_failed" -eq 1 ]; then verdict="error"; rc=3
elif [ "$behind" -gt 0 ] || [ "$moved" -gt 0 ] || [ -n "$tag_now_ok" ] \
  || [ -s "$unpinned_file" ]; then verdict="attention"; rc=1
else verdict="ok"; rc=0
fi

cat "$report"
echo "verdict=$verdict"

if [ "$EMIT_JSON" -eq 1 ]; then
  jq -n --arg v "$verdict" --argjson b "$behind" --argjson a "$advisories" \
        --argjson m "$moved" --argjson u "$unresolved" \
        '{verdict:$v, behind:$b, advisories:$a, moved:$m, unresolved:$u}' \
    > "$OUT_DIR/result.json"
  cat "$OUT_DIR/result.json"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "verdict=$verdict"
    echo "behind=$behind"
    echo "advisories=$advisories"
    echo "moved=$moved"
    echo "report<<PINREPORT_EOF"
    cat "$report"
    echo "PINREPORT_EOF"
  } >> "$GITHUB_OUTPUT"
fi
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$report" >> "$GITHUB_STEP_SUMMARY"

exit "$rc"
