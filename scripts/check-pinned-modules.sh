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

# A precondition failure must not be able to read as a clean report.
#
# This used to be a bare `exit 3`, which left $GITHUB_OUTPUT empty. The
# workflow then read an EMPTY verdict, its case statement fell through to the
# default arm, and the run logged "every pin is current and no advisory
# matches" — the exact inversion this script's header forbids, triggered by
# something as ordinary as a Dockerfile reformat that breaks the parser. So
# the verdict is emitted here too, before exiting.
# The $GITHUB_OUTPUT heredoc delimiter is randomised per run. A fixed
# `PINREPORT_EOF` is forgeable in principle: any untrusted text that reaches
# column 0 of the report ends the heredoc early, and everything after it is
# parsed as further job outputs — letting a hostile proxy or OSV response
# write `verdict=ok` over a real finding. Today no such path exists, because
# every line carrying upstream text is prefixed with `| ` or `- ` and the
# scalars are sanitised; but that is an incidental property of the current
# printf templates, not a designed one, and the next person to add an
# unprefixed line to the report would silently re-open it. A delimiter the
# attacker cannot know makes the breakout structurally impossible regardless.
PINREPORT_DELIM="PINREPORT_EOF_$(od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n' \
  || printf '%s%s' "$$" "$(date +%s%N 2>/dev/null || date +%s)")"

die() {
  echo "check-pinned-modules: $*" >&2
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "verdict=error"
      echo "behind=0"
      echo "advisories=0"
      echo "moved=0"
      echo "report<<$PINREPORT_DELIM"
      echo "### Pinned xcaddy plugin watch"
      echo
      echo "**The check could not run:** $*"
      echo
      echo "No pin was checked. An unchecked pin is not a clean pin."
      echo "$PINREPORT_DELIM"
    } >> "$GITHUB_OUTPUT"
  fi
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '### Pinned xcaddy plugin watch\n\n**The check could not run:** %s\n' "$*" \
      >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 3
}

# `need_value` exists because the obvious form hangs. With `--out-dir` as the
# final argument, `${2:-}` is empty and `shift 2` FAILS (only one positional
# remains), so `$#` never decreases and the loop spins forever — in CI that is
# the job burning its entire timeout with no output, which reads as a network
# hang rather than a typo. Verified: `--out-dir` with no value looped until
# killed. So a missing value is rejected explicitly and every branch shifts a
# fixed, safe amount.
need_value() {
  [ -n "${2+set}" ] || die "option $1 requires a value"
  [ -n "$2" ] || die "option $1 requires a non-empty value"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dockerfile) need_value "$1" "${2+$2}"; DOCKERFILE="$2"; shift; shift ;;
    --out-dir)    need_value "$1" "${2+$2}"; OUT_DIR="$2";    shift; shift ;;
    --offline-fixture) need_value "$1" "${2+$2}"; FIXTURE="$2"; shift; shift ;;
    --json)       EMIT_JSON=1;         shift ;;
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
#
# BOTH SPELLINGS ARE ACCEPTED. xcaddy takes `--with X` and `--with=X`, and an
# earlier version of this matched only the space form: a legal `--with=` pin
# was dropped from pins.tsv AND from unpinned.txt, so the plugin vanished from
# the watch entirely while the report still said every pin was current. A pin
# that silently stops being watched is the same false clean this script exists
# to prevent, so the equals form is normalised to the space form up front and
# the parsed count is reconciled against the raw occurrence count below.
#
# A REPLACEMENT IS STRIPPED BEFORE SPLITTING. xcaddy also takes
# `--with module@version=/local/path`. `${arg##*@}` would have taken the text
# after the LAST @, yielding the version `v0.2.4=../local/fork`: OSV cannot
# parse that, and an unparseable version makes OSV abandon range-matching and
# return the module's entire advisory history (see the pseudo-version note
# further down), so a local fork would have produced a spurious ADVISORY and
# an alert issue. The replacement is recorded as a note instead, because
# building a pinned image against a local path is itself worth a human's
# attention.
# ---------------------------------------------------------------------------
pins_file="$OUT_DIR/pins.tsv"
: > "$pins_file"
unpinned_file="$OUT_DIR/unpinned.txt"
: > "$unpinned_file"
replaced_file="$OUT_DIR/replaced.txt"
: > "$replaced_file"

while IFS= read -r raw; do
  # Normalise `--with=X` to `--with X` so one extraction handles both.
  raw="${raw/--with=/--with }"
  arg="${raw#*--with }"
  arg="${arg%% *}"
  arg="${arg%\\}"
  [ -n "$arg" ] || continue
  # `module@version=replacement` — keep the replacement out of the version.
  replacement=""
  case "$arg" in
    *=*) replacement="${arg#*=}"; arg="${arg%%=*}" ;;
  esac
  # Must look like <host-with-a-dot>/<path>; prose words never do.
  printf '%s' "$arg" | grep -qE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^ ]+$' || continue
  [ -n "$replacement" ] && printf '%s\t%s\n' "$arg" "$replacement" >> "$replaced_file"
  case "$arg" in
    *@*) printf '%s\t%s\n' "${arg%@*}" "${arg##*@}" >> "$pins_file" ;;
    *)   printf '%s\n' "$arg" >> "$unpinned_file" ;;
  esac
done < <(grep -v '^[[:space:]]*#' "$DOCKERFILE" | grep -oE -- '--with[= ][^ \\]+' || true)

pin_count="$(wc -l < "$pins_file" | tr -d ' ')"
unpinned_count="$(wc -l < "$unpinned_file" | tr -d ' ')"
# Zero pins AND zero unpinned arguments means the parser found nothing at all,
# which is a format change rather than a finding. Zero pins with unpinned
# arguments present is a real, reportable finding, so it must not die here:
# dying would replace "these --with arguments lost their version" with
# "did its format change?", hiding the exact regression T-0617 was about.
if [ "$pin_count" -eq 0 ] && [ "$unpinned_count" -eq 0 ]; then
  die "parsed no --with pins out of $DOCKERFILE (did its format change?)"
fi

# Reconcile what was parsed against what is actually in the file. The check
# above only catches a parse yielding ZERO pins; this catches a parse that
# drops SOME, which is the more dangerous shape because the report still looks
# complete. Any future --with spelling this parser does not understand becomes
# a loud `error` verdict here rather than a quietly unwatched plugin.
raw_with_count="$(grep -v '^[[:space:]]*#' "$DOCKERFILE" \
  | grep -oE -- '--with[= ][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^ \\]+' | wc -l | tr -d ' ')"
parsed_count=$(( pin_count + unpinned_count ))
if [ "$raw_with_count" != "$parsed_count" ]; then
  die "parsed $parsed_count pin(s) but $DOCKERFILE contains $raw_with_count --with argument(s); an unparsed pin would be silently unwatched"
fi

# ---------------------------------------------------------------------------
# Untagged pins. Keyed by the --with argument so the table can say why a row
# is compared by commit rather than by version. Extend this when a pin changes
# shape; an entry that no longer matches any pin is reported, not ignored, so
# the list cannot rot into a lie.
# ---------------------------------------------------------------------------
untagged_repo() {
  case "$1" in
    github.com/caddy-dns/digitalocean)              echo "https://github.com/caddy-dns/digitalocean.git" ;;
    # caddy-crowdsec-bouncer is back on a tag (v0.15.0), so it is compared by
    # version like any other pin. Re-add it only if it ever needs a raw commit
    # again; while it is tagged, an entry here would be reported as stale.
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

# Every value taken from an HTTP response or from `git` crosses into a TSV
# row, an awk field and finally a Markdown table cell. A tab or newline in
# such a value therefore forges COLUMNS and ROWS, and that is not a cosmetic
# problem -- it was a demonstrated false clean:
#
#   A proxy returning {"Version":"v9.9.9<newline>PINREPORT_EOF<newline>verdict=ok"}
#   split the row so that `kind` landed on a later line. The first row then
#   had too few fields, `kind` read empty, matched no `case` branch, so
#   `behind` was never incremented -- and the script exited 0 with verdict=ok
#   for a pin it had not actually compared. A watcher that reports "every pin
#   is current" because it was deceived is worse than one that fails loudly.
#
#   The same newline also places text at column 0 of the GITHUB_OUTPUT
#   heredoc, which forges arbitrary step outputs, since the delimiter alone on
#   a line ends the block.
#
# So untrusted scalars are sanitised the moment they are read, before they can
# reach a row: control characters are stripped and the value is length-capped.
# Sanitising at the row-write site instead would be one refactor away from a
# new unsanitised path, which is how this class of bug comes back.
clean_scalar() {
  printf '%s' "$1" | tr -d '\000-\037\177' | cut -c1-120
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
# arg \t pinned \t module \t latest \t latest_time \t kind \t osv_version \t note
#
# osv_version is kept separate from `pinned` on purpose: `pinned` is what the
# Dockerfile says and is what a human must read in the report, while
# osv_version is what OSV can actually range-match (see the pseudo-version
# resolution above). An empty osv_version means "no safe value to query", and
# such a row is excluded from the batch rather than queried with a version OSV
# would misinterpret.
#
# FIELD ORDER MATTERS, and the obvious order was wrong. `note` is free text
# and is usually empty; with IFS=$'\t' bash's `read` collapses a run of
# separators rather than preserving an empty field, so with `note` in the
# middle the trailing osv_version shifted into it. Every row then rendered
# "not checked" and a real advisory on x/net v0.40.0 was missed — a silent
# false clean introduced by the very change meant to prevent one. awk counts
# fields correctly, which is why rows.tsv looked right while the report was
# wrong; do not trust a glance at the TSV to prove this path. So `note`, the
# only routinely-empty field, goes LAST.
rows="$OUT_DIR/rows.tsv"
: > "$rows"
errors="$OUT_DIR/errors.txt"
: > "$errors"
# Housekeeping worth a human's attention but which does NOT invalidate the
# run, kept separate from $errors on purpose: $errors means "these numbers
# cannot be trusted" and forces verdict=error, which would bury a real
# staleness finding under a could-not-run warning.
notices="$OUT_DIR/notices.txt"
: > "$notices"

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
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$arg" "$pinned" "${module:-$arg}" "${latest:-unknown}" "-" "tag" "$pinned" "" >> "$rows"
    continue
  fi

  if ! resolved="$(resolve_module "$arg")"; then
    echo "could not resolve any module path for '$arg' on $PROXY" >> "$errors"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$arg" "$pinned" "unresolved" "unknown" "-" "error" "" "proxy returned no module for this path or any parent" >> "$rows"
    continue
  fi
  module="$(clean_scalar "$(printf '%s' "$resolved" | cut -f1)")"
  latest_json="$(printf '%s' "$resolved" | cut -f2-)"
  # Sanitised at the point of read: these come straight from an HTTP body.
  latest="$(clean_scalar "$(jq -r '.Version // "unknown"' <<<"$latest_json" 2>/dev/null || echo unknown)")"
  latest_time="$(clean_scalar "$(jq -r '(.Time // "-") | .[0:10]' <<<"$latest_json" 2>/dev/null || echo -)")"
  # clean_scalar keeps a mangled value from breaking the row, but a value that
  # is not a plausible Go version should not be shown as though it were one:
  # after stripping newlines a hostile body becomes concatenated nonsense, and
  # printing that as "upstream" invites someone to act on it. Anything that is
  # not a version is treated as unknown, which feeds the error verdict.
  if ! printf '%s' "$latest" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z._-]+)?$'; then
    [ "$latest" = "unknown" ] || \
      printf "implausible version %s from %s for %s; treating as unknown\n" \
        "$latest" "$PROXY" "$arg" >> "$errors"
    latest="unknown"
  fi

  # The version sent to OSV is not always the version written in the
  # Dockerfile. OSV only range-matches a version it can PARSE as a Go
  # version; given anything else it abandons matching and returns the
  # module's entire advisory history. Measured on golang.org/x/net:
  #
  #   v0.62.0 (the real pin)                 ->  0
  #   v0.40.0 (a known-vulnerable release)   -> 18
  #   a raw 40-char commit SHA               -> 36
  #   the literal string "not-a-version"     -> 36   (identical to the SHA)
  #   the empty string                       -> 58   (everything, ever)
  #
  # So a bare SHA re-creates exactly the noise that querying WITH a version
  # is meant to eliminate, for the one pin that is a bare SHA. It is masked
  # today only because that module has no advisories at all; its first
  # advisory would make the row fire unconditionally, whether or not the
  # pinned commit is affected, and an always-firing urgent alert is an
  # ignored one.
  #
  # The module proxy will convert a commit into the canonical pseudo-version
  # (`@v/<sha>.info` -> v0.14.2-0.20260904125551-bdd7e516ec46), which OSV
  # does parse. If that conversion fails there is no safe version to send, so
  # the row is marked advisory-unknown rather than queried with a value OSV
  # will misread.
  osv_version="$pinned"
  if is_untagged_pin "$pinned" && [ "${pinned#v0.0.0-}" = "$pinned" ] \
     && [ "${pinned#*-0.}" = "$pinned" ]; then
    pv="$(clean_scalar "$(proxy_get "$module" "@v/${pinned}.info" | jq -r '.Version // ""' 2>/dev/null || true)")"
    if [ -n "$pv" ]; then
      osv_version="$pv"
    else
      osv_version=""   # no safe value; excluded from the batch below
      echo "could not resolve commit '$pinned' of '$module' to a pseudo-version; advisory status is UNKNOWN for this pin" >> "$errors"
    fi
  fi

  note=""
  kind="tag"
  repo="$(untagged_repo "$arg")"
  # The allowlist says WHERE to look for a commit pin's upstream, not THAT this
  # pin is one. Only the pin's own shape decides that. A module can return to a
  # tag -- the CrowdSec bouncer did, in v0.15.0 -- and treating a tag as a
  # commit would compare it against upstream HEAD forever, reporting a current,
  # tagged pin as "no longer at upstream HEAD". A leftover entry is surfaced as
  # a housekeeping notice rather than silently forcing commit mode, so the list
  # cannot rot. It is a notice and not an error on purpose: the pin is still
  # resolved and compared correctly, so the run stays authoritative.
  if [ -n "$repo" ] && ! is_untagged_pin "$pinned"; then
    echo "\`$arg\` is in the untagged-pin allowlist but is pinned to \`$pinned\`, which is a tag; drop it from untagged_repo()" >> "$notices"
    repo=""
  fi
  if is_untagged_pin "$pinned"; then
    kind="commit"
    if [ -z "$repo" ]; then
      repo="$(jq -r '.Origin.URL // ""' <<<"$latest_json" 2>/dev/null || true)"
      [ -n "$repo" ] && repo="${repo}.git"
    fi
    head=""
    # This URL can come from UPSTREAM JSON (.Origin.URL), so it is untrusted
    # input on its way to a git invocation. Two concrete attacks, both tested
    # on this host:
    #
    #   - Option injection. A value starting with `-` is parsed as a git
    #     option, not a URL: `git ls-remote --upload-pack=touch /tmp/x origin`
    #     really does run `touch`. Confirmed working, so this is not
    #     hypothetical.
    #   - Transport abuse. `ext::sh -c <cmd>` makes git run a command as its
    #     transport. Current git refuses it ("transport 'ext' not allowed"),
    #     but that is a default rather than a guarantee, and `--` does not
    #     help, because the string is a URL and not an option.
    #
    # So the URL is allowlisted rather than escaped: it must be a plain https
    # URL with an ordinary path. `--` additionally ends option parsing, which
    # alone would stop the first attack but not the second. Credential prompts
    # are disabled so a hostile host cannot hang the job waiting on stdin.
    if [ -n "$repo" ] \
       && printf '%s' "$repo" | grep -qE '^https://[a-zA-Z0-9._-]+(/[A-Za-z0-9._-]+)+$' \
       && command -v git >/dev/null 2>&1; then
      head="$(clean_scalar "$(GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/true \
              git ls-remote -- "$repo" HEAD 2>/dev/null | awk 'NR==1{print $1}')")"
    elif [ -n "$repo" ]; then
      echo "refused a malformed or non-https repo URL for '$arg': $repo" >> "$errors"
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

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$arg" "$pinned" "$module" "$latest" "$latest_time" "$kind" "$osv_version" "$note" >> "$rows"
done < "$pins_file"

# ---------------------------------------------------------------------------
# Pass 2 — the bouncer's standing question: does a TAG now support the
# CrowdSec major this image needs? The Dockerfile pins a raw commit only
# because no tag did, and says in so many words to return to a tag once one
# exists. Checking that mechanically is the difference between a watcher and
# a reminder.
# ---------------------------------------------------------------------------
tag_now_ok=""
b_pinned_now="$(awk -F'\t' '$1 ~ /caddy-crowdsec-bouncer/ {print $2}' "$pins_file" | head -1)"
if [ -z "$FIXTURE" ] && [ -n "$b_pinned_now" ] && is_untagged_pin "$b_pinned_now"; then
  cs_floor="$(awk -F'\t' '$1 ~ /crowdsecurity\/crowdsec/ {print $2}' "$pins_file" | head -1)"
  cs_major="$(printf '%s' "${cs_floor#v}" | cut -d. -f1-2)"
  b_mod="github.com/hslatman/caddy-crowdsec-bouncer"
  b_latest="$(clean_scalar "$(proxy_get "$b_mod" '@latest' | jq -r '.Version // ""' 2>/dev/null || true)")"
  if [ -n "$b_latest" ]; then
    b_cs="$(clean_scalar "$(proxy_get "$b_mod" "@v/${b_latest}.mod" \
      | awk '/crowdsecurity\/crowdsec /{print $2; exit}' 2>/dev/null || true)")"
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
  # $8 (osv_version), not $2 (pinned): see the rows.tsv comment. A row with an
  # empty $8 is deliberately left out of the batch — querying it would return
  # the module's whole advisory history and read as an urgent finding.
  q="$(awk -F'\t' '$3 != "unresolved" && $3 != "" && $7 != "" {printf "%s\t%s\n", $3, $7}' "$rows" \
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
  # The response SHAPE is validated before it is trusted, because `paste` fails
  # silently in the dangerous direction. A 200 whose body lacks `.results` --
  # an API change, an error object, a captive portal or proxy page -- makes
  # `.results[]?` emit nothing; paste then leaves the advisory column empty for
  # every row, osv_failed stays 0, and the run reports no advisories for pins
  # it never checked. Confirmed against a body of `{"unexpected":true}`.
  #
  # OSV returns results 1:1 with queries (an empty `{}` per clean pin), so a
  # count mismatch means the mapping cannot be trusted and the whole batch is
  # discarded rather than partially believed.
  n_q="$(jq -r '.queries | length' "$OUT_DIR/osv-query.json" 2>/dev/null || echo 0)"
  n_r="$(jq -r 'if has("results") and (.results | type) == "array" then (.results | length) else -1 end' \
          "$osv_out" 2>/dev/null || echo -1)"
  if [ "$n_r" = "-1" ]; then
    osv_failed=1
    echo "OSV returned a body with no results array; advisory status is UNKNOWN for this run" >> "$errors"
  elif [ "$n_q" != "$n_r" ]; then
    osv_failed=1
    echo "OSV returned $n_r results for $n_q queries; refusing to map them, advisory status is UNKNOWN" >> "$errors"
  else
    paste <(jq -r '.queries[] | "\(.package.name)\t\(.version)"' "$OUT_DIR/osv-query.json") \
          <(jq -r '.results[] | [ (.vulns // [])[].id ] | join(",")' "$osv_out") \
      > "$osv_hits" 2>/dev/null || { osv_failed=1; : > "$osv_hits"; }
    # One line per query, or the row-to-advisory mapping is off by something.
    got="$(wc -l < "$osv_hits" | tr -d ' ')"
    if [ "$got" != "$n_q" ]; then
      osv_failed=1
      : > "$osv_hits"
      echo "OSV mapping produced $got rows for $n_q queries; advisory status is UNKNOWN" >> "$errors"
    fi
  fi
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

malformed_rows=0
while IFS=$'\t' read -r arg pinned module latest latest_time kind osv_version note; do
  # Defence in depth behind clean_scalar. If a row is ever short of fields,
  # `kind` reads empty, matches no `case` branch below, and the pin is
  # silently never compared -- which is how a deceived run produced
  # verdict=ok. Count it as a failure rather than letting it pass quietly.
  case "$kind" in
    tag|commit|commit-unknown|error) ;;
    *)
      malformed_rows=$((malformed_rows+1))
      echo "malformed row for '${arg:-?}' (kind='${kind:-}'); this pin was NOT compared" >> "$errors"
      continue ;;
  esac
  adv=""
  if [ -s "$osv_hits" ] && [ -n "$osv_version" ]; then
    # The advisory list is the LAST field of the table printf, so a newline
    # here would reach column 0 and could end the GITHUB_OUTPUT heredoc.
    # Sanitised even though OSV ids are observed to be [A-Za-z0-9-] only:
    # that is an observation about today's data, not an enforced contract.
    adv="$(clean_scalar "$(awk -F'\t' -v m="$module" -v v="$osv_version" '$1==m && $2==v {print $3; exit}' "$osv_hits")")"
  fi
  state="ok"
  case "$kind" in
    error)           state="unresolved"; unresolved=$((unresolved+1)) ;;
    commit-unknown)  state="unknown" ;;
    commit)
      case "$latest" in commit:*) state="moved"; moved=$((moved+1)) ;; esac ;;
    tag)
      # An unresolved upstream version is NOT a pass. The staleness compare
      # below is guarded on `!= unknown`, and for a long time that guard was
      # the whole story: a pin whose version could not be established skipped
      # the comparison, scored `ok`, and printed under "Every pin is at
      # upstream's newest release" with exit 0 — the same false clean as a
      # proxy outage, but silent because nothing was recorded. The implausible
      # -version branch upstream records an error, so the remaining route here
      # is a 200 whose body simply has no .Version field. Counted as
      # unresolved so it reaches the `error` verdict.
      if [ "$latest" = "unknown" ]; then
        state="unresolved"; unresolved=$((unresolved+1))
        echo "no upstream version could be established for '$arg'" >> "$errors"
      elif [ "$pinned" != "$latest" ]; then
        # `sort -V` gets v1.9.0 < v1.10.0 right, which a string compare does
        # not, and correctly declines to flag a pin that is AHEAD of @latest.
        # It does get semver prereleases backwards — it ranks v1.0.0-rc1 above
        # v1.0.0, so a stable pin would be reported "behind" its own release
        # candidate. proxy.golang.org's @latest excludes prereleases, so this
        # cannot arise from upstream today; it is guarded anyway because the
        # failure is a weekly false alarm, which is how a report gets ignored.
        case "$latest" in
          *-*) ;;   # a prerelease is never grounds for "behind"
          *)
            newest="$(printf '%s\n%s\n' "$pinned" "$latest" | sort -V | tail -1)"
            [ "$newest" = "$latest" ] && { state="behind"; behind=$((behind+1)); } ;;
        esac
      fi ;;
  esac
  if [ -n "$adv" ]; then
    advisories=$((advisories+1))
    state="ADVISORY"
  fi

  up="$latest"
  [ "$latest_time" != "-" ] && [ "$state" = "behind" ] && up="$latest (tagged $latest_time)"
  [ -n "$note" ] && up="$up — $note"

  # An em dash in the advisory column must mean "OSV was asked about this
  # exact version and said no". Where no version could be sent, say so: a
  # dash there would be a clean-looking cell for a pin that was never checked.
  if [ "$osv_failed" -eq 1 ]; then
    adv_cell="**not checked**"
  elif [ -z "$osv_version" ]; then
    adv_cell="**not checked**"
  else
    adv_cell="${adv:-—}"
  fi
  printf '| `%s` | `%s` | %s | %s |\n' \
    "$arg" "$pinned" "$up" "$adv_cell" >> "$report"
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
  if [ -s "$replaced_file" ]; then
    echo "**A \`--with\` argument uses a local replacement.** The published module is not what gets built, so the version compared above and the advisory lookup describe upstream, not the code in the image:"
    while IFS=$'\t' read -r rp_arg rp_to; do
      echo "- \`$rp_arg\` → \`$rp_to\`"
    done < "$replaced_file"
    echo
  fi
  if [ -s "$notices" ]; then
    echo "**Housekeeping** (the comparisons above are unaffected):"
    while IFS= read -r n; do echo "- $n"; done < "$notices"
    echo
  fi
  if [ -s "$errors" ]; then
    echo "**The check could not complete for every pin.** An unchecked pin is not a clean pin:"
    while IFS= read -r e; do echo "- $e"; done < "$errors"
    echo
  fi
  if [ "$advisories" -eq 0 ] && [ "$behind" -eq 0 ] && [ "$moved" -eq 0 ] \
     && [ "$malformed_rows" -eq 0 ] \
     && [ ! -s "$errors" ] && [ ! -s "$unpinned_file" ] \
     && [ ! -s "$replaced_file" ] && [ -z "$tag_now_ok" ]; then
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
# recorded error yields `error` even when real staleness was also found — the
# findings still appear in the report, under a verdict
# that says the run is not authoritative.
# `-s "$errors"` is the backstop and is deliberately broader than the
# counters beside it. Twice now a new failure path wrote a line to $errors and
# forgot to increment a counter, and both times the run reported verdict=ok
# with the error sitting in the report — a hostile proxy response reduced to a
# footnote under an all-clear. Anything that records an error now forces
# `error`, including a path added later that this list does not know about.
if   [ "$advisories" -gt 0 ]; then verdict="advisory"; rc=2
elif [ "$unresolved" -gt 0 ] || [ "$osv_failed" -eq 1 ] \
  || [ "$malformed_rows" -gt 0 ] || [ -s "$errors" ]; then verdict="error"; rc=3
elif [ "$behind" -gt 0 ] || [ "$moved" -gt 0 ] || [ -n "$tag_now_ok" ] \
  || [ -s "$unpinned_file" ] || [ -s "$replaced_file" ] \
  || [ -s "$notices" ]; then verdict="attention"; rc=1
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
    echo "report<<$PINREPORT_DELIM"
    cat "$report"
    echo "$PINREPORT_DELIM"
  } >> "$GITHUB_OUTPUT"
fi
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$report" >> "$GITHUB_STEP_SUMMARY"

exit "$rc"
