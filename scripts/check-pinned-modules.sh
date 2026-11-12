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
#
# 4. THE PACKAGE+VERSION QUERY CANNOT SEE A WHOLE CLASS OF ADVISORY, so on its
#    own it is a detector that reports clean where it is structurally blind.
#    Trap 3 above is still true and still necessary — it is about NOISE. This
#    is the opposite failure, and it is the worse one.
#
#    OSV ingests CVEs that never got a curated Go advisory through the
#    `cve-osv-conversion` pipeline. Those records carry NO `package` field at
#    all: the affected range is a `GIT` range keyed on the repo URL, with the
#    semver equivalent buried in `database_specific.extracted_events`. OSV's
#    package-scoped query index has nothing to match on, so such a record is
#    invisible to a package+version query and reachable only by its ID.
#
#    Measured on the chi pin this image actually shipped (T-0634):
#
#      {"package":"github.com/go-chi/chi/v5","version":"v5.4.0"}  -> {}
#      {"package":"github.com/go-chi/chi/v5"} (no version)        -> {}
#      {"commit":"7f9b7448f51d..."} (v5.4.0's upstream commit)     -> 2 CVEs
#
#    CVE-2026-118681 (auth bypass, fixed 5.5.0) and CVE-2026-122132 (open
#    redirect, 5.2.2 through 5.5.0) BOTH affected the pinned version, and the
#    package query returned clean for both. T-0626 published a table saying
#    "advisory on pin? none" for chi on the strength of that query.
#
#    So the pinned version is ALSO resolved to its upstream commit and queried
#    by `{"commit": ...}`, which matches GIT ranges directly, and the two
#    result sets are unioned. The commit comes from the module proxy's
#    `.info` endpoint (`Origin.Hash`) and is available for a plain tag, a
#    pseudo-version and a bare SHA alike, so every pin gets both questions.
#
#    The commit query does NOT re-introduce trap 3's noise: it is matched
#    against GIT ranges containing that specific commit, not against the
#    module's history. Verified on golang.org/x/net, which has 18 historical
#    advisories and returns 0 for its pinned commit.
#
#    Both questions go in the SAME querybatch. Verified that /v1/querybatch
#    accepts commit and package queries mixed in one request and returns
#    results 1:1 in query order, so the existing count-reconciliation below
#    still holds.
#
#    A pin for which NEITHER question could be asked must not render like a
#    pin that was asked and came back clean — see `adv_cell` near the end.
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
      # Not 0: nothing was established about any pin, and a 0 here would read
      # as "no pin had an unknown advisory status" — the same false clean the
      # verdict above is guarding against.
      echo "advisory_unknown=unknown"
      echo "advisory_partial=unknown"
      echo "github_only=unknown"
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
  # A TAB between `--with` and its argument is legal in a Dockerfile RUN line
  # and the extraction below splits on spaces, so tabs are normalised first.
  raw="${raw//$'\t'/ }"
  # Normalise `--with=X` to `--with X` so one extraction handles both, then
  # collapse a run of separators so `--with=  X` and `--with   X` reduce to
  # the same single-space form the extraction below expects.
  raw="${raw/--with=/--with }"
  while case "$raw" in *'--with  '*) true ;; *) false ;; esac; do
    raw="${raw/--with  /--with }"
  done
  arg="${raw#*--with }"
  arg="${arg%% *}"
  arg="${arg%\\}"
  # QUOTES ARE STRIPPED, because the shell strips them before xcaddy sees
  # argv and therefore `--with="mod@ver"` is a perfectly valid, building pin:
  #
  #   $ bash -c 'set -- --with="github.com/go-chi/chi/v5@v5.4.0"; echo "$1"'
  #   --with=github.com/go-chi/chi/v5@v5.4.0
  #
  # Left in place, the leading quote made `arg` fail the package-path test
  # below, so the pin was dropped from pins.tsv AND from unpinned.txt — the
  # plugin vanished from the watch while the report still said every pin was
  # current. Worse, it also evaded the reconciliation that exists to catch
  # exactly that: the quote is not in `raw_with_count`'s character class, so
  # BOTH counters lost the same argument and agreed. Quoting the CrowdSec CVE
  # floor in the real Dockerfile reproduced it end to end — a one-character
  # PR diff that reads as adding quotes to a string, with no error, no
  # warning, and the floor still shipping in the binary.
  arg="${arg%\"}"; arg="${arg#\"}"
  arg="${arg%\'}"; arg="${arg#\'}"
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
# `[=[:space:]]+` rather than a single separator character: `--with=  arg`
# and `--with<TAB>arg` are both legal and both build, and matching only one
# separator left them unparsed. They now fail loudly thanks to the token
# counter above rather than vanishing silently, but failing a legitimate
# reformat is still a weekly false alarm, so they are parsed properly.
done < <(grep -v '^[[:space:]]*#' "$DOCKERFILE" \
  | grep -oE -- '--with[=[:space:]]+[^ \\]+' || true)

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
# Counted as TOKENS, not as well-formed arguments. The obvious form — reusing
# the same strict package-path pattern the parser uses — cannot do this job,
# because any argument the parser cannot read is also invisible to the
# counter, so both sides lose it together and the comparison passes. That is
# not a theoretical weakness: it is how a quoted `--with` removed a pin from
# the watch silently (see the quote-stripping note above), and the same held
# for a tab separator and for two spaces. Counting every `--with` occurrence
# instead means an argument this parser does not understand is a loud `error`
# rather than an unwatched plugin, which is the whole point of the check.
raw_with_count="$(grep -v '^[[:space:]]*#' "$DOCKERFILE" \
  | grep -oE -- '(^|[[:space:]])--with([=[:space:]]|$)' | wc -l | tr -d ' ')"
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
# arg \t pinned \t module \t latest \t latest_time \t kind \t osv_version \t osv_commit \t note
#
# osv_commit is the upstream commit the pinned version was cut from, used for
# the GIT-range query (trap 4). It is independent of osv_version: a pin can be
# queryable by one and not the other, and the advisory column must only read
# as clean when AT LEAST ONE question was actually asked.
#
# THE ROW IS READ WITH A FIELD-COUNT ASSERTION, NOT BY FIELD POSITION. The
# note below says `note` goes last because `IFS=$'\t' read` collapses a run of
# separators rather than preserving an empty field. Adding osv_commit created a
# SECOND routinely-empty field, and `note` being last stopped protecting
# anything: for a commit pin whose upstream HEAD could not be read,
# osv_commit is empty while note is set, so the note text slid into
# osv_commit, `asked` reached 2, the advisory lookup found nothing, and the
# cell rendered the clean em dash reserved for "both questions asked and
# clean" — a false clean of exactly the kind this script exists to prevent,
# introduced by the change that was meant to remove one. Reproduced before
# fixing.
#
# Position-based reading cannot be made safe by ordering alone once more than
# one field can be empty, so the rows are now split by awk (which counts
# fields correctly) into a NUL-delimited stream with an explicit NF check, and
# a row of the wrong width becomes a malformed row rather than a shifted one.
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

# awk emits, per row, the field count and then EACH FIELD individually, every
# item NUL-terminated. The consumers `mapfile -d ''` that stream, so an empty
# field occupies its own slot and nothing shifts.
#
# Note that `IFS=$'\t' read -r -a` does NOT solve this: word splitting
# collapses a run of separators there exactly as it does for scalar `read`, so
# an array read reproduced the same left-shift. Verified both ways before
# settling on a per-field NUL stream, which is the only form that preserves an
# empty field positionally.
row_reader() {
  awk -F'\t' '{ printf "%d%c", NF, 0; for (i = 1; i <= NF; i++) printf "%s%c", $i, 0 }' "$1"
}
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
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$arg" "$pinned" "${module:-$arg}" "${latest:-unknown}" "-" "tag" "$pinned" "" "" >> "$rows"
    continue
  fi

  if ! resolved="$(resolve_module "$arg")"; then
    echo "could not resolve any module path for '$arg' on $PROXY" >> "$errors"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$arg" "$pinned" "unresolved" "unknown" "-" "error" "" "" "proxy returned no module for this path or any parent" >> "$rows"
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
  # One `.info` fetch answers both questions, so it is done once here. The
  # endpoint returns the canonical version AND `Origin.Hash`, the upstream
  # commit the version was cut from.
  info_json="$(proxy_get "$module" "@v/${pinned}.info" 2>/dev/null || true)"

  osv_version="$pinned"
  if is_untagged_pin "$pinned" && [ "${pinned#v0.0.0-}" = "$pinned" ] \
     && [ "${pinned#*-0.}" = "$pinned" ]; then
    pv="$(clean_scalar "$(jq -r '.Version // ""' <<<"$info_json" 2>/dev/null || true)")"
    if [ -n "$pv" ]; then
      osv_version="$pv"
    else
      osv_version=""   # no safe value; excluded from the batch below
      echo "could not resolve commit '$pinned' of '$module' to a pseudo-version; the version-scoped advisory query was not possible for this pin" >> "$errors"
    fi
  fi

  # The commit for the GIT-range query (trap 4). Validated as a full 40-char
  # hex SHA before use: it is untrusted HTTP body text on its way into a JSON
  # request body, and a non-SHA value there would at best waste the query and
  # at worst be a value OSV misinterprets the way it misinterprets a
  # non-version. A short or malformed hash is treated as "no commit to ask
  # about", which feeds the unknown rendering rather than a clean dash.
  osv_commit="$(clean_scalar "$(jq -r '.Origin.Hash // ""' <<<"$info_json" 2>/dev/null || true)")"
  if [ -n "$osv_commit" ] \
     && ! printf '%s' "$osv_commit" | grep -qE '^[0-9a-f]{40}$'; then
    echo "implausible commit hash '$osv_commit' from $PROXY for '$arg'; the GIT-range advisory query was not possible for this pin" >> "$errors"
    osv_commit=""
  fi
  if [ -z "$osv_commit" ]; then
    echo "could not resolve '$pinned' of '$module' to an upstream commit; the GIT-range advisory query (which is the only one that sees package-less CVE records) was not possible for this pin" >> "$errors"
  fi

  note=""
  kind="tag"
  repo="$(untagged_repo "$arg")"
  if is_untagged_pin "$pinned" || [ -n "$repo" ]; then
    kind="commit"
    if [ -z "$repo" ]; then
      # clean_scalar even though the value is allowlisted below: this is the
      # one upstream scalar that used to skip it, and on the REJECTION path it
      # is echoed into $errors, so a newline in it injected attacker-chosen
      # lines into the report. That was contained only because the error
      # renderer re-prefixes every line with `- ` and because $errors is
      # tested with `-s` (which forces `error`, i.e. away from a clean
      # verdict) — both incidental properties of today's code, which is
      # precisely the condition this file's header says re-opens the bug
      # class. Sanitised at the point of read, like every other scalar.
      repo="$(clean_scalar "$(jq -r '.Origin.URL // ""' <<<"$latest_json" 2>/dev/null || true)")"
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

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$arg" "$pinned" "$module" "$latest" "$latest_time" "$kind" "$osv_version" "$osv_commit" "$note" >> "$rows"
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
# Pass 3 — OSV, one batch, TWO questions per pin.
#
# The package+version question (trap 3) and the commit question (trap 4) are
# both asked, in the same batch, and their results are unioned per pin. Asking
# only the first is the blindness T-0634 is about; asking only the second
# would lose the curated Go advisories that have a proper package range.
#
# The keys are kept disjoint so the mapping back onto rows cannot collide:
# a version query is keyed `v<TAB>module<TAB>version`, a commit query
# `c<TAB>commit<TAB>-`. Two pins sharing a commit (same repo, different
# module paths) is legal and both rows then read the same answer, which is
# correct.
# ---------------------------------------------------------------------------
osv_out="$OUT_DIR/osv.json"
echo '{}' > "$osv_out"
osv_failed=0

if [ -z "$FIXTURE" ]; then
  # $7 (osv_version) and $8 (osv_commit), not $2 (pinned): see the rows.tsv
  # comment. A row with an empty $7 is deliberately left out of the version
  # queries — querying it would return the module's whole advisory history and
  # read as an urgent finding. A row with an empty $8 is left out of the commit
  # queries because there is no commit to ask about. A row left out of BOTH was
  # never asked at all and must not render as clean; that is enforced at
  # `adv_cell`.
  q="$( { awk -F'\t' '$3 != "unresolved" && $3 != "" && $7 != "" {printf "v\t%s\t%s\n", $3, $7}' "$rows"
         awk -F'\t' '$8 != "" {printf "c\t%s\t-\n", $8}' "$rows" ; } \
      | sort -u \
      | jq -R -s -c '{queries: [ split("\n")[] | select(length>0) | split("\t")
          | if .[0] == "c"
            then {commit: .[1]}
            else {package: {name: .[1], ecosystem: "Go"}, version: .[2]}
            end ]}')"
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
    # The key must be reconstructed in the SAME disjoint form the query was
    # built in, or a commit answer could be read as a version answer. `jq`
    # emits the discriminator from the query's own shape rather than from a
    # remembered order, so the two cannot drift apart.
    paste <(jq -r '.queries[] | if has("commit") then "c\t\(.commit)\t-"
                                else "v\t\(.package.name)\t\(.version)" end' \
              "$OUT_DIR/osv-query.json") \
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
# Pass 4 — GitHub's advisory database, as an INDEPENDENT cross-check.
#
# This is a second opinion from a different index, not a replacement for OSV.
# GitHub keys advisories on the REPOSITORY, so it sees records whose Go module
# path is absent or wrong — the same class OSV's package query misses. On the
# chi case it lists GHSA-rqrp-8cg2-5958 with a proper `<=5.4.0` range, which
# OSV's package index does not have at all.
#
# Deliberately advisory-only, never authoritative, for three reasons:
#
#  - The ranges are human-written free text. Real values observed on one repo
#    include `<=5.4.0`, `<= 5.3.2`, `>= 5.2.1`, `>=5.2.2` and `v5.2.1`, with
#    the package named variously `github.com/go-chi/chi/v5`,
#    `https://github.com/go-chi/chi `, `go-chi/chi` and `chi`. Writing a
#    comparator for that is writing a parser for prose, and a wrong parse here
#    would either invent an advisory or excuse one.
#  - Unauthenticated calls are rate-limited to 60/hour per IP, so on a busy
#    runner this will sometimes return nothing for reasons that have nothing
#    to do with the pin.
#  - The GLOBAL `/advisories/{ghsa}` endpoint returns a body with every field
#    null when unauthenticated, which is why the repo-scoped endpoint is used
#    instead. A script that read the global endpoint would conclude "no
#    advisory" from a successful-looking 200.
#
# So a GitHub hit that OSV did not report is surfaced for a human to judge
# and reaches `attention`; it never sets `advisory` on its own, and a GitHub
# failure never downgrades an OSV finding. GH_TOKEN/GITHUB_TOKEN is used when
# present purely for rate limits.
# ---------------------------------------------------------------------------
gh_extra="$OUT_DIR/gh-extra.tsv"
: > "$gh_extra"
gh_checked=0
gh_unavailable=""

# The skip switch is a local/test escape hatch and is set by no workflow, but
# it must not be able to produce a report that CLAIMS the cross-check ran. It
# routes through the same `gh_unavailable` path as a rate limit, so the
# all-clear sentence cannot print and the verdict reaches `attention`.
if [ -z "$FIXTURE" ] && [ "${PINWATCH_SKIP_GITHUB:-0}" = "1" ]; then
  gh_unavailable="the GitHub advisory cross-check was disabled via PINWATCH_SKIP_GITHUB, so no second index was consulted"
fi

if [ -z "$FIXTURE" ] && [ "${PINWATCH_SKIP_GITHUB:-0}" != "1" ]; then
  gh_auth=()
  gh_tok="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  [ -n "$gh_tok" ] && gh_auth=(-H "Authorization: Bearer $gh_tok")

  # Only github.com modules have a repo-scoped endpoint to ask. The owner/repo
  # is taken from the MODULE path (already proxy-verified) and must match a
  # strict pattern before it reaches a URL.
  while IFS=$'\t' read -r g_module g_pinned g_adv; do
    [ -n "$g_module" ] || continue
    case "$g_module" in github.com/*/*) ;; *) continue ;; esac
    g_owner="$(printf '%s' "$g_module" | cut -d/ -f2)"
    g_repo="$(printf '%s' "$g_module" | cut -d/ -f3)"
    # `.` is in the character class, so the pattern alone accepts `../r` and
    # `../..`. Not reachable from a network response today — the module path
    # comes from resolve_module walking the Dockerfile argument, so forging it
    # needs commit access, and curl normalises the traversal server-side while
    # the scheme and host are literal with no -L anywhere — but a path
    # component that can climb has no business reaching a URL regardless.
    printf '%s' "$g_owner/$g_repo" | grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || continue
    case "$g_owner/$g_repo" in *..*) continue ;; esac

    g_body="$(curl -fsS --max-time 25 \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      "${gh_auth[@]+"${gh_auth[@]}"}" \
      "https://api.github.com/repos/$g_owner/$g_repo/security-advisories" 2>/dev/null || true)"
    # An array is the only shape that means "this is the advisory list". A
    # rate-limit or error object is a JSON object, and treating it as an empty
    # list would read as "no advisories" — the exact inversion this script
    # exists to prevent.
    if [ -z "$g_body" ] || ! jq -e 'type == "array"' <<<"$g_body" >/dev/null 2>&1; then
      [ -z "$gh_unavailable" ] && gh_unavailable="GitHub's advisory API did not return a list (rate limit, or no token); the cross-check did not run for every module"
      continue
    fi
    gh_checked=$((gh_checked+1))

    # Report only GHSA ids OSV did not already give us for this pin, by GHSA
    # id and by CVE alias — OSV returns CVE ids for the converted records, so
    # comparing GHSA-to-GHSA alone would re-report the chi finding as new.
    # Fields are read with `read -d` on a NUL-delimited record and split on a
    # literal marker rather than by IFS, because `IFS=$'\t' read` COLLAPSES a
    # run of separators instead of preserving an empty field — the same trap
    # documented for `note` in rows.tsv. `cve_id` is routinely null here, so
    # with tab-splitting the severity and range columns shifted left by one
    # and the table printed a version range under "severity". Observed, not
    # theoretical.
    while IFS= read -r -d '' g_rec; do
      # A record with no marker would leave every ${var#*} unchanged, so the
      # GHSA id would echo into the severity and range cells — visible
      # nonsense in a table a human is asked to judge. Skipped rather than
      # rendered; it cannot hide a finding, because a record this malformed
      # carried no usable advisory in the first place.
      case "$g_rec" in **) ;; *) continue ;; esac
      g_ghsa="${g_rec%%*}";  g_rest="${g_rec#*}"
      g_cve="${g_rest%%*}";  g_rest="${g_rest#*}"
      g_sev="${g_rest%%*}";  g_range="${g_rest#*}"
      [ -n "$g_ghsa" ] || continue

      # Already reported by OSV for this pin? Compare on the GHSA id and on
      # the CVE alias: OSV returns CVE ids for the cve-osv-conversion records,
      # so a GHSA-only comparison would re-report the very finding OSV just
      # gave us as though GitHub had found something extra.
      case ",$g_adv," in *",$g_ghsa,"*) continue ;; esac
      if [ -n "$g_cve" ]; then
        case ",$g_adv," in *",$g_cve,"*) continue ;; esac
      fi

      # Drop advisories that are plainly OLDER than the pin. GitHub's range is
      # free text, so this is a conservative TEXTUAL filter, not a comparator:
      # it only discards a range whose upper bound sorts strictly below the
      # pinned version. Anything it cannot confidently place is KEPT, because
      # the failure to understand a range must not look like the absence of an
      # advisory — a dropped row is invisible, and this is the one place in
      # this script where being wrong produces a false CLEAN.
      #
      # Without any filter the cross-check reported 12 "GitHub-only" findings
      # for this Dockerfile, mostly advisories fixed long before the pinned
      # release — exactly the history noise trap 3 above exists to keep out of
      # this report, re-entering through the second index.
      #
      # THE BOUND IS THE HIGHEST ONE IN THE STRING, NOT THE LAST. An earlier
      # version used `tail -1`, which takes the textually last `<=` match, and
      # that is a false-clean generator on three observed-plausible shapes:
      #
      #   "<= 1.7.8, <= 1.0.0"             pin 1.7.8 -> dropped on 1.0.0
      #   "affects <= 9.9.9 and <= 1.0.0"  pin 5.4.0 -> dropped on 1.0.0
      #
      # A range listing several bounds is legal free text, and an attacker who
      # controls GitHub's response (or simply a sloppy advisory author) could
      # append a low bound to hide a real finding. Taking the maximum means an
      # extra bound can only ever make the row MORE likely to be kept.
      #
      # It is also compared with the pin ZERO-PADDED to the same number of
      # components. `sort -V` ranks "5.4" below "5.4.0", so a truncated bound
      # of `<= 5.4` dropped a row whose pin was exactly v5.4.0 — the advisory
      # covers the pin and the filter hid it. Padding makes "5.4" compare as
      # "5.4.0", so equality is seen and the row is kept.
      g_hi="$(printf '%s' "$g_range" | grep -oiE '<=?[[:space:]]*v?[0-9]+(\.[0-9]+)*' \
              | grep -oE '[0-9]+(\.[0-9]+)*' | sort -V | tail -1 || true)"
      if [ -n "$g_hi" ] && ! printf '%s' "$g_range" | grep -qE '^[[:space:]]*(>|>=)' ; then
        g_pin_n="${g_pinned#v}"
        case "$g_pin_n" in
          *[!0-9.]*) ;;   # pseudo-version or SHA: cannot compare, keep
          *)
            # Pad the SHORTER of the two with .0 components so that a
            # truncated bound compares as the release it names.
            g_cmp_pin="$g_pin_n"; g_cmp_hi="$g_hi"
            while [ "$(printf '%s' "$g_cmp_hi" | tr -cd '.' | wc -c)" \
                 -lt "$(printf '%s' "$g_cmp_pin" | tr -cd '.' | wc -c)" ]; do
              g_cmp_hi="$g_cmp_hi.0"
            done
            while [ "$(printf '%s' "$g_cmp_pin" | tr -cd '.' | wc -c)" \
                 -lt "$(printf '%s' "$g_cmp_hi" | tr -cd '.' | wc -c)" ]; do
              g_cmp_pin="$g_cmp_pin.0"
            done
            if [ "$(printf '%s\n%s\n' "$g_cmp_pin" "$g_cmp_hi" | sort -V | tail -1)" = "$g_cmp_pin" ] \
               && [ "$g_cmp_pin" != "$g_cmp_hi" ]; then
              continue   # upper bound is strictly below the pin
            fi ;;
        esac
      fi

      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$g_module" "$g_pinned" "$(clean_scalar "$g_ghsa")" \
        "$(clean_scalar "${g_sev:-?}")" "$(clean_scalar "${g_range:-?}")" >> "$gh_extra"
    done < <(jq -j --arg mod "$g_module" '
      .[]
      | . as $a
      | (.vulnerabilities // [])[]
      # Keep only entries whose package plausibly names this module or its
      # repo; the field is free text (values seen on one repo include the full
      # module path, a bare repo URL with a trailing space, `owner/repo` and
      # just `repo`), so matching is intentionally loose and the result is
      # only ever a pointer for a human.
      | select((.package.name // "") | ascii_downcase
               | (test($mod | ascii_downcase | split("/") | .[2] | gsub("\\."; "\\\\."))
                  or test($mod | ascii_downcase | gsub("\\."; "\\\\."))))
      | [ ($a.ghsa_id // ""), ($a.cve_id // ""), ($a.severity // ""),
          (.vulnerable_version_range // "") ]
      | join("\u001f") + "\u0000"' <<<"$g_body" 2>/dev/null)
  done < <(
    # module \t pinned \t the OSV ids already found for this pin, so the
    # de-duplication above compares against what OSV actually said rather
    # than against an empty string (which would re-report every OSV hit as
    # a GitHub-only finding).
    # Same field-count discipline as the report loop below: an empty
    # osv_version or osv_commit must not shift the remaining fields.
    mapfile -d '' -t r_toks < <(row_reader "$rows")
    r_i=0
    while [ "$r_i" -lt "${#r_toks[@]}" ]; do
      # Same field-count discipline as the report loop: an empty osv_version
      # or osv_commit must not shift the remaining fields.
      [ "${r_toks[$r_i]}" = "9" ] || break
      r_f=( "${r_toks[@]:$((r_i+1)):9}" )
      r_i=$(( r_i + 10 ))
      r_pinned="${r_f[1]-}"; r_module="${r_f[2]-}"
      r_osvver="${r_f[6]-}"; r_osvcommit="${r_f[7]-}"
      [ -n "$r_module" ] || continue
      case "$r_module" in unresolved) continue ;; esac
      r_ids=""
      if [ -s "$osv_hits" ]; then
        [ -n "$r_osvver" ] && r_ids="$(awk -F'\t' -v m="$r_module" -v v="$r_osvver" \
          '$1=="v" && $2==m && $3==v {print $4; exit}' "$osv_hits")"
        if [ -n "$r_osvcommit" ]; then
          r_c="$(awk -F'\t' -v c="$r_osvcommit" '$1=="c" && $2==c {print $4; exit}' "$osv_hits")"
          [ -n "$r_c" ] && r_ids="$r_ids,$r_c"
        fi
      fi
      printf '%s\t%s\t%s\n' "$r_module" "$r_pinned" "$r_ids"
    done | sort -u
  )
fi

# ---------------------------------------------------------------------------
# Verdict + report.
# ---------------------------------------------------------------------------
behind=0; advisories=0; unresolved=0; moved=0; adv_unknown=0; adv_partial=0
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
mapfile -d '' -t row_toks < <(row_reader "$rows")
row_i=0
while [ "$row_i" -lt "${#row_toks[@]}" ]; do
  row_nf="${row_toks[$row_i]}"
  # A row that is not exactly nine fields wide was not written by this script
  # as it stands, so it is a format error rather than something to interpret.
  # Counting it as malformed reaches the `error` verdict via the existing
  # guard, instead of letting a shifted field render a clean-looking cell.
  case "$row_nf" in
    9) ;;
    *)
      malformed_rows=$((malformed_rows+1))
      echo "row with ${row_nf:-0} field(s) instead of 9; this pin was NOT compared" >> "$errors"
      # Without a trustworthy width there is no way to find the next row, so
      # stop rather than resynchronise onto a field boundary by guesswork.
      break ;;
  esac
  row_f=( "${row_toks[@]:$((row_i+1)):9}" )
  row_i=$(( row_i + 10 ))
  arg="${row_f[0]-}"; pinned="${row_f[1]-}"; module="${row_f[2]-}"
  latest="${row_f[3]-}"; latest_time="${row_f[4]-}"; kind="${row_f[5]-}"
  osv_version="${row_f[6]-}"; osv_commit="${row_f[7]-}"; note="${row_f[8]-}"
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
  # Union the two questions. `asked` counts how many were actually put to
  # OSV for this pin; it is what separates "clean" from "unknown" below, and
  # it is deliberately not inferred from `adv` being empty — empty is exactly
  # what both a clean answer and an unasked question look like.
  adv=""
  asked=0
  if [ -s "$osv_hits" ]; then
    # The advisory list is the LAST field of the table printf, so a newline
    # here would reach column 0 and could end the GITHUB_OUTPUT heredoc.
    # Sanitised even though OSV ids are observed to be [A-Za-z0-9-] only:
    # that is an observation about today's data, not an enforced contract.
    if [ -n "$osv_version" ]; then
      asked=$((asked+1))
      adv_v="$(clean_scalar "$(awk -F'\t' -v m="$module" -v v="$osv_version" \
        '$1=="v" && $2==m && $3==v {print $4; exit}' "$osv_hits")")"
      [ -n "$adv_v" ] && adv="$adv_v"
    fi
    if [ -n "$osv_commit" ]; then
      asked=$((asked+1))
      adv_c="$(clean_scalar "$(awk -F'\t' -v c="$osv_commit" \
        '$1=="c" && $2==c {print $4; exit}' "$osv_hits")")"
      if [ -n "$adv_c" ]; then
        # De-duplicate: a curated advisory with both a package range and a
        # GIT range legitimately answers both questions, and listing its id
        # twice in one cell makes the row look like two findings.
        adv="$(printf '%s,%s' "$adv" "$adv_c" | tr ',' '\n' \
          | grep -v '^$' | sort -u | paste -sd, -)"
      fi
    fi
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

  # An em dash in the advisory column must mean "OSV was asked and said no",
  # and it must mean nothing else. Three cells, three meanings, and the second
  # and third must not look like the first (T-0634 point 3):
  #
  #   —                 both questions asked, neither matched
  #   partial (…)       one question asked and clean, the other impossible
  #   **not checked**   neither question could be asked, or the batch failed
  #
  # `partial` exists because the two questions see different classes of
  # advisory: a version-only answer cannot see package-less GIT-range CVEs
  # (the chi case), and a commit-only answer can miss a curated range. Either
  # alone is a narrower question than this script claims to ask, so it is not
  # allowed to render as a clean dash.
  if [ "$osv_failed" -eq 1 ] || [ "$asked" -eq 0 ]; then
    adv_cell="**not checked**"
    adv_unknown=$((adv_unknown+1))
  elif [ -n "$adv" ]; then
    adv_cell="$adv"
  elif [ "$asked" -lt 2 ]; then
    if [ -z "$osv_commit" ]; then
      adv_cell="partial (no GIT-range query)"
    else
      adv_cell="partial (no version query)"
    fi
    adv_partial=$((adv_partial+1))
  else
    adv_cell="—"
  fi
  printf '| `%s` | `%s` | %s | %s |\n' \
    "$arg" "$pinned" "$up" "$adv_cell" >> "$report"
done

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
  if [ -s "$errors" ]; then
    echo "**The check could not complete for every pin.** An unchecked pin is not a clean pin:"
    while IFS= read -r e; do echo "- $e"; done < "$errors"
    echo
  fi
  if [ -s "$gh_extra" ]; then
    echo "**GitHub's advisory database lists advisories that OSV did not report for these pins.** A second index, keyed on the repository rather than the module path, so it sees records whose Go module path is missing or wrong. The version ranges below are GitHub's own free text and have NOT been compared against the pin mechanically — read them and decide:"
    echo
    echo "| module | pinned | GHSA | severity | GitHub's affected range |"
    echo "| --- | --- | --- | --- | --- |"
    while IFS=$'\t' read -r x_mod x_pin x_ghsa x_sev x_range; do
      printf '| `%s` | `%s` | %s | %s | `%s` |\n' "$x_mod" "$x_pin" "$x_ghsa" "$x_sev" "$x_range"
    done < "$gh_extra"
    echo
  fi
  [ -n "$gh_unavailable" ] && { echo "**$gh_unavailable.** The OSV result above still stands on its own; only the independent second opinion is missing."; echo; }
  if [ "$adv_unknown" -gt 0 ]; then
    echo "**Advisory status could not be established for $adv_unknown pin(s).** Neither the version-scoped nor the commit-scoped query could be asked, so those rows say nothing about whether an advisory applies. An unchecked pin is not a clean pin."
    echo
  fi
  if [ "$adv_partial" -gt 0 ]; then
    echo "**$adv_partial pin(s) were checked by only one of the two queries.** A version-only check cannot see CVE records that carry no package field (their affected range is a \`GIT\` range keyed on the repo); a commit-only check can miss a curated package range. Those rows are narrower than a — and are marked \`partial\`."
    echo
  fi
  if [ "$advisories" -eq 0 ] && [ "$behind" -eq 0 ] && [ "$moved" -eq 0 ] \
     && [ "$malformed_rows" -eq 0 ] && [ "$adv_unknown" -eq 0 ] \
     && [ "$adv_partial" -eq 0 ] \
     && [ ! -s "$errors" ] && [ ! -s "$unpinned_file" ] \
     && [ ! -s "$gh_extra" ] && [ -z "$gh_unavailable" ] \
     && [ ! -s "$replaced_file" ] && [ -z "$tag_now_ok" ]; then
    echo "Every pin is at upstream's newest release, and for every pin both the version-scoped and the commit-scoped advisory query were asked and came back clean. GitHub's advisory database ($gh_checked module(s) cross-checked) adds nothing OSV did not already report."
  fi
  echo
  echo "<sub>Versions from \`$PROXY\`; advisories from \`$OSV\`, queried twice per pin — by module+pinned version, and by the pinned version's upstream commit so that \`GIT\`-range records with no package field are visible too. Untagged pins compared against upstream \`HEAD\`.</sub>"
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
# `adv_unknown` joins the error arm, and that is the point of T-0634: a pin
# whose advisory status could not be established must not be able to leave the
# run at `verdict=ok`. Before this, the only question asked was one that
# structurally cannot see package-less GIT-range CVE records, and every — in
# the column was therefore unproven while the verdict read clean.
#
# `adv_partial` is the weaker form of the same problem — one of the two
# questions was asked and clean, the other was impossible — so it reaches
# `attention` rather than `error`: something real was verified, but less than
# this script claims to verify, and `ok` would overstate it.
if   [ "$advisories" -gt 0 ]; then verdict="advisory"; rc=2
elif [ "$unresolved" -gt 0 ] || [ "$osv_failed" -eq 1 ] \
  || [ "$malformed_rows" -gt 0 ] || [ "$adv_unknown" -gt 0 ] \
  || [ -s "$errors" ]; then verdict="error"; rc=3
elif [ "$behind" -gt 0 ] || [ "$moved" -gt 0 ] || [ -n "$tag_now_ok" ] \
  || [ "$adv_partial" -gt 0 ] || [ -s "$gh_extra" ] || [ -n "$gh_unavailable" ] \
  || [ -s "$unpinned_file" ] || [ -s "$replaced_file" ]; then verdict="attention"; rc=1
else verdict="ok"; rc=0
fi

cat "$report"
echo "verdict=$verdict"

if [ "$EMIT_JSON" -eq 1 ]; then
  jq -n --arg v "$verdict" --argjson b "$behind" --argjson a "$advisories" \
        --argjson m "$moved" --argjson u "$unresolved" \
        --argjson au "$adv_unknown" --argjson ap "$adv_partial" \
        --argjson gx "$(wc -l < "$gh_extra" | tr -d ' ')" \
        --argjson gc "$gh_checked" \
        '{verdict:$v, behind:$b, advisories:$a, moved:$m, unresolved:$u,
          advisory_unknown:$au, advisory_partial:$ap,
          github_only:$gx, github_modules_checked:$gc}' \
    > "$OUT_DIR/result.json"
  cat "$OUT_DIR/result.json"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "verdict=$verdict"
    echo "behind=$behind"
    echo "advisories=$advisories"
    echo "moved=$moved"
    echo "advisory_unknown=$adv_unknown"
    echo "advisory_partial=$adv_partial"
    echo "github_only=$(wc -l < "$gh_extra" | tr -d ' ')"
    echo "report<<$PINREPORT_DELIM"
    cat "$report"
    echo "$PINREPORT_DELIM"
  } >> "$GITHUB_OUTPUT"
fi
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$report" >> "$GITHUB_STEP_SUMMARY"

exit "$rc"
