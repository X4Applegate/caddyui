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
#                           [--binary PATH|image:REF] [--also module@version]...
#
#   --binary  the built caddy binary (or `image:<ref>` to extract one from a
#             container image) whose module graph is swept for advisories, in
#             addition to the `--with` pins. See trap 5: the `--with` list is
#             not the image. Without it the graph sweep is reported as NOT RUN,
#             which reaches `attention` -- an unswept graph is not a clean one.
#   --also    sweep this `module@version` too, for a one-off check or a test
#             fixture. Not a place to maintain a list of engines; use --binary.
#
# Environment:
#   GITHUB_OUTPUT   When set, verdict/counts are appended for CI consumption.
#   GITHUB_STEP_SUMMARY  When set, the Markdown report is appended.
#
# Requires: curl, jq. `git` is used only for the untagged pins (below) and its
# absence degrades those two rows to "unknown" rather than failing the run.
#
# Exit status:
#   0  ok        every pin is current (or deliberately floored, below), no
#                advisory matches a pinned version
#   1  attention at least one pin is behind, or an untagged pin has moved
#   2  advisory  an advisory matches a PINNED version (the urgent case)
#   3  the check could not run (treat as unknown, not as a pass)
#
# Intentional floors: a pin that is behind upstream ON PURPOSE is declared in
# the Dockerfile, immediately above the pin it describes:
#
#   # pin-watch: floor against=v1.8.2 ref=T-0636 reason=<why, in prose>
#   --with github.com/crowdsecurity/crowdsec/pkg/apiclient@v1.7.8 \
#
# Such a pin is reported under "Intentional floors" with its reason and is NOT
# counted as behind, so a settled decision stops holding the verdict at
# `attention` forever. `against=` is the upstream version the decision was
# taken against and is REQUIRED, as is `reason=`: the acknowledgement expires
# the moment upstream moves past `against`, and an advisory on the pinned
# version outranks it regardless. This is an acknowledgement, not an
# exclusion — there is no way to say "ignore this module", because the
# distinction that matters is between "we looked and chose this" and "we have
# not looked", and only the first is allowed to be quiet. See T-0651.
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
#
# 5. THE `--with` LIST IS NOT THE IMAGE. Traps 1-4 are each about asking the
#    right QUESTION about a pin. This one is about the SET being asked, and it
#    is the older bug: for its whole life this script took its input from
#    `--with` arguments and nothing else, so two parts of the image were swept
#    by nothing at all (T-0669, from T-0660):
#
#      - `caddyserver/caddy` ITSELF, the `FROM caddy:<ver>-builder` /
#        `FROM caddy:<ver>-alpine` base. It is the core of the image and was
#        never a `--with` argument, so it was never checked. Measured at the
#        2.11.7 the image shipped: FIVE live advisories, all CVE-less, all
#        invisible to OSV (a package+version query at that version returns 0,
#        and every one of the five is a 404 on OSV by GHSA id). Five unpatched
#        findings in the single most important component, behind a report that
#        said every pin was current -- true, and irrelevant.
#
#      - THE TRANSITIVE GRAPH behind a thin module pin.
#        `corazawaf/coraza-caddy` is the `--with` pin and has 0 advisories;
#        `corazawaf/coraza`, the WAF ENGINE it exists to wrap, has 14, three of
#        them CVE-less. The pin was clean and the code doing the work was not.
#
#    So the sweep's input is now THE BUILT BINARY'S MODULE GRAPH, read with
#    `go version -m`, plus the Dockerfile's base-image tag. The graph is
#    preferred over extending a list by hand for one reason: a hand-maintained
#    extra list is exactly the thing that drifted here. Adding
#    `corazawaf/coraza` to a list would have closed this case and nothing
#    else, and the next engine behind the next thin wrapper would repeat it.
#    The graph is 235 modules and is by construction what shipped.
#
#    AN UNAVAILABLE GRAPH IS UNSWEPT, NOT CLEAN. The graph needs a built image,
#    which a given run may not have; the base-image tag is parsed from the
#    Dockerfile and is always available. So the two inputs degrade differently
#    and are reported differently -- a run with no graph says so rather than
#    printing an all-clear that silently covers one module.
#
#    AND THE COUNT MUST NOT INFLATE. Of Caddy's 23 advisories, 8 are CVE-less;
#    of those 8, THREE are bounded strictly below the shipped version
#    (`< 2.11.5`, `<= 2.11.2`, `< 2.11.3`) and do not apply. Reporting 8 where
#    5 apply is as wrong as reporting 0 (T-0645, T-0660): a reader who checks
#    one row and finds it already fixed stops believing the other seven. The
#    range filter the GitHub cross-check already uses does this job, and is
#    shared rather than reimplemented so the two reports cannot disagree.
set -uo pipefail

PROXY="${GOPROXY_BASE:-https://proxy.golang.org}"
OSV="${OSV_BASE:-https://api.osv.dev}"
# ---------------------------------------------------------------------------
# DESIGN RULE, earned three times in this script: WHEN ONE OUTPUT CARRIES TWO
# MEANINGS, SAY WHICH ONE YOU MEAN -- do not change the behaviour, add the
# distinction.
#   1. `behind` conflated "we have not looked" with "we looked and chose this"
#      -> fixed by the `# pin-watch: floor` acknowledgement, which reports an
#         intentional floor separately and re-arms if upstream passes the
#         version the decision was taken against.
#   2. a leftover untagged-pin allowlist entry was routed to $errors, which
#      means "these numbers cannot be trusted" -> fixed by $notices, rendering
#      a Housekeeping section at attention/rc=1 instead of error/rc=3.
#   3. the report did not say WHICH TREE it read. This script reads
#      $DOCKERFILE by plain path, so a local run in a shared clone can grade
#      an uncommitted pin set while reading identically to a CI run. The fix
#      is disclosure, NOT reading HEAD: the weekly job must grade the
#      checked-out ref (pristine after actions/checkout) and a deliberate
#      pre-commit run is legitimate. So state the path and whether it is dirty.
# Before adding any new verdict, counter or row, ask what it reports when its
# own input is missing, and whether a reader can tell the two cases apart.
# ---------------------------------------------------------------------------
DOCKERFILE="Dockerfile.caddy"
OUT_DIR=""
EMIT_JSON=0
FIXTURE=""
# The built binary whose module graph is the sweep's real input (trap 5). May
# be a path to a caddy binary, or `image:<ref>` to extract one from a built
# container image. Empty means no graph is available for this run, which is
# reported as not-run rather than treated as an empty graph.
BINARY=""
# Extra advisory-sweep targets supplied directly as `module@version`, for the
# acceptance fixture (trap 5's disproof) and for a one-off check. This is NOT
# a maintained list of engines-behind-wrappers: that is what the graph is for.
EXTRA_TARGETS=""

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
      echo "floors_acknowledged=unknown"
      echo "floors_expired=unknown"
      echo "github_only=unknown"
      # Not 0 for the same reason as advisory_unknown above: nothing about the
      # image was established either, and a 0 here would read as "the base
      # image and the module graph were swept and were clean".
      echo "image_findings=unknown"
      echo "image_unswept=unknown"
      echo "image_out_of_scope=unknown"
      echo "image_graph=unknown"
      echo "image_base=unknown"
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
    --binary)     need_value "$1" "${2+$2}"; BINARY="$2";  shift; shift ;;
    --also)       need_value "$1" "${2+$2}"; EXTRA_TARGETS="${EXTRA_TARGETS:+$EXTRA_TARGETS }$2"; shift; shift ;;
    --json)       EMIT_JSON=1;         shift ;;
    # Ends at the separator before the "three traps" essay, which is
    # commentary for a maintainer rather than usage. A fixed upper bound was
    # already one edit away from either truncating the exit-status list or
    # printing half an essay, so the range is anchored on that separator and
    # checked below.
    -h|--help)    sed -n '2,/^# ----/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
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
#
# Defined here, above the parsers, rather than next to the HTTP helpers: the
# floor-directive parser below is the first consumer, and a function defined
# after its caller is a crash under `set -u` the moment the directive path is
# taken — i.e. only on the runs that matter.
clean_scalar() {
  printf '%s' "$1" | tr -d '\000-\037\177' | cut -c1-120
}

# A floor's REASON is prose and is the entire point of the mechanism: a reason
# cut off mid-sentence ("OSV is clean at v1.") is worse than useless, because
# it reads as a complete thought that says something false. So it gets the same
# control-character stripping — which is what defends the TSV rows and the
# GITHUB_OUTPUT heredoc — with a cap wide enough for a sentence of reasoning.
#
# A pipe would forge a Markdown table column, so it is escaped rather than
# stripped: the text is written by whoever edits the Dockerfile, i.e. it is as
# trusted as the pins themselves, and silently deleting a character from a
# human's stated reason is its own small lie.
clean_reason() {
  printf '%s' "$1" | tr -d '\000-\037\177' | sed 's/|/\\|/g' | cut -c1-400
}

# The error log is created here, before any parser can need it. A parser
# writing to an undefined path would be a `set -u` crash on the directive
# path only, which is the shape of failure this file exists to avoid.
errors="$OUT_DIR/errors.txt"
: > "$errors"
# Housekeeping worth a human's attention but which does NOT invalidate the
# comparisons, kept separate from $errors on purpose: routing these to $errors
# would force verdict=error/rc=3 ("these numbers cannot be trusted") and bury
# genuine staleness findings behind a could-not-run warning, even though a
# leftover entry invalidates nothing.
notices="$OUT_DIR/notices.txt"
: > "$notices"

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
  #
  # Stripping quotes off `arg` alone did NOT close this. It fixed
  # `--with="mod@ver"` but left the two spellings where the quote covers the
  # FLAG, and `"--with" "mod@ver"` is the worst of them: the token counter
  # requires a separator immediately after `--with`, and there the next byte
  # is a quote, so the counter sees zero too. Both sides lose the token
  # together, they agree, and the reconciliation stays silent — the same
  # silent-unwatch shape, reproduced on the real Dockerfile (15 → 14 pins,
  # empty errors.txt, verdict=advisory rather than error). That is why the
  # normalisation happens once, at the line level, for both consumers.
  # Nothing to strip here any more: see the line-level normalisation at the
  # bottom of this loop, which removes quotes for the parser and the token
  # counter in the same place so the two cannot disagree about a pin.
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
# Quotes are turned into spaces BEFORE extraction, for the parser and for the
# token counter alike. Doing it here rather than per-argument is what makes
# the quoted-flag spellings (`"--with" "mod@ver"`, `"--with=mod@ver"`) visible
# to both counters instead of invisible to both; see the note above.
done < <(grep -v '^[[:space:]]*#' "$DOCKERFILE" \
  | sed 's/["'"'"']/ /g' \
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
# Same quote normalisation as the parser above, and for the same reason: if
# only one of the two sides understood a spelling, the comparison would pass
# while the pin went unwatched.
raw_with_count="$(grep -v '^[[:space:]]*#' "$DOCKERFILE" \
  | sed 's/["'"'"']/ /g' \
  | grep -oE -- '(^|[[:space:]])--with([=[:space:]]|$)' | wc -l | tr -d ' ')"
parsed_count=$(( pin_count + unpinned_count ))
if [ "$raw_with_count" != "$parsed_count" ]; then
  die "parsed $parsed_count pin(s) but $DOCKERFILE contains $raw_with_count --with argument(s); an unparsed pin would be silently unwatched"
fi

# ---------------------------------------------------------------------------
# Intentional floors — recording that a pin is deliberately behind upstream.
#
# T-0651. Before this, `behind` carried two different meanings: "nobody has
# looked at this" and "we looked and chose this". The crowdsec floor is the
# second kind — T-0636 settled that `crowdsec/pkg/apiclient` STAYS at v1.7.8,
# because a floor states a MINIMUM and v1.7.8 is the exact version fixing all
# four crowdsec advisories, while raising it would break the build for any
# future bouncer needing 1.7.x and fix nothing (OSV is clean at both). With no
# way to say that, the row reported `behind` on every weekly run forever, and a
# permanent finding on the one job whose output is meant to be read is how the
# GIT-range advisory in T-0634 gets skimmed past. A signal that is always on
# carries no information.
#
# THIS IS AN ACKNOWLEDGEMENT, NOT AN EXCLUSION, and the difference is the whole
# point. An "ignore these modules" list would also silence the case where
# nobody has looked, and would keep silencing it after the reasoning expired.
# So a declaration is required to carry:
#
#   # pin-watch: floor pin=<version> against=<version> reason=<text> [ref=<id>]
#
#   pin=      the PINNED version this decision was taken for. Required, and
#             checked against the pin the directive sits above. Without it the
#             directive is paired positionally and therefore matches whatever
#             version the line happens to carry: re-pin the module and the new
#             version SILENTLY INHERITS the old decision's silence, which is a
#             floor outliving its reasoning in the most direct way possible.
#             With it, a re-pin that does not update the directive is a loud
#             error naming both versions.
#   against=  the upstream version the decision was taken against. The
#             acknowledgement covers upstream up to and including this
#             version and RE-ARMS the moment upstream goes past it (see
#             `floor_state` at the classification below). An acknowledgement
#             that silently outlives its reasoning is worse than the noise it
#             replaces — that is T-0646's failure mode in a different place.
#   reason=   why, in prose, in the report. REQUIRED: an acknowledgement
#             whose reason is "" is indistinguishable from an exclusion, so a
#             declaration missing it is an error rather than a quiet floor.
#   ref=      optional task/PR id for the decision's audit trail.
#
# An advisory on the pinned version also re-arms it, and that is enforced at
# the classification rather than here: `advisories` is counted before the
# floor is consulted, so exit 2 still beats an acknowledged floor.
#
# PARSED IN A SEPARATE PASS, over the RAW file. The pin parser above pipes the
# Dockerfile through `grep -v '^#' | grep -oE -- '--with…'`, which discards
# both the comments and the line association, so a directive is invisible to
# it by construction — it cannot be bolted onto that loop. This pass reads the
# file in order and attaches a pending directive to the NEXT `--with` line,
# which is also the only arrangement a human reads correctly: the declaration
# sits immediately above the pin it describes.
#
# A DIRECTIVE THAT MATCHES NO PIN IS AN ERROR, not a no-op. A floor whose pin
# was renamed, re-pinned or deleted is a stale claim about a line that no
# longer exists, and silently dropping it is how the untagged_repo() list in
# T-0625 was able to rot into a lie. Same for a malformed one: a typo in a
# directive must not read as "no floor declared", because that failure is
# invisible — the row simply goes back to `behind` and looks like ordinary
# drift.
# ---------------------------------------------------------------------------
floors_file="$OUT_DIR/floors.tsv"
: > "$floors_file"

# module \t pinned \t against \t ref \t reason  (reason last: free text)
floor_pending=""
floor_pending_line=0
floor_lineno=0
while IFS= read -r fl_raw; do
  floor_lineno=$(( floor_lineno + 1 ))
  case "$fl_raw" in
    *pin-watch:*)
      # A directive must be a comment whose text STARTS with the marker. This
      # file documents its own syntax in prose ("carries a `# pin-watch:
      # floor`"), and that prose is a comment too, so requiring only "a
      # comment mentioning the string" made the header's explanation parse as
      # a real declaration: its body after `floor` is a backtick, so `pin=`
      # came out empty and the run reported the crowdsec floor as missing
      # pin= while the actual directive below was never read. Same prose-
      # harvesting trap the --with counter avoids by excluding comments;
      # here the directive IS a comment, so anchor on position instead.
      # Requiring the comment's first token to be the marker also means a
      # NON-comment line declares nothing, so a `--with` line or an env value
      # mentioning the string cannot acknowledge itself.
      fl_trim="${fl_raw#"${fl_raw%%[![:space:]]*}"}"
      case "$fl_trim" in '#'*) ;; *) continue ;; esac
      fl_marker="${fl_trim#'#'}"
      fl_marker="${fl_marker#"${fl_marker%%[![:space:]]*}"}"
      case "$fl_marker" in
        pin-watch:*) ;;
        *) continue ;;
      esac
      if [ -n "$floor_pending" ]; then
        echo "two \`# pin-watch:\` directives in a row at line $floor_lineno of $DOCKERFILE with no --with between them; the first declared no pin" >> "$errors"
        floor_pending=""
      fi
      floor_pending="$fl_marker"
      floor_pending_line="$floor_lineno"
      continue ;;
  esac
  # A comment line that is not a directive must not break the pairing: the
  # Dockerfile's pin block is full of explanatory prose, and treating any
  # comment as a separator would make a declaration unreadable the moment
  # someone wrote a note between it and its pin.
  fl_trim="${fl_raw#"${fl_raw%%[![:space:]]*}"}"
  case "$fl_trim" in '#'*) continue ;; esac
  case "$fl_raw" in
    *--with*) ;;
    *) continue ;;
  esac
  [ -n "$floor_pending" ] || continue

  # Extract the pin on this line with the SAME normalisation the pin parser
  # uses, so a floor cannot be declared against a spelling the watch records
  # differently (`--with=`, a tab, two spaces, quotes, a replacement).
  fl_line="${fl_raw//$'\t'/ }"
  fl_line="${fl_line/--with=/--with }"
  while case "$fl_line" in *'--with  '*) true ;; *) false ;; esac; do
    fl_line="${fl_line/--with  /--with }"
  done
  fl_arg="${fl_line#*--with }"
  fl_arg="${fl_arg%% *}"
  fl_arg="${fl_arg%\\}"
  fl_arg="${fl_arg%\"}"; fl_arg="${fl_arg#\"}"
  fl_arg="${fl_arg%\'}"; fl_arg="${fl_arg#\'}"
  case "$fl_arg" in *=*) fl_arg="${fl_arg%%=*}" ;; esac
  fl_mod="${fl_arg%@*}"
  fl_ver="${fl_arg##*@}"
  fl_dir="$floor_pending"
  fl_dir_line="$floor_pending_line"
  floor_pending=""
  floor_pending_line=0

  case "$fl_arg" in
    *@*) ;;
    *)
      echo "the \`# pin-watch:\` directive at line $fl_dir_line of $DOCKERFILE sits above an UNPINNED --with argument; a floor can only acknowledge a pinned version" >> "$errors"
      continue ;;
  esac

  # `floor` is the only kind today. An unknown kind is an error rather than a
  # skip: a future `# pin-watch: something-else` must not read as "no floor
  # declared" on a box running an older copy of this script.
  fl_body="${fl_dir#*pin-watch:}"
  fl_body="${fl_body#"${fl_body%%[![:space:]]*}"}"
  case "$fl_body" in
    floor|floor' '*|floor$'\t'*) ;;
    *)
      echo "unknown \`# pin-watch:\` directive at line $fl_dir_line of $DOCKERFILE: $(clean_scalar "$fl_body") (only \`floor\` is understood by this version)" >> "$errors"
      continue ;;
  esac
  fl_body="${fl_body#floor}"

  # key=value, in any order. `reason=` is taken to the end of the line because
  # it is prose and the last thing a human writes; the scalars are matched
  # individually so an unparsed one is empty and fails the checks below rather
  # than swallowing the rest of the directive.
  fl_pin="$(printf '%s' "$fl_body" | grep -oE '(^|[[:space:]])pin=[^[:space:]]+' | head -1 | cut -d= -f2-)"
  fl_against="$(printf '%s' "$fl_body" | grep -oE 'against=[^[:space:]]+' | head -1 | cut -d= -f2-)"
  fl_ref="$(printf '%s' "$fl_body" | grep -oE 'ref=[^[:space:]]+' | head -1 | cut -d= -f2-)"
  fl_reason="$(printf '%s' "$fl_body" | sed -n 's/.*reason=//p')"
  # Strip a trailing line-continuation backslash a Dockerfile comment may end
  # with, and the trailing whitespace it leaves.
  fl_reason="${fl_reason%\\}"
  fl_reason="${fl_reason%"${fl_reason##*[![:space:]]}"}"
  fl_pin="$(clean_scalar "$fl_pin")"
  fl_against="$(clean_scalar "$fl_against")"
  fl_ref="$(clean_scalar "$fl_ref")"
  fl_reason="$(clean_reason "$fl_reason")"

  # `pin=` must be present AND must match the pin this directive sits above.
  # Missing is an error, not a fallback to the positional version: a silent
  # fallback is exactly the inheritance this field exists to prevent, and it
  # would make the protection depend on remembering to use the field.
  if [ -z "$fl_pin" ]; then
    echo "the \`# pin-watch: floor\` directive for \`$fl_mod\` at line $fl_dir_line of $DOCKERFILE is missing pin=; without it a re-pin would silently inherit this decision, so the floor is not honoured" >> "$errors"
    continue
  fi
  if [ "$fl_pin" != "$fl_ver" ]; then
    echo "the \`# pin-watch: floor\` directive at line $fl_dir_line of $DOCKERFILE was written for \`$fl_mod@$fl_pin\` but the pin below it is now \`$fl_ver\`; the pin moved and the acknowledgement did not follow it, so the floor is not honoured" >> "$errors"
    continue
  fi

  if [ -z "$fl_against" ] || [ -z "$fl_reason" ]; then
    echo "the \`# pin-watch: floor\` directive for \`$fl_mod\` at line $fl_dir_line of $DOCKERFILE is missing $( [ -z "$fl_against" ] && printf 'against='; [ -z "$fl_against" ] && [ -z "$fl_reason" ] && printf ' and '; [ -z "$fl_reason" ] && printf 'reason=' ); an acknowledgement without both is an exclusion, and this script does not do exclusions" >> "$errors"
    continue
  fi
  if ! printf '%s' "$fl_against" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z._-]+)?$'; then
    echo "the \`# pin-watch: floor\` directive for \`$fl_mod\` at line $fl_dir_line of $DOCKERFILE has against=$fl_against, which is not a Go version; the re-arm comparison cannot be made, so the floor is not honoured" >> "$errors"
    continue
  fi

  printf '%s\t%s\t%s\t%s\t%s\n' "$fl_mod" "$fl_ver" "$fl_against" "$fl_ref" "$fl_reason" >> "$floors_file"
done < "$DOCKERFILE"

if [ -n "$floor_pending" ]; then
  echo "the \`# pin-watch:\` directive at line $floor_pending_line of $DOCKERFILE is not followed by any --with argument; it acknowledges nothing" >> "$errors"
fi

# A floor must name a pin that exists, at the version it was declared for. A
# floor left behind by a re-pin is the dangerous case: the pin moved, the
# acknowledgement did not, and without this check the new version would
# inherit the old decision's silence.
while IFS=$'\t' read -r fc_mod fc_ver _fc_against _fc_ref _fc_reason; do
  [ -n "$fc_mod" ] || continue
  if ! awk -F'\t' -v m="$fc_mod" -v v="$fc_ver" '$1==m && $2==v {found=1} END{exit !found}' "$pins_file"; then
    echo "a \`# pin-watch: floor\` directive acknowledges \`$fc_mod@$fc_ver\`, but no such pin is in $DOCKERFILE; the pin moved or was removed and the acknowledgement did not follow it" >> "$errors"
  fi
done < "$floors_file"

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
# The pseudo-version arm matches `-0.` followed by go's 14-digit UTC timestamp
# and a `-` before the revision, NOT a bare `-0.`: a legitimate prerelease tag
# such as v1.0.0-0.1 would otherwise be reported as an untagged commit pin and
# compared against git HEAD forever.
is_untagged_pin() {
  case "$1" in
    v0.0.0-*|*-0.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-*) return 0 ;;  # pseudo-version
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
      # A bare hex string of 7+ chars with no dots is a commit SHA.
      case "$1" in *.*) return 1 ;; esac
      [ -z "${1//[0-9a-f]/}" ] && return 0 || return 1 ;;
  esac
  return 1
}

# ---------------------------------------------------------------------------
# Does a GitHub free-text version range plainly EXCLUDE this version?
#
# Returns 0 ("drop the row") only when the range's highest upper bound sorts
# strictly BELOW the version. Everything it cannot confidently place is KEPT,
# because a failure to understand a range must never look like the absence of
# an advisory -- a dropped row is invisible, and this is the one place in this
# script where being wrong produces a false CLEAN.
#
# This was the inline filter inside the GitHub cross-check loop and is now a
# function because the base-image and graph sweeps (trap 5) need exactly the
# same judgement, and the count-inflation guard has to be ONE implementation:
# three of Caddy's eight CVE-less advisories are bounded below the shipped
# version, and a second copy of this logic is a second chance to get that
# wrong in only one of the two reports. It decides nothing but the range
# question; the callers keep their own de-duplication and rendering.
#
# Every subtlety below is load-bearing and each was a demonstrated bug:
#
#   - THE BOUND IS THE HIGHEST ONE IN THE STRING, NOT THE LAST. `tail -1` on
#     textual order drops a row on a trailing low bound: `"<= 1.7.8, <= 1.0.0"`
#     against a 1.7.8 pin, or `"affects <= 9.9.9 and <= 1.0.0"` against 5.4.0.
#     A range listing several bounds is legal free text, and an advisory author
#     -- or anyone controlling the response -- could append a low bound to hide
#     a real finding. Taking the maximum means an extra bound can only ever
#     make the row MORE likely to be kept.
#   - A LOWER BOUND IS NOT A REASON TO IGNORE THE UPPER ONE. This test used
#     to bail out on any range whose text STARTS with `>`, which on a
#     two-sided range throws away the only bound that can settle the
#     question: `>= 2.10.0, < v2.11.2` against 2.11.9 is plainly excluded by
#     its upper bound, and the early return kept it. That is harmless on a
#     pin with few advisories; on `caddyserver/caddy`, which has 23, it
#     turned the correct answer of ZERO live advisories at 2.11.9 into NINE
#     -- the exact count-inflation this sweep carries a guard against
#     (T-0645/T-0660), produced by the guard itself. Reproduced before
#     fixing. A range with no upper bound at all is still kept: there is
#     then nothing to compare it against.
#   - AN EXCLUSIVE BOUND (`<`) EXCLUDES ITS OWN VALUE, an inclusive one
#     (`<=`) does not. Reading `< 2.11.2` as `<= 2.11.2` keeps a row for a
#     version the advisory itself says is fixed, which is the same inflation
#     one release further on. So the operator travels with its bound and the
#     equality case consults it, rather than only the number being compared.
#   - A NON-NUMERIC version (pseudo-version, SHA) cannot be compared: kept.
#   - A BOUND WITH FEWER COMPONENTS than the version names a release SERIES,
#     not a point release. Padding `<= 1.7` to 1.7.0 dropped a row whose pin
#     was v1.7.8 -- an advisory that most likely covers 1.7.x, hidden. Kept.
#   - LEADING ZEROS are stripped per component first: `sort -V` reads
#     "0005.4.0" as NEWER than "5.4.0", so a zero-padded bound that in fact
#     covers the version compared as above it and the row was dropped.
#   - COMPONENT COUNTS are reconciled before comparing: `sort -V` ranks "5.4"
#     below "5.4.0", so a bound of `<= 5.4` dropped a row whose pin was exactly
#     v5.4.0 -- the advisory covers the pin and the filter hid it.
# ---------------------------------------------------------------------------
# Is this advisory's own stated fix already in the shipped version?
#
# A SECOND, INDEPENDENT exclusion beside the range filter, and the two are
# deliberately different in kind: the range filter reads the AFFECTED range
# (free text, conservative, keeps what it cannot place), this one reads the
# advisory's own FIX. `patched_versions` naming a release at or below the
# shipped version means the image already carries the fix, whatever its range
# text happens to say.
#
# This exists because conservatism has a cost on a repo with many advisories.
# Caddy has 23 and its ranges are mostly free text: at 2.11.9 five CVE-bearing
# rows survived the range filter because their ranges are a bare "2.10.2", a
# commit hash, or "v2.4.0 and later" -- unplaceable by any parser -- while
# every one of them states a fix at or below v2.11.3. OSV, which CAN see them
# (they carry CVE ids), reports zero. Rendering five already-fixed rows is the
# count-inflation this sweep carries a guard against (T-0645/T-0660), and a
# reader who checks one and finds it fixed stops believing the rest.
#
# THE FIELD IS `patched_versions`, NOT `first_patched_version` (T-0660). The
# authoritative-looking one is frequently null -- on all five of the Caddy
# 2.11.7 advisories it is null while `patched_versions` carries the real fix --
# and reading the null one filed an available HIGH fix as an unfixable
# residual.
#
# IT CAN ONLY EVER REMOVE A ROW IT HAS POSITIVE EVIDENCE FOR. Empty, null,
# unparseable or non-numeric excludes nothing, so a missing field cannot make
# a row disappear; that direction is the false clean this file is written
# against. Only the LOWEST version in the field is used: a multi-branch fix
# ("2.11.8, 3.0.1") is only evidence for the branch the image is on, and
# taking the lowest means a stated fix can only clear a version at or above it.
patch_already_in_version() { # $1 = patched_versions text, $2 = version
  local p_txt="$1" p_ver="$2" p_lo p_n p_cmp_v p_cmp_lo
  [ -n "$p_txt" ] || return 1
  p_n="${p_ver#v}"
  case "$p_n" in *[!0-9.]*) return 1 ;; esac
  # Lowest stated fix. A fix must have all three components to be comparable:
  # "2.11" names a series and says nothing about which patch release fixed it.
  p_lo="$(printf '%s' "$p_txt" | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' \
          | sed 's/^v//' | sort -V | head -1 || true)"
  [ -n "$p_lo" ] || return 1
  p_cmp_v="$(printf '%s' "$p_n"  | sed 's/\(^\|\.\)0*\([0-9]\)/\1\2/g')"
  p_cmp_lo="$(printf '%s' "$p_lo" | sed 's/\(^\|\.\)0*\([0-9]\)/\1\2/g')"
  # Fixed at or below the shipped version -> the image has the fix.
  [ "$p_cmp_v" = "$p_cmp_lo" ] && return 0
  [ "$(printf '%s\n%s\n' "$p_cmp_v" "$p_cmp_lo" | sort -V | tail -1)" = "$p_cmp_v" ]
}

range_excludes_version() { # $1 = range text, $2 = version; 0 = plainly older
  local r_range="$1" r_ver="$2" r_hi r_op r_n r_hi_dots r_ver_dots r_cmp_v r_cmp_hi r_tok
  [ -n "$r_range" ] || return 1
  r_n="${r_ver#v}"
  case "$r_n" in *[!0-9.]*) return 1 ;; esac

  # Collect every upper bound in the string as "<op> <number>", then take the
  # HIGHEST number. `sort -V` on the number field, so the operator travels
  # with its own bound and `< 2.11.2` is never conflated with `<= 2.11.2`.
  r_tok="$(printf '%s' "$r_range" \
    | grep -oiE '<=?[[:space:]]*v?[0-9]+(\.[0-9]+)*' \
    | sed -E 's/^(<=?)[[:space:]]*v?/\1 /' \
    | sort -t' ' -k2,2V | tail -1 || true)"
  [ -n "$r_tok" ] || return 1
  r_op="${r_tok%% *}"
  r_hi="${r_tok##* }"
  [ -n "$r_hi" ] || return 1

  # A bound with FEWER components than the version names a release SERIES,
  # not a point release: keep rather than guess at the bottom of that series.
  r_hi_dots="$(printf '%s' "$r_hi" | tr -cd '.' | wc -c)"
  r_ver_dots="$(printf '%s' "$r_n" | tr -cd '.' | wc -c)"
  [ "$r_hi_dots" -ge "$r_ver_dots" ] || return 1

  r_cmp_v="$(printf '%s' "$r_n"  | sed 's/\(^\|\.\)0*\([0-9]\)/\1\2/g')"
  r_cmp_hi="$(printf '%s' "$r_hi" | sed 's/\(^\|\.\)0*\([0-9]\)/\1\2/g')"
  while [ "$(printf '%s' "$r_cmp_v" | tr -cd '.' | wc -c)" \
       -lt "$(printf '%s' "$r_cmp_hi" | tr -cd '.' | wc -c)" ]; do
    r_cmp_v="$r_cmp_v.0"
  done

  if [ "$r_cmp_v" = "$r_cmp_hi" ]; then
    # Equal to the bound: `< X` excludes X, `<= X` includes it.
    [ "$r_op" = "<" ]
    return
  fi
  # Strictly above the highest upper bound, under either operator.
  [ "$(printf '%s\n%s\n' "$r_cmp_v" "$r_cmp_hi" | sort -V | tail -1)" = "$r_cmp_v" ]
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
  # NF>0 skips a blank line. A stray trailing newline in rows.tsv would
  # otherwise be read as a 0-field row, trip the malformed branch and push the
  # whole run to verdict=error -- a spurious failure, not a real one. No
  # current writer emits a blank line; this keeps a future one from doing so.
  awk -F'\t' 'NF>0 { printf "%d%c", NF, 0; for (i = 1; i <= NF; i++) printf "%s%c", $i, 0 }' "$1"
}
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
  # Key this on the PIN's shape ALONE. This test used to read
  # `is_untagged_pin "$pinned" || [ -n "$repo" ]`, which let the
  # untagged_repo() allowlist decide THAT a pin is a commit when its only job
  # is to say WHERE a commit pin's upstream lives. A module can return to a tag
  # -- the CrowdSec bouncer did, in v0.15.0 -- and with the pin tagged but
  # still listed, that `||` compared a current, tagged pin against upstream git
  # HEAD forever and reported it as "no longer at upstream HEAD".
  #
  # So a leftover entry is surfaced as a housekeeping notice rather than
  # silently forcing commit mode, and the list cannot rot. It is a notice and
  # not an error on purpose: the pin is still resolved and compared correctly,
  # so the run stays authoritative.
  if [ -n "$repo" ] && ! is_untagged_pin "$pinned"; then
    echo "\`$arg\` is in the untagged-pin allowlist but is pinned to \`$pinned\`, which is a tag; drop it from untagged_repo()" >> "$notices"
    repo=""
  fi
  if is_untagged_pin "$pinned"; then
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
# Which modules the cross-check actually COVERED, and which it could not reach.
#
# Why per-module and not just the `gh_checked` count: a GitHub-only row that
# vanishes between two runs is ambiguous. It means either "the advisory was
# withdrawn or its range moved past the pin" (a real all-clear) or "this
# module's request was rate-limited this time" (nothing learned). Both looked
# identical in the report -- the global caveat said the cross-check had not run
# for *every* module but never said for WHICH, so a reader could not tell a
# cleared row from an unasked one. Observed on two runs minutes apart: five chi
# rows and zero crowdsec rows, then no GitHub-only table at all (T-0664).
#
# Unauthenticated the advisory API allows 60 requests/hour/IP, so on a busy
# runner the skipped set is routinely non-empty and this is the common case,
# not an edge case. Naming both sets costs one line each and makes a missing
# row readable.
gh_covered="$OUT_DIR/gh-covered.tsv"
: > "$gh_covered"
gh_skipped="$OUT_DIR/gh-skipped.tsv"
: > "$gh_skipped"

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
      [ -z "$gh_unavailable" ] && gh_unavailable="GitHub's advisory API did not return a list for at least one module (rate limit, or no token); the modules it could not reach are named below"
      printf '%s\t%s\n' "$g_module" "$g_pinned" >> "$gh_skipped"
      continue
    fi
    gh_checked=$((gh_checked+1))
    printf '%s\t%s\n' "$g_module" "$g_pinned" >> "$gh_covered"

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
      # free text, so this is a conservative TEXTUAL filter, not a comparator;
      # every subtlety is documented on `range_excludes_version` above, which
      # is shared with the base-image and graph sweeps so the count-inflation
      # guard is one implementation rather than two.
      #
      # Without any filter the cross-check reported 12 "GitHub-only" findings
      # for this Dockerfile, mostly advisories fixed long before the pinned
      # release — exactly the history noise trap 3 above exists to keep out of
      # this report, re-entering through the second index.
      range_excludes_version "$g_range" "$g_pinned" && continue

      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$g_module" "$g_pinned" "$(clean_scalar "$g_ghsa")" \
        "$(clean_scalar "${g_sev:-?}")" "$(clean_scalar "${g_range:-?}")" >> "$gh_extra"
    done < <(jq -j --arg mod "$g_module" '
      # Defined at the top of the program: jq `def`s are declarations, not
      # pipeline stages, so one placed mid-pipeline after a `|` is a syntax
      # error — and inside a single-quoted shell argument that surfaces as a
      # BASH parse error pointing at the jq line, which is a confusing way to
      # learn it. See the match discussion below for what they are for.
      def pw_norm: ascii_downcase | gsub("\\s+$"; "") | sub("^https?://"; "") | sub("/+$"; "");
      def pw_is_modpath: test("^[a-z0-9.-]+\\.[a-z]{2,}(:[0-9]+)?/[^ ]+$");
      def pw_demaj: sub("/v[0-9]+$"; "");
      def pw_hasmaj: test("/v[0-9]+$");

      .[]
      | . as $a
      | (.vulnerabilities // [])[]
      # Keep only entries whose package plausibly names this module or its
      # repo; the field is free text (values seen on one repo include the full
      # module path, a bare repo URL with a trailing space, `owner/repo` and
      # just `repo`), so matching is intentionally loose and the result is
      # only ever a pointer for a human.
      #
      # BUT LOOSE ONLY WHERE IT HAS TO BE. The match is split in two by
      # whether `package.name` is itself a full module path, because a full
      # module path is not free text — it is the one spelling that can be
      # compared exactly, and comparing it loosely produced a false ADVISORY
      # on a correctly-patched pin (T-0666):
      #
      #   go-jose/go-jose publishes v3 and v4 side by side. Each of its five
      #   CVE-less advisories carries TWO vulnerability entries — v4 with
      #   `<= v4.1.6` / patched v4.1.7, and v3 with range `all` and no patch.
      #   The old repo-element arm took `.[2]` of github.com/go-jose/go-jose/v4,
      #   i.e. "go-jose", which matches a package named `.../go-jose/v3`, so
      #   the v3 rows attached to the v4 pin. The range filter below cannot
      #   drop them either: `all` carries no upper bound to compare against,
      #   and "keep what you cannot place" is the right default there. Result:
      #   a permanent verdict=advisory naming `go-jose/v4@v4.1.7` — the exact
      #   version that PATCHES all five. The one job whose output is meant to
      #   be read was crying wolf about the pin that had just been fixed,
      #   which is the alert-fatigue failure T-0651 exists to remove.
      #
      # So for a full module path the WHOLE path is compared, major-version
      # suffix included, and two different `/vN` suffixes never match. The
      # three relations that DO still match are kept deliberately, because
      # each is the same code under a different spelling:
      #
      #   - identical paths;
      #   - one side omitting `/vN` where the other carries it, which is legal
      #     only for v0/v1 and is how a pre-v2 module is named — at most one
      #     side may carry a suffix, so v3-vs-v4 is still excluded;
      #   - one path being a PACKAGE INSIDE the other. Three of the pins in
      #     this image are packages within a larger module (see trap 1), so
      #     an advisory naming `crowdsec/pkg/apiclient` against the resolved
      #     module `crowdsec` must keep matching. Dropping that containment
      #     arm was tried first and silently hid that row — a false clean on
      #     one of the two CVE floors, i.e. a worse bug than the one being
      #     fixed.
      #
      # NO APOSTROPHES IN THE COMMENTS BELOW, up to the closing quote. These
      # comments sit INSIDE a single-quoted shell argument, so one apostrophe
      # ends the jq program and bash parses the remainder of the filter as
      # shell. It surfaces as a bash syntax error pointing at a jq line, which
      # reads as a jq problem and is not one. Cost an edit cycle here.
      #
      # The free-text arm below is unchanged and still reached for every
      # other spelling. Its repo-element test is ANCHORED to a path boundary:
      # unanchored, the bare element is a substring test, and `.[2]` of
      # github.com/go-chi/chi/v5 is "chi", which matched an unrelated
      # advisory for github.com/unrelated/archive. That direction of error is
      # noise rather than a false clean, but it pushes verdict=attention and
      # a ::warning:: on records that have nothing to do with the pin, which
      # is exactly how a reader is trained to ignore the report.
      #
      # A trailing space and a `https://` prefix are normalised off both
      # sides first: `https://github.com/go-chi/chi ` is an observed real
      # value, and left alone it fails the module-path test and falls to the
      # loose arm by accident rather than by decision.
      | (.package.name // "" | pw_norm) as $pname
      | ($mod | pw_norm) as $m
      | select(
          if ($pname | pw_is_modpath) then
            ($pname == $m)
            or ((($pname | pw_demaj) == ($m | pw_demaj))
                and ((($pname | pw_hasmaj) | not) or (($m | pw_hasmaj) | not)))
            or ($pname | startswith($m + "/"))
            or ($m | startswith($pname + "/"))
          else
            ($pname | test("(^|[/ ])" + ($m | split("/") | .[2] | gsub("\\."; "\\\\.")) + "($|[/ @])"))
            or ($pname | test($m | gsub("\\."; "\\\\.")))
          end)
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
# Pass 5 — THE IMAGE, not the `--with` list (trap 5, T-0669).
#
# Two inputs the `--with` extractor structurally cannot see:
#
#   base    `FROM caddy:<ver>-builder` / `-alpine` in the Dockerfile. Parsed
#           here, mapped to `caddyserver/caddy`, and swept on the repo-scoped
#           endpoint — the same endpoint pass 4 already uses, so this is a new
#           INPUT to existing code, not a new mechanism.
#   graph   every module in the built binary (`go version -m`), which is what
#           reaches the engine behind a thin wrapper pin. 235 modules on this
#           image; `corazawaf/coraza` is in it and was in nothing before.
#
# WHY THE REPO ENDPOINT AND NOT OSV. Because OSV cannot answer this question.
# Measured on the five Caddy advisories live at the 2.11.7 the image shipped:
# an OSV package+version query at that exact version returns ZERO, and each of
# the five is a 404 on OSV by GHSA id. They carry no CVE id, and T-0654 settled
# that the CVE id — not a lag — is the mechanism: a CVE-less advisory appears
# on the per-repository endpoint and nowhere else measured. So the sweep is
# GitHub-repo-scoped by necessity, and that is also why its findings reach
# `attention` rather than `advisory`: the ranges are free text, exactly as in
# pass 4, and exit 2 stays reserved for OSV's machine-checked matching
# (T-0634's deliberate divergence, kept here).
#
# ONLY A VERSION-BEARING MODULE IS SWEPT, and the rest are COUNTED, not
# dropped: a module with no comparable version cannot be range-filtered, and
# silently omitting it would make the swept count read as the graph size.
#
# The bound on cost is deliberate. One HTTP call per github.com module over
# 235 modules would exhaust an unauthenticated 60/hour budget many times over
# and take minutes, so the graph sweep is capped and reports its own
# truncation. A cap that hid its own effect would be the false-clean shape
# this whole file is written against, so an unswept remainder reads as
# unswept.
# ---------------------------------------------------------------------------
img_extra="$OUT_DIR/image-extra.tsv"
: > "$img_extra"
img_targets="$OUT_DIR/image-targets.tsv"   # module \t version \t source
: > "$img_targets"
img_swept=0
# "Could have been swept and was not" -- a budget cap, or an endpoint that did
# not answer. A defect, and the thing that alerts.
img_unswept=0
# "This index cannot answer for this module, ever" -- not on github.com, so it
# has no per-repository advisory endpoint, or no comparable semver version.
# A permanent scope limit, reported but never alerted on: 74 of this image's
# 236 graph modules are in this class, so counting them as unswept would make
# that counter permanently non-zero and therefore unreadable.
img_out_of_scope=0
img_graph_state="not-run"
img_graph_total=0
img_graph_seen=0
img_unavailable=""
# Derived from the available GitHub budget, not fixed. A token lifts the
# advisory API from 60 requests/hour/IP to 5000, and this image's graph has
# ~162 sweepable modules: one number cannot serve both. A fixed 60 left >=102
# modules unswept on EVERY authenticated run, which turned `image_unswept`
# into an always-on signal -- the alert fatigue this report had already had
# removed once (T-0651) -- and made "an unswept component is not a clean
# component" vacuous by applying it to two thirds of the graph by design.
#
# Unauthenticated, the cap is real and the remainder is honestly reported as
# unswept. PINWATCH_GRAPH_CAP overrides either way, which is how the tests
# drive the named-targets-only path.
if [ -n "${PINWATCH_GRAPH_CAP:-}" ]; then
  GRAPH_SWEEP_CAP="$PINWATCH_GRAPH_CAP"
elif [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
  GRAPH_SWEEP_CAP=400
else
  GRAPH_SWEEP_CAP=40
fi

# --- the base image -------------------------------------------------------
# Both FROM lines are read and reconciled. They are the same version today and
# the Dockerfile's own comments assume so, but a bump that moved only one of
# them would ship a binary built against one Caddy and a runtime image from
# another, and that must be a loud finding rather than a coin toss over which
# line the parser happened to read first.
base_builder="$(clean_scalar "$(sed -n 's/^FROM .*[[:space:]]caddy:\([0-9][^[:space:]]*\)-builder[[:space:]].*$/\1/p' \
  "$DOCKERFILE" | head -1)")"
base_runtime="$(clean_scalar "$(sed -n 's/^FROM[[:space:]]\+caddy:\([0-9][^[:space:]]*\)-alpine[[:space:]]*$/\1/p' \
  "$DOCKERFILE" | head -1)")"
if [ -z "$base_builder" ] && [ -z "$base_runtime" ]; then
  # The core of the image being unswept is the exact gap T-0669 closed, so a
  # parser that can no longer find it is an error, not a silent skip.
  echo "could not parse a \`FROM caddy:<version>-*\` base image out of $DOCKERFILE; the base image is the core of this image and was NOT swept for advisories" >> "$errors"
else
  if [ -n "$base_builder" ] && [ -n "$base_runtime" ] \
     && [ "$base_builder" != "$base_runtime" ]; then
    echo "the builder base is \`caddy:$base_builder\` but the runtime base is \`caddy:$base_runtime\`; the binary and the image it ships in are built on different Caddy versions" >> "$errors"
  fi
  printf '%s\t%s\t%s\n' "github.com/caddyserver/caddy" \
    "${base_builder:-$base_runtime}" "base image" >> "$img_targets"
fi

# --- --also targets -------------------------------------------------------
for t in $EXTRA_TARGETS; do
  case "$t" in
    *@*) printf '%s\t%s\t%s\n' "${t%@*}" "${t##*@}" "--also" >> "$img_targets" ;;
    *) die "--also expects module@version, got: $t" ;;
  esac
done

# --- the built binary's module graph --------------------------------------
# `image:<ref>` extracts the binary from a built image. `docker create` +
# `docker cp` rather than `docker run`: the published image is distroless with
# no shell, so there is nothing to exec, and it has no `--version` flag either
# (passing one boots the server). A missing docker or a failed extraction is
# reported as the graph not having been read.
if [ -n "$BINARY" ] && [ -z "$FIXTURE" ]; then
  bin_path="$BINARY"
  case "$BINARY" in
    image:*)
      img_ref="${BINARY#image:}"
      bin_path=""
      if ! command -v docker >/dev/null 2>&1; then
        img_graph_state="error"
        echo "--binary names a container image but docker is not available; the module graph was NOT swept" >> "$errors"
      else
        bin_cid="$(docker create "$img_ref" 2>/dev/null || true)"
        if [ -n "$bin_cid" ]; then
          if docker cp "$bin_cid:/usr/bin/caddy" "$OUT_DIR/caddy-bin" >/dev/null 2>&1; then
            bin_path="$OUT_DIR/caddy-bin"
          fi
          docker rm -f "$bin_cid" >/dev/null 2>&1 || true
        fi
        if [ -z "$bin_path" ]; then
          img_graph_state="error"
          echo "could not extract /usr/bin/caddy from image '$(clean_scalar "$img_ref")'; the module graph was NOT swept" >> "$errors"
        fi
      fi ;;
  esac

  if [ -n "$bin_path" ]; then
    if [ ! -f "$bin_path" ]; then
      img_graph_state="error"
      echo "--binary '$(clean_scalar "$bin_path")' does not exist; the module graph was NOT swept" >> "$errors"
    elif ! command -v go >/dev/null 2>&1; then
      img_graph_state="error"
      echo "go is not available, so \`go version -m\` could not read the module graph; the graph was NOT swept" >> "$errors"
    else
      # `mod` is the main module, `dep` the dependencies; both ship code.
      # `=>` lines are REPLACEMENTS and are deliberately excluded from the
      # version comparison and counted as unswept instead: the version on a
      # replaced module describes upstream, not the code in the binary, which
      # is the same reason pass 1 reports a `--with` local replacement rather
      # than comparing it.
      graph_raw="$OUT_DIR/module-graph.txt"
      if ! go version -m "$bin_path" > "$graph_raw" 2>/dev/null \
         || ! grep -qE '^[[:space:]]*(dep|mod)[[:space:]]' "$graph_raw"; then
        img_graph_state="error"
        echo "\`go version -m\` read no module graph out of '$(clean_scalar "$bin_path")' (not a Go binary, or stripped of build info); the graph was NOT swept" >> "$errors"
      else
        img_graph_state="ok"
        img_graph_total="$(awk '$1=="dep"||$1=="mod"{n++} END{print n+0}' "$graph_raw")"
        # Only github.com modules have a repo-scoped endpoint to ask, and only
        # a plain semver version can be range-compared. Everything else is
        # counted as unswept below rather than quietly skipped.
        awk '($1=="dep"||$1=="mod") && $2 ~ /^github\.com\// && $3 ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ \
             { printf "%s\t%s\tmodule graph\n", $2, $3 }' "$graph_raw" >> "$img_targets"
        # Everything the filter above dropped is OUT OF SCOPE, not unswept:
        # a module not on github.com has no per-repository advisory endpoint,
        # and one without a plain semver version cannot be range-compared.
        # Counted rather than dropped silently, so the report can say how much
        # of the graph this index structurally cannot answer for -- but kept
        # out of `img_unswept`, which must mean "a defect" to stay readable.
        img_out_of_scope=$(( img_out_of_scope + $(awk '
          ($1=="dep"||$1=="mod") && !($2 ~ /^github\.com\// && $3 ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) {n++}
          END{print n+0}' "$graph_raw") ))
      fi
    fi
  fi
elif [ -z "$FIXTURE" ]; then
  img_unavailable="no built binary was supplied (\`--binary\`), so the image's module graph was not swept; only the base image and the \`--with\` pins above were checked"
fi

# --- sweep the collected targets -----------------------------------------
# Sorted and de-duplicated: the graph legitimately contains a module that is
# also a `--with` pin, and a module can appear under two major-version paths.
# A target already covered by the pin table is swept anyway — pass 4 asks the
# same endpoint for it, and the de-duplication at the end of this loop drops
# the repeat by GHSA id rather than by trusting the two passes to agree.
if [ -s "$img_targets" ] && [ -z "$FIXTURE" ] && [ "${PINWATCH_SKIP_GITHUB:-0}" != "1" ]; then
  # Sorted and de-duplicated, then ORDERED BY PRIORITY: the base image and any
  # explicit `--also` target are swept BEFORE the graph bulk.
  #
  # This ordering is load-bearing, not cosmetic. With a plain `sort -u` the
  # targets came out alphabetically, so a 236-module graph spent the whole
  # unauthenticated 60/hour GitHub budget on modules beginning a-c and never
  # reached `caddyserver` -- the base image, the single component this sweep
  # exists to cover, unswept on a run that named it explicitly. Measured
  # before fixing: 27 swept, 137 unswept, and the acceptance fixture reporting
  # 0 of its 5 advisories. The run did not read clean (the remainder is
  # counted and reaches `error`), so this was a priority bug and not a false
  # clean -- but a sweep whose most important target is the one it drops is
  # not much better. Rate limiting is normal here, so what gets dropped must
  # be the least important thing, by construction.
  sort -u "$img_targets" \
    | awk -F'\t' '{ print ($3 == "module graph" ? 1 : 0) "\t" $0 }' \
    | sort -s -k1,1n | cut -f2- > "$img_targets.sorted" \
    && mv "$img_targets.sorted" "$img_targets"

  i_gh_auth=()
  i_gh_tok="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  [ -n "$i_gh_tok" ] && i_gh_auth=(-H "Authorization: Bearer $i_gh_tok")

  while IFS=$'\t' read -r i_mod i_ver i_src; do
    [ -n "$i_mod" ] && [ -n "$i_ver" ] || continue
    # The base-image row is swept unconditionally; graph rows are capped.
    # The cap exists to bound the GRAPH, which is 235 modules. The base image
    # and an explicit `--also` target are named requests, not graph bulk, so
    # they are never capped -- capping an `--also` made the acceptance fixture
    # report zero findings for a version with five, which is the shape of
    # false clean this file is written against.
    if [ "$i_src" = "module graph" ] && [ "$img_graph_seen" -ge "$GRAPH_SWEEP_CAP" ]; then
      img_unswept=$((img_unswept+1))
      continue
    fi
    # Not a github.com path with a usable owner/repo: there is no
    # per-repository advisory endpoint for it, which is a permanent scope
    # limit rather than a sweep that failed. See img_out_of_scope.
    case "$i_mod" in
      github.com/*/*) ;;
      *) img_out_of_scope=$((img_out_of_scope+1)); continue ;;
    esac
    i_owner="$(printf '%s' "$i_mod" | cut -d/ -f2)"
    i_repo="$(printf '%s' "$i_mod" | cut -d/ -f3)"
    printf '%s' "$i_owner/$i_repo" | grep -qE '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' \
      || { img_out_of_scope=$((img_out_of_scope+1)); continue; }
    case "$i_owner/$i_repo" in *..*) img_out_of_scope=$((img_out_of_scope+1)); continue ;; esac

    i_body="$(curl -fsS --max-time 25 \
      -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' \
      "${i_gh_auth[@]+"${i_gh_auth[@]}"}" \
      "https://api.github.com/repos/$i_owner/$i_repo/security-advisories?per_page=100" 2>/dev/null || true)"
    # An array is the only shape that means "this is the advisory list". A
    # rate-limit or error object is a JSON object, and reading it as an empty
    # list would say "no advisories" — the inversion this file exists against.
    if [ -z "$i_body" ] || ! jq -e 'type == "array"' <<<"$i_body" >/dev/null 2>&1; then
      img_unswept=$((img_unswept+1))
      [ -z "$img_unavailable" ] && img_unavailable="GitHub's advisory API did not return a list for at least one module of the image (rate limit, or no token), so the image sweep is incomplete"
      continue
    fi
    img_swept=$((img_swept+1))
    [ "$i_src" = "module graph" ] && img_graph_seen=$((img_graph_seen+1))

    while IFS= read -r -d '' i_rec; do
      case "$i_rec" in *$'\037'*) ;; *) continue ;; esac
      i_ghsa="${i_rec%%$'\037'*}";  i_rest="${i_rec#*$'\037'}"
      i_cve="${i_rest%%$'\037'*}";  i_rest="${i_rest#*$'\037'}"
      i_sev="${i_rest%%$'\037'*}";  i_rest="${i_rest#*$'\037'}"
      i_range="${i_rest%%$'\037'*}"; i_patched="${i_rest#*$'\037'}"
      [ -n "$i_ghsa" ] || continue

      # THE COUNT-INFLATION GUARD (item 3, T-0645/T-0660). Three of Caddy's
      # eight CVE-less advisories are bounded strictly below the shipped
      # version and do not apply. Reporting eight where five apply is as wrong
      # as reporting zero: a reader who checks one row, finds it already fixed,
      # and stops believing the rest is the failure this guard prevents. Same
      # shared filter as pass 4, so the two reports cannot disagree.
      range_excludes_version "$i_range" "$i_ver" && continue
      # The advisory's own stated fix is already in this version. Independent
      # of the range text, and the only exclusion that can place a range no
      # parser can read -- which on this repo is five of the rows the range
      # filter conservatively keeps. See `patch_already_in_version`.
      patch_already_in_version "$i_patched" "$i_ver" && continue

      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$i_mod" "$i_ver" "$(clean_scalar "$i_ghsa")" \
        "$(clean_scalar "${i_cve:-—}")" "$(clean_scalar "${i_sev:-?}")" \
        "$(clean_scalar "${i_range:-?}")" "$(clean_scalar "${i_patched:-—}")" >> "$img_extra"
    done < <(jq -j --arg mod "$i_mod" '
      def pw_norm: ascii_downcase | gsub("\\s+$"; "") | sub("^https?://"; "") | sub("/+$"; "");
      def pw_is_modpath: test("^[a-z0-9.-]+\\.[a-z]{2,}(:[0-9]+)?/[^ ]+$");
      def pw_demaj: sub("/v[0-9]+$"; "");
      def pw_hasmaj: test("/v[0-9]+$");

      .[]
      | . as $a
      | (.vulnerabilities // [])[]
      # The SAME matching discipline as pass 4, and for the same reason
      # (T-0666): a full module path is the one spelling that can be compared
      # exactly, and comparing it loosely attached go-jose v3 rows to a v4 pin
      # and reported the version that PATCHES all five as vulnerable. Two
      # different /vN suffixes never match. The containment arm is kept so an
      # advisory naming a package inside a module still matches the module.
      #
      # NO APOSTROPHES IN THESE COMMENTS: they sit inside a single-quoted
      # shell argument, so one apostrophe ends the jq program and bash parses
      # the rest as shell, surfacing as a bash error pointing at a jq line.
      | (.package.name // "" | pw_norm) as $pname
      | ($mod | pw_norm) as $m
      | select(
          if ($pname | pw_is_modpath) then
            ($pname == $m)
            or ((($pname | pw_demaj) == ($m | pw_demaj))
                and ((($pname | pw_hasmaj) | not) or (($m | pw_hasmaj) | not)))
            or ($pname | startswith($m + "/"))
            or ($m | startswith($pname + "/"))
          else
            ($pname | test("(^|[/ ])" + ($m | split("/") | .[2] | gsub("\\."; "\\\\.")) + "($|[/ @])"))
            or ($pname | test($m | gsub("\\."; "\\\\.")))
          end)
      # `patched_versions`, NOT `first_patched_version` (T-0660). The
      # authoritative-looking field is frequently null: on all five Caddy
      # 2.11.7 advisories `first_patched_version` is null while
      # `patched_versions` carries the real fix. Reading the null one filed an
      # available HIGH fix as an unfixable residual.
      | [ ($a.ghsa_id // ""), ($a.cve_id // ""), ($a.severity // ""),
          (.vulnerable_version_range // ""), (.patched_versions // "") ]
      | join("\u001f") + "\u0000"' <<<"$i_body" 2>/dev/null)
  done < "$img_targets"

  # De-duplicate on module+GHSA: a module reached by two paths (a `--with` pin
  # that is also in the graph, or two major-version spellings) must not render
  # as two findings.
  if [ -s "$img_extra" ]; then
    # Keyed on module+version+GHSA, NOT the whole line. A GitHub advisory has
    # one `vulnerabilities` entry per affected package, and a module that
    # publishes many packages produces many entries for one advisory:
    # aws-sdk-go-v2 rendered the same GHSA-3jcv-796g-cpjg four times with four
    # different ranges, which a reader counts as four findings. Every entry is
    # still PUT THROUGH the range filter above -- any one of them covering the
    # shipped version is a genuine hit -- and only the rendering is collapsed,
    # to the first entry that survived. `sort -u` on the full line cannot do
    # this, because the lines differ in the range column.
    sort -u "$img_extra" | awk -F'\t' '!seen[$1 FS $2 FS $3]++' \
      > "$img_extra.dedup" && mv "$img_extra.dedup" "$img_extra"
  fi
elif [ "${PINWATCH_SKIP_GITHUB:-0}" = "1" ] && [ -z "$FIXTURE" ]; then
  img_unavailable="the image advisory sweep was disabled via PINWATCH_SKIP_GITHUB, so neither the base image nor the module graph was checked"
fi

# The base image is the core of this image, so "was it swept" must be a fact in
# the output and not something a reader infers from the absence of a row.
img_base_state="not-swept"
if [ -s "$img_targets" ] \
   && awk -F'\t' '$3=="base image"{found=1} END{exit !found}' "$img_targets" \
   && [ "$img_swept" -gt 0 ]; then
  img_base_state="swept"
fi

# ---------------------------------------------------------------------------
# Verdict + report.
# ---------------------------------------------------------------------------
behind=0; advisories=0; unresolved=0; moved=0; adv_unknown=0; adv_partial=0
floors_ack=0; floors_expired=0
floors_report="$OUT_DIR/floors-report.tsv"
: > "$floors_report"
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
    # `asked` must mean "this question reached OSV and OSV answered", not
    # "we had a value we could have asked about". Deriving it from the field
    # being non-empty made the two equivalent only by accident: the version
    # query carries an extra `$3 != "unresolved"` guard the commit query does
    # not, so the batch filters are already asymmetric, and any further drift
    # would let a row that was never in the batch read asked=2 and render the
    # clean em dash reserved for "both questions asked and clean". Presence of
    # the key line in osv_hits is the only evidence that the question was put.
    if [ -n "$osv_version" ] \
       && awk -F'\t' -v m="$module" -v v="$osv_version" \
            '$1=="v" && $2==m && $3==v {found=1} END{exit !found}' "$osv_hits"; then
      asked=$((asked+1))
      adv_v="$(clean_scalar "$(awk -F'\t' -v m="$module" -v v="$osv_version" \
        '$1=="v" && $2==m && $3==v {print $4; exit}' "$osv_hits")")"
      [ -n "$adv_v" ] && adv="$adv_v"
    fi
    if [ -n "$osv_commit" ] \
       && awk -F'\t' -v c="$osv_commit" \
            '$1=="c" && $2==c {found=1} END{exit !found}' "$osv_hits"; then
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

  # -------------------------------------------------------------------------
  # An acknowledged floor (T-0651). Consulted only for a row that is otherwise
  # exactly `behind`, and only after the advisory count above has already been
  # taken, so the ordering carries two guarantees:
  #
  #   - exit 2 still beats an acknowledged floor. `advisories` was incremented
  #     before this block can run, and an ADVISORY row is excluded here by the
  #     state test, so an acknowledged pin that turns out to be vulnerable
  #     reports as an advisory with its floor noted — not quietly.
  #   - nothing else is silenced. `unresolved`, `unknown`, `moved` and
  #     `partial` rows pass through untouched: a floor says "this pin is behind
  #     on purpose", which is a claim about staleness and about nothing else.
  #
  # RE-ARMING is the other half, and it is what separates this from an ignore
  # list. The declaration records the upstream version the decision was taken
  # against; once upstream moves PAST that version the decision was taken on
  # facts that no longer hold, so the acknowledgement expires and the row goes
  # back to `behind` with the expiry stated. An acknowledgement that silently
  # outlives its reasoning is worse than the noise it replaces (T-0646).
  floor_reason=""; floor_against=""; floor_ref=""; floor_state=""
  if [ "$state" = "behind" ] && [ -s "$floors_file" ]; then
    floor_hit="$(awk -F'\t' -v m="$arg" -v v="$pinned" \
      '$1==m && $2==v {print; exit}' "$floors_file")"
    if [ -n "$floor_hit" ]; then
      floor_against="$(printf '%s' "$floor_hit" | cut -f3)"
      floor_ref="$(printf '%s' "$floor_hit" | cut -f4)"
      floor_reason="$(printf '%s' "$floor_hit" | cut -f5)"
      # Has upstream gone past the version this was decided against? `sort -V`
      # for the same reason the staleness compare uses it: v1.10.0 is newer
      # than v1.9.0 and a string compare gets that backwards. Equality is NOT
      # expiry — the decision covers `against` itself.
      fl_newest="$(printf '%s\n%s\n' "$floor_against" "$latest" | sort -V | tail -1)"
      if [ "$latest" != "$floor_against" ] && [ "$fl_newest" = "$latest" ]; then
        floor_state="expired"
        floors_expired=$((floors_expired+1))
        # Stays `behind`: the row must look exactly like un-reviewed drift
        # again, because that is what it now is.
      else
        floor_state="ack"
        floors_ack=$((floors_ack+1))
        behind=$((behind-1))
        state="floor"
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$arg" "$pinned" "$latest" "$floor_against" "$floor_state" \
        "${floor_ref:+[$floor_ref] }$floor_reason" >> "$floors_report"
    fi
  fi

  up="$latest"
  [ "$latest_time" != "-" ] && { [ "$state" = "behind" ] || [ "$state" = "floor" ]; } \
    && up="$latest (tagged $latest_time)"
  # An acknowledged row stays IN the table and says so. Dropping it would make
  # the report describe fewer pins than the Dockerfile has, which is the
  # silent-exclusion shape this change exists to avoid; the reader should see
  # the pin, see that it is behind, and see that the gap is deliberate.
  [ "$state" = "floor" ] && up="$up — intentional floor"
  [ "$floor_state" = "expired" ] \
    && up="$up — floor EXPIRED (decided against $floor_against)"
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
  if [ "$floors_expired" -gt 0 ]; then
    echo "**$floors_expired intentional floor(s) have EXPIRED and are counted as behind again.** Upstream has moved past the version the decision was recorded against, so the reasoning was taken on facts that no longer hold. Re-take the decision and update \`against=\`, or move the pin."
    echo
  fi
  if [ -s "$floors_report" ]; then
    echo "**Intentional floors.** These pins are behind upstream *on purpose*: a decision was taken, recorded next to the pin as a \`# pin-watch: floor\` directive, and is reproduced here. An acknowledged floor is **not** counted as behind, so it cannot hold the verdict at \`attention\` forever — but it re-arms automatically if upstream moves past the version it was decided against, and an advisory on the pinned version always outranks it:"
    echo
    echo "| module | pinned | upstream | decided against | status | reason |"
    echo "| --- | --- | --- | --- | --- | --- |"
    while IFS=$'\t' read -r f_mod f_pin f_up f_against f_state f_reason; do
      case "$f_state" in
        ack)     f_show="acknowledged" ;;
        expired) f_show="**EXPIRED**" ;;
        *)       f_show="$f_state" ;;
      esac
      printf '| `%s` | `%s` | %s | `%s` | %s | %s |\n' \
        "$f_mod" "$f_pin" "$f_up" "$f_against" "$f_show" "$f_reason"
    done < "$floors_report"
    echo
  fi
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
  # Name the two sets. A row's ABSENCE above only means something for a module
  # in the covered list; for a skipped one it means the question was never put.
  if [ -s "$gh_skipped" ]; then
    echo "**The GitHub cross-check did not cover every pin, so a missing row above is not automatically a cleared one.** ${gh_unavailable:-At least one module could not be reached}. For the modules below the second index was NOT consulted on this run — treat them as unanswered, not clean. The OSV result above is unaffected and still stands on its own for every pin:"
    echo
    echo "| module | pinned | GitHub cross-check |"
    echo "| --- | --- | --- |"
    while IFS=$'\t' read -r s_mod s_pin; do
      printf '| `%s` | `%s` | **skipped** — not asked |\n' "$s_mod" "$s_pin"
    done < "$gh_skipped"
    echo
  elif [ -n "$gh_unavailable" ]; then
    echo "**$gh_unavailable.** The OSV result above still stands on its own; only the independent second opinion is missing."
    echo
  fi
  if [ -s "$gh_covered" ]; then
    echo "<details><summary>Modules the GitHub cross-check did cover ($gh_checked)</summary>"
    echo
    echo "For these the second index answered, so the absence of a row above is a real result from it — the advisory list was read and nothing in it outranked the pin."
    echo
    while IFS=$'\t' read -r c_mod c_pin; do
      printf -- '- `%s` `%s`\n' "$c_mod" "$c_pin"
    done < "$gh_covered"
    echo
    echo "</details>"
    echo
  fi
  # -------------------------------------------------------------------------
  # The image itself — base image + module graph (T-0669).
  # -------------------------------------------------------------------------
  echo "#### The image itself — base image and module graph"
  echo
  echo "The \`--with\` list above is not the image. This section sweeps the two parts it cannot see: the \`FROM caddy:<version>\` base, and every module actually linked into the built binary. Both are checked on GitHub's **per-repository** advisory endpoint, because that is the only place a CVE-less advisory appears — at the 2.11.7 this image once shipped, five advisories were live there while an OSV package+version query at the same version returned **zero** and every one of the five was a 404 on OSV by id."
  echo
  printf -- '- **Base image:** '
  if [ -n "$base_builder" ] || [ -n "$base_runtime" ]; then
    printf '`caddy:%s` → `github.com/caddyserver/caddy` — %s\n' \
      "${base_builder:-$base_runtime}" \
      "$([ "$img_base_state" = "swept" ] && echo 'swept' || echo '**NOT swept**')"
  else
    printf '**could not be parsed from `%s`** — NOT swept\n' "$DOCKERFILE"
  fi
  printf -- '- **Module graph:** '
  case "$img_graph_state" in
    ok)      printf '%s modules in the built binary; %s swept' "$img_graph_total" "$img_swept" ;;
    error)   printf '**could not be read** — see the errors below' ;;
    not-run) printf '**not run** (no `--binary` supplied)' ;;
  esac
  [ "$img_unswept" -gt 0 ] && printf ', **%s not swept**' "$img_unswept"
  [ "$img_out_of_scope" -gt 0 ] \
    && printf ', %s outside this index (not on github.com, or no comparable version)' "$img_out_of_scope"
  echo
  echo
  if [ -s "$img_extra" ]; then
    echo "**Advisories whose range covers a version this image actually ships.** Advisories bounded strictly *below* the shipped version are already excluded — of Caddy's eight CVE-less advisories, three are cleared by the shipped version and reporting eight where five apply would be as wrong as reporting zero (T-0645/T-0660). The ranges below are GitHub's own free text and have **not** been compared mechanically beyond that exclusion; \`fixed in\` is \`patched_versions\`, not the frequently-null \`first_patched_version\`:"
    echo
    echo "| component | version in image | source | GHSA | CVE | severity | affected range | fixed in |"
    echo "| --- | --- | --- | --- | --- | --- | --- | --- |"
    while IFS=$'\t' read -r i_mod i_ver i_ghsa i_cve i_sev i_range i_patched; do
      i_src="$(awk -F'\t' -v m="$i_mod" -v v="$i_ver" '$1==m && $2==v {print $3; exit}' "$img_targets")"
      printf '| `%s` | `%s` | %s | %s | %s | %s | `%s` | %s |\n' \
        "$i_mod" "$i_ver" "${i_src:-?}" "$i_ghsa" "$i_cve" "$i_sev" "$i_range" "$i_patched"
    done < "$img_extra"
    echo
  elif [ "$img_swept" -gt 0 ]; then
    echo "No advisory on the per-repository endpoint covers a version this image ships, across the $img_swept component(s) swept above."
    echo
  fi
  if [ "$img_out_of_scope" -gt 0 ]; then
    echo "**$img_out_of_scope component(s) are outside what this index can answer for.** GitHub's advisory database is keyed on a repository, so a module not hosted on github.com (\`cel.dev\`, \`cloud.google.com\`, \`golang.org/x/…\`) has no endpoint to ask, and a module without a plain semver version cannot be range-compared. This is a known and permanent limit of the second index, **not** a sweep that failed — those modules are still covered by the OSV queries on the pins above where they are pinned. Reported separately so that \`not swept\` keeps meaning \"this could have been checked and was not\"."
    echo
  fi
  if [ "$img_unswept" -gt 0 ]; then
    echo "**$img_unswept component(s) of the image COULD have been swept and were NOT.** A module beyond this run's cap of $GRAPH_SWEEP_CAP graph modules, or one whose endpoint did not answer. An unswept component is not a clean component."
    if [ -z "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
      echo
      echo "This run was **unauthenticated**, so the GitHub advisory API allowed 60 requests/hour and the graph sweep was capped at $GRAPH_SWEEP_CAP modules. Supplying \`GH_TOKEN\`/\`GITHUB_TOKEN\` raises that to 5000/hour, which covers the whole graph; CI already does."
    fi
    echo
  fi
  [ -n "$img_unavailable" ] && { echo "**$img_unavailable.**"; echo; }
  if [ "$adv_unknown" -gt 0 ]; then
    echo "**Advisory status could not be established for $adv_unknown pin(s).** Neither the version-scoped nor the commit-scoped query could be asked, so those rows say nothing about whether an advisory applies. An unchecked pin is not a clean pin."
    echo
  fi
  if [ "$adv_partial" -gt 0 ]; then
    echo "**$adv_partial pin(s) were checked by only one of the two queries.** A version-only check cannot see CVE records that carry no package field (their affected range is a \`GIT\` range keyed on the repo); a commit-only check can miss a curated package range. Those rows are narrower than a — and are marked \`partial\`."
    echo
  fi
  # The image sweep joins this guard, and that is the point of T-0669: for its
  # whole life this sentence could print while the base image carried five
  # unswept advisories, because it only ever described the `--with` pins. An
  # all-clear that is true of a subset and silent about the rest is the shape
  # this file is written against.
  if [ "$advisories" -eq 0 ] && [ "$behind" -eq 0 ] && [ "$moved" -eq 0 ] \
     && [ "$malformed_rows" -eq 0 ] && [ "$adv_unknown" -eq 0 ] \
     && [ "$adv_partial" -eq 0 ] && [ "$floors_expired" -eq 0 ] \
     && [ ! -s "$errors" ] && [ ! -s "$unpinned_file" ] \
     && [ ! -s "$gh_extra" ] && [ -z "$gh_unavailable" ] \
     && [ ! -s "$replaced_file" ] && [ -z "$tag_now_ok" ] \
     && [ ! -s "$img_extra" ] && [ "$img_unswept" -eq 0 ] \
     && [ "$img_out_of_scope" -eq 0 ] \
     && [ -z "$img_unavailable" ] && [ "$img_graph_state" = "ok" ] \
     && [ "$img_base_state" = "swept" ]; then
    # The all-clear must not claim more than it checked. With an acknowledged
    # floor present, "every pin is at upstream's newest release" is false, and
    # a sentence a reader can catch being wrong is how a report loses its
    # authority; so the acknowledged pins are named in the same breath.
    if [ "$floors_ack" -gt 0 ]; then
      echo "Every pin is at upstream's newest release except $floors_ack acknowledged intentional floor(s) listed above, and for every pin both the version-scoped and the commit-scoped advisory query were asked and came back clean. GitHub's advisory database ($gh_checked module(s) cross-checked) adds nothing OSV did not already report. The image itself was swept too: the \`caddy:${base_builder:-$base_runtime}\` base and all $img_graph_total modules of the built binary ($img_swept component(s) checked on the per-repository endpoint), with no advisory covering a shipped version."
    else
      echo "Every pin is at upstream's newest release, and for every pin both the version-scoped and the commit-scoped advisory query were asked and came back clean. GitHub's advisory database ($gh_checked module(s) cross-checked) adds nothing OSV did not already report. The image itself was swept too: the \`caddy:${base_builder:-$base_runtime}\` base and all $img_graph_total modules of the built binary ($img_swept component(s) checked on the per-repository endpoint), with no advisory covering a shipped version."
    fi
  fi
  echo
  # Which tree did we actually read? This script reads $DOCKERFILE by plain
  # path, so say so -- a dirty file means the verdict describes uncommitted
  # pins. Disclosure, not relocation: see the design rule in the header.
  tree_note="$DOCKERFILE"
  if git rev-parse --git-dir >/dev/null 2>&1; then
    if git diff --quiet -- "$DOCKERFILE" 2>/dev/null; then
      tree_note="$DOCKERFILE (clean vs HEAD)"
    else
      tree_note="$DOCKERFILE (**UNCOMMITTED CHANGES** vs HEAD -- these pins are not what HEAD builds)"
    fi
  fi
  echo "<sub>Versions from \`$PROXY\`; advisories from \`$OSV\`, queried twice per pin — by module+pinned version, and by the pinned version's upstream commit so that \`GIT\`-range records with no package field are visible too. Untagged pins compared against upstream \`HEAD\`. Read from \`$tree_note\`.</sub>"
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
# An ACKNOWLEDGED floor is deliberately absent from this list: it is the one
# finding this script is now allowed to be quiet about, which is the whole of
# T-0651. An EXPIRED one is listed explicitly even though it is also counted
# in `behind` — the two counters move independently, and a later change to
# either must not be able to make an expired acknowledgement silent. A
# malformed or orphaned directive reaches `error` through `-s "$errors"`
# above, because a floor that cannot be READ must not read as no floor at all.
# THE IMAGE SWEEP (T-0669) joins both of the lower arms, and which arm each
# part lands in is deliberate:
#
#   - A FINDING reaches `attention`, not `advisory`. The ranges are GitHub's
#     free text, so this is the same deliberate divergence T-0634 settled for
#     the pin cross-check: exit 2 stays reserved for OSV's machine-checked
#     matching, and a prose range cannot earn it. A CVE-less advisory on the
#     base image is invisible to OSV by construction, so demanding OSV
#     confirmation before exit 2 would mean this class never reaches it — but
#     inventing exit 2 from a parsed sentence is how a wrong parse excuses or
#     invents a finding. `attention` plus a named table is the honest level.
#   - AN UNSWEPT COMPONENT reaches `error`, exactly as an unaskable OSV
#     question does. A graph that could not be read, a base image that could
#     not be parsed and a capped remainder are all "we did not look", and this
#     file's one rule is that not looking must not read as clean.
#
# `img_graph_state=not-run` is the one case that stays at `attention`: the
# caller did not ask for a graph sweep, which is a narrower run rather than a
# broken one — and the report says so in its own sentence. The workflow passes
# `--binary`, so a CI run that silently stopped doing so still shows up.
if   [ "$advisories" -gt 0 ]; then verdict="advisory"; rc=2
elif [ "$unresolved" -gt 0 ] || [ "$osv_failed" -eq 1 ] \
  || [ "$malformed_rows" -gt 0 ] || [ "$adv_unknown" -gt 0 ] \
  || [ "$img_unswept" -gt 0 ] || [ "$img_graph_state" = "error" ] \
  || [ -s "$errors" ]; then verdict="error"; rc=3
elif [ "$behind" -gt 0 ] || [ "$moved" -gt 0 ] || [ -n "$tag_now_ok" ] \
  || [ "$floors_expired" -gt 0 ] \
  || [ "$adv_partial" -gt 0 ] || [ -s "$gh_extra" ] || [ -n "$gh_unavailable" ] \
  || [ -s "$img_extra" ] || [ -n "$img_unavailable" ] \
  || [ "$img_graph_state" = "not-run" ] \
  || [ -s "$unpinned_file" ] || [ -s "$replaced_file" ] \
  || [ -s "$notices" ]; then verdict="attention"; rc=1
else verdict="ok"; rc=0
fi

cat "$report"
echo "verdict=$verdict"

if [ "$EMIT_JSON" -eq 1 ]; then
  jq -n --arg v "$verdict" --argjson b "$behind" --argjson a "$advisories" \
        --argjson m "$moved" --argjson u "$unresolved" \
        --argjson au "$adv_unknown" --argjson ap "$adv_partial" \
        --argjson fa "$floors_ack" --argjson fe "$floors_expired" \
        --argjson gx "$(wc -l < "$gh_extra" | tr -d ' ')" \
        --argjson gc "$gh_checked" \
        --argjson gs "$(wc -l < "$gh_skipped" | tr -d ' ')" \
        --argjson ix "$(wc -l < "$img_extra" | tr -d ' ')" \
        --argjson iu "$img_unswept" --argjson isw "$img_swept" \
        --argjson ios "$img_out_of_scope" \
        --argjson igt "$img_graph_total" \
        --arg ig "$img_graph_state" --arg ib "$img_base_state" \
        --arg ibv "${base_builder:-${base_runtime:-}}" \
        '{verdict:$v, behind:$b, advisories:$a, moved:$m, unresolved:$u,
          advisory_unknown:$au, advisory_partial:$ap,
          floors_acknowledged:$fa, floors_expired:$fe,
          github_only:$gx, github_modules_checked:$gc,
          github_modules_skipped:$gs,
          image_findings:$ix, image_unswept:$iu, image_swept:$isw,
          image_out_of_scope:$ios,
          image_graph:$ig, image_graph_modules:$igt,
          image_base:$ib, image_base_version:$ibv}' \
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
    echo "floors_acknowledged=$floors_ack"
    echo "floors_expired=$floors_expired"
    echo "github_only=$(wc -l < "$gh_extra" | tr -d ' ')"
    echo "github_modules_checked=$gh_checked"
    echo "github_modules_skipped=$(wc -l < "$gh_skipped" | tr -d ' ')"
    echo "image_findings=$(wc -l < "$img_extra" | tr -d ' ')"
    echo "image_unswept=$img_unswept"
    echo "image_out_of_scope=$img_out_of_scope"
    echo "image_swept=$img_swept"
    echo "image_graph=$img_graph_state"
    echo "image_base=$img_base_state"
    echo "report<<$PINREPORT_DELIM"
    cat "$report"
    echo "$PINREPORT_DELIM"
  } >> "$GITHUB_OUTPUT"
fi
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$report" >> "$GITHUB_STEP_SUMMARY"

exit "$rc"
