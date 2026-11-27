#!/usr/bin/env bash
# Assert the Dockerfile's security FLOORS against the BUILT BINARY (T-0667).
#
#   assert-floor-versions.sh --binary /usr/bin/caddy [--dockerfile PATH]
#   assert-floor-versions.sh --binary image:applegater/caddyui-caddy:stable
#   assert-floor-versions.sh --binary … --expect "pkg@v1.2.3 pkg2@v4.5.6"
#
#   --expect  space-separated `package@version` list that the Dockerfile being
#             read MUST contain. Guards the case where the file read is not
#             the file built: `docker build -f Dockerfile.variant .` builds
#             the variant, but a `COPY Dockerfile.caddy` inside it fetches the
#             CONTEXT's copy, so the assertion would check one file's pins
#             against the other file's binary and report a clean run. Measured
#             while wiring this in: a variant demanding crowdsec v1.9.0 built
#             clean and produced a byte-identical digest, because the edited
#             directive was never read. A mismatch here is exit 2.
#             Only checks the pins NAMED in the list; it is a tripwire for
#             reading the wrong file, not a second pin list.
#   --min-floors N
#             fewer than N parsed `# pin-watch: floor|security` directives is
#             exit 2 (T-0906). Dockerfile.caddy passes ARG FLOOR_MIN.
#   --strict  also makes zero directives exit 2 instead of "nothing to assert".
#
# Why this exists
# ---------------------------------------------------------------------------
# Dockerfile.caddy's build ends with:
#
#   && if grep 'go: downgraded' /tmp/xcaddy.log; then ... exit 1; fi
#
# That guard is correct and catches exactly half of what matters. The pins at
# the top of the `--with` list are version FLOORS: `go get pkg@ver` sets that
# version, later plugins raise it via MVS but never lower it, and the grep
# fails the build if anything is pulled DOWN. What the grep cannot see is a
# plugin raising a floor PAST its pin, because:
#
#   - `go: upgraded` is a different word, and
#   - a module that is only being ADDED at a higher version prints no
#     upgrade line at all.
#
# For an ordinary dependency, upward movement is harmless. For a SECURITY
# floor it is a change to a reviewed decision. A floor pinned at the exact
# version that fixes a CVE is a statement about which code ships; when a
# plugin lifts it, the Dockerfile says one version, the binary contains
# another, and nothing says so.
#
# Measured on the published image (T-0667, reproducing T-0665):
#
#   Dockerfile floor:  crowdsec/pkg/apiclient @v1.7.8
#   go version -m:     github.com/crowdsecurity/crowdsec  v1.8.1
#
# A full xcaddy build of that exact `--with` sequence succeeds and prints no
# `go: downgraded` line. caddy-image-gate.sh diffs `caddy list-modules
# --versions`, which only lists CADDY MODULES -- crowdsec's pkg/apiclient is a
# library and has no row there, so a floor lift is invisible to the gate too.
# check-pinned-modules.sh reads the Dockerfile TEXT, so it reports the written
# pin and is accurate about intent and silent about outcome. `go version -m`
# on the artefact is the only thing that knows, and until this script nothing
# consulted it.
#
# What it does
# ---------------------------------------------------------------------------
# For every `# pin-watch: floor` directive in the Dockerfile, compare the
# pinned version against the version LINKED INTO THE BINARY:
#
#   below the floor  -> FAIL (exit 1). The thing the floor exists to prevent.
#                       The downgrade grep should have caught this; if it did
#                       not, the artefact says it happened anyway.
#   above the floor  -> REPORT as a named divergence (exit 0 by default,
#                       exit 1 under --strict). Expected to be reviewed, not
#                       silently absorbed.
#   equal            -> ok.
#
# Both directions are checked against the ARTEFACT rather than the log, so the
# answer does not depend on go's choice of wording.
#
# THE PIN LIST IS NOT MAINTAINED HERE. It comes from directives that live next
# to the pins in the Dockerfile, so there is one source of truth and a pin
# cannot be added while staying invisible to this assertion. A second
# hand-kept list is precisely the thing that rots -- trap 5 in
# check-pinned-modules.sh documents that happening.
#
# TWO DIRECTIVE KINDS ARE ASSERTED, and the distinction is load-bearing:
#
#   # pin-watch: floor     pin is deliberately BEHIND upstream
#   # pin-watch: security  pin is a SECURITY MINIMUM
#
# Both name a version that must hold in the artefact, so both are checked
# here identically. They differ in what they claim about UPSTREAM, which is
# check-pinned-modules.sh's question: a `floor` is exempt from the staleness
# finding because the decision has been taken, a `security` pin is not.
#
# Reusing `floor` alone for this would have been less code and the wrong
# model. The three security pins added here (x/net, chi, go-jose) are AT
# current upstream, and marking them `floor` would file them under
# "Intentional floors" and exempt them from a staleness check they should be
# subject to -- an acknowledgement covering something nobody acknowledged.
# Before T-0667 only the crowdsec pin carried a directive at all, so an
# assertion keyed on `floor` alone would have covered ONE of the four
# security pins and reported a clean run for the other three, which is this
# file's own failure mode reproduced inside the fix.
#
# Both kinds are read from the file, so the count is whatever the Dockerfile
# declares rather than a number written here: as of this commit that is five
# (`floor` on crowdsec/pkg/apiclient and caddy-dns/route53, `security` on
# x/net/http2, go-chi/chi/v5 and go-jose/v4). Do not treat that total as
# fixed -- adding a directive changes it, which is why the coverage count is
# asserted in scripts/test-floor-versions.sh case 17 rather than assumed.
#
# A `--with` ARGUMENT IS A PACKAGE PATH; `go version -m` REPORTS MODULE PATHS.
# This is trap 1 from check-pinned-modules.sh, and it bites harder here,
# because a lookup miss has no network error to announce it -- it is simply an
# absent row:
#
#   --with github.com/crowdsecurity/crowdsec/pkg/apiclient  (package)
#   dep    github.com/crowdsecurity/crowdsec                (module)
#
# Verified on the shipped binary: grep for the package path returns 0 rows.
# So the path is walked up one element at a time until a `dep`/`mod` row
# matches. `/v2`, `/v5` major-version suffixes are module paths in their own
# right; the walk stops at the first match, which handles them without a
# special case (go-chi/chi/v5 matches at full length).
#
# A FLOOR WHOSE MODULE IS NOT IN THE BINARY IS AN ERROR, NOT A PASS. That is
# the fail-open shape this whole file exists to avoid: "no row matched" and
# "the row matched and was fine" must never produce the same exit status. It
# means the pin no longer corresponds to anything linked, which is a finding.
#
# Exit status:
#   0  every floor is satisfied (equal, or above and merely reported)
#   1  a floor is violated (below pin), or a divergence under --strict
#   2  the assertion could not run (no binary, no go, unreadable Dockerfile,
#      a floor naming a module the binary does not contain)
#
# Requires: go (for `go version -m`). docker only for `image:<ref>`.
#
# IT MUST KEEP RUNNING UNDER BUSYBOX ASH. The shebang says bash and bash is
# what runs it locally and in CI, but Dockerfile.caddy invokes it inside the
# `caddy:*-builder` stage, and THAT IMAGE HAS NO BASH -- only Alpine's
# busybox `sh` and `go`. So the build calls it as `sh assert-floor-versions.sh`
# and every construct here has to work in both.
#
# This is a real constraint, not a note: busybox ash happens to support the
# `${v//a/b}` substitutions and `$'\t'` literals used below, so the current
# file runs identically under both shells -- but that is a property that has
# to hold, not one the shebang enforces. A future edit reaching for a
# bash-only feature (arrays, `[[ ]]`, `declare`) would pass every local test
# and fail only inside `docker build`, where the error reads as a broken
# build rather than a broken check. scripts/test-floor-versions.sh case 19
# runs the real file under busybox ash to keep that from landing silently.
set -uo pipefail

DOCKERFILE="Dockerfile.caddy"
BINARY=""
STRICT=0
JSON=0
# Space-separated `pkg@version` list naming the pins THIS build actually used,
# cross-checked against the Dockerfile that was read. See --expect below.
EXPECT=""
# Minimum number of parsed floor/security directives. Empty = no floor on the
# count. See --min-floors below (T-0906).
MIN_FLOORS=""

die() {
  echo "assert-floor-versions: $*" >&2
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "floor_assert=error"
      # Not 0: nothing was established. A 0 here would read as "no floor was
      # violated", which is the false clean this script exists to prevent.
      echo "floor_violations=unknown"
      echo "floor_divergences=unknown"
      echo "floor_checked=unknown"
    } >> "$GITHUB_OUTPUT"
  fi
  exit 2
}

usage() {
  sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --binary)
      [ -n "${2:-}" ] || die "option --binary requires a value"
      BINARY="$2"; shift; shift ;;
    --dockerfile)
      [ -n "${2:-}" ] || die "option --dockerfile requires a value"
      DOCKERFILE="$2"; shift; shift ;;
    --expect)
      [ -n "${2:-}" ] || die "option --expect requires a value"
      EXPECT="$2"; shift; shift ;;
    --min-floors)
      [ -n "${2:-}" ] || die "option --min-floors requires a value"
      case "$2" in *[!0-9]*) die "--min-floors must be a non-negative integer, got '$2'" ;; esac
      MIN_FLOORS="$2"; shift; shift ;;
    --strict) STRICT=1; shift ;;
    --json)   JSON=1;   shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1" ;;
  esac
done

[ -n "$BINARY" ]     || die "--binary is required (a caddy binary, or image:<ref>)"
[ -f "$DOCKERFILE" ] || die "no such file: $DOCKERFILE"
command -v go >/dev/null 2>&1 || die "go is required for \`go version -m\`"

WORK="$(mktemp -d)" || die "cannot create a temp dir"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Resolve the binary. `image:<ref>` extracts /usr/bin/caddy from a built image
# so this can run against a published tag as well as inside the builder stage.
# ---------------------------------------------------------------------------
case "$BINARY" in
  image:*)
    ref="${BINARY#image:}"
    command -v docker >/dev/null 2>&1 || die "docker is required for image:<ref>"
    cid="$(docker create "$ref" 2>/dev/null)" || die "cannot create a container from $ref"
    docker cp "$cid":/usr/bin/caddy "$WORK/caddy" >/dev/null 2>&1 || {
      docker rm "$cid" >/dev/null 2>&1
      die "cannot copy /usr/bin/caddy out of $ref"
    }
    docker rm "$cid" >/dev/null 2>&1
    BINPATH="$WORK/caddy" ;;
  *)
    [ -f "$BINARY" ] || die "no such binary: $BINARY"
    BINPATH="$BINARY" ;;
esac

# ---------------------------------------------------------------------------
# Read the binary's module graph ONCE.
#
# `go version -m` writes its rows to stdout but reports a non-Go file by
# exiting non-zero with nothing useful, so emptiness is checked explicitly: an
# empty graph must not read as "no floor was violated".
# ---------------------------------------------------------------------------
graph="$WORK/graph.txt"
go version -m "$BINPATH" > "$graph" 2>"$WORK/go.err" || true
# `dep` rows are dependencies, `mod` is the main module. Both are legitimate
# targets for a floor, so both are indexed. Fields: <kind> <path> <version>.
mods="$WORK/mods.tsv"
awk '$1=="dep" || $1=="mod" { print $2 "\t" $3 }' "$graph" > "$mods"
mod_count="$(wc -l < "$mods" | tr -d ' ')"
if [ "$mod_count" -eq 0 ]; then
  die "\`go version -m $BINPATH\` listed no modules ($(head -1 "$WORK/go.err" 2>/dev/null || echo 'no error output')); an unreadable binary is not a clean one"
fi

# ---------------------------------------------------------------------------
# Parse the floors out of the Dockerfile.
#
# Same pairing rule as check-pinned-modules.sh: a `# pin-watch: floor`
# directive attaches to the NEXT `--with` line, non-directive comments do not
# break the pairing, and the directive's `pin=` must match the version on that
# line. The match is re-asserted here rather than assumed, because this script
# can be run standalone and a mismatched directive must not silently select
# the wrong version to compare against.
#
# Deliberately a SEPARATE, SMALLER parser than the watcher's: this one needs
# only module+version, runs in the builder stage where curl/jq may not exist,
# and must not fail the build because an unrelated field of the directive is
# malformed. The watcher is the authority on directive VALIDITY and reports
# that in its own run; this script is the authority on the ARTEFACT. A
# directive it cannot read is reported here as unreadable rather than skipped.
# ---------------------------------------------------------------------------
floors="$WORK/floors.tsv"
: > "$floors"
pending=""
pending_line=0
lineno=0
parse_errors=0

while IFS= read -r raw; do
  lineno=$(( lineno + 1 ))
  trim="${raw#"${raw%%[![:space:]]*}"}"
  case "$trim" in
    '#'*)
      marker="${trim#'#'}"
      marker="${marker#"${marker%%[![:space:]]*}"}"
      case "$marker" in
        pin-watch:*)
          body="${marker#*pin-watch:}"
          body="${body#"${body%%[![:space:]]*}"}"
          case "$body" in
            floor|floor' '*|floor$'\t'*|security|security' '*|security$'\t'*)
              # Both kinds name a version that must hold in the artefact, so
              # both are asserted here. They differ in what they claim about
              # UPSTREAM, which is the watcher's question, not this one's:
              #
              #   floor     deliberately behind upstream; also exempt from
              #             the staleness finding (it has been decided).
              #   security  a security MINIMUM, which may be at current
              #             upstream and stays subject to staleness.
              #
              # Collapsing them into one kind would have been less code and
              # the wrong model: three of this Dockerfile's four security
              # pins are AT upstream, and filing those as `floor` would
              # exempt them from the staleness check. See the kind table in
              # check-pinned-modules.sh.
              #
              # A directive of the SECOND kind replaces a pending one rather
              # than stacking: two directives above one pin both describe
              # that pin, and asserting its single linked version twice would
              # double-count it in the totals.
              pending="$body"; pending_line="$lineno" ;;
            # AN UNKNOWN KIND IS A PARSE ERROR, NOT A SKIP. This arm used to be
            # `*) ;;` with a note that the watcher makes it a loud error, which
            # is true and is the wrong place for it: the watcher runs weekly and
            # at gate time, while THIS runs inside every `docker build`, and the
            # whole argument for putting the assertion in the builder stage is
            # that it holds on every build path. Silently ignoring `Floor`,
            # `SECURITY`, `floorx` or `floor:` meant one typo per directive
            # disarmed that pin at build time and the build still exited 0 --
            # and with every directive mistyped, the file reported "nothing to
            # assert" and passed. A line that is shaped like a directive is
            # treated as one; if it cannot be read, it is unread, and the header
            # already promises an unread directive is reported rather than
            # skipped.
            *)
              echo "ERROR: unknown \`# pin-watch:\` kind at line $lineno of $DOCKERFILE: $(printf '%s' "$body" | cut -c1-40) (expected \`floor\` or \`security\`)" >&2
              parse_errors=$(( parse_errors + 1 )) ;;
          esac ;;
      esac
      continue ;;
  esac
  case "$raw" in *--with*) ;; *) continue ;; esac
  [ -n "$pending" ] || continue

  # Same normalisation as the watcher's parser, so a floor declared against a
  # legal spelling (`--with=`, a tab, two spaces, quotes, a replacement) is
  # read identically by both.
  line="${raw//$'\t'/ }"
  line="${line//\"/ }"
  line="${line//\'/ }"
  line="${line/--with=/--with }"
  while case "$line" in *'--with  '*) true ;; *) false ;; esac; do
    line="${line/--with  /--with }"
  done
  arg="${line#*--with }"
  arg="${arg%% *}"
  arg="${arg%\\}"
  case "$arg" in *=*) arg="${arg%%=*}" ;; esac

  dir="$pending"; dir_line="$pending_line"
  pending=""; pending_line=0

  case "$arg" in
    *@*) ;;
    *)
      echo "ERROR: the floor directive at line $dir_line sits above an unpinned --with argument" >&2
      parse_errors=$(( parse_errors + 1 )); continue ;;
  esac
  pkg="${arg%@*}"
  ver="${arg##*@}"

  case "$dir" in security*) kind="security" ;; *) kind="floor" ;; esac
  dpin="$(printf '%s' "$dir" | grep -oE '(^|[[:space:]])pin=[^[:space:]]+' | head -1 | cut -d= -f2-)"
  dref="$(printf '%s' "$dir" | grep -oE 'ref=[^[:space:]]+' | head -1 | cut -d= -f2-)"
  # `pin=` is REQUIRED on both kinds, and for the same reason: without it the
  # directive is paired positionally, so a re-pin silently inherits the old
  # decision and the assertion compares the binary against a version nobody
  # chose. A missing or stale pin= is therefore an error, never a fallback to
  # the version on the line — a fallback would make the protection depend on
  # remembering to use the field, which is how this class of bug returns.
  if [ -z "$dpin" ]; then
    echo "ERROR: the $kind directive for \`$pkg\` at line $dir_line has no pin=; cannot tell which version this decision was taken for" >&2
    parse_errors=$(( parse_errors + 1 )); continue
  fi
  if [ "$dpin" != "$ver" ]; then
    echo "ERROR: the $kind directive at line $dir_line was written for \`$pkg@$dpin\` but the pin below it is \`$ver\`; the acknowledgement did not follow the pin" >&2
    parse_errors=$(( parse_errors + 1 )); continue
  fi
  printf '%s\t%s\t%s\t%s\n' "$pkg" "$ver" "${dref:-none}" "$kind" >> "$floors"
done < "$DOCKERFILE"

if [ -n "$pending" ]; then
  echo "ERROR: the floor directive at line $pending_line is followed by no --with argument" >&2
  parse_errors=$(( parse_errors + 1 ))
fi

[ "$parse_errors" -eq 0 ] || die "$parse_errors floor directive(s) could not be read; an unread floor is not an asserted one"

# ---------------------------------------------------------------------------
# --expect: is the file we read the file that was built, and is it still armed?
#
# Each named pin must satisfy TWO conditions, and the second was added after
# the first turned out to be bypassable.
#
# 1. IT APPEARS AS A `--with` ARGUMENT. This is the wrong-FILE check, and it
#    reads arguments rather than directives on purpose: a wrong file can differ
#    precisely by having no directive on a pin, in which case comparing
#    directives would find nothing to disagree with and pass. The `--with`
#    lines are present in both files either way.
#
# 2. IT CARRIES A PARSED DIRECTIVE. Condition 1 alone let the guard disarm
#    itself: deleting the `# pin-watch:` comment lines while leaving the pins
#    and the ARG untouched produced "nothing to assert" and exit 0 -- a
#    one-line edit that silently removed the assertion from every build, with
#    the tripwire satisfied because the `--with` arguments were all still
#    there. The caller naming a pin in --expect is asserting that pin is
#    floored, so an unfloored one is a mismatch rather than a non-event.
#    FLOOR_SELFCHECK in Dockerfile.caddy already names every declared floor,
#    so this introduces no second list to keep in step.
#
# AN EMPTY LIST IS REJECTED. `[ -n "$EXPECT" ]` is true for " ", and
# `for want in $EXPECT` then iterates zero times, so --expect=" " passed every
# check having compared nothing -- reachable as
# `docker build --build-arg FLOOR_SELFCHECK=" "`. The token count is asserted
# to be non-zero before the loop: "nothing to compare" must not share an exit
# status with "everything compared and agreed".
# ---------------------------------------------------------------------------
if [ -n "$EXPECT" ]; then
  withs="$WORK/withs.tsv"
  : > "$withs"
  while IFS= read -r wl; do
    case "$wl" in *--with*) ;; *) continue ;; esac
    trim="${wl#"${wl%%[![:space:]]*}"}"
    case "$trim" in '#'*) continue ;; esac
    wline="${wl//$'\t'/ }"
    wline="${wline//\"/ }"
    wline="${wline//\'/ }"
    wline="${wline/--with=/--with }"
    while case "$wline" in *'--with  '*) true ;; *) false ;; esac; do
      wline="${wline/--with  /--with }"
    done
    warg="${wline#*--with }"
    warg="${warg%% *}"
    warg="${warg%\\}"
    case "$warg" in *=*) warg="${warg%%=*}" ;; esac
    [ -n "$warg" ] && printf '%s\n' "$warg" >> "$withs"
  done < "$DOCKERFILE"

  expect_bad=0
  expect_n=0
  for want in $EXPECT; do
    expect_n=$(( expect_n + 1 ))
    if ! grep -qxF "$want" "$withs"; then
      have="$(grep -F "${want%@*}@" "$withs" | head -1)"
      echo "ERROR: --expect names \`$want\`, but $DOCKERFILE has ${have:-no such --with argument}" >&2
      expect_bad=$(( expect_bad + 1 ))
      continue
    fi
    # Condition 2: the pin is present AND floored. `$floors` is pkg<TAB>ver<TAB>…
    if ! awk -F'\t' -v p="${want%@*}" -v v="${want##*@}" \
           'BEGIN{r=1} $1==p && $2==v {r=0} END{exit r}' "$floors"; then
      echo "ERROR: --expect names \`$want\`, and $DOCKERFILE does pin it, but no \`# pin-watch:\` directive was parsed for it; the pin is present and UNASSERTED" >&2
      expect_bad=$(( expect_bad + 1 ))
    fi
  done
  [ "$expect_n" -gt 0 ] || die "--expect was given a value containing no \`pkg@version\` token; nothing was compared, and an empty expectation is not a satisfied one"
  [ "$expect_bad" -eq 0 ] || die "the Dockerfile read is not the one built, or is not armed ($expect_bad pin mismatch(es)); its pins were checked against a different file's binary, which is a clean-looking result that means nothing"
fi

floor_count="$(wc -l < "$floors" | tr -d ' ')"

# T-0906: "nothing established" must never share exit 0 with "checked and
# fine". --expect already catches a stripped file on every build path, but a
# hand run without it got exit 0 on zero directives. Two ways to close that:
#   --min-floors N  a hand-kept count next to the pins (Dockerfile.caddy passes
#                   it); fewer parsed directives than N is a hard error.
#   --strict        zero directives is a hard error: a strict reading that
#                   asserted nothing has not been strict about anything.
# Without either, zero directives stays "nothing to assert", exit 0 -- a
# Dockerfile may legitimately declare no pins.
if [ -n "$MIN_FLOORS" ] && [ "$floor_count" -lt "$MIN_FLOORS" ]; then
  die "parsed $floor_count \`# pin-watch:\` floor/security directive(s) in $DOCKERFILE, --min-floors requires at least $MIN_FLOORS; directives were removed or mistyped, so the pins are present and UNASSERTED"
fi
if [ "$floor_count" -eq 0 ] && [ "$STRICT" -eq 1 ]; then
  die "no \`# pin-watch: floor\` or \`# pin-watch: security\` directive in $DOCKERFILE under --strict; nothing was asserted, and that is not a strict pass"
fi
if [ "$floor_count" -eq 0 ]; then
  # Not a pass and not an error: a Dockerfile may legitimately declare no
  # pins of either kind. Say so explicitly rather than printing an all-clear
  # that covers nothing, so "0 checked" cannot be misread as "0 violations".
  echo "assert-floor-versions: no \`# pin-watch: floor\` or \`# pin-watch: security\` directive in $DOCKERFILE; nothing to assert"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    { echo "floor_assert=none"; echo "floor_violations=0"
      echo "floor_divergences=0"; echo "floor_checked=0"; } >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Version comparison.
#
# `sort -V` WAS USED HERE AND IS WRONG IN THE UNSAFE DIRECTION. It is a
# filename-version sort, not semver, and it has no concept of a prerelease, so
# it puts `v1.7.8-rc1` ABOVE `v1.7.8`:
#
#   $ printf 'v1.7.8\nv1.7.8-rc1\n' | sort -V | head -1
#   v1.7.8
#
# Semver says the opposite -- a prerelease precedes its release -- and so does
# Go: `golang.org/x/mod/semver.Compare("v1.7.8", "v1.7.8-rc1")` is +1. With
# `sort -V`, a binary linking v1.7.8-rc1 against a v1.7.8 floor was classified
# `above` and REPORTED AS A DIVERGENCE WITH EXIT 0, annotated "(a plugin raised
# this pin)", when the artefact was in fact below its floor and the build
# should have failed. That is this file's own failure mode -- a confident clean
# on the condition it exists to catch -- inside its comparison.
#
# Not hypothetical. `v<X.Y.Z>-0.<timestamp>-<sha>` is exactly the shape Go
# emits for a commit pin, Dockerfile.caddy already carries
# `certificates@v0.30.3-0.20261105213751-6d5a251fbe01`, and `--replace` is the
# one mechanism that can pull a module BELOW what MVS chose -- i.e. the only
# way a floor gets breached in practice. Both GNU sort and the builder image's
# busybox sort agree on the wrong answer, so there was no host-vs-build
# divergence to make it visible either.
#
# ver_cmp prints -1, 0 or 1 for $1 <=> $2, implementing the ordering rules of
# semver 2.0.0 §11 that matter here:
#
#   - build metadata (`+...`) is ignored entirely;
#   - release cores compare component-wise and numerically (`sort -V` IS
#     correct for a pure numeric dotted core, which is all it is used for);
#   - a version WITH a prerelease is lower than the same core without one;
#   - two prereleases compare identifier by identifier: numeric identifiers
#     numerically, numeric below alphanumeric, alphanumeric by ASCII, and a
#     shorter identifier list is lower when all its identifiers are equal.
#
# POSIX sh only, like the rest of this file: it runs under the builder image's
# busybox ash, which has no bash. No arrays, no `[[ ]]`, and no string `<` in
# `test` -- hence `sort` for the alphanumeric case.
# ---------------------------------------------------------------------------
ver_core() {  # strip leading v, drop +metadata, keep the part before the first -
  _v="${1#v}"; _v="${_v%%+*}"; printf '%s' "${_v%%-*}"
}
ver_pre() {   # strip leading v, drop +metadata, keep the part after the first -
  _v="${1#v}"; _v="${_v%%+*}"
  case "$_v" in *-*) printf '%s' "${_v#*-}" ;; *) printf '' ;; esac
}

ver_cmp() {
  _ac="$(ver_core "$1")"; _bc="$(ver_core "$2")"
  if [ "$_ac" != "$_bc" ]; then
    _lo="$(printf '%s\n%s\n' "$_ac" "$_bc" | sort -V | head -1)"
    # An empty result means sort produced nothing, which must not silently
    # read as "equal" or pick a direction. There is no safe guess here.
    [ -n "$_lo" ] || { echo "ERROR: cannot order \`$1\` against \`$2\`" >&2; printf 'X'; return; }
    if [ "$_lo" = "$_ac" ]; then printf -- '-1'; else printf '1'; fi
    return
  fi

  _ap="$(ver_pre "$1")"; _bp="$(ver_pre "$2")"
  [ "$_ap" = "$_bp" ] && { printf '0'; return; }
  # Same core, exactly one prerelease: the release is the higher of the two.
  [ -z "$_ap" ] && { printf '1'; return; }
  [ -z "$_bp" ] && { printf -- '-1'; return; }

  _i=1
  while :; do
    # awk, NOT `cut -d. -f$i`. `printf alpha | cut -d. -f2` prints `alpha`,
    # because cut emits the whole line when the delimiter is absent -- so the
    # second identifier of a single-identifier list read back as the FIRST
    # one, and `alpha` vs `alpha.1` compared `1` against `alpha` and answered
    # backwards. awk bounds the index against NF and yields nothing past the
    # end, which is what the shorter-list rule below needs. awk is already a
    # dependency of this file (the module-path walk uses it), so this adds
    # nothing to what the builder stage must provide.
    _ai="$(printf '%s' "$_ap" | awk -F. -v i="$_i" '{ if (i<=NF) printf "%s", $i }')"
    _bi="$(printf '%s' "$_bp" | awk -F. -v i="$_i" '{ if (i<=NF) printf "%s", $i }')"
    # Past the end of the list the field is empty. Both empty means every
    # identifier matched; one empty means that list is shorter, and a shorter
    # list of otherwise-equal identifiers is the lower version.
    if [ -z "$_ai" ] && [ -z "$_bi" ]; then printf '0'; return; fi
    [ -z "$_ai" ] && { printf -- '-1'; return; }
    [ -z "$_bi" ] && { printf '1'; return; }
    if [ "$_ai" = "$_bi" ]; then _i=$(( _i + 1 )); continue; fi

    _an=no; _bn=no
    case "$_ai" in ''|*[!0-9]*) ;; *) _an=yes ;; esac
    case "$_bi" in ''|*[!0-9]*) ;; *) _bn=yes ;; esac
    if [ "$_an" = yes ] && [ "$_bn" = yes ]; then
      if [ "$_ai" -lt "$_bi" ]; then printf -- '-1'; else printf '1'; fi
      return
    fi
    # A numeric identifier always has lower precedence than an alphanumeric one.
    [ "$_an" = yes ] && { printf -- '-1'; return; }
    [ "$_bn" = yes ] && { printf '1'; return; }
    _lo="$(printf '%s\n%s\n' "$_ai" "$_bi" | LC_ALL=C sort | head -1)"
    if [ "$_lo" = "$_ai" ]; then printf -- '-1'; else printf '1'; fi
    return
  done
}

# ---------------------------------------------------------------------------
# Compare each declared floor against the linked version.
# ---------------------------------------------------------------------------
violations=0
divergences=0
checked=0
rows="$WORK/rows.tsv"
: > "$rows"

while IFS=$'\t' read -r pkg pin ref kind; do
  [ -n "$pkg" ] || continue

  # Walk the package path up to its module path (trap 1). Stop at the first
  # row that matches; `/v5`-style suffixes match at full length.
  probe="$pkg"
  mod=""
  linked=""
  while [ -n "$probe" ]; do
    hit="$(awk -F'\t' -v p="$probe" '$1==p { print $2; exit }' "$mods")"
    if [ -n "$hit" ]; then mod="$probe"; linked="$hit"; break; fi
    case "$probe" in
      */*) probe="${probe%/*}" ;;
      *)   probe="" ;;
    esac
  done

  if [ -z "$mod" ]; then
    # Fail-open is the failure mode this script exists to remove, so a pin
    # naming a module that is not in the binary is an error, not a pass.
    echo "ERROR: $kind pin \`$pkg@$pin\` resolves to no module in the binary; the pin names code that is not linked, so it asserts nothing" >&2
    violations=$(( violations + 1 ))
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$pkg" "$pin" "(absent)" "missing" "$ref" "$kind" >> "$rows"
    checked=$(( checked + 1 ))
    continue
  fi

  checked=$(( checked + 1 ))
  if [ "$linked" = "$pin" ]; then
    state="equal"
  else
    cmp="$(ver_cmp "$linked" "$pin")"
    case "$cmp" in
      -1) state="below"; violations=$(( violations + 1 )) ;;
      0)  state="equal" ;;
      1)  state="above"; divergences=$(( divergences + 1 )) ;;
      # Unorderable is NOT a pass. ver_cmp prints X when it cannot establish
      # an order, and "we could not tell" must land on the failing side of a
      # security floor rather than quietly on the reported side.
      *)  echo "ERROR: $kind pin \`$pkg@$pin\` cannot be ordered against the linked \`$linked\`; an unorderable comparison establishes nothing" >&2
          state="unordered"; violations=$(( violations + 1 )) ;;
    esac
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$pkg" "$pin" "$linked" "$state" "$ref" "$kind" >> "$rows"
done < "$floors"

# ---------------------------------------------------------------------------
# Report. Printed in full every run, including the clean one: the point of the
# mechanism is that the shipped version of a floored module is STATED, so a
# reader does not have to know to go looking for it.
# ---------------------------------------------------------------------------
printf '\n=== Security floors vs the built binary ===\n'
printf '  binary:     %s\n' "$BINPATH"
printf '  dockerfile: %s\n' "$DOCKERFILE"
printf '  modules:    %s linked\n\n' "$mod_count"

while IFS=$'\t' read -r pkg pin linked state ref kind; do
  [ -n "$pkg" ] || continue
  case "$state" in
    equal)   printf '  [ok]        %s  (%s)\n              pinned %s, linked %s\n' "$pkg" "$kind" "$pin" "$linked" ;;
    above)   printf '  [DIVERGED]  %s  (%s)\n              pinned %s, LINKED %s  (a plugin raised this pin)\n              The Dockerfile says %s and the binary contains %s. Expected to be\n              reviewed, not absorbed: the pin is a statement about which code\n              ships. ref=%s\n' \
               "$pkg" "$kind" "$pin" "$linked" "$pin" "$linked" "$ref" ;;
    below)   printf '  [VIOLATED]  %s  (%s)\n              pinned %s, LINKED %s  -- BELOW the pin\n              ref=%s\n' \
               "$pkg" "$kind" "$pin" "$linked" "$ref" ;;
    missing) printf '  [ERROR]     %s  (%s)\n              pinned %s, no module row in the binary\n              ref=%s\n' \
               "$pkg" "$kind" "$pin" "$ref" ;;
    unordered) printf '  [ERROR]     %s  (%s)\n              pinned %s, linked %s -- NOT ORDERABLE\n              Neither version could be placed relative to the other, so whether\n              the floor holds is unknown. Counted as a violation: on a security\n              floor, "could not tell" belongs on the failing side.\n              ref=%s\n' \
               "$pkg" "$kind" "$pin" "$linked" "$ref" ;;
    # A state with no arm above would print NOTHING while still being counted,
    # which is a row that exists in the totals and nowhere a reader can see it.
    # Anything unrecognised is printed loudly rather than dropped.
    *)       printf '  [ERROR]     %s  (%s)\n              pinned %s, linked %s -- unrecognised state %s\n              ref=%s\n' \
               "$pkg" "$kind" "$pin" "$linked" "$state" "$ref" ;;
  esac
done < "$rows"

printf '\n  %s floor(s) checked: %s violation(s), %s divergence(s)\n' \
  "$checked" "$violations" "$divergences"

if [ "$JSON" -eq 1 ]; then
  {
    printf '{"checked":%s,"violations":%s,"divergences":%s,"floors":[' \
      "$checked" "$violations" "$divergences"
    first=1
    while IFS=$'\t' read -r pkg pin linked state ref kind; do
      [ -n "$pkg" ] || continue
      [ "$first" -eq 1 ] || printf ','
      first=0
      printf '{"package":"%s","pinned":"%s","linked":"%s","state":"%s","ref":"%s","kind":"%s"}' \
        "$pkg" "$pin" "$linked" "$state" "$ref" "$kind"
    done < "$rows"
    printf ']}\n'
  } > "$WORK/result.json"
  cat "$WORK/result.json"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  if [ "$violations" -gt 0 ]; then v="violated"
  elif [ "$divergences" -gt 0 ]; then v="diverged"
  else v="ok"; fi
  { echo "floor_assert=$v"
    echo "floor_violations=$violations"
    echo "floor_divergences=$divergences"
    echo "floor_checked=$checked"; } >> "$GITHUB_OUTPUT"
fi

if [ "$violations" -gt 0 ]; then
  printf '\n  A floored module is linked BELOW its pin. The floor exists to make\n  that impossible, so this is a build that must not ship.\n\n'
  exit 1
fi
if [ "$divergences" -gt 0 ]; then
  if [ "$STRICT" -eq 1 ]; then
    printf '\n  --strict: a floor was raised past its pin. Review the divergence and\n  update the pin (and its `# pin-watch: floor` reason) to match what ships.\n\n'
    exit 1
  fi
  printf '\n  Not a failure: upward movement is usually fine and sometimes better.\n  It is printed because it is a change to a reviewed decision, and the\n  Dockerfile and the binary now disagree about a security pin.\n\n'
fi
exit 0
