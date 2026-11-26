#!/usr/bin/env bash
# Reachability watch for CaddyUI's Go code AND for the published Caddy image's
# binary, with an explicit verdict when the scanner could not scan.
#
# WHY THIS SCRIPT EXISTS AT ALL, rather than `govulncheck ./...` in a workflow.
#
# Three separate defects, each measured in this repo, and none of them visible
# from a `run:` block that greps stdout:
#
# 1. A GOVULNCHECK OLDER THAN THE TREE CANNOT SCAN IT, AND SAYS SO IN A WAY
#    THAT READS AS AN OPERATOR MISTAKE (T-0740). govulncheck embeds the
#    `go/types` checker of the Go release it was compiled with, so it cannot
#    parse a stdlib newer than itself. Reproduced here on 2026-11-25 with a
#    go1.26.11-built govulncheck against this tree's `toolchain go1.27.4`:
#
#      govulncheck: loading packages:
#      There are errors with the provided package patterns:
#      .../src/math/rand/v2/rand.go:213:17: method must have no type parameters
#      .../tables17.0.0.go:5:9: file requires newer Go version go1.27
#      For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-...
#
#    Exit status 1, ZERO findings printed, and the message points at the
#    package patterns — so the natural reading is a bad `./...`, a missing
#    module or a path typo. Nothing in it says "reinstall me". Any wrapper
#    that treats "no findings printed" as clean records a pass. So this script
#    compares the scanner's own build toolchain against the tree's BEFORE
#    invoking it, and refuses with `could not run` rather than letting that
#    error through.
#
# 2. THE IMAGE BINARY WAS SCANNED BY NOTHING (T-0746). `govulncheck ./...`
#    covers CaddyUI's own module set, which builds the `caddyui` server. The
#    `caddy` binary in `applegater/caddyui-caddy` is a DIFFERENT artefact with
#    a different module graph, and that is where GO-2026-6865 /
#    CVE-2026-116591 (HIGH, klauspost/compress) hid from Trivy: the advisory
#    names the package `klauspost/compress/zstd` while the binary records the
#    module `klauspost/compress`, so Trivy's name match missed it. govulncheck
#    is immune because the Go advisory DB names modules correctly and matches
#    on symbols. `--binary image:<ref>` is that third check.
#
# 3. "COULD NOT DETERMINE" MUST NOT RENDER AS "CLEAN". The exit codes below
#    are the convention `scripts/check-pinned-modules.sh` already uses, and 3
#    is deliberately distinct from 0: an unreadable result is an unknown, not
#    a pass. Every path that cannot answer reaches 3 — absent scanner, stale
#    scanner, unreadable binary, unparsable output, a scan that produced no
#    `config` message, a malformed acknowledgement file.
#
# WHAT THIS IS NOT EVIDENCE OF. `vuln.go.dev` is CVE-keyed, exactly like OSV
# and GitHub's global index. Measured against this repo's module set it reports
# NONE of the five CVE-less go-jose advisories that were live in it (T-0675,
# T-0676). A clean verdict here says nothing about CVE-less advisories; that
# gap is covered by `check-pinned-modules.sh --gomod`, which asks GitHub's
# per-repository endpoint. Two checks, two blind spots, neither a substitute
# for the other.
#
# WHAT "CALLED" MEANS, AND WHAT IT DOES NOT. In source mode (`--source`)
# govulncheck traces call paths, so a symbol-level finding means this code can
# reach the vulnerable function. In BINARY mode it means the symbol is LINKED
# INTO the artefact — not that it is reachable at run time and not that it is
# exploitable. The distinction is not academic: in T-0729 govulncheck named
# `huff0.ReadTable` on a binary whose zstd decoder the linker had dropped
# entirely (`zstd.NewReader` count 0). So binary-mode findings are reported as
# `linked`, never as `called`, and a finding still needs a reachability read
# before it is treated as live.
#
# Usage:
#   govulncheck-gate.sh --source [DIR]            scan Go source (DIR or repo root)
#   govulncheck-gate.sh --binary PATH|image:REF   scan a built binary
#
#   --out-dir DIR         where the report, raw stream and verdict are written
#                         (default: govulncheck-out)
#   --tool PATH           govulncheck to use (default: the one on $PATH)
#   --acks FILE|none      acknowledgement file (default: scripts/govulncheck-acks.txt)
#   --fail-on called|never
#                         `called`  -> a called/linked, unacknowledged finding
#                                      is exit 2 (the urgent verdict)
#                         `never`   -> report only; a finding is exit 1
#                         (default: never, so a new caller is report-only until
#                         it opts in)
#   --gomod PATH          go.mod whose `toolchain` the scanner is checked
#                         against (default: the one beside this script's repo)
#   --label TEXT          what the report calls the thing scanned
#   --offline-fixture F   read a saved govulncheck JSON stream from F instead of
#                         running the scanner. For the regression suite: it
#                         exercises the parsing, classification, acknowledgement
#                         and reporting paths with no network and no scanner.
#                         The staleness guard still runs, because that is the
#                         behaviour most worth testing.
#   --skip-tool-check     do not compare the scanner against the toolchain.
#                         ONLY for a run where the toolchain cannot be read at
#                         all; it is reported in the output as a weakened run,
#                         because the guard it removes is the subject of T-0740.
#
# Exit codes (the check-pinned-modules.sh convention):
#   0  ok         the scan ran and found nothing
#   1  attention  findings present but none called/linked, or an acknowledged
#                 finding, or an acknowledgement that no longer matches a
#                 finding and should be removed
#   2  advisory   at least one called/linked finding that is NOT acknowledged
#                 (only with --fail-on called; otherwise such a finding is 1)
#   3  the check could not run — treat as UNKNOWN, never as a pass
set -uo pipefail

PROG="govulncheck-gate"

MODE=""
TARGET=""
OUT_DIR="govulncheck-out"
TOOL=""
ACKS=""
FAIL_ON="never"
GOMOD=""
LABEL=""
FIXTURE=""
SKIP_TOOL_CHECK=0

# The repository root, used for defaults only. `cd`ing is deliberately NOT
# done: --binary paths and --out-dir are the caller's, relative to the caller's
# directory.
REPO_ROOT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd || true)"

die_usage() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 3; }

while [ $# -gt 0 ]; do
  case "$1" in
    --source)
      MODE=source
      # An optional directory may follow. `--something` is the next flag, not
      # a directory, so it must not be swallowed.
      case "${2:-}" in
        ""|--*) TARGET="" ;;
        *) TARGET="$2"; shift ;;
      esac
      ;;
    --binary)
      MODE=binary
      TARGET="${2:-}"
      [ -n "$TARGET" ] || die_usage "--binary needs a path or image:<ref>"
      shift
      ;;
    --out-dir)   OUT_DIR="${2:-}"; [ -n "$OUT_DIR" ] || die_usage "--out-dir needs a directory"; shift ;;
    --tool)      TOOL="${2:-}";    [ -n "$TOOL" ]    || die_usage "--tool needs a path"; shift ;;
    --acks)      ACKS="${2:-}";    [ -n "$ACKS" ]    || die_usage "--acks needs a file or 'none'"; shift ;;
    --fail-on)   FAIL_ON="${2:-}"; shift ;;
    --gomod)     GOMOD="${2:-}";   [ -n "$GOMOD" ]   || die_usage "--gomod needs a path"; shift ;;
    --label)     LABEL="${2:-}";   shift ;;
    --offline-fixture) FIXTURE="${2:-}"; [ -n "$FIXTURE" ] || die_usage "--offline-fixture needs a file"; shift ;;
    --skip-tool-check) SKIP_TOOL_CHECK=1 ;;
    -h|--help)
      sed -n '2,/^# Exit codes/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) die_usage "unknown argument: $1" ;;
  esac
  shift
done

[ -n "$MODE" ] || die_usage "one of --source or --binary is required"
case "$FAIL_ON" in
  called|never) ;;
  *) die_usage "--fail-on must be 'called' or 'never', not '$FAIL_ON'" ;;
esac

command -v jq >/dev/null 2>&1 || { printf '%s: jq is required\n' "$PROG" >&2; exit 3; }

mkdir -p "$OUT_DIR" || { printf '%s: cannot create %s\n' "$PROG" "$OUT_DIR" >&2; exit 3; }
STREAM="$OUT_DIR/govulncheck.json"
REPORT="$OUT_DIR/summary.md"
VERDICT_FILE="$OUT_DIR/verdict"
: > "$REPORT"

[ -n "$LABEL" ] || case "$MODE" in
  source) LABEL="${TARGET:-$REPO_ROOT} (Go source)" ;;
  binary) LABEL="$TARGET" ;;
esac

# Collected and emitted together at the end, so a run that cannot answer says
# every reason it cannot rather than the first one.
notes=()
note() { notes+=("$1"); }

gh_out() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; return 0; }

# ---------------------------------------------------------------------------
# Version comparison for Go toolchain strings.
#
# Accepts `go1.27.4`, `1.27.4`, `go1.27`, `go1.27rc1`, `1.27.0-0`. A missing
# patch is 0. A prerelease (`rc`, `beta`, `-0`) sorts BELOW the same release,
# which is what OSV's `1.27.0-0` marker means: "from the first 1.27 prerelease
# onwards".
#
# Prints `MAJOR MINOR PATCH PRE` where PRE is 0 for a prerelease and 1 for a
# release, so a plain numeric comparison of the four fields is the order.
# Prints nothing and returns 1 on anything it cannot read — callers must treat
# that as unknown rather than as equal.
# ---------------------------------------------------------------------------
go_version_fields() {
  local v="${1:-}"
  v="${v#go}"
  local pre=1
  case "$v" in
    *rc*|*beta*|*alpha*|*-*) pre=0 ;;
  esac
  # Strip anything that is not part of the dotted numeric core.
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

# go_version_cmp A B -> prints -1, 0 or 1. Returns 1 if either is unreadable.
go_version_cmp() {
  local a b
  a="$(go_version_fields "${1:-}")" || return 1
  b="$(go_version_fields "${2:-}")" || return 1
  local a1 a2 a3 a4 b1 b2 b3 b4
  read -r a1 a2 a3 a4 <<<"$a"
  read -r b1 b2 b3 b4 <<<"$b"
  local i
  for i in 1 2 3 4; do
    local x y
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

# ---------------------------------------------------------------------------
# What toolchain does the TREE need?
#
# `toolchain goX.Y.Z` is what CI reads via `go-version-file: go.mod`, so it is
# the authoritative answer. Falling back to the `go` directive is correct for a
# module with no toolchain line; both are reported so a reader can see which
# one the comparison used.
# ---------------------------------------------------------------------------
tree_toolchain=""
tree_toolchain_src=""
if [ -z "$GOMOD" ]; then
  if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/go.mod" ]; then GOMOD="$REPO_ROOT/go.mod"; fi
fi
if [ -n "$GOMOD" ] && [ -f "$GOMOD" ]; then
  tree_toolchain="$(sed -n 's/^toolchain[[:space:]]\{1,\}\(go[0-9][^[:space:]]*\).*/\1/p' "$GOMOD" | head -1)"
  if [ -n "$tree_toolchain" ]; then
    tree_toolchain_src="toolchain directive in $GOMOD"
  else
    tree_toolchain="$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][^[:space:]]*\).*/go\1/p' "$GOMOD" | head -1)"
    [ -n "$tree_toolchain" ] && tree_toolchain_src="go directive in $GOMOD (no toolchain line)"
  fi
fi

# ---------------------------------------------------------------------------
# THE STALENESS GUARD (T-0740). Runs before the scanner is invoked.
#
# In BINARY mode the artefact's own recorded Go version matters more than the
# tree's: the scanner has to read that binary, not this module. Both are
# compared when both are readable, and the HIGHER one is the requirement — a
# scanner older than either cannot be trusted about the result.
# ---------------------------------------------------------------------------
tool_go=""
required_go=""
required_src=""
bin_go=""

# Sets the global TOOL_RESOLVED rather than printing it. A function whose
# diagnostics matter must not be called in `$( )`: a `note` appended inside a
# command substitution is appended to a COPY of the array and discarded, which
# is how "govulncheck is not on $PATH" came out as "the scanner's build
# toolchain could not be read" -- the right exit code with the wrong reason,
# in the one script whose subject is saying why it could not answer.
TOOL_RESOLVED=""
resolve_tool() {
  if [ -n "$TOOL" ]; then
    if [ ! -x "$TOOL" ]; then
      note "the scanner named by --tool ($TOOL) is missing or not executable"
      return 1
    fi
    TOOL_RESOLVED="$TOOL"
    return 0
  fi
  local p
  p="$(command -v govulncheck 2>/dev/null)" || true
  if [ -z "$p" ]; then
    note "govulncheck is not on \$PATH, so nothing was scanned. Install it with the tree's own toolchain: \`go install golang.org/x/vuln/cmd/govulncheck@latest\`"
    return 1
  fi
  TOOL_RESOLVED="$p"
  return 0
}

# Reads the Go release a binary was built with. `go version -m <bin>` prints
# `<path>: goX.Y.Z` on its first line.
#
# Returns 2 when `go` itself is absent and 1 when its output was unreadable,
# so the caller can say WHICH of those happened. It prints the version and
# nothing else, because it IS called in a command substitution.
binary_go_version() {
  local bin="$1" out
  command -v go >/dev/null 2>&1 || return 2
  out="$(go version -m "$bin" 2>/dev/null | head -1)" || true
  case "$out" in
    *": go"*) ;;
    *) return 1 ;;
  esac
  out="${out##*: }"
  printf '%s\n' "$out"
}

# ---------------------------------------------------------------------------
# Acknowledgements.
#
# An ack suppresses the URGENT verdict for ONE advisory id while there is
# genuinely nothing to do about it — the case T-0744 named: a called stdlib
# finding whose only fix is a toolchain release that does not exist yet. It
# never suppresses the REPORT; the finding is still listed, labelled
# `acknowledged`, with its reason.
#
# Format, one per line, `#` comments and blank lines ignored:
#
#   GO-2026-6859 expires=2026-12-31 reason=<prose> [fixed_in=go1.27.4] [ref=T-0744]
#
#   expires=   REQUIRED. An acknowledgement with no end date is an exclusion,
#              and this script does not do exclusions — that is the mechanism
#              `check-pinned-modules.sh` floors already use, for the same
#              reason: a decision that cannot expire outlives its reasoning.
#   reason=    REQUIRED, and must be the LAST field because it is prose.
#   fixed_in=  optional, and it RE-ARMS EARLY. When the tree's toolchain
#              reaches this version the fix is available, so the excuse is
#              gone and the ack expires regardless of its date.
#   ref=       optional task id.
#
# A malformed line is exit 3, not a skip: a run that cannot establish what is
# acknowledged cannot report a verdict about what is not.
# ---------------------------------------------------------------------------
declare -A ACK_REASON=()
declare -A ACK_EXPIRES=()
declare -A ACK_FIXEDIN=()
declare -A ACK_REF=()
declare -A ACK_LIVE=()
declare -A ACK_SEEN=()
ack_error=0

load_acks() {
  local file="$1" lineno=0 line id rest today
  today="$(date -u +%Y-%m-%d)"
  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    line="${line%%$'\r'}"
    case "$line" in
      ''|'#'*) continue ;;
    esac
    id="${line%% *}"
    rest="${line#"$id"}"
    case "$id" in
      GO-[0-9][0-9][0-9][0-9]-[0-9]*) ;;
      *)
        printf '%s: %s line %d: `%s` is not a GO- advisory id; an acknowledgement is keyed by advisory id\n' \
          "$PROG" "$file" "$lineno" "$id" >&2
        ack_error=1; continue ;;
    esac
    if [ -n "${ACK_REASON[$id]+x}" ]; then
      printf '%s: %s line %d: %s is acknowledged twice; two reasons for one id means neither can be trusted\n' \
        "$PROG" "$file" "$lineno" "$id" >&2
      ack_error=1; continue
    fi

    local expires="" fixed_in="" ref="" reason=""
    # reason= is prose and runs to end of line, so it is cut off first and the
    # remaining head is parsed as whitespace-separated key=value pairs.
    case "$rest" in
      *reason=*)
        reason="${rest#*reason=}"
        rest="${rest%%reason=*}"
        ;;
    esac
    local kv
    for kv in $rest; do
      case "$kv" in
        expires=*)  expires="${kv#expires=}" ;;
        fixed_in=*) fixed_in="${kv#fixed_in=}" ;;
        ref=*)      ref="${kv#ref=}" ;;
        *)
          printf '%s: %s line %d: unknown field `%s` on the %s acknowledgement (only expires=, fixed_in=, ref= and a trailing reason= are understood)\n' \
            "$PROG" "$file" "$lineno" "$kv" "$id" >&2
          ack_error=1 ;;
      esac
    done

    # Trim the prose.
    reason="${reason#"${reason%%[![:space:]]*}"}"
    reason="${reason%"${reason##*[![:space:]]}"}"

    if [ -z "$expires" ] || [ -z "$reason" ]; then
      printf '%s: %s line %d: the %s acknowledgement is missing %s; an acknowledgement without both an expiry and a reason is an exclusion, and this script does not do exclusions\n' \
        "$PROG" "$file" "$lineno" "$id" \
        "$( [ -z "$expires" ] && printf 'expires='; [ -z "$expires" ] && [ -z "$reason" ] && printf ' and '; [ -z "$reason" ] && printf 'reason=' )" >&2
      ack_error=1; continue
    fi
    case "$expires" in
      [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
      *)
        printf '%s: %s line %d: expires=%s on %s is not a YYYY-MM-DD date, so the acknowledgement cannot expire and is not honoured\n' \
          "$PROG" "$file" "$lineno" "$expires" "$id" >&2
        ack_error=1; continue ;;
    esac
    if ! date -u -d "$expires" +%Y-%m-%d >/dev/null 2>&1; then
      printf '%s: %s line %d: expires=%s on %s is not a real date\n' "$PROG" "$file" "$lineno" "$expires" "$id" >&2
      ack_error=1; continue
    fi
    if [ -n "$fixed_in" ] && ! go_version_fields "$fixed_in" >/dev/null; then
      printf '%s: %s line %d: fixed_in=%s on %s is not a Go version, so the early re-arm comparison cannot be made and the acknowledgement is not honoured\n' \
        "$PROG" "$file" "$lineno" "$fixed_in" "$id" >&2
      ack_error=1; continue
    fi

    ACK_REASON[$id]="$reason"
    ACK_EXPIRES[$id]="$expires"
    ACK_FIXEDIN[$id]="$fixed_in"
    ACK_REF[$id]="$ref"

    # Live or expired. Two independent re-arms, and the EARLIER one wins.
    local live=1 why=""
    if [ "$expires" \< "$today" ]; then live=0; why="expired on $expires"; fi
    if [ -n "$fixed_in" ] && [ -n "$tree_toolchain" ]; then
      local c
      if c="$(go_version_cmp "$tree_toolchain" "$fixed_in")"; then
        if [ "$c" != "-1" ]; then
          live=0
          why="${why:+$why; }re-armed: the tree is on $tree_toolchain, which is at or past fixed_in=$fixed_in, so the fix is available"
        fi
      fi
    fi
    ACK_LIVE[$id]="$live"
    if [ "$live" = 0 ]; then
      note "the acknowledgement for $id is no longer in force ($why)"
    fi
  done < "$file"
}

if [ "$ACKS" = none ]; then
  :
else
  if [ -z "$ACKS" ] && [ -n "$REPO_ROOT" ]; then ACKS="$REPO_ROOT/scripts/govulncheck-acks.txt"; fi
  if [ -n "$ACKS" ] && [ -f "$ACKS" ]; then
    load_acks "$ACKS"
  elif [ -n "$ACKS" ] && [ "$ACKS" != none ]; then
    # A named-but-absent acks file is a configuration error: the caller asked
    # for acknowledgements to be honoured and they cannot be read.
    if [ "$ACKS" != "${REPO_ROOT}/scripts/govulncheck-acks.txt" ]; then
      printf '%s: the acknowledgement file %s does not exist\n' "$PROG" "$ACKS" >&2
      ack_error=1
    fi
  fi
fi

if [ "$ack_error" = 1 ]; then
  {
    echo "### govulncheck — could not run"
    echo
    echo "The acknowledgement file could not be read, so this run cannot say which findings are acknowledged and which are not. **This is not a clean result.** The parser's own messages are in the step log."
  } >> "$REPORT"
  cat "$REPORT" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  cat "$REPORT"
  echo unknown > "$VERDICT_FILE"
  gh_out "verdict=unknown"
  gh_out "rc=3"
  printf '::error::%s: the acknowledgement file is malformed, so no verdict was reached\n' "$PROG"
  exit 3
fi

# ---------------------------------------------------------------------------
# Produce the JSON stream — by running the scanner, or by reading a fixture.
# ---------------------------------------------------------------------------
scan_mode_reported=""
scan_level_reported=""
db_modified=""
scanner_version=""
could_not_run=0
extract_dir=""
cleanup() { [ -n "$extract_dir" ] && rm -rf "$extract_dir"; return 0; }
trap cleanup EXIT

scan_target="$TARGET"

# The scanner is resolved for a real run, and ALSO for a fixture run that
# names one with --tool: that combination is how the regression suite drives
# the staleness guard, which is the behaviour most worth testing and cannot be
# exercised by feeding in a saved stream.
no_go=0
if [ -z "$FIXTURE" ] || [ -n "$TOOL" ]; then
  if ! resolve_tool; then
    could_not_run=1
  else
    tool_go="$(binary_go_version "$TOOL_RESOLVED")" || {
      [ "$?" = 2 ] && no_go=1
      tool_go=""
    }
  fi
fi

# In binary mode an `image:<ref>` target is extracted first, because the
# artefact's own Go version is part of the staleness comparison.
if [ "$MODE" = binary ] && [ "$could_not_run" = 0 ]; then
  case "$TARGET" in
    image:*)
      ref="${TARGET#image:}"
      if ! command -v docker >/dev/null 2>&1; then
        note "docker is not available, so the binary could not be extracted from \`$ref\`"
        could_not_run=1
      else
        extract_dir="$(mktemp -d)" || { note "could not create a temporary directory for the extracted binary"; could_not_run=1; }
        if [ "$could_not_run" = 0 ]; then
          # `docker create` on a multi-arch manifest resolves to the HOST's
          # architecture. That is stated in the report rather than hidden: a
          # scan of amd64 is not evidence about arm64.
          cid="$(docker create "$ref" true 2>/dev/null)" || cid=""
          if [ -z "$cid" ]; then
            note "could not create a container from \`$ref\`, so its binary was not scanned (is the image pullable?)"
            could_not_run=1
          else
            if docker cp "$cid:/usr/bin/caddy" "$extract_dir/caddy" >/dev/null 2>&1; then
              scan_target="$extract_dir/caddy"
            else
              note "\`$ref\` has no readable /usr/bin/caddy, so nothing was scanned"
              could_not_run=1
            fi
            docker rm -f "$cid" >/dev/null 2>&1 || true
          fi
        fi
      fi
      ;;
    *)
      if [ ! -f "$TARGET" ]; then
        note "the binary \`$TARGET\` does not exist, so nothing was scanned"
        could_not_run=1
      fi
      ;;
  esac
fi

# What the scanner must be at least as new as.
if [ "$SKIP_TOOL_CHECK" = 1 ]; then
  note "**the T-0740 staleness guard was disabled with \`--skip-tool-check\`**, so a scanner too old to parse this tree would have reported a load error rather than a stale-scanner verdict"
else
  required_go="$tree_toolchain"
  required_src="$tree_toolchain_src"
  if [ "$MODE" = binary ] && [ "$could_not_run" = 0 ] && [ -f "$scan_target" ]; then
    bin_go="$(binary_go_version "$scan_target")" || bin_go=""
    if [ -n "$bin_go" ]; then
      if [ -z "$required_go" ]; then
        required_go="$bin_go"; required_src="the scanned binary's own build toolchain"
      else
        c="$(go_version_cmp "$bin_go" "$required_go")" || c=""
        if [ "$c" = "1" ]; then
          required_go="$bin_go"; required_src="the scanned binary's own build toolchain (newer than $tree_toolchain)"
        fi
      fi
    fi
  fi

  if [ -z "$FIXTURE" ] || [ -n "$TOOL" ]; then
    if [ -z "$required_go" ]; then
      note "the tree's required Go toolchain could not be read, so the scanner's age could not be checked"
    elif [ "$no_go" = 1 ]; then
      note "\`go\` is not on \$PATH, so the scanner's build toolchain could not be read and the T-0740 staleness guard did not run"
    elif [ -z "$tool_go" ]; then
      note "the scanner's build toolchain could not be read, so its age could not be checked against $required_go"
    else
      c="$(go_version_cmp "$tool_go" "$required_go")" || c=""
      if [ -z "$c" ]; then
        note "could not compare the scanner's toolchain ($tool_go) with the required one ($required_go)"
      elif [ "$c" = "-1" ]; then
        could_not_run=1
        # The remedy depends on WHOSE Go set the floor (T-0893). When it is
        # this tree's toolchain line, `go-version-file: go.mod` fixes it. When
        # it is the scanned binary's -- built by the upstream Caddy builder,
        # which moves on its own schedule -- installing under go.mod is
        # exactly what produced this stale scanner, so saying it again would
        # be a circular remedy on a check that then goes red every week.
        if [ -n "${bin_go:-}" ] && [ "$required_go" = "$bin_go" ] && [ "$required_go" != "$tree_toolchain" ]; then
          remedy="install the scanner under Go \`$required_go\` or newer -- the BINARY's Go, not this tree's \`${tree_toolchain:-unknown}\`: the binary was built by the upstream Caddy builder image, whose Go moves independently of go.mod, so installing under \`go-version-file: go.mod\` reproduces this exact stale scanner. In CI, \`setup-go\` with \`go-version: stable\` (not \`go-version-file: go.mod\`) then \`go install\` at the pinned govulncheck version"
        else
          remedy="\`go install golang.org/x/vuln/cmd/govulncheck@latest\` under this tree's toolchain (in CI, \`setup-go\` with \`go-version-file: go.mod\` then \`go install\`)"
        fi
        note "**the scanner is older than the tree it was asked to scan — reinstall it.** govulncheck was built with \`$tool_go\`; this scan needs at least \`$required_go\` ($required_src). A govulncheck built on an older Go embeds that release's type checker and cannot parse a newer stdlib: it exits non-zero with a \`package patterns\` error and NO findings, which reads as an operator mistake and records as a pass. Fix: $remedy."
      fi
    fi
  fi
fi

if [ "$could_not_run" = 0 ]; then
  if [ -n "$FIXTURE" ]; then
    if [ -f "$FIXTURE" ]; then
      cp "$FIXTURE" "$STREAM" || { note "could not read the fixture $FIXTURE"; could_not_run=1; }
    else
      note "the fixture $FIXTURE does not exist"
      could_not_run=1
    fi
  else
    # `-format json` is used rather than the text format ON PURPOSE. The text
    # format's exit status is the only machine-readable thing it offers (3 =
    # findings), and it cannot distinguish a called finding from a present one
    # or a load failure from either. The JSON stream carries the scan mode,
    # the DB timestamp and per-finding traces, so the verdict is derived from
    # data rather than from an exit code and a grep.
    set +e
    if [ "$MODE" = source ]; then
      if [ -n "$TARGET" ]; then
        ( cd "$TARGET" && "$TOOL_RESOLVED" -format json ./... ) > "$STREAM" 2> "$OUT_DIR/stderr.txt"
      else
        ( cd "${REPO_ROOT:-.}" && "$TOOL_RESOLVED" -format json ./... ) > "$STREAM" 2> "$OUT_DIR/stderr.txt"
      fi
    else
      "$TOOL_RESOLVED" -mode=binary -format json "$scan_target" > "$STREAM" 2> "$OUT_DIR/stderr.txt"
    fi
    scan_rc=$?
    set -e
    if [ "$scan_rc" -ne 0 ]; then
      could_not_run=1
      note "govulncheck exited $scan_rc. In \`-format json\` a findings result still exits 0, so a non-zero status here means the scan itself failed — most often an unreadable target or a scanner/toolchain mismatch. Its stderr: $(head -c 800 "$OUT_DIR/stderr.txt" 2>/dev/null | tr '\n' ' ')"
    fi
  fi
fi

# A stream with no `config` message is not a scan. This is the check that
# turns "it printed nothing" into an explicit unknown: an empty file, a
# truncated stream and a wall of text all land here instead of parsing to zero
# findings and reporting clean.
if [ "$could_not_run" = 0 ]; then
  if [ ! -s "$STREAM" ]; then
    could_not_run=1
    note "govulncheck produced NO OUTPUT AT ALL. An empty stream parses to zero findings, which must never read as zero vulnerabilities."
  elif ! jq -e . "$STREAM" >/dev/null 2>&1; then
    could_not_run=1
    note "govulncheck's output is not valid JSON, so no finding could be read from it. The raw output is in the uploaded artifact."
  else
    cfg="$(jq -s -r 'map(select(.config)) | .[0].config // empty' "$STREAM" 2>/dev/null)" || cfg=""
    if [ -z "$cfg" ]; then
      could_not_run=1
      note "govulncheck's output contains no \`config\` message, so it never started a scan. An empty or truncated stream parses to zero findings, which must not read as zero vulnerabilities."
    else
      scan_mode_reported="$(jq -s -r 'map(select(.config)) | .[0].config.scan_mode // "?"' "$STREAM")"
      scan_level_reported="$(jq -s -r 'map(select(.config)) | .[0].config.scan_level // "?"' "$STREAM")"
      db_modified="$(jq -s -r 'map(select(.config)) | .[0].config.db_last_modified // ""' "$STREAM")"
      scanner_version="$(jq -s -r 'map(select(.config)) | .[0].config.scanner_version // "?"' "$STREAM")"
      # A scan that ran at module or package level cannot answer the question
      # this gate asks, so it must not be allowed to answer it by accident.
      if [ "$scan_level_reported" != symbol ]; then
        note "the scan ran at \`$scan_level_reported\` level, not \`symbol\`, so it cannot distinguish a called finding from a merely present one. The called/linked column below is therefore not meaningful and this run is reported as unknown."
        could_not_run=1
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Could not run — one exit, one honest report.
# ---------------------------------------------------------------------------
# A function rather than an inline block, because the classifier below can
# also discover that it cannot answer -- and reaching that conclusion after
# this point must produce the SAME exit 3 and the same honest report, not a
# second, weaker story.
emit_unknown() {
  {
    echo "### govulncheck — **could not run** (reachability unknown)"
    echo
    echo "Target: \`$LABEL\` (mode: $MODE)"
    echo
    echo "This run established **nothing** about reachability. It is not a clean result and must not be read as one."
    echo
    for n in "${notes[@]}"; do echo "- $n"; done
    echo
    echo "_Exit 3 is this repo's \"the check could not run\" status (the same convention as \`check-pinned-modules.sh\`), deliberately distinct from 0._"
  } >> "$REPORT"
  cat "$REPORT" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
  cat "$REPORT"
  echo unknown > "$VERDICT_FILE"
  gh_out "verdict=unknown"
  gh_out "rc=3"
  gh_out "called=unknown"
  gh_out "present=unknown"
  printf '::error::%s: the reachability scan of %s could not run, so its result is UNKNOWN, not clean\n' "$PROG" "$LABEL"
  for n in "${notes[@]}"; do printf '::error::%s\n' "$n"; done
  exit 3
}

if [ "$could_not_run" = 1 ]; then
  emit_unknown
fi

# ---------------------------------------------------------------------------
# Classify. One row per advisory id.
#
# `trace[0].function` is the symbol-level marker: govulncheck emits a finding
# per trace, and only a symbol-level one names a function. Source mode means
# the function is CALLED from this code; binary mode means the symbol is
# LINKED INTO the artefact, which is a weaker claim and is worded as such.
# ---------------------------------------------------------------------------
# Fields are joined with US (0x1f), NOT with a tab. `read` treats tab as IFS
# whitespace and collapses a run of them, so an empty middle field (a finding
# with no symbols) silently shifts every later field left -- which first
# showed up as an empty `summary` column on a row that had one. 0x1f is not
# whitespace, so empty fields survive. Control characters are stripped from
# the values for the same reason: an advisory summary is attacker-adjacent
# text and must not be able to introduce a field or a row.
rows_file="$OUT_DIR/findings.tsv"
jq -s -r '
  (map(select(.osv)) | map({key: .osv.id, value: .osv}) | from_entries) as $osv
  | map(select(.finding) | .finding)
  | group_by(.osv)
  | map({
      id: .[0].osv,
      called: (map(.trace[0].function // empty) | length > 0),
      symbols: (map(.trace[0].function // empty) | unique | join(", ")),
      modules: (map(.trace[0].module // empty) | unique | join(", ")),
      fixed: (map(.fixed_version // empty) | unique | map(select(. != "")) | join(", "))
    })
  | .[]
  | [ .id,
      (if .called then "yes" else "no" end),
      (.modules // ""),
      (.fixed // ""),
      (.symbols // ""),
      ($osv[.id].summary // ""),
      (($osv[.id].aliases // []) | join(" "))
    ]
  | map(split("\t") | join(" ") | split("\n") | join(" ")
        | split("\r") | join(" ") | split("\u001f") | join(" "))
  | join("\u001f")
' "$STREAM" > "$rows_file" 2>"$OUT_DIR/jq-stderr.txt" || {
  # AN UNPARSED STREAM IS NOT AN EMPTY ONE. This used to truncate the rows
  # file and carry on, which meant every later count read 0 and the run
  # reported "no findings" with exit 0 -- a full clean pass produced by a
  # parser that had failed. A stream can be valid JSON (so the `jq -e .`
  # check above passes) and still break this filter: a non-string `.osv.id`
  # makes `from_entries` fail, and a crafted stream carrying a CALLED finding
  # was measured reporting exactly that clean pass. That is the defect this
  # whole script exists to refuse, so it ends in the same place as every
  # other unanswerable question.
  note "the govulncheck stream could not be parsed into findings, so what it contains is unknown. The stream is valid JSON but this filter failed on it: $(head -c 400 "$OUT_DIR/jq-stderr.txt" 2>/dev/null | tr '\n' ' '). An unparsed stream is not an empty one."
  emit_unknown
}

total=0; called_total=0; present_total=0
called_live=0; called_acked=0
ack_rows=()
called_rows=()
present_rows=()

while IFS=$'\037' read -r id called modules fixed symbols summary aliases; do
  [ -n "$id" ] || continue
  total=$((total + 1))
  live_ack=0
  if [ -n "${ACK_REASON[$id]+x}" ]; then
    ACK_SEEN[$id]=1
    [ "${ACK_LIVE[$id]}" = 1 ] && live_ack=1
  fi
  if [ "$called" = yes ]; then
    called_total=$((called_total + 1))
    if [ "$live_ack" = 1 ]; then
      called_acked=$((called_acked + 1))
      ack_rows+=("| \`$id\` | ${modules:-—} | ${fixed:-**no fix available**} | acknowledged until ${ACK_EXPIRES[$id]}${ACK_FIXEDIN[$id]:+, or when the tree reaches ${ACK_FIXEDIN[$id]}} | ${ACK_REASON[$id]}${ACK_REF[$id]:+ (${ACK_REF[$id]})} |")
    else
      called_live=$((called_live + 1))
      called_rows+=("| \`$id\` | ${modules:-—} | ${fixed:-**no fix available**} | ${symbols:-—} | ${summary//|/\\|} | ${aliases:-none} |")
    fi
  else
    present_total=$((present_total + 1))
    present_rows+=("| \`$id\` | ${modules:-—} | ${fixed:-**no fix available**} | ${summary//|/\\|} | ${aliases:-none} |")
  fi
done < "$rows_file"

# An acknowledgement that matches no finding is reported for REMOVAL rather
# than ignored. A stale ack is a standing permission for a finding nobody has
# looked at since, and the next advisory to arrive under that id inherits it.
stale_acks=0
for id in "${!ACK_REASON[@]}"; do
  if [ -z "${ACK_SEEN[$id]+x}" ]; then
    stale_acks=$((stale_acks + 1))
    note "the acknowledgement for \`$id\` matches no finding in this scan — it is either fixed or no longer in the scanned artefact, so remove the line from the acknowledgement file rather than leaving a standing permission behind"
  fi
done

# ---------------------------------------------------------------------------
# Verdict.
# ---------------------------------------------------------------------------
noun_called="called"
reach_wording="reachable from this code"
if [ "$MODE" = binary ]; then
  noun_called="linked"
  reach_wording="linked into the artefact (NOT proven reachable at run time)"
fi

rc=0
verdict=ok
if [ "$called_live" -gt 0 ]; then
  if [ "$FAIL_ON" = called ]; then rc=2; verdict=advisory; else rc=1; verdict=attention; fi
elif [ "$total" -gt 0 ] || [ "$stale_acks" -gt 0 ] || [ "${#notes[@]}" -gt 0 ]; then
  rc=1
  verdict=attention
fi

{
  case "$verdict" in
    ok)        echo "### govulncheck — no findings" ;;
    attention)
      if [ "$called_acked" -gt 0 ]; then
        echo "### govulncheck — $total finding(s); $called_acked $noun_called but **acknowledged**"
      else
        echo "### govulncheck — $total finding(s), none $noun_called"
      fi ;;
    advisory)  echo "### govulncheck — **$called_live $noun_called finding(s)**" ;;
  esac
  echo
  echo "Target: \`$LABEL\` · mode \`${scan_mode_reported}\` · level \`${scan_level_reported}\` · govulncheck \`${scanner_version}\` · advisory DB as of \`${db_modified:-unknown}\`"
  if [ -n "$tool_go" ] || [ -n "$required_go" ]; then
    echo
    echo "Scanner built with \`${tool_go:-unknown}\`; this tree needs \`${required_go:-unknown}\`${required_src:+ ($required_src)}. The scan runs only when the scanner is at least as new (T-0740)."
  fi
  if [ "$MODE" = binary ]; then
    echo
    echo "⚠️ **Binary mode reports symbols LINKED, not symbols called.** The linker's view is not the run-time one: in T-0729 govulncheck named \`huff0.ReadTable\` on a binary whose zstd decoder had been dropped entirely. Treat a finding here as something to read, not as a live exploit path. On a multi-arch reference only the runner's own architecture was extracted."
  fi

  if [ "${#called_rows[@]}" -gt 0 ]; then
    echo
    echo "#### $noun_called — $reach_wording"
    echo
    echo "| advisory | module | fixed in | symbols | summary | aliases |"
    echo "| --- | --- | --- | --- | --- | --- |"
    printf '%s\n' "${called_rows[@]}"
  fi
  if [ "${#ack_rows[@]}" -gt 0 ]; then
    echo
    echo "#### acknowledged (reported, not failed)"
    echo
    echo "| advisory | module | fixed in | acknowledgement | reason |"
    echo "| --- | --- | --- | --- | --- |"
    printf '%s\n' "${ack_rows[@]}"
  fi
  if [ "${#present_rows[@]}" -gt 0 ]; then
    echo
    echo "#### present but not $noun_called"
    echo
    echo "| advisory | module | fixed in | summary | aliases |"
    echo "| --- | --- | --- | --- | --- |"
    printf '%s\n' "${present_rows[@]}"
  fi
  if [ "${#notes[@]}" -gt 0 ]; then
    echo
    echo "#### notes"
    echo
    for n in "${notes[@]}"; do echo "- $n"; done
  fi
  echo
  echo "**What a clean run here is not evidence of.** \`vuln.go.dev\` is CVE-keyed, so this check reports **none** of the five CVE-less go-jose advisories that were live in this repo's module set (T-0675, T-0676). Those are covered by \`scripts/check-pinned-modules.sh --gomod\` against GitHub's per-repository endpoint. Two checks, two blind spots; neither substitutes for the other."
  echo
  case "$FAIL_ON" in
    called) echo "_Gate: a $noun_called, unacknowledged finding **fails** this check (exit 2). Acknowledge one only while there is no fix to take, in \`scripts/govulncheck-acks.txt\`, with an expiry._" ;;
    never)  echo "_Report-only: no finding fails this check. Exit 1 means findings were reported._" ;;
  esac
} >> "$REPORT"

cat "$REPORT" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
cat "$REPORT"

echo "$verdict" > "$VERDICT_FILE"
gh_out "verdict=$verdict"
gh_out "rc=$rc"
gh_out "called=$called_live"
gh_out "called_acknowledged=$called_acked"
gh_out "present=$present_total"
gh_out "stale_acks=$stale_acks"
gh_out "total=$total"

case "$verdict" in
  advisory)  printf '::error::%s: %d %s finding(s) on %s - see the job summary\n' "$PROG" "$called_live" "$noun_called" "$LABEL" ;;
  attention)
    if [ "$called_live" -gt 0 ]; then
      printf '::warning::%s: %d %s finding(s) on %s, reported not failed - see the job summary\n' "$PROG" "$called_live" "$noun_called" "$LABEL"
    elif [ "$total" -gt 0 ]; then
      printf '::notice::%s: %d finding(s) on %s, none %s\n' "$PROG" "$total" "$LABEL" "$noun_called"
    fi
    for n in "${notes[@]}"; do printf '::warning::%s\n' "$n"; done
    ;;
esac

exit "$rc"
