#!/usr/bin/env bash
# The publish gate for applegater/caddyui-caddy.
#
# Decides whether a rebuilt Caddy image may replace the published one. Used by
# BOTH workflows that move this image's :stable/:latest tags:
#
#   caddy-image-refresh.yml  the weekly base-layer refresh, from its unattended
#                            scan AND its post-approval publish
#   release-docker.yml       the release that publishes :vX.Y.Z, after the push
#                            and before the moving tags are created
#
# One copy, so the standard cannot drift between the paths: the check that
# gave a reviewer their verdict is byte-for-byte the check that guards the
# moving tags.
#
# Usage:
#   caddy-image-gate.sh <new-image-ref> <baseline-image-ref> <out-dir> [arches]
#
#   new-image-ref       The rebuild. Locally loaded tag, or repo@sha256:… .
#   baseline-image-ref  The currently-published image, normally <repo>:stable.
#   out-dir             Written to: per-arch scans, id lists, module lists,
#                       summary.md, and verdict.
#   arches              Space-separated, default "amd64 arm64".
#
# Environment:
#   TRIVY_SEVERITY      Severities to scan. Default UNKNOWN,LOW,…,CRITICAL.
#   MODULE_DRIFT_POLICY block (default) | report. See gate 2 below. The default
#                       is the strict one so a caller that forgets the variable
#                       gets the SAFER behaviour, never the weaker one.
#
# Requires: trivy, jq, docker. Trivy's DB must already be downloaded
# (`trivy image --download-db-only`): the caller does that ONCE so every scan
# in a run compares against the same DB version. A subset comparison across
# two DB versions is meaningless, which is why this script never updates it.
#
# Writes "verdict=<improved|unchanged|blocked>" plus the summary to stdout and,
# when GITHUB_OUTPUT is set, to that file. Exit status:
#   0  improved or unchanged  (safe: nothing new)
#   1  blocked                (a human must look)
#   2  the gate could not run (treat as blocked)
#
# A COVERAGE PRECONDITION, then TWO independent gates:
#
#  0. Scan coverage. Before either gate runs, assert the new image's Trivy scan
#     actually looked at the image: an OS was detected, it is not end-of-life,
#     every scan target the baseline had is still present, and each shared
#     target's package count has not collapsed. This is a precondition rather
#     than a gate because it produces no verdict -- it exits 2 ("the gate could
#     not run"), which all three call sites already treat as blocking.
#
#     It exists because gate 1 is set arithmetic, and set arithmetic reads an
#     EMPTY findings list as a perfect score. That made this the ONE fail-open
#     path in the script: an image Trivy cannot analyse has no findings to add,
#     so the subset check passes and the verdict comes out `improved` precisely
#     because nothing could be seen. See assert_scan_coverage below.
#
#  1. Vulnerability subset. The rebuild's findings must be a SUBSET of the
#     published image's, per arch. Deliberately not "zero findings": every
#     image to date carries GO-2026-5932 (x/crypto/openpgp unmaintained, no
#     fix, not reached by the binary), so a zero-findings rule could never
#     publish anything. Because such a standing finding is present on BOTH
#     sides it cancels out of the set arithmetic by construction, with no
#     allowlist to maintain and no exception that could quietly start hiding
#     something real.
#
#     Compared as ID+package, not ID alone: the same CVE ID appearing against
#     a DIFFERENT package is a new exposure, and comparing bare IDs would let
#     it cancel out.
#
#  2. Module set, from `caddy list-modules --versions`. Every --with argument
#     in Dockerfile.caddy now carries a version, so a rebuild should reproduce
#     the same module set; this gate is the independent check that it actually
#     did. It catches what gate 1 cannot: a resolver, proxy or toolchain change
#     that moves a DNS provider, caddy-l4 or Coraza with no CVE change at all,
#     and a pin edit that reached the image without going through a release.
#
#     What a module-set change MEANS depends on which path is running, so this
#     gate has two policies and the caller picks:
#
#       block   (default, the refresh path) Any drift is wrong BY DEFINITION.
#               A refresh rebuilds an UNCHANGED Dockerfile.caddy from a release
#               tag, so the module set must come out identical; if it did not,
#               something re-resolved and a timer is about to ship a plugin bump
#               to :stable. Blocking is the whole point.
#
#       report  (the release path) Drift is the EXPECTED OUTCOME of a release
#               that edits Dockerfile.caddy — that is how a plugin bump is
#               meant to arrive. Blocking here would mean no module change
#               could ever be released, i.e. the gate would forbid the one
#               legitimate route it tells refreshes to use. So the diff is
#               computed, printed in full and carried into the job summary,
#               and the verdict is decided by gate 1 alone.
#
#     report does NOT weaken gate 1: a release that introduces a NEW
#     vulnerability still blocks, under either policy. Drift stops being an
#     automatic verdict; it does not stop being reviewed. The release diff is
#     the reviewable record of what the module set change actually was.
set -euo pipefail

die() { echo "::error::$*" >&2; exit 2; }

[ $# -ge 3 ] || die "usage: $0 <new-image> <baseline-image> <out-dir> [arches]"

NEW_IMAGE="$1"
BASELINE="$2"
OUT="$3"
ARCHES="${4:-amd64 arm64}"

command -v trivy >/dev/null || die "trivy not found"
command -v jq    >/dev/null || die "jq not found"
command -v docker >/dev/null || die "docker not found"

mkdir -p "$OUT"

# Remove any verdict left by a PREVIOUS run in this directory, before anything
# that can `die`.
#
# The refresh path reads the verdict FILE rather than the exit status
# (`cat scan/verdict 2>/dev/null || echo error`) and turns a missing file into
# verdict=error, which fails the job. That is what makes exit 2 blocking there.
# A stale file from an earlier run in the same directory would be read as THIS
# run's answer, so a gate that aborted at exit 2 would be reported as whatever
# the last run concluded -- including `improved`. Deleting it up front means an
# aborted gate always presents as an ABSENT verdict, never an old one.
rm -f "$OUT/verdict"

SEVERITY="${TRIVY_SEVERITY:-UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}"

# Unset or empty means block: a caller that forgets this variable gets the
# strict refresh behaviour. Only the two spellings are accepted — a typo such
# as MODULE_DRIFT_POLICY=Report must not silently fall through to the weaker
# policy, so it is a hard stop rather than a default.
DRIFT_POLICY="${MODULE_DRIFT_POLICY:-block}"
case "$DRIFT_POLICY" in
  block|report) ;;
  *) die "MODULE_DRIFT_POLICY must be 'block' or 'report' (got: $DRIFT_POLICY)" ;;
esac

# A finding is identified by ID *and* package, and DELIBERATELY NOT by the
# installed version.
#
# Target is excluded because it contains the image reference, which differs
# between the two sides by definition, so including it would make every finding
# look new.
#
# InstalledVersion is excluded for a sharper reason: including it made an
# UPGRADE of a still-affected package look like a brand-new exposure. Measured
# on the real images — GO-2026-5932 (x/crypto, unmaintained openpgp, no fix
# available) sits on both sides of v2.61.0 -> v2.68.9, at v0.57.0 and v0.58.0.
# Keyed with the version it appeared as one finding removed plus one added, so
# the subset gate BLOCKED; keyed on ID+package it correctly cancels out and the
# added count is zero.
#
# That mattered little while this gate only guarded refreshes, where the
# package set is not supposed to move at all. On the release path it would
# block the ordinary case of a security release: bump a module to a newer
# version that is still affected by one standing advisory, and the gate calls
# your fix a regression. Fixing forward would block the same way.
#
# What this gives up is small and recoverable: a same-ID finding against the
# same package whose version moved is no longer counted as new. The version
# change is still visible in the per-arch JSON kept as a build artifact, and a
# genuinely new exposure means a new ID or a new package, which is still
# caught.
ids_from() {
  jq -r '[.Results[]?.Vulnerabilities[]?
          | "\(.VulnerabilityID)\t\(.PkgName)"]
         | unique | .[]' "$1"
}

# ---------------------------------------------------------------------------
# Scan coverage: did Trivy actually LOOK at the new image?
#
# Gate 1 is set arithmetic on two findings lists, so it reads an EMPTY findings
# list as a perfect result. Every other failure mode in this script is
# fail-closed; this one is fail-OPEN, and that is the dangerous direction. An
# image Trivy cannot analyse produces no findings to add, so the subset check
# passes and the verdict comes out `improved` *because* nothing could be seen.
# Fewer findings is read as better rather than as blind, and the moving tags
# then advance onto an unscanned image.
#
# Reachable without anything exotic. A release may edit Dockerfile.caddy
# freely, and all of these produce it:
#   - the base becomes scratch or distroless, so there is no OS package
#     database to detect and the `alpine` result disappears
#   - the Go build info is stripped (-ldflags, a trimmed binary, a different
#     builder), so the `gobinary` result disappears and with it every Go
#     module finding
#   - the binary moves, so Trivy's language-file walk no longer finds it
#   - a Trivy upgrade, a missing java-db, or an analyser error degrades one
#     target silently and exits 0 anyway
#
# Measured on the real images to be sure this is not theoretical: the published
# :stable scan yields exactly two results, `alpine` (32 packages) and
# `gobinary` (236 packages). Delete the `gobinary` result alone and all 8
# findings vanish; the gate then reports 8 removed, 0 added, verdict=improved,
# exit 0 -- and :stable and :latest move.
#
# So before comparing, assert the new scan is actually a scan. Each check is a
# hard stop (exit 2, "the gate could not run") rather than a verdict, because
# "I could not see" is not a result and must never be averaged with one. Exit 2
# is already blocking in all three call sites.
#
# Checked against the BASELINE rather than against hardcoded expectations: the
# baseline is a real scan of the image the fleet is running, so it defines what
# "looked at this image properly" means for this image, and it moves forward on
# its own as the image changes. A hardcoded list of expected types would have
# to be edited by the same release that is being gated -- which is precisely
# the actor this check exists to constrain.
scan_types() {
  jq -r '[.Results[]?.Type | select(. != null and . != "")] | unique | .[]' "$1"
}

# Scan-derived strings are UNTRUSTED. .Metadata.OS.Family and .Results[].Type
# come from the image under test, which on the release path is built from a
# Dockerfile the submitter controls -- i.e. the exact actor this gate exists to
# constrain. These values are interpolated into `::error::` lines, and the
# summary they land in is also appended to $GITHUB_OUTPUT inside a
# `summary<<GATE_SUMMARY_EOF` heredoc.
#
# A newline in such a value therefore lets the image forge GitHub Actions
# workflow commands, and a line reading exactly GATE_SUMMARY_EOF closes the
# heredoc early so the rest is parsed as further step outputs -- including
# `verdict=improved`. Verified reachable through all three new messages before
# this was added.
#
# So flatten to one line and strip the two metacharacter sequences that give a
# log line authority: `::` (a workflow command) and `%` (the encoding GitHub
# uses for escaped newlines in those commands). Truncated, because an
# arbitrarily long field is its own denial-of-readability.
#
# Collapse any RUN of colons to one, rather than replacing the pair `::`.
# `s/::/:/g` consumes non-overlapping pairs, so `:::error` -> `::error` leaves
# exactly the sequence being removed; `:::::` -> `:::`. A run-collapse has no
# such residue for any number of colons. Flattening newlines already stops a
# forged command from starting a line, which is what GitHub actually requires,
# but the two are independent defences and neither should carry this alone.
safe_text() {
  printf '%s' "$1" \
    | tr '\n\r\t' '   ' \
    | sed -e 's/:\{2,\}/:/g' -e 's/%/pct/g' \
    | cut -c1-200
}

# Packages are present even under `--scanners vuln` (verified: 32 OS packages,
# 236 Go modules on :stable), so a per-type package count is available without
# a second scan. This is the check that catches a PARTIAL blinding, where the
# result type still exists but has been reduced to almost nothing -- which set
# arithmetic cannot distinguish from a genuine fix.
#
# Counts the Packages ARRAY rather than its entries, so "the key is absent or
# null" is distinguishable from "the key is an empty list". Emits the literal
# `unmeasurable` for the former. A count that cannot be taken must not be
# reported as 0: 0 reads as "nothing to compare" and skips the floor, which is
# the same fail-open shape this whole function exists to close, one level down.
pkg_count_for_type() {
  jq -r --arg t "$2" '
    [ .Results[]? | select(.Type == $t) ] as $r
    | if ($r | length) == 0 then "absent"
      elif ($r | map(select((.Packages | type) == "array")) | length) == 0 then "unmeasurable"
      else ( $r | map(.Packages // [] | length) | add )
      end' "$1"
}

assert_scan_coverage() {
  local new="$1" old="$2" arch="$3"
  local os_family new_types old_types missing t new_pkgs old_pkgs floor eosl

  # 1. The OS layer was identified.
  #
  # Absent Family means Trivy could not tell what the base was, so the `alpine`
  # result and every OS package finding are missing by definition. jq prints
  # the string "null" for a missing key, so test for that spelling too.
  os_family="$(jq -r '.Metadata.OS.Family // ""' "$new")"
  case "$os_family" in
    ""|null)
      die "no OS detected in the rebuild's scan of linux/$arch (.Metadata.OS.Family absent): Trivy could not analyse this image, so an empty findings list means BLIND, not clean. Refusing to read it as an improvement." ;;
  esac

  # 2. The OS is still supported by the vulnerability database.
  #
  # Trivy omits EOSL entirely when false and emits only `"EOSL": true`
  # (verified on both alpine 3.23.6 and 3.23.7), so test for true rather than
  # for presence -- `has("EOSL")` would be false on every healthy image and
  # `// ""` would make absent indistinguishable from false.
  #
  # Past end-of-life the distro stops publishing advisories, so OS findings
  # stop appearing while the packages stay just as vulnerable. That is the same
  # fail-open shape as a missing scanner: the list shrinks because the data
  # stopped, not because the image got better.
  eosl="$(jq -r '.Metadata.OS.EOSL // false' "$new")"
  if [ "$eosl" = true ]; then
    die "the rebuild's base OS ($(safe_text "$os_family")) is flagged END-OF-LIFE in the vulnerability database for linux/$arch: advisories are no longer published for it, so a short findings list reflects missing DATA rather than a fixed image. Rebase onto a supported release."
  fi

  # 3. Every scan target the baseline had, the rebuild still has.
  #
  # This is the check that catches a vanished `gobinary`. A target that was
  # scanned before and is not scanned now is an ERROR, not an improvement:
  # whatever it used to report is now simply unobserved. Direction matters --
  # the rebuild may ADD types (a new ecosystem is more coverage, which is
  # fine), it may not LOSE them.
  new_types="$(scan_types "$new")"
  old_types="$(scan_types "$old")"
  missing="$(comm -13 <(printf '%s\n' "$new_types" | sort) \
                      <(printf '%s\n' "$old_types" | sort))"
  if [ -n "$missing" ]; then
    # tr-join each list onto one line, then trim the trailing separator, so the
    # message reads as prose instead of "gobinary-- that target".
    local missing_1l old_1l new_1l
    missing_1l="$(safe_text "$(printf '%s' "$missing"   | tr '\n' ' ')")"; missing_1l="${missing_1l% }"
    old_1l="$(safe_text "$(printf '%s' "$old_types"    | tr '\n' ' ')")"; old_1l="${old_1l% }"
    new_1l="$(safe_text "$(printf '%s' "$new_types"    | tr '\n' ' ')")"; new_1l="${new_1l% }"
    die "the rebuild's scan of linux/$arch lost scan target(s) the published image has: $missing_1l -- that target is now UNOBSERVED, not clean, so any finding it used to report would silently cancel out of the subset comparison. (published: $old_1l / rebuild: $new_1l)"
  fi

  # 4. A package-count floor per shared target.
  #
  # Checks 1-3 catch a target that disappeared; this catches one that is still
  # present but has been gutted -- a stripped binary that still parses as
  # `gobinary` but yields 3 modules instead of 236, or an OS database read
  # partially. Set arithmetic cannot tell that from a real fix.
  #
  # The floor is deliberately loose (50% of baseline), because a legitimate
  # release really can remove packages: dropping a plugin removes its whole
  # dependency subtree. The purpose is to catch a COLLAPSE in visibility, not
  # to police ordinary churn -- a tight floor here would block real releases
  # and get switched off, which is worse than a loose one that stays on.
  # Measured for scale: the Go module count moved 213 -> 236 across v2.55.0 ->
  # :stable, i.e. ~10% and upward, nowhere near this floor.
  #
  # Rounded UP, not down. Rounded down, a baseline of 1 package yields floor 0,
  # and `0 -lt 0` is false, so a target the baseline could see one package in
  # and the rebuild can see NONE in would pass. Rounding up makes a floor of at
  # least 1 for any non-empty baseline, so "the baseline saw something here and
  # the rebuild sees nothing" is always caught.
  #
  # Only types present on BOTH sides are compared. A type the rebuild added has
  # no baseline to be measured against, and check 3 has already established
  # nothing was lost.
  for t in $new_types; do
    printf '%s\n' "$old_types" | grep -qxF "$t" || continue
    new_pkgs="$(pkg_count_for_type "$new" "$t")"
    old_pkgs="$(pkg_count_for_type "$old" "$t")"

    # An unmeasurable count is a hard stop, on EITHER side, rather than a
    # skipped check. `unmeasurable` means the result exists but its Packages is
    # absent or not a list, so the count cannot be taken -- and check 3 cannot
    # help here, because the type IS present on both sides. Treating it as
    # "nothing to compare" would let a rebuild be gutted for exactly the
    # targets whose baseline count happens to be unreadable.
    case "$new_pkgs" in
      unmeasurable|absent)
        die "the rebuild's '$(safe_text "$t")' scan of linux/$arch reports no readable package list (Packages absent or not an array), so its package count cannot be taken and the target's contents are UNOBSERVED rather than clean. Refusing to compare against it." ;;
    esac
    case "$old_pkgs" in
      absent) continue ;;
      unmeasurable)
        die "the published image's '$(safe_text "$t")' scan of linux/$arch reports no readable package list, so there is no measurable baseline for this target and a collapse in the rebuild's coverage could not be detected. Refusing to treat an unmeasurable baseline as nothing to check." ;;
    esac

    # Both counts are integers from here: jq's `add` over array lengths.
    [ "$old_pkgs" -gt 0 ] || continue
    floor=$(( (old_pkgs + 1) / 2 ))
    if [ "$new_pkgs" -lt "$floor" ]; then
      die "the rebuild's '$(safe_text "$t")' scan of linux/$arch sees $new_pkgs package(s) where the published image has $old_pkgs (floor $floor): the target is present but its contents largely could not be read, so most of it is UNOBSERVED rather than fixed. A findings list this far short of the baseline's cannot be compared against it."
    fi
  done

  printf 'scan coverage OK (linux/%s): os=%s, targets=%s\n' \
    "$arch" "$(safe_text "$os_family")" "$(safe_text "$(printf '%s' "$new_types" | tr '\n' ' ')")"
}

# `caddy list-modules --versions` from inside the image. The image is
# distroless-ish with caddy as its entrypoint, so --entrypoint is required;
# without it the binary boots a server instead of answering.
modules_from() {
  local ref="$1" arch="$2" out="$3"
  if ! docker run --rm --platform "linux/$arch" --entrypoint /usr/bin/caddy \
        "$ref" list-modules --versions >"$out" 2>/dev/null; then
    die "cannot list modules in $ref ($arch); refusing to guess the module set"
  fi
  # Drop blank lines and the "Standard modules"/"Non-standard" headings so the
  # diff is module lines only.
  grep -E '^[a-z0-9_.]+ v' "$out" | sort -o "$out"
  [ -s "$out" ] || die "no modules parsed from $ref ($arch)"
}

for arch in $ARCHES; do
  echo "::group::gate: linux/$arch"

  # Make sure the right architecture of each side is in the local daemon.
  #
  # A baseline that cannot be obtained is a HARD STOP, not an empty set. An
  # empty baseline would make every finding look new (noisy but safe) or, read
  # the other way, "nothing to compare" (silent and dangerous). Neither is a
  # verdict, so fail instead.
  #
  # A pull failure is only fatal when the image is not already local at the
  # right arch: in CI the rebuild is a locally-loaded tag that does not exist
  # in any registry, and in a local dry-run the baseline may be too.
  #
  # A MUTABLE TAG CANNOT NAME AN ARCHITECTURE. One tag is one entry in the
  # local image store, so after the amd64 pass `:stable` is resolved to amd64
  # there, and whether a later `docker pull --platform linux/arm64` of the
  # same tag replaces that entry is daemon- and store-dependent: it does on a
  # plain overlay2 host, and does NOT on the GitHub runner, where the arm64
  # pass then died with "cannot obtain baseline ... (local arch: amd64)".
  # So for a registry image, resolve the tag through its manifest list to the
  # DIGEST for the arch being gated and use that digest as the reference.
  # A digest names exactly one artifact, cannot be shadowed by the other
  # arch's copy of the same tag, and does not depend on pull-replaces-tag
  # semantics. Returns the reference to actually use, on stdout.
  resolve_ref() {
    local ref="$1" want="$2" role="$3" have digest repo

    # Already local at the right arch (the locally-built rebuild, or a
    # dry-run baseline that was loaded by hand): use it as given. Checked
    # first so a locally-loaded tag never needs a registry at all.
    have="$(docker image inspect --format '{{.Architecture}}' "$ref" 2>/dev/null || true)"
    if [ "$have" = "$want" ] && ! printf '%s' "$ref" | grep -q '@sha256:'; then
      printf '%s\n' "$ref"
      return 0
    fi

    # A DIGEST IS NOT NECESSARILY ONE ARTIFACT. A multi-arch push reports the
    # INDEX digest, and an index names one child manifest per arch, so pulling
    # it yields the host's native arch exactly like a tag does. Treating
    # `@sha256:` as inherently unambiguous is what made the first real publish
    # abort: the amd64 pass gated `improved`, then the arm64 pass pulled the
    # same index digest, got amd64, and died with "cannot obtain rebuild image
    # ... (got: amd64)" — after the -pN tag had already been pushed.
    # So resolve through the manifest list for BOTH forms below, and only fall
    # back to pulling the reference as given when it has no manifest list
    # (a true single-arch image digest, or an unreachable registry).
    #
    # Reduce the reference to its repository before appending the child digest.
    # Strip a trailing @digest first, then a trailing :tag — and only when that
    # colon is in the LAST path segment, because `%%:*` would otherwise eat a
    # registry port ("registry:5000/ns/img" -> "registry").
    repo="${ref%%@*}"
    case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
    digest="$(docker manifest inspect "$ref" 2>/dev/null | jq -r --arg a "$want" '
      if .manifests then
        [ .manifests[]
          | select(.platform.architecture == $a and .platform.os == "linux")
          | .digest ] | first // empty
      else empty end' || true)"

    if [ -n "$digest" ]; then
      docker pull --quiet "$repo@$digest" >/dev/null 2>&1 || true
      have="$(docker image inspect --format '{{.Architecture}}' "$repo@$digest" 2>/dev/null || true)"
      [ "$have" = "$want" ] \
        || die "cannot obtain $role image $repo@$digest for linux/$want (got: ${have:-absent}); refusing to compare against an unknown image"
      printf '%s\n' "$repo@$digest"
      return 0
    fi

    # No manifest list (single-arch image, or the registry is unreachable).
    # Fall back to the platform pull, then VERIFY the arch, so a
    # single-arch repo still gates and a wrong arch is still a hard stop.
    docker pull --quiet --platform "linux/$want" "$ref" >/dev/null 2>&1 || true
    have="$(docker image inspect --format '{{.Architecture}}' "$ref" 2>/dev/null || true)"
    [ "$have" = "$want" ] \
      || die "cannot obtain $role image $ref for linux/$want (local arch: ${have:-absent}); refusing to compare against an unknown image"
    printf '%s\n' "$ref"
  }

  base_ref="$(resolve_ref "$BASELINE"  "$arch" baseline)"
  new_ref="$(resolve_ref "$NEW_IMAGE" "$arch" rebuild)"

  trivy image --skip-db-update --scanners vuln --severity "$SEVERITY" \
    --format json --output "$OUT/new-$arch.json" "$new_ref"
  trivy image --skip-db-update --scanners vuln --severity "$SEVERITY" \
    --format json --output "$OUT/old-$arch.json" "$base_ref"

  # Before ANY comparison: prove the new scan actually looked at the image.
  # Gate 1 cannot tell an image with no vulnerabilities from an image Trivy
  # could not read, so that distinction has to be made here, against the
  # baseline, while both scans are in hand. Hard-stops at exit 2 on failure.
  assert_scan_coverage "$OUT/new-$arch.json" "$OUT/old-$arch.json" "$arch"

  ids_from "$OUT/new-$arch.json" | sort > "$OUT/new-$arch.ids"
  ids_from "$OUT/old-$arch.json" | sort > "$OUT/old-$arch.ids"
  comm -23 "$OUT/new-$arch.ids" "$OUT/old-$arch.ids" > "$OUT/added-$arch.ids"
  comm -13 "$OUT/new-$arch.ids" "$OUT/old-$arch.ids" > "$OUT/removed-$arch.ids"

  modules_from "$new_ref"  "$arch" "$OUT/mods-new-$arch.txt"
  modules_from "$base_ref" "$arch" "$OUT/mods-old-$arch.txt"
  diff -u "$OUT/mods-old-$arch.txt" "$OUT/mods-new-$arch.txt" \
    > "$OUT/mods-diff-$arch.txt" || true

  echo "::endgroup::"
done

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
added_total=0
removed_total=0
moddrift=0
for arch in $ARCHES; do
  added_total=$(( added_total + $(wc -l < "$OUT/added-$arch.ids") ))
  removed_total=$(( removed_total + $(wc -l < "$OUT/removed-$arch.ids") ))
  [ -s "$OUT/mods-diff-$arch.txt" ] && moddrift=1
done

# Gate 2 contributes to the verdict only under the block policy. Under report
# the drift is still measured, still diffed and still printed below — it just
# does not decide the verdict, because on the release path drift is the
# intended result rather than a fault.
drift_blocks=0
if [ "$moddrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
  drift_blocks=1
fi

if [ "$added_total" -gt 0 ] || [ "$drift_blocks" -eq 1 ]; then
  verdict=blocked
elif [ "$removed_total" -gt 0 ]; then
  verdict=improved
else
  verdict=unchanged
fi

{
  # The heading names the path, because this script now guards two of them and
  # a summary headed "refresh" on a release run would be actively misleading.
  if [ "$DRIFT_POLICY" = block ]; then
    echo "### Caddy image refresh — \`$verdict\`"
  else
    echo "### Caddy image release gate — \`$verdict\`"
  fi
  echo
  echo "\`$NEW_IMAGE\` vs published \`$BASELINE\`"
  echo
  printf '| | %s |\n' "$(echo "$ARCHES" | tr ' ' '|')"
  printf '|---|%s\n' "$(for _ in $ARCHES; do printf -- '---|'; done)"
  for label in old new removed added; do
    case "$label" in
      old)     name='findings, published' ;;
      new)     name='findings, rebuilt' ;;
      removed) name='closed by the rebuild' ;;
      added)   name='**newly introduced**' ;;
    esac
    row="| $name |"
    for arch in $ARCHES; do
      row+=" $(wc -l < "$OUT/$label-$arch.ids" | tr -d ' ') |"
    done
    echo "$row"
  done
  row='| module-set drift |'
  for arch in $ARCHES; do
    if [ -s "$OUT/mods-diff-$arch.txt" ]; then
      # Say which policy is in force on the row itself: "yes" alone reads as a
      # failure, and on the release path it is not one.
      if [ "$DRIFT_POLICY" = block ]; then row+=' **yes** |'; else row+=' yes (expected) |'; fi
    else
      row+=' none |'
    fi
  done
  echo "$row"
  echo

  if [ "$added_total" -gt 0 ]; then
    echo "**Gate 1 FAILED — the rebuild introduces findings the published image does not have:**"
    echo
    echo '```'
    for arch in $ARCHES; do
      while IFS=$'\t' read -r id pkg; do
        [ -n "${id:-}" ] || continue
        printf '%s  %s  %s\n' "$arch" "$id" "$pkg"
      done < "$OUT/added-$arch.ids"
    done
    echo '```'
    echo
    if [ "$DRIFT_POLICY" = block ]; then
      echo "A refresh must only ever remove findings. Investigate before publishing."
    else
      echo "A release may change the module set, but it must not introduce a vulnerability the published image does not already have. The immutable \`:vX.Y.Z\` tag exists; \`:stable\` and \`:latest\` were NOT moved. Investigate before moving them."
    fi
    echo
  fi

  if [ "$moddrift" -eq 1 ] && [ "$DRIFT_POLICY" = block ]; then
    echo "**Gate 2 FAILED — the Caddy module set changed.** A refresh may change the OS layer and nothing else."
    echo
    echo "Every \`--with\` in Dockerfile.caddy is pinned, so a module-set change here means the build did not reproduce the pinned set — a re-resolved DNS provider, caddy-l4 or Coraza, or a pin edit that never went through a release. That is a Caddy change, not a base-layer refresh, and it must go through a normal release (edit \`Dockerfile.caddy\`, cut a tag) so it is reviewed and versioned rather than arriving on \`:stable\` via a timer."
    echo
  elif [ "$moddrift" -eq 1 ]; then
    echo "**Module set changed — reported, not blocked.** This is the release path, where editing \`Dockerfile.caddy\` is how a plugin bump is *supposed* to arrive, so the diff below is the expected result rather than a fault."
    echo
    echo "Read it anyway: it is the authoritative record of what this release actually did to the module set, taken from \`caddy list-modules --versions\` inside the pushed image rather than from the Dockerfile diff. Modules can move **without** a \`--with\` edit (a transitive dependency of a bumped plugin), and a \`--with\` edit can fail to move anything. Anything here you did not intend to change is a finding."
    echo
  fi

  if [ "$moddrift" -eq 1 ]; then
    for arch in $ARCHES; do
      if [ -s "$OUT/mods-diff-$arch.txt" ]; then
        echo "<details><summary>Module diff, linux/$arch (published → rebuilt)</summary>"
        echo
        echo '```diff'
        cat "$OUT/mods-diff-$arch.txt"
        echo '```'
        echo
        echo "</details>"
        echo
      fi
    done
  fi

  if [ "$verdict" != blocked ]; then
    if [ "$moddrift" -eq 1 ]; then
      echo "No new findings: every vulnerability in the new image is already present in the baseline image, against the same package. The module set changed, which is expected here and is diffed above."
    else
      echo "No new findings, and the module set is unchanged: every vulnerability in the rebuilt image is already present in the published image, against the same package."
    fi
    echo
  fi

  if [ "$removed_total" -gt 0 ]; then
    echo "<details><summary>Closed by this rebuild</summary>"
    echo
    echo '```'
    for arch in $ARCHES; do
      while IFS=$'\t' read -r id pkg; do
        [ -n "${id:-}" ] || continue
        printf '%s  %s  %s\n' "$arch" "$id" "$pkg"
      done < "$OUT/removed-$arch.ids"
    done
    echo '```'
    echo
    echo "</details>"
    echo
  fi
} > "$OUT/summary.md"

cat "$OUT/summary.md"
echo "$verdict" > "$OUT/verdict"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "verdict=$verdict"
    echo "added_count=$added_total"
    echo "removed_count=$removed_total"
    echo "module_drift=$moddrift"
    echo "module_drift_policy=$DRIFT_POLICY"
    echo "summary<<GATE_SUMMARY_EOF"
    cat "$OUT/summary.md"
    echo "GATE_SUMMARY_EOF"
  } >> "$GITHUB_OUTPUT"
fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi

[ "$verdict" = blocked ] && exit 1
exit 0
