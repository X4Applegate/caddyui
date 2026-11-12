#!/usr/bin/env bash
# The publish gate for applegater/caddyui-caddy base-layer refreshes.
#
# Decides whether a rebuilt Caddy image may replace the published one. Used by
# .github/workflows/caddy-image-refresh.yml from BOTH the unattended scan and
# the post-approval publish, so the two cannot drift apart: the check that
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
# TWO independent gates, both hard:
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
#  2. Module set. `caddy list-modules --versions` must be IDENTICAL. Nine of
#     Dockerfile.caddy's --with arguments are unpinned and re-resolve on every
#     build, so a rebuild can bump a DNS provider, caddy-l4 or Coraza with no
#     CVE change at all — invisible to gate 1, and exactly the risk that makes
#     release-docker.yml refuse to rebuild this image blindly. A refresh is
#     allowed to change the OS layer and nothing else; bumping a plugin is a
#     deliberate act that goes through a release.
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
SEVERITY="${TRIVY_SEVERITY:-UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL}"

# A finding is identified by ID *and* package. Target is deliberately excluded:
# it contains the image reference, which differs between the two sides by
# definition, so including it would make every finding look new.
ids_from() {
  jq -r '[.Results[]?.Vulnerabilities[]?
          | "\(.VulnerabilityID)\t\(.PkgName)\t\(.InstalledVersion // "-")"]
         | unique | .[]' "$1"
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

if [ "$added_total" -gt 0 ] || [ "$moddrift" -eq 1 ]; then
  verdict=blocked
elif [ "$removed_total" -gt 0 ]; then
  verdict=improved
else
  verdict=unchanged
fi

{
  echo "### Caddy image refresh — \`$verdict\`"
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
    if [ -s "$OUT/mods-diff-$arch.txt" ]; then row+=' **yes** |'; else row+=' none |'; fi
  done
  echo "$row"
  echo

  if [ "$added_total" -gt 0 ]; then
    echo "**Gate 1 FAILED — the rebuild introduces findings the published image does not have:**"
    echo
    echo '```'
    for arch in $ARCHES; do
      while IFS=$'\t' read -r id pkg ver; do
        [ -n "${id:-}" ] || continue
        printf '%s  %s  %s %s\n' "$arch" "$id" "$pkg" "$ver"
      done < "$OUT/added-$arch.ids"
    done
    echo '```'
    echo
    echo "A refresh must only ever remove findings. Investigate before publishing."
    echo
  fi

  if [ "$moddrift" -eq 1 ]; then
    echo "**Gate 2 FAILED — the Caddy module set changed.** A refresh may change the OS layer and nothing else."
    echo
    echo "Dockerfile.caddy leaves nine \`--with\` arguments unpinned, so a rebuild can re-resolve a DNS provider, caddy-l4 or Coraza. That is a Caddy change, not a base-layer refresh, and it must go through a normal release (edit \`Dockerfile.caddy\`, cut a tag) so it is reviewed and versioned rather than arriving on \`:stable\` via a timer."
    echo
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
    echo "No new findings, and the module set is unchanged: every vulnerability in the rebuilt image is already present in the published image, against the same package."
    echo
  fi

  if [ "$removed_total" -gt 0 ]; then
    echo "<details><summary>Closed by this rebuild</summary>"
    echo
    echo '```'
    for arch in $ARCHES; do
      while IFS=$'\t' read -r id pkg ver; do
        [ -n "${id:-}" ] || continue
        printf '%s  %s  %s %s\n' "$arch" "$id" "$pkg" "$ver"
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
