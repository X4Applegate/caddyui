#!/usr/bin/env bash
# Refresh scripts/fixtures/caddy-image-coverage-floor.json from a published image.
#
# The absolute coverage floor (gate check 5e, T-0811) pins the Go-module NAME
# set observed at the last tagged release. This script regenerates it, so the
# refresh is a reproducible command producing a reviewable diff rather than a
# hand-edit nobody can check.
#
# Usage:
#   scripts/refresh-caddy-image-coverage-floor.sh [image-ref]
#
# Default ref is applegater/caddyui-caddy:stable. Pass an explicit tag or digest
# to pin the floor to a specific release.
#
# WHY THIS WRITES THROUGH A TEMP FILE AND SHOWS THE DELTA.
# The fixture's whole value is that a change to it is seen by a human. A script
# that silently overwrote it would restore exactly the invisibility this check
# exists to remove, so it prints what moved and refuses to write a floor that
# looks like a collapse unless told to.
set -euo pipefail

die() { echo "error: $*" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTFILE="$HERE/fixtures/caddy-image-coverage-floor.json"
IMAGE="${1:-applegater/caddyui-caddy:stable}"
PLATFORM="${PLATFORM:-linux/amd64}"
FLOOR_PCT="${FLOOR_PCT:-50}"

# Deliberately NOT --severity-filtered and NOT --ignore-unfixed: this reads the
# PACKAGE list, not the findings, so any filter that drops rows would shrink the
# floor. Scanners limited to vuln for speed; the package list is the same.
command -v trivy >/dev/null || die "trivy not found"
command -v jq    >/dev/null || die "jq not found"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "scanning $IMAGE ($PLATFORM) ..." >&2
trivy image --quiet --scanners vuln --format json \
      --platform "$PLATFORM" --output "$TMP/scan.json" "$IMAGE" \
  || die "trivy scan of $IMAGE failed"

# The gate compares per TARGET, so the fixture records the target it was taken
# from. Resolved from the scan rather than hardcoded, and asserted to be exactly
# one: more than one gobinary result means the image gained a second Go binary,
# which is a change a human must look at before it is baked into the floor.
mapfile -t targets < <(jq -r '[.Results[]? | select(.Type=="gobinary") | .Target] | unique | .[]' "$TMP/scan.json")
[ "${#targets[@]}" -gt 0 ] || die "$IMAGE has no gobinary scan result; nothing to pin"
if [ "${#targets[@]}" -ne 1 ]; then
  die "$IMAGE reports ${#targets[@]} gobinary targets (${targets[*]}); refusing to guess which one is the shipped binary. Inspect the image first."
fi
TARGET="${targets[0]}"

DIGEST="$(jq -r '.Metadata.RepoDigests[0]? // ""' "$TMP/scan.json")"

# Same sanitization and the same `unique` the gate applies, so the two sides
# render identically. A fixture rendered even slightly differently from the scan
# side would under-report the intersection and block legitimate releases.
jq -S --arg digest "$DIGEST" --arg target "$TARGET" \
      --arg captured "$(date +%Y-%m-%d)" --argjson pct "$FLOOR_PCT" '
  {
    _comment: "T-0811 absolute coverage floor. Go-module NAME set observed at the last tagged release. REFRESH DELIBERATELY in the release PR with scripts/refresh-caddy-image-coverage-floor.sh; see scripts/fixtures/README-caddy-image-coverage-floor.md and caddy-image-gate.sh check 5e.",
    schema: 1,
    captured: $captured,
    source_digest: $digest,
    type: "gobinary",
    target: $target,
    floor_percent: $pct,
    names: ([ .Results[]? | select(.Type == "gobinary" and .Target == $target)
              | .Packages[]?.Name
              | select(. != null and . != "")
              | tostring | gsub("[^A-Za-z0-9._:/@+-]"; "?") | .[0:160] ] | unique)
  }' "$TMP/scan.json" > "$TMP/new.json"

new_n="$(jq -r '.names | length' "$TMP/new.json")"
[ "$new_n" -gt 0 ] || die "the scan yielded zero Go module names; refusing to write an empty floor"

if [ -r "$OUTFILE" ]; then
  old_n="$(jq -r '(.names // []) | length' "$OUTFILE" 2>/dev/null || echo 0)"
  jq -r '.names[]?' "$OUTFILE" 2>/dev/null | LC_ALL=C sort -u > "$TMP/old.names" || : > "$TMP/old.names"
  jq -r '.names[]?' "$TMP/new.json"       | LC_ALL=C sort -u > "$TMP/new.names"
  added=$(LC_ALL=C comm -13 "$TMP/old.names" "$TMP/new.names" | wc -l | tr -d '[:space:]')
  removed=$(LC_ALL=C comm -23 "$TMP/old.names" "$TMP/new.names" | wc -l | tr -d '[:space:]')
  echo "current floor: $old_n names" >&2
  echo "new scan:      $new_n names  (+$added / -$removed)" >&2
  if [ "$removed" -gt 0 ]; then
    echo >&2
    echo "names this refresh would REMOVE from the floor:" >&2
    LC_ALL=C comm -23 "$TMP/old.names" "$TMP/new.names" | sed 's/^/  - /' >&2
    echo >&2
    # A refresh that drops names is exactly what the reviewer must see, so it
    # is loud. Not a refusal: removing a plugin legitimately drops its whole
    # dependency subtree, and that is a normal release.
    echo "NOTE: a refresh that removes names LOWERS the floor. That is legitimate for a" >&2
    echo "      removed plugin, and is the thing to explain in the release PR description." >&2
  fi
else
  echo "no existing floor; writing $new_n names" >&2
fi

mv "$TMP/new.json" "$OUTFILE"
echo >&2
echo "wrote $OUTFILE" >&2
echo "  type=gobinary target=$TARGET names=$new_n floor=${FLOOR_PCT}%" >&2
echo "  source=$IMAGE${DIGEST:+ ($DIGEST)}" >&2
echo >&2
echo "review the diff before committing:" >&2
echo "  git diff -- scripts/fixtures/caddy-image-coverage-floor.json" >&2
