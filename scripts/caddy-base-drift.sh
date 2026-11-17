#!/usr/bin/env bash
# caddy-base-drift.sh — has the pinned Caddy base image moved since the published
# applegater/caddyui-caddy was built?
#
# WHY THIS EXISTS (T-0709)
# ------------------------
# release-docker.yml rebuilds the Caddy image only when Dockerfile.caddy differs from the
# previous release tag. That trigger asks "did a human edit the file?", which is uncorrelated
# with "does the image need rebuilding?": Dockerfile.caddy pins its bases by TAG
# (caddy:2.11.9-alpine), and that tag is mutable upstream, so Alpine can ship a security fix
# under the same name with nothing in this repository changing. release-docker.yml's own
# header concedes it — "Alpine security fixes can sit built-but-unshipped between releases".
#
# Three of the eight releases before v2.68.9 (v2.68.6, v2.68.7, v2.68.8) skipped the rebuild,
# and nothing anywhere said so. This script is what makes the answer checkable.
#
# WHAT IT COMPARES, AND WHY THE TWO OBVIOUS COMPARISONS ARE BOTH WRONG
# ---------------------------------------------------------------------
# Each of these looks right and produces a FALSE "the base moved" on runs where nothing that
# ships has changed. Both were measured against the live registry before this script settled
# on the third approach.
#
#   1. GREPPING THE PROVENANCE for a sha256. The provenance JSON holds many digests — layers,
#      the build context, the SBOM scanner. The first match is an unrelated hash. The base
#      lives in buildDefinition.resolvedDependencies keyed by a purl and must be looked up BY
#      NAME (pkg:docker/library/caddy@2.11.9-alpine), never by position.
#
#   2. COMPARING INDEX DIGESTS. `imagetools inspect <tag>` reports the multi-arch INDEX
#      digest, and the provenance also records an index digest — so this one at least
#      compares like with like. It still cries wolf: an index digest changes when the tag is
#      re-pushed even if every platform manifest it points at is byte-identical. Measured on
#      caddy:2.11.9-alpine — provenance recorded index sha256:0bbb055b…, the tag now resolves
#      to index sha256:003a9780…, and BOTH indexes serve the SAME amd64 manifest
#      sha256:fc9cbc10… . Nothing that ships changed; an index comparison would have reported
#      a security-relevant base move.
#
# So this script resolves BOTH SIDES DOWN TO PER-PLATFORM MANIFEST DIGESTS and compares
# those: the base recorded in provenance is dereferenced through its index, the pinned tag is
# dereferenced through its index, and the two are matched per platform. That is the only
# comparison that answers "do the bytes that would ship differ?".
#
# Note arm64 is listed as linux/arm64/v8 in the caddy index but as linux/arm64 in provenance,
# so variant spellings are reconciled; matching on the bare key alone silently drops arm64.
#
# EXIT STATUS — three outcomes, never collapsed into two:
#   0  base unchanged (or, with --advisory, any outcome at all)
#   1  base MOVED: the published image is missing upstream base-layer changes
#   2  could not determine (registry unreachable, provenance unreadable, platform absent)
#
# Status 2 is not status 0. An unanswered question must not be scored as a pass — that is the
# same standard caddy-image-gate.sh and release-docker.yml's move step already hold: "an
# unanswered question must not be scored as a pass".
#
# USAGE
#   scripts/caddy-base-drift.sh [--advisory] [IMAGE_REF] [DOCKERFILE]
#     IMAGE_REF   published image to check   (default applegater/caddyui-caddy:stable)
#     DOCKERFILE  file holding the base pin  (default Dockerfile.caddy)
#     --advisory  always exit 0; report the verdict on stdout only. Used by release-docker.yml,
#                 where a moved base must not fail a release that was itself correct.
#
# Writes a Markdown verdict to $GITHUB_STEP_SUMMARY when set, and sets a `drift` output key
# (unchanged|moved|unknown) when $GITHUB_OUTPUT is set.

set -uo pipefail

advisory=false
if [ "${1:-}" = --advisory ]; then advisory=true; shift; fi

IMAGE_REF="${1:-applegater/caddyui-caddy:stable}"
DOCKERFILE="${2:-Dockerfile.caddy}"

note() { printf '%s\n' "$*"; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; return 0; }

finish() {
  local status="$1" code="$2"
  [ -n "${GITHUB_OUTPUT:-}" ] && printf 'drift=%s\n' "$status" >> "$GITHUB_OUTPUT"
  if [ "$advisory" = true ]; then exit 0; fi
  exit "$code"
}

command -v docker >/dev/null 2>&1 || { note "docker not available"; summary "⚠️ \`docker\` is not available, so base drift could not be checked."; finish unknown 2; }
command -v python3 >/dev/null 2>&1 || { note "python3 not available"; summary "⚠️ \`python3\` is not available, so base drift could not be checked."; finish unknown 2; }

# The RUNTIME stage's base — the last FROM in the file — is the one carrying the Alpine layer
# and its CVEs. Read from the Dockerfile so bumping the pin cannot leave this comparing
# against a version nobody builds any more. `--platform=` on the builder stage is ignored
# because only the final FROM is taken.
BASE="$(awk '/^[[:space:]]*FROM[[:space:]]/ { for (i = 2; i <= NF; i++) if ($i !~ /^--/) { f = $i; break } } END { print f }' "$DOCKERFILE" 2>/dev/null)"
if [ -z "$BASE" ]; then
  note "could not read a base image from $DOCKERFILE"
  summary "⚠️ Could not read the base image pin from \`$DOCKERFILE\`, so this run cannot say whether the base moved."
  finish unknown 2
fi
note "base pin:    $BASE"
note "published:   $IMAGE_REF"

upstream_raw="$(docker buildx imagetools inspect "$BASE" --raw 2>&1)"
if [ $? -ne 0 ] || [ -z "$upstream_raw" ]; then
  note "could not resolve $BASE upstream"
  summary "⚠️ Could not resolve \`$BASE\` upstream, so this run cannot say whether the base moved."
  finish unknown 2
fi

prov="$(docker buildx imagetools inspect "$IMAGE_REF" --format '{{ json .Provenance }}' 2>&1)"
if [ $? -ne 0 ] || [ -z "$prov" ]; then
  note "could not read provenance for $IMAGE_REF"
  summary "⚠️ Could not read provenance for \`$IMAGE_REF\`, so this run cannot say whether the base moved."
  finish unknown 2
fi

# The digest the provenance recorded for the base is an INDEX (see note 2 in the header), so
# dereference it to per-platform manifests before comparing. Done here in bash because it
# needs a second registry call: the python below is pure comparison over data on stdin.
recorded_index="$(printf '%s' "$prov" | BASE_PIN="$BASE" python3 -I -c '
import json, os, sys, urllib.parse
pin = os.environ["BASE_PIN"]
name, _, tag = pin.partition(":")
if "/" not in name:
    name = "library/" + name
try:
    prov = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for entry in (prov or {}).values():
    deps = (((entry or {}).get("SLSA") or {}).get("buildDefinition") or {}).get("resolvedDependencies") or []
    for d in deps:
        uri = d.get("uri", "")
        if not uri.startswith("pkg:docker/"):
            continue
        body = urllib.parse.unquote(uri[len("pkg:docker/"):].split("?", 1)[0])
        n, _, t = body.partition("@")
        if "/" not in n:
            n = "library/" + n
        if n == name and t == tag:
            sha = (d.get("digest") or {}).get("sha256")
            if sha:
                print("sha256:" + sha)
                sys.exit(0)
')"

if [ -z "$recorded_index" ]; then
  note "provenance for $IMAGE_REF does not name $BASE"
  summary "⚠️ The provenance for \`$IMAGE_REF\` does not record \`$BASE\`, so this run cannot say whether the base moved."
  finish unknown 2
fi
note "recorded:    $recorded_index (index recorded in provenance)"

# Repository part of the pin, so the recorded index can be addressed by digest.
base_repo="${BASE%%:*}"
recorded_raw="$(docker buildx imagetools inspect "${base_repo}@${recorded_index}" --raw 2>&1)"
if [ $? -ne 0 ] || [ -z "$recorded_raw" ]; then
  note "could not resolve the recorded base index ${recorded_index}"
  summary "⚠️ Could not resolve the base index \`${recorded_index}\` recorded in \`$IMAGE_REF\`'s provenance, so this run cannot say whether the base moved."
  finish unknown 2
fi

# -I: no site dir, no cwd on sys.path. Both JSON blobs are untrusted registry output and are
# passed on stdin as data, never interpolated into the program text.
verdict="$(printf '%s\n\x00\n%s\n' "$upstream_raw" "$recorded_raw" | python3 -I -c '
import json, sys

raw = sys.stdin.read()
up_s, _, rec_s = raw.partition("\n\x00\n")

def fail(msg):
    print("unknown\t" + msg)
    sys.exit(0)

try:
    up = json.loads(up_s)
except Exception as e:
    fail("upstream index is not JSON: %s" % e)
try:
    rec = json.loads(rec_s)
except Exception as e:
    fail("recorded base index is not JSON: %s" % e)

# platform -> per-platform manifest digest. The attestation manifests buildx attaches carry
# architecture "unknown" and are skipped: they are not a platform anyone runs, and they
# change whenever provenance is regenerated, which would be pure noise here.
def platforms(index):
    out = {}
    for m in index.get("manifests", []):
        p = m.get("platform", {}) or {}
        arch, osname = p.get("architecture"), p.get("os")
        if not arch or not osname or "unknown" in (arch, osname):
            continue
        key = "%s/%s" % (osname, arch)
        if p.get("variant"):
            key += "/" + p["variant"]
        out[key] = m.get("digest", "")
    return out

# A single-manifest (non-index) image has no "manifests" list; treat it as one platform so a
# base that is not multi-arch still gets compared rather than silently reported unknown.
def platforms_or_single(index, label):
    got = platforms(index)
    if got:
        return got
    if index.get("config") or index.get("layers"):
        return {"<single>": label}
    return {}

up_p = platforms_or_single(up, "upstream")
rec_p = platforms_or_single(rec, "recorded")

if not up_p:
    fail("the upstream index listed no usable platforms")
if not rec_p:
    fail("the recorded base index listed no usable platforms")

# Only platforms this project actually builds for. A base that gains or drops ppc64le is not
# a change to anything shipped here, and reporting it would train the reader to ignore this.
WANTED = ("linux/amd64", "linux/arm64")

def lookup(table, plat):
    if plat in table:
        return table[plat]
    for k, v in table.items():
        if k == plat or k.startswith(plat + "/"):
            return v
    return None

moved, checked, skipped = [], 0, []
for plat in WANTED:
    want = lookup(up_p, plat)
    have = lookup(rec_p, plat)
    if want is None or have is None:
        skipped.append("%s: %s" % (plat, "absent upstream" if want is None else "absent in the recorded base"))
        continue
    checked += 1
    if want != have:
        moved.append((plat, have, want))

if checked == 0:
    fail("no platform could be compared (" + "; ".join(skipped) + ")")

if moved:
    print("moved\t" + "; ".join("%s built-from %s upstream-now %s" % m for m in moved))
else:
    extra = (" (" + "; ".join(skipped) + ")") if skipped else ""
    print("unchanged\t%d platform(s) compared, all current%s" % (checked, extra))
')"

status="${verdict%%	*}"
detail="${verdict#*	}"
note "verdict:     $status — $detail"

case "$status" in
  unchanged)
    summary "✅ Base image \`$BASE\` has **not** moved since \`$IMAGE_REF\` was built ($detail)."
    finish unchanged 0 ;;
  moved)
    summary "⚠️ Base image \`$BASE\` has **MOVED** since \`$IMAGE_REF\` was built, so the published image may be missing base-layer security fixes."
    summary ""
    summary "\`$detail\`"
    finish moved 1 ;;
  *)
    summary "⚠️ Could not determine whether \`$BASE\` moved: $detail"
    finish unknown 2 ;;
esac
