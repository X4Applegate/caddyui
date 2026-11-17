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

# A dropped write is the one failure mode this whole script exists to prevent -- its only
# product is a report, so a summary append that silently fails (unwritable file, or the 1 MiB
# step-summary cap, which this workflow writes a lot of prose toward) means nobody is told,
# on a green step. Report the failure to the job log rather than returning 0 regardless.
summary() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY" \
    || note "::warning::could not write to the step summary; the base-drift verdict may not appear in the run summary"
  return 0
}

finish() {
  local status="$1" code="$2"

  # UNKNOWN IS ANNOUNCED, NOT JUST RECORDED.
  #
  # This script is advisory on the release path, so `moved` and `unknown` both end in a green
  # step. That makes "I could not check" visually identical to "I checked and it is current"
  # unless something says otherwise -- which would recreate, one level up, exactly the
  # silent-skip defect this change exists to remove. An unresolvable registry call is a
  # realistic steady state here (the job deliberately holds no Docker Hub credential and so
  # pulls anonymously), not a rare event, so it must be loud.
  #
  # ::warning:: surfaces on the run header, where a reader looks, rather than only inside
  # summary prose. `moved` gets one too: the fleet tracks :stable, and a stale base is worth
  # an annotation even though it must not fail the release.
  case "$status" in
    unknown)
      note "::warning::base-drift check could not determine whether the pinned base moved; this run did NOT verify the published image's base"
      # Stated HERE rather than at each call site so every unknown path is worded the same,
      # including the early exits above that never reach the verdict block at the end. Those
      # each explain their own specific cause; this adds the one line that must always be
      # present -- that the absence of a warning is not an all-clear.
      summary "❓ **Base NOT VERIFIED.** This is **not** an all-clear: the check did not complete, so whether the published image's base is current is unknown."
      ;;
    moved)
      note "::warning::the pinned base image has moved since the published image was built; it may be missing base-layer security fixes"
      ;;
  esac

  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'drift=%s\n' "$status" >> "$GITHUB_OUTPUT" \
      || note "::warning::could not write the drift verdict to GITHUB_OUTPUT; a later step keyed on it will not see this result"
  fi
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

# Each registry call is tested with `if ! var=$(...)`, NOT by reading $? on the next line.
# Bash does propagate a command substitution's status through a simple assignment, so the
# $? form worked — but only while nothing sits between the assignment and the test, and a
# single statement inserted there would silently turn a failed registry call into a pass.
# For a check whose whole purpose is to avoid reporting "all clear" when it could not
# verify, that is too thin a margin. shellcheck flags the $? form as SC2181.
#
# stderr is NOT merged into the data (no 2>&1). Capturing the error text would make the
# `-z` emptiness guard useless exactly when the call fails, and would feed an error string
# to a JSON parser; diagnostics belong on this script's own stderr, not in the variable
# being parsed.
if ! upstream_raw="$(docker buildx imagetools inspect "$BASE" --raw 2>/dev/null)" || [ -z "$upstream_raw" ]; then
  note "could not resolve $BASE upstream"
  summary "⚠️ Could not resolve \`$BASE\` upstream, so this run cannot say whether the base moved."
  finish unknown 2
fi

if ! prov="$(docker buildx imagetools inspect "$IMAGE_REF" --format '{{ json .Provenance }}' 2>/dev/null)" || [ -z "$prov" ]; then
  note "could not read provenance for $IMAGE_REF"
  summary "⚠️ Could not read provenance for \`$IMAGE_REF\`, so this run cannot say whether the base moved."
  finish unknown 2
fi

# The digest the provenance recorded for the base is an INDEX (see note 2 in the header), so
# dereference it to per-platform manifests before comparing. Done here in bash because it
# needs a second registry call: the python below is pure comparison over data on stdin.
recorded_index="$(printf '%s' "$prov" | BASE_PIN="$BASE" python3 -I -c '
import json, os, re, sys, urllib.parse
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
            # VALIDATED, not merely non-empty. This value comes from a registry response and
            # is interpolated into an image reference below. It is used inside a quoted
            # expansion, so it is one argv element and cannot word-split or glob today --
            # but an unvalidated digest is one unquoting away from argument injection, and a
            # malformed one would silently weaken the comparison. Require the real shape.
            #
            # A malformed digest is reported as MALFORMED rather than skipped. Skipping it
            # would leave the caller saying "provenance does not name the base", which is a
            # different and misleading diagnosis: the base IS named, its digest is junk, and
            # those two faults want different responses from whoever reads the run.
            if sha and re.fullmatch(r"[0-9a-f]{64}", sha):
                print("sha256:" + sha)
            else:
                print("MALFORMED")
            sys.exit(0)
')"

if [ -z "$recorded_index" ]; then
  note "provenance for $IMAGE_REF does not name $BASE"
  summary "⚠️ The provenance for \`$IMAGE_REF\` does not record \`$BASE\`, so this run cannot say whether the base moved."
  finish unknown 2
fi
if [ "$recorded_index" = MALFORMED ]; then
  note "provenance for $IMAGE_REF records a malformed base digest for $BASE"
  summary "⚠️ The provenance for \`$IMAGE_REF\` records \`$BASE\` with a malformed digest, so this run cannot say whether the base moved."
  finish unknown 2
fi
# Re-checked here as well as in the emitter above: the emitter is the only writer today, but
# this is the value that becomes an image reference, so the check belongs next to the use.
if [[ ! "$recorded_index" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  note "provenance recorded a malformed base digest: $recorded_index"
  summary "⚠️ The provenance for \`$IMAGE_REF\` recorded a malformed base digest, so this run cannot say whether the base moved."
  finish unknown 2
fi
note "recorded:    $recorded_index (index recorded in provenance)"

# Repository part of the pin, so the recorded index can be addressed by digest.
base_repo="${BASE%%:*}"
if ! recorded_raw="$(docker buildx imagetools inspect "${base_repo}@${recorded_index}" --raw 2>/dev/null)" || [ -z "$recorded_raw" ]; then
  note "could not resolve the recorded base index ${recorded_index}"
  summary "⚠️ Could not resolve the base index \`${recorded_index}\` recorded in \`$IMAGE_REF\`'s provenance, so this run cannot say whether the base moved."
  finish unknown 2
fi

# -I: no site dir, no cwd on sys.path. Both JSON blobs are untrusted registry output and are
# passed on stdin as data, never interpolated into the program text.
# shellcheck disable=SC2016  # single quotes are REQUIRED: the python body must reach the
# interpreter verbatim. Double quotes would let the shell expand $-expressions inside the
# program text, which is both wrong and the shape that becomes injection.
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
        # A manifest with no digest is DROPPED, not stored as "". Defaulting to the empty
        # string made two digest-less entries compare EQUAL, so a platform nobody could
        # actually compare was counted as checked and reported current -- a false all-clear
        # from an index that said nothing at all.
        dig = m.get("digest")
        if not dig:
            continue
        key = "%s/%s" % (osname, arch)
        if p.get("variant"):
            key += "/" + p["variant"]
        out[key] = dig
    return out

# A single-manifest (non-index) image is deliberately NOT supported: this project builds a
# multi-arch base and compares per platform, so there is no sensible platform key for a bare
# manifest. Such an input reports unknown rather than being guessed at.
#
# An earlier version pretended to handle it by returning a {"<single>": label} sentinel,
# which WANTED could never match -- dead code whose comment promised a capability the code
# did not have, and which would have produced a false `moved` if it had ever fired.
up_p = platforms(up)
rec_p = platforms(rec)

if not up_p:
    fail("the upstream index listed no usable platform manifests")
if not rec_p:
    fail("the recorded base index listed no usable platform manifests")

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
    # A real difference is reported even if another platform could not be checked: the
    # finding stands on its own and withholding it would be worse than reporting it.
    print("moved\t" + "; ".join("%s built-from %s upstream-now %s" % m for m in moved))
elif skipped:
    # PARTIAL COVERAGE IS NOT AN ALL-CLEAR. Every WANTED platform must have been compared
    # before this says "current". Previously 1-of-2 compared rendered as "VERIFIED CURRENT"
    # while 0-of-2 was unknown, so a truncated index, a mid-run rate limit, or upstream
    # dropping an arch produced a green all-clear for an architecture nobody looked at --
    # and the fleet pulls arm64. The script header already states the rule this broke: an
    # unanswered question must not be scored as a pass.
    fail("%d platform(s) matched but %d could not be compared (%s)"
         % (checked, len(skipped), "; ".join(skipped)))
else:
    print("unchanged\t%d platform(s) compared, all current" % checked)
')"

status="${verdict%%	*}"
detail="${verdict#*	}"
note "verdict:     $status — $detail"

# Three states, named differently on purpose. "Not verified" must not read like "verified
# clean": both leave the step green, so the words are the only thing distinguishing them.
case "$status" in
  unchanged)
    summary "✅ **Base VERIFIED CURRENT.** \`$BASE\` has not moved since \`$IMAGE_REF\` was built ($detail)."
    finish unchanged 0 ;;
  moved)
    summary "⚠️ **Base MOVED.** \`$BASE\` has moved since \`$IMAGE_REF\` was built, so the published image may be missing base-layer security fixes."
    summary ""
    summary "\`$detail\`"
    finish moved 1 ;;
  *)
    summary "Could not determine whether \`$BASE\` moved: $detail"
    summary ""
    summary "Check by hand before assuming the published base is current: \`docker buildx imagetools inspect $BASE\`."
    finish unknown 2 ;;
esac
