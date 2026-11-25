#!/usr/bin/env bash
# precedence.sh — T-0713: route-precedence DIFFERENTIAL for the caddy-l4
# listener wrapper, across caddy-l4 v0.1.2 and v0.1.3.
#
# WHY THIS IS NOT run.sh --prove
# ------------------------------
# run.sh (T-0631) tests two defects with a right answer: a leaked TLS
# ClientHello (#483) and a deadlocked config reload (#482/#492). Both are wrong
# on any reading, so that harness can demand the fixed image PASS and the buggy
# image FAIL, and a green run on the buggy image would mean the harness proves
# nothing.
#
# This covers the third part of the v0.1.3 delta, which has no such anchor.
# v0.1.3 replaced the single `lastNeedsMoreIdx` watermark in layer4/routes.go
# with `anyRouteNeedsMore(before)`, scanning the per-route status map:
#
#   anyRouteNeedsMore := func(before int) bool {
#       for i, s := range routesStatus {
#           if s == routeNeedsMore && i > lastMatchedRouteIdx && i < before {
#               return true
#           }
#       }
#       return false
#   }
#
# The upstream comment names what the watermark got wrong: "a conclusively
# unmatched route can bury an earlier one that is still waiting for data". So
# the same first bytes can land on a DIFFERENT route between the two versions.
#
# That is a behaviour change, not a defect, until the intended behaviour is
# established. There is no buggy image to fail. So this script RECORDS the
# landing route per image and prints the differences as a table. A difference is
# an output, not a failure.
#
# WHAT IT STILL FAILS ON
#   - either image could not be started, or a sink could not bind  (exit 2)
#   - a route answered for a protocol it does not match            (exit 1)
#   - --strict and a probe reached no destination at all           (exit 1)
#
# HOW THE LANDING ROUTE IS OBSERVED
# ---------------------------------
# Each of the four routes CaddyUI generates proxies to its OWN sink port, and
# each sink announces which route it is. So the landing route is read off the
# wire rather than inferred from a success/failure pattern — inference cannot
# tell "route 2 matched" from "route 0 matched and its upstream was down".
#
# USAGE
#   ./precedence.sh                 # differential across both images
#   ./precedence.sh --catch-all     # also append a hand-written catch-all route
#   ./precedence.sh --image IMG     # record one image only
#   ./precedence.sh --strict        # fail if a probe reaches nothing
#   ./precedence.sh --repeat 5      # runs per probe (default 3)
#
# Exit 0 = the differential ran (differences may have been found and printed).
# Exit 1 = a real failure. Exit 2 = the harness could not run, which is NOT a pass.

set -uo pipefail

NEW_IMAGE="${NEW_IMAGE:-applegater/caddyui-caddy:v2.68.12}"
OLD_IMAGE="${OLD_IMAGE:-applegater/caddyui-caddy:v2.68.9}"
IMAGE=""
CATCH_ALL=0
STRICT=""
REPEAT=3

PORT="${PORT:-18453}"
ADMIN_PORT="${ADMIN_PORT:-12029}"
ASK_PORT="${ASK_PORT:-12030}"

# Must match the precSink* constants in internal/server/layer4_precedence_config_test.go.
SINK_LABELS="22301=ssh,22302=postgres,22303=rdp,22304=tls-sni,22305=catch-all"

WORK="$(mktemp -d /tmp/l4prec.XXXXXX)"
CONTAINER="l4prec-$$"
SINK_PID=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

die()  { printf 'l4-precedence: %s\n' "$*" >&2; cleanup; exit 2; }
note() { printf '\n== %s ==\n' "$*"; }

cleanup() {
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  [ -n "${KEEP_WORK:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

while [ $# -gt 0 ]; do
  case "$1" in
    --image)     IMAGE="${2:?}"; shift 2 ;;
    --catch-all) CATCH_ALL=1; shift ;;
    --strict)    STRICT="-strict"; shift ;;
    --repeat)    REPEAT="${2:?}"; shift 2 ;;
    -h|--help)   sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)           die "unknown option: $1" ;;
  esac
done

command -v docker >/dev/null || die "docker is required"
command -v go     >/dev/null || die "go is required (the probe and the config generator are Go)"

# ---------------------------------------------------------------- build
note "building the precedence harness"
go build -o "$WORK/precedence" "$REPO_ROOT/scripts/layer4-concurrency/cmd/precedence" || die "probe build failed"
go build -o "$WORK/labelsink"  "$REPO_ROOT/scripts/layer4-concurrency/cmd/labelsink"  || die "labelsink build failed"

# The config comes from CaddyUI's OWN buildLayer4ListenerWrappers, via the emit
# test. Hand-writing four competing routes would measure the harness's idea of
# route order rather than CaddyUI's — and route order IS precedence here, since
# ListLayer4Proxies sorts by (protocol, listen_port, id) and the operator cannot
# reorder them.
emit_env=(
  CADDYUI_L4P_EMIT="$WORK/caddy.json"
  CADDYUI_L4P_ADMIN="localhost:$ADMIN_PORT"
  CADDYUI_L4P_PORT="$PORT"
  CADDYUI_L4P_ASKPORT="$ASK_PORT"
)
[ "$CATCH_ALL" = 1 ] && emit_env+=(CADDYUI_L4P_CATCHALL=1)

( cd "$REPO_ROOT" && env "${emit_env[@]}" \
  go test ./internal/server/ -run TestEmitLayer4PrecedenceConfig -count=1 >"$WORK/emit.log" 2>&1 ) \
  || { sed 's/^/     /' "$WORK/emit.log" >&2; die "could not generate the config from buildLayer4ListenerWrappers"; }
[ -s "$WORK/caddy.json" ] || die "generated config is empty"

for m in '"wrapper": "layer4"' '"ssh"' '"postgres"' '"rdp"' '"sni"'; do
  grep -q "$m" "$WORK/caddy.json" || die "generated config is missing $m — the probes would prove nothing"
done
routes_n="$(grep -c '"handler": "proxy"' "$WORK/caddy.json")"
echo "   config generated from buildLayer4ListenerWrappers: $routes_n layer4 route(s), catch-all=$CATCH_ALL"

# ---------------------------------------------------------------- sinks
# One process, all five labels. Five processes was the first version and made a
# port-binding failure indistinguishable from a routing result.
"$WORK/labelsink" -labels "$SINK_LABELS" >"$WORK/sink.log" 2>&1 &
SINK_PID=$!
sleep 1
kill -0 "$SINK_PID" 2>/dev/null || die "labelsink did not start: $(cat "$WORK/sink.log")"
grep -q 'listening on 5 ports' "$WORK/sink.log" \
  || die "labelsink did not bind all five ports: $(cat "$WORK/sink.log")"
echo "   sinks: $SINK_LABELS"

# ---------------------------------------------------------------- run one image
# $1 image, $2 output json, $3 optional baseline to compare against
run_image() {
  local img="$1" out="$2" cmp="${3:-}" rc=0
  note "image $img"

  docker rm -f "$CONTAINER" >/dev/null 2>&1
  docker run -d --name "$CONTAINER" --network host \
    -v "$WORK:$WORK" "$img" caddy run --config "$WORK/caddy.json" >/dev/null 2>&1 \
    || { echo "   could not start $img"; return 2; }

  # Read caddy-l4's version from the BINARY, not the tag. A result has to be
  # attributable to a version; a tag is a label someone can move.
  local l4ver cid
  cid="$(docker create "$img" 2>/dev/null)"
  docker cp "$cid:/usr/bin/caddy" "$WORK/caddybin" >/dev/null 2>&1
  docker rm "$cid" >/dev/null 2>&1
  l4ver="$(go version -m "$WORK/caddybin" 2>/dev/null | awk '/caddy-l4/{print $3; exit}')"
  [ -n "$l4ver" ] || { echo "   could not read caddy-l4 version from the binary"; return 2; }

  local i=0
  until curl -fsS --max-time 2 "http://localhost:$ADMIN_PORT/config/" >/dev/null 2>&1; do
    i=$((i+1)); [ "$i" -gt 20 ] && { echo "   admin never came up"; docker logs "$CONTAINER" 2>&1 | tail -5; return 2; }
    sleep 1
  done

  local args=(-addr "127.0.0.1:$PORT" -image "$img" -l4 "$l4ver"
              -repeat "$REPEAT" -baseline "$out")
  [ "$CATCH_ALL" = 1 ] && args+=(-catch-all)
  [ -n "$cmp" ] && args+=(-compare "$cmp")
  [ -n "$STRICT" ] && args+=("$STRICT")

  "$WORK/precedence" "${args[@]}" || rc=$?

  docker rm -f "$CONTAINER" >/dev/null 2>&1
  return $rc
}

# ---------------------------------------------------------------- main
FAILED=0

if [ -n "$IMAGE" ]; then
  run_image "$IMAGE" "$WORK/one.json"; rc=$?
  [ "$rc" = 2 ] && die "harness could not run against $IMAGE"
  [ "$rc" != 0 ] && FAILED=1
  note "verdict"
  echo "   recorded the precedence table for $IMAGE"
  echo "   NOTE: one image is a RECORDING, not a differential. Run without --image"
  echo "         to compare v0.1.2 against v0.1.3."
else
  # Old first, so the differential reads "what changed" in release order.
  run_image "$OLD_IMAGE" "$WORK/old.json"; old_rc=$?
  [ "$old_rc" = 2 ] && die "harness could not run against $OLD_IMAGE"
  [ "$old_rc" != 0 ] && FAILED=1

  run_image "$NEW_IMAGE" "$WORK/new.json" "$WORK/old.json"; new_rc=$?
  [ "$new_rc" = 2 ] && die "harness could not run against $NEW_IMAGE"
  [ "$new_rc" != 0 ] && FAILED=1

  note "verdict"
  if [ "$FAILED" = 0 ]; then
    echo "   ok    the differential ran on both images"
    echo "   Differences above, if any, are REPORTED not failed: a precedence change"
    echo "   is not a defect until the intended behaviour is established. Read the"
    echo "   table before a host depends on which route wins a given first packet."
  else
    echo "   FAIL  a probe landed somewhere no version should put it (see above)"
  fi

  if [ -n "${KEEP_WORK:-}" ]; then
    echo "   tables: $WORK/old.json $WORK/new.json"
  fi
fi

exit $FAILED
