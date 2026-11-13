#!/usr/bin/env bash
# run.sh — T-0631: concurrency + reload test for the caddy-l4 listener wrapper.
#
# WHY THIS EXISTS
# ---------------
# v2.68.11 ships caddy-l4 v0.1.3, whose two headline fixes are a RACE and a
# DEADLOCK on the listener-wrapper path. Both were verified for that release by
# reading the source diff, because the release e2e suite ran sequential single
# connections against a DEDICATED layer4 server — and the bugs live only in the
# `listener_wrappers` pass-through. That was acceptable while no host ran layer4
# at all. It stops being acceptable the moment one does, which is what this
# harness is for: run it BEFORE the first shared-port Layer4 proxy goes live.
#
#   #483  the prefetch buffer went back to a shared sync.Pool even on the
#         HIJACKED path, so a second connection could draw a buffer still
#         holding the first client's TLS ClientHello.
#   #482/#492  l4remoteiplist's StopMonitoring did a blocking send on an
#         unbuffered channel, deadlocking config reload.
#
# WHAT IT RUNS
# ------------
#   1. Generates the config from CaddyUI's OWN buildLayer4ListenerWrappers
#      (internal/server/layer4_concurrency_config_test.go), not a hand-written
#      layer4 server — the hijacked path only exists in the real wrapper output.
#   2. Concurrency phase: ~500 TLS clients with unique SNIs, interleaved with
#      ~500 SSH-banner connections, all released from one barrier.
#   3. Reload phase: ~50 reloads with remote_ip_list configured, asserting each
#      reload completes and the goroutine count returns to baseline (±2).
#
# AND IT VALIDATES ITSELF AGAINST THE BUGGY IMAGE
# -----------------------------------------------
# `--prove` runs everything twice: once on the fixed image (must pass) and once
# on v2.68.9 / caddy-l4 v0.1.2 (must fail). A concurrency test that passes on the
# buggy image proves nothing, and this harness has already caught itself doing
# exactly that twice — see KNOWN TRAPS below.
#
# KNOWN TRAPS, both of which produced a false PASS on the buggy image
# -------------------------------------------------------------------
#  A. Scoring TLS protocol errors as generic failures. "server did not echo the
#     legacy session ID" / "bad record MAC" / "error decoding message" ARE the
#     race; they must be counted as contamination, not inferred from a
#     success-rate threshold. With a 95% threshold the buggy image passed 1 run
#     in 3 (489/500 ok, 6 real contamination events, exit 0).
#  B. Reloading an IDENTICAL config. Caddy skips a no-op load, so nothing is torn
#     down, Cleanup never runs, and the deadlock is never reached. Every reload
#     must change the config. With identical reloads the buggy image sat flat at
#     21 goroutines for 50 reloads and reported PASS.
#
# USAGE
#   ./run.sh                       # test the default fixed image
#   ./run.sh --image IMG           # test a specific image
#   ./run.sh --prove               # fixed must pass AND buggy must fail
#   ./run.sh --tls 500 --ssh 500 --reloads 50
#
# Exit 0 = pass. Exit 1 = a real failure. Exit 2 = the harness could not run,
# which is NOT a pass.

set -uo pipefail

FIXED_IMAGE="${FIXED_IMAGE:-applegater/caddyui-caddy:v2.68.11}"
BUGGY_IMAGE="${BUGGY_IMAGE:-applegater/caddyui-caddy:v2.68.9}"
IMAGE=""
TLS_N=500
SSH_N=500
RELOADS=50
PROVE=0

PORT="${PORT:-18443}"
ADMIN_PORT="${ADMIN_PORT:-12019}"
ASK_PORT="${ASK_PORT:-12020}"
SINK_PORT="${SINK_PORT:-22222}"

WORK="$(mktemp -d /tmp/l4conc.XXXXXX)"
CONTAINER="l4conc-$$"
SINK_PID=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

die()  { printf 'l4-concurrency: %s\n' "$*" >&2; cleanup; exit 2; }
note() { printf '\n== %s ==\n' "$*"; }

cleanup() {
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null
  docker rm -f "$CONTAINER" >/dev/null 2>&1
  [ -n "${KEEP_WORK:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

while [ $# -gt 0 ]; do
  case "$1" in
    --image)   IMAGE="${2:?}"; shift 2 ;;
    --tls)     TLS_N="${2:?}"; shift 2 ;;
    --ssh)     SSH_N="${2:?}"; shift 2 ;;
    --reloads) RELOADS="${2:?}"; shift 2 ;;
    --prove)   PROVE=1; shift ;;
    -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)         die "unknown option: $1" ;;
  esac
done
[ -n "$IMAGE" ] || IMAGE="$FIXED_IMAGE"

command -v docker >/dev/null || die "docker is required"
command -v go     >/dev/null || die "go is required (the driver and config generator are Go)"

# ---------------------------------------------------------------- build
note "building harness"
go build -o "$WORK/driver"  "$REPO_ROOT/scripts/layer4-concurrency/cmd/driver"  || die "driver build failed"
go build -o "$WORK/sshsink" "$REPO_ROOT/scripts/layer4-concurrency/cmd/sshsink" || die "sshsink build failed"

# The config comes from CaddyUI's own builder, via the emit test. Generating it
# any other way would test a layer4 server CaddyUI does not produce.
echo "127.0.0.1/32" > "$WORK/ips.txt"
( cd "$REPO_ROOT" && \
  CADDYUI_L4_EMIT="$WORK/caddy.json" \
  CADDYUI_L4_ADMIN="localhost:$ADMIN_PORT" \
  CADDYUI_L4_PORT="$PORT" \
  CADDYUI_L4_ASKPORT="$ASK_PORT" \
  CADDYUI_L4_IPFILE="$WORK/ips.txt" \
  go test ./internal/server/ -run TestEmitLayer4ConcurrencyConfig -count=1 >/dev/null 2>&1 ) \
  || die "could not generate the config from buildLayer4ListenerWrappers"
[ -s "$WORK/caddy.json" ] || die "generated config is empty"
grep -q '"wrapper": "layer4"' "$WORK/caddy.json" || die "generated config has no layer4 wrapper"
grep -q 'remote_ip_list'     "$WORK/caddy.json" || die "generated config has no remote_ip_list — the reload phase would prove nothing"
echo "   config generated from buildLayer4ListenerWrappers: $WORK/caddy.json"

# ---------------------------------------------------------------- sink
"$WORK/sshsink" -addr "127.0.0.1:$SINK_PORT" >"$WORK/sink.log" 2>&1 &
SINK_PID=$!
sleep 1
kill -0 "$SINK_PID" 2>/dev/null || die "sshsink did not start: $(cat "$WORK/sink.log")"

# ---------------------------------------------------------------- run one image
run_image() {
  local img="$1" expect="$2" rc=0
  note "image $img (expected: $expect)"

  docker rm -f "$CONTAINER" >/dev/null 2>&1
  docker run -d --name "$CONTAINER" --network host \
    -v "$WORK:$WORK" "$img" caddy run --config "$WORK/caddy.json" >/dev/null 2>&1 \
    || { echo "   could not start $img"; return 2; }

  # Confirm which caddy-l4 the image actually carries, so a result is always
  # attributable to a version rather than to a tag.
  local l4ver cid
  cid="$(docker create "$img" 2>/dev/null)"
  docker cp "$cid:/usr/bin/caddy" "$WORK/caddybin" >/dev/null 2>&1
  docker rm "$cid" >/dev/null 2>&1
  l4ver="$(go version -m "$WORK/caddybin" 2>/dev/null | awk '/caddy-l4/{print $3; exit}')"
  echo "   caddy-l4: ${l4ver:-unknown}"

  local i=0
  until curl -fsS --max-time 2 "http://localhost:$ADMIN_PORT/config/" >/dev/null 2>&1; do
    i=$((i+1)); [ "$i" -gt 20 ] && { echo "   admin never came up"; docker logs "$CONTAINER" 2>&1 | tail -5; return 2; }
    sleep 1
  done

  "$WORK/driver" -addr "127.0.0.1:$PORT" -admin "localhost:$ADMIN_PORT" \
    -tls "$TLS_N" -ssh "$SSH_N" -phase concurrency || rc=1

  # The reload phase deadlocks the admin API on a buggy image, so it runs second:
  # a hung admin endpoint would make the concurrency phase unattributable.
  "$WORK/driver" -admin "localhost:$ADMIN_PORT" -config "$WORK/caddy.json" \
    -reloads "$RELOADS" -phase leak || rc=1

  docker rm -f "$CONTAINER" >/dev/null 2>&1
  return $rc
}

# ---------------------------------------------------------------- main
FAILED=0

if [ "$PROVE" = 1 ]; then
  run_image "$FIXED_IMAGE" "PASS"; fixed_rc=$?
  [ "$fixed_rc" = 2 ] && die "harness could not run against the fixed image"
  run_image "$BUGGY_IMAGE" "FAIL"; buggy_rc=$?
  [ "$buggy_rc" = 2 ] && die "harness could not run against the buggy image"

  note "verdict"
  if [ "$fixed_rc" != 0 ]; then
    echo "   FAIL  $FIXED_IMAGE did not pass — a real regression, or the harness is broken"
    FAILED=1
  else
    echo "   ok    $FIXED_IMAGE passed"
  fi
  if [ "$buggy_rc" = 0 ]; then
    echo "   FAIL  $BUGGY_IMAGE PASSED — the harness proves nothing; do not trust a green run"
    FAILED=1
  else
    echo "   ok    $BUGGY_IMAGE failed, as it must"
  fi
else
  run_image "$IMAGE" "PASS"; rc=$?
  [ "$rc" = 2 ] && die "harness could not run"
  note "verdict"
  if [ "$rc" = 0 ]; then
    echo "   ok    $IMAGE passed"
    echo "   NOTE: a pass is only meaningful if --prove has shown the harness"
    echo "         still fails on $BUGGY_IMAGE."
  else
    echo "   FAIL  $IMAGE did not pass"
    FAILED=1
  fi
fi

exit $FAILED
