#!/usr/bin/env bash
# Publish or diff the Docker Hub repository overview.
#
# The overview used to live only on Docker Hub, so it silently kept serving
# the pre-Apache-2.0 licence for a week after the relicense. docs/dockerhub.md
# is now the source of truth; this script pushes it and, more usefully, tells
# you when the live page has drifted away from it.
#
#   scripts/dockerhub-description.sh diff       # live page vs docs/dockerhub.md
#   scripts/dockerhub-description.sh publish    # overwrite the live page
#
# publish needs a Docker Hub access token with write scope:
#   export DOCKERHUB_USERNAME=... DOCKERHUB_TOKEN=dckr_pat_...
# The token is never echoed. diff needs no credentials.

set -euo pipefail

REPO="${DOCKERHUB_REPO:-applegater/caddyui}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/docs/dockerhub.md"

die() { printf '%s\n' "$*" >&2; exit 1; }

[ -f "$SOURCE" ] || die "missing $SOURCE"

# Everything after the leading HTML comment is what Docker Hub receives.
rendered() {
  python3 - "$SOURCE" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
sys.stdout.write(re.sub(r"\A\s*<!--.*?-->\s*", "", text, count=1, flags=re.S))
PY
}

# The "short-description:" line inside the leading comment sets the one-liner
# under the repository name (Docker Hub caps it at 100 characters).
short_description() {
  python3 - "$SOURCE" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
head = re.match(r"\A\s*<!--(.*?)-->", text, flags=re.S)
found = re.search(r"^short-description:\s*(.+?)\s*$", head.group(1), flags=re.M) if head else None
sys.stdout.write(found.group(1) if found else "")
PY
}

live() {
  curl -fsS -m 30 "https://hub.docker.com/v2/repositories/$REPO/" \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin).get("full_description") or "")'
}

case "${1:-diff}" in
  diff)
    live > /tmp/.hub-live.$$ || die "could not read the live description"
    rendered > /tmp/.hub-local.$$
    if diff -u --label "docker hub (live)" /tmp/.hub-live.$$ \
              --label "docs/dockerhub.md" /tmp/.hub-local.$$; then
      echo "in sync"
    else
      status=1
    fi
    rm -f /tmp/.hub-live.$$ /tmp/.hub-local.$$
    exit "${status:-0}"
    ;;

  publish)
    : "${DOCKERHUB_USERNAME:?set DOCKERHUB_USERNAME}"
    : "${DOCKERHUB_TOKEN:?set DOCKERHUB_TOKEN (Docker Hub access token, write scope)}"

    jwt="$(
      python3 - <<'PY'
import json, os, sys, urllib.request
body = json.dumps({
    "username": os.environ["DOCKERHUB_USERNAME"],
    "password": os.environ["DOCKERHUB_TOKEN"],
}).encode()
req = urllib.request.Request(
    "https://hub.docker.com/v2/users/login/",
    data=body, headers={"Content-Type": "application/json"}, method="POST")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        sys.stdout.write(json.load(r)["token"])
except Exception as exc:
    sys.exit("docker hub login failed: %s" % exc)
PY
    )" || die "could not authenticate to Docker Hub"

    # The payload goes via a file, not a pipe: this script feeds python its
    # program on stdin (`python3 - <<PY`), so a piped description would be
    # swallowed by the heredoc and publish an EMPTY page. That happened once.
    payload="$(mktemp)"
    trap 'rm -f "$payload"' EXIT
    rendered > "$payload"
    [ -s "$payload" ] || die "refusing to publish: rendered description is empty"

    DOCKERHUB_JWT="$jwt" DOCKERHUB_REPO="$REPO" DOCKERHUB_PAYLOAD="$payload" \
    DOCKERHUB_SHORT="$(short_description)" python3 - <<'PY'
import json, os, sys, urllib.request
description = open(os.environ["DOCKERHUB_PAYLOAD"], encoding="utf-8").read()
if not description.strip():
    sys.exit("refusing to publish an empty description")
body = {"full_description": description}
short = os.environ.get("DOCKERHUB_SHORT", "").strip()
if short:
    if len(short) > 100:
        sys.exit("short description is %d characters; Docker Hub allows 100" % len(short))
    body["description"] = short
req = urllib.request.Request(
    "https://hub.docker.com/v2/repositories/%s/" % os.environ["DOCKERHUB_REPO"],
    data=json.dumps(body).encode(),
    headers={
        "Content-Type": "application/json",
        "Authorization": "JWT %s" % os.environ["DOCKERHUB_JWT"],
    },
    method="PATCH")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        json.load(r)
except Exception as exc:
    sys.exit("publish failed: %s" % exc)
print("published %d characters to %s%s" % (
    len(description), os.environ["DOCKERHUB_REPO"],
    " (+ short description)" if short else ""))
PY
    ;;

  *)
    die "usage: ${0##*/} [diff|publish]"
    ;;
esac
