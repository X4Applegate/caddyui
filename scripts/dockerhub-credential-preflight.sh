#!/usr/bin/env bash
# Check every Docker Hub credential a release or -pN publish depends on, before
# the step that needs one discovers it is dead.
#
#   scripts/dockerhub-credential-preflight.sh          # check all, exit 1 on any failure
#   scripts/dockerhub-credential-preflight.sh --quiet  # only print problems
#
# Run this at the START of a release and of a -pN publish. The problem it
# exists to catch is not a missing credential, it is a credential that died
# weeks ago and nobody noticed: /root/.dockerhub.env was dead for ~7 weeks and
# surfaced only when T-0613 happened to use it. The two local credentials have
# now independently expired at different times, each silently, and every note
# recording which one was live went stale without any signal.
#
# THREE credentials, three separate expiry clocks, no shared rotation:
#
#   1. /root/.dockerhub.env        DOCKERHUB_USERNAME + DOCKERHUB_TOKEN.
#                                  Used by scripts/dockerhub-description.sh to
#                                  publish the two public Hub overviews.
#   2. ~/.docker/config.json       The `docker login` credential. Used by
#                                  docker push/pull, and it also happens to
#                                  work on the Hub API.
#   3. GitHub secret DOCKERHUB_TOKEN  Used by release-docker.yml and
#                                  dockerhub-description.yml. NOT on this host,
#                                  so nothing local can test it; its age is
#                                  reported instead (see "why" below).
#
# Deliberately read-only. It authenticates and inspects grants; it pushes
# nothing, publishes nothing and rotates nothing, so it is safe to run at any
# point in a release, as often as you like.
#
# Exit status:
#   0  every testable credential works
#   1  at least one failed, or is missing and was expected
#   2  the preflight could not run (treat as a failure, not a pass)

set -uo pipefail

# --- exit 2 for our own breakage, never a silent pass -------------------------
die() { printf 'preflight: %s\n' "$*" >&2; exit 2; }

for tool in python3 curl; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

QUIET=0
case "${1:-}" in
  --quiet) QUIET=1 ;;
  "") ;;
  -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "usage: ${0##*/} [--quiet]" ;;
esac

ENV_FILE="${DOCKERHUB_ENV_FILE:-/root/.dockerhub.env}"
DOCKER_CONFIG_FILE="${DOCKER_CONFIG_FILE:-$HOME/.docker/config.json}"
# The repos whose overviews a release republishes, i.e. what credential 1 must
# be able to PATCH.
REPOS="${DOCKERHUB_REPOS:-applegater/caddyui applegater/caddyui-caddy}"
GITHUB_REPO="${PREFLIGHT_GITHUB_REPO:-X4Applegate/caddyui}"
# A repo secret older than this is worth replacing pre-emptively. 60 days is
# under the shortest observed real lifetime: the local PAT set 2026-10-06 was
# dead by 2026-11-12 (37 days), so this warns before that window.
SECRET_AGE_WARN_DAYS="${SECRET_AGE_WARN_DAYS:-60}"

failures=0
warnings=0

say()  { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }
ok()   { [ "$QUIET" = 1 ] || printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*" >&2; failures=$((failures + 1)); }
warn() { printf '  warn  %s\n' "$*" >&2; warnings=$((warnings + 1)); }

# --- Hub API: PAT -> JWT -----------------------------------------------------
# A raw PAT is NOT a bearer token for /v2/user/ — that endpoint takes only a
# JWT and 401s on a healthy PAT, which is exactly how T-0613's first report
# mistook a live credential for a dead one. Always exchange at /v2/users/login/
# first. Credentials arrive by env var, never on argv, so they stay out of ps
# and out of any shell history.
hub_jwt() {
  PF_USER="$1" PF_TOKEN="$2" python3 -I - <<'PY'
import json, os, sys, urllib.error, urllib.request
body = json.dumps({"username": os.environ["PF_USER"],
                   "password": os.environ["PF_TOKEN"]}).encode()
req = urllib.request.Request("https://hub.docker.com/v2/users/login/",
                             data=body,
                             headers={"Content-Type": "application/json"},
                             method="POST")
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        sys.stdout.write(json.load(r)["token"])
except urllib.error.HTTPError as exc:
    sys.exit("HTTP %s" % exc.code)
except Exception as exc:
    sys.exit(str(exc))
PY
}

# Who does Hub think this credential is? Confirms the JWT resolves to a real
# account rather than merely being well-formed.
hub_whoami() {
  PF_JWT="$1" python3 -I - <<'PY'
import json, os, sys, urllib.error, urllib.request
req = urllib.request.Request(
    "https://hub.docker.com/v2/user/",
    headers={"Authorization": "JWT %s" % os.environ["PF_JWT"]})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        sys.stdout.write(json.load(r).get("username") or "")
except urllib.error.HTTPError as exc:
    sys.exit("HTTP %s" % exc.code)
except Exception as exc:
    sys.exit(str(exc))
PY
}

# Can it actually PATCH the overview? A JWT that authenticates may still lack
# write scope, and scope cannot be read from the PAT itself:
# GET /v2/access-tokens returns 403 "token issued from personal access token is
# not allowed". So probe the real target object instead.
hub_repo_readable() {
  PF_JWT="$1" PF_REPO="$2" python3 -I - <<'PY'
import json, os, sys, urllib.error, urllib.request
req = urllib.request.Request(
    "https://hub.docker.com/v2/repositories/%s/" % os.environ["PF_REPO"],
    headers={"Authorization": "JWT %s" % os.environ["PF_JWT"]})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        json.load(r)
except urllib.error.HTTPError as exc:
    sys.exit("HTTP %s" % exc.code)
except Exception as exc:
    sys.exit(str(exc))
PY
}

# The registry grant is the one place a PAT's effective scope IS readable: the
# auth.docker.io token carries an `access` claim listing what it granted. Ask
# for pull,push,delete and report what comes back, so a token narrowed too far
# (T-0579) shows up here rather than mid-release.
registry_grant() {
  PF_USER="$1" PF_TOKEN="$2" PF_REPO="$3" python3 -I - <<'PY'
import base64, json, os, sys, urllib.error, urllib.parse, urllib.request
user, token, repo = (os.environ["PF_USER"], os.environ["PF_TOKEN"],
                     os.environ["PF_REPO"])
qs = urllib.parse.urlencode({
    "service": "registry.docker.io",
    "scope": "repository:%s:pull,push,delete" % repo,
})
req = urllib.request.Request("https://auth.docker.io/token?%s" % qs)
basic = base64.b64encode(("%s:%s" % (user, token)).encode()).decode()
req.add_header("Authorization", "Basic %s" % basic)
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        payload = json.load(r)
except urllib.error.HTTPError as exc:
    sys.exit("HTTP %s" % exc.code)
except Exception as exc:
    sys.exit(str(exc))

# The granted scope lives in the JWT's own claims, not the response envelope.
raw = payload.get("token") or payload.get("access_token") or ""
parts = raw.split(".")
if len(parts) < 2:
    sys.exit("malformed registry token")
seg = parts[1] + "=" * (-len(parts[1]) % 4)
try:
    claims = json.loads(base64.urlsafe_b64decode(seg))
except Exception as exc:
    sys.exit("could not read registry token claims: %s" % exc)
actions = []
for entry in claims.get("access") or []:
    if entry.get("name") == repo:
        actions = sorted(entry.get("actions") or [])
sys.stdout.write(",".join(actions) if actions else "none")
PY
}

# --- credential 1: /root/.dockerhub.env --------------------------------------
say "1. $ENV_FILE  (Hub overviews, scripts/dockerhub-description.sh)"
if [ ! -f "$ENV_FILE" ]; then
  bad "file does not exist — the overview-republish step cannot run"
else
  perms="$(stat -c '%a %U:%G' "$ENV_FILE" 2>/dev/null || echo '?')"
  case "$perms" in
    600*) ok "permissions $perms" ;;
    *)    warn "permissions $perms — expected 600; it holds a write-scope PAT" ;;
  esac

  # Subshell: the credential must not leak into the rest of the script's env.
  env_user=""
  if ! env_dump="$(
        set -a
        # shellcheck disable=SC1090
        . "$ENV_FILE" 2>/dev/null
        set +a
        printf '%s\n' "${DOCKERHUB_USERNAME:-}"
        printf '%s\n' "${DOCKERHUB_TOKEN:-}"
      )"; then
    bad "could not source the file"
  else
    env_user="$(printf '%s' "$env_dump" | sed -n 1p)"
    env_token="$(printf '%s' "$env_dump" | sed -n 2p)"
    if [ -z "$env_user" ] || [ -z "$env_token" ]; then
      bad "DOCKERHUB_USERNAME or DOCKERHUB_TOKEN is empty"
    else
      ok "username $env_user, token ${#env_token} chars, prefix ${env_token%%_*}_"
      if jwt="$(hub_jwt "$env_user" "$env_token" 2>&1)"; then
        ok "POST /v2/users/login/ -> JWT"
        if who="$(hub_whoami "$jwt" 2>&1)"; then
          ok "GET /v2/user/ -> $who"
        else
          bad "GET /v2/user/ failed: $who"
        fi
        for repo in $REPOS; do
          if err="$(hub_repo_readable "$jwt" "$repo" 2>&1)"; then
            ok "can read $repo (the PATCH target for its overview)"
          else
            bad "cannot read $repo: $err"
          fi
        done
        for repo in $REPOS; do
          grant="$(registry_grant "$env_user" "$env_token" "$repo" 2>&1)" || grant="error: $grant"
          case "$grant" in
            *delete*push*|*push*delete*) ok "registry grant on $repo: $grant" ;;
            *push*) warn "registry grant on $repo: $grant (no delete — an orphaned -pN tag cannot be removed)" ;;
            *)      warn "registry grant on $repo: $grant" ;;
          esac
        done
      else
        bad "POST /v2/users/login/ failed: $jwt — this is the call the publish script makes, so the overview step WILL fail"
      fi
    fi
  fi
fi

# --- credential 2: ~/.docker/config.json -------------------------------------
say ""
say "2. $DOCKER_CONFIG_FILE  (docker push / docker pull)"
if [ ! -f "$DOCKER_CONFIG_FILE" ]; then
  bad "file does not exist — docker push will prompt or fail"
else
  # index.docker.io is what `docker login` with no registry argument writes.
  # 2>&1 matters: the parser reports problems via sys.exit(), i.e. on stderr.
  # Without it a failure yields an empty capture that reads as success and the
  # checks below then run with empty credentials and report false failures.
  cfg_rc=0
  cfg_dump="$(PF_CFG="$DOCKER_CONFIG_FILE" python3 -I - 2>&1 <<'PY'
import base64, json, os, sys
try:
    cfg = json.load(open(os.environ["PF_CFG"], encoding="utf-8"))
except Exception as exc:
    sys.exit("unreadable: %s" % exc)
auths = cfg.get("auths") or {}
keys = [k for k in auths if "docker.io" in k] or list(auths)
if not keys:
    sys.exit("no auths entries")
entry = auths[keys[0]]
blob = entry.get("auth")
if not blob:
    # A credential helper keeps the secret outside this file; that is fine, but
    # this script cannot test it, so say so rather than calling it a failure.
    sys.exit("helper:%s" % (cfg.get("credsStore") or entry.get("identitytoken") and "identitytoken" or "unknown"))
try:
    user, _, token = base64.b64decode(blob).decode().partition(":")
except Exception as exc:
    sys.exit("could not decode auth: %s" % exc)
if not user or not token:
    sys.exit("auth entry has no user:token pair")
sys.stdout.write("%s\n%s\n%s\n" % (keys[0], user, token))
PY
  )" || cfg_rc=$?

  if [ "$cfg_rc" -ne 0 ]; then
    case "$cfg_dump" in
      helper:*) warn "credential is in a helper (${cfg_dump#helper:}), not in the file — cannot test it here; verify with a real push" ;;
      *)        bad "${cfg_dump:-could not parse $DOCKER_CONFIG_FILE}" ;;
    esac
  else
    cfg_reg="$(printf '%s' "$cfg_dump" | sed -n 1p)"
    cfg_user="$(printf '%s' "$cfg_dump" | sed -n 2p)"
    cfg_token="$(printf '%s' "$cfg_dump" | sed -n 3p)"
    ok "registry $cfg_reg, username $cfg_user, token ${#cfg_token} chars"
    # Registry auth is what actually matters for this credential: it is the
    # push path. Check that first and loudest.
    for repo in $REPOS; do
      grant="$(registry_grant "$cfg_user" "$cfg_token" "$repo" 2>&1)" || grant="error: $grant"
      case "$grant" in
        *push*) ok "registry grant on $repo: $grant" ;;
        error:*) bad "registry auth on $repo failed: ${grant#error: } — docker push will fail" ;;
        *)      bad "registry grant on $repo is '$grant' — no push, so a release cannot publish tags" ;;
      esac
    done
    # It also works on the Hub API today, which is why option 2 in T-0614 was
    # possible at all. Informational: a release does not depend on it.
    if jwt2="$(hub_jwt "$cfg_user" "$cfg_token" 2>&1)"; then
      if who2="$(hub_whoami "$jwt2" 2>&1)"; then
        ok "also valid on the Hub API -> $who2"
      else
        warn "Hub API login succeeded but /v2/user/ failed: $who2"
      fi
    else
      say "  note  not valid on the Hub API ($jwt2) — fine, nothing requires it to be"
    fi
  fi
fi

# --- credential 3: the GitHub repo secret ------------------------------------
# Untestable from here by design: a secret is write-only through the API, and
# the only workflow that exercises it (dockerhub-description.yml) has no
# diff-only mode, so dispatching it to "check" would republish both live public
# overview pages as a side effect. Report its AGE instead — the one signal
# available without using it — and let a human judge.
say ""
say "3. GitHub secret DOCKERHUB_TOKEN on $GITHUB_REPO  (release-docker.yml, dockerhub-description.yml)"
if ! command -v gh >/dev/null 2>&1; then
  warn "gh not installed — cannot read the secret's age; check it by hand"
else
  meta="$(gh api "repos/$GITHUB_REPO/actions/secrets" 2>&1)" || meta=""
  if [ -z "$meta" ]; then
    warn "could not list repo secrets (gh auth?) — check the secret by hand"
  else
    updated="$(PF_META="$meta" python3 -I - <<'PY'
import json, os, sys
try:
    data = json.loads(os.environ["PF_META"])
except Exception:
    sys.exit(1)
for s in data.get("secrets") or []:
    if s.get("name") == "DOCKERHUB_TOKEN":
        sys.stdout.write(s.get("updated_at") or "")
        break
PY
    )" || updated=""
    if [ -z "$updated" ]; then
      warn "secret DOCKERHUB_TOKEN not found on $GITHUB_REPO"
    else
      age_days="$(PF_TS="$updated" python3 -I - <<'PY'
import datetime, os, sys
ts = os.environ["PF_TS"].replace("Z", "+00:00")
try:
    then = datetime.datetime.fromisoformat(ts)
except Exception:
    sys.exit(1)
now = datetime.datetime.now(datetime.timezone.utc)
sys.stdout.write(str((now - then).days))
PY
      )" || age_days=""
      if [ -z "$age_days" ]; then
        warn "last set $updated (could not compute age)"
      elif [ "$age_days" -ge "$SECRET_AGE_WARN_DAYS" ]; then
        warn "last set $updated — $age_days days ago, at or past the $SECRET_AGE_WARN_DAYS-day mark; cannot be tested from here, so rotate it rather than find out during a release"
      else
        ok "last set $updated ($age_days days ago, under the $SECRET_AGE_WARN_DAYS-day warn mark)"
      fi
      say "  note  value is write-only and its only workflow publishes as a side effect, so age is the only local signal"
    fi
  fi
fi

# --- verdict -----------------------------------------------------------------
say ""
if [ "$failures" -gt 0 ]; then
  printf 'preflight: %d FAILED, %d warning(s) — fix before releasing\n' \
    "$failures" "$warnings" >&2
  exit 1
fi
if [ "$warnings" -gt 0 ]; then
  say "preflight: all testable credentials work, $warnings warning(s) above"
else
  say "preflight: all credentials ok"
fi
exit 0
