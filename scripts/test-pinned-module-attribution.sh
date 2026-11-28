#!/usr/bin/env bash
# Tests for WHICH MODULE an advisory is attributed to in the image / go.mod
# sweep of check-pinned-modules.sh (T-0889).
#
#   ./scripts/test-pinned-module-attribution.sh     # exit 0 = all pass
#
# ---------------------------------------------------------------------------
# WHY THIS SUITE EXISTS
# ---------------------------------------------------------------------------
# The sweep asks GitHub's per-repository advisory endpoint, so it receives
# every advisory for a whole REPOSITORY. aws/aws-sdk-go-v2 is one repository
# holding ~400 Go MODULES (every `service/*` is its own module), and the
# matcher's package-containment arm read `.../aws-sdk-go-v2/service/rds` as a
# package INSIDE the root module `github.com/aws/aws-sdk-go-v2`. On PR #194
# that put two false findings on `aws-sdk-go-v2 v1.48.0`:
#
#   GHSA-xmrv-pmrh-hhx2  names eventstream, s3, kinesis, lambda, bedrock* ...
#                        none of which caddyui links, and never the root module
#   GHSA-3jcv-796g-cpjg  406 service modules; the 4 linked here (route53, sts,
#                        sso, ssooidc) are their OWN pins, all past the patch.
#                        Reported range `< v1.108.8` is an rds version the
#                        root module has never had.
#
# The fix narrows ATTRIBUTION, not coverage:
#   1. a package path is owned by the LONGEST module in the swept set that
#      contains it, so route53 rows go to the route53 pin, not the root;
#   2. for go.mod rows, a package BELOW the pinned module counts only if the
#      build links it (`go list -deps ./...`). If that list cannot be
#      produced, rule 2 is skipped -- the old, conservative behaviour.
#
# Exact module matches are untouched, which is what keeps the CVE-less
# per-repository coverage: GHSA-4v5x-9mc8-gr98 on go-sql-driver/mysql 1.10.1
# must still be reported (case 3).
#
# Runs the REAL script end to end, with `curl` and `go` shimmed to serve the
# fixtures in scripts/fixtures/t0889/ (captured live 2026-11-25, trimmed to the
# fields the sweep reads). No network calls are answered by the outside world.
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/check-pinned-modules.sh"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$(cd "$(dirname "$0")" && pwd)/fixtures/t0889"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS  $1"
  else fail=$((fail+1)); echo "FAIL  $1"; echo "      expected: $2"; echo "      actual:   $3"; fi
}
command -v jq >/dev/null 2>&1 || { echo "FATAL: jq is required (it is the code under test)" >&2; exit 1; }

# --- shims -----------------------------------------------------------------
# curl: the per-repository advisory endpoint is answered from fixtures ($ADV_DIR
# so a case can swap in a modified copy); a repo with no fixture gets an empty
# list; every other URL fails like an unreachable host.
mkshims() { # $1 = shim dir, $2 = advisory dir, $3 = "deps-ok" | "deps-fail"
  mkdir -p "$1"
  cat > "$1/curl" <<SHIM
#!/usr/bin/env bash
for a in "\$@"; do
  case "\$a" in
    https://api.github.com/repos/*/security-advisories*)
      r="\${a#https://api.github.com/repos/}"; r="\${r%%/security-advisories*}"
      f="$2/\${r%%/*}-\${r#*/}-advisories.json"
      if [ -f "\$f" ]; then cat "\$f"; else echo '[]'; fi
      exit 0 ;;
  esac
done
exit 7
SHIM
  cat > "$1/go" <<SHIM
#!/usr/bin/env bash
case "\$*" in
  "list -m all")      cat "$WORK/modules.txt" ;;
  "list -deps ./...") [ "$3" = deps-ok ] && cat "$FIX/linked-packages.txt" || exit 1 ;;
  "version -m "*)     cat "$WORK/graph.txt" ;;
  *) exit 1 ;;
esac
SHIM
  chmod +x "$1/curl" "$1/go"
}

# The build list as `go list -m all` prints it (main module first, no version).
write_modules() { # $1 = route53 version
  cat > "$WORK/modules.txt" <<MODS
example.com/caddyui-fixture
github.com/aws/aws-sdk-go-v2 v1.48.0
github.com/aws/aws-sdk-go-v2/credentials v1.21.3
github.com/aws/aws-sdk-go-v2/service/route53 $1
github.com/aws/aws-sdk-go-v2/service/sso v1.39.5
github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.5
github.com/aws/aws-sdk-go-v2/service/sts v1.53.0
github.com/go-sql-driver/mysql v1.10.1
MODS
}
mkdir -p "$WORK/mod"
printf 'module example.com/caddyui-fixture\n\ngo 1.26.0\n' > "$WORK/mod/go.mod"

run() { # $1 = name, $2 = advisory dir, $3 = deps-ok|deps-fail ; prints findings tsv path
  mkshims "$WORK/shim-$1" "$2" "$3"
  PATH="$WORK/shim-$1:$PATH" GH_TOKEN='' GITHUB_TOKEN='' bash "$SCRIPT" \
    --dockerfile "$REPO_ROOT/Dockerfile.caddy" --gomod "$WORK/mod/go.mod" \
    --out-dir "$WORK/o-$1" >/dev/null 2>&1 || true
  printf '%s' "$WORK/o-$1/image-extra.tsv"
}
rows() { # $1 = tsv, $2 = module, $3 = ghsa (optional) -> count
  [ -f "$1" ] || { echo 0; return; }
  awk -F'\t' -v m="$2" -v g="${3:-}" '$1==m && (g=="" || $3==g) {n++} END {print n+0}' "$1"
}

ROOT=github.com/aws/aws-sdk-go-v2
R53=github.com/aws/aws-sdk-go-v2/service/route53
MYSQL=github.com/go-sql-driver/mysql

echo "=== the PR #194 shape: patched sub-modules, unlinked services ==="
write_modules v1.72.0
t="$(run main "$FIX" deps-ok)"
check "0  the sweep actually ran and wrote findings (mysql is live)" \
  "yes" "$([ -s "$t" ] && echo yes || echo no)"
check "1  GHSA-xmrv-pmrh-hhx2 (eventstream/s3/kinesis... unlinked) is NOT on the root pin" \
  "0" "$(rows "$t" "$ROOT" GHSA-xmrv-pmrh-hhx2)"
check "1b GHSA-3jcv-796g-cpjg (service modules, own pins patched) is NOT on the root pin" \
  "0" "$(rows "$t" "$ROOT" GHSA-3jcv-796g-cpjg)"
check "1c the root module carries no finding at all" "0" "$(rows "$t" "$ROOT")"
check "2  route53 v1.72.0 is past the 3jcv patch (v1.59.4) -> no route53 finding" \
  "0" "$(rows "$t" "$R53")"
check "3  CVE-less coverage unchanged: GHSA-4v5x-9mc8-gr98 on mysql 1.10.1 is reported" \
  "1" "$(rows "$t" "$MYSQL" GHSA-4v5x-9mc8-gr98)"

echo
echo "=== narrowing must not hide a real hit ==="
# Case 4. The same advisory, with route53 BELOW its patch: the row must land
# on route53 -- the module that owns the package -- not vanish.
write_modules v1.59.0
t="$(run lowr53 "$FIX" deps-ok)"
check "4  route53 v1.59.0 (< v1.59.4) IS reported for GHSA-3jcv-796g-cpjg" \
  "1" "$(rows "$t" "$R53" GHSA-3jcv-796g-cpjg)"
check "4b ... and attributed to route53, not to the root module" \
  "0" "$(rows "$t" "$ROOT" GHSA-3jcv-796g-cpjg)"
write_modules v1.72.0

# Case 5. A package that IS inside the root module and IS linked must still
# attribute to the root pin (the containment arm exists for exactly this).
mkdir -p "$WORK/adv5"
cp "$FIX"/*.json "$WORK/adv5/"
jq -c '. + [{ghsa_id:"GHSA-test-root-retry", cve_id:null, severity:"high",
             vulnerabilities:[{package:{ecosystem:"go", name:"github.com/aws/aws-sdk-go-v2/aws/retry"},
                               vulnerable_version_range:"< v1.49.0", patched_versions:"v1.49.0"}]}]' \
  "$FIX/aws-aws-sdk-go-v2-advisories.json" > "$WORK/adv5/aws-aws-sdk-go-v2-advisories.json"
t="$(run linkedpkg "$WORK/adv5" deps-ok)"
check "5  a linked package of the root module still attributes to the root pin" \
  "1" "$(rows "$t" "$ROOT" GHSA-test-root-retry)"
check "5b ... while the unlinked-service advisory stays off it" \
  "0" "$(rows "$t" "$ROOT" GHSA-xmrv-pmrh-hhx2)"

echo
echo "=== degradation is conservative, not silent ==="
# Case 6. No package list (`go list -deps` fails): rule 2 cannot run, so the
# unlinked-service advisory is KEPT on the root pin -- a false positive, never
# a false clean. Rule 1 (longest owning module) needs no toolchain and still
# keeps route53's patched rows off the root.
t="$(run nodeps "$FIX" deps-fail)"
check "6  without a package list, GHSA-xmrv-pmrh-hhx2 is kept on the root (fail-safe)" \
  "1" "$(rows "$t" "$ROOT" GHSA-xmrv-pmrh-hhx2)"
check "6b mysql is still reported" "1" "$(rows "$t" "$MYSQL" GHSA-4v5x-9mc8-gr98)"

echo
echo "=== the image binary path: rule 2 from the binary's function table (T-0951) ==="
# A `--binary` run has no `go list -deps`. Before T-0951 graph rows fell back
# to prefix matching, so GHSA-3jcv (`< v1.108.8`, an rds range) and
# GHSA-xmrv (eventstream) sat on the root pin of the published caddy image.
# The fake binary carries the pclntab-style function names the real one does,
# PACKED BACK TO BACK as Go stores them (the sso/github.com glue is real).
printf 'mod\tcaddy\t(devel)\n' > "$WORK/graph.txt"
awk 'NR>1 {printf "\tdep\t%s\t%s\th1:x=\n", $1, $2}' "$WORK/modules.txt" >> "$WORK/graph.txt"
mkbin() { # $1 = out file, $2.. = function names
  local f="$1"; shift
  { printf '\x7fELF\0\0'; printf '%s' "$@"; printf '\0'; } > "$f"
}
mkbin "$WORK/caddy-bin" \
  'github.com/aws/aws-sdk-go-v2/aws.Bool' \
  'github.com/aws/aws-sdk-go-v2/aws/retry.NewStandard' \
  'github.com/aws/aws-sdk-go-v2/service/route53.New' \
  'github.com/aws/aws-sdk-go-v2/service/sso.New' \
  'github.com/aws/aws-sdk-go-v2/service/sts.(*Client).AssumeRole' \
  'github.com/go-sql-driver/mysql.(*mysqlConn).Close'
runbin() { # $1 = name, $2 = advisory dir, $3 = binary
  mkshims "$WORK/shim-$1" "$2" deps-fail
  PATH="$WORK/shim-$1:$PATH" GH_TOKEN='' GITHUB_TOKEN='' bash "$SCRIPT" \
    --dockerfile "$REPO_ROOT/Dockerfile.caddy" --binary "$3" \
    --out-dir "$WORK/o-$1" >/dev/null 2>&1 || true
  printf '%s' "$WORK/o-$1/image-extra.tsv"
}
t="$(runbin bin "$WORK/adv5" "$WORK/caddy-bin")"
check "7  binary sweep ran (mysql is live on the graph row)" \
  "1" "$(rows "$t" "$MYSQL" GHSA-4v5x-9mc8-gr98)"
check "7b GHSA-3jcv-796g-cpjg (rds range) is NOT on the root graph row" \
  "0" "$(rows "$t" "$ROOT" GHSA-3jcv-796g-cpjg)"
check "7c GHSA-xmrv-pmrh-hhx2 (eventstream, unlinked) is NOT on the root graph row" \
  "0" "$(rows "$t" "$ROOT" GHSA-xmrv-pmrh-hhx2)"
check "7d a linked root package (aws/retry) still attributes to the root graph row" \
  "1" "$(rows "$t" "$ROOT" GHSA-test-root-retry)"
check "7e the binary's package list was written" \
  "yes" "$(grep -qx 'github.com/aws/aws-sdk-go-v2/service/sso' "$WORK/o-bin/binary-packages.txt" 2>/dev/null && echo yes || echo no)"
# Case 8. A binary with no readable function table: no package list, so rule
# 2 is skipped and the unlinked advisory is KEPT on the root (fail-safe).
mkbin "$WORK/bare-bin" 'nothing-here'
t="$(runbin bare "$FIX" "$WORK/bare-bin")"
check "8  no function table -> GHSA-xmrv-pmrh-hhx2 kept on the root graph row" \
  "1" "$(rows "$t" "$ROOT" GHSA-xmrv-pmrh-hhx2)"

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
