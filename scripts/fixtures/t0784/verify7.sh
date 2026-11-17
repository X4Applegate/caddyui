#!/usr/bin/env bash
# T-0784: prove gate 4 compares the filesystem as COLUMNS, and that the change
# neither reopened a known bypass nor started blocking legitimate change.
#
# 10 gate runs over purpose-built fixtures:
#   A  the two bypasses found in the T-0641 security review must still BLOCK
#   B  the five previously-detected shapes must still BLOCK, plus the new
#      T-0784 symlink repoint
#   C  the two controls (identical image, simulated apk upgrade) must stay 0/0/0
#
# Fixtures are built from applegater/caddyui-caddy:stable; see
# Dockerfile.symlink-repoint here for the T-0784 one. The others are the
# T-0641 set. a/b/c below are the three assertions: (a) trust store,
# (b) setuid/setgid, (c) new paths outside the allowlist.
set -u
R=${T0784_RESULTS:-/tmp/t0784-verify/results}
G=${T0784_GATE_REPO:-/mnt/volumes/8TB/caddyui-wt/t0641}
B=applegater/caddyui-caddy:stable
mkdir -p "$R"
exec >"$R/verify7.log" 2>&1
cd "$G" || exit 2

echo "### provenance"
echo "commit : $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"
echo "sha256 : $(sha256sum scripts/caddy-image-gate.sh | cut -d' ' -f1)"
echo

run() { # name image policy want_exit note
  local n=$1 img=$2 pol=$3 want=$4 note=${5:-}
  rm -rf "$R/g-$n"
  FS_DELTA=on MODULE_DRIFT_POLICY="$pol" \
    scripts/caddy-image-gate.sh "$img" "$B" "$R/g-$n" amd64 >"$R/$n.out" 2>&1
  local rc=$? v a b c
  v=$(cat "$R/g-$n/verdict" 2>/dev/null || echo NONE)
  a=$(wc -l < "$R/g-$n/fs-ca-amd64.txt" 2>/dev/null || echo -)
  b=$(wc -l < "$R/g-$n/fs-suid-amd64.txt" 2>/dev/null || echo -)
  c=$(wc -l < "$R/g-$n/fs-newpaths-amd64.txt" 2>/dev/null || echo -)
  printf '%-18s exit=%s(want %s) verdict=%-10s a/b/c=%s/%s/%s %-6s %s\n' \
    "$n" "$rc" "$want" "$v" "$a" "$b" "$c" \
    "$([ "$rc" = "$want" ] && echo PASS || echo '**FAIL**')" "$note"
}

echo "### A. the two confirmed bypasses must now BLOCK"
run mozilla      t0641-evade-mozilla:test      block 1 "in-place Mozilla root overwrite (was exit 0)"
run apkprefix    t0641-evade-apkprefix:test    block 1 "/etc/apk/.hook.sh (was exit 0)"

echo
echo "### B. previously-detected shapes must STILL block (no regression)"
run careplace    t0641-careplace-stealth:test  block 1 "appended cert, no new path"
run ca           t0641-ca:test                 block 1 "added CA"
run setuid       t0641-setuid:test             block 1 "chmod u+s"
run copyscript   t0641-copyscript:test         block 1 "COPY extra script"
run usrshare     t0641-evade-usrshare:test     block 1 "CA at /usr/share + conf edit"
run symrepoint   t0784-symlink-repoint:test    block 1 "T-0784: repointed trust-store symlink"

echo
echo "### C. legitimate change must NOT block -- the false-positive question"
run control      "$B"                          block 0 "identical image"
run refresh      t0641-refresh:test            block 0 "simulated apk upgrade"

echo
echo "### D. the (a) coverage actually fires on the mozilla row"
echo "--- fs-ca for mozilla (MUST name the overwritten root) ---"
sed 's/^/    /' "$R/g-mozilla/fs-ca-amd64.txt" 2>/dev/null | head -5
echo "--- new paths for mozilla (expect 0: overwritten in place) ---"
echo "    count=$(wc -l < "$R/g-mozilla/fs-newpaths-amd64.txt" 2>/dev/null)"
echo "--- apkprefix caught by (c) ---"
sed 's/^/    /' "$R/g-apkprefix/fs-newpaths-amd64.txt" 2>/dev/null | head -5

echo
echo "### E. refresh noise detail (must stay quiet)"
echo "raw diff lines : $(wc -l < "$R/g-refresh/fs-diff-amd64.txt" 2>/dev/null)"
echo "asserted a/b/c : $(wc -l < "$R/g-refresh/fs-ca-amd64.txt")/$(wc -l < "$R/g-refresh/fs-suid-amd64.txt")/$(wc -l < "$R/g-refresh/fs-newpaths-amd64.txt")"

echo
echo "### G. T-0784: symlink repoint shape (want: (a) names it, (c) adds NO path)"
# The point of the whole change. Under the old space-separated key this
# repoint read as one removed path + one added path; with columns it is a
# changed target column on an unchanged path.
echo "--- fs-ca (expect the repointed link, target column changed) ---"
sed 's/^/    /' "$R/g-symrepoint/fs-ca-amd64.txt" 2>/dev/null | head -5
echo "--- new paths from the TRUST STORE (must be none) ---"
if grep -E 'ssl/certs|ca-certificates' "$R/g-symrepoint/fs-newpaths-amd64.txt" 2>/dev/null | sed 's/^/    /'; then
  echo "    ^^ UNEXPECTED: the repoint contributed a new path"
else
  echo "    (none from the trust store -- correct)"
fi
echo "--- all new paths (the fixture's own COPY is expected here) ---"
sed 's/^/    /' "$R/g-symrepoint/fs-newpaths-amd64.txt" 2>/dev/null | head -5
echo "--- tab-column format sanity: first 3 lines of the raw file list ---"
head -3 "$R/g-symrepoint/fs-new-amd64.txt" 2>/dev/null | cat -A | sed 's/^/    /' | cut -c1-120

echo
echo "### F. leaked containers (want 0)"
docker ps -a --filter status=created --format '{{.Image}}' | grep -c 'caddyui-caddy\|t0641\|t0784' || true
echo "### DONE"
