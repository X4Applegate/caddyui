#!/usr/bin/env bash
# agent-worktree.sh — give a session its own git worktree of caddyui.
#
# WHY THIS EXISTS
# ---------------
# `/mnt/volumes/8TB/caddyui` was one checkout shared by every session on this host. Three
# incidents trace to that single shared index, all of them in caddyui and none in mothership
# (which has had per-agent worktrees since T-0342):
#
#   T-0677  a local commit sat on shared `main`; two sessions committed on top of it and the next
#           push published all three, bypassing an `approval: publish` gate.
#   T-0678  `git push origin main` published two commits belonging to another card, because a
#           concurrent session committed between this session's commit and its push.
#   T-0678  two sessions independently rebased the same release minutes apart.
#
# A session that commits in its own worktree cannot publish another session's work by accident,
# because its index and its branch are its own.
#
# THE ONE COLLISION THAT MATTERS  (do not remove the unique-branch logic below)
# ----------------------------------------------------------------------------
# A branch can be checked out in only ONE worktree at a time. If a worktree parks on `main`, then
# any `git checkout main` in the main checkout fails:
#
#   fatal: 'main' is already used by worktree at '/mnt/volumes/8TB/caddyui-wt/<agent>'
#   exit 128
#
# caddyui's release path does checkouts, so a worktree sitting on `main` can abort a release.
# Therefore: a worktree NEVER sits on `main`, and no two agents share a branch. Each agent gets
# `wt/<agent>`, created from current `origin/main`.
#
# WHAT IS DELIBERATELY NOT PORTED FROM MOTHERSHIP'S VERSION
# --------------------------------------------------------
# Roughly half of mothership/scripts/agent-worktree.sh handles Next.js specifics that do not apply
# to a Go repo: the `node_modules` symlink, the per-tree `.next/`, and the turbopack
# workspace-root defect (T-0347). None of that is reproduced here.
#
# Go needs no equivalent: the module cache is shared through GOMODCACHE (/root/go/pkg/mod), so a
# worktree builds and tests with no extra wiring. Verified, not assumed — see T-0681.
#
# RELEASES AND TAGS STAY IN THE MAIN CHECKOUT, as they do for mothership.

set -euo pipefail

MAIN_REPO="${CADDYUI_MAIN_REPO:-/mnt/volumes/8TB/caddyui}"
WT_ROOT="${CADDYUI_WT_ROOT:-/mnt/volumes/8TB/caddyui-wt}"

die() { printf 'agent-worktree: %s\n' "$*" >&2; exit 1; }

# Agent names become both a branch name and a path component. A stray slash would create
# `wt/a/b`, and `..` would escape WT_ROOT. Restrict to a safe charset rather than quoting harder.
validate_agent() {
  local a="$1"
  [ -n "$a" ] || die "agent name is empty"
  case "$a" in
    *[!a-zA-Z0-9._-]*) die "agent name '$a' may contain only letters, digits, dot, underscore, hyphen" ;;
    .|..|-*)           die "agent name '$a' is not usable as a path component" ;;
  esac
}

cmd_add() {
  local agent="${1:-}"
  validate_agent "$agent"

  local dir="$WT_ROOT/$agent" branch="wt/$agent"

  # Base every new branch on the REMOTE tip, not on local `main`. Local `main` in a shared clone
  # can sit behind without any error surfacing (it is not moved by `git fetch`), which is itself
  # one of the failures this script exists to stop.
  git -C "$MAIN_REPO" fetch origin --quiet
  local base; base="$(git -C "$MAIN_REPO" rev-parse --short origin/main)"

  mkdir -p "$WT_ROOT"

  if git -C "$MAIN_REPO" worktree list --porcelain | grep -qx "worktree $dir"; then
    printf 'existing worktree: %s\n' "$dir"
  elif git -C "$MAIN_REPO" show-ref --verify --quiet "refs/heads/$branch"; then
    # Branch exists from an earlier run but the tree is gone: re-attach rather than re-create,
    # so any unpushed commits on that branch survive.
    git -C "$MAIN_REPO" worktree add "$dir" "$branch" >&2
  else
    git -C "$MAIN_REPO" worktree add -b "$branch" "$dir" "origin/main" >&2
  fi

  # Never leave a worktree on `main` — see the collision note above.
  local on; on="$(git -C "$dir" rev-parse --abbrev-ref HEAD)"
  [ "$on" = "main" ] && die "worktree $dir is on 'main'; that will break releases in the main checkout"

  printf '%s\n' "$dir"
  printf 'branch %s (from origin/main %s)\n' "$branch" "$base" >&2
}

cmd_list() {
  git -C "$MAIN_REPO" worktree list
}

# Remove a worktree only when it has nothing unpushed. Refuses otherwise rather than discarding
# work; `trash` beats `rm` and a refusal beats either.
cmd_remove() {
  local agent="${1:-}"
  validate_agent "$agent"
  local dir="$WT_ROOT/$agent" branch="wt/$agent"

  [ -d "$dir" ] || die "no worktree at $dir"

  local dirty; dirty="$(git -C "$dir" status --porcelain | wc -l)"
  [ "$dirty" -eq 0 ] || die "$dir has $dirty uncommitted change(s); commit or stash first"

  git -C "$MAIN_REPO" fetch origin --quiet
  local ahead; ahead="$(git -C "$dir" rev-list --count "origin/main..$branch" 2>/dev/null || echo 0)"
  [ "$ahead" -eq 0 ] || die "$branch has $ahead commit(s) not on origin/main; push or cherry-pick first"

  git -C "$MAIN_REPO" worktree remove "$dir"
  git -C "$MAIN_REPO" branch -d "$branch"
  printf 'removed %s and %s\n' "$dir" "$branch"
}

usage() {
  cat >&2 <<'USAGE'
usage: agent-worktree.sh <add|list|remove> [agent]

  add <agent>     create (or re-attach) /mnt/volumes/8TB/caddyui-wt/<agent> on branch wt/<agent>,
                  based on origin/main. Prints the path on stdout.
  list            show all worktrees of the caddyui repo.
  remove <agent>  remove the worktree and its branch. Refuses if anything is uncommitted or
                  unpushed.

Releases and tags stay in the main checkout (/mnt/volumes/8TB/caddyui).
USAGE
  exit 2
}

case "${1:-}" in
  add)    shift; cmd_add "${1:-}" ;;
  list)   shift; cmd_list ;;
  remove) shift; cmd_remove "${1:-}" ;;
  *)      usage ;;
esac
