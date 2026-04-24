# CaddyUI release SOP

Reusable runbook for cutting a new CaddyUI release. Works for patch (x.y.**z**), minor (x.**y**.0), and major (**x**.0.0) bumps — the only thing that changes is the version number and the prose in CHANGELOG / blog.

---

## 0. Prerequisites (one-time setup, already in place)

- `docker login` — authenticated as `applegater` to Docker Hub.
- `docker buildx ls` shows a `multiplatform` builder with `linux/amd64` + `linux/arm64` support.
- GitHub remote `origin` points at `https://github.com/X4Applegate/caddyui.git`.
- Working directory clean on `main` before you start (no stray uncommitted files).

Sanity check before every release:
```bash
docker buildx ls | grep multiplatform
docker info | grep -i 'username: applegater'
git status
git rev-parse --abbrev-ref HEAD   # should print 'main'
```

---

## 1. Pick the version number

Use semver:
- **Patch** (`v2.5.9` → `v2.5.10`) — bug fix, no behaviour change for correctly-configured setups.
- **Minor** (`v2.5.x` → `v2.6.0`) — new feature, additive only, no breaking change.
- **Major** (`v2.x.x` → `v3.0.0`) — breaking change, schema migration required, or removal of a documented feature.

Write the chosen version into a shell var so the rest of the SOP is copy-pasteable:
```bash
export VER=v2.5.11
```

---

## 2. Make the code change

- Edit files under `internal/`, `web/`, `cmd/` as needed.
- Keep commits small and focused — one logical change per commit. Don't bundle a bug fix with a refactor.
- Update any stale comments touched by the change. If a code comment claims the old behaviour, fix it in the same commit.

---

## 3. Update CHANGELOG.md

Insert a new block above the previous release. Template:

```markdown
## [$VER] — YYYY-MM-DD · Short descriptive headline

### Fixed / Added / Changed   (pick the section that matches)
- **One-sentence lead** explaining what the user-facing behaviour change is. Then a paragraph of implementation detail: what file changed, what the old code did wrong, what the new code does, and (for bug fixes) how the symptom would have manifested to a user.

### Implementation notes
- Bulleted secondary details: schema changes, migration story, self-healing behaviour for existing DB rows, caveats, follow-ups.

### Docker
- Published as `applegater/caddyui:$VER` and `:latest` (multi-arch `linux/amd64` + `linux/arm64`, SBOM + provenance, scratch base, non-root UID 10001).
```

Rules:
- Date in ISO format (`YYYY-MM-DD`), the day you're publishing.
- Lead sentence is bold and describes the *behaviour*, not the code location.
- Implementation notes cover the "why" and the "upgrade story" (what happens to existing rows, whether a restart is enough, etc.).
- Never rewrite an older CHANGELOG block — append only.

---

## 4. Update the docker-compose.yml version hint

The comment in `docker-compose.yml` shows an example build command with the version — bump it so copy-pasters get the right tag:

```yaml
# e.g. `CADDYUI_VERSION=v2.5.11 docker compose up -d --build`.
```

No other compose change is needed for a normal release.

---

## 5. Local build & vet (catch typos before Docker Hub sees them)

Go isn't installed on the host, so run through the Go container:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.24-alpine sh -c '
  go build ./... && go vet ./... && echo BUILD_OK
'
```

Expected output: `BUILD_OK`. Any compile error stops here — fix and re-run before committing.

---

## 6. Commit

Always create a new commit. Never amend a published commit. Never use `--no-verify`.

Commit message format (matches existing history):

```
<type>(<scope>): $VER — <short headline>

<wrapped body explaining what, why, and how. Reference the files and
functions touched. Include the user-visible symptom for bug fixes.>

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

- `type`: `feat` | `fix` | `docs` | `chore` | `refactor`
- `scope`: the subsystem — `dns`, `proxy-hosts`, `raw-routes`, `auth`, `deploy-page`, `settings`, `ui`, …
- Headline ≤ 70 chars including the version prefix.

Example run:
```bash
git add CHANGELOG.md docker-compose.yml internal/… web/…
git commit -m "$(cat <<'EOF'
fix(dns): v2.5.11 — short headline

Paragraph explaining the change.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## 7. Tag

```bash
git tag $VER
git tag --list | grep -F "$VER"   # verify it landed
```

The tag points at the commit you just made. If the build in step 8 fails, drop the tag (`git tag -d $VER`) before retrying — a failed push shouldn't leave behind a tag that doesn't correspond to a published image.

---

## 8. Multi-arch buildx push to Docker Hub

Single command, pushes both tags (`:$VER` and `:latest`) with SBOM + provenance:

```bash
docker buildx build \
  --builder multiplatform \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=$VER \
  --sbom=true \
  --provenance=true \
  -t applegater/caddyui:$VER \
  -t applegater/caddyui:latest \
  --push \
  .
```

Runtime: ~3–6 minutes on this host when layers are cached, ~8–10 minutes cold. Run in the background if you have other work:
```bash
… --push . > /tmp/build.log 2>&1 &
```

Success marker: the last lines of the output include
```
pushing manifest for docker.io/applegater/caddyui:$VER@sha256:…
pushing manifest for docker.io/applegater/caddyui:latest@sha256:…
```
and both manifest digests match (they point at the same multi-arch manifest list).

---

## 9. Push git

```bash
git push origin main
git push origin $VER
```

If step 8 failed and you dropped the tag locally, **don't** push — fix the problem and start over from step 6.

---

## 10. Verify what's live

```bash
docker buildx imagetools inspect applegater/caddyui:$VER | head -20
```

Should show manifests for `linux/amd64` + `linux/arm64` plus SBOM + provenance attestations.

Then check GitHub: `https://github.com/X4Applegate/caddyui/releases/tag/$VER` should exist and show the tag.

---

## 11. Write the announcement posts

Three files, all under `docs/`:

| File | Audience | Tone |
|---|---|---|
| `blog-post-$VER.html` | Personal blog | Longest. Problem → fix → implementation notes → upgrade block. |
| `caddy-forum-post-$VER.md` | Caddy community forum | Middle. Tech-heavy, forum-friendly markdown. |
| `facebook-post-$VER.md` | Social | Shortest. One paragraph + link, consumer-friendly. |

Use the v2.5.0 versions as templates — same `<style>` block, same hero card, same divider pattern. Swap the scope-appropriate content; keep the cert/Docker/footer sections intact.

Commit separately with `docs(posts): add $VER announcement drafts (blog HTML, Caddy forum, Facebook)`.

---

## 12. Hotfix override

If you push a broken tag, retract by pushing a new patch version — **do not** force-push over an existing tag. Users who already pulled `:$VER` expect it to be immutable. The `:latest` tag moves forward on every release automatically.

If the image is genuinely dangerous (leaks creds, RCE), additionally:
1. `docker pull applegater/caddyui:$VER` on a workstation
2. Retag something safe (e.g. the previous release) and re-push to `:latest`
3. Open an issue on GitHub marking `$VER` as yanked
4. Note the yank in the next release's CHANGELOG

---

## Appendix A — copy-paste release script

```bash
export VER=v2.5.11

# 5. Build + vet
docker run --rm -v "$PWD":/src -w /src golang:1.24-alpine sh -c 'go build ./... && go vet ./... && echo BUILD_OK'

# 6. Commit (edit the HEREDOC body first)
git add -A
git commit -m "$(cat <<EOF
fix(scope): $VER — headline

Body paragraph.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"

# 7. Tag
git tag $VER

# 8. Multi-arch push
docker buildx build \
  --builder multiplatform \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=$VER \
  --sbom=true --provenance=true \
  -t applegater/caddyui:$VER \
  -t applegater/caddyui:latest \
  --push .

# 9. Push git
git push origin main && git push origin $VER

# 10. Verify
docker buildx imagetools inspect applegater/caddyui:$VER | head
```

That's the whole loop. Every release I've cut since v2.3 has gone through these 12 steps in roughly this order — the script is just the muscle-memory version once the CHANGELOG block is written.
