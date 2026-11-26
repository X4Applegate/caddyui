# Moved — this is not the Docker Hub overview

The source of truth for the Docker Hub repository overview
(<https://hub.docker.com/r/applegater/caddyui>) is **[`docs/dockerhub.md`](docs/dockerhub.md)**.
That is the file `scripts/dockerhub-description.sh` publishes; nothing publishes this one.

Edit `docs/dockerhub.md`, then `scripts/dockerhub-description.sh diff` to see how the live page has
drifted from it, and `publish` to overwrite the page.

For `applegater/caddyui-caddy`, the overview lives in
[`docs/dockerhub-caddy.md`](docs/dockerhub-caddy.md).

This file used to be a second copy of the overview and fell 72 lines behind the real one — it had
lost the relicense explanation, the OIDC/SSO, scheduled-backup and per-host rate-limiting entries,
and the prominent Apache-2.0 statement in the header. Publishing it would have reverted all of
that. It is kept as this pointer rather than deleted because the root of the repository is where a
reader looks for a file by this name.
