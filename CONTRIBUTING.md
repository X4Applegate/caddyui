# Contributing to Caddy UI

Thank you for your interest in contributing! This document explains how to get involved.

---

## Ways to Contribute

- **Bug reports** — open a GitHub Issue with steps to reproduce
- **Feature requests** — open an Issue describing the use case
- **Pull requests** — bug fixes and small improvements are welcome
- **Documentation** — corrections, clarifications, and examples

---

## Before You Open a PR

1. **Check existing issues and PRs** to avoid duplicate work.
2. For anything beyond a small bug fix, open an Issue first to discuss approach.
3. Keep PRs focused — one concern per PR makes review easier.

---

## Development Setup

### Prerequisites

- [Go 1.22+](https://go.dev/dl/)
- [Docker](https://docs.docker.com/get-docker/) (for local Caddy instance)
- A running Caddy instance with admin API accessible (default: `http://localhost:2019`)

### Run Locally

```bash
git clone https://github.com/X4Applegate/caddyui.git
cd caddyui

# Start a local Caddy for testing
docker run -d --name caddy-dev \
  -p 2019:2019 \
  caddy:2-alpine caddy run --config "" --adapter ""

# Run CaddyUI
CADDY_ADMIN_URL=http://localhost:2019 \
CADDYUI_DB=/tmp/caddyui-dev.db \
go run ./cmd/caddyui
```

Open http://localhost:8080 and complete first-run setup.

### Project Layout

```
cmd/caddyui/        main(), env vars, startup wiring
internal/auth/      sessions, bcrypt, TOTP
internal/caddy/     admin API client, Caddyfile adapter
internal/db/        SQLite open + migrations
internal/models/    structs and DB queries
internal/server/    all HTTP handlers + background goroutines
web/templates/      Go html/template (one file per page)
web/static/         CSS (Tailwind CDN), icons, PWA files
```

### Templates

Templates use Tailwind CSS loaded from CDN — no build step needed. The `web/embed.go` file embeds everything into the binary at compile time.

---

## Pull Request Guidelines

- Run `go build ./...` and confirm it compiles before submitting.
- Follow existing code style (no external linters required, just match what's there).
- Add a clear description of what changed and why.
- Reference the related Issue number if applicable (`Closes #123`).
- Keep commits clean — squash WIP commits before opening the PR.

---

## AI Assistance

This project uses [Claude (Anthropic)](https://claude.ai/) as a development assistant. Contributors are welcome to use AI tools in their own workflow. Please review AI-generated code carefully before submitting — you are responsible for what you open in a PR.

---

## Reporting Bugs

Please include:

1. CaddyUI version (shown in the sidebar footer)
2. Caddy version (shown in Servers page)
3. Browser and OS
4. Steps to reproduce
5. What you expected vs. what happened
6. Any relevant browser console or server log output

---

## License of Contributions

By submitting a pull request you agree that your contribution is licensed under the same [CaddyUI Source Available License 1.0](LICENSE) as the rest of the project.
