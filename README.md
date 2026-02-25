# Superhuman

VPS-first AI chat stack with Open WebUI frontend, Superhuman API/worker, Redis, and self-hosted Convex.

## Quick Start (Fresh Ubuntu/Debian VPS)

Recommended: one command bootstrap with automatic install, systemd setup, firewall, Nginx reverse proxy, and TLS.

```bash
curl -fsSL <raw-bootstrap-url>/deploy/bootstrap/bootstrap-vps.sh | bash -s -- \
  --repo <your-repo-url> \
  --branch main \
  --target /opt/superhuman \
  --service-user superhuman \
  --domain <your-domain> \
  --email <ops-email>
```

Notes:
- `--domain` is required unless you pass `--ssh-only`.
- `--email` is required for TLS (Let's Encrypt), unless you pass `--skip-tls`.
- For private-only access, use `--ssh-only`.

## Manual Setup

```bash
sudo apt-get update && sudo apt-get install -y git curl ca-certificates

git clone <your-repo-url> /opt/superhuman
cd /opt/superhuman

corepack enable
pnpm install --frozen-lockfile
pnpm build

superhuman setup \
  --auto \
  --mode systemd \
  --convex-mode self-hosted \
  --target /opt/superhuman \
  --service-user superhuman \
  --domain <your-domain> \
  --email <ops-email>
```

## `superhuman setup --auto` Behavior

Default path (recommended):
- Ensures Node.js 22.x, pnpm, Redis, and Docker (for self-hosted Convex).
- Clones/updates repo to target path.
- Builds monorepo + Open WebUI.
- Creates/uses service user for systemd services.
- Seeds `.env` from defaults and optional `--env-file` overrides.
- Starts self-hosted Convex and deploys schema/functions.
- Writes and enables systemd units.
- Optionally configures ingress with UFW + Nginx + Let's Encrypt.
- Runs `superhuman doctor` at the end.

## Networking and Firewall Defaults

When using public ingress (no `--ssh-only`):
- Opens `80/tcp` and `443/tcp` in UFW.
- Keeps app internals behind Nginx (`127.0.0.1:3000` and `127.0.0.1:4173`).
- Routes:
  - `/` -> frontend (`4173`)
  - `/api` and `/oauth` -> web API (`3000`)

Self-hosted Convex compose binds to localhost:
- backend `3210`, site proxy `3211`, dashboard `6791`

## CLI Commands

```bash
superhuman install [--mode systemd|docker] [--convex-mode self-hosted|cloud]
superhuman onboard [--target <path>] [--auto] [--domain <domain>] [--skip-tls] [--env-file <path>]
superhuman setup [--auto] [--non-interactive] [--domain <domain>] [--email <email>] [--ssh-only] [--skip-tls] [--env-file <path>]
superhuman configure providers [--target <path>]
superhuman doctor [--target <path>] [--json]
superhuman allow <email>
superhuman allow list
superhuman remove <email>
superhuman oauth [codex|qwen]
```

## Environment

Copy `.env.example` to `.env` (or pass `--env-file` during setup).

Required for base runtime:
- `APP_URL`, `FRONTEND_URL`, `REDIS_URL`
- Convex runtime values:
  - preferred self-hosted: `CONVEX_SELF_HOSTED_URL`, `CONVEX_SELF_HOSTED_ADMIN_KEY`
  - cloud fallback: `CONVEX_URL`, `CONVEX_ADMIN_KEY`
- `OAUTH_ENCRYPTION_KEY` (32+ chars)

Optional provider integrations (no longer required for initial setup):
- `AGENTMAIL_API_KEY`, `DEEPGRAM_API_KEY`, `FIREWORKS_API_KEY`, `OLLAMA_API_KEY`, `BASETEN_API_KEY`, `DEEPSEEK_API_KEY`, `TAVILY_API_KEY`

## Verify

```bash
superhuman doctor --target /opt/superhuman
superhuman oauth --target /opt/superhuman

sudo systemctl status superhuman-web superhuman-worker superhuman-frontend --no-pager
sudo journalctl -u superhuman-web -u superhuman-worker -u superhuman-frontend -n 200 --no-pager

sudo nginx -t
sudo ufw status verbose
```

## Repo Layout

- `apps/web`: Superhuman API server
- `apps/worker`: queue worker
- `apps/cli`: `superhuman` CLI
- `packages/convex`: Convex schema/functions
- `vendor/open-webui`: Open WebUI baseline frontend
- `deploy/bootstrap/bootstrap-vps.sh`: one-command VPS bootstrap
- `deploy/docker`: Docker compose templates
- `deploy/systemd`: systemd unit templates
