# Superhuman

VPS-first experimental AI chat stack with Convex Cloud + Redis + worker orchestration.

## Fresh VPS Setup (Ubuntu/Debian)

Node compatibility note:
- `vendor/open-webui` currently requires Node.js major `18-22`.
- If your VPS image has Node `24.x`, `superhuman setup` will now automatically install Node `22.x`.

1. Prepare host and clone:
   - `sudo apt-get update && sudo apt-get install -y git curl ca-certificates`
   - `git clone <your-repo-url> superhuman && cd superhuman`
2. Build once and install CLI binary:
   - `corepack enable`
   - `pnpm install`
   - `pnpm build`
   - After build, `superhuman` is globally linked (`which superhuman` should resolve).
3. (Recommended) create a dedicated runtime user for systemd services:
   - `sudo useradd --system --create-home --shell /usr/sbin/nologin superhuman || true`
4. Run full setup:
   - `superhuman setup --mode systemd --target /opt/superhuman --service-user superhuman`
5. Verify runtime:
   - `superhuman doctor --target /opt/superhuman`
   - `superhuman oauth --target /opt/superhuman`
6. Confirm systemd:
   - `sudo systemctl status superhuman-web superhuman-worker superhuman-frontend --no-pager`
   - `sudo journalctl -u superhuman-web -u superhuman-worker -u superhuman-frontend -n 200 --no-pager`

Notes:
- For production domains, set `APP_URL` and `FRONTEND_URL` to `https://...`.
- OAuth redirect URIs must match `https://<vps-domain>/oauth/callback/codex` and `/oauth/callback/qwen`.

## Workspace

- `apps/web`: Superhuman web API server (health, OAuth callback/status, access gate endpoint)
- `apps/worker`: Redis-backed worker loop for long-running agent tasks
- `apps/cli`: global `superhuman` CLI (`install`, `onboard`, `setup`, `doctor`, allowlist commands)
- `packages/core`: shared config/logging/types/crypto
- `packages/convex`: Convex schema/functions including allowlist and ownership-scoped data access
- `packages/providers`: model/provider registry abstraction (Vercel AI SDK integration point)
- `packages/agent`: queue/state helpers for kernel-pictures orchestration
- `packages/email`: agentmail integration surface
- `packages/voice`: Deepgram integration surface
- `vendor/open-webui`: upstream Open WebUI source (frontend baseline)

## Open WebUI Baseline

The project vendors Open WebUI at `vendor/open-webui`. Frontend constants are patched to support runtime API base URL via:

- `VITE_SUPERHUMAN_WEBUI_BASE_URL`

This keeps the actual Open WebUI frontend source as baseline while backend integration moves to Superhuman APIs.
Systemd deployment starts this frontend at `http://<host>:4173`.
Brand assets are applied by `scripts/apply-branding.mjs` during `superhuman install`.

## API Compatibility Surface

The web service currently implements high-impact Open WebUI-compatible endpoints for bootstrap and chat:

- `GET /api/config`
- `GET /api/version`
- `GET /api/v1/auths/signup/enabled`
- `POST /api/v1/auths/signup`
- `POST /api/v1/auths/signin`
- `GET /api/v1/auths/`
- `GET /api/v1/models`
- `POST /api/chat/completions`
- `POST /api/v1/chat/completions`
- `POST /api/v1/tasks`
- `GET /api/v1/tasks`
- `GET /api/v1/tasks/:taskId`
- `POST /api/v1/tasks/:taskId/stop`
- `POST /api/oauth/start/:provider`
- `GET /api/oauth/status/:provider`
- `POST /api/oauth/manual/:provider`
- `GET /oauth/callback/:provider`

Web search/fetch behavior:

- Open WebUI `features.web_search` requests are supported.
- If `TAVILY_API_KEY` is configured, backend performs Tavily search and injects source snippets into model context.
- URL fetch snippets are automatically added when user prompt contains `http(s)` links.
- Marketplace/workspace-heavy features are gated off by default, while chat-focused capabilities (including web search/fetch) stay enabled.

## Convex Auth + Allowlist Gate

Convex functions in `packages/convex/convex` include:

- `allowlist:allow`
- `allowlist:remove`
- `allowlist:list`
- `users:accessStatus`
- `users:activateIfAllowlisted`
- `users:deactivateByEmail`

Ownership-scoped chat/message functions enforce authenticated active users.

OAuth provider tokens are stored encrypted in Convex (`oauth_tokens_encrypted`) by backend exchange handlers.
Authorization codes and tokens never pass through frontend/browser state.
OAuth setup/status routes require an authenticated allowlisted active session.
`/oauth/callback/:provider` stores the auth code and marks status; token exchange is completed by the authenticated CLI/server-side manual exchange route.

## CLI

Build CLI:

```bash
pnpm --filter @superhuman/cli build
pnpm --filter @superhuman/cli dev -- --help
```

Commands:

- `superhuman install`
- `superhuman onboard`
- `superhuman setup`
- `superhuman doctor`
- `superhuman allow <email>`
- `superhuman remove <email>`
- `superhuman allow list`
- `superhuman oauth [codex|qwen]`
- `superhuman ... --target /opt/superhuman` for non-current install paths
- `superhuman install --mode systemd|docker --service-user <linux-user>`

`doctor` includes OAuth authorization checks when OAuth client IDs are configured.

Production behavior of `install`:

- Enforces Redis memory config (`maxmemory 256mb`, `maxmemory-policy allkeys-lru`) in Redis config files and restarts service.
- Installs/updates dependencies idempotently on Ubuntu/Debian (`node`, `pnpm`, `redis`, optional `docker`).
- Builds monorepo + Open WebUI with retry memory tuning for Vite build reliability.
- Regenerates hardened systemd unit files each run using selected target path and service user.
- Runs `superhuman doctor` at the end.

## Deployment templates

- `deploy/systemd/superhuman-web.service`
- `deploy/systemd/superhuman-worker.service`
- `deploy/systemd/superhuman-frontend.service`
- `deploy/docker/docker-compose.yml`

Docker compose is production-oriented:

- worker runs compiled `start` mode (not dev/watch),
- restart policies enabled,
- healthchecks for Redis and web,
- Redis memory policy configured to match VPS/systemd defaults,
- frontend API base defaults to `APP_URL` (fallback `http://127.0.0.1:3000`) so browser clients can reach the API.

Docker override note:

- If you intentionally run the frontend behind an internal reverse proxy, override `VITE_SUPERHUMAN_WEBUI_BASE_URL` with a browser-reachable URL before `docker compose up`.
- `http://web:3000` only works for containers on the internal Docker network, not end-user browsers.

## Environment

Copy `.env.example` to `.env` and fill in values.

OAuth exchange-related env values:

- `CODEX_OAUTH_CLIENT_ID`, `CODEX_OAUTH_CLIENT_SECRET`, `CODEX_OAUTH_AUTH_URL`, `CODEX_OAUTH_TOKEN_URL`
- `QWEN_OAUTH_CLIENT_ID`, `QWEN_OAUTH_CLIENT_SECRET`, `QWEN_OAUTH_AUTH_URL`, `QWEN_OAUTH_TOKEN_URL`
- `OAUTH_ENCRYPTION_KEY` (32+ chars; used to encrypt access/refresh tokens before Convex storage)
