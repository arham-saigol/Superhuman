#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-}"
BRANCH="${BRANCH:-main}"
TARGET="${TARGET:-/opt/superhuman}"
SERVICE_USER="${SERVICE_USER:-superhuman}"
MODE="${MODE:-systemd}"
CONVEX_MODE="${CONVEX_MODE:-self-hosted}"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
SSH_ONLY="${SSH_ONLY:-false}"
SKIP_TLS="${SKIP_TLS:-false}"
ENV_FILE="${ENV_FILE:-}"
OWNER_USER="${SUDO_USER:-${USER:-$(id -un)}}"

run_as_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_URL="$2"
      shift 2
      ;;
    --branch)
      BRANCH="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --service-user)
      SERVICE_USER="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --convex-mode)
      CONVEX_MODE="$2"
      shift 2
      ;;
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --email)
      EMAIL="$2"
      shift 2
      ;;
    --env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    --ssh-only)
      SSH_ONLY="true"
      shift
      ;;
    --skip-tls)
      SKIP_TLS="true"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "${REPO_URL}" ]]; then
  echo "Missing --repo <git-url>" >&2
  exit 1
fi

if [[ "${SSH_ONLY}" != "true" && -z "${DOMAIN}" ]]; then
  echo "Missing --domain. Use --ssh-only to skip public ingress setup." >&2
  exit 1
fi

if [[ "${SSH_ONLY}" != "true" && "${SKIP_TLS}" != "true" && -z "${EMAIL}" ]]; then
  echo "Missing --email for TLS certificate provisioning." >&2
  exit 1
fi

echo "[bootstrap] installing base packages"
run_as_root apt-get update
run_as_root apt-get install -y curl ca-certificates git

if [[ ! -d "${TARGET}/.git" ]]; then
  echo "[bootstrap] cloning repository"
  run_as_root mkdir -p "${TARGET}"
  run_as_root chown -R "${OWNER_USER}:${OWNER_USER}" "${TARGET}"
  git clone --depth 1 -b "${BRANCH}" "${REPO_URL}" "${TARGET}"
else
  echo "[bootstrap] updating repository"
  git -C "${TARGET}" fetch origin "${BRANCH}" --depth 1
  git -C "${TARGET}" checkout "${BRANCH}"
  git -C "${TARGET}" pull --ff-only origin "${BRANCH}"
fi

cd "${TARGET}"

echo "[bootstrap] ensuring Node.js 22.x"
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL "https://deb.nodesource.com/setup_22.x" | run_as_root bash -
  run_as_root apt-get install -y nodejs
else
  MAJOR="$(node -v | sed -E 's/^v([0-9]+).*/\1/')"
  if [[ "${MAJOR}" -lt 18 || "${MAJOR}" -gt 22 ]]; then
    curl -fsSL "https://deb.nodesource.com/setup_22.x" | run_as_root bash -
    run_as_root apt-get install -y nodejs
  fi
fi

echo "[bootstrap] installing pnpm and building CLI"
corepack enable || true
corepack prepare pnpm@10.5.2 --activate || run_as_root npm i -g pnpm@10.5.2
pnpm install --frozen-lockfile
pnpm build

CMD=(superhuman setup --auto --mode "${MODE}" --convex-mode "${CONVEX_MODE}" --target "${TARGET}" --service-user "${SERVICE_USER}")
if [[ -n "${DOMAIN}" ]]; then
  CMD+=(--domain "${DOMAIN}")
fi
if [[ -n "${EMAIL}" ]]; then
  CMD+=(--email "${EMAIL}")
fi
if [[ "${SSH_ONLY}" == "true" ]]; then
  CMD+=(--ssh-only)
fi
if [[ "${SKIP_TLS}" == "true" ]]; then
  CMD+=(--skip-tls)
fi
if [[ -n "${ENV_FILE}" ]]; then
  CMD+=(--env-file "${ENV_FILE}")
fi

echo "[bootstrap] running setup: ${CMD[*]}"
"${CMD[@]}"

echo "[bootstrap] done"
