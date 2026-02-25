#!/usr/bin/env node
import { Command } from "commander";
import prompts from "prompts";
import { chmodSync, existsSync, readFileSync } from "node:fs";
import { mkdir, access, constants, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { userInfo } from "node:os";
import { ConvexHttpClient } from "convex/browser";
import { resolveConvexConfig } from "@superhuman/core";
import {
  applyConvexEnvDefaults,
  DEFAULT_SELF_HOSTED_CONVEX_URL,
  extractAdminKeyFromOutput,
  isPlaceholderSecret
} from "./convex.js";

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

const PNPM_VERSION = "10.5.2";
const NODE_MIN_MAJOR = 18;
const NODE_MAX_MAJOR = 22;
const NODE_SETUP_MAJOR = 22;
const WEB_PORT = Number(process.env.PORT ?? 3000);
const FRONTEND_PORT = Number(process.env.FRONTEND_PORT ?? 4173);
type AppMode = "systemd" | "docker";
type ConvexRuntimeMode = "self-hosted" | "cloud";
type InstallOptions = {
  mode?: AppMode;
  convexMode?: ConvexRuntimeMode;
  repo?: string;
  branch?: string;
  target?: string;
  serviceUser?: string;
  skipDoctor?: boolean;
  deferServiceOwnership?: boolean;
};

type SetupOptions = InstallOptions & {
  auto?: boolean;
  nonInteractive?: boolean;
  domain?: string;
  email?: string;
  sshOnly?: boolean;
  skipTls?: boolean;
  envFile?: string;
};

type OnboardOptions = {
  auto?: boolean;
  domain?: string;
  skipTls?: boolean;
  envOverrides?: Record<string, string>;
  runOAuth?: boolean;
};

const OPTIONAL_PROVIDER_KEYS = [
  "AGENTMAIL_API_KEY",
  "DEEPGRAM_API_KEY",
  "FIREWORKS_API_KEY",
  "OLLAMA_API_KEY",
  "BASETEN_API_KEY",
  "DEEPSEEK_API_KEY"
] as const;

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function run(command: string, args: string[], cwd?: string): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ["inherit", "pipe", "pipe"],
      shell: process.platform === "win32"
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stdout.write(text);
    });

    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr += text;
      process.stderr.write(text);
    });

    child.on("close", (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

async function runOrThrow(command: string, args: string[], cwd?: string): Promise<RunResult> {
  const result = await run(command, args, cwd);
  if (result.code !== 0) {
    throw new Error(`Command failed: ${command} ${args.join(" ")}`);
  }
  return result;
}

async function bashOrThrow(script: string, cwd?: string): Promise<RunResult> {
  return runOrThrow("bash", ["-lc", script], cwd);
}

async function commandExists(cmd: string): Promise<boolean> {
  try {
    await access(cmd, constants.X_OK);
    return true;
  } catch {
    const whichCmd = process.platform === "win32" ? "where" : "which";
    const result = await run(whichCmd, [cmd]);
    return result.code === 0;
  }
}

async function hasDockerComposePlugin(): Promise<boolean> {
  if (!(await commandExists("docker"))) {
    return false;
  }
  const result = await run("docker", ["compose", "version"]);
  return result.code === 0;
}

async function runDockerComposeOrThrow(args: string[], cwd?: string): Promise<RunResult> {
  if (await hasDockerComposePlugin()) {
    return runOrThrow("docker", ["compose", ...args], cwd);
  }
  if (await commandExists("docker-compose")) {
    return runOrThrow("docker-compose", args, cwd);
  }
  throw new Error("Docker Compose is required but not available. Install docker-compose-plugin or docker-compose.");
}

function parseDotEnv(content: string): Record<string, string> {
  const lines = content.split(/\r?\n/);
  const out: Record<string, string> = {};
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith("#")) {
      continue;
    }
    const idx = line.indexOf("=");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    out[key] = value;
  }
  return out;
}

function stringifyDotEnv(values: Record<string, string>): string {
  return Object.entries(values)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n") + "\n";
}

function normalizeDomain(value?: string): string | undefined {
  const raw = (value ?? "").trim();
  if (!raw) return undefined;
  const withScheme = raw.includes("://") ? raw : `https://${raw}`;
  let hostname: string;
  try {
    hostname = new URL(withScheme).hostname.trim().toLowerCase();
  } catch {
    throw new Error(`Invalid domain: ${raw}`);
  }
  if (!hostname || !/^[a-z0-9.-]+$/i.test(hostname)) {
    throw new Error(`Invalid domain: ${raw}`);
  }
  return hostname;
}

function resolvePathFromCwd(pathValue: string): string {
  if (isAbsolute(pathValue)) {
    return pathValue;
  }
  return resolve(process.cwd(), pathValue);
}

async function loadEnvOverrides(pathValue?: string): Promise<Record<string, string>> {
  const path = (pathValue ?? "").trim();
  if (!path) {
    return {};
  }
  const resolvedPath = resolvePathFromCwd(path);
  if (!existsSync(resolvedPath)) {
    throw new Error(`Env file not found: ${resolvedPath}`);
  }
  return parseDotEnv(readFileSync(resolvedPath, "utf8"));
}

function normalizeOnboardValue(value: unknown): string {
  return String(value ?? "").trim();
}

function defaultOauthEncryptionKey(): string {
  return randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
}

async function ensureLinuxServiceUser(serviceUser: string): Promise<void> {
  if (process.platform !== "linux") return;
  const userExists = await run("bash", ["-lc", `id -u ${shellQuote(serviceUser)}`]);
  if (userExists.code === 0) {
    return;
  }
  console.log(`[install] creating system user: ${serviceUser}`);
  await bashOrThrow(
    `sudo useradd --system --create-home --shell /usr/sbin/nologin ${shellQuote(serviceUser)} || true`
  );
}

async function ensureServiceOwnershipLinux(targetDir: string, serviceUser: string): Promise<void> {
  if (process.platform !== "linux") return;
  await bashOrThrow(`sudo chown -R ${shellQuote(serviceUser)}:${shellQuote(serviceUser)} ${shellQuote(targetDir)}`);
}

async function ensureEnvFileOwnershipLinux(targetDir: string, serviceUser: string): Promise<void> {
  if (process.platform !== "linux") return;
  const envPath = join(targetDir, ".env");
  if (!existsSync(envPath)) return;
  await bashOrThrow(`sudo chown ${shellQuote(serviceUser)}:${shellQuote(serviceUser)} ${shellQuote(envPath)}`);
  await bashOrThrow(`sudo chmod 640 ${shellQuote(envPath)}`);
}

function ingressProtocol(skipTls: boolean): "http" | "https" {
  return skipTls ? "http" : "https";
}

function buildIngressUrl(domain: string, skipTls: boolean): string {
  return `${ingressProtocol(skipTls)}://${domain}`;
}

function nginxSiteConfig(domain: string): string {
  return [
    "server {",
    "  listen 80;",
    `  server_name ${domain};`,
    "",
    "  location /api/ {",
    "    proxy_pass http://127.0.0.1:3000;",
    "    proxy_http_version 1.1;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto $scheme;",
    "    proxy_set_header Upgrade $http_upgrade;",
    "    proxy_set_header Connection upgrade;",
    "  }",
    "",
    "  location /oauth/ {",
    "    proxy_pass http://127.0.0.1:3000;",
    "    proxy_http_version 1.1;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto $scheme;",
    "    proxy_set_header Upgrade $http_upgrade;",
    "    proxy_set_header Connection upgrade;",
    "  }",
    "",
    "  location / {",
    "    proxy_pass http://127.0.0.1:4173;",
    "    proxy_http_version 1.1;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto $scheme;",
    "    proxy_set_header Upgrade $http_upgrade;",
    "    proxy_set_header Connection upgrade;",
    "  }",
    "}",
    ""
  ].join("\n");
}

async function configureIngressLinux(targetDir: string, params: {
  domain: string;
  email: string;
  skipTls: boolean;
}): Promise<void> {
  if (process.platform !== "linux") return;
  const configDir = join(targetDir, "deploy", "nginx");
  const localConfigPath = join(configDir, "superhuman.conf");
  await mkdir(configDir, { recursive: true });
  await writeFile(localConfigPath, nginxSiteConfig(params.domain), "utf8");

  await bashOrThrow("sudo apt-get update");
  await bashOrThrow("sudo apt-get install -y ufw nginx certbot python3-certbot-nginx");

  await bashOrThrow("sudo ufw allow OpenSSH");
  await bashOrThrow("sudo ufw allow 80/tcp");
  if (!params.skipTls) {
    await bashOrThrow("sudo ufw allow 443/tcp");
  }
  await bashOrThrow("sudo ufw deny 3000/tcp || true");
  await bashOrThrow("sudo ufw deny 4173/tcp || true");
  await bashOrThrow("sudo ufw --force enable");

  await bashOrThrow(`sudo install -m 0644 ${shellQuote(localConfigPath)} /etc/nginx/sites-available/superhuman`);
  await bashOrThrow("sudo ln -sf /etc/nginx/sites-available/superhuman /etc/nginx/sites-enabled/superhuman");
  await bashOrThrow("sudo rm -f /etc/nginx/sites-enabled/default");
  await bashOrThrow("sudo nginx -t");
  await bashOrThrow("sudo systemctl enable nginx");
  await bashOrThrow("sudo systemctl restart nginx");

  if (!params.skipTls) {
    await bashOrThrow(
      `sudo certbot --nginx -d ${shellQuote(params.domain)} -m ${shellQuote(params.email)} --agree-tos --redirect --non-interactive`
    );
    await bashOrThrow("sudo systemctl reload nginx");
  }
}

async function ensureConvexEnvDefaults(baseDir: string, preferSelfHosted: boolean): Promise<Record<string, string>> {
  const envPath = join(baseDir, ".env");
  const envExamplePath = join(baseDir, ".env.example");
  let values: Record<string, string> = {};
  let seedChanged = false;

  if (existsSync(envPath)) {
    values = parseDotEnv(readFileSync(envPath, "utf8"));
  } else if (existsSync(envExamplePath)) {
    values = parseDotEnv(readFileSync(envExamplePath, "utf8"));
    seedChanged = true;
  }

  if (!preferSelfHosted) {
    const seededSelfHostedUrl = (values.CONVEX_SELF_HOSTED_URL ?? "").trim();
    const seededSelfHostedAdmin = (values.CONVEX_SELF_HOSTED_ADMIN_KEY ?? "").trim();
    if (seededSelfHostedUrl === DEFAULT_SELF_HOSTED_CONVEX_URL || isPlaceholderSecret(seededSelfHostedAdmin)) {
      values.CONVEX_SELF_HOSTED_URL = "";
      values.CONVEX_SELF_HOSTED_ADMIN_KEY = "";
      seedChanged = true;
    }
  }

  const { values: normalized, changed } = applyConvexEnvDefaults(values, preferSelfHosted);
  values = normalized;

  if (seedChanged || changed) {
    await writeFile(envPath, stringifyDotEnv(values), "utf8");
    chmodSync(envPath, 0o600);
  }

  return values;
}

async function ensureSelfHostedAdminKey(baseDir: string, values: Record<string, string>): Promise<Record<string, string>> {
  const current = (values.CONVEX_SELF_HOSTED_ADMIN_KEY ?? "").trim();
  if (!isPlaceholderSecret(current)) {
    return values;
  }

  await runDockerComposeOrThrow(["-f", "deploy/docker/convex-compose.yml", "up", "-d", "backend"], baseDir);
  const result = await runDockerComposeOrThrow(
    ["-f", "deploy/docker/convex-compose.yml", "exec", "-T", "backend", "./generate_admin_key.sh"],
    baseDir
  );
  const key = extractAdminKeyFromOutput(`${result.stdout}\n${result.stderr}`);
  if (!key) {
    throw new Error("Unable to extract Convex admin key from generate_admin_key.sh output");
  }

  const envPath = join(baseDir, ".env");
  const next = { ...values, CONVEX_SELF_HOSTED_ADMIN_KEY: key };
  await writeFile(envPath, stringifyDotEnv(next), "utf8");
  chmodSync(envPath, 0o600);
  return next;
}

async function deployConvexSelfHosted(targetDir: string, values: Record<string, string>): Promise<void> {
  const convexUrl = (values.CONVEX_SELF_HOSTED_URL ?? "").trim();
  const convexAdminKey = (values.CONVEX_SELF_HOSTED_ADMIN_KEY ?? "").trim();
  if (!convexUrl || !convexAdminKey) {
    console.log("[install] skipping convex deploy (missing self-hosted url/admin key)");
    return;
  }

  const previousUrl = process.env.CONVEX_SELF_HOSTED_URL;
  const previousAdminKey = process.env.CONVEX_SELF_HOSTED_ADMIN_KEY;
  process.env.CONVEX_SELF_HOSTED_URL = convexUrl;
  process.env.CONVEX_SELF_HOSTED_ADMIN_KEY = convexAdminKey;
  try {
    console.log("[install] deploying Convex functions/schema to self-hosted backend");
    await runOrThrow(
      "pnpm",
      ["--filter", "@superhuman/convex", "exec", "convex", "deploy", "-y", "--typecheck", "disable"],
      targetDir
    );
  } finally {
    if (previousUrl === undefined) {
      delete process.env.CONVEX_SELF_HOSTED_URL;
    } else {
      process.env.CONVEX_SELF_HOSTED_URL = previousUrl;
    }
    if (previousAdminKey === undefined) {
      delete process.env.CONVEX_SELF_HOSTED_ADMIN_KEY;
    } else {
      process.env.CONVEX_SELF_HOSTED_ADMIN_KEY = previousAdminKey;
    }
  }
}

async function detectLinuxDistro(): Promise<string | null> {
  if (process.platform !== "linux") return null;
  try {
    const osRelease = await readFile("/etc/os-release", "utf8");
    const idLine = osRelease
      .split(/\r?\n/)
      .find((line) => line.startsWith("ID="));
    return idLine ? idLine.replace("ID=", "").replace(/"/g, "") : null;
  } catch {
    return null;
  }
}

async function detectCurrentRepo(): Promise<string | null> {
  const result = await run("git", ["config", "--get", "remote.origin.url"]);
  const value = result.stdout.trim();
  if (result.code === 0 && value) {
    return value;
  }
  return null;
}

function serviceUnitContent(params: {
  description: string;
  workingDirectory: string;
  environmentFile: string;
  execStart: string;
  user: string;
}): string {
  return [
    "[Unit]",
    `Description=${params.description}`,
    "After=network-online.target redis-server.service",
    "Wants=network-online.target redis-server.service",
    "",
    "[Service]",
    "Type=simple",
    `WorkingDirectory=${params.workingDirectory}`,
    `EnvironmentFile=${params.environmentFile}`,
    "Environment=NODE_ENV=production",
    "Environment=PATH=/usr/local/bin:/usr/bin:/bin",
    "Restart=always",
    "RestartSec=5",
    "TimeoutStopSec=30",
    "KillSignal=SIGTERM",
    "KillMode=mixed",
    "NoNewPrivileges=true",
    "PrivateTmp=true",
    "ProtectSystem=full",
    "ProtectHome=true",
    `ReadWritePaths=${params.workingDirectory}`,
    "LimitNOFILE=65535",
    "UMask=0027",
    `User=${params.user}`,
    `Group=${params.user}`,
    `ExecStart=${params.execStart}`,
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    ""
  ].join("\n");
}

async function writeSystemdUnits(targetDir: string, serviceUser: string) {
  const systemdDir = join(targetDir, "deploy", "systemd");
  const envFile = `${targetDir}/.env`;
  const webExec = "/usr/bin/env node apps/web/dist/server.js";
  const workerExec = "/usr/bin/env node apps/worker/dist/index.js";
  const frontendExec = "/usr/bin/env bash -c 'export VITE_SUPERHUMAN_WEBUI_BASE_URL=${APP_URL:-http://127.0.0.1:3000}; npm run preview -- --host 0.0.0.0 --port ${FRONTEND_PORT:-4173}'";

  const webUnit = serviceUnitContent({
    description: "Superhuman Web Service",
    workingDirectory: targetDir,
    environmentFile: envFile,
    execStart: webExec,
    user: serviceUser
  });
  const workerUnit = serviceUnitContent({
    description: "Superhuman Worker Service",
    workingDirectory: targetDir,
    environmentFile: envFile,
    execStart: workerExec,
    user: serviceUser
  });
  const frontendUnit = serviceUnitContent({
    description: "Superhuman Open WebUI Frontend",
    workingDirectory: `${targetDir}/vendor/open-webui`,
    environmentFile: envFile,
    execStart: frontendExec,
    user: serviceUser
  });

  await writeFile(join(systemdDir, "superhuman-web.service"), webUnit, "utf8");
  await writeFile(join(systemdDir, "superhuman-worker.service"), workerUnit, "utf8");
  await writeFile(join(systemdDir, "superhuman-frontend.service"), frontendUnit, "utf8");
}

async function buildOpenWebUI(openWebUiDir: string) {
  const attempts = ["4096", "6144"];
  let lastError: Error | null = null;

  for (const memory of attempts) {
    try {
      await bashOrThrow(`export NODE_OPTIONS=--max-old-space-size=${memory}; npm run build`, openWebUiDir);
      return;
    } catch (error) {
      lastError = error as Error;
      console.log(`[install] Open WebUI build failed with NODE_OPTIONS=${memory}; retrying if possible`);
    }
  }

  throw lastError ?? new Error("Open WebUI build failed");
}

async function ensureRedisConfigLinux() {
  const confCandidates = ["/etc/redis/redis.conf", "/etc/redis/redis-server.conf"];
  let redisConfPath = confCandidates[0];

  for (const path of confCandidates) {
    const check = await run("bash", ["-lc", `[ -f ${shellQuote(path)} ]`]);
    if (check.code === 0) {
      redisConfPath = path;
      break;
    }
  }

  const conf = shellQuote(redisConfPath);
  await bashOrThrow(`sudo sed -i 's/^#\\?maxmemory .*/maxmemory 256mb/' ${conf}`);
  await bashOrThrow(`sudo grep -q '^maxmemory ' ${conf} || echo 'maxmemory 256mb' | sudo tee -a ${conf}`);
  await bashOrThrow(`sudo sed -i 's/^#\\?maxmemory-policy .*/maxmemory-policy allkeys-lru/' ${conf}`);
  await bashOrThrow(`sudo grep -q '^maxmemory-policy ' ${conf} || echo 'maxmemory-policy allkeys-lru' | sudo tee -a ${conf}`);
}

function normalizeMode(value?: string): AppMode {
  if (value && value !== "systemd" && value !== "docker") {
    throw new Error("Invalid mode. Use --mode systemd or --mode docker");
  }
  if (value === "docker") return "docker";
  return "systemd";
}

function normalizeConvexMode(value?: string): ConvexRuntimeMode {
  if (value && value !== "self-hosted" && value !== "cloud") {
    throw new Error("Invalid Convex mode. Use --convex-mode self-hosted or --convex-mode cloud");
  }
  if (value === "cloud") return "cloud";
  return "self-hosted";
}

function createConvexHttpClient(convexUrl: string, opts?: { auth?: string; skipConvexDeploymentUrlCheck?: boolean }): ConvexHttpClient {
  const options: Record<string, unknown> = {};
  if (opts?.auth) {
    options.auth = opts.auth;
  }
  if (opts?.skipConvexDeploymentUrlCheck) {
    options.skipConvexDeploymentUrlCheck = true;
  }
  return new ConvexHttpClient(convexUrl, options as ConstructorParameters<typeof ConvexHttpClient>[1]);
}

function resolveConvexRuntimeConfig(values: Record<string, string | undefined>) {
  return resolveConvexConfig(values);
}

function resolveConvexAdminFromEnv(baseDir = process.cwd()): {
  mode: "self-hosted" | "cloud";
  url: string;
  adminKey: string;
  skipConvexDeploymentUrlCheck: boolean;
} {
  const envPath = join(baseDir, ".env");
  const envFile = existsSync(envPath) ? parseDotEnv(readFileSync(envPath, "utf8")) : {};
  const merged = {
    ...envFile,
    ...Object.fromEntries(Object.entries(process.env).map(([key, value]) => [key, value ?? undefined]))
  };
  const resolved = resolveConvexRuntimeConfig(merged);

  if (!resolved.url) {
    throw new Error("Missing Convex URL. Set CONVEX_SELF_HOSTED_URL or CONVEX_URL.");
  }
  if (!resolved.adminKey) {
    throw new Error("Missing Convex admin key. Set CONVEX_SELF_HOSTED_ADMIN_KEY or CONVEX_ADMIN_KEY.");
  }
  if (resolved.mode === "none") {
    throw new Error("Convex mode is not configured.");
  }

  return {
    mode: resolved.mode,
    url: resolved.url,
    adminKey: resolved.adminKey,
    skipConvexDeploymentUrlCheck: resolved.skipConvexDeploymentUrlCheck
  };
}

async function installCommand(opts: InstallOptions) {
  const mode = normalizeMode(opts.mode);
  const convexMode = normalizeConvexMode(opts.convexMode);
  const repo = opts.repo ?? process.env.SUPERHUMAN_REPO ?? (await detectCurrentRepo()) ?? "https://github.com/your-org/superhuman.git";
  const branch = opts.branch ?? "main";
  const targetDir = opts.target ?? (process.platform === "linux" ? "/opt/superhuman" : process.cwd());
  const invokingUser = userInfo().username;
  const serviceUser = opts.serviceUser ?? process.env.SUPERHUMAN_SERVICE_USER ?? userInfo().username;

  console.log(
    `[install] mode=${mode} convexMode=${convexMode} repo=${repo} branch=${branch} target=${targetDir} serviceUser=${serviceUser}`
  );
  const distro = await detectLinuxDistro();

  if (process.platform === "linux") {
    if (mode === "systemd") {
      await ensureLinuxServiceUser(serviceUser);
    }
    if (!distro || !["ubuntu", "debian"].includes(distro)) {
      console.log("[install] warning: non Ubuntu/Debian distro detected; automatic dependency install may require manual fixes");
    } else {
      console.log(`[install] detected ${distro}; ensuring dependencies`);
      await bashOrThrow("sudo apt-get update");
      await bashOrThrow("sudo apt-get install -y curl ca-certificates git");

      const hasNode = await commandExists("node");
      let installedNodeMajor = 0;
      if (hasNode) {
        const version = await run("node", ["-v"]);
        installedNodeMajor = Number((version.stdout.trim().match(/^v(\d+)/) ?? [])[1] ?? "0");
      }
      const needsNodeInstall =
        !hasNode ||
        installedNodeMajor < NODE_MIN_MAJOR ||
        installedNodeMajor > NODE_MAX_MAJOR;
      if (needsNodeInstall) {
        const detected = hasNode && installedNodeMajor > 0
          ? `detected Node.js major ${installedNodeMajor}`
          : "node not detected";
        console.log(
          `[install] ${detected}; installing Node.js ${NODE_SETUP_MAJOR}.x (required range ${NODE_MIN_MAJOR}-${NODE_MAX_MAJOR})`
        );
        await bashOrThrow(`curl -fsSL https://deb.nodesource.com/setup_${NODE_SETUP_MAJOR}.x | sudo -E bash -`);
        await bashOrThrow("sudo apt-get install -y nodejs");
      }

      await bashOrThrow("corepack enable || true");
      await bashOrThrow(`corepack prepare pnpm@${PNPM_VERSION} --activate || sudo npm i -g pnpm@${PNPM_VERSION}`);

      if (!(await commandExists("redis-server"))) {
        await bashOrThrow("sudo apt-get install -y redis-server");
      }

      if (mode === "docker" || convexMode === "self-hosted") {
        if (!(await commandExists("docker"))) {
          await bashOrThrow("sudo apt-get install -y docker.io");
        }
        const composeReady = (await hasDockerComposePlugin()) || (await commandExists("docker-compose"));
        if (!composeReady) {
          await bashOrThrow(
            "sudo apt-get install -y docker-compose-plugin || sudo apt-get install -y docker-compose-v2 || sudo apt-get install -y docker-compose || true"
          );
        }
        const composeReadyAfterInstall = (await hasDockerComposePlugin()) || (await commandExists("docker-compose"));
        if (!composeReadyAfterInstall) {
          throw new Error(
            "Docker compose is required but unavailable. Install docker-compose-plugin or docker-compose and rerun setup."
          );
        }
      }

      await ensureRedisConfigLinux();
      await bashOrThrow("sudo systemctl enable redis-server");
      await bashOrThrow("sudo systemctl restart redis-server");
    }

    await bashOrThrow(`sudo mkdir -p ${shellQuote(targetDir)}`);
    await bashOrThrow(`sudo chown -R ${shellQuote(invokingUser)}:${shellQuote(invokingUser)} ${shellQuote(targetDir)}`);
  } else {
    await mkdir(targetDir, { recursive: true });
  }

  const gitDir = process.platform === "linux" ? `${targetDir}/.git` : join(targetDir, ".git");
  if (!existsSync(gitDir)) {
    if (process.platform === "linux") {
      await bashOrThrow(`git clone --depth 1 -b ${shellQuote(branch)} ${shellQuote(repo)} ${shellQuote(targetDir)}`);
    } else {
      await runOrThrow("git", ["clone", "--depth", "1", "-b", branch, repo, targetDir]);
    }
  } else {
    await runOrThrow("git", ["-C", targetDir, "fetch", "origin", branch, "--depth", "1"]);
    await runOrThrow("git", ["-C", targetDir, "checkout", branch]);
    await runOrThrow("git", ["-C", targetDir, "pull", "--ff-only", "origin", branch]);
  }

  if (process.platform === "linux") {
    await bashOrThrow(`chown -R ${shellQuote(invokingUser)}:${shellQuote(invokingUser)} ${shellQuote(targetDir)}`);
  }

  if (!(await commandExists("pnpm"))) {
    throw new Error("pnpm is required but not found in PATH");
  }

  await runOrThrow("pnpm", ["install", "--frozen-lockfile"], targetDir);
  await runOrThrow("node", ["scripts/apply-branding.mjs"], targetDir);
  await runOrThrow("pnpm", ["build"], targetDir);
  await runOrThrow("node", ["scripts/ensure-superhuman-bin.mjs"], targetDir);

  const envPath = join(targetDir, ".env");
  let envValues = await ensureConvexEnvDefaults(targetDir, convexMode === "self-hosted");
  if (existsSync(envPath)) {
    chmodSync(envPath, 0o600);
  }

  const openWebUiDir = join(targetDir, "vendor", "open-webui");
  if (existsSync(join(openWebUiDir, "package-lock.json"))) {
    await runOrThrow("npm", ["ci", "--no-audit", "--no-fund", "--legacy-peer-deps"], openWebUiDir);
  } else {
    await runOrThrow("npm", ["install", "--no-audit", "--no-fund", "--legacy-peer-deps"], openWebUiDir);
  }
  await buildOpenWebUI(openWebUiDir);

  if (convexMode === "self-hosted") {
    console.log("[install] launching self-hosted Convex");
    await runDockerComposeOrThrow(["-f", "deploy/docker/convex-compose.yml", "up", "-d"], targetDir);
    envValues = await ensureSelfHostedAdminKey(targetDir, envValues);
    await deployConvexSelfHosted(targetDir, envValues);
    const autoConvexUrl = envValues.CONVEX_SELF_HOSTED_URL ?? DEFAULT_SELF_HOSTED_CONVEX_URL;
    console.log(`[install] self-hosted Convex URL=${autoConvexUrl}`);
  } else {
    console.log("[install] using Convex Cloud mode");
  }

  if (mode === "systemd") {
    console.log("[install] generating hardened systemd unit files");
    await writeSystemdUnits(targetDir, serviceUser);
    if (!opts.deferServiceOwnership) {
      await ensureServiceOwnershipLinux(targetDir, serviceUser);
      await ensureEnvFileOwnershipLinux(targetDir, serviceUser);
    } else if (process.platform === "linux") {
      const deferredEnvPath = join(targetDir, ".env");
      if (existsSync(deferredEnvPath)) {
        await bashOrThrow(`sudo chmod 644 ${shellQuote(deferredEnvPath)}`);
      }
    }
    await bashOrThrow(`sudo install -m 0644 ${shellQuote(join(targetDir, "deploy", "systemd", "superhuman-web.service"))} /etc/systemd/system/superhuman-web.service`);
    await bashOrThrow(`sudo install -m 0644 ${shellQuote(join(targetDir, "deploy", "systemd", "superhuman-worker.service"))} /etc/systemd/system/superhuman-worker.service`);
    await bashOrThrow(`sudo install -m 0644 ${shellQuote(join(targetDir, "deploy", "systemd", "superhuman-frontend.service"))} /etc/systemd/system/superhuman-frontend.service`);
    await bashOrThrow("sudo systemctl daemon-reload");
    await bashOrThrow("sudo systemctl enable superhuman-web superhuman-worker superhuman-frontend");
    await bashOrThrow("sudo systemctl restart superhuman-web superhuman-worker superhuman-frontend");
  } else {
    console.log("[install] launching docker compose");
    await runDockerComposeOrThrow(["-f", "deploy/docker/docker-compose.yml", "up", "-d", "--build"], targetDir);
  }

  if (!opts.skipDoctor) {
    await doctorCommand({ json: false }, targetDir);
  }
  return targetDir;
}

async function validateKey(
  name: string,
  value: string,
  context?: Record<string, string>,
  opts?: { required?: boolean }
): Promise<{ ok: boolean; detail: string }> {
  if (!value.trim()) {
    if (opts?.required === false) {
      return { ok: true, detail: "not set" };
    }
    return { ok: false, detail: "missing" };
  }

  if (
    name === "CONVEX_SELF_HOSTED_URL" ||
    name === "CONVEX_URL" ||
    name === "APP_URL" ||
    name === "FRONTEND_URL" ||
    name === "CODEX_OAUTH_AUTH_URL" ||
    name === "CODEX_OAUTH_TOKEN_URL" ||
    name === "QWEN_OAUTH_AUTH_URL" ||
    name === "QWEN_OAUTH_TOKEN_URL"
  ) {
    try {
      new URL(value);
      return { ok: true, detail: "url format valid" };
    } catch {
      return { ok: false, detail: "invalid url" };
    }
  }

  if (name === "CONVEX_DEPLOYMENT") {
    return { ok: true, detail: "deprecated (ignored)" };
  }

  if (name === "REDIS_URL") {
    try {
      const url = new URL(value);
      if (url.protocol !== "redis:") {
        return { ok: false, detail: "must use redis:// scheme" };
      }
      return { ok: true, detail: "url format valid" };
    } catch {
      return { ok: false, detail: "invalid redis url" };
    }
  }

  if (name === "DEEPGRAM_API_KEY") {
    const res = await fetch("https://api.deepgram.com/v1/projects", {
      headers: { Authorization: `Token ${value}` }
    });
    return res.ok ? { ok: true, detail: `deepgram ok (${res.status})` } : { ok: false, detail: `deepgram status ${res.status}` };
  }

  if (name === "AGENTMAIL_API_KEY") {
    const res = await fetch("https://api.agentmail.to/v1/me", {
      headers: { Authorization: `Bearer ${value}` }
    });
    return res.ok ? { ok: true, detail: `agentmail ok (${res.status})` } : { ok: false, detail: `agentmail status ${res.status}` };
  }

  if (name === "FIREWORKS_API_KEY") {
    const res = await fetch("https://api.fireworks.ai/inference/v1/models", {
      headers: { Authorization: `Bearer ${value}` }
    });
    return res.ok ? { ok: true, detail: `fireworks ok (${res.status})` } : { ok: false, detail: `fireworks status ${res.status}` };
  }

  if (name === "DEEPSEEK_API_KEY") {
    const res = await fetch("https://api.deepseek.com/models", {
      headers: { Authorization: `Bearer ${value}` }
    });
    return res.ok ? { ok: true, detail: `deepseek ok (${res.status})` } : { ok: false, detail: `deepseek status ${res.status}` };
  }

  if (name === "OLLAMA_API_KEY") {
    const base = context?.OLLAMA_BASE_URL ?? process.env.OLLAMA_BASE_URL;
    if (!base) {
      return { ok: true, detail: "present (OLLAMA_BASE_URL not set; skipped live check)" };
    }
    const res = await fetch(`${base.replace(/\/$/, "")}/models`, {
      headers: { Authorization: `Bearer ${value}` }
    });
    return res.ok ? { ok: true, detail: `ollama ok (${res.status})` } : { ok: false, detail: `ollama status ${res.status}` };
  }

  if (name === "BASETEN_API_KEY") {
    const base = context?.BASETEN_BASE_URL ?? process.env.BASETEN_BASE_URL;
    if (!base) {
      return { ok: true, detail: "present (BASETEN_BASE_URL not set; skipped live check)" };
    }
    const res = await fetch(`${base.replace(/\/$/, "")}/models`, {
      headers: { Authorization: `Bearer ${value}` }
    });
    return res.ok ? { ok: true, detail: `baseten ok (${res.status})` } : { ok: false, detail: `baseten status ${res.status}` };
  }

  if (name === "TAVILY_API_KEY") {
    const res = await fetch("https://api.tavily.com/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        api_key: value,
        query: "latest web search test",
        search_depth: "basic",
        max_results: 1
      })
    });
    return res.ok ? { ok: true, detail: `tavily ok (${res.status})` } : { ok: false, detail: `tavily status ${res.status}` };
  }

  return { ok: true, detail: "present" };
}

async function requestOAuthStart(
  appUrl: string,
  provider: "codex" | "qwen"
): Promise<{ state: string; authorizationUrl: string; redirectUri: string; expiresInSeconds: number }> {
  const startUrl = `${appUrl.replace(/\/$/, "")}/api/oauth/start/${provider}`;
  const res = await fetch(startUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({})
  });

  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { detail?: string };
    throw new Error(body.detail ?? `OAuth start failed (${res.status})`);
  }

  const body = (await res.json()) as {
    state?: string;
    authorization_url?: string;
    redirect_uri?: string;
    expires_in_seconds?: number;
  };

  if (!body.state || !body.authorization_url || !body.redirect_uri) {
    throw new Error("OAuth start response missing required fields");
  }

  return {
    state: body.state,
    authorizationUrl: body.authorization_url,
    redirectUri: body.redirect_uri,
    expiresInSeconds: body.expires_in_seconds ?? 600
  };
}

async function pollOAuthStatus(appUrl: string, provider: "codex" | "qwen", state: string): Promise<boolean> {
  const statusUrl = `${appUrl.replace(/\/$/, "")}/api/oauth/status/${provider}?state=${encodeURIComponent(state)}`;
  const end = Date.now() + 120_000;

  while (Date.now() < end) {
    try {
      const res = await fetch(statusUrl);
      const body = (await res.json()) as { status?: string; authorized?: boolean };
      if (body.status === "authorized" || body.authorized === true) {
        return true;
      }
      if (body.status?.startsWith("error:")) {
        return false;
      }
    } catch {
      // ignore while polling
    }
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }

  return false;
}

async function submitManualOAuthCode(appUrl: string, provider: "codex" | "qwen", state: string, code: string): Promise<boolean> {
  try {
    const res = await fetch(`${appUrl.replace(/\/$/, "")}/api/oauth/manual/${provider}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state, code })
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function onboardCommand(baseDir = process.cwd(), preferSelfHosted = true, options: OnboardOptions = {}) {
  const existing = await ensureConvexEnvDefaults(baseDir, preferSelfHosted);
  const auto = Boolean(options.auto);
  const runOAuth = options.runOAuth ?? !auto;
  const domain = normalizeDomain(options.domain);
  const skipTls = Boolean(options.skipTls);
  const envPath = join(baseDir, ".env");

  let merged: Record<string, string> = { ...existing };

  if (auto) {
    const appUrl = domain
      ? buildIngressUrl(domain, skipTls)
      : (existing.APP_URL ?? `http://127.0.0.1:${WEB_PORT}`);
    const frontendUrl = domain
      ? buildIngressUrl(domain, skipTls)
      : (existing.FRONTEND_URL ?? `http://127.0.0.1:${FRONTEND_PORT}`);
    merged = {
      ...merged,
      APP_URL: appUrl,
      FRONTEND_URL: frontendUrl,
      REDIS_URL: existing.REDIS_URL ?? "redis://localhost:6379",
      CODEX_OAUTH_AUTH_URL: existing.CODEX_OAUTH_AUTH_URL ?? "https://auth.openai.com/oauth/authorize",
      CODEX_OAUTH_TOKEN_URL: existing.CODEX_OAUTH_TOKEN_URL ?? "https://auth.openai.com/oauth/token",
      CODEX_OAUTH_SCOPES: existing.CODEX_OAUTH_SCOPES ?? "openid profile email offline_access",
      QWEN_OAUTH_AUTH_URL: existing.QWEN_OAUTH_AUTH_URL ?? "https://auth.qwen.ai/oauth/authorize",
      QWEN_OAUTH_TOKEN_URL: existing.QWEN_OAUTH_TOKEN_URL ?? "https://auth.qwen.ai/oauth/token",
      QWEN_OAUTH_SCOPES: existing.QWEN_OAUTH_SCOPES ?? "openid profile email offline_access"
    };
    if ((merged.OAUTH_ENCRYPTION_KEY ?? "").length < 32 || isPlaceholderSecret(merged.OAUTH_ENCRYPTION_KEY)) {
      merged.OAUTH_ENCRYPTION_KEY = defaultOauthEncryptionKey();
    }
  } else {
    const response = await prompts([
      {
        type: "text",
        name: "APP_URL",
        message: "App URL (for OAuth callback)",
        initial: existing.APP_URL || "http://localhost:3000"
      },
      {
        type: "text",
        name: "FRONTEND_URL",
        message: "Frontend URL (what users open in browser)",
        initial: existing.FRONTEND_URL || "http://localhost:4173"
      },
      {
        type: "password",
        name: "AGENTMAIL_API_KEY",
        message: "Agentmail API key (optional)",
        initial: existing.AGENTMAIL_API_KEY || ""
      },
      {
        type: "password",
        name: "DEEPGRAM_API_KEY",
        message: "Deepgram API key (optional)",
        initial: existing.DEEPGRAM_API_KEY || ""
      },
      {
        type: "password",
        name: "FIREWORKS_API_KEY",
        message: "Fireworks API key (optional)",
        initial: existing.FIREWORKS_API_KEY || ""
      },
      {
        type: "password",
        name: "OLLAMA_API_KEY",
        message: "Ollama Cloud API key (optional)",
        initial: existing.OLLAMA_API_KEY || ""
      },
      {
        type: "password",
        name: "BASETEN_API_KEY",
        message: "Baseten API key (optional)",
        initial: existing.BASETEN_API_KEY || ""
      },
      {
        type: "password",
        name: "DEEPSEEK_API_KEY",
        message: "Deepseek API key (optional)",
        initial: existing.DEEPSEEK_API_KEY || ""
      },
      {
        type: "password",
        name: "TAVILY_API_KEY",
        message: "Tavily API key (optional, for web search/fetch tools)",
        initial: existing.TAVILY_API_KEY || ""
      },
      {
        type: "text",
        name: "CODEX_OAUTH_CLIENT_ID",
        message: "Codex OAuth client ID (optional)",
        initial: existing.CODEX_OAUTH_CLIENT_ID || ""
      },
      {
        type: "password",
        name: "CODEX_OAUTH_CLIENT_SECRET",
        message: "Codex OAuth client secret (optional)",
        initial: existing.CODEX_OAUTH_CLIENT_SECRET || ""
      },
      {
        type: "text",
        name: "CODEX_OAUTH_AUTH_URL",
        message: "Codex OAuth authorization URL",
        initial: existing.CODEX_OAUTH_AUTH_URL || "https://auth.openai.com/oauth/authorize"
      },
      {
        type: "text",
        name: "CODEX_OAUTH_TOKEN_URL",
        message: "Codex OAuth token URL",
        initial: existing.CODEX_OAUTH_TOKEN_URL || "https://auth.openai.com/oauth/token"
      },
      {
        type: "text",
        name: "CODEX_OAUTH_SCOPES",
        message: "Codex OAuth scopes",
        initial: existing.CODEX_OAUTH_SCOPES || "openid profile email offline_access"
      },
      {
        type: "text",
        name: "QWEN_OAUTH_CLIENT_ID",
        message: "Qwen OAuth client ID (optional)",
        initial: existing.QWEN_OAUTH_CLIENT_ID || ""
      },
      {
        type: "password",
        name: "QWEN_OAUTH_CLIENT_SECRET",
        message: "Qwen OAuth client secret (optional)",
        initial: existing.QWEN_OAUTH_CLIENT_SECRET || ""
      },
      {
        type: "text",
        name: "QWEN_OAUTH_AUTH_URL",
        message: "Qwen OAuth authorization URL",
        initial: existing.QWEN_OAUTH_AUTH_URL || "https://auth.qwen.ai/oauth/authorize"
      },
      {
        type: "text",
        name: "QWEN_OAUTH_TOKEN_URL",
        message: "Qwen OAuth token URL",
        initial: existing.QWEN_OAUTH_TOKEN_URL || "https://auth.qwen.ai/oauth/token"
      },
      {
        type: "text",
        name: "QWEN_OAUTH_SCOPES",
        message: "Qwen OAuth scopes",
        initial: existing.QWEN_OAUTH_SCOPES || "openid profile email offline_access"
      },
      {
        type: "text",
        name: "REDIS_URL",
        message: "Redis URL",
        initial: existing.REDIS_URL || "redis://localhost:6379"
      },
      {
        type: "password",
        name: "OAUTH_ENCRYPTION_KEY",
        message: "OAuth encryption key",
        initial: existing.OAUTH_ENCRYPTION_KEY || defaultOauthEncryptionKey()
      }
    ]);

    merged = {
      ...merged,
      ...Object.fromEntries(Object.entries(response).map(([k, v]) => [k, normalizeOnboardValue(v)]))
    };
  }

  if (options.envOverrides && Object.keys(options.envOverrides).length > 0) {
    merged = {
      ...merged,
      ...Object.fromEntries(
        Object.entries(options.envOverrides).map(([key, value]) => [key, normalizeOnboardValue(value)])
      )
    };
  }

  const convexRuntime = resolveConvexRuntimeConfig(merged);

  if (convexRuntime.mode === "self-hosted" && isPlaceholderSecret(merged.CONVEX_SELF_HOSTED_ADMIN_KEY)) {
    await writeFile(envPath, stringifyDotEnv(merged), "utf8");
    chmodSync(envPath, 0o600);
    const updated = await ensureSelfHostedAdminKey(baseDir, merged);
    Object.assign(merged, updated);
  }

  const requiredPairs = [
    "APP_URL",
    "FRONTEND_URL",
    "CODEX_OAUTH_AUTH_URL",
    "CODEX_OAUTH_TOKEN_URL",
    "QWEN_OAUTH_AUTH_URL",
    "QWEN_OAUTH_TOKEN_URL",
    "REDIS_URL"
  ];

  if (convexRuntime.mode === "self-hosted") {
    requiredPairs.push("CONVEX_SELF_HOSTED_URL");
  }
  if (convexRuntime.mode === "cloud") {
    requiredPairs.push("CONVEX_URL");
  }

  for (const key of requiredPairs) {
    const result = await validateKey(key, merged[key] ?? "", merged);
    if (!result.ok) {
      throw new Error(`Validation failed for ${key}: ${result.detail}`);
    }
    console.log(`[onboard] ${key}: ${result.detail}`);
  }

  for (const key of OPTIONAL_PROVIDER_KEYS) {
    const value = (merged[key] ?? "").trim();
    if (!value) {
      console.log(`[onboard] ${key}: not set (optional)`);
      continue;
    }
    const result = await validateKey(key, value, merged, { required: false });
    if (!result.ok) {
      throw new Error(`Validation failed for ${key}: ${result.detail}`);
    }
    console.log(`[onboard] ${key}: ${result.detail}`);
  }

  if (!merged.APP_URL.includes("localhost") && !merged.APP_URL.startsWith("https://")) {
    throw new Error("Validation failed for APP_URL: production APP_URL must use https://");
  }

  if (convexRuntime.mode !== "none") {
    const convexAdminKey = (merged.CONVEX_SELF_HOSTED_ADMIN_KEY ?? merged.CONVEX_ADMIN_KEY ?? "").trim();
    if (!convexAdminKey) {
      throw new Error("Validation failed for Convex admin key: set CONVEX_SELF_HOSTED_ADMIN_KEY or CONVEX_ADMIN_KEY");
    }
  }

  if (merged.TAVILY_API_KEY) {
    const tavilyResult = await validateKey("TAVILY_API_KEY", merged.TAVILY_API_KEY, merged, { required: false });
    if (!tavilyResult.ok) {
      throw new Error(`Validation failed for TAVILY_API_KEY: ${tavilyResult.detail}`);
    }
    console.log(`[onboard] TAVILY_API_KEY: ${tavilyResult.detail}`);
  } else {
    console.log("[onboard] TAVILY_API_KEY: not set (web search tool disabled)");
  }

  if ((merged.OAUTH_ENCRYPTION_KEY ?? "").length < 32) {
    throw new Error("Validation failed for OAUTH_ENCRYPTION_KEY: must be at least 32 characters");
  }

  await writeFile(envPath, stringifyDotEnv(merged), "utf8");
  chmodSync(envPath, 0o600);
  console.log("[onboard] .env updated with secure permissions (600)");

  if (!runOAuth) {
    return;
  }

  for (const provider of ["codex", "qwen"] as const) {
    const clientIdKey = provider === "codex" ? "CODEX_OAUTH_CLIENT_ID" : "QWEN_OAUTH_CLIENT_ID";
    if (!merged[clientIdKey]) {
      console.log(`[onboard] ${provider.toUpperCase()} OAuth skipped: ${clientIdKey} is not configured`);
      continue;
    }

    const { runOauth } = await prompts({
      type: "confirm",
      name: "runOauth",
      message: `Configure OAuth for ${provider}?`,
      initial: true
    });

    if (!runOauth) continue;

    let start: { state: string; authorizationUrl: string; redirectUri: string; expiresInSeconds: number };
    try {
      start = await requestOAuthStart(merged.APP_URL, provider);
    } catch (error) {
      console.log(`[onboard] Failed to start ${provider.toUpperCase()} OAuth: ${(error as Error).message}`);
      continue;
    }
    console.log(`\n[onboard] ${provider.toUpperCase()} OAuth URL:`);
    console.log(start.authorizationUrl);
    console.log(`[onboard] Open the URL in your browser. Redirect URI is ${start.redirectUri}`);
    console.log(`[onboard] OAuth state expires in ~${start.expiresInSeconds}s`);

    const ok = await pollOAuthStatus(merged.APP_URL, provider, start.state);
    if (ok) {
      console.log(`[onboard] OAuth success for ${provider}`);
      continue;
    }

    console.log(`[onboard] OAuth callback not detected for ${provider}. Manual fallback enabled.`);
    const { manualCode } = await prompts({
      type: "password",
      name: "manualCode",
      message: `Paste authorization code for ${provider}`
    });

    const code = String(manualCode ?? "").trim();
    if (code) {
      const accepted = await submitManualOAuthCode(merged.APP_URL, provider, start.state, code);
      if (accepted) {
        console.log(`[onboard] Manual OAuth code accepted for ${provider}`);
        const manualOk = await pollOAuthStatus(merged.APP_URL, provider, start.state);
        console.log(`[onboard] ${provider.toUpperCase()} authorization ${manualOk ? "confirmed" : "not confirmed"}`);
      } else {
        console.log(`[onboard] Manual OAuth fallback failed for ${provider}. Check backend reachability and callback route.`);
      }
    }
  }
}

async function configureProvidersCommand(baseDir = process.cwd()) {
  const envPath = join(baseDir, ".env");
  const existing = existsSync(envPath) ? parseDotEnv(readFileSync(envPath, "utf8")) : {};
  const response = await prompts([
    {
      type: "password",
      name: "AGENTMAIL_API_KEY",
      message: "Agentmail API key (optional)",
      initial: existing.AGENTMAIL_API_KEY || ""
    },
    {
      type: "password",
      name: "DEEPGRAM_API_KEY",
      message: "Deepgram API key (optional)",
      initial: existing.DEEPGRAM_API_KEY || ""
    },
    {
      type: "password",
      name: "FIREWORKS_API_KEY",
      message: "Fireworks API key (optional)",
      initial: existing.FIREWORKS_API_KEY || ""
    },
    {
      type: "password",
      name: "OLLAMA_API_KEY",
      message: "Ollama Cloud API key (optional)",
      initial: existing.OLLAMA_API_KEY || ""
    },
    {
      type: "password",
      name: "BASETEN_API_KEY",
      message: "Baseten API key (optional)",
      initial: existing.BASETEN_API_KEY || ""
    },
    {
      type: "password",
      name: "DEEPSEEK_API_KEY",
      message: "Deepseek API key (optional)",
      initial: existing.DEEPSEEK_API_KEY || ""
    },
    {
      type: "password",
      name: "TAVILY_API_KEY",
      message: "Tavily API key (optional)",
      initial: existing.TAVILY_API_KEY || ""
    }
  ]);

  const merged = {
    ...existing,
    ...Object.fromEntries(Object.entries(response).map(([key, value]) => [key, normalizeOnboardValue(value)]))
  };

  for (const key of [...OPTIONAL_PROVIDER_KEYS, "TAVILY_API_KEY"]) {
    const value = (merged[key] ?? "").trim();
    if (!value) {
      console.log(`[configure] ${key}: not set (optional)`);
      continue;
    }
    const result = await validateKey(key, value, merged, { required: false });
    if (!result.ok) {
      throw new Error(`Validation failed for ${key}: ${result.detail}`);
    }
    console.log(`[configure] ${key}: ${result.detail}`);
  }

  await writeFile(envPath, stringifyDotEnv(merged), "utf8");
  chmodSync(envPath, 0o600);
  console.log("[configure] provider settings written to .env");
}

async function doctorCommand(opts: { json?: boolean }, baseDir = process.cwd()) {
  const result = {
    ok: true,
    checks: {} as Record<string, { ok: boolean; detail: string }>
  };

  const envPath = join(baseDir, ".env");
  const envFile = existsSync(envPath) ? parseDotEnv(readFileSync(envPath, "utf8")) : {};
  const mergedEnv = {
    ...Object.fromEntries(Object.entries(process.env).map(([key, value]) => [key, value ?? undefined])),
    ...envFile
  };
  const appUrl = envFile.APP_URL ?? process.env.APP_URL ?? `http://127.0.0.1:${WEB_PORT}`;
  const frontendUrl = envFile.FRONTEND_URL ?? process.env.FRONTEND_URL ?? `http://127.0.0.1:${FRONTEND_PORT}`;
  const redisUrl = envFile.REDIS_URL ?? process.env.REDIS_URL ?? "redis://localhost:6379";
  const convexRuntime = resolveConvexRuntimeConfig(mergedEnv);
  const convexUrl = convexRuntime.url;
  const convexAdminKey = convexRuntime.adminKey;
  const tavilyApiKey = envFile.TAVILY_API_KEY ?? process.env.TAVILY_API_KEY;
  const codexOauthConfigured = Boolean(envFile.CODEX_OAUTH_CLIENT_ID ?? process.env.CODEX_OAUTH_CLIENT_ID);
  const qwenOauthConfigured = Boolean(envFile.QWEN_OAUTH_CLIENT_ID ?? process.env.QWEN_OAUTH_CLIENT_ID);
  result.checks.convex_mode = { ok: convexRuntime.mode !== "none", detail: convexRuntime.mode };

  try {
    const res = await fetch(`${appUrl.replace(/\/$/, "")}/api/health`);
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean };
    result.checks.web = { ok: res.ok && body.ok === true, detail: `status=${res.status}` };
  } catch (error) {
    result.checks.web = { ok: false, detail: (error as Error).message };
  }

  try {
    const res = await fetch(`${appUrl.replace(/\/$/, "")}/api/v1/models`);
    result.checks.models_api = { ok: res.ok, detail: `status=${res.status}` };
  } catch (error) {
    result.checks.models_api = { ok: false, detail: (error as Error).message };
  }

  try {
    const res = await fetch(frontendUrl);
    result.checks.frontend = { ok: res.ok, detail: `status=${res.status}` };
  } catch (error) {
    result.checks.frontend = { ok: false, detail: (error as Error).message };
  }

  try {
    const url = new URL(redisUrl);
    result.checks.redis = { ok: Boolean(url.hostname), detail: "url parse ok" };
  } catch (error) {
    result.checks.redis = { ok: false, detail: (error as Error).message };
  }

  if (convexUrl) {
    try {
      new URL(convexUrl);
      if (convexAdminKey) {
        result.checks.convex_admin = { ok: true, detail: "configured" };
        const client = createConvexHttpClient(convexUrl, {
          skipConvexDeploymentUrlCheck: convexRuntime.skipConvexDeploymentUrlCheck
        });
        (client as unknown as { setAdminAuth: (token: string) => void }).setAdminAuth(convexAdminKey);
        await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
          "allowlist:list",
          {}
        );

        const providerStatuses = (await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
          "oauth:listProviderStatus",
          { subject: "system" }
        )) as Array<{ provider: string; authorized: boolean; updatedAt: number; accountEmail?: string | null }>;

        const statusMap = new Map(providerStatuses.map((row) => [row.provider, row]));
        const codexStatus = statusMap.get("codex");
        const qwenStatus = statusMap.get("qwen");

        result.checks.oauth_codex = codexOauthConfigured
          ? {
              ok: Boolean(codexStatus?.authorized),
              detail: codexStatus?.authorized
                ? `authorized (updatedAt=${new Date(codexStatus.updatedAt).toISOString()})`
                : "not authorized"
            }
          : { ok: true, detail: "not configured" };

        result.checks.oauth_qwen = qwenOauthConfigured
          ? {
              ok: Boolean(qwenStatus?.authorized),
              detail: qwenStatus?.authorized
                ? `authorized (updatedAt=${new Date(qwenStatus.updatedAt).toISOString()})`
                : "not authorized"
            }
          : { ok: true, detail: "not configured" };
      } else {
        result.checks.convex_admin = {
          ok: false,
          detail: "missing CONVEX_SELF_HOSTED_ADMIN_KEY or CONVEX_ADMIN_KEY"
        };
        if (codexOauthConfigured) {
          result.checks.oauth_codex = {
            ok: false,
            detail: "missing CONVEX_SELF_HOSTED_ADMIN_KEY or CONVEX_ADMIN_KEY"
          };
        }
        if (qwenOauthConfigured) {
          result.checks.oauth_qwen = {
            ok: false,
            detail: "missing CONVEX_SELF_HOSTED_ADMIN_KEY or CONVEX_ADMIN_KEY"
          };
        }
      }
      result.checks.convex = { ok: true, detail: "reachable/configured" };
    } catch (error) {
      result.checks.convex = { ok: false, detail: (error as Error).message };
      result.checks.convex_admin = { ok: false, detail: "convex check failed" };
      if (codexOauthConfigured) {
        result.checks.oauth_codex = { ok: false, detail: "convex check failed" };
      }
      if (qwenOauthConfigured) {
        result.checks.oauth_qwen = { ok: false, detail: "convex check failed" };
      }
    }
  } else {
    result.checks.convex = { ok: false, detail: "missing CONVEX_SELF_HOSTED_URL or CONVEX_URL" };
    result.checks.convex_admin = { ok: false, detail: "missing CONVEX_SELF_HOSTED_URL or CONVEX_URL" };
    if (codexOauthConfigured) {
      result.checks.oauth_codex = { ok: false, detail: "missing CONVEX_SELF_HOSTED_URL or CONVEX_URL" };
    }
    if (qwenOauthConfigured) {
      result.checks.oauth_qwen = { ok: false, detail: "missing CONVEX_SELF_HOSTED_URL or CONVEX_URL" };
    }
  }

  if (process.platform === "linux") {
    const redisPing = await run("bash", ["-lc", `redis-cli -u ${shellQuote(redisUrl)} PING`]);
    result.checks.redis_ping = {
      ok: redisPing.code === 0 && redisPing.stdout.toUpperCase().includes("PONG"),
      detail: redisPing.code === 0 ? redisPing.stdout.trim() : redisPing.stderr.trim() || "redis-cli failed"
    };

    const redisMem = await run("bash", ["-lc", "redis-cli CONFIG GET maxmemory maxmemory-policy" ]);
    const ok = redisMem.code === 0 && redisMem.stdout.includes("allkeys-lru") && redisMem.stdout.includes("268435456");
    result.checks.redis_policy = { ok, detail: ok ? "maxmemory and policy enforced" : "policy mismatch" };

    const heartbeat = await run("bash", ["-lc", "redis-cli GET superhuman:worker:heartbeat"]);
    const workerOk = heartbeat.code === 0 && heartbeat.stdout.trim().length > 0 && !heartbeat.stdout.includes("(nil)");
    result.checks.worker = { ok: workerOk, detail: workerOk ? "heartbeat present" : "no heartbeat key" };

    const hasSystemctl = await commandExists("systemctl");
    const hasSuperhumanUnits = (await run("bash", ["-lc", "test -f /etc/systemd/system/superhuman-web.service"])).code === 0;
    if (hasSystemctl && hasSuperhumanUnits) {
      const systemd = await run("bash", ["-lc", "systemctl is-active superhuman-web superhuman-worker superhuman-frontend"]);
      const activeLines = systemd.stdout
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      const allActive = activeLines.length >= 3 && activeLines.every((line) => line === "active");
      result.checks.systemd = { ok: allActive, detail: allActive ? "all services active" : activeLines.join(", ") || "services inactive" };
    } else {
      result.checks.systemd = { ok: true, detail: "skipped (systemd units not detected)" };
    }
  }

  if (tavilyApiKey) {
    try {
      const res = await fetch("https://api.tavily.com/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          api_key: tavilyApiKey,
          query: "superhuman doctor",
          search_depth: "basic",
          max_results: 1
        })
      });
      result.checks.tavily = { ok: res.ok, detail: `status=${res.status}` };
    } catch (error) {
      result.checks.tavily = { ok: false, detail: (error as Error).message };
    }
  } else {
    result.checks.tavily = { ok: true, detail: "not configured (optional)" };
  }

  result.checks.app_url = { ok: true, detail: appUrl };
  result.checks.frontend_url = { ok: true, detail: frontendUrl };

  result.ok = Object.values(result.checks).every((check) => check.ok);

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    for (const [name, check] of Object.entries(result.checks)) {
      console.log(`[doctor] ${name}: ${check.ok ? "ok" : "fail"} (${check.detail})`);
    }
    console.log(`[doctor] overall=${result.ok ? "ok" : "fail"}`);
  }

  if (!result.ok) {
    process.exitCode = 1;
  }
}

async function allowlistCommand(action: "allow" | "remove" | "list", email?: string, baseDir = process.cwd()) {
  const convex = resolveConvexAdminFromEnv(baseDir);
  const client = createConvexHttpClient(convex.url, {
    skipConvexDeploymentUrlCheck: convex.skipConvexDeploymentUrlCheck
  });
  (client as unknown as { setAdminAuth: (token: string) => void }).setAdminAuth(convex.adminKey);

  if (action === "allow") {
    if (!email) {
      throw new Error("Missing email");
    }
    const res = await (client as unknown as { mutation: (name: string, args: unknown) => Promise<unknown> }).mutation(
      "allowlist:allow",
      { email, addedBy: "superhuman-cli" }
    );
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  if (action === "remove") {
    if (!email) {
      throw new Error("Missing email");
    }
    const res = await (client as unknown as { mutation: (name: string, args: unknown) => Promise<unknown> }).mutation(
      "allowlist:remove",
      { email }
    );
    if ((res as { status?: string }).status === "removed") {
      await (client as unknown as { mutation: (name: string, args: unknown) => Promise<unknown> }).mutation(
        "users:deactivateByEmail",
        { email }
      );
    }
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  const res = await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
    "allowlist:list",
    {}
  );
  console.log(JSON.stringify(res, null, 2));
}

async function oauthStatusCommand(provider?: "codex" | "qwen", baseDir = process.cwd()) {
  const convex = resolveConvexAdminFromEnv(baseDir);
  const client = createConvexHttpClient(convex.url, {
    skipConvexDeploymentUrlCheck: convex.skipConvexDeploymentUrlCheck
  });
  (client as unknown as { setAdminAuth: (token: string) => void }).setAdminAuth(convex.adminKey);

  if (provider) {
    const row = await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
      "oauth:providerStatus",
      { provider, subject: "system" }
    );
    console.log(JSON.stringify(row, null, 2));
    return;
  }

  const rows = await (client as unknown as { query: (name: string, args: unknown) => Promise<unknown> }).query(
    "oauth:listProviderStatus",
    { subject: "system" }
  );
  console.log(JSON.stringify(rows, null, 2));
}

async function setupCommand(opts: SetupOptions) {
  const preferSelfHosted = normalizeConvexMode(opts.convexMode) === "self-hosted";
  const mode = normalizeMode(opts.mode);
  const auto = Boolean(opts.auto || opts.nonInteractive);
  const skipTls = Boolean(opts.skipTls);
  const sshOnly = Boolean(opts.sshOnly);
  const serviceUser = opts.serviceUser ?? process.env.SUPERHUMAN_SERVICE_USER ?? userInfo().username;
  const envOverrides = await loadEnvOverrides(opts.envFile);

  let domain = normalizeDomain(opts.domain ?? envOverrides.SUPERHUMAN_DOMAIN);
  if (!domain) {
    const overriddenAppUrl = (envOverrides.APP_URL ?? "").trim();
    if (overriddenAppUrl) {
      try {
        domain = normalizeDomain(overriddenAppUrl);
      } catch {
        // ignore; URL-specific validation happens later
      }
    }
  }

  if (auto && !sshOnly && !domain) {
    throw new Error("Automatic setup without --ssh-only requires --domain (or SUPERHUMAN_DOMAIN in --env-file).");
  }
  if (auto && !sshOnly && !skipTls && !(opts.email ?? "").trim()) {
    throw new Error("Automatic TLS setup requires --email for Let's Encrypt.");
  }

  const targetDir = await installCommand({
    ...opts,
    skipDoctor: true,
    deferServiceOwnership: true
  });

  await onboardCommand(targetDir, preferSelfHosted, {
    auto,
    domain,
    skipTls,
    envOverrides,
    runOAuth: !auto
  });

  if (process.platform === "linux" && mode === "systemd") {
    await ensureServiceOwnershipLinux(targetDir, serviceUser);
    await ensureEnvFileOwnershipLinux(targetDir, serviceUser);
    await bashOrThrow("sudo systemctl restart superhuman-web superhuman-worker superhuman-frontend");
  }

  if (auto && process.platform === "linux" && mode === "systemd" && !sshOnly && domain) {
    const email = (opts.email ?? "").trim();
    console.log(`[setup] configuring ingress for ${domain} (${skipTls ? "http" : "https"})`);
    await configureIngressLinux(targetDir, { domain, email, skipTls });
  } else if (auto && !sshOnly && !domain) {
    console.log("[setup] ingress skipped: no domain configured");
  }

  await doctorCommand({ json: false }, targetDir);

  const envPath = join(targetDir, ".env");
  const envFile = existsSync(envPath) ? parseDotEnv(readFileSync(envPath, "utf8")) : {};
  const appUrl = envFile.FRONTEND_URL ?? process.env.FRONTEND_URL ?? `http://127.0.0.1:${FRONTEND_PORT}`;
  console.log(`[setup] final app url: ${appUrl}`);
}

const program = new Command();
program.name("superhuman").description("Superhuman CLI").version("0.1.0");

program
  .command("install")
  .option("--mode <mode>", "systemd|docker")
  .option("--convex-mode <convexMode>", "self-hosted|cloud", "self-hosted")
  .option("--repo <url>", "repository url")
  .option("--branch <branch>", "repository branch", "main")
  .option("--target <path>", "install target directory")
  .option("--service-user <user>", "linux user for systemd services")
  .action(async (opts) => {
    await installCommand(opts as InstallOptions);
  });

program
  .command("onboard")
  .option("--target <path>", "target directory containing .env")
  .option("--auto", "non-interactive with defaults", false)
  .option("--domain <domain>", "public domain used for APP_URL/FRONTEND_URL in auto mode")
  .option("--skip-tls", "use http URLs in auto mode", false)
  .option("--env-file <path>", "optional env file with overrides")
  .action(async (opts) => {
    const envOverrides = await loadEnvOverrides(opts.envFile as string | undefined);
    await onboardCommand(opts.target ?? process.cwd(), true, {
      auto: Boolean(opts.auto),
      domain: opts.domain as string | undefined,
      skipTls: Boolean(opts.skipTls),
      envOverrides,
      runOAuth: !Boolean(opts.auto)
    });
  });

program
  .command("setup")
  .option("--mode <mode>", "systemd|docker")
  .option("--convex-mode <convexMode>", "self-hosted|cloud", "self-hosted")
  .option("--repo <url>", "repository url")
  .option("--branch <branch>", "repository branch", "main")
  .option("--target <path>", "install target directory")
  .option("--service-user <user>", "linux user for systemd services")
  .option("--auto", "non-interactive setup with defaults", false)
  .option("--non-interactive", "alias for --auto", false)
  .option("--domain <domain>", "public domain used for URLs and ingress")
  .option("--email <email>", "email used for Let's Encrypt when TLS is enabled")
  .option("--ssh-only", "skip public ingress/firewall setup", false)
  .option("--skip-tls", "configure ingress without TLS (http only)", false)
  .option("--env-file <path>", "optional env file with setup overrides")
  .action(async (opts) => {
    await setupCommand(opts as SetupOptions);
  });

program.command("doctor").option("--json", "json output", false).option("--target <path>", "target directory containing .env").action(async (opts) => {
  await doctorCommand({ json: Boolean(opts.json) }, opts.target ?? process.cwd());
});

const configureCommand = program.command("configure").description("Configuration helpers");

configureCommand
  .command("providers")
  .description("Configure optional provider API keys")
  .option("--target <path>", "target directory containing .env")
  .action(async (opts) => {
    await configureProvidersCommand(opts.target ?? process.cwd());
  });

program.command("allow [value]").option("--target <path>", "target directory containing .env").action(async (value: string | undefined, opts) => {
  if (!value || value === "list") {
    await allowlistCommand("list", undefined, opts.target ?? process.cwd());
    return;
  }
  await allowlistCommand("allow", value, opts.target ?? process.cwd());
});

program.command("remove <email>").option("--target <path>", "target directory containing .env").action(async (email: string, opts) => {
  await allowlistCommand("remove", email, opts.target ?? process.cwd());
});

program
  .command("oauth [provider]")
  .description("Show OAuth authorization status from Convex encrypted token store")
  .option("--target <path>", "target directory containing .env")
  .action(async (provider: string | undefined, opts) => {
    if (provider && provider !== "codex" && provider !== "qwen") {
      throw new Error("provider must be one of: codex, qwen");
    }
    await oauthStatusCommand(provider as "codex" | "qwen" | undefined, opts.target ?? process.cwd());
  });

program.parseAsync(process.argv).catch((error) => {
  console.error(error);
  process.exit(1);
});
