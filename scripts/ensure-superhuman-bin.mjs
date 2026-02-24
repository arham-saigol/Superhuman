import { accessSync, constants, chmodSync, existsSync, mkdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const root = process.cwd();
const cliEntry = join(root, "apps", "cli", "dist", "index.js");

if (!existsSync(cliEntry)) {
  throw new Error(`CLI dist entry not found: ${cliEntry}`);
}

try {
  chmodSync(cliEntry, 0o755);
} catch {
  // best effort
}

const pathEntries = (process.env.PATH ?? "").split(process.platform === "win32" ? ";" : ":").filter(Boolean);

const candidates = [];
if (process.env.PNPM_HOME) candidates.push(process.env.PNPM_HOME);
if (process.platform !== "win32") {
  candidates.push("/usr/local/bin");
  candidates.push(join(homedir(), ".local", "bin"));
}

function isWritableDir(dir) {
  try {
    mkdirSync(dir, { recursive: true });
    accessSync(dir, constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

if (process.platform === "win32") {
  const binDir = join(root, ".bin");
  mkdirSync(binDir, { recursive: true });
  const cmdPath = join(binDir, "superhuman.cmd");
  writeFileSync(cmdPath, `@echo off\r\nnode "${cliEntry.replace(/\\/g, "\\\\")}" %*\r\n`, "utf8");
  console.log(`[build] superhuman shim created at ${cmdPath}`);
  process.exit(0);
}

const targetDir = candidates.find(isWritableDir);
if (!targetDir) {
  throw new Error("Unable to find writable directory for superhuman binary (tried PNPM_HOME, /usr/local/bin, ~/.local/bin)");
}

const linkPath = join(targetDir, "superhuman");
try {
  if (existsSync(linkPath)) {
    unlinkSync(linkPath);
  }
} catch {
  // ignore
}

symlinkSync(cliEntry, linkPath);
console.log(`[build] superhuman linked at ${linkPath} -> ${cliEntry}`);

if (!pathEntries.includes(targetDir)) {
  console.log(`[build] warning: ${targetDir} is not currently in PATH`);
}
