export const DEFAULT_SELF_HOSTED_CONVEX_URL = "http://127.0.0.1:3210";

export function isPlaceholderSecret(value: string | undefined): boolean {
  const normalized = String(value ?? "").trim().toLowerCase();
  return !normalized || normalized.startsWith("replace-with-");
}

export function extractAdminKeyFromOutput(output: string): string | null {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    const match = line.match(/^admin key:\s*(.+)$/i);
    if (match?.[1]) {
      return match[1].trim();
    }
  }
  return null;
}

export function applyConvexEnvDefaults(
  values: Record<string, string>,
  preferSelfHosted: boolean
): { values: Record<string, string>; changed: boolean } {
  const next = { ...values };
  let changed = false;

  if (!preferSelfHosted) {
    return { values: next, changed };
  }

  const cloudUrl = (next.CONVEX_URL ?? "").trim();
  const selfHostedUrl = (next.CONVEX_SELF_HOSTED_URL ?? "").trim();
  const selfHostedAdmin = (next.CONVEX_SELF_HOSTED_ADMIN_KEY ?? "").trim();

  if (!selfHostedUrl) {
    if (cloudUrl && !cloudUrl.includes(".convex.cloud")) {
      next.CONVEX_SELF_HOSTED_URL = cloudUrl;
    } else {
      next.CONVEX_SELF_HOSTED_URL = DEFAULT_SELF_HOSTED_CONVEX_URL;
    }
    changed = true;
  }

  if (!("CONVEX_SELF_HOSTED_ADMIN_KEY" in next) || isPlaceholderSecret(selfHostedAdmin)) {
    next.CONVEX_SELF_HOSTED_ADMIN_KEY = "";
    changed = true;
  }

  return { values: next, changed };
}
