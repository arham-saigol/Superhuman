import { z } from "zod";

const optionalUrl = z.preprocess(
  (value) => (typeof value === "string" && value.trim() === "" ? undefined : value),
  z.string().url().optional()
);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  APP_URL: z.string().url().default("http://localhost:3000"),
  REDIS_URL: z.string().default("redis://localhost:6379"),
  CONVEX_SELF_HOSTED_URL: optionalUrl,
  CONVEX_SELF_HOSTED_ADMIN_KEY: z.string().optional(),
  CONVEX_URL: optionalUrl,
  CONVEX_DEPLOYMENT: z.string().min(1).optional(),
  CONVEX_ADMIN_KEY: z.string().optional(),
  AGENTMAIL_API_KEY: z.string().optional(),
  DEEPGRAM_API_KEY: z.string().optional(),
  FIREWORKS_API_KEY: z.string().optional(),
  FIREWORKS_BASE_URL: optionalUrl,
  OLLAMA_API_KEY: z.string().optional(),
  OLLAMA_BASE_URL: optionalUrl,
  BASETEN_API_KEY: z.string().optional(),
  BASETEN_BASE_URL: optionalUrl,
  DEEPSEEK_API_KEY: z.string().optional(),
  TAVILY_API_KEY: z.string().optional(),
  CODEX_ACCESS_TOKEN: z.string().optional(),
  CODEX_OAUTH_CLIENT_ID: z.string().optional(),
  CODEX_OAUTH_CLIENT_SECRET: z.string().optional(),
  CODEX_OAUTH_AUTH_URL: z.string().url().default("https://auth.openai.com/oauth/authorize"),
  CODEX_OAUTH_TOKEN_URL: z.string().url().default("https://auth.openai.com/oauth/token"),
  CODEX_OAUTH_SCOPES: z.string().default("openid profile email offline_access"),
  QWEN_API_KEY: z.string().optional(),
  QWEN_OAUTH_CLIENT_ID: z.string().optional(),
  QWEN_OAUTH_CLIENT_SECRET: z.string().optional(),
  QWEN_OAUTH_AUTH_URL: z.string().url().default("https://auth.qwen.ai/oauth/authorize"),
  QWEN_OAUTH_TOKEN_URL: z.string().url().default("https://auth.qwen.ai/oauth/token"),
  QWEN_OAUTH_SCOPES: z.string().default("openid profile email offline_access"),
  QWEN_BASE_URL: optionalUrl,
  OAUTH_ENCRYPTION_KEY: z.string().min(32).default("replace-with-a-real-32-byte-secret-value")
});

export type AppEnv = z.infer<typeof envSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): AppEnv {
  return envSchema.parse(source);
}

export type ConvexMode = "self-hosted" | "cloud" | "none";

export type ResolvedConvexConfig = {
  mode: ConvexMode;
  url: string | null;
  adminKey: string | null;
  skipConvexDeploymentUrlCheck: boolean;
};

function isConvexCloudHostname(hostname: string): boolean {
  return hostname === "convex.cloud" || hostname.endsWith(".convex.cloud");
}

export function shouldSkipConvexDeploymentUrlCheck(url: string): boolean {
  try {
    const parsed = new URL(url);
    return !isConvexCloudHostname(parsed.hostname);
  } catch {
    return false;
  }
}

export function resolveConvexConfig(
  source: Record<string, string | undefined> | Partial<AppEnv> = process.env
): ResolvedConvexConfig {
  const selfHostedUrl = source.CONVEX_SELF_HOSTED_URL?.trim();
  const selfHostedAdminKey = source.CONVEX_SELF_HOSTED_ADMIN_KEY?.trim();
  const cloudUrl = source.CONVEX_URL?.trim();
  const cloudAdminKey = source.CONVEX_ADMIN_KEY?.trim();

  if (selfHostedUrl) {
    return {
      mode: "self-hosted",
      url: selfHostedUrl,
      adminKey: selfHostedAdminKey || null,
      skipConvexDeploymentUrlCheck: true
    };
  }

  if (cloudUrl) {
    const skipCheck = shouldSkipConvexDeploymentUrlCheck(cloudUrl);
    return {
      mode: skipCheck ? "self-hosted" : "cloud",
      url: cloudUrl,
      adminKey: cloudAdminKey || null,
      skipConvexDeploymentUrlCheck: skipCheck
    };
  }

  return {
    mode: "none",
    url: null,
    adminKey: null,
    skipConvexDeploymentUrlCheck: false
  };
}
