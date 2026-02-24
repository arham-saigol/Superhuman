import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  APP_URL: z.string().url().default("http://localhost:3000"),
  REDIS_URL: z.string().default("redis://localhost:6379"),
  CONVEX_URL: z.string().url().optional(),
  CONVEX_DEPLOYMENT: z.string().min(1).optional(),
  CONVEX_ADMIN_KEY: z.string().optional(),
  AGENTMAIL_API_KEY: z.string().optional(),
  DEEPGRAM_API_KEY: z.string().optional(),
  FIREWORKS_API_KEY: z.string().optional(),
  FIREWORKS_BASE_URL: z.string().url().optional(),
  OLLAMA_API_KEY: z.string().optional(),
  OLLAMA_BASE_URL: z.string().url().optional(),
  BASETEN_API_KEY: z.string().optional(),
  BASETEN_BASE_URL: z.string().url().optional(),
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
  QWEN_BASE_URL: z.string().url().optional(),
  OAUTH_ENCRYPTION_KEY: z.string().min(32).default("replace-with-a-real-32-byte-secret-value")
});

export type AppEnv = z.infer<typeof envSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): AppEnv {
  return envSchema.parse(source);
}
