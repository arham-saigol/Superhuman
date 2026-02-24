import pino from "pino";

export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: {
    paths: [
      "*.apiKey",
      "*.token",
      "*.authorization",
      "*.password",
      "env.AGENTMAIL_API_KEY",
      "env.DEEPGRAM_API_KEY",
      "env.DEEPSEEK_API_KEY",
      "env.FIREWORKS_API_KEY",
      "env.OLLAMA_API_KEY",
      "env.BASETEN_API_KEY",
      "env.CONVEX_ADMIN_KEY"
    ],
    censor: "[REDACTED]"
  }
});
