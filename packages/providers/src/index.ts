import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import { logger, type AppEnv, type ModelId, type ProviderId } from "@superhuman/core";

export interface ProviderBinding {
  provider: ProviderId;
  model: ModelId;
}

const PROVIDER_MODEL_CACHE_TTL_MS = 5 * 60 * 1_000;
const providerModelCache = new Map<string, { expiresAt: number; ids: string[] }>();

const KNOWN_UPSTREAM_MODEL_IDS: Partial<Record<ProviderId, Partial<Record<ModelId, string[]>>>> = {
  codex: {
    "gpt-5.3-codex": ["gpt-5.3-codex", "gpt-5.3", "gpt-5"]
  },
  qwen: {
    "qwen-3.5": ["qwen-3.5", "qwen3", "qwen-plus"]
  },
  fireworks: {
    "minimax-m2.5": [
      "fireworks/minimax-m2p5",
      "accounts/fireworks/models/minimax-m2p5",
      "minimax-m2p5",
      "minimax-m2.5"
    ],
    "glm-5": ["fireworks/glm-5", "accounts/fireworks/models/glm-5", "glm-5"],
    "deepseek-v3.2": [
      "fireworks/deepseek-v3p2",
      "accounts/fireworks/models/deepseek-v3p2",
      "deepseek-v3p2",
      "deepseek-v3.2",
      "deepseek-v3"
    ]
  },
  deepseek: {
    "deepseek-v3.2": ["deepseek-chat", "deepseek-v3.2", "deepseek-v3"]
  },
  ollama: {
    "minimax-m2.5": ["minimax-m2.5", "minimax-m2p5"],
    "glm-5": ["glm-5", "glm:5"],
    "deepseek-v3.2": ["deepseek-v3.2", "deepseek-r1", "deepseek-chat"]
  },
  baseten: {
    "minimax-m2.5": ["minimax-m2.5", "minimax-m2p5"],
    "glm-5": ["glm-5"],
    "deepseek-v3.2": ["deepseek-v3.2", "deepseek-v3"]
  }
};

function envModelOverride(provider: ProviderId, model: ModelId): string | null {
  const logicalModelSuffix = model.toUpperCase().replace(/[^A-Z0-9]+/g, "_");
  const providerPrefix = provider.toUpperCase();
  const key = `MODEL_OVERRIDE_${providerPrefix}_${logicalModelSuffix}`;
  const value = process.env[key];
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function knownModelCandidates(provider: ProviderId, model: ModelId): string[] {
  return KNOWN_UPSTREAM_MODEL_IDS[provider]?.[model] ?? [model];
}

function normalizeModelId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function modelVersionCompatible(provider: ProviderId, targetModel: ModelId, candidateId: string): boolean {
  const raw = candidateId.toLowerCase();

  switch (targetModel) {
    case "minimax-m2.5":
      return raw.includes("minimax") && /m2([._-]?5|p5)/.test(raw);
    case "glm-5":
      return raw.includes("glm") && /(^|[^0-9])5([^0-9]|$)/.test(raw);
    case "deepseek-v3.2":
      if (provider === "deepseek") {
        return raw.includes("deepseek-chat") || (raw.includes("deepseek") && /v3([._-]?2|p2)/.test(raw));
      }
      return raw.includes("deepseek") && /v3([._-]?2|p2)/.test(raw);
    case "qwen-3.5":
      return raw.includes("qwen") && (/(3([._-]?5|p5))/.test(raw) || raw.includes("qwen-plus") || raw.includes("qwenplus"));
    case "gpt-5.3-codex":
      return raw.includes("gpt") && /(5([._-]?3)?)/.test(raw);
    default:
      return true;
  }
}

function modelMatchScore(targetModel: ModelId, candidateId: string): number {
  const raw = candidateId.toLowerCase();
  const normalized = normalizeModelId(candidateId);
  const checks: Array<[boolean, number]> = [];

  switch (targetModel) {
    case "minimax-m2.5":
      checks.push([raw.includes("minimax"), 8], [/m2([._-]?5|p5)/.test(raw), 5], [normalized.includes("m25"), 3]);
      break;
    case "glm-5":
      checks.push([raw.includes("glm"), 8], [/(^|[^0-9])5([^0-9]|$)/.test(raw), 5], [normalized.includes("glm5"), 3]);
      break;
    case "deepseek-v3.2":
      checks.push([raw.includes("deepseek"), 8], [/(v3([._-]?2|p2)|deepseek-chat)/.test(raw), 5], [normalized.includes("v32"), 3]);
      break;
    case "qwen-3.5":
      checks.push([raw.includes("qwen"), 8], [/(3([._-]?5|p5)|qwenplus)/.test(raw), 5], [normalized.includes("qwen35"), 3]);
      break;
    case "gpt-5.3-codex":
      checks.push([raw.includes("gpt"), 6], [/(5([._-]?3)?)/.test(raw), 4], [raw.includes("codex"), 2]);
      break;
    default:
      break;
  }

  return checks.reduce((sum, [ok, points]) => sum + (ok ? points : 0), 0);
}

function rankedDiscoveredCandidates(provider: ProviderId, targetModel: ModelId, discoveredModelIds: string[]): string[] {
  const ranked = discoveredModelIds
    .map((id) => ({ id, score: modelMatchScore(targetModel, id) }))
    .filter((item) => item.score > 0 && modelVersionCompatible(provider, targetModel, item.id))
    .sort((a, b) => b.score - a.score)
    .map((item) => item.id);

  return ranked.slice(0, 5);
}

function dedupeNonEmpty(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter((value) => value.length > 0)));
}

async function fetchProviderModelIds(
  provider: ProviderId,
  providerConfig: { baseURL: string; apiKey: string }
): Promise<string[]> {
  const cacheKey = `${provider}:${providerConfig.baseURL}`;
  const now = Date.now();
  const cached = providerModelCache.get(cacheKey);
  if (cached && cached.expiresAt > now) {
    return cached.ids;
  }

  try {
    const url = `${providerConfig.baseURL.replace(/\/$/, "")}/models`;
    const response = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${providerConfig.apiKey}`,
        Accept: "application/json"
      }
    });
    if (!response.ok) {
      return [];
    }
    const body = (await response.json()) as { data?: Array<{ id?: string }> };
    const ids = Array.isArray(body.data)
      ? body.data
          .map((entry) => (typeof entry?.id === "string" ? entry.id.trim() : ""))
          .filter((id) => id.length > 0)
      : [];
    providerModelCache.set(cacheKey, { expiresAt: now + PROVIDER_MODEL_CACHE_TTL_MS, ids });
    return ids;
  } catch {
    return [];
  }
}

function normalizeBaseUrl(provider: ProviderId, rawBaseURL: string): string {
  const trimmed = rawBaseURL.trim();
  if (!trimmed) return rawBaseURL;

  try {
    const parsed = new URL(trimmed);
    const hostname = parsed.hostname.toLowerCase();
    const stripTrailing = (value: string) => value.replace(/\/+$/, "");
    let pathname = stripTrailing(parsed.pathname || "");
    pathname = pathname.replace(/\/(chat\/completions|completions|responses)$/, "");

    if (provider === "fireworks" && hostname.endsWith("fireworks.ai")) {
      if (!pathname || pathname === "/") pathname = "/inference/v1";
      if (pathname === "/inference") pathname = "/inference/v1";
    }

    if (provider === "qwen" && hostname.includes("dashscope")) {
      if (!pathname || pathname === "/") pathname = "/compatible-mode/v1";
      if (pathname === "/compatible-mode") pathname = "/compatible-mode/v1";
    }

    if (provider === "ollama") {
      if (!pathname || pathname === "/") pathname = "/v1";
    }

    parsed.pathname = pathname || "/";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return rawBaseURL;
  }
}

export interface OpenAIChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface OpenAIStyleChatCompletionRequest {
  model: string;
  messages: OpenAIChatMessage[];
  stream?: boolean;
  max_tokens?: number;
  temperature?: number;
}

export interface OpenAIStyleChatCompletionResponse {
  id: string;
  object: "chat.completion";
  created: number;
  model: string;
  choices: Array<{
    index: number;
    finish_reason: "stop";
    message: { role: "assistant"; content: string };
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

const REQUIRED_MODELS: Array<{ id: ModelId; label: string; providers: ProviderId[] }> = [
  { id: "gpt-5.3-codex", label: "GPT-5.3 Codex", providers: ["codex"] },
  { id: "minimax-m2.5", label: "Minimax M2.5", providers: ["fireworks", "ollama", "baseten"] },
  { id: "glm-5", label: "GLM 5", providers: ["fireworks", "ollama", "baseten"] },
  { id: "deepseek-v3.2", label: "Deepseek V3.2", providers: ["deepseek", "fireworks", "ollama"] },
  { id: "qwen-3.5", label: "Qwen 3.5", providers: ["qwen"] }
];

function estimateTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

function getProviderConfig(provider: ProviderId, env: AppEnv): { baseURL: string; apiKey: string } | null {
  switch (provider) {
    case "codex":
      if (!env.CODEX_ACCESS_TOKEN) return null;
      return { baseURL: normalizeBaseUrl(provider, "https://api.openai.com/v1"), apiKey: env.CODEX_ACCESS_TOKEN };
    case "qwen":
      if (!env.QWEN_API_KEY) return null;
      return {
        baseURL: normalizeBaseUrl(provider, env.QWEN_BASE_URL ?? "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"),
        apiKey: env.QWEN_API_KEY
      };
    case "fireworks":
      if (!env.FIREWORKS_API_KEY) return null;
      return {
        baseURL: normalizeBaseUrl(provider, env.FIREWORKS_BASE_URL ?? "https://api.fireworks.ai/inference/v1"),
        apiKey: env.FIREWORKS_API_KEY
      };
    case "deepseek":
      if (!env.DEEPSEEK_API_KEY) return null;
      return { baseURL: normalizeBaseUrl(provider, "https://api.deepseek.com"), apiKey: env.DEEPSEEK_API_KEY };
    case "ollama":
      if (!env.OLLAMA_API_KEY || !env.OLLAMA_BASE_URL) return null;
      return { baseURL: normalizeBaseUrl(provider, env.OLLAMA_BASE_URL), apiKey: env.OLLAMA_API_KEY };
    case "baseten":
      if (!env.BASETEN_API_KEY || !env.BASETEN_BASE_URL) return null;
      return { baseURL: normalizeBaseUrl(provider, env.BASETEN_BASE_URL), apiKey: env.BASETEN_API_KEY };
    default:
      return null;
  }
}

export function resolveModel(model: ModelId, availableProviders: ProviderId[]): ProviderBinding | null {
  const spec = REQUIRED_MODELS.find((x) => x.id === model);
  if (!spec) return null;
  const provider = spec.providers.find((p) => availableProviders.includes(p));
  return provider ? { provider, model } : null;
}

export function availableProviders(env: AppEnv): ProviderId[] {
  const providers: ProviderId[] = [];
  const candidates: ProviderId[] = ["codex", "qwen", "fireworks", "deepseek", "ollama", "baseten"];
  for (const provider of candidates) {
    if (getProviderConfig(provider, env)) {
      providers.push(provider);
    }
  }
  return providers;
}

export function listOpenAIStyleModels(env: AppEnv) {
  const available = availableProviders(env);
  return REQUIRED_MODELS.map((model) => ({
    id: model.id,
    object: "model",
    created: 1_735_689_600,
    owned_by: "superhuman",
    name: model.label,
    available: model.providers.some((p) => available.includes(p)),
    providers: model.providers,
    info: {
      meta: {
        tags: [
          {
            name: "superhuman"
          }
        ],
        capabilities: {
          vision: true,
          web_search: true,
          image_generation: false,
          code_interpreter: false,
          usage: true
        }
      },
      params: {
        stream_response: false
      }
    }
  }));
}

export async function generateModelResponse(
  env: AppEnv,
  request: OpenAIStyleChatCompletionRequest
): Promise<OpenAIStyleChatCompletionResponse> {
  const modelId = request.model as ModelId;
  const available = availableProviders(env);
  const binding = resolveModel(modelId, available);

  if (!binding) {
    throw new Error(`No configured provider available for model: ${request.model}`);
  }

  const providerConfig = getProviderConfig(binding.provider, env);
  if (!providerConfig) {
    throw new Error(`Provider not configured: ${binding.provider}`);
  }

  const openai = createOpenAI({
    baseURL: providerConfig.baseURL,
    apiKey: providerConfig.apiKey
  });

  const explicitOverride = envModelOverride(binding.provider, binding.model);
  const knownCandidates = knownModelCandidates(binding.provider, binding.model);
  const discoveredModelIds = await fetchProviderModelIds(binding.provider, providerConfig);
  const discoveredCandidates = rankedDiscoveredCandidates(binding.provider, binding.model, discoveredModelIds);
  const providerCandidates = dedupeNonEmpty([
    ...(explicitOverride ? [explicitOverride] : []),
    ...knownCandidates,
    ...discoveredCandidates,
    binding.model
  ]);

  let result: Awaited<ReturnType<typeof generateText>> | null = null;
  const failures: string[] = [];

  for (const providerModel of providerCandidates) {
    try {
      result = await generateText({
        model: openai(providerModel),
        messages: request.messages,
        temperature: request.temperature
      });
      break;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      failures.push(`${providerModel}: ${detail}`);
    }
  }

  if (!result) {
    logger.error(
      {
        provider: binding.provider,
        logicalModel: binding.model,
        candidateModels: providerCandidates,
        failures
      },
      "all upstream model candidates failed"
    );

    const lastError = failures.at(-1) ?? "unknown provider error";
    throw new Error(
      `Provider ${binding.provider} failed for model ${binding.model}. Tried ${providerCandidates.join(", ")}. Last error: ${lastError}`
    );
  }

  const promptTokenGuess = estimateTokens(request.messages.map((m) => m.content).join("\n"));
  const completionTokenGuess = estimateTokens(result.text);

  return {
    id: `chatcmpl_${Math.random().toString(36).slice(2)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: binding.model,
    choices: [
      {
        index: 0,
        finish_reason: "stop",
        message: {
          role: "assistant",
          content: result.text
        }
      }
    ],
    usage: {
      prompt_tokens: promptTokenGuess,
      completion_tokens: completionTokenGuess,
      total_tokens: promptTokenGuess + completionTokenGuess
    }
  };
}
