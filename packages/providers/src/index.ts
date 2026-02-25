import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import type { AppEnv, ModelId, ProviderId } from "@superhuman/core";

export interface ProviderBinding {
  provider: ProviderId;
  model: ModelId;
}

function upstreamModelId(provider: ProviderId, model: ModelId): string {
  if (provider === "deepseek" && model === "deepseek-v3.2") {
    // DeepSeek OpenAI-compatible endpoint expects concrete provider model ids.
    return "deepseek-chat";
  }
  return model;
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
      return { baseURL: "https://api.openai.com/v1", apiKey: env.CODEX_ACCESS_TOKEN };
    case "qwen":
      if (!env.QWEN_API_KEY) return null;
      return {
        baseURL: env.QWEN_BASE_URL ?? "https://dashscope.aliyuncs.com/compatible-mode/v1",
        apiKey: env.QWEN_API_KEY
      };
    case "fireworks":
      if (!env.FIREWORKS_API_KEY) return null;
      return {
        baseURL: env.FIREWORKS_BASE_URL ?? "https://api.fireworks.ai/inference/v1",
        apiKey: env.FIREWORKS_API_KEY
      };
    case "deepseek":
      if (!env.DEEPSEEK_API_KEY) return null;
      return { baseURL: "https://api.deepseek.com", apiKey: env.DEEPSEEK_API_KEY };
    case "ollama":
      if (!env.OLLAMA_API_KEY || !env.OLLAMA_BASE_URL) return null;
      return { baseURL: env.OLLAMA_BASE_URL, apiKey: env.OLLAMA_API_KEY };
    case "baseten":
      if (!env.BASETEN_API_KEY || !env.BASETEN_BASE_URL) return null;
      return { baseURL: env.BASETEN_BASE_URL, apiKey: env.BASETEN_API_KEY };
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
  const providerModel = upstreamModelId(binding.provider, binding.model);

  const openai = createOpenAI({
    baseURL: providerConfig.baseURL,
    apiKey: providerConfig.apiKey
  });

  const result = await generateText({
    model: openai(providerModel),
    messages: request.messages,
    temperature: request.temperature
  });

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
