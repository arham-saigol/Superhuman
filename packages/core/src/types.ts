export type ProviderId =
  | "fireworks"
  | "ollama"
  | "baseten"
  | "deepseek"
  | "codex"
  | "qwen"
  | "deepgram";

export type ModelId =
  | "gpt-5.3-codex"
  | "minimax-m2.5"
  | "glm-5"
  | "deepseek-v3.2"
  | "qwen-3.5";

export type TaskState =
  | "queued"
  | "running"
  | "waiting_io"
  | "retry_scheduled"
  | "completed"
  | "failed"
  | "cancelled";

export interface AgentTask {
  id: string;
  userId: string;
  chatId: string;
  prompt: string;
  state: TaskState;
  attempt: number;
  maxAttempts: number;
  createdAt: number;
  updatedAt: number;
}

export interface HealthReport {
  ok: boolean;
  web: { ok: boolean; detail?: string };
  worker: { ok: boolean; detail?: string };
  redis: { ok: boolean; detail?: string };
  convex: { ok: boolean; detail?: string };
  providers: Record<string, { ok: boolean; detail?: string }>;
}
