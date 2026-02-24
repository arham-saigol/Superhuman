import type { AgentTask, TaskState } from "@superhuman/core";

export const AGENT_QUEUE_KEY = "superhuman:queue:tasks";
export const AGENT_RETRY_ZSET_KEY = "superhuman:queue:retries";
export const AGENT_LOCK_PREFIX = "superhuman:lock:task:";
export const AGENT_STATUS_PREFIX = "superhuman:task:";

type RedisLike = {
  lpush: (key: string, value: string) => Promise<number>;
  rpop: (key: string) => Promise<string | null>;
  zadd: (key: string, score: number, member: string) => Promise<number>;
  zrangebyscore: (key: string, min: number, max: number, ...rest: Array<string | number>) => Promise<string[]>;
  zrem: (key: string, ...members: string[]) => Promise<number>;
  set: (key: string, value: string, ...args: Array<string | number>) => Promise<unknown>;
  del: (...keys: string[]) => Promise<number>;
  hset: (key: string, values: Record<string, string | number>) => Promise<number>;
  hgetall: (key: string) => Promise<Record<string, string>>;
  expire: (key: string, seconds: number) => Promise<number>;
  eval?: (script: string, numKeys: number, ...args: string[]) => Promise<number | string>;
};

export function nextState(current: TaskState, event: "start" | "wait" | "retry" | "complete" | "fail" | "cancel"): TaskState {
  switch (event) {
    case "start":
      return "running";
    case "wait":
      return "waiting_io";
    case "retry":
      return "retry_scheduled";
    case "complete":
      return "completed";
    case "fail":
      return "failed";
    case "cancel":
      return "cancelled";
    default:
      return current;
  }
}

export function canRetry(task: AgentTask): boolean {
  return task.attempt < task.maxAttempts;
}

export async function enqueueTask(redis: RedisLike, task: AgentTask) {
  await redis.lpush(AGENT_QUEUE_KEY, JSON.stringify(task));
  await setTaskStatus(redis, task.id, task.state, task.attempt, task.maxAttempts, {
    userId: task.userId,
    chatId: task.chatId
  });
}

export async function popTask(redis: RedisLike): Promise<AgentTask | null> {
  const payload = await redis.rpop(AGENT_QUEUE_KEY);
  if (!payload) return null;
  try {
    return JSON.parse(payload) as AgentTask;
  } catch {
    return null;
  }
}

export async function acquireTaskLock(redis: RedisLike, taskId: string, workerId: string, ttlMs = 30_000): Promise<boolean> {
  const result = await redis.set(`${AGENT_LOCK_PREFIX}${taskId}`, workerId, "NX", "PX", ttlMs);
  return result === "OK";
}

export async function renewTaskLock(redis: RedisLike, taskId: string, workerId: string, ttlMs = 30_000): Promise<boolean> {
  if (typeof redis.eval !== "function") {
    return false;
  }

  const result = await redis.eval(
    `if redis.call("get", KEYS[1]) == ARGV[1] then
       return redis.call("pexpire", KEYS[1], tonumber(ARGV[2]))
     else
       return 0
     end`,
    1,
    `${AGENT_LOCK_PREFIX}${taskId}`,
    workerId,
    String(ttlMs)
  );
  return result === 1 || result === "1";
}

export async function releaseTaskLock(redis: RedisLike, taskId: string, workerId?: string): Promise<void> {
  const lockKey = `${AGENT_LOCK_PREFIX}${taskId}`;
  if (!workerId || typeof redis.eval !== "function") {
    await redis.del(lockKey);
    return;
  }

  await redis.eval(
    `if redis.call("get", KEYS[1]) == ARGV[1] then
       return redis.call("del", KEYS[1])
     else
       return 0
     end`,
    1,
    lockKey,
    workerId
  );
}

export async function scheduleRetry(redis: RedisLike, task: AgentTask, delayMs: number): Promise<void> {
  const due = Date.now() + delayMs;
  await redis.zadd(AGENT_RETRY_ZSET_KEY, due, JSON.stringify(task));
  await setTaskStatus(redis, task.id, "retry_scheduled", task.attempt, task.maxAttempts);
}

export async function moveDueRetries(redis: RedisLike, batchSize = 25): Promise<number> {
  const due = await redis.zrangebyscore(AGENT_RETRY_ZSET_KEY, 0, Date.now(), "LIMIT", 0, batchSize);
  if (due.length === 0) return 0;

  let moved = 0;
  for (const payload of due) {
    await redis.lpush(AGENT_QUEUE_KEY, payload);
    moved += 1;
  }
  await redis.zrem(AGENT_RETRY_ZSET_KEY, ...due);
  return moved;
}

export async function setTaskStatus(
  redis: RedisLike,
  taskId: string,
  state: TaskState,
  attempt: number,
  maxAttempts: number,
  extra?: Record<string, string>
): Promise<void> {
  await redis.hset(`${AGENT_STATUS_PREFIX}${taskId}`, {
    state,
    attempt,
    maxAttempts,
    updatedAt: Date.now(),
    ...(extra ?? {})
  });
  await redis.expire(`${AGENT_STATUS_PREFIX}${taskId}`, 60 * 60 * 24);
}

export async function getTaskStatus(redis: RedisLike, taskId: string) {
  return await redis.hgetall(`${AGENT_STATUS_PREFIX}${taskId}`);
}
