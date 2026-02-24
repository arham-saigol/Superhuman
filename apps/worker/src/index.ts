import Redis from "ioredis";
import {
  acquireTaskLock,
  canRetry,
  getTaskStatus,
  moveDueRetries,
  popTask,
  releaseTaskLock,
  renewTaskLock,
  scheduleRetry,
  setTaskStatus
} from "@superhuman/agent";
import type { AgentTask } from "@superhuman/core";
import { loadEnv, logger } from "@superhuman/core";

const env = loadEnv();
const WORKER_ID = `${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
const HEARTBEAT_KEY = "superhuman:worker:heartbeat";

type RedisClient = {
  set: (key: string, value: string, ...args: Array<string | number>) => Promise<unknown>;
  ping: () => Promise<string>;
  rpop: (key: string) => Promise<string | null>;
  lpush: (key: string, value: string) => Promise<number>;
  zadd: (key: string, score: number, member: string) => Promise<number>;
  zrangebyscore: (key: string, min: number, max: number, ...rest: Array<string | number>) => Promise<string[]>;
  zrem: (key: string, ...members: string[]) => Promise<number>;
  del: (...keys: string[]) => Promise<number>;
  hset: (key: string, values: Record<string, string | number>) => Promise<number>;
  hgetall: (key: string) => Promise<Record<string, string>>;
  expire: (key: string, seconds: number) => Promise<number>;
};

const redis = new (Redis as unknown as new (url: string, options: { maxRetriesPerRequest: null }) => RedisClient)(
  env.REDIS_URL,
  { maxRetriesPerRequest: null }
);

async function heartbeatLoop() {
  await redis.set(HEARTBEAT_KEY, `${WORKER_ID}:${new Date().toISOString()}`, "EX", 30);
  setTimeout(() => void heartbeatLoop(), 10_000);
}

class TaskInterruptedError extends Error {
  constructor(public readonly reason: "cancelled" | "lock_lost") {
    super(reason);
    this.name = "TaskInterruptedError";
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function isTaskCancelled(taskId: string): Promise<boolean> {
  const status = await getTaskStatus(redis, taskId);
  return status.state === "cancelled";
}

async function executeTask(task: AgentTask, checkpoint: () => Promise<void>): Promise<void> {
  // kernel-pictures orchestration hook goes here.
  for (let i = 0; i < 15; i += 1) {
    await checkpoint();
    await sleep(50);
  }
  await checkpoint();
  logger.info({ taskId: task.id, userId: task.userId }, "task complete");
}

async function processTask(task: AgentTask): Promise<void> {
  const lockAcquired = await acquireTaskLock(redis, task.id, WORKER_ID, 30_000);
  if (!lockAcquired) {
    logger.warn({ taskId: task.id }, "skipping task because lock was not acquired");
    return;
  }

  let lockLost = false;
  const checkpoint = async (): Promise<void> => {
    if (lockLost) {
      throw new TaskInterruptedError("lock_lost");
    }
    if (await isTaskCancelled(task.id)) {
      throw new TaskInterruptedError("cancelled");
    }
  };

  await checkpoint();
  await setTaskStatus(redis, task.id, "running", task.attempt, task.maxAttempts);

  const renewInterval = setInterval(() => {
    void renewTaskLock(redis, task.id, WORKER_ID, 30_000)
      .then((ok) => {
        if (!ok) {
          lockLost = true;
        }
      })
      .catch(() => {
        lockLost = true;
      });
  }, 10_000);

  try {
    await executeTask(task, checkpoint);
    await checkpoint();
    await setTaskStatus(redis, task.id, "completed", task.attempt, task.maxAttempts);
  } catch (error) {
    if (error instanceof TaskInterruptedError) {
      if (error.reason === "cancelled") {
        await setTaskStatus(redis, task.id, "cancelled", task.attempt, task.maxAttempts);
        return;
      }
      logger.warn({ taskId: task.id, workerId: WORKER_ID }, "task lock ownership was lost; aborting task");
      return;
    }

    logger.error({ error, taskId: task.id }, "task failed");
    if (canRetry(task)) {
      const retryTask: AgentTask = {
        ...task,
        state: "retry_scheduled",
        attempt: task.attempt + 1,
        updatedAt: Date.now()
      };
      const delayMs = Math.min(60_000, 2 ** retryTask.attempt * 1_000);
      await scheduleRetry(redis, retryTask, delayMs);
      logger.info({ taskId: task.id, delayMs, attempt: retryTask.attempt }, "task scheduled for retry");
    } else {
      await setTaskStatus(redis, task.id, "failed", task.attempt, task.maxAttempts, {
        lastError: error instanceof Error ? error.message : "unknown_error"
      });
    }
  } finally {
    clearInterval(renewInterval);
    await releaseTaskLock(redis, task.id, WORKER_ID);
  }
}

async function processLoop() {
  while (true) {
    await moveDueRetries(redis);
    const task = await popTask(redis);
    if (!task) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      continue;
    }

    if (task.state === "cancelled" || (await isTaskCancelled(task.id))) {
      await setTaskStatus(redis, task.id, "cancelled", task.attempt, task.maxAttempts);
      continue;
    }

    await processTask(task);
  }
}

async function main() {
  logger.info({ workerId: WORKER_ID, redisUrl: env.REDIS_URL }, "worker starting");
  await redis.ping();
  void heartbeatLoop();

  await processLoop();
}

main().catch((error) => {
  logger.fatal({ error }, "worker crashed");
  process.exit(1);
});
