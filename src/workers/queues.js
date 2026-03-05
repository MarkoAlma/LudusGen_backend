// src/workers/queues.js
//
// BullMQ queue definitions.
// Redis / queues are only initialized when USE_QUEUE=true in .env
// Without that flag the server starts cleanly even without Redis.

import { Queue, QueueEvents } from "bullmq";
import { QUEUE_NAMES } from "../config/tripo.config.js";

const USE_QUEUE = process.env.USE_QUEUE === "true";

/* ─── Redis connection config ─────────────────────────────────────────── */
function getRedisOpts() {
  const url = process.env.REDIS_URL ?? "redis://localhost:6379";
  try {
    const parsed = new URL(url);
    return {
      host:     parsed.hostname,
      port:     parseInt(parsed.port) || 6379,
      password: parsed.password || undefined,
      username: parsed.username || undefined,
      tls:      parsed.protocol === "rediss:" ? {} : undefined,
      maxRetriesPerRequest: null, // required for BullMQ
    };
  } catch {
    return { host: "localhost", port: 6379, maxRetriesPerRequest: null };
  }
}

/* ─── Default job options ─────────────────────────────────────────────── */
const DEFAULT_JOB_OPTS = {
  attempts: 3,
  backoff: { type: "exponential", delay: 2_000 },
  removeOnComplete: { count: 500 },
  removeOnFail:     { count: 200 },
};

/* ─── Queues — csak USE_QUEUE=true esetén jönnek létre ───────────────── */
export const tripoTaskQueue = USE_QUEUE
  ? new Queue(QUEUE_NAMES.TRIPO_TASKS, {
      connection: getRedisOpts(),
      defaultJobOptions: DEFAULT_JOB_OPTS,
    })
  : null;

export const tripoPollQueue = USE_QUEUE
  ? new Queue(QUEUE_NAMES.TRIPO_POLL, {
      connection: getRedisOpts(),
      defaultJobOptions: {
        ...DEFAULT_JOB_OPTS,
        attempts: 60,
        backoff: { type: "fixed", delay: 4_000 },
      },
    })
  : null;

export const tripoWebhookQueue = USE_QUEUE
  ? new Queue(QUEUE_NAMES.TRIPO_WEBHOOK, {
      connection: getRedisOpts(),
      defaultJobOptions: { ...DEFAULT_JOB_OPTS, attempts: 5 },
    })
  : null;

export const tripoTaskQueueEvents = USE_QUEUE
  ? new QueueEvents(QUEUE_NAMES.TRIPO_TASKS, { connection: getRedisOpts() })
  : null;

/* ─── Helper: single task enqueue ────────────────────────────────────── */
export async function enqueueTripoTask(data, opts = {}) {
  if (!tripoTaskQueue) throw new Error("Queue not enabled — set USE_QUEUE=true in .env");
  const job = await tripoTaskQueue.add(data.jobType, data, {
    jobId:    opts.jobId,
    priority: opts.priority,
    delay:    opts.delay,
  });
  return job.id;
}

/* ─── Helper: bulk enqueue ────────────────────────────────────────────── */
export async function enqueueBatch(items) {
  if (!tripoTaskQueue) throw new Error("Queue not enabled — set USE_QUEUE=true in .env");
  const jobs = await tripoTaskQueue.addBulk(
    items.map(data => ({ name: data.jobType, data })),
  );
  return jobs.map(j => j.id);
}

/* ─── Graceful shutdown ───────────────────────────────────────────────── */
export async function closeQueues() {
  if (!USE_QUEUE) return;
  await Promise.all([
    tripoTaskQueue.close(),
    tripoPollQueue.close(),
    tripoWebhookQueue.close(),
    tripoTaskQueueEvents.close(),
  ]);
}