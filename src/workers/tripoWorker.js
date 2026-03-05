// src/workers/tripoWorker.js
//
// BullMQ worker: processes TripoJobData jobs from the task queue.
// Runs in a separate process / thread from the HTTP server.
// Start with: node src/workers/tripoWorker.js

import { Worker } from "bullmq";
import { QUEUE_NAMES } from "../config/tripo.config.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { taskService } from "../services/taskService.js";
import { analyticsService } from "../services/analyticsService.js";
import { webhookService } from "../services/webhookService.js";

/* ─── Redis connection (same as queues.js) ────────────────────────────── */
function getRedisOpts() {
  const url = process.env.REDIS_URL ?? "redis://localhost:6379";
  try {
    const parsed = new URL(url);
    return {
      host:     parsed.hostname,
      port:     parseInt(parsed.port) || 6379,
      password: parsed.password || undefined,
      tls:      parsed.protocol === "rediss:" ? {} : undefined,
      maxRetriesPerRequest: null,
    };
  } catch {
    return { host: "localhost", port: 6379, maxRetriesPerRequest: null };
  }
}

/* ─── Worker processor ────────────────────────────────────────────────── */
async function processJob(job) {
  const { taskBody, callbackUrl, pipelineId, pipelineStep, batchId, batchIndex } = job.data;
  const client  = getTripoClient();
  const startMs = Date.now();

  console.log(`[Worker] job=${job.id} type=${taskBody.type} attempt=${job.attemptsMade + 1}`);

  await job.updateProgress(0);

  /* ── Create Tripo task ─────────────────────────────────────────── */
  const validatedBody = taskService.validate(taskBody);
  if (callbackUrl) validatedBody["callback_url"] = callbackUrl;

  const taskId = await client.createTask(validatedBody, job.data.idempotencyKey);
  analyticsService.recordTaskStart(taskId, taskBody.type);

  console.log(`[Worker] job=${job.id} → Tripo task=${taskId}`);

  // Store taskId in job data so it's accessible on retry
  await job.updateData({ ...job.data, _tripoTaskId: taskId });

  /* ── Poll task ──────────────────────────────────────────────────── */
  const result = await client.pollTask(taskId, {
    pollIntervalMs: job.data.pollIntervalMs,
    maxMs: job.data.maxPollAttempts
      ? job.data.maxPollAttempts * (job.data.pollIntervalMs ?? 4_000)
      : undefined,
    onProgress: async (progress) => {
      await job.updateProgress(progress);
    },
  });

  const durationMs = Date.now() - startMs;
  analyticsService.recordTaskEnd(taskId, result.status, durationMs);

  if (!result.success) {
    throw new Error(`Tripo task ${taskId} ended with status=${result.status}`);
  }

  const jobResult = {
    taskId,
    status:    result.status,
    modelUrl:  result.modelUrl,
    rawOutput: result.rawOutput,
    durationMs,
  };

  /* ── Callback URL delivery ──────────────────────────────────────── */
  if (callbackUrl) {
    await deliverCallback(callbackUrl, jobResult).catch(err =>
      console.warn(`[Worker] callback delivery failed:`, err.message),
    );
  }

  /* ── Webhook notification ────────────────────────────────────────── */
  if (result.modelUrl) {
    await webhookService.handlePayload({
      task_id:   taskId,
      type:      taskBody.type,
      status:    result.status,
      progress:  100,
      output:    result.rawOutput ?? undefined,
      timestamp: Date.now(),
    }).catch(err =>
      console.warn(`[Worker] webhook handler error:`, err.message),
    );
  }

  /* ── Pipeline continuation ───────────────────────────────────────── */
  if (pipelineId && pipelineStep !== undefined) {
    console.log(`[Worker] pipeline=${pipelineId} step=${pipelineStep} completed task=${taskId}`);
  }

  /* ── Batch tracking ──────────────────────────────────────────────── */
  if (batchId && batchIndex !== undefined) {
    console.log(`[Worker] batch=${batchId} item[${batchIndex}] completed task=${taskId}`);
  }

  return jobResult;
}

/* ─── Callback delivery (HTTP POST) ──────────────────────────────────── */
async function deliverCallback(url, result) {
  const body = JSON.stringify(result);
  const res  = await fetch(url, {
    method:  "POST",
    headers: { "Content-Type": "application/json", "X-Tripo-Worker": "1" },
    body,
    signal:  AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Callback HTTP ${res.status} to ${url}`);
  console.log(`[Worker] callback delivered to ${url}`);
}

/* ─── Worker instance ─────────────────────────────────────────────────── */
export function startWorker(concurrency = 5) {
  const worker = new Worker(
    QUEUE_NAMES.TRIPO_TASKS,
    processJob,
    {
      connection:  getRedisOpts(),
      concurrency,
      limiter: {
        max:      10,     // max 10 jobs per duration window
        duration: 1_000,  // 1 second window
      },
    },
  );

  worker.on("completed", (job, result) => {
    console.log(`[Worker] ✅ job=${job.id} task=${result.taskId} in ${result.durationMs}ms`);
  });

  worker.on("failed", (job, err) => {
    console.error(`[Worker] ❌ job=${job?.id} attempt=${job?.attemptsMade}:`, err.message);
    if (job) {
      analyticsService.recordTaskError(
        job.id ?? "unknown",
        job.data.taskBody.type,
        err.message,
      );
    }
  });

  worker.on("stalled", jobId => {
    console.warn(`[Worker] ⚠ job=${jobId} stalled — will be retried`);
  });

  worker.on("error", err => {
    console.error("[Worker] worker error:", err.message);
  });

  console.log(`[Worker] started (concurrency=${concurrency})`);
  return worker;
}

/* ─── Graceful shutdown ───────────────────────────────────────────────── */
export async function stopWorker(worker) {
  console.log("[Worker] shutting down…");
  await worker.close();
  console.log("[Worker] stopped");
}

/* ─── Standalone entry point ──────────────────────────────────────────── */
const isMain = process.argv[1] === new URL(import.meta.url).pathname;
if (isMain) {
  const concurrency = parseInt(process.env.WORKER_CONCURRENCY ?? "5", 10);
  const worker = startWorker(concurrency);

  const shutdown = async () => {
    await stopWorker(worker);
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT",  shutdown);
}