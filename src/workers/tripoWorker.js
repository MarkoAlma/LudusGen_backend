// src/workers/tripoWorker.js
//
// BullMQ worker: processes TripoJobData jobs from the task queue.
// Runs in a separate process / thread from the HTTP server.
// Start with: node src/workers/tripoWorker.js

import { Worker } from "bullmq";
import { DEFAULT_MODEL, QUEUE_NAMES } from "../config/tripo.config.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { taskService } from "../services/taskService.js";
import { analyticsService } from "../services/analyticsService.js";
import { webhookService } from "../services/webhookService.js";
import { linkTaskIdToTransaction, refundCredits } from "../services/creditService.js";
import {
  persistPendingRecoveryTask,
  registerTask as registerForRecovery,
  startTaskRecovery,
} from "../services/taskRecoveryService.js";

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

function getWorkerTaskPrompt(taskBody = {}) {
  return taskBody.prompt ?? taskBody._sourceName ?? taskBody.type ?? "tripo_task";
}

async function registerWorkerTaskForRecovery(job, taskId, billing) {
  const taskBody = job.data.taskBody ?? {};
  const userId = billing?.userId ?? job.data.userId ?? null;
  if (!taskId || !userId) return;

  const prompt = getWorkerTaskPrompt(taskBody);
  try {
    await persistPendingRecoveryTask({
      taskId,
      userId,
      body: taskBody,
      prompt,
    });
  } catch (err) {
    console.warn(`[Worker] pending recovery persist failed for task=${taskId}:`, err.message);
  }

  registerForRecovery(
    taskId,
    userId,
    taskBody.type,
    taskBody.model_version ?? DEFAULT_MODEL,
    prompt,
    {
      texture: taskBody.texture === true,
      pbr: taskBody.pbr === true,
    },
  );
}

/* ─── Worker processor ────────────────────────────────────────────────── */
async function processJob(job) {
  const { taskBody, callbackUrl, pipelineId, pipelineStep, batchId, batchIndex } = job.data;
  const billing = job.data.billing ?? null;
  const client  = getTripoClient();
  const startMs = Date.now();


  await job.updateProgress(0);

  /* ── Create Tripo task ─────────────────────────────────────────── */
  let taskId = job.data._tripoTaskId ?? null;
  if (!taskId) {
    const validatedBody = taskService.validate(taskBody);
    if (callbackUrl) validatedBody["callback_url"] = callbackUrl;

    taskId = await client.createTask(validatedBody, job.data.idempotencyKey);

    // Store taskId before any Firestore billing work so retries poll the same provider task.
    job.data = { ...job.data, _tripoTaskId: taskId };
    await job.updateData({ ...job.data, _tripoTaskId: taskId });

    analyticsService.recordTaskStart(taskId, taskBody.type);
    console.log(`[Worker] job=${job.id} -> Tripo task=${taskId}`);
  } else {
    console.log(`[Worker] job=${job.id} reusing Tripo task=${taskId}`);
  }

  await registerWorkerTaskForRecovery(job, taskId, billing);

  if (billing?.userId && billing?.tempTxId) {
    try {
      await linkTaskIdToTransaction(billing.userId, billing.tempTxId, taskId);
    } catch (err) {
      if (!err.billingLinkMapped) throw err;
      console.warn(`[Worker] billing link incomplete for task=${taskId}; continuing with durable billing link`);
    }
  }

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
    if (billing?.userId && billing?.amount > 0) {
      await refundCredits(billing.userId, billing.amount, taskId, `worker_${result.status}`);
    }
    return {
      taskId,
      status:    result.status,
      modelUrl:  null,
      rawOutput: result.rawOutput,
      durationMs,
      failed:    true,
    };
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

  /* ── Batch tracking ──────────────────────────────────────────────── */

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
}

/* ─── Worker instance ─────────────────────────────────────────────────── */
export function startWorker(concurrency = 5) {
  startTaskRecovery();

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
  });

  worker.on("failed", async (job, err) => {
    console.error(`[Worker] ❌ job=${job?.id} attempt=${job?.attemptsMade}:`, err.message);
    if (job) {
      analyticsService.recordTaskError(
        job.id ?? "unknown",
        job.data.taskBody.type,
        err.message,
      );
      const attempts = job.opts?.attempts ?? 1;
      const isFinalAttempt = job.attemptsMade >= attempts;
      const billing = job.data.billing ?? null;
      if (isFinalAttempt && job.data._tripoTaskId) {
        await registerWorkerTaskForRecovery(job, job.data._tripoTaskId, billing);
      }
      if (isFinalAttempt && billing?.userId && billing?.amount > 0 && billing?.tempTxId && !job.data._tripoTaskId) {
        try {
          await refundCredits(billing.userId, billing.amount, billing.tempTxId, "worker_create_failed");
        } catch (refundErr) {
          console.error(`[Worker] refund failed for job=${job.id}:`, refundErr.message);
        }
      }
    }
  });

  worker.on("stalled", jobId => {
    console.warn(`[Worker] ⚠ job=${jobId} stalled — will be retried`);
  });

  worker.on("error", err => {
    console.error("[Worker] worker error:", err.message);
  });

  return worker;
}

/* ─── Graceful shutdown ───────────────────────────────────────────────── */
export async function stopWorker(worker) {
  await worker.close();
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
