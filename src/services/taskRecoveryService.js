// src/services/taskRecoveryService.js
//
// Background task tracker — automatically polls pending Tripo tasks and
// saves completed ones to Firestore history, even if the user navigated away.
//
// This runs independently of webhooks (which may not be reachable on localhost).
// When a task is created, its ID is registered here. A periodic poller checks
// each registered task. On success, the model is saved to trellis_history.
// On failure, credits are refunded.

import { getTripoClient } from "../lib/tripoClient.js";
import { refundCredits } from "./creditService.js";
import admin from "firebase-admin";

const HISTORY_COLLECTION = "trellis_history";
const POLL_INTERVAL_MS = 5_000; // check every 5 seconds
const MAX_POLL_MS = 600_000; // 10 minutes max per task
const CLEANUP_INTERVAL_MS = 60_000; // cleanup completed tasks every minute

const HISTORY_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/** @type {Map<string, { taskId: string, userId: string, type: string, modelVersion: string, startedAt: number }>} */
const pendingTasks = new Map();

/* ─── Type → mode mapping (same as webhookController) ─────────────────── */
const TYPE_TO_MODE = {
  text_to_model: "generate",
  image_to_model: "generate",
  multiview_to_model: "generate",
  refine_model: "refine",
  stylize_model: "stylize",
  texture_model: "texture",
  convert_model: "retopo",
  smart_low_poly: "retopo",
  mesh_segmentation: "segment",
  mesh_completion: "fill_parts",
  animate_rig: "animate",
  animate_retarget: "animate",
};

/* ─── Register a task for background tracking ─────────────────────────── */
export function registerTask(taskId, userId, type, modelVersion, prompt = null) {
  if (!taskId || !userId) return;
  pendingTasks.set(taskId, {
    taskId,
    userId,
    type: type ?? "unknown",
    modelVersion: modelVersion ?? "unknown",
    prompt,
    startedAt: Date.now(),
  });
  console.log(`[TaskRecovery] Registered task ${taskId} for user ${userId}${prompt ? ` (${prompt})` : ''}`);
}

/* ─── Unregister a task (called when frontend successfully polls it) ──── */
export function unregisterTask(taskId) {
  pendingTasks.delete(taskId);
}

/* ─── Start the background poller ─────────────────────────────────────── */
let pollerInterval = null;
let cleanupInterval = null;

export function startTaskRecovery() {
  if (pollerInterval) return; // already running

  console.log("[TaskRecovery] Background task recovery started");

  pollerInterval = setInterval(async () => {
    if (pendingTasks.size === 0) return;

    const now = Date.now();
    const toPoll = [...pendingTasks.values()];

    for (const entry of toPoll) {
      // Timeout check
      if (now - entry.startedAt > MAX_POLL_MS) {
        console.log(`[TaskRecovery] Task ${entry.taskId} timed out after ${MAX_POLL_MS / 1000}s`);
        pendingTasks.delete(entry.taskId);
        continue;
      }

      try {
        const taskData = await getTripoClient().getTask(entry.taskId);
        const status = taskData.status;

        if (status === "success") {
          await saveToHistory(entry, taskData);
          pendingTasks.delete(entry.taskId);
        } else if (status === "failed" || status === "cancelled") {
          await handleFailedTask(entry, taskData);
          pendingTasks.delete(entry.taskId);
        } else {
          // "queued" or "running" — keep polling
          console.log(`[TaskRecovery] Task ${entry.taskId} (${entry.type}) still ${status}...`);
        }
      } catch (err) {
        console.error(`[TaskRecovery] Poll error for task ${entry.taskId}:`, err.message);
      }
    }
  }, POLL_INTERVAL_MS);

  // Cleanup old entries periodically
  cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [taskId, entry] of pendingTasks) {
      if (now - entry.startedAt > MAX_POLL_MS) {
        console.log(`[TaskRecovery] Cleaning up timed-out task ${taskId}`);
        pendingTasks.delete(taskId);
      }
    }
  }, CLEANUP_INTERVAL_MS);
}

/* ─── Stop the background poller ──────────────────────────────────────── */
export function stopTaskRecovery() {
  if (pollerInterval) {
    clearInterval(pollerInterval);
    pollerInterval = null;
  }
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
  console.log("[TaskRecovery] Background task recovery stopped");
}

/* ─── Save completed task to Firestore history ────────────────────────── */
async function saveToHistory(entry, taskData) {
  const db = admin.firestore();
  const out = taskData.output ?? {};

  // prerigcheck only returns is_animatable — no model to save
  if (entry.type === "animate_prerigcheck") {
    console.log(`[TaskRecovery] prerigcheck task ${entry.taskId} completed (is_animatable=${out.is_animatable}) — no model to save`);
    return;
  }

  const animatedModels = Array.isArray(out.animated_models) && out.animated_models.length > 0
    ? out.animated_models
    : null;
  const modelUrl = out.model ?? out.model_url ?? out.pbr_model ?? out.base_model
    ?? out.rigged_model ?? (animatedModels ? animatedModels[0] : out.animated_model)
    ?? out.converted_model ?? out.low_poly_model
    ?? out.stylized_model ?? null;

  if (!modelUrl) {
    console.warn(`[TaskRecovery] Task ${entry.taskId} (${entry.type}) succeeded but no model URL found in output:`, JSON.stringify(out));
    return;
  }

  // Check if history entry already exists (idempotency)
  const existing = await db.collection(HISTORY_COLLECTION)
    .where("taskId", "==", entry.taskId)
    .where("userId", "==", entry.userId)
    .limit(1)
    .get();

  if (!existing.empty) {
    console.log(`[TaskRecovery] History already exists for task ${entry.taskId}`);
    return;
  }

  const mode = TYPE_TO_MODE[entry.type] ?? "generate";
  const now = Date.now();

  const urlsToSave = animatedModels ?? [modelUrl];
  for (let i = 0; i < urlsToSave.length; i++) {
    const url = urlsToSave[i];
    if (!url) continue;
    await db.collection(HISTORY_COLLECTION).add({
      userId: entry.userId,
      prompt: entry.prompt ?? taskData.prompt ?? entry.type,
      status: "succeeded",
      model_url: url,
      source: "tripo",
      mode,
      taskId: entry.taskId,
      animationIndex: (urlsToSave.length > 1 && { animationIndex: i }),
      params: {
        model_version: entry.modelVersion,
        mode,
        type: entry.type,
        rig_type: out.rig_type ?? out.topology ?? null,
        topology: out.topology ?? null,
        is_animatable: out.is_animatable ?? out.animatable ?? out.riggable ?? null,
      },
      ts: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: now + HISTORY_TTL_MS,
    });
  }
  console.log(`[TaskRecovery] Saved ${urlsToSave.length} model(s) for task ${entry.taskId} to history for user ${entry.userId}`);

  console.log(`[TaskRecovery] Saved task ${entry.taskId} to history for user ${entry.userId}`);
}

/* ─── Handle failed/cancelled task — refund credits ───────────────────── */
async function handleFailedTask(entry, taskData) {
  const taskId = entry.taskId;
  const userId = entry.userId;

  // Look up the charged amount from credit_history
  // NOTE: collectionGroup with multiple where() requires a composite index.
  // Instead, query by taskId only and filter type in-memory to avoid index setup.
  const db = admin.firestore();
  const snap = await db.collection("credit_history")
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", taskId)
    .limit(10)
    .get();

  if (snap.empty) {
    console.log(`[TaskRecovery] No credit charge found for failed task ${taskId}`);
    return;
  }

  // Find the debit transaction in-memory
  const debitDoc = snap.docs.find(d => d.data().type === "debit");
  if (!debitDoc) {
    console.log(`[TaskRecovery] No debit transaction found for failed task ${taskId}`);
    return;
  }
  const data = debitDoc.data();

  // Check for NSFW/content policy — no refund
  const errorMsg = (taskData.error ?? "").toLowerCase();
  if (errorMsg.includes("nsfw") || errorMsg.includes("content policy") || errorMsg.includes("safety") || errorMsg.includes("moderat")) {
    console.log(`[TaskRecovery] No refund for task ${taskId}: NSFW/content policy violation`);
    return;
  }

  try {
    await refundCredits(userId, data.amount, taskId, `recovery_${taskData.status}`);
    console.log(`[TaskRecovery] Refunded ${data.amount} credits for failed task ${taskId}`);
  } catch (err) {
    console.error(`[TaskRecovery] Refund failed for task ${taskId}:`, err.message);
  }
}

/* ─── Get pending task count (for debugging) ──────────────────────────── */
export function getPendingCount() {
  return pendingTasks.size;
}
