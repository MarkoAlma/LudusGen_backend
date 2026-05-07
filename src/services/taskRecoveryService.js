// src/services/taskRecoveryService.js
//
// Background task tracker — automatically polls pending Tripo tasks and
// saves completed ones to Firestore history, even if the user navigated away.
//
// This runs independently of webhooks (which may not be reachable on localhost).
// When a task is created, its ID is registered here. A periodic poller checks
// each registered task. On success, the model is saved to trellis_history.
// Recovery never refunds credits because it cannot prove provider-side billing.

import { getTripoClient } from "../lib/tripoClient.js";
import admin from "firebase-admin";
import { extractModelUrl } from "../utils/tripoUtils.js";
import { isFailedLikeTripoTaskStatus, normalizeTripoTaskStatus } from "../utils/tripoTaskStatus.js";
import { TASK_TYPE_TO_MODE, HISTORY_TTL_MS } from "../config/tripo.config.js";

// Task types that are expected to produce a downloadable model URL on success.
// If Tripo reports success but no URL is found, treat it as a billable failure
// (credit was already debited, so recovery marks failed without refunding).
const MODEL_PRODUCING_TYPES = new Set([
  "text_to_model",
  "image_to_model",
  "multiview_to_model",
  "refine_model",
  "stylize_model",
  "texture_model",
  "convert_model",
  "smart_low_poly",
  "mesh_segmentation",
  "mesh_completion",
  "animate_rig",
  "animate_retarget",
  "import_model",
]);

const HISTORY_COLLECTION = "tripo_history";
const DEBUG_TRIPO = process.env.DEBUG_TRIPO === "true";
const POLL_INTERVAL_MS = 5_000; // check every 5 seconds
const MAX_POLL_MS = 600_000; // 10 minutes max per task
const CLEANUP_INTERVAL_MS = 60_000; // cleanup completed tasks every minute
const MAX_CONSECUTIVE_ERRORS = Math.max(1, Number(process.env.TRIPO_RECOVERY_MAX_CONSECUTIVE_ERRORS || 20));
const GLOBAL_OUTAGE_ERROR_STREAK = Math.max(1, Number(process.env.TRIPO_RECOVERY_GLOBAL_OUTAGE_STREAK || 5));
const HEALTH_CHECK_COOLDOWN_MS = Math.max(5_000, Number(process.env.TRIPO_RECOVERY_HEALTH_COOLDOWN_MS || 30_000));


/** @type {Map<string, { taskId: string, userId: string, type: string, modelVersion: string, texture: boolean, pbr: boolean, startedAt: number }>} */
const pendingTasks = new Map();
const recentTaskMeta = new Map();
/** @type {Map<string, { consecutiveErrors: number, lastError: string | null, lastErrorAt: number | null, lastSuccessAt: number | null }>} */
const taskRecoveryStats = new Map();
let consecutiveGlobalPollErrors = 0;
let tripoUnavailableUntil = 0;
let tripoHealthLastError = null;
let tripoHealthLastLogAt = 0;

function getTaskRecoveryStats(taskId) {
  if (!taskRecoveryStats.has(taskId)) {
    taskRecoveryStats.set(taskId, {
      consecutiveErrors: 0,
      lastError: null,
      lastErrorAt: null,
      lastSuccessAt: null,
    });
  }
  return taskRecoveryStats.get(taskId);
}

function clearTaskRecoveryStats(taskId) {
  taskRecoveryStats.delete(taskId);
}

function noteTaskPollSuccess(taskId) {
  const stats = getTaskRecoveryStats(taskId);
  stats.consecutiveErrors = 0;
  stats.lastError = null;
  stats.lastErrorAt = null;
  stats.lastSuccessAt = Date.now();
  consecutiveGlobalPollErrors = 0;
  tripoHealthLastError = null;
}

function noteTaskPollError(taskId, err) {
  const stats = getTaskRecoveryStats(taskId);
  stats.consecutiveErrors += 1;
  stats.lastError = err?.message ?? "unknown_error";
  stats.lastErrorAt = Date.now();
  consecutiveGlobalPollErrors += 1;
  return stats;
}

async function applyTripoHealthGuard(triggerErr = null) {
  const now = Date.now();
  if (now < tripoUnavailableUntil) return false;

  try {
    await getTripoClient().getBalance();
    consecutiveGlobalPollErrors = 0;
    tripoHealthLastError = null;
    tripoUnavailableUntil = 0;
    console.log("[TaskRecovery] Tripo health check OK (balance endpoint reachable)");
    return true;
  } catch (err) {
    tripoUnavailableUntil = now + HEALTH_CHECK_COOLDOWN_MS;
    tripoHealthLastError = err?.message ?? triggerErr?.message ?? "health_check_failed";
    tripoHealthLastLogAt = 0;
    console.warn(
      `[TaskRecovery] Tripo health check failed, pausing recovery polling for ${Math.round(HEALTH_CHECK_COOLDOWN_MS / 1000)}s: ${tripoHealthLastError}`,
    );
    return false;
  }
}

function toMillis(value) {
  if (value == null) return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.getTime();
  if (typeof value?.toMillis === "function") {
    const millis = value.toMillis();
    return Number.isFinite(millis) ? millis : null;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

async function markHistoryTaskFailed(entry, {
  failReason,
  taskStatus = null,
  errorMessage = null,
  errorCode = null,
} = {}) {
  if (!entry?.taskId || !entry?.userId) return false;

  const patch = {
    status: "failed",
    failReason: failReason || "recovery_failed",
    recoveryStoppedAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    ...(taskStatus != null && { taskStatus }),
    ...(errorMessage != null && { recoveryError: errorMessage }),
    ...(errorCode != null && { recoveryErrorCode: errorCode }),
  };

  try {
    const db = admin.firestore();
    const snap = await db.collection(HISTORY_COLLECTION)
      .where("taskId", "==", entry.taskId)
      .where("userId", "==", entry.userId)
      .limit(25)
      .get();

    if (snap.empty) {
      await db.collection(HISTORY_COLLECTION).doc(`tripo_${entry.taskId}`).set({
        userId: entry.userId,
        taskId: entry.taskId,
        source: entry.type === "import_model" ? "upload" : "tripo",
        mode: TASK_TYPE_TO_MODE[entry.type] ?? "generate",
        ...patch,
      }, { merge: true });
      return true;
    }

    await Promise.all(snap.docs.map((doc) => doc.ref.set(patch, { merge: true })));
    return true;
  } catch (err) {
    console.error(`[TaskRecovery] Failed to mark history as failed for task ${entry.taskId}:`, err.message);
    return false;
  }
}


/* ─── Register a task for background tracking ─────────────────────────── */
function inferTaskTypeFromHistory(data = {}) {
  const explicitType = data?.params?.type;
  if (explicitType) return explicitType;
  if (data?.source === "upload" || data?.mode === "upload") return "import_model";
  return null;
}

async function restorePendingHistoryTasks() {
  const db = admin.firestore();
  const snap = await db.collection(HISTORY_COLLECTION)
    .where("status", "==", "pending")
    .limit(500)
    .get();

  if (snap.docs.length >= 500) {
    console.warn("[TaskRecovery] restorePendingHistoryTasks hit the 500-doc limit — some pending tasks may not have been restored.");
  }

  let restored = 0;
  for (const doc of snap.docs) {
    const data = doc.data() ?? {};
    const taskId = data.taskId;
    const userId = data.userId;
    const type = inferTaskTypeFromHistory(data);
    if (!taskId || !userId || !type || pendingTasks.has(taskId)) continue;

    registerTask(
      taskId,
      userId,
      type,
      data?.params?.model_version ?? null,
      data?.prompt ?? null,
      {
        texture: data?.params?.texture === true,
        pbr: data?.params?.pbr === true,
        startedAt: toMillis(data.ts) ?? toMillis(data.createdAt) ?? Date.now(),
      },
    );
    restored += 1;
  }

}

export function registerTask(taskId, userId, type, modelVersion, prompt = null, extra = {}) {
  if (!taskId || !userId) return;
  const meta = {
    taskId,
    userId,
    type: type ?? "unknown",
    modelVersion: modelVersion ?? "unknown",
    prompt,
    texture: extra.texture === true,
    pbr: extra.pbr === true,
    startedAt: toMillis(extra.startedAt) ?? Date.now(),
  };
  pendingTasks.set(taskId, meta);
  recentTaskMeta.set(taskId, meta);
  getTaskRecoveryStats(taskId);
  console.log(`[TaskRecovery] Registered task ${taskId} for user ${userId}${prompt ? ` (${prompt})` : ''}`);
}

export function getRegisteredTaskMeta(taskId) {
  return pendingTasks.get(taskId) ?? recentTaskMeta.get(taskId) ?? null;
}

function omitUndefinedValues(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, value]) => value !== undefined));
}

export async function persistPendingRecoveryTask({
  taskId,
  userId,
  body = {},
  prompt = null,
} = {}) {
  if (!taskId || !userId) return;

  const type = body.type ?? "unknown";
  const mode = TASK_TYPE_TO_MODE[type] ?? "generate";
  const now = Date.now();
  const params = omitUndefinedValues({
    model_version: body.model_version ?? null,
    mode,
    type,
    texture: body.texture === true,
    pbr: body.pbr === true,
    originalModelTaskId: body.original_model_task_id ?? body.original_model_id,
    originalTaskId: body.original_task_id,
    draftModelTaskId: body.draft_model_task_id,
    model_seed: body.model_seed,
    image_seed: body.image_seed,
    texture_seed: body.texture_seed,
    preprocessTaskId: body.preprocessTaskId,
    preprocessTaskType: body.preprocessTaskType,
    generate_parts: body.generate_parts === true ? true : undefined,
  });

  await admin.firestore().collection(HISTORY_COLLECTION).doc(`tripo_${taskId}`).set({
    userId,
    prompt: prompt ?? body.prompt ?? type,
    status: "pending",
    source: type === "import_model" ? "upload" : "tripo",
    mode,
    taskId,
    params,
    ts: now,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: now + HISTORY_TTL_MS,
  }, { merge: true });
}

/* ─── Unregister a task (called when frontend successfully polls it) ──── */
export function unregisterTask(taskId) {
  pendingTasks.delete(taskId);
  clearTaskRecoveryStats(taskId);
}

/* ─── Start the background poller ─────────────────────────────────────── */
let pollerInterval = null;
let cleanupInterval = null;

export function startTaskRecovery() {
  if (pollerInterval) return; // already running

  restorePendingHistoryTasks().catch((err) => {
    console.error("[TaskRecovery] Failed to restore pending history tasks:", err.message);
  });

  pollerInterval = setInterval(async () => {
    if (pendingTasks.size === 0) return;

    const now = Date.now();
    if (now < tripoUnavailableUntil) {
      if (now - tripoHealthLastLogAt > 10_000) {
        const waitSec = Math.max(1, Math.ceil((tripoUnavailableUntil - now) / 1000));
        console.warn(
          `[TaskRecovery] Skipping poll cycle while Tripo is marked unavailable (${waitSec}s left). lastError=${tripoHealthLastError ?? "unknown"}`,
        );
        tripoHealthLastLogAt = now;
      }
      return;
    }

    const toPoll = [...pendingTasks.values()];

    for (const entry of toPoll) {
      // Timeout check
      if (now - entry.startedAt > MAX_POLL_MS) {
        console.log(`[TaskRecovery] Task ${entry.taskId} timed out after ${MAX_POLL_MS / 1000}s`);
        const markedFailed = await markHistoryTaskFailed(entry, {
          failReason: "stale_recovery_timeout",
          taskStatus: "recovery_timeout",
          errorMessage: `No terminal Tripo status within ${MAX_POLL_MS / 1000}s`,
        });
        if (!markedFailed) continue;
        pendingTasks.delete(entry.taskId);
        clearTaskRecoveryStats(entry.taskId);
        continue;
      }

      try {
        const taskData = await getTripoClient().getTask(entry.taskId);
        noteTaskPollSuccess(entry.taskId);
        const status = normalizeTripoTaskStatus(taskData.status);

        if (status === "success") {
          const saved = await saveToHistory(entry, taskData);
          if (saved === false) continue;
          pendingTasks.delete(entry.taskId);
          clearTaskRecoveryStats(entry.taskId);
        } else if (isFailedLikeTripoTaskStatus(taskData.status)) {
          const markedFailed = await handleFailedTask(entry, taskData);
          if (!markedFailed) continue;
          pendingTasks.delete(entry.taskId);
          clearTaskRecoveryStats(entry.taskId);
          // "queued" or "running" — keep polling
        }
      } catch (err) {
        const erroredStats = noteTaskPollError(entry.taskId, err);
        console.error(`[TaskRecovery] Poll error for task ${entry.taskId}:`, err.message);

        if (erroredStats.consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
          console.warn(
            `[TaskRecovery] Task ${entry.taskId} exceeded max consecutive poll errors (${MAX_CONSECUTIVE_ERRORS}). Marking failed.`,
          );
          const markedFailed = await handleFailedTask(entry, {
            status: "recovery_poll_error_exhausted",
            error_message: err.message,
            rawOutput: null,
          });
          if (!markedFailed) continue;
          pendingTasks.delete(entry.taskId);
          clearTaskRecoveryStats(entry.taskId);
          continue;
        }

        if (consecutiveGlobalPollErrors >= GLOBAL_OUTAGE_ERROR_STREAK) {
          const healthy = await applyTripoHealthGuard(err);
          if (!healthy) break;
        }
      }
    }
  }, POLL_INTERVAL_MS);

  // Cleanup old entries periodically
  cleanupInterval = setInterval(async () => {
    const now = Date.now();
    for (const [taskId, entry] of pendingTasks) {
      if (now - entry.startedAt > MAX_POLL_MS) {
        console.log(`[TaskRecovery] Cleaning up timed-out task ${taskId}`);
        const markedFailed = await markHistoryTaskFailed(entry, {
          failReason: "stale_recovery_timeout",
          taskStatus: "recovery_timeout",
          errorMessage: `No terminal Tripo status within ${MAX_POLL_MS / 1000}s`,
        });
        if (!markedFailed) continue;
        pendingTasks.delete(taskId);
        clearTaskRecoveryStats(taskId);
      }
    }
    for (const [taskId, entry] of recentTaskMeta) {
      if (now - entry.startedAt > MAX_POLL_MS) {
        recentTaskMeta.delete(taskId);
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
  taskRecoveryStats.clear();
  consecutiveGlobalPollErrors = 0;
  tripoUnavailableUntil = 0;
  tripoHealthLastError = null;
  tripoHealthLastLogAt = 0;
  console.log("[TaskRecovery] Background task recovery stopped");
}

/* ─── Save completed task to Firestore history ────────────────────────── */
async function saveToHistory(entry, taskData) {
  const db = admin.firestore();
  const out = taskData.output ?? {};

  // prerigcheck only returns is_animatable — no model to save
  if (entry.type === "animate_prerigcheck") {
    console.log(`[TaskRecovery] prerigcheck task ${entry.taskId} completed (is_animatable=${out.is_animatable}) — no model to save`);
    return true;
  }

  const animatedModels = Array.isArray(out.animated_models) && out.animated_models.length > 0
    ? out.animated_models
    : null;
  const prefersTexturedOutput = entry.type === "texture_model" || entry.texture === true || entry.pbr === true;
  const prefersRetopoOutput = ["convert_model", "smart_low_poly"].includes(entry.type);
  const prefersDraftOutput = !prefersTexturedOutput && ["text_to_model", "image_to_model", "multiview_to_model", "refine_model"].includes(entry.type);
  const { modelUrl, chosenSource, previewImageUrl, previewImageUrls } = extractModelUrl(
    { output: out, type: entry.type },
    { preferBaseModel: prefersDraftOutput, preferPbrModel: prefersTexturedOutput, preferRetopoModel: prefersRetopoOutput },
  );
  if (DEBUG_TRIPO) console.log("[TaskRecovery] output selection:", JSON.stringify({
    taskId: entry.taskId,
    type: entry.type,
    prefersDraftOutput,
    prefersTexturedOutput,
    prefersRetopoOutput,
    chosenSource,
    modelUrl,
    availableOutputKeys: Object.keys(out),
  }, null, 2));

  if (!modelUrl) {
    console.warn(`[TaskRecovery] Task ${entry.taskId} (${entry.type}) succeeded but no model URL found in output:`, JSON.stringify(out));

    // For task types that should always produce a model URL, a missing URL at
    // "success" means delivery failed. Recovery records the failure only.
    if (MODEL_PRODUCING_TYPES.has(entry.type)) {
      const markedFailed = await markHistoryTaskFailed(entry, {
        failReason: "success_no_output",
        taskStatus: "success",
        errorMessage: "Tripo returned success without a downloadable model URL",
      });
      if (!markedFailed) return false;
      console.log(`[TaskRecovery] Refund skipped for task ${entry.taskId}: recovery cannot verify provider-side credit consumption`);
    }
    return true;
  }

  // Reuse pending history rows when they already exist for this task
  const existing = await db.collection(HISTORY_COLLECTION)
    .where("taskId", "==", entry.taskId)
    .where("userId", "==", entry.userId)
    .limit(1)
    .get();
  const existingDoc = existing.docs[0] ?? null;
  const existingData = existingDoc?.data() ?? null;

  const mode = TASK_TYPE_TO_MODE[entry.type] ?? "generate";
  const now = Date.now();
  const taskInput = taskData.input ?? taskData.request ?? {};

  const urlsToSave = animatedModels ?? [modelUrl];
  for (let i = 0; i < urlsToSave.length; i++) {
    const url = urlsToSave[i];
    if (!url) continue;
    const stableDocId = urlsToSave.length > 1 ? `tripo_${entry.taskId}_${i}` : `tripo_${entry.taskId}`;
    const targetRef = i === 0 && existingDoc
      ? existingDoc.ref
      : db.collection(HISTORY_COLLECTION).doc(stableDocId);
    await targetRef.set({
      userId: entry.userId,
      prompt: entry.prompt ?? existingData?.prompt ?? taskData.prompt ?? entry.type,
      status: "succeeded",
      model_url: url,
      source: existingData?.source ?? (entry.type === "import_model" ? "upload" : "tripo"),
      mode,
      taskId: entry.taskId,
      ...(urlsToSave.length > 1 && { animationIndex: i }),
      params: {
        ...(existingData?.params ?? {}),
        model_version: entry.modelVersion,
        mode,
        type: entry.type,
        texture: !!entry.texture,
        pbr: !!entry.pbr,
        chosen_source: chosenSource,
        consumed_credit: taskData.consumed_credit ?? out.consumed_credit ?? null,
        preview_image_url: previewImageUrl ?? null,
        preview_image_urls: previewImageUrls ?? [],
        originalModelTaskId: taskInput.original_model_task_id ?? taskInput.original_model_id ?? null,
        originalTaskId: taskInput.original_task_id ?? null,
        draftModelTaskId: taskInput.draft_model_task_id ?? null,
        model_seed: taskInput.model_seed ?? existingData?.params?.model_seed ?? null,
        image_seed: taskInput.image_seed ?? existingData?.params?.image_seed ?? null,
        texture_seed: taskInput.texture_seed ?? existingData?.params?.texture_seed ?? null,
        rig_type: out.rig_type ?? out.topology ?? null,
        topology: out.topology ?? null,
        is_animatable: out.is_animatable ?? out.animatable ?? out.riggable ?? null,
      },
      ts: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: now + HISTORY_TTL_MS,
    }, { merge: true });
  }
  console.log(`[TaskRecovery] Saved ${urlsToSave.length} model(s) for task ${entry.taskId} to history for user ${entry.userId}`);
  return true;
}

/* ─── Handle failed/cancelled task — record failure only ──────────────── */
async function handleFailedTask(entry, taskData) {
  const taskId = entry.taskId;
  const userId = entry.userId;
  const out = taskData.output ?? taskData.rawOutput ?? {};
  const taskError =
    taskData.error_msg ??
    taskData.error_message ??
    taskData.error ??
    taskData.message ??
    taskData.reason ??
    out.error_msg ??
    out.error_message ??
    out.error ??
    out.message ??
    out.reason ??
    null;
  const taskErrorCode =
    taskData.error_code ??
    taskData.code ??
    out.error_code ??
    out.code ??
    null;
  console.error(`[TaskRecovery] Task ${taskId} (${entry.type}) failed. error=${taskError ?? "unknown"} code=${taskErrorCode ?? "unknown"} rawOutput:`, JSON.stringify(taskData.rawOutput ?? taskData.output ?? {}));

  const markedFailed = await markHistoryTaskFailed(entry, {
    failReason: taskError || taskData.status || "unknown_failure",
    taskStatus: taskData.status ?? null,
    errorMessage: taskError,
    errorCode: taskErrorCode,
  });
  if (!markedFailed) return false;
  console.log(`[TaskRecovery] Refund skipped for task ${taskId}: recovery cannot verify provider-side credit consumption`);
  return true;
}

/* ─── Get pending task count (for debugging) ──────────────────────────── */
export function getPendingCount() {
  return pendingTasks.size;
}
