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
import { findDebitTransactionForTask, refundCredits } from "./creditService.js";
import admin from "firebase-admin";
import { extractModelUrl } from "../utils/tripoUtils.js";
import { isFailedLikeTripoTaskStatus, normalizeTripoTaskStatus } from "../utils/tripoTaskStatus.js";
import { TASK_TYPE_TO_MODE, HISTORY_TTL_MS } from "../config/tripo.config.js";

// Task types that are expected to produce a downloadable model URL on success.
// If Tripo reports success but no URL is found, treat it as a billable failure
// (credit was already debited — refund and mark failed).
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


/** @type {Map<string, { taskId: string, userId: string, type: string, modelVersion: string, texture: boolean, pbr: boolean, startedAt: number }>} */
const pendingTasks = new Map();
const recentTaskMeta = new Map();


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
      },
    );
    restored += 1;
  }

  if (restored > 0) {
    console.log(`[TaskRecovery] Restored ${restored} pending history task(s) from Firestore`);
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
    startedAt: Date.now(),
  };
  pendingTasks.set(taskId, meta);
  recentTaskMeta.set(taskId, meta);
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
}

/* ─── Start the background poller ─────────────────────────────────────── */
let pollerInterval = null;
let cleanupInterval = null;

export function startTaskRecovery() {
  if (pollerInterval) return; // already running

  console.log("[TaskRecovery] Background task recovery started");
  restorePendingHistoryTasks().catch((err) => {
    console.error("[TaskRecovery] Failed to restore pending history tasks:", err.message);
  });

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
        const status = normalizeTripoTaskStatus(taskData.status);

        if (status === "success") {
          await saveToHistory(entry, taskData);
          pendingTasks.delete(entry.taskId);
        } else if (isFailedLikeTripoTaskStatus(taskData.status)) {
          await handleFailedTask(entry, taskData);
          pendingTasks.delete(entry.taskId);
          // "queued" or "running" — keep polling
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
  if (animatedModels && entry.type === "animate_retarget") {
    console.log(`[TaskRecovery] animate_retarget ${entry.taskId}: animated_models count=${animatedModels.length}`, animatedModels);
  }
  const prefersTexturedOutput = entry.type === "texture_model" || entry.texture === true || entry.pbr === true;
  const prefersDraftOutput = !prefersTexturedOutput && ["text_to_model", "image_to_model", "multiview_to_model", "refine_model"].includes(entry.type);
  const { modelUrl, chosenSource, previewImageUrl, previewImageUrls } = extractModelUrl(
    { output: out, type: entry.type },
    { preferBaseModel: prefersDraftOutput, preferPbrModel: prefersTexturedOutput },
  );
  if (DEBUG_TRIPO) console.log("[TaskRecovery] output selection:", JSON.stringify({
    taskId: entry.taskId,
    type: entry.type,
    prefersDraftOutput,
    prefersTexturedOutput,
    chosenSource,
    modelUrl,
    availableOutputKeys: Object.keys(out),
  }, null, 2));

  if (!modelUrl) {
    console.warn(`[TaskRecovery] Task ${entry.taskId} (${entry.type}) succeeded but no model URL found in output:`, JSON.stringify(out));

    // For task types that should always produce a model URL, a missing URL at
    // "success" means delivery failed. Refund the credit and mark the history
    // doc as failed so the user can see what happened.
    if (MODEL_PRODUCING_TYPES.has(entry.type)) {
      // Mark the pending history doc as failed (best-effort).
      const failSnap = await db.collection(HISTORY_COLLECTION)
        .where("taskId", "==", entry.taskId)
        .where("userId", "==", entry.userId)
        .limit(1)
        .get();
      if (!failSnap.empty) {
        await failSnap.docs[0].ref.set(
          { status: "failed", failReason: "success_no_output" },
          { merge: true },
        );
      }
      // Issue refund.
      const debit = await findDebitTransactionForTask(entry.taskId, entry.userId);
      if (debit) {
        try {
          await refundCredits(entry.userId, debit.data.amount, entry.taskId, "recovery_success_no_output");
          console.log(`[TaskRecovery] Refunded ${debit.data.amount} credits for task ${entry.taskId} (success but no model URL)`);
        } catch (refundErr) {
          console.error(`[TaskRecovery] Refund failed for task ${entry.taskId}:`, refundErr.message);
        }
      } else {
        console.warn(`[TaskRecovery] No debit found to refund for task ${entry.taskId}`);
      }
    }
    return;
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
}

/* ─── Handle failed/cancelled task — refund credits ───────────────────── */
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

  const debit = await findDebitTransactionForTask(taskId, userId);
  if (!debit) {
    console.log(`[TaskRecovery] No debit transaction found for failed task ${taskId}`);
    return;
  }
  const data = debit.data;

  // Check for NSFW/content policy — no refund
  const errorMsg = String(taskError ?? "").toLowerCase();
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
