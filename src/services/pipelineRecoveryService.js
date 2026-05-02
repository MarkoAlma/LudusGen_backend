// src/services/pipelineRecoveryService.js
//
// Persists pipeline state to Firestore so that server restarts don't silently
// lose in-progress pipelines and leave users' credits unreturned.
//
// Lifecycle:
//   1. startPipeline()   — creates a "running" doc in Firestore
//   2. updatePipeline()  — updates step list + status during execution
//   3. On server boot:   recoverStalePipelines() marks any "running" docs
//      as "failed" and refunds each step's debited credits.

import admin from "firebase-admin";
import { findDebitTransactionForTask, refundCredits } from "./creditService.js";

const PIPELINE_COLLECTION = "tripo_pipelines";

// How long before a "running" pipeline is considered stale on boot (15 min).
// Pipelines that finish in < 15 min won't be wrongly refunded.
const STALE_THRESHOLD_MS = 15 * 60 * 1000;

// ─── Write helpers ────────────────────────────────────────────────────────────

export async function startPipeline({ pipelineId, userId, type, prompt }) {
  if (!pipelineId || !userId) return;
  try {
    await admin.firestore().collection(PIPELINE_COLLECTION).doc(pipelineId).set({
      pipelineId,
      userId,
      type,
      prompt: prompt ?? null,
      status: "running",
      steps: [],
      startedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.warn(`[PipelineRecovery] startPipeline write failed for ${pipelineId}:`, err.message);
  }
}

export async function updatePipeline(pipelineId, patch) {
  if (!pipelineId) return;
  try {
    await admin.firestore().collection(PIPELINE_COLLECTION).doc(pipelineId).update({
      ...patch,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.warn(`[PipelineRecovery] updatePipeline write failed for ${pipelineId}:`, err.message);
  }
}

export async function finishPipeline(pipelineId, { status, finalModelUrl = null, error = null } = {}) {
  if (!pipelineId) return;
  try {
    await admin.firestore().collection(PIPELINE_COLLECTION).doc(pipelineId).update({
      status,
      ...(finalModelUrl != null && { finalModelUrl }),
      ...(error != null && { error }),
      finishedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.warn(`[PipelineRecovery] finishPipeline write failed for ${pipelineId}:`, err.message);
  }
}

// ─── Boot-time recovery ───────────────────────────────────────────────────────

export async function recoverStalePipelines() {
  const db = admin.firestore();
  const cutoff = new Date(Date.now() - STALE_THRESHOLD_MS);

  let snap;
  try {
    snap = await db.collection(PIPELINE_COLLECTION)
      .where("status", "==", "running")
      .where("startedAt", "<=", cutoff)
      .get();
  } catch (err) {
    console.warn("[PipelineRecovery] Stale pipeline query failed:", err.message);
    return;
  }

  if (snap.empty) return;

  console.log(`[PipelineRecovery] Found ${snap.size} stale pipeline(s) — marking failed and refunding`);

  for (const doc of snap.docs) {
    const data = doc.data();
    const pipelineId = data.pipelineId;
    const userId = data.userId;

    // Mark failed
    try {
      await doc.ref.update({
        status: "failed",
        error: "server_restart",
        finishedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    } catch (err) {
      console.warn(`[PipelineRecovery] Failed to mark pipeline ${pipelineId} as failed:`, err.message);
    }

    // Refund every step that has a taskId
    const steps = Array.isArray(data.steps) ? data.steps : [];
    for (const step of steps) {
      if (!step.taskId) continue;
      try {
        const debit = await findDebitTransactionForTask(step.taskId, userId);
        if (debit) {
          await refundCredits(userId, debit.data.amount, step.taskId, `pipeline_crash_${step.type}`);
          console.log(`[PipelineRecovery] Refunded ${debit.data.amount} credits for step ${step.type} (task ${step.taskId}) in crashed pipeline ${pipelineId}`);
        }
      } catch (err) {
        console.error(`[PipelineRecovery] Refund failed for step ${step.type} task ${step.taskId}:`, err.message);
      }
    }
  }
}
