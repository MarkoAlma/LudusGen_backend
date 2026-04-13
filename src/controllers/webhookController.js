// src/controllers/webhookController.js
import { webhookService } from "../services/webhookService.js";
import { refundCredits, hasBeenCharged } from "../services/creditService.js";
import admin from "firebase-admin";

export async function handleWebhook(req, res) {
  // Signature verification — raw body must be captured by express.raw() middleware
  const rawBody   = req.rawBody ?? Buffer.from(JSON.stringify(req.body));
  const sigHeader = (req.headers["x-tripo-signature"] ?? "");

  if (!webhookService.verifySignature(rawBody, sigHeader)) {
    console.warn("[WebhookController] invalid signature — rejecting");
    res.status(401).json({ success: false, message: "Invalid webhook signature" });
    return;
  }

  try {
    const payload = req.body;
    if (!payload.task_id || !payload.status) {
      res.status(400).json({ success: false, message: "Invalid webhook payload: task_id and status required" });
      return;
    }

    // Acknowledge immediately — process async
    res.json({ success: true, received: true });

    // If task failed via webhook, trigger refund (webhook doesn't have userId,
    // so we look it up from credit_history)
    if (["failed", "cancelled"].includes(payload.status)) {
      await processRefundForTask(payload.task_id, payload.status, payload);
    }

    await webhookService.handlePayload(payload);
  } catch (err) {
    console.error("[WebhookController] handleWebhook error:", err.message);
    // Already responded 200 above — nothing to do
  }
}

export async function testWebhook(req, res) {
  if (process.env.NODE_ENV === "production") {
    res.status(403).json({ success: false, message: "Test endpoint disabled in production" });
    return;
  }
  const { task_id = "test_task", status = "success" } = req.body;
  const { payload, signature } = webhookService.buildTestPayload(task_id, status);
  res.json({ success: true, payload, signature, pendingCallbacks: webhookService.pendingCount });
}

/**
 * Process a refund for a failed/cancelled task.
 * Looks up userId from credit_history by taskId.
 * Does NOT refund for NSFW/content policy failures.
 *
 * @param {string} taskId - Tripo task ID
 * @param {string} status - Task status ("failed" or "cancelled")
 * @param {object} payload - Full webhook payload
 */
async function processRefundForTask(taskId, status, payload) {
  // Check for NSFW/content policy — no refund
  const errorMsg = (payload.error_msg ?? payload.message ?? payload.reason ?? "").toLowerCase();
  if (errorMsg.includes("nsfw") || errorMsg.includes("content policy") || errorMsg.includes("safety") || errorMsg.includes("moderat")) {
    console.log(`[WebhookController] No refund for task ${taskId}: NSFW/content policy violation`);
    return;
  }

  // Look up userId from credit_history
  const db = admin.firestore();
  const snap = await db.collectionGroup("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "debit")
    .limit(1)
    .get();

  if (snap.empty) {
    console.log(`[WebhookController] No credit charge found for task ${taskId}, skipping refund`);
    return;
  }

  const doc = snap.docs[0];
  const data = doc.data();
  // The document path is: credit_history/{userId}/transactions/{txId}
  const userId = doc.ref.parent.parent.id;

  console.log(`[WebhookController] Processing refund for task ${taskId}, user ${userId}, amount ${data.amount}`);

  try {
    await refundCredits(userId, data.amount, taskId, `webhook_${status}`);
  } catch (err) {
    console.error(`[WebhookController] Refund failed for task ${taskId}:`, err.message);
  }
}