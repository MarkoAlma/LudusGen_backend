// src/controllers/webhookController.js
import { webhookService } from "../services/webhookService.js";
import { refundCredits, hasBeenCharged } from "../services/creditService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import admin from "firebase-admin";
import { storageService } from "../services/storageService.js";
import axios from "axios";

const HISTORY_COLLECTION = "tripo_history";

export async function handleWebhook(req, res) {
  // Signature verification — raw body must be captured by express.raw() middleware
  const rawBody = req.rawBody ?? Buffer.from(JSON.stringify(req.body));
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

    if (payload.status === "success") {
      // Task completed successfully — save to Firestore history automatically.
      // This ensures the model is preserved even if the user navigated away.
      await saveCompletedTaskToHistory(payload.task_id, payload);
    }

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

/**
 * Save a completed Tripo task to the user's Firestore history.
 * Looks up userId from credit_history, fetches full task details from Tripo,
 * and creates a history entry — same shape as the frontend saveHist function.
 *
 * @param {string} taskId - Tripo task ID
 * @param {object} payload - Webhook payload
 */
async function saveCompletedTaskToHistory(taskId, payload) {
  const db = admin.firestore();

  // Look up userId from credit_history
  const snap = await db.collectionGroup("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "debit")
    .limit(1)
    .get();

  if (snap.empty) {
    console.log(`[WebhookController] No credit charge found for task ${taskId}, skipping history save`);
    return;
  }

  const doc = snap.docs[0];
  const data = doc.data();
  const userId = doc.ref.parent.parent.id;

  // Check if history entry already exists (idempotency)
  const existing = await db.collection(HISTORY_COLLECTION)
    .where("taskId", "==", taskId)
    .where("userId", "==", userId)
    .limit(1)
    .get();

  if (!existing.empty) {
    console.log(`[WebhookController] History already exists for task ${taskId}, skipping`);
    return;
  }

  // Fetch full task details from Tripo to get model URL and params
  let taskData;
  try {
    taskData = await getTripoClient().getTask(taskId);
  } catch (err) {
    console.error(`[WebhookController] Failed to fetch task ${taskId} from Tripo:`, err.message);
    return;
  }

  const out = taskData.output ?? {};
  const modelUrl = out.model ?? out.pbr_model ?? out.base_model
    ?? out.rigged_model
    ?? (Array.isArray(out.animated_models) ? out.animated_models[0] : out.animated_model)
    ?? out.converted_model ?? out.low_poly_model
    ?? out.segmented_model ?? out.stylized_model ?? null;

  if (!modelUrl) {
    console.log(`[WebhookController] No model URL for completed task ${taskId}`);
    return;
  }

  // Determine mode from task type
  const typeMap = {
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
  const mode = typeMap[payload.type ?? taskData.type] ?? "generate";

  const now = Date.now();
  const HISTORY_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

  const taskInput = taskData.input ?? taskData.request ?? {};
  const docRef = await db.collection(HISTORY_COLLECTION).add({
    userId,
    prompt: taskData.prompt ?? payload.type ?? "3D Model",
    status: "succeeded",
    model_url: modelUrl,
    source: "tripo",
    mode,
    taskId,
    params: {
      model_version: taskData.model_version ?? "unknown",
      mode,
      type: taskData.type,
      ...(taskInput.texture === true && { texture: true }),
    },
    ts: now,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: now + HISTORY_TTL_MS,
  });

  const historyId = docRef.id;

  // ── Permanent Storage: Save to B2 ───────────────────────────────
  // We do this in the background after acknowledging the webhook
  (async () => {
    try {
      console.log(`[WebhookController] Downloading model from Tripo for task ${taskId}...`);
      const resp = await axios.get(modelUrl, { responseType: 'arraybuffer', timeout: 60000 });
      const buffer = Buffer.from(resp.data);
      
      const ext = modelUrl.split("?")[0].split(".").pop()?.toLowerCase() || "glb";
      const contentTypeMap = {
        glb: "model/gltf-binary",
        fbx: "application/octet-stream",
        obj: "text/plain",
        usdz: "model/vnd.usdz+zip",
      };
      const contentType = contentTypeMap[ext] || "application/octet-stream";
      
      const b2Key = `tripo/${taskId}.${ext}`;
      await storageService.uploadFile(buffer, b2Key, contentType);
      
      // Update history with B2 info
      await db.collection(HISTORY_COLLECTION).doc(historyId).update({
        b2_key: b2Key,
        // We keep model_url as a fallback, but we'll prefer b2_key in proxy
      });
      
      console.log(`[WebhookController] Task ${taskId} successfully archived to B2: ${b2Key}`);
    } catch (archiveErr) {
      console.error(`[WebhookController] Failed to archive task ${taskId} to B2:`, archiveErr.message);
    }
  })();

  console.log(`[WebhookController] Saved task ${taskId} to history for user ${userId}`);
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