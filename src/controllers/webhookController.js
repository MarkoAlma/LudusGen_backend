// src/controllers/webhookController.js
import { webhookService } from "../services/webhookService.js";
import { findDebitTransactionForTask, refundCredits } from "../services/creditService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import admin from "firebase-admin";
import { storageService } from "../services/storageService.js";
import axios from "axios";
import { extractModelUrl } from "../utils/tripoUtils.js";
import { isFailedLikeTripoTaskStatus, normalizeTripoTaskStatus } from "../utils/tripoTaskStatus.js";
import { TASK_TYPE_TO_MODE, HISTORY_TTL_MS } from "../config/tripo.config.js";

// Task types that are expected to produce a downloadable model URL on success.
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

export function parseWebhookPayload(body, rawBody = null) {
  if (body && typeof body === "object" && !Buffer.isBuffer(body)) {
    return body;
  }

  const raw = Buffer.isBuffer(rawBody)
    ? rawBody
    : Buffer.isBuffer(body)
      ? body
      : null;

  if (!raw) {
    throw new Error("Invalid webhook payload");
  }

  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error("Invalid webhook JSON payload");
  }
}

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
    const payload = parseWebhookPayload(req.body, rawBody);
    if (!payload.task_id || !payload.status) {
      res.status(400).json({ success: false, message: "Invalid webhook payload: task_id and status required" });
      return;
    }

    // Acknowledge immediately — process async
    res.json({ success: true, received: true });

    const normalizedStatus = normalizeTripoTaskStatus(payload.status);

    if (normalizedStatus === "success") {
      // Task completed successfully — save to Firestore history automatically.
      // This ensures the model is preserved even if the user navigated away.
      await saveCompletedTaskToHistory(payload.task_id, payload);
    }

    // If task failed via webhook, trigger refund (webhook doesn't have userId,
    // so we look it up from credit_history)
    if (isFailedLikeTripoTaskStatus(payload.status)) {
      await processRefundForTask(payload.task_id, normalizedStatus, payload);
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

  // Look up userId from credit_history or the durable pending billing link map.
  const debit = await findDebitTransactionForTask(taskId);
  if (!debit) {
    console.log(`[WebhookController] No credit charge found for task ${taskId}, skipping history save`);
    return;
  }

  const data = debit.data;
  const userId = debit.userId;

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
  const taskInput = taskData.input ?? taskData.request ?? {};
  const taskType = payload.type ?? taskData.type;
  const preferTexturedOutput = taskType === "texture_model" || taskInput.texture === true || taskInput.pbr === true;
  const preferDraftOutput = !preferTexturedOutput && ["text_to_model", "image_to_model", "multiview_to_model", "refine_model"].includes(taskType);
  const { modelUrl, chosenSource, previewImageUrl, previewImageUrls } = extractModelUrl(
    { output: out, type: taskType },
    { preferBaseModel: preferDraftOutput, preferPbrModel: preferTexturedOutput },
  );


  if (!modelUrl) {
    console.warn(`[WebhookController] Task ${taskId} (type: ${taskType}) succeeded but no model URL found in output.`);

    // For model-producing task types, this means delivery failed — refund.
    if (MODEL_PRODUCING_TYPES.has(taskType)) {
      // Mark any pending history doc as failed.
      const failSnap = await db.collection(HISTORY_COLLECTION)
        .where("taskId", "==", taskId)
        .where("userId", "==", userId)
        .limit(1)
        .get();
      if (!failSnap.empty) {
        await failSnap.docs[0].ref.set(
          { status: "failed", failReason: "success_no_output" },
          { merge: true },
        );
      }
      try {
        await refundCredits(userId, data.amount, taskId, "webhook_success_no_output");
        console.log(`[WebhookController] Refunded ${data.amount} credits for task ${taskId} (success but no model URL)`);
      } catch (refundErr) {
        console.error(`[WebhookController] Refund failed for task ${taskId}:`, refundErr.message);
      }
    }
    return;
  }

  // Determine mode from task type (shared map from tripo.config.js)
  const mode = TASK_TYPE_TO_MODE[taskType] ?? "generate";

  const now = Date.now();

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
      type: taskType,
      texture: !!taskInput.texture,
      pbr: !!taskInput.pbr,
      chosen_source: chosenSource,
      preview_image_url: previewImageUrl ?? null,
      preview_image_urls: previewImageUrls ?? [],
      originalModelTaskId: taskInput.original_model_task_id ?? taskInput.original_model_id ?? null,
      draftModelTaskId: taskInput.draft_model_task_id ?? null,
      rig_type: out.rig_type ?? out.topology ?? null,
      topology: out.topology ?? null,
      is_animatable: out.is_animatable ?? out.animatable ?? out.riggable ?? null,
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

  // Look up userId from credit_history or the durable pending billing link map.
  const debit = await findDebitTransactionForTask(taskId);
  if (!debit) {
    console.log(`[WebhookController] No credit charge found for task ${taskId}, skipping refund`);
    return;
  }

  const data = debit.data;
  const userId = debit.userId;

  console.log(`[WebhookController] Processing refund for task ${taskId}, user ${userId}, amount ${data.amount}`);

  try {
    await refundCredits(userId, data.amount, taskId, `webhook_${status}`);
  } catch (err) {
    console.error(`[WebhookController] Refund failed for task ${taskId}:`, err.message);
  }
}
