// src/controllers/taskController.js
import { taskService } from "../services/taskService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { storageService } from "../services/storageService.js";
import { enqueueTripoTask, enqueueBatch } from "../workers/queues.js";
import { estimateCost } from "../lib/creditEstimator.js";
import { resolveEnginePreset } from "../lib/enginePresets.js";
import { refundCredits, hasBeenCharged, findDebitTransactionForTask } from "../services/creditService.js";
import {
  reserveCreditsForTask,
  refundCreditReservation,
  linkReservationToTask,
  getCreateFailureRefundReason,
} from "../services/tripoBillingService.js";
import { registerTask as registerForRecovery, unregisterTask, getRegisteredTaskMeta } from "../services/taskRecoveryService.js";
import {
  MARKETPLACE_COLLECTIONS,
  canAccessMarketplaceStorageKey,
  getVerifiedMarketplacePurchase,
} from "../services/marketplaceService.js";
import { DEFAULT_MODEL, VALID_MODEL_VERSIONS, MODEL_CAPABILITIES, DEFAULT_CAPABILITIES, HISTORY_TTL_MS, TRIPO_IMAGE_UPLOAD_MAX_BYTES } from "../config/tripo.config.js";
import { v4 as uuid } from "uuid";
import admin from "firebase-admin";
import { createHash } from "node:crypto";
import { registerJob, unregisterJob } from "../lib/jobRegistry.js";
import { getTaskLookupHttpStatus, isMissingTripoTaskError } from "../lib/tripoTaskErrors.js";
import { normalizeTripoTaskStatus } from "../utils/tripoTaskStatus.js";

const USE_QUEUE = process.env.USE_QUEUE === "true";
const DEBUG_TRIPO = process.env.DEBUG_TRIPO === "true";
// NOTE: existing docs with tripo_ prefixed IDs in 'trellis_history' need a one-time migration
const HISTORY_COLLECTION = "tripo_history";
const REFINE_DIRECT_SOURCE_TYPES = new Set(["text_to_model", "image_to_model", "multiview_to_model"]);
const REFINE_UPSTREAM_SOURCE_TYPES = new Set(["texture_model", "convert_model", "smart_low_poly", "stylize_model", "mesh_segmentation", "mesh_completion"]);
const TEXTURE_DIRECT_SOURCE_TYPES = new Set(["text_to_model", "image_to_model", "multiview_to_model", "texture_model", "import_model"]);
const TASK_TYPE_TO_MODE = {
  text_to_model: "generate",
  image_to_model: "generate",
  multiview_to_model: "generate",
  import_model: "upload",
  generate_image: "views",
  generate_multiview_image: "views",
  edit_multiview_image: "views",
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

function getHistoryModelVersion(data) {
  return data?.params?.model_version ||
    data?.params?.modelVersion ||
    data?.model_version ||
    data?.modelVersion ||
    data?.modelVer ||
    "";
}

function isRefineModelVersionSupported(version) {
  if (!version) return true;
  return String(version).toLowerCase().startsWith("v1.4");
}

function logDebug(label, payload) {
  if (!DEBUG_TRIPO) return;
  try {
    console.log(label, JSON.stringify(payload, null, 2));
  } catch {
    console.log(label, payload);
  }
}

function errorPayload(err, message = err.message) {
  return {
    success: false,
    message,
    ...(err.traceId && { tripoTraceId: err.traceId }),
    ...(err.code && { tripoCode: err.code }),
    ...(err.suggestion && { tripoSuggestion: err.suggestion }),
  };
}

function handleBillingErrorResponse(res, err) {
  if (err?.code === "INSUFFICIENT_CREDITS" || err?.code === "INSUFFICIENT_TRIPO_CREDITS") {
    return res.status(402).json({
      success: false,
      message: `Insufficient credits: ${err.available} available, ${err.required} required. Please top up your balance.`,
      code: "INSUFFICIENT_CREDITS",
    });
  }

  console.error("[TaskController] Billing reservation error:", err?.message || err);
  return res.status(500).json({
    success: false,
    message: "Credit reservation failed. Please try again.",
    code: "BILLING_RESERVATION_FAILED",
  });
}

async function refundUncreatedDirectBatchReservations(batchReservations, reason) {
  const refunds = [];
  for (const reservation of batchReservations || []) {
    if (reservation?.taskId) continue;
    refunds.push(refundCreditReservation(reservation, reason));
  }
  return Promise.allSettled(refunds);
}

function omitUndefined(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, value]) => value !== undefined));
}

function uniqueDocs(docs) {
  return Array.from(new Map(docs.filter(Boolean).map(d => [d.ref.path, d])).values());
}

function normalizeHistoryTaskKey(value) {
  const key = String(value || "").trim();
  return key.startsWith("tripo_") ? key.slice(6) : key;
}

async function getHistoryDocsByTaskKey(db, taskId) {
  const normalizedTaskId = normalizeHistoryTaskKey(taskId);
  if (!normalizedTaskId) return [];

  const collection = db.collection(HISTORY_COLLECTION);
  const docs = [];

  const prefixedDoc = await collection.doc(`tripo_${normalizedTaskId}`).get();
  if (prefixedDoc.exists) docs.push(prefixedDoc);

  if (String(taskId || "").trim() !== `tripo_${normalizedTaskId}`) {
    const directDoc = await collection.doc(String(taskId || "").trim()).get();
    if (directDoc.exists) docs.push(directDoc);
  }

  const taskSnap = await collection
    .where("taskId", "==", normalizedTaskId)
    .limit(25)
    .get();
  docs.push(...taskSnap.docs);

  if (String(taskId || "").trim() && String(taskId || "").trim() !== normalizedTaskId) {
    const rawTaskSnap = await collection
      .where("taskId", "==", String(taskId || "").trim())
      .limit(25)
      .get();
    docs.push(...rawTaskSnap.docs);
  }

  return uniqueDocs(docs);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isAllowedProxyHost(hostname, allowedHosts) {
  const normalizedHost = String(hostname || "").trim().toLowerCase();
  return allowedHosts.some((candidate) => {
    const normalizedCandidate = String(candidate || "").trim().toLowerCase();
    return normalizedHost === normalizedCandidate || normalizedHost.endsWith(`.${normalizedCandidate}`);
  });
}

function toMillis(value) {
  if (value == null) return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.getTime();
  if (typeof value?.toMillis === "function") {
    try {
      const millis = value.toMillis();
      return Number.isFinite(millis) ? millis : null;
    } catch {
      return null;
    }
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function getHistoryExpiryMillis(data) {
  if (!data || typeof data !== "object") return null;
  if (data.marketplaceLocked === true || data.marketplaceAssetId) return null;
  const explicitExpiry = toMillis(data.expiresAt);
  if (explicitExpiry != null) return explicitExpiry;

  const createdAt = toMillis(data.createdAt);
  if (createdAt != null) return createdAt + HISTORY_TTL_MS;

  const ts = toMillis(data.ts);
  if (ts != null) return ts + HISTORY_TTL_MS;

  return null;
}

async function userOwnsTask(taskId, uid) {
  if (!taskId || !uid) return false;
  const normalizedTaskId = normalizeHistoryTaskKey(taskId);
  const taskMeta = getRegisteredTaskMeta(normalizedTaskId) || getRegisteredTaskMeta(taskId);
  if (taskMeta?.userId === uid) return true;

  try {
    if (await hasBeenCharged(uid, normalizedTaskId)) return true;
    if (normalizedTaskId !== taskId && await hasBeenCharged(uid, taskId)) return true;
  } catch (err) {
    console.warn(`[TaskController] Credit ownership lookup failed for task ${taskId}:`, err.message);
  }

  const db = admin.firestore();
  const docs = await getHistoryDocsByTaskKey(db, taskId);
  return docs.some((doc) => doc.data()?.userId === uid);
}

async function requireTaskAccess(req, res, taskId = req.params.taskId) {
  const uid = req.user?.uid;
  if (!uid) {
    res.status(401).json({ success: false, message: "Unauthorized" });
    return false;
  }
  const allowed = await userOwnsTask(taskId, uid);
  if (!allowed) {
    res.status(403).json({ success: false, message: "Forbidden" });
    return false;
  }
  return true;
}

async function writePendingHistoryTask({
  taskId,
  userId,
  body = {},
  prompt = null,
}) {
  if (!taskId || !userId) return;

  const type = body.type ?? "unknown";
  const mode = TASK_TYPE_TO_MODE[type] ?? "generate";
  const now = Date.now();
  const params = omitUndefined({
    model_version: body.model_version ?? DEFAULT_MODEL,
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

  try {
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
  } catch (err) {
    console.warn(`[TaskController] Pending history write failed for task ${taskId}:`, err.message);
  }
}

async function deleteHistoryDocsWithStorage(docs, reason = "history_delete") {
  const cleanDocs = uniqueDocs(docs);
  if (cleanDocs.length === 0) return { deleted: 0, b2Deleted: 0, b2Failed: 0 };

  const b2Keys = [...new Set(cleanDocs.map(doc => doc.data()?.b2_key).filter(Boolean))];
  let b2Deleted = 0;
  let b2Failed = 0;
  for (const key of b2Keys) {
    const ok = await storageService.deleteFile(key);
    if (ok) b2Deleted += 1;
    else b2Failed += 1;
  }

  let deleted = 0;
  const db = admin.firestore();
  for (let i = 0; i < cleanDocs.length; i += 500) {
    const batch = db.batch();
    const slice = cleanDocs.slice(i, i + 500);
    slice.forEach(doc => batch.delete(doc.ref));
    await batch.commit();
    deleted += slice.length;
  }

  console.log(`[HistoryController] cleanup reason=${reason} docs=${deleted} b2Deleted=${b2Deleted} b2Failed=${b2Failed}`);
  return { deleted, b2Deleted, b2Failed };
}

async function deleteHistoryForDeadModel({ taskId, modelUrl, uid = null, reason = "dead_model" }) {
  const db = admin.firestore();
  const queries = [];

  if (taskId) {
    let q = db.collection(HISTORY_COLLECTION).where("taskId", "==", taskId);
    if (uid) q = q.where("userId", "==", uid);
    queries.push(q.get());
  }

  if (modelUrl) {
    let q = db.collection(HISTORY_COLLECTION).where("model_url", "==", modelUrl);
    if (uid) q = q.where("userId", "==", uid);
    queries.push(q.get());
  }

  if (queries.length === 0) return { deleted: 0, b2Deleted: 0, b2Failed: 0 };
  const snaps = await Promise.all(queries);
  return deleteHistoryDocsWithStorage(snaps.flatMap(snap => snap.docs), reason);
}

async function authorizeHistoryDocForModelProxy(doc, uid) {
  if (!doc || !uid) return null;
  const db = admin.firestore();
  const data = doc.data();
  if (data.marketplaceAssetId) {
    const assetDoc = await db.collection(MARKETPLACE_COLLECTIONS.assets).doc(data.marketplaceAssetId).get();
    if (!assetDoc.exists) return null;
    const assetData = assetDoc.data();
    const isMarketplaceAssetOwner = assetData.ownerId === uid;
    if (!isMarketplaceAssetOwner) {
      const purchase = await getVerifiedMarketplacePurchase(db, {
        buyerId: uid,
        assetId: data.marketplaceAssetId,
        asset: assetData,
      });
      if (!purchase) return null;
    }
  }

  if (data.b2_key) {
    const canRead = await canAccessMarketplaceStorageKey(db, {
      userId: uid,
      key: data.b2_key,
      assetId: data.marketplaceAssetId || null,
    });
    if (!canRead) return null;
  }

  return { doc, data };
}

async function getAuthorizedHistoryForModelProxy(taskId, uid, modelUrl = null) {
  if (!uid || (!taskId && !modelUrl)) return null;

  const db = admin.firestore();
  const candidates = [];

  if (taskId) {
    candidates.push(...await getHistoryDocsByTaskKey(db, taskId));
  }

  if (modelUrl) {
    const urlSnap = await db.collection(HISTORY_COLLECTION)
      .where("model_url", "==", modelUrl)
      .where("userId", "==", uid)
      .limit(10)
      .get();
    candidates.push(...urlSnap.docs);
  }

  const seenIds = new Set();
  const uniqueCandidates = candidates.filter((doc) => {
    if (!doc?.id || seenIds.has(doc.id)) return false;
    seenIds.add(doc.id);
    return true;
  });

  const exactUrlDoc = modelUrl
    ? uniqueCandidates.find((item) => item.data()?.userId === uid && item.data()?.model_url === modelUrl)
    : null;
  if (exactUrlDoc) {
    return authorizeHistoryDocForModelProxy(exactUrlDoc, uid);
  }

  const taskDoc = uniqueCandidates.find((item) => item.data()?.userId === uid);
  if (!taskDoc) return null;
  return authorizeHistoryDocForModelProxy(taskDoc, uid);
}

function collectHistoryPreviewImageUrls(historyData = {}) {
  const params = historyData.params ?? {};
  return [...new Set([
    ...(Array.isArray(historyData.previewImageUrls) ? historyData.previewImageUrls : []),
    ...(Array.isArray(historyData.preview_image_urls) ? historyData.preview_image_urls : []),
    ...(historyData.previewImageUrl ? [historyData.previewImageUrl] : []),
    ...(historyData.preview_image_url ? [historyData.preview_image_url] : []),
    ...(Array.isArray(params.previewImageUrls) ? params.previewImageUrls : []),
    ...(Array.isArray(params.preview_image_urls) ? params.preview_image_urls : []),
    ...(params.previewImageUrl ? [params.previewImageUrl] : []),
    ...(params.preview_image_url ? [params.preview_image_url] : []),
  ].filter(Boolean))];
}

async function buildArchivedTaskFallback(taskId, uid) {
  const authorizedHistory = await getAuthorizedHistoryForModelProxy(taskId, uid);
  if (!authorizedHistory) return null;

  const historyData = authorizedHistory.data ?? {};
  const params = historyData.params ?? {};
  const previewImageUrls = collectHistoryPreviewImageUrls(historyData);

  let modelUrl = historyData.model_url ?? null;
  if (historyData.b2_key) {
    try {
      const signedUrl = await storageService.getSignedUrl(historyData.b2_key);
      if (signedUrl) modelUrl = signedUrl;
    } catch (err) {
      console.warn(`[TaskController] archived task fallback B2 URL failed for ${taskId}:`, err.message);
    }
  }

  const normalizedStatus = historyData.status === "succeeded" ? "success" : (historyData.status ?? "success");
  return {
    success: true,
    status: normalizedStatus,
    progress: normalizedStatus === "success" ? 100 : 0,
    modelUrl,
    tripoTraceId: null,
    chosenSource: params.chosen_source ?? "history",
    rigCheckResult: params.is_animatable ?? null,
    rigType: params.rig_type ?? params.topology ?? null,
    topology: params.topology ?? null,
    previewImageUrl: previewImageUrls[0] ?? null,
    previewImageUrls,
    consumedCredit: params.consumed_credit ?? null,
    originalTaskId: params.originalTaskId ?? params.originalModelTaskId ?? params.draftModelTaskId ?? null,
    rawOutput: {
      model_url: modelUrl,
      preview_image_url: previewImageUrls[0] ?? null,
      preview_image_urls: previewImageUrls,
    },
    errorMessage: null,
    errorCode: null,
    archivedHistoryFallback: true,
  };
}

/* ─── Task: create (unified) ──────────────────────────────────────────── */
export async function createTask(req, res) {
  const { type, callback_url, idempotency_key, ...rest } = req.body;
  const userId = req.user?.uid;
  const jobId = req.body.jobId;
  const controller = new AbortController();
  let estimatedCost = 0;
  let creditReservation = null;
  let batchReservations = [];
  let tripoTaskCreated = false;

  try {
    if (jobId) {
      registerJob(jobId, controller, 1800000); // 30 min for 3D
    }

    let body = { type, ...rest };

    logDebug("[TaskController][create-debug] incoming req.body:", req.body);
    if (type === "refine_model") {
      logDebug("[TaskController][refine-debug] incoming request:", {
        userId,
        draft_model_task_id: body.draft_model_task_id ?? null,
        original_model_task_id: body.original_model_task_id ?? null,
        hasPrompt: typeof body.prompt === "string" && body.prompt.trim().length > 0,
        hasNegativePrompt: typeof body.negative_prompt === "string" && body.negative_prompt.trim().length > 0,
      });
    }
    
    // Normalize image inputs
    if (type === "image_to_model") {
      const imageInputs = Array.isArray(body.images)
        ? body.images
        : Array.isArray(body.batch_images)
          ? body.batch_images
          : [];

      if (imageInputs.length === 1) {
        // Normalize single image task
        const imageInput = imageInputs[0];
        body.file = typeof imageInput === "string" ? { type: "jpg", file_token: imageInput } : imageInput;
        delete body.images;
        delete body.batch_images;
      } else if (imageInputs.length > 1) {
        // Keep inputs for later splitting in this controller
        body.batch_images = imageInputs;
        delete body.images;
      }
    }
    logDebug("[TaskController][create-debug] normalized body:", body);

    if (type === "texture_model" && body.original_model_task_id) {
      try {
        const sourceTask = await getTripoClient().getTask(body.original_model_task_id);
        const sourceType = sourceTask?.type ?? null;
        const upstreamId =
          sourceTask?.input?.original_model_id ??
          sourceTask?.input?.original_model_task_id ??
          null;
        if (upstreamId && sourceType && !TEXTURE_DIRECT_SOURCE_TYPES.has(sourceType)) {
          console.log(`[TaskController][texture-source] Rewriting texture source ${body.original_model_task_id} (${sourceType}) -> ${upstreamId}`);
          body.original_model_task_id = upstreamId;
        }
      } catch (sourceErr) {
        console.warn(`[TaskController][texture-source] Failed to inspect source task ${body.original_model_task_id}:`, sourceErr.message);
      }
    }

    if (type === "refine_model" && userId) {
      const parentTaskId = body.original_model_task_id || body.draft_model_task_id;
      if (parentTaskId) {
        const db = admin.firestore();
        const snap = await db.collection(HISTORY_COLLECTION)
          .where("taskId", "==", parentTaskId)
          .limit(1)
          .get();
        if (!snap.empty) {
          const parentData = snap.docs[0].data();
          let effectiveParentData = parentData;
          const histType = parentData.params?.type;
          const upstreamTaskId =
            parentData.params?.originalModelTaskId ||
            parentData.params?.original_model_task_id ||
            parentData.params?.draftModelTaskId ||
            parentData.params?.draft_model_task_id ||
            null;
          const hasTexture = (
            parentData.mode === "texture" ||
            parentData.params?.mode === "texture" ||
            parentData.params?.type === "texture_model" ||
            parentData.params?.texture === true ||
            parentData.params?.texture === "true" ||
            parentData.params?.pbr === true ||
            parentData.params?.pbr === "true"
          );

          logDebug("[TaskController][refine-debug] pre-credit parent resolved:", {
            parentTaskId,
            parentMode: parentData.mode ?? null,
            parentType: histType ?? null,
            upstreamTaskId,
            hasTexture,
          });

          if (histType === "refine_model") {
            return res.status(400).json({
              success: false,
              message: "A már refine-olt modelleket nem lehet újra refine-olni.",
              code: "ALREADY_REFINED_SOURCE",
            });
          }

          if (
            upstreamTaskId &&
            (hasTexture ||
              REFINE_UPSTREAM_SOURCE_TYPES.has(histType) ||
              (histType && !REFINE_DIRECT_SOURCE_TYPES.has(histType)))
          ) {
            body.draft_model_task_id = upstreamTaskId;
            delete body.original_model_task_id;
            const upstreamSnap = await db.collection(HISTORY_COLLECTION)
              .where("taskId", "==", upstreamTaskId)
              .limit(1)
              .get();
            if (!upstreamSnap.empty) effectiveParentData = upstreamSnap.docs[0].data();
          } else if (histType && !REFINE_DIRECT_SOURCE_TYPES.has(histType)) {
            return res.status(400).json({
              success: false,
              message: `Ez a modell nem finomítható. A refine_model csak alap generálásból származó modellre alkalmazható. Forrástípus: ${histType}`,
              code: "UNSUPPORTED_REFINE_SOURCE",
            });
          }

          const sourceVersion = getHistoryModelVersion(effectiveParentData);
          if (!isRefineModelVersionSupported(sourceVersion)) {
            return res.status(400).json({
              success: false,
              message: `Refine csak Tripo v1.4 draft modellel működik. Ez a modell: ${sourceVersion}`,
              code: "UNSUPPORTED_REFINE_MODEL_VERSION",
            });
          }
        }
      }
    }

    // Estimate credit cost for this task
    taskService.validate(body);
    const estimateResult = estimateCost(body);
    estimatedCost = estimateResult.total;
    console.log(`[TaskController][create] type=${body.type} model=${body.model_version} base_cost=${estimateResult.breakdown.base} tex_addon=${estimateResult.breakdown.texture || 0} total_cost=${estimatedCost}`);
    console.log(`[TaskController] create type=${body.type} model=${body.model_version ?? "default"} cost=${estimatedCost}`);

    const isDirectImageBatch = !USE_QUEUE && body.type === "image_to_model" && Array.isArray(body.batch_images) && body.batch_images.length > 1;
    if (!isDirectImageBatch) {
      try {
        creditReservation = await reserveCreditsForTask({
          userId,
          amount: estimatedCost,
          taskType: type,
        });
      } catch (creditErr) {
        return handleBillingErrorResponse(res, creditErr);
      }
    }

    // ── Pre-Task Logic: Metadata Inheritance ──────────────────────────
    let inheritedPrompt = body.prompt || null;
    const parentTaskId = body.original_model_task_id || body.draft_model_task_id;

    if (parentTaskId && userId) {
      try {
        const db = admin.firestore();
        const snap = await db.collection(HISTORY_COLLECTION)
          .where("taskId", "==", parentTaskId)
          .limit(1)
          .get();

        if (!snap.empty) {
          const parentData = snap.docs[0].data();
          inheritedPrompt = parentData.prompt || null;

          // Special logic for animate_retarget/rig (Rig-aware presets)
          if (type === "animate_rig" || type === "animate_prerigcheck" || type === "animate_retarget") {
            const rigType = parentData.params?.rig_type || "biped";
            const version = parentData.params?.model_version || "";
            const isV1 = version.toLowerCase().startsWith("v1.") || version.includes("Turbo-v1.0");

            const anim = body.animation || (body.animations && body.animations[0]);
            if (anim && !anim.startsWith("preset:")) {
              let formattedAnim;
              if (rigType === "biped" || rigType === "quadruped" || isV1) {
                formattedAnim = `preset:${rigType}:${anim}`;
              } else {
                formattedAnim = `preset:${anim}`;
              }
              console.log(`[TaskController] Formatted ${type} animation: ${formattedAnim} (ver=${version}, rig=${rigType})`);
              if (body.animations) {
                body.animations = body.animations.map(a => a.startsWith("preset:") ? a : (rigType === "biped" || rigType === "quadruped" || isV1 ? `preset:${rigType}:${a}` : `preset:${a}`));
              } else {
                body.animation = formattedAnim;
              }
            }
          }

          // Refine source validation
          if (type === "refine_model") {
            let effectiveParentData = parentData;
            const histType = parentData.params?.type;
            const upstreamTaskId =
              parentData.params?.originalModelTaskId ||
              parentData.params?.original_model_task_id ||
              parentData.params?.draftModelTaskId ||
              parentData.params?.draft_model_task_id ||
              null;
            const hasTexture = (
              parentData.mode === "texture" ||
              parentData.params?.mode === "texture" ||
              parentData.params?.type === "texture_model" ||
              parentData.params?.texture === true ||
              parentData.params?.texture === "true" ||
              parentData.params?.pbr === true ||
              parentData.params?.pbr === "true"
            );
            logDebug("[TaskController][refine-debug] parent resolved:", {
              parentTaskId,
              parentMode: parentData.mode ?? null,
              parentType: histType ?? null,
              parentTexture: parentData.params?.texture ?? null,
              parentPbr: parentData.params?.pbr ?? null,
              upstreamTaskId,
              hasTexture,
            });
            if (histType === "refine_model") {
              await refundCreditReservation(creditReservation, "already_refined_source");
              return res.status(400).json({
                success: false,
                message: "A már refine-olt modelleket nem lehet újra refine-olni.",
                code: "ALREADY_REFINED_SOURCE",
              });
            }
            if (
              upstreamTaskId &&
              (hasTexture ||
                REFINE_UPSTREAM_SOURCE_TYPES.has(histType) ||
                (histType && !REFINE_DIRECT_SOURCE_TYPES.has(histType)))
            ) {
              logDebug("[TaskController][refine-debug] rewriting source:", {
                from: parentTaskId,
                histType: histType ?? "unknown",
                to: upstreamTaskId,
              });
              body.draft_model_task_id = upstreamTaskId;
              delete body.original_model_task_id;
              const upstreamSnap = await db.collection(HISTORY_COLLECTION)
                .where("taskId", "==", upstreamTaskId)
                .limit(1)
                .get();
              if (!upstreamSnap.empty) effectiveParentData = upstreamSnap.docs[0].data();
            }
            if (histType && !REFINE_DIRECT_SOURCE_TYPES.has(histType) && !upstreamTaskId) {
              await refundCreditReservation(creditReservation, "unsupported_refine_source");
              return res.status(400).json({
                success: false,
                message: `Ez a modell nem finomítható. A refine_model csak alap generálásból származó modellre alkalmazható. Forrástípus: ${histType}`,
                code: "UNSUPPORTED_REFINE_SOURCE",
              });
            }
            const sourceVersion = getHistoryModelVersion(effectiveParentData);
            if (!isRefineModelVersionSupported(sourceVersion)) {
              await refundCreditReservation(creditReservation, "unsupported_refine_model_version");
              return res.status(400).json({
                success: false,
                message: `Refine csak Tripo v1.4 draft modellel működik. Ez a modell: ${sourceVersion}`,
                code: "UNSUPPORTED_REFINE_MODEL_VERSION",
              });
            }
          }
        } else if (type === "animate_retarget") {
          const defaultRigType = "biped";
          if (body.animations?.length > 0) {
            body.animations = body.animations.map(a =>
              a.startsWith("preset:") ? a : `preset:${defaultRigType}:${a}`
            );
            delete body.animation;
          } else if (body.animation && !body.animation.startsWith("preset:")) {
            body.animation = `preset:${defaultRigType}:${body.animation}`;
          }
        } else if (type === "refine_model") {
          logDebug("[TaskController][refine-debug] parent task was not found in history", {
            parentTaskId,
            userId,
          });
        }
      } catch (err) {
        console.warn(`[TaskController] Parent metadata lookup failed:`, err.message);
      }
    }
    // Extra logging for animate_retarget to verify request structure
    if (type === "animate_retarget") {
      console.log(`[TaskController] animate_retarget request validation:`, {
        original_model_task_id: body.original_model_task_id,
        animation: body.animation,
        animations: body.animations,
        out_format: body.out_format ?? "glb",
        bake_animation: body.bake_animation ?? true,
        export_with_geometry: body.export_with_geometry ?? true,
        animate_in_place: body.animate_in_place ?? false,
      });
    }
    if (type === "refine_model") {
      logDebug("[TaskController][refine-debug] validated body before taskService.create:", {
        draft_model_task_id: body.draft_model_task_id ?? null,
        original_model_task_id: body.original_model_task_id ?? null,
        prompt: body.prompt ?? null,
        negative_prompt: body.negative_prompt ?? null,
      });
    }
    logDebug("[TaskController][create-debug] final body before create:", body);

    if (USE_QUEUE) {
      if (body.batch_images && body.batch_images.length > 1) {
        const { batch_images, ...common } = body;
        const items = batch_images.map(token => ({
          jobType: "single",
          taskBody: {
            ...common,
            file: typeof token === "string" ? { type: "jpg", file_token: token } : token,
          },
          userId,
          callbackUrl: callback_url,
          idempotencyKey: uuid(),
        }));
        const jobIds = await enqueueBatch(items);
        res.json({ success: true, queued: true, jobIds });
      } else {
        const jobId = await enqueueTripoTask({
          jobType: "single",
          taskBody: body,
          userId,
          callbackUrl: callback_url,
          idempotencyKey: idempotency_key ?? uuid(),
        });
        res.json({ success: true, queued: true, jobId });
      }
    } else {
      // Sequential/Direct execution
      if (body.batch_images && body.batch_images.length > 1) {
        const { batch_images, ...common } = body;
        const taskIds = [];
        const directBatchPlans = [];
        for (const token of batch_images) {
          const subBody = {
            ...common,
            file: typeof token === "string" ? { type: "jpg", file_token: token } : token,
          };
          const subEstimate = estimateCost(subBody);
          const subReservation = await reserveCreditsForTask({
            userId,
            amount: subEstimate.total,
            taskType: subBody.type,
          });
          batchReservations.push(subReservation);
          directBatchPlans.push({ subBody, subReservation });
        }
        for (const plan of directBatchPlans) {
          const { subBody, subReservation } = plan;
          const taskId = await taskService.create(subBody, {
            callbackUrl: callback_url,
            idempotencyKey: uuid(),
            signal: controller.signal,
          });
          tripoTaskCreated = true;
          await linkReservationToTask(subReservation, taskId);
          if (userId) {
            await writePendingHistoryTask({
              taskId,
              userId,
              body: subBody,
              prompt: inheritedPrompt,
            });
            registerForRecovery(taskId, userId, subBody.type, subBody.model_version ?? DEFAULT_MODEL, inheritedPrompt, {
              texture: subBody.texture === true,
              pbr: subBody.pbr === true,
            });
          }
          taskIds.push(taskId);
        }
        res.json({ success: true, taskIds });
      } else {
        const taskId = await taskService.create(body, {
          callbackUrl: callback_url,
          idempotencyKey: idempotency_key,
          signal: controller.signal,
        });
        tripoTaskCreated = true;

        await linkReservationToTask(creditReservation, taskId);

        // Register for background recovery with inherited prompt
        if (userId) {
          await writePendingHistoryTask({
            taskId,
            userId,
            body,
            prompt: inheritedPrompt,
          });
          registerForRecovery(taskId, userId, body.type, body.model_version ?? DEFAULT_MODEL, inheritedPrompt, {
            texture: body.texture === true,
            pbr: body.pbr === true,
          });
        }
        res.json({ success: true, taskId });
      }
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      return res.status(499).json({ success: false, message: "Folyamat megszakítva" });
    }
    console.error(`[TaskController] create error:`, err.message);
    logDebug("[TaskController][create-debug] error context:", {
      type,
      userId,
      estimatedCost,
      creditsDeducted: Boolean(creditReservation?.creditsDeducted || batchReservations.some((reservation) => reservation?.creditsDeducted)),
      requestBody: req.body,
      error: err.message,
    });

    const refundDeductedCredits = async (reason) => {
      try {
        if (batchReservations.length > 0) {
          await refundUncreatedDirectBatchReservations(batchReservations, reason);
          return;
        }
        if (!tripoTaskCreated) {
          await refundCreditReservation(creditReservation, reason);
        }
      } catch (refundErr) {
        console.error(`[TaskController] Refund error (${reason}):`, refundErr.message);
      }
    };

    // Tripo 403 = insufficient credit → refund the locally deducted amount
    if (err.message?.includes("403") && err.message?.includes("credit")) {
      if (userId && estimatedCost > 0) {
        console.log(`[TaskController] Tripo returned 403 credit error — refunding ${estimatedCost} credits to user ${userId}`);
        await refundDeductedCredits("tripo_403_insufficient_credit");
      }
    }

    // Tripo 1004 on refine_model = model has no draft output (was generated with texture, or wrong task type)
    let userMessage = err.message;
    if (type === "refine_model" && err.message?.includes("1004")) {
      if (userId && estimatedCost > 0) {
        await refundDeductedCredits("refine_no_draft_output");
      }
      userMessage = "Ez a modell nem finomítható. A Refine csak textúra nélkül generált (draft) modelleknél működik. Generálj új modellt textúra nélkül, majd alkalmazd rá a Refine-t.";
    }

    if (type === "texture_model" && err.message?.startsWith("Invalid texture model_version")) {
      userMessage = "Ez a texture modellverzio jelenleg nem tamogatott. Valassz V3.0, V2.5 vagy V2.0 texture modellt, majd probald ujra.";
    } else if (type === "texture_model" && err.message?.includes('texture_quality "detailed" requires')) {
      userMessage = "A 4K/detailed texture csak V3.0 texture modellel futtathato. Kapcsold V3.0-ra, majd probald ujra.";
    } else if (type === "texture_model" && err.code === 1004) {
      userMessage = "A Tripo nem fogadta el a texture pass parametereit. Ellenorizd a texture targetet es a referencia kepet, majd probald ujra.";
    }

    await refundDeductedCredits(getCreateFailureRefundReason(type, err));

    res.status(400).json(errorPayload(err, userMessage));
  } finally {
    unregisterJob(jobId);
  }
}

/* ─── Task: get status ────────────────────────────────────────────────── */
export async function getTask(req, res) {
  try {
    if (!await requireTaskAccess(req, res)) return;
    const taskMeta = getRegisteredTaskMeta(req.params.taskId);
    const preferTexturedOutput = taskMeta?.type === "texture_model" || taskMeta?.texture === true || taskMeta?.pbr === true;
    const preferDraftOutput = !preferTexturedOutput && ["text_to_model", "image_to_model", "multiview_to_model", "refine_model"].includes(taskMeta?.type);
    logDebug("[TaskController][getTask-debug] request:", {
      taskId: req.params.taskId,
      taskMeta,
      preferTexturedOutput,
      preferDraftOutput,
    });
    const result = await taskService.get(req.params.taskId, {
      preferBaseModel: preferDraftOutput,
      preferPbrModel: preferTexturedOutput,
    });
    logDebug("[TaskController][getTask-debug] result:", {
      taskId: req.params.taskId,
      status: result.status ?? null,
      progress: result.progress ?? null,
      modelUrl: result.modelUrl ?? null,
      errorMessage: result.errorMessage ?? null,
      errorCode: result.errorCode ?? null,
      outputKeys: Object.keys(result.rawOutput ?? {}),
      rawOutput: result.rawOutput ?? null,
    });
    // FIX: result.success-t kivesszük, hogy ne írja felül a success: true-t
    const { success: _ignored, ...taskData } = result;
    res.json({ success: true, ...taskData });
  } catch (err) {
    console.error("[TaskController] getTask error:", err.message);
    const status = getTaskLookupHttpStatus(err);
    if (status === 410) {
      const archivedFallback = await buildArchivedTaskFallback(req.params.taskId, req.user?.uid ?? null);
      if (archivedFallback) {
        console.log(`[TaskController] getTask served archived history fallback for ${req.params.taskId}`);
        res.json(archivedFallback);
        return;
      }
    }
    res.status(status).json(
      errorPayload(err, status === 410 ? "Task expired or deleted from source" : err.message),
    );
  }
}

export async function streamTask(req, res) {
  const taskId = req.params.taskId;
  if (!taskId) {
    res.status(400).json({ success: false, message: "taskId required" });
    return;
  }
  if (!await requireTaskAccess(req, res, taskId)) return;

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  let closed = false;
  req.on("close", () => {
    closed = true;
  });

  const send = (event, payload) => {
    if (closed) return;
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(payload)}\n\n`);
  };

  send("connected", { success: true, taskId, ts: Date.now() });

  try {
    while (!closed) {
      const taskMeta = getRegisteredTaskMeta(taskId);
      const preferTexturedOutput = taskMeta?.type === "texture_model" || taskMeta?.texture === true || taskMeta?.pbr === true;
      const preferDraftOutput = !preferTexturedOutput && ["text_to_model", "image_to_model", "multiview_to_model", "refine_model"].includes(taskMeta?.type);
      const result = await taskService.get(taskId, {
        preferBaseModel: preferDraftOutput,
        preferPbrModel: preferTexturedOutput,
      });
      const { success: _ignored, ...taskData } = result;
      send("status", { success: true, ...taskData, ts: Date.now() });

      if (["success", "failed", "cancelled"].includes(result.status)) break;
      await delay(2_500);
    }
  } catch (err) {
    if (isMissingTripoTaskError(err)) {
      send("status", {
        success: true,
        status: "failed",
        progress: 100,
        errorMessage: "Task expired or deleted from source",
        errorCode: "TASK_NOT_FOUND",
        ts: Date.now(),
      });
    } else {
      send("error", errorPayload(err));
    }
  } finally {
    if (!closed) {
      res.end();
    }
  }
}

/* ─── Task: cancel ────────────────────────────────────────────────────── */
export async function cancelTask(req, res) {
  try {
    if (!await requireTaskAccess(req, res)) return;

    const { taskId } = req.params;
    const userId = req.user?.uid;

    // Fetch current task status BEFORE cancelling.
    // Refund only if the task is still "queued" — Tripo hasn't started
    // processing it yet so their side hasn't debited their credits either.
    let statusBeforeCancel = null;
    try {
      const currentTask = await getTripoClient().getTask(taskId);
      statusBeforeCancel = normalizeTripoTaskStatus(currentTask?.status ?? "");
    } catch (fetchErr) {
      console.warn(`[TaskController] cancelTask: could not fetch status for ${taskId}:`, fetchErr.message);
      // Status unknown — proceed with cancel but skip refund to be safe.
    }

    const result = await taskService.cancel(taskId);

    if (statusBeforeCancel === "queued" && userId) {
      // Task was still queued — Tripo hadn't started billing. Refund the user.
      try {
        const debit = await findDebitTransactionForTask(taskId, userId);
        if (debit?.data?.amount > 0) {
          await refundCredits(userId, debit.data.amount, taskId, "cancel_while_queued");
          console.log(`[TaskController] Refunded ${debit.data.amount} credits for queued task ${taskId} (user ${userId})`);
        }
      } catch (refundErr) {
        console.error(`[TaskController] Refund after cancel failed for task ${taskId}:`, refundErr.message);
      }
    } else if (statusBeforeCancel && statusBeforeCancel !== "queued") {
      console.log(`[TaskController] Task ${taskId} was already ${statusBeforeCancel} when cancelled — no refund (Tripo credits consumed)`);
    }

    res.json({ success: true, cancelled: result.cancelled, message: result.message });
  } catch (err) {
    console.warn("[TaskController] cancelTask:", err.message);
    res.json({ success: false, cancelled: false, message: err.message });
  }
}

export async function acknowledgeTask(req, res) {
  try {
    const { taskId } = req.params;
    if (!taskId) return res.status(400).json({ success: false, message: "taskId required" });
    if (!await requireTaskAccess(req, res, taskId)) return;
    unregisterTask(taskId);
    res.json({ success: true, unregistered: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
}

/* ─── Task: list ──────────────────────────────────────────────────────── */
export async function listTasks(req, res) {
  try {
    const status = req.query.status;
    const limit = req.query.limit ? parseInt(req.query.limit, 10) : 20;
    const cursor = req.query.cursor;

    const VALID_STATUSES = ["queued", "running", "success", "failed", "cancelled"];
    if (status && !VALID_STATUSES.includes(status)) {
      res.status(400).json({ success: false, message: `Invalid status. Valid: ${VALID_STATUSES.join(", ")}` });
      return;
    }

    const result = await taskService.list({ status, limit, cursor });
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[TaskController] listTasks error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}

/* ─── Balance ─────────────────────────────────────────────────────────── */
export async function getBalance(req, res) {
  try {
    const client = getTripoClient();
    const data = await client.getBalance();
    res.json({ success: true, ...data });
  } catch (err) {
    console.error("[TaskController] balance error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}

/* ─── Upload ──────────────────────────────────────────────────────────── */
export async function uploadFile(req, res) {
  const file = req.file;
  if (!file) { res.status(400).json({ success: false, message: "File missing" }); return; }

  if (file.size > TRIPO_IMAGE_UPLOAD_MAX_BYTES) {
    res.status(400).json({ success: false, message: `File too large. Maximum size: ${TRIPO_IMAGE_UPLOAD_MAX_BYTES / (1024 * 1024)}MB` });
    return;
  }

  const allowed = ["image/jpeg", "image/png", "image/webp"];
  if (!allowed.includes(file.mimetype)) {
    res.status(400).json({ success: false, message: "Only JPG/PNG/WEBP allowed" });
    return;
  }

  try {
    const client = getTripoClient();
    const imageToken = await client.uploadFile(file.buffer, file.originalname || "image.jpg", file.mimetype);
    console.log(`[TaskController] uploaded image token: ${imageToken.slice(0, 12)}…`);
    // FIX: volt itt egy setImgToken(d.imageToken) — az React frontend kód, nem ide való
    res.json({ success: true, imageToken });
  } catch (err) {
    console.error("[TaskController] upload error:", err.message);
    res.status(500).json(errorPayload(err));
  }
}

/* ─── Model proxy ─────────────────────────────────────────────────────── */

// pre-signed URLs expire after a few hours, so we cache the fetched blob
// keyed by taskId. Entries are evicted after 6 hours (TTL).
const MODEL_CACHE = new Map();
const MODEL_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const MODEL_IN_FLIGHT = new Map();

// Track tasks that Tripo reports as 404 (deleted/expired).
// We cache these for 1 hour to avoid repeated expensive refresh attempts
// for "dead" models.
const REFRESH_FAILURE_CACHE = new Map();
const REFRESH_FAILURE_TTL_MS = 1 * 60 * 60 * 1000;

// Periodic cleanup of stale cache entries (every 30 min)
let _cacheCleanupTimer = null;
function startCacheCleanup() {
  if (_cacheCleanupTimer) return;
  _cacheCleanupTimer = setInterval(() => {
    const now = Date.now();
    let cleanedModel = 0;
    for (const [key, entry] of MODEL_CACHE.entries()) {
      if (now - entry.cachedAt > MODEL_CACHE_TTL_MS) {
        MODEL_CACHE.delete(key);
        cleanedModel++;
      }
    }
    let cleanedFailure = 0;
    for (const [key, timestamp] of REFRESH_FAILURE_CACHE.entries()) {
      if (now - timestamp > REFRESH_FAILURE_TTL_MS) {
        REFRESH_FAILURE_CACHE.delete(key);
        cleanedFailure++;
      }
    }
    if (cleanedModel > 0 || cleanedFailure > 0) {
      console.log(`[TaskController] cache cleanup: removed ${cleanedModel} models, ${cleanedFailure} dead marks`);
    }
  }, 30 * 60 * 1000);
  _cacheCleanupTimer.unref?.();
}
startCacheCleanup();

function storageKeyFromB2Url(parsedUrl) {
  const bucket = process.env.B2_BUCKET_NAME;
  const pathParts = parsedUrl.pathname.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
  if (bucket && pathParts[0] === bucket) return pathParts.slice(1).join("/");
  return pathParts.join("/");
}

function isModelProxyArchiveEnabled() {
  return ["B2_ENDPOINT", "B2_KEY_ID", "B2_APP_KEY", "B2_BUCKET_NAME"]
    .every((name) => Boolean(process.env[name]?.trim?.()));
}

function safeArchivePathPart(value, fallback) {
  return String(value || fallback)
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96) || fallback;
}

function buildModelProxyArchiveKey({ requesterId, taskId, sourceUrl, ext }) {
  const hash = createHash("sha1").update(`${taskId || ""}|${sourceUrl || ""}`).digest("hex").slice(0, 12);
  const safeUid = safeArchivePathPart(requesterId, "user");
  const safeTaskId = safeArchivePathPart(taskId, hash);
  const safeExt = safeArchivePathPart(ext, "glb").toLowerCase();
  return `tripo/${safeUid}/${safeTaskId}_${hash}.${safeExt}`;
}

async function archiveModelProxyFetch({
  authorizedHistory,
  requesterId,
  taskId,
  sourceUrl,
  buffer,
  contentType,
  ext,
}) {
  if (!isModelProxyArchiveEnabled()) return;
  if (!authorizedHistory?.doc?.ref || authorizedHistory.data?.b2_key) return;
  if (!taskId || !buffer?.length) return;

  const key = buildModelProxyArchiveKey({ requesterId, taskId, sourceUrl, ext });
  try {
    await storageService.uploadFile(buffer, key, contentType);
    await authorizedHistory.doc.ref.update({
      b2_key: key,
      archivedAt: admin.firestore.FieldValue.serverTimestamp(),
      archiveSource: "model_proxy",
    });
    console.log(`[TaskController] modelProxy archived task ${taskId} to ${key}`);
  } catch (err) {
    console.warn(`[TaskController] modelProxy archive failed for ${taskId}:`, err.message);
  }
}

export async function modelProxy(req, res) {
  let { url, taskId: taskIdParam } = req.query;
  const requesterId = req.user?.uid;
  let requestCacheKey;
  let rejectInFlight = null;

  if (!url) { res.status(400).json({ success: false, message: "url missing" }); return; }

  const allowedHosts = [
    "tripo3d.ai",
    "tripo3d.com",
    "cdn.tripo3d.ai",
    "cdn.tripo3d.com",
    "assets.tripo3d.ai",
    "assets.tripo3d.com",
    "data.tripo3d.com",
  ];
  let b2Host = null;
  try {
    b2Host = process.env.B2_ENDPOINT ? new URL(process.env.B2_ENDPOINT).hostname : null;
    if (b2Host) allowedHosts.push(b2Host);
  } catch {
    // Ignore malformed optional B2 endpoint; Tripo hosts are still enforced.
  }

  // Inner helper to perform the actual fetch
  const performFetch = async (targetUrl) => {
    let parsed;
    try { parsed = new URL(targetUrl); } catch {
      return { error: 400, message: "Invalid URL" };
    }

    if (!isAllowedProxyHost(parsed.hostname, allowedHosts)) {
      return { error: 400, message: "Source not allowed" };
    }

    if (b2Host && parsed.hostname.endsWith(b2Host)) {
      const key = storageKeyFromB2Url(parsed);
      const canRead = await canAccessMarketplaceStorageKey(admin.firestore(), {
        userId: requesterId,
        key,
      });
      if (!canRead) return { error: 403, message: "Forbidden" };
    }

    const apiKey = process.env.TRIPO3D_API_KEY;
    const isPresigned = parsed.searchParams.has('Signature') || parsed.searchParams.has('Policy')
      || parsed.searchParams.has('X-Amz-Signature') || parsed.hostname.includes('tripo-data');
    const fetchHeaders = isPresigned ? {} : { Authorization: `Bearer ${apiKey}` };

    const upstream = await fetch(targetUrl, {
      headers: fetchHeaders,
      signal: AbortSignal.timeout(30_000),
    });

    if (!upstream.ok) {
      return { error: upstream.status, upstream };
    }
    return { upstream };
  };

  try {
    let authorizedHistory = null;
    if (taskIdParam) {
      authorizedHistory = await getAuthorizedHistoryForModelProxy(taskIdParam, requesterId, url);
      if (!authorizedHistory) {
        res.status(403).json({ success: false, message: "Forbidden" });
        return;
      }
    }

    const sendModelEntry = (entry, cacheHeader = "HIT") => {
      res.setHeader("Content-Type", entry.contentType);
      res.setHeader("Content-Disposition", `attachment; filename="model.${entry.ext}"`);
      res.setHeader("Content-Length", entry.buffer.length);
      res.setHeader("X-Cache", cacheHeader);
      res.end(entry.buffer);
    };

    // Read entire model binary into a Buffer (for caching)
    const readBody = async (upstream) => {
      const chunks = [];
      for await (const chunk of upstream.body) chunks.push(chunk);
      return Buffer.concat(chunks);
    };

    // ── Cache hit ──────────────────────────────────────────────────────
    if (taskIdParam && MODEL_CACHE.has(taskIdParam)) {
      const entry = MODEL_CACHE.get(taskIdParam);
      if (Date.now() - entry.cachedAt < MODEL_CACHE_TTL_MS) {
        sendModelEntry(entry, "HIT");
        return;
      }
      MODEL_CACHE.delete(taskIdParam); // expired
    }

    // ── Permanent Storage: Check B2 first ─────────────────────────────
    if (taskIdParam) {
      try {
        const histData = authorizedHistory?.data;
        if (histData?.b2_key) {
          console.log(`[TaskController] modelProxy: found B2 key ${histData.b2_key} for task ${taskIdParam}`);
          const b2Url = await storageService.getSignedUrl(histData.b2_key);
          if (b2Url) {
            url = b2Url; // Use B2 URL instead of Tripo URL
          }
        }
      } catch (fsErr) {
        console.warn(`[TaskController] modelProxy: B2 lookup failed:`, fsErr.message);
      }
    }

    // ── Fetch from upstream (B2 or Tripo) ────────────────────────────
    requestCacheKey = taskIdParam || `url_${url}`;
    const existingInFlight = MODEL_IN_FLIGHT.get(requestCacheKey);
    if (existingInFlight) {
      const entry = await existingInFlight;
      sendModelEntry(entry, "INFLIGHT");
      return;
    }

    let resolveInFlight;
    const inFlightPromise = new Promise((resolve, reject) => {
      resolveInFlight = resolve;
      rejectInFlight = reject;
    });
    inFlightPromise.catch(() => {});
    MODEL_IN_FLIGHT.set(requestCacheKey, inFlightPromise);

    let { error, upstream, message } = await performFetch(url);

    // If upstream returns 401/403/410/502, try to refresh URL via taskId
    if (error && [401, 403, 410, 502].includes(error)) {
      const taskIdSource = taskIdParam ? "query_param" : "none";
      const taskId = taskIdParam || null;

      if (taskId) {
        console.log(`[TaskController] modelProxy: Upstream ${error} for task ${taskId} (source: ${taskIdSource})`);
        // Check if we already know this task is dead
        if (REFRESH_FAILURE_CACHE.has(taskId)) {
          console.log(`[TaskController] modelProxy: skipping refresh for known dead task ${taskId}`);
          rejectInFlight?.(Object.assign(new Error("Task expired or deleted from source"), { status: 410, code: "TASK_NOT_FOUND" }));
          MODEL_IN_FLIGHT.delete(requestCacheKey);
          res.status(410).json({ success: false, message: "Task expired or deleted from source", code: "TASK_NOT_FOUND" });
          return;
        }

        console.log(`[TaskController] modelProxy: URL expired (Upstream ${error}), refreshing task ${taskId}...`);
        try {
          const freshData = await taskService.get(taskId);
          if (freshData.success && freshData.modelUrl) {
            if (freshData.modelUrl !== url) {
              console.log(`[TaskController] modelProxy: refresh successful, retrying with new URL`);
              url = freshData.modelUrl;
              const retry = await performFetch(url);
              error = retry.error;
              upstream = retry.upstream;
              message = retry.message;
            } else {
              console.warn(`[TaskController] modelProxy: refresh returned same URL for ${taskId}. Item is likely dead.`);
              error = 410; // Treat as gone since it didn't refresh
              message = "Tripo API returned same expired URL";
            }
          }
        } catch (refreshErr) {
          console.error(`[TaskController] Refresh attempt failed for ${taskId}:`, refreshErr.message);

          // If Tripo says 404 (Not Found), mark it as dead
          if (refreshErr.message?.includes("404") || refreshErr.message?.includes("2001")) {
            REFRESH_FAILURE_CACHE.set(taskId, Date.now());

            // Attempt to update status in Firestore so client stops asking
            (async () => {
              try {
                const db = admin.firestore();
                // 1. Try taskId matches
                const taskSnap = await db.collection(HISTORY_COLLECTION)
                  .where("taskId", "==", taskId)
                  .where("userId", "==", requesterId)
                  .get();

                // 2. Try model_url matches (important for old records missing taskId field)
                const urlSnap = await db.collection(HISTORY_COLLECTION)
                  .where("model_url", "==", url)
                  .where("userId", "==", requesterId)
                  .get();

                const allDocs = [...taskSnap.docs, ...urlSnap.docs];
                const cleanup = await deleteHistoryDocsWithStorage(allDocs, "model_proxy_source_missing");
                if (cleanup.deleted > 0) console.log(`[TaskController] Deleted ${cleanup.deleted} dead history documents for taskId ${taskId}`);
              } catch (fsErr) {
                console.warn(`[TaskController] Dead history cleanup failed:`, fsErr.message);
              }
            })();

            res.status(410).json({ success: false, message: "Model no longer exists on Tripo", code: "TASK_NOT_FOUND" });
            rejectInFlight?.(Object.assign(new Error("Model no longer exists on Tripo"), { status: 410, code: "TASK_NOT_FOUND" }));
            MODEL_IN_FLIGHT.delete(requestCacheKey);
            return;
          }
        }
      }
    }

    if (error) {
      const finalStatus = [401, 403, 404, 410].includes(error) ? error : 502;
      if (taskIdParam && [404, 410].includes(finalStatus)) {
        try {
          await deleteHistoryForDeadModel({
            taskId: taskIdParam,
            modelUrl: req.query.url,
            uid: req.user?.uid ?? null,
            reason: `model_proxy_${finalStatus}`,
          });
        } catch (cleanupErr) {
          console.warn(`[TaskController] modelProxy cleanup failed for ${taskIdParam}:`, cleanupErr.message);
        }
      }
      rejectInFlight?.(Object.assign(new Error(message || `Upstream ${error}`), {
        status: finalStatus,
        code: error === 410 ? "TASK_EXPIRED" : "UPSTREAM_ERROR",
      }));
      MODEL_IN_FLIGHT.delete(requestCacheKey);
      res.status(finalStatus).json({ success: false, message: message || `Upstream ${error}`, code: error === 410 ? "TASK_EXPIRED" : "UPSTREAM_ERROR" });
      return;
    }

    // Read body into buffer
    const buffer = await readBody(upstream);

    // Determine content type
    const parsed = new URL(url);
    const cleanPath = parsed.pathname.split("?")[0];
    const ext = cleanPath.split(".").pop()?.toLowerCase() ?? "glb";

    const EXT_CT_MAP = {
      glb: "model/gltf-binary",
      fbx: "application/octet-stream; x-format=fbx",
      obj: "text/plain",
      stl: "model/stl",
      usdz: "model/vnd.usdz+zip",
    };
    const ct = EXT_CT_MAP[ext] ?? "model/gltf-binary";

    void archiveModelProxyFetch({
      authorizedHistory,
      requesterId,
      taskId: taskIdParam,
      sourceUrl: url,
      buffer,
      contentType: ct,
      ext,
    });

    // ── Cache the result ───────────────────────────────────────────────
    const cacheKey = taskIdParam || `url_${cleanPath}`;
    MODEL_CACHE.set(cacheKey, {
      buffer,
      contentType: ct,
      ext,
      cachedAt: Date.now(),
    });
    const createdEntry = MODEL_CACHE.get(cacheKey);
    resolveInFlight?.(createdEntry);
    MODEL_IN_FLIGHT.delete(requestCacheKey);

    // ── Stream to client ───────────────────────────────────────────────
    sendModelEntry(createdEntry, "MISS");
  } catch (err) {
    rejectInFlight?.(err);
    if (requestCacheKey) MODEL_IN_FLIGHT.delete(requestCacheKey);
    console.error("[TaskController] proxy error:", err.message);
    if (!res.headersSent) res.status(500).json({ success: false, message: err.message });
  }
}


/* ─── Credit estimator ────────────────────────────────────────────────── */
export async function creditEstimate(req, res) {
  try {
    const { type, model_version, ...rest } = req.body;
    if (!type) { res.status(400).json({ success: false, message: "type required" }); return; }

    const mv = model_version ?? DEFAULT_MODEL;
    if (!VALID_MODEL_VERSIONS.has(mv)) {
      res.status(400).json({ success: false, message: `Invalid model_version "${mv}"` }); return;
    }

    const estimate = estimateCost({ type, model_version: mv, ...rest });
    res.json({ success: true, estimate });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
}

/* ─── Engine preset resolver ──────────────────────────────────────────── */
export async function getEnginePreset(req, res) {
  try {
    const { engine } = req.params;
    const preset = resolveEnginePreset(engine);
    res.json({ success: true, engine, preset });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
}

/* ─── Batch generation ────────────────────────────────────────────────── */
export async function batchGenerate(req, res) {
  const { prompts, image_tokens, images, model_version, texture, pbr, texture_quality, callback_url } = req.body;
  const items = prompts ?? images ?? image_tokens ?? [];

  if (!items.length) {
    res.status(400).json({ success: false, message: "prompts, images, or image_tokens array required (min 1)" });
    return;
  }

  const isPrompt = !!prompts;
  const mv = model_version ?? DEFAULT_MODEL;

  try {
    if (!isPrompt) {
      req.body = {
        type: "image_to_model",
        batch_images: items,
        model_version: mv,
        texture: texture === true,
        ...(pbr === true && { pbr: true }),
        ...(texture_quality && { texture_quality }),
        ...(callback_url && { callback_url }),
      };
      return createTask(req, res);
    }

    res.status(400).json({
      success: false,
      message: "Batch prompts are disabled on this endpoint until per-item billing and task ownership tracking are enabled.",
      code: "BATCH_PROMPTS_DISABLED",
    });
    return;
  } catch (err) {
    console.error("[TaskController] batchGenerate error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}
/* ─── Model capabilities ──────────────────────────────────────────────────── */

/**
 * GET /api/tripo/model-capabilities
 * Returns per-model capability map. Frontend uses this to render/disable
 * UI controls dynamically — no hardcoding on the client side.
 */
export async function getModelCapabilities(req, res) {
  res.json({
    success: true,
    capabilities: MODEL_CAPABILITIES,
    default: DEFAULT_CAPABILITIES,
    historyTtlMs: HISTORY_TTL_MS,
  });
}

/* ─── History management ──────────────────────────────────────────────────── */

/**
 * DELETE /api/tripo/history/:id
 * Deletes a single history item owned by the authenticated user.
 */
export async function deleteHistoryItem(req, res) {
  const { id } = req.params;
  const uid = req.user?.uid;
  if (!id) { res.status(400).json({ success: false, message: "id required" }); return; }

  try {
    const db = admin.firestore();
    const ref = db.collection(HISTORY_COLLECTION).doc(id);
    const doc = await ref.get();

    if (!doc.exists) {
      res.json({ success: true, id, deleted: 0, b2Deleted: 0, b2Failed: 0, alreadyDeleted: true });
      return;
    }
    if (doc.data()?.userId !== uid) {
      res.status(403).json({ success: false, message: "Forbidden" });
      return;
    }

    const cleanup = await deleteHistoryDocsWithStorage([doc], "single_delete");
    console.log(`[HistoryController] deleted item ${id} for user ${uid}`);
    res.json({ success: true, id, ...cleanup });
  } catch (err) {
    console.error("[HistoryController] deleteHistoryItem error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}

/**
 * DELETE /api/tripo/history
 * Deletes ALL tripo history items for the authenticated user.
 */
export async function clearHistory(req, res) {
  const uid = req.user?.uid;
  if (!uid) { res.status(401).json({ success: false, message: "Unauthorized" }); return; }

  const ALLOWED_SOURCES = ["tripo", "trellis", "upload"];
  const source = ALLOWED_SOURCES.includes(req.query.source) ? req.query.source : "tripo";

  try {
    const db = admin.firestore();
    const snap = await db.collection(HISTORY_COLLECTION)
      .where("userId", "==", uid)
      .where("source", "==", source)
      .get();

    const cleanup = await deleteHistoryDocsWithStorage(snap.docs, `clear_${source}`);

    console.log(`[HistoryController] cleared ${snap.size} ${source} items for user ${uid}`);
    res.json({ success: true, ...cleanup });
  } catch (err) {
    console.error("[HistoryController] clearHistory error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}

/**
 * DELETE /api/tripo/history/expired
 * Deletes tripo_history items older than HISTORY_TTL_MS for the authenticated user.
 *
 * To run this daily without Cloud Functions, add a cron job that calls:
 *   curl -X DELETE https://<host>/api/tripo/history/expired \
 *        -H "Authorization: Bearer <service-account-token>"
 * Or use a Cloud Scheduler job pointing at this endpoint with OIDC auth.
 */
export async function cleanupExpiredHistory(req, res) {
  const uid = req.user?.uid;
  if (!uid) { res.status(401).json({ success: false, message: "Unauthorized" }); return; }

  try {
    const db = admin.firestore();
    const now = Date.now();

    // Query only by userId so cleanup works without a composite Firestore index.
    const snap = await db.collection(HISTORY_COLLECTION)
      .where("userId", "==", uid)
      .get();

    const expiredDocs = snap.docs.filter((doc) => {
      if (doc.data()?.marketplaceLocked === true || doc.data()?.marketplaceAssetId) return false;
      const expiresAt = getHistoryExpiryMillis(doc.data());
      return expiresAt != null && expiresAt <= now;
    });

    if (expiredDocs.length === 0) {
      res.json({ success: true, deleted: 0, message: "Nothing to clean up" });
      return;
    }

    const cleanup = await deleteHistoryDocsWithStorage(expiredDocs, "expired_ttl");

    console.log(`[HistoryController] cleaned up ${cleanup.deleted} expired items for user ${uid}`);
    res.json({ success: true, ...cleanup });
  } catch (err) {
    console.error("[HistoryController] cleanupExpiredHistory error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}
