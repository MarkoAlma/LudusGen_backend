// src/controllers/taskController.js
import { taskService } from "../services/taskService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { storageService } from "../services/storageService.js";
import { enqueueTripoTask, enqueueBatch } from "../workers/queues.js";
import { estimateCost } from "../lib/creditEstimator.js";
import { resolveEnginePreset } from "../lib/enginePresets.js";
import { deductCredits, refundCredits, linkTaskIdToTransaction } from "../services/creditService.js";
import { registerTask as registerForRecovery, unregisterTask, getRegisteredTaskMeta } from "../services/taskRecoveryService.js";
import {
  MARKETPLACE_COLLECTIONS,
  canAccessMarketplaceStorageKey,
  getVerifiedMarketplacePurchase,
} from "../services/marketplaceService.js";
import { DEFAULT_MODEL, VALID_MODEL_VERSIONS, MODEL_CAPABILITIES, DEFAULT_CAPABILITIES, HISTORY_TTL_MS, TRIPO_IMAGE_UPLOAD_MAX_BYTES } from "../config/tripo.config.js";
import { v4 as uuid } from "uuid";
import admin from "firebase-admin";
import { registerJob, unregisterJob } from "../lib/jobRegistry.js";

const USE_QUEUE = process.env.USE_QUEUE === "true";
const DEBUG_TRIPO = process.env.DEBUG_TRIPO === "true";
// NOTE: existing docs with tripo_ prefixed IDs in 'trellis_history' need a one-time migration
const HISTORY_COLLECTION = "tripo_history";
const REFINE_DIRECT_SOURCE_TYPES = new Set(["text_to_model", "image_to_model", "multiview_to_model"]);
const REFINE_UPSTREAM_SOURCE_TYPES = new Set(["texture_model", "convert_model", "smart_low_poly", "stylize_model", "mesh_segmentation", "mesh_completion"]);
const TEXTURE_DIRECT_SOURCE_TYPES = new Set(["text_to_model", "image_to_model", "multiview_to_model", "texture_model", "import_model"]);

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

function uniqueDocs(docs) {
  return Array.from(new Map(docs.filter(Boolean).map(d => [d.ref.path, d])).values());
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

async function getAuthorizedHistoryForModelProxy(taskId, uid) {
  if (!taskId || !uid) return null;

  const db = admin.firestore();
  const snap = await db.collection(HISTORY_COLLECTION)
    .where("taskId", "==", taskId)
    .limit(25)
    .get();

  const doc = snap.docs.find((item) => item.data()?.userId === uid);
  if (!doc) return null;

  const data = doc.data();
  if (data.marketplaceAssetId) {
    const assetDoc = await db.collection(MARKETPLACE_COLLECTIONS.assets).doc(data.marketplaceAssetId).get();
    if (!assetDoc.exists) return null;
    const purchase = await getVerifiedMarketplacePurchase(db, {
      buyerId: uid,
      assetId: data.marketplaceAssetId,
      asset: assetDoc.data(),
    });
    if (!purchase) return null;
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

/* ─── Task: create (unified) ──────────────────────────────────────────── */
export async function createTask(req, res) {
  const { type, callback_url, idempotency_key, ...rest } = req.body;
  const userId = req.user?.uid;
  const jobId = req.body.jobId;
  const controller = new AbortController();
  let estimatedCost = 0;
  let creditsDeducted = false;
  let tempTxId = null;
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
      const tokens = (body.images && Array.isArray(body.images)) ? body.images
                   : (body.batch_images && Array.isArray(body.batch_images)) ? body.batch_images
                   : [];
      const onlyStringTokens = tokens.length > 0 && tokens.every((item) => typeof item === "string");

      if (onlyStringTokens && tokens.length === 1) {
        // Normalize single image task
        body.file = { type: "jpg", file_token: tokens[0] };
        delete body.images;
        delete body.batch_images;
      } else if (onlyStringTokens && tokens.length > 1) {
        // Keep tokens for later splitting in this controller
        body.batch_images = tokens;
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

    if (estimatedCost > 0 && userId) {
      tempTxId = `pending_${type}_${Date.now()}`;
      try {
        const tripoBalance = await getTripoClient().getBalance();
        const availableTripo = tripoBalance.balance ?? 0;
        if (availableTripo < estimatedCost) {
          console.log(`[TaskController] Tripo balance ${availableTripo} < estimated cost ${estimatedCost} — rejecting`);
          return res.status(402).json({
            success: false,
            message: `Insufficient credits: ${availableTripo} available, ${estimatedCost} required. Please top up your balance.`,
            code: "INSUFFICIENT_CREDITS",
          });
        }
      } catch (balanceErr) {
        console.error(`[TaskController] Tripo balance check error:`, balanceErr.message);
      }

      try {
        await deductCredits(userId, estimatedCost, tempTxId, type);
        creditsDeducted = true;
      } catch (creditErr) {
        if (creditErr.code === "INSUFFICIENT_CREDITS") {
          return res.status(402).json({
            success: false,
            message: `Insufficient credits: ${creditErr.available} available, ${creditErr.required} required. Please top up your balance.`,
            code: "INSUFFICIENT_CREDITS",
          });
        }
        console.error(`[TaskController] Credit deduction error:`, creditErr.message);
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
              if (userId && estimatedCost > 0 && tempTxId && creditsDeducted) {
                await refundCredits(userId, estimatedCost, tempTxId, "already_refined_source");
                creditsDeducted = false;
              }
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
              if (userId && estimatedCost > 0 && tempTxId && creditsDeducted) {
                await refundCredits(userId, estimatedCost, tempTxId, "unsupported_refine_source");
                creditsDeducted = false;
              }
              return res.status(400).json({
                success: false,
                message: `Ez a modell nem finomítható. A refine_model csak alap generálásból származó modellre alkalmazható. Forrástípus: ${histType}`,
                code: "UNSUPPORTED_REFINE_SOURCE",
              });
            }
            const sourceVersion = getHistoryModelVersion(effectiveParentData);
            if (!isRefineModelVersionSupported(sourceVersion)) {
              if (userId && estimatedCost > 0 && tempTxId && creditsDeducted) {
                await refundCredits(userId, estimatedCost, tempTxId, "unsupported_refine_model_version");
                creditsDeducted = false;
              }
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
        for (const token of batch_images) {
          const subBody = {
            ...common,
            file: typeof token === "string" ? { type: "jpg", file_token: token } : token,
          };
          const taskId = await taskService.create(subBody, {
            callbackUrl: callback_url,
            idempotencyKey: uuid(),
            signal: controller.signal,
          });
          tripoTaskCreated = true;
          
          if (userId && tempTxId) {
            linkTaskIdToTransaction(userId, tempTxId, taskId).catch(e =>
              console.error(`[TaskController] Failed to link taskId ${taskId}:`, e.message)
            );
          }
          if (userId) {
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

        // Link real taskId to credit transaction for refunds
        if (userId && tempTxId) {
          linkTaskIdToTransaction(userId, tempTxId, taskId).catch(e =>
            console.error(`[TaskController] Failed to link taskId ${taskId}:`, e.message)
          );
        }

        // Register for background recovery with inherited prompt
        if (userId) {
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
      creditsDeducted,
      requestBody: req.body,
      error: err.message,
    });

    const refundDeductedCredits = async (reason) => {
      if (!userId || estimatedCost <= 0 || !creditsDeducted || !tempTxId || tripoTaskCreated) return;
      try {
        await refundCredits(userId, estimatedCost, tempTxId, reason);
        creditsDeducted = false;
      } catch (refundErr) {
        console.error(`[TaskController] Refund error (${reason}):`, refundErr.message);
      }
    };

    // Tripo 403 = insufficient credit → refund the locally deducted amount
    if (err.message?.includes("403") && err.message?.includes("credit")) {
      if (userId && estimatedCost > 0 && creditsDeducted) {
        console.log(`[TaskController] Tripo returned 403 credit error — refunding ${estimatedCost} credits to user ${userId}`);
        await refundDeductedCredits("tripo_403_insufficient_credit");
      }
    }

    // Tripo 1004 on refine_model = model has no draft output (was generated with texture, or wrong task type)
    let userMessage = err.message;
    if (type === "refine_model" && err.message?.includes("1004")) {
      if (userId && estimatedCost > 0 && creditsDeducted) {
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

    await refundDeductedCredits(type === "texture_model" ? "texture_model_create_failed" : "tripo_create_failed");

    res.status(400).json(errorPayload(err, userMessage));
  } finally {
    unregisterJob(jobId);
  }
}

/* ─── Task: get status ────────────────────────────────────────────────── */
export async function getTask(req, res) {
  try {
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
    res.status(500).json(errorPayload(err));
  }
}

export async function streamTask(req, res) {
  const taskId = req.params.taskId;
  if (!taskId) {
    res.status(400).json({ success: false, message: "taskId required" });
    return;
  }

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
    send("error", errorPayload(err));
  } finally {
    if (!closed) {
      res.end();
    }
  }
}

/* ─── Task: cancel ────────────────────────────────────────────────────── */
export async function cancelTask(req, res) {
  try {
    const result = await taskService.cancel(req.params.taskId);
    res.json({ success: true, cancelled: result.cancelled, message: result.message });
  } catch (err) {
    console.warn("[TaskController] cancelTask:", err.message);
    res.json({ success: false, cancelled: false, message: err.message });
  }
}

/* ─── Task: acknowledge (stop background poll) ────────────────────────── */
export async function acknowledgeTask(req, res) {
  try {
    const { taskId } = req.params;
    if (!taskId) return res.status(400).json({ success: false, message: "taskId required" });
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

export async function modelProxy(req, res) {
  let { url, taskId: taskIdParam } = req.query;
  const requesterId = req.user?.uid;

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

    if (!allowedHosts.some(h => parsed.hostname.endsWith(h))) {
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
      authorizedHistory = await getAuthorizedHistoryForModelProxy(taskIdParam, requesterId);
      if (!authorizedHistory) {
        res.status(403).json({ success: false, message: "Forbidden" });
        return;
      }
    }

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
        res.setHeader("Content-Type", entry.contentType);
        res.setHeader("Content-Disposition", `attachment; filename="model.${entry.ext}"`);
        res.setHeader("Content-Length", entry.buffer.length);
        res.setHeader("X-Cache", "HIT");
        res.end(entry.buffer);
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

    // ── Cache the result ───────────────────────────────────────────────
    const cacheKey = taskIdParam || `url_${cleanPath}`;
    MODEL_CACHE.set(cacheKey, {
      buffer,
      contentType: ct,
      ext,
      cachedAt: Date.now(),
    });

    // ── Stream to client ───────────────────────────────────────────────
    res.setHeader("Content-Type", ct);
    res.setHeader("Content-Disposition", `attachment; filename="model.${ext}"`);
    res.setHeader("Content-Length", buffer.length);
    res.setHeader("X-Cache", "MISS");
    res.end(buffer);
  } catch (err) {
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
  const { prompts, image_tokens, model_version, texture, pbr, texture_quality, callback_url } = req.body;
  const items = prompts ?? image_tokens ?? [];

  if (!items.length) {
    res.status(400).json({ success: false, message: "prompts or image_tokens array required (min 1)" });
    return;
  }
  if (items.length > 50) {
    res.status(400).json({ success: false, message: "max 50 items per batch" });
    return;
  }

  const batchId = uuid();
  const isPrompt = !!prompts;
  const mv = model_version ?? DEFAULT_MODEL;

  try {
    const jobDataList = items.map((item, index) => ({
      jobType: "batch_item",
      batchId,
      batchIndex: index,
      callbackUrl: callback_url,
      taskBody: {
        type: isPrompt ? "text_to_model" : "image_to_model",
        ...(isPrompt
          ? { prompt: item }
          : { file: { type: "jpg", file_token: item } }),
        model_version: mv,
        texture: texture === true,
        ...(pbr === true && { pbr: true }),
        texture_quality: texture_quality ?? "detailed",
      },
    }));

    if (USE_QUEUE) {
      const jobIds = await enqueueBatch(jobDataList);
      res.json({
        success: true,
        batchId,
        total: items.length,
        jobIds,
        message: "Batch enqueued. Track progress via GET /tripo/batch/:batchId",
      });
    } else {
      const taskIds = await Promise.allSettled(
        jobDataList.map(d => taskService.create(d.taskBody, { callbackUrl: callback_url })),
      );
      res.json({
        success: true,
        batchId,
        total: items.length,
        tasks: taskIds.map((r, i) => ({
          index: i,
          taskId: r.status === "fulfilled" ? r.value : null,
          error: r.status === "rejected" ? r.reason.message : undefined,
        })),
      });
    }
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
    const collection = req.query.collection || HISTORY_COLLECTION;
    const ref = db.collection(collection).doc(id);
    const doc = await ref.get();

    if (!doc.exists) {
      res.status(404).json({ success: false, message: "Item not found" });
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
  const collection = req.query.collection || HISTORY_COLLECTION;

  try {
    const db = admin.firestore();
    const snap = await db.collection(collection)
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
