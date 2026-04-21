// src/controllers/taskController.js
import { taskService } from "../services/taskService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { enqueueTripoTask, enqueueBatch } from "../workers/queues.js";
import { estimateCost } from "../lib/creditEstimator.js";
import { resolveEnginePreset } from "../lib/enginePresets.js";
import { deductCredits, refundCredits, linkTaskIdToTransaction } from "../services/creditService.js";
import { registerTask as registerForRecovery, unregisterTask } from "../services/taskRecoveryService.js";
import { DEFAULT_MODEL, VALID_MODEL_VERSIONS, MODEL_CAPABILITIES, DEFAULT_CAPABILITIES, HISTORY_TTL_MS } from "../config/tripo.config.js";
import { v4 as uuid } from "uuid";
import admin from "firebase-admin";
import { registerJob, unregisterJob } from "../lib/jobRegistry.js";

const USE_QUEUE = process.env.USE_QUEUE === "true";
const HISTORY_COLLECTION = "trellis_history";

/* ─── Task: create (unified) ──────────────────────────────────────────── */
export async function createTask(req, res) {
  const { type, callback_url, idempotency_key, ...rest } = req.body;
  if (!type) { res.status(400).json({ success: false, message: "type field required" }); return; }

  try {
    const body = { type, ...rest };
    const userId = req.user?.uid;
    const jobId = req.body.jobId;

    const controller = new AbortController();
    if (jobId) {
      registerJob(jobId, controller, 1800000); // 30 min for 3D
    }

    // Estimate credit cost for this task
    const { total: estimatedCost } = estimateCost(body);
    console.log(`[TaskController] create type=${body.type} model=${body.model_version ?? "default"} cost=${estimatedCost}`);

    let tempTxId = null;
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
            const histType = parentData.params?.type;
            const VALID_REFINE_SOURCES = new Set(["text_to_model", "image_to_model", "multiview_to_model"]);
            if (histType && !VALID_REFINE_SOURCES.has(histType)) {
              return res.status(400).json({
                success: false,
                message: `Ez a modell nem finomítható. A refine_model csak alap generálásból származó modellre alkalmazható (kivéve: ${histType}).`,
                code: "UNSUPPORTED_REFINE_SOURCE",
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

    if (USE_QUEUE) {
      const jobId = await enqueueTripoTask({
        jobType: "single",
        taskBody: body,
        userId,
        callbackUrl: callback_url,
        idempotencyKey: idempotency_key ?? uuid(),
      });
      res.json({ success: true, queued: true, jobId });
    } else {
      const taskId = await taskService.create(body, {
        callbackUrl: callback_url,
        idempotencyKey: idempotency_key,
        signal: controller.signal,
      });

      // Link real taskId to credit transaction for refunds
      if (userId && tempTxId) {
        linkTaskIdToTransaction(userId, tempTxId, taskId).catch(e =>
          console.error(`[TaskController] Failed to link taskId ${taskId}:`, e.message)
        );
      }

      // Register for background recovery with inherited prompt
      if (userId) {
        registerForRecovery(taskId, userId, body.type, body.model_version ?? DEFAULT_MODEL, inheritedPrompt);
      }
      unregisterJob(jobId);
      res.json({ success: true, taskId });
    }
  } catch (err) {
    unregisterJob(jobId);
    if (err.name === 'AbortError') {
      return res.status(499).json({ success: false, message: "Folyamat megszakítva" });
    }
    console.error(`[TaskController] create error:`, err.message);

    // Tripo 403 = insufficient credit → refund the locally deducted amount
    if (err.message?.includes("403") && err.message?.includes("credit")) {
      console.log(`[TaskController] Tripo returned 403 credit error — refunding ${estimatedCost} credits to user ${userId}`);
      try {
        await refundCredits(userId, estimatedCost, `pending_${type}_${Date.now()}`, "tripo_403_insufficient_credit");
      } catch (refundErr) {
        console.error(`[TaskController] Refund error:`, refundErr.message);
      }
    }

    res.status(400).json({ success: false, message: err.message });
  }
}

/* ─── Task: get status ────────────────────────────────────────────────── */
export async function getTask(req, res) {
  try {
    const result = await taskService.get(req.params.taskId);
    // FIX: result.success-t kivesszük, hogy ne írja felül a success: true-t
    const { success: _ignored, ...taskData } = result;
    res.json({ success: true, ...taskData });
  } catch (err) {
    console.error("[TaskController] getTask error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}

/* ─── Task: cancel ────────────────────────────────────────────────────── */
export async function cancelTask(req, res) {
  try {
    await taskService.cancel(req.params.taskId);
    res.json({ success: true, cancelled: true });
  } catch (err) {
    console.warn("[TaskController] cancelTask:", err.message);
    // Már befejezett/failed task cancel kísérlete nem kritikus hiba
    // A frontend kezeli, 200-at küldünk vissza hogy ne logoljon hibát
    res.json({ success: false, message: err.message });
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
    res.status(500).json({ success: false, message: err.message });
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

export async function modelProxy(req, res) {
  let { url, taskId: taskIdParam } = req.query;

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

  // Inner helper to perform the actual fetch
  const performFetch = async (targetUrl) => {
    let parsed;
    try { parsed = new URL(targetUrl); } catch {
      return { error: 400, message: "Invalid URL" };
    }

    if (!allowedHosts.some(h => parsed.hostname.endsWith(h))) {
      return { error: 400, message: "Source not allowed" };
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

    // ── Fetch from upstream ────────────────────────────────────────────
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
                  .get();

                // 2. Try model_url matches (important for old records missing taskId field)
                const urlSnap = await db.collection(HISTORY_COLLECTION)
                  .where("model_url", "==", url)
                  .get();

                const allDocs = [...taskSnap.docs, ...urlSnap.docs];
                const uniqueDocs = Array.from(new Map(allDocs.map(d => [d.id, d])).values());

                if (uniqueDocs.length > 0) {
                  const batch = db.batch();
                  uniqueDocs.forEach(doc => {
                    batch.update(doc.ref, {
                      status: "failed",
                      error: "Task expired on Tripo platform (Source deleted)"
                    });
                  });
                  await batch.commit();
                  console.log(`[TaskController] Marked ${uniqueDocs.length} documents as failed for taskId ${taskId}`);
                }
              } catch (fsErr) {
                console.warn(`[TaskController] Firestore batch update failed:`, fsErr.message);
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
        // FIX: csak true értéket küldünk, explicit false-t soha
        ...(texture !== false && { texture: true }),
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
    const ref = db.collection(HISTORY_COLLECTION).doc(id);
    const doc = await ref.get();

    if (!doc.exists) {
      res.status(404).json({ success: false, message: "Item not found" });
      return;
    }
    if (doc.data()?.userId !== uid) {
      res.status(403).json({ success: false, message: "Forbidden" });
      return;
    }

    await ref.delete();
    console.log(`[HistoryController] deleted item ${id} for user ${uid}`);
    res.json({ success: true, id });
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

    const batch = db.batch();
    snap.docs.forEach(doc => batch.delete(doc.ref));
    await batch.commit();

    console.log(`[HistoryController] cleared ${snap.size} ${source} items for user ${uid}`);
    res.json({ success: true, deleted: snap.size });
  } catch (err) {
    console.error("[HistoryController] clearHistory error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}

/**
 * DELETE /api/tripo/history/expired
 * Deletes history items older than HISTORY_TTL_MS for the authenticated user.
 */
export async function cleanupExpiredHistory(req, res) {
  const uid = req.user?.uid;
  if (!uid) { res.status(401).json({ success: false, message: "Unauthorized" }); return; }

  try {
    const db = admin.firestore();
    const cutoffMs = Date.now() - HISTORY_TTL_MS;

    // Filter in memory to avoid needing a composite index
    const snap = await db.collection(HISTORY_COLLECTION)
      .where("userId", "==", uid)
      .get();

    if (snap.empty) {
      res.json({ success: true, deleted: 0, message: "Nothing to clean up" });
      return;
    }

    const docsToDelete = snap.docs.filter(doc => {
      const data = doc.data();
      if (!data.createdAt) return false;
      let createdMs = 0;
      if (typeof data.createdAt.toMillis === "function") {
        createdMs = data.createdAt.toMillis();
      } else if (data.createdAt.seconds !== undefined) {
        createdMs = data.createdAt.seconds * 1000;
      } else if (data.createdAt instanceof Date) {
        createdMs = data.createdAt.getTime();
      } else {
        createdMs = new Date(data.createdAt).getTime();
      }
      return createdMs && createdMs < cutoffMs;
    });

    if (docsToDelete.length === 0) {
      res.json({ success: true, deleted: 0, message: "Nothing to clean up" });
      return;
    }

    // Firestore batch limit = 500
    let deleted = 0;
    for (let i = 0; i < docsToDelete.length; i += 500) {
      const b = db.batch();
      const chunk = docsToDelete.slice(i, i + 500);
      chunk.forEach(doc => b.delete(doc.ref));
      await b.commit();
      deleted += chunk.length;
    }

    console.log(`[HistoryController] cleaned up ${deleted} expired items for user ${uid}`);
    res.json({ success: true, deleted });
  } catch (err) {
    console.error("[HistoryController] cleanupExpiredHistory error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}