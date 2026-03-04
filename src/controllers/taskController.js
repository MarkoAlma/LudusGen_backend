// src/controllers/taskController.js
import { taskService } from "../services/taskService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { enqueueTripoTask, enqueueBatch } from "../workers/queues.js";
import { estimateCost } from "../lib/creditEstimator.js";
import { resolveEnginePreset } from "../lib/enginePresets.js";
import { DEFAULT_MODEL, VALID_MODEL_VERSIONS } from "../config/tripo.config.js";
import { v4 as uuid } from "uuid";

const USE_QUEUE = process.env.USE_QUEUE === "true";

/* ─── Task: create (unified) ──────────────────────────────────────────── */
export async function createTask(req, res) {
  const { type, callback_url, idempotency_key, ...rest } = req.body;
  if (!type) { res.status(400).json({ success: false, message: "type field required" }); return; }

  try {
    const body = { type, ...rest };

    if (USE_QUEUE) {
      const jobId = await enqueueTripoTask({
        jobType:        "single",
        taskBody:       body,
        userId:         req.user?.uid,
        callbackUrl:    callback_url,
        idempotencyKey: idempotency_key ?? uuid(),
      });
      res.json({ success: true, queued: true, jobId });
    } else {
      const taskId = await taskService.create(body, {
        callbackUrl:    callback_url,
        idempotencyKey: idempotency_key,
      });
      res.json({ success: true, taskId });
    }
  } catch (err) {
    console.error(`[TaskController] create error:`, err.message);
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
    console.error("[TaskController] cancelTask error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}

/* ─── Task: list ──────────────────────────────────────────────────────── */
export async function listTasks(req, res) {
  try {
    const status = req.query.status;
    const limit  = req.query.limit ? parseInt(req.query.limit, 10) : 20;
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
    const data   = await client.getBalance();
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
    const client     = getTripoClient();
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
export async function modelProxy(req, res) {
  const { url } = req.query;
  if (!url) { res.status(400).json({ success: false, message: "url missing" }); return; }

  let parsed;
  try { parsed = new URL(url); } catch {
    res.status(400).json({ success: false, message: "Invalid URL" }); return;
  }

  const allowedHosts = ["tripo3d.ai", "cdn.tripo3d.ai", "assets.tripo3d.ai"];
  if (!allowedHosts.some(h => parsed.hostname.endsWith(h))) {
    res.status(400).json({ success: false, message: "Source not allowed" }); return;
  }

  try {
    const apiKey   = process.env.TRIPO3D_API_KEY;
    const upstream = await fetch(url, { headers: { Authorization: `Bearer ${apiKey}` } });

    if (!upstream.ok) {
      res.status(502).json({ success: false, message: `Upstream ${upstream.status}` }); return;
    }

    const ct  = upstream.headers.get("content-type") || "model/gltf-binary";
    const cl  = upstream.headers.get("content-length");
    const ext = parsed.pathname.split(".").pop()?.toLowerCase() ?? "glb";

    res.setHeader("Content-Type", ct);
    res.setHeader("Content-Disposition", `attachment; filename="model.${ext}"`);
    if (cl) res.setHeader("Content-Length", cl);

    const reader = upstream.body?.getReader();
    if (!reader) { res.status(502).json({ success: false, message: "No body" }); return; }

    const pump = async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      res.end();
    };
    await pump();
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

  const batchId  = uuid();
  const isPrompt = !!prompts;
  const mv       = model_version ?? DEFAULT_MODEL;

  try {
    const jobDataList = items.map((item, index) => ({
      jobType:     "batch_item",
      batchId,
      batchIndex:  index,
      callbackUrl: callback_url,
      taskBody: {
        type: isPrompt ? "text_to_model" : "image_to_model",
        ...(isPrompt
          ? { prompt: item }
          : { file: { type: "jpg", file_token: item } }),
        model_version:   mv,
        // FIX: csak true értéket küldünk, explicit false-t soha
        ...(texture !== false && { texture: true }),
        ...(pbr === true      && { pbr: true }),
        texture_quality: texture_quality ?? "detailed",
      },
    }));

    if (USE_QUEUE) {
      const jobIds = await enqueueBatch(jobDataList);
      res.json({
        success: true,
        batchId,
        total:   items.length,
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
        total:   items.length,
        tasks:   taskIds.map((r, i) => ({
          index:  i,
          taskId: r.status === "fulfilled" ? r.value : null,
          error:  r.status === "rejected"  ? r.reason.message : undefined,
        })),
      });
    }
  } catch (err) {
    console.error("[TaskController] batchGenerate error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}