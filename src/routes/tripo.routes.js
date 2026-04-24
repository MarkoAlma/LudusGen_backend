// src/routes/tripo.routes.js
//
// Unified Tripo API router.
// Mounts on /api or wherever your app registers it.

import express, { Router } from "express";
import multer from "multer";
import rateLimit from "express-rate-limit";

// Controllers
import {
  createTask,
  getTask,
  streamTask,
  cancelTask,
  acknowledgeTask,
  listTasks,
  getBalance,
  uploadFile,
  modelProxy,
  creditEstimate,
  getEnginePreset,
  batchGenerate,
  getModelCapabilities,
  deleteHistoryItem,
  clearHistory,
  cleanupExpiredHistory,
} from "../controllers/taskController.js";

import {
  generateCharacter,
  getPipeline,
  estimatePipeline,
  generateLod,
} from "../controllers/pipelineController.js";

import {
  getSummary,
  getDailyCredits,
  getRecentTasks,
} from "../controllers/analyticsController.js";

import {
  handleWebhook,
  testWebhook,
} from "../controllers/webhookController.js";

import {
  uploadAsset,
  importUploadedAsset,
} from "../controllers/assetController.js";
import {
  getUploadStsTarget,
} from "../controllers/uploadController.js";
import {
  TRIPO_IMAGE_UPLOAD_MAX_BYTES,
  TRIPO_MODEL_IMPORT_MAX_BYTES,
} from "../config/tripo.config.js";

/* ─── Middleware ──────────────────────────────────────────────────────── */
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: TRIPO_IMAGE_UPLOAD_MAX_BYTES },
});

/** Asset upload multer - GLB/FBX/OBJ/STL, max 150MB */
const assetUpload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: TRIPO_MODEL_IMPORT_MAX_BYTES },
  fileFilter: (req, file, cb) => {
    const ext = file.originalname.split(".").pop()?.toLowerCase();
    const allowed = new Set(["glb", "fbx", "obj", "stl"]);
    if (allowed.has(ext)) cb(null, true);
    else cb(new Error(`Unsupported file type: ${ext}. Allowed: glb, fbx, obj, stl`));
  },
});

/** Generation rate limiter — 30 req/min per authenticated user */
const genLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  keyGenerator: (req) => `user:${req.user.uid}`,
  message: {
    success: false,
    message: "Rate limit exceeded. Max 30 generation requests per minute.",
  },
});

/** Admin rate limiter — analytics / monitoring endpoints */
const adminLimiter = rateLimit({
  windowMs: 60_000,
  max:      120,
  message:  { success: false, message: "Rate limit exceeded." },
});

/* ─── Router factory ──────────────────────────────────────────────────── */
export function createTripoRouter(verifyAuth) {
  const router = Router();

  /* ════════════════════════════════════════════════════════════════════
   *  CORE ENDPOINTS
   * ════════════════════════════════════════════════════════════════════ */

  /** Upload image → image_token */
  router.post("/tripo/upload", verifyAuth, upload.single("file"), uploadFile);
  router.post("/tripo/upload/sts-target", verifyAuth, getUploadStsTarget);

  /** Upload 3D asset (GLB/FBX/OBJ) → import_model task */
  router.post("/tripo/assets/upload", verifyAuth, assetUpload.single("file"), uploadAsset);
  router.post("/tripo/assets/import", verifyAuth, importUploadedAsset);

  /** Create any Tripo task */
  router.post("/tripo/task", verifyAuth, genLimiter, createTask);

  /** Poll a single task */
  router.get("/tripo/task/:taskId", verifyAuth, getTask);
  router.get("/tripo/task/:taskId/stream", verifyAuth, streamTask);

  /** Cancel a running/queued task */
  router.post("/tripo/task/:taskId/cancel", verifyAuth, cancelTask);

  /** Acknowledge task completion (stops background poll) */
  router.post("/tripo/task/:taskId/ack", verifyAuth, acknowledgeTask);

  /** List tasks with pagination + status filter */
  router.get("/tripo/tasks", verifyAuth, listTasks);

  /** Authenticated model download proxy */
  router.get("/tripo/model-proxy", verifyAuth, modelProxy);

  /** Wallet balance */
  router.get("/tripo/balance", verifyAuth, getBalance);

  /* ════════════════════════════════════════════════════════════════════
   *  WEBHOOK
   * ════════════════════════════════════════════════════════════════════ */

  /**
   * Tripo webhook receiver — express.raw captures the raw body for signature verification
   * before express.json() in the app can parse and discard it.
   */
  router.post(
    "/tripo/webhook",
    express.raw({ type: "application/json", verify: (req, _res, buf) => { req.rawBody = buf; } }),
    handleWebhook,
  );

  /** Local test — POST { task_id, status } to simulate a webhook */
  router.post("/tripo/webhook/test", verifyAuth, testWebhook);

  /* ════════════════════════════════════════════════════════════════════
   *  CREDIT ESTIMATOR
   * ════════════════════════════════════════════════════════════════════ */

  /** Estimate credits BEFORE task creation */
  router.post("/tripo/estimate", verifyAuth, creditEstimate);

  /** Estimate full pipeline cost */
  router.post("/tripo/estimate/pipeline", verifyAuth, estimatePipeline);

  /* ════════════════════════════════════════════════════════════════════
   *  ENGINE PRESETS
   * ════════════════════════════════════════════════════════════════════ */

  /** Get convert_model params for a specific engine */
  router.get("/tripo/preset/:engine", verifyAuth, getEnginePreset);

  /* ════════════════════════════════════════════════════════════════════
   *  PIPELINE ORCHESTRATOR
   * ════════════════════════════════════════════════════════════════════ */

  /**
   * Full character generation pipeline:
   * generation → [retopo] → [rig] → [animate] → [convert]
   *
   * Body: GenerateCharacterRequest
   * Returns: { pipelineId } immediately; poll /pipeline/:id for status
   */
  router.post("/tripo/pipeline/character", verifyAuth, genLimiter, generateCharacter);

  /** Get pipeline status */
  router.get("/tripo/pipeline/:pipelineId", verifyAuth, getPipeline);

  /* ════════════════════════════════════════════════════════════════════
   *  AUTO LOD CHAIN
   * ════════════════════════════════════════════════════════════════════ */

  /**
   * Generate multiple LOD levels from a source task.
   * Body: { source_task_id, levels?: [...], export_zip?: boolean }
   * Default levels: LOD0=50k, LOD1=20k, LOD2=5k
   */
  router.post("/tripo/lod", verifyAuth, genLimiter, generateLod);

  /* ════════════════════════════════════════════════════════════════════
   *  BATCH GENERATION
   * ════════════════════════════════════════════════════════════════════ */

  /**
   * Batch text/image → 3D.
   * Body: { prompts?: string[], image_tokens?: string[], ... }
   * Max 50 items per batch.
   */
  router.post("/tripo/batch", verifyAuth, genLimiter, batchGenerate);

  /* ════════════════════════════════════════════════════════════════════
   *  ANALYTICS + MONITORING
   * ════════════════════════════════════════════════════════════════════ */

  router.get("/tripo/analytics/summary", verifyAuth, adminLimiter, getSummary);
  router.get("/tripo/analytics/credits",  verifyAuth, adminLimiter, getDailyCredits);
  router.get("/tripo/analytics/tasks",    verifyAuth, adminLimiter, getRecentTasks);

  /* ════════════════════════════════════════════════════════════════════
   *  MODEL CAPABILITIES
   * ════════════════════════════════════════════════════════════════════ */

  /**
   * Returns per-model capability map so the frontend can render options
   * dynamically without any hardcoded model-specific logic.
   */
  router.get("/tripo/model-capabilities", verifyAuth, getModelCapabilities);

  /* ════════════════════════════════════════════════════════════════════
   *  HISTORY MANAGEMENT  (Firestore-backed, 7-day TTL)
   * ════════════════════════════════════════════════════════════════════ */

  /** Delete a single history item */
  router.delete("/tripo/history/expired", verifyAuth, cleanupExpiredHistory);
  router.delete("/tripo/history/:id",     verifyAuth, deleteHistoryItem);
  router.delete("/tripo/history",         verifyAuth, clearHistory);

  return router;
}

export default createTripoRouter;
