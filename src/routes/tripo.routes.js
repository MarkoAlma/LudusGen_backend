// src/routes/tripo.routes.js
//
// Unified Tripo API router.
// Mounts on /api or wherever your app registers it.

import { Router } from "express";
import multer from "multer";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";

// Controllers
import {
  createTask,
  getTask,
  cancelTask,
  listTasks,
  getBalance,
  uploadFile,
  modelProxy,
  creditEstimate,
  getEnginePreset,
  batchGenerate,
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

/* ─── Middleware ──────────────────────────────────────────────────────── */
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 20 * 1024 * 1024 },
});

/** Generation rate limiter — 30 req/min per user */
const genLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  keyGenerator: (req) => {
    if (req.user?.uid) {
      return `user:${req.user.uid}`;
    }
    return ipKeyGenerator(req);
  },
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

  /** Create any Tripo task */
  router.post("/tripo/task", verifyAuth, genLimiter, createTask);

  /** Poll a single task */
  router.get("/tripo/task/:taskId", verifyAuth, getTask);

  /** Cancel a running/queued task */
  router.post("/tripo/task/:taskId/cancel", verifyAuth, cancelTask);

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
   * Tripo webhook receiver.
   * NOTE: mount express.raw({ verify: captureRawBody }) BEFORE express.json()
   * on this route in your app setup:
   *   app.use("/api/tripo/webhook", express.raw({ type: "application/json", verify: (req, res, buf) => { req.rawBody = buf; } }))
   */
  router.post("/tripo/webhook", handleWebhook);

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

  return router;
}

export default createTripoRouter;