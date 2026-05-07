// src/controllers/pipelineController.js
import { pipelineService } from "../services/pipelineService.js";
import { lodService } from "../services/lodService.js";
import { estimatePipelineCost } from "../lib/creditEstimator.js";
import { LOD_PRESETS } from "../config/tripo.config.js";
import { randomUUID } from "crypto";

/* ─── generateCharacter ───────────────────────────────────────────────── */
export async function generateCharacter(req, res) {
  const body = req.body;

  if (!body.prompt && !body.image_token) {
    res.status(400).json({ success: false, message: "prompt or image_token required" });
    return;
  }

  // FIX: a pipelineId-t a controller generálja és adja át a service-nek,
  // hogy a kliens és a _pipelines Map ugyanazt az ID-t használja.
  const pipelineId = randomUUID();
  res.json({
    success:    true,
    pipelineId,
    message:    "Pipeline started. Poll GET /tripo/pipeline/:id for status.",
  });

  // Fire-and-forget
  pipelineService.generateCharacter({ ...body, pipelineId, userId: req.user?.uid }).then(result => {
    console.log(`[Pipeline ${result.pipelineId}] final status=${result.status}`);
  }).catch(err => {
    console.error("[pipelineController] generateCharacter error:", err.message);
  });
}

/* ─── Get pipeline status ─────────────────────────────────────────────── */
export async function getPipeline(req, res) {
  // Fast path: in-memory Map (set during this server's lifetime)
  const result = pipelineService.get(req.params.pipelineId);
  if (result) {
    res.json({ success: true, ...result });
    return;
  }

  // Fallback: Firestore for pipelines started by a previous server instance
  // (e.g. after nodemon restart during a long-running pipeline)
  try {
    const admin = (await import("firebase-admin")).default;
    const snap = await admin.firestore()
      .collection("tripo_pipelines")
      .doc(req.params.pipelineId)
      .get();
    if (snap.exists) {
      res.json({ success: true, fromFirestore: true, ...snap.data() });
      return;
    }
  } catch (err) {
    console.warn("[pipelineController] getPipeline Firestore fallback error:", err.message);
  }

  res.status(404).json({ success: false, message: "Pipeline not found" });
}

export async function estimatePipeline(req, res) {
  try {
    const estimate = estimatePipelineCost(req.body);
    res.json({ success: true, estimate });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
}

/* ─── Generate LOD chain ──────────────────────────────────────────────── */
export async function generateLod(req, res) {
  const { source_task_id, levels, export_zip } = req.body;

  if (!source_task_id) {
    res.status(400).json({ success: false, message: "source_task_id required" });
    return;
  }

  // Validate levels if provided
  if (levels) {
    for (const l of levels) {
      if (!l.label || !l.face_limit || l.face_limit < 1 || l.face_limit > 500_000) {
        res.status(400).json({ success: false, message: "Each level needs label and face_limit (1–500 000)" });
        return;
      }
    }
  }

  try {
    const result = await lodService.generateChain(
      source_task_id,
      levels ?? LOD_PRESETS.map(l => ({ label: l.label, face_limit: l.face_limit })),
      export_zip ?? false,
      req.user?.uid,
    );
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[pipelineController] generateLod error:", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
}
