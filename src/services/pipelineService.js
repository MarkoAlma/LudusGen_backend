// src/services/pipelineService.js
import { randomUUID } from "crypto";
import { getTripoClient } from "../lib/tripoClient.js";
import { resolveEnginePreset } from "../lib/enginePresets.js";
import { analyticsService } from "./analyticsService.js";
import { createTaskWithBilling, refundCreditReservation } from "./tripoBillingService.js";
import { DEFAULT_MODEL } from "../config/tripo.config.js";
import {
  startPipeline,
  updatePipeline,
  finishPipeline,
} from "./pipelineRecoveryService.js";

/** @type {Map<string, object>} pipelineId → PipelineResult */
const _pipelines = new Map();

class PipelineService {
  get(pipelineId) { return _pipelines.get(pipelineId); }

  /**
   * Full character generation pipeline.
   * generation → [smart_low_poly] → prerigcheck → rig → retarget → convert
   * @param {import("../../src/config/tripo.config.js").GenerateCharacterRequest} req
   */
  async generateCharacter(req) {
    // FIX: ha a controller átadja a pipelineId-t, azt használjuk — így a kliens
    // és a _pipelines Map ugyanazt az ID-t látja.
    const pipelineId   = req.pipelineId ?? randomUUID();
    const client       = getTripoClient();
    const enginePreset = req.engine ? resolveEnginePreset(req.engine) : null;
    const genType      = req.image_token ? "image_to_model" : "text_to_model";

    const result = { pipelineId, steps: [], finalModelUrl: null, status: "running" };
    _pipelines.set(pipelineId, result);
    console.log(`[Pipeline ${pipelineId}] starting (${genType})`);

    // Persist initial state to Firestore so a server crash can be detected
    // at boot time and credits refunded for each completed step.
    await startPipeline({
      pipelineId,
      userId: req.userId,
      type: genType,
      prompt: req.prompt ?? null,
    });

    try {
      /* Step 1 — Generation */
      let currentTaskId = await this._runStep(result, genType, {
        type: genType,
        ...(genType === "text_to_model"
          ? { prompt: req.prompt }
          : { file: { type: "jpg", file_token: req.image_token } }),
        model_version:   req.model_version ?? DEFAULT_MODEL,
        texture:         true,
        pbr:             true,
        texture_quality: "detailed",
        ...(req.callback_url && { callback_url: req.callback_url }),
      }, client, req.userId);

      /* Step 2 — Smart Low Poly (optional) */
      if (req.run_smart_low_poly && req.smart_low_poly_faces) {
        try {
          currentTaskId = await this._runStep(result, "smart_low_poly", {
            type: "smart_low_poly",
            original_model_task_id: currentTaskId,
            face_limit: req.smart_low_poly_faces,
            quad: false,
          }, client, req.userId);
        } catch (err) {
          console.warn(`[Pipeline ${pipelineId}] smart_low_poly skipped:`, err.message);
          result.steps.push({ type: "smart_low_poly", status: "skipped" });
        }
      }

      /* Step 3 — Pre-rig check */
      if (req.run_rig) {
        let isAnimatable = true;
        try {
          const checkId = await this._runStep(result, "animate_prerigcheck", {
            type: "animate_prerigcheck",
            original_model_task_id: currentTaskId,
          }, client, req.userId);
          const checkTask = await client.getTask(checkId);
          isAnimatable    = checkTask.output?.is_animatable !== false;
          console.log(`[Pipeline ${pipelineId}] rig check: isAnimatable=${isAnimatable}`);
        } catch (err) {
          console.warn(`[Pipeline ${pipelineId}] prerigcheck skipped:`, err.message);
          result.steps.push({ type: "animate_prerigcheck", status: "skipped" });
        }

        /* Step 4 — Rig */
        if (isAnimatable) {
          currentTaskId = await this._runStep(result, "animate_rig", {
            type: "animate_rig",
            original_model_task_id: currentTaskId,
            spec:       req.rig_spec ?? "mixamo",
            out_format: "glb",
          }, client, req.userId);
        }
      }

      /* Step 5 — Retarget (optional) */
      if (req.animations?.length && req.run_rig) {
        try {
          currentTaskId = await this._runStep(result, "animate_retarget", {
            type: "animate_retarget",
            original_model_task_id: currentTaskId,
            animations: req.animations,
            out_format: "glb",
          }, client, req.userId);
        } catch (err) {
          console.warn(`[Pipeline ${pipelineId}] retarget skipped:`, err.message);
          result.steps.push({ type: "animate_retarget", status: "skipped" });
        }
      }

      /* Step 6 — Convert (engine-specific) */
      if (enginePreset || req.convert_format) {
        const p = enginePreset ?? { format: req.convert_format, quad: false, face_limit: null, scale_factor: 1, pivot_to_center_bottom: false };
        currentTaskId = await this._runStep(result, "convert_model", {
          type:                    "convert_model",
          original_model_task_id: currentTaskId,
          format:                  p.format,
          quad:                    p.quad,
          pivot_to_center_bottom:  p.pivot_to_center_bottom,
          scale_factor:            p.scale_factor,
          ...(p.face_limit !== null && { face_limit: p.face_limit }),
        }, client, req.userId);
      }

      /* Done */
      const finalTask = await client.getTask(currentTaskId);
      const out       = finalTask.output ?? {};
      result.finalModelUrl = out.model ?? out.animated_model ?? out.rigged_model ?? null;
      result.status        = "completed";
      console.log(`[Pipeline ${pipelineId}] completed`);

      // Persist final success state to Firestore
      await finishPipeline(pipelineId, { status: "completed", finalModelUrl: result.finalModelUrl });

      return result;

    } catch (err) {
      result.status = "failed";
      result.error  = err.message;
      analyticsService.recordTaskError(pipelineId, "text_to_model", err.message);
      console.error(`[Pipeline ${pipelineId}] failed:`, err.message);

      // Persist failure so boot-time recovery doesn't try to refund again
      await finishPipeline(pipelineId, { status: "failed", error: err.message });

      return result;
    }
  }

  async _runStep(result, type, body, client, userId) {
    const step = { type, status: "running", startedAt: Date.now() };
    result.steps.push(step);
    let reservation = null;
    let taskId = null;
    try {
      const billedTask = await createTaskWithBilling({ userId, body });
      taskId = billedTask.taskId;
      reservation = billedTask.reservation;
      step.taskId  = taskId;

      // Persist step start (includes taskId so crash recovery can refund it)
      await updatePipeline(result.pipelineId, { steps: result.steps }).catch(() => {});

      const poll = await client.pollTask(taskId, {
        onProgress: (p, s) => console.log(`[Pipeline step=${type} task=${taskId}] ${s} ${p}%`),
      });
      if (!poll.success) {
        await refundCreditReservation(reservation, `pipeline_${type}_${poll.status}`, taskId);
        throw new Error(`Step "${type}" task ${taskId} status=${poll.status}`);
      }
      step.status     = "success";
      step.modelUrl   = poll.modelUrl;
      step.finishedAt = Date.now();
      analyticsService.recordTaskEnd(taskId, "success", step.finishedAt - step.startedAt);

      // Persist step completion
      await updatePipeline(result.pipelineId, { steps: result.steps }).catch(() => {});

      return taskId;
    } catch (err) {
      step.status     = "failed";
      step.error      = err.message;
      step.finishedAt = Date.now();
      await updatePipeline(result.pipelineId, { steps: result.steps }).catch(() => {});
      throw err;
    }
  }
}

export const pipelineService = new PipelineService();
