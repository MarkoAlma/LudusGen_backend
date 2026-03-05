// src/services/lodService.js
import { getTripoClient } from "../lib/tripoClient.js";
import { analyticsService } from "./analyticsService.js";
import { LOD_PRESETS } from "../config/tripo.config.js";

class LodService {
  /**
   * Generate multiple LOD levels in parallel for a source task.
   * @param {string} sourceTaskId
   * @param {{ label: string, face_limit: number, quad?: boolean, format?: string }[]} [levels]
   * @param {boolean} [exportZip]
   */
  async generateChain(sourceTaskId, levels = LOD_PRESETS, exportZip = false) {
    const client = getTripoClient();
    console.log(`[LOD] generating ${levels.length} levels from task=${sourceTaskId}`);

    const lodLevels = levels.map((l, i) => ({
      level: i, label: l.label, face_limit: l.face_limit, status: "pending",
    }));

    const results = await Promise.allSettled(
      levels.map((spec, i) => this._runLevel(sourceTaskId, lodLevels[i], spec, client)),
    );

    results.forEach((r, i) => {
      if (r.status === "fulfilled") Object.assign(lodLevels[i], r.value);
      else { lodLevels[i].status = "failed"; console.error(`[LOD] ${lodLevels[i].label} failed:`, r.reason?.message); }
    });

    let zipUrl;
    if (exportZip) {
      try { zipUrl = await this._bundleZip(sourceTaskId, lodLevels); }
      catch (err) { console.warn("[LOD] ZIP export failed:", err.message); }
    }

    return { sourceTaskId, levels: lodLevels, ...(zipUrl && { zipUrl }) };
  }

  async _runLevel(sourceTaskId, lod, spec, client) {
    const startMs = Date.now();
    const taskId  = await client.createTask({
      type:                    "convert_model",
      original_model_task_id: sourceTaskId,
      format:                  spec.format ?? "glb",
      quad:                    spec.quad   ?? false,
      face_limit:              spec.face_limit,
    });
    analyticsService.recordTaskStart(taskId, "convert_model");
    console.log(`[LOD] ${lod.label} task=${taskId} (face_limit=${spec.face_limit})`);

    const result = await client.pollTask(taskId);
    if (!result.success) {
      analyticsService.recordTaskEnd(taskId, result.status, Date.now() - startMs);
      throw new Error(`LOD ${lod.label} task ${taskId} status=${result.status}`);
    }
    analyticsService.recordTaskEnd(taskId, "success", Date.now() - startMs);
    return { taskId, modelUrl: result.modelUrl ?? undefined, status: "success" };
  }

  async _bundleZip(_sourceTaskId, _levels) {
    // Implement with `archiver` npm package:
    // 1. Download each lod.modelUrl with authenticated fetch
    // 2. Archive them as LOD0.glb, LOD1.glb, LOD2.glb
    // 3. Upload to your storage, return signed URL
    throw new Error("ZIP export not configured — implement _bundleZip() with your storage provider.");
  }
}

export const lodService = new LodService();