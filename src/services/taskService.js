// src/services/taskService.js
import { getTripoClient } from "../lib/tripoClient.js";
import { analyticsService } from "./analyticsService.js";
import {
  VALID_MODEL_VERSIONS,
  VALID_CONVERT_FORMATS,
  VALID_ANIMATIONS,
  VALID_STYLES,
  RIGGED_UNSUPPORTED_FORMATS,
  DEFAULT_MODEL,
} from "../config/tripo.config.js";
import { validateFaceLimit } from "../lib/enginePresets.js";
import crypto from "crypto";

/* ─── TaskService ─────────────────────────────────────────────────────── */

class TaskService {
  /* ── Create ─────────────────────────────────────────────────────── */
  async create(body, opts = {}) {
    const validated = this.validate(body);
    if (opts.callbackUrl) validated["callback_url"] = opts.callbackUrl;

    const idempotencyKey = opts.idempotencyKey ?? crypto.randomUUID();
    const client  = getTripoClient();
    const startMs = Date.now();

    try {
      const taskId = await client.createTask(validated, idempotencyKey);
      analyticsService.recordTaskStart(taskId, body.type, body.model_version);
      console.log(`[TaskService] created task ${taskId} (type=${body.type}) in ${Date.now() - startMs}ms`);
      return taskId;
    } catch (err) {
      analyticsService.recordTaskError("unknown", body.type, err.message);
      throw err;
    }
  }

  /* ── Get ─────────────────────────────────────────────────────────── */
  async get(taskId) {
    const client = getTripoClient();
    const task   = await client.getTask(taskId);
    return this.taskToPollResult(task);
  }

  /* ── Cancel ──────────────────────────────────────────────────────── */
  async cancel(taskId) {
    const client = getTripoClient();
    await client.cancelTask(taskId);
    analyticsService.recordTaskEnd(taskId, "cancelled", 0);
    console.log(`[TaskService] cancelled task ${taskId}`);
  }

  /* ── List ────────────────────────────────────────────────────────── */
  async list(params) {
    const client = getTripoClient();
    const limit = Math.min(100, Math.max(1, params.limit ?? 20));
    return client.listTasks({ ...params, limit });
  }

  /* ── Poll ────────────────────────────────────────────────────────── */
  async poll(taskId) {
    const client  = getTripoClient();
    const startMs = Date.now();
    try {
      const result = await client.pollTask(taskId, {
        onProgress: (p, s) =>
          console.log(`[TaskService] poll ${taskId}: ${s} ${p}%`),
      });
      analyticsService.recordTaskEnd(taskId, result.status, Date.now() - startMs);
      return result;
    } catch (err) {
      analyticsService.recordTaskError(taskId, "unknown", err.message);
      throw err;
    }
  }

  /* ── Validate task body ──────────────────────────────────────────── */
  validate(body) {
    const b = { ...body }; // ne mutáljuk az eredetit

    switch (body.type) {
      case "text_to_model":
      case "image_to_model":
      case "multiview_to_model": {
        // model_version
        const mv = b["model_version"] ?? DEFAULT_MODEL;
        if (!VALID_MODEL_VERSIONS.has(mv))
          throw new Error(`Invalid model_version "${mv}". Valid: ${[...VALID_MODEL_VERSIONS].join(", ")}`);
        b["model_version"] = mv;

        // prompt length
        if (body.type === "text_to_model" || (body.type === "image_to_model" && b["prompt"])) {
          const p = b["prompt"];
          if (body.type === "text_to_model" && !p?.trim())
            throw new Error("prompt is required for text_to_model");
          if (p && p.length > 1000) throw new Error("prompt max 1000 characters");
        }

        // generate_parts constraints
        const gp = b["generate_parts"];
        if (gp) {
          if (b["texture"] || b["pbr"])
            throw new Error("generate_parts is not compatible with texture=true or pbr=true");
          if (b["quad"])
            throw new Error("generate_parts is not compatible with quad=true");
        }
        // FIX: generate_parts false értéket ne küldjük el
        if (!b["generate_parts"]) delete b["generate_parts"];

        // face_limit
        const fl = validateFaceLimit(b["face_limit"], !!b["smart_low_poly"], !!b["quad"]);
        if (fl !== undefined) b["face_limit"] = fl; else delete b["face_limit"];

        // texture_quality — csak "detailed" vagy "HD" megengedett
        b["texture_quality"] = b["texture_quality"] === "HD" ? "HD" : "detailed";

        // FIX: texture/pbr false értéket ne küldjük el
        if (!b["texture"]) delete b["texture"];
        if (!b["pbr"])     delete b["pbr"];

        // style
        if (b["style"] && !VALID_STYLES.has(b["style"]))
          throw new Error(`Invalid style "${b["style"]}". Valid: ${[...VALID_STYLES].join(", ")}`);

        // FIX: geometry_quality — csak "detailed" megengedett, "standard"-ot töröljük
        // (az API alapból standard-ot használ, explicit megadása hibát okoz)
        if (b["geometry_quality"] !== "detailed") {
          delete b["geometry_quality"];
        }
        break;
      }

      case "smart_low_poly": {
        if (!b["original_model_task_id"])
          throw new Error("original_model_task_id required");
        const fl = validateFaceLimit(b["face_limit"], true, !!b["quad"]);
        if (fl === undefined)
          throw new Error("face_limit is required for smart_low_poly");
        b["face_limit"] = fl;
        if (!b["quad"]) delete b["quad"];
        break;
      }

      case "convert_model": {
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        const fmt = b["format"] ?? "glb";
        if (!VALID_CONVERT_FORMATS.has(fmt))
          throw new Error(`Invalid format "${fmt}". Valid: ${[...VALID_CONVERT_FORMATS].join(", ")}`);
        if (b["is_rigged_input"] && RIGGED_UNSUPPORTED_FORMATS.has(fmt))
          throw new Error(`Format "${fmt}" is not supported for rigged model inputs. Use GLB or FBX.`);
        if (b["quad"]) b["format"] = "fbx";
        delete b["is_rigged_input"];
        const fl = validateFaceLimit(b["face_limit"], false, !!b["quad"]);
        if (fl !== undefined) b["face_limit"] = fl; else delete b["face_limit"];
        if (!b["quad"])               delete b["quad"];
        if (!b["pivot_to_center_bottom"]) delete b["pivot_to_center_bottom"];
        break;
      }

      case "animate_rig": {
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        const fmt = b["out_format"] ?? "glb";
        if (!["glb", "fbx"].includes(fmt))
          throw new Error("out_format must be glb or fbx");
        b["out_format"] = fmt;
        const spec = b["spec"] ?? "mixamo";
        if (!["mixamo", "tripo"].includes(spec))
          throw new Error("spec must be mixamo or tripo");
        b["spec"] = spec;
        break;
      }

      case "animate_retarget": {
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        const fmt = b["out_format"] ?? "glb";
        if (!["glb", "fbx"].includes(fmt))
          throw new Error("out_format must be glb or fbx");
        b["out_format"] = fmt;
        const animList = b["animations"] ?? (b["animation"] ? [b["animation"]] : []);
        if (animList.length === 0) throw new Error("animation or animations array required");
        const invalid = animList.filter(a => !VALID_ANIMATIONS.has(a));
        if (invalid.length) throw new Error(`Unknown animation(s): ${invalid.join(", ")}`);
        if (animList.length > 1) {
          b["animations"] = animList;
          delete b["animation"];
        } else {
          b["animation"] = animList[0];
          delete b["animations"];
        }
        break;
      }

      case "stylize_model": {
        if (!b["original_model_task_id"] || !b["style"])
          throw new Error("original_model_task_id and style required");
        if (!VALID_STYLES.has(b["style"]))
          throw new Error(`Invalid style "${b["style"]}". Valid: ${[...VALID_STYLES].join(", ")}`);
        break;
      }

      case "mesh_segmentation":
      case "mesh_completion":
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        if (b["is_rigged_input"])
          throw new Error(`${body.type} is not supported for rigged/animated models`);
        delete b["is_rigged_input"];
        break;

      case "texture_model":
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        b["texture_quality"] = b["texture_quality"] === "HD" ? "HD" : "detailed";
        if (!b["pbr"]) delete b["pbr"];
        break;

      case "animate_prerigcheck":
      case "refine_model":
        if (!b["original_model_task_id"] && !b["draft_model_task_id"])
          throw new Error("original_model_task_id / draft_model_task_id required");
        break;

      case "text_to_image": {
        const p = b["prompt"];
        if (!p?.trim()) throw new Error("prompt required for text_to_image");
        if (p.length > 1000) throw new Error("prompt max 1000 characters");
        break;
      }

      case "import_model":
        if (!b["file"]?.["object"])
          throw new Error("file.object required for import_model");
        break;
    }

    return b;
  }

  /* ── Convert raw task to PollResult ──────────────────────────────── */
  taskToPollResult(task) {
    const out = task.output ?? {};
    return {
      success:        task.status === "success",
      status:         task.status,
      progress:       task.progress ?? 0,
      modelUrl:
        out.model          ??
        out.pbr_model      ??
        out.base_model     ??
        out.rigged_model   ??
        out.animated_model ??
        null,
      rigCheckResult: out.is_animatable ?? null,
      rawOutput:      out,
    };
  }
}

export const taskService = new TaskService();