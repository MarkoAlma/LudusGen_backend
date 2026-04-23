// src/services/taskService.js
import { getTripoClient } from "../lib/tripoClient.js";
import { analyticsService } from "./analyticsService.js";
import { extractModelUrl } from "../utils/tripoUtils.js";
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
    const client = getTripoClient();
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
  async get(taskId, outputHints = {}) {
    const client = getTripoClient();
    const task = await client.getTask(taskId);
    return this.taskToPollResult(task, outputHints);
  }

  /* ── Cancel ──────────────────────────────────────────────────────── */
  async cancel(taskId) {
    const client = getTripoClient();
    const result = await client.cancelTask(taskId);
    analyticsService.recordTaskEnd(taskId, "stop_requested", 0);
    console.log(`[TaskService] stop requested for ${taskId} — task is still running on Tripo servers`);
    return result;
  }

  /* ── List ────────────────────────────────────────────────────────── */
  async list(params) {
    const client = getTripoClient();
    const limit = Math.min(100, Math.max(1, params.limit ?? 20));
    return client.listTasks({ ...params, limit });
  }

  /* ── Poll ────────────────────────────────────────────────────────── */
  async poll(taskId, outputHints = {}) {
    const client = getTripoClient();
    const startMs = Date.now();
    try {
      const result = await client.pollTask(taskId, {
        onProgress: (p, s) =>
          console.log(`[TaskService] poll ${taskId}: ${s} ${p}%`),
      });
      analyticsService.recordTaskEnd(taskId, result.status, Date.now() - startMs);
      if (!outputHints || Object.keys(outputHints).length === 0) {
        return result;
      }
      return {
        ...result,
        ...this.taskToPollResult({ ...result, output: result.rawOutput ?? {}, type: result.rawOutput?.type ?? null }, outputHints),
      };
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

        // ── P1-20260311: csak engedélyezett paraméterek ──────────────────
        // A P1 modell nem támogatja: quad, smart_low_poly, generate_parts,
        // geometry_quality, t_pose, style
        // Forrás: Tripo API docs – "P1-20260311 Parameter Support"
        if (mv === "P1-20260311") {
          const P1_ALLOWED = new Set([
            "type", "model_version", "prompt", "file", "files",
            "images", "batch_images",
            "texture", "pbr", "texture_quality",
            "face_limit", "model_seed", "texture_seed",
            "auto_size", "compress", "export_uv",
            "negative_prompt",
            "callback_url",
          ]);
          for (const key of Object.keys(b)) {
            if (!P1_ALLOWED.has(key)) {
              console.warn(`[TaskService] P1-20260311: dropping unsupported param "${key}"`);
              delete b[key];
            }
          }
          // face_limit: P1 range = 48–20000
          if (b["face_limit"] !== undefined) {
            const fl = Number(b["face_limit"]);
            if (!Number.isFinite(fl) || fl < 48 || fl > 20_000) {
              console.warn(`[TaskService] P1-20260311: face_limit ${fl} out of range 48–20000, dropping`);
              delete b["face_limit"];
            }
          }
          // texture_quality: P1 only supports "standard" — "detailed" is not available
          if (b["texture_quality"] && b["texture_quality"] !== "standard") {
            console.warn(`[TaskService] P1-20260311: dropping unsupported texture_quality "${b["texture_quality"]}", using standard`);
            delete b["texture_quality"];
          }
          if (!b["texture"] && !b["pbr"]) delete b["texture_quality"];
          if (b["texture"] === undefined) delete b["texture"];
          if (!b["pbr"]) delete b["pbr"];
          break; // P1 validáció kész, többi szabály nem vonatkozik rá
        }

        // prompt length
        if (body.type === "text_to_model" || (body.type === "image_to_model" && b["prompt"])) {
          const p = b["prompt"];
          if (body.type === "text_to_model" && !p?.trim())
            throw new Error("prompt is required for text_to_model");
          if (p && p.length > 1000) throw new Error("prompt max 1000 characters");
        }

        // image/batch validation
        if (body.type === "image_to_model") {
          const hasFile = !!b.file || (!!b.images && b.images.length > 0) || (!!b.batch_images && b.batch_images.length > 0);
          if (!hasFile) throw new Error("file, images, or batch_images required for image_to_model");
        }

        // negative_prompt length — Tripo API max 255 characters
        const np = b["negative_prompt"];
        if (np && np.length > 255) {
          b["negative_prompt"] = np.slice(0, 255);
          console.warn(`[TaskService] negative_prompt truncated to 255 chars (was ${np.length})`);
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
        if (b["smart_low_poly"] && !b["face_limit"]) {
          b["face_limit"] = b["quad"] ? 5_000 : 8_000; // getFaceLimitConfig defaultVal-ok
        }
        const fl = validateFaceLimit(b["face_limit"], !!b["smart_low_poly"], !!b["quad"]);
        if (fl !== undefined) b["face_limit"] = fl; else delete b["face_limit"];

        // texture_quality — "detailed" (default), "HD" vagy "standard" (→ "detailed") megengedett
        // FIX: "standard" értéket ne írjuk felül "detailed"-re csendben
        if (!b["texture"] && !b["pbr"]) {
          delete b["texture_quality"];
        } else {
          // API valid values: "standard" (default) | "detailed" (high-res)
          // "HD" nem létező API érték — "detailed"-re mappolva
          const tq = b["texture_quality"];
          if (tq === "standard") {
            b["texture_quality"] = "standard";
          } else {
            b["texture_quality"] = "detailed"; // "HD", undefined, egyéb → detailed
          }
        }
        if (b["texture"] === undefined) delete b["texture"];
        if (!b["pbr"]) delete b["pbr"];

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
        const fmt = String(b["format"] ?? "glb").trim().toLowerCase();
        if (!VALID_CONVERT_FORMATS.has(fmt))
          throw new Error(`Invalid format "${fmt}". Valid: ${[...VALID_CONVERT_FORMATS].join(", ")}`);
        if (b["is_rigged_input"] && RIGGED_UNSUPPORTED_FORMATS.has(fmt))
          throw new Error(`Format "${fmt}" is not supported for rigged model inputs. Use GLB or FBX.`);
        const apiFormatMap = {
          glb: "GLTF",
          gltf: "GLTF",
          fbx: "FBX",
          obj: "OBJ",
          stl: "STL",
          "3mf": "3MF",
          usdz: "USDZ",
        };
        b["format"] = b["quad"] ? "FBX" : (apiFormatMap[fmt] ?? fmt.toUpperCase());
        delete b["is_rigged_input"];
        
        const isSlp = !!b["smart_low_poly"];
        const fl = validateFaceLimit(b["face_limit"], isSlp, !!b["quad"]);
        if (fl !== undefined) b["face_limit"] = fl; else delete b["face_limit"];
        
        if (!b["quad"]) delete b["quad"];
        if (!b["pivot_to_center_bottom"]) delete b["pivot_to_center_bottom"];
        // Tripo does not accept smart_low_poly parameter here, so delete it before passing to API
        delete b["smart_low_poly"];
        break;
      }

      case "animate_rig": {
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        const fmt = b["out_format"] ?? "glb";
        if (!["glb", "fbx"].includes(fmt))
          throw new Error("out_format must be glb or fbx");
        b["out_format"] = fmt;

        // Default to "tripo" spec (API preferred)
        const spec = b["spec"] ?? "tripo";
        if (!["mixamo", "tripo"].includes(spec))
          throw new Error("spec must be mixamo or tripo");
        b["spec"] = spec;

        // Set rig_type if not provided
        if (!b["rig_type"]) b["rig_type"] = "biped";
        const validRigTypes = ["biped", "quadruped", "hexapod", "octopod", "avian", "serpentine", "aquatic"];
        if (!validRigTypes.includes(b["rig_type"]))
          throw new Error(`Invalid rig_type. Valid: ${validRigTypes.join(", ")}`);

        // Add missing optional flags with proper defaults
        // FIX: handle export_geometry alias from older frontend code
        if (b["export_with_geometry"] === undefined && b["export_geometry"] !== undefined) {
          b["export_with_geometry"] = b["export_geometry"];
        }
        delete b["export_geometry"]; // always cleanup the alias

        if (b["bake_animation"] === undefined) b["bake_animation"] = true;
        if (b["export_with_geometry"] === undefined) b["export_with_geometry"] = true;
        if (b["animate_in_place"] === undefined) b["animate_in_place"] = false;

        break;
      }

      case "animate_retarget": {
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");

        const fmt = b["out_format"] ?? "glb";
        if (!["glb", "fbx"].includes(fmt))
          throw new Error("out_format must be glb or fbx");
        b["out_format"] = fmt;

        // Handle both animation (single) and animations (array) formats
        // taskController már preset:biped:walk formátumra alakítja az értéket
        const animList = b["animations"] ?? (b["animation"] ? [b["animation"]] : []);
        if (animList.length === 0) throw new Error("animation or animations array required");

        // Validate: preset: prefixes always pass, otherwise check VALID_ANIMATIONS
        const invalid = animList.filter(a => {
          if (a.startsWith("preset:")) return false;
          return !VALID_ANIMATIONS.has(a);
        });
        if (invalid.length) throw new Error(`Unknown animation(s): ${invalid.join(", ")}`);

        // Normalize to API format: arrays > 1 item, single strings for 1 item
        if (animList.length > 1) {
          b["animations"] = animList;
          delete b["animation"];
        } else {
          b["animation"] = animList[0];
          delete b["animations"];
        }

        // Add optional parameters with proper defaults
        if (b["bake_animation"] === undefined) b["bake_animation"] = true;
        if (b["export_with_geometry"] === undefined) b["export_with_geometry"] = true;
        if (b["animate_in_place"] === undefined) b["animate_in_place"] = false;

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
        // FIX: "standard" is valid, don't coerce to "detailed"
        if (!["standard", "detailed"].includes(b["texture_quality"])) {
          b["texture_quality"] = "detailed";
        }
        if (!b["pbr"]) delete b["pbr"];
        break;

      case "animate_prerigcheck":
      case "refine_model":
        if (!b["original_model_task_id"] && !b["draft_model_task_id"])
          throw new Error("original_model_task_id / draft_model_task_id required");
        // Refine also accepts prompt and negative_prompt to guide refinement
        if (b["prompt"] && b["prompt"].length > 1000) throw new Error("prompt max 1000 characters");
        if (b["negative_prompt"] && b["negative_prompt"].length > 255) b["negative_prompt"] = b["negative_prompt"].slice(0, 255);
        break;

      case "text_to_image": {
        const p = b["prompt"];
        if (!p?.trim()) throw new Error("prompt required for text_to_image");
        if (p.length > 1000) throw new Error("prompt max 1000 characters");
        break;
      }

      case "import_model":
        if (!b["file"])
          throw new Error("file required for import_model");
        break;

      case "texture_edit":
        b["type"] = "texture_model";
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        if (!["standard", "detailed"].includes(b["texture_quality"])) {
          b["texture_quality"] = "standard";
        }
        delete b["creativity_strength"];
        break;
    }

    return b;
  }

  /* ── Convert raw task to PollResult ──────────────────────────────── */
  taskToPollResult(task, outputHints = {}) {
    const out = task.output ?? {};
    if (task.status === "success" && (task.type === "animate_retarget") && Array.isArray(out.animated_models)) {
      console.log(`[TaskService] animate_retarget result for ${task.task_id}:`, { animated_models_count: out.animated_models.length, animated_models: out.animated_models, animated_model: out.animated_model ?? null });
    }
    const { modelUrl, rigCheckResult, rigType, topology, rawOutput } = extractModelUrl(task, outputHints);
    return {
      success: task.status === "success",
      status: task.status,
      progress: task.progress ?? 0,
      modelUrl,
      rigCheckResult,
      rigType,
      topology,
      rawOutput,
    };
  }
}

export const taskService = new TaskService();
