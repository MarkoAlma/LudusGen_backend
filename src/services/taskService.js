// src/services/taskService.js
import { getTripoClient } from "../lib/tripoClient.js";
import { analyticsService } from "./analyticsService.js";
import { extractModelUrl } from "../utils/tripoUtils.js";
import {
  VALID_MODEL_VERSIONS,
  VALID_CONVERT_FORMATS,
  VALID_ANIMATIONS,
  VALID_GENERATION_STYLES,
  VALID_STYLIZE_STYLES,
  VALID_TEXTURE_MODEL_VERSIONS,
  VALID_COMPRESS_TYPES,
  VALID_IMAGE_ORIENTATIONS,
  VALID_MULTIVIEW_IMAGE_MODES,
  RIGGED_UNSUPPORTED_FORMATS,
  DEFAULT_MODEL,
  TRIPO_PROMPT_MAX_LENGTH,
  TRIPO_NEGATIVE_PROMPT_MAX_LENGTH,
  TRIPO_IMAGE_TO_MODEL_BATCH_MAX,
} from "../config/tripo.config.js";
import { validateFaceLimit } from "../lib/enginePresets.js";
import crypto from "crypto";

const DEBUG_TRIPO = process.env.DEBUG_TRIPO === "true";
const DETAILED_TEXTURE_MODEL_VERSION = "v3.0-20250812";
const VALID_TEXTURE_QUALITIES = new Set(["standard", "detailed"]);
const VALID_TEXTURE_ALIGNMENTS = new Set(["original_image", "geometry"]);

function trimString(value) {
  return typeof value === "string" ? value.trim() : value;
}

function validatePromptLength(value, fieldName) {
  if (!value) return;
  if (String(value).length > TRIPO_PROMPT_MAX_LENGTH) {
    throw new Error(`${fieldName} max ${TRIPO_PROMPT_MAX_LENGTH} characters`);
  }
}

function normalizeBoolean(value, fallback = false) {
  if (value === undefined) return fallback;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value === "true";
  return Boolean(value);
}

function normalizeStringField(body, key) {
  if (body[key] === undefined) return;
  const value = trimString(body[key]);
  if (value) body[key] = value;
  else delete body[key];
}

function normalizeOptionalEnum(body, key, validValues) {
  if (body[key] === undefined) return;
  const value = trimString(body[key]);
  if (!value) {
    delete body[key];
    return;
  }
  if (!validValues.has(value)) {
    throw new Error(`Invalid ${key} "${body[key]}". Valid: ${[...validValues].filter(Boolean).join(", ")}`);
  }
  body[key] = value;
}

function normalizeCallbackUrl(value) {
  const urlValue = trimString(value);
  if (!urlValue) return null;
  if (urlValue.length > 2048) {
    throw new Error("callback_url too long");
  }
  let parsed;
  try {
    parsed = new URL(urlValue);
  } catch {
    throw new Error("Invalid callback_url");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("callback_url must use http or https");
  }
  return parsed.toString();
}

function normalizeObjectRef(input) {
  if (!input || typeof input !== "object") return null;
  const bucket = trimString(input.bucket);
  const key = trimString(input.key);
  if (!bucket || !key) return null;
  return { bucket, key };
}

function normalizeFileRef(input, fallbackType = "png") {
  if (!input) return null;
  if (typeof input === "string") {
    return { type: fallbackType, file_token: input.trim() };
  }
  if (typeof input !== "object") {
    throw new Error("Invalid file reference");
  }

  const type = trimString(input.type) || fallbackType;
  const fileToken = trimString(input.file_token);
  const url = trimString(input.url);
  const object = normalizeObjectRef(input.object);

  if (fileToken) return { type, file_token: fileToken };
  if (url) return { type, url };
  if (object) return { type, object };

  throw new Error("file reference must include file_token, url, or object");
}

function normalizeFileRefList(list, fallbackType = "png") {
  if (!Array.isArray(list)) return [];
  return list.map((item) => normalizeFileRef(item, fallbackType));
}

function normalizeOptionalFileRef(input, fallbackType = "png") {
  if (!input) return {};
  if (typeof input === "object" && !trimString(input.file_token) && !trimString(input.url) && !normalizeObjectRef(input.object)) {
    return {};
  }
  return normalizeFileRef(input, fallbackType);
}

function normalizeMultiviewFileRefList(list, fallbackType = "png") {
  if (!Array.isArray(list)) return [];
  return list.map((item, index) => {
    try {
      return normalizeOptionalFileRef(item, fallbackType);
    } catch (err) {
      throw new Error(`files[${index}] ${err.message}`);
    }
  });
}

function hasConcreteFileRef(ref) {
  return Boolean(ref?.file_token || ref?.url || ref?.object);
}

function validateMultiviewFileList(files) {
  if (!Array.isArray(files) || files.length !== 4) {
    throw new Error("multiview_to_model files must contain exactly 4 items in order: front, left, back, right");
  }
  if (!hasConcreteFileRef(files[0])) {
    throw new Error("multiview_to_model files[0] front view is required");
  }
  if (files.filter(hasConcreteFileRef).length < 2) {
    throw new Error("multiview_to_model requires at least two uploaded views");
  }
}

function normalizeTexturePromptFileRef(input) {
  const ref = normalizeFileRef(input, "jpg");
  return ref;
}

function normalizeTexturePromptFileRefList(list) {
  if (!Array.isArray(list)) return [];
  return list.map((item) => normalizeTexturePromptFileRef(item));
}

function normalizeSharedGenerationFields(body) {
  normalizeOptionalEnum(body, "compress", VALID_COMPRESS_TYPES);
  normalizeOptionalEnum(body, "orientation", VALID_IMAGE_ORIENTATIONS);
  normalizeStringField(body, "texture_alignment");
  if (body.render_image !== undefined) {
    body.render_image = normalizeBoolean(body.render_image, false);
  }
  normalizeStringField(body, "original_task_id");
}

function normalizeTexturePrompt(body) {
  const prompt = { ...(body.texture_prompt ?? {}) };

  if (body.prompt && !prompt.text) prompt.text = trimString(body.prompt);
  if (body.file && !prompt.image) prompt.image = body.file;
  if (body.files && !prompt.images) prompt.images = body.files;

  if (prompt.text !== undefined) {
    prompt.text = trimString(prompt.text);
    if (!prompt.text) delete prompt.text;
  }
  if (prompt.text) validatePromptLength(prompt.text, "texture_prompt.text");

  if (prompt.text && prompt.image && !prompt.style_image) {
    prompt.style_image = prompt.image;
    delete prompt.image;
  }
  const hasText = Boolean(prompt.text);
  const hasImage = Boolean(prompt.image);
  const hasImages = Array.isArray(prompt.images) && prompt.images.some(Boolean);
  if ([hasText, hasImage, hasImages].filter(Boolean).length > 1) {
    throw new Error("texture_prompt must include only one of text, image, or images");
  }

  if (prompt.image) prompt.image = normalizeTexturePromptFileRef(prompt.image);
  if (prompt.style_image) prompt.style_image = normalizeTexturePromptFileRef(prompt.style_image);
  if (Array.isArray(prompt.images)) {
    if (prompt.images.length === 0) {
      delete prompt.images;
    } else {
      if (prompt.images.length !== 4) {
        throw new Error("texture_prompt.images must contain exactly 4 views in order: front, left, back, right");
      }
      prompt.images = prompt.images.map((item, index) => {
        try {
          return normalizeTexturePromptFileRef(item);
        } catch (err) {
          throw new Error(`texture_prompt.images[${index}] ${err.message}`);
        }
      });
      if (!prompt.images[0]) {
        throw new Error("texture_prompt.images[0] front view is required");
      }
      if (prompt.images.filter(Boolean).length < 2) {
        throw new Error("texture_prompt.images requires at least two uploaded views");
      }
    }
  }

  delete body.prompt;
  delete body.negative_prompt;
  delete body.file;
  delete body.files;

  if (Object.keys(prompt).length > 0) body.texture_prompt = prompt;
  else delete body.texture_prompt;
}

function normalizeTextureModelBody(body) {
  normalizeTexturePrompt(body);

  const qualityInput = String(body.texture_quality ?? "standard").trim();
  body.texture_quality = qualityInput === "HD" ? "detailed" : qualityInput;
  if (!VALID_TEXTURE_QUALITIES.has(body.texture_quality)) {
    body.texture_quality = "standard";
  }

  const mv = body.model_version ?? (body.texture_quality === "detailed" ? DETAILED_TEXTURE_MODEL_VERSION : DEFAULT_MODEL);
  if (!VALID_TEXTURE_MODEL_VERSIONS.has(mv)) {
    throw new Error(`Invalid texture model_version "${mv}". Valid: ${[...VALID_TEXTURE_MODEL_VERSIONS].join(", ")}`);
  }
  if (body.texture_quality === "detailed" && mv !== DETAILED_TEXTURE_MODEL_VERSION) {
    throw new Error(`texture_quality "detailed" requires model_version "${DETAILED_TEXTURE_MODEL_VERSION}"`);
  }
  body.model_version = mv;

  if (body.texture !== undefined) {
    body.texture = normalizeBoolean(body.texture, true);
  }
  if (body.pbr !== undefined) {
    body.pbr = normalizeBoolean(body.pbr, true);
  }
  if (body.texture_quality === "standard" && body.texture === false && body.pbr === false) {
    throw new Error('texture_quality "standard" cannot be used with texture=false and pbr=false');
  }

  normalizeOptionalEnum(body, "texture_alignment", VALID_TEXTURE_ALIGNMENTS);

  if (body.compress !== undefined) {
    const compress = String(body.compress ?? "").trim();
    if (!VALID_COMPRESS_TYPES.has(compress)) {
      throw new Error(`Invalid compress "${body.compress}". Valid: ${[...VALID_COMPRESS_TYPES].join(", ")}`);
    }
    if (compress) body.compress = compress;
    else delete body.compress;
  }

  if (body.part_names !== undefined) {
    const partNames = Array.isArray(body.part_names)
      ? body.part_names.map(v => String(v).trim()).filter(Boolean)
      : [];
    if (partNames.length) body.part_names = partNames;
    else delete body.part_names;
  }

  if (body.bake === undefined) delete body.bake;
  else body.bake = body.bake === true || body.bake === "true";

  delete body._sourceName;
}

function extractTaskError(task = {}) {
  const out = task.output ?? {};
  return (
    task.error_msg ??
    task.error_message ??
    task.error ??
    task.message ??
    task.reason ??
    out.error_msg ??
    out.error_message ??
    out.error ??
    out.message ??
    out.reason ??
    null
  );
}

function extractTaskErrorCode(task = {}) {
  const out = task.output ?? {};
  return (
    task.error_code ??
    task.code ??
    out.error_code ??
    out.code ??
    null
  );
}

/* ─── TaskService ─────────────────────────────────────────────────────── */

class TaskService {
  /* ── Create ─────────────────────────────────────────────────────── */
  async create(body, opts = {}) {
    const validated = this.validate(body);
    if (opts.callbackUrl) validated["callback_url"] = normalizeCallbackUrl(opts.callbackUrl);

    const idempotencyKey = opts.idempotencyKey ?? crypto.randomUUID();
    const client = getTripoClient();
    const startMs = Date.now();
    console.log("[TaskService] validated create body:", JSON.stringify({
      idempotencyKey,
      validated,
    }, null, 2));

    try {
      const taskId = await client.createTask(validated, idempotencyKey, opts);
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
      const result = await client.pollTask(taskId);
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
    if (b.callback_url !== undefined) {
      const normalizedCallbackUrl = normalizeCallbackUrl(b.callback_url);
      if (normalizedCallbackUrl) b.callback_url = normalizedCallbackUrl;
      else delete b.callback_url;
    }

    switch (body.type) {
      case "text_to_model":
      case "image_to_model":
      case "multiview_to_model": {
        normalizeSharedGenerationFields(b);

        // model_version
        const mv = b["model_version"] ?? DEFAULT_MODEL;
        if (!VALID_MODEL_VERSIONS.has(mv))
          throw new Error(`Invalid model_version "${mv}". Valid: ${[...VALID_MODEL_VERSIONS].join(", ")}`);
        b["model_version"] = mv;

        // Core input validation applies to P1 too.
        if (body.type === "text_to_model" || (body.type === "image_to_model" && b["prompt"])) {
          const p = b["prompt"];
          if (body.type === "text_to_model" && !p?.trim())
            throw new Error("prompt is required for text_to_model");
          validatePromptLength(p, "prompt");
        }

        if (body.type === "image_to_model") {
          if (b.file) b.file = normalizeFileRef(b.file, "png");
          if (b.images) b.images = normalizeFileRefList(b.images, "png");
          if (b.batch_images) b.batch_images = normalizeFileRefList(b.batch_images, "png");
          if (b.batch_images?.length > TRIPO_IMAGE_TO_MODEL_BATCH_MAX) {
            throw new Error(`image_to_model batch_images maximum ${TRIPO_IMAGE_TO_MODEL_BATCH_MAX} images`);
          }
          const hasFile = !!b.file || (!!b.images && b.images.length > 0) || (!!b.batch_images && b.batch_images.length > 0);
          if (!hasFile) throw new Error("file, images, or batch_images required for image_to_model");
        }

        if (body.type === "multiview_to_model") {
          if (b.files) b.files = normalizeMultiviewFileRefList(b.files, "png");
          if (!b.original_task_id && (!Array.isArray(b.files) || b.files.length === 0)) {
            throw new Error("files or original_task_id required for multiview_to_model");
          }
          if (!b.original_task_id) validateMultiviewFileList(b.files);
        }

        const np = b["negative_prompt"];
        if (np && np.length > TRIPO_NEGATIVE_PROMPT_MAX_LENGTH) {
          b["negative_prompt"] = np.slice(0, TRIPO_NEGATIVE_PROMPT_MAX_LENGTH);
          console.warn(`[TaskService] negative_prompt truncated to ${TRIPO_NEGATIVE_PROMPT_MAX_LENGTH} chars (was ${np.length})`);
        }

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
            "orientation", "render_image", "texture_alignment", "original_task_id",
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
          if (!b["texture"] && !b["pbr"]) {
            delete b["texture_quality"];
          }
          if (b["texture"] === undefined) delete b["texture"];
          if (b["pbr"] === undefined) delete b["pbr"];
          break; // P1 validáció kész, többi szabály nem vonatkozik rá
        }

        // prompt length
        if (body.type === "text_to_model" || (body.type === "image_to_model" && b["prompt"])) {
          const p = b["prompt"];
          if (body.type === "text_to_model" && !p?.trim())
            throw new Error("prompt is required for text_to_model");
          validatePromptLength(p, "prompt");
        }

        // image/batch validation
        if (body.type === "image_to_model") {
          if (b.file) b.file = normalizeFileRef(b.file, "png");
          if (b.images) b.images = normalizeFileRefList(b.images, "png");
          if (b.batch_images) b.batch_images = normalizeFileRefList(b.batch_images, "png");
          if (b.batch_images?.length > TRIPO_IMAGE_TO_MODEL_BATCH_MAX) {
            throw new Error(`image_to_model batch_images maximum ${TRIPO_IMAGE_TO_MODEL_BATCH_MAX} images`);
          }
          const hasFile = !!b.file || (!!b.images && b.images.length > 0) || (!!b.batch_images && b.batch_images.length > 0);
          if (!hasFile) throw new Error("file, images, or batch_images required for image_to_model");
        }

        if (body.type === "multiview_to_model") {
          if (b.files) b.files = normalizeMultiviewFileRefList(b.files, "png");
          if (!b.original_task_id && (!Array.isArray(b.files) || b.files.length === 0)) {
            throw new Error("files or original_task_id required for multiview_to_model");
          }
          if (!b.original_task_id) validateMultiviewFileList(b.files);
        }

        // negative_prompt length — Tripo API max 255 characters
        const np2 = b["negative_prompt"];
        if (np2 && np2.length > TRIPO_NEGATIVE_PROMPT_MAX_LENGTH) {
          b["negative_prompt"] = np2.slice(0, TRIPO_NEGATIVE_PROMPT_MAX_LENGTH);
          console.warn(`[TaskService] negative_prompt truncated to ${TRIPO_NEGATIVE_PROMPT_MAX_LENGTH} chars (was ${np2.length})`);
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
        if (b["pbr"] === undefined) delete b["pbr"];

        // style
        if (b["style"] && !VALID_GENERATION_STYLES.has(b["style"]))
          throw new Error(`Invalid style "${b["style"]}". Valid: ${[...VALID_GENERATION_STYLES].join(", ")}`);

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

      case "generate_image": {
        const prompt = trimString(b.prompt);
        if (!prompt) throw new Error("prompt required for generate_image");
        b.prompt = prompt;
        validatePromptLength(prompt, "prompt");
        normalizeStringField(b, "negative_prompt");
        normalizeStringField(b, "model");
        normalizeStringField(b, "template_id");
        normalizeSharedGenerationFields(b);
        if (b.reference_image) b.reference_image = normalizeFileRef(b.reference_image, "png");
        if (b.reference_images) b.reference_images = normalizeFileRefList(b.reference_images, "png");
        break;
      }

      case "generate_multiview_image": {
        if (b.file) b.file = normalizeFileRef(b.file, "png");
        if (!b.file) throw new Error("file required for generate_multiview_image");
        break;
      }

      case "edit_multiview_image": {
        normalizeStringField(b, "original_task_id");
        if (!b.original_task_id) throw new Error("original_task_id required for edit_multiview_image");
        const prompts = Array.isArray(b.prompts) ? b.prompts : [];
        b.prompts = prompts.map((entry, index) => {
          const prompt = trimString(entry?.prompt);
          const view = trimString(entry?.view);
          if (!prompt) throw new Error(`prompts[${index}].prompt required`);
          validatePromptLength(prompt, `prompts[${index}].prompt`);
          if (!["front", "left", "back", "right"].includes(view)) {
            throw new Error(`prompts[${index}].view must be one of front, left, back, right`);
          }
          return { prompt, view };
        });
        if (b.prompts.length === 0) throw new Error("prompts required for edit_multiview_image");
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
        if (!VALID_STYLIZE_STYLES.has(b["style"]))
          throw new Error(`Invalid style "${b["style"]}". Valid: ${[...VALID_STYLIZE_STYLES].join(", ")}`);
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
        normalizeTextureModelBody(b);
        break;

      case "animate_prerigcheck":
      case "refine_model":
        if (b["type"] === "refine_model" && !b["draft_model_task_id"] && b["original_model_task_id"]) {
          b["draft_model_task_id"] = b["original_model_task_id"];
        }
        if (b["type"] === "refine_model") {
          if (!b["draft_model_task_id"]) throw new Error("draft_model_task_id required");
          delete b["original_model_task_id"];
          delete b["prompt"];
          delete b["negative_prompt"];
          delete b["_sourceName"];
        } else if (!b["original_model_task_id"]) {
          throw new Error("original_model_task_id required");
        }
        break;

      case "text_to_image": {
        const p = b["prompt"];
        if (!p?.trim()) throw new Error("prompt required for text_to_image");
        validatePromptLength(p, "prompt");
        break;
      }

      case "import_model":
        if (!b["file"])
          throw new Error("file required for import_model");
        if (!b["file"].object && !b["file"].file_token && !b["file"].url)
          throw new Error("file.object, file.file_token, or file.url required for import_model");
        if (b["file"].object) {
          const { bucket, key } = b["file"].object;
          if (!bucket || !key) throw new Error("file.object.bucket and file.object.key required for import_model");
          b["file"] = { object: { bucket, key } };
        }
        break;

      case "texture_edit":
        b["type"] = "texture_model";
        if (!b["original_model_task_id"]) throw new Error("original_model_task_id required");
        normalizeTextureModelBody(b);
        delete b["creativity_strength"];
        break;
    }

    return b;
  }

  /* ── Convert raw task to PollResult ──────────────────────────────── */
  taskToPollResult(task, outputHints = {}) {
    const out = task.output ?? {};
    const errorMessage = extractTaskError(task);
    const errorCode = extractTaskErrorCode(task);
    if (task.status === "success" && (task.type === "animate_retarget") && Array.isArray(out.animated_models)) {
      console.log(`[TaskService] animate_retarget result for ${task.task_id}:`, { animated_models_count: out.animated_models.length, animated_models: out.animated_models, animated_model: out.animated_model ?? null });
    }
    const {
      modelUrl,
      chosenSource,
      rigCheckResult,
      rigType,
      topology,
      rawOutput,
      previewImageUrl,
      previewImageUrls,
    } = extractModelUrl(task, outputHints);
    if (DEBUG_TRIPO && task.status === "success") {
      console.log("[TaskService] output selection:", JSON.stringify({
        taskId: task.task_id ?? null,
        type: task.type ?? null,
        preferDraftOutput: outputHints.preferBaseModel === true,
        preferTexturedOutput: outputHints.preferPbrModel === true,
        chosenSource,
        availableOutputKeys: Object.keys(out),
      }, null, 2));
    }
    return {
      success: task.status === "success",
      status: task.status,
      progress: task.progress ?? 0,
      modelUrl,
      tripoTraceId: task._traceId ?? null,
      chosenSource,
      rigCheckResult,
      rigType,
      topology,
      previewImageUrl,
      previewImageUrls,
      consumedCredit: task.consumed_credit ?? rawOutput?.consumed_credit ?? null,
      originalTaskId:
        task.input?.original_task_id ??
        task.input?.original_model_task_id ??
        task.input?.draft_model_task_id ??
        null,
      rawOutput,
      errorMessage,
      errorCode,
    };
  }
}

export const taskService = new TaskService();
