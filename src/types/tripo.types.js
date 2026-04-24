// src/types/tripo.types.js
//
// Runtime konstansok és dokumentáció a Tripo típusokhoz.
// TypeScript interface-ek helyett JSDoc kommentekkel dokumentálva.

/* ─── Task státuszok ──────────────────────────────────────────────────── */
export const TASK_STATUSES = /** @type {const} */ (["queued", "running", "success", "failed", "cancelled"]);

/* ─── Task típusok ────────────────────────────────────────────────────── */
export const TASK_TYPES = /** @type {const} */ ([
  "text_to_model",
  "image_to_model",
  "multiview_to_model",
  "texture_model",
  "smart_low_poly",
  "convert_model",
  "mesh_segmentation",
  "mesh_completion",
  "animate_prerigcheck",
  "animate_rig",
  "animate_retarget",
  "stylize_model",
  "refine_model",
  "import_model",
  "text_to_image",
  "generate_image",
  "generate_multiview_image",
  "edit_multiview_image",
]);

/* ─── Model verziók ───────────────────────────────────────────────────── */
export const MODEL_VERSIONS = /** @type {const} */ ([
  "v3.0-20250812",
  "v2.5-20250123",
  "turbo-v1.0-20250506",
  "v2.0-20240919",
  "v1.4-20240625",
]);

/* ─── Texture / geometry minőség ─────────────────────────────────────── */
export const TEXTURE_QUALITIES   = /** @type {const} */ (["detailed", "HD"]);
export const GEOMETRY_QUALITIES  = /** @type {const} */ (["standard", "detailed"]);

/* ─── Konverziós formátumok ───────────────────────────────────────────── */
export const CONVERT_FORMATS = /** @type {const} */ (["glb", "fbx", "obj", "stl", "3mf", "usdz", "schematic"]);

/** Formátumok amik NEM támogatottak rigged model inputhoz */
export const RIGGED_UNSUPPORTED_FORMATS = /** @type {const} */ (["obj", "stl"]);

/* ─── Rig specifikációk ───────────────────────────────────────────────── */
export const RIG_SPECS = /** @type {const} */ (["mixamo", "tripo"]);

/* ─── Texture igazítás ────────────────────────────────────────────────── */
export const TEXTURE_ALIGNMENTS = /** @type {const} */ (["original_image", "geometry"]);

/* ─── Animáció presetek ───────────────────────────────────────────────── */
export const ANIMATION_PRESETS = /** @type {const} */ ([
  "idle", "walk", "run", "jump", "wave",
  "dance", "attack", "die", "crouch", "swim",
]);

/* ─── Stílus típusok ──────────────────────────────────────────────────── */
export const STYLE_TYPES = /** @type {const} */ ([
  "cartoon", "clay", "alien", "christmas", "steampunk",
  "lego", "voxel", "voronoi", "minecraft", "gold", "ancient_bronze",
]);

/* ─── Engine célplatformok ────────────────────────────────────────────── */
export const ENGINE_TARGETS = /** @type {const} */ (["unity", "unreal", "webgl", "ios_ar", "print"]);

/* ─── Job típusok (queue) ─────────────────────────────────────────────── */
export const JOB_TYPES = /** @type {const} */ (["single", "pipeline", "lod", "batch_item"]);

/* ─── Set verziók (gyors lookup-hoz) ─────────────────────────────────── */
export const MODEL_VERSIONS_SET          = new Set(MODEL_VERSIONS);
export const TASK_TYPES_SET              = new Set(TASK_TYPES);
export const CONVERT_FORMATS_SET         = new Set(CONVERT_FORMATS);
export const RIGGED_UNSUPPORTED_SET      = new Set(RIGGED_UNSUPPORTED_FORMATS);
export const ANIMATION_PRESETS_SET       = new Set(ANIMATION_PRESETS);
export const STYLE_TYPES_SET             = new Set(STYLE_TYPES);
export const TASK_STATUSES_SET           = new Set(TASK_STATUSES);

/* ─── JSDoc shape dokumentációk (runtime érték nélkül, csak referencia) ─ */

/**
 * @typedef {Object} FileRef
 * @property {string} type - "jpg" | "png" | "glb" | ...
 * @property {string} [file_token]
 * @property {string} [url]
 * @property {{ bucket: string, key: string }} [object]
 */

/**
 * @typedef {Object} PollResult
 * @property {boolean} success
 * @property {string} status
 * @property {number} progress
 * @property {string|null} modelUrl
 * @property {boolean|null} rigCheckResult
 * @property {Object|null} rawOutput
 */

/**
 * @typedef {Object} EnginePreset
 * @property {string} format
 * @property {boolean} quad
 * @property {number|null} face_limit - null = auto
 * @property {number} scale_factor
 * @property {boolean} pivot_to_center_bottom
 * @property {string} description
 */

/**
 * @typedef {Object} CreditEstimate
 * @property {number} base
 * @property {number} texture
 * @property {number} pbr
 * @property {number} texture_quality
 * @property {number} geometry_quality
 * @property {number} smart_low_poly
 * @property {number} animation
 * @property {number} total
 * @property {Record<string, number>} breakdown
 */

/**
 * @typedef {Object} LodLevel
 * @property {number} level - 0 = legjobb minőség
 * @property {string} label - "LOD0", "LOD1", "LOD2"
 * @property {number} face_limit
 * @property {string} [taskId]
 * @property {string} [modelUrl]
 * @property {string} status
 */

/**
 * @typedef {Object} LodChainResult
 * @property {string} sourceTaskId
 * @property {LodLevel[]} levels
 * @property {string} [zipUrl]
 */

/**
 * @typedef {Object} PipelineStep
 * @property {string} type
 * @property {string} [taskId]
 * @property {string} status - "pending" | "skipped" | TaskStatus
 * @property {string|null} [modelUrl]
 * @property {number} [startedAt]
 * @property {number} [finishedAt]
 * @property {string} [error]
 */

/**
 * @typedef {Object} PipelineResult
 * @property {string} pipelineId
 * @property {PipelineStep[]} steps
 * @property {string|null} finalModelUrl
 * @property {"running"|"completed"|"failed"} status
 * @property {string} [error]
 */

/**
 * @typedef {Object} GenerateCharacterRequest
 * @property {string} [prompt]
 * @property {string} [image_token]
 * @property {string} [model_version]
 * @property {boolean} [run_smart_low_poly]
 * @property {number} [smart_low_poly_faces]
 * @property {boolean} [run_rig]
 * @property {string} [rig_spec] - "mixamo" | "tripo"
 * @property {string[]} [animations]
 * @property {string} [convert_format]
 * @property {string} [engine]
 * @property {string} [callback_url]
 */

/**
 * @typedef {Object} BatchGenerateRequest
 * @property {string[]} [prompts]
 * @property {string[]} [image_tokens]
 * @property {string} [model_version]
 * @property {boolean} [texture]
 * @property {boolean} [pbr]
 * @property {string} [texture_quality]
 * @property {string} [callback_url]
 */

/**
 * @typedef {Object} WebhookPayload
 * @property {string} task_id
 * @property {string} type
 * @property {string} status
 * @property {number} progress
 * @property {Object} [output]
 * @property {number} timestamp
 */

/**
 * @typedef {Object} TaskMetric
 * @property {string} taskId
 * @property {string} type
 * @property {string} status
 * @property {number} durationMs
 * @property {number} [creditsUsed]
 * @property {string} [modelVersion]
 * @property {number} createdAt
 * @property {string} [error]
 */

/**
 * @typedef {Object} DailyStats
 * @property {string} date - "YYYY-MM-DD"
 * @property {number} creditsUsed
 * @property {number} tasksTotal
 * @property {number} tasksSuccess
 * @property {number} tasksFailed
 * @property {number} avgDurationMs
 * @property {Record<string, number>} byType
 */

/**
 * @typedef {Object} AnalyticsSummary
 * @property {DailyStats} today
 * @property {DailyStats[]} last7Days
 * @property {number} errorRate - 0–1
 * @property {number} p50DurationMs
 * @property {number} p95DurationMs
 * @property {TaskMetric[]} recentErrors
 */

/**
 * @typedef {Object} TripoJobData
 * @property {"single"|"pipeline"|"lod"|"batch_item"} jobType
 * @property {Object} taskBody
 * @property {string} [userId]
 * @property {string} [batchId]
 * @property {number} [batchIndex]
 * @property {string} [pipelineId]
 * @property {number} [pipelineStep]
 * @property {string} [callbackUrl]
 * @property {string} [idempotencyKey]
 * @property {number} [maxPollAttempts]
 * @property {number} [pollIntervalMs]
 */

/**
 * @typedef {Object} TripoJobResult
 * @property {string} taskId
 * @property {string} status
 * @property {string|null} modelUrl
 * @property {Object|null} rawOutput
 * @property {number} durationMs
 */
/**
 * @typedef {Object} AnimateRetargetRequest
 * @property {"animate_retarget"} type
 * @property {string} original_model_task_id
 * @property {string} [animation] - Single animation (e.g., "preset:idle")
 * @property {string[]} [animations] - Multiple animations
 * @property {"glb"|"fbx"} [out_format="glb"]
 * @property {boolean} [bake_animation=true]
 * @property {boolean} [export_with_geometry=true]
 * @property {boolean} [animate_in_place=false]
 */

/**
 * @typedef {Object} AnimateRigRequest
 * @property {"animate_rig"} type
 * @property {string} original_model_task_id
 * @property {string} [spec="tripo"] - "tripo" or "mixamo"
 * @property {"glb"|"fbx"} [out_format="glb"]
 * @property {"biped"|"quadruped"|"hexapod"|"octopod"|"avian"|"serpentine"|"aquatic"} [rig_type="biped"]
 * @property {string} [model_version] - Rigging model version
 * @property {boolean} [bake_animation=true]
 * @property {boolean} [export_with_geometry=true]
 * @property {boolean} [animate_in_place=false]
 */
