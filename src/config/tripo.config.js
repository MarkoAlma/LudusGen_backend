// src/config/tripo.config.js

export const TRIPO_BASE_URL  = "https://api.tripo3d.ai/v2/openapi";
export const DEFAULT_MODEL   = "v3.0-20250812";
export const DEFAULT_TIMEOUT = 30_000;
export const MAX_POLL_MS     = 600_000;
export const POLL_INTERVAL   = 4_000;

export const VALID_MODEL_VERSIONS = new Set([
  "v3.0-20250812",
  "v2.5-20250123",
  "turbo-v1.0-20250506",
  "v2.0-20240919",
  "v1.4-20240625",
]);

export const VALID_CONVERT_FORMATS = new Set([
  "glb", "fbx", "obj", "stl", "3mf", "usdz", "schematic",
]);

export const RIGGED_UNSUPPORTED_FORMATS = new Set(["obj", "stl"]);

export const VALID_ANIMATIONS = new Set([
  "idle", "walk", "run", "jump", "wave",
  "dance", "attack", "die", "crouch", "swim",
]);

export const VALID_STYLES = new Set([
  "cartoon", "clay", "alien", "christmas", "steampunk",
  "lego", "voxel", "voronoi", "minecraft", "gold", "ancient_bronze",
]);

export const RETRY_CONFIG = {
  maxRetries:        3,
  baseDelayMs:       1_000,
  maxDelayMs:        32_000,
  jitterMs:          500,
  retryableStatuses: new Set([429, 500, 502, 503, 504]),
};

/**
 * Approximate credit costs per task type / addon.
 * Keys: "type:model_version" for generation, plain "type" for post-process.
 */
export const CREDIT_COSTS = {
  "text_to_model:v3.0-20250812":        40,
  "text_to_model:v2.5-20250123":        20,
  "text_to_model:turbo-v1.0-20250506":  5,
  "text_to_model:v2.0-20240919":        20,
  "text_to_model:v1.4-20240625":        15,

  "image_to_model:v3.0-20250812":       45,
  "image_to_model:v2.5-20250123":       25,
  "image_to_model:turbo-v1.0-20250506": 6,
  "image_to_model:v2.0-20240919":       25,
  "image_to_model:v1.4-20240625":       20,

  "multiview_to_model:v3.0-20250812":       50,
  "multiview_to_model:v2.5-20250123":       30,
  "multiview_to_model:turbo-v1.0-20250506": 8,

  texture_model:        10,
  smart_low_poly:       10,
  convert_model:         2,
  mesh_segmentation:     5,
  mesh_completion:       5,
  animate_prerigcheck:   2,
  animate_rig:          15,
  animate_retarget:     10,
  stylize_model:        10,
  refine_model:          5,
  import_model:          0,
  text_to_image:         2,

  "addon:texture_detailed":     10,
  "addon:texture_HD":           20,
  "addon:pbr":                   5,
  "addon:geometry_detailed":     5,
  "addon:smart_low_poly_gen":   10,
  "addon:generate_parts":       10,
  "addon:animation_per_preset": 10,
};

/**
 * Engine presets for convert_model.
 * @type {Record<string, { format: string, quad: boolean, face_limit: number|null, scale_factor: number, pivot_to_center_bottom: boolean, description: string }>}
 */
export const ENGINE_PRESETS = {
  unity: {
    format:                 "glb",
    quad:                   false,
    face_limit:             50_000,
    scale_factor:           1.0,
    pivot_to_center_bottom: true,
    description:            "Unity-optimised GLB, 50k triangles, Y-up pivot at base",
  },
  unreal: {
    format:                 "fbx",
    quad:                   true,
    face_limit:             50_000,
    scale_factor:           100.0,  // Unreal uses cm
    pivot_to_center_bottom: false,
    description:            "Unreal Engine FBX, quad mesh, 50k faces, cm scale",
  },
  webgl: {
    format:                 "glb",
    quad:                   false,
    face_limit:             20_000,
    scale_factor:           1.0,
    pivot_to_center_bottom: false,
    description:            "Web-optimised GLB, 20k triangles",
  },
  ios_ar: {
    format:                 "usdz",
    quad:                   false,
    face_limit:             15_000,
    scale_factor:           1.0,
    pivot_to_center_bottom: true,
    description:            "Apple AR / iOS USDZ, 15k triangles",
  },
  print: {
    format:                 "stl",
    quad:                   false,
    face_limit:             null,   // auto — max detail
    scale_factor:           1.0,
    pivot_to_center_bottom: false,
    description:            "3D printing STL, auto face count",
  },
};

export const LOD_PRESETS = [
  { level: 0, label: "LOD0", face_limit: 50_000 },
  { level: 1, label: "LOD1", face_limit: 20_000 },
  { level: 2, label: "LOD2", face_limit:  5_000 },
];

export const QUEUE_NAMES = {
  TRIPO_TASKS:   "tripo_tasks",
  TRIPO_POLL:    "tripo_poll",
  TRIPO_WEBHOOK: "tripo_webhook",
};

export const ANALYTICS_RETENTION_DAYS = 30;
export const MAX_RECENT_ERRORS        = 50;