// src/config/tripo.config.js

export const TRIPO_BASE_URL  = "https://api.tripo3d.ai/v2/openapi";
export const DEFAULT_MODEL   = "v2.5-20250123";
export const DEFAULT_TIMEOUT = 30_000;
export const MAX_POLL_MS     = 600_000;
export const POLL_INTERVAL   = 4_000;
export const TRIPO_PROMPT_MAX_LENGTH = 1024;
export const TRIPO_NEGATIVE_PROMPT_MAX_LENGTH = 255;
export const TRIPO_IMAGE_UPLOAD_MAX_BYTES = 10 * 1024 * 1024;
export const TRIPO_IMAGE_TO_MODEL_BATCH_MAX = 10;
export const TRIPO_MODEL_IMPORT_MAX_BYTES = 150 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// VALID SETS
// ─────────────────────────────────────────────────────────────────────────────

export const VALID_MODEL_VERSIONS = new Set([
  "P1-20260311",
  "v3.1-20260211",
  "v3.0-20250812",
  "v2.5-20250123",
  "Turbo-v1.0-20250506",
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
  // Full Tripo animation library (all slugs from animationlibrary.js)
  "afraid", "agree", "angry_01", "angry_02", "angry_03",
  "basketball_shot", "bow", "box_01", "box_02", "box_03",
  "cast_a_spell", "cheer", "chop", "clap", "climb",
  "complain_01", "complain_02", "crossover_dribble", "cry",
  "dance_01", "dance_02", "dance_03", "dance_04", "dance_05", "dance_06",
  "defeat", "defeat_02", "depressed", "dig", "dive", "dribble",
  "fall", "fire", "flee_01", "flee_02", "flip", "fold_arms",
  "football_catch", "football_save", "football_pass", "freaky", "frightened",
  "front_kick_01", "front_kick_02", "frustrated_01", "frustrated_02",
  "greet_01", "greet_02", "greet_03", "greet_04", "heart_pose",
  "hit_to_body_01", "hit_to_body_02", "hit_to_head", "hit_to_side", "hit_to_stomach",
  "hug", "jump_down", "jump_rope_01", "jump_rope_02",
  "laugh_01", "laugh_02", "lift_heavy", "look_around",
  "make_a_call_01", "make_a_call_02", "pitch_baseball",
  "play_mobile_game", "play_video_game", "press-up",
  "run_upstairs", "scared_01", "scared_02", "scratch", "shoot",
  "shovel", "sing_01", "sing_02", "sing_03", "sing_04",
  "sit", "slash", "sob", "standing_relax", "surf", "swagger",
  "turn", "volleyball", "wait", "warm_up",
  "wave_goodbye_01", "wave_goodbye_02",
]);

export const VALID_GENERATION_STYLES = new Set([
  "person:person2cartoon",
  "animal:venom",
  "object:clay",
  "object:steampunk",
  "object:christmas",
  "object:barbie",
  "gold",
  "ancient_bronze",
]);

export const VALID_STYLIZE_STYLES = new Set([
  "lego", "voxel", "voronoi", "minecraft",
]);

export const VALID_STYLES = VALID_STYLIZE_STYLES;

export const VALID_TEXTURE_MODEL_VERSIONS = new Set([
  "v3.0-20250812",
  "v2.5-20250123",
  "v2.0-20240919",
]);

export const VALID_COMPRESS_TYPES = new Set(["", "geometry"]);
export const VALID_IMAGE_ORIENTATIONS = new Set(["", "default", "portrait", "landscape", "square"]);
export const VALID_MULTIVIEW_IMAGE_MODES = new Set(["", "concept", "orthographic", "character", "product"]);

// ─────────────────────────────────────────────────────────────────────────────
// RETRY CONFIG
// ─────────────────────────────────────────────────────────────────────────────

export const RETRY_CONFIG = {
  maxRetries:        3,
  baseDelayMs:       1_000,
  maxDelayMs:        32_000,
  jitterMs:          500,
  retryableStatuses: new Set([500, 502, 503, 504]),
};

// ─────────────────────────────────────────────────────────────────────────────
// CREDIT COSTS  —  forrás: Tripo hivatalos árszabás
//
// A "*_to_model:model" kulcsok = WITHOUT TEXTURE ár (textúra nélküli alap).
//
// Összesített árak (tájékoztató):
//   P1-20260311  text:         30 (no tex) | 40 (std) | 50 (HD)
//   P1-20260311  image/multi:  40 (no tex) | 50 (std) | 60 (HD)
//   Többi text:         10 (no tex) | 20 (std) | 30 (HD)
//   Többi image/multi:  20 (no tex) | 30 (std) | 40 (HD)
//   V1.4  text: 20  |  image: 30  (lapos, addon nincs)
//
// Textúra addonok (mindig +10 / +10, modelltől függetlenül):
//   Standard Texture: alap + 10
//   HD Texture:       alap + 20  (standard + HD upgrade)
// ─────────────────────────────────────────────────────────────────────────────

export const CREDIT_COSTS = {

  // ── 3D GENERÁLÁS — WITHOUT TEXTURE alapár ────────────────────────────────

  "text_to_model:P1-20260311":                30,
  "text_to_model:v3.1-20260211":       10,
  "text_to_model:v3.0-20250812":       10,
  "text_to_model:v2.5-20250123":       10,
  "text_to_model:Turbo-v1.0-20250506": 10,
  "text_to_model:v2.0-20240919":       10,
  "text_to_model:v1.4-20240625":       20,  // lapos, nincs addon

  "image_to_model:P1-20260311":                40,
  "image_to_model:v3.1-20260211":       20,
  "image_to_model:v3.0-20250812":       20,
  "image_to_model:v2.5-20250123":       20,
  "image_to_model:Turbo-v1.0-20250506": 20,
  "image_to_model:v2.0-20240919":       20,
  "image_to_model:v1.4-20240625":       30,  // lapos, nincs addon

  "multiview_to_model:P1-20260311":                40,
  "multiview_to_model:v3.1-20260211":       20,
  "multiview_to_model:v3.0-20250812":       20,
  "multiview_to_model:v2.5-20250123":       20,
  "multiview_to_model:Turbo-v1.0-20250506": 20,
  "multiview_to_model:v2.0-20240919":       20,
  // V1.4 nem támogatja a multiview-t

  // ── ADVANCED GENERATION SETUP addonok ────────────────────────────────────
  // Az without_texture alapárra adódnak.

  "addon:texture_standard":   10,  // Standard Texture: +10 (modelltől függetlenül)
  "addon:texture_HD_upgrade": 10,  // HD Texture upgrade: standard + 10
  "addon:geometry_detailed":  20,  // Detailed Geometry Quality (Ultra)
  "addon:smart_low_poly_gen": 10,  // Low Poly
  "addon:generate_parts":     20,  // Generate in parts
  "addon:quad":                5,  // Quad Topology
  "addon:style":               5,  // Style

  // ── TEXTURE GENERATION ────────────────────────────────────────────────────

  texture_model:              10,  // Standard Texture (önálló task)
  "texture_model:HD":         20,  // HD Texture (önálló task)
  "addon:texture_style_ref":   5,  // Style Reference

  // ── SEGMENTATION AND PARTS COMPLETION ────────────────────────────────────

  mesh_segmentation:          40,
  mesh_completion:            50,

  // ── POST PROCESSING ───────────────────────────────────────────────────────

  stylize_model:              20,
  convert_model:               5,
  "convert_model:advanced":   10,
  smart_low_poly:             10,
  refine_model:               30,

  // ── RIGGING AND ANIMATION ─────────────────────────────────────────────────

  animate_prerigcheck:         0,
  animate_rig:                25,
  animate_retarget:           10,

  // ── EGYÉB ─────────────────────────────────────────────────────────────────

  import_model:                0,
  text_to_image:               5,
  generate_image:              5,
  generate_multiview_image:   10,
  edit_multiview_image:       10,
};

// ─────────────────────────────────────────────────────────────────────────────
// ENGINE PRESETS
// ─────────────────────────────────────────────────────────────────────────────

export const ENGINE_PRESETS = {
  unity:  { format: "glb",  quad: false, face_limit: 50_000, scale_factor: 1.0,   pivot_to_center_bottom: true,  description: "Unity-optimised GLB, 50k triangles, Y-up pivot at base" },
  unreal: { format: "fbx",  quad: true,  face_limit: 50_000, scale_factor: 100.0, pivot_to_center_bottom: false, description: "Unreal Engine FBX, quad mesh, 50k faces, cm scale" },
  webgl:  { format: "glb",  quad: false, face_limit: 20_000, scale_factor: 1.0,   pivot_to_center_bottom: false, description: "Web-optimised GLB, 20k triangles" },
  ios_ar: { format: "usdz", quad: false, face_limit: 15_000, scale_factor: 1.0,   pivot_to_center_bottom: true,  description: "Apple AR / iOS USDZ, 15k triangles" },
  print:  { format: "stl",  quad: false, face_limit: null,   scale_factor: 1.0,   pivot_to_center_bottom: false, description: "3D printing STL, max detail" },
};

// ─────────────────────────────────────────────────────────────────────────────
// LOD PRESETS
// ─────────────────────────────────────────────────────────────────────────────

export const LOD_PRESETS = [
  { level: 0, label: "LOD0", face_limit: 50_000 },
  { level: 1, label: "LOD1", face_limit: 20_000 },
  { level: 2, label: "LOD2", face_limit:  5_000 },
];

// ─────────────────────────────────────────────────────────────────────────────
// QUEUE / ANALYTICS
// ─────────────────────────────────────────────────────────────────────────────

export const QUEUE_NAMES = {
  TRIPO_TASKS:   "tripo_tasks",
  TRIPO_POLL:    "tripo_poll",
  TRIPO_WEBHOOK: "tripo_webhook",
};

export const ANALYTICS_RETENTION_DAYS = 30;
export const MAX_RECENT_ERRORS        = 50;

// ─────────────────────────────────────────────────────────────────────────────
// MODEL CAPABILITIES  —  single source of truth
//
// Frontend fetches GET /api/tripo/model-capabilities and uses this map to
// render/disable UI controls dynamically.  Adding a new model only requires
// updating this object — no hardcoding elsewhere.
//
// Key naming matches the frontend MODEL_CAPS convention so the response can
// be used as a drop-in replacement.
// ─────────────────────────────────────────────────────────────────────────────

export const MODEL_CAPABILITIES = {
  "P1-20260311": {
    ultraMesh:    true,  texture:   true,  pbr:        true,  tex4K:       false,
    multiview:    true,  batch:     true,  tPose:      false, inParts:     false,
    negPrompt:    true,  smartLowPoly: false, quad:    false,
    autoSize:     true,  exportUv:  true,  makeBetter: true,
    modelSeed:    true,  imageSeed: false, textureSeed: true,
  },
  "v3.1-20260211": {
    ultraMesh:    true,  texture:   true,  pbr:        true,  tex4K:       true,
    multiview:    true,  batch:     true,  tPose:      true,  inParts:     true,
    negPrompt:    true,  smartLowPoly: true, quad:     true,
    autoSize:     true,  exportUv:  true,  makeBetter: true,
    modelSeed:    true,  imageSeed: true,  textureSeed: true,
  },
  "v3.0-20250812": {
    ultraMesh:    true,  texture:   true,  pbr:        true,  tex4K:       true,
    multiview:    true,  batch:     true,  tPose:      true,  inParts:     true,
    negPrompt:    true,  smartLowPoly: true, quad:     true,
    autoSize:     true,  exportUv:  true,  makeBetter: true,
    modelSeed:    true,  imageSeed: true,  textureSeed: true,
  },
  "v2.5-20250123": {
    ultraMesh:    false, texture:   true,  pbr:        true,  tex4K:       true,
    multiview:    true,  batch:     true,  tPose:      false, inParts:     true,
    negPrompt:    true,  smartLowPoly: false, quad:    true,
    autoSize:     true,  exportUv:  true,  makeBetter: true,
    modelSeed:    true,  imageSeed: true,  textureSeed: true,
  },
  "Turbo-v1.0-20250506": {
    ultraMesh:    false, texture:   false, pbr:        false, tex4K:       false,
    multiview:    false, batch:     true,  tPose:      false, inParts:     false,
    negPrompt:    false, smartLowPoly: false, quad:    false,
    autoSize:     false, exportUv:  true,  makeBetter: true,
    modelSeed:    true,  imageSeed: false, textureSeed: false,
  },
  "v2.0-20240919": {
    ultraMesh:    false, texture:   true,  pbr:        true,  tex4K:       true,
    multiview:    true,  batch:     true,  tPose:      false, inParts:     true,
    negPrompt:    true,  smartLowPoly: false, quad:    true,
    autoSize:     true,  exportUv:  true,  makeBetter: true,
    modelSeed:    true,  imageSeed: true,  textureSeed: true,
  },
  "v1.4-20240625": {
    ultraMesh:    false, texture:   true,  pbr:        false, tex4K:       false,
    multiview:    false, batch:     false, tPose:      false, inParts:     false,
    negPrompt:    false, smartLowPoly: false, quad:    false,
    autoSize:     false, exportUv:  true,  makeBetter: true,
    modelSeed:    false, imageSeed: false, textureSeed: false,
  },
};

// Default fallback for unknown model versions
export const DEFAULT_CAPABILITIES = MODEL_CAPABILITIES["v2.5-20250123"];

// History TTL in milliseconds (7 days)
export const HISTORY_TTL_MS = 7 * 24 * 60 * 60 * 1000;
