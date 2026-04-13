// src/config/tripo.config.js

export const TRIPO_BASE_URL  = "https://api.tripo3d.ai/v2/openapi";
export const DEFAULT_MODEL   = "P1-20260311";
export const DEFAULT_TIMEOUT = 30_000;
export const MAX_POLL_MS     = 600_000;
export const POLL_INTERVAL   = 4_000;

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
]);

export const VALID_STYLES = new Set([
  "cartoon", "clay", "alien", "christmas", "steampunk",
  "lego", "voxel", "voronoi", "minecraft", "gold", "ancient_bronze",
]);

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
    ultraMesh:    false, texture:   true,  pbr:        true,  tex4K:       true,
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
