// src/lib/creditEstimator.js
import { CREDIT_COSTS, DEFAULT_MODEL } from "../config/tripo.config.js";

/**
 * Returns true if the model version is v3.x or newer.
 * @param {string} mv
 */
function isV3Model(mv) {
  return mv.startsWith("v3.") || mv.startsWith("v3.1");
}

/**
 * Estimate credit cost for a single task BEFORE creation.
 *
 * Empirikusan bizonyított értékek:
 *   text+v3+tex+pbr+"detailed"+quad        = 35  → base10 + tex20 + quad5       ✓
 *   text+v3+Ultra+quad (tex OFF)           = 55  → base10 + ultra40 + quad5     ✓
 *   text+v3+Ultra+tex+pbr+"detailed"+quad  = 55  → base10 + ultra40 + quad5 (+0)✓
 *
 * @param {{ type: string, model_version?: string, texture?: boolean, pbr?: boolean,
 *           texture_quality?: string, geometry_quality?: string,
 *           smart_low_poly?: boolean, generate_parts?: boolean,
 *           quad?: boolean, animation?: boolean }} req
 */
export function estimateCost(req) {
  const mv = req.model_version ?? DEFAULT_MODEL;
  const v3 = isV3Model(mv);
  const breakdown = {};

  /* ── Base ─────────────────────────────────────────────────────────── */
  const versionedKey = `${req.type}:${mv}`;
  const base = CREDIT_COSTS[versionedKey] ?? CREDIT_COSTS[req.type] ?? 0;
  breakdown.base = base;

  /* ── Ultra / geometry_quality:"detailed" ─────────────────────────── */
  // Ultra = 40 kredit ÉS magában foglalja a texture cost-ot (texCost=0 ha ultra)
  const isUltra = req.geometry_quality === "detailed";
  const geometry_quality = isUltra ? (CREDIT_COSTS["addon:geometry_detailed"] ?? 40) : 0;
  if (geometry_quality) breakdown.geometry_quality = geometry_quality;

  /* ── Texture ──────────────────────────────────────────────────────── */
  // Ha Ultra aktív, texture cost = 0 (az Ultra tartalmazza)
  let texture = 0;
  if (!isUltra && (req.texture || req.pbr)) {
    const isHD = req.texture_quality === "HD";
    if (isHD) {
      texture = v3
        ? (CREDIT_COSTS["addon:texture_HD:v3"]  ?? 30)
        : (CREDIT_COSTS["addon:texture_HD"]     ?? 20);
    } else {
      // "detailed" (default) vagy "standard"
      texture = v3
        ? (CREDIT_COSTS["addon:texture_standard:v3"] ?? 20)
        : (CREDIT_COSTS["addon:texture_standard"]    ?? 10);
    }
    breakdown.texture = texture;
  }

  /* ── Smart Low Poly at generation time ───────────────────────────── */
  const smart_low_poly = req.smart_low_poly
    ? (CREDIT_COSTS["addon:smart_low_poly_gen"] ?? 10)
    : 0;
  if (smart_low_poly) breakdown.smart_low_poly = smart_low_poly;

  /* ── Generate Parts ───────────────────────────────────────────────── */
  const generate_parts = req.generate_parts
    ? (CREDIT_COSTS["addon:generate_parts"] ?? 20)
    : 0;
  if (generate_parts) breakdown.generate_parts = generate_parts;

  /* ── Quad ─────────────────────────────────────────────────────────── */
  const quad = req.quad ? (CREDIT_COSTS["addon:quad"] ?? 5) : 0;
  if (quad) breakdown.quad = quad;

  /* ── Animation ────────────────────────────────────────────────────── */
  const animation = req.animation
    ? (CREDIT_COSTS["addon:animation_per_preset"] ?? 0)
    : 0;
  if (animation) breakdown.animation = animation;

  const total = base + texture + geometry_quality + smart_low_poly + generate_parts + quad + animation;
  return {
    base, texture, pbr: 0, texture_quality: 0,
    geometry_quality, smart_low_poly, quad, animation,
    total, breakdown,
  };
}

/**
 * Estimate credit cost for a full pipeline.
 */
export function estimatePipelineCost(req) {
  const mv = req.modelVersion ?? DEFAULT_MODEL;
  const v3 = isV3Model(mv);
  const steps = {};

  steps.text_to_model = CREDIT_COSTS[`text_to_model:${mv}`] ?? CREDIT_COSTS.text_to_model ?? 0;

  if (req.hasTexture || req.hasPbr) {
    const isHD = req.textureQuality === "HD";
    const key = isHD
      ? (v3 ? "addon:texture_HD:v3"       : "addon:texture_HD")
      : (v3 ? "addon:texture_standard:v3" : "addon:texture_standard");
    steps.texture_addon = CREDIT_COSTS[key] ?? 0;
  }

  if (req.runSmartLowPoly) steps.smart_low_poly = CREDIT_COSTS.smart_low_poly ?? 0;
  if (req.runRig) {
    steps.animate_prerigcheck = CREDIT_COSTS.animate_prerigcheck ?? 0;
    steps.animate_rig = CREDIT_COSTS.animate_rig ?? 0;
  }
  if (req.animations?.length) {
    steps.animate_retarget =
      (CREDIT_COSTS.animate_retarget ?? 0) +
      (req.animations.length - 1) * (CREDIT_COSTS["addon:animation_per_preset"] ?? 0);
  }
  if (req.lodLevels > 0) {
    steps.convert_model_lod = (CREDIT_COSTS.convert_model ?? 0) * req.lodLevels;
  }

  const total = Object.values(steps).reduce((a, b) => a + b, 0);
  return { steps, total };
}