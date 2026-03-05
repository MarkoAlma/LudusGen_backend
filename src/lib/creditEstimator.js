// src/lib/creditEstimator.js
import { CREDIT_COSTS, DEFAULT_MODEL } from "../config/tripo.config.js";

/**
 * Estimate credit cost for a single task BEFORE creation.
 * @param {{ type: string, model_version?: string, texture?: boolean, pbr?: boolean,
 *           texture_quality?: string, geometry_quality?: string,
 *           smart_low_poly?: boolean, generate_parts?: boolean, animation?: boolean }} req
 */
export function estimateCost(req) {
  const modelVersion = req.model_version ?? DEFAULT_MODEL;
  const breakdown = {};

  // Base
  const versionedKey = `${req.type}:${modelVersion}`;
  const base = CREDIT_COSTS[versionedKey] ?? CREDIT_COSTS[req.type] ?? 0;
  breakdown.base = base;

  // Texture
let texture = 0;
if (req.texture || req.pbr) {
  // HD = texture_quality "HD" vagy "detailed" → +20 total
  // Standard = default → +10 total
  const isHD = req.texture_quality === "HD" || req.texture_quality === "detailed";
  texture = isHD
    ? (CREDIT_COSTS["addon:texture_HD"] ?? 20)
    : (CREDIT_COSTS["addon:texture_standard"] ?? 10);
  breakdown.texture = texture;
}
// PBR külön cost nincs — benne van a textúrában

  // PBR: benne van a texture csomagban, külön ár nincs
  const pbr = 0;

  // Geometry quality (v3.0+ only)
  let geometry_quality = 0;
  if (req.geometry_quality === "detailed") {
    geometry_quality = CREDIT_COSTS["addon:geometry_detailed"] ?? 0;
    breakdown.geometry_quality = geometry_quality;
  }

  // Smart Low Poly at generation time
  let smart_low_poly = 0;
  if (req.smart_low_poly) {
    smart_low_poly = CREDIT_COSTS["addon:smart_low_poly_gen"] ?? 0;
    breakdown.smart_low_poly = smart_low_poly;
  }

  // Generate Parts
  let generate_parts = 0;
  if (req.generate_parts) {
    generate_parts = CREDIT_COSTS["addon:generate_parts"] ?? 0;
    breakdown.generate_parts = generate_parts;
  }

  let quad = 0;
  if (req.quad) {
    quad = CREDIT_COSTS["addon:quad"] ?? 5;
    breakdown.quad = quad;
  }
  // Animation
  let animation = 0;
  if (req.animation) {
    animation = CREDIT_COSTS["addon:animation_per_preset"] ?? 0;
    breakdown.animation = animation;
  }

  const total = base + texture + geometry_quality + smart_low_poly + generate_parts + quad + animation;
  return { base, texture, pbr: 0, texture_quality: 0, geometry_quality, smart_low_poly, quad, animation, total, breakdown };

}

/**
 * Estimate credit cost for a full pipeline.
 * @param {{ modelVersion?: string, hasTexture?: boolean, hasPbr?: boolean,
 *           textureQuality?: string, runSmartLowPoly?: boolean, runRig?: boolean,
 *           animations?: string[], lodLevels?: number }} req
 */
export function estimatePipelineCost(req) {
  const modelVersion = req.modelVersion ?? DEFAULT_MODEL;
  const steps = {};

  steps.text_to_model = CREDIT_COSTS[`text_to_model:${modelVersion}`] ?? CREDIT_COSTS.text_to_model ?? 0;

  if (req.hasTexture) {
    const key = req.textureQuality === "HD" || req.textureQuality === "detailed"
  ? "addon:texture_HD"
  : "addon:texture_standard";
    steps.texture_addon = CREDIT_COSTS[key] ?? 0;
  }
  if (req.hasPbr) steps.pbr_addon = CREDIT_COSTS["addon:pbr"] ?? 0;
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