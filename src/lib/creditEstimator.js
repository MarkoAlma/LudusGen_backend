// src/lib/creditEstimator.js
import { CREDIT_COSTS, DEFAULT_MODEL } from "../config/tripo.config.js";

const isV14         = (mv) => mv === "v1.4-20240625";
const supportsUltra = (mv) => mv === "P1-20260311" || mv.startsWith("v3.");

// P1-20260311 does NOT support: quad, smart_low_poly, generate_parts, geometry_quality.
// It also only supports texture_quality="standard" (not "detailed").
// The estimator must mirror what taskService.validate() actually sends to the API,
// otherwise users get overcharged for addons that get stripped.
const P1_UNSUPPORTED = new Set(["quad", "smart_low_poly", "generate_parts", "geometry_quality"]);
const isP1 = (mv) => mv === "P1-20260311";

// ─────────────────────────────────────────────────────────────────────────────
// GENERATION COST
//
// Alap  = CREDIT_COSTS["type:mv"]            → without_texture ár
// std   = alap + addon:texture_standard      → +10
// HD    = alap + addon:texture_standard + addon:texture_HD_upgrade  → +20
// V1.4  = fix ár, nincs addon
// ─────────────────────────────────────────────────────────────────────────────

export function estimateCost(req) {
  const mv  = req.model_version ?? DEFAULT_MODEL;
  const key = `${req.type}:${mv}`;
  const base = CREDIT_COSTS[key] ?? 10;
  const breakdown = { base };

  // V1.4: lapos árazás, nincs addon
  if (isV14(mv)) return { total: base, breakdown };

  // Textúra addonok
  // P1-20260311 only supports texture_quality="standard" — taskService strips "detailed".
  // So for P1, never charge the HD upgrade even if req.texture_quality === "detailed".
  const hasTex  = req.texture || req.pbr;
  const isHD    = req.texture_quality === "detailed" && !isP1(mv);
  let texAddon  = 0;
  if (hasTex) {
    const std  = CREDIT_COSTS["addon:texture_standard"]   ?? 10;
    const hdUp = CREDIT_COSTS["addon:texture_HD_upgrade"] ?? 10;
    texAddon = std + (isHD ? hdUp : 0);
    breakdown.texture = texAddon;
  }

  // Advanced Generation Setup addonok
  // P1-20260311 strips unsupported params in taskService.validate(), so we must
  // not charge for them here either — otherwise users get overcharged.
  const ultraAddon = (req.geometry_quality === "detailed" && supportsUltra(mv) && !isP1(mv))
    ? (CREDIT_COSTS["addon:geometry_detailed"] ?? 20) : 0;
  const slpAddon   = (req.smart_low_poly && !isP1(mv)) ? (CREDIT_COSTS["addon:smart_low_poly_gen"] ?? 10) : 0;
  const partsAddon = (req.generate_parts && !isP1(mv)) ? (CREDIT_COSTS["addon:generate_parts"]    ?? 20) : 0;
  const quadAddon  = (req.quad && !isP1(mv)) ? (CREDIT_COSTS["addon:quad"]               ??  5) : 0;
  const styleAddon = (req.style && !isP1(mv)) ? (CREDIT_COSTS["addon:style"]              ??  5) : 0;

  if (ultraAddon)  breakdown.geometry_detailed = ultraAddon;
  if (slpAddon)    breakdown.smart_low_poly    = slpAddon;
  if (partsAddon)  breakdown.generate_parts    = partsAddon;
  if (quadAddon)   breakdown.quad              = quadAddon;
  if (styleAddon)  breakdown.style             = styleAddon;

  const total = base + texAddon + ultraAddon + slpAddon + partsAddon + quadAddon + styleAddon;
  return { total, breakdown };
}

// ─────────────────────────────────────────────────────────────────────────────
// TEXTURE GENERATION COST  (önálló texture_model task)
// ─────────────────────────────────────────────────────────────────────────────

export function estimateTextureCost(req) {
  const isHD     = req.texture_quality === "HD";
  const base     = isHD ? (CREDIT_COSTS["texture_model:HD"] ?? 20) : (CREDIT_COSTS.texture_model ?? 10);
  const styleRef = req.style_reference ? (CREDIT_COSTS["addon:texture_style_ref"] ?? 5) : 0;
  const breakdown = { base, ...(styleRef && { style_reference: styleRef }) };
  return { total: base + styleRef, breakdown };
}

// ─────────────────────────────────────────────────────────────────────────────
// POST-PROCESSING COST
// ─────────────────────────────────────────────────────────────────────────────

export function estimatePostCost(req) {
  let cost;
  if (req.type === "convert_model") {
    cost = req.advanced
      ? (CREDIT_COSTS["convert_model:advanced"] ?? 10)
      : (CREDIT_COSTS.convert_model             ??  5);
  } else {
    cost = CREDIT_COSTS[req.type] ?? 0;
  }
  return { total: cost, breakdown: { [req.type]: cost } };
}

// ─────────────────────────────────────────────────────────────────────────────
// ANIMATION COST
// ─────────────────────────────────────────────────────────────────────────────

export function estimateAnimationCost(req) {
  const count    = req.animationCount ?? 1;
  const precheck = CREDIT_COSTS.animate_prerigcheck ?? 0;
  const rig      = CREDIT_COSTS.animate_rig         ?? 25;
  const retarget = (CREDIT_COSTS.animate_retarget   ?? 10) * count;
  const breakdown = { animate_prerigcheck: precheck, animate_rig: rig, animate_retarget: retarget };
  return { total: precheck + rig + retarget, breakdown };
}

// ─────────────────────────────────────────────────────────────────────────────
// FULL PIPELINE COST
// ─────────────────────────────────────────────────────────────────────────────

export function estimatePipelineCost(req) {
  const mv    = req.modelVersion ?? DEFAULT_MODEL;
  const steps = {};

  const genResult = estimateCost({
    type:             "text_to_model",
    model_version:    mv,
    texture:          req.hasTexture,
    pbr:              req.hasPbr,
    texture_quality:  req.textureQuality,
    geometry_quality: req.geometryQuality,
    smart_low_poly:   req.smartLowPoly,
    generate_parts:   req.generateParts,
    quad:             req.quad,
    style:            req.style,
  });
  steps.generation = genResult.total;

  if (req.runSmartLowPoly) steps.smart_low_poly = CREDIT_COSTS.smart_low_poly ?? 10;
  if (req.runRig) {
    const animResult = estimateAnimationCost({ animationCount: req.animations?.length ?? 1 });
    Object.assign(steps, animResult.breakdown);
  }
  if (req.lodLevels > 0) {
    steps.convert_model_lod = (CREDIT_COSTS.convert_model ?? 5) * req.lodLevels;
  }

  const total = Object.values(steps).reduce((a, b) => a + b, 0);
  return { steps, total };
}
