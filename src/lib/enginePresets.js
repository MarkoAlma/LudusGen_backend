// src/lib/enginePresets.js
import { ENGINE_PRESETS } from "../config/tripo.config.js";

/* ─── Engine preset resolver ──────────────────────────────────────────── */
export function resolveEnginePreset(engine) {
  const preset = ENGINE_PRESETS[engine];
  if (!preset) throw new Error(
    `Unknown engine "${engine}". Valid: ${Object.keys(ENGINE_PRESETS).join(", ")}`,
  );
  return preset;
}

export function mergeEnginePreset(engine, overrides = {}) {
  const base = resolveEnginePreset(engine);
  return { ...base, ...Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined)) };
}

/* ─── Face limit config (mirrors frontend getFaceLimitConfig) ─────────── */
/**
 * @param {boolean} smartLowPoly
 * @param {boolean} quad
 * @returns {{ min: number, max: number, step: number, defaultVal: number, allowAuto: boolean }}
 */
export function getFaceLimitConfig(smartLowPoly, quad) {
  if (smartLowPoly && quad)  return { min: 500,   max: 10_000,  step: 500,   defaultVal: 5_000,  allowAuto: false };
  if (smartLowPoly && !quad) return { min: 1_000,  max: 20_000,  step: 1_000, defaultVal: 8_000,  allowAuto: false };
  if (!smartLowPoly && quad) return { min: 0,      max: 100_000, step: 1_000, defaultVal: 10_000, allowAuto: true  };
  return                      { min: 0,      max: 500_000, step: 5_000, defaultVal: 0,      allowAuto: true  };
}

/* ─── Face limit validator (throws on constraint violation) ───────────── */
/**
 * Validates and normalises face_limit.
 * Returns undefined when the value means "auto" (omit from API payload).
 * @param {number|undefined|null} face_limit
 * @param {boolean} smart_low_poly
 * @param {boolean} quad
 * @returns {number|undefined}
 */
export function validateFaceLimit(face_limit, smart_low_poly, quad) {
  if (face_limit === undefined || face_limit === null) {
    if (smart_low_poly) {
      const cfg = getFaceLimitConfig(smart_low_poly, quad);
      throw new Error(`face_limit is required when smart_low_poly=true. Valid range: ${cfg.min}–${cfg.max}`);
    }
    return undefined;
  }

  const fl = Number(face_limit);
  if (!Number.isFinite(fl) || fl < 0) {
    if (smart_low_poly) throw new Error("face_limit must be a positive number when smart_low_poly=true");
    return undefined;
  }

  const cfg = getFaceLimitConfig(smart_low_poly, quad);
  if (!cfg.allowAuto && fl < cfg.min)
    throw new Error(`face_limit must be ≥ ${cfg.min} (got ${fl})`);
  if (fl > cfg.max)
    throw new Error(`face_limit must be ≤ ${cfg.max} (got ${fl})`);
  if (fl === 0 && cfg.allowAuto) return undefined; // auto → omit

  return fl;
}