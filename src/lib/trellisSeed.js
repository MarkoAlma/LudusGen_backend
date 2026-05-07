export const TRELLIS_SEED_MAX = 2147483647;

function clampTrellisSeed(value, fallback = 0) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(TRELLIS_SEED_MAX, Math.max(0, Math.floor(parsed)));
}

export function createTrellisRandomSeed(random = Math.random) {
  const raw = Number(random());
  const normalized = Number.isFinite(raw) ? Math.min(1, Math.max(0, raw)) : 0;
  return clampTrellisSeed(Math.floor((TRELLIS_SEED_MAX + 1) * normalized));
}

export function resolveTrellisRequestSeed(body = {}, random = Math.random) {
  const rawSeed = body?.seed;
  if (rawSeed === undefined || rawSeed === null || String(rawSeed).trim() === "") {
    return createTrellisRandomSeed(random);
  }
  return clampTrellisSeed(rawSeed, 0);
}
