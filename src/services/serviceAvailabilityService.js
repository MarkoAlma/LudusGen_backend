export const API_NO_BALANCE_MESSAGE = "Currently no balance on API";
export const SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE = "Service temporarily unavailable";

export const TRIPO_API_NO_BALANCE_CODE = "TRIPO_API_NO_BALANCE";
export const TRIPO_API_UNAVAILABLE_CODE = "TRIPO_API_UNAVAILABLE";
export const TRELLIS_API_LIMIT_REACHED_CODE = "TRELLIS_API_LIMIT_REACHED";
export const TRELLIS_API_UNAVAILABLE_CODE = "TRELLIS_API_UNAVAILABLE";
export const IMAGE_STUDIO_SUBSCRIPTION_REQUIRED_CODE = "IMAGE_STUDIO_SUBSCRIPTION_REQUIRED";

const DEFAULT_TRELLIS_DAILY_LIMIT = 1000;
const trellisUsage = {
  dayKey: "",
  used: 0,
};

function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

export function getUtcDayKey(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

export function getNextUtcDayStartIso(date = new Date()) {
  const next = new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate() + 1,
    0,
    0,
    0,
    0,
  ));
  return next.toISOString();
}

export function normalizeTrellisLimit(value, fallback = DEFAULT_TRELLIS_DAILY_LIMIT) {
  const limit = Math.floor(toNumber(value, fallback));
  return limit > 0 ? limit : fallback;
}

export function buildTripoAvailability(balancePayload = {}, { requiredCredits = 0 } = {}) {
  const balance = toNumber(balancePayload?.balance, 0);
  const frozen = toNumber(balancePayload?.frozen, 0);
  const required = Math.max(0, toNumber(requiredCredits, 0));
  const effectiveRequired = Math.max(required, 1);
  const available = balance >= effectiveRequired;

  return {
    service: "tripo",
    available,
    balance,
    frozen,
    requiredCredits: required,
    code: available ? null : TRIPO_API_NO_BALANCE_CODE,
    message: available ? "" : API_NO_BALANCE_MESSAGE,
  };
}

export function buildServiceUnavailableAvailability(
  service,
  code,
  message = SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE,
) {
  return {
    service,
    available: false,
    code,
    message,
  };
}

export function buildTrellisAvailability({
  used = 0,
  limit = DEFAULT_TRELLIS_DAILY_LIMIT,
  apiKeyConfigured = true,
  now = new Date(),
} = {}) {
  const normalizedLimit = normalizeTrellisLimit(limit);
  const normalizedUsed = Math.max(0, Math.floor(toNumber(used, 0)));
  const remaining = Math.max(0, normalizedLimit - normalizedUsed);

  if (!apiKeyConfigured) {
    return {
      service: "trellis",
      available: false,
      used: normalizedUsed,
      limit: normalizedLimit,
      remaining,
      resetsAt: getNextUtcDayStartIso(now),
      code: TRELLIS_API_UNAVAILABLE_CODE,
      message: SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE,
    };
  }

  const available = remaining > 0;
  return {
    service: "trellis",
    available,
    used: normalizedUsed,
    limit: normalizedLimit,
    remaining,
    resetsAt: getNextUtcDayStartIso(now),
    code: available ? null : TRELLIS_API_LIMIT_REACHED_CODE,
    message: available ? "" : SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE,
  };
}

export function getTrellisLimitFromEnv(env = process.env) {
  return normalizeTrellisLimit(
    env.NVIDIA_TRELLIS_DAILY_LIMIT ?? env.TRELLIS_DAILY_CALL_LIMIT,
    DEFAULT_TRELLIS_DAILY_LIMIT,
  );
}

function resetTrellisUsageIfNeeded(now = new Date()) {
  const dayKey = getUtcDayKey(now);
  if (trellisUsage.dayKey !== dayKey) {
    trellisUsage.dayKey = dayKey;
    trellisUsage.used = 0;
  }
}

export function getTrellisUsageSnapshot({ now = new Date(), env = process.env } = {}) {
  resetTrellisUsageIfNeeded(now);
  return {
    dayKey: trellisUsage.dayKey,
    used: trellisUsage.used,
    limit: getTrellisLimitFromEnv(env),
  };
}

export function getTrellisAvailabilitySnapshot({ now = new Date(), env = process.env } = {}) {
  const snapshot = getTrellisUsageSnapshot({ now, env });
  return buildTrellisAvailability({
    ...snapshot,
    apiKeyConfigured: Boolean(env.NVIDIA_API_KEY),
    now,
  });
}

export function recordTrellisCall({ now = new Date(), env = process.env } = {}) {
  resetTrellisUsageIfNeeded(now);
  trellisUsage.used += 1;
  return getTrellisAvailabilitySnapshot({ now, env });
}

export function buildImageStudioAvailability() {
  return {
    service: "image-studio",
    available: false,
    code: IMAGE_STUDIO_SUBSCRIPTION_REQUIRED_CODE,
    message: SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE,
  };
}
