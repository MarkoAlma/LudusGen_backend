import admin from "firebase-admin";

import { hashSpritePrompt } from "../lib/spriteSecurity.js";
import { deductCredits, refundCredits, getUserBalance } from "./creditService.js";

export const CREDIT_USD_VALUE = 39.99 / 5000;
export const TARGET_MARGIN_RATIO = 0.2;
export const PROVIDER_USD_PER_LUDUS_CREDIT = CREDIT_USD_VALUE * (1 - TARGET_MARGIN_RATIO);

const DEFAULT_PROVIDER_COST_USD = {
  pixellab: 0.09,
  godmode: 0.40,
  segmind: 0.24,
};

function providerEnvCostKey(provider) {
  return `${String(provider || "").toUpperCase()}_SPRITE_COST_USD`;
}

function normalizeOperationCount(usage) {
  const operationCount = Number(usage?.operationCount);
  if (!Number.isFinite(operationCount) || operationCount <= 0) return 1;
  return Math.max(1, Math.ceil(operationCount));
}

function normalizeCreditAmount(amount) {
  const normalized = Number(amount);
  if (!Number.isFinite(normalized) || normalized < 0) {
    throw new Error(`Invalid sprite credit amount: ${amount}`);
  }
  return Math.ceil(normalized);
}

export function makeSpriteCreditReservationId(requestId) {
  const safeRequestId = String(requestId || "")
    .trim()
    .replace(/[^a-zA-Z0-9_.-]/g, "_")
    .slice(0, 360);
  if (!safeRequestId) throw new Error("requestId is required for sprite credit reservation");
  return `sprite_pending_${safeRequestId}`;
}

export function calculateSpriteCreditCharge(providerCostUsd) {
  const cost = Number(providerCostUsd);
  if (!Number.isFinite(cost) || cost <= 0) return 0;
  return Math.ceil(cost / PROVIDER_USD_PER_LUDUS_CREDIT);
}

export function normalizeProviderCostUsd({ usage = null, provider, env = process.env } = {}) {
  const usageUsd = Number(usage?.usd);
  if (Number.isFinite(usageUsd) && usageUsd > 0) return usageUsd;

  const operationCount = normalizeOperationCount(usage);

  const configured = Number(env[providerEnvCostKey(provider)]);
  if (Number.isFinite(configured) && configured >= 0) return configured * operationCount;

  return (DEFAULT_PROVIDER_COST_USD[provider] ?? DEFAULT_PROVIDER_COST_USD.segmind) * operationCount;
}

export function makeSpriteAuditPayload({
  userId,
  requestId,
  provider,
  prompt,
  creditAmount = 0,
  usdCost = 0,
  cacheHit = false,
  event = "charged",
  errorCode = null,
} = {}) {
  return {
    user_id: userId,
    request_id: requestId,
    provider,
    prompt_hash: hashSpritePrompt(prompt),
    credit_amount: creditAmount,
    usd_cost: usdCost,
    cache_hit: Boolean(cacheHit),
    event,
    error_code: errorCode,
  };
}

export async function ensureSufficientSpriteCredits({ userId, estimatedCreditAmount }) {
  if (!userId || estimatedCreditAmount <= 0) return { ok: true, balance: 0 };
  const balance = await getUserBalance(userId);
  if (balance < estimatedCreditAmount) {
    throw Object.assign(
      new Error(`Insufficient credits: ${balance} available, ${estimatedCreditAmount} required`),
      {
        code: "INSUFFICIENT_CREDITS",
        available: balance,
        required: estimatedCreditAmount,
      },
    );
  }
  return { ok: true, balance };
}

export async function reserveSpriteCredits({
  userId,
  requestId,
  provider,
  estimatedCreditAmount,
} = {}, {
  deduct = deductCredits,
} = {}) {
  const amount = normalizeCreditAmount(estimatedCreditAmount);
  const reservation = {
    userId,
    requestId,
    provider,
    amount,
    tempTxId: null,
    creditsDeducted: false,
    settled: false,
  };

  if (!userId || amount <= 0) return reservation;

  reservation.tempTxId = makeSpriteCreditReservationId(requestId);
  await deduct(userId, amount, reservation.tempTxId, `sprite:${provider || "auto"}:reservation`);
  reservation.creditsDeducted = true;
  return reservation;
}

export async function refundSpriteCreditReservation(
  reservation,
  reason = "sprite_generation_failed",
  { refund = refundCredits } = {},
) {
  if (
    !reservation?.creditsDeducted ||
    reservation.settled ||
    !reservation.userId ||
    reservation.amount <= 0 ||
    !reservation.tempTxId
  ) {
    return { success: true, skipped: true };
  }

  const result = await refund(reservation.userId, reservation.amount, reservation.tempTxId, reason);
  reservation.creditsDeducted = false;
  return result;
}

export async function settleSpriteCreditReservation({
  reservation,
  actualCreditAmount,
  provider,
} = {}, {
  deduct = deductCredits,
  refund = refundCredits,
} = {}) {
  const actualAmount = normalizeCreditAmount(actualCreditAmount);
  if (!reservation?.creditsDeducted || !reservation.userId || !reservation.tempTxId) {
    return { reservedCreditAmount: 0, adjustmentCreditAmount: actualAmount };
  }

  const adjustmentTaskId = `${reservation.tempTxId}_settlement`;
  const delta = actualAmount - reservation.amount;
  if (delta > 0) {
    await deduct(reservation.userId, delta, adjustmentTaskId, `sprite:${provider || reservation.provider || "auto"}:settlement`);
  } else if (delta < 0) {
    await refund(reservation.userId, Math.abs(delta), adjustmentTaskId, "sprite_over_reserved");
  }

  reservation.settled = true;
  return {
    reservedCreditAmount: reservation.amount,
    adjustmentCreditAmount: delta,
  };
}

export async function writeSpriteAuditLog(payload, { db = admin.firestore() } = {}) {
  const cleanPayload = Object.fromEntries(
    Object.entries(payload).filter(([, value]) => value !== undefined),
  );
  await db.collection("sprite_audit_logs").add({
    ...cleanPayload,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });
}

export function estimateSpriteGenerationCharge({
  providerCostUsd,
  usage = null,
  provider,
  reservation = null,
  env = process.env,
} = {}) {
  const usdCost = providerCostUsd ?? normalizeProviderCostUsd({ usage, provider, env });
  const creditAmount = calculateSpriteCreditCharge(usdCost);
  const reservedCreditAmount = reservation?.creditsDeducted ? reservation.amount : 0;

  return {
    creditAmount,
    usdCost,
    reservedCreditAmount,
    adjustmentCreditAmount: creditAmount - reservedCreditAmount,
  };
}

export async function chargeSpriteGeneration({
  userId,
  requestId,
  provider,
  prompt,
  providerCostUsd,
  usage = null,
  reservation = null,
} = {}, {
  deduct = deductCredits,
  refund = refundCredits,
  writeAuditLog = writeSpriteAuditLog,
  env = process.env,
} = {}) {
  const estimated = estimateSpriteGenerationCharge({
    providerCostUsd,
    usage,
    provider,
    reservation,
    env,
  });
  const settlement = await settleSpriteCreditReservation({
    reservation,
    actualCreditAmount: estimated.creditAmount,
    provider,
  }, {
    deduct,
    refund,
  });

  if (!reservation?.creditsDeducted && estimated.creditAmount > 0) {
    await deduct(userId, estimated.creditAmount, requestId, `sprite:${provider}`);
  }

  const auditPayload = makeSpriteAuditPayload({
    userId,
    requestId,
    provider,
    prompt,
    creditAmount: estimated.creditAmount,
    usdCost: estimated.usdCost,
    cacheHit: false,
    event: "charged",
  });
  let auditLogError = null;
  try {
    await writeAuditLog(auditPayload);
  } catch (error) {
    auditLogError = error?.message || String(error);
    console.warn("[SpriteBilling] Audit log write failed:", auditLogError);
  }

  return {
    creditAmount: estimated.creditAmount,
    usdCost: estimated.usdCost,
    reservedCreditAmount: settlement.reservedCreditAmount,
    adjustmentCreditAmount: settlement.adjustmentCreditAmount,
    auditPayload,
    ...(auditLogError ? { auditLogError } : {}),
  };
}
