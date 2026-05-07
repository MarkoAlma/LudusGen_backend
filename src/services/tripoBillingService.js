import { v4 as uuid } from "uuid";

import { estimateCost } from "../lib/creditEstimator.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { taskService } from "./taskService.js";
import { deductCredits, refundCredits, linkTaskIdToTransaction } from "./creditService.js";
import {
  SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE,
  TRIPO_API_NO_BALANCE_CODE,
  TRIPO_API_UNAVAILABLE_CODE,
  buildTripoAvailability,
} from "./serviceAvailabilityService.js";

function isInsufficientProviderCredit(err) {
  return err?.code === "INSUFFICIENT_TRIPO_CREDITS" || err?.code === TRIPO_API_NO_BALANCE_CODE;
}

export function getTaskCreditEstimate(body) {
  const estimate = estimateCost(body);
  return {
    estimate,
    amount: estimate.total,
  };
}

export function makePendingCreditTransactionId(taskType) {
  return `pending_${taskType || "tripo_task"}_${uuid()}`;
}

export async function ensureProviderCredits(amount) {
  const required = Math.max(Number(amount) || 0, 1);

  try {
    const tripoBalance = await getTripoClient().getBalance();
    const availability = buildTripoAvailability(tripoBalance, { requiredCredits: required });
    if (!availability.available) {
      throw Object.assign(new Error(availability.message), {
        code: availability.code,
        available: availability.balance,
        required,
      });
    }
  } catch (err) {
    if (isInsufficientProviderCredit(err)) throw err;
    console.warn("[TripoBilling] Provider balance check failed:", err.message);
    throw Object.assign(new Error(SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE), {
      code: TRIPO_API_UNAVAILABLE_CODE,
      cause: err,
    });
  }
}

export async function reserveCreditsForTask({
  userId,
  amount,
  taskType,
  transactionId = null,
  checkProviderBalance = true,
} = {}) {
  const normalizedAmount = Number(amount);
  if (!Number.isFinite(normalizedAmount) || normalizedAmount < 0) {
    throw new Error(`Invalid credit amount: ${amount}`);
  }

  const reservation = {
    userId,
    amount: normalizedAmount,
    taskType,
    tempTxId: null,
    creditsDeducted: false,
  };

  if (checkProviderBalance) {
    await ensureProviderCredits(normalizedAmount);
  }

  if (normalizedAmount <= 0 || !userId) return reservation;

  reservation.tempTxId = transactionId ?? makePendingCreditTransactionId(taskType);
  await deductCredits(userId, normalizedAmount, reservation.tempTxId, taskType);
  reservation.creditsDeducted = true;
  return reservation;
}

export async function refundCreditReservation(reservation, reason, taskIdOverride = null) {
  if (!reservation?.creditsDeducted || !reservation.userId || reservation.amount <= 0) {
    return { success: true, skipped: true };
  }

  const refundTaskId = taskIdOverride ?? reservation.taskId ?? reservation.tempTxId;
  if (!refundTaskId) return { success: true, skipped: true };

  const result = await refundCredits(reservation.userId, reservation.amount, refundTaskId, reason);
  reservation.creditsDeducted = false;
  return result;
}

export async function linkReservationToTask(reservation, taskId) {
  if (!reservation?.creditsDeducted || !reservation.userId || !reservation.tempTxId || !taskId) {
    return reservation;
  }

  try {
    await linkTaskIdToTransaction(reservation.userId, reservation.tempTxId, taskId);
    reservation.taskId = taskId;
  } catch (err) {
    reservation.taskId = taskId;
    reservation.linkError = err.message;
    console.error(`[TripoBilling] Failed to link ${reservation.tempTxId} to task ${taskId}:`, err.message);
    if (!err.billingLinkMapped) throw err;
    return reservation;
  }
  return reservation;
}

export function getCreateFailureRefundReason(taskType, err) {
  if (err?.message?.includes("403") && err.message?.includes("credit")) {
    return "tripo_403_insufficient_credit";
  }
  if (taskType === "texture_model") return "texture_model_create_failed";
  if (taskType === "refine_model" && err?.message?.includes("1004")) return "refine_no_draft_output";
  return "tripo_create_failed";
}

export async function createTaskWithBilling({
  userId,
  body,
  callbackUrl = null,
  idempotencyKey = null,
  signal = null,
  checkProviderBalance = true,
} = {}) {
  const { estimate, amount } = getTaskCreditEstimate(body);
  const reservation = await reserveCreditsForTask({
    userId,
    amount,
    taskType: body?.type,
    checkProviderBalance,
  });

  let taskId = null;
  try {
    taskId = await taskService.create(body, {
      callbackUrl,
      idempotencyKey,
      signal,
    });
    await linkReservationToTask(reservation, taskId);
    return { taskId, estimate, amount, reservation };
  } catch (err) {
    if (!taskId) {
      await refundCreditReservation(reservation, getCreateFailureRefundReason(body?.type, err));
    }
    throw err;
  }
}
