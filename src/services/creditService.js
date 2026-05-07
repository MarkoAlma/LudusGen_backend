// src/services/creditService.js
//
// Credit deduction, refund, and transaction logging.
// Uses Firestore transactions to prevent race conditions on concurrent requests.

import admin from "firebase-admin";

const CREDIT_HISTORY_COLLECTION = "credit_history";
const USERS_COLLECTION = "users";

/**
 * Deduct credits from a user's balance.
 * Uses a Firestore transaction to prevent race conditions.
 *
 * @param {string} userId - Firebase UID
 * @param {number} amount - Credits to deduct
 * @param {string} taskId - Tripo task ID (for idempotency)
 * @param {string} taskType - Tripo task type (e.g. "text_to_model")
 * @returns {{ success: boolean, remaining: number }}
 * @throws {Error} If insufficient credits or already deducted
 */
export async function deductCredits(userId, amount, taskId, taskType) {
  if (amount <= 0) return { success: true, remaining: await getUserBalance(userId) };

  const db = admin.firestore();
  const userRef = db.collection(USERS_COLLECTION).doc(userId);

  // Idempotency check: if this taskId already has a debit entry, skip
  const existingTx = await db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "debit")
    .limit(1)
    .get();

  if (!existingTx.empty) {
    const doc = existingTx.docs[0].data();
    return { success: true, remaining: doc.balanceAfter };
  }

  let remaining = 0;

  await db.runTransaction(async (tx) => {
    const userDoc = await tx.get(userRef);

    if (!userDoc.exists) {
      throw new Error("User document not found");
    }

    const userData = userDoc.data();
    const currentBalance = userData.credits ?? 0;

    if (currentBalance < amount) {
      throw Object.assign(
        new Error(`Insufficient credits: ${currentBalance} available, ${amount} required`),
        { code: "INSUFFICIENT_CREDITS", available: currentBalance, required: amount }
      );
    }

    const newBalance = currentBalance - amount;
    tx.update(userRef, { credits: newBalance });

    // Log transaction
    const txRef = db
      .collection(CREDIT_HISTORY_COLLECTION)
      .doc(userId)
      .collection("transactions")
      .doc();

    tx.set(txRef, {
      type: "debit",
      amount,
      taskId,
      taskType,
      balanceBefore: currentBalance,
      balanceAfter: newBalance,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    remaining = newBalance;
  });

  return { success: true, remaining };
}

/**
 * Refund credits to a user's balance.
 * Uses a Firestore transaction for atomicity.
 *
 * @param {string} userId - Firebase UID
 * @param {number} amount - Credits to refund
 * @param {string} taskId - Tripo task ID
 * @param {string} reason - Reason for refund (e.g. "task_failed", "task_cancelled")
 * @returns {{ success: boolean, remaining: number }}
 */
export async function refundCredits(userId, amount, taskId, reason) {
  if (amount <= 0) return { success: true, remaining: await getUserBalance(userId) };

  const db = admin.firestore();
  const userRef = db.collection(USERS_COLLECTION).doc(userId);

  // Idempotency check: if this taskId already has a refund entry, skip
  const existingTx = await db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "refund")
    .limit(1)
    .get();

  if (!existingTx.empty) {
    const doc = existingTx.docs[0].data();
    return { success: true, remaining: doc.balanceAfter };
  }

  let remaining = 0;

  await db.runTransaction(async (tx) => {
    const userDoc = await tx.get(userRef);

    if (!userDoc.exists) {
      throw new Error("User document not found");
    }

    const userData = userDoc.data();
    const currentBalance = userData.credits ?? 0;
    const newBalance = currentBalance + amount;

    tx.update(userRef, { credits: newBalance });

    // Log transaction
    const txRef = db
      .collection(CREDIT_HISTORY_COLLECTION)
      .doc(userId)
      .collection("transactions")
      .doc();

    tx.set(txRef, {
      type: "refund",
      amount,
      taskId,
      reason,
      balanceBefore: currentBalance,
      balanceAfter: newBalance,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    remaining = newBalance;
  });

  return { success: true, remaining };
}

/**
 * Link a real Tripo taskId to an existing transaction.
 * Usually used to replace the "pending_..." temporary ID after task creation.
 *
 * @param {string} userId - Firebase UID
 * @param {string} tempTaskId - The temporary ID used during deduction
 * @param {string} realTaskId - The actual ID returned by Tripo
 */
export async function linkTaskIdToTransaction(userId, tempTaskId, realTaskId) {
  const db = admin.firestore();
  const snap = await db.collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", tempTaskId)
    .limit(1)
    .get();

  if (snap.empty) {
    console.warn(`[CreditService] No transaction found with temp ID ${tempTaskId} for user ${userId}`);
    return;
  }

  await snap.docs[0].ref.update({ taskId: realTaskId });
}

/**
 * Get current credit balance for a user.
 *
 * @param {string} userId - Firebase UID
 * @returns {number}
 */
export async function getUserBalance(userId) {
  const db = admin.firestore();
  const doc = await db.collection(USERS_COLLECTION).doc(userId).get();
  if (!doc.exists) return 0;
  return doc.data().credits ?? 0;
}

/**
 * Check if a task has already been charged (idempotency helper).
 *
 * @param {string} userId - Firebase UID
 * @param {string} taskId - Tripo task ID
 * @returns {boolean}
 */
export async function hasBeenCharged(userId, taskId) {
  const db = admin.firestore();
  const snap = await db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "debit")
    .limit(1)
    .get();

  return !snap.empty;
}
