// src/services/creditService.js
//
// Credit deduction, refund, and transaction logging.
// Uses Firestore transactions to prevent race conditions on concurrent requests.

import admin from "firebase-admin";

const CREDIT_HISTORY_COLLECTION = "credit_history";
const USERS_COLLECTION = "users";
const BILLING_LINKS_COLLECTION = "tripo_billing_links";

export function makeCreditTransactionDocId(type, taskId) {
  const normalizedType = String(type || "").trim();
  const normalizedTaskId = String(taskId || "").trim();
  if (!normalizedType) throw new Error("transaction type required");
  if (!normalizedTaskId) throw new Error("taskId required");

  const safeTaskId = normalizedTaskId
    .replace(/[^a-zA-Z0-9_.-]/g, "_")
    .slice(0, 420);
  return `${normalizedType}_${safeTaskId}`;
}

function makeBillingLinkDocId(taskId) {
  return makeCreditTransactionDocId("link", taskId);
}

async function markBillingLink(linkRef, patch) {
  try {
    await linkRef.set({
      ...patch,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
  } catch (err) {
    console.warn(`[CreditService] Billing link status update failed for ${linkRef.id}:`, err.message);
  }
}

function assertValidCreditAmount(amount) {
  if (!Number.isFinite(amount) || amount < 0) {
    throw new Error(`Invalid credit amount: ${amount}`);
  }
}

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
  assertValidCreditAmount(amount);

  const db = admin.firestore();
  const userRef = db.collection(USERS_COLLECTION).doc(userId);
  const txRef = db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .doc(makeCreditTransactionDocId("debit", taskId));

  // Legacy idempotency check: query-based lookup OUTSIDE the transaction.
  // Firestore transactions only guarantee isolation for document-path reads;
  // where-queries inside a transaction are NOT safely isolated.
  const legacySnap = await db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "debit")
    .limit(1)
    .get();
  if (!legacySnap.empty) {
    const legacyData = legacySnap.docs[0].data();
    console.log(`[CreditService] Legacy deduction already exists for task ${taskId}, skipping`);
    return { success: true, remaining: legacyData.balanceAfter ?? 0 };
  }

  let remaining = 0;

  await db.runTransaction(async (tx) => {
    // Primary idempotency: doc-ID based check — safe inside a transaction.
    const existingTx = await tx.get(txRef);
    if (existingTx.exists) {
      console.log(`[CreditService] Deduction already exists for task ${taskId}, skipping`);
      remaining = existingTx.data().balanceAfter ?? 0;
      return;
    }

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
  assertValidCreditAmount(amount);

  const db = admin.firestore();
  const userRef = db.collection(USERS_COLLECTION).doc(userId);
  const txRef = db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .doc(makeCreditTransactionDocId("refund", taskId));

  // Legacy idempotency check OUTSIDE the transaction (query-based reads are
  // not safely isolated inside a Firestore transaction).
  const legacySnap = await db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "refund")
    .limit(1)
    .get();
  if (!legacySnap.empty) {
    const legacyData = legacySnap.docs[0].data();
    console.log(`[CreditService] Legacy refund already exists for task ${taskId}, skipping`);
    return { success: true, remaining: legacyData.balanceAfter ?? 0 };
  }

  let remaining = 0;

  await db.runTransaction(async (tx) => {
    // Primary idempotency: doc-ID based check — safe inside a transaction.
    const existingTx = await tx.get(txRef);
    if (existingTx.exists) {
      console.log(`[CreditService] Refund already exists for task ${taskId}, skipping`);
      remaining = existingTx.data().balanceAfter ?? 0;
      return;
    }

    const userDoc = await tx.get(userRef);
    if (!userDoc.exists) {
      throw new Error("User document not found");
    }

    const userData = userDoc.data();
    const currentBalance = userData.credits ?? 0;
    const newBalance = currentBalance + amount;

    tx.update(userRef, { credits: newBalance });
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
  const linkRef = db.collection(BILLING_LINKS_COLLECTION).doc(makeBillingLinkDocId(realTaskId));
  await linkRef.set({
    userId,
    tempTaskId,
    realTaskId,
    status: "pending",
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });

  const directRef = db.collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .doc(makeCreditTransactionDocId("debit", tempTaskId));
  const directDoc = await directRef.get();
  if (directDoc.exists) {
    try {
      await directRef.update({
        taskId: realTaskId,
        pendingTaskId: tempTaskId,
        linkedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    } catch (err) {
      err.billingLinkMapped = true;
      throw err;
    }
    await markBillingLink(linkRef, {
      status: "linked",
      linkedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`[CreditService] Linked temp ID ${tempTaskId} to real taskId ${realTaskId}`);
    return;
  }

  const snap = await db.collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", tempTaskId)
    .limit(1)
    .get();

  if (snap.empty) {
    await markBillingLink(linkRef, {
      status: "missing_debit",
      error: "debit_not_found",
    });
    const err = new Error(`No debit transaction found with temp ID ${tempTaskId} for user ${userId}`);
    err.billingLinkMapped = true;
    throw err;
  }

  try {
    await snap.docs[0].ref.update({
      taskId: realTaskId,
      pendingTaskId: tempTaskId,
      linkedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (err) {
    err.billingLinkMapped = true;
    throw err;
  }
  await markBillingLink(linkRef, {
    status: "linked",
    linkedAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  console.log(`[CreditService] Linked temp ID ${tempTaskId} to real taskId ${realTaskId}`);
}

async function getDebitTransactionForUserTask(db, userId, taskId) {
  const snap = await db
    .collection(CREDIT_HISTORY_COLLECTION)
    .doc(userId)
    .collection("transactions")
    .where("taskId", "==", taskId)
    .where("type", "==", "debit")
    .limit(1)
    .get();

  if (snap.empty) return null;
  const doc = snap.docs[0];
  return { doc, data: doc.data(), userId };
}

export async function findDebitTransactionForTask(taskId, userId = null) {
  const db = admin.firestore();

  if (userId) {
    const userDebit = await getDebitTransactionForUserTask(db, userId, taskId);
    if (userDebit) return { ...userDebit, refundTaskId: taskId };
  } else {
    const snap = await db.collectionGroup("transactions")
      .where("taskId", "==", taskId)
      .where("type", "==", "debit")
      .limit(1)
      .get();

    if (!snap.empty) {
      const doc = snap.docs[0];
      return {
        doc,
        data: doc.data(),
        userId: doc.ref.parent.parent.id,
        refundTaskId: taskId,
      };
    }
  }

  const linkDoc = await db.collection(BILLING_LINKS_COLLECTION).doc(makeBillingLinkDocId(taskId)).get();
  if (!linkDoc.exists) return null;

  const link = linkDoc.data();
  const linkedUserId = link.userId;
  const tempTaskId = link.tempTaskId;
  if (!linkedUserId || !tempTaskId) return null;
  if (userId && linkedUserId !== userId) return null;

  const pendingDebit = await getDebitTransactionForUserTask(db, linkedUserId, tempTaskId);
  if (!pendingDebit) return null;
  return { ...pendingDebit, refundTaskId: taskId, pendingTaskId: tempTaskId };
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
