import crypto from "node:crypto";
import admin from "firebase-admin";

import { hashSpritePrompt } from "../lib/spriteSecurity.js";

export const SPRITE_JOBS_COLLECTION = "sprite_jobs";
export const SPRITE_JOB_STATUSES = ["queued", "running", "completed", "failed"];

function safeTimestampMs(value = Date.now()) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : Date.now();
}

function hashReferenceImage(referenceImage) {
  if (!referenceImage) return null;
  return crypto.createHash("sha256").update(String(referenceImage), "utf8").digest("hex");
}

function sanitizeRequestOptions(options) {
  if (!options || typeof options !== "object") return {};
  return JSON.parse(JSON.stringify(options));
}

function sanitizeBillingReservation(reservation) {
  if (!reservation || typeof reservation !== "object") return null;
  return {
    userId: reservation.userId || null,
    requestId: reservation.requestId || null,
    provider: reservation.provider || null,
    amount: Math.max(0, Number(reservation.amount) || 0),
    tempTxId: reservation.tempTxId || null,
    creditsDeducted: Boolean(reservation.creditsDeducted),
    settled: Boolean(reservation.settled),
  };
}

function normalizeJobStatus(status) {
  if (!SPRITE_JOB_STATUSES.includes(status)) {
    throw new Error(`Invalid sprite job status: ${status}`);
  }
  return status;
}

export function createSpriteJobRecord({
  jobId,
  userId,
  requestId,
  request,
  route = null,
  estimatedCredits = 0,
  creditReservation = null,
  now = Date.now(),
} = {}) {
  if (!jobId) throw new Error("jobId is required");
  if (!userId) throw new Error("userId is required");
  if (!requestId) throw new Error("requestId is required");
  if (!request?.prompt) throw new Error("request.prompt is required");

  const timestampMs = safeTimestampMs(now);

  return {
    id: String(jobId),
    userId: String(userId),
    requestId: String(requestId),
    status: "queued",
    provider: route?.provider || request.provider || null,
    route: route ? JSON.parse(JSON.stringify(route)) : null,
    estimatedCredits: Math.max(0, Number(estimatedCredits) || 0),
    billingReservation: sanitizeBillingReservation(creditReservation),
    request: {
      provider: request.provider || null,
      style: String(request.style || ""),
      options: sanitizeRequestOptions(request.options),
      promptHash: hashSpritePrompt(request.prompt),
      referenceImageHash: hashReferenceImage(request.referenceImage),
    },
    createdAtMs: timestampMs,
    updatedAtMs: timestampMs,
  };
}

export function transitionSpriteJob(job, patch = {}) {
  if (!job?.id) throw new Error("job is required");
  const nextStatus = patch.status ? normalizeJobStatus(patch.status) : job.status;
  const updatedAtMs = safeTimestampMs(patch.now);

  return {
    ...job,
    status: nextStatus,
    provider: patch.provider ?? job.provider ?? null,
    response: patch.response ?? job.response,
    billing: patch.billing ?? job.billing,
    error: patch.error ?? job.error,
    updatedAtMs,
  };
}

export function sanitizeSpriteJobForClient(job) {
  if (!job) return null;
  return {
    jobId: job.id,
    requestId: job.requestId,
    status: job.status,
    provider: job.provider || null,
    route: job.route || null,
    estimatedCredits: job.estimatedCredits || 0,
    response: job.response || null,
    billing: job.billing || null,
    error: job.error || null,
    createdAtMs: job.createdAtMs || null,
    updatedAtMs: job.updatedAtMs || null,
  };
}

function stripUndefined(value) {
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}

export async function saveSpriteJobRecord(job, { db = admin.firestore() } = {}) {
  const payload = stripUndefined({
    ...job,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  await db.collection(SPRITE_JOBS_COLLECTION).doc(job.id).set(payload, { merge: false });
  return job;
}

export async function updateSpriteJobRecord(job, patch = {}, { db = admin.firestore() } = {}) {
  const next = transitionSpriteJob(job, patch);
  await db.collection(SPRITE_JOBS_COLLECTION).doc(next.id).set(stripUndefined({
    ...next,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  }), { merge: true });
  return next;
}

export async function getSpriteJobRecord({ jobId, userId, db = admin.firestore() } = {}) {
  if (!jobId) throw new Error("jobId is required");
  const snap = await db.collection(SPRITE_JOBS_COLLECTION).doc(String(jobId)).get();
  if (!snap.exists) return null;
  const data = { id: snap.id, ...snap.data() };
  if (userId && data.userId !== userId) return null;
  return data;
}
