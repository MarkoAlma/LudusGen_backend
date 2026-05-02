// src/lib/jobRegistry.js
import { Router } from 'express';

export const activeJobs = new Map();

/**
 * Registers a new active job with an AbortController and a timeout.
 * @param {string} jobId Unique identifier for the job
 * @param {string} userId Owner user ID for authorization
 * @param {AbortController} controller AbortController to signal cancellation
 * @param {number} timeoutMs Timeout in milliseconds (default 10 minutes)
 */
export function registerJob(jobId, userId, controller, timeoutMs = 600000) {
    if (!jobId) return;

    if (userId && typeof userId === 'object' && typeof userId.abort === 'function') {
        timeoutMs = typeof controller === 'number' ? controller : timeoutMs;
        controller = userId;
        userId = null;
    }

    const existingJob = activeJobs.get(jobId);
    if (existingJob?.userId && userId && existingJob.userId !== userId) {
        console.warn(`[JobRegistry] Refusing to replace job ${jobId} owned by a different user.`);
        return;
    }

    // Clear any existing job with the same ID for the same owner (unlikely but safe)
    unregisterJob(jobId);

    const timeoutId = setTimeout(() => {
        console.log(`[Timeout] Job ${jobId} exceeded ${timeoutMs}ms. Aborting.`);
        controller.abort();
        activeJobs.delete(jobId);
    }, timeoutMs);

    activeJobs.set(jobId, { userId: userId || null, controller, timeoutId });
}

/**
 * Removes a job from the registry and clears its timeout.
 * @param {string} jobId Unique identifier for the job
 */
export function unregisterJob(jobId) {
    if (!jobId) return;
    const job = activeJobs.get(jobId);
    if (job) {
        clearTimeout(job.timeoutId);
        activeJobs.delete(jobId);
    }
}
