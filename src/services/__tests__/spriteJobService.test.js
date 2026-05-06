import assert from "node:assert/strict";

import {
  createSpriteJobRecord,
  sanitizeSpriteJobForClient,
  transitionSpriteJob,
} from "../spriteJobService.js";

console.log("\nScenario 1: job records store safe request metadata only");
{
  const job = createSpriteJobRecord({
    jobId: "sprite_job_1",
    userId: "user_1",
    requestId: "req_1",
    request: {
      prompt: "secret prompt",
      referenceImage: "data:image/png;base64,very-secret",
      provider: "pixellab",
      options: { output: "sprite" },
    },
    route: { provider: "pixellab", strategy: "keyword" },
    estimatedCredits: 10,
  });

  assert.equal(job.id, "sprite_job_1");
  assert.equal(job.status, "queued");
  assert.equal(job.userId, "user_1");
  assert.equal(job.request.provider, "pixellab");
  assert.equal(job.request.referenceImageHash.length, 64);
  assert.equal(JSON.stringify(job).includes("very-secret"), false);
}

console.log("\nScenario 2: job transitions preserve terminal billing and response data");
{
  const job = createSpriteJobRecord({
    jobId: "sprite_job_2",
    userId: "user_1",
    requestId: "req_2",
    request: { prompt: "hero", options: {} },
    route: { provider: "segmind" },
    estimatedCredits: 8,
  });

  const running = transitionSpriteJob(job, { status: "running", provider: "segmind" });
  assert.equal(running.status, "running");
  assert.equal(running.provider, "segmind");

  const completed = transitionSpriteJob(running, {
    status: "completed",
    response: { images: ["data:image/png;base64,ok"] },
    billing: { creditAmount: 8, usdCost: 0.07 },
  });

  assert.equal(completed.status, "completed");
  assert.equal(completed.response.images.length, 1);
  assert.equal(completed.billing.creditAmount, 8);
}

console.log("\nScenario 3: client job view never exposes prompt text or internal request payload");
{
  const job = transitionSpriteJob(createSpriteJobRecord({
    jobId: "sprite_job_3",
    userId: "user_1",
    requestId: "req_3",
    request: { prompt: "secret", options: {}, referenceImage: "abc" },
    route: { provider: "segmind" },
    estimatedCredits: 4,
    creditReservation: {
      userId: "user_1",
      requestId: "req_3",
      provider: "segmind",
      amount: 12,
      tempTxId: "sprite_pending_req_3",
      creditsDeducted: true,
    },
  }), {
    status: "failed",
    error: { code: "NO_PROVIDER", message: "Provider failed" },
  });

  const view = sanitizeSpriteJobForClient(job);
  assert.equal(view.jobId, "sprite_job_3");
  assert.equal(view.status, "failed");
  assert.equal(view.error.message, "Provider failed");
  assert.equal(JSON.stringify(view).includes("secret"), false);
  assert.equal(view.request, undefined);
  assert.equal(view.billingReservation, undefined);
}

console.log("spriteJobService assertions passed");
