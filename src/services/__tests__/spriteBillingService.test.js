import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  CREDIT_USD_VALUE,
  calculateSpriteCreditCharge,
  chargeSpriteGeneration,
  reserveSpriteCredits,
  settleSpriteCreditReservation,
  makeSpriteAuditPayload,
  normalizeProviderCostUsd,
} from "../spriteBillingService.js";

console.log("\nScenario 1: credit conversion uses the lowest live topup value and preserves 20 percent margin");
{
  assert.equal(CREDIT_USD_VALUE, 39.99 / 5000);
  assert.equal(calculateSpriteCreditCharge(1), 157);
  assert.equal(calculateSpriteCreditCharge(0.09), 15);
  assert.equal(calculateSpriteCreditCharge(0.24), 38);
}

console.log("\nScenario 2: provider cost normalization uses usage usd first and multiplies flat fallbacks by operation count");
{
  assert.equal(normalizeProviderCostUsd({ usage: { usd: 0.24 }, provider: "pixellab" }), 0.24);
  assert.equal(normalizeProviderCostUsd({ usage: null, provider: "segmind", env: { SEGMIND_SPRITE_COST_USD: "0.33" } }), 0.33);
  assert.equal(normalizeProviderCostUsd({ usage: null, provider: "pixellab", env: { PIXELLAB_SPRITE_COST_USD: "0" } }), 0);
  assert.equal(normalizeProviderCostUsd({ usage: null, provider: "pixellab", env: {} }), 0.09);
  assert.equal(normalizeProviderCostUsd({ usage: { operationCount: 8 }, provider: "pixellab", env: {} }), 0.72);
  assert.equal(normalizeProviderCostUsd({ usage: { operationCount: 4 }, provider: "godmode", env: { GODMODE_SPRITE_COST_USD: "0.5" } }), 2);
  assert.equal(normalizeProviderCostUsd({ usage: null, provider: "segmind", env: {} }), 0.24);
  assert.equal(normalizeProviderCostUsd({ usage: null, provider: "godmode", env: {} }), 0.40);
}

console.log("\nScenario 3: audit payload contains hashes and accounting fields but not raw prompt");
{
  const payload = makeSpriteAuditPayload({
    userId: "user_1",
    requestId: "req_1",
    provider: "pixellab",
    prompt: "secret prompt text",
    creditAmount: 13,
    usdCost: 0.12,
    cacheHit: false,
  });

  assert.equal(payload.user_id, "user_1");
  assert.equal(payload.provider, "pixellab");
  assert.equal(payload.credit_amount, 13);
  assert.equal(payload.usd_cost, 0.12);
  assert.equal(payload.request_id, "req_1");
  assert.equal(payload.cache_hit, false);
  assert.match(payload.prompt_hash, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(payload).includes("secret prompt text"), false);
}

console.log("\nScenario 4: reservation settlement refunds over-reserved credits");
{
  const calls = [];
  const reservation = await reserveSpriteCredits({
    userId: "user_1",
    requestId: "req_1",
    provider: "segmind",
    estimatedCreditAmount: 18,
  }, {
    deduct: async (userId, amount, taskId, taskType) => {
      calls.push({ type: "deduct", userId, amount, taskId, taskType });
      return { success: true, remaining: 82 };
    },
  });

  await settleSpriteCreditReservation({
    reservation,
    actualCreditAmount: 12,
    provider: "segmind",
  }, {
    deduct: async (userId, amount, taskId, taskType) => {
      calls.push({ type: "deduct", userId, amount, taskId, taskType });
      return { success: true, remaining: 0 };
    },
    refund: async (userId, amount, taskId, reason) => {
      calls.push({ type: "refund", userId, amount, taskId, reason });
      return { success: true, remaining: 88 };
    },
  });

  assert.deepEqual(calls, [
    {
      type: "deduct",
      userId: "user_1",
      amount: 18,
      taskId: "sprite_pending_req_1",
      taskType: "sprite:segmind:reservation",
    },
    {
      type: "refund",
      userId: "user_1",
      amount: 6,
      taskId: "sprite_pending_req_1_settlement",
      reason: "sprite_over_reserved",
    },
  ]);
  assert.equal(reservation.creditsDeducted, true);
  assert.equal(reservation.settled, true);
}

console.log("\nScenario 5: legacy sprite-sheet endpoint delegates to billed sprite generation");
{
  const source = readFileSync(resolve(process.cwd(), "ai-routes.js"), "utf8");
  assert(
    source.includes("router.post('/sprite-sheet'") &&
      source.includes("handleSpriteGenerate(req, res, { legacyProvider: 'segmind' })"),
    "legacy /sprite-sheet route should not bypass sprite credit billing",
  );
}

console.log("\nScenario 6: audit log failures do not convert a successful billed sprite into an API error");
{
  const calls = [];
  const reservation = await reserveSpriteCredits({
    userId: "user_99",
    requestId: "req_audit",
    provider: "pixellab",
    estimatedCreditAmount: 20,
  }, {
    deduct: async (userId, amount, taskId, taskType) => {
      calls.push({ type: "deduct", userId, amount, taskId, taskType });
      return { success: true, remaining: 80 };
    },
  });

  const result = await chargeSpriteGeneration({
    userId: "user_99",
    requestId: "req_audit",
    provider: "pixellab",
    prompt: "audit me",
    providerCostUsd: 0.09,
    reservation,
  }, {
    deduct: async (userId, amount, taskId, taskType) => {
      calls.push({ type: "deduct", userId, amount, taskId, taskType });
      return { success: true, remaining: 65 };
    },
    refund: async (userId, amount, taskId, reason) => {
      calls.push({ type: "refund", userId, amount, taskId, reason });
      return { success: true, remaining: 85 };
    },
    writeAuditLog: async () => {
      throw new Error("firestore unavailable");
    },
  });

  assert.equal(result.creditAmount, 15);
  assert.equal(result.auditLogError, "firestore unavailable");
  assert.equal(reservation.settled, true);
  assert.deepEqual(calls, [
    {
      type: "deduct",
      userId: "user_99",
      amount: 20,
      taskId: "sprite_pending_req_audit",
      taskType: "sprite:pixellab:reservation",
    },
    {
      type: "refund",
      userId: "user_99",
      amount: 5,
      taskId: "sprite_pending_req_audit_settlement",
      reason: "sprite_over_reserved",
    },
  ]);
}

console.log("spriteBillingService assertions passed");
