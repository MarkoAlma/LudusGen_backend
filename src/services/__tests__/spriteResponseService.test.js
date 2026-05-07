import assert from "node:assert/strict";

import { finalizeSpriteSuccessResponse } from "../spriteResponseService.js";

console.log("\nScenario 1: cache and usage logging failures do not block a successful billed sprite response");
{
  const order = [];
  const warnings = [];
  const responsePayload = {
    success: true,
    billing: {
      creditAmount: 15,
      usdCost: 0.09,
      reservedCreditAmount: 20,
      adjustmentCreditAmount: -5,
    },
  };

  const result = await finalizeSpriteSuccessResponse({
    responsePayload,
    cacheWriter: async () => {
      order.push("cache");
      throw new Error("cache unavailable");
    },
    usageLogger: async () => {
      order.push("usage");
      throw new Error("usage log unavailable");
    },
    chargeGeneration: async () => {
      order.push("charge");
      return responsePayload.billing;
    },
    logger: {
      warn: (message) => warnings.push(message),
    },
  });

  assert.equal(result.responsePayload, responsePayload);
  assert.equal(result.billing.creditAmount, 15);
  assert.deepEqual(order, ["cache", "usage", "charge"]);
  assert.equal(warnings.length, 2);
}

console.log("\nScenario 2: billing failures still surface to the caller after best-effort persistence");
{
  const order = [];
  await assert.rejects(
    finalizeSpriteSuccessResponse({
      responsePayload: { success: true, billing: { creditAmount: 38 } },
      cacheWriter: async () => {
        order.push("cache");
      },
      usageLogger: async () => {
        order.push("usage");
      },
      chargeGeneration: async () => {
        order.push("charge");
        throw Object.assign(new Error("billing unavailable"), { code: "BILLING_DOWN" });
      },
      logger: console,
    }),
    /billing unavailable/,
  );
  assert.deepEqual(order, ["cache", "usage", "charge"]);
}

console.log("spriteResponseService assertions passed");
