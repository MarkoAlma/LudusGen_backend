import assert from "node:assert/strict";

import {
  createSpriteCircuitStore,
  getOpenSpriteProviders,
  isSpriteProviderCircuitOpen,
  recordSpriteCircuitFailure,
  recordSpriteCircuitSuccess,
} from "../spriteCircuitBreaker.js";

console.log("\nScenario 1: provider circuit opens after threshold failures");
{
  const store = createSpriteCircuitStore();
  const now = 1_000;

  recordSpriteCircuitFailure(store, "pixellab", { now, threshold: 3, cooldownMs: 300_000 });
  recordSpriteCircuitFailure(store, "pixellab", { now: now + 1, threshold: 3, cooldownMs: 300_000 });
  assert.equal(isSpriteProviderCircuitOpen(store, "pixellab", { now: now + 2 }), false);

  recordSpriteCircuitFailure(store, "pixellab", { now: now + 3, threshold: 3, cooldownMs: 300_000 });
  assert.equal(isSpriteProviderCircuitOpen(store, "pixellab", { now: now + 4 }), true);
  assert.deepEqual(getOpenSpriteProviders(store, { now: now + 5 }), ["pixellab"]);
}

console.log("\nScenario 2: circuit closes after cooldown or success");
{
  const store = createSpriteCircuitStore();
  recordSpriteCircuitFailure(store, "segmind", { now: 10, threshold: 1, cooldownMs: 100 });

  assert.equal(isSpriteProviderCircuitOpen(store, "segmind", { now: 50 }), true);
  assert.equal(isSpriteProviderCircuitOpen(store, "segmind", { now: 111 }), false);

  recordSpriteCircuitFailure(store, "godmode", { now: 200, threshold: 1, cooldownMs: 1000 });
  assert.equal(isSpriteProviderCircuitOpen(store, "godmode", { now: 250 }), true);
  recordSpriteCircuitSuccess(store, "godmode");
  assert.equal(isSpriteProviderCircuitOpen(store, "godmode", { now: 260 }), false);
}

console.log("spriteCircuitBreaker assertions passed");
