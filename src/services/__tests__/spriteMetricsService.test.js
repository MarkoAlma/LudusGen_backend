import assert from "node:assert/strict";

import {
  createSpriteMetricsStore,
  getProviderHealthSnapshot,
  recordSpriteProviderMetric,
} from "../spriteMetricsService.js";

console.log("\nScenario 1: provider metrics calculate success rate and average duration");
{
  const store = createSpriteMetricsStore();

  recordSpriteProviderMetric(store, { provider: "pixellab", ok: true, elapsedMs: 1000 });
  recordSpriteProviderMetric(store, { provider: "pixellab", ok: false, elapsedMs: 3000 });

  const snapshot = getProviderHealthSnapshot(store, {
    env: { PIXELLAB_API_KEY: "x" },
    now: 10_000,
  });

  assert.equal(snapshot.providers.pixellab.configured, true);
  assert.equal(snapshot.providers.pixellab.requests, 2);
  assert.equal(snapshot.providers.pixellab.successRate, 0.5);
  assert.equal(snapshot.providers.pixellab.avgGenerationMs, 2000);
  assert.equal(snapshot.providers.godmode.configured, false);
}

console.log("spriteMetricsService assertions passed");
