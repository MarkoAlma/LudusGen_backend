import assert from "node:assert/strict";

import {
  executeProviderWithRetry,
  getSpriteFallbackChain,
  runSpriteGenerationWithFallback,
} from "../spriteExecutionService.js";

console.log("\nScenario 1: fallback chain starts with routed provider and follows canonical order");
{
  assert.deepEqual(getSpriteFallbackChain("pixellab"), ["pixellab", "godmode", "segmind"]);
  assert.deepEqual(getSpriteFallbackChain("godmode"), ["godmode", "segmind"]);
  assert.deepEqual(getSpriteFallbackChain("segmind"), ["segmind"]);
}

console.log("\nScenario 2: provider retry uses exponential delays and succeeds on third attempt");
{
  const delays = [];
  let attempts = 0;
  const result = await executeProviderWithRetry({
    provider: "pixellab",
    maxAttempts: 3,
    baseDelayMs: 10,
    sleep: async (ms) => { delays.push(ms); },
    logger: () => {},
    callProvider: async () => {
      attempts += 1;
      if (attempts < 3) throw Object.assign(new Error("temporary"), { code: "E_TEMP" });
      return { provider: "pixellab", images: ["data:image/png;base64,ok"] };
    },
  });

  assert.equal(result.provider, "pixellab");
  assert.equal(attempts, 3);
  assert.deepEqual(delays, [10, 20]);
}

console.log("\nScenario 3: fallback switches after three failed provider attempts");
{
  const seen = [];
  const result = await runSpriteGenerationWithFallback({
    initialProvider: "pixellab",
    request: { prompt: "pixel hero" },
    maxAttempts: 3,
    sleep: async () => {},
    callProvider: async (provider) => {
      seen.push(provider);
      if (provider === "pixellab") throw Object.assign(new Error("down"), { code: "DOWN" });
      return { provider, images: ["data:image/png;base64,ok"] };
    },
    logger: () => {},
  });

  assert.equal(result.provider, "godmode");
  assert.deepEqual(seen, ["pixellab", "pixellab", "pixellab", "godmode"]);
  assert.equal(result.failures.length, 3);
}

console.log("\nScenario 4: fallback skips providers with open circuits");
{
  const seen = [];
  const result = await runSpriteGenerationWithFallback({
    initialProvider: "pixellab",
    openProviders: ["pixellab"],
    request: { prompt: "pixel hero" },
    maxAttempts: 3,
    sleep: async () => {},
    callProvider: async (provider) => {
      seen.push(provider);
      return { provider, images: ["data:image/png;base64,ok"] };
    },
    logger: () => {},
  });

  assert.equal(result.provider, "godmode");
  assert.deepEqual(seen, ["godmode"]);
}

console.log("spriteExecutionService assertions passed");
