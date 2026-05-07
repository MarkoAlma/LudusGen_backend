import assert from "node:assert/strict";

import {
  getSpriteCapabilities,
  getSpriteOperation,
  providerSupportsSpriteOperation,
  resolveSpriteCapabilityRoute,
} from "../spriteCapabilities.js";

console.log("\nScenario 1: provider capabilities expose the production 2D surface");
{
  const capabilities = getSpriteCapabilities();

  assert(capabilities.providers.pixellab.operations.includes("rotation_8"));
  assert(capabilities.providers.pixellab.operations.includes("skeleton_animation"));
  assert(capabilities.providers.godmode.operations.includes("spine_export"));
  assert(capabilities.providers.godmode.operations.includes("retarget_animation"));
  assert(capabilities.providers.segmind.operations.includes("flux_image"));
  assert(capabilities.providers.segmind.operations.includes("batch_generation"));
}

console.log("\nScenario 2: operation inference chooses provider-only feature owners");
{
  assert.equal(getSpriteOperation({ options: { output: "spine" } }), "spine_export");
  assert.equal(getSpriteOperation({ options: { output: "layered" } }), "layered_export");
  assert.equal(getSpriteOperation({ options: { output: "retarget" } }), "retarget_animation");
  assert.equal(getSpriteOperation({ options: { output: "animation_skeleton" } }), "skeleton_animation");
  assert.equal(getSpriteOperation({ options: { output: "rotation", directionSet: "8-way" } }), "rotation_8");
  assert.equal(getSpriteOperation({ options: { model: "flux-schnell" } }), "flux_image");
}

console.log("\nScenario 3: unsupported manual providers are capability-routed safely");
{
  assert.equal(providerSupportsSpriteOperation("pixellab", "spine_export"), false);

  const rerouted = resolveSpriteCapabilityRoute(
    { provider: "pixellab", strategy: "manual", reason: "manual" },
    { provider: "pixellab", options: { output: "spine" } },
  );

  assert.equal(rerouted.provider, "godmode");
  assert.equal(rerouted.strategy, "capability");
  assert.equal(rerouted.operation, "spine_export");
  assert(rerouted.reason.includes("spine_export"));
}

console.log("spriteCapabilities assertions passed");
