// src/lib/__tests__/creditEstimator.test.js
//
// Billing-break scenario tests for the credit estimator.
// Run: node src/lib/__tests__/creditEstimator.test.js
//
// These tests verify that the estimator does NOT overcharge for addons
// that get stripped by taskService.validate() before reaching the Tripo API.

import { estimateCost } from "../creditEstimator.js";

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    passed++;
  } else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 1: P1 + text_to_model + texture_quality="detailed"
//
// BEFORE FIX: Estimator charged base(30) + texture_std(10) + HD_upgrade(10) = 50
// AFTER FIX:  Estimator charges base(30) + texture_std(10) = 40
// Why: P1 strips texture_quality="detailed" → only standard texture reaches API
// ─────────────────────────────────────────────────────────────────────────────
{
  const result = estimateCost({
    type: "text_to_model",
    model_version: "P1-20260311",
    prompt: "a cat",
    texture: true,
    texture_quality: "detailed",
  });
  assert(result.total === 40, `Total should be 40 (base 30 + std texture 10), got ${result.total}`);
  assert(result.breakdown.texture === 10, `Texture addon should be 10 (standard only), got ${result.breakdown.texture}`);
  assert(!result.breakdown.geometry_detailed, "Should NOT have geometry_detailed addon");
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 2: P1 + text_to_model + geometry_quality="detailed" + smart_low_poly
//
// BEFORE FIX: Estimator charged base(30) + ultra(20) + slp(10) = 60
// AFTER FIX:  Estimator charges base(30) = 30
// Why: P1 strips both geometry_quality and smart_low_poly
// ─────────────────────────────────────────────────────────────────────────────
{
  const result = estimateCost({
    type: "text_to_model",
    model_version: "P1-20260311",
    prompt: "a cat",
    geometry_quality: "detailed",
    smart_low_poly: true,
  });
  assert(result.total === 30, `Total should be 30 (base only), got ${result.total}`);
  assert(!result.breakdown.geometry_detailed, "Should NOT have geometry_detailed addon for P1");
  assert(!result.breakdown.smart_low_poly, "Should NOT have smart_low_poly addon for P1");
}

// ─────────────────────────────────────────────────────────────────────────────
// Scenario 3: P1 + text_to_model + generate_parts + quad + detailed texture
//
// BEFORE FIX: Estimator charged base(30) + parts(20) + quad(5) + tex_std(10) + HD(10) = 75
// AFTER FIX:  Estimator charges base(30) + tex_std(10) = 40
// Why: P1 strips generate_parts, quad, and texture_quality="detailed"
// ─────────────────────────────────────────────────────────────────────────────
{
  const result = estimateCost({
    type: "text_to_model",
    model_version: "P1-20260311",
    prompt: "a cat",
    generate_parts: true,
    quad: true,
    texture: true,
    texture_quality: "detailed",
  });
  assert(result.total === 40, `Total should be 40 (base 30 + std texture 10), got ${result.total}`);
  assert(!result.breakdown.generate_parts, "Should NOT have generate_parts addon for P1");
  assert(!result.breakdown.quad, "Should NOT have quad addon for P1");
  assert(result.breakdown.texture === 10, `Texture addon should be 10 (standard only), got ${result.breakdown.texture}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanity: v3.1 should STILL charge for all addons (not P1)
// ─────────────────────────────────────────────────────────────────────────────
{
  const result = estimateCost({
    type: "text_to_model",
    model_version: "v3.1-20260211",
    prompt: "a cat",
    texture: true,
    texture_quality: "detailed",
    geometry_quality: "detailed",
    smart_low_poly: true,
    generate_parts: true,
    quad: true,
  });
  // base(10) + tex_std(10) + HD(10) + ultra(20) + slp(10) + parts(20) + quad(5) = 85
  assert(result.total === 85, `Total should be 85, got ${result.total}`);
  assert(result.breakdown.geometry_detailed === 20, "Should have geometry_detailed addon for v3.1");
  assert(result.breakdown.smart_low_poly === 10, "Should have smart_low_poly addon for v3.1");
  assert(result.breakdown.generate_parts === 20, "Should have generate_parts addon for v3.1");
  assert(result.breakdown.quad === 5, "Should have quad addon for v3.1");
}

// ─────────────────────────────────────────────────────────────────────────────
// Sanity: P1 with standard texture (no overcharge scenario)
// ─────────────────────────────────────────────────────────────────────────────
{
  const result = estimateCost({
    type: "text_to_model",
    model_version: "P1-20260311",
    prompt: "a cat",
    texture: true,
    texture_quality: "standard",
  });
  assert(result.total === 40, `Total should be 40 (base 30 + std texture 10), got ${result.total}`);
  assert(result.breakdown.texture === 10, `Texture addon should be 10, got ${result.breakdown.texture}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
{
  const result = estimateCost({
    type: "image_to_model",
    model_version: "v3.1-20260211",
    images: [
      { type: "png", file_token: "one" },
      { type: "png", file_token: "two" },
      { type: "png", file_token: "three" },
    ],
    texture: false,
    pbr: false,
  });

  assert(result.total === 60, `Total should be 60 (20 x 3 images), got ${result.total}`);
  assert(
    result.breakdown.batch_multiplier === "x3",
    `Batch multiplier should be x3, got ${result.breakdown.batch_multiplier}`,
  );
}

{
  const premium = estimateCost({
    type: "generate_image",
    model_version: "gpt_image_1.5",
    prompt: "hero warrior",
  });
  const standard = estimateCost({
    type: "generate_image",
    model_version: "gemini_2.5_flash_image_preview",
    prompt: "hero warrior",
  });
  const defaultModel = estimateCost({
    type: "generate_image",
    prompt: "hero warrior",
  });

  assert(premium.total === 10, `GPT Image 1.5 should cost 10 credits, got ${premium.total}`);
  assert(standard.total === 5, `Gemini 2.5 Flash Image should cost 5 credits, got ${standard.total}`);
  assert(defaultModel.total === 5, `Default generate_image should cost 5 credits, got ${defaultModel.total}`);
}

{
  const result = estimateCost({
    type: "edit_multiview_image",
    original_task_id: "task-123",
    prompts: [
      { prompt: "add a helmet", view: "front" },
      { prompt: "make side sharper", view: "left" },
    ],
  });

  assert(result.total === 10, `Two edited images should cost 10 credits, got ${result.total}`);
}

console.log("\nScenario: texture_model detailed quality charges HD texture and style reference");
{
  const result = estimateCost({
    type: "texture_model",
    original_model_task_id: "task-123",
    texture_quality: "detailed",
    style_reference: true,
  });

  assert(result.total === 25, `Detailed texture with style reference should cost 25 credits, got ${result.total}`);
  assert(result.breakdown.base === 20, `Detailed texture base should be 20, got ${result.breakdown.base}`);
  assert(result.breakdown.style_reference === 5, `Style reference addon should be 5, got ${result.breakdown.style_reference}`);
}

console.log("\nScenario: animate_retarget charges per requested animation");
{
  const result = estimateCost({
    type: "animate_retarget",
    original_model_task_id: "task-123",
    animations: ["walk", "run"],
  });

  assert(result.total === 20, `Two retarget animations should cost 20 credits, got ${result.total}`);
  assert(result.breakdown.animate_retarget === 20, `Retarget breakdown should be 20, got ${result.breakdown.animate_retarget}`);
}

console.log(`\n${"=".repeat(60)}`);
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
  console.error("BILLING TESTS FAILED");
  process.exit(1);
} else {
}
