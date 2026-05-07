import assert from "node:assert/strict";

import {
  buildSegmindDirectPayload,
  buildGodModeSpriteRequest,
  buildPixellabSpriteRequest,
  buildSegmindWorkflowPayload,
  generatePixellabSprite,
} from "../spriteProviderAdapters.js";

console.log("\nScenario 1: PixelLab static sprite requests use pixflux");
{
  const request = buildPixellabSpriteRequest({
    prompt: "tiny retro chest",
    style: "pixel art",
    referenceImage: "data:image/png;base64,abc123",
    options: {
      output: "sprite",
      imageSize: { width: 128, height: 64 },
      noBackground: true,
    },
  });

  assert.equal(request.path, "/generate-image-pixflux");
  assert.equal(request.body.description, "tiny retro chest, style: pixel art");
  assert.deepEqual(request.body.image_size, { width: 128, height: 64 });
  assert.deepEqual(request.body.init_image, { type: "base64", base64: "abc123" });
  assert.equal(request.body.no_background, true);
}

console.log("\nScenario 2: PixelLab animation requests use animate-with-text when a reference image exists");
{
  const request = buildPixellabSpriteRequest({
    prompt: "knight walk cycle",
    style: "",
    referenceImage: "abc123",
    options: {
      output: "animation",
      action: "walk",
      imageSize: { width: 128, height: 128 },
    },
  });

  assert.equal(request.path, "/animate-with-text");
  assert.equal(request.body.description, "knight walk cycle");
  assert.equal(request.body.action, "walk");
  assert.deepEqual(request.body.image_size, { width: 128, height: 128 });
  assert.deepEqual(request.body.reference_image, { type: "base64", base64: "abc123" });
}

console.log("\nScenario 3: God Mode payload keeps animation intent and reference image");
{
  const request = buildGodModeSpriteRequest({
    prompt: "smooth ninja",
    style: "spine",
    referenceImage: "data:image/webp;base64,zzz",
    options: {
      output: "spine",
      action: "run",
      directionSet: "8-way",
      noBackground: true,
    },
  });

  assert.equal(request.path, "/v1/sprite/generate");
  assert.equal(request.body.prompt, "smooth ninja");
  assert.equal(request.body.style, "spine");
  assert.equal(request.body.output, "spine");
  assert.equal(request.body.animation, "run");
  assert.equal(request.body.directionSet, "8-way");
  assert.equal(request.body.referenceImage, "zzz");
}

console.log("\nScenario 4: Segmind workflow payload preserves legacy input shape");
{
  const payload = buildSegmindWorkflowPayload({
    prompt: "anime fantasy archer",
    referenceImage: "data:image/jpeg;base64,ref456",
  });

  assert.deepEqual(payload, {
    Animation_Scene: "anime fantasy archer",
    image: "ref456",
  });
}

console.log("\nScenario 5: PixelLab rotation requests target the rotate endpoint");
{
  const request = buildPixellabSpriteRequest({
    prompt: "turn the knight",
    style: "pixel art",
    referenceImage: "data:image/png;base64,ref123",
    options: {
      output: "rotation",
      directionSet: "8-way",
      imageSize: { width: 128, height: 128 },
      fromDirection: "south",
      toDirection: "east",
      fromView: "side",
      toView: "side",
      seed: 42,
    },
  });

  assert.equal(request.path, "/rotate");
  assert.equal(request.body.from_direction, "south");
  assert.equal(request.body.to_direction, "east");
  assert.equal(request.body.from_view, "side");
  assert.equal(request.body.to_view, "side");
  assert.deepEqual(request.body.from_image, { type: "base64", base64: "ref123" });
}

console.log("\nScenario 6: PixelLab skeleton animation requests include keypoints");
{
  const request = buildPixellabSpriteRequest({
    prompt: "skeleton attack",
    referenceImage: "data:image/png;base64,ref123",
    options: {
      output: "animation_skeleton",
      imageSize: { width: 64, height: 64 },
      direction: "south",
      skeletonKeypoints: [{ name: "head", x: 12, y: 8 }],
    },
  });

  assert.equal(request.path, "/animate-with-skeleton");
  assert.deepEqual(request.body.reference_image, { type: "base64", base64: "ref123" });
  assert.deepEqual(request.body.skeleton_keypoints, [{ name: "head", x: 12, y: 8 }]);
}

console.log("\nScenario 7: God Mode payload exposes rigging, layered, and retarget fields");
{
  const request = buildGodModeSpriteRequest({
    prompt: "smooth rogue",
    style: "modern",
    referenceImage: "data:image/png;base64,abc",
    options: {
      output: "retarget",
      action: "slash combo",
      animationPreset: "run_forward",
      retargetAnimationId: "anim_123",
      exportFormats: ["spine", "layers"],
      directionSet: "none",
      noBackground: true,
      imageSize: { width: 128, height: 128 },
    },
  });

  assert.equal(request.body.mode, "retarget");
  assert.equal(request.body.autoRig, true);
  assert.equal(request.body.layeredExport, true);
  assert.equal(request.body.retargetAnimationId, "anim_123");
  assert.deepEqual(request.body.exportFormats, ["spine", "layers"]);
}

console.log("\nScenario 8: Segmind direct payload supports FLUX/SDXL style batching");
{
  const payload = buildSegmindDirectPayload({
    prompt: "anime fantasy mage",
    style: "illustrated",
    options: {
      model: "flux-schnell",
      imageSize: { width: 768, height: 768 },
      batchCount: 3,
      steps: 6,
      seed: 123,
    },
  });

  assert.equal(payload.prompt, "anime fantasy mage, style: illustrated");
  assert.equal(payload.width, 768);
  assert.equal(payload.height, 768);
  assert.equal(payload.samples, 3);
  assert.equal(payload.steps, 6);
  assert.equal(payload.seed, 123);
}

console.log("\nScenario 9: PixelLab 8-way rotation aggregates usage across every provider call");
{
  const request = {
    prompt: "rotate the knight",
    style: "pixel art",
    referenceImage: "data:image/png;base64,ref123",
    options: {
      output: "rotation",
      directionSet: "8-way",
      imageSize: { width: 64, height: 64 },
      fromDirection: "south",
      fromView: "side",
      toView: "side",
    },
  };

  const calls = [];
  const result = await generatePixellabSprite(request, {
    env: { PIXELLAB_API_KEY: "secret" },
    axiosClient: {
      post: async (_url, payload) => {
        calls.push(payload.to_direction);
        return {
          data: {
            image: `https://example.com/${payload.to_direction}.png`,
            usage: { usd: 0.09 },
          },
        };
      },
    },
  });

  assert.equal(calls.length, 8);
  assert.equal(result.images.length, 8);
  assert.equal(result.usage.usd, 0.72);
  assert.equal(result.usage.operationCount, 8);
}

console.log("\nScenario 10: PixelLab fallback billing still knows how many rotate calls ran when usage is absent");
{
  const result = await generatePixellabSprite({
    prompt: "rotate the slime",
    style: "pixel art",
    referenceImage: "data:image/png;base64,ref123",
    options: {
      output: "rotation",
      directionSet: "4-way",
      imageSize: { width: 64, height: 64 },
      fromDirection: "south",
      fromView: "side",
      toView: "side",
    },
  }, {
    env: { PIXELLAB_API_KEY: "secret" },
    axiosClient: {
      post: async (_url, payload) => ({
        data: {
          image: `https://example.com/${payload.to_direction}.png`,
        },
      }),
    },
  });

  assert.equal(result.images.length, 4);
  assert.equal(result.usage.operationCount, 4);
}

console.log("spriteProviderAdapters assertions passed");
