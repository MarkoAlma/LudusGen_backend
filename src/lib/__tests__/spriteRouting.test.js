import assert from "node:assert/strict";

import {
  SUPPORTED_SPRITE_PROVIDERS,
  classifySpriteRequest,
  normalizeSpriteGenerateRequest,
  normalizeSpriteProviderImages,
  parseSpriteProviderChoice,
} from "../spriteRouting.js";

console.log("\nScenario 1: keyword router selects PixelLab for pixel-art sprite work");
{
  const route = classifySpriteRequest({
    prompt: "Create a 16-bit pixel art knight walk cycle sprite sheet",
  });

  assert.equal(route.provider, "pixellab");
  assert.equal(route.strategy, "keyword");
  assert(route.matchedKeywords.includes("16-bit"));
  assert(route.matchedKeywords.includes("walk cycle"));
}

console.log("\nScenario 2: keyword router selects God Mode AI for Spine rigging");
{
  const route = classifySpriteRequest({
    prompt: "Modern smooth 2D character",
    style: "Spine auto-rig with layered export",
  });

  assert.equal(route.provider, "godmode");
  assert.equal(route.strategy, "keyword");
  assert(route.matchedKeywords.includes("spine"));
  assert(route.matchedKeywords.includes("auto-rig"));
}

console.log("\nScenario 3: keyword router selects Segmind for illustrated anime styles");
{
  const route = classifySpriteRequest({
    prompt: "Anime fantasy rogue, hand-drawn cartoon style",
  });

  assert.equal(route.provider, "segmind");
  assert.equal(route.strategy, "keyword");
  assert(route.matchedKeywords.includes("anime"));
  assert(route.matchedKeywords.includes("fantasy"));
}

console.log("\nScenario 4: explicit provider override is validated and preserved");
{
  const normalized = normalizeSpriteGenerateRequest({
    prompt: "small idle character",
    provider: "pixellab",
    options: {
      imageSize: { width: 1024, height: 8 },
      output: "animation",
      noBackground: false,
    },
  });

  assert.equal(normalized.provider, "pixellab");
  assert.equal(normalized.options.output, "animation");
  assert.deepEqual(normalized.options.imageSize, { width: 400, height: 16 });
  assert.equal(normalized.options.noBackground, false);
}

console.log("\nScenario 5: malformed provider and empty prompts fail early");
{
  assert.throws(
    () => normalizeSpriteGenerateRequest({ prompt: "idle", provider: "unknown" }),
    /Unsupported sprite provider/
  );
  assert.throws(
    () => normalizeSpriteGenerateRequest({ prompt: " ".repeat(2) }),
    /prompt is required/
  );
}

console.log("\nScenario 6: provider image outputs normalize to displayable URLs");
{
  const images = normalizeSpriteProviderImages({
    image: { type: "base64", base64: "abc123" },
    nested: {
      frames: [
        { url: "https://cdn.example.com/a.png" },
        "data:image/webp;base64,zzz",
      ],
    },
  });

  assert.deepEqual(images, [
    "data:image/png;base64,abc123",
    "https://cdn.example.com/a.png",
    "data:image/webp;base64,zzz",
  ]);
}

console.log("\nScenario 7: provider list stays intentionally small and known");
{
  assert.deepEqual(SUPPORTED_SPRITE_PROVIDERS, ["pixellab", "godmode", "segmind"]);
}

console.log("\nScenario 8: Claude fallback parser accepts compact JSON choices");
{
  const parsed = parseSpriteProviderChoice(
    '{"provider":"pixellab","confidence":0.74,"reason":"pixel-art keywords"}',
  );

  assert.equal(parsed.provider, "pixellab");
  assert.equal(parsed.confidence, 0.74);
  assert.equal(parsed.reason, "pixel-art keywords");
  assert.equal(parseSpriteProviderChoice("not json"), null);
  assert.equal(parseSpriteProviderChoice('{"provider":"unknown"}'), null);
}

console.log("\nScenario 9: advanced provider options are normalized and clamped");
{
  const request = normalizeSpriteGenerateRequest({
    prompt: "animated hero",
    options: {
      output: "animation_skeleton",
      frameCount: 15,
      view: "side",
      direction: "south",
      fromDirection: "south",
      toDirection: "north-east",
      model: "flux-schnell",
      batchCount: 12,
      exportFormats: ["png", "spine", "atlas_json", "unknown"],
      skeletonKeypoints: [{ name: "head", x: 10, y: 20 }, { bogus: true }],
    },
  });

  assert.equal(request.options.output, "animation_skeleton");
  assert.equal(request.options.frameCount, 16);
  assert.equal(request.options.direction, "south");
  assert.equal(request.options.toDirection, "north-east");
  assert.equal(request.options.model, "flux-schnell");
  assert.equal(request.options.batchCount, 8);
  assert.deepEqual(request.options.exportFormats, ["png", "spine", "atlas_json"]);
  assert.deepEqual(request.options.skeletonKeypoints, [{ name: "head", x: 10, y: 20 }]);
}

console.log("spriteRouting assertions passed");
