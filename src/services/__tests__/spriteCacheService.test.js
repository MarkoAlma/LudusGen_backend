import assert from "node:assert/strict";

import {
  SPRITE_CACHE_TTL_SECONDS,
  buildSpriteCacheKey,
  sanitizeCachedSpritePayload,
} from "../spriteCacheService.js";

console.log("\nScenario 1: sprite cache key is deterministic and excludes raw reference image data");
{
  const request = {
    prompt: "pixel hero",
    style: "pixel art",
    provider: "pixellab",
    referenceImage: "data:image/png;base64,secret-image-bytes",
    options: { output: "sprite", imageSize: { width: 128, height: 128 } },
  };

  const first = buildSpriteCacheKey(request);
  const second = buildSpriteCacheKey({ ...request, referenceImage: "data:image/png;base64,secret-image-bytes" });

  assert.equal(SPRITE_CACHE_TTL_SECONDS, 86400);
  assert.equal(first, second);
  assert.match(first, /^sprite:v1:[a-f0-9]{64}$/);
  assert.equal(first.includes("pixel hero"), false);
  assert.equal(first.includes("secret-image-bytes"), false);
}

console.log("\nScenario 2: cached payload keeps only response-safe fields");
{
  const cached = sanitizeCachedSpritePayload({
    provider: "pixellab",
    route: { provider: "pixellab" },
    images: ["data:image/png;base64,ok"],
    assets: { images: ["data:image/png;base64,ok"] },
    output: { apiKey: "must-not-cache" },
    elapsedSeconds: 1.2,
  });

  assert.deepEqual(Object.keys(cached).sort(), ["assets", "elapsedSeconds", "images", "provider", "route"].sort());
  assert.equal(JSON.stringify(cached).includes("must-not-cache"), false);
}

console.log("spriteCacheService assertions passed");
