import assert from "node:assert/strict";
import sharp from "sharp";

import {
  buildSpriteAtlas,
  postProcessSpriteAssets,
} from "../spritePostProcessingService.js";

async function makePngDataUrl(color) {
  const buffer = await sharp({
    create: {
      width: 2,
      height: 2,
      channels: 4,
      background: color,
    },
  }).png().toBuffer();
  return `data:image/png;base64,${buffer.toString("base64")}`;
}

console.log("\nScenario 1: atlas metadata describes frame coordinates safely");
{
  const atlas = buildSpriteAtlas({
    frameCount: 3,
    frameWidth: 16,
    frameHeight: 24,
    columns: 2,
    provider: "pixellab",
    operation: "rotation_4",
    requestId: "req_atlas",
  });

  assert.equal(atlas.image.width, 32);
  assert.equal(atlas.image.height, 48);
  assert.equal(atlas.frames.length, 3);
  assert.deepEqual(atlas.frames[2], {
    name: "frame_002",
    index: 2,
    x: 0,
    y: 24,
    w: 16,
    h: 24,
  });
}

console.log("\nScenario 2: multiple frames are assembled into a transparent PNG sheet");
{
  const red = await makePngDataUrl({ r: 255, g: 0, b: 0, alpha: 1 });
  const blue = await makePngDataUrl({ r: 0, g: 0, b: 255, alpha: 1 });
  const assets = await postProcessSpriteAssets({
    images: [red, blue],
    request: {
      options: {
        output: "rotation",
        directionSet: "4-way",
        imageSize: { width: 2, height: 2 },
      },
    },
    result: {
      provider: "pixellab",
      metadata: { mode: "rotation" },
    },
    route: {
      provider: "pixellab",
      operation: "rotation_4",
    },
    requestId: "req_sheet",
  });

  assert.match(assets.spriteSheet, /^data:image\/png;base64,/);
  assert.equal(assets.postProcessError, null);
  assert.equal(assets.atlas.mode, "assembled");
  assert.equal(assets.atlas.image.width, 4);
  assert.equal(assets.atlas.image.height, 2);
  assert.equal(assets.atlas.frames.length, 2);

  const metadata = await sharp(Buffer.from(assets.spriteSheet.split(",")[1], "base64")).metadata();
  assert.equal(metadata.width, 4);
  assert.equal(metadata.height, 2);
}

console.log("spritePostProcessingService assertions passed");
