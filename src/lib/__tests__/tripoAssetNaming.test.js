import assert from "node:assert/strict";
import {
  buildTripoAssetNamingMessages,
  buildTripoAssetNameFallback,
  normalizeTripoAssetName,
} from "../tripoAssetNaming.js";

{
  const messages = buildTripoAssetNamingMessages({
    mode: "generate",
    type: "text_to_model",
    prompt: "high-quality anime 3D model, cel-shaded aesthetics, fox samurai with red armor",
    basePrompt: "fox samurai with red armor",
    styleId: "anime",
    negativePrompt: "blurry",
    modelVersion: "v3.1-20260211",
  });

  assert.equal(messages.length, 2);
  assert.equal(messages[0].role, "system");
  assert.equal(messages[1].role, "user");
  assert.match(messages[0].content, /JSON/i);
  assert.match(messages[1].content, /fox samurai with red armor/i);
  assert.match(messages[1].content, /anime/i);
  assert.match(messages[1].content, /text_to_model/i);
}

assert.equal(
  normalizeTripoAssetName('  "Anime Fox Warrior."  '),
  "Anime Fox Warrior"
);

assert.equal(
  buildTripoAssetNameFallback({
    mode: "segment",
    sourceName: "Crystal Wolf",
  }),
  "Segmented Crystal Wolf"
);

assert.equal(
  buildTripoAssetNameFallback({
    mode: "generate",
    basePrompt: "ancient stone golem guardian",
  }),
  "Ancient Stone Golem"
);

console.log("tripoAssetNaming assertions passed");
