import assert from "node:assert/strict";
import { extractModelUrl } from "../tripoUtils.js";

const textured = extractModelUrl({
  type: "texture_model",
  output: {
    pbr_model: "https://cdn.example.test/pbr.glb",
    model: "https://cdn.example.test/plain.glb",
  },
});

assert.equal(
  textured.modelUrl,
  "https://cdn.example.test/pbr.glb",
  "Texture tasks should still prefer the PBR/textured model output",
);

const smartLowPoly = extractModelUrl({
  type: "smart_low_poly",
  output: {
    pbr_model: "https://cdn.example.test/source-pbr.glb",
    low_poly_model: "https://cdn.example.test/retopo-low.glb",
    model: "https://cdn.example.test/generic.glb",
  },
});

assert.equal(
  smartLowPoly.modelUrl,
  "https://cdn.example.test/retopo-low.glb",
  "Smart-low-poly retopo tasks should prefer the generated low_poly_model over source texture variants",
);
assert.equal(smartLowPoly.chosenSource, "low_poly_model");

const convertModel = extractModelUrl({
  type: "convert_model",
  output: {
    pbr_model: "https://cdn.example.test/source-pbr.glb",
    converted_model: "https://cdn.example.test/converted.glb",
    base_model: "https://cdn.example.test/source-base.glb",
  },
});

assert.equal(
  convertModel.modelUrl,
  "https://cdn.example.test/converted.glb",
  "Convert-model retopo tasks should prefer the generated converted_model over source texture variants",
);
assert.equal(convertModel.chosenSource, "converted_model");

console.log("tripoModelUrlSelection assertions passed");
