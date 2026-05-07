import assert from "node:assert/strict";
import {
  extractTrellisModelBase64,
  normalizeTrellisBase64Candidate,
} from "../trellisResponse.js";

assert.equal(
  extractTrellisModelBase64({
    artifacts: [{ glb_base64: "QUJD" }],
  }),
  "QUJD",
  "should read glb_base64 from artifact responses",
);

assert.equal(
  extractTrellisModelBase64({
    glb_base64: "data:model/gltf-binary;base64,QUJD",
  }),
  "QUJD",
  "should strip data URL prefixes from top-level glb_base64 payloads",
);

assert.equal(
  extractTrellisModelBase64({
    result: {
      model: {
        base64: "QUJD",
      },
    },
  }),
  "QUJD",
  "should read nested model.base64 response shapes",
);

assert.equal(
  normalizeTrellisBase64Candidate("  data:application/octet-stream;base64,QUJD  "),
  "QUJD",
  "should normalize surrounding whitespace and data URL wrappers",
);

console.log("trellisResponse assertions passed");
