import assert from "node:assert/strict";
import {
  TRELLIS_SEED_MAX,
  resolveTrellisRequestSeed,
} from "../trellisSeed.js";

assert.equal(
  resolveTrellisRequestSeed({}, () => 0.25),
  Math.floor((TRELLIS_SEED_MAX + 1) * 0.25),
  "missing Trellis seed should resolve to a fresh random seed",
);

assert.equal(
  resolveTrellisRequestSeed({ seed: "" }, () => 0.75),
  Math.floor((TRELLIS_SEED_MAX + 1) * 0.75),
  "empty Trellis seed should resolve to a fresh random seed",
);

assert.equal(
  resolveTrellisRequestSeed({ seed: 0 }, () => {
    throw new Error("random should not be called for explicit Trellis seed");
  }),
  0,
  "explicit Trellis seed zero should be preserved",
);

assert.equal(resolveTrellisRequestSeed({ seed: TRELLIS_SEED_MAX + 100 }), TRELLIS_SEED_MAX);
assert.equal(resolveTrellisRequestSeed({ seed: -10 }), 0);

console.log("trellisSeed assertions passed");
