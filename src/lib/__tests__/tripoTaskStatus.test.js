import assert from "node:assert/strict";
import {
  getTripoTaskErrorMessage,
  isFailedLikeTripoTaskStatus,
  isTerminalTripoTaskStatus,
  normalizeTripoTaskStatus,
} from "../../utils/tripoTaskStatus.js";

assert.equal(normalizeTripoTaskStatus("banned"), "failed");
assert.equal(normalizeTripoTaskStatus("success"), "success");
assert.equal(isFailedLikeTripoTaskStatus("banned"), true);
assert.equal(isTerminalTripoTaskStatus("banned"), true);
assert.match(
  getTripoTaskErrorMessage({ status: "banned", output: {} }),
  /blocked by Tripo moderation/i,
);

console.log("tripoTaskStatus assertions passed");
