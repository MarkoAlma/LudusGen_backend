import assert from "node:assert/strict";
import { taskService } from "../../services/taskService.js";

const result = taskService.taskToPollResult({
  status: "banned",
  progress: 100,
  type: "text_to_model",
  output: {},
});

assert.equal(result.success, false);
assert.equal(result.status, "failed");
assert.match(result.errorMessage, /blocked by Tripo moderation/i);

console.log("tripoTaskServiceBannedStatus assertions passed");
