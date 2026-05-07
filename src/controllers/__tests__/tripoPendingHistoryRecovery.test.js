import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../taskController.js"), "utf8");

assert(
  source.includes("async function writePendingHistoryTask"),
  "taskController should have a helper that persists pending Tripo task ownership for backend restart recovery",
);

assert(
  source.includes('status: "pending"'),
  "pending history records should be written with pending status",
);

assert(
  source.includes("writePendingHistoryTask({"),
  "createTask should write pending history records immediately after Tripo returns task IDs",
);

assert(
  source.includes("await writePendingHistoryTask"),
  "pending history writes should be awaited before returning task IDs to the frontend",
);

assert(
  source.includes("hasBeenCharged(uid, taskId)"),
  "task ownership checks should accept linked credit transactions for pre-pending-history tasks after backend restarts",
);
