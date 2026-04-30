import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../taskController.js"), "utf8");

assert(
  source.includes("async function getHistoryDocsByTaskKey"),
  "taskController should centralize task history lookup so old doc-id-only history entries authorize correctly",
);

assert(
  source.includes('doc(`tripo_${normalizedTaskId}`)'),
  "task history auth should try the stable tripo_<taskId> document id fallback",
);

assert(
  source.includes("const normalizedTaskId = normalizeHistoryTaskKey(taskId)"),
  "task history auth should normalize tripo_-prefixed task ids before lookup",
);

assert(
  source.includes("assetData.ownerId === uid"),
  "model proxy marketplace guard should allow the asset owner to load their own published Tripo history item",
);

console.log("taskController history auth fallback assertions passed");
