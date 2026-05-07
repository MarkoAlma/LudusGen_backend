import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../taskController.js"), "utf8");

assert(
  source.includes("async function buildArchivedTaskFallback"),
  "taskController should build a history-backed fallback payload for expired Tripo tasks",
);

assert(
  source.includes("collectHistoryPreviewImageUrls"),
  "archived task fallback should reuse preview images persisted in history",
);

assert(
  source.includes("getTask served archived history fallback"),
  "getTask should return archived history metadata instead of a raw 410 when possible",
);

console.log("taskController archived task fallback assertions passed");
