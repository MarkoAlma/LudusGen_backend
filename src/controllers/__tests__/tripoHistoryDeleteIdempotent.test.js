import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../taskController.js"), "utf8");

const start = source.indexOf("export async function deleteHistoryItem");
const end = source.indexOf("export async function clearHistory", start);

assert.notEqual(start, -1, "deleteHistoryItem should exist");
assert.notEqual(end, -1, "clearHistory should follow deleteHistoryItem");

const block = source.slice(start, end);

assert(
  block.includes("alreadyDeleted"),
  "deleteHistoryItem should treat missing history documents as an idempotent success",
);
assert.equal(
  block.includes("res.status(404).json({ success: false, message: \"Item not found\" })"),
  false,
  "deleteHistoryItem should not emit a visible 404 for already-cleaned-up history docs",
);

console.log("tripoHistoryDeleteIdempotent assertions passed");
