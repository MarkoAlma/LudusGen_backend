import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../taskController.js"), "utf8").replace(/\r\n/g, "\n");

assert(
  source.includes("function isMarketplaceProtectedHistoryData"),
  "taskController should centralize marketplace history protection checks",
);

assert(
  source.includes("data.params?.type === \"marketplace_asset\"") &&
    source.includes("data.params?.downloadOnly === true"),
  "Marketplace protection should cover purchase-synced history documents even when top-level flags are missing",
);

const deleteStart = source.indexOf("async function deleteHistoryDocsWithStorage");
const deleteEnd = source.indexOf("async function deleteHistoryForDeadModel", deleteStart);

assert.notEqual(deleteStart, -1, "deleteHistoryDocsWithStorage should exist");
assert.notEqual(deleteEnd, -1, "deleteHistoryForDeadModel should follow deleteHistoryDocsWithStorage");

const deleteBlock = source.slice(deleteStart, deleteEnd);

assert(
  deleteBlock.includes("storageDocs") &&
    deleteBlock.includes("!isMarketplaceProtectedHistoryData") &&
    deleteBlock.includes("storageDocs.map"),
  "History cleanup must never delete B2 storage keys that belong to marketplace-protected history docs",
);

assert(
  deleteBlock.includes("shouldPreserveMarketplaceHistoryDoc") &&
    deleteBlock.includes("deletableDocs"),
  "Automated dead-model and TTL cleanup should preserve marketplace-protected history docs instead of deleting them",
);

assert(
  source.includes("isMarketplaceProtectedHistoryData(data)") &&
    source.includes("if (isMarketplaceProtectedHistoryData(doc.data())) return false;"),
  "TTL expiry checks should use the same marketplace protection helper as the destructive cleanup path",
);

console.log("taskController marketplace retention assertions passed");
