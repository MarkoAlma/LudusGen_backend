import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../taskController.js"), "utf8");

const modelProxyStart = source.indexOf("export async function modelProxy");
const modelProxyEnd = source.indexOf("/*", modelProxyStart + 1);

assert.notEqual(modelProxyStart, -1, "modelProxy should exist");
assert.notEqual(modelProxyEnd, -1, "modelProxy block should be bounded by the next section comment");

const modelProxyBlock = source.slice(modelProxyStart, modelProxyEnd);

assert(
  modelProxyBlock.includes("const authorizedHistory = await getAuthorizedHistoryForModelProxy(taskIdParam, requesterId, url);"),
  "modelProxy should always authorize the requested URL against the caller's history, even when taskId is omitted",
);

assert(
  modelProxyBlock.includes('if (!authorizedHistory) {') &&
    modelProxyBlock.includes('res.status(403).json({ success: false, message: "Forbidden" });'),
  "modelProxy should reject every unauthorized model fetch before proxying the file",
);

console.log("taskController model proxy auth assertions passed");
