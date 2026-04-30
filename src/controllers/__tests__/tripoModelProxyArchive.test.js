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

const beforeModelProxy = source.slice(0, modelProxyStart);
const modelProxyBlock = source.slice(modelProxyStart, modelProxyEnd);

assert(
  beforeModelProxy.includes("async function archiveModelProxyFetch"),
  "taskController should expose a model-proxy archival helper",
);
assert(
  modelProxyBlock.includes("archiveModelProxyFetch"),
  "modelProxy should archive successfully fetched models for durable history reloads",
);

console.log("tripoModelProxyArchive assertions passed");
