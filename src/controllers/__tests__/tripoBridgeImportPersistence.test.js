import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const assetControllerSource = readFileSync(resolve(__dirname, "../assetController.js"), "utf8").replace(/\r\n/g, "\n");
const taskControllerSource = readFileSync(resolve(__dirname, "../taskController.js"), "utf8").replace(/\r\n/g, "\n");

assert(
  assetControllerSource.includes("function isTripoBridgeImportSourceKind"),
  "asset upload should explicitly recognize Trellis/stored bridge imports",
);

assert(
  assetControllerSource.includes('const historySource = isTripoBridgeImportSourceKind(sourceKind) ? "tripo" : "upload";'),
  "Trellis/stored bridge imports should be stored in Tripo history, while manual uploads stay in Uploads",
);

assert(
  assetControllerSource.includes("source: historySource,"),
  "uploaded import history rows should use the computed source so bridge imports appear in the Tripo tab",
);

assert(
  assetControllerSource.includes('type: "import_model",'),
  "asset import pending history params should persist the Tripo task type for restart/recovery paths",
);

assert(
  taskControllerSource.includes("async function syncSuccessfulHistoryTaskFromStatus"),
  "task polling should be able to persist successful import_model results without waiting for the recovery loop",
);

assert(
  taskControllerSource.includes("await syncSuccessfulHistoryTaskFromStatus({") &&
    taskControllerSource.includes("result,") &&
    taskControllerSource.includes("taskMeta,"),
  "getTask should sync successful model URLs into history before returning to the frontend",
);

assert(
  taskControllerSource.includes("source: existingData?.source ?? (taskType === \"import_model\" ? \"upload\" : \"tripo\")"),
  "status sync should preserve the bridge import source instead of forcing all import_model tasks into Uploads",
);

console.log("tripoBridgeImportPersistence assertions passed");
