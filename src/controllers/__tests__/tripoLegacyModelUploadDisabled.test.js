import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const assetController = readFileSync(resolve(__dirname, "../assetController.js"), "utf8");
const uploadController = readFileSync(resolve(__dirname, "../uploadController.js"), "utf8");

assert(
  uploadController.includes('if (normalizedKind === "model" && !isLegacyModelStsImportEnabled())') &&
    uploadController.includes("Legacy direct model uploads are disabled. Use /api/tripo/assets/upload instead."),
  "STS targets for direct model uploads should stay disabled unless the legacy override is explicitly enabled",
);

assert(
  assetController.includes("if (!isLegacyStsImportEnabled())") &&
    assetController.includes("Legacy direct model imports are disabled. Upload the model through /api/tripo/assets/upload instead."),
  "legacy STS model imports should be rejected server-side by default",
);

console.log("tripo legacy model upload assertions passed");
