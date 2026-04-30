import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const controllerSource = readFileSync(resolve(__dirname, "../marketplaceController.js"), "utf8");

assert(
  controllerSource.includes("viewerCanAccessFile"),
  "assetForClient should expose when the current viewer can access the protected marketplace file",
);

assert(
  controllerSource.includes("modelPreviewUrl"),
  "assetForClient should expose a protected inline model preview URL for owned/owner 3D assets",
);

assert(
  controllerSource.includes("assetForClient(doc, ownedIds, viewerId)"),
  "marketplace list responses should hydrate assets with the current viewer id",
);

console.log("marketplaceControllerClientAsset assertions passed");
