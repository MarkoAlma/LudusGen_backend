import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const serviceSource = readFileSync(resolve(__dirname, "../marketplaceService.js"), "utf8");

assert(
  serviceSource.includes("getMarketplacePreviewImageUrl"),
  "marketplace purchase history sync should centralize preview image URL generation",
);

assert(
  serviceSource.includes("/api/marketplace/assets/${assetId}/preview"),
  "marketplace purchase history sync should store a stable marketplace preview image endpoint",
);

assert(
  serviceSource.includes("previewImageUrl: previewImageUrl ?? null"),
  "marketplace 3D purchase history should store the preview image URL on the history record",
);

assert(
  serviceSource.includes("previewImageUrls: previewImageUrl ? [previewImageUrl] : []"),
  "marketplace 3D purchase history should store preview image URL arrays for existing history helpers",
);

console.log("marketplaceHistoryPreviewSync assertions passed");
