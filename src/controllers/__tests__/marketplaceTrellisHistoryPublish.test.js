import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../marketplaceController.js"), "utf8").replace(/\r\n/g, "\n");

assert(
  source.includes('new Set(["tripo_history", "trellis_history"])'),
  "3D marketplace history publishing should accept both Tripo and Trellis history collections",
);

assert(
  source.includes("function normalizeHistorySourceCollection") &&
    source.includes('trellis: "trellis_history"') &&
    source.includes('tripo: "tripo_history"'),
  "3D marketplace history publishing should normalize short Tripo/Trellis source aliases before validating collections",
);

assert(
  source.includes("async function resolve3dHistorySourceById") &&
    source.includes('for (const fallbackCollection of ["trellis_history", "tripo_history"])') &&
    source.includes("collectionName = fallback.collectionName;"),
  "3D marketplace history publishing should fall back to resolving Trellis/Tripo source items by id when the client sends a stale source collection",
);

assert(
  source.includes("function isImportModelHistoryItem") &&
    source.includes('throw Object.assign(new Error("Import models cannot be listed on the marketplace")'),
  "3D marketplace publishing should reject Tripo import_model/upload bridge history items server-side",
);

assert(
  source.includes('collectionName !== "tripo_history" && collectionName !== "trellis_history"'),
  "Marketplace lock reconciliation should support Trellis source history refs as well as Tripo refs",
);

assert(
  source.includes("resolveMarketplace3dPreviewFallback") &&
    source.includes('const sourceCollection = normalizeHistorySourceCollection(data.source?.collection, "tripo_history");') &&
    source.includes('db.collection(sourceCollection).doc(sourceHistoryId)'),
  "3D preview fallback should read preview metadata from the actual source collection, including trellis_history",
);

assert(
  source.includes("createImageThumb(imgBuf, userId, `preview_${sourceId}`, { watermark: false })"),
  "3D model preview thumbnails should be stored without the LudusGen watermark",
);

assert(
  source.includes("function decodeMarketplacePreviewDataUrl") &&
    source.includes("body.previewDataUrl") &&
    source.includes("createImageThumb(previewBuffer, userId, `preview_${assetRef.id}`"),
  "3D marketplace publishing should persist the client-generated preview image when history has no stored preview",
);

assert(
  source.includes("watermarked: assetType === \"image\" || assetType === \"audio\""),
  "Image and audio marketplace previews should keep their watermark metadata",
);

console.log("marketplaceTrellisHistoryPublish assertions passed");
