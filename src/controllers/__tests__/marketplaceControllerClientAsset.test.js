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

assert(
  controllerSource.includes("collectHistoryPreviewImageUrls"),
  "marketplace controller should normalize Tripo preview-image fields before building 3D thumbnails",
);

assert(
  controllerSource.includes("const previewFallbackUrl = await resolveMarketplace3dPreviewFallback(data);"),
  "marketplace assets without stored thumbs should fall back to the history preview image",
);

assert(
  controllerSource.includes("getMarketplaceAssetPreview"),
  "marketplace controller should expose a lightweight public image preview endpoint for stored preview keys",
);

assert(
  controllerSource.match(/export async function getMarketplaceAssetPreview[\s\S]*?if \(data\.status !== "published"\)/),
  "marketplace preview endpoint should not serve hidden or deleted assets publicly",
);

assert(
  !controllerSource.includes("return res.redirect(302, fallbackUrl);"),
  "marketplace preview endpoint should not redirect to raw fallback history URLs",
);

assert(
  controllerSource.includes("data.tripo?.sourceHistoryId || data.source?.id || null"),
  "3D marketplace preview fallback should resolve the source history record first",
);

console.log("marketplaceControllerClientAsset assertions passed");
