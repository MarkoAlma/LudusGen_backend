import assert from "node:assert/strict";

import { getMarketplacePreviewImageUrl } from "../marketplaceService.js";

const originalEnv = {
  NODE_ENV: process.env.NODE_ENV,
  PUBLIC_BACKEND_URL: process.env.PUBLIC_BACKEND_URL,
  BACKEND_URL: process.env.BACKEND_URL,
  API_BASE_URL: process.env.API_BASE_URL,
  RENDER_EXTERNAL_URL: process.env.RENDER_EXTERNAL_URL,
};

function restoreEnv() {
  for (const [key, value] of Object.entries(originalEnv)) {
    if (value == null) delete process.env[key];
    else process.env[key] = value;
  }
}

try {
  const asset = { preview: { key: "marketplace/previews/user_1/thumb.webp" } };

  process.env.PUBLIC_BACKEND_URL = "https://api.example.test/";
  assert.equal(
    getMarketplacePreviewImageUrl("asset_123", asset),
    "https://api.example.test/api/marketplace/assets/asset_123/preview",
    "Marketplace preview URLs should use the configured backend origin",
  );

  delete process.env.PUBLIC_BACKEND_URL;
  delete process.env.BACKEND_URL;
  delete process.env.API_BASE_URL;
  delete process.env.RENDER_EXTERNAL_URL;
  process.env.NODE_ENV = "production";

  assert.equal(
    getMarketplacePreviewImageUrl("asset_123", asset),
    "https://ludusgen-backend.onrender.com/api/marketplace/assets/asset_123/preview",
    "Production marketplace preview URLs should not fall back to the frontend origin",
  );

  assert.equal(
    getMarketplacePreviewImageUrl("asset_123", { preview: { key: "marketplace/assets/user_1/model.glb" } }),
    null,
    "Only marketplace preview storage keys should expose the public preview endpoint",
  );

  console.log("marketplacePreviewUrl assertions passed");
} finally {
  restoreEnv();
}
