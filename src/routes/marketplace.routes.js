import express from "express";
import multer from "multer";
import {
  createMarketplaceAsset,
  deleteMarketplaceAsset,
  downloadMarketplaceAsset,
  getMarketplaceAsset,
  getMyMarketplaceLibrary,
  listMarketplaceAssets,
  purchaseMarketplaceAsset,
  updateMarketplaceAsset,
  uploadMarketplaceAsset,
} from "../controllers/marketplaceController.js";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 260 * 1024 * 1024 },
});

export function createMarketplaceRouter(verifyFirebaseToken) {
  const router = express.Router();

  router.get("/marketplace/assets", listMarketplaceAssets);
  router.get("/marketplace/assets/:id", getMarketplaceAsset);
  router.post("/marketplace/assets/upload", verifyFirebaseToken, upload.single("file"), uploadMarketplaceAsset);
  router.post("/marketplace/assets", verifyFirebaseToken, createMarketplaceAsset);
  router.patch("/marketplace/assets/:id", verifyFirebaseToken, updateMarketplaceAsset);
  router.delete("/marketplace/assets/:id", verifyFirebaseToken, deleteMarketplaceAsset);
  router.post("/marketplace/assets/:id/purchase", verifyFirebaseToken, purchaseMarketplaceAsset);
  router.get("/marketplace/assets/:id/download", verifyFirebaseToken, downloadMarketplaceAsset);
  router.get("/marketplace/me/library", verifyFirebaseToken, getMyMarketplaceLibrary);

  return router;
}
