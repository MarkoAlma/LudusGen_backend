import express from "express";
import multer from "multer";
import os from "os";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
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

// Váltás memoryStorage-ról diskStorage-ra, hogy megakadályozzuk a szerver RAM OOM hibáját nagy (pl 250MB-os 3D fájlok) feltöltésekor.
const upload = multer({
  dest: os.tmpdir(),
  limits: { fileSize: 260 * 1024 * 1024 },
});

// Biztonsági Rate Limiterek a Spam / DDoS támadások és Race Conditionök ellen
const marketplaceUploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 100, // 100 feltöltés / óra
  keyGenerator: (req) => req.userId || ipKeyGenerator(req),
  message: { success: false, message: 'Túl sok feltöltés — próbáld újra később' },
});

const marketplacePurchaseLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30, // 30 vásárlás / perc (spam klikkelés ellen)
  keyGenerator: (req) => req.userId || ipKeyGenerator(req),
  message: { success: false, message: 'Túl sok kérés — várj egy percet a következő vásárlásig' },
});

export function createMarketplaceRouter(verifyFirebaseToken) {
  const router = express.Router();

  router.get("/marketplace/assets", listMarketplaceAssets);
  router.get("/marketplace/assets/:id", getMarketplaceAsset);
  router.post("/marketplace/assets/upload", verifyFirebaseToken, marketplaceUploadLimiter, upload.single("file"), uploadMarketplaceAsset);
  router.post("/marketplace/assets", verifyFirebaseToken, createMarketplaceAsset);
  router.patch("/marketplace/assets/:id", verifyFirebaseToken, updateMarketplaceAsset);
  router.delete("/marketplace/assets/:id", verifyFirebaseToken, deleteMarketplaceAsset);
  router.post("/marketplace/assets/:id/purchase", verifyFirebaseToken, marketplacePurchaseLimiter, purchaseMarketplaceAsset);
  router.get("/marketplace/assets/:id/download", verifyFirebaseToken, downloadMarketplaceAsset);
  router.get("/marketplace/me/library", verifyFirebaseToken, getMyMarketplaceLibrary);

  return router;
}
