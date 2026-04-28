import admin from "firebase-admin";
import crypto from "node:crypto";

export const MARKETPLACE_COLLECTIONS = {
  assets: "marketplace_assets",
  purchases: "marketplace_purchases",
  library: "marketplace_library",
  revenue: "marketplace_revenue",
};

const USERS_COLLECTION = "users";
const CREDIT_HISTORY_COLLECTION = "credit_history";
const PURCHASE_SIGNATURE_VERSION = "v1";
const PAYOUT_BUCKETS = [
  { percent: 80, weight: 45 },
  { percent: 85, weight: 35 },
  { percent: 90, weight: 5 },
  { percent: 95, weight: 5 },
  { percent: 100, weight: 10 },
];

function toMillis(value) {
  if (!value) return null;
  if (typeof value === "number") return value;
  if (value instanceof Date) return value.getTime();
  if (typeof value?.toMillis === "function") return value.toMillis();
  if (typeof value?.toDate === "function") return value.toDate().getTime();
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function isMetadataComplete(asset = {}) {
  const storageKey = asset.storage?.key || asset.storageKey;
  return Boolean(
    asset.title &&
    asset.type &&
    Number.isInteger(asset.priceCredits) &&
    asset.priceCredits >= 20 &&
    asset.ownerId &&
    storageKey,
  );
}

function getStorageKey(asset = {}) {
  return asset.storage?.key || asset.storageKey || null;
}

function safePositiveDimension(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  const rounded = Math.round(number);
  return rounded > 0 && rounded <= 200_000 ? rounded : null;
}

function normalizeAssetMetadata(metadata = {}, type = "") {
  if (type !== "image") return null;

  const source = metadata?.image || metadata || {};
  const width = safePositiveDimension(source.width);
  const height = safePositiveDimension(source.height);
  if (!width || !height) return null;

  return {
    image: {
      width,
      height,
      ...(source.format ? { format: String(source.format).slice(0, 24) } : {}),
      ...(source.animated === true ? { animated: true } : {}),
    },
  };
}

export function isProtectedMarketplaceStorageKey(key) {
  const value = String(key || "");
  return value.startsWith("marketplace/") && !value.startsWith("marketplace/previews/");
}

function getPurchaseSigningSecret() {
  return process.env.MARKETPLACE_PURCHASE_SIGNING_SECRET || process.env.B2_APP_KEY;
}

function canonicalPurchasePayload(purchase = {}) {
  return JSON.stringify({
    version: PURCHASE_SIGNATURE_VERSION,
    id: String(purchase.id || ""),
    buyerId: String(purchase.buyerId || ""),
    sellerId: String(purchase.sellerId || ""),
    assetId: String(purchase.assetId || ""),
    assetType: String(purchase.assetType || ""),
    priceCredits: Number(purchase.priceCredits || 0),
    storageKey: String(purchase.storageKey || ""),
    status: String(purchase.status || ""),
  });
}

export function signMarketplacePurchase(purchase = {}) {
  const secret = getPurchaseSigningSecret();
  if (!secret) {
    throw new Error("Missing marketplace purchase signing secret");
  }
  return crypto
    .createHmac("sha256", secret)
    .update(canonicalPurchasePayload(purchase))
    .digest("hex");
}

function signaturesMatch(actual, expected) {
  if (!actual || !expected || actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

export function isVerifiedMarketplacePurchase(purchase = {}, { buyerId, assetId, asset } = {}) {
  if (!purchase || typeof purchase !== "object") return false;
  if (purchase.status !== "completed") return false;
  if (purchase.buyerId !== buyerId) return false;
  if (purchase.assetId !== assetId) return false;
  if (purchase.sellerId !== asset?.ownerId) return false;
  if (purchase.assetType !== asset?.type) return false;
  if (purchase.storageKey !== getStorageKey(asset)) return false;
  if (!Number.isInteger(Number(purchase.priceCredits)) || Number(purchase.priceCredits) < 20) return false;
  if (purchase.signatureVersion !== PURCHASE_SIGNATURE_VERSION || purchase.serverVerified !== true) return false;

  try {
    return signaturesMatch(purchase.accessSignature, signMarketplacePurchase(purchase));
  } catch {
    return false;
  }
}

export async function getVerifiedMarketplacePurchase(db, { buyerId, assetId, asset } = {}) {
  if (!buyerId || !assetId || !asset) return null;
  const purchaseRef = db.collection(MARKETPLACE_COLLECTIONS.purchases).doc(getPurchaseId(buyerId, assetId));
  const purchaseDoc = await purchaseRef.get();
  if (!purchaseDoc.exists) return null;

  const purchase = purchaseDoc.data();
  if (!isVerifiedMarketplacePurchase(purchase, { buyerId, assetId, asset })) return null;
  return { id: purchaseDoc.id, ...purchase };
}

export async function canAccessMarketplaceStorageKey(db, { userId, key, assetId = null } = {}) {
  if (!isProtectedMarketplaceStorageKey(key)) return true;
  if (!userId || !key) return false;

  let resolvedAssetId = assetId;
  let asset = null;

  if (resolvedAssetId) {
    const assetDoc = await db.collection(MARKETPLACE_COLLECTIONS.assets).doc(resolvedAssetId).get();
    if (!assetDoc.exists) return false;
    asset = assetDoc.data();
  } else {
    const assetSnap = await db.collection(MARKETPLACE_COLLECTIONS.assets)
      .where("storage.key", "==", key)
      .limit(1)
      .get();
    if (assetSnap.empty) return false;
    const assetDoc = assetSnap.docs[0];
    resolvedAssetId = assetDoc.id;
    asset = assetDoc.data();
  }

  if (getStorageKey(asset) !== key) return false;
  if (asset.ownerId === userId) return true;

  const purchase = await getVerifiedMarketplacePurchase(db, {
    buyerId: userId,
    assetId: resolvedAssetId,
    asset,
  });
  return Boolean(purchase);
}

export function sanitizePurchaseForClient(purchase = {}) {
  const {
    accessSignature,
    serverVerified,
    signatureVersion,
    storageKey,
    ...safePurchase
  } = purchase;
  return safePurchase;
}

export function calculateFeaturedScore(asset = {}, now = Date.now()) {
  const manualFeaturedBoost = Number(asset.manualFeaturedBoost || 0);
  const purchaseCount = Number(asset.metrics?.purchaseCount ?? asset.purchaseCount ?? 0);
  const purchaseScore = Math.min(purchaseCount * 12, 120);
  const createdAtMs = toMillis(asset.createdAt) ?? toMillis(asset.ts) ?? now;
  const ageDays = Math.max(0, (now - createdAtMs) / (24 * 60 * 60 * 1000));
  const freshnessScore = ageDays < 7 ? 30 : ageDays <= 30 ? 15 : 0;
  const compatibilityScore = asset.type === "3d"
    ? (asset.tripo?.compatible ? 20 : 0)
    : 10;
  const previewExists = Boolean(asset.preview?.key || asset.storage?.thumbKey || asset.previewUrl);
  const qualityScore = previewExists && isMetadataComplete(asset) ? 10 : 0;

  return manualFeaturedBoost + purchaseScore + freshnessScore + compatibilityScore + qualityScore;
}

export function drawSellerPayoutPercent(randomValue = Math.random()) {
  const total = PAYOUT_BUCKETS.reduce((sum, item) => sum + item.weight, 0);
  let cursor = randomValue * total;
  for (const bucket of PAYOUT_BUCKETS) {
    cursor -= bucket.weight;
    if (cursor < 0) return bucket.percent;
  }
  return 100;
}

export function getPurchaseId(buyerId, assetId) {
  return `${buyerId}_${assetId}`;
}

export function normalizeAssetForClient(id, data = {}) {
  return {
    id,
    title: data.title || "Nevtelen asset",
    description: data.description || "",
    type: data.type || "image",
    priceCredits: Number(data.priceCredits || 0),
    ownerId: data.ownerId,
    ownerName: data.ownerName || data.ownerEmail || "Alkoto",
    ownerAvatar: data.ownerAvatar || "",
    tags: Array.isArray(data.tags) ? data.tags : [],
    status: data.status || "published",
    source: data.source || null,
    metadata: normalizeAssetMetadata(data.metadata, data.type),
    storage: {
      fileName: data.storage?.fileName || data.fileName || "asset",
      contentType: data.storage?.contentType || data.contentType || "application/octet-stream",
      size: Number(data.storage?.size || data.size || 0),
    },
    tripo: data.tripo || { compatible: data.type !== "3d", importStatus: data.type === "3d" ? "not_started" : "not_applicable" },
    metrics: {
      purchaseCount: Number(data.metrics?.purchaseCount || 0),
      viewCount: Number(data.metrics?.viewCount || 0),
    },
    featuredScore: Number(data.featuredScore || calculateFeaturedScore(data)),
    createdAt: data.createdAt,
    updatedAt: data.updatedAt,
    createdAtMs: toMillis(data.createdAt) ?? toMillis(data.ts),
  };
}

export async function syncPurchasedAssetToHistory(buyerId, assetId, asset, purchaseId) {
  const db = admin.firestore();
  const now = Date.now();
  const storageKey = getStorageKey(asset);
  const downloadUrl = `/api/marketplace/assets/${assetId}/download?inline=1`;

  if (asset.type === "3d") {
    await db.collection("tripo_history").doc(`marketplace_${buyerId}_${assetId}`).set({
      userId: buyerId,
      prompt: asset.title || asset.storage?.fileName || "Marketplace 3D asset",
      status: "succeeded",
      model_url: downloadUrl,
      source: "tripo",
      mode: "marketplace",
      taskId: asset.tripo?.importTaskId || null,
      marketplaceLocked: true,
      marketplaceAssetId: assetId,
      marketplacePurchaseId: purchaseId,
      params: {
        type: "marketplace_asset",
        mode: "marketplace",
        compatible: asset.tripo?.compatible === true,
        fileType: asset.storage?.fileName?.split(".").pop()?.toLowerCase() || null,
        downloadOnly: asset.tripo?.compatible !== true,
      },
      ts: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });
  }

  if (asset.type === "audio" && storageKey) {
    await db.collection("generated_audio").doc(`marketplace_${buyerId}_${assetId}`).set({
      userId: buyerId,
      type: asset.source?.audioKind || "audio",
      title: asset.title || "Marketplace audio",
      prompt: asset.description || "",
      b2_key: storageKey,
      marketplaceLocked: true,
      marketplaceAssetId: assetId,
      marketplacePurchaseId: purchaseId,
      fileName: asset.storage?.fileName || "marketplace_audio.mp3",
      fileFormat: asset.storage?.fileName?.split(".").pop()?.toLowerCase() || "mp3",
      contentType: asset.storage?.contentType || "audio/mpeg",
      fileSize: Number(asset.storage?.size || 0),
      storage: "b2",
      provider: "marketplace",
      createdAtMs: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ts: now,
    }, { merge: true });
  }
}

export async function purchaseAsset(assetId, buyerId) {
  if (!assetId || !buyerId) {
    throw Object.assign(new Error("Missing asset or buyer identifier"), { status: 400 });
  }

  const db = admin.firestore();
  const assetRef = db.collection(MARKETPLACE_COLLECTIONS.assets).doc(assetId);
  const purchaseId = getPurchaseId(buyerId, assetId);
  const purchaseRef = db.collection(MARKETPLACE_COLLECTIONS.purchases).doc(purchaseId);
  const libraryRef = db.collection(MARKETPLACE_COLLECTIONS.library).doc(purchaseId);
  const revenueRef = db.collection(MARKETPLACE_COLLECTIONS.revenue).doc(purchaseId);

  let result = null;

  await db.runTransaction(async (tx) => {
    const assetDoc = await tx.get(assetRef);
    if (!assetDoc.exists) {
      throw Object.assign(new Error("Asset nem talalhato"), { status: 404 });
    }

    const asset = assetDoc.data();
    const purchaseDoc = await tx.get(purchaseRef);
    if (purchaseDoc.exists) {
      const existing = purchaseDoc.data();
      if (!isVerifiedMarketplacePurchase(existing, { buyerId, assetId, asset })) {
        throw Object.assign(new Error("Ervenytelen marketplace purchase record"), { status: 409 });
      }

      const safePurchase = sanitizePurchaseForClient({ id: purchaseId, ...existing });
      result = {
        alreadyOwned: true,
        purchaseId,
        purchase: safePurchase,
        libraryItem: safePurchase,
      };
      return;
    }

    if (asset.status !== "published") {
      throw Object.assign(new Error("Ez az asset jelenleg nem vasarolhato"), { status: 409 });
    }
    if (asset.ownerId === buyerId) {
      throw Object.assign(new Error("You cannot buy your own asset"), { status: 400 });
    }

    const priceCredits = Number(asset.priceCredits || 0);
    if (!Number.isInteger(priceCredits) || priceCredits < 20) {
      throw Object.assign(new Error("Ervenytelen marketplace ar"), { status: 400 });
    }

    const buyerRef = db.collection(USERS_COLLECTION).doc(buyerId);
    const sellerRef = db.collection(USERS_COLLECTION).doc(asset.ownerId);
    const buyerDoc = await tx.get(buyerRef);
    const sellerDoc = await tx.get(sellerRef);

    if (!buyerDoc.exists) {
      throw Object.assign(new Error("Buyer profile not found"), { status: 404 });
    }
    if (!sellerDoc.exists) {
      throw Object.assign(new Error("Seller profile not found"), { status: 404 });
    }

    const buyerCredits = Number(buyerDoc.data().credits || 0);
    if (buyerCredits < priceCredits) {
      throw Object.assign(new Error("Not enough credits for this purchase"), {
        status: 402,
        code: "INSUFFICIENT_CREDITS",
        available: buyerCredits,
        required: priceCredits,
      });
    }

    const payoutPercent = drawSellerPayoutPercent();
    const sellerPayoutCredits = Math.round(priceCredits * payoutPercent / 100);
    const platformProfitCredits = priceCredits - sellerPayoutCredits;
    const createdAt = admin.firestore.FieldValue.serverTimestamp();
    const assetSnapshot = normalizeAssetForClient(assetDoc.id, asset);

    const purchaseBase = {
      id: purchaseId,
      buyerId,
      sellerId: asset.ownerId,
      assetId,
      assetType: asset.type,
      assetTitle: asset.title || "",
      priceCredits,
      sellerPayoutPercent: payoutPercent,
      sellerPayoutCredits,
      platformProfitCredits,
      storageKey: getStorageKey(asset),
      createdAt,
      status: "completed",
    };
    const purchase = {
      ...purchaseBase,
      serverVerified: true,
      signatureVersion: PURCHASE_SIGNATURE_VERSION,
      accessSignature: signMarketplacePurchase(purchaseBase),
    };
    const safePurchase = sanitizePurchaseForClient(purchase);

    tx.update(buyerRef, { credits: buyerCredits - priceCredits });
    tx.update(sellerRef, { credits: admin.firestore.FieldValue.increment(sellerPayoutCredits) });
    tx.update(assetRef, {
      "metrics.purchaseCount": admin.firestore.FieldValue.increment(1),
      featuredScore: calculateFeaturedScore({
        ...asset,
        metrics: {
          ...(asset.metrics || {}),
          purchaseCount: Number(asset.metrics?.purchaseCount || 0) + 1,
        },
      }),
      updatedAt: createdAt,
    });

    tx.set(purchaseRef, purchase);
    tx.set(libraryRef, {
      ...purchase,
      asset: assetSnapshot,
    });
    tx.set(revenueRef, {
      purchaseId,
      assetId,
      buyerId,
      sellerId: asset.ownerId,
      priceCredits,
      sellerPayoutPercent: payoutPercent,
      sellerPayoutCredits,
      platformProfitCredits,
      createdAt,
    });

    tx.set(db.collection(CREDIT_HISTORY_COLLECTION).doc(buyerId).collection("transactions").doc(), {
      type: "debit",
      amount: priceCredits,
      taskId: `marketplace_${assetId}`,
      taskType: "marketplace_purchase",
      assetId,
      purchaseId,
      balanceBefore: buyerCredits,
      balanceAfter: buyerCredits - priceCredits,
      timestamp: createdAt,
    });

    const sellerCredits = Number(sellerDoc.data().credits || 0);
    tx.set(db.collection(CREDIT_HISTORY_COLLECTION).doc(asset.ownerId).collection("transactions").doc(), {
      type: "marketplace_payout",
      amount: sellerPayoutCredits,
      taskId: `marketplace_${assetId}`,
      taskType: "marketplace_sale",
      assetId,
      purchaseId,
      payoutPercent,
      balanceBefore: sellerCredits,
      balanceAfter: sellerCredits + sellerPayoutCredits,
      timestamp: createdAt,
    });

    result = {
      alreadyOwned: false,
      purchaseId,
      purchase: safePurchase,
      libraryItem: {
        id: purchaseId,
        ...safePurchase,
        asset: assetSnapshot,
      },
      asset,
    };
  });

  if (result && !result.alreadyOwned && result.asset) {
    try {
      await syncPurchasedAssetToHistory(buyerId, assetId, result.asset, purchaseId);
    } catch (err) {
      console.warn(`[Marketplace] Library history sync failed for ${purchaseId}:`, err.message);
    }
  }

  return result;
}
