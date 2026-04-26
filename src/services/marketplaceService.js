import admin from "firebase-admin";

export const MARKETPLACE_COLLECTIONS = {
  assets: "marketplace_assets",
  purchases: "marketplace_purchases",
  library: "marketplace_library",
  revenue: "marketplace_revenue",
};

const USERS_COLLECTION = "users";
const CREDIT_HISTORY_COLLECTION = "credit_history";
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
  const previewExists = Boolean(asset.preview?.key || asset.storage?.thumbKey || asset.storage?.key || asset.previewUrl);
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
  const storageKey = asset.storage?.key || asset.storageKey;
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
    await db.collection("audio_history").doc(`marketplace_${buyerId}_${assetId}`).set({
      userId: buyerId,
      type: asset.source?.audioKind || "audio",
      title: asset.title || "Marketplace audio",
      prompt: asset.description || "",
      storageKey,
      marketplaceLocked: true,
      marketplaceAssetId: assetId,
      marketplacePurchaseId: purchaseId,
      fileName: asset.storage?.fileName || "marketplace_audio.mp3",
      fileFormat: asset.storage?.fileName?.split(".").pop()?.toLowerCase() || "mp3",
      contentType: asset.storage?.contentType || "audio/mpeg",
      size: Number(asset.storage?.size || 0),
      provider: "marketplace",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ts: now,
    }, { merge: true });
  }
}

export async function purchaseAsset(assetId, buyerId) {
  if (!assetId || !buyerId) {
    throw Object.assign(new Error("Hianyzo asset vagy vasarlo azonosito"), { status: 400 });
  }

  const db = admin.firestore();
  const assetRef = db.collection(MARKETPLACE_COLLECTIONS.assets).doc(assetId);
  const purchaseId = getPurchaseId(buyerId, assetId);
  const purchaseRef = db.collection(MARKETPLACE_COLLECTIONS.purchases).doc(purchaseId);
  const libraryRef = db.collection(MARKETPLACE_COLLECTIONS.library).doc(purchaseId);
  const revenueRef = db.collection(MARKETPLACE_COLLECTIONS.revenue).doc(purchaseId);

  let result = null;

  await db.runTransaction(async (tx) => {
    const purchaseDoc = await tx.get(purchaseRef);
    if (purchaseDoc.exists) {
      const existing = purchaseDoc.data();
      result = {
        alreadyOwned: true,
        purchaseId,
        purchase: existing,
        libraryItem: { id: purchaseId, ...existing },
      };
      return;
    }

    const assetDoc = await tx.get(assetRef);
    if (!assetDoc.exists) {
      throw Object.assign(new Error("Asset nem talalhato"), { status: 404 });
    }

    const asset = assetDoc.data();
    if (asset.status !== "published") {
      throw Object.assign(new Error("Ez az asset jelenleg nem vasarolhato"), { status: 409 });
    }
    if (asset.ownerId === buyerId) {
      throw Object.assign(new Error("Sajat assetet nem lehet megvasarolni"), { status: 400 });
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
      throw Object.assign(new Error("Vasarloi profil nem talalhato"), { status: 404 });
    }
    if (!sellerDoc.exists) {
      throw Object.assign(new Error("Eladoi profil nem talalhato"), { status: 404 });
    }

    const buyerCredits = Number(buyerDoc.data().credits || 0);
    if (buyerCredits < priceCredits) {
      throw Object.assign(new Error("Nincs eleg kredit a vasarlashoz"), {
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

    const purchase = {
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
      storageKey: asset.storage?.key || asset.storageKey || null,
      createdAt,
      status: "completed",
    };

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
      purchase,
      libraryItem: {
        id: purchaseId,
        ...purchase,
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
