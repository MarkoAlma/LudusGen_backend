import admin from "firebase-admin";
import axios from "axios";
import crypto from "node:crypto";
import path from "node:path";
import sharp from "sharp";
import { storageService } from "../services/storageService.js";
import {
  MARKETPLACE_COLLECTIONS,
  calculateFeaturedScore,
  normalizeAssetForClient,
  purchaseAsset,
} from "../services/marketplaceService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { taskService } from "../services/taskService.js";
import { registerTask as registerForRecovery } from "../services/taskRecoveryService.js";

const TYPE_CONFIG = {
  image: {
    extensions: new Set(["jpg", "jpeg", "png", "webp", "gif"]),
    maxBytes: 50 * 1024 * 1024,
    accepts: (mime) => String(mime || "").startsWith("image/"),
  },
  audio: {
    extensions: new Set(["mp3", "wav", "ogg", "opus", "aac", "flac", "m4a"]),
    maxBytes: 100 * 1024 * 1024,
    accepts: (mime) => String(mime || "").startsWith("audio/"),
  },
  "3d": {
    extensions: new Set(["glb", "gltf", "fbx", "obj", "stl"]),
    maxBytes: 250 * 1024 * 1024,
    accepts: (mime) => String(mime || "").startsWith("model/") || mime === "application/octet-stream" || mime === "text/plain",
  },
};

const DEFAULT_CONTENT_TYPES = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  webp: "image/webp",
  gif: "image/gif",
  mp3: "audio/mpeg",
  wav: "audio/wav",
  ogg: "audio/ogg",
  opus: "audio/ogg",
  aac: "audio/aac",
  flac: "audio/flac",
  m4a: "audio/mp4",
  glb: "model/gltf-binary",
  gltf: "model/gltf+json",
  fbx: "application/octet-stream",
  obj: "text/plain",
  stl: "model/stl",
};

function normalizeAssetType(value) {
  const type = String(value || "").trim().toLowerCase();
  if (["image", "images", "kep", "kepek"].includes(type)) return "image";
  if (["audio", "sound", "hang", "music"].includes(type)) return "audio";
  if (["3d", "model", "models", "model3d"].includes(type)) return "3d";
  return "";
}

function inferAssetType(file) {
  const mime = String(file?.mimetype || "");
  const ext = getExt(file?.originalname);
  if (TYPE_CONFIG.image.accepts(mime) || TYPE_CONFIG.image.extensions.has(ext)) return "image";
  if (TYPE_CONFIG.audio.accepts(mime) || TYPE_CONFIG.audio.extensions.has(ext)) return "audio";
  if (TYPE_CONFIG["3d"].accepts(mime) || TYPE_CONFIG["3d"].extensions.has(ext)) return "3d";
  return "";
}

function getExt(nameOrUrl = "") {
  const clean = String(nameOrUrl).split("?")[0].split("#")[0];
  return path.extname(clean).replace(".", "").toLowerCase();
}

function contentTypeFor(ext, fallback = "application/octet-stream") {
  return DEFAULT_CONTENT_TYPES[ext] || fallback;
}

function safeFileName(name = "asset") {
  return String(name || "asset")
    .replace(/[^\w.\-]+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 120);
}

function safeTags(tags) {
  if (Array.isArray(tags)) return tags.map((tag) => String(tag).trim()).filter(Boolean).slice(0, 12);
  if (typeof tags === "string") return tags.split(",").map((tag) => tag.trim()).filter(Boolean).slice(0, 12);
  return [];
}

function keyFor(userId, type, filename, folder = "assets") {
  const ext = getExt(filename) || (type === "image" ? "png" : type === "audio" ? "mp3" : "glb");
  const base = safeFileName(path.basename(filename, path.extname(filename)) || "asset");
  return `marketplace/${folder}/${userId}/${Date.now()}_${crypto.randomUUID()}_${base}.${ext}`;
}

function toMillis(value) {
  if (!value) return null;
  if (typeof value === "number") return value;
  if (value instanceof Date) return value.getTime();
  if (typeof value?.toMillis === "function") return value.toMillis();
  if (typeof value?.toDate === "function") return value.toDate().getTime();
  return null;
}

async function getOptionalUserId(req) {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) return null;
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    return decoded.uid || null;
  } catch {
    return null;
  }
}

async function getOwnedAssetIds(userId) {
  if (!userId) return new Set();
  const snap = await admin.firestore()
    .collection(MARKETPLACE_COLLECTIONS.purchases)
    .where("buyerId", "==", userId)
    .limit(500)
    .get();
  return new Set(snap.docs.map((doc) => doc.data().assetId).filter(Boolean));
}

async function assetForClient(doc, ownedIds = new Set()) {
  let data = doc.data ? doc.data() : doc;
  const id = doc.id || data.id;

  if (
    doc.ref &&
    data.type === "3d" &&
    data.tripo?.importStatus === "pending" &&
    data.tripo?.importTaskId
  ) {
    const historySnap = await admin.firestore()
      .collection("tripo_history")
      .where("taskId", "==", data.tripo.importTaskId)
      .limit(10)
      .get();
    const succeededHistory = historySnap.docs.find((historyDoc) => {
      const history = historyDoc.data();
      return history.userId === data.ownerId && history.status === "succeeded";
    });

    if (succeededHistory) {
      data = {
        ...data,
        tripo: {
          ...(data.tripo || {}),
          compatible: true,
          importStatus: "succeeded",
          sourceHistoryId: succeededHistory.id,
        },
      };
      doc.ref.update({
        tripo: data.tripo,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(() => {});
    }
  }

  const asset = normalizeAssetForClient(id, data);
  const previewKey = data.preview?.key || data.storage?.thumbKey || (data.type === "image" ? data.storage?.key : null);

  if (previewKey) {
    asset.previewUrl = await storageService.getSignedUrl(previewKey, 3600);
  }
  asset.hasPreview = Boolean(previewKey);
  asset.owned = ownedIds.has(id);
  asset.downloadOnly = data.type === "3d" && data.tripo?.compatible !== true;
  return asset;
}

async function createImageThumb(buffer, userId, sourceName) {
  const thumbBuffer = await sharp(buffer)
    .resize(520, 520, { fit: "inside", withoutEnlargement: true })
    .webp({ quality: 82 })
    .toBuffer();
  const thumbKey = `marketplace/previews/${userId}/${Date.now()}_${crypto.randomUUID()}_${safeFileName(sourceName)}.webp`;
  await storageService.uploadFile(thumbBuffer, thumbKey, "image/webp");
  return thumbKey;
}

async function startTripoImportForUpload(file, userId) {
  const ext = getExt(file.originalname);
  try {
    const uploadedObject = await getTripoClient().uploadFileObject(
      file.buffer,
      file.originalname,
      file.mimetype || contentTypeFor(ext),
      ext,
    );

    const taskId = await taskService.create({
      type: "import_model",
      file: {
        object: {
          bucket: uploadedObject.bucket,
          key: uploadedObject.key,
        },
      },
    }, {});

    registerForRecovery(taskId, userId, "import_model", null, file.originalname, {
      marketplaceUpload: true,
    });

    return {
      compatible: false,
      importStatus: "pending",
      importTaskId: taskId,
      message: "Tripo import ellenorzes elindult",
    };
  } catch (err) {
    return {
      compatible: false,
      importStatus: "failed",
      importError: err.message,
      message: "Csak letolteskent publikalhato, a Tripo import nem sikerult",
    };
  }
}

async function copyB2Object(sourceKey, targetKey, contentType) {
  const buffer = await storageService.getFileBuffer(sourceKey);
  await storageService.uploadFile(buffer, targetKey, contentType);
  return { key: targetKey, size: buffer.length };
}

async function downloadExternalAsset(url) {
  const response = await axios.get(url, {
    responseType: "arraybuffer",
    timeout: 120_000,
    maxContentLength: 260 * 1024 * 1024,
    headers: { "User-Agent": "LudusGen-Marketplace/1.0" },
  });
  return {
    buffer: Buffer.from(response.data),
    contentType: response.headers["content-type"] || "application/octet-stream",
  };
}

async function copyFromHistory(userId, assetType, sourceCollection, sourceId) {
  const db = admin.firestore();
  const collectionName = sourceCollection || (
    assetType === "image" ? "generated_images" :
    assetType === "audio" ? "audio_history" :
    "tripo_history"
  );
  const ref = db.collection(collectionName).doc(sourceId);
  const snap = await ref.get();

  if (!snap.exists) {
    throw Object.assign(new Error("Forras elem nem talalhato"), { status: 404 });
  }

  const data = snap.data();
  if (data.userId !== userId) {
    throw Object.assign(new Error("Nincs jogosultsag ehhez a history elemhez"), { status: 403 });
  }

  if (assetType === "image") {
    const sourceKey = data.full_key || data.storageKey || data.b2_key;
    if (!sourceKey) throw Object.assign(new Error("A kep fajlja nem masolhato"), { status: 400 });
    const ext = getExt(sourceKey) || "png";
    const fileName = `ludusgen_image_${sourceId}.${ext}`;
    const targetKey = keyFor(userId, "image", fileName, "assets");
    const copied = await copyB2Object(sourceKey, targetKey, contentTypeFor(ext, "image/png"));
    let thumbKey = null;
    if (data.thumb_key) {
      try {
        thumbKey = `marketplace/previews/${userId}/${Date.now()}_${crypto.randomUUID()}_${sourceId}.webp`;
        await copyB2Object(data.thumb_key, thumbKey, "image/webp");
      } catch {
        thumbKey = null;
      }
    }

    return {
      storage: {
        key: copied.key,
        thumbKey,
        fileName,
        contentType: contentTypeFor(ext, "image/png"),
        size: copied.size,
      },
      source: {
        kind: "history",
        collection: collectionName,
        id: sourceId,
        prompt: data.prompt || "",
      },
      tripo: { compatible: false, importStatus: "not_applicable" },
    };
  }

  if (assetType === "audio") {
    const sourceKey = data.storageKey || data.b2_key || data.key;
    if (!sourceKey) throw Object.assign(new Error("Az audio fajl nem masolhato"), { status: 400 });
    const ext = getExt(sourceKey) || data.fileFormat || "mp3";
    const fileName = data.fileName || `ludusgen_audio_${sourceId}.${ext}`;
    const targetKey = keyFor(userId, "audio", fileName, "assets");
    const contentType = data.contentType || contentTypeFor(ext, "audio/mpeg");
    const copied = await copyB2Object(sourceKey, targetKey, contentType);

    return {
      storage: {
        key: copied.key,
        fileName,
        contentType,
        size: copied.size,
      },
      source: {
        kind: "history",
        collection: collectionName,
        id: sourceId,
        audioKind: data.type || "audio",
        prompt: data.prompt || "",
      },
      tripo: { compatible: false, importStatus: "not_applicable" },
    };
  }

  const sourceKey = data.b2_key || data.storageKey || data.key;
  const sourceUrl = data.model_url || data.url;
  let buffer;
  let contentType = "model/gltf-binary";
  let ext = getExt(sourceKey || sourceUrl) || "glb";

  if (sourceKey) {
    buffer = await storageService.getFileBuffer(sourceKey);
    contentType = contentTypeFor(ext, "model/gltf-binary");
  } else if (sourceUrl?.includes("/api/trellis/model/")) {
    const filename = sourceUrl.split("/api/trellis/model/").pop().split("?")[0];
    const trellisKey = `trellis/${filename}`;
    buffer = await storageService.getFileBuffer(trellisKey);
    ext = getExt(filename) || "glb";
    contentType = contentTypeFor(ext, "model/gltf-binary");
  } else if (/^https?:\/\//.test(sourceUrl || "")) {
    const downloaded = await downloadExternalAsset(sourceUrl);
    buffer = downloaded.buffer;
    contentType = downloaded.contentType;
  } else {
    throw Object.assign(new Error("A 3D history fajl nem masolhato"), { status: 400 });
  }

  const fileName = data.params?.filename || data.prompt || `ludusgen_model_${sourceId}.${ext}`;
  const targetKey = keyFor(userId, "3d", fileName, "assets");
  await storageService.uploadFile(buffer, targetKey, contentType);

  return {
    storage: {
      key: targetKey,
      fileName: safeFileName(fileName.endsWith(`.${ext}`) ? fileName : `${fileName}.${ext}`),
      contentType,
      size: buffer.length,
    },
    source: {
      kind: "history",
      collection: collectionName,
      id: sourceId,
      taskId: data.taskId || null,
      prompt: data.prompt || "",
    },
    tripo: {
      compatible: true,
      importStatus: "succeeded",
      importTaskId: data.taskId || null,
      sourceHistoryId: sourceId,
    },
    sourceRef: ref,
  };
}

export async function listMarketplaceAssets(req, res) {
  try {
    const viewerId = await getOptionalUserId(req);
    const ownedIds = await getOwnedAssetIds(viewerId);
    const requestedType = normalizeAssetType(req.query.type);
    const qText = String(req.query.q || "").trim().toLowerCase();
    const minPrice = req.query.minPrice ? Number(req.query.minPrice) : null;
    const maxPrice = req.query.maxPrice ? Number(req.query.maxPrice) : null;
    const ownership = String(req.query.ownership || "all").toLowerCase();
    const tripo = String(req.query.tripo || "all").toLowerCase();
    const sort = String(req.query.sort || "featured").toLowerCase();

    const db = admin.firestore();
    const snap = await db.collection(MARKETPLACE_COLLECTIONS.assets)
      .where("status", "==", "published")
      .limit(300)
      .get();

    let docs = snap.docs.filter((doc) => {
      const data = doc.data();
      if (requestedType && data.type !== requestedType) return false;
      if (qText) {
        const hay = [
          data.title,
          data.description,
          data.ownerName,
          ...(Array.isArray(data.tags) ? data.tags : []),
        ].join(" ").toLowerCase();
        if (!hay.includes(qText)) return false;
      }
      if (minPrice != null && Number(data.priceCredits || 0) < minPrice) return false;
      if (maxPrice != null && Number(data.priceCredits || 0) > maxPrice) return false;
      if (ownership === "owned" && !ownedIds.has(doc.id)) return false;
      if (ownership === "not_owned" && ownedIds.has(doc.id)) return false;
      if (tripo === "compatible" && !(data.type === "3d" && data.tripo?.compatible === true)) return false;
      if (tripo === "download_only" && !(data.type === "3d" && data.tripo?.compatible !== true)) return false;
      return true;
    });

    docs = docs.sort((a, b) => {
      const ad = a.data();
      const bd = b.data();
      if (sort === "newest") return (toMillis(bd.createdAt) || bd.ts || 0) - (toMillis(ad.createdAt) || ad.ts || 0);
      if (sort === "price_asc") return Number(ad.priceCredits || 0) - Number(bd.priceCredits || 0);
      if (sort === "price_desc") return Number(bd.priceCredits || 0) - Number(ad.priceCredits || 0);
      if (sort === "most_bought" || sort === "popular") return Number(bd.metrics?.purchaseCount || 0) - Number(ad.metrics?.purchaseCount || 0);
      return Number(bd.featuredScore || 0) - Number(ad.featuredScore || 0);
    });

    const assets = await Promise.all(docs.map((doc) => assetForClient(doc, ownedIds)));
    res.json({ success: true, assets, ownedAssetIds: [...ownedIds], sort: sort || "featured" });
  } catch (err) {
    console.error("[Marketplace] list error:", err);
    res.status(500).json({ success: false, message: "Marketplace lista betoltese sikertelen" });
  }
}

export async function getMarketplaceAsset(req, res) {
  try {
    const viewerId = await getOptionalUserId(req);
    const ownedIds = await getOwnedAssetIds(viewerId);
    const ref = admin.firestore().collection(MARKETPLACE_COLLECTIONS.assets).doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ success: false, message: "Asset nem talalhato" });

    if (snap.data().status === "published") {
      ref.update({
        "metrics.viewCount": admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(() => {});
    }

    const asset = await assetForClient(snap, ownedIds);
    res.json({ success: true, asset });
  } catch (err) {
    console.error("[Marketplace] detail error:", err);
    res.status(500).json({ success: false, message: "Asset betoltese sikertelen" });
  }
}

export async function uploadMarketplaceAsset(req, res) {
  try {
    const userId = req.user?.uid || req.userId;
    const file = req.file;
    if (!file) return res.status(400).json({ success: false, message: "Hianyzo fajl" });

    const assetType = normalizeAssetType(req.body.assetType) || inferAssetType(file);
    const config = TYPE_CONFIG[assetType];
    if (!config) return res.status(400).json({ success: false, message: "Ismeretlen asset tipus" });
    if (file.size > config.maxBytes) return res.status(400).json({ success: false, message: "Tul nagy fajl" });

    const ext = getExt(file.originalname);
    if (!config.extensions.has(ext)) {
      return res.status(400).json({ success: false, message: `Nem tamogatott fajltipus: .${ext}` });
    }

    const storageKey = keyFor(userId, assetType, file.originalname, "uploads");
    const contentType = file.mimetype || contentTypeFor(ext);
    await storageService.uploadFile(file.buffer, storageKey, contentType);

    let thumbKey = null;
    if (assetType === "image") {
      thumbKey = await createImageThumb(file.buffer, userId, file.originalname);
    }

    const tripo = assetType === "3d"
      ? await startTripoImportForUpload(file, userId)
      : { compatible: false, importStatus: "not_applicable" };

    res.json({
      success: true,
      upload: {
        assetType,
        storage: {
          key: storageKey,
          thumbKey,
          fileName: safeFileName(file.originalname),
          contentType,
          size: file.size,
        },
        tripo,
      },
    });
  } catch (err) {
    console.error("[Marketplace] upload error:", err);
    res.status(500).json({ success: false, message: err.message || "Feltoltes sikertelen" });
  }
}

export async function createMarketplaceAsset(req, res) {
  try {
    const userId = req.user?.uid || req.userId;
    const body = req.body || {};
    const title = String(body.title || "").trim();
    const description = String(body.description || "").trim();
    const assetType = normalizeAssetType(body.assetType || body.type);
    const priceCredits = Number(body.priceCredits);

    if (!title) return res.status(400).json({ success: false, message: "Hianyzo cim" });
    if (!TYPE_CONFIG[assetType]) return res.status(400).json({ success: false, message: "Ismeretlen asset tipus" });
    if (!Number.isInteger(priceCredits) || priceCredits < 20) {
      return res.status(400).json({ success: false, message: "Az ar legalabb 20 kredit es egesz szam legyen" });
    }

    let sourceBundle;
    const sourceMode = String(body.sourceMode || body.sourceType || "upload").toLowerCase();
    if (sourceMode === "history") {
      sourceBundle = await copyFromHistory(userId, assetType, body.sourceCollection, body.sourceId);
    } else {
      const upload = body.upload || body.uploadResult || {};
      const storage = upload.storage || body.storage || {};
      if (!storage.key || !String(storage.key).startsWith(`marketplace/uploads/${userId}/`)) {
        return res.status(400).json({ success: false, message: "Ervenytelen feltoltesi hivatkozas" });
      }
      sourceBundle = {
        storage: {
          key: storage.key,
          thumbKey: storage.thumbKey || null,
          fileName: storage.fileName || "asset",
          contentType: storage.contentType || "application/octet-stream",
          size: Number(storage.size || 0),
        },
        source: { kind: "upload" },
        tripo: upload.tripo || body.tripo || (assetType === "3d"
          ? { compatible: false, importStatus: "failed" }
          : { compatible: false, importStatus: "not_applicable" }),
      };
    }

    const db = admin.firestore();
    const userDoc = await db.collection("users").doc(userId).get();
    const userData = userDoc.exists ? userDoc.data() : {};
    const now = Date.now();
    const assetRef = db.collection(MARKETPLACE_COLLECTIONS.assets).doc();
    const asset = {
      ownerId: userId,
      ownerEmail: req.userEmail || req.user?.email || userData.email || "",
      ownerName: userData.displayName || userData.name || req.user?.email || "LudusGen alkoto",
      ownerAvatar: userData.profilePicture || "",
      title,
      description,
      type: assetType,
      priceCredits,
      tags: safeTags(body.tags),
      status: "published",
      storage: sourceBundle.storage,
      preview: {
        key: sourceBundle.storage.thumbKey || (assetType === "image" ? sourceBundle.storage.key : null),
        kind: assetType === "image" ? "image" : assetType === "audio" ? "waveform" : "model",
      },
      source: sourceBundle.source,
      tripo: assetType === "3d" ? sourceBundle.tripo : { compatible: false, importStatus: "not_applicable" },
      metrics: { purchaseCount: 0, viewCount: 0 },
      manualFeaturedBoost: 0,
      ts: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    asset.featuredScore = calculateFeaturedScore(asset, now);

    await assetRef.set(asset);

    if (assetType === "3d" && sourceBundle.sourceRef) {
      await sourceBundle.sourceRef.set({
        marketplaceLocked: true,
        marketplaceAssetId: assetRef.id,
        marketplacePublishedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
    }

    const createdSnap = await assetRef.get();
    const clientAsset = await assetForClient(createdSnap, new Set());
    res.status(201).json({ success: true, asset: clientAsset });
  } catch (err) {
    console.error("[Marketplace] create error:", err);
    res.status(err.status || 500).json({ success: false, message: err.message || "Publikalas sikertelen" });
  }
}

export async function updateMarketplaceAsset(req, res) {
  try {
    const userId = req.user?.uid || req.userId;
    const ref = admin.firestore().collection(MARKETPLACE_COLLECTIONS.assets).doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ success: false, message: "Asset nem talalhato" });
    const data = snap.data();
    if (data.ownerId !== userId) return res.status(403).json({ success: false, message: "Csak a feltolto modosithatja" });

    const patch = {};
    if (req.body.title != null) patch.title = String(req.body.title).trim();
    if (req.body.description != null) patch.description = String(req.body.description).trim();
    if (req.body.tags != null) patch.tags = safeTags(req.body.tags);
    if (req.body.priceCredits != null) {
      const priceCredits = Number(req.body.priceCredits);
      if (!Number.isInteger(priceCredits) || priceCredits < 20) {
        return res.status(400).json({ success: false, message: "Az ar legalabb 20 kredit legyen" });
      }
      patch.priceCredits = priceCredits;
    }
    if (["published", "hidden"].includes(req.body.status)) patch.status = req.body.status;

    const next = { ...data, ...patch };
    patch.featuredScore = calculateFeaturedScore(next);
    patch.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await ref.update(patch);

    const updated = await ref.get();
    res.json({ success: true, asset: await assetForClient(updated, new Set()) });
  } catch (err) {
    console.error("[Marketplace] update error:", err);
    res.status(500).json({ success: false, message: err.message || "Modositas sikertelen" });
  }
}

export async function purchaseMarketplaceAsset(req, res) {
  try {
    const result = await purchaseAsset(req.params.id, req.user?.uid || req.userId);
    res.json({ success: true, ...result });
  } catch (err) {
    console.error("[Marketplace] purchase error:", err.message);
    res.status(err.status || 500).json({
      success: false,
      message: err.message || "Vasarlas sikertelen",
      code: err.code,
      available: err.available,
      required: err.required,
    });
  }
}

export async function downloadMarketplaceAsset(req, res) {
  try {
    const userId = req.user?.uid || req.userId;
    const db = admin.firestore();
    const assetRef = db.collection(MARKETPLACE_COLLECTIONS.assets).doc(req.params.id);
    const assetDoc = await assetRef.get();
    if (!assetDoc.exists) return res.status(404).json({ success: false, message: "Asset nem talalhato" });

    const asset = assetDoc.data();
    const purchaseDoc = await db.collection(MARKETPLACE_COLLECTIONS.purchases)
      .doc(`${userId}_${req.params.id}`)
      .get();
    const canAccess = asset.ownerId === userId || purchaseDoc.exists;
    if (!canAccess) return res.status(403).json({ success: false, message: "Elobb meg kell vasarolnod az assetet" });

    const key = asset.storage?.key || asset.storageKey;
    if (!key) return res.status(404).json({ success: false, message: "Letoltheto fajl nem talalhato" });

    const signedUrl = req.query.inline === "1"
      ? await storageService.getSignedUrl(key, 3600)
      : await storageService.getSignedDownloadUrl(key, asset.storage?.fileName || `${asset.title || "asset"}.bin`, 3600);
    if (!signedUrl) return res.status(500).json({ success: false, message: "Letoltesi URL nem keszitheto" });

    res.redirect(signedUrl);
  } catch (err) {
    console.error("[Marketplace] download error:", err);
    res.status(500).json({ success: false, message: err.message || "Letoltes sikertelen" });
  }
}

export async function getMyMarketplaceLibrary(req, res) {
  try {
    const userId = req.user?.uid || req.userId;
    const db = admin.firestore();
    const snap = await db.collection(MARKETPLACE_COLLECTIONS.purchases)
      .where("buyerId", "==", userId)
      .limit(300)
      .get();

    const ownedIds = new Set(snap.docs.map((doc) => doc.data().assetId).filter(Boolean));
    const items = await Promise.all(snap.docs.map(async (doc) => {
      const purchase = doc.data();
      let asset = purchase.asset || null;
      if (purchase.assetId) {
        const assetSnap = await db.collection(MARKETPLACE_COLLECTIONS.assets).doc(purchase.assetId).get();
        if (assetSnap.exists) asset = await assetForClient(assetSnap, ownedIds);
      }
      return {
        id: doc.id,
        ...purchase,
        asset,
        createdAtMs: toMillis(purchase.createdAt),
      };
    }));

    items.sort((a, b) => (b.createdAtMs || 0) - (a.createdAtMs || 0));
    res.json({ success: true, items, ownedAssetIds: [...ownedIds] });
  } catch (err) {
    console.error("[Marketplace] library error:", err);
    res.status(500).json({ success: false, message: "Konyvtar betoltese sikertelen" });
  }
}
