import admin from "firebase-admin";
import axios from "axios";
import crypto from "node:crypto";
import path from "node:path";
import { Readable } from "node:stream";
import sharp from "sharp";
import { storageService } from "../services/storageService.js";
import {
  MARKETPLACE_COLLECTIONS,
  calculateFeaturedScore,
  getVerifiedMarketplacePurchase,
  isVerifiedMarketplacePurchase,
  normalizeAssetForClient,
  purchaseAsset,
  sanitizePurchaseForClient,
} from "../services/marketplaceService.js";
import { getTripoClient } from "../lib/tripoClient.js";
import { taskService } from "../services/taskService.js";
import { registerTask as registerForRecovery } from "../services/taskRecoveryService.js";
import { createWatermarkedAudioPreview } from "../services/audioPreviewService.js";

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
  if (["image", "images", "asset", "assets"].includes(type)) return "image";
  if (["audio", "sound", "voice", "music"].includes(type)) return "audio";
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

function contentDisposition(type, filename) {
  const fallback = safeFileName(filename || "asset.bin").replace(/"/g, "") || "asset.bin";
  const encoded = encodeURIComponent(String(filename || fallback))
    .replace(/['()]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
  return `${type}; filename="${fallback}"; filename*=UTF-8''${encoded}`;
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

function safePreviewKey(key, ownerId, storageKey = null) {
  const value = String(key || "");
  if (!value) return null;
  if (storageKey && value === storageKey) return null;
  return value.startsWith(`marketplace/previews/${ownerId}/`) ? value : null;
}

function safePositiveDimension(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  const rounded = Math.round(number);
  return rounded > 0 && rounded <= 200_000 ? rounded : null;
}

function imageMetadataFromSharpMetadata(metadata = {}) {
  const rawWidth = safePositiveDimension(metadata.width);
  const rawHeight = safePositiveDimension(metadata.height);
  if (!rawWidth || !rawHeight) return null;

  const orientation = Number(metadata.orientation || 1);
  const shouldSwap = [5, 6, 7, 8].includes(orientation);
  const image = {
    width: shouldSwap ? rawHeight : rawWidth,
    height: shouldSwap ? rawWidth : rawHeight,
  };

  if (metadata.format) image.format = String(metadata.format);
  if (Number(metadata.pages || 0) > 1) image.animated = true;
  return { image };
}

function sanitizeImageMetadata(metadata = {}) {
  const source = metadata?.image || metadata || {};
  const width = safePositiveDimension(source.width);
  const height = safePositiveDimension(source.height);
  if (!width || !height) return null;

  const image = { width, height };
  if (source.format) image.format = String(source.format).slice(0, 24);
  if (source.animated === true) image.animated = true;
  return { image };
}

async function getImageMetadata(buffer) {
  const metadata = await sharp(buffer, { failOn: "none" }).metadata();
  return imageMetadataFromSharpMetadata(metadata);
}

async function getImageMetadataFromStorage(storageKey) {
  if (!storageKey) return null;
  const buffer = await storageService.getFileBuffer(storageKey);
  return getImageMetadata(buffer);
}

async function ensureImageMetadata(ref, data = {}) {
  if (data.type !== "image") return data;

  const existing = sanitizeImageMetadata(data.metadata);
  if (existing) return { ...data, metadata: existing };

  try {
    const metadata = await getImageMetadataFromStorage(data.storage?.key || data.storageKey);
    if (!metadata) return data;

    ref.update({
      metadata,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }).catch(() => {});
    return { ...data, metadata };
  } catch (err) {
    console.warn("[Marketplace] image metadata detection failed:", err.message);
    return data;
  }
}

function toMillis(value) {
  if (!value) return null;
  if (typeof value === "number") return value;
  if (value instanceof Date) return value.getTime();
  if (typeof value?.toMillis === "function") return value.toMillis();
  if (typeof value?.toDate === "function") return value.toDate().getTime();
  return null;
}

const DEFAULT_MARKETPLACE_PAGE_SIZE = 32;
const MAX_MARKETPLACE_PAGE_SIZE = 64;
const MARKETPLACE_CURSOR_VERSION = 1;

const MARKETPLACE_SORTS = {
  featured: { id: "featured", field: "featuredScore", direction: "desc" },
  newest: { id: "newest", field: "ts", direction: "desc" },
  price_asc: { id: "price_asc", field: "priceCredits", direction: "asc" },
  price_desc: { id: "price_desc", field: "priceCredits", direction: "desc" },
  most_bought: { id: "most_bought", field: "metrics.purchaseCount", direction: "desc" },
  popular: { id: "most_bought", field: "metrics.purchaseCount", direction: "desc" },
};

function parseMarketplacePageSize(value) {
  const size = Number(value);
  if (!Number.isFinite(size)) return DEFAULT_MARKETPLACE_PAGE_SIZE;
  return Math.min(MAX_MARKETPLACE_PAGE_SIZE, Math.max(1, Math.floor(size)));
}

function parseOptionalPrice(value, name) {
  if (value == null || value === "") return null;
  const price = Number(value);
  if (!Number.isFinite(price) || price < 0) {
    throw Object.assign(new Error(`Invalid ${name}`), { status: 400 });
  }
  return price;
}

function normalizeMarketplaceSort(value) {
  const key = String(value || "featured").toLowerCase();
  return MARKETPLACE_SORTS[key] || MARKETPLACE_SORTS.featured;
}

function encodeMarketplaceCursor(doc, sortConfig) {
  const payload = JSON.stringify({
    v: MARKETPLACE_CURSOR_VERSION,
    sort: sortConfig.id,
    id: doc.id,
  });
  return Buffer.from(payload, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeMarketplaceCursor(value, sortConfig) {
  const cursor = String(value || "").trim();
  if (!cursor) return null;

  try {
    const base64 = cursor.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const payload = JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
    if (
      payload?.v !== MARKETPLACE_CURSOR_VERSION ||
      payload?.sort !== sortConfig.id ||
      typeof payload?.id !== "string" ||
      payload.id.length > 180
    ) {
      throw new Error("Cursor does not match this marketplace query");
    }
    return payload;
  } catch (err) {
    throw Object.assign(new Error(err.message || "Invalid marketplace cursor"), { status: 400 });
  }
}

function matchesMarketplaceFilters(doc, filters) {
  const data = doc.data();
  if (data.status !== "published") return false;
  if (filters.requestedType && data.type !== filters.requestedType) return false;

  if (filters.qText) {
    const haystack = [
      data.title,
      data.description,
      data.ownerName,
      ...(Array.isArray(data.tags) ? data.tags : []),
    ].join(" ").toLowerCase();
    if (!haystack.includes(filters.qText)) return false;
  }

  const priceCredits = Number(data.priceCredits || 0);
  if (filters.minPrice != null && priceCredits < filters.minPrice) return false;
  if (filters.maxPrice != null && priceCredits > filters.maxPrice) return false;
  if (filters.ownership === "owned" && !filters.ownedIds.has(doc.id)) return false;
  if (filters.ownership === "not_owned" && filters.ownedIds.has(doc.id)) return false;
  if (filters.tripo === "compatible" && !(data.type === "3d" && data.tripo?.compatible === true)) return false;
  if (filters.tripo === "download_only" && !(data.type === "3d" && data.tripo?.compatible !== true)) return false;
  return true;
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

async function getOwnedAssetIds(userId, { verifyAssets = true } = {}) {
  if (!userId) return new Set();
  const db = admin.firestore();
  const snap = await admin.firestore()
    .collection(MARKETPLACE_COLLECTIONS.purchases)
    .where("buyerId", "==", userId)
    .limit(500)
    .get();
  const ownedIds = new Set();

  if (!verifyAssets) {
    snap.docs.forEach((doc) => {
      const purchase = doc.data();
      if (
        purchase?.buyerId === userId &&
        purchase?.assetId &&
        purchase?.status === "completed" &&
        purchase?.serverVerified === true
      ) {
        ownedIds.add(purchase.assetId);
      }
    });
    return ownedIds;
  }

  await Promise.all(snap.docs.map(async (doc) => {
    const purchase = doc.data();
    const assetId = purchase.assetId;
    if (!assetId) return;

    const assetSnap = await db.collection(MARKETPLACE_COLLECTIONS.assets).doc(assetId).get();
    if (!assetSnap.exists) return;
    if (isVerifiedMarketplacePurchase(purchase, { buyerId: userId, assetId, asset: assetSnap.data() })) {
      ownedIds.add(assetId);
    }
  }));

  return ownedIds;
}

function extractPreviewUrlFromNode(node) {
  if (!node) return null;
  if (typeof node === "string") return node;
  if (Array.isArray(node)) {
    for (const entry of node) {
      const url = extractPreviewUrlFromNode(entry);
      if (url) return url;
    }
    return null;
  }
  if (typeof node !== "object") return null;

  return (
    node.url ||
    node.image_url ||
    node.rendered_image_url ||
    node.preview_url ||
    node.file_url ||
    node.href ||
    null
  );
}

function collectHistoryPreviewImageUrls(historyData = {}) {
  const params = historyData.params ?? {};
  const output = historyData.output ?? historyData.rawOutput ?? {};
  const directUrls = [
    ...(Array.isArray(historyData.image_urls) ? historyData.image_urls : []),
    ...(Array.isArray(historyData.previewImageUrls) ? historyData.previewImageUrls : []),
    ...(Array.isArray(historyData.preview_image_urls) ? historyData.preview_image_urls : []),
    ...(historyData.previewImageUrl ? [historyData.previewImageUrl] : []),
    ...(historyData.preview_image_url ? [historyData.preview_image_url] : []),
    ...(Array.isArray(params.previewImageUrls) ? params.previewImageUrls : []),
    ...(Array.isArray(params.preview_image_urls) ? params.preview_image_urls : []),
    ...(params.previewImageUrl ? [params.previewImageUrl] : []),
    ...(params.preview_image_url ? [params.preview_image_url] : []),
    ...(Array.isArray(output.previewImageUrls) ? output.previewImageUrls : []),
    ...(Array.isArray(output.preview_image_urls) ? output.preview_image_urls : []),
    ...(output.previewImageUrl ? [output.previewImageUrl] : []),
    ...(output.preview_image_url ? [output.preview_image_url] : []),
  ].filter(Boolean);

  const derivedUrls = [];
  const nestedCandidates = [
    historyData.rendered_image,
    historyData.rendered_images,
    historyData.preview_image,
    historyData.preview_images,
    params.rendered_image,
    params.rendered_images,
    params.preview_image,
    params.preview_images,
    output.rendered_image,
    output.rendered_images,
    output.preview_image,
    output.preview_images,
    output.image,
    output.images,
    output.generated_image,
    output.generated_images,
    output.multiview_images,
    output.views,
  ];

  for (const candidate of nestedCandidates) {
    if (!candidate) continue;
    if (Array.isArray(candidate)) {
      candidate.forEach((entry) => {
        const url = extractPreviewUrlFromNode(entry);
        if (url) derivedUrls.push(url);
      });
      continue;
    }

    const url = extractPreviewUrlFromNode(candidate);
    if (url) derivedUrls.push(url);
  }

  return [...new Set([...directUrls, ...derivedUrls])];
}

async function resolveMarketplace3dPreviewFallback(data = {}) {
  if (data.type !== "3d") return null;

  const sourceHistoryId = data.tripo?.sourceHistoryId || data.source?.id || null;
  const ownerId = data.ownerId || null;
  const db = admin.firestore();
  let historyData = null;

  if (sourceHistoryId) {
    const historySnap = await db.collection("tripo_history").doc(sourceHistoryId).get();
    if (historySnap.exists) {
      const sourceHistory = historySnap.data();
      if (!ownerId || sourceHistory?.userId === ownerId) {
        historyData = sourceHistory;
      }
    }
  }

  if (!historyData && data.tripo?.importTaskId && ownerId) {
    const historySnap = await db
      .collection("tripo_history")
      .where("taskId", "==", data.tripo.importTaskId)
      .limit(10)
      .get();
    const succeededHistory = historySnap.docs.find((historyDoc) => {
      const history = historyDoc.data();
      return history.userId === ownerId && history.status === "succeeded";
    });
    historyData = succeededHistory?.data() || null;
  }

  if (!historyData) return null;
  const previewUrls = collectHistoryPreviewImageUrls(historyData);
  return previewUrls[0] || null;
}

function getHistorySourceRef(db, assetType, source = {}, tripo = {}) {
  if (assetType !== "3d") return null;
  const collectionName = source?.collection || "tripo_history";
  const sourceId = source?.id || tripo?.sourceHistoryId || null;
  if (collectionName !== "tripo_history" || !sourceId) return null;
  return db.collection("tripo_history").doc(sourceId);
}

async function clearHistoryMarketplaceLock(historyRef) {
  if (!historyRef) return;
  await historyRef.set({
    marketplaceLocked: false,
    marketplaceAssetId: admin.firestore.FieldValue.delete(),
    marketplacePublishedAt: admin.firestore.FieldValue.delete(),
  }, { merge: true });
}

async function reconcileHistoryMarketplaceLock({ db, historyRef, historyData, ownerId }) {
  if (!historyRef || !historyData) return historyData;
  if (historyData.marketplaceLocked !== true) return historyData;

  const listedAssetId = historyData.marketplaceAssetId || null;
  if (!listedAssetId) {
    await clearHistoryMarketplaceLock(historyRef);
    return {
      ...historyData,
      marketplaceLocked: false,
      marketplaceAssetId: null,
      marketplacePublishedAt: null,
    };
  }

  const listedAssetSnap = await db.collection(MARKETPLACE_COLLECTIONS.assets).doc(listedAssetId).get();
  const listedAsset = listedAssetSnap.exists ? listedAssetSnap.data() : null;
  const stillPublished = Boolean(
    listedAsset &&
    listedAsset.ownerId === ownerId &&
    listedAsset.status === "published"
  );

  if (stillPublished) {
    throw Object.assign(new Error("This history item is already listed on the marketplace"), { status: 409 });
  }

  await clearHistoryMarketplaceLock(historyRef);
  return {
    ...historyData,
    marketplaceLocked: false,
    marketplaceAssetId: null,
    marketplacePublishedAt: null,
  };
}

async function assetForClient(doc, ownedIds = new Set(), viewerId = null) {
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
  const storageKey = data.storage?.key || data.storageKey;
  const previewKey = safePreviewKey(data.preview?.key || data.storage?.thumbKey, data.ownerId, storageKey);
  const viewerOwnsAsset = ownedIds.has(id);
  const viewerIsOwner = Boolean(viewerId && data.ownerId === viewerId);
  const viewerCanAccessFile = Boolean(viewerOwnsAsset || viewerIsOwner);

  if (previewKey) {
    asset.previewUrl = await storageService.getSignedUrl(previewKey, 3600);
  } else if (data.type === "3d") {
    const previewFallbackUrl = await resolveMarketplace3dPreviewFallback(data);
    if (previewFallbackUrl) asset.previewUrl = previewFallbackUrl;
  }
  asset.hasPreview = Boolean(previewKey || asset.previewUrl);
  asset.owned = viewerOwnsAsset;
  asset.viewerCanAccessFile = viewerCanAccessFile;
  asset.downloadOnly = data.type === "3d" && data.tripo?.compatible !== true;
  if (data.type === "3d" && viewerCanAccessFile) {
    const inlineModelUrl = `/api/marketplace/assets/${id}/download?inline=1`;
    asset.modelUrl = inlineModelUrl;
    asset.modelPreviewUrl = inlineModelUrl;
  }
  return asset;
}

const MARKETPLACE_PREVIEW_MAX_SIZE = 720;
const MARKETPLACE_WATERMARK_TEXT = "LudusGen Preview";
const MARKETPLACE_WATERMARK_MICROTEXT = "LUDUSGEN MARKETPLACE PREVIEW ONLY";

function escapeSvgText(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function createWatermarkNoise(width, height, seedText) {
  const count = Math.max(28, Math.round((width * height) / 15500));
  const marks = [];

  for (let index = 0; index < count; index += 1) {
    const hash = crypto.createHash("sha256")
      .update(`${seedText}:${width}:${height}:${index}`)
      .digest();
    const x = Math.round((hash[0] / 255) * width);
    const y = Math.round((hash[1] / 255) * height);
    const length = 6 + Math.round((hash[2] / 255) * 18);
    const angle = ((hash[3] / 255) * 360) * (Math.PI / 180);
    const x2 = Math.round(x + Math.cos(angle) * length);
    const y2 = Math.round(y + Math.sin(angle) * length);
    const opacity = (0.018 + (hash[4] / 255) * 0.026).toFixed(3);
    const stroke = hash[5] % 2 === 0 ? "#ffffff" : "#000000";

    marks.push(`<line x1="${x}" y1="${y}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-opacity="${opacity}" stroke-width="1" stroke-linecap="round" />`);
  }

  return marks.join("");
}

function createWatermarkSvg(width, height, seedText = "") {
  const fontSize = Math.max(18, Math.round(Math.min(width, height) * 0.044));
  const microFontSize = Math.max(7, Math.round(Math.min(width, height) * 0.014));
  const patternWidth = Math.max(260, Math.round(width * 0.44));
  const patternHeight = Math.max(116, Math.round(height * 0.18));
  const microPatternWidth = Math.max(210, Math.round(width * 0.31));
  const microPatternHeight = Math.max(58, Math.round(height * 0.085));
  const label = escapeSvgText(MARKETPLACE_WATERMARK_TEXT);
  const microLabel = escapeSvgText(MARKETPLACE_WATERMARK_MICROTEXT);
  const noise = createWatermarkNoise(width, height, seedText || label);

  return `
    <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <pattern id="wm-main" width="${patternWidth}" height="${patternHeight}" patternUnits="userSpaceOnUse" patternTransform="rotate(-31)">
          <text x="14" y="${Math.round(patternHeight * 0.52)}"
            font-family="Arial, Helvetica, sans-serif"
            font-size="${fontSize}"
            font-weight="900"
            letter-spacing="0.8"
            fill="#ffffff"
            fill-opacity="0.18"
            stroke="#000000"
            stroke-width="2.4"
            stroke-opacity="0.2">${label}</text>
          <text x="${Math.round(patternWidth * 0.22)}" y="${Math.round(patternHeight * 0.88)}"
            font-family="Arial, Helvetica, sans-serif"
            font-size="${Math.max(12, Math.round(fontSize * 0.54))}"
            font-weight="900"
            letter-spacing="1.2"
            fill="#000000"
            fill-opacity="0.1"
            stroke="#ffffff"
            stroke-width="1.4"
            stroke-opacity="0.12">${label}</text>
        </pattern>
        <pattern id="wm-micro" width="${microPatternWidth}" height="${microPatternHeight}" patternUnits="userSpaceOnUse" patternTransform="rotate(19)">
          <text x="6" y="${Math.round(microPatternHeight * 0.58)}"
            font-family="Arial, Helvetica, sans-serif"
            font-size="${microFontSize}"
            font-weight="800"
            letter-spacing="1.1"
            fill="#ffffff"
            fill-opacity="0.095"
            stroke="#000000"
            stroke-width="0.8"
            stroke-opacity="0.09">${microLabel}</text>
        </pattern>
        <pattern id="wm-fine-lines" width="56" height="56" patternUnits="userSpaceOnUse" patternTransform="rotate(-31)">
          <path d="M0 18H56 M0 46H56" fill="none" stroke="#ffffff" stroke-opacity="0.026" stroke-width="1" />
          <path d="M0 32H56" fill="none" stroke="#000000" stroke-opacity="0.02" stroke-width="1" />
        </pattern>
      </defs>
      <rect width="${width}" height="${height}" fill="url(#wm-fine-lines)" />
      <rect width="${width}" height="${height}" fill="url(#wm-main)" />
      <rect width="${width}" height="${height}" fill="url(#wm-micro)" />
      <g>${noise}</g>
      <rect x="0" y="${Math.max(0, height - 36)}" width="${width}" height="36" fill="#000000" fill-opacity="0.2" />
      <text x="${Math.max(16, width - 232)}" y="${Math.max(24, height - 13)}"
        font-family="Arial, Helvetica, sans-serif"
        font-size="13"
        font-weight="900"
        letter-spacing="1.5"
        fill="#ffffff"
        fill-opacity="0.76">${label}</text>
    </svg>
  `;
}

async function createImageThumb(buffer, userId, sourceName) {
  const resized = await sharp(buffer, { failOn: "none" })
    .rotate()
    .resize(MARKETPLACE_PREVIEW_MAX_SIZE, MARKETPLACE_PREVIEW_MAX_SIZE, { fit: "inside", withoutEnlargement: true })
    .toColorspace("srgb")
    .png()
    .toBuffer({ resolveWithObject: true });

  const watermarkSvg = createWatermarkSvg(resized.info.width, resized.info.height, sourceName);
  const thumbBuffer = await sharp(resized.data)
    .composite([{ input: Buffer.from(watermarkSvg), blend: "over" }])
    .webp({ quality: 74, effort: 5 })
    .toBuffer();

  const thumbKey = `marketplace/previews/${userId}/${Date.now()}_${crypto.randomUUID()}_${safeFileName(sourceName)}.webp`;
  await storageService.uploadFile(thumbBuffer, thumbKey, "image/webp");
  return thumbKey;
}

async function startTripoImportForUpload(file, userId) {
  const ext = getExt(file.originalname);
  try {
    const uploadedObject = await getTripoClient().uploadFileObjectFromPath(
      file.path,
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
      message: "Tripo import verification started",
    };
  } catch (err) {
    return {
      compatible: false,
      importStatus: "failed",
      importError: err.message,
      message: "Can only be published as download-only because the Tripo import failed",
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
  const defaultCollection = (
    assetType === "image" ? "generated_images" :
    assetType === "audio" ? "generated_audio" :
    "tripo_history"
  );
  const collectionName = String(sourceCollection || defaultCollection).trim();
  const allowedCollections = assetType === "image"
    ? new Set(["generated_images"])
    : assetType === "audio"
      ? new Set(["generated_audio", "audio_history"])
      : new Set(["tripo_history"]);

  if (!allowedCollections.has(collectionName)) {
    throw Object.assign(new Error("Unsupported history source"), { status: 400 });
  }

  const ref = db.collection(collectionName).doc(sourceId);
  const snap = await ref.get();

  if (!snap.exists) {
    throw Object.assign(new Error("Source item not found"), { status: 404 });
  }

  let data = snap.data();
  if (data.userId !== userId) {
    throw Object.assign(new Error("You do not have access to this history item"), { status: 403 });
  }

  if (assetType === "3d") {
    data = await reconcileHistoryMarketplaceLock({
      db,
      historyRef: getHistorySourceRef(db, assetType, { collection: collectionName, id: sourceId }),
      historyData: data,
      ownerId: userId,
    });
  }

  if (assetType === "image") {
    const sourceKey = data.full_key || data.storageKey || data.b2_key;
    if (!sourceKey) throw Object.assign(new Error("The image file cannot be copied"), { status: 400 });
    const ext = getExt(sourceKey) || "png";
    const fileName = `ludusgen_image_${sourceId}.${ext}`;
    const targetKey = keyFor(userId, "image", fileName, "assets");
    const contentType = contentTypeFor(ext, "image/png");
    const sourceBuffer = await storageService.getFileBuffer(sourceKey);
    await storageService.uploadFile(sourceBuffer, targetKey, contentType);
    const copied = { key: targetKey, size: sourceBuffer.length };
    const metadata = await getImageMetadata(sourceBuffer).catch(() => null);
    let thumbKey = null;
    try {
      thumbKey = await createImageThumb(sourceBuffer, userId, fileName);
    } catch {
      thumbKey = null;
    }

    return {
      storage: {
        key: copied.key,
        thumbKey,
        fileName,
        contentType,
        size: copied.size,
      },
      metadata,
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
    if (!sourceKey) throw Object.assign(new Error("The audio file cannot be copied"), { status: 400 });
    const ext = getExt(sourceKey) || data.fileFormat || "mp3";
    const fileName = data.fileName || `ludusgen_audio_${sourceId}.${ext}`;
    const targetKey = keyFor(userId, "audio", fileName, "assets");
    const contentType = data.contentType || contentTypeFor(ext, "audio/mpeg");
    const sourceBuffer = await storageService.getFileBuffer(sourceKey);
    await storageService.uploadFile(sourceBuffer, targetKey, contentType);
    const preview = await createWatermarkedAudioPreview(sourceBuffer, userId, fileName);

    return {
      storage: {
        key: targetKey,
        thumbKey: preview.key,
        fileName,
        contentType,
        size: sourceBuffer.length,
      },
      preview: {
        ...preview,
        kind: "audio",
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
    throw Object.assign(new Error("The 3D history file cannot be copied"), { status: 400 });
  }

  const fileName = data.params?.filename || data.prompt || `ludusgen_model_${sourceId}.${ext}`;
  const targetKey = keyFor(userId, "3d", fileName, "assets");
  await storageService.uploadFile(buffer, targetKey, contentType);

  // Prefer the Tripo preview image so marketplace cards show the actual model silhouette.
  let thumbKey = null;
  const previewImageUrl = collectHistoryPreviewImageUrls(data)[0] || null;
  if (previewImageUrl) {
    try {
      const { buffer: imgBuf } = await downloadExternalAsset(previewImageUrl);
      thumbKey = await createImageThumb(imgBuf, userId, `preview_${sourceId}`);
    } catch (err) {
      console.warn(`[Marketplace] 3D preview thumb failed for ${sourceId}:`, err.message);
    }
  }

  return {
    storage: {
      key: targetKey,
      thumbKey,
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
    const ownedIds = await getOwnedAssetIds(viewerId, { verifyAssets: false });
    const requestedType = normalizeAssetType(req.query.type);
    const qText = String(req.query.q || "").trim().toLowerCase().slice(0, 120);
    const minPrice = parseOptionalPrice(req.query.minPrice, "minPrice");
    const maxPrice = parseOptionalPrice(req.query.maxPrice, "maxPrice");
    const ownership = String(req.query.ownership || "all").toLowerCase();
    const tripo = String(req.query.tripo || "all").toLowerCase();
    const sortConfig = normalizeMarketplaceSort(req.query.sort);
    const pageSize = parseMarketplacePageSize(req.query.limit);

    if (minPrice != null && maxPrice != null && minPrice > maxPrice) {
      return res.status(400).json({ success: false, message: "minPrice cannot be greater than maxPrice" });
    }

    const allowedOwnership = new Set(["all", "owned", "not_owned"]);
    const allowedTripo = new Set(["all", "compatible", "download_only"]);
    if (!allowedOwnership.has(ownership)) {
      return res.status(400).json({ success: false, message: "Invalid ownership filter" });
    }
    if (!allowedTripo.has(tripo)) {
      return res.status(400).json({ success: false, message: "Invalid 3D compatibility filter" });
    }

    const db = admin.firestore();
    const assetsRef = db.collection(MARKETPLACE_COLLECTIONS.assets);
    const decodedCursor = decodeMarketplaceCursor(req.query.cursor, sortConfig);
    let cursorDoc = null;
    if (decodedCursor?.id) {
      cursorDoc = await assetsRef.doc(decodedCursor.id).get();
      if (!cursorDoc.exists) {
        return res.status(400).json({ success: false, message: "Marketplace cursor is no longer valid" });
      }
    }

    const filters = {
      requestedType,
      qText,
      minPrice,
      maxPrice,
      ownership,
      tripo,
      ownedIds,
    };
    const docs = [];
    const needsFilteredScan = Boolean(
      requestedType ||
      qText ||
      minPrice != null ||
      maxPrice != null ||
      ownership !== "all" ||
      tripo !== "all"
    );
    const batchSize = needsFilteredScan ? Math.max(pageSize * 3, 96) : pageSize + 1;
    let exhausted = false;
    let lastScannedDoc = cursorDoc;

    while (docs.length < pageSize + 1 && !exhausted) {
      let queryRef = assetsRef
        .orderBy(sortConfig.field, sortConfig.direction)
        .limit(batchSize);

      if (lastScannedDoc) {
        queryRef = queryRef.startAfter(lastScannedDoc);
      }

      const snap = await queryRef.get();
      if (snap.empty) {
        exhausted = true;
        break;
      }

      for (const doc of snap.docs) {
        lastScannedDoc = doc;
        if (matchesMarketplaceFilters(doc, filters)) {
          docs.push(doc);
          if (docs.length >= pageSize + 1) break;
        }
      }

      if (snap.size < batchSize) exhausted = true;
    }

    const pageDocs = docs.slice(0, pageSize);
    const assets = await Promise.all(pageDocs.map((doc) => assetForClient(doc, ownedIds, viewerId)));
    const nextCursor = pageDocs.length
      ? encodeMarketplaceCursor(pageDocs[pageDocs.length - 1], sortConfig)
      : null;

    res.json({
      success: true,
      assets,
      ownedAssetIds: [...ownedIds],
      sort: sortConfig.id,
      limit: pageSize,
      nextCursor,
      hasMore: docs.length > pageSize,
    });
  } catch (err) {
    console.error("[Marketplace] list error:", err);
    res.status(err.status || 500).json({ success: false, message: err.message || "Failed to load marketplace list" });
  }
}

export async function getMarketplaceAsset(req, res) {
  try {
    const viewerId = await getOptionalUserId(req);
    const ownedIds = await getOwnedAssetIds(viewerId);
    const ref = admin.firestore().collection(MARKETPLACE_COLLECTIONS.assets).doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ success: false, message: "Asset not found" });

    let data = snap.data();
    if (data.status !== "published") {
      if (!viewerId) return res.status(404).json({ success: false, message: "Asset not found" });
      const isOwner = data.ownerId === viewerId;
      const purchase = !isOwner ? await getVerifiedMarketplacePurchase(admin.firestore(), {
        buyerId: viewerId,
        assetId: req.params.id,
        asset: data,
      }) : null;
      if (!isOwner && !purchase) return res.status(404).json({ success: false, message: "Asset not found" });
    }

    data = await ensureImageMetadata(ref, data);

    if (data.status === "published") {
      ref.update({
        "metrics.viewCount": admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(() => {});
    }

    const asset = await assetForClient({ id: snap.id, ref, data: () => data }, ownedIds, viewerId);
    res.json({ success: true, asset });
  } catch (err) {
    console.error("[Marketplace] detail error:", err);
    res.status(500).json({ success: false, message: "Failed to load asset" });
  }
}

export async function uploadMarketplaceAsset(req, res) {
  const fs = await import("node:fs/promises");
  let filePath = null;

  try {
    const userId = req.user?.uid || req.userId;
    const file = req.file;
    if (!file) return res.status(400).json({ success: false, message: "Missing file" });

    filePath = file.path;

    const assetType = normalizeAssetType(req.body.assetType) || inferAssetType(file);
    const config = TYPE_CONFIG[assetType];
    if (!config) return res.status(400).json({ success: false, message: "Unknown asset type" });
    if (file.size > config.maxBytes) return res.status(400).json({ success: false, message: "File is too large" });

    const ext = getExt(file.originalname);
    if (!config.extensions.has(ext)) {
      return res.status(400).json({ success: false, message: `Unsupported file type: .${ext}` });
    }

    const storageKey = keyFor(userId, assetType, file.originalname, "uploads");
    const contentType = file.mimetype || contentTypeFor(ext);
    
    // Stream directly from disk to S3
    await storageService.uploadFileFromPath(filePath, storageKey, contentType);

    let thumbKey = null;
    let metadata = null;
    let preview = null;
    
    if (assetType === "image") {
      // For images, we can load them into memory since they are max 50MB
      const buffer = await fs.readFile(filePath);
      metadata = await getImageMetadata(buffer);
      thumbKey = await createImageThumb(buffer, userId, file.originalname);
    } else if (assetType === "audio") {
      // Audio is max 100MB, acceptable for short-lived buffer or ffmpeg
      const buffer = await fs.readFile(filePath);
      preview = await createWatermarkedAudioPreview(buffer, userId, file.originalname);
      thumbKey = preview.key;
    }

    // 3D files can be up to 250MB, so we pass the file path stream to Tripo
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
        preview,
        metadata,
        tripo,
      },
    });
  } catch (err) {
    console.error("[Marketplace] upload error:", err);
    res.status(500).json({ success: false, message: err.message || "Upload failed" });
  } finally {
    if (filePath) {
      const fs = await import("node:fs/promises");
      await fs.unlink(filePath).catch(() => {});
    }
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

    if (!title) return res.status(400).json({ success: false, message: "Missing title" });
    if (!TYPE_CONFIG[assetType]) return res.status(400).json({ success: false, message: "Unknown asset type" });
    if (!Number.isInteger(priceCredits) || priceCredits < 20) {
      return res.status(400).json({ success: false, message: "Price must be an integer and at least 20 credits" });
    }

    let sourceBundle;
    const sourceMode = String(body.sourceMode || body.sourceType || "upload").toLowerCase();
    if (sourceMode === "history") {
      sourceBundle = await copyFromHistory(userId, assetType, body.sourceCollection, body.sourceId);
    } else {
      const upload = body.upload || body.uploadResult || {};
      const storage = upload.storage || body.storage || {};
      if (!storage.key || !String(storage.key).startsWith(`marketplace/uploads/${userId}/`)) {
        return res.status(400).json({ success: false, message: "Invalid upload reference" });
      }
      let thumbKey = safePreviewKey(storage.thumbKey, userId);
      let preview = upload.preview || null;
      if (assetType === "audio" && !thumbKey) {
        const sourceBuffer = await storageService.getFileBuffer(storage.key);
        preview = await createWatermarkedAudioPreview(sourceBuffer, userId, storage.fileName || "audio.mp3");
        thumbKey = preview.key;
      }
      sourceBundle = {
        storage: {
          key: storage.key,
          thumbKey,
          fileName: storage.fileName || "asset",
          contentType: storage.contentType || "application/octet-stream",
          size: Number(storage.size || 0),
        },
        preview,
        metadata: assetType === "image"
          ? await getImageMetadataFromStorage(storage.key).catch(() => sanitizeImageMetadata(upload.metadata || body.metadata))
          : null,
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
      ownerName: userData.displayName || userData.name || req.user?.email || "LudusGen creator",
      ownerAvatar: userData.profilePicture || "",
      title,
      description,
      type: assetType,
      priceCredits,
      tags: safeTags(body.tags),
      status: "published",
      storage: sourceBundle.storage,
      preview: {
        key: safePreviewKey(sourceBundle.storage.thumbKey, userId),
        kind: assetType === "image" ? "image" : assetType === "audio" ? "audio" : "model",
        watermarked: assetType === "image" || assetType === "audio",
        ...(assetType === "audio" ? {
          contentType: sourceBundle.preview?.contentType || "audio/mpeg",
          fileName: sourceBundle.preview?.fileName || null,
          fullLength: sourceBundle.preview?.fullLength === true,
          watermarkIntervalSeconds: sourceBundle.preview?.watermarkIntervalSeconds || null,
        } : {}),
      },
      metadata: sourceBundle.metadata || null,
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
    const clientAsset = await assetForClient(createdSnap, new Set(), userId);
    res.status(201).json({ success: true, asset: clientAsset });
  } catch (err) {
    console.error("[Marketplace] create error:", err);
    res.status(err.status || 500).json({ success: false, message: err.message || "Publishing failed" });
  }
}

export async function updateMarketplaceAsset(req, res) {
  try {
    const userId = req.user?.uid || req.userId;
    const ref = admin.firestore().collection(MARKETPLACE_COLLECTIONS.assets).doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ success: false, message: "Asset not found" });
    const data = snap.data();
    if (data.ownerId !== userId) return res.status(403).json({ success: false, message: "Only the uploader can edit this asset" });

    const patch = {};
    if (req.body.title != null) patch.title = String(req.body.title).trim();
    if (req.body.description != null) patch.description = String(req.body.description).trim();
    if (req.body.tags != null) patch.tags = safeTags(req.body.tags);
    if (req.body.priceCredits != null) {
      const priceCredits = Number(req.body.priceCredits);
      if (!Number.isInteger(priceCredits) || priceCredits < 20) {
        return res.status(400).json({ success: false, message: "Price must be at least 20 credits" });
      }
      patch.priceCredits = priceCredits;
    }
    if (["published", "hidden"].includes(req.body.status)) patch.status = req.body.status;

    const next = { ...data, ...patch };
    patch.featuredScore = calculateFeaturedScore(next);
    patch.updatedAt = admin.firestore.FieldValue.serverTimestamp();
    await ref.update(patch);

    const updated = await ref.get();
    res.json({ success: true, asset: await assetForClient(updated, new Set(), userId) });
  } catch (err) {
    console.error("[Marketplace] update error:", err);
    res.status(500).json({ success: false, message: err.message || "Update failed" });
  }
}

export async function deleteMarketplaceAsset(req, res) {
  try {
    const userId = req.user?.uid || req.userId;
    const db = admin.firestore();
    const ref = db.collection(MARKETPLACE_COLLECTIONS.assets).doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ success: false, message: "Asset not found" });

    const data = snap.data();
    if (data.ownerId !== userId) {
      return res.status(403).json({ success: false, message: "Only the uploader can delete this asset" });
    }

    await ref.update({
      status: "deleted",
      deletedAt: admin.firestore.FieldValue.serverTimestamp(),
      deletedBy: userId,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    if (data.type === "3d") {
      const historyRef = getHistorySourceRef(db, data.type, data.source, data.tripo);
      if (historyRef) {
        const historySnap = await historyRef.get();
        if (historySnap.exists) {
          const historyData = historySnap.data() || {};
          if (!historyData.marketplaceAssetId || historyData.marketplaceAssetId === req.params.id) {
            await clearHistoryMarketplaceLock(historyRef);
          }
        }
      }
    }

    res.json({
      success: true,
      id: req.params.id,
      message: "Asset removed from marketplace list",
    });
  } catch (err) {
    console.error("[Marketplace] delete error:", err);
    res.status(500).json({ success: false, message: err.message || "Delete failed" });
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
      message: err.message || "Purchase failed",
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
    const isOwner = asset.ownerId === userId;
    if (!isOwner) {
      const purchase = await getVerifiedMarketplacePurchase(db, {
        buyerId: userId,
        assetId: req.params.id,
        asset,
      });
      if (!purchase) return res.status(403).json({ success: false, message: "You must purchase the asset first" });
    }

    const key = asset.storage?.key || asset.storageKey;
    if (!key) return res.status(404).json({ success: false, message: "Downloadable file not found" });

    const fileName = asset.storage?.fileName || `${asset.title || "asset"}.bin`;
    const fileObject = await storageService.getFileObject(key);
    const body = fileObject.Body;
    if (!body) return res.status(404).json({ success: false, message: "Downloadable file not found" });

    res.setHeader("Content-Type", fileObject.ContentType || asset.storage?.contentType || "application/octet-stream");
    res.setHeader("Content-Disposition", contentDisposition(req.query.inline === "1" ? "inline" : "attachment", fileName));
    res.setHeader("Cache-Control", "private, max-age=0, must-revalidate");
    if (fileObject.ContentLength != null) {
      res.setHeader("Content-Length", String(fileObject.ContentLength));
    }

    if (typeof body.pipe === "function") {
      body.on("error", (streamErr) => {
        console.error("[Marketplace] download stream error:", streamErr);
        if (!res.headersSent) res.status(500).end();
        else res.destroy(streamErr);
      });
      body.pipe(res);
      return;
    }

    if (typeof body.transformToWebStream === "function") {
      Readable.fromWeb(body.transformToWebStream()).pipe(res);
      return;
    }

    if (typeof body.transformToByteArray === "function") {
      res.end(Buffer.from(await body.transformToByteArray()));
      return;
    }

    res.status(500).json({ success: false, message: "Download stream could not be read" });
  } catch (err) {
    console.error("[Marketplace] download error:", err);
    res.status(500).json({ success: false, message: err.message || "Download failed" });
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

    const ownedIds = await getOwnedAssetIds(userId);
    const items = (await Promise.all(snap.docs.map(async (doc) => {
      const purchase = doc.data();
      if (!purchase.assetId) return null;

      const assetSnap = await db.collection(MARKETPLACE_COLLECTIONS.assets).doc(purchase.assetId).get();
      if (!assetSnap.exists) return null;
      if (!isVerifiedMarketplacePurchase(purchase, {
        buyerId: userId,
        assetId: purchase.assetId,
        asset: assetSnap.data(),
      })) {
        return null;
      }

      const asset = await assetForClient(assetSnap, ownedIds, userId);
      const safePurchase = sanitizePurchaseForClient({ id: doc.id, ...purchase });
      return {
        id: doc.id,
        ...safePurchase,
        asset,
        createdAtMs: toMillis(purchase.createdAt),
      };
    }))).filter(Boolean);

    items.sort((a, b) => (b.createdAtMs || 0) - (a.createdAtMs || 0));
    res.json({ success: true, items, ownedAssetIds: [...ownedIds] });
  } catch (err) {
    console.error("[Marketplace] library error:", err);
    res.status(500).json({ success: false, message: "Failed to load library" });
  }
}
