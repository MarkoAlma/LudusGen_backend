import axios from "axios";
import sharp from "sharp";

const MAX_ASSEMBLY_FRAMES = 64;
const MAX_SHEET_PIXELS = 4096 * 4096;

function clampPositiveInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.round(parsed);
}

function isDataImageUrl(value) {
  return typeof value === "string" && /^data:image\/[a-z0-9.+-]+;base64,/i.test(value);
}

function dataUrlToBuffer(value) {
  return Buffer.from(value.split(",")[1] || "", "base64");
}

async function imageUrlToBuffer(url, { axiosClient = axios } = {}) {
  if (isDataImageUrl(url)) return dataUrlToBuffer(url);
  if (!/^https?:\/\//i.test(url)) {
    throw new Error("Unsupported sprite image source.");
  }
  const response = await axiosClient.get(url, {
    responseType: "arraybuffer",
    timeout: 30_000,
  });
  return Buffer.from(response.data);
}

function chooseAtlasColumns(frameCount, options = {}) {
  const requested = clampPositiveInt(options.columns, 0);
  if (requested > 0) return Math.min(requested, frameCount);
  if (options.output === "animation" || options.output === "animation_text" || options.output === "animation_skeleton") {
    return frameCount;
  }
  if (options.directionSet === "4-way" || frameCount === 4) return Math.min(4, frameCount);
  if (options.directionSet === "8-way" || frameCount === 8) return Math.min(8, frameCount);
  return Math.min(frameCount, 8);
}

export function buildSpriteAtlas({
  frameCount,
  frameWidth,
  frameHeight,
  columns,
  provider,
  operation,
  requestId,
  mode,
} = {}) {
  const safeFrameCount = clampPositiveInt(frameCount, 1);
  const safeFrameWidth = clampPositiveInt(frameWidth, 128);
  const safeFrameHeight = clampPositiveInt(frameHeight, 128);
  const safeColumns = Math.max(1, Math.min(clampPositiveInt(columns, safeFrameCount), safeFrameCount));
  const rows = Math.ceil(safeFrameCount / safeColumns);

  return {
    version: 1,
    provider: provider || "unknown",
    operation: operation || "static_sprite",
    requestId: requestId || null,
    mode: mode || "metadata",
    image: {
      width: safeColumns * safeFrameWidth,
      height: rows * safeFrameHeight,
      frameWidth: safeFrameWidth,
      frameHeight: safeFrameHeight,
      columns: safeColumns,
      rows,
      frameCount: safeFrameCount,
    },
    frames: Array.from({ length: safeFrameCount }, (_, index) => ({
      name: `frame_${String(index).padStart(3, "0")}`,
      index,
      x: (index % safeColumns) * safeFrameWidth,
      y: Math.floor(index / safeColumns) * safeFrameHeight,
      w: safeFrameWidth,
      h: safeFrameHeight,
    })),
  };
}

export async function assembleSpriteSheetPng({
  images,
  options = {},
  axiosClient = axios,
  sharpLib = sharp,
} = {}) {
  const sources = Array.isArray(images) ? images.slice(0, MAX_ASSEMBLY_FRAMES) : [];
  if (sources.length === 0) return null;

  const frames = [];
  for (const source of sources) {
    const input = await imageUrlToBuffer(source, { axiosClient });
    const metadata = await sharpLib(input).metadata();
    const width = clampPositiveInt(metadata.width, options.imageSize?.width || 128);
    const height = clampPositiveInt(metadata.height, options.imageSize?.height || 128);
    frames.push({ input, width, height });
  }

  const frameWidth = Math.max(...frames.map((frame) => frame.width));
  const frameHeight = Math.max(...frames.map((frame) => frame.height));
  const columns = chooseAtlasColumns(frames.length, options);
  const rows = Math.ceil(frames.length / columns);
  const width = frameWidth * columns;
  const height = frameHeight * rows;

  if (width * height > MAX_SHEET_PIXELS) {
    throw new Error("Sprite sheet exceeds the safe assembly size.");
  }

  const composite = frames.map((frame, index) => ({
    input: frame.input,
    left: (index % columns) * frameWidth,
    top: Math.floor(index / columns) * frameHeight,
  }));

  const png = await sharpLib({
    create: {
      width,
      height,
      channels: 4,
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    },
  }).composite(composite).png().toBuffer();

  return {
    spriteSheet: `data:image/png;base64,${png.toString("base64")}`,
    frameWidth,
    frameHeight,
    columns,
    rows,
    frameCount: frames.length,
  };
}

export async function postProcessSpriteAssets({
  images,
  request,
  result,
  requestId,
  route,
  axiosClient = axios,
  sharpLib = sharp,
} = {}) {
  const options = request?.options || {};
  const frameCount = Math.max(1, Array.isArray(images) ? images.length : 0);
  const fallbackWidth = clampPositiveInt(options.imageSize?.width, 128);
  const fallbackHeight = clampPositiveInt(options.imageSize?.height, 128);
  const columns = chooseAtlasColumns(frameCount, options);
  const provider = result?.provider || route?.provider || "unknown";
  const operation = route?.operation || result?.metadata?.mode || options.output || "static_sprite";

  let assembled = null;
  let postProcessError = null;
  if (frameCount > 1) {
    try {
      assembled = await assembleSpriteSheetPng({
        images,
        options,
        axiosClient,
        sharpLib,
      });
    } catch (error) {
      postProcessError = error?.message || "Sprite post-processing failed.";
    }
  }

  const atlas = buildSpriteAtlas({
    frameCount,
    frameWidth: assembled?.frameWidth || fallbackWidth,
    frameHeight: assembled?.frameHeight || fallbackHeight,
    columns: assembled?.columns || columns,
    provider,
    operation,
    requestId,
    mode: assembled?.spriteSheet ? "assembled" : "metadata",
  });

  return {
    spriteSheet: assembled?.spriteSheet || null,
    atlas,
    postProcessError,
  };
}
