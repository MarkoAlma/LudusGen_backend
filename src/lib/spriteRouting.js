const PROMPT_MAX = 500;
const STYLE_MAX = 160;
const MIN_IMAGE_SIZE = 16;
const MAX_IMAGE_SIZE = 400;
const MAX_SEGMIND_IMAGE_SIZE = 2048;
const MAX_GODMODE_IMAGE_SIZE = 1024;
const MAX_BATCH_COUNT = 8;

export const SUPPORTED_SPRITE_PROVIDERS = ["pixellab", "godmode", "segmind"];

const OUTPUT_MODES = [
  "auto",
  "sprite",
  "sprite_sheet",
  "animation",
  "animation_text",
  "animation_skeleton",
  "spine",
  "layered",
  "retarget",
  "rotation",
  "batch",
];

const DIRECTIONS = [
  "north",
  "north-east",
  "east",
  "south-east",
  "south",
  "south-west",
  "west",
  "north-west",
];

const VIEWS = ["side", "low top-down", "high top-down", "isometric"];
const EXPORT_FORMATS = ["png", "sprite_sheet", "atlas_json", "spine", "layers"];

const PROVIDER_KEYWORDS = {
  pixellab: [
    "pixel art",
    "pixelart",
    "pixel",
    "retro",
    "8-bit",
    "8bit",
    "16-bit",
    "16bit",
    "sprite sheet",
    "walk cycle",
    "run cycle",
    "top-down",
    "isometric",
    "side-scroll",
    "side scroll",
    "side-scrolling",
    "side scrolling",
  ],
  godmode: [
    "spine",
    "rigged",
    "rigging",
    "auto-rig",
    "auto rig",
    "retarget",
    "layered",
    "modern",
    "smooth",
    "2d animation",
    "skeletal",
  ],
  segmind: [
    "anime",
    "cartoon",
    "illustrated",
    "illustration",
    "hand-drawn",
    "hand drawn",
    "fantasy",
    "manga",
  ],
};

function normalizeSearchText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[‐‑‒–—]/g, "-")
    .replace(/\s+/g, " ")
    .trim();
}

function clampNumber(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

function clampEvenNumber(value, min, max, fallback) {
  const clamped = clampNumber(value, min, max, fallback);
  if (clamped % 2 === 0) return clamped;
  return clamped >= max ? clamped - 1 : clamped + 1;
}

function normalizeProvider(provider) {
  const value = String(provider || "").toLowerCase().trim();
  if (!value || value === "auto") return null;
  if (!SUPPORTED_SPRITE_PROVIDERS.includes(value)) {
    throw new Error(`Unsupported sprite provider: ${provider}`);
  }
  return value;
}

export function classifySpriteRequest({ prompt = "", style = "", provider = null } = {}) {
  const explicitProvider = normalizeProvider(provider);
  if (explicitProvider) {
    return {
      provider: explicitProvider,
      strategy: "manual",
      confidence: 1,
      matchedKeywords: [],
      reason: "User selected provider override.",
    };
  }

  const haystack = normalizeSearchText(`${style} ${prompt}`);
  const scores = SUPPORTED_SPRITE_PROVIDERS.map((candidate) => {
    const matchedKeywords = PROVIDER_KEYWORDS[candidate].filter((keyword) =>
      haystack.includes(normalizeSearchText(keyword)),
    );

    return {
      provider: candidate,
      matchedKeywords,
      score: matchedKeywords.length,
    };
  });

  scores.sort((a, b) => b.score - a.score);
  const best = scores[0];

  if (best.score > 0) {
    return {
      provider: best.provider,
      strategy: "keyword",
      confidence: Math.min(0.95, 0.55 + best.score * 0.1),
      matchedKeywords: best.matchedKeywords,
      reason: `${best.provider} matched ${best.score} style keyword(s).`,
    };
  }

  return {
    provider: "segmind",
    strategy: "default",
    confidence: 0.25,
    matchedKeywords: [],
    reason: "No style keywords matched; Segmind is the general illustrated fallback.",
  };
}

export function normalizeSpriteGenerateRequest(body = {}) {
  const prompt = String(body.prompt ?? body.animationScene ?? "").trim();
  if (!prompt) throw new Error("prompt is required");
  if (prompt.length > PROMPT_MAX) throw new Error(`prompt must be <=${PROMPT_MAX} characters`);

  const provider = normalizeProvider(body.provider);
  const style = String(body.style || "").trim().slice(0, STYLE_MAX);
  const options = body.options && typeof body.options === "object" ? body.options : {};
  const imageSize = options.imageSize && typeof options.imageSize === "object" ? options.imageSize : {};
  const maxImageSize = provider === "segmind"
    ? MAX_SEGMIND_IMAGE_SIZE
    : provider === "godmode"
      ? MAX_GODMODE_IMAGE_SIZE
      : MAX_IMAGE_SIZE;

  const output = OUTPUT_MODES.includes(options.output)
    ? options.output
    : "auto";
  const direction = DIRECTIONS.includes(options.direction) ? options.direction : "south";
  const fromDirection = DIRECTIONS.includes(options.fromDirection) ? options.fromDirection : direction;
  const toDirection = DIRECTIONS.includes(options.toDirection) ? options.toDirection : "east";
  const view = VIEWS.includes(options.view) ? options.view : "side";
  const fromView = VIEWS.includes(options.fromView) ? options.fromView : view;
  const toView = VIEWS.includes(options.toView) ? options.toView : view;
  const exportFormats = Array.isArray(options.exportFormats)
    ? options.exportFormats.filter((format) => EXPORT_FORMATS.includes(format)).slice(0, 6)
    : [];
  const skeletonKeypoints = Array.isArray(options.skeletonKeypoints)
    ? options.skeletonKeypoints
        .filter((point) =>
          point &&
          typeof point.name === "string" &&
          Number.isFinite(Number(point.x)) &&
          Number.isFinite(Number(point.y)),
        )
        .slice(0, 80)
        .map((point) => ({
          name: point.name.slice(0, 40),
          x: Math.round(Number(point.x)),
          y: Math.round(Number(point.y)),
        }))
    : [];

  return {
    prompt,
    style,
    provider,
    referenceImage: body.referenceImage || body.characterImage || null,
    options: {
      output,
      action: typeof options.action === "string" ? options.action.trim().slice(0, 80) : "",
      directionSet: ["none", "4-way", "8-way"].includes(options.directionSet)
        ? options.directionSet
        : "none",
      noBackground: options.noBackground === false ? false : true,
      imageSize: {
        width: clampNumber(imageSize.width, MIN_IMAGE_SIZE, maxImageSize, 128),
        height: clampNumber(imageSize.height, MIN_IMAGE_SIZE, maxImageSize, 128),
      },
      seed: Number.isFinite(Number(options.seed)) ? Number(options.seed) : undefined,
      frameCount: clampEvenNumber(options.frameCount, 4, 16, 4),
      view,
      direction,
      fromDirection,
      toDirection,
      fromView,
      toView,
      isometric: Boolean(options.isometric),
      obliqueProjection: Boolean(options.obliqueProjection),
      model: typeof options.model === "string" ? options.model.trim().slice(0, 80) : "",
      batchCount: clampNumber(options.batchCount, 1, MAX_BATCH_COUNT, 1),
      steps: clampNumber(options.steps, 1, 50, 4),
      denoise: Math.min(1, Math.max(0, Number(options.denoise) || 1)),
      detail: typeof options.detail === "string" ? options.detail.trim().slice(0, 40) : "",
      outline: typeof options.outline === "string" ? options.outline.trim().slice(0, 60) : "",
      exportFormats,
      animationPreset: typeof options.animationPreset === "string" ? options.animationPreset.trim().slice(0, 80) : "",
      retargetAnimationId: typeof options.retargetAnimationId === "string" ? options.retargetAnimationId.trim().slice(0, 120) : "",
      skeletonKeypoints,
    },
  };
}

function isLikelyBase64(value) {
  return /^[A-Za-z0-9+/]{20,}={0,2}$/.test(value);
}

function pushUnique(target, seen, value) {
  if (!value || seen.has(value)) return;
  seen.add(value);
  target.push(value);
}

export function normalizeSpriteProviderImages(value, depth = 0, seen = new Set()) {
  const images = [];
  if (!value || depth > 8) return images;

  if (typeof value === "string") {
    if (value.startsWith("http") || value.startsWith("data:image")) {
      pushUnique(images, seen, value);
    } else if (isLikelyBase64(value)) {
      pushUnique(images, seen, `data:image/png;base64,${value}`);
    }
    return images;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      for (const image of normalizeSpriteProviderImages(item, depth + 1, seen)) {
        images.push(image);
      }
    }
    return images;
  }

  if (typeof value === "object") {
    if (typeof value.base64 === "string") {
      const mime = typeof value.mimeType === "string" && value.mimeType.startsWith("image/")
        ? value.mimeType
        : "image/png";
      pushUnique(images, seen, `data:${mime};base64,${value.base64}`);
    }

    for (const child of Object.values(value)) {
      for (const image of normalizeSpriteProviderImages(child, depth + 1, seen)) {
        images.push(image);
      }
    }
  }

  return images;
}

export function stripImageDataPrefix(image) {
  if (!image || typeof image !== "string") return "";
  return image.includes("base64,") ? image.split("base64,").pop() : image;
}

export function toBase64ImagePayload(image) {
  const base64 = stripImageDataPrefix(image);
  return base64 ? { type: "base64", base64 } : null;
}

export function parseSpriteProviderChoice(raw) {
  if (!raw || typeof raw !== "string") return null;
  try {
    const parsed = JSON.parse(raw.trim());
    const provider = normalizeProvider(parsed.provider);
    if (!provider) return null;
    const confidence = Math.min(1, Math.max(0, Number(parsed.confidence) || 0.5));
    return {
      provider,
      confidence,
      reason: typeof parsed.reason === "string" ? parsed.reason.slice(0, 180) : "Claude fallback selected provider.",
    };
  } catch {
    return null;
  }
}
