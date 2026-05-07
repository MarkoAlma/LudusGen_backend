import axios from "axios";

import {
  normalizeSpriteProviderImages,
  stripImageDataPrefix,
  toBase64ImagePayload,
} from "../lib/spriteRouting.js";

const PIXELLAB_BASE_URL = "https://api.pixellab.ai/v1";
const GODMODE_BASE_URL = "https://api.godmodeai.co";
const GODMODE_DEFAULT_PATH = "/v1/sprite/generate";
const SEGMIND_WORKFLOW_URL = "https://api.segmind.com/workflows/6836c47e3d5f6408be00bd26-v7";
const SEGMIND_API_BASE_URL = "https://api.segmind.com/v1";
const EXTERNAL_API_TIMEOUT_MS = 30_000;
const SEGMIND_POLL_MS = 7000;
const SEGMIND_MAX_POLLS = 26;
const SEGMIND_TRANSIENT_RETRY = 3;
const PIXELLAB_ROTATION_4 = ["south", "east", "north", "west"];
const PIXELLAB_ROTATION_8 = ["south", "south-east", "east", "north-east", "north", "north-west", "west", "south-west"];

export class SpriteProviderError extends Error {
  constructor(message, { status = 502, provider = "unknown", code = "SPRITE_PROVIDER_ERROR", details = null } = {}) {
    super(message);
    this.name = "SpriteProviderError";
    this.status = status;
    this.provider = provider;
    this.code = code;
    this.details = details;
  }
}

function joinUrl(base, path) {
  return `${String(base || "").replace(/\/+$/, "")}${path.startsWith("/") ? path : `/${path}`}`;
}

function requireApiKey(env, keys, provider) {
  const key = keys.map((name) => env[name]).find(Boolean);
  if (!key) {
    throw new SpriteProviderError(`${provider} API key is not configured.`, {
      status: 503,
      provider,
      code: "PROVIDER_NOT_CONFIGURED",
    });
  }
  return key;
}

async function getAxiosErrorDetails(error) {
  const status = error?.response?.status || null;
  const data = error?.response?.data;
  if (typeof data === "string") return { status, message: data.slice(0, 300), data };
  const message = data?.message || data?.error?.message || data?.error || error?.message;
  return { status, message, data };
}

function makePromptDescription(prompt, style) {
  return style ? `${prompt}, style: ${style}` : prompt;
}

function clampImageSize(imageSize = {}, max = 400, fallback = 128) {
  const clamp = (value) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(16, Math.round(parsed)));
  };
  return {
    width: clamp(imageSize.width),
    height: clamp(imageSize.height),
  };
}

function wantsPixellabAnimation(request) {
  const text = `${request.prompt} ${request.style} ${request.options.action}`.toLowerCase();
  return request.options.output === "animation" ||
    request.options.output === "animation_text" ||
    /\b(walk|run|attack|idle|jump|cycle|animate|animation)\b/.test(text);
}

export function buildPixellabSpriteRequest(request) {
  const referenceImage = toBase64ImagePayload(request.referenceImage);
  const options = request.options || {};
  const description = makePromptDescription(request.prompt, request.style);

  if (options.output === "animation_skeleton" || options.skeletonKeypoints?.length) {
    return {
      path: "/animate-with-skeleton",
      body: {
        image_size: clampImageSize(options.imageSize, 256, 64),
        reference_image: referenceImage,
        skeleton_keypoints: options.skeletonKeypoints || [],
        direction: options.direction || "south",
        view: options.view || "side",
        guidance_scale: Number(options.guidanceScale) || 4,
        init_image_strength: Number(options.initImageStrength) || 300,
        isometric: Boolean(options.isometric),
        oblique_projection: Boolean(options.obliqueProjection),
        seed: options.seed ?? 0,
      },
    };
  }

  if ((options.output === "rotation" || options.directionSet === "4-way" || options.directionSet === "8-way") && referenceImage) {
    return {
      path: "/rotate",
      body: {
        description,
        image_size: clampImageSize(options.imageSize, 128, 64),
        from_image: referenceImage,
        from_direction: options.fromDirection || options.direction || "south",
        to_direction: options.toDirection || "east",
        from_view: options.fromView || options.view || "side",
        to_view: options.toView || options.view || "side",
        image_guidance_scale: Number(options.imageGuidanceScale) || 7.5,
        isometric: Boolean(options.isometric),
        oblique_projection: Boolean(options.obliqueProjection),
        seed: options.seed ?? 0,
      },
    };
  }

  const shouldAnimate = wantsPixellabAnimation(request) && referenceImage;
  if (shouldAnimate) {
    return {
      path: "/animate-with-text",
      body: {
        image_size: clampImageSize(options.imageSize, 256, 64),
        description,
        action: options.action || "idle",
        direction: options.direction || "south",
        view: options.view || "side",
        text_guidance_scale: 8,
        image_guidance_scale: 1.4,
        n_frames: options.frameCount || 4,
        no_background: options.noBackground,
        reference_image: referenceImage,
        seed: options.seed ?? 0,
      },
    };
  }

  return {
    path: "/generate-image-pixflux",
    body: {
      description,
      image_size: clampImageSize(options.imageSize, 400, 128),
      no_background: options.noBackground,
      direction: options.direction || undefined,
      detail: options.detail || undefined,
      outline: options.outline || undefined,
      isometric: options.isometric || undefined,
      ...(referenceImage ? { init_image: referenceImage } : {}),
      ...(options.seed !== undefined ? { seed: options.seed } : {}),
    },
  };
}

export function buildGodModeSpriteRequest(request, path = GODMODE_DEFAULT_PATH) {
  const options = request.options || {};
  const output = options.output === "auto" ? "sprite_sheet" : options.output;
  const exportFormats = options.exportFormats?.length
    ? options.exportFormats
    : output === "spine"
      ? ["spine"]
      : output === "layered"
        ? ["layers", "png"]
        : ["png"];

  return {
    path,
    body: {
      prompt: request.prompt,
      style: request.style || undefined,
      mode: output,
      output,
      animation: options.action || options.animationPreset || undefined,
      animationPreset: options.animationPreset || undefined,
      directionSet: options.directionSet,
      autoRig: ["spine", "layered", "retarget", "animation"].includes(output),
      layeredExport: output === "layered" || exportFormats.includes("layers"),
      retargetAnimationId: options.retargetAnimationId || undefined,
      exportFormats,
      transparentBackground: options.noBackground,
      referenceImage: request.referenceImage ? stripImageDataPrefix(request.referenceImage) : undefined,
      options: {
        imageSize: options.imageSize,
        seed: options.seed,
      },
    },
  };
}

export function buildSegmindWorkflowPayload(request) {
  const payload = { Animation_Scene: request.prompt };
  if (request.referenceImage) payload.image = stripImageDataPrefix(request.referenceImage);
  return payload;
}

export function buildSegmindDirectPayload(request) {
  const options = request.options || {};
  return {
    prompt: makePromptDescription(request.prompt, request.style),
    steps: options.steps || 4,
    seed: options.seed,
    sampler_name: options.samplerName || "euler",
    scheduler: options.scheduler || "normal",
    samples: options.batchCount || 1,
    width: options.imageSize?.width || 1024,
    height: options.imageSize?.height || 1024,
    denoise: options.denoise ?? 1,
  };
}

function shouldUseSegmindDirectApi(request) {
  const model = String(request.options?.model || "").toLowerCase();
  if (request.referenceImage) return false;
  return model.includes("flux") || model.includes("sdxl") || request.options?.output === "batch" || request.options?.batchCount > 1;
}

function getSegmindDirectEndpoint(request, env = process.env) {
  const model = String(request.options?.model || "flux-schnell").toLowerCase();
  if (model.includes("fast-flux")) return env.SEGMIND_FAST_FLUX_URL || joinUrl(env.SEGMIND_API_BASE || SEGMIND_API_BASE_URL, "/fast-flux-schnell");
  if (model.includes("sdxl")) return env.SEGMIND_SDXL_URL || joinUrl(env.SEGMIND_API_BASE || SEGMIND_API_BASE_URL, "/sdxl1.0-txt2img");
  return env.SEGMIND_FLUX_URL || joinUrl(env.SEGMIND_API_BASE || SEGMIND_API_BASE_URL, "/flux-schnell");
}

function getPixellabRotationTargets(options = {}) {
  if (options.directionSet === "4-way") return PIXELLAB_ROTATION_4;
  if (options.directionSet === "8-way") return PIXELLAB_ROTATION_8;
  return [options.toDirection || "east"];
}

function aggregateSpriteUsage(usages = [], operationCount = 1) {
  const mergedUsage = {
    operationCount: Math.max(1, Number(operationCount) || 1),
  };

  for (const usage of usages) {
    if (!usage || typeof usage !== "object") continue;

    for (const [key, value] of Object.entries(usage)) {
      if (key === "operationCount") continue;

      const numericValue = Number(value);
      if (!Number.isFinite(numericValue)) continue;
      const nextValue = (mergedUsage[key] || 0) + numericValue;
      mergedUsage[key] = Math.round(nextValue * 1_000_000) / 1_000_000;
    }
  }

  return mergedUsage;
}

export async function generatePixellabSprite(request, { env = process.env, axiosClient = axios, httpsAgent = undefined } = {}) {
  const apiKey = requireApiKey(env, ["PIXELLAB_API_KEY", "PIXELLAB_TOKEN"], "pixellab");
  const baseUrl = env.PIXELLAB_API_BASE || PIXELLAB_BASE_URL;
  const { path, body } = buildPixellabSpriteRequest(request);

  try {
    const postPixellab = (payload) => axiosClient.post(joinUrl(baseUrl, path), payload, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: EXTERNAL_API_TIMEOUT_MS,
      httpsAgent,
    });
    const responses = [];
    if (path === "/rotate" && ["4-way", "8-way"].includes(request.options?.directionSet)) {
      for (const toDirection of getPixellabRotationTargets(request.options)) {
        responses.push(await postPixellab({ ...body, to_direction: toDirection }));
      }
    } else {
      responses.push(await postPixellab(body));
    }

    const output = responses.length === 1
      ? responses[0].data
      : responses.map((response) => response.data);
    const usage = aggregateSpriteUsage(
      responses.map((response) => response.data?.usage || null),
      responses.length,
    );
    return {
      provider: "pixellab",
      endpoint: path,
      images: normalizeSpriteProviderImages(output),
      output,
      usage,
      metadata: {
        mode: path === "/animate-with-text"
          ? "animation"
          : path === "/animate-with-skeleton"
            ? "skeleton_animation"
            : path === "/rotate"
              ? "rotation"
              : "sprite",
        rotationTargets: path === "/rotate" ? getPixellabRotationTargets(request.options) : undefined,
      },
    };
  } catch (error) {
    const details = await getAxiosErrorDetails(error);
    throw new SpriteProviderError(details.message || "PixelLab generation failed.", {
      status: details.status || 502,
      provider: "pixellab",
      details: details.data,
    });
  }
}

export async function generateGodModeSprite(request, { env = process.env, axiosClient = axios, httpsAgent = undefined } = {}) {
  const apiKey = requireApiKey(env, ["GODMODE_API_KEY", "GOD_MODE_API_KEY"], "godmode");
  const baseUrl = env.GODMODE_API_BASE || GODMODE_BASE_URL;
  const configuredPath = env.GODMODE_SPRITE_PATH || GODMODE_DEFAULT_PATH;
  const { path, body } = buildGodModeSpriteRequest(request, configuredPath);

  try {
    const response = await axiosClient.post(joinUrl(baseUrl, path), body, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: EXTERNAL_API_TIMEOUT_MS,
      httpsAgent,
    });

    return {
      provider: "godmode",
      endpoint: path,
      images: normalizeSpriteProviderImages(response.data),
      output: response.data,
      usage: response.data?.usage || null,
      metadata: {
        spine: response.data?.spine || response.data?.spineFiles || response.data?.files || null,
      },
    };
  } catch (error) {
    const details = await getAxiosErrorDetails(error);
    throw new SpriteProviderError(details.message || "God Mode AI generation failed.", {
      status: details.status || 502,
      provider: "godmode",
      details: details.data,
    });
  }
}

export async function generateSegmindSprite(
  request,
  {
    env = process.env,
    axiosClient = axios,
    httpsAgent = undefined,
    sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    pollMs = SEGMIND_POLL_MS,
    maxPolls = SEGMIND_MAX_POLLS,
  } = {},
) {
  const apiKey = requireApiKey(env, ["SEGMIND_API_KEY"], "segmind");
  if (shouldUseSegmindDirectApi(request)) {
    const endpoint = getSegmindDirectEndpoint(request, env);
    try {
      const response = await axiosClient.post(endpoint, buildSegmindDirectPayload(request), {
        headers: {
          "x-api-key": apiKey,
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        timeout: EXTERNAL_API_TIMEOUT_MS,
        httpsAgent,
      });

      return {
        provider: "segmind",
        endpoint,
        images: normalizeSpriteProviderImages(response.data),
        output: response.data,
        usage: response.data?.usage || null,
        metadata: {
          mode: "direct",
          model: request.options?.model || "flux-schnell",
        },
      };
    } catch (error) {
      const details = await getAxiosErrorDetails(error);
      throw new SpriteProviderError(details.message || "Segmind direct generation failed.", {
        status: details.status || 502,
        provider: "segmind",
        details: details.data,
      });
    }
  }

  const workflowUrl = env.SEGMIND_SPRITE_WORKFLOW_URL || SEGMIND_WORKFLOW_URL;
  const startedAt = Date.now();
  const payload = buildSegmindWorkflowPayload(request);

  let submitData;
  try {
    const submitResponse = await axiosClient.post(workflowUrl, payload, {
      headers: {
        "x-api-key": apiKey,
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: EXTERNAL_API_TIMEOUT_MS,
      httpsAgent,
    });
    submitData = submitResponse.data;
  } catch (error) {
    const details = await getAxiosErrorDetails(error);
    const status = details.status === 429 ? 429 : details.status === 402 ? 402 : details.status || 502;
    throw new SpriteProviderError(details.message || "Failed to submit job to Segmind.", {
      status,
      provider: "segmind",
      details: details.data,
    });
  }

  const { poll_url: pollUrl, id: jobId } = submitData || {};
  if (!pollUrl) {
    throw new SpriteProviderError("Segmind did not return a poll URL.", {
      provider: "segmind",
      details: submitData,
    });
  }

  let polls = 0;
  let consecutiveErrors = 0;
  while (polls < maxPolls) {
    await sleep(pollMs);
    polls += 1;

    let pollData = null;
    for (let attempt = 1; attempt <= SEGMIND_TRANSIENT_RETRY; attempt += 1) {
      try {
        const pollResponse = await axiosClient.get(pollUrl, {
          headers: { Authorization: `Bearer ${apiKey}` },
          timeout: 15000,
          httpsAgent,
        });
        pollData = pollResponse.data;
        consecutiveErrors = 0;
        break;
      } catch (error) {
        const details = await getAxiosErrorDetails(error);
        if (details.status === 429 && attempt < SEGMIND_TRANSIENT_RETRY) {
          await sleep(3000 * attempt);
          continue;
        }
        if (attempt === SEGMIND_TRANSIENT_RETRY) consecutiveErrors += 1;
      }
    }

    if (!pollData) {
      if (consecutiveErrors >= 4) {
        throw new SpriteProviderError("Lost connection to Segmind while polling.", {
          provider: "segmind",
        });
      }
      continue;
    }

    const { status, output, error } = pollData;
    if (status === "COMPLETED") {
      let parsed = output;
      if (typeof parsed === "string") {
        try {
          parsed = JSON.parse(parsed);
        } catch {
          parsed = output;
        }
      }

      return {
        provider: "segmind",
        endpoint: workflowUrl,
        images: normalizeSpriteProviderImages(parsed),
        output: parsed,
        usage: null,
        metadata: {
          jobId: jobId || null,
          pollCount: polls,
          elapsedSeconds: (Date.now() - startedAt) / 1000,
        },
      };
    }

    if (status === "FAILED" || status === "CANCELLED") {
      throw new SpriteProviderError(error || `Segmind generation ${String(status).toLowerCase()}.`, {
        status: 500,
        provider: "segmind",
        details: pollData,
      });
    }
  }

  throw new SpriteProviderError(`Segmind generation timed out after ${maxPolls} polls.`, {
    status: 504,
    provider: "segmind",
  });
}

export async function generateSpriteWithProvider(provider, request, dependencies = {}) {
  if (provider === "pixellab") return generatePixellabSprite(request, dependencies);
  if (provider === "godmode") return generateGodModeSprite(request, dependencies);
  if (provider === "segmind") return generateSegmindSprite(request, dependencies);
  throw new SpriteProviderError(`Unsupported sprite provider: ${provider}`, {
    status: 400,
    provider,
    code: "UNSUPPORTED_PROVIDER",
  });
}
