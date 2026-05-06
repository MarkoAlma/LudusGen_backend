import crypto from "node:crypto";

export const SPRITE_CACHE_TTL_SECONDS = 24 * 60 * 60;

let redisClientPromise = null;

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");
}

export function buildSpriteCacheKey(request) {
  const cacheShape = {
    prompt: request.prompt,
    style: request.style,
    provider: request.provider || "auto",
    options: request.options || {},
    referenceImageHash: request.referenceImage ? sha256(request.referenceImage) : null,
  };
  return `sprite:v1:${sha256(stableStringify(cacheShape))}`;
}

export function sanitizeCachedSpritePayload(payload = {}) {
  return {
    provider: payload.provider || null,
    route: payload.route || null,
    images: Array.isArray(payload.images) ? payload.images : [],
    assets: payload.assets || null,
    elapsedSeconds: payload.elapsedSeconds || null,
  };
}

export async function getRedisClient(env = process.env) {
  if (!env.REDIS_URL || env.SPRITE_CACHE_ENABLED === "false") return null;
  if (!redisClientPromise) {
    redisClientPromise = import("ioredis")
      .then(async ({ default: Redis }) => {
        const client = new Redis(env.REDIS_URL, {
          lazyConnect: true,
          maxRetriesPerRequest: 1,
          enableOfflineQueue: false,
        });
        await client.connect();
        return client;
      })
      .catch((error) => {
        console.warn("[SpriteCache] Redis disabled:", error?.message || error);
        redisClientPromise = null;
        return null;
      });
  }
  return redisClientPromise;
}

export async function getCachedSpriteGeneration(request, { env = process.env } = {}) {
  const client = await getRedisClient(env);
  if (!client) return null;
  const key = buildSpriteCacheKey(request);
  const raw = await client.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function setCachedSpriteGeneration(request, payload, { env = process.env } = {}) {
  const client = await getRedisClient(env);
  if (!client) return false;
  const key = buildSpriteCacheKey(request);
  await client.set(key, JSON.stringify(sanitizeCachedSpritePayload(payload)), "EX", SPRITE_CACHE_TTL_SECONDS);
  return true;
}
