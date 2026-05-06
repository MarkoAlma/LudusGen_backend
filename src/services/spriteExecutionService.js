import { SpriteProviderError } from "./spriteProviderAdapters.js";

const FALLBACK_ORDER = ["pixellab", "godmode", "segmind"];

function errorCode(error) {
  return error?.code || error?.response?.status || error?.status || "PROVIDER_ERROR";
}

export function getSpriteFallbackChain(initialProvider, { openProviders = [] } = {}) {
  const start = FALLBACK_ORDER.includes(initialProvider)
    ? FALLBACK_ORDER.indexOf(initialProvider)
    : 0;
  const open = new Set(openProviders);
  return FALLBACK_ORDER.slice(start).filter((provider) => !open.has(provider));
}

export async function executeProviderWithRetry({
  provider,
  request,
  dependencies = {},
  callProvider,
  maxAttempts = 3,
  baseDelayMs = 750,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  logger = console.warn,
  requestId = "unknown",
} = {}) {
  const failures = [];

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const startedAt = Date.now();
    try {
      const result = await callProvider(provider, request, dependencies);
      return {
        ...result,
        attempts: attempt,
        failures,
      };
    } catch (error) {
      const elapsedMs = Date.now() - startedAt;
      const failure = {
        request_id: requestId,
        provider,
        attempt,
        error_code: errorCode(error),
        elapsed_ms: elapsedMs,
      };
      failures.push(failure);
      logger(JSON.stringify({ event: "sprite_provider_error", ...failure }));

      if (attempt >= maxAttempts) {
        const wrapped = error instanceof SpriteProviderError
          ? error
          : new SpriteProviderError(error?.message || "Sprite provider failed.", {
              provider,
              status: error?.status || 502,
              code: errorCode(error),
            });
        wrapped.failures = failures;
        throw wrapped;
      }

      await sleep(baseDelayMs * (2 ** (attempt - 1)));
    }
  }

  throw new SpriteProviderError("Sprite provider failed.", { provider });
}

export async function runSpriteGenerationWithFallback({
  initialProvider,
  request,
  dependencies = {},
  callProvider,
  maxAttempts = 3,
  openProviders = [],
  onProviderFailure = null,
  onProviderSuccess = null,
  sleep,
  logger = console.warn,
  requestId = "unknown",
} = {}) {
  const allFailures = [];
  const providers = getSpriteFallbackChain(initialProvider, { openProviders });

  if (providers.length === 0) {
    throw new SpriteProviderError("No sprite provider available.", {
      provider: initialProvider,
      code: "NO_PROVIDER_AVAILABLE",
      status: 503,
    });
  }

  for (const provider of providers) {
    try {
      const result = await executeProviderWithRetry({
        provider,
        request,
        dependencies,
        callProvider,
        maxAttempts,
        sleep,
        logger,
        requestId,
      });
      if (onProviderSuccess) onProviderSuccess(provider, result);
      return {
        ...result,
        provider,
        fallbackProvidersTried: providers.slice(0, providers.indexOf(provider) + 1),
        failures: [...allFailures, ...(result.failures || [])],
      };
    } catch (error) {
      if (onProviderFailure) onProviderFailure(provider, error);
      allFailures.push(...(error.failures || [{
        request_id: requestId,
        provider,
        error_code: errorCode(error),
        elapsed_ms: 0,
      }]));
      if (provider === providers[providers.length - 1]) {
        error.failures = allFailures;
        throw error;
      }
    }
  }

  throw new SpriteProviderError("No sprite provider available.", {
    provider: initialProvider,
    code: "NO_PROVIDER_AVAILABLE",
  });
}
