const PROVIDERS = ["pixellab", "godmode", "segmind"];

export function createSpriteMetricsStore() {
  return new Map(PROVIDERS.map((provider) => [provider, {
    requests: 0,
    successes: 0,
    failures: 0,
    totalGenerationMs: 0,
    lastErrorCode: null,
    lastUpdatedMs: null,
  }]));
}

export const spriteMetricsStore = createSpriteMetricsStore();

export function recordSpriteProviderMetric(store, { provider, ok, elapsedMs = 0, errorCode = null, now = Date.now() }) {
  if (!store.has(provider)) return;
  const metric = store.get(provider);
  metric.requests += 1;
  if (ok) metric.successes += 1;
  else {
    metric.failures += 1;
    metric.lastErrorCode = errorCode;
  }
  metric.totalGenerationMs += Math.max(0, Number(elapsedMs) || 0);
  metric.lastUpdatedMs = now;
}

function isConfigured(provider, env) {
  if (provider === "pixellab") return Boolean(env.PIXELLAB_API_KEY || env.PIXELLAB_TOKEN);
  if (provider === "godmode") return Boolean(env.GODMODE_API_KEY || env.GOD_MODE_API_KEY);
  if (provider === "segmind") return Boolean(env.SEGMIND_API_KEY);
  return false;
}

export function getProviderHealthSnapshot(
  store = spriteMetricsStore,
  { env = process.env, now = Date.now(), openProviders = [] } = {},
) {
  const providers = {};
  const openProviderSet = new Set(openProviders);

  for (const provider of PROVIDERS) {
    const metric = store.get(provider) || {};
    const requests = metric.requests || 0;
    const successRate = requests > 0 ? Number(((metric.successes || 0) / requests).toFixed(4)) : null;
    const avgGenerationMs = requests > 0 ? Math.round((metric.totalGenerationMs || 0) / requests) : null;
    const configured = isConfigured(provider, env);
    const circuitOpen = openProviderSet.has(provider);

    providers[provider] = {
      configured,
      status: circuitOpen ? "circuit_open" : configured ? "available" : "not_configured",
      circuitOpen,
      requests,
      successes: metric.successes || 0,
      failures: metric.failures || 0,
      successRate,
      avgGenerationMs,
      lastErrorCode: metric.lastErrorCode || null,
      lastUpdatedMs: metric.lastUpdatedMs || null,
    };
  }

  return {
    service: "ludusgen-api",
    ok: true,
    now,
    providers,
  };
}
