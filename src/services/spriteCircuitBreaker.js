import { SUPPORTED_SPRITE_PROVIDERS } from "../lib/spriteRouting.js";

export const SPRITE_CIRCUIT_FAILURE_THRESHOLD = 3;
export const SPRITE_CIRCUIT_COOLDOWN_MS = 5 * 60 * 1000;

function emptyCircuitState() {
  return {
    failures: 0,
    openedUntilMs: null,
    lastFailureMs: null,
    lastSuccessMs: null,
  };
}

export function createSpriteCircuitStore() {
  return new Map(SUPPORTED_SPRITE_PROVIDERS.map((provider) => [provider, emptyCircuitState()]));
}

export const spriteCircuitStore = createSpriteCircuitStore();

function getCircuitState(store, provider) {
  if (!SUPPORTED_SPRITE_PROVIDERS.includes(provider)) return null;
  if (!store.has(provider)) store.set(provider, emptyCircuitState());
  return store.get(provider);
}

export function isSpriteProviderCircuitOpen(store, provider, { now = Date.now() } = {}) {
  const state = getCircuitState(store, provider);
  if (!state?.openedUntilMs) return false;

  if (state.openedUntilMs > now) return true;

  state.failures = 0;
  state.openedUntilMs = null;
  return false;
}

export function recordSpriteCircuitFailure(
  store,
  provider,
  {
    now = Date.now(),
    threshold = SPRITE_CIRCUIT_FAILURE_THRESHOLD,
    cooldownMs = SPRITE_CIRCUIT_COOLDOWN_MS,
  } = {},
) {
  const state = getCircuitState(store, provider);
  if (!state) return null;

  state.failures += 1;
  state.lastFailureMs = now;

  if (state.failures >= threshold) {
    state.openedUntilMs = now + cooldownMs;
  }

  return { ...state };
}

export function recordSpriteCircuitSuccess(store, provider, { now = Date.now() } = {}) {
  const state = getCircuitState(store, provider);
  if (!state) return null;

  state.failures = 0;
  state.openedUntilMs = null;
  state.lastSuccessMs = now;

  return { ...state };
}

export function getOpenSpriteProviders(store = spriteCircuitStore, { now = Date.now() } = {}) {
  return SUPPORTED_SPRITE_PROVIDERS.filter((provider) =>
    isSpriteProviderCircuitOpen(store, provider, { now }),
  );
}
