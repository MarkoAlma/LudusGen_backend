function normalizeMillis(value) {
  const millis = Number(value);
  return Number.isFinite(millis) && millis > 0 ? Math.floor(millis) : 0;
}

export function encodeImageGalleryCursor({ createdAtMs, id }) {
  return Buffer.from(
    JSON.stringify({
      createdAtMs: normalizeMillis(createdAtMs),
      id: String(id || ""),
    })
  ).toString("base64url");
}

export function decodeImageGalleryCursor(cursor) {
  if (!cursor) return null;

  try {
    const parsed = JSON.parse(Buffer.from(String(cursor), "base64url").toString("utf8"));
    const createdAtMs = normalizeMillis(parsed?.createdAtMs);
    const id = String(parsed?.id || "");
    if (!id || createdAtMs <= 0) return null;

    return {
      createdAtMs,
      id,
    };
  } catch {
    return null;
  }
}

export function clampImageGalleryLimit(limit, fallback = 24, max = 48) {
  const parsed = Number(limit);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(Math.floor(parsed), 1), max);
}
