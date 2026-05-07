const DATA_URL_BASE64_PREFIX = /^data:[^;,]+(?:;[^,]*)?;base64,/i;

function isLikelyBase64Payload(value) {
  if (typeof value !== "string") return false;
  const compact = value.replace(/\s+/g, "");
  if (!compact) return false;
  if (DATA_URL_BASE64_PREFIX.test(compact)) return true;
  if (compact.length < 4 || compact.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/=]+$/.test(compact);
}

export function normalizeTrellisBase64Candidate(candidate) {
  if (typeof candidate !== "string") return null;
  const compact = candidate.trim().replace(/\s+/g, "");
  if (!compact) return null;

  if (DATA_URL_BASE64_PREFIX.test(compact)) {
    return compact.replace(DATA_URL_BASE64_PREFIX, "") || null;
  }

  return isLikelyBase64Payload(compact) ? compact : null;
}

function extractFromNode(node, depth = 0) {
  if (depth > 5 || node == null) return null;

  const direct = normalizeTrellisBase64Candidate(node);
  if (direct) return direct;

  if (Array.isArray(node)) {
    for (const item of node) {
      const nested = extractFromNode(item, depth + 1);
      if (nested) return nested;
    }
    return null;
  }

  if (typeof node !== "object") return null;

  const prioritizedKeys = [
    "glb_base64",
    "base64",
    "glb",
    "model_base64",
    "file_base64",
    "data",
  ];

  for (const key of prioritizedKeys) {
    if (!(key in node)) continue;
    const nested = extractFromNode(node[key], depth + 1);
    if (nested) return nested;
  }

  const containerKeys = [
    "artifacts",
    "result",
    "response",
    "output",
    "outputs",
    "payload",
    "model",
    "models",
    "file",
    "files",
    "content",
    "items",
  ];

  for (const key of containerKeys) {
    if (!(key in node)) continue;
    const nested = extractFromNode(node[key], depth + 1);
    if (nested) return nested;
  }

  return null;
}

export function extractTrellisModelBase64(body) {
  return extractFromNode(body);
}

export function summarizeTrellisResponse(body) {
  if (!body || typeof body !== "object") {
    return { topLevelKeys: [], artifactKeys: [] };
  }

  const artifact = Array.isArray(body.artifacts) && body.artifacts.length > 0 && typeof body.artifacts[0] === "object"
    ? body.artifacts[0]
    : null;

  return {
    topLevelKeys: Object.keys(body),
    artifactKeys: artifact ? Object.keys(artifact) : [],
  };
}
