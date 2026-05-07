const TRUTHY_VALUES = new Set(["1", "true", "yes", "on"]);

function readMeshyFlag(env = process.env) {
  return String(env.ENABLE_MESHY || env.MESHY_ENABLED || "")
    .trim()
    .toLowerCase();
}

function hasMeshyApiKey(env = process.env) {
  return Boolean(env.MESHY_API_KEY || env.TRIPO3D_API_KEY || env.TRIPO3D);
}

export function isMeshyEnabled(env = process.env) {
  return TRUTHY_VALUES.has(readMeshyFlag(env));
}

export function assertMeshyAccess(env = process.env) {
  if (!isMeshyEnabled(env)) {
    throw Object.assign(new Error("Meshy is disabled. Set ENABLE_MESHY=true to re-enable it."), {
      status: 403,
      code: "MESHY_DISABLED",
    });
  }

  if (!hasMeshyApiKey(env)) {
    throw Object.assign(new Error("MESHY_API_KEY is not configured."), {
      status: 503,
      code: "MESHY_NOT_CONFIGURED",
    });
  }

  return true;
}
