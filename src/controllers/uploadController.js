import { getTripoClient } from "../lib/tripoClient.js";
import {
  TRIPO_IMAGE_UPLOAD_MAX_BYTES,
  TRIPO_MODEL_IMPORT_MAX_BYTES,
} from "../config/tripo.config.js";

function errorPayload(err) {
  return {
    success: false,
    message: err.message,
    ...(err.traceId && { tripoTraceId: err.traceId }),
    ...(err.code && { tripoCode: err.code }),
    ...(err.suggestion && { tripoSuggestion: err.suggestion }),
  };
}

function inferFormat(filename = "", explicitFormat = "", mimeType = "") {
  if (explicitFormat) return String(explicitFormat).trim().toLowerCase();
  const fromName = String(filename).split(".").pop()?.toLowerCase();
  if (fromName) return fromName === "jpg" ? "jpeg" : fromName;
  if (mimeType === "image/jpeg") return "jpeg";
  if (mimeType === "image/png") return "png";
  if (mimeType === "image/webp") return "webp";
  return "";
}

const TRUTHY_VALUES = new Set(["1", "true", "yes", "on"]);

function isLegacyModelStsImportEnabled(env = process.env) {
  return TRUTHY_VALUES.has(String(env.ENABLE_LEGACY_TRIPO_MODEL_STS_IMPORT || "")
    .trim()
    .toLowerCase());
}

export async function getUploadStsTarget(req, res) {
  try {
    const {
      kind = "image",
      filename = "",
      mimeType = "application/octet-stream",
      format: explicitFormat = "",
    } = req.body ?? {};

    const normalizedKind = String(kind).trim().toLowerCase();
    if (!["image", "model"].includes(normalizedKind)) {
      return res.status(400).json({ success: false, message: "kind must be image or model" });
    }

    if (normalizedKind === "model" && !isLegacyModelStsImportEnabled()) {
      return res.status(410).json({
        success: false,
        message: "Legacy direct model uploads are disabled. Use /api/tripo/assets/upload instead.",
      });
    }

    const format = inferFormat(filename, explicitFormat, mimeType);
    if (!format) {
      return res.status(400).json({ success: false, message: "Could not infer upload format" });
    }

    const maxBytes = normalizedKind === "model"
      ? TRIPO_MODEL_IMPORT_MAX_BYTES
      : TRIPO_IMAGE_UPLOAD_MAX_BYTES;

    const target = await getTripoClient().createPresignedUploadTarget({
      filename,
      mimeType,
      format,
    });

    return res.json({
      success: true,
      kind: normalizedKind,
      maxBytes,
      ...target,
    });
  } catch (err) {
    console.error("[UploadController] getUploadStsTarget error:", err.message);
    return res.status(500).json(errorPayload(err));
  }
}
