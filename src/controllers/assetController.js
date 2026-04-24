// src/controllers/assetController.js
//
// Handles user-uploaded 3D assets (GLB/FBX/OBJ/STL).
// Uploads to Tripo via import_model task type (0 credit cost).
// Saves to history on success.

import { getTripoClient } from "../lib/tripoClient.js";
import { taskService } from "../services/taskService.js";
import { registerTask as registerForRecovery } from "../services/taskRecoveryService.js";
import { HISTORY_TTL_MS, TRIPO_MODEL_IMPORT_MAX_BYTES } from "../config/tripo.config.js";
import admin from "firebase-admin";

const HISTORY_COLLECTION = "tripo_history";
const ALLOWED_MIME_TYPES = new Set([
  "model/gltf-binary",       // .glb
  "model/gltf+json",         // .gltf
  "application/octet-stream", // .fbx (generic binary)
  "model/stl",
  "application/sla",
  "text/plain",              // .obj (text-based)
]);
const ALLOWED_EXTENSIONS = new Set(["glb", "fbx", "obj", "stl"]);
const MAX_FILE_SIZE = TRIPO_MODEL_IMPORT_MAX_BYTES;

function errorPayload(err) {
  return {
    success: false,
    message: err.message,
    ...(err.traceId && { tripoTraceId: err.traceId }),
    ...(err.code && { tripoCode: err.code }),
    ...(err.suggestion && { tripoSuggestion: err.suggestion }),
  };
}

/**
 * POST /api/tripo/assets/upload
 * Uploads a 3D model file through Tripo STS and creates an import_model task.
 */
export async function uploadAsset(req, res) {
  const file = req.file;
  if (!file) {
    res.status(400).json({ success: false, message: "File missing" });
    return;
  }

  // Validate file size
  if (file.size > MAX_FILE_SIZE) {
    res.status(400).json({ success: false, message: `File too large. Maximum size: ${MAX_FILE_SIZE / (1024 * 1024)}MB` });
    return;
  }

  // Validate file extension
  const ext = file.originalname.split(".").pop()?.toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    res.status(400).json({ success: false, message: `Unsupported file type. Allowed: ${[...ALLOWED_EXTENSIONS].join(", ")}` });
    return;
  }
  if (file.mimetype && !ALLOWED_MIME_TYPES.has(file.mimetype)) {
    console.warn(`[AssetController] Unusual MIME type for .${ext}: ${file.mimetype}`);
  }

  const userId = req.user?.uid;
  if (!userId) {
    res.status(401).json({ success: false, message: "Unauthorized" });
    return;
  }

  try {
    const client = getTripoClient();

    const uploadedObject = await client.uploadFileObject(
      file.buffer,
      file.originalname,
      file.mimetype || "application/octet-stream",
      ext,
    );

    // Create import_model task
    const taskId = await taskService.create({
      type: "import_model",
      file: {
        type: ext,
        object: {
          bucket: uploadedObject.bucket,
          key: uploadedObject.key,
        },
      },
    }, {});

    registerForRecovery(taskId, userId, "import_model", null, file.originalname, {});

    console.log(`[AssetController] Uploaded asset for user ${userId}, task ${taskId}`);

    // Save to history immediately as "upload" source
    const db = admin.firestore();
    const historyRef = db.collection(HISTORY_COLLECTION).doc(`tripo_${taskId}`);
    const now = Date.now();
    await historyRef.set({
      userId,
      source: "upload",
      mode: "upload",
      prompt: file.originalname,
      status: "pending",
      model_url: null,
      taskId,
      params: {
        model_version: null,
        mode: "upload",
        filename: file.originalname,
        fileSize: file.size,
        fileType: ext,
        uploadObject: {
          bucket: uploadedObject.bucket,
          key: uploadedObject.key,
        },
      },
      ts: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: now + HISTORY_TTL_MS,
    });

    res.json({
      success: true,
      taskId,
      historyId: historyRef.id,
      filename: file.originalname,
      fileSize: file.size,
      fileType: ext,
    });
  } catch (err) {
    console.error(`[AssetController] upload error:`, err.message);
    res.status(500).json(errorPayload(err));
  }
}

/**
 * POST /api/tripo/assets/import
 * Creates an import_model task from a client-side STS uploaded object.
 */
export async function importUploadedAsset(req, res) {
  const userId = req.user?.uid;
  if (!userId) {
    res.status(401).json({ success: false, message: "Unauthorized" });
    return;
  }

  const inputFile = req.body?.file;
  const normalizedObject = inputFile?.object;
  const fileType = String(inputFile?.type || "").trim().toLowerCase();

  if (!normalizedObject?.bucket || !normalizedObject?.key || !fileType) {
    res.status(400).json({
      success: false,
      message: "file.object.bucket, file.object.key and file.type are required",
    });
    return;
  }

  try {
    const taskId = await taskService.create({
      type: "import_model",
      file: {
        type: fileType,
        object: {
          bucket: normalizedObject.bucket,
          key: normalizedObject.key,
        },
      },
    }, {});

    registerForRecovery(taskId, userId, "import_model", null, req.body?.filename || `${fileType.toUpperCase()} upload`, {});

    const db = admin.firestore();
    const historyRef = db.collection(HISTORY_COLLECTION).doc(`tripo_${taskId}`);
    const now = Date.now();
    await historyRef.set({
      userId,
      source: "upload",
      mode: "upload",
      prompt: req.body?.filename || `${fileType.toUpperCase()} upload`,
      status: "pending",
      model_url: null,
      taskId,
      params: {
        model_version: null,
        mode: "upload",
        filename: req.body?.filename || null,
        fileType,
        uploadObject: {
          bucket: normalizedObject.bucket,
          key: normalizedObject.key,
        },
        source_kind: "sts",
      },
      ts: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: now + HISTORY_TTL_MS,
    });

    res.json({
      success: true,
      taskId,
      historyId: historyRef.id,
      fileType,
    });
  } catch (err) {
    console.error("[AssetController] importUploadedAsset error:", err.message);
    res.status(500).json(errorPayload(err));
  }
}
