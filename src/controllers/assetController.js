// src/controllers/assetController.js
//
// Handles user-uploaded 3D assets (GLB/FBX/OBJ).
// Uploads to Tripo via import_model task type (0 credit cost).
// Saves to history on success.

import { getTripoClient } from "../lib/tripoClient.js";
import { taskService } from "../services/taskService.js";
import admin from "firebase-admin";

const HISTORY_COLLECTION = "trellis_history";
const ALLOWED_MIME_TYPES = new Set([
  "model/gltf-binary",       // .glb
  "model/gltf+json",         // .gltf
  "application/octet-stream", // .fbx (generic binary)
  "text/plain",              // .obj (text-based)
]);
const ALLOWED_EXTENSIONS = new Set(["glb", "fbx", "obj"]);
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

/**
 * POST /api/tripo/assets/upload
 * Uploads a 3D model file and creates an import_model task.
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

  const userId = req.user?.uid;
  if (!userId) {
    res.status(401).json({ success: false, message: "Unauthorized" });
    return;
  }

  try {
    const client = getTripoClient();

    // Upload file to Tripo
    const imageToken = await client.uploadFile(file.buffer, file.originalname, file.mimetype || "application/octet-stream");

    // Create import_model task
    const taskId = await taskService.create({
      type: "import_model",
      file: { type: ext === "glb" ? "glb" : ext, file_token: imageToken },
    }, {});

    console.log(`[AssetController] Uploaded asset for user ${userId}, task ${taskId}`);

    // Save to history immediately as "upload" source
    const db = admin.firestore();
    const historyRef = db.collection(HISTORY_COLLECTION).doc();
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
      },
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
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
    res.status(500).json({ success: false, message: err.message });
  }
}
