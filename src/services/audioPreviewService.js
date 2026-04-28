import crypto from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import ffmpegStatic from "ffmpeg-static";
import { storageService } from "./storageService.js";

const DEFAULT_WATERMARK_VOLUME = 0.56;
const DEFAULT_WATERMARK_INTERVAL_SECONDS = 8.25;
const PREVIEW_SAMPLE_RATE = 44100;
const PREVIEW_BITRATE = "96k";
const PREVIEW_CONTENT_TYPE = "audio/mpeg";

function cleanEnv(name) {
  const value = process.env[name];
  return typeof value === "string" ? value.trim() : "";
}

function safeFileName(name = "audio") {
  return String(name || "audio")
    .replace(/[^\w.\-]+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 120);
}

function getExt(name = "") {
  return path.extname(String(name || "")).replace(".", "").toLowerCase() || "mp3";
}

function resolveFfmpegPath() {
  return cleanEnv("FFMPEG_PATH") || ffmpegStatic || "ffmpeg";
}

function resolveWatermarkPath() {
  return cleanEnv("MARKETPLACE_AUDIO_WATERMARK_PATH") ||
    path.resolve(process.cwd(), "assets", "audio", "ludusgen-preview-watermark.wav");
}

function getWatermarkVolume() {
  const configured = Number(cleanEnv("MARKETPLACE_AUDIO_WATERMARK_VOLUME"));
  if (!Number.isFinite(configured)) return DEFAULT_WATERMARK_VOLUME;
  return Math.min(1, Math.max(0.15, configured));
}

function getWatermarkIntervalSeconds() {
  const configured = Number(cleanEnv("MARKETPLACE_AUDIO_WATERMARK_INTERVAL_SECONDS"));
  if (!Number.isFinite(configured)) return DEFAULT_WATERMARK_INTERVAL_SECONDS;
  return Math.min(15, Math.max(4, configured));
}

async function assertReadableFile(filePath, label) {
  try {
    const stat = await fs.stat(filePath);
    if (!stat.isFile()) throw new Error(`${label} is not a file`);
  } catch (err) {
    throw new Error(`${label} nem talalhato vagy nem olvashato: ${filePath}`);
  }
}

function runFfmpeg(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(resolveFfmpegPath(), args, { windowsHide: true });
    let stderr = "";

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (err) => {
      if (err.code === "ENOENT") {
        reject(new Error("ffmpeg nem talalhato. Allitsd be az FFMPEG_PATH env valtozot."));
        return;
      }
      reject(err);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`ffmpeg preview keszites sikertelen (${code}): ${stderr.trim()}`));
    });
  });
}

function audioPreviewFilter(watermarkVolume, watermarkIntervalSeconds) {
  const loopSamples = Math.round(PREVIEW_SAMPLE_RATE * watermarkIntervalSeconds);

  return [
    `[0:a]asetpts=PTS-STARTPTS,aresample=${PREVIEW_SAMPLE_RATE},aformat=channel_layouts=stereo[base]`,
    `[1:a]aresample=${PREVIEW_SAMPLE_RATE},aformat=channel_layouts=stereo,volume=${watermarkVolume},apad=pad_dur=${watermarkIntervalSeconds},atrim=0:${watermarkIntervalSeconds},aloop=loop=-1:size=${loopSamples},asetpts=N/SR/TB[wm]`,
    "[base][wm]amix=inputs=2:duration=first:dropout_transition=0,alimiter=limit=0.95[out]",
  ].join(";");
}

export async function createWatermarkedAudioPreview(buffer, userId, sourceName) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new Error("Hianyzo audio buffer a preview kesziteshez");
  }

  const watermarkPath = resolveWatermarkPath();
  await assertReadableFile(watermarkPath, "Audio watermark fajl");

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ludusgen-audio-preview-"));
  const inputPath = path.join(tempDir, `source.${getExt(sourceName)}`);
  const outputPath = path.join(tempDir, "preview.mp3");

  try {
    await fs.writeFile(inputPath, buffer);
    const watermarkVolume = getWatermarkVolume();
    const watermarkIntervalSeconds = getWatermarkIntervalSeconds();
    await runFfmpeg([
      "-y",
      "-hide_banner",
      "-loglevel",
      "error",
      "-i",
      inputPath,
      "-i",
      watermarkPath,
      "-filter_complex",
      audioPreviewFilter(watermarkVolume, watermarkIntervalSeconds),
      "-map",
      "[out]",
      "-vn",
      "-codec:a",
      "libmp3lame",
      "-b:a",
      PREVIEW_BITRATE,
      "-ar",
      "44100",
      outputPath,
    ]);

    const previewBuffer = await fs.readFile(outputPath);
    const previewName = `${path.basename(safeFileName(sourceName), path.extname(sourceName || "")) || "audio"}_preview.mp3`;
    const key = `marketplace/previews/${userId}/${Date.now()}_${crypto.randomUUID()}_${safeFileName(previewName)}`;
    await storageService.uploadFile(previewBuffer, key, PREVIEW_CONTENT_TYPE);

    return {
      key,
      contentType: PREVIEW_CONTENT_TYPE,
      fileName: safeFileName(previewName),
      size: previewBuffer.length,
      fullLength: true,
      watermarkIntervalSeconds,
      bitrate: PREVIEW_BITRATE,
      watermarked: true,
    };
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}
