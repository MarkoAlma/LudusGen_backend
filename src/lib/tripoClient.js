// src/lib/tripoClient.js
//
// Core Tripo HTTP client.
// Handles: retry, exponential backoff, 429 rate-limit, 5xx errors,
//          timeout, idempotency keys, response normalisation.

import {
  TRIPO_BASE_URL, DEFAULT_TIMEOUT, MAX_POLL_MS,
  POLL_INTERVAL, RETRY_CONFIG,
} from "../config/tripo.config.js";
import { extractModelUrl } from "../utils/tripoUtils.js";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

/* ─── helpers ─────────────────────────────────────────────────────────── */
const sleep = ms => new Promise(r => setTimeout(r, ms));

const jitter = ms => ms + Math.floor(Math.random() * RETRY_CONFIG.jitterMs);

const backoffDelay = attempt =>
  jitter(Math.min(RETRY_CONFIG.baseDelayMs * 2 ** attempt, RETRY_CONFIG.maxDelayMs));

function logDebug(label, payload) {
  try {
    console.log(label, JSON.stringify(payload, null, 2));
  } catch {
    console.log(label, payload);
  }
}

function appendTrace(message, traceId) {
  return traceId ? `${message} [Tripo trace: ${traceId}]` : message;
}

function tripoError(message, traceId, extra = {}) {
  const err = new Error(appendTrace(message, traceId));
  if (traceId) err.traceId = traceId;
  Object.assign(err, extra);
  return err;
}

function getTraceId(headers) {
  return headers.get("X-Tripo-Trace-ID") || headers.get("x-tripo-trace-id") || null;
}

function parseJsonMaybe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function formatFromFilename(filename = "") {
  const ext = String(filename).split(".").pop()?.toLowerCase() ?? "";
  if (ext === "jpg") return "jpeg";
  return ext;
}

function inferS3Region(s3Host = "") {
  const match = String(s3Host).match(/s3[.-]([a-z0-9-]+)\./i);
  return match?.[1] || "us-west-2";
}

function contentTypeForFormat(format, fallback = "application/octet-stream") {
  const map = {
    jpeg: "image/jpeg",
    jpg: "image/jpeg",
    png: "image/png",
    webp: "image/webp",
    glb: "model/gltf-binary",
    obj: "text/plain",
    fbx: "application/octet-stream",
    stl: "model/stl",
  };
  return map[format] ?? fallback;
}

/* ─── TripoClient ─────────────────────────────────────────────────────── */
export class TripoClient {
  /** @param {string} [apiKey] @param {string} [baseUrl] @param {number} [timeoutMs] */
  constructor(apiKey, baseUrl, timeoutMs) {
    const key = apiKey ?? process.env.TRIPO3D_API_KEY;
    if (!key) throw new Error("TRIPO3D_API_KEY is not configured");
    this.apiKey = key;
    this.baseUrl = baseUrl ?? TRIPO_BASE_URL;
    this.timeoutMs = timeoutMs ?? DEFAULT_TIMEOUT;
  }

  /* ── Core fetch with retry ──────────────────────────────────────── */
  async fetch(path, options = {}, idempotencyKey) {
    const url = `${this.baseUrl}${path}`;
    const headers = {
      Authorization: `Bearer ${this.apiKey}`,
      ...(options.headers ?? {}),
    };
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;

    let lastError = null;

    for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, this.timeoutMs);

      const abortFromCaller = () => controller.abort();
      if (options.signal?.aborted) {
        abortFromCaller();
      } else if (options.signal) {
        options.signal.addEventListener("abort", abortFromCaller, { once: true });
      }
      const cleanup = () => {
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", abortFromCaller);
      };

      try {
        const res = await fetch(url, { ...options, headers, signal: controller.signal });
        cleanup();
        const traceId = getTraceId(res.headers);
        const method = options.method ?? "GET";
        if (traceId) {
          console.log(`[TripoClient] ${method} ${path} trace=${traceId}`);
        }

        // 429 — rate limited
        if (res.status === 429) {
          const ra = res.headers.get("Retry-After");
          const delay = ra ? parseInt(ra, 10) * 1000 : backoffDelay(attempt);
          console.warn(`[TripoClient] 429 rate limited, retry ${attempt + 1} in ${delay}ms${traceId ? ` trace=${traceId}` : ""}`);
          await sleep(delay);
          lastError = tripoError("Rate limited (429)", traceId, { status: 429 });
          continue;
        }

        // 5xx — retryable
        if (res.status >= 500 && RETRY_CONFIG.retryableStatuses.has(res.status)) {
          if (attempt < RETRY_CONFIG.maxRetries) {
            const delay = backoffDelay(attempt);
            console.warn(`[TripoClient] ${res.status} server error, retry ${attempt + 1} in ${delay}ms${traceId ? ` trace=${traceId}` : ""}`);
            await sleep(delay);
            lastError = tripoError(`Server error (${res.status})`, traceId, { status: res.status });
            continue;
          }
        }

        // Non-retryable HTTP error
        if (!res.ok) {
          const body = await res.text().catch(() => "");
          const parsed = parseJsonMaybe(body);
          const apiMessage = parsed?.message
            ? `code=${parsed.code ?? res.status}: ${parsed.message}${parsed.suggestion ? ` (${parsed.suggestion})` : ""}`
            : body.slice(0, 300);
          throw tripoError(`Tripo API error (${res.status}): ${apiMessage}`, traceId, {
            status: res.status,
            code: parsed?.code,
            suggestion: parsed?.suggestion,
          });
        }

        const json = await res.json();
        if (traceId) json._traceId = traceId;
        if (json.code !== 0) {
          throw tripoError(`Tripo API code=${json.code}: ${json.message ?? "unknown error"}${json.suggestion ? ` (${json.suggestion})` : ""}`, traceId, {
            code: json.code,
            suggestion: json.suggestion,
          });
        }
        return json;

      } catch (err) {
        cleanup();
        if (err.name === "AbortError") {
          if (options.signal?.aborted && !timedOut) {
            const abortErr = new Error("AbortError");
            abortErr.name = "AbortError";
            throw abortErr;
          }
          lastError = new Error(`Request to ${path} timed out after ${this.timeoutMs}ms`);
          if (attempt < RETRY_CONFIG.maxRetries) { await sleep(backoffDelay(attempt)); continue; }
          throw lastError;
        }
        if (!lastError || err.message !== lastError.message) throw err;
      }
    }

    throw lastError ?? new Error(`Request to ${path} failed after ${RETRY_CONFIG.maxRetries} retries`);
  }

  /* ── Convenience wrappers ─────────────────────────────────────── */
  get(path, signal) {
    return this.fetch(path, { method: "GET", signal });
  }

  post(path, body, idempotencyKey, signal) {
    return this.fetch(
      path,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal },
      idempotencyKey,
    );
  }

  postForm(path, form, signal) {
    return this.fetch(path, { method: "POST", body: form, signal });
  }

  /* ── Task operations ──────────────────────────────────────────── */
  async createTask(taskBody, idempotencyKey, opts = {}) {
    console.log("[TripoClient] createTask body:", JSON.stringify(taskBody, null, 2));

    // Extra logging for animate tasks to help debugging
    if (taskBody.type?.startsWith("animate_")) {
      console.log(`[TripoClient] ${taskBody.type} request details:`, {
        original_model_task_id: taskBody.original_model_task_id,
        animation: taskBody.animation,
        animations: taskBody.animations,
        rig_type: taskBody.rig_type,
        out_format: taskBody.out_format,
        spec: taskBody.spec,
        bake_animation: taskBody.bake_animation,
        export_with_geometry: taskBody.export_with_geometry,
        animate_in_place: taskBody.animate_in_place,
      });
    }

    const res = await this.post("/task", taskBody, idempotencyKey, opts.signal);
    logDebug("[TripoClient] createTask response:", res);
    const taskId = res.data?.task_id;
    if (!taskId) throw new Error(`No task_id in response: ${JSON.stringify(res).slice(0, 200)}`);
    return taskId;
  }

  async getTask(taskId) {
    const res = await this.get(`/task/${taskId}`);
    if (!res.data) throw new Error(`No task data for ${taskId}`);
    return { ...res.data, ...(res._traceId && { _traceId: res._traceId }) };
  }

  async cancelTask(taskId) {
    // Tripo API does not support task cancellation.
    // We only stop polling on the frontend side.
    console.log(`[TripoClient] cancel requested for ${taskId} — no-op (Tripo has no cancel endpoint)`);
    return { success: true, cancelled: false, message: "Task cannot be cancelled after submission — it will continue running on Tripo servers until complete." };
  }

  async listTasks({ status, limit = 20, cursor } = {}) {
    const qs = new URLSearchParams();
    if (status) qs.set("status", status);
    if (limit) qs.set("limit", String(limit));
    if (cursor) qs.set("cursor", cursor);
    const path = `/tasks${qs.toString() ? "?" + qs : ""}`;
    const res = await this.get(path);
    return res.data ?? { tasks: [], total: 0 };
  }

  async getBalance() {
    const res = await this.get("/user/balance");
    return res.data ?? { balance: 0, frozen: 0 };
  }

  async getUploadStsToken(format) {
    const normalizedFormat = format === "jpg" ? "jpeg" : format;
    const res = await this.post("/upload/sts/token", { format: normalizedFormat });
    if (!res.data?.resource_bucket || !res.data?.resource_uri) {
      throw new Error(`No STS upload target in response: ${JSON.stringify(res).slice(0, 200)}`);
    }
    return res.data;
  }

  async uploadFileObject(buffer, filename, mimeType, format) {
    const uploadFormat = format ?? formatFromFilename(filename);
    if (!uploadFormat) throw new Error("Cannot determine Tripo upload format");
    const sts = await this.getUploadStsToken(uploadFormat);
    const region = inferS3Region(sts.s3_host);
    const endpoint = sts.s3_host ? `https://${sts.s3_host}` : undefined;
    const s3 = new S3Client({
      region,
      ...(endpoint && { endpoint }),
      credentials: {
        accessKeyId: sts.sts_ak,
        secretAccessKey: sts.sts_sk,
        sessionToken: sts.session_token,
      },
    });

    await s3.send(new PutObjectCommand({
      Bucket: sts.resource_bucket,
      Key: sts.resource_uri,
      Body: buffer,
      ContentType: mimeType || contentTypeForFormat(uploadFormat),
    }));

    return {
      bucket: sts.resource_bucket,
      key: sts.resource_uri,
      format: uploadFormat,
      s3Host: sts.s3_host,
    };
  }

  async createPresignedUploadTarget({ filename, mimeType, format, expiresIn = 900 } = {}) {
    const uploadFormat = format ?? formatFromFilename(filename);
    if (!uploadFormat) throw new Error("Cannot determine Tripo upload format");

    const sts = await this.getUploadStsToken(uploadFormat);
    const region = inferS3Region(sts.s3_host);
    const endpoint = sts.s3_host ? `https://${sts.s3_host}` : undefined;
    const s3 = new S3Client({
      region,
      ...(endpoint && { endpoint }),
      credentials: {
        accessKeyId: sts.sts_ak,
        secretAccessKey: sts.sts_sk,
        sessionToken: sts.session_token,
      },
    });

    const contentType = mimeType || contentTypeForFormat(uploadFormat);
    const command = new PutObjectCommand({
      Bucket: sts.resource_bucket,
      Key: sts.resource_uri,
      ContentType: contentType,
    });
    const uploadUrl = await getSignedUrl(s3, command, { expiresIn });

    return {
      uploadUrl,
      bucket: sts.resource_bucket,
      key: sts.resource_uri,
      format: uploadFormat,
      contentType,
      expiresIn,
    };
  }

  async uploadFile(buffer, filename, mimeType) {
    const { Blob } = await import("buffer");
    const form = new FormData();
    form.append("file", new Blob([buffer], { type: mimeType }), filename);
    const res = await this.postForm("/upload/sts", form);
    const token = res.data?.image_token;
    if (!token) throw new Error("No image_token in upload response");
    return token;
  }

  /* ── Poll until task completes ────────────────────────────────── */
  /**
   * @param {string} taskId
   * @param {{ pollIntervalMs?: number, maxMs?: number, onProgress?: Function }} [opts]
   */
  async pollTask(taskId, opts = {}) {
    const interval = opts.pollIntervalMs ?? POLL_INTERVAL;
    const maxMs = opts.maxMs ?? MAX_POLL_MS;
    const deadline = Date.now() + maxMs;

    while (Date.now() < deadline) {
      const task = await this.getTask(taskId);
      opts.onProgress?.(task.progress ?? 0, task.status);

      if (task.status === "success") {
        const { modelUrl, rigCheckResult, rigType, topology, rawOutput } = extractModelUrl(task);
        return {
          success: true,
          status: "success",
          progress: 100,
          modelUrl,
          tripoTraceId: task._traceId ?? null,
          outputFormat: rawOutput.format ?? null,
          rigCheckResult,
          rigType,
          topology,
          rawOutput,
        };
      }

      if (task.status === "failed" || task.status === "cancelled") {
        return {
          success: false, status: task.status, progress: task.progress ?? 0,
          modelUrl: null, tripoTraceId: task._traceId ?? null, rigCheckResult: null, rawOutput: null
        };
      }

      await sleep(interval);
    }

    throw new Error(`Task ${taskId} timed out after ${maxMs / 1000}s`);
  }

  /* ── Create + poll in one step ────────────────────────────────── */
  async createAndPoll(taskBody, opts = {}) {
    const { idempotencyKey, ...pollOpts } = opts;
    const taskId = await this.createTask(taskBody, idempotencyKey);
    const result = await this.pollTask(taskId, pollOpts);
    return { taskId, ...result };
  }
}

/* ─── Singleton ────────────────────────────────────────────────────────── */
let _instance = null;
export function getTripoClient() {
  if (!_instance) _instance = new TripoClient();
  return _instance;
}
