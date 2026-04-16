// src/lib/tripoClient.js
//
// Core Tripo HTTP client.
// Handles: retry, exponential backoff, 429 rate-limit, 5xx errors,
//          timeout, idempotency keys, response normalisation.

import {
  TRIPO_BASE_URL, DEFAULT_TIMEOUT, MAX_POLL_MS,
  POLL_INTERVAL, RETRY_CONFIG,
} from "../config/tripo.config.js";

/* ─── helpers ─────────────────────────────────────────────────────────── */
const sleep = ms => new Promise(r => setTimeout(r, ms));

const jitter = ms => ms + Math.floor(Math.random() * RETRY_CONFIG.jitterMs);

const backoffDelay = attempt =>
  jitter(Math.min(RETRY_CONFIG.baseDelayMs * 2 ** attempt, RETRY_CONFIG.maxDelayMs));

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
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const res = await fetch(url, { ...options, headers, signal: controller.signal });
        clearTimeout(timer);

        // 429 — rate limited
        if (res.status === 429) {
          const ra = res.headers.get("Retry-After");
          const delay = ra ? parseInt(ra, 10) * 1000 : backoffDelay(attempt);
          console.warn(`[TripoClient] 429 rate limited, retry ${attempt + 1} in ${delay}ms`);
          await sleep(delay);
          lastError = new Error("Rate limited (429)");
          continue;
        }

        // 5xx — retryable
        if (res.status >= 500 && RETRY_CONFIG.retryableStatuses.has(res.status)) {
          if (attempt < RETRY_CONFIG.maxRetries) {
            const delay = backoffDelay(attempt);
            console.warn(`[TripoClient] ${res.status} server error, retry ${attempt + 1} in ${delay}ms`);
            await sleep(delay);
            lastError = new Error(`Server error (${res.status})`);
            continue;
          }
        }

        // Non-retryable HTTP error
        if (!res.ok) {
          const body = await res.text().catch(() => "");
          throw new Error(`Tripo API error (${res.status}): ${body.slice(0, 300)}`);
        }

        const json = await res.json();
        if (json.code !== 0) {
          throw new Error(`Tripo API code=${json.code}: ${json.message ?? "unknown error"}`);
        }
        return json;

      } catch (err) {
        clearTimeout(timer);
        if (err.name === "AbortError") {
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
  get(path) {
    return this.fetch(path, { method: "GET" });
  }

  post(path, body, idempotencyKey) {
    return this.fetch(
      path,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
      idempotencyKey,
    );
  }

  postForm(path, form) {
    return this.fetch(path, { method: "POST", body: form });
  }

  /* ── Task operations ──────────────────────────────────────────── */
  async createTask(taskBody, idempotencyKey) {
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

    const res = await this.post("/task", taskBody, idempotencyKey);
    const taskId = res.data?.task_id;
    if (!taskId) throw new Error(`No task_id in response: ${JSON.stringify(res).slice(0, 200)}`);
    return taskId;
  }

  async getTask(taskId) {
    const res = await this.get(`/task/${taskId}`);
    if (!res.data) throw new Error(`No task data for ${taskId}`);
    return res.data;
  }

  async cancelTask(taskId) {
    // Tripo API does not support task cancellation.
    // We only stop polling on the frontend side.
    console.log(`[TripoClient] cancel requested for ${taskId} — no-op (Tripo has no cancel endpoint)`);
    return { success: true, cancelled: false };
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

  async uploadFile(buffer, filename, mimeType) {
    const { Blob } = await import("buffer");
    const form = new FormData();
    form.append("file", new Blob([buffer], { type: mimeType }), filename);
    const res = await this.postForm("/upload", form);
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
        const out = task.output ?? {};
        return {
          success: true,
          status: "success",
          progress: 100,
          // FIX: converted_model, stylized_model, segmented_model, textured_model,
          //        refined_model hozzáadva — history cardban megjelenik
          modelUrl: out.pbr_model ?? out.textured_model ?? out.model
            ?? out.base_model ?? out.rigged_model ?? out.animated_model
            ?? out.converted_model ?? out.low_poly_model
            ?? out.segmented_model
            ?? out.stylized_model ?? out.refined_model ?? null,
          outputFormat: out.format ?? null,
          rigCheckResult: out.is_animatable ?? null,
          rawOutput: out,
        };
      }

      if (task.status === "failed" || task.status === "cancelled") {
        return {
          success: false, status: task.status, progress: task.progress ?? 0,
          modelUrl: null, rigCheckResult: null, rawOutput: null
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