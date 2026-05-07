// src/services/webhookService.js
import crypto from "crypto";
import { analyticsService } from "./analyticsService.js";

const getWebhookSecret = () =>
  process.env.TRIPO_WEBHOOK_SECRET ?? process.env.TRIPO3D_API_KEY ?? "";

class WebhookService {
  constructor() {
    /** @type {Map<string, { taskId: string, callback: Function, registeredAt: number, ttlMs: number }>} */
    this._callbacks = new Map();
  }

  register(taskId, callback, ttlMs = 600_000) {
    this._callbacks.set(taskId, { taskId, callback, registeredAt: Date.now(), ttlMs });
    setTimeout(() => {
      const reg = this._callbacks.get(taskId);
      if (reg && Date.now() - reg.registeredAt >= reg.ttlMs) this._callbacks.delete(taskId);
    }, ttlMs);
  }

  /** @param {Buffer} rawBody @param {string} signatureHeader */
  verifySignature(rawBody, signatureHeader) {
    const secret = getWebhookSecret();
    if (!secret) { console.warn("[WebhookService] No webhook secret configured"); return true; }
    if (!signatureHeader) return false;

    const sig = signatureHeader.startsWith("sha256=") ? signatureHeader.slice(7) : signatureHeader;
    const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");

    try {
      return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
    } catch { return false; }
  }

  async handlePayload(payload) {
    const { task_id, status, progress } = payload;

    if (["success", "failed", "cancelled"].includes(status))
      analyticsService.recordTaskEnd(task_id, status, 0);

    const reg = this._callbacks.get(task_id);
    if (reg) {
      try   { await reg.callback(payload); }
      catch (err) { console.error(`[WebhookService] callback error task=${task_id}:`, err.message); }
      finally {
        if (["success", "failed", "cancelled"].includes(status))
          this._callbacks.delete(task_id);
      }
    }
  }

  buildTestPayload(taskId, status) {
    const payload = { task_id: taskId, type: "text_to_model", status, progress: status === "success" ? 100 : 50, timestamp: Date.now() };
    const body    = Buffer.from(JSON.stringify(payload));
    const secret  = getWebhookSecret();
    const signature = secret ? "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex") : "unsigned";
    return { payload, signature };
  }

  get pendingCount() { return this._callbacks.size; }
}

export const webhookService = new WebhookService();