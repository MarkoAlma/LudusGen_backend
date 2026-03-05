// src/controllers/webhookController.js
import { webhookService } from "../services/webhookService.js";

export async function handleWebhook(req, res) {
  // Signature verification — raw body must be captured by express.raw() middleware
  const rawBody   = req.rawBody ?? Buffer.from(JSON.stringify(req.body));
  const sigHeader = (req.headers["x-tripo-signature"] ?? "");

  if (!webhookService.verifySignature(rawBody, sigHeader)) {
    console.warn("[WebhookController] invalid signature — rejecting");
    res.status(401).json({ success: false, message: "Invalid webhook signature" });
    return;
  }

  try {
    const payload = req.body;
    if (!payload.task_id || !payload.status) {
      res.status(400).json({ success: false, message: "Invalid webhook payload: task_id and status required" });
      return;
    }

    // Acknowledge immediately — process async
    res.json({ success: true, received: true });

    await webhookService.handlePayload(payload);
  } catch (err) {
    console.error("[WebhookController] handleWebhook error:", err.message);
    // Already responded 200 above — nothing to do
  }
}

export async function testWebhook(req, res) {
  if (process.env.NODE_ENV === "production") {
    res.status(403).json({ success: false, message: "Test endpoint disabled in production" });
    return;
  }
  const { task_id = "test_task", status = "success" } = req.body;
  const { payload, signature } = webhookService.buildTestPayload(task_id, status);
  res.json({ success: true, payload, signature, pendingCallbacks: webhookService.pendingCount });
}