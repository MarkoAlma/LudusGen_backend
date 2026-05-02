import assert from "node:assert/strict";

import { parseWebhookPayload } from "../webhookController.js";

const payload = { task_id: "task_123", status: "failed", error_msg: "provider failed" };
const raw = Buffer.from(JSON.stringify(payload));

assert.deepEqual(
  parseWebhookPayload(raw, raw),
  payload,
  "webhook parser should parse raw Buffer bodies produced by express.raw",
);

assert.deepEqual(
  parseWebhookPayload(payload, raw),
  payload,
  "webhook parser should keep already parsed JSON payloads intact",
);

assert.throws(
  () => parseWebhookPayload(Buffer.from("{"), Buffer.from("{")),
  /Invalid webhook JSON payload/,
  "webhook parser should reject invalid raw JSON",
);

console.log("webhook payload parsing assertions passed");
