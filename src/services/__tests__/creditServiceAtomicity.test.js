import assert from "node:assert/strict";

import { makeCreditTransactionDocId } from "../creditService.js";

assert.equal(
  makeCreditTransactionDocId("debit", "task_123"),
  "debit_task_123",
  "credit transaction doc IDs should be deterministic for idempotent transaction writes",
);

assert.equal(
  makeCreditTransactionDocId("refund", "task/with/slash"),
  "refund_task_with_slash",
  "credit transaction doc IDs should sanitize Firestore path separators",
);

assert.throws(
  () => makeCreditTransactionDocId("debit", ""),
  /taskId required/,
  "credit transaction doc IDs should reject empty task IDs",
);

console.log("credit service atomicity assertions passed");
