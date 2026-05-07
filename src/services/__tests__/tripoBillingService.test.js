import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { reserveCreditsForTask } from "../tripoBillingService.js";

await assert.rejects(
  () => reserveCreditsForTask({ userId: "user-1", amount: Number.NaN, taskType: "text_to_model" }),
  /Invalid credit amount/,
  "billing reservations should reject invalid credit amounts before touching Firestore",
);

const source = readFileSync(resolve(import.meta.dirname, "../tripoBillingService.js"), "utf8");
const linkReservationFn = source.match(/export async function linkReservationToTask[\s\S]*?\n}/)?.[0] ?? "";
assert(
  /catch\s*\([^)]*\)\s*{[\s\S]*throw\s+err\s*;[\s\S]*}/.test(linkReservationFn),
  "billing link failures should be thrown to callers instead of silently continuing with an unlinked debit",
);

assert(
  linkReservationFn.includes("err.billingLinkMapped") &&
    /if\s*\(!err\.billingLinkMapped\)\s*throw\s+err\s*;/.test(linkReservationFn),
  "billing link failures with a durable pending map should not force a user-visible createTask failure",
);

console.log("tripo billing service assertions passed");
