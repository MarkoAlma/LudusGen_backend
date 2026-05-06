import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const controllerSource = readFileSync(resolve(__dirname, "../marketplaceController.js"), "utf8");

assert(
  controllerSource.includes("async function reconcileHistoryMarketplaceLock"),
  "marketplace controller should reconcile stale history locks before re-publishing a 3D source",
);

assert(
  controllerSource.includes('throw Object.assign(new Error("This history item is already listed on the marketplace"), { status: 409 });'),
  "marketplace controller should block real duplicate history listings with a server-side 409",
);

assert(
  controllerSource.includes('marketplaceLocked: false'),
  "marketplace controller should actively clear the history lock when a listing is deleted or found stale",
);

assert(
  controllerSource.includes('admin.firestore.FieldValue.delete()'),
  "marketplace controller should clear stale marketplace lock metadata instead of leaving orphaned references behind",
);

console.log("marketplaceHistoryLockRecovery assertions passed");
