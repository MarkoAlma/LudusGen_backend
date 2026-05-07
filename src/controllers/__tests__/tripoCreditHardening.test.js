import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../../..");
const read = (path) => readFileSync(resolve(root, path), "utf8");

const taskController = read("src/controllers/taskController.js");
const pipelineController = read("src/controllers/pipelineController.js");
const pipelineService = read("src/services/pipelineService.js");
const lodService = read("src/services/lodService.js");
const worker = read("src/workers/tripoWorker.js");

assert(
  taskController.includes("reserveCreditsForTask") && taskController.includes("handleBillingErrorResponse"),
  "createTask should reserve credits through a shared billing helper and stop when reservation fails",
);

assert(
  taskController.includes("batchReservations") && taskController.includes("refundCreditReservation"),
  "batch image creation should reserve and refund credits per subtask, not with one shared debit",
);

assert(
  pipelineController.includes("userId: req.user?.uid") &&
    pipelineService.includes("createTaskWithBilling") &&
    lodService.includes("createTaskWithBilling"),
  "pipeline and LOD task creation should run through billed Tripo task creation",
);

assert(
  worker.includes("linkTaskIdToTransaction") &&
    worker.includes("job.data.billing") &&
    worker.includes("_tripoTaskId"),
  "queue worker should link billing to the real Tripo taskId and reuse existing task IDs on retry",
);

const workerTaskIdPersistIndex = worker.indexOf("await job.updateData({ ...job.data, _tripoTaskId: taskId");
const workerBillingLinkIndex = worker.indexOf("await linkTaskIdToTransaction");
assert(
  workerTaskIdPersistIndex !== -1 &&
    workerBillingLinkIndex !== -1 &&
    workerTaskIdPersistIndex < workerBillingLinkIndex,
  "queue worker should persist the provider taskId before billing-link work so retries cannot orphan a paid Tripo task",
);

assert(
  worker.includes("billingLinkMapped") &&
    worker.includes("continuing with durable billing link"),
  "queue worker should continue polling when a durable pending billing link exists but the debit update still needs retry/recovery",
);

const workerRecoveryRegisterIndex = worker.indexOf("await registerWorkerTaskForRecovery(job, taskId, billing)");
assert(
  worker.includes("persistPendingRecoveryTask") &&
    worker.includes("startTaskRecovery()") &&
    workerRecoveryRegisterIndex !== -1 &&
    workerRecoveryRegisterIndex < workerBillingLinkIndex,
  "queue worker should persist/register provider tasks for recovery before billing-link or poll failures can strand the debit",
);

assert(
  worker.includes("await registerWorkerTaskForRecovery(job, job.data._tripoTaskId, billing)"),
  "queue worker final failure should re-register known provider taskIds for recovery after poll timeouts",
);

assert(
  taskController.includes("const directBatchPlans = []") &&
    taskController.includes("for (const plan of directBatchPlans)"),
  "direct image batch creation should reserve every batch item before creating any provider task",
);

assert(
  taskController.includes("refundUncreatedDirectBatchReservations"),
  "direct image batch failures should refund reservations for batch items whose provider task was never created",
);

console.log("tripo credit hardening assertions passed");
