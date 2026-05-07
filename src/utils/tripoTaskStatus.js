const FAILED_LIKE_STATUSES = new Set(["failed", "cancelled", "banned"]);
const TERMINAL_STATUSES = new Set(["success", ...FAILED_LIKE_STATUSES]);

export function normalizeTripoTaskStatus(status) {
  const normalized = String(status || "").trim().toLowerCase();
  if (normalized === "banned") return "failed";
  return normalized || "unknown";
}

export function isTerminalTripoTaskStatus(status) {
  return TERMINAL_STATUSES.has(String(status || "").trim().toLowerCase());
}

export function isFailedLikeTripoTaskStatus(status) {
  return FAILED_LIKE_STATUSES.has(String(status || "").trim().toLowerCase());
}

export function getTripoTaskErrorMessage(task = {}) {
  const status = String(task.status || "").trim().toLowerCase();
  const out = task.output ?? task.rawOutput ?? {};
  const explicit =
    task.error_msg ??
    task.error_message ??
    task.error ??
    task.message ??
    task.reason ??
    out.error_msg ??
    out.error_message ??
    out.error ??
    out.message ??
    out.reason ??
    null;

  if (explicit) return explicit;
  if (status === "banned") return "Content blocked by Tripo moderation. Credits will be refunded automatically.";
  if (status === "cancelled") return "Task cancelled.";
  if (status === "failed") return "Task failed on Tripo.";
  return null;
}

export { FAILED_LIKE_STATUSES, TERMINAL_STATUSES };
