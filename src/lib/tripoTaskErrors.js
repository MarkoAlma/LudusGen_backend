function readErrorMessage(err) {
  return String(err?.message || "");
}

export function isMissingTripoTaskError(err) {
  const message = readErrorMessage(err);
  return message.includes("(404)") || message.includes("code=2001");
}

export function getTaskLookupHttpStatus(err) {
  return isMissingTripoTaskError(err) ? 410 : 500;
}
