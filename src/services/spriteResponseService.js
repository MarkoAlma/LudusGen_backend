async function runBestEffort(label, task, logger = console) {
  if (typeof task !== "function") return;

  try {
    await task();
  } catch (error) {
    logger?.warn?.(`[SpriteRouter] ${label} failed: ${error?.message || error}`);
  }
}

export async function finalizeSpriteSuccessResponse({
  responsePayload,
  cacheWriter,
  usageLogger,
  chargeGeneration,
  logger = console,
} = {}) {
  await runBestEffort("sprite cache write", cacheWriter, logger);
  await runBestEffort("sprite usage log", usageLogger, logger);

  const billing = typeof chargeGeneration === "function"
    ? await chargeGeneration()
    : responsePayload?.billing || null;

  if (responsePayload && billing) {
    responsePayload.billing = billing;
  }

  return {
    responsePayload,
    billing,
  };
}
