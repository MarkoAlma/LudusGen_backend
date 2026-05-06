import crypto from "node:crypto";

const PROMPT_MAX = 500;
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/gi,
  /disregard\s+(all\s+)?previous\s+instructions/gi,
  /system\s*prompt/gi,
  /developer\s*message/gi,
  /jailbreak/gi,
];

export function sanitizeSpritePrompt(prompt) {
  if (typeof prompt !== "string") throw new Error("prompt is required");
  if (prompt.length > PROMPT_MAX) throw new Error(`prompt must be at most ${PROMPT_MAX} characters`);

  let sanitized = prompt
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/<\/?script[^>]*>/gi, " ");

  for (const pattern of INJECTION_PATTERNS) {
    sanitized = sanitized.replace(pattern, " ");
  }

  sanitized = sanitized.replace(/\s+/g, " ").trim();
  if (!sanitized) throw new Error("prompt must contain safe prompt content");
  return sanitized;
}

export function hashSpritePrompt(prompt) {
  return crypto.createHash("sha256").update(String(prompt || ""), "utf8").digest("hex");
}

export function verifySpriteWebhookSignature({ rawBody, signatureHeader, secret }) {
  if (!secret || !rawBody || !signatureHeader) return false;

  const signature = String(signatureHeader).startsWith("sha256=")
    ? String(signatureHeader).slice(7)
    : String(signatureHeader);
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex"));
  } catch {
    return false;
  }
}

export function getSpriteWebhookSecret(provider, env = process.env) {
  const key = `SPRITE_${String(provider || "").toUpperCase()}_WEBHOOK_SECRET`;
  return env[key] || env.SPRITE_WEBHOOK_SECRET || "";
}
