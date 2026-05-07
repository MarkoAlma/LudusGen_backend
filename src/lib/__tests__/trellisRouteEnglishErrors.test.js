import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(resolve(__dirname, "../../../ai-routes.js"), "utf8");
const start = source.indexOf("router.post('/trellis'");
const end = source.indexOf("router.post('/chat/summary'", start);
const trellisRouteSource = source.slice(start, end);

assert(start > -1 && end > start, "Trellis route source should be discoverable");

for (const expected of [
  "Prompt is required.",
  "Prompt must be 1000 characters or fewer.",
  "Trellis prompts must be",
  "NVIDIA_API_KEY is not configured.",
  "Invalid NVIDIA API key",
  "The Trellis API response did not include a 3D model. Try a shorter prompt or another style.",
  "Generation cancelled.",
  "Network error",
]) {
  assert(
    trellisRouteSource.includes(expected),
    `Trellis route should expose English error copy: missing ${expected}`,
  );
}

assert.doesNotMatch(
  trellisRouteSource,
  /Ă|Ä|Å|PrÄ|GenerĂ|megad|karakter|modellt|stÄ|hĂ|HĂ/,
  "Trellis route generation errors should not contain Hungarian mojibake text",
);

console.log("trellis route English error assertions passed");
