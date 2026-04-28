import {
  encodeImageGalleryCursor,
  decodeImageGalleryCursor,
  clampImageGalleryLimit,
} from "../imageGalleryCursor.js";

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  PASS: ${label}`);
    passed++;
  } else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

console.log("\nScenario 1: cursor round-trip");
{
  const encoded = encodeImageGalleryCursor({ createdAtMs: 1714000000000, id: "abc123" });
  const decoded = decodeImageGalleryCursor(encoded);
  assert(decoded?.createdAtMs === 1714000000000, "createdAtMs should survive round-trip");
  assert(decoded?.id === "abc123", "id should survive round-trip");
}

console.log("\nScenario 2: invalid cursor is ignored");
{
  const decoded = decodeImageGalleryCursor("not-a-valid-cursor");
  assert(decoded === null, "invalid cursor should decode to null");
}

console.log("\nScenario 3: invalid payload fields are rejected");
{
  const invalidCreatedAtCursor = Buffer.from(
    JSON.stringify({ createdAtMs: "not-a-number", id: "abc123" })
  ).toString("base64url");
  const zeroCreatedAtCursor = Buffer.from(
    JSON.stringify({ createdAtMs: 0, id: "abc123" })
  ).toString("base64url");
  const negativeCreatedAtCursor = Buffer.from(
    JSON.stringify({ createdAtMs: -10, id: "abc123" })
  ).toString("base64url");
  const missingCreatedAtCursor = Buffer.from(JSON.stringify({ id: "abc123" })).toString(
    "base64url"
  );
  const missingIdCursor = Buffer.from(JSON.stringify({ createdAtMs: 1714000000000 })).toString(
    "base64url"
  );
  const emptyIdCursor = Buffer.from(
    JSON.stringify({ createdAtMs: 1714000000000, id: "" })
  ).toString("base64url");

  assert(
    decodeImageGalleryCursor(invalidCreatedAtCursor) === null,
    "invalid createdAtMs should decode to null"
  );
  assert(
    decodeImageGalleryCursor(zeroCreatedAtCursor) === null,
    "zero createdAtMs should decode to null"
  );
  assert(
    decodeImageGalleryCursor(negativeCreatedAtCursor) === null,
    "negative createdAtMs should decode to null"
  );
  assert(
    decodeImageGalleryCursor(missingCreatedAtCursor) === null,
    "missing createdAtMs should decode to null"
  );
  assert(
    decodeImageGalleryCursor(missingIdCursor) === null,
    "missing id should decode to null"
  );
  assert(
    decodeImageGalleryCursor(emptyIdCursor) === null,
    "empty id should decode to null"
  );
}

console.log("\nScenario 4: limit clamp");
{
  assert(clampImageGalleryLimit(undefined) === 24, "default limit should be 24");
  assert(clampImageGalleryLimit(3) === 3, "small explicit limit should pass through");
  assert(clampImageGalleryLimit(999) === 48, "limit should be capped at 48");
}

console.log(`\nResults: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
  process.exit(1);
}
console.log("ALL GALLERY CURSOR TESTS PASSED");
