import {
  encodeImageGalleryCursor,
  decodeImageGalleryCursor,
  clampImageGalleryLimit,
} from "../imageGalleryCursor.js";

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    passed++;
  } else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

{
  const encoded = encodeImageGalleryCursor({ createdAtMs: 1714000000000, id: "abc123" });
  const decoded = decodeImageGalleryCursor(encoded);
  assert(decoded?.createdAtMs === 1714000000000, "createdAtMs should survive round-trip");
  assert(decoded?.id === "abc123", "id should survive round-trip");
}

{
  const decoded = decodeImageGalleryCursor("not-a-valid-cursor");
  assert(decoded === null, "invalid cursor should decode to null");
}

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

{
  assert(clampImageGalleryLimit(undefined) === 24, "default limit should be 24");
  assert(clampImageGalleryLimit(3) === 3, "small explicit limit should pass through");
  assert(clampImageGalleryLimit(999) === 48, "limit should be capped at 48");
}

if (failed > 0) {
  process.exit(1);
}
