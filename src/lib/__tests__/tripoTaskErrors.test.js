import assert from "node:assert/strict";
import {
  isMissingTripoTaskError,
  getTaskLookupHttpStatus,
} from "../tripoTaskErrors.js";

assert.equal(
  isMissingTripoTaskError(new Error("Tripo API error (404): code=2001: task not found")),
  true,
  "404 task lookup errors should be recognized as missing Tripo tasks",
);

assert.equal(
  isMissingTripoTaskError(new Error("Tripo API code=2001: resource missing")),
  true,
  "Tripo code 2001 should be treated as a missing task even without an HTTP status",
);

assert.equal(
  isMissingTripoTaskError(new Error("Tripo API error (500): upstream failed")),
  false,
  "generic upstream errors must not be treated as missing tasks",
);

assert.equal(
  getTaskLookupHttpStatus(new Error("Tripo API error (404): code=2001: task not found")),
  410,
  "missing Tripo tasks should map to HTTP 410 Gone",
);

assert.equal(
  getTaskLookupHttpStatus(new Error("Tripo API error (500): upstream failed")),
  500,
  "unexpected Tripo errors should stay as HTTP 500",
);
