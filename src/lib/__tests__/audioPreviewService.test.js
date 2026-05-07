import assert from "node:assert/strict";

const service = await import("../../services/audioPreviewService.js");

assert.equal(typeof service.createWatermarkedAudioPreview, "function");
