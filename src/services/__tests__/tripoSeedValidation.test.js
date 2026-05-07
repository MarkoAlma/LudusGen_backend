import assert from "node:assert/strict";
import { taskService } from "../taskService.js";

{
  const validated = taskService.validate({
    type: "text_to_model",
    prompt: "ornate fantasy sword",
    model_version: "P1-20260311",
    texture: false,
    pbr: false,
    model_seed: 11,
    image_seed: 22,
    texture_seed: 33,
  });

  assert.equal(validated.model_seed, 11);
  assert.equal(validated.image_seed, 22);
  assert.equal(validated.texture_seed, 33);
}

console.log("tripo seed validation assertions passed");
