import assert from "node:assert/strict";
import { taskService } from "../../services/taskService.js";

const multiview = taskService.validate({
  type: "multiview_to_model",
  model_version: "v3.1-20260211",
  files: [
    { type: "jpg", file_token: "front-token" },
    {},
    { type: "jpg", file_token: "back-token" },
    {},
  ],
});

assert.equal(multiview.files.length, 4);
assert.deepEqual(multiview.files[1], {});
assert.equal(multiview.files[0].file_token, "front-token");
assert.equal(multiview.files[2].file_token, "back-token");

assert.throws(
  () => taskService.validate({
    type: "multiview_to_model",
    model_version: "v3.1-20260211",
    files: [
      {},
      { type: "jpg", file_token: "left-token" },
      { type: "jpg", file_token: "back-token" },
      {},
    ],
  }),
  /front view is required/
);

assert.throws(
  () => taskService.validate({
    type: "multiview_to_model",
    model_version: "v3.1-20260211",
    files: [
      { type: "jpg", file_token: "front-token" },
      {},
      {},
      {},
    ],
  }),
  /at least two uploaded views/
);

const generatedViews = taskService.validate({
  type: "generate_multiview_image",
  file: { type: "jpg", file_token: "source-token" },
});

assert.equal(generatedViews.file.file_token, "source-token");

const editedViews = taskService.validate({
  type: "edit_multiview_image",
  original_task_id: "task-123",
  prompts: [{ prompt: "add a helmet", view: "front" }],
});

assert.equal(editedViews.original_task_id, "task-123");
assert.deepEqual(editedViews.prompts, [{ prompt: "add a helmet", view: "front" }]);

const generatedImage = taskService.validate({
  type: "generate_image",
  prompt: "hero warrior",
  model: "seedream_v4",
  template_id: "character_completion",
  negative_prompt: "blurry",
  compress: "geometry",
  orientation: "landscape",
  render_image: true,
  texture_alignment: "geometry",
  reference_image: { type: "png", file_token: "reference-token" },
});

assert.equal(generatedImage.model_version, "seedream_v4");
assert.equal(generatedImage.template, "character_completion");
assert.deepEqual(generatedImage.file, { type: "png", file_token: "reference-token" });
assert.equal(generatedImage.model, undefined);
assert.equal(generatedImage.template_id, undefined);
assert.equal(generatedImage.negative_prompt, undefined);
assert.equal(generatedImage.compress, undefined);
assert.equal(generatedImage.orientation, undefined);
assert.equal(generatedImage.render_image, undefined);
assert.equal(generatedImage.texture_alignment, undefined);
assert.equal(generatedImage.reference_image, undefined);

const promptOnlyGeneratedImage = taskService.validate({
  type: "generate_image",
  prompt: "hero warrior",
  model_version: "flux.1_dev",
  file: { type: "png", file_token: "reference-token" },
  files: [{ type: "png", file_token: "reference-token-2" }],
});

assert.equal(promptOnlyGeneratedImage.model_version, "flux.1_dev");
assert.equal(promptOnlyGeneratedImage.prompt, "hero warrior");
assert.equal(promptOnlyGeneratedImage.file, undefined);
assert.equal(promptOnlyGeneratedImage.files, undefined);

const multiReferenceGeneratedImage = taskService.validate({
  type: "generate_image",
  prompt: "hero warrior",
  model_version: "gpt_4o",
  files: Array.from({ length: 10 }, (_, index) => ({
    type: "png",
    file_token: `reference-token-${index}`,
  })),
});

assert.equal(multiReferenceGeneratedImage.file, undefined);
assert.equal(multiReferenceGeneratedImage.files.length, 10);

assert.throws(
  () => taskService.validate({
    type: "generate_image",
    prompt: "hero warrior",
    model_version: "flux.1_kontext_pro",
    files: Array.from({ length: 5 }, (_, index) => ({
      type: "png",
      file_token: `reference-token-${index}`,
    })),
  }),
  /maximum 4 reference images/
);

assert.throws(
  () => taskService.validate({
    type: "generate_image",
    prompt: "hero warrior",
    model_version: "flux.1_kontext_pro",
    file: { type: "webp", file_token: "webp-reference" },
  }),
  /does not support WebP/
);

assert.throws(
  () => taskService.validate({
    type: "image_to_model",
    model_version: "v3.1-20260211",
    batch_images: Array.from({ length: 11 }, (_, index) => ({
      type: "jpg",
      file_token: `image-token-${index}`,
    })),
  }),
  /maximum 10 images/
);
