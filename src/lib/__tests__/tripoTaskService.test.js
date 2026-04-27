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

console.log("tripoTaskService assertions passed");
