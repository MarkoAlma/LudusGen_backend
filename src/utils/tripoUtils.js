/**
 * Extracts the primary model URL from a Tripo API task output object.
 * Priority order matches the Tripo API's output field precedence.
 * Both tripoClient.js and taskService.js must use this function — do not inline.
 *
 * @param {object} task - Raw task object from Tripo API
 * @param {{ preferBaseModel?: boolean, preferPbrModel?: boolean }} [opts]
 * @returns {{ modelUrl: string|null, chosenSource: string|null, rigCheckResult: boolean|null, rigType: string|null, topology: string|null, rawOutput: object, previewImageUrl: string|null, previewImageUrls: string[] }}
 */
export function extractModelUrl(task, opts = {}) {
  const out = task.output ?? {};
  const taskType = task.type ?? null;
  const animatedModel =
    Array.isArray(out.animated_models) && out.animated_models.length > 0
      ? out.animated_models[0]
      : out.animated_model;
  const hasExplicitTexturedVariants = Boolean(out.pbr_model || out.textured_model);
  const shouldPreferTextured =
    opts.preferPbrModel === true || taskType === "texture_model";
  const shouldPreferDraft =
    opts.preferBaseModel === true ||
    (!shouldPreferTextured &&
      ["text_to_model", "image_to_model", "multiview_to_model", "refine_model"].includes(taskType));
  let orderedOutputs;

  if (shouldPreferTextured) {
    orderedOutputs = [
      { key: "pbr_model", value: out.pbr_model },
      { key: "model", value: out.model },
      { key: "textured_model", value: out.textured_model },
      { key: "model_url", value: out.model_url },
      { key: "base_model", value: out.base_model },
      { key: "rigged_model", value: out.rigged_model },
      { key: "animated_model", value: animatedModel },
      { key: "converted_model", value: out.converted_model },
      { key: "low_poly_model", value: out.low_poly_model },
      { key: "segmented_model", value: out.segmented_model },
      { key: "stylized_model", value: out.stylized_model },
      { key: "refined_model", value: out.refined_model },
    ];
  } else if (shouldPreferDraft) {
    orderedOutputs = [
      { key: "base_model", value: hasExplicitTexturedVariants ? out.base_model : null },
      { key: "model", value: out.model },
      { key: "model_url", value: out.model_url },
      { key: "base_model", value: out.base_model },
      { key: "pbr_model", value: out.pbr_model },
      { key: "textured_model", value: out.textured_model },
      { key: "rigged_model", value: out.rigged_model },
      { key: "animated_model", value: animatedModel },
      { key: "converted_model", value: out.converted_model },
      { key: "low_poly_model", value: out.low_poly_model },
      { key: "segmented_model", value: out.segmented_model },
      { key: "stylized_model", value: out.stylized_model },
      { key: "refined_model", value: out.refined_model },
    ];
  } else {
    orderedOutputs = [
      { key: "pbr_model", value: out.pbr_model },
      { key: "textured_model", value: out.textured_model },
      { key: "model", value: out.model },
      { key: "model_url", value: out.model_url },
      { key: "base_model", value: out.base_model },
      { key: "rigged_model", value: out.rigged_model },
      { key: "animated_model", value: animatedModel },
      { key: "converted_model", value: out.converted_model },
      { key: "low_poly_model", value: out.low_poly_model },
      { key: "segmented_model", value: out.segmented_model },
      { key: "stylized_model", value: out.stylized_model },
      { key: "refined_model", value: out.refined_model },
    ];
  }
  const selected = orderedOutputs.find((entry) => Boolean(entry.value)) ?? null;
  const modelUrl = selected?.value ?? null;
  const previewImageUrls = extractPreviewImages(out);
  const previewImageUrl = previewImageUrls[0] ?? null;

  return {
    modelUrl,
    chosenSource: selected?.key ?? null,
    rigCheckResult: out.is_animatable ?? out.animatable ?? out.riggable ?? out.rig_check_result ?? null,
    rigType: out.rig_type ?? out.topology ?? null,
    topology: out.topology ?? null,
    rawOutput: out,
    previewImageUrl,
    previewImageUrls,
  };
}

function extractUrlFromNode(node) {
  if (!node) return null;
  if (typeof node === "string") return node;
  if (Array.isArray(node)) {
    for (const item of node) {
      const value = extractUrlFromNode(item);
      if (value) return value;
    }
    return null;
  }
  if (typeof node !== "object") return null;

  return (
    node.url ??
    node.image_url ??
    node.rendered_image_url ??
    node.preview_url ??
    node.file_url ??
    null
  );
}

export function extractPreviewImages(out = {}) {
  const candidates = [
    out.rendered_image,
    out.rendered_images,
    out.preview_image,
    out.preview_images,
    out.image,
    out.images,
    out.generated_image,
    out.generated_images,
    out.multiview_images,
    out.views,
  ];

  const urls = [];
  for (const candidate of candidates) {
    if (!candidate) continue;
    if (Array.isArray(candidate)) {
      candidate.forEach((item) => {
        const url = extractUrlFromNode(item);
        if (url) urls.push(url);
      });
      continue;
    }
    const url = extractUrlFromNode(candidate);
    if (url) urls.push(url);
  }

  return [...new Set(urls)];
}
