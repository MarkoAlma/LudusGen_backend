/**
 * Extracts the primary model URL from a Tripo API task output object.
 * Priority order matches the Tripo API's output field precedence.
 * Both tripoClient.js and taskService.js must use this function — do not inline.
 *
 * @param {object} task - Raw task object from Tripo API
 * @param {{ preferBaseModel?: boolean, preferPbrModel?: boolean }} [opts]
 * @returns {{ modelUrl: string|null, rigCheckResult: boolean|null, rigType: string|null, topology: string|null, rawOutput: object }}
 */
export function extractModelUrl(task, opts = {}) {
  const out = task.output ?? {};
  const animatedModel =
    Array.isArray(out.animated_models) && out.animated_models.length > 0
      ? out.animated_models[0]
      : out.animated_model;
  const orderedUrls = [
    opts.preferPbrModel ? out.pbr_model : null,
    opts.preferPbrModel ? out.textured_model : null,
    opts.preferBaseModel ? out.base_model : null,
    out.pbr_model,
    out.textured_model,
    out.model,
    out.model_url,
    out.base_model,
    out.rigged_model,
    animatedModel,
    out.converted_model,
    out.low_poly_model,
    out.segmented_model,
    out.stylized_model,
    out.refined_model,
  ];
  const modelUrl =
    orderedUrls.find(Boolean) ?? null;

  return {
    modelUrl,
    rigCheckResult: out.is_animatable ?? out.animatable ?? out.riggable ?? out.rig_check_result ?? null,
    rigType: out.rig_type ?? out.topology ?? null,
    topology: out.topology ?? null,
    rawOutput: out,
  };
}
