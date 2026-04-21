/**
 * Extracts the primary model URL from a Tripo API task output object.
 * Priority order matches the Tripo API's output field precedence.
 * Both tripoClient.js and taskService.js must use this function — do not inline.
 *
 * @param {object} task - Raw task object from Tripo API
 * @returns {{ modelUrl: string|null, rigCheckResult: boolean|null, rigType: string|null, topology: string|null, rawOutput: object }}
 */
export function extractModelUrl(task) {
  const out = task.output ?? {};
  const modelUrl =
    out.pbr_model ??
    out.textured_model ??
    out.model ??
    out.model_url ??
    out.base_model ??
    out.rigged_model ??
    (Array.isArray(out.animated_models) && out.animated_models.length > 0
      ? out.animated_models[0]
      : out.animated_model) ??
    out.converted_model ??
    out.low_poly_model ??
    out.segmented_model ??
    out.stylized_model ??
    out.refined_model ??
    null;

  return {
    modelUrl,
    rigCheckResult: out.is_animatable ?? out.animatable ?? out.riggable ?? out.rig_check_result ?? null,
    rigType: out.rig_type ?? out.topology ?? null,
    topology: out.topology ?? null,
    rawOutput: out,
  };
}
