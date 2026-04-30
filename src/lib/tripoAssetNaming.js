const OPERATION_PREFIX = {
  segment: "Segmented",
  fill_parts: "Completed",
  retopo: "Retopo",
  texture: "Textured",
  refine: "Refined",
  stylize: "Stylized",
  rig: "Rigged",
  animate: "Animated",
};

function clampWords(value, maxWords = 4) {
  return String(value || "")
    .trim()
    .replace(/[_/\\|-]+/g, " ")
    .replace(/\s+/g, " ")
    .split(" ")
    .filter(Boolean)
    .slice(0, maxWords)
    .join(" ");
}

function titleCase(value) {
  return clampWords(value)
    .split(" ")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ")
    .trim();
}

export function normalizeTripoAssetName(value) {
  return titleCase(
    String(value || "")
      .replace(/^["'\s]+|["'\s]+$/g, "")
      .replace(/[.!,;:]+$/g, "")
  );
}

export function buildTripoAssetNameFallback({
  mode = "generate",
  sourceName = "",
  basePrompt = "",
  prompt = "",
}) {
  const sourceBase = titleCase(clampWords(sourceName, 3));
  const promptBase = titleCase(clampWords(basePrompt || prompt, 3));
  const prefix = OPERATION_PREFIX[mode] || "";

  if (prefix && sourceBase) {
    return normalizeTripoAssetName(`${prefix} ${sourceBase}`);
  }
  if (promptBase) {
    return promptBase;
  }
  if (sourceBase) {
    return sourceBase;
  }
  return prefix ? `${prefix} Model` : "Tripo Model";
}

export function buildTripoAssetNamingMessages({
  mode = "generate",
  type = "text_to_model",
  prompt = "",
  basePrompt = "",
  styleId = "",
  sourceName = "",
  negativePrompt = "",
  modelVersion = "",
}) {
  const system = [
    "You are an elite 3D asset naming assistant for a Tripo3D generation pipeline.",
    "Return raw JSON only with this exact shape: {\"name\":\"...\",\"summary\":\"...\"}.",
    "The name must be 2 to 4 words, Title Case, concise, memorable, and production-usable.",
    "Prefer the core subject over filler words. Preserve meaningful style identity when it helps distinguish the asset.",
    "For post-process operations, keep the original asset identity and reflect the operation only if it adds clarity.",
    "The summary must be a short 8 to 18 word internal descriptor of the asset concept.",
    "Do not return markdown. Do not return explanations.",
  ].join(" ");

  const user = [
    `mode: ${mode}`,
    `type: ${type}`,
    `style preset: ${styleId || "none"}`,
    `base prompt: ${basePrompt || "none"}`,
    `full prompt: ${prompt || "none"}`,
    `source asset name: ${sourceName || "none"}`,
    `negative prompt: ${negativePrompt || "none"}`,
    `model version: ${modelVersion || "unknown"}`,
  ].join("\n");

  return [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
}
