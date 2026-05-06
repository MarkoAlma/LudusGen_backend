import { SUPPORTED_SPRITE_PROVIDERS } from "./spriteRouting.js";

export const SPRITE_OPERATION_DEFINITIONS = {
  static_sprite: {
    label: "Static sprite",
    providers: ["pixellab", "segmind", "godmode"],
    requiresReference: false,
  },
  sprite_sheet: {
    label: "Sprite sheet",
    providers: ["pixellab", "godmode", "segmind"],
    requiresReference: false,
  },
  text_animation: {
    label: "Text animation",
    providers: ["pixellab", "godmode"],
    requiresReference: true,
  },
  skeleton_animation: {
    label: "Skeleton animation",
    providers: ["pixellab"],
    requiresReference: true,
  },
  rotation_4: {
    label: "4-way rotation",
    providers: ["pixellab"],
    requiresReference: true,
  },
  rotation_8: {
    label: "8-way rotation",
    providers: ["pixellab"],
    requiresReference: true,
  },
  spine_export: {
    label: "Spine export",
    providers: ["godmode"],
    requiresReference: true,
  },
  layered_export: {
    label: "Layered export",
    providers: ["godmode"],
    requiresReference: true,
  },
  retarget_animation: {
    label: "Retarget animation",
    providers: ["godmode"],
    requiresReference: true,
  },
  flux_image: {
    label: "FLUX image",
    providers: ["segmind"],
    requiresReference: false,
  },
  sdxl_image: {
    label: "SDXL image",
    providers: ["segmind"],
    requiresReference: false,
  },
  batch_generation: {
    label: "Batch generation",
    providers: ["segmind"],
    requiresReference: false,
  },
};

export const SPRITE_PROVIDER_CAPABILITIES = {
  pixellab: {
    label: "PixelLab",
    bestFor: ["pixel art", "rotations", "sprite sheets", "skeleton animation"],
    operations: [
      "static_sprite",
      "sprite_sheet",
      "text_animation",
      "skeleton_animation",
      "rotation_4",
      "rotation_8",
    ],
    endpoints: {
      generate: "/generate-image-pixflux",
      rotate: "/rotate",
      animateText: "/animate-with-text",
      animateSkeleton: "/animate-with-skeleton",
      estimateSkeleton: "/estimate-skeleton",
      bitforge: "/generate-image-bitforge",
    },
    constraints: {
      maxStaticSize: 400,
      maxRotateSize: 128,
      maxSkeletonSize: 256,
      animationFrameCounts: [4, 6, 8, 10, 12, 14, 16],
    },
  },
  godmode: {
    label: "God Mode AI",
    bestFor: ["Spine", "auto-rig", "layered export", "retargeting"],
    operations: [
      "static_sprite",
      "sprite_sheet",
      "text_animation",
      "spine_export",
      "layered_export",
      "retarget_animation",
    ],
    endpoints: {
      sprite: "/v1/sprite/generate",
      rig: "/v1/sprite/generate",
      retarget: "/v1/sprite/generate",
    },
    constraints: {
      exportFormats: ["png", "spine", "layers", "atlas_json"],
    },
  },
  segmind: {
    label: "Segmind",
    bestFor: ["anime", "cartoon", "illustrated", "FLUX", "SDXL", "batch"],
    operations: [
      "static_sprite",
      "sprite_sheet",
      "flux_image",
      "sdxl_image",
      "batch_generation",
    ],
    endpoints: {
      workflow: "SEGMIND_SPRITE_WORKFLOW_URL",
      flux: "/v1/flux-schnell",
      fastFlux: "/v1/fast-flux-schnell",
    },
    constraints: {
      maxImageSize: 2048,
      maxBatchCount: 8,
    },
  },
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

export function getSpriteCapabilities() {
  return {
    providers: clone(SPRITE_PROVIDER_CAPABILITIES),
    operations: clone(SPRITE_OPERATION_DEFINITIONS),
    providerOrder: [...SUPPORTED_SPRITE_PROVIDERS],
  };
}

export function providerSupportsSpriteOperation(provider, operation) {
  return Boolean(SPRITE_PROVIDER_CAPABILITIES[provider]?.operations.includes(operation));
}

export function getSpriteProvidersForOperation(operation) {
  return SPRITE_OPERATION_DEFINITIONS[operation]?.providers || [...SUPPORTED_SPRITE_PROVIDERS];
}

export function getSpriteOperation(request = {}) {
  const options = request.options || {};
  const output = options.output || "auto";
  const model = String(options.model || "").toLowerCase();

  if (output === "spine") return "spine_export";
  if (output === "layered") return "layered_export";
  if (output === "retarget") return "retarget_animation";
  if (output === "animation_skeleton" || options.skeletonKeypoints?.length) return "skeleton_animation";
  if (output === "rotation" || options.directionSet === "4-way") return options.directionSet === "8-way" ? "rotation_8" : "rotation_4";
  if (options.directionSet === "8-way") return "rotation_8";
  if (output === "animation" || output === "animation_text") return "text_animation";
  if (output === "batch" || Number(options.batchCount) > 1) return "batch_generation";
  if (model.includes("sdxl")) return "sdxl_image";
  if (model.includes("flux")) return "flux_image";
  if (output === "sprite_sheet") return "sprite_sheet";
  return "static_sprite";
}

export function resolveSpriteCapabilityRoute(route, request) {
  const operation = getSpriteOperation(request);
  const currentProvider = route?.provider || "segmind";
  if (providerSupportsSpriteOperation(currentProvider, operation)) {
    return {
      ...route,
      operation,
    };
  }

  const targetProvider = SPRITE_OPERATION_DEFINITIONS[operation]?.providers?.[0] || currentProvider;
  return {
    ...route,
    provider: targetProvider,
    strategy: "capability",
    confidence: 1,
    matchedKeywords: route?.matchedKeywords || [],
    operation,
    reason: `${operation} is supported by ${targetProvider}, not ${currentProvider}.`,
  };
}

export function spriteOperationRequiresReference(operation) {
  return Boolean(SPRITE_OPERATION_DEFINITIONS[operation]?.requiresReference);
}
