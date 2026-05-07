import assert from "node:assert/strict";

import {
  assertMeshyAccess,
  isMeshyEnabled,
} from "../meshyAccessService.js";

console.log("\nScenario 1: Meshy stays disabled by default even when an API key exists");
{
  assert.equal(isMeshyEnabled({ MESHY_API_KEY: "secret" }), false);
  assert.throws(
    () => assertMeshyAccess({ MESHY_API_KEY: "secret" }),
    (error) => error.code === "MESHY_DISABLED" && error.status === 403,
  );
}

console.log("\nScenario 2: Meshy becomes available only when the opt-in flag is explicitly enabled");
{
  assert.equal(isMeshyEnabled({ ENABLE_MESHY: "true", MESHY_API_KEY: "secret" }), true);
  assert.doesNotThrow(() => assertMeshyAccess({ ENABLE_MESHY: "true", MESHY_API_KEY: "secret" }));
}

console.log("\nScenario 3: explicit enable without credentials returns configuration error");
{
  assert.throws(
    () => assertMeshyAccess({ ENABLE_MESHY: "1" }),
    (error) => error.code === "MESHY_NOT_CONFIGURED" && error.status === 503,
  );
}

console.log("meshyAccessService assertions passed");
