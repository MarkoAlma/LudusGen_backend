import assert from "node:assert/strict";

import {
  API_NO_BALANCE_MESSAGE,
  IMAGE_STUDIO_SUBSCRIPTION_REQUIRED_CODE,
  SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE,
  TRELLIS_API_LIMIT_REACHED_CODE,
  TRELLIS_API_UNAVAILABLE_CODE,
  TRIPO_API_NO_BALANCE_CODE,
  buildImageStudioAvailability,
  buildTrellisAvailability,
  buildTripoAvailability,
} from "../serviceAvailabilityService.js";

const tripoEmpty = buildTripoAvailability({ balance: 0 }, { requiredCredits: 1 });
assert.equal(tripoEmpty.available, false);
assert.equal(tripoEmpty.code, TRIPO_API_NO_BALANCE_CODE);
assert.equal(tripoEmpty.message, API_NO_BALANCE_MESSAGE);

const tripoAvailable = buildTripoAvailability({ balance: 25 }, { requiredCredits: 10 });
assert.equal(tripoAvailable.available, true);
assert.equal(tripoAvailable.code, null);
assert.equal(tripoAvailable.message, "");

const trellisLimited = buildTrellisAvailability({
  used: 10,
  limit: 10,
  apiKeyConfigured: true,
  now: new Date("2026-05-06T10:00:00.000Z"),
});
assert.equal(trellisLimited.available, false);
assert.equal(trellisLimited.code, TRELLIS_API_LIMIT_REACHED_CODE);
assert.equal(trellisLimited.message, SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE);
assert.equal(trellisLimited.remaining, 0);
assert.equal(trellisLimited.resetsAt, "2026-05-07T00:00:00.000Z");

const trellisMissingKey = buildTrellisAvailability({
  used: 0,
  limit: 10,
  apiKeyConfigured: false,
  now: new Date("2026-05-06T10:00:00.000Z"),
});
assert.equal(trellisMissingKey.available, false);
assert.equal(trellisMissingKey.code, TRELLIS_API_UNAVAILABLE_CODE);
assert.equal(trellisMissingKey.message, SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE);

const imageStudio = buildImageStudioAvailability();
assert.equal(imageStudio.available, false);
assert.equal(imageStudio.code, IMAGE_STUDIO_SUBSCRIPTION_REQUIRED_CODE);
assert.equal(imageStudio.message, SERVICE_TEMPORARILY_UNAVAILABLE_MESSAGE);

console.log("serviceAvailabilityService tests passed");
