import assert from "node:assert/strict";
import test from "node:test";
import { clearAuthTokens, logoutSession } from "./auth.js";

test("logout clears both persisted authentication tokens", () => {
  const values = new Map([
    ["gds_access_token", "access-test-token"],
    ["gds_refresh_token", "refresh-test-token"],
    ["unrelated", "preserved"],
  ]);
  const storage = {
    removeItem(key) { values.delete(key); },
  };

  clearAuthTokens(storage);

  assert.equal(values.has("gds_access_token"), false);
  assert.equal(values.has("gds_refresh_token"), false);
  assert.equal(values.get("unrelated"), "preserved");
});

test("logout revokes access and refresh tokens through the API", async () => {
  const values = new Map([
    ["gds_access_token", "access-test-token"],
    ["gds_refresh_token", "refresh-test-token"],
  ]);
  const storage = {
    getItem(key) { return values.get(key) || null; },
    removeItem(key) { values.delete(key); },
  };
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    return { ok: true };
  };

  await logoutSession({ storage, apiUrl: "http://api.test/api/v1", fetchImpl });

  assert.equal(values.size, 0);
  assert.equal(requests.length, 2);
  assert.deepEqual(requests.map(({ options }) => options.headers.Authorization), [
    "Bearer access-test-token",
    "Bearer refresh-test-token",
  ]);
  assert.ok(requests.every(({ url }) => url === "http://api.test/api/v1/auth/logout"));
});
