import test from "node:test";
import assert from "node:assert/strict";
import { assignableRoles, fetchAssignableRoles, submittedRoleId } from "./roles.js";

test("role dropdown accepts configured canonical role rows", () => {
  const roles = ["Admin", "Developer", "Approver", "Viewer"].map((name, index) => ({ id: index + 1, name, configured: true }));
  assert.deepEqual(assignableRoles(roles), roles);
});

test("role dropdown excludes unconfigured roles, invalid IDs, and unsupported roles", () => {
  assert.deepEqual(assignableRoles([
    { id: null, name: "Admin", configured: false },
    { id: 2, name: "Auditor", configured: true },
    { id: "3", name: "Developer", configured: true },
  ]), []);
});

test("empty or failed role responses safely produce no assignable options", () => {
  assert.deepEqual(assignableRoles([]), []);
  assert.deepEqual(assignableRoles(undefined), []);
});

test("API returning no configured role rows reports that role setup is required", async () => {
  const result = await fetchAssignableRoles(async () => []);
  assert.deepEqual(result.roles, []);
  assert.match(result.error, /No supported roles are configured/);
});

test("API failure is surfaced to the form instead of silently leaving an empty dropdown", async () => {
  const result = await fetchAssignableRoles(async () => { throw new Error("request failed (503)"); });
  assert.deepEqual(result.roles, []);
  assert.match(result.error, /request failed \(503\)/);
});

test("selected dropdown role ID is converted from its HTML string value", () => {
  assert.equal(submittedRoleId("3"), 3);
  assert.equal(submittedRoleId(""), null);
});
