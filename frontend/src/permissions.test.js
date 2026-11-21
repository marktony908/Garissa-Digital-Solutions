import assert from "node:assert/strict";
import test from "node:test";
import { canAccessPage } from "./permissions.js";

test("only Admin sees user management, roles, and audit trail", () => {
  for (const role of ["Approver", "Developer", "Viewer"]) {
    assert.equal(canAccessPage(role, "Users"), false);
    assert.equal(canAccessPage(role, "Roles"), false);
    assert.equal(canAccessPage(role, "Audit Trail"), false);
  }
  assert.equal(canAccessPage("Admin", "Users"), true);
  assert.equal(canAccessPage("Admin", "Roles"), true);
  assert.equal(canAccessPage("Admin", "Audit Trail"), true);
});

test("only Admin and Approver see the approval queue", () => {
  assert.equal(canAccessPage("Admin", "Approvals"), true);
  assert.equal(canAccessPage("Approver", "Approvals"), true);
  assert.equal(canAccessPage("Developer", "Approvals"), false);
  assert.equal(canAccessPage("Viewer", "Approvals"), false);
});
