export function canAccessPage(role, page) {
  if (["Users", "Roles", "Audit Trail"].includes(page)) return role === "Admin";
  if (page === "Approvals") return role === "Admin" || role === "Approver";
  return Boolean(role);
}
