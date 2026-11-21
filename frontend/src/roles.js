const supportedRoles = new Set(["Admin", "Developer", "Approver", "Viewer"]);

// Keep only database-backed role rows. The API may describe unconfigured
// canonical roles, but those cannot be submitted as user role IDs.
export function assignableRoles(roleDefinitions) {
  if (!Array.isArray(roleDefinitions)) return [];
  return roleDefinitions.filter((role) =>
    role && supportedRoles.has(role.name) && role.configured === true &&
    Number.isInteger(role.id) && role.id > 0
  );
}

export async function fetchAssignableRoles(loadRoleDefinitions) {
  try {
    const roles = assignableRoles(await loadRoleDefinitions());
    return {
      roles,
      error: roles.length ? "" : "No supported roles are configured. Ask an administrator to configure roles before creating users.",
    };
  } catch (error) {
    return { roles: [], error: `Roles could not be loaded: ${error.message}` };
  }
}

export function submittedRoleId(value) {
  return value === "" ? null : Number(value);
}
