"""Canonical application roles and user-facing permission descriptions."""

ROLE_CATALOG = {
    "Admin": {
        "description": "System administrator with full access across the application.",
        "access_level": "All projects and system administration",
        "permissions": [
            "Manage users and assign the four supported roles.",
            "Create, edit, and manage all projects and their resources.",
            "Approve or reject submitted updates.",
            "View reports and all audit records.",
        ],
    },
    "Developer": {
        "description": "Builds and maintains software work in projects they created or are assigned to.",
        "access_level": "Projects created by or assigned to this user",
        "permissions": [
            "Create projects and manage permitted projects, versions, and updates.",
            "Submit their own updates for review.",
            "Manage deployments in permitted projects and view scoped reports.",
            "Cannot approve updates or access user and audit administration.",
        ],
    },
    "Approver": {
        "description": "Reviews submitted updates for projects assigned to them.",
        "access_level": "Assigned projects and submitted updates",
        "permissions": [
            "View assigned projects and their permitted records.",
            "Review pending submitted updates and approve or reject them.",
            "View reports scoped to assigned projects.",
            "Cannot manage users or access audit administration.",
        ],
    },
    "Viewer": {
        "description": "Reads project information and reports for projects assigned to them.",
        "access_level": "Assigned projects; read-only",
        "permissions": [
            "View assigned projects, versions, updates, and deployments.",
            "View reports scoped to assigned projects.",
            "Cannot create, edit, approve, reject, or delete records.",
            "Cannot access user management or audit records.",
        ],
    },
}

SUPPORTED_ROLE_NAMES = frozenset(ROLE_CATALOG)
