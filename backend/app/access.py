"""Shared project-scoped authorization rules for API resources."""

from sqlalchemy import or_

from app.models import Project


def project_scope(user):
    """Return projects visible to a user under the project access policy.

    Admins see every project. Developers see projects they created or that
    are assigned to them. Approvers and Viewers need an explicit owner grant.
    """
    query = Project.query
    if not user or not user.is_active:
        return query.filter(Project.id == -1)
    role = user.role.name
    if role == "Admin":
        return query
    if role == "Developer":
        return query.filter(or_(Project.owner_id == user.id, Project.created_by_id == user.id))
    return query.filter(Project.owner_id == user.id)


def accessible_project_ids(user):
    return project_scope(user).with_entities(Project.id)


def can_access_project(user, project):
    if not user or not user.is_active or not project:
        return False
    if user.role.name == "Admin":
        return True
    if user.role.name == "Developer":
        return project.owner_id == user.id or project.created_by_id == user.id
    return project.owner_id == user.id


def can_manage_project(user, project):
    return bool(
        user
        and user.role
        and user.role.name in {"Admin", "Developer"}
        and can_access_project(user, project)
    )
