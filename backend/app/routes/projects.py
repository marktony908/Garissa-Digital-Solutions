
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from app import db
from app.access import can_manage_project, project_scope
from app.models import AuditLog, Project, User

projects_bp = Blueprint(
    "projects",
    __name__,
    url_prefix="/api/v1/projects",
)


def serialize_project(project):
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "status": project.status,
        "created_at": (
            project.created_at.isoformat()
            if project.created_at
            else None
        ),
        "owner_id": project.owner_id,
        "created_by_id": project.created_by_id,
        "created_by_name": project.creator.full_name if project.creator else None,
        "version_count": len(project.versions),
        "owner_name": (
            project.owner.full_name if project.owner else None
        ),
    }


def current_user():
    return db.session.get(User, int(get_jwt_identity()))


def can_manage(user):
    return user and user.role.name in {"Admin", "Developer"}


@projects_bp.route("", methods=["GET"])
@jwt_required()
def list_projects():
    query = project_scope(current_user())
    term = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    if len(term) > 100:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "Search text must be 100 characters or fewer."}}), 400
    if status and status not in {"active", "inactive", "completed", "archived"}:
        return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "Invalid project status filter."}}), 400
    if term:
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        query = query.filter(or_(Project.name.ilike(pattern, escape="\\"), Project.description.ilike(pattern, escape="\\"), Project.owner.has(User.full_name.ilike(pattern, escape="\\")), Project.creator.has(User.full_name.ilike(pattern, escape="\\"))))
    if status:
        query = query.filter(Project.status == status)
    projects = query.order_by(Project.created_at.desc()).all()

    return jsonify({
        "data": [serialize_project(project) for project in projects],
        "count": len(projects),
    }), 200


@projects_bp.route("/<int:project_id>", methods=["GET"])
@jwt_required()
def get_project(project_id):
    project = project_scope(current_user()).filter_by(id=project_id).first()

    if project is None:
        return jsonify({
            "error": {
                "code": "PROJECT_NOT_FOUND",
                "message": "Project not found.",
            }
        }), 404

    return jsonify({"data": serialize_project(project)}), 200


@projects_bp.route("", methods=["POST"])
@jwt_required()
def create_project():
    user = current_user()
    if not user or not user.is_active:
        return jsonify({"error": {"code": "UNAUTHORIZED", "message": "Active user required."}}), 401
    if not can_manage(user):
        return jsonify({"error": {"code": "FORBIDDEN", "message": "Your role cannot manage projects."}}), 403
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": {
                "code": "INVALID_REQUEST",
                "message": "A JSON request body is required.",
            }
        }), 400

    name = data.get("name")
    owner_id = data.get("owner_id", user.id)

    if not isinstance(name, str) or not name.strip():
        return jsonify({
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Project name is required.",
            }
        }), 400

    if isinstance(owner_id, bool) or not isinstance(owner_id, int):
        return jsonify({
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "owner_id must be an integer.",
            }
        }), 400

    description = data.get("description")
    if description is not None and not isinstance(description, str):
        return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "Description must be a string or null."}}), 400
    status = data.get("status", "active")
    if status not in ("active", "inactive", "completed", "archived"):
        return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "Invalid project status."}}), 400

    owner = db.session.get(User, owner_id)
    if owner is None or not owner.is_active:
        return jsonify({
            "error": {
                "code": "OWNER_NOT_FOUND",
                "message": "The specified owner does not exist.",
            }
        }), 400

    project = Project(
        name=name.strip(),
        description=description,
        status=status,
        owner_id=owner_id,
        created_by_id=user.id,
    )

    db.session.add(project)
    db.session.flush()
    db.session.add(AuditLog(action="created", entity_type="project", entity_id=project.id, user_id=user.id, details={"name": project.name}))

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            "error": {
                "code": "PROJECT_CONFLICT",
                "message": (
                    "The project name already exists or the data "
                    "conflicts with a database constraint."
                ),
            }
        }), 409

    return jsonify({"data": serialize_project(project)}), 201


@projects_bp.route("/<int:project_id>", methods=["PATCH"])
@jwt_required()
def update_project(project_id):
    user = current_user()
    if not user or not user.is_active:
        return jsonify({"error": {"code": "UNAUTHORIZED", "message": "Active user required."}}), 401
    if not can_manage(user):
        return jsonify({"error": {"code": "FORBIDDEN", "message": "Your role cannot manage projects."}}), 403
    project = db.session.get(Project, project_id)

    if project is None:
        return jsonify({
            "error": {
                "code": "PROJECT_NOT_FOUND",
                "message": "Project not found.",
            }
        }), 404

    if not can_manage_project(user, project):
        return jsonify({"error": {"code": "FORBIDDEN", "message": "You cannot manage this project."}}), 403

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": {
                "code": "INVALID_REQUEST",
                "message": "A JSON request body is required.",
            }
        }), 400

    if "name" in data:
        name = data["name"]

        if not isinstance(name, str) or not name.strip():
            return jsonify({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Project name cannot be empty.",
                }
            }), 400

        project.name = name.strip()

    if "description" in data:
        description = data["description"]

        if description is not None and not isinstance(description, str):
            return jsonify({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Description must be a string or null.",
                }
            }), 400

        project.description = description

    if "status" in data:
        status = data["status"]

        if status not in ("active", "inactive", "completed", "archived"):
            return jsonify({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid project status.",
                }
            }), 400

        project.status = status

    if "owner_id" in data:
        owner_id = data["owner_id"]

        if (
            isinstance(owner_id, bool)
            or not isinstance(owner_id, int)
        ):
            return jsonify({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "owner_id must be an integer.",
                }
            }), 400

        owner = db.session.get(User, owner_id)
        if owner is None or not owner.is_active:
            return jsonify({
                "error": {
                    "code": "OWNER_NOT_FOUND",
                    "message": "The specified owner does not exist.",
                }
            }), 400

        project.owner_id = owner_id

    db.session.add(AuditLog(action="updated", entity_type="project", entity_id=project.id, user_id=user.id))

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            "error": {
                "code": "PROJECT_CONFLICT",
                "message": "The update conflicts with a database constraint.",
            }
        }), 409

    return jsonify({"data": serialize_project(project)}), 200


@projects_bp.route("/<int:project_id>", methods=["DELETE"])
@jwt_required()
def delete_project(project_id):
    user = current_user()
    if not user or not user.is_active:
        return jsonify({"error": {"code": "UNAUTHORIZED", "message": "Active user required."}}), 401
    if not can_manage(user):
        return jsonify({"error": {"code": "FORBIDDEN", "message": "Your role cannot manage projects."}}), 403
    project = db.session.get(Project, project_id)

    if project is None:
        return jsonify({
            "error": {
                "code": "PROJECT_NOT_FOUND",
                "message": "Project not found.",
            }
        }), 404

    if not can_manage_project(user, project):
        return jsonify({"error": {"code": "FORBIDDEN", "message": "You cannot manage this project."}}), 403

    if project.versions:
        return jsonify({
            "error": {
                "code": "PROJECT_HAS_HISTORY",
                "message": "Projects with version history cannot be deleted. Archive the project instead.",
            }
        }), 409

    db.session.delete(project)
    db.session.add(AuditLog(action="deleted", entity_type="project", entity_id=project.id, user_id=user.id, details={"name": project.name}))

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({
            "error": {
                "code": "PROJECT_DELETE_CONFLICT",
                "message": (
                    "Related records prevent this project from being deleted."
                ),
            }
        }), 409

    return "", 204
