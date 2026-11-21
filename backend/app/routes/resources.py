from datetime import date, datetime, timezone
import re

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from app import db
from app.access import accessible_project_ids, can_access_project, can_manage_project
from app.models import Approval, AuditLog, Deployment, Project, Role, Update, User, Version
from app.role_catalog import ROLE_CATALOG, SUPPORTED_ROLE_NAMES

resources_bp = Blueprint("resources", __name__, url_prefix="/api/v1")
VERSION_STATES = {"planned", "released", "deprecated"}
UPDATE_STATES = {"draft", "pending", "approved", "rejected", "deployed"}
DEPLOYMENT_STATES = {"pending", "successful", "failed"}
CHANGE_TYPES = {"major", "minor", "patch", "hotfix"}
EMAIL_PATTERN = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$",
    re.IGNORECASE,
)


def actor():
    try:
        user = db.session.get(User, int(get_jwt_identity()))
    except (TypeError, ValueError):
        return None
    return user if user and user.is_active else None


def allowed(user, roles):
    return bool(user and user.role and user.role.name in roles)


def denied():
    return jsonify({"error": {"code": "FORBIDDEN", "message": "Your role cannot perform this action."}}), 403


def invalid(message, field=None):
    error = {"code": "VALIDATION_ERROR", "message": message}
    if field:
        error["field"] = field
    return jsonify({"error": error}), 400


def valid_email(value):
    return (
        isinstance(value, str)
        and len(value.strip()) <= 255
        and bool(EMAIL_PATTERN.fullmatch(value.strip()))
    )


def audit(user, action, entity, entity_id, details=None):
    db.session.add(AuditLog(action=action, entity_type=entity, entity_id=entity_id, details=details, user_id=user.id))


def as_iso(value):
    return value.isoformat() if value else None


def version_json(v):
    return {"id": v.id, "version_number": v.version_number, "release_notes": v.release_notes, "release_date": as_iso(v.release_date), "status": v.status, "update_count": len(v.updates), "created_at": as_iso(v.created_at), "project_id": v.project_id, "project_name": v.project.name, "created_by_id": v.created_by_id}


def project_json(p):
    return {"id": p.id, "name": p.name, "description": p.description, "status": p.status, "created_at": as_iso(p.created_at), "owner_id": p.owner_id, "owner_name": p.owner.full_name if p.owner else None, "created_by_id": p.created_by_id, "created_by_name": p.creator.full_name if p.creator else None, "version_count": len(p.versions)}


def update_json(u):
    return {"id": u.id, "title": u.title, "description": u.description, "change_type": u.change_type, "status": u.status, "created_at": as_iso(u.created_at), "version_id": u.version_id, "version_number": u.version.version_number, "project_id": u.version.project_id, "project_name": u.version.project.name, "created_by_id": u.created_by_id, "created_by": u.creator.full_name if getattr(u, "creator", None) else None, "approvals": [{"id": a.id, "decision": a.decision, "comments": a.comments, "reviewed_at": as_iso(a.reviewed_at), "reviewer": a.reviewer.full_name} for a in u.approvals]}


def deployment_json(d):
    return {"id": d.id, "environment": d.environment, "status": d.status, "deployed_at": as_iso(d.deployed_at), "notes": d.notes, "version_id": d.version_id, "version_number": d.version.version_number, "project_id": d.version.project_id, "project_name": d.version.project.name, "update_id": d.update_id, "update_title": d.update.title if d.update else None, "deployed_by_id": d.deployed_by_id, "deployed_by": d.deployer.full_name if getattr(d, "deployer", None) else None}


def reconcile_update_deployment_state(update):
    """Keep update status aligned with its successful deployment records."""
    if update is None:
        return
    successful = Deployment.query.filter_by(
        update_id=update.id,
        status="successful",
    ).first() is not None
    if successful:
        update.status = "deployed"
    elif update.status == "deployed":
        update.status = "approved"


def parse_date(value, label):
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must use YYYY-MM-DD format.")


def list_query_values(valid_statuses=None):
    term = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    if len(term) > 100:
        return None, None, invalid("Search text must be 100 characters or fewer.")
    if status and valid_statuses is not None and status not in valid_statuses:
        return None, None, invalid("Invalid status filter.")
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return (f"%{escaped}%" if term else None), status, None


@resources_bp.get("/versions")
@jwt_required()
def list_versions():
    user = actor()
    pattern, status, error = list_query_values(VERSION_STATES)
    if error: return error
    query = Version.query.join(Project).filter(Version.project_id.in_(accessible_project_ids(user)))
    if pattern:
        query = query.filter(or_(Version.version_number.ilike(pattern, escape="\\"), Version.release_notes.ilike(pattern, escape="\\"), Project.name.ilike(pattern, escape="\\")))
    if status: query = query.filter(Version.status == status)
    rows = query.order_by(Version.created_at.desc()).all()
    return jsonify({"data": [version_json(v) for v in rows], "count": len(rows)})


@resources_bp.get("/versions/<int:version_id>")
@jwt_required()
def get_version(version_id):
    row = db.session.get(Version, version_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Version not found."}}), 404
    if not can_access_project(actor(), row.project): return denied()
    return jsonify({"data": version_json(row)})


@resources_bp.post("/versions")
@jwt_required()
def create_version():
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    name, project_id = data.get("version_number"), data.get("project_id")
    if not isinstance(name, str) or not name.strip(): return invalid("Version number is required.")
    project = db.session.get(Project, project_id) if isinstance(project_id, int) and not isinstance(project_id, bool) else None
    if not project: return invalid("A valid project_id is required.")
    if not can_manage_project(user, project): return denied()
    if Version.query.filter_by(project_id=project.id, version_number=name.strip()).first():
        return jsonify({"error": {"code": "VERSION_CONFLICT", "message": "That version number already exists in this project."}}), 409
    status = data.get("status", "planned")
    if not isinstance(status, str) or status not in VERSION_STATES: return invalid("Version status must be planned, released, or deprecated.")
    try: release_date = parse_date(data.get("release_date"), "Release date")
    except ValueError as e: return invalid(str(e))
    if status == "released" and release_date is None: release_date = date.today()
    row = Version(version_number=name.strip(), project=project, created_by_id=user.id, release_notes=data.get("release_notes"), release_date=release_date, status=status)
    if row.release_notes is not None and not isinstance(row.release_notes, str): return invalid("Release notes must be text or null.")
    db.session.add(row); db.session.flush(); audit(user, "created", "version", row.id)
    try: db.session.commit()
    except IntegrityError: db.session.rollback(); return jsonify({"error": {"code": "VERSION_CONFLICT", "message": "That version number already exists in this project."}}), 409
    return jsonify({"data": version_json(row)}), 201


@resources_bp.patch("/versions/<int:version_id>")
@jwt_required()
def edit_version(version_id):
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    row = db.session.get(Version, version_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Version not found."}}), 404
    if not can_manage_project(user, row.project): return denied()
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    target_number = row.version_number
    if "version_number" in data:
        if not isinstance(data["version_number"], str) or not data["version_number"].strip(): return invalid("Version number cannot be empty.")
        target_number = data["version_number"].strip()
    target_project = row.project
    if "project_id" in data:
        project_id = data["project_id"]
        project = db.session.get(Project, project_id) if isinstance(project_id, int) and not isinstance(project_id, bool) else None
        if not project: return invalid("Project was not found.")
        if not can_manage_project(user, project): return denied()
        target_project = project
    if Version.query.filter(
        Version.project_id == target_project.id,
        Version.version_number == target_number,
        Version.id != row.id,
    ).first():
        return jsonify({"error": {"code": "VERSION_CONFLICT", "message": "That version number already exists in this project."}}), 409
    target_notes = row.release_notes
    if "release_notes" in data:
        if data["release_notes"] is not None and not isinstance(data["release_notes"], str): return invalid("Release notes must be text or null.")
        target_notes = data["release_notes"]
    target_status = row.status
    if "status" in data:
        if not isinstance(data["status"], str) or data["status"] not in VERSION_STATES: return invalid("Invalid version status.")
        target_status = data["status"]
    target_release_date = row.release_date
    if "release_date" in data:
        try: target_release_date = parse_date(data["release_date"], "Release date")
        except ValueError as e: return invalid(str(e))
    elif target_status == "released" and target_release_date is None:
        target_release_date = date.today()
    row.version_number = target_number
    row.project = target_project
    row.release_notes = target_notes
    row.status = target_status
    row.release_date = target_release_date
    audit(user, "updated", "version", row.id)
    try: db.session.commit()
    except IntegrityError: db.session.rollback(); return jsonify({"error": {"code": "VERSION_CONFLICT", "message": "That version number already exists in this project."}}), 409
    return jsonify({"data": version_json(row)})


@resources_bp.delete("/versions/<int:version_id>")
@jwt_required()
def delete_version(version_id):
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    row = db.session.get(Version, version_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Version not found."}}), 404
    if not can_manage_project(user, row.project): return denied()
    if row.status == "released" or row.updates:
        return jsonify({"error": {"code": "VERSION_HAS_HISTORY", "message": "Released versions or versions with update history cannot be deleted. Deprecate the version instead."}}), 409
    audit(user, "deleted", "version", row.id); db.session.delete(row)
    try: db.session.commit()
    except IntegrityError: db.session.rollback(); return jsonify({"error": {"code": "CONFLICT", "message": "Version is referenced by a deployment and cannot be deleted."}}), 409
    return "", 204


@resources_bp.get("/updates")
@jwt_required()
def list_updates():
    user = actor()
    pattern, status, error = list_query_values(UPDATE_STATES)
    if error: return error
    query = Update.query.join(Version).join(Project).filter(Version.project_id.in_(accessible_project_ids(user)))
    if pattern:
        query = query.filter(or_(Update.title.ilike(pattern, escape="\\"), Update.description.ilike(pattern, escape="\\"), Update.change_type.ilike(pattern, escape="\\"), Version.version_number.ilike(pattern, escape="\\"), Project.name.ilike(pattern, escape="\\")))
    if status: query = query.filter(Update.status == status)
    if user and user.role.name == "Approver": query = query.filter(Update.status != "draft")
    rows = query.order_by(Update.created_at.desc()).all()
    return jsonify({"data": [update_json(u) for u in rows], "count": len(rows)})


@resources_bp.get("/updates/<int:update_id>")
@jwt_required()
def get_update(update_id):
    row = db.session.get(Update, update_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Update not found."}}), 404
    if not can_access_project(actor(), row.version.project): return denied()
    if actor().role.name == "Approver" and row.status == "draft": return denied()
    return jsonify({"data": update_json(row)})


@resources_bp.post("/updates")
@jwt_required()
def create_update():
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    title, desc, version_id = data.get("title"), data.get("description"), data.get("version_id")
    if not isinstance(title, str) or not title.strip(): return invalid("Update title is required.")
    if not isinstance(desc, str) or not desc.strip(): return invalid("Update description is required.")
    version = db.session.get(Version, version_id) if isinstance(version_id, int) and not isinstance(version_id, bool) else None
    if not version: return invalid("A valid version_id is required.")
    if not can_manage_project(user, version.project): return denied()
    kind = data.get("change_type", "patch")
    if not isinstance(kind, str) or kind not in CHANGE_TYPES: return invalid("Change type must be major, minor, patch, or hotfix.")
    row = Update(title=title.strip(), description=desc.strip(), change_type=kind, status="draft", version=version, created_by_id=user.id)
    db.session.add(row); db.session.flush(); audit(user, "created", "update", row.id)
    db.session.commit()
    return jsonify({"data": update_json(row)}), 201


@resources_bp.patch("/updates/<int:update_id>")
@jwt_required()
def edit_update(update_id):
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    row = db.session.get(Update, update_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Update not found."}}), 404
    if not can_manage_project(user, row.version.project): return denied()
    if row.status not in {"draft", "rejected"}: return jsonify({"error": {"code": "INVALID_STATE", "message": "Only draft or rejected updates can be edited."}}), 409
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    for key in ("title", "description"):
        if key in data:
            if not isinstance(data[key], str) or not data[key].strip(): return invalid(f"{key.replace('_', ' ').title()} is required.")
            setattr(row, key, data[key].strip())
    if "change_type" in data:
        if not isinstance(data["change_type"], str) or data["change_type"] not in CHANGE_TYPES: return invalid("Invalid change type.")
        row.change_type = data["change_type"]
    if "version_id" in data:
        version = db.session.get(Version, data["version_id"]) if isinstance(data["version_id"], int) else None
        if not version: return invalid("Version was not found.")
        if not can_manage_project(user, version.project): return denied()
        row.version = version
    audit(user, "updated", "update", row.id); db.session.commit()
    return jsonify({"data": update_json(row)})


@resources_bp.post("/updates/<int:update_id>/submit")
@jwt_required()
def submit_update(update_id):
    user = actor(); row = db.session.get(Update, update_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Update not found."}}), 404
    if not allowed(user, {"Admin", "Developer"}): return denied()
    if not can_access_project(user, row.version.project): return denied()
    if user.role.name == "Developer" and row.created_by_id != user.id: return denied()
    if row.status not in {"draft", "rejected"}: return jsonify({"error": {"code": "INVALID_STATE", "message": "Only draft or rejected updates can be submitted."}}), 409
    row.status = "pending"; audit(user, "submitted_for_approval", "update", row.id); db.session.commit()
    return jsonify({"data": update_json(row)})


@resources_bp.delete("/updates/<int:update_id>")
@jwt_required()
def delete_update(update_id):
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    row = db.session.get(Update, update_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Update not found."}}), 404
    if not can_manage_project(user, row.version.project): return denied()
    if row.status != "draft": return jsonify({"error": {"code": "INVALID_STATE", "message": "Only draft updates can be deleted; submitted update history is retained."}}), 409
    audit(user, "deleted", "update", row.id); db.session.delete(row)
    try: db.session.commit()
    except IntegrityError: db.session.rollback(); return jsonify({"error": {"code": "CONFLICT", "message": "Update is referenced by a deployment and cannot be deleted."}}), 409
    return "", 204


@resources_bp.get("/approvals")
@jwt_required()
def list_approvals():
    user = actor()
    if not allowed(user, {"Admin", "Approver"}): return denied()
    pattern, _, error = list_query_values()
    if error: return error
    query = Update.query.filter_by(status="pending").join(Version).join(Project).filter(Version.project_id.in_(accessible_project_ids(user)))
    if pattern:
        query = query.filter(or_(Update.title.ilike(pattern, escape="\\"), Update.description.ilike(pattern, escape="\\"), Version.version_number.ilike(pattern, escape="\\"), Project.name.ilike(pattern, escape="\\")))
    rows = query.order_by(Update.created_at.asc()).all()
    return jsonify({"data": [update_json(row) for row in rows], "count": len(rows)})


@resources_bp.post("/approvals/<int:update_id>")
@jwt_required()
def decide_approval(update_id):
    user = actor()
    if not allowed(user, {"Admin", "Approver"}): return denied()
    row = db.session.get(Update, update_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Update not found."}}), 404
    if not can_access_project(user, row.version.project): return denied()
    if row.created_by_id == user.id: return denied()
    if row.status != "pending": return jsonify({"error": {"code": "INVALID_STATE", "message": "Only pending updates can be reviewed."}}), 409
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("decision"), str) or data.get("decision") not in {"approved", "rejected"}: return invalid("Decision must be approved or rejected.")
    comments = data.get("comments")
    if comments is not None and not isinstance(comments, str): return invalid("Review comments must be text or null.")
    if data["decision"] == "rejected" and not (comments or "").strip(): return invalid("A reason is required when rejecting an update.")
    approval = Approval(decision=data["decision"], comments=comments, reviewed_at=datetime.now(timezone.utc), update=row, reviewer_id=user.id)
    db.session.add(approval); row.status = data["decision"]
    audit(user, data["decision"], "update", row.id, {"comments": comments}); db.session.commit()
    return jsonify({"data": update_json(row)})


@resources_bp.get("/deployments")
@jwt_required()
def list_deployments():
    user = actor()
    pattern, status, error = list_query_values(DEPLOYMENT_STATES)
    if error: return error
    query = Deployment.query.join(Version).join(Project).filter(Version.project_id.in_(accessible_project_ids(user)))
    if pattern:
        query = query.filter(or_(Deployment.environment.ilike(pattern, escape="\\"), Deployment.status.ilike(pattern, escape="\\"), Deployment.notes.ilike(pattern, escape="\\"), Version.version_number.ilike(pattern, escape="\\"), Project.name.ilike(pattern, escape="\\")))
    if status: query = query.filter(Deployment.status == status)
    rows = query.order_by(Deployment.id.desc()).all()
    return jsonify({"data": [deployment_json(d) for d in rows], "count": len(rows)})


@resources_bp.get("/deployments/<int:deployment_id>")
@jwt_required()
def get_deployment(deployment_id):
    user = actor()
    row = db.session.get(Deployment, deployment_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Deployment not found."}}), 404
    if not can_access_project(user, row.version.project): return denied()
    return jsonify({"data": deployment_json(row)})


@resources_bp.post("/deployments")
@jwt_required()
def create_deployment():
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    environment = data.get("environment")
    version = db.session.get(Version, data.get("version_id")) if isinstance(data.get("version_id"), int) else None
    if not isinstance(environment, str) or not environment.strip(): return invalid("Deployment environment is required.")
    if not version: return invalid("A valid version_id is required.")
    if not can_manage_project(user, version.project): return denied()
    update = None
    if data.get("update_id") is not None:
        update = db.session.get(Update, data["update_id"]) if isinstance(data["update_id"], int) else None
        if not update or update.version_id != version.id: return invalid("Selected update must belong to the selected version.")
        if update.status not in {"approved", "deployed"}: return jsonify({"error": {"code": "INVALID_STATE", "message": "Only approved updates can be deployed."}}), 409
        if not can_access_project(user, update.version.project): return denied()
    status = data.get("status", "pending")
    if not isinstance(status, str) or status not in DEPLOYMENT_STATES: return invalid("Deployment status must be pending, successful, or failed.")
    row = Deployment(environment=environment.strip(), status=status, notes=data.get("notes"), deployed_at=datetime.now(timezone.utc) if status == "successful" else None, version=version, update=update, deployed_by_id=user.id)
    if row.notes is not None and not isinstance(row.notes, str): return invalid("Deployment notes must be text or null.")
    db.session.add(row)
    if update and status == "successful": update.status = "deployed"
    db.session.flush(); audit(user, "created", "deployment", row.id); db.session.commit()
    return jsonify({"data": deployment_json(row)}), 201


@resources_bp.patch("/deployments/<int:deployment_id>")
@jwt_required()
def edit_deployment(deployment_id):
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    row = db.session.get(Deployment, deployment_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Deployment not found."}}), 404
    if not can_manage_project(user, row.version.project): return denied()
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    if "environment" in data:
        if not isinstance(data["environment"], str) or not data["environment"].strip(): return invalid("Environment cannot be empty.")
        row.environment = data["environment"].strip()
    target_version = row.version
    if "version_id" in data:
        version_id = data["version_id"]
        target_version = db.session.get(Version, version_id) if isinstance(version_id, int) and not isinstance(version_id, bool) else None
        if not target_version: return invalid("Version was not found.")
        if not can_manage_project(user, target_version.project): return denied()

    target_update = row.update
    if "update_id" in data:
        update_id = data["update_id"]
        target_update = db.session.get(Update, update_id) if isinstance(update_id, int) and not isinstance(update_id, bool) else None
        if update_id is not None and (not target_update or target_update.version_id != target_version.id or target_update.status not in {"approved", "deployed"}):
            return invalid("Selected update must be approved and belong to the selected version.")
        if target_update and not can_access_project(user, target_update.version.project): return denied()
    elif target_update and target_update.version_id != target_version.id:
        return invalid("Choose an update from the selected version or clear the update selection.")

    previous_update = row.update
    if "version_id" in data:
        row.version = target_version
    if "update_id" in data:
        row.update = target_update
    if "status" in data:
        if not isinstance(data["status"], str) or data["status"] not in DEPLOYMENT_STATES: return invalid("Invalid deployment status.")
        row.status = data["status"]
        row.deployed_at = datetime.now(timezone.utc) if row.status == "successful" else None
    if "notes" in data:
        if data["notes"] is not None and not isinstance(data["notes"], str): return invalid("Notes must be text or null.")
        row.notes = data["notes"]
    reconcile_update_deployment_state(previous_update)
    if row.update is not previous_update:
        reconcile_update_deployment_state(row.update)
    audit(user, "updated", "deployment", row.id)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": {"code": "CONFLICT", "message": "Deployment update conflicts with existing data."}}), 409
    return jsonify({"data": deployment_json(row)})


@resources_bp.delete("/deployments/<int:deployment_id>")
@jwt_required()
def delete_deployment(deployment_id):
    user = actor()
    if not allowed(user, {"Admin"}): return denied()
    row = db.session.get(Deployment, deployment_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "Deployment not found."}}), 404
    if row.status == "successful": return jsonify({"error": {"code": "DEPLOYMENT_RECORDED", "message": "Successful deployments are retained as history and cannot be deleted."}}), 409
    audit(user, "deleted", "deployment", row.id); db.session.delete(row); db.session.commit()
    return "", 204


@resources_bp.get("/users")
@jwt_required()
def list_users():
    user = actor()
    if not allowed(user, {"Admin"}): return denied()
    pattern, status, error = list_query_values({"active", "inactive"})
    if error: return error
    role_name = request.args.get("role", "").strip()
    if role_name and role_name not in SUPPORTED_ROLE_NAMES: return invalid("Invalid role filter.")
    query = User.query.join(Role)
    if pattern: query = query.filter(or_(User.full_name.ilike(pattern, escape="\\"), User.email.ilike(pattern, escape="\\"), Role.name.ilike(pattern, escape="\\")))
    if status: query = query.filter(User.is_active.is_(status == "active"))
    if role_name: query = query.filter(Role.name == role_name)
    rows = query.order_by(User.full_name).all()
    return jsonify({"data": [{"id": u.id, "full_name": u.full_name, "email": u.email, "role": u.role.name, "role_id": u.role_id, "is_active": u.is_active, "is_email_verified": u.is_email_verified, "created_at": as_iso(u.created_at)} for u in rows], "count": len(rows), "roles": [{"id": r.id, "name": r.name} for r in Role.query.filter(Role.name.in_(SUPPORTED_ROLE_NAMES)).order_by(Role.name).all()]})


@resources_bp.get("/roles")
@jwt_required()
def list_roles():
    admin = actor()
    if not allowed(admin, {"Admin"}): return denied()

    role_rows = {
        role.name: role
        for role in Role.query.filter(Role.name.in_(SUPPORTED_ROLE_NAMES)).all()
    }
    user_counts = dict(
        db.session.query(User.role_id, func.count(User.id))
        .group_by(User.role_id)
        .all()
    )
    data = []
    for name, definition in ROLE_CATALOG.items():
        role = role_rows.get(name)
        data.append({
            "id": role.id if role else None,
            "name": name,
            **definition,
            "user_count": user_counts.get(role.id, 0) if role else 0,
            "configured": role is not None,
        })
    return jsonify({"data": data, "count": len(data)}), 200


@resources_bp.post("/users")
@jwt_required()
def create_user():
    user = actor()
    if not allowed(user, {"Admin"}): return denied()
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    name, email, password, role_id = data.get("full_name"), data.get("email"), data.get("password"), data.get("role_id")
    if not isinstance(name, str) or not name.strip(): return invalid("Full name is required.", "full_name")
    if len(name.strip()) > 120: return invalid("Full name must be 120 characters or fewer.", "full_name")
    if not valid_email(email): return invalid("Enter a valid email address with a domain.", "email")
    if not isinstance(password, str) or len(password) < 12: return invalid("Password must contain at least 12 characters.", "password")
    role = db.session.get(Role, role_id) if isinstance(role_id, int) and not isinstance(role_id, bool) else None
    if not role or role.name not in SUPPORTED_ROLE_NAMES: return invalid("Select one of the four supported roles.", "role_id")
    is_email_verified = data.get("is_email_verified", False)
    if not isinstance(is_email_verified, bool): return invalid("is_email_verified must be true or false.", "is_email_verified")
    row = User(full_name=name.strip(), email=email.strip().lower(), password_hash=generate_password_hash(password), role=role, is_active=True, is_email_verified=is_email_verified)
    db.session.add(row)
    try:
        db.session.flush()
        audit(user, "created", "user", row.id)
        db.session.commit()
    except IntegrityError: db.session.rollback(); return jsonify({"error": {"code": "EMAIL_CONFLICT", "message": "A user with this email already exists.", "field": "email"}}), 409
    return jsonify({"data": {"id": row.id, "full_name": row.full_name, "email": row.email, "role": role.name, "role_id": row.role_id, "is_active": row.is_active, "is_email_verified": row.is_email_verified}}), 201


@resources_bp.patch("/users/<int:user_id>")
@jwt_required()
def update_user(user_id):
    admin = actor()
    if not allowed(admin, {"Admin"}): return denied()
    row = db.session.get(User, user_id)
    if not row: return jsonify({"error": {"code": "NOT_FOUND", "message": "User not found."}}), 404
    was_active = row.is_active
    was_active_admin = row.is_active and row.role.name == "Admin"
    active_admins_before = User.query.join(Role).filter(Role.name == "Admin", User.is_active.is_(True)).count() if was_active_admin else 0
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return invalid("A JSON request body is required.")
    if "full_name" in data:
        if not isinstance(data["full_name"], str) or not data["full_name"].strip(): return invalid("Full name cannot be empty.", "full_name")
        if len(data["full_name"].strip()) > 120: return invalid("Full name must be 120 characters or fewer.", "full_name")
        row.full_name = data["full_name"].strip()
    if "email" in data:
        if not valid_email(data["email"]): return invalid("Enter a valid email address with a domain.", "email")
        row.email = data["email"].strip().lower()
    if "role_id" in data:
        role = db.session.get(Role, data["role_id"]) if isinstance(data["role_id"], int) and not isinstance(data["role_id"], bool) else None
        if not role or role.name not in SUPPORTED_ROLE_NAMES: return invalid("Select one of the four supported roles.", "role_id")
        row.role = role
    if "is_active" in data:
        if not isinstance(data["is_active"], bool): return invalid("is_active must be true or false.", "is_active")
        if row.id == admin.id and not data["is_active"]: return invalid("You cannot deactivate your own account.", "is_active")
        row.is_active = data["is_active"]
    if "is_email_verified" in data:
        if not isinstance(data["is_email_verified"], bool): return invalid("is_email_verified must be true or false.", "is_email_verified")
        row.is_email_verified = data["is_email_verified"]
    if was_active_admin and not (row.is_active and row.role.name == "Admin"):
        if active_admins_before <= 1: return invalid("At least one active Admin account must remain.", "role_id")
    changed_fields = sorted(key for key in data if key in {"full_name", "email", "role_id", "is_active", "is_email_verified"})
    action = "deactivated" if was_active and data.get("is_active") is False else "updated"
    audit(admin, action, "user", row.id, {"changed_fields": changed_fields})
    try: db.session.commit()
    except IntegrityError: db.session.rollback(); return jsonify({"error": {"code": "EMAIL_CONFLICT", "message": "A user with this email already exists.", "field": "email"}}), 409
    return jsonify({"data": {"id": row.id, "full_name": row.full_name, "email": row.email, "role": row.role.name, "role_id": row.role_id, "is_active": row.is_active, "is_email_verified": row.is_email_verified}})


@resources_bp.get("/reports")
@jwt_required()
def reports():
    actor_user = actor()
    if not actor_user: return jsonify({"error": {"code": "UNAUTHORIZED", "message": "Active user required."}}), 401
    project_ids = accessible_project_ids(actor_user)
    projects = Project.query.filter(Project.id.in_(project_ids))
    versions = Version.query.filter(Version.project_id.in_(project_ids))
    updates = Update.query.join(Version).filter(Version.project_id.in_(project_ids))
    deployments = Deployment.query.join(Version).filter(Version.project_id.in_(project_ids))
    approvals = Approval.query.join(Update).join(Version).filter(Version.project_id.in_(project_ids))
    if actor_user.role.name == "Approver": updates = updates.filter(Update.status != "draft")
    approval_history = approvals.order_by(Approval.reviewed_at.desc()).limit(20).all()
    return jsonify({"data": {
        "projects": {"total": projects.count(), "active": projects.filter_by(status="active").count(), "completed": projects.filter_by(status="completed").count()},
        "versions": {"total": versions.count(), "released": versions.filter_by(status="released").count()},
        "updates": {"total": updates.count(), "pending_approvals": updates.filter(Update.status == "pending").count(), "approved": approvals.filter(Approval.decision == "approved").count(), "rejected": approvals.filter(Approval.decision == "rejected").count()},
        "deployments": {"total": deployments.count(), "successful": deployments.filter(Deployment.status == "successful").count(), "failed": deployments.filter(Deployment.status == "failed").count(), "pending": deployments.filter(Deployment.status == "pending").count(), "history": [deployment_json(d) for d in deployments.order_by(Deployment.id.desc()).limit(20).all()]},
        "project_history": [project_json(p) for p in projects.order_by(Project.created_at.desc()).limit(20).all()],
        "version_history": [version_json(v) for v in versions.order_by(Version.created_at.desc()).limit(20).all()],
        "update_history": [update_json(u) for u in updates.order_by(Update.created_at.desc()).limit(20).all()],
        "approval_history": [{"id": a.id, "update_title": a.update.title, "project_name": a.update.version.project.name, "version_number": a.update.version.version_number, "decision": a.decision, "comments": a.comments, "reviewer": a.reviewer.full_name, "reviewed_at": as_iso(a.reviewed_at)} for a in approval_history],
    }})


@resources_bp.get("/audit-logs")
@jwt_required()
def list_audit_logs():
    user = actor()
    if not allowed(user, {"Admin"}): return denied()
    pattern, _, error = list_query_values()
    if error: return error
    query = AuditLog.query.join(User)
    if pattern: query = query.filter(or_(AuditLog.action.ilike(pattern, escape="\\"), AuditLog.entity_type.ilike(pattern, escape="\\"), User.full_name.ilike(pattern, escape="\\")))
    rows = query.order_by(AuditLog.created_at.desc()).limit(200).all()
    return jsonify({"data": [{"id": a.id, "action": a.action, "entity_type": a.entity_type, "entity_id": a.entity_id, "details": a.details, "created_at": as_iso(a.created_at), "user": a.user.full_name} for a in rows]})


@resources_bp.get("/project-owners")
@jwt_required()
def list_project_owners():
    user = actor()
    if not allowed(user, {"Admin", "Developer"}): return denied()
    rows = User.query.filter_by(is_active=True).order_by(User.full_name).all()
    return jsonify({"data": [{"id": row.id, "full_name": row.full_name} for row in rows], "count": len(rows)})

