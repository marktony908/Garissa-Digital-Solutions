
import time

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.exc import IntegrityError

from app import db
from app.models import AuditLog, RevokedToken, User

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


def serialize_user(user):
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role.name,
        "is_active": user.is_active,
        "is_email_verified": user.is_email_verified,
    }


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        data = {}

    email_value = data.get("email", "")
    email = email_value.strip().lower() if isinstance(email_value, str) else ""
    password = data.get("password", "")

    if not email or not isinstance(password, str) or not password:
        return jsonify({
            "error": "Email and password are required."
        }), 400

    user = User.query.filter_by(email=email).first()

    if (
        user is None
        or not user.is_active
        or not check_password_hash(user.password_hash, password)
    ):
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    identity = str(user.id)

    access_token = create_access_token(identity=identity)
    refresh_token = create_refresh_token(identity=identity)

    return jsonify({
        "message": "Login successful.",
        "user": serialize_user(user),
        "access_token": access_token,
        "refresh_token": refresh_token,
    }), 200


@auth_bp.get("/me")
@jwt_required()
def me():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)

    if user is None or not user.is_active:
        return jsonify({"error": "User not found or inactive."}), 401

    return jsonify({"user": serialize_user(user)}), 200


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)

    if user is None or not user.is_active:
        return jsonify({"error": "User not found or inactive."}), 401

    return jsonify({
        "access_token": create_access_token(identity=str(user.id))
    }), 200


@auth_bp.post("/logout")
@jwt_required(verify_type=False)
def logout():
    """Revoke the presented access or refresh token."""
    claims = get_jwt()
    db.session.query(RevokedToken).filter(
        RevokedToken.expires_at <= int(time.time())
    ).delete(synchronize_session=False)
    if not db.session.query(RevokedToken.id).filter_by(jti=claims["jti"]).first():
        db.session.add(RevokedToken(jti=claims["jti"], expires_at=claims["exp"]))
        db.session.commit()
    return jsonify({"message": "Logout successful."}), 200


@auth_bp.patch("/profile")
@jwt_required()
def update_profile():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        return jsonify({"error": "User not found or inactive."}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request body is required."}), 400
    full_name = data.get("full_name")
    email = data.get("email")
    if full_name is not None:
        if not isinstance(full_name, str) or not full_name.strip():
            return jsonify({"error": "Full name cannot be empty."}), 400
        user.full_name = full_name.strip()
    if email is not None:
        if not isinstance(email, str) or "@" not in email:
            return jsonify({"error": "A valid email is required."}), 400
        user.email = email.strip().lower()
    db.session.add(AuditLog(action="updated_profile", entity_type="user", entity_id=user.id, user_id=user.id))
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Email address is already in use."}), 409
    return jsonify({"user": serialize_user(user)}), 200


@auth_bp.post("/password")
@jwt_required()
def change_password():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        return jsonify({"error": "User not found or inactive."}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON request body is required."}), 400
    current = data.get("current_password")
    new_password = data.get("new_password")
    if not isinstance(current, str) or not check_password_hash(user.password_hash, current):
        return jsonify({"error": "Current password is incorrect."}), 400
    if not isinstance(new_password, str) or len(new_password) < 12:
        return jsonify({"error": "New password must contain at least 12 characters."}), 400
    if current == new_password:
        return jsonify({"error": "Choose a password different from the current password."}), 400
    user.password_hash = generate_password_hash(new_password)
    db.session.add(AuditLog(action="changed_password", entity_type="user", entity_id=user.id, user_id=user.id))
    db.session.commit()
    return jsonify({"message": "Password changed successfully."}), 200
