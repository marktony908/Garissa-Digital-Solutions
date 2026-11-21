
import os
from urllib.parse import urlsplit

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()


def create_app():
    app = Flask(__name__)

    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
    if not app.config["JWT_SECRET_KEY"]:
        raise RuntimeError(
            "JWT_SECRET_KEY is missing. Check your backend/.env file."
        )

    jwt.init_app(app)

    @jwt.token_verification_loader
    def active_user_token(jwt_header, jwt_payload):
        try:
            user = db.session.get(models.User, int(jwt_payload["sub"]))
        except (KeyError, TypeError, ValueError):
            return False
        return bool(user and user.is_active)

    @jwt.token_verification_failed_loader
    def inactive_user_token(jwt_header, jwt_payload):
        return jsonify({"error": {"code": "UNAUTHORIZED", "message": "User is not active."}}), 401

    # Database configuration
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is missing. Check your backend/.env file."
        )

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Use explicit origins. A blank environment value should not silently disable
    # the local Vite origins; wildcard origins are intentionally rejected.
    configured_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
    origin_values = (
        configured_origins.split(",")
        if configured_origins.strip()
        else ["http://localhost:5173", "http://localhost:5174"]
    )
    allowed_origins = []
    for value in origin_values:
        candidate = value.strip()
        parsed = urlsplit(candidate)
        if (
            candidate == "*"
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError(
                "CORS_ALLOWED_ORIGINS must contain specific HTTP(S) origins only."
            )
        origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        if origin not in allowed_origins:
            allowed_origins.append(origin)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": allowed_origins,
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": False,
            }
        },
        always_send=False,
        vary_header=True,
    )

    # Initialize extensions before importing models or routes
    db.init_app(app)
    migrate.init_app(app, db)

    # Import models so Flask-Migrate can discover database tables
    from app import models  # noqa: F401
    from app.models import RevokedToken

    @jwt.token_in_blocklist_loader
    def token_is_revoked(jwt_header, jwt_payload):
        return db.session.query(RevokedToken.id).filter_by(
            jti=jwt_payload["jti"]
        ).first() is not None

    # Register REST API blueprints
    from app.routes.projects import projects_bp
    from app.routes.auth import auth_bp
    from app.routes.resources import resources_bp
    app.register_blueprint(auth_bp)

    app.register_blueprint(projects_bp)
    app.register_blueprint(resources_bp)

    # API health checks
    @app.get("/api/health")
    def health_check():
        return jsonify({
            "status": "success",
            "message": "Garissa Digital Solutions API is running",
        }), 200

    @app.get("/api/health/database")
    def database_health():
        try:
            with db.engine.connect():
                pass

            return jsonify({
                "status": "success",
                "message": "PostgreSQL connection is working",
            }), 200

        except Exception:
            app.logger.exception("Database connection failed")
            return jsonify({
                "status": "error",
                "message": "Could not connect to PostgreSQL",
            }), 500

    return app
