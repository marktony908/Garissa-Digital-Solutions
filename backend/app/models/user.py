
from datetime import datetime, timezone

from app import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_email_verified = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    role_id = db.Column(
        db.Integer,
        db.ForeignKey("roles.id"),
        nullable=False,
    )

    role = db.relationship("Role", back_populates="users")
    projects = db.relationship(
        "Project", foreign_keys="Project.owner_id", back_populates="owner"
    )
    created_projects = db.relationship(
        "Project", foreign_keys="Project.created_by_id", back_populates="creator"
    )
    approvals = db.relationship("Approval", back_populates="reviewer")
    audit_logs = db.relationship("AuditLog", back_populates="user")

    def __repr__(self):
        return f"<User {self.email}>"
