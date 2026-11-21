from datetime import datetime, timezone
from app import db


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(30), default="active", nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    owner = db.relationship(
        "User", foreign_keys=[owner_id], back_populates="projects"
    )
    # Legacy projects may have no reliable creator record; keep that unknown explicit.
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    creator = db.relationship(
        "User", foreign_keys=[created_by_id], back_populates="created_projects"
    )

    versions = db.relationship(
        "Version", back_populates="project", cascade="all, delete-orphan"
    )
