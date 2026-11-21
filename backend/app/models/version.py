from datetime import datetime, timezone
from app import db


class Version(db.Model):
    __tablename__ = "versions"
    __table_args__ = (
        db.UniqueConstraint(
            "project_id",
            "version_number",
            name="uq_versions_project_version",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(50), nullable=False)
    release_notes = db.Column(db.Text)
    release_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(30), default="planned", server_default="planned", nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id"), nullable=False
    )
    created_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )

    project = db.relationship("Project", back_populates="versions")
    updates = db.relationship(
        "Update", back_populates="version", cascade="all, delete-orphan"
    )
    deployments = db.relationship("Deployment", back_populates="version")
