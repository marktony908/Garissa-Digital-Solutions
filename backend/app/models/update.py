from datetime import datetime, timezone
from app import db


class Update(db.Model):
    __tablename__ = "updates"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, nullable=False)
    change_type = db.Column(db.String(40), default="patch", nullable=False)
    status = db.Column(db.String(30), default="pending", nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    version_id = db.Column(
        db.Integer, db.ForeignKey("versions.id"), nullable=False
    )
    created_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )

    version = db.relationship("Version", back_populates="updates")
    creator = db.relationship("User", foreign_keys=[created_by_id])
    approvals = db.relationship(
        "Approval", back_populates="update", cascade="all, delete-orphan"
    )
    deployments = db.relationship("Deployment", back_populates="update")
