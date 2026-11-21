from datetime import datetime, timezone
from app import db


class Deployment(db.Model):
    __tablename__ = "deployments"

    id = db.Column(db.Integer, primary_key=True)
    environment = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), default="pending", nullable=False)
    deployed_at = db.Column(db.DateTime(timezone=True))
    notes = db.Column(db.Text)

    version_id = db.Column(
        db.Integer, db.ForeignKey("versions.id"), nullable=False
    )
    update_id = db.Column(db.Integer, db.ForeignKey("updates.id"), nullable=True)
    deployed_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )

    version = db.relationship("Version", back_populates="deployments")
    update = db.relationship("Update", back_populates="deployments")
    deployer = db.relationship("User", foreign_keys=[deployed_by_id])
