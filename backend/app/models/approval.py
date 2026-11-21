
from datetime import datetime, timezone

from app import db


class Approval(db.Model):
    __tablename__ = "approvals"

    id = db.Column(db.Integer, primary_key=True)
    decision = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
    )
    comments = db.Column(db.Text)
    reviewed_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    update_id = db.Column(
        db.Integer,
        db.ForeignKey("updates.id"),
        nullable=False,
    )
    reviewer_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
    )

    update = db.relationship("Update", back_populates="approvals")
    reviewer = db.relationship("User", back_populates="approvals")

    def __repr__(self):
        return f"<Approval {self.id}: {self.decision}>"
