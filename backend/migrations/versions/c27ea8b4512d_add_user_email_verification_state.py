"""Add email verification state to user accounts.

Revision ID: c27ea8b4512d
Revises: af137c46d201
Create Date: 2026-11-04
"""
from alembic import op
import sqlalchemy as sa


revision = "c27ea8b4512d"
down_revision = "af137c46d201"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column(
            "is_email_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade():
    op.drop_column("users", "is_email_verified")
