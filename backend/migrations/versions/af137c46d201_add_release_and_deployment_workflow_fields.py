"""Add release dates/status and deployment update association.

Revision ID: af137c46d201
Revises: 839ed0a4778e
Create Date: 2026-11-04
"""
from alembic import op
import sqlalchemy as sa


revision = "af137c46d201"
down_revision = "839ed0a4778e"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("versions") as batch_op:
        batch_op.add_column(sa.Column("release_date", sa.Date(), nullable=True))
        batch_op.add_column(sa.Column("status", sa.String(length=30), nullable=False, server_default="planned"))
    with op.batch_alter_table("deployments") as batch_op:
        batch_op.add_column(sa.Column("update_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key("fk_deployments_update_id_updates", "updates", ["update_id"], ["id"])


def downgrade():
    with op.batch_alter_table("deployments") as batch_op:
        batch_op.drop_constraint("fk_deployments_update_id_updates", type_="foreignkey")
        batch_op.drop_column("update_id")
    with op.batch_alter_table("versions") as batch_op:
        batch_op.drop_column("status")
        batch_op.drop_column("release_date")
