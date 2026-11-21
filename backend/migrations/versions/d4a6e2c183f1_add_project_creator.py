"""Add a distinct project creator while preserving current ownership.

Revision ID: d4a6e2c183f1
Revises: c27ea8b4512d
"""
from alembic import op
import sqlalchemy as sa


revision = "d4a6e2c183f1"
down_revision = "c27ea8b4512d"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("projects") as batch_op:
        batch_op.add_column(sa.Column("created_by_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_projects_created_by_id_users",
            "users",
            ["created_by_id"],
            ["id"],
        )
    op.execute(sa.text("""
        UPDATE projects
        SET created_by_id = (
            SELECT audit_logs.user_id
            FROM audit_logs
            WHERE audit_logs.entity_type = 'project'
              AND audit_logs.action = 'created'
              AND audit_logs.entity_id = projects.id
            ORDER BY audit_logs.created_at ASC, audit_logs.id ASC
            LIMIT 1
        )
        WHERE created_by_id IS NULL
    """))


def downgrade():
    with op.batch_alter_table("projects") as batch_op:
        batch_op.drop_constraint("fk_projects_created_by_id_users", type_="foreignkey")
        batch_op.drop_column("created_by_id")
