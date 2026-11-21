"""Require version numbers to be unique within each project.

Revision ID: f3e6a91c0d42
Revises: ab128f8d63a1
"""
from alembic import op
import sqlalchemy as sa


revision = "f3e6a91c0d42"
down_revision = "ab128f8d63a1"
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    duplicates = connection.execute(sa.text("""
        SELECT project_id, version_number, COUNT(*) AS record_count
        FROM versions
        GROUP BY project_id, version_number
        HAVING COUNT(*) > 1
        ORDER BY project_id, version_number
        LIMIT 10
    """)).all()
    if duplicates:
        examples = ", ".join(
            f"project_id={project_id}, version_number={version_number!r}, count={count}"
            for project_id, version_number, count in duplicates
        )
        raise RuntimeError(
            "Cannot add per-project version uniqueness while duplicate records "
            f"exist. Review and resolve these pairs first: {examples}"
        )

    with op.batch_alter_table("versions") as batch_op:
        batch_op.create_unique_constraint(
            "uq_versions_project_version",
            ["project_id", "version_number"],
        )


def downgrade():
    with op.batch_alter_table("versions") as batch_op:
        batch_op.drop_constraint(
            "uq_versions_project_version",
            type_="unique",
        )
