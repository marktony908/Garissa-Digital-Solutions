import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import inspect, text


class ProjectCreatorMigrationTests(unittest.TestCase):
    def setUp(self):
        from tests.test_database_isolation import require_isolated_sqlite_url

        self.temp_dir = tempfile.TemporaryDirectory(prefix="gds-migration-test-")
        self.addCleanup(self.temp_dir.cleanup)
        database_path = Path(self.temp_dir.name) / "migration.sqlite"
        database_url = require_isolated_sqlite_url(f"sqlite:///{database_path}")
        self.environment = patch.dict(os.environ, {
            "DATABASE_URL": database_url,
            "JWT_SECRET_KEY": "migration-test-signing-key-at-least-32-bytes",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

        from app import create_app, db

        self.db = db
        self.app = create_app()
        self.addCleanup(self.cleanup_database)
        self.runner = self.app.test_cli_runner()

    def cleanup_database(self):
        if not hasattr(self, "app"):
            return
        with self.app.app_context():
            self.db.session.remove()
            self.db.engine.dispose()

    def run_migration(self, *args):
        result = self.runner.invoke(args=["db", *args])
        self.assertEqual(result.exit_code, 0, result.output)

    def test_upgrade_preserves_owner_and_only_backfills_verified_creator(self):
        self.run_migration("upgrade", "c27ea8b4512d")
        now = datetime.now(timezone.utc).isoformat()
        with self.app.app_context(), self.db.engine.begin() as connection:
            connection.execute(text("INSERT INTO roles (name) VALUES ('Admin')"))
            connection.execute(text("""
                INSERT INTO users
                    (full_name, email, password_hash, is_active, is_email_verified, created_at, role_id)
                VALUES
                    ('Creator', 'creator@example.test', 'test-hash', true, true, :now, 1),
                    ('Owner', 'owner@example.test', 'test-hash', true, true, :now, 1)
            """), {"now": now})
            connection.execute(text("""
                INSERT INTO projects (name, status, created_at, owner_id)
                VALUES ('Has creation audit', 'active', :now, 2),
                       ('Creator unknown', 'active', :now, 2)
            """), {"now": now})
            connection.execute(text("""
                INSERT INTO audit_logs (action, entity_type, entity_id, created_at, user_id)
                VALUES ('created', 'project', 1, :now, 1)
            """), {"now": now})

        self.run_migration("upgrade", "head")
        with self.app.app_context(), self.db.engine.connect() as connection:
            projects = connection.execute(text(
                "SELECT id, owner_id, created_by_id FROM projects ORDER BY id"
            )).all()
            self.assertEqual(projects, [(1, 2, 1), (2, 2, None)])
            foreign_keys = inspect(connection).get_foreign_keys("projects")
            self.assertTrue(any(
                fk["referred_table"] == "users" and fk["constrained_columns"] == ["created_by_id"]
                for fk in foreign_keys
            ))
            self.assertEqual(connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one(), "f3e6a91c0d42")
            self.assertIn("revoked_tokens", inspect(connection).get_table_names())
            unique_constraints = inspect(connection).get_unique_constraints("versions")
            self.assertTrue(any(
                constraint["name"] == "uq_versions_project_version"
                for constraint in unique_constraints
            ))

        self.run_migration("downgrade", "c27ea8b4512d")
        with self.app.app_context(), self.db.engine.connect() as connection:
            self.assertNotIn("revoked_tokens", inspect(connection).get_table_names())
            self.assertNotIn("created_by_id", {column["name"] for column in inspect(connection).get_columns("projects")})
            rows = connection.execute(text("SELECT id, owner_id FROM projects ORDER BY id")).all()
            self.assertEqual(rows, [(1, 2), (2, 2)])

    def test_version_constraint_migration_stops_safely_on_existing_duplicates(self):
        self.run_migration("upgrade", "c27ea8b4512d")
        now = datetime.now(timezone.utc).isoformat()
        with self.app.app_context(), self.db.engine.begin() as connection:
            connection.execute(text("INSERT INTO roles (name) VALUES ('Admin')"))
            connection.execute(text("""
                INSERT INTO users
                    (full_name, email, password_hash, is_active, is_email_verified, created_at, role_id)
                VALUES
                    ('Creator', 'creator@example.test', 'test-hash', true, true, :now, 1),
                    ('Owner', 'owner@example.test', 'test-hash', true, true, :now, 1)
            """), {"now": now})
            connection.execute(text("""
                INSERT INTO projects (name, status, created_at, owner_id)
                VALUES ('Duplicate versions', 'active', :now, 2)
            """), {"now": now})
            connection.execute(text("""
                INSERT INTO versions
                    (version_number, created_at, project_id, created_by_id, status)
                VALUES ('1.0', :now, 1, 1, 'planned'),
                       ('1.0', :now, 1, 1, 'planned')
            """), {"now": now})

        failed = self.runner.invoke(args=["db", "upgrade", "head"])
        self.assertNotEqual(failed.exit_code, 0, failed.output)
        with self.app.app_context(), self.db.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT COUNT(*) FROM versions")).scalar_one(), 2)
            self.assertFalse(any(
                constraint["name"] == "uq_versions_project_version"
                for constraint in inspect(connection).get_unique_constraints("versions")
            ))

        with self.app.app_context(), self.db.engine.begin() as connection:
            connection.execute(text("DELETE FROM versions WHERE id = 2"))
        self.run_migration("upgrade", "head")
        with self.app.app_context(), self.db.engine.connect() as connection:
            self.assertTrue(any(
                constraint["name"] == "uq_versions_project_version"
                for constraint in inspect(connection).get_unique_constraints("versions")
            ))


if __name__ == "__main__":
    unittest.main()
