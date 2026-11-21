"""Fail-closed guards for test database URLs."""

import tempfile
from pathlib import Path
import unittest

from sqlalchemy.engine import make_url


def require_isolated_sqlite_url(database_url):
    """Reject non-SQLite and non-temporary file databases before app startup."""
    url = make_url(database_url)
    if url.drivername not in {"sqlite", "sqlite+pysqlite"}:
        raise ValueError("Tests may only use SQLite databases.")

    database = url.database
    if database in (None, "", ":memory:"):
        return database_url

    database_path = Path(database).resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if not database_path.is_relative_to(temp_root):
        raise ValueError("File-backed test databases must be inside the temporary directory.")
    return database_url


class TestDatabaseIsolationGuard(unittest.TestCase):
    def test_accepts_in_memory_sqlite(self):
        self.assertEqual(require_isolated_sqlite_url("sqlite://"), "sqlite://")

    def test_accepts_sqlite_file_under_temporary_directory(self):
        database_path = Path(tempfile.gettempdir()) / "gds-isolation-check.sqlite"
        self.assertEqual(
            require_isolated_sqlite_url(f"sqlite:///{database_path}"),
            f"sqlite:///{database_path}",
        )

    def test_rejects_postgresql_before_connecting(self):
        with self.assertRaisesRegex(ValueError, "only use SQLite"):
            require_isolated_sqlite_url("postgresql://test:test@localhost/application")

    def test_rejects_file_backed_sqlite_outside_temporary_directory(self):
        with self.assertRaisesRegex(ValueError, "temporary directory"):
            require_isolated_sqlite_url("sqlite:////etc/gds-test.sqlite")
