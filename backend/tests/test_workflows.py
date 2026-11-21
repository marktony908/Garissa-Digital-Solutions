import os
import unittest
from datetime import timedelta
from unittest.mock import patch

from flask_jwt_extended import create_access_token, create_refresh_token
from werkzeug.security import generate_password_hash


class WorkflowApiTests(unittest.TestCase):
    def setUp(self):
        from tests.test_database_isolation import require_isolated_sqlite_url

        database_url = require_isolated_sqlite_url("sqlite://")
        env = patch.dict(os.environ, {
            "DATABASE_URL": database_url,
            "JWT_SECRET_KEY": "unit-test-signing-key-with-at-least-32-bytes",
            "CORS_ALLOWED_ORIGINS": "",
        })
        env.start()
        self.addCleanup(env.stop)
        from app import create_app, db
        from app.models import Role, User

        self.db = db
        self.app = create_app()
        self.app.config.update(TESTING=True)
        self.addCleanup(self.cleanup_database)
        with self.app.app_context():
            self.assertEqual(db.engine.url.drivername, "sqlite")
            db.create_all()
            self.roles = {name: Role(name=name) for name in ("Admin", "Developer", "Approver", "Viewer")}
            db.session.add_all(self.roles.values())
            db.session.flush()
            self.role_ids = {name: role.id for name, role in self.roles.items()}
            self.users = {}
            for name in self.roles:
                email = f"{name.lower()}@example.test"
                user = User(full_name=name, email=email, password_hash=generate_password_hash(f"{name.lower()}-test-password-123"), role=self.roles[name])
                db.session.add(user)
                self.users[name] = (email, f"{name.lower()}-test-password-123")
            db.session.commit()
        self.client = self.app.test_client()
        self.headers = {name: self.login(*credentials) for name, credentials in self.users.items()}

    def cleanup_database(self):
        if not hasattr(self, "app"):
            return
        with self.app.app_context():
            self.db.session.remove()
            self.db.drop_all()
            self.db.engine.dispose()

    def login(self, email, password):
        response = self.client.post("/api/v1/auth/login", json={"email": email, "password": password})
        self.assertEqual(response.status_code, 200, response.get_json())
        return {"Authorization": f"Bearer {response.get_json()['access_token']}"}

    def test_login_endpoint_allows_preflight_cors_for_frontend(self):
        response = self.client.options(
            "/api/v1/auth/login",
            headers={
                "Origin": "http://localhost:5174",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Access-Control-Allow-Origin"), "http://localhost:5174")
        self.assertIn("POST", response.headers.get("Access-Control-Allow-Methods", ""))
        self.assertIn("Authorization", response.headers.get("Access-Control-Allow-Headers", ""))

    def test_auth_me_cors_preflight_success_and_auth_errors(self):
        origin = "http://localhost:5173"
        preflight = self.client.options(
            "/api/v1/auth/me",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )
        self.assertEqual(preflight.status_code, 200)
        self.assertEqual(preflight.headers.get("Access-Control-Allow-Origin"), origin)
        self.assertIn("GET", preflight.headers.get("Access-Control-Allow-Methods", ""))
        self.assertIn("OPTIONS", preflight.headers.get("Access-Control-Allow-Methods", ""))
        self.assertIn("Authorization", preflight.headers.get("Access-Control-Allow-Headers", ""))
        self.assertIn("Content-Type", preflight.headers.get("Access-Control-Allow-Headers", ""))

        success = self.client.get(
            "/api/v1/auth/me",
            headers={**self.headers["Admin"], "Origin": origin},
        )
        self.assertEqual(success.status_code, 200)
        self.assertEqual(success.headers.get("Access-Control-Allow-Origin"), origin)

        missing_auth = self.client.get("/api/v1/auth/me", headers={"Origin": origin})
        self.assertEqual(missing_auth.status_code, 401)
        self.assertEqual(missing_auth.headers.get("Access-Control-Allow-Origin"), origin)

        with self.app.app_context():
            user_id = self.client.get("/api/v1/auth/me", headers=self.headers["Admin"]).get_json()["user"]["id"]
            expired = create_access_token(identity=str(user_id), expires_delta=timedelta(seconds=-1))
        expired_auth = self.client.get(
            "/api/v1/auth/me",
            headers={"Origin": origin, "Authorization": f"Bearer {expired}"},
        )
        self.assertEqual(expired_auth.status_code, 401)
        self.assertEqual(expired_auth.headers.get("Access-Control-Allow-Origin"), origin)

    def test_cors_rejects_wildcard_origin_configuration(self):
        with patch.dict(os.environ, {"CORS_ALLOWED_ORIGINS": "*"}):
            from app import create_app
            with self.assertRaisesRegex(RuntimeError, "specific HTTP"):
                create_app()

    def test_project_access_and_crud(self):
        self.assertEqual(self.client.get("/api/v1/projects").status_code, 401)
        self.assertEqual(self.client.post("/api/v1/projects", headers=self.headers["Viewer"], json={"name": "Denied"}).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/projects", headers=self.headers["Approver"], json={"name": "Approver cannot create"}).status_code, 403)
        dev_project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={"name": "Developer Project"})
        self.assertEqual(dev_project.status_code, 201, dev_project.get_json())
        developer_id = self.client.get("/api/v1/auth/me", headers=self.headers["Developer"]).get_json()["user"]["id"]
        created = self.client.post("/api/v1/projects", headers=self.headers["Admin"], json={"name": "Portal", "owner_id": developer_id})
        self.assertEqual(created.status_code, 201)
        project_id = created.get_json()["data"]["id"]
        self.assertEqual(created.get_json()["data"]["owner_id"], developer_id)
        admin_id = self.client.get("/api/v1/auth/me", headers=self.headers["Admin"]).get_json()["user"]["id"]
        self.assertEqual(created.get_json()["data"]["created_by_id"], admin_id)
        self.assertNotEqual(created.get_json()["data"]["owner_id"], created.get_json()["data"]["created_by_id"])
        self.assertEqual(self.client.get("/api/v1/projects", headers=self.headers["Admin"]).get_json()["count"], 2)
        self.assertEqual(self.client.get("/api/v1/projects", headers=self.headers["Viewer"]).get_json()["count"], 0)
        changed = self.client.patch(f"/api/v1/projects/{project_id}", headers=self.headers["Admin"], json={"status": "completed", "owner_id": self.role_user_id("Viewer")})
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(changed.get_json()["data"]["created_by_id"], admin_id)
        self.assertEqual(changed.get_json()["data"]["owner_id"], self.role_user_id("Viewer"))
        self.assertEqual(self.client.get("/api/v1/projects", headers=self.headers["Viewer"]).get_json()["count"], 1)
        self.assertEqual(self.client.delete(f"/api/v1/projects/{project_id}", headers=self.headers["Admin"]).status_code, 204)

    def role_user_id(self, role):
        users = self.client.get("/api/v1/users", headers=self.headers["Admin"]).get_json()["data"]
        return next(user["id"] for user in users if user["role"] == role)

    def test_user_creation_roles_validation_and_user_filters(self):
        role_response = self.client.get("/api/v1/roles", headers=self.headers["Admin"])
        self.assertEqual(role_response.status_code, 200)
        role_ids = {role["name"]: role["id"] for role in role_response.get_json()["data"] if role["configured"]}
        for name in ("Admin", "Developer", "Approver", "Viewer"):
            email = f"created-{name.lower()}@example.test"
            created = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
                "full_name": f"Created {name}", "email": email,
                "password": "a-long-enough-password", "role_id": role_ids[name],
            })
            self.assertEqual(created.status_code, 201, created.get_json())
            self.assertEqual(created.get_json()["data"]["role"], name)
            self.assertFalse(created.get_json()["data"]["is_email_verified"])

        malformed_email = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
            "full_name": "Bad Email", "email": "not-an-email", "password": "a-long-enough-password", "role_id": role_ids["Viewer"],
        })
        self.assertEqual(malformed_email.status_code, 400)
        self.assertEqual(malformed_email.get_json()["error"]["field"], "email")
        short_password = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
            "full_name": "Short Password", "email": "short-password@example.test", "password": "short", "role_id": role_ids["Viewer"],
        })
        self.assertEqual(short_password.status_code, 400)
        self.assertEqual(short_password.get_json()["error"]["field"], "password")
        short_name = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
            "full_name": "x" * 121, "email": "long-name@example.test", "password": "a-long-enough-password", "role_id": role_ids["Viewer"],
        })
        self.assertEqual(short_name.status_code, 400)
        duplicate_email = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
            "full_name": "Duplicate", "email": "admin@example.test", "password": "a-long-enough-password", "role_id": role_ids["Viewer"],
        })
        self.assertEqual(duplicate_email.status_code, 409)
        self.assertEqual(duplicate_email.get_json()["error"]["code"], "EMAIL_CONFLICT")
        self.assertEqual(duplicate_email.get_json()["error"]["field"], "email")
        user_rows = self.client.get("/api/v1/users", headers=self.headers["Admin"]).get_json()["data"]
        self.assertEqual(sum(row["email"] == "admin@example.test" for row in user_rows), 1)
        created_viewer = next(row for row in user_rows if row["email"] == "created-viewer@example.test")
        duplicate_edit = self.client.patch(f"/api/v1/users/{created_viewer['id']}", headers=self.headers["Admin"], json={"email": "admin@example.test"})
        self.assertEqual(duplicate_edit.status_code, 409)
        self.assertEqual(duplicate_edit.get_json()["error"]["field"], "email")

        filtered = self.client.get("/api/v1/users?role=Viewer&status=active&q=created", headers=self.headers["Admin"])
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual([row["email"] for row in filtered.get_json()["data"]], ["created-viewer@example.test"])
        self.assertEqual(self.client.get("/api/v1/users?role=Manager", headers=self.headers["Admin"]).status_code, 400)
        self.assertEqual(self.client.get("/api/v1/users?status=archived", headers=self.headers["Admin"]).status_code, 400)

        edited = self.client.patch(f"/api/v1/users/{filtered.get_json()['data'][0]['id']}", headers=self.headers["Admin"], json={
            "full_name": "Edited Viewer", "role_id": role_ids["Approver"], "is_email_verified": True,
        })
        self.assertEqual(edited.status_code, 200, edited.get_json())
        self.assertEqual(edited.get_json()["data"]["role"], "Approver")
        self.assertTrue(edited.get_json()["data"]["is_email_verified"])

    def test_user_management_remains_admin_only(self):
        for role in ("Developer", "Approver", "Viewer"):
            self.assertEqual(self.client.get("/api/v1/users", headers=self.headers[role]).status_code, 403)
            self.assertEqual(self.client.get("/api/v1/roles", headers=self.headers[role]).status_code, 403)

    def test_project_scope_applies_to_resources_search_approvals_and_reports(self):
        second_dev = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
            "full_name": "Second Developer", "email": "second-dev@example.test",
            "password": "second-developer-password", "role_id": self.role_ids["Developer"],
        }).get_json()["data"]
        projects = {}
        for name, owner_id in (
            ("Dev One Private", self.role_user_id("Developer")),
            ("Dev Two Private", second_dev["id"]),
            ("Viewer Grant", self.role_user_id("Viewer")),
            ("Approver Grant", self.role_user_id("Approver")),
        ):
            response = self.client.post("/api/v1/projects", headers=self.headers["Admin"], json={"name": name, "owner_id": owner_id})
            self.assertEqual(response.status_code, 201, response.get_json())
            projects[name] = response.get_json()["data"]

        resources = {}
        for name, project in projects.items():
            version_response = self.client.post("/api/v1/versions", headers=self.headers["Admin"], json={
                "project_id": project["id"], "version_number": f"{project['id']}.0",
            })
            self.assertEqual(version_response.status_code, 201, version_response.get_json())
            version = version_response.get_json()["data"]
            update_response = self.client.post("/api/v1/updates", headers=self.headers["Admin"], json={
                "version_id": version["id"], "title": f"{name} update", "description": "Scoped test update",
            })
            self.assertEqual(update_response.status_code, 201, update_response.get_json())
            update = update_response.get_json()["data"]
            self.assertEqual(self.client.post(f"/api/v1/updates/{update['id']}/submit", headers=self.headers["Admin"], json={}).status_code, 200)
            resources[name] = {"version": version, "update": update}

        draft_response = self.client.post("/api/v1/updates", headers=self.headers["Admin"], json={
            "version_id": resources["Approver Grant"]["version"]["id"],
            "title": "Approver must not see draft", "description": "Not submitted",
        })
        self.assertEqual(draft_response.status_code, 201, draft_response.get_json())
        approver_draft_id = draft_response.get_json()["data"]["id"]

        dev_headers = self.headers["Developer"]
        admin_projects = self.client.get("/api/v1/projects", headers=self.headers["Admin"]).get_json()
        self.assertEqual(admin_projects["count"], 4)
        dev_list = self.client.get("/api/v1/projects", headers=dev_headers).get_json()
        self.assertEqual([row["id"] for row in dev_list["data"]], [projects["Dev One Private"]["id"]])
        self.assertEqual(self.client.get(f"/api/v1/projects/{projects['Dev Two Private']['id']}", headers=dev_headers).status_code, 404)
        self.assertEqual(self.client.get(f"/api/v1/versions/{resources['Dev Two Private']['version']['id']}", headers=dev_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/updates/{resources['Dev Two Private']['update']['id']}", headers=dev_headers).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/projects?q=Dev%20Two", headers=dev_headers).get_json()["count"], 0)
        self.assertEqual(self.client.get("/api/v1/versions", headers=dev_headers).get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/v1/updates", headers=dev_headers).get_json()["count"], 1)

        viewer_headers = self.headers["Viewer"]
        self.assertEqual(self.client.get("/api/v1/projects", headers=viewer_headers).get_json()["count"], 1)
        self.assertEqual(self.client.get(f"/api/v1/projects/{projects['Dev One Private']['id']}", headers=viewer_headers).status_code, 404)
        self.assertEqual(self.client.get("/api/v1/versions", headers=viewer_headers).get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/v1/updates", headers=viewer_headers).get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/v1/projects?q=Dev%20One", headers=viewer_headers).get_json()["count"], 0)
        viewer_report = self.client.get("/api/v1/reports", headers=viewer_headers).get_json()["data"]
        self.assertEqual(viewer_report["projects"]["total"], 1)
        self.assertEqual([row["name"] for row in viewer_report["project_history"]], ["Viewer Grant"])

        approver_headers = self.headers["Approver"]
        approval_list = self.client.get("/api/v1/approvals", headers=approver_headers).get_json()
        self.assertEqual([row["id"] for row in approval_list["data"]], [resources["Approver Grant"]["update"]["id"]])
        approver_updates = self.client.get("/api/v1/updates", headers=approver_headers).get_json()
        self.assertNotIn(approver_draft_id, [row["id"] for row in approver_updates["data"]])
        self.assertEqual(self.client.get(f"/api/v1/updates/{approver_draft_id}", headers=approver_headers).status_code, 403)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{resources['Dev One Private']['update']['id']}", headers=approver_headers, json={"decision": "approved"}).status_code, 403)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{resources['Approver Grant']['update']['id']}", headers=approver_headers, json={"decision": "approved"}).status_code, 200)

        private_version = resources["Dev Two Private"]["version"]
        deployment = self.client.post("/api/v1/deployments", headers=self.headers["Admin"], json={"version_id": private_version["id"], "environment": "private-test"}).get_json()["data"]
        self.assertEqual(self.client.get(f"/api/v1/deployments/{deployment['id']}", headers=dev_headers).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/deployments", headers=dev_headers).get_json()["count"], 0)
        admin_report = self.client.get("/api/v1/reports", headers=self.headers["Admin"]).get_json()["data"]
        self.assertEqual(admin_report["projects"]["total"], 4)

    def test_approver_can_review_but_developer_and_viewer_cannot(self):
        project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={"name": "Review Project", "owner_id": self.role_user_id("Approver")}).get_json()["data"]
        version = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={"project_id": project["id"], "version_number": "1.0"}).get_json()["data"]
        self.assertEqual(self.client.post("/api/v1/versions", headers=self.headers["Approver"], json={"project_id": project["id"], "version_number": "blocked"}).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/updates", headers=self.headers["Approver"], json={"version_id": version["id"], "title": "blocked", "description": "blocked"}).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/deployments", headers=self.headers["Approver"], json={"version_id": version["id"], "environment": "test"}).status_code, 403)
        update = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={"version_id": version["id"], "title": "Review me", "description": "Test approval roles"}).get_json()["data"]
        self.assertEqual(self.client.post(f"/api/v1/updates/{update['id']}/submit", headers=self.headers["Developer"], json={}).status_code, 200)
        admin_authored = self.client.post("/api/v1/updates", headers=self.headers["Admin"], json={"version_id": version["id"], "title": "Admin draft", "description": "Developer cannot submit another user's record"}).get_json()["data"]
        self.assertEqual(self.client.post(f"/api/v1/updates/{admin_authored['id']}/submit", headers=self.headers["Developer"], json={}).status_code, 403)
        approver_queue = self.client.get("/api/v1/approvals", headers=self.headers["Approver"])
        self.assertEqual(approver_queue.status_code, 200)
        self.assertEqual([row["id"] for row in approver_queue.get_json()["data"]], [update["id"]])
        self.assertEqual(self.client.get("/api/v1/approvals", headers=self.headers["Developer"]).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/approvals", headers=self.headers["Viewer"]).status_code, 403)
        payload = {"decision": "approved", "comments": "Checked"}
        self.assertEqual(self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Developer"], json=payload).status_code, 403)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Viewer"], json=payload).status_code, 403)
        approved = self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Approver"], json=payload)
        self.assertEqual(approved.status_code, 200, approved.get_json())
        self.assertEqual(approved.get_json()["data"]["approvals"][0]["reviewer"], "Approver")
        self.assertEqual(approved.get_json()["data"]["status"], "approved")
        self.assertEqual(self.client.get(f"/api/v1/updates/{update['id']}", headers=self.headers["Approver"]).status_code, 200)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Approver"], json=payload).status_code, 409)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Approver"], json={"decision": "rejected", "comments": "Late reversal"}).status_code, 409)

        admin_authored_submit = self.client.post(f"/api/v1/updates/{admin_authored['id']}/submit", headers=self.headers["Admin"], json={})
        self.assertEqual(admin_authored_submit.status_code, 200)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{admin_authored['id']}", headers=self.headers["Admin"], json=payload).status_code, 403)

        approver_authored = self.client.post("/api/v1/updates", headers=self.headers["Admin"], json={"version_id": version["id"], "title": "Approver authored", "description": "Self review is forbidden"}).get_json()["data"]
        approver_id = self.role_user_id("Approver")
        with self.app.app_context():
            from app.models import Update
            row = self.db.session.get(Update, approver_authored["id"])
            row.created_by_id = approver_id
            self.db.session.commit()
        self.assertEqual(self.client.post(f"/api/v1/updates/{approver_authored['id']}/submit", headers=self.headers["Admin"], json={}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{approver_authored['id']}", headers=self.headers["Approver"], json=payload).status_code, 403)
        own_update = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={"version_id": version["id"], "title": "Own review", "description": "Cannot self approve"}).get_json()["data"]
        self.assertEqual(self.client.post(f"/api/v1/updates/{own_update['id']}/submit", headers=self.headers["Developer"], json={}).status_code, 200)
        developer = next(row for row in self.client.get("/api/v1/users", headers=self.headers["Admin"]).get_json()["data"] if row["email"] == self.users["Developer"][0])
        self.assertEqual(self.client.patch(f"/api/v1/users/{developer['id']}", headers=self.headers["Admin"], json={"role_id": self.role_ids["Approver"]}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{own_update['id']}", headers=self.headers["Developer"], json=payload).status_code, 403)

    def test_search_filters_and_restricted_audit_and_owner_endpoints(self):
        project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={"name": "Searchable Portal", "status": "active", "owner_id": self.role_user_id("Approver")}).get_json()["data"]
        self.assertEqual(self.client.get("/api/v1/projects?q=searchable", headers=self.headers["Developer"]).get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/v1/projects?q=searchable&status=active", headers=self.headers["Developer"]).get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/v1/projects?q=missing", headers=self.headers["Developer"]).get_json()["count"], 0)
        self.assertEqual(self.client.get(f"/api/v1/projects?q={'x' * 101}", headers=self.headers["Developer"]).status_code, 400)
        self.assertEqual(self.client.get("/api/v1/projects?q=%25", headers=self.headers["Developer"]).get_json()["count"], 0)
        self.assertEqual(self.client.get("/api/v1/projects?status=unknown", headers=self.headers["Developer"]).status_code, 400)
        self.assertEqual(self.client.get("/api/v1/project-owners", headers=self.headers["Developer"]).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/project-owners", headers=self.headers["Viewer"]).status_code, 403)
        version = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={"project_id": project["id"], "version_number": "search-v2", "status": "planned"}).get_json()["data"]
        self.assertEqual(self.client.get("/api/v1/versions?q=search-v2&status=planned", headers=self.headers["Approver"]).get_json()["count"], 1)
        update = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={"version_id": version["id"], "title": "Needle update", "description": "Search test"}).get_json()["data"]
        self.assertEqual(self.client.get("/api/v1/updates?q=needle&status=draft", headers=self.headers["Approver"]).get_json()["count"], 0)
        self.assertEqual(self.client.get(f"/api/v1/updates/{update['id']}", headers=self.headers["Approver"]).status_code, 403)
        self.assertEqual(self.client.post(f"/api/v1/updates/{update['id']}/submit", headers=self.headers["Developer"], json={}).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/updates?q=needle&status=pending", headers=self.headers["Approver"]).get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/v1/approvals?q=needle", headers=self.headers["Approver"]).get_json()["count"], 1)
        self.assertEqual(self.client.get("/api/v1/audit-logs", headers=self.headers["Viewer"]).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/audit-logs?q=project", headers=self.headers["Admin"]).status_code, 200)

    def test_audit_trail_records_required_actions_and_has_no_mutation_routes(self):
        project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={"name": "Audited Project", "owner_id": self.role_user_id("Approver")}).get_json()["data"]
        self.client.patch(f"/api/v1/projects/{project['id']}", headers=self.headers["Admin"], json={"description": "Updated"})
        version = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={"project_id": project["id"], "version_number": "audit-v1"}).get_json()["data"]
        self.client.patch(f"/api/v1/versions/{version['id']}", headers=self.headers["Developer"], json={"release_notes": "Notes updated"})
        update = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={"version_id": version["id"], "title": "Audit update", "description": "Track this workflow"}).get_json()["data"]
        self.client.post(f"/api/v1/updates/{update['id']}/submit", headers=self.headers["Developer"], json={})
        self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Approver"], json={"decision": "rejected", "comments": "Needs more detail"})
        deployment = self.client.post("/api/v1/deployments", headers=self.headers["Developer"], json={"version_id": version["id"], "environment": "test"}).get_json()["data"]
        self.client.patch(f"/api/v1/deployments/{deployment['id']}", headers=self.headers["Developer"], json={"status": "failed"})
        created_user = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={"full_name": "Audit User", "email": "audit-user@example.test", "password": "audit-user-password", "role_id": self.role_ids["Viewer"]}).get_json()["data"]
        self.client.patch(f"/api/v1/users/{created_user['id']}", headers=self.headers["Admin"], json={"full_name": "Updated Audit User"})
        self.client.patch(f"/api/v1/users/{created_user['id']}", headers=self.headers["Admin"], json={"is_active": False})

        result = self.client.get("/api/v1/audit-logs", headers=self.headers["Admin"])
        self.assertEqual(result.status_code, 200)
        events = {(row["entity_type"], row["action"]) for row in result.get_json()["data"]}
        expected = {
            ("project", "created"), ("project", "updated"),
            ("version", "created"), ("version", "updated"),
            ("update", "created"), ("update", "submitted_for_approval"), ("update", "rejected"),
            ("deployment", "created"), ("deployment", "updated"),
            ("user", "created"), ("user", "updated"), ("user", "deactivated"),
        }
        self.assertTrue(expected.issubset(events), expected - events)
        deactivation = next(row for row in result.get_json()["data"] if row["entity_type"] == "user" and row["action"] == "deactivated")
        self.assertIn("is_active", deactivation["details"]["changed_fields"])
        audit_id = result.get_json()["data"][0]["id"]
        self.assertEqual(self.client.patch(f"/api/v1/audit-logs/{audit_id}", headers=self.headers["Admin"], json={"action": "tampered"}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/v1/audit-logs/{audit_id}", headers=self.headers["Admin"]).status_code, 404)

    def test_version_update_approval_deployment_and_reports(self):
        project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={"name": "Release Project"}).get_json()["data"]
        version_response = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={"project_id": project["id"], "version_number": "1.0.0", "status": "released"})
        self.assertEqual(version_response.status_code, 201, version_response.get_json())
        version = version_response.get_json()["data"]
        self.assertTrue(version["release_date"])
        self.assertEqual(self.client.delete(f"/api/v1/versions/{version['id']}", headers=self.headers["Developer"]).status_code, 409)
        self.assertEqual(self.client.delete(f"/api/v1/projects/{project['id']}", headers=self.headers["Admin"]).status_code, 409)
        update = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={"version_id": version["id"], "title": "Release", "description": "First release"}).get_json()["data"]
        self.assertEqual(self.client.post(f"/api/v1/updates/{update['id']}/submit", headers=self.headers["Developer"], json={}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Developer"], json={"decision": "approved"}).status_code, 403)
        approval = self.client.post(f"/api/v1/approvals/{update['id']}", headers=self.headers["Admin"], json={"decision": "approved", "comments": "Reviewed"})
        self.assertEqual(approval.status_code, 200, approval.get_json())
        deployment = self.client.post("/api/v1/deployments", headers=self.headers["Developer"], json={"version_id": version["id"], "update_id": update["id"], "environment": "staging"})
        self.assertEqual(deployment.status_code, 201, deployment.get_json())
        deployment_id = deployment.get_json()["data"]["id"]
        wrong_method = self.client.post(f"/api/v1/deployments/{deployment_id}", headers=self.headers["Developer"], json={"status": "successful"})
        self.assertEqual(wrong_method.status_code, 405)
        self.assertEqual(self.client.patch(f"/api/v1/deployments/{deployment_id}", headers=self.headers["Developer"], json={"status": "successful"}).status_code, 200)
        retrieved = self.client.get(f"/api/v1/deployments/{deployment_id}", headers=self.headers["Developer"])
        self.assertEqual(retrieved.status_code, 200, retrieved.get_json())
        self.assertEqual(retrieved.get_json()["data"]["status"], "successful")
        self.assertEqual(self.client.get("/api/v1/deployments?status=successful&q=staging", headers=self.headers["Developer"]).get_json()["count"], 1)
        self.assertEqual(self.client.delete(f"/api/v1/deployments/{deployment_id}", headers=self.headers["Admin"]).status_code, 409)
        report = self.client.get("/api/v1/reports", headers=self.headers["Admin"]).get_json()["data"]
        self.assertEqual(report["updates"]["approved"], 1)
        self.assertEqual(report["deployments"]["successful"], 1)
        rejected = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={"version_id": version["id"], "title": "Rejected release", "description": "Needs changes"}).get_json()["data"]
        self.client.post(f"/api/v1/updates/{rejected['id']}/submit", headers=self.headers["Developer"], json={})
        self.assertEqual(self.client.post(f"/api/v1/approvals/{rejected['id']}", headers=self.headers["Admin"], json={"decision": "rejected"}).status_code, 400)
        decision = self.client.post(f"/api/v1/approvals/{rejected['id']}", headers=self.headers["Admin"], json={"decision": "rejected", "comments": "Missing acceptance criteria"})
        self.assertEqual(decision.status_code, 200, decision.get_json())
        self.assertEqual(decision.get_json()["data"]["approvals"][0]["reviewer"], "Admin")
        self.assertEqual(self.client.patch(f"/api/v1/updates/{rejected['id']}", headers=self.headers["Developer"], json={"description": "Corrected after review"}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/v1/updates/{rejected['id']}/submit", headers=self.headers["Developer"], json={}).status_code, 200)
        self.assertEqual(self.client.post(f"/api/v1/approvals/{rejected['id']}", headers=self.headers["Admin"], json={"decision": "approved"}).status_code, 200)
        failed = self.client.post("/api/v1/deployments", headers=self.headers["Developer"], json={"version_id": version["id"], "environment": "production", "status": "failed"})
        self.assertEqual(failed.status_code, 201, failed.get_json())
        refreshed_report = self.client.get("/api/v1/reports", headers=self.headers["Admin"]).get_json()["data"]
        self.assertEqual(refreshed_report["updates"]["rejected"], 1)
        self.assertEqual(refreshed_report["updates"]["approved"], 2)
        self.assertEqual(refreshed_report["deployments"]["failed"], 1)

    def test_user_admin_and_account_security(self):
        self.assertEqual(self.client.get("/api/v1/users", headers=self.headers["Developer"]).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/users", headers=self.headers["Approver"]).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/users", headers=self.headers["Viewer"]).status_code, 403)
        role_id = self.role_ids["Viewer"]
        created = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={"full_name": "New Viewer", "email": "new@example.test", "password": "new-viewer-password", "role_id": role_id, "is_email_verified": True})
        self.assertEqual(created.status_code, 201, created.get_json())
        self.assertTrue(created.get_json()["data"]["is_email_verified"])
        user_id = created.get_json()["data"]["id"]
        self.assertEqual(self.client.patch(f"/api/v1/users/{user_id}", headers=self.headers["Admin"], json={"is_active": False}).status_code, 200)
        self.assertEqual(self.client.post("/api/v1/auth/login", json={"email": "new@example.test", "password": "new-viewer-password"}).status_code, 401)
        admin_id = next(row["id"] for row in self.client.get("/api/v1/users", headers=self.headers["Admin"]).get_json()["data"] if row["email"] == self.users["Admin"][0])
        self.assertEqual(self.client.patch(f"/api/v1/users/{admin_id}", headers=self.headers["Admin"], json={"is_active": False}).status_code, 400)
        second_admin = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={"full_name": "Second Admin", "email": "second-admin@example.test", "password": "second-admin-password", "role_id": self.role_ids["Admin"]})
        self.assertEqual(second_admin.status_code, 201, second_admin.get_json())
        second_admin_id = second_admin.get_json()["data"]["id"]
        self.assertEqual(self.client.patch(f"/api/v1/users/{second_admin_id}", headers=self.headers["Admin"], json={"role_id": self.role_ids["Developer"]}).status_code, 200)
        self.assertEqual(self.client.patch("/api/v1/auth/profile", headers=self.headers["Developer"], json={"full_name": "Developer Updated"}).status_code, 200)
        changed = self.client.post("/api/v1/auth/password", headers=self.headers["Developer"], json={"current_password": self.users["Developer"][1], "new_password": "developer-new-password-123"})
        self.assertEqual(changed.status_code, 200, changed.get_json())

    def test_role_catalog_is_fixed_admin_only_and_assignments_are_counted(self):
        for name in ("Developer", "Approver", "Viewer"):
            self.assertEqual(self.client.get("/api/v1/roles", headers=self.headers[name]).status_code, 403)

        catalog_response = self.client.get("/api/v1/roles", headers=self.headers["Admin"])
        self.assertEqual(catalog_response.status_code, 200)
        catalog = catalog_response.get_json()["data"]
        self.assertEqual([role["name"] for role in catalog], ["Admin", "Developer", "Approver", "Viewer"])
        for role in catalog:
            self.assertTrue(role["description"])
            self.assertTrue(role["access_level"])
            self.assertTrue(role["permissions"])
            self.assertEqual(role["user_count"], 1)
            self.assertTrue(role["configured"])

        from app.models import Role
        from sqlalchemy.exc import IntegrityError
        with self.app.app_context():
            self.db.session.add(Role(name="Admin"))
            with self.assertRaises(IntegrityError):
                self.db.session.flush()
            self.db.session.rollback()
            unsupported = Role(name="Auditor")
            self.db.session.add(unsupported)
            self.db.session.commit()
            unsupported_role_id = unsupported.id

        self.assertNotIn("Auditor", [role["name"] for role in self.client.get("/api/v1/roles", headers=self.headers["Admin"]).get_json()["data"]])
        invalid_role = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
            "full_name": "Unsupported Role User", "email": "unsupported-role@example.test",
            "password": "unsupported-user-password", "role_id": unsupported_role_id,
        })
        self.assertEqual(invalid_role.status_code, 400)

        created = self.client.post("/api/v1/users", headers=self.headers["Admin"], json={
            "full_name": "Role Assignment User", "email": "role-assignment@example.test",
            "password": "role-assignment-password", "role_id": self.role_ids["Developer"],
        })
        self.assertEqual(created.status_code, 201, created.get_json())
        user_id = created.get_json()["data"]["id"]
        self.assertEqual(self.client.patch(f"/api/v1/users/{user_id}", headers=self.headers["Developer"], json={
            "role_id": self.role_ids["Viewer"],
        }).status_code, 403)
        changed = self.client.patch(f"/api/v1/users/{user_id}", headers=self.headers["Admin"], json={
            "role_id": self.role_ids["Viewer"],
        })
        self.assertEqual(changed.status_code, 200, changed.get_json())
        self.assertEqual(changed.get_json()["data"]["role_id"], self.role_ids["Viewer"])
        counts = {role["name"]: role["user_count"] for role in self.client.get("/api/v1/roles", headers=self.headers["Admin"]).get_json()["data"]}
        self.assertEqual(counts, {"Admin": 1, "Developer": 1, "Approver": 1, "Viewer": 2})

        self.assertEqual(self.client.post("/api/v1/roles", headers=self.headers["Admin"], json={"name": "Auditor"}).status_code, 405)

    def test_invalid_login_inactive_tokens_and_expired_tokens(self):
        email, password = self.users["Developer"]
        self.assertEqual(self.client.post("/api/v1/auth/login", json={"email": email, "password": "wrong-password"}).status_code, 401)
        with self.app.app_context():
            identity = str(self.client.get("/api/v1/auth/me", headers=self.headers["Developer"]).get_json()["user"]["id"])
            expired_access = create_access_token(identity=identity, expires_delta=timedelta(seconds=-1))
            expired_refresh = create_refresh_token(identity=identity, expires_delta=timedelta(seconds=-1))
        self.assertEqual(self.client.get("/api/v1/projects", headers={"Authorization": f"Bearer {expired_access}"}).status_code, 401)
        self.assertEqual(self.client.post("/api/v1/auth/refresh", headers={"Authorization": f"Bearer {expired_refresh}"}).status_code, 401)
        users = self.client.get("/api/v1/users", headers=self.headers["Admin"]).get_json()["data"]
        developer = next(row for row in users if row["email"] == email)
        self.assertEqual(self.client.patch(f"/api/v1/users/{developer['id']}", headers=self.headers["Admin"], json={"is_active": False}).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=self.headers["Developer"]).status_code, 401)
        self.assertEqual(self.client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code, 401)

    def test_logout_revokes_access_and_refresh_tokens(self):
        login = self.client.post("/api/v1/auth/login", json={
            "email": self.users["Developer"][0],
            "password": self.users["Developer"][1],
        }).get_json()
        access = {"Authorization": f"Bearer {login['access_token']}"}
        refresh = {"Authorization": f"Bearer {login['refresh_token']}"}

        self.assertEqual(self.client.post("/api/v1/auth/logout", headers=access).status_code, 200)
        self.assertEqual(self.client.post("/api/v1/auth/logout", headers=refresh).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=access).status_code, 401)
        self.assertEqual(self.client.post("/api/v1/auth/refresh", headers=refresh).status_code, 401)

    def test_deployment_edits_reconcile_update_deployed_status(self):
        project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={
            "name": "Deployment State Project",
        }).get_json()["data"]
        version = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={
            "project_id": project["id"], "version_number": "1.0",
        }).get_json()["data"]

        rejected = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={
            "version_id": version["id"], "title": "Rejected change", "description": "Must not be deployed",
        }).get_json()["data"]
        self.client.post(f"/api/v1/updates/{rejected['id']}/submit", headers=self.headers["Developer"], json={})
        self.assertEqual(self.client.post(f"/api/v1/approvals/{rejected['id']}", headers=self.headers["Admin"], json={
            "decision": "rejected", "comments": "Not ready",
        }).status_code, 200)
        blocked_deployment = self.client.post("/api/v1/deployments", headers=self.headers["Developer"], json={
            "version_id": version["id"], "update_id": rejected["id"], "environment": "test",
        })
        self.assertEqual(blocked_deployment.status_code, 409)
        invalid_status = self.client.post("/api/v1/deployments", headers=self.headers["Developer"], json={
            "version_id": version["id"], "environment": "test", "status": "deployed",
        })
        self.assertEqual(invalid_status.status_code, 400)

        def approved_update(title):
            row = self.client.post("/api/v1/updates", headers=self.headers["Developer"], json={
                "version_id": version["id"], "title": title, "description": "Deployment transition test",
            }).get_json()["data"]
            self.client.post(f"/api/v1/updates/{row['id']}/submit", headers=self.headers["Developer"], json={})
            self.assertEqual(self.client.post(f"/api/v1/approvals/{row['id']}", headers=self.headers["Admin"], json={
                "decision": "approved",
            }).status_code, 200)
            return row

        first = approved_update("First update")
        second = approved_update("Second update")
        deployment = self.client.post("/api/v1/deployments", headers=self.headers["Developer"], json={
            "version_id": version["id"], "update_id": first["id"],
            "environment": "test", "status": "successful",
        }).get_json()["data"]
        self.assertEqual(self.client.get(f"/api/v1/updates/{first['id']}", headers=self.headers["Developer"]).get_json()["data"]["status"], "deployed")

        changed = self.client.patch(f"/api/v1/deployments/{deployment['id']}", headers=self.headers["Developer"], json={
            "update_id": second["id"],
        })
        self.assertEqual(changed.status_code, 200, changed.get_json())
        self.assertEqual(self.client.get(f"/api/v1/updates/{first['id']}", headers=self.headers["Developer"]).get_json()["data"]["status"], "approved")
        self.assertEqual(self.client.get(f"/api/v1/updates/{second['id']}", headers=self.headers["Developer"]).get_json()["data"]["status"], "deployed")

        other_version = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={
            "project_id": project["id"], "version_number": "2.0",
        }).get_json()["data"]
        mismatch = self.client.patch(f"/api/v1/deployments/{deployment['id']}", headers=self.headers["Developer"], json={
            "version_id": other_version["id"],
        })
        self.assertEqual(mismatch.status_code, 400)

        cleared = self.client.patch(f"/api/v1/deployments/{deployment['id']}", headers=self.headers["Developer"], json={
            "update_id": None,
        })
        self.assertEqual(cleared.status_code, 200, cleared.get_json())
        self.assertEqual(self.client.get(f"/api/v1/updates/{second['id']}", headers=self.headers["Developer"]).get_json()["data"]["status"], "approved")

    def test_version_number_uniqueness_is_scoped_to_project(self):
        first_project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={
            "name": "Version Scope A",
        }).get_json()["data"]
        second_project = self.client.post("/api/v1/projects", headers=self.headers["Developer"], json={
            "name": "Version Scope B",
        }).get_json()["data"]
        first = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={
            "project_id": first_project["id"], "version_number": "1.0",
        })
        self.assertEqual(first.status_code, 201, first.get_json())
        self.assertEqual(self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={
            "project_id": second_project["id"], "version_number": "1.0",
        }).status_code, 201)
        duplicate = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={
            "project_id": first_project["id"], "version_number": "1.0",
        })
        self.assertEqual(duplicate.status_code, 409)

        second = self.client.post("/api/v1/versions", headers=self.headers["Developer"], json={
            "project_id": first_project["id"], "version_number": "2.0",
        }).get_json()["data"]
        conflict = self.client.patch(f"/api/v1/versions/{second['id']}", headers=self.headers["Developer"], json={
            "version_number": "1.0",
        })
        self.assertEqual(conflict.status_code, 409)


if __name__ == "__main__":
    unittest.main()
